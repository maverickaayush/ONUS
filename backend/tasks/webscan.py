import json
import logging
import os
import re
import shutil
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from typing import List, Optional, Tuple
from urllib.parse import urljoin, quote

import psutil
import requests
from celery.exceptions import SoftTimeLimitExceeded
from zapv2 import ZAPv2

from config import settings
from tasks.base_task import (
    BaseTask, normalize_finding, update_module_status,
    get_tool_version, build_module_result, resolve_target_url,
)
from tasks.celery_app import app

logger = logging.getLogger(__name__)
MODULE = 'webscan'

# Mirrors analysis/cvss_scorer.py's _DIRECTORY_LISTING_RE - kept as a
# separate copy rather than a shared import (tasks/ modules never import
# analysis/, only scan_orchestrator.py bridges the two).
_NIKTO_DIRECTORY_LISTING_RE = re.compile(r'directory index|autoindex|index of /', re.IGNORECASE)

# ZAP risk string → normalized severity
_ZAP_RISK_MAP = {
    'High':           'High',
    'Medium':         'Medium',
    'Low':            'Low',
    'Informational':  'Informational',
    'False Positive': 'Informational',
}

# --- Timing budget -----------------------------------------------------------
# Webscan is the heaviest module: ZAP active scanning legitimately needs minutes.
# It therefore runs with a RAISED per-task Celery limit (see the run_webscan
# decorator) instead of the default 300/360 - otherwise the worst case below
# would be SIGKILL'd mid-scan, which breaks the chord and fails the whole scan.
#
#   ZAP readiness wait   : <= 60s   (_ZAP_READY_TIMEOUT)
#   ZAP spider + ascan   : <= 240s  (_ZAP_SCAN_BUDGET, combined hard cap)
#   Katana               : <= 180s  (_KATANA_TIMEOUT) - runs in a thread
#                                    ALONGSIDE ZAP (see run_webscan), so it
#                                    adds no wall-clock time of its own; the
#                                    worst case below is still gated by ZAP.
#   Nikto                : <= 130s  (subprocess timeout; -maxtime 120s)
#   ----------------------------------------------------------------------
#   worst case           : <= ~430s  (well under the 480s soft / 540s hard limit)
_ZAP_READY_TIMEOUT = 60
_ZAP_SCAN_BUDGET = 240
_KATANA_TIMEOUT = 180
_NIKTO_TIMEOUT = 130
_WEBSCAN_SOFT_LIMIT = 480
_WEBSCAN_HARD_LIMIT = 540
# A ZAP status-poll can fail transiently while the daemon is alive but busy
# (its single API thread stalls under active-scan load, or one HTTP request
# times out) - the daemon recovers on the next poll. Only conclude the daemon
# is actually unreachable after this many *consecutive* failed polls, so one
# blip no longer discards a whole scan's findings. Confirmed real: webscan
# reported "ZAP unreachable" while the container had never restarted
# (RestartCount unchanged) - i.e. a false positive from a single blip.
_ZAP_POLL_MAX_CONSECUTIVE_FAILURES = 4
_ZAP_POLL_FAILURE_BACKOFF = 3  # seconds between retries of a failed poll


# ---------------------------------------------------------------------------
# ZAP process lifecycle helpers
# ---------------------------------------------------------------------------

def _zap_port(scan_id: str) -> int:
    """
    Derive a per-scan ZAP port so concurrent scans don't collide.
    Range 8090-8989. (hash() is per-process-randomized, but the port is computed
    and used within one task execution, so that's fine here.)
    """
    return 8090 + (hash(scan_id) % 900)


def _kill_zap(proc: Optional[subprocess.Popen]) -> None:
    """
    Terminate the ZAP daemon and all its children: graceful SIGTERM first,
    then SIGKILL after 5s, then reap the Popen so it can't become a zombie.
    Never raises - called from finally blocks.
    """
    if proc is None:
        return
    try:
        parent = psutil.Process(proc.pid)
        children = parent.children(recursive=True)
        for child in children:
            try:
                child.terminate()
            except psutil.NoSuchProcess:
                pass
        parent.terminate()

        gone, alive = psutil.wait_procs([parent] + children, timeout=5)
        for p in alive:
            try:
                p.kill()
            except psutil.NoSuchProcess:
                pass
    except psutil.NoSuchProcess:
        pass
    except Exception as e:
        logger.warning("ZAP kill warning (non-fatal): %s", e)
    finally:
        # Reap the subprocess handle so no zombie is left behind.
        try:
            proc.wait(timeout=3)
        except Exception:
            pass


def _start_zap(scan_id: str, port: int) -> Optional[subprocess.Popen]:
    """
    Start ZAP daemon and return the Popen handle, or None if zap.sh is missing.
    Does NOT wait for readiness - call _wait_for_zap() after this.
    """
    zap_cmd = None
    for candidate in ('zap.sh', 'zap', '/usr/share/zaproxy/zap.sh',
                      '/opt/zaproxy/zap.sh'):
        if shutil.which(candidate) or (os.path.isabs(candidate) and os.access(candidate, os.X_OK)):
            zap_cmd = candidate
            break

    if not zap_cmd:
        logger.warning("ZAP not found in PATH - web scan will use Nikto only")
        return None

    try:
        proc = subprocess.Popen(
            [
                zap_cmd, '-daemon',
                '-port', str(port),
                '-config', 'api.disablekey=true',
                '-config', 'connection.timeoutInSecs=60',
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        logger.info("ZAP daemon started (pid=%d) on port %d for scan %s",
                    proc.pid, port, scan_id)
        return proc
    except Exception as e:
        logger.error("Failed to start ZAP for scan %s: %s", scan_id, e)
        return None


def _wait_for_zap(base_url: str, timeout: int = _ZAP_READY_TIMEOUT) -> bool:
    """
    Poll ZAP's version endpoint every 2s for up to timeout seconds.
    base_url is e.g. 'http://localhost:8090' (local daemon) or
    'http://zap:8090' (Docker sidecar) - no trailing slash.
    Returns True when ZAP is ready, False if it never responds.
    """
    url = f'{base_url}/JSON/core/view/version/'
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            r = requests.get(url, timeout=2)
            if r.status_code == 200:
                logger.info("ZAP ready at %s", base_url)
                return True
        except Exception:
            pass
        time.sleep(2)
    logger.warning("ZAP did not become ready within %ds at %s", timeout, base_url)
    return False


def _is_zap_scan_id(val) -> bool:
    """
    ZAP's spider.scan()/ascan.scan() return the new scan's id as a numeric
    string ('0', '1', ...). On failure they instead hand back a non-numeric
    status string ('does_not_exist', 'url_not_in_context', ...) which must NOT
    then be fed to status() as if it were a real id - doing so is exactly what
    made a reachable-but-idle ZAP look "unreachable" (int('does_not_exist')
    raised, and the old code read that as a disconnect).
    """
    try:
        return int(val) >= 0
    except (TypeError, ValueError):
        return False


def _poll_zap_scan(status_fn, scan_deadline: float, interval: int,
                   scan_id: str, phase: str) -> str:
    """
    Poll a ZAP scan's progress (spider or active scan) until it reaches 100%,
    the shared scan budget runs out, ZAP goes genuinely unreachable, or the
    scan handle becomes invalid. `status_fn` is a zero-arg callable returning
    ZAP's percent-complete string (e.g. lambda: zap.spider.status(spider_id)).

    Returns one of: 'complete' | 'budget' | 'disconnected' | 'invalid'.

    Two failure modes are deliberately kept distinct - conflating them is the
    original bug this fixes:
      - status_fn() *raising* (ConnectionError/timeout) = ZAP is unreachable.
        A single one is NOT fatal - ZAP's API blips while the daemon is alive
        but saturated (effectively single-threaded under active-scan load).
        Only _ZAP_POLL_MAX_CONSECUTIVE_FAILURES in a row, with a short backoff
        and the counter reset on any success, concludes the daemon is gone
        ('disconnected'). One blip used to abandon the whole scan.
      - status_fn() *returning a non-numeric string* ('does_not_exist') = ZAP
        is perfectly reachable but the scan handle is gone/never valid. That's
        'invalid', NOT a disconnect - the phase just can't produce results,
        and the caller collects whatever alerts already exist and reports
        success rather than a misleading 'partial'.
    """
    consecutive_failures = 0
    while time.monotonic() < scan_deadline:
        try:
            raw = status_fn()
        except Exception as e:
            consecutive_failures += 1
            if consecutive_failures >= _ZAP_POLL_MAX_CONSECUTIVE_FAILURES:
                logger.error("ZAP %s status failed %d times in a row for scan "
                             "%s - treating ZAP as unreachable: %s",
                             phase, consecutive_failures, scan_id, e)
                return 'disconnected'
            logger.warning("ZAP %s status check blipped for scan %s "
                           "(failure %d/%d, retrying): %s", phase, scan_id,
                           consecutive_failures,
                           _ZAP_POLL_MAX_CONSECUTIVE_FAILURES, e)
            time.sleep(_ZAP_POLL_FAILURE_BACKOFF)
            continue
        try:
            if int(raw) >= 100:
                return 'complete'
            consecutive_failures = 0
        except (TypeError, ValueError):
            logger.warning("ZAP %s returned a non-numeric status %r for scan "
                           "%s - scan handle invalid, ending this phase "
                           "(ZAP itself is still reachable)", phase, raw, scan_id)
            return 'invalid'
        time.sleep(interval)
    return 'budget'


# ---------------------------------------------------------------------------
# ZAP scanning
# ---------------------------------------------------------------------------

def _run_zap(scan_id: str, domain: str, target_url: str) -> Tuple[List[dict], Optional[str], bool]:
    """
    Run OWASP ZAP: spider + active scan + collect alerts.
    Returns (normalized findings, zap_version, disconnected_mid_scan).
    zap_version comes from the ZAP API itself (zap.core.version), not
    subprocess, since ZAP is a daemon/sidecar rather than a plain CLI tool;
    None if ZAP never became reachable.

    disconnected_mid_scan is distinct from "ZAP never became reachable at
    all" (that case is the pre-existing, deliberate "ZAP is one of three
    optional tools" behavior below - not a failure). It's True only when ZAP
    passed its initial readiness check, scanning started, and it then went
    unreachable during spider/active-scan polling or alert retrieval - e.g. a
    ZAP daemon restart mid-scan (observed in practice, see docs/
    test_findings.md's "ZAP restart pattern" notes). That case previously
    looked identical to "ZAP legitimately found nothing" (empty findings,
    status='success') - a real instance of the exact silent-data-loss anti-
    pattern Section 4.3/the project docs warns against, since 3+ minutes of spider/
    ascan time had already been sunk into a target that never got its
    results collected.

    Two modes, chosen by settings.ZAP_URL:
    - Remote (Docker): ZAP runs as a separate sidecar container reachable at
      ZAP_URL (e.g. http://zap:8090). No local process to spawn or kill.
      A unique session per scan_id replaces the port-hash isolation scheme,
      since the daemon is shared across concurrent scans.
    - Local (native dev, ZAP_URL unset): spawn+kill a local ZAP daemon on a
      per-scan port, exactly as before.
    """
    findings = []
    proc = None
    zap_version = None
    disconnected_mid_scan = False
    # Set when a JSON-auth Replacer rule is added, so the finally block can
    # remove it - the rule is GLOBAL on the shared ZAP sidecar, so leaving it
    # would leak this scan's bearer token into every later scan's requests.
    json_auth_rule_desc = None
    remote_zap_url = settings.ZAP_URL.rstrip('/')

    try:
        if remote_zap_url:
            if not _wait_for_zap(remote_zap_url, timeout=_ZAP_READY_TIMEOUT):
                logger.warning("Remote ZAP not ready for scan %s - skipping ZAP", scan_id)
                return findings, zap_version, disconnected_mid_scan

            zap = ZAPv2(
                apikey='',
                proxies={'http': remote_zap_url, 'https': remote_zap_url},
            )
            try:
                zap.core.new_session(name=scan_id, overwrite='true')
            except Exception as e:
                logger.warning("ZAP new_session failed for scan %s (continuing "
                               "on shared session): %s", scan_id, e)
        else:
            port = _zap_port(scan_id)
            proc = _start_zap(scan_id, port)
            if proc is None:
                return findings, zap_version, disconnected_mid_scan

            local_base_url = f'http://localhost:{port}'
            if not _wait_for_zap(local_base_url, timeout=_ZAP_READY_TIMEOUT):
                logger.warning("ZAP not ready for scan %s - skipping ZAP", scan_id)
                return findings, zap_version, disconnected_mid_scan

            zap = ZAPv2(
                apikey='',
                proxies={
                    'http': f'http://127.0.0.1:{port}',
                    'https': f'http://127.0.0.1:{port}',
                },
            )

        try:
            zap_version = zap.core.version
        except Exception as e:
            logger.debug("ZAP version lookup failed for scan %s: %s", scan_id, e)

        # --- Authenticated scanning (optional) ---
        # Form-based login only (v1 scope - see schemas.py's AuthConfig
        # docstring). Forced-user mode means the spider/active-scan calls
        # below need no code changes - ZAP transparently carries whatever
        # session it establishes into every request once this is set up.
        #
        # Uses ZAP script-based authentication (zap-scripts/vapt_form_auth.js,
        # mounted read-only into the zap service - see docker-compose.yml),
        # not the simpler `formBasedAuthentication` config. That simpler
        # config only sends a static username/password template on every
        # (re-)login ZAP performs internally, with no way to include a
        # submit-button field some apps require (DVWA's `Login=Login`) or a
        # fresh per-request CSRF token (DVWA's `user_token`, NodeGoat's
        # `_csrf`) - confirmed NOT to work by direct testing before this was
        # replaced with the script below. The script mirrors owasp.py's own
        # `_make_session()`/`_FormFieldExtractor` exactly: GET the login page
        # fresh, submit every field already on the form with username/
        # password overridden, rather than special-casing known CSRF field
        # names. Confirmed working by direct testing against DVWA (proxying
        # a request through ZAP with forced-user mode enabled now returns
        # authenticated content, not the login form).
        #
        # Non-fatal on any failure here, matching this function's existing
        # "ZAP is one of three optional tools" resilience pattern - an
        # unauthenticated scan is still better than no scan.
        #
        # Deliberately NEVER calls zap.authentication.set_logged_in_indicator(),
        # even though AuthConfig accepts logged_in_indicator (owasp.py's own
        # _make_session() does use it, as a one-time best-effort check - that
        # usage is fine). On the ZAP side it's a different, much more
        # dangerous mechanism: once set, ZAP checks the regex against every
        # single response the spider/active-scanner receives - including
        # CSS/JS/image/redirect/error responses that legitimately never
        # contain the indicator text - and its "Insights" add-on counts each
        # non-match as an authentication failure. Confirmed by direct
        # testing: with the indicator set, ZAP hit its 100-failure threshold
        # and self-terminated the entire daemon in ~1 second of real
        # scanning (not a crash or OOM - "Shutting down ZAP due to High
        # Level Insight: ... insight.auth.failure : 100"), even though the
        # authenticate() script itself was working correctly the whole time
        # (proven by a clean, direct call to _run_zap with the indicator
        # omitted: 95 real findings, zero disconnects). Thread-count/
        # concurrency tuning was tried first and looked like a fix in
        # isolated tests, but the real culprit was this indicator check, not
        # load - concurrency wasn't touched in the end.
        from tasks.auth_store import get_scan_auth
        auth = get_scan_auth(scan_id)
        # login_type defaults to auto-detection (form vs JSON sniffed from the
        # login URL) unless the operator forced 'form'/'json'.
        from tasks.auth_login import resolve_login_type
        auth_login_type = resolve_login_type(auth) if auth else None
        if auth and auth_login_type == 'json':
            # JSON-API login: fetch a bearer token in Python, then inject it
            # into every ZAP request via the Replacer add-on. No auth script /
            # forced-user needed for a static bearer token - the Replacer rule
            # adds the header to all initiators. (Confirmed the replacer
            # component is present on the ZAP sidecar.)
            try:
                from tasks.auth_login import fetch_json_auth_token, auth_header_from
                token = fetch_json_auth_token(auth)
                if token:
                    header, value = auth_header_from(auth, token)
                    # Scan-scoped description (removed in finally) + url-scoped
                    # to this target only, so the header never lands on a
                    # concurrent scan's requests through the shared sidecar.
                    # (Same-target concurrency can't happen - Section 8 rejects
                    # duplicate active scans for one domain.)
                    json_auth_rule_desc = f'vapt-json-auth-{scan_id}'
                    zap.replacer.add_rule(
                        description=json_auth_rule_desc, enabled='true',
                        matchtype='REQ_HEADER', matchregex='false',
                        matchstring=header, replacement=value, initiators='',
                        url=re.escape(target_url) + '.*')
                    logger.info("ZAP JSON auth header injected for scan %s", scan_id)
                else:
                    logger.warning("ZAP JSON login failed for scan %s "
                                   "(continuing unauthenticated)", scan_id)
            except Exception as e:
                logger.warning("ZAP JSON auth setup failed for scan %s "
                               "(continuing unauthenticated): %s", scan_id, e)
        elif auth:
            try:
                ctx_name = f'ctx-{scan_id}'
                context_id = zap.context.new_context(ctx_name)
                zap.context.include_in_context(ctx_name, re.escape(target_url) + '.*')
                # The script is a fixed, shared name (not scan_id-scoped) since
                # it's identical content for every scan - ZAP's script store
                # persists across sessions, so a second scan's zap.script.load()
                # would otherwise hit ApiException: ALREADY_EXISTS (confirmed
                # during this feature's own verification). Load only if not
                # already present, rather than remove-then-reload every scan -
                # this file never changes at runtime in production, and
                # removing a shared script could disrupt a *different*,
                # concurrently-running authenticated scan using the same one
                # (Section 8 allows up to 3 concurrent scans).
                if not any(s.get('name') == 'vapt-form-auth' for s in zap.script.list_scripts):
                    zap.script.load(
                        'vapt-form-auth', 'authentication', 'ECMAScript : Graal.js',
                        '/zap-scripts/vapt_form_auth.js', 'VAPT form auth',
                    )
                configparams = (
                    'scriptName=vapt-form-auth'
                    f'&loginUrl={quote(auth["login_url"], safe="")}'
                    f'&usernameField={quote(auth["username_field"], safe="")}'
                    f'&passwordField={quote(auth["password_field"], safe="")}'
                )
                zap.authentication.set_authentication_method(
                    context_id, 'scriptBasedAuthentication', configparams)
                user_id = zap.users.new_user(context_id, 'vapt-user')
                zap.users.set_authentication_credentials(
                    context_id, user_id,
                    f'username={auth["username"]}&password={auth["password"]}')
                zap.users.set_user_enabled(context_id, user_id, True)
                zap.forcedUser.set_forced_user(context_id, user_id)
                zap.forcedUser.set_forced_user_mode_enabled(True)
            except Exception as e:
                logger.warning("ZAP auth setup failed for scan %s (continuing "
                                "unauthenticated): %s", scan_id, e)

        scan_deadline = time.monotonic() + _ZAP_SCAN_BUDGET

        # --- Spider ---
        logger.info("ZAP spider starting for scan %s", scan_id)
        spider_id = zap.spider.scan(target_url)
        if not _is_zap_scan_id(spider_id):
            # ZAP is reachable but the spider didn't start (returned an error
            # string, not a scan id) - usually nothing spiderable in scope.
            # Not a disconnect; fall through to alert collection.
            logger.warning("ZAP spider did not start for scan %s (returned %r) "
                           "- skipping to alert collection", scan_id, spider_id)
        else:
            spider_outcome = _poll_zap_scan(
                lambda: zap.spider.status(spider_id),
                scan_deadline, 3, scan_id, 'spider')
            if spider_outcome == 'disconnected':
                disconnected_mid_scan = True
            elif spider_outcome == 'budget':
                logger.warning("ZAP spider hit scan budget for scan %s", scan_id)

        # --- Active scan (only if budget remains AND ZAP is still reachable) ---
        # A spider-phase disconnect skips ascan (zap.ascan.scan would just
        # raise into the outer handler and lose the alerts we can still try to
        # collect below); we fall straight through to alert collection.
        if not disconnected_mid_scan and time.monotonic() < scan_deadline:
            logger.info("ZAP active scan starting for scan %s", scan_id)
            ascan_id = zap.ascan.scan(target_url)
            if not _is_zap_scan_id(ascan_id):
                # Reachable ZAP, but nothing in scope to actively scan (this is
                # exactly the testphp 'does_not_exist' case). Collect whatever
                # the spider found; do NOT report a misleading disconnect.
                logger.warning("ZAP active scan did not start for scan %s "
                               "(returned %r) - collecting spider alerts only",
                               scan_id, ascan_id)
            else:
                ascan_outcome = _poll_zap_scan(
                    lambda: zap.ascan.status(ascan_id),
                    scan_deadline, 5, scan_id, 'active scan')
                if ascan_outcome == 'disconnected':
                    disconnected_mid_scan = True
                elif ascan_outcome == 'budget':
                    logger.warning("ZAP active scan hit scan budget for scan %s "
                                   "- collecting alerts found so far", scan_id)

        # --- Collect alerts (whatever exists, even on a budget cut) ---
        try:
            alerts = zap.core.alerts(baseurl=target_url)
            if not isinstance(alerts, list):
                alerts = []
        except Exception as e:
            logger.error("ZAP alert retrieval failed for scan %s: %s", scan_id, e)
            alerts = []
            disconnected_mid_scan = True

        logger.info("ZAP collected %d alerts for scan %s", len(alerts), scan_id)

        for alert in alerts:
            risk = alert.get('risk', 'Informational')
            severity = _ZAP_RISK_MAP.get(risk, 'Informational')
            evidence = alert.get('evidence', '') or alert.get('description', '')
            url = alert.get('url', target_url)
            findings.append(normalize_finding(
                module=MODULE,
                tool='zap',
                type_=f'zap_{alert.get("pluginId", "alert")}',
                title=alert.get('alert', 'ZAP Alert'),
                evidence=f'{url} | {evidence}',
                severity=severity,
                target=domain,
            ))

    except Exception as e:
        logger.error("ZAP unexpected error for scan %s: %s", scan_id, e)
    finally:
        # Remove the JSON-auth Replacer rule so this scan's bearer token never
        # leaks into later scans on the shared sidecar. Best-effort - a
        # dangling rule is url-scoped to this target anyway, but clean is
        # better. `zap` may be unbound if ZAP never became reachable.
        if json_auth_rule_desc:
            try:
                zap.replacer.remove_rule(json_auth_rule_desc)
            except Exception as e:
                logger.warning("Failed to remove ZAP JSON auth rule %s: %s",
                               json_auth_rule_desc, e)
        _kill_zap(proc)  # no-op when proc is None (remote ZAP mode)
        logger.info("ZAP scan finished for scan %s", scan_id)

    return findings, zap_version, disconnected_mid_scan


# ---------------------------------------------------------------------------
# Katana (JS-aware crawler, supplements ZAP's HTML spider)
# ---------------------------------------------------------------------------

def _run_katana(scan_id: str, domain: str, target_url: str) -> List[dict]:
    """
    Run Katana as a supplemental crawler for SPA/JS-heavy targets that ZAP's
    HTML spider misses. Does not replace ZAP - runs alongside it in a thread
    (see run_webscan). Returns normalized 'crawled_endpoint_katana' findings,
    each tagged with an extra 'endpoint' key (same pattern as tech_fingerprint's
    finding['technology']) so run_webscan can diff them against ZAP's URLs
    once both threads finish, to flag JS-only routes as 'js_hidden_endpoints'.
    """
    findings = []
    out_path = f'/tmp/katana_{scan_id}.txt'
    try:
        subprocess.run(
            ['katana', '-u', target_url,
             '-jc', '-kf', 'all', '-d', '3', '-c', '10', '-rate-limit', '50',
             '-timeout', '15', '-o', out_path, '-silent', '-no-color', '-json'],
            timeout=_KATANA_TIMEOUT,
            capture_output=True,
            check=False,
        )

        if not os.path.exists(out_path):
            return findings
        with open(out_path) as f:
            raw = f.read().strip()
        if not raw:
            return findings

        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            endpoint = entry.get('endpoint', '')
            if not endpoint:
                continue
            method = entry.get('method', 'GET')
            status_code = entry.get('status_code', '')
            finding = normalize_finding(
                module=MODULE, tool='katana', type_='crawled_endpoint_katana',
                title=f'Endpoint discovered: {method} {endpoint}',
                evidence=f'Discovered by Katana JS crawler | Status: {status_code}',
                severity='Informational', target=domain,
            )
            finding['endpoint'] = endpoint
            findings.append(finding)

    except subprocess.TimeoutExpired:
        logger.warning("Katana timed out (%ds) for scan %s", _KATANA_TIMEOUT, scan_id)
    except FileNotFoundError:
        logger.warning("Katana not installed - skipping for scan %s", scan_id)
    except Exception as e:
        logger.error("Katana error for scan %s: %s", scan_id, e)
    finally:
        if os.path.exists(out_path):
            try:
                os.unlink(out_path)
            except OSError:
                pass

    return findings


def _js_hidden_endpoints_finding(domain: str, zap_findings: List[dict],
                                  katana_findings: List[dict]) -> Optional[dict]:
    """Diff Katana's crawled endpoints against ZAP's alert URLs (once both
    threads have finished) and flag routes ZAP's HTML spider never saw."""
    zap_urls = {f['evidence'].split(' | ', 1)[0] for f in zap_findings if f.get('evidence')}
    katana_endpoints = {f['endpoint'] for f in katana_findings if f.get('endpoint')}
    hidden = katana_endpoints - zap_urls
    if not hidden:
        return None
    return normalize_finding(
        module=MODULE, tool='katana', type_='js_hidden_endpoints',
        title=f'{len(hidden)} endpoints only visible to JS crawler',
        evidence="These routes were not discoverable by ZAP's HTML spider "
                 "and may not have been actively tested.",
        severity='Low', cvss=3.5, target=domain,
    )


# ---------------------------------------------------------------------------
# Nikto
# ---------------------------------------------------------------------------

def _run_nikto(scan_id: str, domain: str, target_url: str) -> List[dict]:
    """Run Nikto and return normalized findings."""
    findings = []
    out_path = f'/tmp/nikto_{scan_id}.json'
    try:
        subprocess.run(
            [
                'nikto', '-h', target_url,
                '-Format', 'json',
                '-o', out_path,
                '-Tuning', '1234578b',
                '-maxtime', '120s',
            ],
            timeout=_NIKTO_TIMEOUT,
            capture_output=True,
            check=False,
        )

        if not os.path.exists(out_path):
            logger.warning("Nikto produced no output for scan %s", scan_id)
            return findings

        with open(out_path) as f:
            raw = f.read().strip()
        if not raw:
            return findings

        data = json.loads(raw)

        # Nikto -Format json emits a list of host objects, each holding a
        # "vulnerabilities" list:  [{"host":..., "vulnerabilities":[{...}]}].
        # Handle that, a bare dict, and a flat list of vulns defensively.
        if isinstance(data, dict):
            hosts = [data]
        elif isinstance(data, list):
            hosts = data
        else:
            hosts = []

        for host in hosts:
            if not isinstance(host, dict):
                continue
            vulns = host.get('vulnerabilities', [])
            if not isinstance(vulns, list):
                continue
            for item in vulns:
                if not isinstance(item, dict):
                    continue
                msg = item.get('msg') or item.get('message') or ''
                uri = item.get('url') or item.get('uri') or ''
                method = item.get('method', '')
                parts = [p for p in (method, uri, msg) if p]
                evidence = ' | '.join(parts) if parts else str(item)

                # Directory-listing verifiability - mirrors the same
                # text-match analysis/cvss_scorer.py's _resolve_vector()
                # uses to reclassify this finding's severity later. Set here
                # (generation time) rather than in the scorer, consistent
                # with how owasp.py/enumeration.py flag their own verifiable
                # findings.
                verify_kwargs = {}
                if uri and _NIKTO_DIRECTORY_LISTING_RE.search(msg):
                    verify_kwargs = {
                        'confidence': 'probable',
                        'verifiable': True,
                        'verification_target': {'url': urljoin(target_url, uri)},
                    }

                findings.append(normalize_finding(
                    module=MODULE,
                    tool='nikto',
                    type_='nikto_finding',
                    title=(msg[:120] if msg else 'Nikto finding'),
                    evidence=evidence,
                    severity='Low',
                    target=domain,
                    **verify_kwargs,
                ))

    except subprocess.TimeoutExpired:
        logger.warning("Nikto timed out for scan %s", scan_id)
    except FileNotFoundError:
        logger.warning("Nikto not installed - skipping for scan %s", scan_id)
    except json.JSONDecodeError as e:
        logger.error("Nikto JSON parse error for scan %s: %s", scan_id, e)
    except Exception as e:
        logger.error("Nikto error for scan %s: %s", scan_id, e)
    finally:
        if os.path.exists(out_path):
            try:
                os.unlink(out_path)
            except OSError:
                pass

    return findings


# ---------------------------------------------------------------------------
# Main task
# ---------------------------------------------------------------------------

@app.task(
    base=BaseTask,
    name='tasks.webscan.run_webscan',
    soft_time_limit=_WEBSCAN_SOFT_LIMIT,
    time_limit=_WEBSCAN_HARD_LIMIT,
)
def run_webscan(scan_id: str, domain: str) -> dict:
    """
    Web scan module: OWASP ZAP (spider + active scan) + Katana (parallel,
    JS-aware supplemental crawl) + Nikto.

    ZAP, Katana and Nikto are all optional - if any is missing (never
    reachable at all) the module continues with whatever is available, and
    partial results are still reported as 'success' (that case is a startup-
    time absence, not a mid-scan failure). Runs with a raised per-task time
    limit because ZAP active scanning is the pipeline's long pole (see the
    timing-budget note above). Katana runs in a thread ALONGSIDE ZAP so it
    adds no wall-clock time; Nikto still runs sequentially after both finish.
    Returns a build_module_result() envelope (Section 4.3 schema note).

    A second, distinct case - ZAP going unreachable *after* scanning already
    started (a mid-scan daemon restart) - is reported as 'partial' with a
    descriptive error instead, the same pattern tech_fingerprint.py uses when
    exactly one of whatweb/wafw00f fails. See `_run_zap`'s docstring for why
    this distinction matters: silently reporting 'success' here previously
    made a lost ZAP scan indistinguishable from "ZAP genuinely found nothing".
    """
    update_module_status(scan_id, MODULE, 'running')
    start = time.monotonic()
    findings = []
    target_url = resolve_target_url(domain)

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            zap_future = executor.submit(_run_zap, scan_id, domain, target_url)
            katana_future = executor.submit(_run_katana, scan_id, domain, target_url)
            zap_findings, zap_version, zap_disconnected = zap_future.result()
            katana_findings = katana_future.result()

        findings.extend(zap_findings)
        findings.extend(katana_findings)
        hidden_finding = _js_hidden_endpoints_finding(domain, zap_findings, katana_findings)
        if hidden_finding:
            findings.append(hidden_finding)

        findings.extend(_run_nikto(scan_id, domain, target_url))

        tool_versions = {
            'zap':    zap_version or 'unknown',
            'katana': get_tool_version('katana', '-version'),
            'nikto':  get_tool_version('nikto', '-Version'),
        }
        update_module_status(scan_id, MODULE, 'complete')
        if zap_disconnected:
            return build_module_result(
                MODULE, findings, tool_versions, status='partial',
                error='ZAP became unreachable mid-scan (daemon restart or '
                      'connection loss) - some or all ZAP alerts for this '
                      'scan were not collected; Katana/Nikto findings above '
                      'are unaffected.',
                duration_seconds=time.monotonic() - start)
        return build_module_result(MODULE, findings, tool_versions, status='success',
                                    duration_seconds=time.monotonic() - start)
    except SoftTimeLimitExceeded:
        logger.warning("webscan hit its soft time limit (%ds) for scan %s",
                        _WEBSCAN_SOFT_LIMIT, scan_id)
        update_module_status(scan_id, MODULE, 'failed')
        return build_module_result(
            MODULE, findings, {}, status='timeout',
            error=f'Module exceeded its soft time limit ({_WEBSCAN_SOFT_LIMIT}s)',
            duration_seconds=time.monotonic() - start)
    except Exception as e:
        logger.exception("webscan unexpected error scan=%s: %s", scan_id, e)
        update_module_status(scan_id, MODULE, 'failed')
        return build_module_result(MODULE, findings, {}, status='failed',
                                    error=str(e), duration_seconds=time.monotonic() - start)
