"""
Confidence verification stage - runs between aggregate() and score_finding()
(scan_orchestrator.py's _finalize()).

HARD CONSTRAINT: every verifier here does passive re-observation only - it
re-issues the exact same non-destructive, read-only payload the originating
scanning module already used (owasp.py/enumeration.py/webscan.py) and checks
whether the same evidence still reproduces. No verifier may escalate to a
new exploitation technique, write data, or use a payload the source module
didn't already send once during the scan. If you're adding a verifier and
it does anything beyond "GET (or headless-browser-navigate to) the same
thing again and compare the response", it does not belong in this file -
the project docs Section 8's non-destructive guardrail applies here exactly as it
does to the scanning modules. verify_reflected_xss (Phase 2) is the one
verifier that uses a browser instead of raw `requests` - it still only
re-issues owasp.py's own already-sent payload and observes whether the
same alert() call fires, nothing more.

On failure to reproduce (wrong response, timeout, connection error, or
missing verification_target data), a finding is demoted to
confidence='unverified' with a verification_note explaining why - it is
NEVER dropped from the findings list. Silently dropping a finding here would
reintroduce the exact silent-data-loss bug class the project docs Section 4.3 warns
about for the aggregator, just one stage later.
"""
import logging
import re
import time
from typing import List, Optional
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import requests
import urllib3
from playwright.sync_api import sync_playwright

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

_TIMEOUT = 15

# docs/ai.md - measured against the approved demo-target.example target: median 0.39s /
# p95 0.93s per verification request. 60s covers ~65 findings even at the p95
# rate, comfortably above realistic Phase-1-verifiable finding counts (these
# types are inherently rare after the aggregator's own dedup/collapse).
# Phase 2's verify_reflected_xss shares this same budget rather than getting
# its own - measured at ~0.65s/check (docs/ai.md) and dispatched at most
# once per scan (test_xss returns on its first match), it's negligible
# against the 60s ceiling.
_TIME_BUDGET_SECONDS = 60

# Playwright navigation timeout for the XSS re-check, plus a short buffer
# after load to catch a payload whose alert() fires asynchronously (the
# onerror=alert(...) payload fires on the image's error event, not
# synchronously during parse like the <script> payload does).
_XSS_NAV_TIMEOUT_MS = 15000
_XSS_POST_LOAD_WAIT_MS = 300

_TRAVERSAL_SENTINELS = ('root:x:0:', 'root:x:', 'root:!:', '/bin/bash', '/bin/sh')

# Mirrors analysis/cvss_scorer.py's _DIRECTORY_LISTING_RE (kept as a separate
# copy, not a shared import - tasks/analysis stay decoupled except through
# scan_orchestrator.py, and this one regex isn't worth crossing that boundary
# for).
_DIRECTORY_LISTING_RE = re.compile(r'directory index|autoindex|index of /', re.IGNORECASE)

# Keyed off enumeration.py's _SENSITIVE_FILES entries. Each signature checks
# the re-fetched body actually looks like the named file format, not just
# "some 200 response" - a custom 200 error page would otherwise false-positive
# a confirm.
_SENSITIVE_FILE_SIGNATURES = {
    '.env': lambda t: bool(t.strip()) and '<html' not in t.lower() and '=' in t.splitlines()[0],
    '.git/config': lambda t: '[core]' in t,
    '.git/head': lambda t: t.strip().lower().startswith('ref:') or re.match(r'^[0-9a-f]{40}$', t.strip()) is not None,
    'backup.sql': lambda t: 'insert into' in t.lower() or 'create table' in t.lower(),
    'dump.sql': lambda t: 'insert into' in t.lower() or 'create table' in t.lower(),
    'database.sql': lambda t: 'insert into' in t.lower() or 'create table' in t.lower(),
    'wp-config.php': lambda t: 'DB_' in t or '<?php' in t,
    'config.php': lambda t: '<?php' in t,
    'settings.py': lambda t: 'SECRET_KEY' in t or 'DEBUG' in t,
    '.htpasswd': lambda t: ':' in t and '<html' not in t.lower(),
    'id_rsa': lambda t: 'PRIVATE KEY' in t,
    'id_rsa.pub': lambda t: t.strip().startswith('ssh-'),
}

# Slack when comparing a re-issued time-based payload's delay against the
# expected value - real network jitter, not a false-positive tolerance.
_SQLI_TIME_TOLERANCE = 0.5


def _demote(finding: dict, note: str) -> dict:
    finding['confidence'] = 'unverified'
    finding['verification_note'] = note
    return finding


def _promote(finding: dict, note: str) -> dict:
    finding['confidence'] = 'confirmed'
    finding['verification_note'] = note
    return finding


def verify_open_redirect(finding: dict, session: Optional[requests.Session] = None) -> dict:
    """Source: owasp.py's test_open_redirect. `session`, when given, carries
    the same authenticated cookies/headers the original detection used
    (see verify_findings's docstring) - a plain `requests` client otherwise,
    unchanged from before auth support existed."""
    client = session or requests
    vt = finding.get('verification_target') or {}
    url, param, payload = vt.get('url'), vt.get('param'), vt.get('payload')
    if not (url and param and payload):
        return _demote(finding, 'Verification skipped - missing verification_target data.')
    try:
        resp = client.get(url, params={param: payload}, timeout=_TIMEOUT,
                           verify=False, allow_redirects=False)
        if resp.status_code in (301, 302, 303, 307, 308) and payload in resp.headers.get('Location', ''):
            return _promote(finding, f'Re-issued request confirmed a redirect to {payload!r} via the Location header.')
        return _demote(finding, 'Re-issued request did not reproduce the redirect - target may be patched, '
                                 'or the response has changed since the original scan.')
    except requests.RequestException as e:
        return _demote(finding, f'Verification request failed: {e}')


def verify_path_traversal(finding: dict, session: Optional[requests.Session] = None) -> dict:
    """Source: owasp.py's test_path_traversal."""
    client = session or requests
    vt = finding.get('verification_target') or {}
    url, param, payload = vt.get('url'), vt.get('param'), vt.get('payload')
    if not url:
        return _demote(finding, 'Verification skipped - missing verification_target data.')
    try:
        if param:
            resp = client.get(url, params={param: payload}, timeout=_TIMEOUT,
                               verify=False, allow_redirects=False)
        else:
            resp = client.get(url, timeout=_TIMEOUT, verify=False, allow_redirects=False)
        if any(s in resp.text for s in _TRAVERSAL_SENTINELS):
            return _promote(finding, 'Re-issued request reproduced known-safe sentinel content '
                                      '(e.g. /etc/passwd markers) in the response body.')
        return _demote(finding, 'Re-issued request did not reproduce the sentinel content - target may be '
                                 'patched, or the response has changed since the original scan.')
    except requests.RequestException as e:
        return _demote(finding, f'Verification request failed: {e}')


def verify_sensitive_file_exposure(finding: dict, session: Optional[requests.Session] = None) -> dict:
    """Source: enumeration.py's exposed_sensitive_file, keyed off its
    _SENSITIVE_FILES list."""
    client = session or requests
    vt = finding.get('verification_target') or {}
    url, filename = vt.get('url'), vt.get('filename')
    if not (url and filename):
        return _demote(finding, 'Verification skipped - missing verification_target data.')
    signature = _SENSITIVE_FILE_SIGNATURES.get(filename)
    if signature is None:
        return _demote(finding, f'No known content signature for {filename!r} - cannot verify automatically.')
    try:
        resp = client.get(url, timeout=_TIMEOUT, verify=False, allow_redirects=False)
        if resp.status_code == 200 and signature(resp.text):
            return _promote(finding, f'Re-fetched {filename} and confirmed its content matches the expected file format.')
        return _demote(finding, 'Re-fetch did not reproduce the expected file content - target may be patched, '
                                 'or access has since been restricted.')
    except requests.RequestException as e:
        return _demote(finding, f'Verification request failed: {e}')


def verify_directory_listing(finding: dict, session: Optional[requests.Session] = None) -> dict:
    """Source: webscan.py's Nikto integration - dispatched off the same
    directory-listing text-match webscan.py uses to set verifiable=True at
    generation time (not a dedicated headers.py autoindex check)."""
    client = session or requests
    vt = finding.get('verification_target') or {}
    url = vt.get('url')
    if not url:
        return _demote(finding, 'Verification skipped - missing verification_target data.')
    try:
        resp = client.get(url, timeout=_TIMEOUT, verify=False, allow_redirects=True)
        if resp.status_code == 200 and _DIRECTORY_LISTING_RE.search(resp.text):
            return _promote(finding, 'Re-fetched the URL and confirmed an autoindex-style listing is still present.')
        return _demote(finding, 'Re-fetch did not reproduce the autoindex listing - target may be patched '
                                 'or reconfigured since the original scan.')
    except requests.RequestException as e:
        return _demote(finding, f'Verification request failed: {e}')


def verify_sqli_time_based(finding: dict, session: Optional[requests.Session] = None) -> dict:
    """
    Dormant in Phase 1: no scanning module emits sqli_time_based findings
    yet (cvss_scorer.py's _RULES entry is a forward-compat placeholder).
    Implemented so the dispatch table is complete the day a module starts
    emitting this type - unreachable on real scans today.
    """
    client = session or requests
    vt = finding.get('verification_target') or {}
    url, param, payload = vt.get('url'), vt.get('param'), vt.get('payload')
    expected_delay = vt.get('expected_delay_seconds')
    if not (url and param and payload and expected_delay):
        return _demote(finding, 'Verification skipped - missing verification_target data.')
    try:
        baseline_start = time.monotonic()
        client.get(url, timeout=_TIMEOUT, verify=False, allow_redirects=False)
        baseline_elapsed = time.monotonic() - baseline_start

        probe_start = time.monotonic()
        client.get(url, params={param: payload}, timeout=_TIMEOUT + expected_delay,
                    verify=False, allow_redirects=False)
        probe_elapsed = time.monotonic() - probe_start

        if probe_elapsed >= (baseline_elapsed + expected_delay - _SQLI_TIME_TOLERANCE):
            return _promote(finding, f'Re-issued payload delayed the response by {probe_elapsed:.1f}s '
                                      f'vs a {baseline_elapsed:.1f}s baseline, consistent with time-based injection.')
        return _demote(finding, 'Re-issued payload did not reproduce the expected response delay.')
    except requests.RequestException as e:
        return _demote(finding, f'Verification request failed: {e}')


def _merge_url_params(url: str, params: dict) -> str:
    """Merge params into url's own query string correctly whether or not it
    already has one. Real bug found live: owasp.py's test_xss passes an
    already-crawled URL (which usually already carries its own query string,
    e.g. Mutillidae's `index.php?page=home.php&popUpNotificationCode=HPH0`)
    as verification_target['url'] - naively formatting f'{url}?{params}'
    (the old code) produces a malformed URL with two `?` characters and a
    duplicated parameter, confirmed directly from a real stored
    verification_note. This merges into the existing query instead."""
    parts = urlsplit(url)
    merged = parse_qsl(parts.query, keep_blank_values=True) + list(params.items())
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(merged), parts.fragment))


def _playwright_cookies_from_session(session: requests.Session) -> list:
    return [{'name': c.name, 'value': c.value, 'domain': c.domain or '', 'path': c.path or '/'}
            for c in session.cookies]


def _xss_payload_fires(url: str, params: dict, marker: str,
                        session: Optional[requests.Session] = None) -> bool:
    """Launch a fresh headless Chromium instance, navigate to the exact
    same request owasp.py's test_xss already sent, and check whether the
    payload's own alert(marker) call actually executes as script - a
    materially stronger signal than substring-matching the response text,
    since a CSP or output-encoding change can leave the string reflected
    but non-executing. Fresh browser per call (not a shared/pooled
    instance): at most one reflected_xss finding per scan (test_xss
    returns on its first match), so pooling buys nothing and avoids any
    cross-task state leakage under Celery's prefork workers.

    `session`, when given, carries the same authenticated cookies/headers
    (including a JSON-auth bearer token) the original detection used - real
    bug found live: without this, an authenticated finding's replay always
    hits an unauthenticated response (e.g. a login redirect) and can never
    confirm, regardless of whether the finding is real."""
    fired = {'v': False}

    def _on_dialog(dialog):
        fired['v'] = marker in (dialog.message or '')
        dialog.dismiss()

    full_url = _merge_url_params(url, params)

    with sync_playwright() as p:
        browser = p.chromium.launch(args=['--no-sandbox', '--disable-gpu'])
        try:
            if session is not None:
                context = browser.new_context(extra_http_headers=dict(session.headers))
                context.add_cookies(_playwright_cookies_from_session(session))
                page = context.new_page()
            else:
                page = browser.new_page()
            page.on('dialog', _on_dialog)
            page.goto(full_url, timeout=_XSS_NAV_TIMEOUT_MS)
            page.wait_for_timeout(_XSS_POST_LOAD_WAIT_MS)
        finally:
            browser.close()

    return fired['v']


def verify_reflected_xss(finding: dict, session: Optional[requests.Session] = None) -> dict:
    """
    Phase 2. Source: owasp.py's test_xss. The only Phase 1/2 verifier that
    uses a browser instead of raw `requests` - see this module's top
    docstring for why that's still within the passive-re-observation
    constraint (same payload, same request, just observed via Chromium).
    """
    vt = finding.get('verification_target') or {}
    url, params, marker = vt.get('url'), vt.get('params'), vt.get('marker')
    if not (url and params and marker):
        return _demote(finding, 'Verification skipped - missing verification_target data.')
    try:
        if _xss_payload_fires(url, params, marker, session=session):
            return _promote(finding, 'Headless-browser re-check confirmed the injected payload '
                                      'executed as script (alert dialog fired).')
        return _demote(finding, 'Headless-browser re-check did not observe the payload executing - '
                                 'target may be patched, a Content-Security-Policy may block it, or '
                                 'the reflection does not actually execute as script.')
    except Exception as e:
        return _demote(finding, f'Headless-browser verification failed: {e}')


# Keyed by finding `type` - verification runs before cvss_scorer.py, so a
# Nikto directory-listing hit still has type='nikto_finding' at this stage
# (the 'directory_listing_enabled' type only exists as the scorer's own
# post-hoc reclassification, see cvss_scorer.py's _resolve_vector).
_VERIFIERS = {
    'open_redirect': verify_open_redirect,
    'path_traversal': verify_path_traversal,
    'exposed_sensitive_file': verify_sensitive_file_exposure,
    'nikto_finding': verify_directory_listing,
    'sqli_time_based': verify_sqli_time_based,
    'reflected_xss': verify_reflected_xss,
}


def verify_findings(findings: List[dict], enabled: bool = True,
                     session: Optional[requests.Session] = None) -> List[dict]:
    """
    Re-observe every verifiable finding via passive HTTP re-issue. Mutates
    and returns the same list - confirmed findings get confidence='confirmed'
    plus a verification_note; findings that fail to reproduce are demoted to
    confidence='unverified' with a verification_note. Never removes a finding.

    No-ops entirely when enabled=False (config.ENABLE_VERIFICATION).

    `session`, when the scan was authenticated, is the same requests.Session
    owasp.py's _make_session() built (cookies from a form login, or a
    bearer-token header from a JSON login) - passed through to every
    verifier so an authenticated finding's replay carries the same session
    the original detection used, instead of always replaying unauthenticated
    (real bug found live: every open_redirect/path_traversal/reflected_xss
    finding on an authenticated scan was structurally unable to ever reach
    confidence='confirmed' before this, since the replay had no session and
    almost always hit a login redirect instead of reproducing the finding).
    None for an unauthenticated scan - unchanged behavior from before.
    """
    if not enabled:
        return findings

    start = time.monotonic()
    budget_exceeded = False

    for f in findings:
        if not isinstance(f, dict) or not f.get('verifiable'):
            continue

        if not budget_exceeded and (time.monotonic() - start) > _TIME_BUDGET_SECONDS:
            budget_exceeded = True
            logger.warning("verify_findings: time budget (%ss) exceeded - remaining "
                            "verifiable findings will be demoted unverified", _TIME_BUDGET_SECONDS)
        if budget_exceeded:
            _demote(f, 'Verification skipped - scan-wide verification time budget exceeded.')
            continue

        verifier = _VERIFIERS.get(f.get('type'))
        if verifier is None:
            continue
        try:
            verifier(f, session=session)
        except Exception as e:
            logger.exception("verifier for type=%s raised unexpectedly", f.get('type'))
            _demote(f, f'Verification failed with an internal error: {e}')

    return findings
