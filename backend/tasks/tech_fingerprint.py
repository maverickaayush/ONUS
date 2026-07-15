import json
import logging
import os
import re
import subprocess
import time
from typing import List, Optional, Tuple

from celery.exceptions import SoftTimeLimitExceeded

from tasks.base_task import (
    BaseTask, normalize_finding, update_module_status,
    get_tool_version, build_module_result, resolve_target_url, scaled_timeout,
)
from tasks.celery_app import app

logger = logging.getLogger(__name__)
MODULE = 'tech_fingerprint'

_WHATWEB_TIMEOUT = scaled_timeout(60)
_WAFW00F_TIMEOUT = scaled_timeout(30)
_SOFT_LIMIT = scaled_timeout(120)
_HARD_LIMIT = scaled_timeout(150)

# EOL thresholds: plugin name substring (lowercase) -> minimum non-EOL (major, minor)
_EOL_THRESHOLDS = {
    'php':       (7, 4),
    'apache':    (2, 4),
    'nginx':     (1, 18),
    'jquery':    (3, 0),
    'wordpress': (6, 0),
    'drupal':    (10, 0),
    'python':    (3, 8),
}

_VERSION_RE = re.compile(r'(\d+)\.(\d+)')


def _parse_version(version_str: str) -> Optional[Tuple[int, int]]:
    m = _VERSION_RE.search(version_str or '')
    if not m:
        return None
    return int(m.group(1)), int(m.group(2))


def _eol_threshold(plugin_name: str) -> Optional[Tuple[int, int]]:
    """
    Exact match (case-insensitive) against a technology's own name, not a
    substring check - WhatWeb reports each technology under its own distinct
    identifier (e.g. 'PHP', 'JQuery', 'WordPress'), so a plugin's exact name
    is the right signal, not whether one of our keys happens to appear
    inside it. Real false positive found live: the old `key in name`
    substring check matched 'phpMyAdmin' against 'php', 'jQuery-UI' against
    'jquery', and any WordPress plugin (e.g. 'WordPress Super Cache')
    against 'wordpress' - each then got scored against the WRONG product's
    EOL threshold and flagged outdated even when fully current.

    recon.py's httpx-based caller passes a combined 'name:version' string
    (e.g. 'nginx:1.14.0') rather than WhatWeb's clean standalone name -
    split off everything from the first ':' onward before matching, so both
    callers compare against just the technology name either way.
    """
    name = plugin_name.split(':', 1)[0].strip().lower()
    return _EOL_THRESHOLDS.get(name)


# ---------------------------------------------------------------------------
# WhatWeb
# ---------------------------------------------------------------------------

def _run_whatweb(scan_id: str, target: str, domain: str) -> List[dict]:
    """Passive (aggression 1) technology fingerprinting via WhatWeb."""
    findings: List[dict] = []
    out_path = f'/tmp/whatweb_{scan_id}.json'
    try:
        subprocess.run(
            ['whatweb', target, f'--log-json={out_path}',
             '--no-errors', '--quiet', '--aggression', '1'],
            timeout=_WHATWEB_TIMEOUT,
            capture_output=True,
            check=False,
        )

        if not os.path.exists(out_path):
            return findings
        with open(out_path) as f:
            raw = f.read().strip()
        if not raw:
            return findings

        # WhatWeb --log-json emits one JSON object per line (NDJSON).
        results = []
        try:
            parsed = json.loads(raw)
            results = parsed if isinstance(parsed, list) else [parsed]
        except json.JSONDecodeError:
            for line in raw.splitlines():
                line = line.strip().rstrip(',')
                if not line:
                    continue
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

        for result in results:
            if not isinstance(result, dict):
                continue
            plugins = result.get('plugins', {})
            if not isinstance(plugins, dict):
                continue
            for plugin_name, details in plugins.items():
                versions = details.get('version') if isinstance(details, dict) else None
                version = versions[0] if isinstance(versions, list) and versions else None

                threshold = _eol_threshold(plugin_name)
                parsed_version = _parse_version(version) if version else None
                is_eol = bool(threshold and parsed_version and parsed_version < threshold)

                label = f'{plugin_name} detected' + (f' ({version})' if version else '')
                finding = normalize_finding(
                    module=MODULE, tool='whatweb',
                    type_='outdated_tech' if is_eol else 'tech_detected',
                    title=f'Outdated {label} - end of life' if is_eol else label,
                    evidence=json.dumps(details)[:500] if isinstance(details, dict) else str(details),
                    severity='Medium' if is_eol else 'Informational',
                    target=domain,
                )
                finding['technology'] = plugin_name
                finding['version'] = version
                findings.append(finding)

    except subprocess.TimeoutExpired:
        logger.warning("WhatWeb timed out for scan %s", scan_id)
    except FileNotFoundError:
        logger.warning("WhatWeb not installed - skipping for scan %s", scan_id)
    except SoftTimeLimitExceeded:
        raise
    except Exception as e:
        logger.error("WhatWeb error for scan %s: %s", scan_id, e)
    finally:
        if os.path.exists(out_path):
            try:
                os.unlink(out_path)
            except OSError:
                pass

    return findings


# ---------------------------------------------------------------------------
# WAFW00F
# ---------------------------------------------------------------------------

def _run_wafw00f(scan_id: str, target: str, domain: str) -> List[dict]:
    """WAF detection via WAFW00F."""
    out_path = f'/tmp/wafw_{scan_id}.txt'
    try:
        subprocess.run(
            ['wafw00f', target, '-o', out_path, '-f', 'json'],
            timeout=_WAFW00F_TIMEOUT,
            capture_output=True,
            check=False,
        )

        if not os.path.exists(out_path):
            return [normalize_finding(
                module=MODULE, tool='wafw00f', type_='waf_unknown',
                title='WAF detection inconclusive',
                evidence='wafw00f produced no output', severity='Informational',
                target=domain,
            )]
        with open(out_path) as f:
            raw = f.read().strip()
        if not raw:
            return [normalize_finding(
                module=MODULE, tool='wafw00f', type_='waf_unknown',
                title='WAF detection inconclusive',
                evidence='wafw00f produced empty output', severity='Informational',
                target=domain,
            )]

        data = json.loads(raw)
        entries = data if isinstance(data, list) else [data]
        detected = [e for e in entries if isinstance(e, dict) and e.get('detected')]

        if detected:
            waf_name = detected[0].get('firewall', 'Unknown WAF')
            finding = normalize_finding(
                module=MODULE, tool='wafw00f', type_='waf_detected',
                title=f'WAF detected: {waf_name}',
                evidence=f'Target is protected by {waf_name}. Active scan results '
                         f'from webscan and owasp modules may be incomplete due to '
                         f'WAF filtering.',
                severity='Medium', target=domain,
            )
            finding['waf_name'] = waf_name
            return [finding]

        return [normalize_finding(
            module=MODULE, tool='wafw00f', type_='no_waf_detected',
            title='No WAF detected',
            evidence='wafw00f found no web application firewall in front of the target',
            severity='Informational', target=domain,
        )]

    except subprocess.TimeoutExpired:
        logger.warning("WAFW00F timed out for scan %s", scan_id)
    except FileNotFoundError:
        logger.warning("WAFW00F not installed - skipping for scan %s", scan_id)
    except SoftTimeLimitExceeded:
        raise
    except (json.JSONDecodeError, Exception) as e:
        # A bare Exception already sat in this tuple (making json.JSONDecodeError
        # redundant, since Exception covers it) and would have silently
        # swallowed SoftTimeLimitExceeded too - guarded above, same real bug
        # class found live in headers.py/enumeration.py/nuclei_scan.py this pass.
        logger.warning("WAFW00F output unparseable for scan %s: %s", scan_id, e)
        return [normalize_finding(
            module=MODULE, tool='wafw00f', type_='waf_unknown',
            title='WAF detection inconclusive',
            evidence=f'wafw00f output could not be parsed: {e}',
            severity='Informational', target=domain,
        )]
    finally:
        if os.path.exists(out_path):
            try:
                os.unlink(out_path)
            except OSError:
                pass

    return []


# ---------------------------------------------------------------------------
# Celery task
# ---------------------------------------------------------------------------

def scan_tech_fingerprint(scan_id: str, domain: str, auth: dict = None, quick: bool = False) -> dict:
    """
    Pure half (runs locally or on Modal via tasks.dispatch): technology
    fingerprinting - WhatWeb (passive) + WAFW00F. Partial results ok (the one
    module where 'partial' is legitimate - whatweb_ok/wafw00f_ok already
    distinguish "one of two sub-tools failed" from a clean run). No DB/Redis;
    returns a build_module_result() envelope (Section 4.3). `auth` unused.
    """
    start = time.monotonic()
    target = resolve_target_url(domain)
    findings: List[dict] = []
    whatweb_ok = wafw00f_ok = False
    whatweb_error = wafw00f_error = None

    try:
        try:
            findings.extend(_run_whatweb(scan_id, target, domain))
            whatweb_ok = True
        except SoftTimeLimitExceeded:
            # Real bug found live: even after _run_whatweb's own internal
            # except re-raises this (fixed above), this outer wrapper's
            # partial-success bookkeeping would have caught it again with a
            # plain `except Exception`, treating a graceful timeout as
            # "whatweb failed, keep going to wafw00f" instead of letting it
            # reach this task's own SoftTimeLimitExceeded handler below.
            raise
        except Exception as e:
            whatweb_error = str(e)
            logger.error("tech_fingerprint whatweb failed for scan %s: %s", scan_id, e)

        # Quick Assessment (passive-only): WhatWeb sends ordinary requests, but
        # WAFW00F sends attack-like probes to trip a WAF — excluded from quick.
        if not quick:
            try:
                findings.extend(_run_wafw00f(scan_id, target, domain))
                wafw00f_ok = True
            except SoftTimeLimitExceeded:
                raise
            except Exception as e:
                wafw00f_error = str(e)
                logger.error("tech_fingerprint wafw00f failed for scan %s: %s", scan_id, e)

        tool_versions = {'whatweb': get_tool_version('whatweb', '--version')}
        if not quick:
            tool_versions['wafw00f'] = get_tool_version('wafw00f', '--version')

        if quick:
            # WhatWeb-only: success iff WhatWeb ran; WAFW00F is intentionally absent.
            status = 'success' if whatweb_ok else 'failed'
            error = None if whatweb_ok else f'whatweb: {whatweb_error}'
        elif whatweb_ok and wafw00f_ok:
            status, error = 'success', None
        elif whatweb_ok or wafw00f_ok:
            status = 'partial'
            error = f'whatweb: {whatweb_error or "ok"} | wafw00f: {wafw00f_error or "ok"}'
        else:
            status = 'failed'
            error = f'whatweb: {whatweb_error} | wafw00f: {wafw00f_error}'

        return build_module_result(MODULE, findings, tool_versions, status=status,
                                    error=error, duration_seconds=time.monotonic() - start)
    except SoftTimeLimitExceeded:
        logger.warning("tech_fingerprint hit its soft time limit for scan %s", scan_id)
        return build_module_result(MODULE, findings, {}, status='timeout',
                                    error='Module exceeded its soft time limit',
                                    duration_seconds=time.monotonic() - start)
    except Exception as e:
        logger.exception("tech_fingerprint unexpected error scan=%s: %s", scan_id, e)
        return build_module_result(MODULE, findings, {}, status='failed',
                                    error=str(e), duration_seconds=time.monotonic() - start)


@app.task(
    base=BaseTask,
    name='tasks.tech_fingerprint.run_tech_fingerprint',
    soft_time_limit=_SOFT_LIMIT,
    time_limit=_HARD_LIMIT,
)
def run_tech_fingerprint(scan_id: str, domain: str, quick: bool = False) -> dict:
    """Dispatcher: owns the DB status writes (module namespace); tasks.dispatch
    picks where the pure half runs (local subprocess vs Modal). quick=True runs
    WhatWeb only (Quick Assessment profile)."""
    update_module_status(scan_id, MODULE, 'running')
    from tasks.dispatch import dispatch_scan
    envelope = dispatch_scan(MODULE, scan_id, domain, quick)
    update_module_status(scan_id, MODULE,
                         'complete' if envelope.get('status') in ('success', 'partial') else 'failed')
    return envelope
