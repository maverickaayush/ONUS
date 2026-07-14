import json
import logging
import os
import random
import re
import subprocess
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from typing import List, Optional, Tuple

import requests
import urllib3
from celery.exceptions import SoftTimeLimitExceeded

from tasks.base_task import (
    BaseTask, normalize_finding, update_module_status,
    get_tool_version, build_module_result, resolve_target_url, scaled_timeout,
)
from tasks.celery_app import app

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)
MODULE = 'enumeration'

# Timing budget: baseline calibration (<=10s, probes run concurrently) +
# FFUF (<=130s) + a handful of sequential admin-panel login-form checks
# (~10s each, typically 0-3 hits) - raised from 180/240 for headroom, same
# pattern as recon/webscan's documented per-module ceilings. Further scaled
# by SCAN_TIMEOUT_MULTIPLIER for real-world targets slower than the
# measured baseline (larger wordlists, WAF rate-limiting, network latency).
_FFUF_TIMEOUT = scaled_timeout(130)
_SOFT_LIMIT = scaled_timeout(220)
_HARD_LIMIT = scaled_timeout(280)
_WORDLIST = '/opt/wordlists/common.txt'
_BASELINE_TIMEOUT = scaled_timeout(10)

_SENSITIVE_FILES = (
    '.env', '.git/config', '.git/head', 'backup.sql', 'dump.sql', 'database.sql',
    'wp-config.php', 'config.php', 'settings.py', '.htpasswd', 'id_rsa', 'id_rsa.pub',
)
_ADMIN_PANELS = (
    '/admin', '/administrator', '/wp-admin', '/phpmyadmin', '/adminer',
    '/console', '/manager', '/dashboard', '/.git/', '/api/v1/admin',
)
_LOGIN_MARKERS = re.compile(
    r'type=["\']?password|<form[^>]*(login|signin)|name=["\']?(user(name)?|pass(word)?)',
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Baseline calibration - detect a WAF/server-level catch-all deny page before
# trusting FFUF's hit list. Without this, a single generic 403/soft-404 page
# gets logged as thousands of distinct "findings", one per wordlist entry.
# ---------------------------------------------------------------------------

def _baseline_probe_paths() -> List[str]:
    """3-5 path strings guaranteed not to exist, mixing formats so a
    format-specific soft-404 rule (e.g. only PHP paths redirect) still shows up."""
    return [
        f'/{uuid.uuid4().hex}',
        f'/nonexistent-{uuid.uuid4().hex[:8]}',
        f'/does-not-exist-{random.randint(100000, 999999)}',
        f'/{uuid.uuid4().hex[:10]}.php',
        f'/{uuid.uuid4().hex[:8]}/',
    ]


def _calibrate_baseline(target: str) -> Optional[dict]:
    """
    Probe guaranteed-nonexistent paths. If the responses cluster (same status,
    sizes within 5%), the server has a wildcard/catch-all page (WAF deny,
    soft-404, etc.) and every FFUF hit matching that signature is noise, not
    a finding. Returns None if the target returns clean, inconsistent 404s -
    no baseline filtering needed.
    """
    def _probe(path: str) -> Optional[Tuple[int, int]]:
        try:
            resp = requests.get(f'{target}{path}', timeout=_BASELINE_TIMEOUT,
                                 verify=False, allow_redirects=False)
            return (resp.status_code, len(resp.content))
        except requests.RequestException:
            return None

    # Run concurrently, not sequentially - 5 probes at 10s each would add up
    # to 50s of pure wait time on a slow/unresponsive target before FFUF
    # (up to 130s) even starts, risking the module's 180s soft time limit.
    paths = _baseline_probe_paths()
    with ThreadPoolExecutor(max_workers=len(paths)) as executor:
        samples = [s for s in executor.map(_probe, paths) if s is not None]

    if len(samples) < 2:
        return None  # not enough data to judge clustering

    statuses = {s[0] for s in samples}
    if len(statuses) > 1:
        return None  # inconsistent statuses - no single catch-all page

    sizes = [s[1] for s in samples]
    size_min, size_max = min(sizes), max(sizes)
    size_median = sorted(sizes)[len(sizes) // 2]
    # Cluster if within 5% of the median, or within 20 bytes for tiny bodies
    # where 5% is meaningless.
    spread_ok = (size_max - size_min) <= max(20, size_median * 0.05)
    if not spread_ok:
        return None

    return {
        'status': statuses.pop(),
        'size_range': (size_min, size_max),
        'size_median': size_median,
    }


def _within_baseline(status_code: int, size: int, baseline: Optional[dict]) -> bool:
    if not baseline:
        return False
    if status_code != baseline['status']:
        return False
    lo, hi = baseline['size_range']
    return (lo - 50) <= size <= (hi + 50)


# ---------------------------------------------------------------------------
# Admin-panel login-form check - one-off verification GET, only for the
# small number of confirmed admin-panel path matches (not the whole
# wordlist), to distinguish a login-gated panel from a fully open one.
# ---------------------------------------------------------------------------

def _is_admin_path(path: str) -> bool:
    p = f'/{path.lstrip("/")}'.lower()
    return any(p == a or p.startswith(a) for a in _ADMIN_PANELS)


def _check_login_form(target: str, path: str) -> bool:
    try:
        resp = requests.get(f'{target}/{path.lstrip("/")}', timeout=_BASELINE_TIMEOUT,
                             verify=False, allow_redirects=True)
        return bool(_LOGIN_MARKERS.search(resp.text[:5000]))
    except requests.RequestException:
        return False  # can't confirm a login gate - treat conservatively as open


# ---------------------------------------------------------------------------
# Classification - determines finding `type` only. severity/cvss returned
# here are placeholders (Section 4.3 schema note) - the CVSS scorer
# (analysis/cvss_scorer.py) is the deterministic source of truth downstream.
# ---------------------------------------------------------------------------

def _matched_sensitive_file(path: str) -> Optional[str]:
    """Return the _SENSITIVE_FILES entry `path` matches, or None. Shared by
    _classify() (severity) and _run_ffuf() (verification_target filename)."""
    p = f'/{path.lstrip("/")}'.lower()
    for s in _SENSITIVE_FILES:
        if p.endswith(f'/{s}') or p == f'/{s}':
            return s
    return None


def _classify(path: str, status_code: int,
              login_form_detected: Optional[bool] = None) -> Tuple[str, str, float]:
    """Return (type, severity, cvss) for one FFUF hit."""
    p = f'/{path.lstrip("/")}'.lower()
    is_sensitive = any(p.endswith(f'/{s}') or p == f'/{s}' for s in _SENSITIVE_FILES)
    is_admin = any(p == a or p.startswith(a) for a in _ADMIN_PANELS)

    if is_sensitive:
        if status_code == 200:
            return 'exposed_sensitive_file', 'Critical', 9.1
        # 401/403: access control is doing its job - informational only,
        # dropped at the source by default (see _run_ffuf).
        return 'exposed_sensitive_file_denied', 'Informational', 0.0

    if is_admin:
        if status_code == 200:
            if login_form_detected:
                return 'exposed_admin_panel_login', 'Medium', 5.3
            return 'exposed_admin_panel_open', 'High', 8.2
        return 'exposed_admin_panel_denied', 'Informational', 0.0

    if status_code in (401, 403):
        return f'exposed_path_{status_code}', 'Informational', 0.0
    if status_code == 200 and ('backup' in p or 'old' in p):
        # Not an admin panel - a discovered backup/legacy file. Distinct
        # type so it maps to Security Misconfiguration, not Broken Access
        # Control, in the OWASP category table.
        return 'exposed_backup_file', 'High', 7.3
    if status_code == 200:
        return 'exposed_path_200', 'Medium', 5.3
    if status_code in (301, 302):
        return f'exposed_path_{status_code}', 'Informational', 0.0
    return f'exposed_path_{status_code}', 'Informational', 0.0


def _run_ffuf(scan_id: str, target: str, domain: str) -> List[dict]:
    findings: List[dict] = []
    out_path = f'/tmp/ffuf_{scan_id}.json'

    if not os.path.exists(_WORDLIST):
        logger.warning("FFUF wordlist missing at %s - skipping enumeration for scan %s",
                        _WORDLIST, scan_id)
        return findings

    baseline = _calibrate_baseline(target)
    if baseline:
        logger.info(
            "enumeration scan=%s baseline detected: status=%s size_range=%s",
            scan_id, baseline['status'], baseline['size_range'],
        )

    try:
        result = subprocess.run(
            [
                'ffuf', '-u', f'{target}/FUZZ',
                '-w', _WORDLIST,
                '-mc', '200,201,301,302,401,403',
                '-ac', '-t', '20', '-timeout', '10',
                '-o', out_path, '-of', 'json',
                '-s', '-maxtime', '120',
            ],
            timeout=_FFUF_TIMEOUT,
            capture_output=True,
            check=False,
        )
        # Connection refused / unreachable host - ffuf exits non-zero with no output.
        if result.returncode != 0 and not os.path.exists(out_path):
            logger.info("FFUF found no reachable web server for scan %s", scan_id)
            return findings

        if not os.path.exists(out_path):
            return findings
        with open(out_path) as f:
            raw = f.read().strip()
        if not raw:
            return findings

        data = json.loads(raw)
        total_hits = 0
        baseline_filtered = 0

        for hit in data.get('results', []):
            if not isinstance(hit, dict):
                continue
            path = hit.get('input', {}).get('FUZZ', '') if isinstance(hit.get('input'), dict) else ''
            status_code = hit.get('status', 0)
            length = hit.get('length', 0)
            total_hits += 1

            # Real bug found live (Opus review): baseline filtering only
            # compares status+size, never body content - a genuine exposed
            # .env/.git/config that happens to land within the guaranteed-404
            # baseline's size cluster was silently dropped as noise before it
            # was ever classified as sensitive. A sensitive-file match is
            # always worth surfacing regardless of baseline collision - the
            # cost of an occasional false positive here is far lower than
            # silently losing a real credential-exposure Critical.
            if _within_baseline(status_code, length, baseline) and not _matched_sensitive_file(path):
                baseline_filtered += 1
                continue

            login_form_detected = None
            if status_code == 200 and _is_admin_path(path):
                login_form_detected = _check_login_form(target, path)

            type_, severity, cvss = _classify(path, status_code, login_form_detected)

            # 401/403 hits on sensitive-file paths are dropped by default -
            # access control working as intended is not a finding.
            # ponytail: no verbosity flag exists yet to opt back in; add one
            # if an operator ever needs the full denied-path list.
            if type_ == 'exposed_sensitive_file_denied':
                continue

            verify_kwargs = {}
            if type_ == 'exposed_sensitive_file':
                verify_kwargs = {
                    'confidence': 'probable',
                    'verifiable': True,
                    'verification_target': {
                        'url': f'{target}/{path.lstrip("/")}',
                        'filename': _matched_sensitive_file(path),
                    },
                }

            finding = normalize_finding(
                module=MODULE, tool='ffuf', type_=type_,
                title=f'Path {path} returned HTTP {status_code}',
                evidence=f'GET {target}/{path} -> {status_code} ({length} bytes)',
                severity=severity,
                cvss=cvss,
                target=domain,
                **verify_kwargs,
            )
            finding['http_status'] = status_code
            finding['http_size'] = length
            findings.append(finding)

        if baseline:
            logger.info(
                "enumeration scan=%s baseline filtered %d/%d findings",
                scan_id, baseline_filtered, total_hits,
            )

    except subprocess.TimeoutExpired:
        logger.warning("FFUF timed out for scan %s", scan_id)
    except FileNotFoundError:
        logger.warning("FFUF not installed - skipping for scan %s", scan_id)
    except json.JSONDecodeError as e:
        logger.error("FFUF JSON parse error for scan %s: %s", scan_id, e)
    except SoftTimeLimitExceeded:
        raise
    except Exception as e:
        logger.error("FFUF error for scan %s: %s", scan_id, e)
    finally:
        if os.path.exists(out_path):
            try:
                os.unlink(out_path)
            except OSError:
                pass

    return findings


def scan_enumeration(scan_id: str, domain: str, auth: dict = None) -> dict:
    """
    Pure half (runs locally or on Modal via tasks.dispatch): directory/file
    enumeration via FFUF - finds hidden paths ZAP's crawler misses. No DB/Redis;
    returns a build_module_result() envelope (Section 4.3). `auth` unused.
    """
    start = time.monotonic()
    findings = []
    target = resolve_target_url(domain)
    try:
        findings = _run_ffuf(scan_id, target, domain)
        tool_versions = {'ffuf': get_tool_version('ffuf', '-V')}
        return build_module_result(MODULE, findings, tool_versions, status='success',
                                    duration_seconds=time.monotonic() - start)
    except SoftTimeLimitExceeded:
        logger.warning("enumeration hit its soft time limit for scan %s", scan_id)
        return build_module_result(MODULE, findings, {}, status='timeout',
                                    error='Module exceeded its soft time limit',
                                    duration_seconds=time.monotonic() - start)
    except Exception as e:
        logger.exception("enumeration unexpected error scan=%s: %s", scan_id, e)
        return build_module_result(MODULE, findings, {}, status='failed',
                                    error=str(e), duration_seconds=time.monotonic() - start)


@app.task(
    base=BaseTask,
    name='tasks.enumeration.run_enumeration',
    soft_time_limit=_SOFT_LIMIT,
    time_limit=_HARD_LIMIT,
)
def run_enumeration(scan_id: str, domain: str) -> dict:
    """Dispatcher: owns the DB status writes (module namespace); tasks.dispatch
    picks where the pure half runs (local subprocess vs Modal)."""
    update_module_status(scan_id, MODULE, 'running')
    from tasks.dispatch import dispatch_scan
    envelope = dispatch_scan(MODULE, scan_id, domain)
    update_module_status(scan_id, MODULE,
                         'complete' if envelope.get('status') in ('success', 'partial') else 'failed')
    return envelope
