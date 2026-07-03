"""
Confidence verification stage - runs between aggregate() and score_finding()
(scan_orchestrator.py's _finalize()).

HARD CONSTRAINT: every verifier here does passive re-observation only - it
re-issues the exact same non-destructive, read-only payload the originating
scanning module already used (owasp.py/enumeration.py/webscan.py) and checks
whether the same evidence still reproduces. No verifier may escalate to a
new exploitation technique, write data, or use a payload the source module
didn't already send once during the scan. If you're adding a verifier and
it does anything beyond "GET the same thing again and compare the response",
it does not belong in this file - the project docs Section 8's non-destructive
guardrail applies here exactly as it does to the scanning modules.

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
from typing import List

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

_TIMEOUT = 15

# docs/ai.md - measured against the approved demo-target.example target: median 0.39s /
# p95 0.93s per verification request. 60s covers ~65 findings even at the p95
# rate, comfortably above realistic Phase-1-verifiable finding counts (these
# types are inherently rare after the aggregator's own dedup/collapse).
_TIME_BUDGET_SECONDS = 60

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


def verify_open_redirect(finding: dict) -> dict:
    """Source: owasp.py's test_open_redirect."""
    vt = finding.get('verification_target') or {}
    url, param, payload = vt.get('url'), vt.get('param'), vt.get('payload')
    if not (url and param and payload):
        return _demote(finding, 'Verification skipped - missing verification_target data.')
    try:
        resp = requests.get(url, params={param: payload}, timeout=_TIMEOUT,
                             verify=False, allow_redirects=False)
        if resp.status_code in (301, 302, 303, 307, 308) and payload in resp.headers.get('Location', ''):
            return _promote(finding, f'Re-issued request confirmed a redirect to {payload!r} via the Location header.')
        return _demote(finding, 'Re-issued request did not reproduce the redirect - target may be patched, '
                                 'or the response has changed since the original scan.')
    except requests.RequestException as e:
        return _demote(finding, f'Verification request failed: {e}')


def verify_path_traversal(finding: dict) -> dict:
    """Source: owasp.py's test_path_traversal."""
    vt = finding.get('verification_target') or {}
    url, param, payload = vt.get('url'), vt.get('param'), vt.get('payload')
    if not url:
        return _demote(finding, 'Verification skipped - missing verification_target data.')
    try:
        if param:
            resp = requests.get(url, params={param: payload}, timeout=_TIMEOUT,
                                 verify=False, allow_redirects=False)
        else:
            resp = requests.get(url, timeout=_TIMEOUT, verify=False, allow_redirects=False)
        if any(s in resp.text for s in _TRAVERSAL_SENTINELS):
            return _promote(finding, 'Re-issued request reproduced known-safe sentinel content '
                                      '(e.g. /etc/passwd markers) in the response body.')
        return _demote(finding, 'Re-issued request did not reproduce the sentinel content - target may be '
                                 'patched, or the response has changed since the original scan.')
    except requests.RequestException as e:
        return _demote(finding, f'Verification request failed: {e}')


def verify_sensitive_file_exposure(finding: dict) -> dict:
    """Source: enumeration.py's exposed_sensitive_file, keyed off its
    _SENSITIVE_FILES list."""
    vt = finding.get('verification_target') or {}
    url, filename = vt.get('url'), vt.get('filename')
    if not (url and filename):
        return _demote(finding, 'Verification skipped - missing verification_target data.')
    signature = _SENSITIVE_FILE_SIGNATURES.get(filename)
    if signature is None:
        return _demote(finding, f'No known content signature for {filename!r} - cannot verify automatically.')
    try:
        resp = requests.get(url, timeout=_TIMEOUT, verify=False, allow_redirects=False)
        if resp.status_code == 200 and signature(resp.text):
            return _promote(finding, f'Re-fetched {filename} and confirmed its content matches the expected file format.')
        return _demote(finding, 'Re-fetch did not reproduce the expected file content - target may be patched, '
                                 'or access has since been restricted.')
    except requests.RequestException as e:
        return _demote(finding, f'Verification request failed: {e}')


def verify_directory_listing(finding: dict) -> dict:
    """Source: webscan.py's Nikto integration - dispatched off the same
    directory-listing text-match webscan.py uses to set verifiable=True at
    generation time (not a dedicated headers.py autoindex check)."""
    vt = finding.get('verification_target') or {}
    url = vt.get('url')
    if not url:
        return _demote(finding, 'Verification skipped - missing verification_target data.')
    try:
        resp = requests.get(url, timeout=_TIMEOUT, verify=False, allow_redirects=True)
        if resp.status_code == 200 and _DIRECTORY_LISTING_RE.search(resp.text):
            return _promote(finding, 'Re-fetched the URL and confirmed an autoindex-style listing is still present.')
        return _demote(finding, 'Re-fetch did not reproduce the autoindex listing - target may be patched '
                                 'or reconfigured since the original scan.')
    except requests.RequestException as e:
        return _demote(finding, f'Verification request failed: {e}')


def verify_sqli_time_based(finding: dict) -> dict:
    """
    Dormant in Phase 1: no scanning module emits sqli_time_based findings
    yet (cvss_scorer.py's _RULES entry is a forward-compat placeholder).
    Implemented so the dispatch table is complete the day a module starts
    emitting this type - unreachable on real scans today.
    """
    vt = finding.get('verification_target') or {}
    url, param, payload = vt.get('url'), vt.get('param'), vt.get('payload')
    expected_delay = vt.get('expected_delay_seconds')
    if not (url and param and payload and expected_delay):
        return _demote(finding, 'Verification skipped - missing verification_target data.')
    try:
        baseline_start = time.monotonic()
        requests.get(url, timeout=_TIMEOUT, verify=False, allow_redirects=False)
        baseline_elapsed = time.monotonic() - baseline_start

        probe_start = time.monotonic()
        requests.get(url, params={param: payload}, timeout=_TIMEOUT + expected_delay,
                     verify=False, allow_redirects=False)
        probe_elapsed = time.monotonic() - probe_start

        if probe_elapsed >= (baseline_elapsed + expected_delay - _SQLI_TIME_TOLERANCE):
            return _promote(finding, f'Re-issued payload delayed the response by {probe_elapsed:.1f}s '
                                      f'vs a {baseline_elapsed:.1f}s baseline, consistent with time-based injection.')
        return _demote(finding, 'Re-issued payload did not reproduce the expected response delay.')
    except requests.RequestException as e:
        return _demote(finding, f'Verification request failed: {e}')


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
}


def verify_findings(findings: List[dict], enabled: bool = True) -> List[dict]:
    """
    Re-observe every verifiable finding via passive HTTP re-issue. Mutates
    and returns the same list - confirmed findings get confidence='confirmed'
    plus a verification_note; findings that fail to reproduce are demoted to
    confidence='unverified' with a verification_note. Never removes a finding.

    No-ops entirely when enabled=False (config.ENABLE_VERIFICATION).
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
            verifier(f)
        except Exception as e:
            logger.exception("verifier for type=%s raised unexpectedly", f.get('type'))
            _demote(f, f'Verification failed with an internal error: {e}')

    return findings
