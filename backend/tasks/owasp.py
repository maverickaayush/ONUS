import logging
import re
import time
import urllib.parse
import urllib3
from typing import List

import requests
from celery.exceptions import SoftTimeLimitExceeded

from tasks.base_task import (
    BaseTask, normalize_finding, update_module_status, build_module_result, resolve_target_url,
)
from tasks.celery_app import app

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)
MODULE = 'owasp'

_TIMEOUT = 30
_SESSION_KWARGS = dict(timeout=_TIMEOUT, verify=False, allow_redirects=False)

# SQL error patterns that indicate injection vulnerability
_SQL_ERRORS = [
    r"sql syntax", r"mysql_fetch", r"ORA-\d{5}", r"pg_query\(\)",
    r"sqlite3?\.OperationalError", r"SQLSTATE", r"syntax error.*SQL",
    r"Unclosed quotation mark", r"Microsoft OLE DB",
    r"supplied argument is not a valid MySQL",
    r"You have an error in your SQL syntax",
]
_SQL_ERROR_RE = re.compile('|'.join(_SQL_ERRORS), re.IGNORECASE)

# Patterns that suggest stack trace / error disclosure
_TRACE_PATTERNS = [
    r"Traceback \(most recent call last\)",
    r"at .+\(.+\.java:\d+\)",
    r"System\.Exception",
    r"stack overflow",
    r"Fatal error.*on line",
    r"Warning:.*in.*on line",
    r"Parse error:.*in.*on line",
    r"SQLSTATE\[",
    r"ORA-\d{5}",
    r"Microsoft.*\.NET Framework",
]
_TRACE_RE = re.compile('|'.join(_TRACE_PATTERNS), re.IGNORECASE)


def _get_params(target: str) -> dict:
    """Extract existing GET params from the URL, or return a safe default."""
    parsed = urllib.parse.urlparse(target)
    params = dict(urllib.parse.parse_qsl(parsed.query))
    if not params:
        params = {'id': '1', 'q': 'test', 'search': 'test'}
    return params


def test_sqli(target: str, domain: str) -> List[dict]:
    """
    Inject SQL payloads into GET parameters.
    Non-destructive: read-only payloads only (boolean-based, no DROP/UPDATE).
    """
    findings = []
    payloads = ["' OR '1'='1", "'", "' OR 1=1--", "1 AND 1=1", "1 AND 1=2"]
    base_params = _get_params(target)

    try:
        # Baseline response for boolean comparison
        baseline = requests.get(target, params=base_params, **_SESSION_KWARGS)
        baseline_len = len(baseline.text)

        for param in list(base_params.keys())[:3]:  # limit to first 3 params
            for payload in payloads[:2]:  # 2 payloads per param
                injected = dict(base_params)
                injected[param] = payload
                try:
                    resp = requests.get(target, params=injected, **_SESSION_KWARGS)
                    body = resp.text

                    if _SQL_ERROR_RE.search(body):
                        findings.append(normalize_finding(
                            module=MODULE, tool='owasp', type_='sqli_error_based',
                            title='Potential SQL Injection (error-based)',
                            evidence=f'Parameter "{param}" with payload {payload!r} '
                                     f'triggered SQL error in response',
                            severity='High', target=domain,
                            # A DBMS error string in the response IS the proof -
                            # no verifier dispatch needed, unlike boolean-based.
                            confidence='confirmed',
                        ))
                        return findings  # one confirmed finding is enough

                    # Boolean-based: significantly different response length
                    if abs(len(body) - baseline_len) > 500 and resp.status_code == 200:
                        findings.append(normalize_finding(
                            module=MODULE, tool='owasp', type_='sqli_boolean_based',
                            title='Potential SQL Injection (boolean-based response diff)',
                            evidence=f'Parameter "{param}" with payload {payload!r} '
                                     f'produced {abs(len(body) - baseline_len)}-byte diff',
                            severity='Medium', target=domain,
                        ))
                        return findings
                except requests.RequestException:
                    pass
    except Exception as e:
        logger.debug("sqli test error for %s: %s", domain, e)
    return findings


def test_xss(target: str, domain: str) -> List[dict]:
    """
    Inject XSS payloads into GET parameters and check if reflected unsanitized.
    Non-destructive: read-only GET requests.
    """
    findings = []
    marker = 'VAPT_XSS_8675309'
    payloads = [
        f'<script>alert("{marker}")</script>',
        f'"><img src=x onerror=alert("{marker}")>',
        f"'{marker}",
    ]
    base_params = _get_params(target)

    try:
        for param in list(base_params.keys())[:3]:
            for payload in payloads[:2]:
                injected = dict(base_params)
                injected[param] = payload
                try:
                    resp = requests.get(target, params=injected, **_SESSION_KWARGS)
                    if marker in resp.text and payload in resp.text:
                        findings.append(normalize_finding(
                            module=MODULE, tool='owasp', type_='reflected_xss',
                            title='Reflected XSS - payload reflected unsanitized',
                            evidence=f'Parameter "{param}" reflects '
                                     f'payload {payload[:60]!r} verbatim',
                            severity='High', target=domain,
                            # Phase 2: both payloads tried here (payloads[:2])
                            # call alert(marker) - verify_reflected_xss
                            # (analysis/verifier.py) re-issues this exact
                            # request in headless Chromium and checks whether
                            # the alert dialog actually fires, not just
                            # whether the string is present in the response.
                            confidence='probable', verifiable=True,
                            verification_target={'url': target, 'params': injected,
                                                  'payload': payload, 'marker': marker},
                        ))
                        return findings
                except requests.RequestException:
                    pass
    except Exception as e:
        logger.debug("xss test error for %s: %s", domain, e)
    return findings


def test_path_traversal(target: str, domain: str) -> List[dict]:
    """
    Inject path traversal sequences into URL path and params.
    Non-destructive: read-only GET requests.
    """
    findings = []
    traversals = [
        '/../../../etc/passwd',
        '/../../../../etc/passwd',
        '/%2e%2e/%2e%2e/%2e%2e/etc/passwd',
    ]
    indicators = ['root:x:', 'root:!:', '/bin/bash', '/bin/sh']

    try:
        parsed = urllib.parse.urlparse(target)
        for trav in traversals:
            probe_url = f'{parsed.scheme}://{parsed.netloc}{trav}'
            try:
                resp = requests.get(probe_url, **_SESSION_KWARGS)
                if any(ind in resp.text for ind in indicators):
                    findings.append(normalize_finding(
                        module=MODULE, tool='owasp', type_='path_traversal',
                        title='Path traversal - /etc/passwd accessible',
                        evidence=f'GET {probe_url} returned /etc/passwd content',
                        severity='Critical', target=domain,
                        confidence='probable', verifiable=True,
                        verification_target={'url': probe_url, 'param': None, 'payload': trav},
                    ))
                    return findings
            except requests.RequestException:
                pass

        # Also try file= / path= params
        base_params = _get_params(target)
        for param in [p for p in base_params if any(
                k in p.lower() for k in ('file', 'path', 'page', 'doc', 'view'))]:
            injected = dict(base_params)
            injected[param] = '../../../../etc/passwd'
            try:
                resp = requests.get(target, params=injected, **_SESSION_KWARGS)
                if any(ind in resp.text for ind in indicators):
                    findings.append(normalize_finding(
                        module=MODULE, tool='owasp', type_='path_traversal',
                        title='Path traversal via parameter - /etc/passwd readable',
                        evidence=f'Parameter "{param}" with traversal payload '
                                 f'returned /etc/passwd content',
                        severity='Critical', target=domain,
                        confidence='probable', verifiable=True,
                        verification_target={'url': target, 'param': param,
                                              'payload': injected[param]},
                    ))
                    return findings
            except requests.RequestException:
                pass
    except Exception as e:
        logger.debug("path traversal test error for %s: %s", domain, e)
    return findings


def test_open_redirect(target: str, domain: str) -> List[dict]:
    """
    Inject external URLs into common redirect parameters.
    Non-destructive: read-only GET requests, allow_redirects=False.
    """
    findings = []
    redirect_params = ['next', 'redirect', 'url', 'return', 'returnUrl',
                       'redirect_uri', 'continue', 'goto', 'dest', 'destination']
    external_url = 'https://evil-vapt-test.example.com'

    try:
        for param in redirect_params:
            try:
                resp = requests.get(
                    target,
                    params={param: external_url},
                    timeout=_TIMEOUT,
                    verify=False,
                    allow_redirects=False,
                )
                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get('Location', '')
                    if 'evil-vapt-test.example.com' in location:
                        findings.append(normalize_finding(
                            module=MODULE, tool='owasp', type_='open_redirect',
                            title='Open Redirect vulnerability',
                            evidence=f'Parameter "{param}" redirects to '
                                     f'injected URL: {location}',
                            severity='Medium', target=domain,
                            confidence='probable', verifiable=True,
                            verification_target={'url': target, 'param': param,
                                                  'payload': external_url},
                        ))
                        return findings
            except requests.RequestException:
                pass
    except Exception as e:
        logger.debug("open redirect test error for %s: %s", domain, e)
    return findings


def test_error_disclosure(target: str, domain: str) -> List[dict]:
    """
    Send malformed requests to probe for stack trace / error disclosure.
    Non-destructive: read-only, no data modification.
    """
    findings = []
    probes = [
        # Invalid parameter type
        {'id': "' INVALID", 'page': '-1'},
        # Extremely long value
        {'q': 'A' * 4096},
        # Null bytes / special chars
        {'id': '\x00\x01\x02'},
    ]

    try:
        for params in probes:
            try:
                resp = requests.get(target, params=params,
                                    timeout=_TIMEOUT, verify=False,
                                    allow_redirects=True)
                if resp.status_code == 500 and _TRACE_RE.search(resp.text):
                    # Find the matched pattern for evidence
                    match = _TRACE_RE.search(resp.text)
                    snippet = resp.text[max(0, match.start()-30):match.end()+80]
                    findings.append(normalize_finding(
                        module=MODULE, tool='owasp', type_='error_disclosure',
                        title='Error/stack trace disclosure on 500 response',
                        evidence=f'Stack trace or framework error exposed: ...{snippet[:200]}...',
                        severity='Medium', target=domain,
                    ))
                    return findings
            except requests.RequestException:
                pass
    except Exception as e:
        logger.debug("error disclosure test error for %s: %s", domain, e)
    return findings


@app.task(base=BaseTask, name='tasks.owasp.run_owasp')
def run_owasp(scan_id: str, domain: str) -> dict:
    """
    OWASP Top 10 module: 5 non-destructive active tests.
    All payloads are read-only GET requests - no data modification ever.
    Pure Python (requests) - tool_versions is always empty for this module.
    Returns a build_module_result() envelope (Section 4.3 schema note).
    """
    update_module_status(scan_id, MODULE, 'running')
    start = time.monotonic()
    findings = []
    target = resolve_target_url(domain)

    try:
        for test_fn in (test_sqli, test_xss, test_path_traversal,
                        test_open_redirect, test_error_disclosure):
            try:
                findings.extend(test_fn(target, domain))
            except Exception as e:
                logger.error("owasp %s failed for scan %s: %s",
                             test_fn.__name__, scan_id, e)

        update_module_status(scan_id, MODULE, 'complete')
        return build_module_result(MODULE, findings, {}, status='success',
                                    duration_seconds=time.monotonic() - start)
    except SoftTimeLimitExceeded:
        logger.warning("owasp hit its soft time limit for scan %s", scan_id)
        update_module_status(scan_id, MODULE, 'failed')
        return build_module_result(MODULE, findings, {}, status='timeout',
                                    error='Module exceeded its soft time limit',
                                    duration_seconds=time.monotonic() - start)
    except Exception as e:
        logger.exception("owasp unexpected error scan=%s: %s", scan_id, e)
        update_module_status(scan_id, MODULE, 'failed')
        return build_module_result(MODULE, findings, {}, status='failed',
                                    error=str(e), duration_seconds=time.monotonic() - start)
