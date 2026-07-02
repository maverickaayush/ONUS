import json
import logging
import re
import time
import urllib3
from typing import List, Tuple

import requests
from celery.exceptions import SoftTimeLimitExceeded

from tasks.base_task import BaseTask, normalize_finding, update_module_status, build_module_result
from tasks.celery_app import app

# verify=False is a deliberate scanner design choice - test targets commonly
# have self-signed or invalid certs that must not block the analysis.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)
MODULE = 'headers'

_REQUEST_KWARGS = dict(timeout=15, verify=False, allow_redirects=True)

# All headers we record in the positive/informational summary finding
_SECURITY_HEADERS = {
    'strict-transport-security', 'content-security-policy', 'x-frame-options',
    'x-content-type-options', 'referrer-policy', 'permissions-policy',
    'access-control-allow-origin', 'access-control-allow-credentials',
    'x-xss-protection', 'cache-control', 'feature-policy',
}


# ---------------------------------------------------------------------------
# Cookie parsing (raw Set-Cookie headers - requests' jar doesn't expose flags)
# ---------------------------------------------------------------------------

def _parse_raw_cookies(resp) -> List[Tuple[str, set]]:
    """
    Parse raw Set-Cookie headers and return [(cookie_name, {lowercase_flags})].
    Uses resp.raw.headers.getlist to reliably capture all Set-Cookie headers
    including HttpOnly and SameSite which requests' cookie jar silently drops.
    """
    raw_vals: List[str] = []
    try:
        raw_vals = resp.raw.headers.getlist('Set-Cookie')
    except AttributeError:
        # Fallback for mocks / non-urllib3 transports
        sc = resp.headers.get('Set-Cookie', '')
        if sc:
            raw_vals = [sc]

    cookies = []
    for raw in raw_vals:
        if not raw:
            continue
        parts = [p.strip() for p in raw.split(';')]
        if not parts[0]:
            continue
        name = parts[0].split('=', 1)[0].strip()
        # Collect directive names (lowercased, no values needed for flag checks)
        flags = {p.lower().split('=', 1)[0].strip() for p in parts[1:] if p.strip()}
        cookies.append((name, flags))
    return cookies


# ---------------------------------------------------------------------------
# Individual header checks
# ---------------------------------------------------------------------------

def _check_hsts(value: str, domain: str) -> List[dict]:
    if not value:
        return [normalize_finding(
            module=MODULE, tool='headers', type_='missing_hsts',
            title='Missing Strict-Transport-Security header',
            evidence='HSTS not present - browsers can connect over plain HTTP',
            severity='High', target=domain,
        )]

    findings = []
    m = re.search(r'max-age=(\d+)', value, re.IGNORECASE)
    max_age = int(m.group(1)) if m else 0
    if max_age < 31536000:
        findings.append(normalize_finding(
            module=MODULE, tool='headers', type_='weak_hsts_max_age',
            title=f'HSTS max-age too short: {max_age}s (minimum 31536000)',
            evidence=f'Strict-Transport-Security: {value}',
            severity='Low', target=domain,
        ))
    if 'includesubdomains' not in value.lower():
        findings.append(normalize_finding(
            module=MODULE, tool='headers', type_='hsts_missing_includesubdomains',
            title='HSTS missing includeSubDomains directive',
            evidence=f'Strict-Transport-Security: {value}',
            severity='Low', target=domain,
        ))
    return findings


def _check_csp(value: str, domain: str) -> List[dict]:
    if not value:
        return [normalize_finding(
            module=MODULE, tool='headers', type_='missing_csp',
            title='Missing Content-Security-Policy header',
            evidence='No CSP set - XSS mitigation policy absent',
            severity='Medium', target=domain,
        )]
    findings = []
    if 'unsafe-inline' in value:
        findings.append(normalize_finding(
            module=MODULE, tool='headers', type_='csp_unsafe_inline',
            title="CSP contains 'unsafe-inline' - weakens XSS protection",
            evidence=f'Content-Security-Policy: {value[:200]}',
            severity='Medium', target=domain,
        ))
    if 'unsafe-eval' in value:
        findings.append(normalize_finding(
            module=MODULE, tool='headers', type_='csp_unsafe_eval',
            title="CSP contains 'unsafe-eval'",
            evidence=f'Content-Security-Policy: {value[:200]}',
            severity='Low', target=domain,
        ))
    return findings


def _check_clickjacking(xfo: str, csp: str, domain: str) -> List[dict]:
    """
    Flag clickjacking risk only when BOTH X-Frame-Options is absent AND
    CSP has no frame-ancestors directive - either one alone is sufficient.
    """
    has_xfo = bool(xfo)
    has_frame_ancestors = 'frame-ancestors' in csp.lower() if csp else False
    if not has_xfo and not has_frame_ancestors:
        return [normalize_finding(
            module=MODULE, tool='headers', type_='missing_clickjacking_protection',
            title='No clickjacking protection (missing X-Frame-Options and CSP frame-ancestors)',
            evidence='Neither X-Frame-Options nor CSP frame-ancestors directive is set',
            severity='Medium', target=domain,
        )]
    return []


def _check_cors(acao: str, acac: str, domain: str) -> List[dict]:
    """
    Wildcard ACAO + credentials=true → High (serious misconfiguration).
    Wildcard ACAO alone → Medium (common but worth noting).
    """
    if acao != '*':
        return []
    if acac.lower() == 'true':
        return [normalize_finding(
            module=MODULE, tool='headers', type_='cors_wildcard_with_credentials',
            title='CORS wildcard with Access-Control-Allow-Credentials: true',
            evidence='Any origin can make credentialed cross-origin requests - '
                     'session tokens / cookies exposed to attacker-controlled sites',
            severity='High', target=domain,
        )]
    return [normalize_finding(
        module=MODULE, tool='headers', type_='cors_wildcard',
        title='CORS wildcard: Access-Control-Allow-Origin: *',
        evidence='Any origin can read non-credentialed responses',
        severity='Medium', target=domain,
    )]


def _check_server_info(server: str, powered_by: str, domain: str) -> List[dict]:
    """Flag version-exposing Server / X-Powered-By values as Low."""
    findings = []
    version_re = re.compile(r'[/\s]\d[\d.]+')
    if server:
        if version_re.search(server):
            findings.append(normalize_finding(
                module=MODULE, tool='headers', type_='server_version_exposed',
                title=f'Server header exposes version: {server}',
                evidence=f'Server: {server}',
                severity='Low', target=domain,
            ))
    if powered_by:
        findings.append(normalize_finding(
            module=MODULE, tool='headers', type_='x_powered_by_exposed',
            title=f'X-Powered-By header present: {powered_by}',
            evidence=f'X-Powered-By: {powered_by}',
            severity='Low', target=domain,
        ))
    return findings


def _check_redirect_chain(resp, domain: str) -> List[dict]:
    """Flag any HTTP URL in the redirect chain before the HTTPS final URL."""
    findings = []
    for hist in resp.history:
        if hist.url.startswith('http://'):
            findings.append(normalize_finding(
                module=MODULE, tool='headers', type_='insecure_redirect',
                title='Insecure HTTP redirect in chain before HTTPS landing',
                evidence=f'Redirect chain includes: {hist.url} -> ... -> {resp.url}',
                severity='Medium', target=domain,
            ))
            break  # one finding is enough
    return findings


# ---------------------------------------------------------------------------
# Main fetch + analysis
# ---------------------------------------------------------------------------

def _run_headers(scan_id: str, domain: str) -> List[dict]:
    # Attempt HTTPS, then fall back to HTTP on connection failure
    resp = None
    for scheme in ('https', 'http'):
        try:
            resp = requests.get(f'{scheme}://{domain}', **_REQUEST_KWARGS)
            break
        except requests.exceptions.SSLError:
            continue  # try next scheme
        except (requests.exceptions.ConnectionError,
                requests.exceptions.Timeout,
                requests.exceptions.TooManyRedirects,
                Exception) as e:
            logger.warning("headers: %s://%s failed: %s", scheme, domain, e)

    if resp is None:
        return [normalize_finding(
            module=MODULE, tool='headers', type_='target_unreachable',
            title='Target unreachable for header analysis',
            evidence=f'Both https://{domain} and http://{domain} failed',
            severity='Informational', target=domain,
        )]

    headers = {k.lower(): v for k, v in resp.headers.items()}
    findings: List[dict] = []

    # Redirect chain check
    findings.extend(_check_redirect_chain(resp, domain))

    # HSTS
    findings.extend(_check_hsts(headers.get('strict-transport-security', ''), domain))

    # CSP
    csp_value = headers.get('content-security-policy', '')
    findings.extend(_check_csp(csp_value, domain))

    # Clickjacking (needs both XFO and CSP to make the right call)
    findings.extend(_check_clickjacking(
        headers.get('x-frame-options', ''), csp_value, domain))

    # X-Content-Type-Options
    if headers.get('x-content-type-options', '').lower() != 'nosniff':
        findings.append(normalize_finding(
            module=MODULE, tool='headers', type_='missing_x_content_type_options',
            title='Missing or incorrect X-Content-Type-Options header',
            evidence=f'Value: {headers.get("x-content-type-options", "not set")}',
            severity='Low', target=domain,
        ))

    # Referrer-Policy
    referrer = headers.get('referrer-policy', '').lower()
    if referrer not in ('no-referrer', 'strict-origin',
                        'strict-origin-when-cross-origin', 'same-origin'):
        findings.append(normalize_finding(
            module=MODULE, tool='headers', type_='missing_referrer_policy',
            title='Missing or weak Referrer-Policy header',
            evidence=f'Referrer-Policy: {headers.get("referrer-policy", "not set")}',
            severity='Low', target=domain,
        ))

    # Permissions-Policy (also accept legacy Feature-Policy)
    if not headers.get('permissions-policy') and not headers.get('feature-policy'):
        findings.append(normalize_finding(
            module=MODULE, tool='headers', type_='missing_permissions_policy',
            title='Missing Permissions-Policy header',
            evidence='Browser feature access (camera/mic/geolocation) unrestricted',
            severity='Low', target=domain,
        ))

    # CORS (check both headers together for correct severity)
    findings.extend(_check_cors(
        headers.get('access-control-allow-origin', ''),
        headers.get('access-control-allow-credentials', ''),
        domain,
    ))

    # Server info / version disclosure
    findings.extend(_check_server_info(
        headers.get('server', ''),
        headers.get('x-powered-by', ''),
        domain,
    ))

    # Cookie flags (raw header parsing - reliable across all servers)
    for cookie_name, flags in _parse_raw_cookies(resp):
        if 'secure' not in flags:
            findings.append(normalize_finding(
                module=MODULE, tool='headers', type_='cookie_missing_secure',
                title=f'Cookie "{cookie_name}" missing Secure flag',
                evidence=f'Cookie "{cookie_name}" can be transmitted over plain HTTP',
                severity='Medium', target=domain,
            ))
        if 'httponly' not in flags:
            findings.append(normalize_finding(
                module=MODULE, tool='headers', type_='cookie_missing_httponly',
                title=f'Cookie "{cookie_name}" missing HttpOnly flag',
                evidence=f'Cookie "{cookie_name}" is accessible via JavaScript (XSS risk)',
                severity='Medium', target=domain,
            ))
        samesite = next((f for f in flags if f.startswith('samesite')), '')
        samesite_val = samesite.split('=', 1)[-1].strip() if '=' in samesite else ''
        if samesite_val.lower() not in ('strict', 'lax'):
            findings.append(normalize_finding(
                module=MODULE, tool='headers', type_='cookie_missing_samesite',
                title=f'Cookie "{cookie_name}" missing or weak SameSite attribute',
                evidence=f'Cookie "{cookie_name}" SameSite={samesite_val or "not set"}',
                severity='Low', target=domain,
            ))

    # Single Informational finding - all present security headers as a dict
    present = {k: v[:200] for k, v in headers.items() if k in _SECURITY_HEADERS and v}
    if present:
        findings.append(normalize_finding(
            module=MODULE, tool='headers', type_='headers_present_summary',
            title='Security headers present on target',
            evidence=json.dumps(present),
            severity='Informational', target=domain,
        ))

    return findings


# ---------------------------------------------------------------------------
# Celery task
# ---------------------------------------------------------------------------

@app.task(base=BaseTask, name='tasks.headers.run_headers')
def run_headers(scan_id: str, domain: str) -> dict:
    """
    HTTP security headers analysis - single GET request, pure Python, no
    external tool (tool_versions is always empty for this module).
    Returns a build_module_result() envelope (Section 4.3 schema note).
    """
    update_module_status(scan_id, MODULE, 'running')
    start = time.monotonic()
    findings = []
    try:
        findings = _run_headers(scan_id, domain)
        update_module_status(scan_id, MODULE, 'complete')
        return build_module_result(MODULE, findings, {}, status='success',
                                    duration_seconds=time.monotonic() - start)
    except SoftTimeLimitExceeded:
        logger.warning("headers hit its soft time limit for scan %s", scan_id)
        update_module_status(scan_id, MODULE, 'failed')
        return build_module_result(MODULE, findings, {}, status='timeout',
                                    error='Module exceeded its soft time limit',
                                    duration_seconds=time.monotonic() - start)
    except Exception as e:
        logger.exception("headers unexpected error scan=%s: %s", scan_id, e)
        update_module_status(scan_id, MODULE, 'failed')
        return build_module_result(MODULE, findings, {}, status='failed',
                                    error=str(e), duration_seconds=time.monotonic() - start)
