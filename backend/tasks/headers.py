import logging
import re
import urllib3
from typing import List

import requests

from tasks.base_task import BaseTask, normalize_finding, update_module_status
from tasks.celery_app import app

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)
MODULE = 'headers'

# Headers to record as Informational when present
_INFORMATIONAL_HEADERS = {
    'server', 'x-powered-by', 'via', 'x-aspnet-version',
    'x-aspnetmvc-version', 'x-generator',
}


def _check_hsts(value: str, domain: str) -> List[dict]:
    findings = []
    if not value:
        findings.append(normalize_finding(
            module=MODULE, tool='headers', type_='missing_hsts',
            title='Missing Strict-Transport-Security header',
            evidence='HSTS header not present — browser connections not forced to HTTPS',
            severity='High', target=domain,
        ))
        return findings

    max_age = 0
    m = re.search(r'max-age=(\d+)', value, re.IGNORECASE)
    if m:
        max_age = int(m.group(1))

    if max_age < 31536000:
        findings.append(normalize_finding(
            module=MODULE, tool='headers', type_='weak_hsts_max_age',
            title=f'HSTS max-age too short: {max_age}s (minimum: 31536000)',
            evidence=f'Strict-Transport-Security: {value}',
            severity='Medium', target=domain,
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
            evidence='CSP header not present — no XSS/injection mitigation policy set',
            severity='Medium', target=domain,
        )]
    # CSP present but wildcard or unsafe-inline are weaknesses
    findings = []
    if "unsafe-inline" in value:
        findings.append(normalize_finding(
            module=MODULE, tool='headers', type_='csp_unsafe_inline',
            title="CSP contains 'unsafe-inline' — weakens XSS protection",
            evidence=f'Content-Security-Policy: {value[:200]}',
            severity='Medium', target=domain,
        ))
    if "unsafe-eval" in value:
        findings.append(normalize_finding(
            module=MODULE, tool='headers', type_='csp_unsafe_eval',
            title="CSP contains 'unsafe-eval'",
            evidence=f'Content-Security-Policy: {value[:200]}',
            severity='Low', target=domain,
        ))
    return findings


def _check_cors(value: str, domain: str) -> List[dict]:
    if value == '*':
        return [normalize_finding(
            module=MODULE, tool='headers', type_='cors_wildcard',
            title='CORS wildcard: Access-Control-Allow-Origin: *',
            evidence='Any origin can read responses — potential data leak on credentialed endpoints',
            severity='High', target=domain,
        )]
    return []


def _check_cookies(cookies, domain: str) -> List[dict]:
    findings = []
    for cookie in cookies:
        name = cookie.name
        if not cookie.secure:
            findings.append(normalize_finding(
                module=MODULE, tool='headers', type_='cookie_missing_secure',
                title=f'Cookie "{name}" missing Secure flag',
                evidence=f'Cookie {name} can be transmitted over HTTP',
                severity='Medium', target=domain,
            ))
        if not cookie.has_nonstandard_attr('HttpOnly'):
            findings.append(normalize_finding(
                module=MODULE, tool='headers', type_='cookie_missing_httponly',
                title=f'Cookie "{name}" missing HttpOnly flag',
                evidence=f'Cookie {name} is accessible via JavaScript',
                severity='Medium', target=domain,
            ))
        samesite = cookie.get_nonstandard_attr('SameSite') or ''
        if samesite.lower() not in ('strict', 'lax'):
            findings.append(normalize_finding(
                module=MODULE, tool='headers', type_='cookie_missing_samesite',
                title=f'Cookie "{name}" missing or weak SameSite attribute',
                evidence=f'Cookie {name} SameSite={samesite or "not set"} — CSRF risk',
                severity='Low', target=domain,
            ))
    return findings


def _run_headers(scan_id: str, domain: str) -> List[dict]:
    findings = []
    try:
        resp = requests.get(
            f'https://{domain}',
            timeout=15,
            verify=False,
            allow_redirects=True,
        )
    except requests.exceptions.ConnectionError:
        # Fallback to HTTP if HTTPS fails
        try:
            resp = requests.get(
                f'http://{domain}',
                timeout=15,
                verify=False,
                allow_redirects=True,
            )
        except Exception as e:
            logger.error("headers: request failed for scan %s: %s", scan_id, e)
            return findings
    except Exception as e:
        logger.error("headers: request failed for scan %s: %s", scan_id, e)
        return findings

    headers = {k.lower(): v for k, v in resp.headers.items()}

    # --- Security header checks ---
    findings.extend(_check_hsts(
        headers.get('strict-transport-security', ''), domain))

    findings.extend(_check_csp(
        headers.get('content-security-policy', ''), domain))

    if not headers.get('x-frame-options'):
        findings.append(normalize_finding(
            module=MODULE, tool='headers', type_='missing_x_frame_options',
            title='Missing X-Frame-Options header',
            evidence='Clickjacking protection not set',
            severity='Medium', target=domain,
        ))

    if headers.get('x-content-type-options', '').lower() != 'nosniff':
        findings.append(normalize_finding(
            module=MODULE, tool='headers', type_='missing_x_content_type_options',
            title='Missing or incorrect X-Content-Type-Options header',
            evidence=f'Value: {headers.get("x-content-type-options", "not set")}',
            severity='Low', target=domain,
        ))

    referrer = headers.get('referrer-policy', '')
    if referrer.lower() not in ('no-referrer', 'strict-origin',
                                'strict-origin-when-cross-origin',
                                'same-origin'):
        findings.append(normalize_finding(
            module=MODULE, tool='headers', type_='missing_referrer_policy',
            title='Missing or weak Referrer-Policy header',
            evidence=f'Referrer-Policy: {referrer or "not set"}',
            severity='Low', target=domain,
        ))

    if not headers.get('permissions-policy') and not headers.get('feature-policy'):
        findings.append(normalize_finding(
            module=MODULE, tool='headers', type_='missing_permissions_policy',
            title='Missing Permissions-Policy header',
            evidence='Browser feature access (camera/mic/geolocation) not restricted',
            severity='Low', target=domain,
        ))

    findings.extend(_check_cors(
        headers.get('access-control-allow-origin', ''), domain))

    # --- Cookie checks ---
    findings.extend(_check_cookies(resp.cookies, domain))

    # --- Informational: record headers that leak server info ---
    for hname in _INFORMATIONAL_HEADERS:
        val = headers.get(hname)
        if val:
            findings.append(normalize_finding(
                module=MODULE, tool='headers', type_=f'header_info_{hname.replace("-","_")}',
                title=f'Server info header present: {hname}',
                evidence=f'{hname}: {val}',
                severity='Informational', target=domain,
            ))

    return findings


@app.task(base=BaseTask, name='tasks.headers.run_headers')
def run_headers(scan_id: str, domain: str) -> list:
    """HTTP security headers analysis — single GET request, pure Python."""
    update_module_status(scan_id, MODULE, 'running')
    findings = []
    try:
        findings = _run_headers(scan_id, domain)
        update_module_status(scan_id, MODULE, 'complete')
        return findings
    except Exception as e:
        logger.exception("headers unexpected error scan=%s: %s", scan_id, e)
        update_module_status(scan_id, MODULE, 'failed')
        return findings
