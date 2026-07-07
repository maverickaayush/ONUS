"""
Step 5 (headers) verification tests.

Targets:
  - example.com  - minimal headers, expect several missing
  - github.com   - well-configured, expect few or none

Run with:
    cd backend && python3 -m pytest tests/test_headers.py -v
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
from unittest.mock import patch, MagicMock
import pytest

REQUIRED_FIELDS = {'module', 'tool', 'type', 'title', 'evidence',
                   'severity', 'cvss', 'target', 'found_by'}
VALID_SEVERITIES = {'Critical', 'High', 'Medium', 'Low', 'Informational', 'Info'}
MODULE = 'headers'
SCAN_ID = 'test-headers-v2'


def _mock_resp(headers: dict, cookies_raw: list = None,
               history=None, url='https://example.com', status=200):
    resp = MagicMock()
    resp.status_code = status
    resp.url = url
    resp.headers = MagicMock()
    resp.headers.items.return_value = list(headers.items())
    resp.headers.get = lambda k, d='': headers.get(k, headers.get(k.lower(), d))
    resp.history = history or []
    resp.cookies = []
    # raw.headers.getlist for cookie parsing
    resp.raw = MagicMock()
    resp.raw.headers.getlist = lambda k: (cookies_raw or []) if k == 'Set-Cookie' else []
    return resp


class TestHeadersSchema:

    def test_all_required_fields_present(self):
        """Every finding must carry all Section 4.3 fields + found_by."""
        from tasks.headers import _run_headers
        resp = _mock_resp({})
        with patch('tasks.headers.requests.get', return_value=resp):
            findings = _run_headers(SCAN_ID, 'example.com')
        for f in findings:
            missing = REQUIRED_FIELDS - set(f.keys())
            assert not missing, f"Missing {missing} in: {f['title']}"
            assert f['found_by'] == [MODULE]
            assert f['severity'] in VALID_SEVERITIES

    def test_unreachable_target_returns_informational_not_empty(self):
        """Connection failure must return an Informational finding, not []."""
        from tasks.headers import _run_headers
        import requests as rlib
        with patch('tasks.headers.requests.get',
                   side_effect=rlib.exceptions.ConnectionError("refused")):
            findings = _run_headers(SCAN_ID, 'unreachable.invalid')
        assert len(findings) == 1
        assert findings[0]['type'] == 'target_unreachable'
        assert findings[0]['severity'] == 'Informational'
        assert findings[0]['found_by'] == [MODULE]

    def test_hsts_missing_is_high(self):
        from tasks.headers import _run_headers
        resp = _mock_resp({})
        with patch('tasks.headers.requests.get', return_value=resp):
            findings = _run_headers(SCAN_ID, 'example.com')
        types = {f['type'] for f in findings}
        assert 'missing_hsts' in types
        hsts = next(f for f in findings if f['type'] == 'missing_hsts')
        assert hsts['severity'] == 'High'

    def test_hsts_short_max_age_is_low_not_medium(self):
        """max-age < 31536000 must be Low (not Medium - spec says Low)."""
        from tasks.headers import _check_hsts
        findings = _check_hsts('max-age=3600', 'example.com')
        weak = [f for f in findings if f['type'] == 'weak_hsts_max_age']
        assert weak, "Short max-age must produce a finding"
        assert weak[0]['severity'] == 'Low', \
            f"Expected Low, got {weak[0]['severity']}"

    def test_cors_wildcard_alone_is_medium(self):
        """Wildcard ACAO without credentials must be Medium, not High."""
        from tasks.headers import _check_cors
        findings = _check_cors('*', '', 'example.com')
        assert findings
        assert findings[0]['severity'] == 'Medium', \
            f"Wildcard alone must be Medium, got {findings[0]['severity']}"
        assert findings[0]['type'] == 'cors_wildcard'

    def test_cors_wildcard_plus_credentials_is_high(self):
        """Wildcard ACAO + credentials=true must be High."""
        from tasks.headers import _check_cors
        findings = _check_cors('*', 'true', 'example.com')
        assert findings
        assert findings[0]['severity'] == 'High', \
            f"Wildcard + credentials must be High, got {findings[0]['severity']}"
        assert findings[0]['type'] == 'cors_wildcard_with_credentials'

    def test_xfo_missing_but_csp_frame_ancestors_no_finding(self):
        """CSP frame-ancestors is sufficient - must not flag missing XFO."""
        from tasks.headers import _check_clickjacking
        findings = _check_clickjacking(
            xfo='',
            csp="default-src 'self'; frame-ancestors 'none'",
            domain='example.com',
        )
        assert findings == [], \
            "frame-ancestors in CSP satisfies clickjacking protection"

    def test_both_xfo_and_frame_ancestors_missing_flags(self):
        """Both absent must produce a clickjacking finding."""
        from tasks.headers import _check_clickjacking
        findings = _check_clickjacking(xfo='', csp='', domain='example.com')
        assert findings
        assert findings[0]['type'] == 'missing_clickjacking_protection'
        assert findings[0]['severity'] == 'Medium'

    def test_cookie_httponly_detected_via_raw_parsing(self):
        """HttpOnly must be detected via raw Set-Cookie header, not cookie jar."""
        from tasks.headers import _run_headers
        resp = _mock_resp(
            {'Strict-Transport-Security': 'max-age=31536000; includeSubDomains'},
            cookies_raw=['SESSID=abc123; Path=/; Secure'],  # missing HttpOnly
        )
        with patch('tasks.headers.requests.get', return_value=resp):
            findings = _run_headers(SCAN_ID, 'example.com')
        httponly_findings = [f for f in findings
                             if f['type'] == 'cookie_missing_httponly']
        assert httponly_findings, \
            "Missing HttpOnly flag must be detected via raw header parsing"
        assert 'SESSID' in httponly_findings[0]['evidence']

    def test_cookie_all_flags_present_no_finding(self):
        """Cookie with Secure; HttpOnly; SameSite=Strict must produce no findings."""
        from tasks.headers import _parse_raw_cookies
        resp = MagicMock()
        resp.raw = MagicMock()
        resp.raw.headers.getlist = lambda k: [
            'token=xyz; Path=/; Secure; HttpOnly; SameSite=Strict'
        ]
        cookies = _parse_raw_cookies(resp)
        assert len(cookies) == 1
        name, flags = cookies[0]
        assert name == 'token'
        assert 'secure' in flags
        assert 'httponly' in flags
        assert any('samesite' in f for f in flags)

    def test_server_version_exposed_is_low(self):
        """Server header with version string must be Low severity."""
        from tasks.headers import _check_server_info
        findings = _check_server_info('Apache/2.4.51', '', 'example.com')
        assert findings
        assert findings[0]['type'] == 'server_version_exposed'
        assert findings[0]['severity'] == 'Low'

    def test_server_without_version_no_finding(self):
        """Server header without version must not produce a finding."""
        from tasks.headers import _check_server_info
        findings = _check_server_info('nginx', '', 'example.com')
        assert not findings, "Plain 'nginx' without version must not be flagged"

    def test_x_powered_by_is_low(self):
        """X-Powered-By present must produce a Low finding."""
        from tasks.headers import _check_server_info
        findings = _check_server_info('', 'PHP/7.4.3', 'example.com')
        assert findings
        assert findings[0]['type'] == 'x_powered_by_exposed'
        assert findings[0]['severity'] == 'Low'

    def test_redirect_chain_http_flagged(self):
        """HTTP URL in redirect chain before HTTPS must produce a finding."""
        from tasks.headers import _check_redirect_chain
        hist = MagicMock()
        hist.url = 'http://example.com/'
        resp = MagicMock()
        resp.url = 'https://example.com/'
        resp.history = [hist]
        findings = _check_redirect_chain(resp, 'example.com')
        assert findings
        assert findings[0]['type'] == 'insecure_redirect'
        assert findings[0]['severity'] == 'Medium'

    def test_informational_summary_is_single_finding(self):
        """Present security headers must produce ONE Informational finding, not many."""
        from tasks.headers import _run_headers
        resp = _mock_resp({
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
            'Content-Security-Policy': "default-src 'self'",
            'X-Frame-Options': 'DENY',
        })
        with patch('tasks.headers.requests.get', return_value=resp):
            findings = _run_headers(SCAN_ID, 'example.com')
        summaries = [f for f in findings if f['type'] == 'headers_present_summary']
        assert len(summaries) == 1, \
            f"Must produce exactly one summary finding, got {len(summaries)}"
        # The evidence must be valid JSON
        data = json.loads(summaries[0]['evidence'])
        assert 'strict-transport-security' in data


class TestHeadersModuleStatus:

    def test_status_running_then_complete(self):
        status_calls = []

        def record(sid, mod, status): status_calls.append(status)

        resp = _mock_resp({})
        with patch('tasks.headers.update_module_status', side_effect=record), \
             patch('tasks.headers.requests.get', return_value=resp):
            from tasks.headers import run_headers
            run_headers.run(SCAN_ID, 'example.com')

        assert status_calls[0] == 'running'
        assert status_calls[-1] == 'complete'

    def test_unreachable_still_marks_complete(self):
        """Unreachable target must still end as complete, not failed."""
        status_calls = []

        def record(sid, mod, status): status_calls.append(status)

        import requests as rlib
        with patch('tasks.headers.update_module_status', side_effect=record), \
             patch('tasks.headers.requests.get',
                   side_effect=rlib.exceptions.ConnectionError):
            from tasks.headers import run_headers
            run_headers.run(SCAN_ID, 'unreachable.invalid')

        assert status_calls[-1] == 'complete'

    def test_soft_time_limit_not_swallowed_as_unreachable(self):
        """
        Real bug found live (forced a real Celery SoftTimeLimitExceeded
        against this task): `_run_headers`'s scheme-fallback loop had a bare
        `Exception` sitting in its except tuple alongside the specific
        request exceptions (making those specific ones redundant - Exception
        already covers them), which silently swallowed
        SoftTimeLimitExceeded. A soft-timeout was misreported as
        status='success' with a 'target_unreachable' finding instead of the
        honest status='timeout' envelope. Confirmed only after re-raising
        SoftTimeLimitExceeded before the generic catch: the same live test
        then correctly returned status='timeout' at ~3s instead of falsely
        reporting success at the full duration.
        """
        from celery.exceptions import SoftTimeLimitExceeded
        from tasks.headers import run_headers

        with patch('tasks.headers.update_module_status'), \
             patch('tasks.headers.requests.get', side_effect=SoftTimeLimitExceeded()):
            result = run_headers.run(SCAN_ID, 'example.com')

        assert result['status'] == 'timeout'
        assert result['findings'] == []


class TestHeadersLive:
    """
    Live tests against real targets - no mocks.
    example.com has minimal headers; github.com is well-configured.
    """

    def test_example_com_has_missing_headers(self):
        """example.com must have at least some missing security headers."""
        from tasks.headers import _run_headers
        findings = _run_headers(SCAN_ID, 'example.com')

        assert isinstance(findings, list)
        assert len(findings) > 0
        for f in findings:
            assert REQUIRED_FIELDS <= set(f.keys()), \
                f"Missing keys in: {f.get('title')}"
            assert f['found_by'] == [MODULE]

        security_issues = [f for f in findings
                           if f['severity'] in ('High', 'Medium', 'Low')]
        assert security_issues, \
            "example.com should have at least some security header findings"

    def test_github_com_well_configured(self):
        """github.com should have few or no High/Critical findings."""
        from tasks.headers import _run_headers
        findings = _run_headers(SCAN_ID, 'github.com')

        assert isinstance(findings, list)
        for f in findings:
            assert REQUIRED_FIELDS <= set(f.keys())
            assert f['found_by'] == [MODULE]

        critical_high = [f for f in findings
                         if f['severity'] in ('Critical', 'High')]
        assert len(critical_high) == 0, \
            f"github.com should have no Critical/High findings, got: " \
            f"{[f['title'] for f in critical_high]}"

    def test_run_headers_task_returns_list_with_found_by(self):
        """Full task run must return list of dicts with found_by and complete status."""
        status_calls = []

        def record(sid, mod, status): status_calls.append(status)

        with patch('tasks.headers.update_module_status', side_effect=record):
            from tasks.headers import run_headers
            result = run_headers.run(SCAN_ID, 'example.com')

        assert isinstance(result, dict)
        assert result['status'] == 'success'
        assert status_calls[-1] == 'complete'
        for f in result['findings']:
            assert f.get('found_by') == [MODULE], \
                f"found_by missing or wrong in: {f.get('title')}"


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
