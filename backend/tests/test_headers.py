"""
Step 5 verification tests for the headers module.

Run with:
    cd backend && python3 -m pytest tests/test_headers.py -v
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unittest.mock import patch, MagicMock
import pytest

REQUIRED_FIELDS = {'module', 'tool', 'type', 'title', 'evidence',
                   'severity', 'cvss', 'target', 'found_by'}
VALID_SEVERITIES = {'Critical', 'High', 'Medium', 'Low', 'Informational', 'Info'}
MODULE = 'headers'
TEST_DOMAIN = 'testphp.vulnweb.com'
TEST_SCAN_ID = 'test-headers-step5'


def _make_response(headers: dict, cookies=None, status=200):
    """Build a minimal mock requests.Response."""
    resp = MagicMock()
    resp.status_code = status
    resp.headers = headers
    resp.cookies = cookies or []
    return resp


class TestHeadersSchema:

    def test_all_required_fields(self):
        from tasks.base_task import normalize_finding
        f = normalize_finding(MODULE, 'headers', 'missing_hsts',
                              'Missing HSTS', 'evidence', 'High',
                              target=TEST_DOMAIN)
        assert not (REQUIRED_FIELDS - set(f.keys()))
        assert f['found_by'] == [MODULE]

    def test_missing_security_headers_flagged(self):
        """A response with no security headers must produce findings for each."""
        from tasks.headers import _run_headers

        mock_resp = _make_response({})
        with patch('tasks.headers.requests.get', return_value=mock_resp):
            findings = _run_headers(TEST_SCAN_ID, TEST_DOMAIN)

        types = {f['type'] for f in findings}
        assert 'missing_hsts' in types
        assert 'missing_csp' in types
        assert 'missing_x_frame_options' in types
        assert 'missing_x_content_type_options' in types

        for f in findings:
            assert REQUIRED_FIELDS <= set(f.keys()), f"Missing keys in: {f['title']}"
            assert f['found_by'] == [MODULE]
            assert f['severity'] in VALID_SEVERITIES

    def test_cors_wildcard_flagged_high(self):
        """Access-Control-Allow-Origin: * must be High severity."""
        from tasks.headers import _run_headers

        mock_resp = _make_response({'Access-Control-Allow-Origin': '*'})
        with patch('tasks.headers.requests.get', return_value=mock_resp):
            findings = _run_headers(TEST_SCAN_ID, TEST_DOMAIN)

        cors = [f for f in findings if f['type'] == 'cors_wildcard']
        assert cors, "CORS wildcard must produce a finding"
        assert cors[0]['severity'] == 'High'

    def test_hsts_present_and_valid_no_missing_finding(self):
        """Valid HSTS header must not produce a 'missing_hsts' finding."""
        from tasks.headers import _run_headers

        mock_resp = _make_response({
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        })
        with patch('tasks.headers.requests.get', return_value=mock_resp):
            findings = _run_headers(TEST_SCAN_ID, TEST_DOMAIN)

        types = {f['type'] for f in findings}
        assert 'missing_hsts' not in types
        assert 'weak_hsts_max_age' not in types
        assert 'hsts_missing_includesubdomains' not in types

    def test_hsts_short_max_age_flagged(self):
        """HSTS max-age below 31536000 must produce a medium finding."""
        from tasks.headers import _run_headers

        mock_resp = _make_response({
            'Strict-Transport-Security': 'max-age=3600',
        })
        with patch('tasks.headers.requests.get', return_value=mock_resp):
            findings = _run_headers(TEST_SCAN_ID, TEST_DOMAIN)

        types = {f['type'] for f in findings}
        assert 'weak_hsts_max_age' in types
        weak = next(f for f in findings if f['type'] == 'weak_hsts_max_age')
        assert weak['severity'] == 'Medium'

    def test_csp_unsafe_inline_flagged(self):
        """CSP with 'unsafe-inline' must produce a finding."""
        from tasks.headers import _run_headers

        mock_resp = _make_response({
            'Content-Security-Policy': "default-src 'self'; script-src 'unsafe-inline'",
        })
        with patch('tasks.headers.requests.get', return_value=mock_resp):
            findings = _run_headers(TEST_SCAN_ID, TEST_DOMAIN)

        types = {f['type'] for f in findings}
        assert 'csp_unsafe_inline' in types

    def test_server_info_header_informational(self):
        """Server header must produce an Informational finding."""
        from tasks.headers import _run_headers

        mock_resp = _make_response({'Server': 'Apache/2.4.51'})
        with patch('tasks.headers.requests.get', return_value=mock_resp):
            findings = _run_headers(TEST_SCAN_ID, TEST_DOMAIN)

        server = [f for f in findings
                  if f['type'] == 'header_info_server']
        assert server, "Server header must produce Informational finding"
        assert server[0]['severity'] == 'Informational'

    def test_connection_error_returns_empty_list(self):
        """Network failure must return [] gracefully (no crash)."""
        from tasks.headers import _run_headers
        import requests as req_lib

        with patch('tasks.headers.requests.get',
                   side_effect=req_lib.exceptions.ConnectionError("refused")):
            findings = _run_headers(TEST_SCAN_ID, 'unreachable.invalid')

        assert findings == []


class TestHeadersModuleStatus:

    def test_complete_on_success(self):
        status_calls = []

        def record(sid, mod, status):
            status_calls.append(status)

        mock_resp = _make_response({})
        with patch('tasks.headers.update_module_status', side_effect=record), \
             patch('tasks.headers.requests.get', return_value=mock_resp):
            from tasks.headers import run_headers
            run_headers.run(TEST_SCAN_ID, TEST_DOMAIN)

        assert status_calls[0] == 'running'
        assert status_calls[-1] == 'complete'


class TestHeadersLive:

    def test_live_demo_target_example(self):
        """Live test against demo-target.example — authorized target."""
        from tasks.headers import _run_headers
        findings = _run_headers('live', 'demo-target.example')

        assert isinstance(findings, list)
        assert len(findings) > 0, "Expected at least some header findings"
        for f in findings:
            assert REQUIRED_FIELDS <= set(f.keys())
            assert f['found_by'] == [MODULE]
            assert f['severity'] in VALID_SEVERITIES


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
