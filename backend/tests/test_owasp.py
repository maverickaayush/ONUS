"""
Step 5 verification tests for the owasp module.

Run with:
    cd backend && python3 -m pytest tests/test_owasp.py -v
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unittest.mock import patch, MagicMock
import pytest

REQUIRED_FIELDS = {'module', 'tool', 'type', 'title', 'evidence',
                   'severity', 'cvss', 'target', 'found_by'}
VALID_SEVERITIES = {'Critical', 'High', 'Medium', 'Low', 'Informational', 'Info'}
MODULE = 'owasp'
TEST_DOMAIN = 'testphp.vulnweb.com'
TEST_SCAN_ID = 'test-owasp-step5'


def _mock_resp(text='', status=200, headers=None, location=None):
    resp = MagicMock()
    resp.text = text
    resp.status_code = status
    resp.headers = headers or {}
    if location:
        resp.headers['Location'] = location
    return resp


class TestOwaspSchema:

    def test_all_required_fields(self):
        from tasks.base_task import normalize_finding
        f = normalize_finding(MODULE, 'owasp', 'sqli_error_based',
                              'SQL Injection', 'evidence', 'High',
                              target=TEST_DOMAIN)
        assert not (REQUIRED_FIELDS - set(f.keys()))
        assert f['found_by'] == [MODULE]

    def test_sqli_error_based_detected(self):
        """SQL error pattern in response must produce a High finding."""
        from tasks.owasp import test_sqli

        def mock_get(url, **kwargs):
            params = kwargs.get('params', {})
            if "' OR '1'='1" in str(params.values()):
                return _mock_resp("You have an error in your SQL syntax near")
            return _mock_resp("normal response " * 10)

        with patch('tasks.owasp.requests.get', side_effect=mock_get):
            findings = test_sqli(f'https://{TEST_DOMAIN}?id=1', TEST_DOMAIN)

        assert findings, "SQL error pattern must produce a finding"
        assert findings[0]['severity'] == 'High'
        assert findings[0]['type'] == 'sqli_error_based'
        assert REQUIRED_FIELDS <= set(findings[0].keys())
        assert findings[0]['found_by'] == [MODULE]

    def test_sqli_no_finding_on_clean_response(self):
        """Clean response must produce no SQLi findings."""
        from tasks.owasp import test_sqli

        with patch('tasks.owasp.requests.get',
                   return_value=_mock_resp("Welcome to our site")):
            findings = test_sqli(f'https://{TEST_DOMAIN}?id=1', TEST_DOMAIN)

        assert findings == []

    def test_xss_reflected_detected(self):
        """XSS payload reflected verbatim must produce a High finding."""
        from tasks.owasp import test_xss
        marker = 'VAPT_XSS_8675309'

        def mock_get(url, **kwargs):
            params = kwargs.get('params', {})
            for v in params.values():
                if marker in str(v):
                    return _mock_resp(str(v))  # reflect the payload
            return _mock_resp("clean")

        with patch('tasks.owasp.requests.get', side_effect=mock_get):
            findings = test_xss(f'https://{TEST_DOMAIN}?q=hello', TEST_DOMAIN)

        assert findings, "Reflected payload must produce a finding"
        assert findings[0]['severity'] == 'High'
        assert findings[0]['type'] == 'reflected_xss'
        assert findings[0]['found_by'] == [MODULE]

    def test_xss_no_finding_on_escaped_response(self):
        """HTML-escaped payload must NOT produce an XSS finding."""
        from tasks.owasp import test_xss

        def mock_get(url, **kwargs):
            params = kwargs.get('params', {})
            # Return escaped version — not a reflection vulnerability
            return _mock_resp('&lt;script&gt;alert&lt;/script&gt;')

        with patch('tasks.owasp.requests.get', side_effect=mock_get):
            findings = test_xss(f'https://{TEST_DOMAIN}?q=x', TEST_DOMAIN)

        assert findings == []

    def test_open_redirect_detected(self):
        """302 to injected external URL must produce a Medium finding."""
        from tasks.owasp import test_open_redirect

        def mock_get(url, **kwargs):
            params = kwargs.get('params', {})
            if 'evil-vapt-test.example.com' in str(params.values()):
                return _mock_resp(status=302,
                                  location='https://evil-vapt-test.example.com/pwned')
            return _mock_resp()

        with patch('tasks.owasp.requests.get', side_effect=mock_get):
            findings = test_open_redirect(f'https://{TEST_DOMAIN}', TEST_DOMAIN)

        assert findings, "Redirect to injected URL must produce a finding"
        assert findings[0]['type'] == 'open_redirect'
        assert findings[0]['severity'] == 'Medium'
        assert findings[0]['found_by'] == [MODULE]

    def test_error_disclosure_detected(self):
        """Stack trace in 500 response must produce a Medium finding."""
        from tasks.owasp import test_error_disclosure

        trace = "Traceback (most recent call last):\n  File app.py line 42\nKeyError: 'id'"
        with patch('tasks.owasp.requests.get',
                   return_value=_mock_resp(trace, status=500)):
            findings = test_error_disclosure(f'https://{TEST_DOMAIN}', TEST_DOMAIN)

        assert findings, "Stack trace in 500 must produce a finding"
        assert findings[0]['type'] == 'error_disclosure'
        assert findings[0]['severity'] == 'Medium'

    def test_error_disclosure_no_finding_on_clean_500(self):
        """Generic 500 with no trace must NOT produce a finding."""
        from tasks.owasp import test_error_disclosure

        with patch('tasks.owasp.requests.get',
                   return_value=_mock_resp("Internal Server Error", status=500)):
            findings = test_error_disclosure(f'https://{TEST_DOMAIN}', TEST_DOMAIN)

        assert findings == []

    def test_network_error_returns_empty(self):
        """Any network error in a test must return [] gracefully."""
        from tasks.owasp import test_sqli
        import requests as req_lib

        with patch('tasks.owasp.requests.get',
                   side_effect=req_lib.exceptions.ConnectionError("refused")):
            findings = test_sqli(f'https://unreachable.invalid?id=1',
                                 'unreachable.invalid')

        assert findings == []


class TestOwaspModuleStatus:

    def test_complete_on_success(self):
        status_calls = []

        def record(sid, mod, status):
            status_calls.append(status)

        with patch('tasks.owasp.update_module_status', side_effect=record), \
             patch('tasks.owasp.requests.get', return_value=_mock_resp("clean")):
            from tasks.owasp import run_owasp
            run_owasp.run(TEST_SCAN_ID, TEST_DOMAIN)

        assert status_calls[0] == 'running'
        assert status_calls[-1] == 'complete'

    def test_one_test_failure_does_not_stop_others(self):
        """If one test function raises, remaining tests still run."""
        import requests as req_lib
        call_count = [0]

        def mock_get(url, **kwargs):
            call_count[0] += 1
            if call_count[0] <= 2:
                raise req_lib.exceptions.Timeout("timeout")
            return _mock_resp("clean")

        status_calls = []

        def record(sid, mod, status):
            status_calls.append(status)

        with patch('tasks.owasp.update_module_status', side_effect=record), \
             patch('tasks.owasp.requests.get', side_effect=mock_get):
            from tasks.owasp import run_owasp
            result = run_owasp.run(TEST_SCAN_ID, TEST_DOMAIN)

        assert status_calls[-1] == 'complete', \
            "Module must still complete even when some tests time out"
        assert isinstance(result, list)

    def test_all_findings_have_required_fields(self):
        """Every finding from a full run must match Section 4.3 schema."""
        from tasks.owasp import test_sqli, test_xss, test_error_disclosure

        marker = 'VAPT_XSS_8675309'
        trace = "Traceback (most recent call last):\nKeyError"

        call_n = [0]

        def mock_get(url, **kwargs):
            call_n[0] += 1
            params = kwargs.get('params', {})
            vals = str(params.values())
            if 'OR' in vals and "1'='1" in vals:
                return _mock_resp("You have an error in your SQL syntax")
            if marker in vals:
                for v in params.values():
                    if marker in str(v):
                        return _mock_resp(str(v))
            return _mock_resp("clean " * 5)

        target = f'https://{TEST_DOMAIN}?id=1'
        with patch('tasks.owasp.requests.get', side_effect=mock_get):
            findings = test_sqli(target, TEST_DOMAIN)

        for f in findings:
            missing = REQUIRED_FIELDS - set(f.keys())
            assert not missing, f"Missing keys {missing} in {f.get('title')}"
            assert f['found_by'] == [MODULE]
            assert f['severity'] in VALID_SEVERITIES
            assert f['module'] == MODULE


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
