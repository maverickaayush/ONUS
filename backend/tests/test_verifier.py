"""
Phase 1 confidence verification tests (analysis/verifier.py).

Run with:
    cd backend && python3 -m pytest tests/test_verifier.py -v
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unittest.mock import patch, MagicMock
import pytest
import requests

from analysis.verifier import (
    verify_open_redirect, verify_path_traversal, verify_sensitive_file_exposure,
    verify_directory_listing, verify_sqli_time_based, verify_findings,
)


def _mock_resp(text='', status=200, headers=None, location=None):
    resp = MagicMock()
    resp.text = text
    resp.status_code = status
    resp.headers = headers or {}
    if location:
        resp.headers['Location'] = location
    return resp


def _finding(**overrides):
    base = {
        'type': 'open_redirect', 'title': 'x', 'severity': 'Medium',
        'confidence': 'probable', 'verifiable': True, 'verification_target': {},
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# The one behavior that must never regress: a verifier that fails to
# reproduce demotes to 'unverified' with a note - it never drops the finding.
# ---------------------------------------------------------------------------

class TestNeverDropsFindings:

    def test_failed_open_redirect_is_demoted_not_dropped(self):
        f = _finding(type='open_redirect',
                     verification_target={'url': 'https://x.test', 'param': 'next',
                                           'payload': 'https://evil-vapt-test.example.com'})
        with patch('analysis.verifier.requests.get', return_value=_mock_resp(status=200)):
            result = verify_open_redirect(f)
        assert result is f  # same object, not removed/replaced
        assert result['confidence'] == 'unverified'
        assert result['verification_note']

    def test_connection_error_demotes_not_drops(self):
        f = _finding(type='open_redirect',
                     verification_target={'url': 'https://x.test', 'param': 'next',
                                           'payload': 'https://evil-vapt-test.example.com'})
        with patch('analysis.verifier.requests.get',
                   side_effect=requests.exceptions.ConnectionError('refused')):
            result = verify_open_redirect(f)
        assert result['confidence'] == 'unverified'
        assert 'refused' in result['verification_note']

    def test_missing_verification_target_demotes_not_drops(self):
        f = _finding(type='open_redirect', verification_target={})
        result = verify_open_redirect(f)
        assert result['confidence'] == 'unverified'
        assert result['verification_note']

    def test_verify_findings_never_shrinks_the_list(self):
        findings = [
            _finding(type='open_redirect', verification_target={}),  # will fail (no target)
            {'type': 'tech_detected', 'severity': 'Informational'},   # not verifiable at all
        ]
        result = verify_findings(findings, enabled=True)
        assert len(result) == 2


# ---------------------------------------------------------------------------
# Per-verifier success/failure fixtures
# ---------------------------------------------------------------------------

class TestVerifyOpenRedirect:

    def test_reproduced_redirect_confirms(self):
        f = _finding(type='open_redirect',
                     verification_target={'url': 'https://x.test', 'param': 'next',
                                           'payload': 'https://evil-vapt-test.example.com'})
        resp = _mock_resp(status=302, location='https://evil-vapt-test.example.com/pwned')
        with patch('analysis.verifier.requests.get', return_value=resp):
            result = verify_open_redirect(f)
        assert result['confidence'] == 'confirmed'

    def test_no_longer_redirecting_demotes(self):
        f = _finding(type='open_redirect',
                     verification_target={'url': 'https://x.test', 'param': 'next',
                                           'payload': 'https://evil-vapt-test.example.com'})
        with patch('analysis.verifier.requests.get', return_value=_mock_resp(status=200)):
            result = verify_open_redirect(f)
        assert result['confidence'] == 'unverified'


class TestVerifyPathTraversal:

    def test_sentinel_reproduced_confirms(self):
        f = _finding(type='path_traversal',
                     verification_target={'url': 'https://x.test/etc/passwd', 'param': None, 'payload': None})
        with patch('analysis.verifier.requests.get',
                   return_value=_mock_resp('root:x:0:0:root:/root:/bin/bash')):
            result = verify_path_traversal(f)
        assert result['confidence'] == 'confirmed'

    def test_patched_response_demotes(self):
        f = _finding(type='path_traversal',
                     verification_target={'url': 'https://x.test/etc/passwd', 'param': None, 'payload': None})
        with patch('analysis.verifier.requests.get', return_value=_mock_resp('404 not found')):
            result = verify_path_traversal(f)
        assert result['confidence'] == 'unverified'

    def test_param_based_traversal_uses_params_kwarg(self):
        f = _finding(type='path_traversal',
                     verification_target={'url': 'https://x.test', 'param': 'file',
                                           'payload': '../../../../etc/passwd'})
        with patch('analysis.verifier.requests.get') as mock_get:
            mock_get.return_value = _mock_resp('root:x:0:0:root')
            verify_path_traversal(f)
        _, kwargs = mock_get.call_args
        assert kwargs['params'] == {'file': '../../../../etc/passwd'}


class TestVerifySensitiveFileExposure:

    def test_env_content_confirms(self):
        f = _finding(type='exposed_sensitive_file',
                     verification_target={'url': 'https://x.test/.env', 'filename': '.env'})
        with patch('analysis.verifier.requests.get',
                   return_value=_mock_resp('DB_PASSWORD=hunter2\nDEBUG=True\n')):
            result = verify_sensitive_file_exposure(f)
        assert result['confidence'] == 'confirmed'

    def test_html_error_page_does_not_confirm(self):
        """A generic HTML 200 error page must not false-positive as .env content."""
        f = _finding(type='exposed_sensitive_file',
                     verification_target={'url': 'https://x.test/.env', 'filename': '.env'})
        with patch('analysis.verifier.requests.get',
                   return_value=_mock_resp('<html><body>Not Found</body></html>')):
            result = verify_sensitive_file_exposure(f)
        assert result['confidence'] == 'unverified'

    def test_gitconfig_content_confirms(self):
        f = _finding(type='exposed_sensitive_file',
                     verification_target={'url': 'https://x.test/.git/config', 'filename': '.git/config'})
        with patch('analysis.verifier.requests.get',
                   return_value=_mock_resp('[core]\n\trepositoryformatversion = 0\n')):
            result = verify_sensitive_file_exposure(f)
        assert result['confidence'] == 'confirmed'

    def test_unknown_filename_cannot_verify(self):
        f = _finding(type='exposed_sensitive_file',
                     verification_target={'url': 'https://x.test/mystery.bin', 'filename': 'mystery.bin'})
        result = verify_sensitive_file_exposure(f)
        assert result['confidence'] == 'unverified'


class TestVerifyDirectoryListing:

    def test_autoindex_reproduced_confirms(self):
        f = _finding(type='nikto_finding',
                     verification_target={'url': 'https://x.test/public/'})
        with patch('analysis.verifier.requests.get',
                   return_value=_mock_resp('<title>Index of /public</title>')):
            result = verify_directory_listing(f)
        assert result['confidence'] == 'confirmed'

    def test_no_longer_listing_demotes(self):
        f = _finding(type='nikto_finding',
                     verification_target={'url': 'https://x.test/public/'})
        with patch('analysis.verifier.requests.get', return_value=_mock_resp(status=403)):
            result = verify_directory_listing(f)
        assert result['confidence'] == 'unverified'


class TestVerifySqliTimeBased:
    """Dormant in Phase 1 - no module emits sqli_time_based yet, but the
    verifier itself must still behave correctly if ever dispatched."""

    def test_reproduced_delay_confirms(self):
        f = _finding(type='sqli_time_based',
                     verification_target={'url': 'https://x.test', 'param': 'id',
                                           'payload': "1' AND SLEEP(3)--", 'expected_delay_seconds': 3})
        calls = [0]

        def fake_get(url, **kwargs):
            calls[0] += 1
            return _mock_resp('ok')

        with patch('analysis.verifier.requests.get', side_effect=fake_get), \
             patch('analysis.verifier.time.monotonic', side_effect=[0, 0, 0, 3.2]):
            result = verify_sqli_time_based(f)
        assert result['confidence'] == 'confirmed'

    def test_no_delay_demotes(self):
        f = _finding(type='sqli_time_based',
                     verification_target={'url': 'https://x.test', 'param': 'id',
                                           'payload': "1' AND SLEEP(3)--", 'expected_delay_seconds': 3})
        with patch('analysis.verifier.requests.get', return_value=_mock_resp('ok')), \
             patch('analysis.verifier.time.monotonic', side_effect=[0, 0, 0, 0.1]):
            result = verify_sqli_time_based(f)
        assert result['confidence'] == 'unverified'


# ---------------------------------------------------------------------------
# Dispatch / no-op behavior
# ---------------------------------------------------------------------------

class TestVerifyFindingsDispatch:

    def test_disabled_is_a_full_noop(self):
        f = _finding(type='open_redirect', verification_target={})
        with patch('analysis.verifier.requests.get') as mock_get:
            result = verify_findings([f], enabled=False)
        mock_get.assert_not_called()
        assert result[0]['confidence'] == 'probable'  # untouched

    def test_non_verifiable_finding_is_skipped(self):
        f = {'type': 'open_redirect', 'severity': 'Medium', 'verifiable': False}
        with patch('analysis.verifier.requests.get') as mock_get:
            verify_findings([f], enabled=True)
        mock_get.assert_not_called()

    def test_unknown_type_with_verifiable_true_is_skipped(self):
        # Defensive: a verifiable=True finding whose type has no dispatch
        # entry must not raise.
        f = {'type': 'some_future_type', 'severity': 'Medium', 'verifiable': True}
        result = verify_findings([f], enabled=True)
        assert result[0].get('confidence') is None  # untouched, not crashed

    def test_verifier_exception_demotes_gracefully(self):
        f = _finding(type='open_redirect',
                     verification_target={'url': 'https://x.test', 'param': 'next',
                                           'payload': 'https://evil-vapt-test.example.com'})
        with patch('analysis.verifier.requests.get', side_effect=RuntimeError('boom')):
            result = verify_findings([f], enabled=True)
        assert result[0]['confidence'] == 'unverified'

    def test_time_budget_exceeded_demotes_remaining(self):
        findings = [_finding(type='open_redirect', verification_target={}) for _ in range(3)]
        with patch('analysis.verifier.time.monotonic', side_effect=[0, 100, 100, 100, 100]):
            result = verify_findings(findings, enabled=True)
        for f in result:
            assert f['confidence'] == 'unverified'
            assert 'budget' in f['verification_note']


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
