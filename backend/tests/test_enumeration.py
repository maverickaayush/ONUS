"""
enumeration module verification tests (FFUF + baseline calibration).

Run with:
    cd backend && python3 -m pytest tests/test_enumeration.py -v
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
from unittest.mock import patch, MagicMock
import pytest


@pytest.fixture(autouse=True)
def _bypass_ssrf_pin():
    # enumeration's baseline probe now routes through net_guard's SNI-preserving
    # pinned client; bypass it here so the existing requests.get mocks apply
    # (SSRF/pin behaviour is covered in test_net_guard.py).
    import net_guard, requests as _rq
    from unittest.mock import patch as _patch
    def _pass(method, url, *, session=None, follow=None, max_redirects=5, **kw):
        kw.setdefault("verify", False)
        return getattr(session or _rq, method.lower())(url, **kw)
    with _patch.object(net_guard, "guarded_request", _pass), \
         _patch.object(net_guard, "assert_public_host", lambda *_a, **_k: None), \
         _patch.object(net_guard, "guarded_get", lambda url, **kw: _pass("get", url, **kw)):
        yield

REQUIRED_FIELDS = {'module', 'tool', 'type', 'title', 'evidence',
                   'severity', 'cvss', 'target', 'found_by'}
VALID_SEVERITIES = {'Critical', 'High', 'Medium', 'Low', 'Informational', 'Info'}
MODULE = 'enumeration'
SCAN_ID = 'test-enum-v1'


class TestClassify:

    def test_sensitive_file_200_is_critical(self):
        from tasks.enumeration import _classify
        type_, severity, cvss = _classify('.env', 200)
        assert type_ == 'exposed_sensitive_file'
        assert severity == 'Critical'

    def test_sensitive_file_403_is_denied_informational(self):
        from tasks.enumeration import _classify
        type_, severity, cvss = _classify('.env', 403)
        assert type_ == 'exposed_sensitive_file_denied'
        assert severity == 'Informational'

    def test_sensitive_file_401_is_denied_informational(self):
        from tasks.enumeration import _classify
        type_, severity, cvss = _classify('id_rsa', 401)
        assert type_ == 'exposed_sensitive_file_denied'

    def test_admin_panel_200_no_login_form_is_open_high(self):
        from tasks.enumeration import _classify
        type_, severity, cvss = _classify('admin', 200, login_form_detected=False)
        assert type_ == 'exposed_admin_panel_open'
        assert severity == 'High'

    def test_admin_panel_200_with_login_form_is_medium(self):
        from tasks.enumeration import _classify
        type_, severity, cvss = _classify('admin', 200, login_form_detected=True)
        assert type_ == 'exposed_admin_panel_login'
        assert severity == 'Medium'

    def test_admin_panel_403_is_denied_informational(self):
        from tasks.enumeration import _classify
        type_, severity, cvss = _classify('admin', 403)
        assert type_ == 'exposed_admin_panel_denied'
        assert severity == 'Informational'

    def test_generic_403_is_informational_not_medium(self):
        # Real bug fix: a 403 means access control is working, not a vuln.
        from tasks.enumeration import _classify
        type_, severity, cvss = _classify('secret', 403)
        assert type_ == 'exposed_path_403'
        assert severity == 'Informational'

    def test_generic_401_is_informational(self):
        from tasks.enumeration import _classify
        type_, severity, cvss = _classify('secret', 401)
        assert severity == 'Informational'

    def test_plain_200_is_medium(self):
        from tasks.enumeration import _classify
        type_, severity, cvss = _classify('robots.txt', 200)
        assert type_ == 'exposed_path_200'
        assert severity == 'Medium'

    def test_redirect_is_informational(self):
        from tasks.enumeration import _classify
        type_, severity, cvss = _classify('old-page', 301)
        assert severity == 'Informational'

    def test_backup_in_200_path_is_exposed_backup_file_not_admin_panel(self):
        from tasks.enumeration import _classify
        type_, severity, cvss = _classify('site-backup', 200)
        assert type_ == 'exposed_backup_file'
        assert severity == 'High'


class TestBaselineCalibration:

    def test_clustered_403s_produce_baseline(self):
        from tasks.enumeration import _calibrate_baseline

        def fake_get(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 403
            resp.content = b'x' * 33810
            return resp

        with patch('tasks.enumeration.requests.get', side_effect=fake_get):
            baseline = _calibrate_baseline('https://example.com')

        assert baseline is not None
        assert baseline['status'] == 403
        assert baseline['size_range'][0] <= 33810 <= baseline['size_range'][1]

    def test_clean_varied_404s_produce_no_baseline(self):
        from tasks.enumeration import _calibrate_baseline
        import itertools

        sizes = itertools.cycle([50, 4000, 120, 9999, 300])

        def fake_get(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 404
            resp.content = b'y' * next(sizes)
            return resp

        with patch('tasks.enumeration.requests.get', side_effect=fake_get):
            baseline = _calibrate_baseline('https://example.com')

        assert baseline is None

    def test_within_baseline_matches_status_and_size_range(self):
        from tasks.enumeration import _within_baseline
        baseline = {'status': 403, 'size_range': (33800, 33817),
                     'size_median': 33810, 'body_hash_set': set()}
        assert _within_baseline(403, 33810, baseline) is True
        assert _within_baseline(403, 34000, baseline) is False  # outside +50 margin
        assert _within_baseline(200, 33810, baseline) is False  # status mismatch

    def test_within_baseline_false_when_no_baseline(self):
        from tasks.enumeration import _within_baseline
        assert _within_baseline(403, 33810, None) is False


class TestFfufIntegration:

    def test_schema_and_cleanup(self):
        from tasks.enumeration import _run_ffuf
        out_path = f'/tmp/ffuf_{SCAN_ID}.json'
        payload = {'results': [
            {'input': {'FUZZ': '.env'}, 'status': 200, 'length': 128},
            {'input': {'FUZZ': 'admin'}, 'status': 200, 'length': 512},
        ]}

        def fake_run(*args, **kwargs):
            with open(out_path, 'w') as f:
                json.dump(payload, f)
            return MagicMock(returncode=0)

        with patch('tasks.enumeration.subprocess.run', side_effect=fake_run), \
             patch('tasks.enumeration._calibrate_baseline', return_value=None), \
             patch('tasks.enumeration._check_login_form', return_value=False), \
             patch('tasks.enumeration.os.path.exists', side_effect=lambda p: p == '/opt/wordlists/common.txt' or p == out_path):
            findings = _run_ffuf(SCAN_ID, 'https://example.com', 'example.com')

        assert len(findings) == 2
        for f in findings:
            missing = REQUIRED_FIELDS - set(f.keys())
            assert not missing, f"Missing {missing}"
            assert f['found_by'] == [MODULE]
            assert f['severity'] in VALID_SEVERITIES
            assert 'http_status' in f
            assert 'http_size' in f
        types = {f['type'] for f in findings}
        assert 'exposed_sensitive_file' in types
        assert 'exposed_admin_panel_open' in types
        assert not os.path.exists(out_path)

        by_type = {f['type']: f for f in findings}
        sensitive = by_type['exposed_sensitive_file']
        assert sensitive['confidence'] == 'probable'
        assert sensitive['verifiable'] is True
        assert sensitive['verification_target'] == {
            'url': 'https://example.com/.env', 'filename': '.env',
        }
        # Admin panels aren't a Phase 1 verifier - stay at normalize_finding()'s
        # own defaults.
        admin = by_type['exposed_admin_panel_open']
        assert admin['confidence'] == 'probable'
        assert admin['verifiable'] is False

    def test_matched_sensitive_file_helper(self):
        from tasks.enumeration import _matched_sensitive_file
        assert _matched_sensitive_file('.env') == '.env'
        assert _matched_sensitive_file('/.env') == '.env'
        assert _matched_sensitive_file('.git/config') == '.git/config'
        assert _matched_sensitive_file('robots.txt') is None

    def test_missing_wordlist_returns_empty(self):
        from tasks.enumeration import _run_ffuf
        with patch('tasks.enumeration.os.path.exists', return_value=False):
            findings = _run_ffuf(SCAN_ID, 'https://example.com', 'example.com')
        assert findings == []

    def test_denied_sensitive_file_hits_are_dropped(self):
        from tasks.enumeration import _run_ffuf
        out_path = f'/tmp/ffuf_{SCAN_ID}.json'
        payload = {'results': [
            {'input': {'FUZZ': '.env'}, 'status': 403, 'length': 200},
            {'input': {'FUZZ': 'robots.txt'}, 'status': 200, 'length': 50},
        ]}

        def fake_run(*args, **kwargs):
            with open(out_path, 'w') as f:
                json.dump(payload, f)
            return MagicMock(returncode=0)

        with patch('tasks.enumeration.subprocess.run', side_effect=fake_run), \
             patch('tasks.enumeration._calibrate_baseline', return_value=None), \
             patch('tasks.enumeration.os.path.exists', side_effect=lambda p: p == '/opt/wordlists/common.txt' or p == out_path):
            findings = _run_ffuf(SCAN_ID, 'https://example.com', 'example.com')

        # .env 403 hit dropped at source; robots.txt 200 kept.
        assert len(findings) == 1
        assert findings[0]['type'] == 'exposed_path_200'

    def test_baseline_filters_flood_of_identical_403s(self):
        """The actual demo-target.example scenario: hundreds of wordlist hits all
        returning the same catch-all 403 page should be filtered before
        ever becoming findings."""
        from tasks.enumeration import _run_ffuf
        out_path = f'/tmp/ffuf_{SCAN_ID}.json'
        payload = {'results': [
            {'input': {'FUZZ': f'path{i}'}, 'status': 403, 'length': 33810}
            for i in range(200)
        ] + [
            {'input': {'FUZZ': 'robots.txt'}, 'status': 200, 'length': 50},
        ]}

        def fake_run(*args, **kwargs):
            with open(out_path, 'w') as f:
                json.dump(payload, f)
            return MagicMock(returncode=0)

        baseline = {'status': 403, 'size_range': (33800, 33817),
                     'size_median': 33810, 'body_hash_set': set()}

        with patch('tasks.enumeration.subprocess.run', side_effect=fake_run), \
             patch('tasks.enumeration._calibrate_baseline', return_value=baseline), \
             patch('tasks.enumeration.os.path.exists', side_effect=lambda p: p == '/opt/wordlists/common.txt' or p == out_path):
            findings = _run_ffuf(SCAN_ID, 'https://example.com', 'example.com')

        assert len(findings) == 1  # only robots.txt survives baseline filtering
        assert findings[0]['type'] == 'exposed_path_200'


class TestEnumerationModuleStatus:

    def test_status_running_then_complete(self):
        status_calls = []

        def record(sid, mod, status): status_calls.append(status)

        with patch('tasks.enumeration.update_module_status', side_effect=record), \
             patch('tasks.enumeration._run_ffuf', return_value=[]):
            from tasks.enumeration import run_enumeration
            result = run_enumeration.run(SCAN_ID, 'example.com')

        assert isinstance(result, dict)
        assert result['status'] == 'success'
        assert isinstance(result['findings'], list)
        assert status_calls[0] == 'running'
        assert status_calls[-1] == 'complete'


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
