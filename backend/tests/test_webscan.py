"""
Step 4 verification tests for the webscan module.

Runs against http://testphp.vulnweb.com - a legally-authorized intentionally
vulnerable PHP app maintained by Acunetix for security tool testing.

Run with:
    cd backend && python3 -m pytest tests/test_webscan.py -v
"""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import psutil
import pytest
from unittest.mock import patch, MagicMock

# Required fields per Section 4.3 schema
REQUIRED_FIELDS = {'module', 'tool', 'type', 'title', 'evidence',
                   'severity', 'cvss', 'target', 'found_by'}

VALID_SEVERITIES = {'Critical', 'High', 'Medium', 'Low', 'Informational', 'Info'}

TEST_DOMAIN = 'testphp.vulnweb.com'
TEST_SCAN_ID = 'test-webscan-step4'


def _stub_update_status(scan_id, module, status):
    """No-op DB write for unit tests."""
    pass


class TestWebscanRemoteZap:
    """Step 9: remote/Docker ZAP mode, selected via settings.ZAP_URL."""

    def test_remote_zap_skips_local_daemon_spawn(self):
        """When ZAP_URL is set, _start_zap/_kill_zap (local process) must never run."""
        from tasks.webscan import _run_zap

        mock_zap = MagicMock()
        mock_zap.spider.scan.return_value = '1'
        mock_zap.spider.status.return_value = '100'
        mock_zap.ascan.scan.return_value = '1'
        mock_zap.ascan.status.return_value = '100'
        mock_zap.core.alerts.return_value = []

        with patch('tasks.webscan.settings') as mock_settings, \
             patch('tasks.webscan._wait_for_zap', return_value=True) as mock_wait, \
             patch('tasks.webscan.ZAPv2', return_value=mock_zap), \
             patch('tasks.webscan._start_zap') as mock_start, \
             patch('tasks.webscan._kill_zap') as mock_kill:
            mock_settings.ZAP_URL = 'http://zap:8090'
            findings, zap_version, disconnected = _run_zap(TEST_SCAN_ID, TEST_DOMAIN, f'https://{TEST_DOMAIN}')

        assert findings == []
        assert disconnected is False
        mock_start.assert_not_called()
        # _kill_zap is still called (no-op on proc=None) - confirm it was called with None
        mock_kill.assert_called_once_with(None)
        mock_wait.assert_called_once_with('http://zap:8090', timeout=60)

    def test_remote_zap_creates_session_per_scan(self):
        """Remote mode must isolate scans via a named ZAP session, not a port."""
        from tasks.webscan import _run_zap

        mock_zap = MagicMock()
        mock_zap.spider.scan.return_value = '1'
        mock_zap.spider.status.return_value = '100'
        mock_zap.ascan.scan.return_value = '1'
        mock_zap.ascan.status.return_value = '100'
        mock_zap.core.alerts.return_value = []

        with patch('tasks.webscan.settings') as mock_settings, \
             patch('tasks.webscan._wait_for_zap', return_value=True), \
             patch('tasks.webscan.ZAPv2', return_value=mock_zap), \
             patch('tasks.webscan._kill_zap'):
            mock_settings.ZAP_URL = 'http://zap:8090'
            _run_zap(TEST_SCAN_ID, TEST_DOMAIN, f'https://{TEST_DOMAIN}')

        mock_zap.core.new_session.assert_called_once_with(
            name=TEST_SCAN_ID, overwrite='true')

    def test_transient_status_blip_does_not_disconnect(self):
        """Root-cause regression: a single failed spider status poll (ZAP busy,
        not dead) must NOT abandon the scan. The next poll succeeds, the scan
        proceeds, and its alerts are still collected - disconnected is False."""
        from tasks.webscan import _run_zap

        mock_zap = MagicMock()
        mock_zap.spider.scan.return_value = '1'
        # First poll raises (blip), second says done.
        mock_zap.spider.status.side_effect = [
            ConnectionError("ZAP API momentarily busy"), '100']
        mock_zap.ascan.scan.return_value = '1'
        mock_zap.ascan.status.return_value = '100'
        mock_zap.core.alerts.return_value = [
            {'risk': 'High', 'alert': 'SQLi', 'evidence': 'x',
             'url': f'https://{TEST_DOMAIN}/', 'pluginId': '40018'}]

        with patch('tasks.webscan.settings') as mock_settings, \
             patch('tasks.webscan._wait_for_zap', return_value=True), \
             patch('tasks.webscan.ZAPv2', return_value=mock_zap), \
             patch('tasks.webscan._kill_zap'), \
             patch('tasks.webscan.time.sleep'):
            mock_settings.ZAP_URL = 'http://zap:8090'
            findings, zap_version, disconnected = _run_zap(
                TEST_SCAN_ID, TEST_DOMAIN, f'https://{TEST_DOMAIN}')

        assert disconnected is False, "one blip must not count as a disconnect"
        assert len(findings) == 1, "alerts must still be collected after a blip"

    def test_sustained_status_failures_report_disconnect(self):
        """The flip side: if the status poll keeps failing (ZAP genuinely
        gone), it must still be reported as a disconnect after the retry
        budget is exhausted - the fix must not mask a real outage."""
        from tasks.webscan import _run_zap

        mock_zap = MagicMock()
        mock_zap.spider.scan.return_value = '1'
        mock_zap.spider.status.side_effect = ConnectionError("ZAP is down")
        mock_zap.core.alerts.return_value = []

        with patch('tasks.webscan.settings') as mock_settings, \
             patch('tasks.webscan._wait_for_zap', return_value=True), \
             patch('tasks.webscan.ZAPv2', return_value=mock_zap), \
             patch('tasks.webscan._kill_zap'), \
             patch('tasks.webscan.time.sleep'):
            mock_settings.ZAP_URL = 'http://zap:8090'
            findings, zap_version, disconnected = _run_zap(
                TEST_SCAN_ID, TEST_DOMAIN, f'https://{TEST_DOMAIN}')

        assert disconnected is True, "sustained failures must report disconnect"

    def test_ascan_does_not_exist_is_not_a_disconnect(self):
        """Real root-cause regression (testphp.vulnweb.com): when the active
        scan can't start (nothing in scope), ZAP's ascan.status() returns the
        string 'does_not_exist'. That is a reachable ZAP with an invalid scan
        handle - NOT a disconnect. The spider's alerts must still be collected
        and disconnected must be False (previously: int('does_not_exist')
        raised, was read as 'unreachable', and the scan reported 'partial')."""
        from tasks.webscan import _run_zap

        mock_zap = MagicMock()
        mock_zap.spider.scan.return_value = '1'
        mock_zap.spider.status.return_value = '100'
        # ascan.scan hands back an error string, not a numeric id.
        mock_zap.ascan.scan.return_value = 'does_not_exist'
        mock_zap.core.alerts.return_value = [
            {'risk': 'Medium', 'alert': 'Header issue', 'evidence': 'y',
             'url': f'https://{TEST_DOMAIN}/', 'pluginId': '10020'}]

        with patch('tasks.webscan.settings') as mock_settings, \
             patch('tasks.webscan._wait_for_zap', return_value=True), \
             patch('tasks.webscan.ZAPv2', return_value=mock_zap), \
             patch('tasks.webscan._kill_zap'), \
             patch('tasks.webscan.time.sleep'):
            mock_settings.ZAP_URL = 'http://zap:8090'
            findings, zap_version, disconnected = _run_zap(
                TEST_SCAN_ID, TEST_DOMAIN, f'https://{TEST_DOMAIN}')

        assert disconnected is False, \
            "'does_not_exist' means reachable ZAP, invalid handle - not a disconnect"
        assert len(findings) == 1, "spider alerts must still be collected"
        # ascan.status must never be polled with the bogus id.
        mock_zap.ascan.status.assert_not_called()

    def test_json_auth_injects_bearer_via_replacer(self):
        """JSON login must inject the bearer token into every ZAP request via
        the Replacer add-on (no auth script / forced-user), and must NOT touch
        the form-auth script path."""
        from tasks.webscan import _run_zap

        mock_zap = MagicMock()
        mock_zap.spider.scan.return_value = '1'
        mock_zap.spider.status.return_value = '100'
        mock_zap.ascan.scan.return_value = '1'
        mock_zap.ascan.status.return_value = '100'
        mock_zap.core.alerts.return_value = []

        json_auth = {'login_url': 'https://juiceshop.local/rest/user/login',
                     'username': 'a@b.c', 'password': 'pw',
                     'username_field': 'email', 'password_field': 'password',
                     'login_type': 'json', 'token_json_path': 'authentication.token'}

        with patch('tasks.webscan.settings') as mock_settings, \
             patch('tasks.webscan._wait_for_zap', return_value=True), \
             patch('tasks.webscan.ZAPv2', return_value=mock_zap), \
             patch('tasks.webscan._kill_zap'), \
             patch('tasks.webscan.time.sleep'), \
             patch('tasks.auth_store.get_scan_auth', return_value=json_auth), \
             patch('tasks.auth_login.fetch_json_auth_token', return_value='JWT'):
            mock_settings.ZAP_URL = 'http://zap:8090'
            _run_zap(TEST_SCAN_ID, TEST_DOMAIN, f'https://{TEST_DOMAIN}')

        mock_zap.replacer.add_rule.assert_called_once()
        _, kwargs = mock_zap.replacer.add_rule.call_args
        assert kwargs['matchstring'] == 'Authorization'
        assert kwargs['replacement'] == 'Bearer JWT'
        # rule must be url-scoped to the target (no cross-scan contamination)
        assert kwargs.get('url'), "JSON auth rule must be url-scoped to the target"
        # ...and removed afterwards so the token never leaks into later scans
        mock_zap.replacer.remove_rule.assert_called_once()
        # form-auth script path must not run for JSON login
        mock_zap.authentication.set_authentication_method.assert_not_called()

    def test_remote_zap_not_ready_returns_empty_no_local_spawn(self):
        """Remote ZAP unreachable must return [] without ever touching local daemon code."""
        from tasks.webscan import _run_zap

        with patch('tasks.webscan.settings') as mock_settings, \
             patch('tasks.webscan._wait_for_zap', return_value=False), \
             patch('tasks.webscan._start_zap') as mock_start:
            mock_settings.ZAP_URL = 'http://zap:8090'
            findings, zap_version, disconnected = _run_zap(TEST_SCAN_ID, TEST_DOMAIN, f'https://{TEST_DOMAIN}')

        assert findings == []
        assert disconnected is False
        mock_start.assert_not_called()

    def test_local_mode_unaffected_when_zap_url_empty(self):
        """Empty ZAP_URL (native dev default) must still use the local daemon path."""
        from tasks.webscan import _run_zap

        with patch('tasks.webscan.settings') as mock_settings, \
             patch('tasks.webscan._start_zap', return_value=None) as mock_start:
            mock_settings.ZAP_URL = ''
            findings, zap_version, disconnected = _run_zap(TEST_SCAN_ID, TEST_DOMAIN, f'https://{TEST_DOMAIN}')

        assert findings == []
        assert disconnected is False
        mock_start.assert_called_once()


class TestWebscanSchema:
    """Schema and contract tests - run without ZAP/Nikto/DB."""

    def test_nikto_schema(self):
        """Nikto findings must match Section 4.3 schema including found_by."""
        from tasks.webscan import _run_nikto

        findings = _run_nikto(TEST_SCAN_ID, TEST_DOMAIN, f'http://{TEST_DOMAIN}')

        assert isinstance(findings, list), "Nikto must return a list"
        for f in findings:
            missing = REQUIRED_FIELDS - set(f.keys())
            assert not missing, f"Finding missing keys: {missing} - {f.get('title')}"
            assert f['found_by'] == ['webscan'], \
                f"found_by must be ['webscan'], got {f['found_by']}"
            assert f['module'] == 'webscan', \
                f"module must be 'webscan', got {f['module']}"
            assert f['severity'] in VALID_SEVERITIES, \
                f"Invalid severity '{f['severity']}'"

    def test_nikto_nested_host_json_parsing(self):
        """Nikto emits a list of host objects, each with a 'vulnerabilities'
        list. The parser must descend into that structure, not treat each host
        object as a finding."""
        import json as _json
        from unittest.mock import mock_open
        from tasks import webscan

        nikto_output = _json.dumps([{
            "host": TEST_DOMAIN,
            "ip": "1.2.3.4",
            "port": "80",
            "vulnerabilities": [
                {"id": "999990", "method": "GET", "url": "/admin/",
                 "msg": "Admin login page found"},
                {"id": "999991", "method": "GET", "url": "/config.php",
                 "msg": "Potentially sensitive file"},
            ],
        }])

        # Pretend nikto ran and wrote this file; skip the real subprocess + unlink.
        with patch('tasks.webscan.subprocess.run'), \
             patch('tasks.webscan.os.path.exists', return_value=True), \
             patch('tasks.webscan.os.unlink'), \
             patch('builtins.open', mock_open(read_data=nikto_output)):
            findings = webscan._run_nikto(TEST_SCAN_ID, TEST_DOMAIN,
                                          f'http://{TEST_DOMAIN}')

        assert len(findings) == 2, \
            f"Expected 2 vulns from nested structure, got {len(findings)}"
        titles = {f['title'] for f in findings}
        assert 'Admin login page found' in titles
        for f in findings:
            assert REQUIRED_FIELDS <= set(f.keys())
            assert f['found_by'] == ['webscan']
            assert '/admin/' in findings[0]['evidence'] or \
                   '/config.php' in findings[1]['evidence']
        # Neither msg here is a directory-listing hit - not verifiable.
        for f in findings:
            assert f['verifiable'] is False

    def test_nikto_directory_listing_is_verifiable(self):
        """A Nikto 'Directory indexing found' hit must be flagged verifiable
        with an absolute verification_target URL - the source for
        verify_directory_listing (analysis/verifier.py), per the correction
        that this is dispatched off Nikto's own text-match, not a dedicated
        headers.py autoindex check."""
        import json as _json
        from unittest.mock import mock_open
        from tasks import webscan

        nikto_output = _json.dumps([{
            "host": TEST_DOMAIN,
            "vulnerabilities": [
                {"id": "999992", "method": "GET", "url": "/images/",
                 "msg": "Directory indexing found."},
                {"id": "999993", "method": "GET", "url": "/old/",
                 "msg": "Outdated software version detected."},
            ],
        }])

        with patch('tasks.webscan.subprocess.run'), \
             patch('tasks.webscan.os.path.exists', return_value=True), \
             patch('tasks.webscan.os.unlink'), \
             patch('builtins.open', mock_open(read_data=nikto_output)):
            findings = webscan._run_nikto(TEST_SCAN_ID, TEST_DOMAIN,
                                          f'http://{TEST_DOMAIN}')

        by_msg = {f['title']: f for f in findings}
        listing = by_msg['Directory indexing found.']
        assert listing['confidence'] == 'probable'
        assert listing['verifiable'] is True
        assert listing['verification_target'] == {'url': f'http://{TEST_DOMAIN}/images/'}

        other = by_msg['Outdated software version detected.']
        assert other['verifiable'] is False

    def test_zap_not_installed_returns_empty_list(self):
        """If ZAP is not installed, _run_zap must return [] gracefully."""
        from tasks.webscan import _run_zap

        with patch('tasks.webscan._start_zap', return_value=None):
            findings, zap_version, disconnected = _run_zap(TEST_SCAN_ID, TEST_DOMAIN,
                                f'https://{TEST_DOMAIN}')
        assert findings == [], "ZAP missing must return empty list"
        assert disconnected is False, "ZAP never installed is not a mid-scan disconnect"

    def test_zap_not_ready_returns_empty_list(self):
        """If ZAP starts but never becomes ready, must return [] and kill process."""
        from tasks.webscan import _run_zap

        mock_proc = MagicMock()
        mock_proc.pid = 99999

        with patch('tasks.webscan._start_zap', return_value=mock_proc), \
             patch('tasks.webscan._wait_for_zap', return_value=False), \
             patch('tasks.webscan._kill_zap') as mock_kill:
            findings, zap_version, disconnected = _run_zap(TEST_SCAN_ID, TEST_DOMAIN,
                                f'https://{TEST_DOMAIN}')

        assert findings == [], "ZAP not-ready must return empty list"
        assert disconnected is False, "ZAP never becoming ready is not a mid-scan disconnect"
        mock_kill.assert_called_once_with(mock_proc)

    def test_zap_alerts_normalized_correctly(self):
        """ZAP alerts must be normalized to Section 4.3 schema."""
        from tasks.webscan import _run_zap

        fake_alerts = [
            {'alert': 'SQL Injection', 'risk': 'High',
             'evidence': "' OR '1'='1", 'url': 'http://test.com/login',
             'pluginId': '40018', 'description': 'SQL injection found'},
            {'alert': 'XSS', 'risk': 'Medium',
             'evidence': '<script>alert(1)</script>', 'url': 'http://test.com/',
             'pluginId': '40012', 'description': 'Reflected XSS'},
            {'alert': 'Info finding', 'risk': 'Informational',
             'evidence': '', 'url': 'http://test.com/',
             'pluginId': '10000', 'description': 'Information'},
        ]

        mock_proc = MagicMock()
        mock_proc.pid = 99999
        mock_zap = MagicMock()
        mock_zap.spider.scan.return_value = '1'
        mock_zap.spider.status.return_value = '100'
        mock_zap.ascan.scan.return_value = '1'
        mock_zap.ascan.status.return_value = '100'
        mock_zap.core.alerts.return_value = fake_alerts

        with patch('tasks.webscan._start_zap', return_value=mock_proc), \
             patch('tasks.webscan._wait_for_zap', return_value=True), \
             patch('tasks.webscan.ZAPv2', return_value=mock_zap), \
             patch('tasks.webscan._kill_zap'):
            findings, zap_version, disconnected = _run_zap(TEST_SCAN_ID, TEST_DOMAIN,
                                f'https://{TEST_DOMAIN}')

        assert disconnected is False
        assert len(findings) == 3
        for f in findings:
            missing = REQUIRED_FIELDS - set(f.keys())
            assert not missing, f"Missing keys: {missing}"
            assert f['found_by'] == ['webscan']
            assert f['severity'] in VALID_SEVERITIES

        # Severity mapping
        sev = {f['title']: f['severity'] for f in findings}
        assert sev['SQL Injection'] == 'High'
        assert sev['XSS'] == 'Medium'
        assert sev['Info finding'] == 'Informational'

    def test_port_isolation(self):
        """Each scan_id must produce a distinct ZAP port in range 8090-8989."""
        from tasks.webscan import _zap_port

        scan_ids = [f'scan-{i}' for i in range(100)]
        ports = [_zap_port(sid) for sid in scan_ids]

        for p in ports:
            assert 8090 <= p <= 8989, f"Port {p} out of expected range"

        # Concurrent scans should use different ports (hash collisions allowed
        # but rare - at least confirm the formula doesn't always give the same port)
        assert len(set(ports)) > 1, "Port formula produces same port for all scans"

    def test_zap_port_http_and_https_in_proxies(self):
        """ZAPv2 must be initialized with both http AND https proxy keys."""
        from tasks.webscan import _run_zap

        captured = {}

        def mock_zapv2(**kwargs):
            captured.update(kwargs)
            mock = MagicMock()
            mock.spider.scan.return_value = '1'
            mock.spider.status.return_value = '100'
            mock.ascan.scan.return_value = '1'
            mock.ascan.status.return_value = '100'
            mock.core.alerts.return_value = []
            return mock

        mock_proc = MagicMock()
        mock_proc.pid = 12345

        with patch('tasks.webscan._start_zap', return_value=mock_proc), \
             patch('tasks.webscan._wait_for_zap', return_value=True), \
             patch('tasks.webscan.ZAPv2', side_effect=mock_zapv2), \
             patch('tasks.webscan._kill_zap'):
            _run_zap(TEST_SCAN_ID, TEST_DOMAIN, f'https://{TEST_DOMAIN}')

        from tasks.webscan import _zap_port
        proxies = captured.get('proxies', {})
        assert 'http' in proxies, "ZAPv2 proxies missing 'http' key"
        assert 'https' in proxies, "ZAPv2 proxies missing 'https' key"
        port = _zap_port(TEST_SCAN_ID)
        assert str(port) in proxies['http'], "Proxy URL must use per-scan port"
        assert str(port) in proxies['https'], "Proxy URL must use per-scan port"


class TestKatana:
    """Katana supplemental crawler - runs alongside ZAP, not instead of it."""

    def test_parses_endpoints_and_tags_finding_with_endpoint_key(self):
        import json as _json
        from unittest.mock import mock_open
        from tasks import webscan

        katana_output = '\n'.join(_json.dumps(o) for o in [
            {'endpoint': f'https://{TEST_DOMAIN}/app.js', 'method': 'GET', 'status_code': 200},
            {'endpoint': f'https://{TEST_DOMAIN}/api/data', 'method': 'GET', 'status_code': 200},
        ])

        with patch('tasks.webscan.subprocess.run'), \
             patch('tasks.webscan.os.path.exists', return_value=True), \
             patch('tasks.webscan.os.unlink'), \
             patch('builtins.open', mock_open(read_data=katana_output)):
            findings = webscan._run_katana(TEST_SCAN_ID, TEST_DOMAIN, f'https://{TEST_DOMAIN}')

        assert len(findings) == 2
        for f in findings:
            missing = REQUIRED_FIELDS - set(f.keys())
            assert not missing, f"Missing keys: {missing}"
            assert f['type'] == 'crawled_endpoint_katana'
            assert f['found_by'] == ['webscan']
            assert 'endpoint' in f, "Katana findings must carry the extra 'endpoint' key"

    def test_js_hidden_endpoints_flags_only_katana_exclusive_routes(self):
        from tasks.webscan import _js_hidden_endpoints_finding

        zap_findings = [
            {'evidence': f'https://{TEST_DOMAIN}/ | some html alert'},
        ]
        katana_findings = [
            {'endpoint': f'https://{TEST_DOMAIN}/'},          # also seen by ZAP
            {'endpoint': f'https://{TEST_DOMAIN}/api/hidden'},  # JS-only
        ]

        finding = _js_hidden_endpoints_finding(TEST_DOMAIN, zap_findings, katana_findings)

        assert finding is not None
        assert finding['type'] == 'js_hidden_endpoints'
        assert finding['severity'] == 'Low'
        assert '1 endpoints' in finding['title']

    def test_no_hidden_endpoints_returns_none(self):
        from tasks.webscan import _js_hidden_endpoints_finding

        zap_findings = [{'evidence': f'https://{TEST_DOMAIN}/ | x'}]
        katana_findings = [{'endpoint': f'https://{TEST_DOMAIN}/'}]

        assert _js_hidden_endpoints_finding(TEST_DOMAIN, zap_findings, katana_findings) is None

    def test_run_webscan_executes_zap_and_katana_in_parallel(self):
        """ZAP and Katana must both be invoked via the thread pool, and Nikto
        must still run afterward - confirms Katana doesn't replace anything."""
        status_calls = []

        with patch('tasks.webscan.update_module_status',
                   side_effect=lambda sid, mod, status: status_calls.append(status)), \
             patch('tasks.webscan._run_zap', return_value=([], None, False)) as mock_zap, \
             patch('tasks.webscan._run_katana', return_value=[]) as mock_katana, \
             patch('tasks.webscan._run_nikto', return_value=[]) as mock_nikto:
            from tasks.webscan import run_webscan
            run_webscan.run(TEST_SCAN_ID, TEST_DOMAIN)

        mock_zap.assert_called_once()
        mock_katana.assert_called_once()
        mock_nikto.assert_called_once()
        assert status_calls[-1] == 'complete'


class TestWebscanModuleStatus:
    """Module status state-machine tests."""

    def test_complete_on_success(self):
        """run_webscan must set status 'complete' on success."""
        status_calls = []

        def record_status(scan_id, module, status):
            status_calls.append(status)

        with patch('tasks.webscan.update_module_status', side_effect=record_status), \
             patch('tasks.webscan._run_zap', return_value=([], None, False)), \
             patch('tasks.webscan._run_nikto', return_value=[]):
            from tasks.webscan import run_webscan
            run_webscan.run(TEST_SCAN_ID, TEST_DOMAIN)

        assert 'running' in status_calls, "Must call 'running' at start"
        assert status_calls[-1] == 'complete', \
            f"Last status must be 'complete', got {status_calls[-1]}"

    def test_partial_success_still_complete(self):
        """ZAP failure + Nikto success = 'complete', not 'failed'."""
        status_calls = []

        def record_status(scan_id, module, status):
            status_calls.append(status)

        with patch('tasks.webscan.update_module_status', side_effect=record_status), \
             patch('tasks.webscan._run_zap', return_value=([], None, False)), \
             patch('tasks.webscan._run_nikto', return_value=[
                 {'module': 'webscan', 'tool': 'nikto', 'type': 'nikto_finding',
                  'title': 'Test', 'evidence': 'test', 'severity': 'Low',
                  'cvss': 0.0, 'target': TEST_DOMAIN, 'found_by': ['webscan']}
             ]):
            from tasks.webscan import run_webscan
            run_webscan.run(TEST_SCAN_ID, TEST_DOMAIN)

        assert status_calls[-1] == 'complete', \
            "Partial success (ZAP miss + Nikto hit) must still be 'complete'"

    def test_zap_mid_scan_disconnect_reports_partial_not_success(self):
        """Regression test for the real bug this fixes: ZAP going unreachable
        after scanning started (e.g. a daemon restart) must produce
        status='partial' with a descriptive error in the returned envelope -
        not a silent 'success' with 0 findings indistinguishable from ZAP
        genuinely finding nothing. Module-level status (update_module_status)
        is still 'complete' - it's the envelope's own `status` field that
        must carry the distinction, same as tech_fingerprint.py's partial
        case."""
        with patch('tasks.webscan.update_module_status'), \
             patch('tasks.webscan._run_zap', return_value=([], '2.15.0', True)), \
             patch('tasks.webscan._run_katana', return_value=[]), \
             patch('tasks.webscan._run_nikto', return_value=[]), \
             patch('tasks.webscan.get_tool_version', return_value='unknown'):
            from tasks.webscan import run_webscan
            result = run_webscan.run(TEST_SCAN_ID, TEST_DOMAIN)

        assert result['status'] == 'partial', \
            f"ZAP mid-scan disconnect must report 'partial', got {result['status']!r}"
        assert result['error'] and 'unreachable' in result['error'].lower(), \
            "Envelope must carry a descriptive error explaining the lost ZAP data"


class TestNoZapLeak:
    """Verify no ZAP process leaks after the task finishes."""

    def test_no_zap_process_after_task(self):
        """No ZAP processes spawned by the task must survive after it finishes."""
        def zap_pids_running():
            return {p.pid for p in psutil.process_iter(['name', 'cmdline'])
                    if 'zap' in (p.info.get('name') or '').lower()
                    or any('zap' in str(c).lower()
                           for c in (p.info.get('cmdline') or []))}

        # Snapshot pre-existing ZAP-related processes so we don't flag them.
        pids_before = zap_pids_running()

        with patch('tasks.webscan.update_module_status', _stub_update_status), \
             patch('tasks.webscan._run_nikto', return_value=[]):
            from tasks.webscan import run_webscan
            run_webscan.run(TEST_SCAN_ID, TEST_DOMAIN)

        # Only fail if NEW ZAP processes appeared and weren't cleaned up.
        pids_after = zap_pids_running()
        leaked = pids_after - pids_before
        assert not leaked, \
            f"ZAP process(es) leaked after task: new PIDs {leaked}"


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
