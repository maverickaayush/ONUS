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
            findings = _run_zap(TEST_SCAN_ID, TEST_DOMAIN, f'https://{TEST_DOMAIN}')

        assert findings == []
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

    def test_remote_zap_not_ready_returns_empty_no_local_spawn(self):
        """Remote ZAP unreachable must return [] without ever touching local daemon code."""
        from tasks.webscan import _run_zap

        with patch('tasks.webscan.settings') as mock_settings, \
             patch('tasks.webscan._wait_for_zap', return_value=False), \
             patch('tasks.webscan._start_zap') as mock_start:
            mock_settings.ZAP_URL = 'http://zap:8090'
            findings = _run_zap(TEST_SCAN_ID, TEST_DOMAIN, f'https://{TEST_DOMAIN}')

        assert findings == []
        mock_start.assert_not_called()

    def test_local_mode_unaffected_when_zap_url_empty(self):
        """Empty ZAP_URL (native dev default) must still use the local daemon path."""
        from tasks.webscan import _run_zap

        with patch('tasks.webscan.settings') as mock_settings, \
             patch('tasks.webscan._start_zap', return_value=None) as mock_start:
            mock_settings.ZAP_URL = ''
            findings = _run_zap(TEST_SCAN_ID, TEST_DOMAIN, f'https://{TEST_DOMAIN}')

        assert findings == []
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

    def test_zap_not_installed_returns_empty_list(self):
        """If ZAP is not installed, _run_zap must return [] gracefully."""
        from tasks.webscan import _run_zap

        with patch('tasks.webscan._start_zap', return_value=None):
            findings = _run_zap(TEST_SCAN_ID, TEST_DOMAIN,
                                f'https://{TEST_DOMAIN}')
        assert findings == [], "ZAP missing must return empty list"

    def test_zap_not_ready_returns_empty_list(self):
        """If ZAP starts but never becomes ready, must return [] and kill process."""
        from tasks.webscan import _run_zap

        mock_proc = MagicMock()
        mock_proc.pid = 99999

        with patch('tasks.webscan._start_zap', return_value=mock_proc), \
             patch('tasks.webscan._wait_for_zap', return_value=False), \
             patch('tasks.webscan._kill_zap') as mock_kill:
            findings = _run_zap(TEST_SCAN_ID, TEST_DOMAIN,
                                f'https://{TEST_DOMAIN}')

        assert findings == [], "ZAP not-ready must return empty list"
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
            findings = _run_zap(TEST_SCAN_ID, TEST_DOMAIN,
                                f'https://{TEST_DOMAIN}')

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


class TestWebscanModuleStatus:
    """Module status state-machine tests."""

    def test_complete_on_success(self):
        """run_webscan must set status 'complete' on success."""
        status_calls = []

        def record_status(scan_id, module, status):
            status_calls.append(status)

        with patch('tasks.webscan.update_module_status', side_effect=record_status), \
             patch('tasks.webscan._run_zap', return_value=[]), \
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
             patch('tasks.webscan._run_zap', return_value=[]), \
             patch('tasks.webscan._run_nikto', return_value=[
                 {'module': 'webscan', 'tool': 'nikto', 'type': 'nikto_finding',
                  'title': 'Test', 'evidence': 'test', 'severity': 'Low',
                  'cvss': 0.0, 'target': TEST_DOMAIN, 'found_by': ['webscan']}
             ]):
            from tasks.webscan import run_webscan
            run_webscan.run(TEST_SCAN_ID, TEST_DOMAIN)

        assert status_calls[-1] == 'complete', \
            "Partial success (ZAP miss + Nikto hit) must still be 'complete'"


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
