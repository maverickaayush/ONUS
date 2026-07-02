"""
tech_fingerprint module verification tests (WhatWeb + WAFW00F).

Run with:
    cd backend && python3 -m pytest tests/test_tech_fingerprint.py -v
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
from unittest.mock import patch, MagicMock
import pytest

REQUIRED_FIELDS = {'module', 'tool', 'type', 'title', 'evidence',
                   'severity', 'cvss', 'target', 'found_by'}
VALID_SEVERITIES = {'Critical', 'High', 'Medium', 'Low', 'Informational', 'Info'}
MODULE = 'tech_fingerprint'
SCAN_ID = 'test-techfp-v1'


def _write_whatweb_output(scan_id: str, plugins: dict):
    path = f'/tmp/whatweb_{scan_id}.json'
    with open(path, 'w') as f:
        json.dump([{'target': 'https://example.com', 'plugins': plugins}], f)


def _write_wafw00f_output(scan_id: str, entries: list):
    path = f'/tmp/wafw_{scan_id}.txt'
    with open(path, 'w') as f:
        json.dump(entries, f)


class TestWhatWebSchema:

    def test_plugin_detected_has_required_fields(self):
        from tasks.tech_fingerprint import _run_whatweb
        _write_whatweb_output(SCAN_ID, {'Nginx': {'version': ['1.20.1']}})
        with patch('tasks.tech_fingerprint.subprocess.run', return_value=MagicMock()):
            findings = _run_whatweb(SCAN_ID, 'https://example.com', 'example.com')
        assert findings
        for f in findings:
            missing = REQUIRED_FIELDS - set(f.keys())
            assert not missing, f"Missing {missing}"
            assert f['found_by'] == [MODULE]
            assert f['severity'] in VALID_SEVERITIES
        assert findings[0]['technology'] == 'Nginx'
        assert findings[0]['version'] == '1.20.1'
        assert findings[0]['type'] == 'tech_detected'
        assert findings[0]['severity'] == 'Informational'
        # temp file must be cleaned up
        assert not os.path.exists(f'/tmp/whatweb_{SCAN_ID}.json')

    def test_eol_php_upgrades_to_outdated_medium(self):
        from tasks.tech_fingerprint import _run_whatweb
        _write_whatweb_output(SCAN_ID, {'PHP': {'version': ['5.6.40']}})
        with patch('tasks.tech_fingerprint.subprocess.run', return_value=MagicMock()):
            findings = _run_whatweb(SCAN_ID, 'https://example.com', 'example.com')
        assert findings[0]['type'] == 'outdated_tech'
        assert findings[0]['severity'] == 'Medium'

    def test_current_php_stays_informational(self):
        from tasks.tech_fingerprint import _run_whatweb
        _write_whatweb_output(SCAN_ID, {'PHP': {'version': ['8.2.1']}})
        with patch('tasks.tech_fingerprint.subprocess.run', return_value=MagicMock()):
            findings = _run_whatweb(SCAN_ID, 'https://example.com', 'example.com')
        assert findings[0]['type'] == 'tech_detected'
        assert findings[0]['severity'] == 'Informational'


class TestWafw00fSchema:

    def test_waf_detected_is_medium(self):
        from tasks.tech_fingerprint import _run_wafw00f
        _write_wafw00f_output(SCAN_ID, [{'detected': True, 'firewall': 'Cloudflare'}])
        with patch('tasks.tech_fingerprint.subprocess.run', return_value=MagicMock()):
            findings = _run_wafw00f(SCAN_ID, 'https://example.com', 'example.com')
        assert findings
        assert findings[0]['type'] == 'waf_detected'
        assert findings[0]['severity'] == 'Medium'
        assert 'Cloudflare' in findings[0]['title']
        assert not os.path.exists(f'/tmp/wafw_{SCAN_ID}.txt')

    def test_no_waf_is_informational(self):
        from tasks.tech_fingerprint import _run_wafw00f
        _write_wafw00f_output(SCAN_ID, [{'detected': False}])
        with patch('tasks.tech_fingerprint.subprocess.run', return_value=MagicMock()):
            findings = _run_wafw00f(SCAN_ID, 'https://example.com', 'example.com')
        assert findings[0]['type'] == 'no_waf_detected'
        assert findings[0]['severity'] == 'Informational'


class TestTechFingerprintModuleStatus:

    def test_status_running_then_complete(self):
        status_calls = []

        def record(sid, mod, status): status_calls.append(status)

        with patch('tasks.tech_fingerprint.update_module_status', side_effect=record), \
             patch('tasks.tech_fingerprint._run_whatweb', return_value=[]), \
             patch('tasks.tech_fingerprint._run_wafw00f', return_value=[]):
            from tasks.tech_fingerprint import run_tech_fingerprint
            result = run_tech_fingerprint.run(SCAN_ID, 'example.com')

        assert isinstance(result, dict)
        assert result['status'] == 'success'
        assert isinstance(result['findings'], list)
        assert status_calls[0] == 'running'
        assert status_calls[-1] == 'complete'

    def test_both_tools_failing_marks_failed(self):
        status_calls = []

        def record(sid, mod, status): status_calls.append(status)

        with patch('tasks.tech_fingerprint.update_module_status', side_effect=record), \
             patch('tasks.tech_fingerprint._run_whatweb', side_effect=Exception('boom')), \
             patch('tasks.tech_fingerprint._run_wafw00f', side_effect=Exception('boom')):
            from tasks.tech_fingerprint import run_tech_fingerprint
            run_tech_fingerprint.run(SCAN_ID, 'example.com')

        assert status_calls[-1] == 'failed'


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
