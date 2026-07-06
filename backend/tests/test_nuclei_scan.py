"""
nuclei_scan module verification tests.

Run with:
    cd backend && python3 -m pytest tests/test_nuclei_scan.py -v
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
from unittest.mock import patch, MagicMock
import pytest

REQUIRED_FIELDS = {'module', 'tool', 'type', 'title', 'evidence',
                   'severity', 'cvss', 'target', 'found_by'}
VALID_SEVERITIES = {'Critical', 'High', 'Medium', 'Low', 'Informational', 'Info'}
MODULE = 'nuclei'
SCAN_ID = 'test-nuclei-v1'


def _write_ndjson(scan_id: str, results: list):
    path = f'/tmp/nuclei_{scan_id}.jsonl'
    with open(path, 'w') as f:
        f.write('\n'.join(json.dumps(r) for r in results))


class TestNucleiSchema:

    def test_ndjson_result_has_required_fields(self):
        from tasks.nuclei_scan import _run_nuclei
        _write_ndjson(SCAN_ID, [{
            'template-id': 'CVE-2021-44228',
            'info': {'name': 'Log4Shell RCE', 'severity': 'critical',
                      'classification': {'cve-id': ['CVE-2021-44228']}},
            'matched-at': 'https://example.com/',
            'extracted-results': ['jndi:ldap'],
        }])
        with patch('tasks.nuclei_scan.subprocess.run', return_value=MagicMock()):
            findings = _run_nuclei(SCAN_ID, 'https://example.com', 'example.com')

        assert len(findings) == 1
        f = findings[0]
        missing = REQUIRED_FIELDS - set(f.keys())
        assert not missing, f"Missing {missing}"
        assert f['found_by'] == [MODULE]
        assert f['severity'] in VALID_SEVERITIES
        assert f['type'] == 'nuclei_CVE-2021-44228'
        assert f['severity'] == 'Critical'
        assert f['cvss'] == 9.0
        assert f['template_id'] == 'CVE-2021-44228'
        assert f['cve_id'] == 'CVE-2021-44228'
        assert not os.path.exists(f'/tmp/nuclei_{SCAN_ID}.jsonl')

    def test_multiple_ndjson_lines_parsed(self):
        from tasks.nuclei_scan import _run_nuclei
        _write_ndjson(SCAN_ID, [
            {'template-id': 'tech-detect', 'info': {'name': 'Tech', 'severity': 'info'},
             'matched-at': 'https://example.com/'},
            {'template-id': 'exposed-panel', 'info': {'name': 'Panel', 'severity': 'high'},
             'matched-at': 'https://example.com/admin'},
        ])
        with patch('tasks.nuclei_scan.subprocess.run', return_value=MagicMock()):
            findings = _run_nuclei(SCAN_ID, 'https://example.com', 'example.com')
        assert len(findings) == 2
        severities = {f['severity'] for f in findings}
        assert severities == {'Informational', 'High'}

    def test_unknown_severity_defaults_informational(self):
        from tasks.nuclei_scan import _run_nuclei
        _write_ndjson(SCAN_ID, [{
            'template-id': 'weird', 'info': {'name': 'X', 'severity': 'bogus'},
            'matched-at': 'https://example.com/',
        }])
        with patch('tasks.nuclei_scan.subprocess.run', return_value=MagicMock()):
            findings = _run_nuclei(SCAN_ID, 'https://example.com', 'example.com')
        assert findings[0]['severity'] == 'Informational'
        assert findings[0]['cvss'] == 0.0


class TestNucleiModuleStatus:

    def test_status_running_then_complete(self):
        status_calls = []

        def record(sid, mod, status): status_calls.append(status)

        with patch('tasks.nuclei_scan.update_module_status', side_effect=record), \
             patch('tasks.nuclei_scan._run_nuclei', return_value=[]):
            from tasks.nuclei_scan import run_nuclei
            result = run_nuclei.run(SCAN_ID, 'example.com')

        assert isinstance(result, dict)
        assert result['status'] == 'success'
        assert isinstance(result['findings'], list)
        assert status_calls[0] == 'running'
        assert status_calls[-1] == 'complete'


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
