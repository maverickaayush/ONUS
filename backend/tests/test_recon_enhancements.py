"""
Verification tests for the Amass -> httpx -> Naabu recon chain added to
tasks/recon.py (Amass deep subdomains, httpx liveness/tech probing, Naabu
port pre-scan on live subdomains).

Run with:
    cd backend && python3 -m pytest tests/test_recon_enhancements.py -v
"""
import json
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unittest.mock import patch, MagicMock
import pytest

REQUIRED_FIELDS = {'module', 'tool', 'type', 'title', 'evidence',
                   'severity', 'cvss', 'target', 'found_by'}
VALID_SEVERITIES = {'Critical', 'High', 'Medium', 'Low', 'Informational', 'Info'}
SCAN_ID = 'test-recon-enh-v1'
DOMAIN = 'example.com'


def _write_ndjson(path, objs):
    with open(path, 'w') as f:
        f.write('\n'.join(json.dumps(o) for o in objs))


class TestAmass:
    def test_parses_ndjson_names_deduplicated(self):
        from tasks.recon import _run_amass
        path = f'/tmp/amass_{SCAN_ID}.json'
        _write_ndjson(path, [
            {'name': 'a.example.com'},
            {'name': 'b.example.com'},
            {'name': 'a.example.com'},
        ])
        with patch('tasks.recon.subprocess.run', return_value=MagicMock()):
            subs = _run_amass(SCAN_ID, DOMAIN)
        assert subs == ['a.example.com', 'b.example.com']
        assert not os.path.exists(path)


class TestHttpx:
    def test_empty_subdomains_skips_subprocess(self):
        from tasks.recon import _run_httpx
        with patch('tasks.recon.subprocess.run') as mock_run:
            result = _run_httpx(SCAN_ID, DOMAIN, [])
        assert result == []
        mock_run.assert_not_called()

    def test_parses_live_hosts_and_cleans_up(self):
        from tasks.recon import _run_httpx
        out_path = f'/tmp/httpx_{SCAN_ID}.json'
        subs_path = f'/tmp/subs_{SCAN_ID}.txt'

        def fake_run(cmd, **kwargs):
            _write_ndjson(out_path, [
                {'url': 'https://sub.example.com', 'status_code': 200,
                 'title': 'Home', 'tech': ['nginx:1.14.0']},
            ])
            return MagicMock()

        with patch('tasks.recon.subprocess.run', side_effect=fake_run):
            live_hosts = _run_httpx(SCAN_ID, DOMAIN, ['sub.example.com'])

        assert len(live_hosts) == 1
        assert live_hosts[0]['url'] == 'https://sub.example.com'
        assert not os.path.exists(out_path)
        assert not os.path.exists(subs_path)

    def test_findings_flag_outdated_tech_and_live_subdomain(self):
        from tasks.recon import _httpx_findings
        live_hosts = [{'url': 'https://sub.example.com', 'status_code': 200,
                       'title': 'Home', 'tech': ['nginx:1.14.0']}]
        findings = _httpx_findings(live_hosts, DOMAIN)

        types = {f['type'] for f in findings}
        assert types == {'live_subdomain', 'outdated_tech'}
        for f in findings:
            missing = REQUIRED_FIELDS - set(f.keys())
            assert not missing, f"Missing {missing}"
            assert f['found_by'] == ['recon']
            assert f['severity'] in VALID_SEVERITIES

        outdated = next(f for f in findings if f['type'] == 'outdated_tech')
        assert outdated['severity'] == 'Medium'
        assert outdated['cvss'] == 5.4

    def test_current_tech_not_flagged_outdated(self):
        from tasks.recon import _httpx_findings
        live_hosts = [{'url': 'https://sub.example.com', 'status_code': 200,
                       'title': 'Home', 'tech': ['nginx:1.25.0']}]
        findings = _httpx_findings(live_hosts, DOMAIN)
        assert {f['type'] for f in findings} == {'live_subdomain'}


class TestNaabu:
    def test_no_live_hosts_skips_subprocess(self):
        from tasks.recon import _run_naabu
        with patch('tasks.recon.subprocess.run') as mock_run:
            result = _run_naabu(SCAN_ID, DOMAIN, [])
        assert result == []
        mock_run.assert_not_called()

    def test_parses_open_ports_deduplicated(self):
        from tasks.recon import _run_naabu
        out_path = f'/tmp/naabu_{SCAN_ID}.json'

        def fake_run(cmd, **kwargs):
            _write_ndjson(out_path, [
                {'host': 'sub.example.com', 'port': 443},
                {'host': 'sub.example.com', 'port': 443},
                {'host': 'sub.example.com', 'port': 80},
            ])
            return MagicMock(stderr=b'')

        live_hosts = [{'url': 'https://sub.example.com'}]
        with patch('tasks.recon.subprocess.run', side_effect=fake_run):
            findings = _run_naabu(SCAN_ID, DOMAIN, live_hosts)

        assert len(findings) == 2
        for f in findings:
            missing = REQUIRED_FIELDS - set(f.keys())
            assert not missing, f"Missing {missing}"
            assert f['type'] == 'open_port_naabu'
            assert f['found_by'] == ['recon']
        assert not os.path.exists(out_path)

    def test_permission_denied_falls_back_to_connect_scan(self):
        from tasks.recon import _run_naabu
        calls = []

        def fake_run(cmd, **kwargs):
            calls.append(cmd)
            if '-sT' not in cmd:
                return MagicMock(stderr=b'naabu: permission denied (are you root?)')
            return MagicMock(stderr=b'')

        live_hosts = [{'url': 'https://sub.example.com'}]
        with patch('tasks.recon.subprocess.run', side_effect=fake_run):
            _run_naabu(SCAN_ID, DOMAIN, live_hosts)

        assert len(calls) == 2, "Must retry once with -sT after permission denied"
        assert '-sT' in calls[1]


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
