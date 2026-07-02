"""
aggregator verification tests - dedup, response-fingerprint collapse (Fix 2),
finding_id assignment.

Run with:
    cd backend && python3 -m pytest tests/test_aggregator.py -v
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from analysis.aggregator import aggregate, _collapse_response_fingerprints


def _enum_finding(i, status=403, size=33810):
    return {
        'module': 'enumeration', 'tool': 'ffuf', 'type': 'exposed_path_403',
        'title': f'Path /{i} returned HTTP {status}',
        'evidence': f'GET https://example.com/{i} -> {status} ({size} bytes)',
        'severity': 'Informational', 'cvss': 0.0, 'target': 'example.com',
        'found_by': ['enumeration'], 'http_status': status, 'http_size': size,
    }


class TestFingerprintCollapse:

    def test_over_5_identical_findings_collapse_to_one(self):
        findings = [_enum_finding(i) for i in range(100)]
        result = _collapse_response_fingerprints(findings)
        assert len(result) == 1
        assert result[0]['details']['matched_paths']
        assert len(result[0]['details']['matched_paths']) == 100
        assert '100 paths' in result[0]['title']

    def test_5_or_fewer_stay_individual(self):
        findings = [_enum_finding(i) for i in range(5)]
        result = _collapse_response_fingerprints(findings)
        assert len(result) == 5

    def test_6_findings_collapse(self):
        findings = [_enum_finding(i) for i in range(6)]
        result = _collapse_response_fingerprints(findings)
        assert len(result) == 1

    def test_different_status_codes_dont_group_together(self):
        findings = [_enum_finding(i, status=403) for i in range(10)] + \
                   [_enum_finding(i, status=200) for i in range(10, 20)]
        result = _collapse_response_fingerprints(findings)
        assert len(result) == 2  # two separate collapsed groups

    def test_findings_without_http_data_are_left_ungrouped(self):
        findings = [
            {'type': 'open_port', 'title': 'Port 22', 'evidence': 'x',
             'severity': 'Info', 'found_by': ['recon']}
            for _ in range(20)
        ]
        result = _collapse_response_fingerprints(findings)
        assert len(result) == 20  # no http_status/http_size - never grouped

    def test_collapsed_finding_preserves_type_and_severity(self):
        findings = [_enum_finding(i) for i in range(10)]
        result = _collapse_response_fingerprints(findings)
        assert result[0]['type'] == 'exposed_path_403'
        assert result[0]['http_status'] == 403
        assert result[0]['module'] == 'enumeration'

    def test_collapsed_finding_merges_found_by(self):
        findings = [_enum_finding(i) for i in range(6)]
        findings[0]['found_by'] = ['enumeration', 'nikto']
        result = _collapse_response_fingerprints(findings)
        assert set(result[0]['found_by']) == {'enumeration', 'nikto'}


class TestAggregateEndToEnd:

    def test_demo_target_example_style_flood_collapses(self):
        """Regression test for the reported bug: 4636 identical-signature
        403 findings from one module should not survive aggregation intact."""
        flood = [_enum_finding(i) for i in range(4636)]
        other = [{
            'module': 'ssl_tls', 'tool': 'sslscan', 'type': 'tls10_enabled',
            'title': 'TLS 1.0 enabled', 'evidence': 'TLS 1.0 is enabled',
            'severity': 'High', 'cvss': 0.0, 'target': 'example.com',
            'found_by': ['ssl_tls'],
        }]
        result = aggregate([flood, other])
        assert result['total'] < 10  # collapsed to a handful of findings, not 4637
        assert all('finding_id' in f for f in result['findings'])

    def test_finding_ids_are_unique_and_sequential(self):
        findings = [_enum_finding(i, status=200 + (i % 3)) for i in range(3)]
        result = aggregate([findings])
        ids = [f['finding_id'] for f in result['findings']]
        assert len(ids) == len(set(ids))
        assert ids == [f'f{i}' for i in range(len(ids))]

    def test_exact_duplicate_across_modules_still_merges_found_by(self):
        f1 = {'module': 'zap', 'tool': 'zap', 'type': 'zap_1', 'title': 'X',
              'evidence': 'same evidence', 'severity': 'Medium', 'cvss': 5.0,
              'target': 'example.com', 'found_by': ['webscan']}
        f2 = dict(f1, module='nikto', found_by=['webscan'])
        result = aggregate([[f1], [f2]])
        assert result['total'] == 1
        assert set(result['findings'][0]['found_by']) == {'webscan'}


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
