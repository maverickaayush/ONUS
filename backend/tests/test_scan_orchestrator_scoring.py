"""
Full-pipeline determinism check for _score_and_describe (aggregate -> score
-> describe). Verification requirement: running the same raw findings
through the pipeline twice must produce byte-identical severity/cvss/
priority/risk_score - only description/remediation/executive_summary may
differ (and in these tests, Ollama is mocked out entirely, so even those
are identical).

Run with:
    cd backend && python3 -m pytest tests/test_scan_orchestrator_scoring.py -v
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unittest.mock import patch
import pytest

from analysis.aggregator import aggregate

DETERMINISTIC_FIELDS = ('severity', 'cvss_score', 'cvss_vector', 'priority', 'owasp_category')


def _raw_findings():
    enum_flood = [
        {
            'module': 'enumeration', 'tool': 'ffuf', 'type': 'exposed_path_403',
            'title': f'Path /{i} returned HTTP 403',
            'evidence': f'GET https://demo-target.example/{i} -> 403 (33810 bytes)',
            'severity': 'Informational', 'cvss': 0.0, 'target': 'demo-target.example',
            'found_by': ['enumeration'], 'http_status': 403, 'http_size': 33810,
        }
        for i in range(200)
    ]
    other = [
        {'module': 'ssl_tls', 'tool': 'sslscan', 'type': 'tls10_enabled',
         'title': 'TLS 1.0 enabled', 'evidence': 'TLS 1.0 is enabled',
         'severity': 'High', 'cvss': 0.0, 'target': 'demo-target.example', 'found_by': ['ssl_tls']},
        {'module': 'owasp', 'tool': 'owasp', 'type': 'sqli_error_based',
         'title': 'Potential SQL Injection', 'evidence': 'SQL error triggered',
         'severity': 'High', 'cvss': 0.0, 'target': 'demo-target.example', 'found_by': ['owasp']},
    ]
    return [enum_flood, other]


class TestPipelineDeterminism:

    def test_scoring_is_byte_identical_across_two_runs(self):
        from tasks.scan_orchestrator import _score_and_describe

        with patch('analysis.ollama_client.analyse') as mock_analyse:
            mock_analyse.return_value = {
                'executive_summary': 'Fixed summary for determinism test.',
                'descriptions': {}, 'ai_unavailable': True,
            }

            aggregated_1 = aggregate(_raw_findings())
            result_1 = _score_and_describe(aggregated_1, 'demo-target.example')

            aggregated_2 = aggregate(_raw_findings())
            result_2 = _score_and_describe(aggregated_2, 'demo-target.example')

        assert result_1['risk_score'] == result_2['risk_score']
        assert len(result_1['findings']) == len(result_2['findings'])

        for f1, f2 in zip(result_1['findings'], result_2['findings']):
            for field in DETERMINISTIC_FIELDS:
                assert f1[field] == f2[field], f'{field} differs: {f1[field]!r} vs {f2[field]!r}'

    def test_flood_does_not_produce_100_risk_score(self):
        """Direct regression test for the reported demo-target.example bug."""
        from tasks.scan_orchestrator import _score_and_describe

        with patch('analysis.ollama_client.analyse') as mock_analyse:
            mock_analyse.return_value = {
                'executive_summary': 'x', 'descriptions': {}, 'ai_unavailable': True,
            }
            aggregated = aggregate(_raw_findings())
            result = _score_and_describe(aggregated, 'demo-target.example')

        assert result['risk_score'] < 100
        assert len(result['findings']) < 20  # flood collapsed, not 202 findings


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
