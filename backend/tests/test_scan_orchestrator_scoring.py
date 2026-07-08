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
from analysis.verifier import verify_findings

DETERMINISTIC_FIELDS = ('severity', 'cvss_score', 'cvss_vector', 'priority', 'owasp_category')
VERIFICATION_DETERMINISTIC_FIELDS = DETERMINISTIC_FIELDS + ('confidence',)


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


def _raw_findings_with_verifiable():
    """One open_redirect finding carrying a verification_target, plus the
    baseline mix, so aggregate -> verify -> score exercises the full
    Phase 1 pipeline stage order (ARCHITECTURE.md: aggregate stays pure, verify
    is its own stage before scoring)."""
    findings, extra = _raw_findings()[0], _raw_findings()[1]
    verifiable = {
        'module': 'owasp', 'tool': 'owasp', 'type': 'open_redirect',
        'title': 'Open Redirect vulnerability', 'evidence': 'Parameter "next" redirects',
        'severity': 'Medium', 'cvss': 0.0, 'target': 'demo-target.example', 'found_by': ['owasp'],
        'confidence': 'probable', 'verifiable': True,
        'verification_target': {'url': 'https://demo-target.example', 'param': 'next',
                                 'payload': 'https://evil-vapt-test.example.com'},
    }
    return [findings, extra + [verifiable]]


class TestVerificationDeterminism:
    """analysis/verifier.py sits between aggregate() and score_finding() in
    _finalize() (scan_orchestrator.py). Running the same raw findings +
    the same (mocked) verification HTTP responses through the full
    aggregate -> verify -> score pipeline twice must produce byte-identical
    output, same guarantee as pre-verification determinism, now including
    the new `confidence` field."""

    def _mock_redirect_resp(self):
        from unittest.mock import MagicMock
        resp = MagicMock()
        resp.status_code = 302
        resp.headers = {'Location': 'https://evil-vapt-test.example.com/pwned'}
        return resp

    def test_enabled_true_is_byte_identical_across_two_runs(self):
        from tasks.scan_orchestrator import _score_and_describe

        with patch('analysis.ollama_client.analyse') as mock_analyse, \
             patch('analysis.verifier._DEFAULT_CLIENT.get', return_value=self._mock_redirect_resp()):
            mock_analyse.return_value = {
                'executive_summary': 'x', 'descriptions': {}, 'ai_unavailable': True,
            }

            aggregated_1 = aggregate(_raw_findings_with_verifiable())
            aggregated_1['findings'] = verify_findings(aggregated_1['findings'], enabled=True)
            result_1 = _score_and_describe(aggregated_1, 'demo-target.example')

            aggregated_2 = aggregate(_raw_findings_with_verifiable())
            aggregated_2['findings'] = verify_findings(aggregated_2['findings'], enabled=True)
            result_2 = _score_and_describe(aggregated_2, 'demo-target.example')

        assert result_1['risk_score'] == result_2['risk_score']
        assert len(result_1['findings']) == len(result_2['findings'])
        for f1, f2 in zip(result_1['findings'], result_2['findings']):
            for field in VERIFICATION_DETERMINISTIC_FIELDS:
                assert f1.get(field) == f2.get(field), \
                    f'{field} differs: {f1.get(field)!r} vs {f2.get(field)!r}'

        redirect = next(f for f in result_1['findings'] if f['type'] == 'open_redirect')
        assert redirect['confidence'] == 'confirmed'  # the mocked response reproduces it
        assert redirect['priority'] == 2  # Medium's base priority 3, shifted -1 for 'confirmed'

    def test_enabled_false_is_a_full_noop_on_confidence(self):
        """ENABLE_VERIFICATION=False must never touch the network and must
        leave every finding at its module-assigned baseline confidence."""
        aggregated = aggregate(_raw_findings_with_verifiable())
        with patch('analysis.verifier._DEFAULT_CLIENT.get') as mock_get:
            aggregated['findings'] = verify_findings(aggregated['findings'], enabled=False)
        mock_get.assert_not_called()
        redirect = next(f for f in aggregated['findings'] if f['type'] == 'open_redirect')
        assert redirect['confidence'] == 'probable'  # untouched
        assert 'verification_note' not in redirect


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
