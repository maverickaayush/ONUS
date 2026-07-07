"""
ollama_client verification tests - descriptive-only prompt, fallback path,
finding_id-based merge, top-50 input shaping.

Run with:
    cd backend && python3 -m pytest tests/test_ollama_client.py -v
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
from unittest.mock import patch, MagicMock

import pytest
import requests

from analysis.ollama_client import (
    analyse, _rule_based_fallback, _generic_remediation, _shape_for_prompt, _SYSTEM_PROMPT,
)

FORBIDDEN_PROMPT_WORDS = ('cvss', 'severity', 'priority', 'risk_score')


def _finding(fid, owasp_category='A03:2021 - Injection', priority=1, severity='High'):
    return {
        'finding_id': fid, 'title': f'Finding {fid}', 'evidence': 'some evidence',
        'severity': severity, 'cvss_score': 7.5, 'priority': priority,
        'owasp_category': owasp_category, 'module': 'owasp',
    }


class TestSystemPrompt:

    def test_prompt_forbids_numeric_ratings(self):
        # The prompt text itself must instruct the model not to invent
        # numbers - this is the actual defense against the demo-target.example-style
        # bug recurring in AI-generated text. Normalize whitespace since the
        # verbatim spec text line-wraps mid-sentence.
        normalized = ' '.join(_SYSTEM_PROMPT.split())
        assert 'Do NOT mention CVSS scores' in normalized
        assert 'Do NOT invent numbers' in normalized

    def test_prompt_only_asks_for_prose_fields(self):
        assert '"description"' in _SYSTEM_PROMPT
        assert '"remediation"' in _SYSTEM_PROMPT
        assert '"executive_summary"' in _SYSTEM_PROMPT
        assert 'cvss_score' not in _SYSTEM_PROMPT.lower().replace('cvss scores', '')


class TestInputShaping:

    def test_shaped_findings_omit_authoritative_numbers(self):
        shaped = _shape_for_prompt([_finding('f0')])
        assert 'cvss_score' not in shaped[0]
        assert 'priority' not in shaped[0]
        assert shaped[0]['severity_hint'] == 'high'

    def test_only_top_50_sent_by_priority(self):
        findings = [_finding(f'f{i}', priority=(i % 5) + 1) for i in range(120)]
        with patch('analysis.ollama_client._call_ollama') as mock_call:
            mock_call.return_value = {'executive_summary': 'ok', 'findings': []}
            analyse(findings, 'example.com')
        shaped_arg = mock_call.call_args[0][0]
        overflow_arg = mock_call.call_args[0][1]
        assert len(shaped_arg) == 50
        assert overflow_arg == 70
        priorities_sent = [f['severity_hint'] for f in shaped_arg]
        assert len(priorities_sent) == 50


class TestSuccessPath:

    def test_descriptions_merged_by_finding_id(self):
        findings = [_finding('f0'), _finding('f1')]
        with patch('analysis.ollama_client._call_ollama') as mock_call:
            mock_call.return_value = {
                'executive_summary': 'All good.',
                'findings': [
                    {'finding_id': 'f0', 'description': 'd0', 'remediation': 'r0'},
                    {'finding_id': 'f1', 'description': 'd1', 'remediation': 'r1'},
                ],
            }
            result = analyse(findings, 'example.com')

        assert result['ai_unavailable'] is False
        assert result['descriptions']['f0'] == {'description': 'd0', 'remediation': 'r0'}
        assert result['descriptions']['f1'] == {'description': 'd1', 'remediation': 'r1'}

    def test_strips_emdashes(self):
        findings = [_finding('f0')]
        with patch('analysis.ollama_client._call_ollama') as mock_call:
            mock_call.return_value = {
                'executive_summary': 'Summary with an em—dash.',
                'findings': [{'finding_id': 'f0', 'description': 'd—0', 'remediation': 'r0'}],
            }
            result = analyse(findings, 'example.com')
        assert '—' not in result['executive_summary']
        assert '—' not in result['descriptions']['f0']['description']


class TestFallbackPath:

    def test_timeout_triggers_fallback_no_retry(self):
        findings = [_finding('f0')]
        with patch('analysis.ollama_client._call_ollama',
                    side_effect=requests.exceptions.Timeout) as mock_call:
            result = analyse(findings, 'example.com')
        assert mock_call.call_count == 1  # no retry on timeout
        assert result['ai_unavailable'] is True

    def test_connection_error_triggers_fallback_no_retry(self):
        findings = [_finding('f0')]
        with patch('analysis.ollama_client._call_ollama',
                    side_effect=requests.exceptions.ConnectionError) as mock_call:
            result = analyse(findings, 'example.com')
        assert mock_call.call_count == 1
        assert result['ai_unavailable'] is True

    def test_invalid_json_retries_then_falls_back(self):
        findings = [_finding('f0')]
        with patch('analysis.ollama_client._call_ollama',
                    side_effect=json.JSONDecodeError('bad', 'doc', 0)) as mock_call:
            result = analyse(findings, 'example.com')
        assert mock_call.call_count == 3  # 1 initial + 2 retries
        assert result['ai_unavailable'] is True

    def test_fallback_uses_placeholder_not_hallucinated_text(self):
        findings = [_finding('f0'), _finding('f1', owasp_category='A02:2021 - Cryptographic Failures')]
        result = _rule_based_fallback(findings, 'example.com')

        assert result['ai_unavailable'] is True
        for fid in ('f0', 'f1'):
            desc = result['descriptions'][fid]['description']
            assert desc == 'AI-generated description unavailable | see remediation and evidence below.'
            assert result['descriptions'][fid]['remediation']  # non-empty generic template

    def test_fallback_remediation_is_category_specific(self):
        injection = _generic_remediation(_finding('f0', owasp_category='A03:2021 - Injection'))
        crypto = _generic_remediation(_finding('f1', owasp_category='A02:2021 - Cryptographic Failures'))
        unknown = _generic_remediation(_finding('f2', owasp_category='Some Unmapped Category'))
        assert injection != crypto
        assert unknown[1]  # default template is non-empty

    def test_collapsed_fingerprint_finding_gets_accurate_description_not_category_template(self):
        """
        Real bug found live (user-reported against demo-target.example, an approved
        real target): a response-fingerprint-collapsed finding (aggregator's
        >5-identical-response collapse) inherits its owasp_category from
        whichever original finding was the group's first member, so it used
        to get a generic per-category template written for a single
        distinct vulnerability ("review this endpoint for unintended
        exposure") - misleading for "1311 paths all got the same blanket
        403." Must instead explain what a collapse actually means, keyed off
        the aggregator's own `details.matched_paths` marker rather than
        owasp_category.
        """
        collapsed = _finding('f0', owasp_category='A05:2021 - Security Misconfiguration')
        collapsed['details'] = {'matched_paths': ['/a', '/b', '/c']}
        description, remediation = _generic_remediation(collapsed)

        assert '3' in description
        assert 'catch-all' in description or 'blanket' in description
        assert 'separate findings' in description
        assert description != _generic_remediation(
            _finding('f1', owasp_category='A05:2021 - Security Misconfiguration'))[0]


class TestNeverRaises:

    def test_unexpected_exception_still_returns_fallback_shape(self):
        findings = [_finding('f0')]
        with patch('analysis.ollama_client._call_ollama', side_effect=RuntimeError('boom')):
            result = analyse(findings, 'example.com')
        assert result['ai_unavailable'] is True
        assert 'descriptions' in result
        assert 'executive_summary' in result


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
