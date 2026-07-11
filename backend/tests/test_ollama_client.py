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
    _TYPE_REMEDIATION, _GENERIC_REMEDIATION, _extract_target_profile, _looks_vague,
    _full_scan_stats, _coerce_to_text,
)
from analysis.cvss_scorer import _RULES

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
        # numbers - this is the actual defense against the clinkl.in-style
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

    def test_fallback_uses_deterministic_template_not_hallucinated_text(self):
        # Real bug found live (bwapp.local, during the AI+template pipeline
        # replay): this used to hardcode a placeholder description for every
        # finding here, discarding the perfectly good deterministic
        # description _generic_remediation() already has for it (type
        # template, OWASP-category template, or default) - the same
        # (description, remediation) pair _score_and_describe() already uses
        # for any finding that never reaches the AI batch. The scan-level
        # ai_unavailable flag - not per-finding placeholder text - is what
        # drives the report's "AI analysis unavailable" badge.
        findings = [_finding('f0'), _finding('f1', owasp_category='A02:2021 - Cryptographic Failures')]
        result = _rule_based_fallback(findings, 'example.com')

        assert result['ai_unavailable'] is True
        for fid, category in (('f0', 'A03:2021 - Injection'), ('f1', 'A02:2021 - Cryptographic Failures')):
            expected_description, expected_remediation = _GENERIC_REMEDIATION[category]
            desc = result['descriptions'][fid]['description']
            assert desc == expected_description
            assert desc != 'AI-generated description unavailable | see remediation and evidence below.'
            assert result['descriptions'][fid]['remediation'] == expected_remediation

    def test_fallback_uses_type_template_when_available(self):
        # A finding whose type has its own _TYPE_REMEDIATION entry must use
        # that exact (description, remediation) pair even in total-fallback
        # mode - it was never going to need Ollama in the first place
        # (analyse() excludes templated types from the AI batch entirely),
        # so an Ollama outage must not cost it its guaranteed-concrete text.
        finding = _finding('f0')
        finding['type'] = 'missing_hsts'
        result = _rule_based_fallback([finding], 'example.com')

        expected_description, expected_remediation = _TYPE_REMEDIATION['missing_hsts']
        assert result['descriptions']['f0']['description'] == expected_description
        assert result['descriptions']['f0']['remediation'] == expected_remediation

    def test_fallback_remediation_is_category_specific(self):
        injection = _generic_remediation(_finding('f0', owasp_category='A03:2021 - Injection'))
        crypto = _generic_remediation(_finding('f1', owasp_category='A02:2021 - Cryptographic Failures'))
        unknown = _generic_remediation(_finding('f2', owasp_category='Some Unmapped Category'))
        assert injection != crypto
        assert unknown[1]  # default template is non-empty

    def test_collapsed_fingerprint_finding_gets_accurate_description_not_category_template(self):
        """
        Real bug found live (user-reported against clinkl.in, an approved
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


class TestTypeRemediationCompleteness:
    """
    Guards against the exact bug class this file was written to catch: a
    finding type that cvss_scorer.py scores correctly but ollama_client.py
    has no dedicated template for, silently falling through to vague
    generic/default text. Real-world case that motivated this: seven types
    in enumeration.py/webscan.py (exposed_admin_panel_denied,
    exposed_path_401/403/301/302/201, crawled_endpoint_katana,
    js_hidden_endpoints) were scored correctly by cvss_scorer.py's _RULES
    but had no _TYPE_REMEDIATION entry.
    """

    # Types intentionally excluded from this check, each for a documented
    # reason (mirrors the exclusions already documented in ollama_client.py
    # itself, lines 175-177):
    #   - nikto_finding: open-ended, tool-generated per-instance text -
    #     deliberately still routed to the LLM, never templated.
    #   - directory_listing_enabled: not a real finding.type - it's an
    #     internal-only key cvss_scorer.py's _resolve_vector() uses to pick
    #     a vector for certain nikto_finding text matches; no module ever
    #     writes this into a finding dict via normalize_finding().
    #   - sqli_time_based / xss_stored / path_traversal_suspected /
    #     no_ocsp_stapling: explicit "not yet emitted - forward-compat"
    #     entries in cvss_scorer.py's _RULES - registered for a future
    #     module that doesn't exist yet, so there's nothing real to
    #     template today.
    #   - exposed_sensitive_file_denied: classified by enumeration.py's
    #     _classify() but always dropped by a `continue` before being
    #     appended to findings (no verbosity flag exists yet to opt back
    #     in) - scored defensively in cvss_scorer.py, but can never appear
    #     in a real report today.
    _NOT_APPLICABLE = {
        'nikto_finding',
        'directory_listing_enabled',
        'sqli_time_based',
        'xss_stored',
        'path_traversal_suspected',
        'no_ocsp_stapling',
        'exposed_sensitive_file_denied',
    }

    def test_every_scored_emitted_type_has_a_remediation_template(self):
        scored_types = set(_RULES.keys()) - self._NOT_APPLICABLE
        missing = sorted(scored_types - set(_TYPE_REMEDIATION.keys()))
        assert not missing, (
            f'{missing} are scored by cvss_scorer.py but have no '
            f'_TYPE_REMEDIATION entry in ollama_client.py - they will '
            f'silently fall back to vague generic/category text.'
        )

    # No inverse "every _TYPE_REMEDIATION key must be in _RULES" check here:
    # cvss_scorer.py deliberately scores several _TYPE_REMEDIATION-covered
    # types through mechanisms other than a literal _RULES entry - the
    # dns_*_record family and exposed_path_201 fall through to its
    # documented "unknown type" band-vector fallback (still a valid,
    # deterministic score, see _resolve_vector()'s final branch), and
    # whois_expiry is scored via _TRUST_SOURCE_TYPES instead. None of that
    # makes their remediation template stale.


class TestTypeRemediationExcludedFromLLM:

    def test_templated_type_never_sent_to_ollama(self):
        templated = _finding('f0', priority=1)
        templated['type'] = 'missing_hsts'  # a real _TYPE_REMEDIATION key
        untemplated = _finding('f1', priority=2)
        untemplated['type'] = 'some_type_with_no_template'

        with patch('analysis.ollama_client._call_ollama') as mock_call:
            mock_call.return_value = {'executive_summary': 'ok', 'findings': []}
            analyse([templated, untemplated], 'example.com')

        shaped_arg = mock_call.call_args[0][0]
        sent_ids = {f['finding_id'] for f in shaped_arg}
        assert 'f0' not in sent_ids
        assert 'f1' in sent_ids

    def test_templated_type_gets_its_fixed_text_via_fallback_path(self):
        finding = _finding('f0')
        finding['type'] = 'missing_hsts'
        _, remediation = _generic_remediation(finding)
        assert remediation == _TYPE_REMEDIATION['missing_hsts'][1]


class TestTypeRemediationQuality:

    _BARE_VAGUE_STARTS = ('review', 'ensure', 'verify', 'check that')

    def test_no_template_opens_with_a_bare_vague_instruction(self):
        # Mirrors the instruction _SYSTEM_PROMPT already gives the LLM
        # (never open with "review"/"ensure"/"verify" and stop there) -
        # hand-written templates should hold themselves to the same bar.
        offenders = []
        for ftype, (_, remediation) in _TYPE_REMEDIATION.items():
            first_word_area = remediation.strip().lower()
            # Strip a leading "1) " / "No action" style prefix before
            # checking - only flag a genuinely bare, action-less opener.
            stripped = first_word_area.split(') ', 1)[-1]
            if any(stripped.startswith(w) for w in self._BARE_VAGUE_STARTS):
                offenders.append(ftype)
        assert not offenders, f'Vague opening remediation text for: {offenders}'

    def test_every_template_has_nonempty_description_and_remediation(self):
        empty = [
            ftype for ftype, (desc, rem) in _TYPE_REMEDIATION.items()
            if not desc.strip() or not rem.strip()
        ]
        assert not empty, f'Empty description/remediation for: {empty}'


class TestTargetProfile:

    def test_extracts_server_framework_waf_and_technologies(self):
        findings = [
            _finding('f0'), {'type': 'waf_detected', 'waf_name': 'Cloudflare'},
            {'type': 'server_version_exposed', 'server_value': 'nginx/1.18.0'},
            {'type': 'x_powered_by_exposed', 'powered_by_value': 'Express'},
            {'type': 'tech_detected', 'technology': 'WordPress', 'version': '6.2'},
        ]
        profile = _extract_target_profile(findings)
        assert profile['waf'] == 'Cloudflare'
        assert profile['server'] == 'nginx/1.18.0'
        assert profile['framework'] == 'Express'
        assert profile['technologies'] == ['WordPress 6.2']

    def test_empty_findings_give_empty_profile(self):
        assert _extract_target_profile([_finding('f0')]) == {}

    def test_whatweb_metadata_plugins_excluded_as_noise(self):
        # Real bug found regenerating oa.iitk.ac.in/clinkl.in: WhatWeb fires
        # dozens of these per scan and they used to fill the technologies
        # list ahead of anything actually useful.
        findings = [
            {'type': 'tech_detected', 'technology': 'Country'},
            {'type': 'tech_detected', 'technology': 'IP'},
            {'type': 'tech_detected', 'technology': 'Apache'},
        ]
        profile = _extract_target_profile(findings)
        assert profile['technologies'] == ['Apache']

    def test_httpserver_plugin_unwraps_real_value_from_evidence(self):
        # Real bug found on clinkl.in: technology='HTTPServer' is a generic
        # plugin label, the actual server name ("Vercel") is inside evidence.
        findings = [{'type': 'tech_detected', 'technology': 'HTTPServer',
                     'evidence': '{"string": ["Vercel"]}'}]
        profile = _extract_target_profile(findings)
        assert profile['technologies'] == ['Vercel']

    def test_httpserver_plugin_with_unparseable_evidence_is_dropped(self):
        findings = [{'type': 'tech_detected', 'technology': 'HTTPServer', 'evidence': 'not json'}]
        assert _extract_target_profile(findings) == {}

    def test_profile_is_sent_to_ollama(self):
        findings = [_finding('f0'), {'type': 'waf_detected', 'waf_name': 'Sucuri'}]
        with patch('analysis.ollama_client._call_ollama') as mock_call:
            mock_call.return_value = {'executive_summary': 'ok', 'findings': []}
            analyse(findings, 'example.com')
        sent_profile = mock_call.call_args[0][3]
        assert sent_profile == {'waf': 'Sucuri'}


class TestVaguenessGate:

    def test_bare_review_instruction_is_vague(self):
        assert _looks_vague('Review the configuration.')
        assert _looks_vague('1) Ensure the setting is correct.')

    def test_concrete_instruction_is_not_vague(self):
        assert not _looks_vague(
            '1) Add `Strict-Transport-Security: max-age=31536000` to nginx config. '
            '2) Restart nginx.'
        )

    def test_empty_remediation_is_vague(self):
        assert _looks_vague('')
        assert _looks_vague(None)

    def test_vague_ollama_output_falls_back_to_generic_template(self):
        findings = [_finding('f0', owasp_category='A02:2021 - Cryptographic Failures')]
        with patch('analysis.ollama_client._call_ollama') as mock_call:
            mock_call.return_value = {
                'executive_summary': 'ok',
                'findings': [{'finding_id': 'f0', 'description': 'd0',
                              'remediation': 'Review the finding and verify it is fixed.'}],
            }
            result = analyse(findings, 'example.com')
        expected_remediation = _generic_remediation(findings[0])[1]
        assert result['descriptions']['f0']['remediation'] == expected_remediation
        assert result['descriptions']['f0']['description'] == 'd0'  # description untouched

    def test_concrete_ollama_output_is_kept_as_is(self):
        findings = [_finding('f0')]
        concrete = '1) Add X-Frame-Options: DENY to nginx config. 2) Restart nginx.'
        with patch('analysis.ollama_client._call_ollama') as mock_call:
            mock_call.return_value = {
                'executive_summary': 'ok',
                'findings': [{'finding_id': 'f0', 'description': 'd0', 'remediation': concrete}],
            }
            result = analyse(findings, 'example.com')
        assert result['descriptions']['f0']['remediation'] == concrete


class TestFullScanStats:

    def test_counts_by_severity(self):
        findings = [_finding('f0', severity='Critical'), _finding('f1', severity='Critical'),
                    _finding('f2', severity='Low')]
        stats = _full_scan_stats(findings)
        assert stats == {'total_findings': 3, 'counts_by_severity': {'Critical': 2, 'Low': 1}}

    def test_stats_reflect_full_list_even_when_all_findings_are_templated(self):
        """
        Real bug found live against clinkl.in: a 38-finding scan where every
        real finding had its own fixed template left only one leftover
        non-vulnerability meta finding as the sole input to the AI - the
        executive_summary described the whole scan as "a single low-
        severity issue". scan_stats must reflect all 38 regardless of how
        many get excluded from the AI batch as separately-templated.
        """
        findings = [_finding(f'f{i}', severity='Low') for i in range(37)]
        for f in findings:
            f['type'] = 'missing_hsts'  # a real _TYPE_REMEDIATION key
        findings.append({'finding_id': 'f37', 'type': 'testssl_scanTime',
                          'severity': 'Informational', 'priority': 5})

        with patch('analysis.ollama_client._call_ollama') as mock_call:
            mock_call.return_value = {'executive_summary': 'ok', 'findings': []}
            analyse(findings, 'example.com')

        sent_stats = mock_call.call_args[0][4]
        assert sent_stats['total_findings'] == 38


class TestTestsslScanTimeTemplate:

    def test_scantime_has_a_template_and_is_informational_toned(self):
        assert 'testssl_scanTime' in _TYPE_REMEDIATION
        description, remediation = _TYPE_REMEDIATION['testssl_scanTime']
        assert "isn't a vulnerability" in description.lower()

    def test_scantime_excluded_from_ai_batch(self):
        findings = [_finding('f0'), {'finding_id': 'f1', 'type': 'testssl_scanTime',
                                      'severity': 'Informational', 'priority': 5}]
        with patch('analysis.ollama_client._call_ollama') as mock_call:
            mock_call.return_value = {'executive_summary': 'ok', 'findings': []}
            analyse(findings, 'example.com')
        sent_ids = {f['finding_id'] for f in mock_call.call_args[0][0]}
        assert 'f1' not in sent_ids


class TestCoerceToText:

    def test_list_joined_with_newlines(self):
        # Real bug found live: Qwen returned remediation as a JSON array of
        # step strings; the report template's plain {{ finding.remediation
        # }} rendered raw Python-list syntax (brackets, quotes) into the PDF.
        assert _coerce_to_text(['1) Do X.', '2) Do Y.']) == '1) Do X.\n2) Do Y.'

    def test_string_passed_through_unchanged(self):
        assert _coerce_to_text('1) Do X. 2) Do Y.') == '1) Do X. 2) Do Y.'

    def test_none_becomes_empty_string(self):
        assert _coerce_to_text(None) == ''


class TestMalformedOllamaFindingsItem:

    def test_non_dict_item_skipped_not_fatal_to_whole_batch(self):
        # Real crash found live: 'str' object has no attribute 'get' when
        # one item in Ollama's returned findings array wasn't a dict -
        # took down descriptions for the entire batch, not just that item.
        findings = [_finding('f0'), _finding('f1')]
        with patch('analysis.ollama_client._call_ollama') as mock_call:
            mock_call.return_value = {
                'executive_summary': 'ok',
                'findings': [
                    {'finding_id': 'f0', 'description': 'd0', 'remediation': 'r0'},
                    'a malformed string item, not a dict',
                ],
            }
            result = analyse(findings, 'example.com')
        assert result['ai_unavailable'] is False
        assert result['descriptions']['f0'] == {'description': 'd0', 'remediation': 'r0'}
        assert 'f1' not in result['descriptions']  # simply not described, not a crash


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
