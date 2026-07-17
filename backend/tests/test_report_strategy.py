"""Report-generation routing, managed-platform awareness, and honest testssl
classification. Covers the fixes for generic/misleading TLS wording:

- testssl capability/artefact lines classified honestly at the source
- false-Critical FS/KEM/sig-alg lines capped to Informational
- the 4-lane strategy router (template/inventory/hybrid/ai)
- managed-platform (Vercel/…) TLS findings never told to "edit server config"
- TLS-layer findings on a managed host are NOT sent to the LLM

Run: cd backend && python3 -m pytest tests/test_report_strategy.py -v
"""
import os
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analysis.ollama_client import (
    detect_platform, report_strategy, apply_platform_context, analyse,
    classify_actionability, _TYPE_REMEDIATION, _is_tls_layer,
    STRATEGY_TEMPLATE, STRATEGY_INVENTORY, STRATEGY_HYBRID, STRATEGY_AI,
    ACTION_DIRECT, ACTION_INDIRECT, ACTION_NONE,
)
from analysis.cvss_scorer import score_finding
from tasks.ssl_tls import _classify_testssl


def _f(**kw):
    base = {'finding_id': 'f0', 'type': 'x', 'title': 't', 'evidence': 'e',
            'severity': 'Medium', 'module': 'ssl_tls', 'priority': 3}
    base.update(kw)
    return base


# ── honest testssl classification (source) ───────────────────────────────────
class TestClassifyTestssl:
    def test_fs_sigalgs_is_capability_informational(self):
        # The exact false-Critical from the real report.
        assert _classify_testssl('FS_TLS12_sig_algs', 'FS_TLS12_sig_algs', 'CRITICAL') \
            == ('testssl_capability', 'Informational')
        assert _classify_testssl('FS_TLS13_sig_algs', 'x', 'HIGH') \
            == ('testssl_capability', 'Informational')
        assert _classify_testssl('FS_KEMs', 'No KEMs offered', 'MEDIUM') \
            == ('testssl_capability', 'Informational')

    def test_missing_extension_is_low(self):
        assert _classify_testssl('TLS_misses_extension_23', 'No extended master secret', 'MEDIUM') \
            == ('testssl_missing_extension', 'Low')

    def test_scantime_kept_informational(self):
        assert _classify_testssl('scanTime', '133', 'WARN') == ('testssl_scanTime', 'Informational')

    def test_stalled_test_is_dropped_artefact(self):
        # "BREACH: Test failed as first HTTP request stalled and was terminated"
        assert _classify_testssl('BREACH', 'Test failed as first HTTP request stalled and was terminated', 'LOW') is None

    def test_real_weak_protocol_keeps_grade(self):
        # A genuine weakness is NOT swept into capability - keeps testssl's grade.
        assert _classify_testssl('SSLv3', 'offered (NOT ok)', 'HIGH') == ('testssl_SSLv3', 'High')

    def test_passing_check_skipped(self):
        assert _classify_testssl('cipherlist_STRONG', 'offered', 'OK') is None


# ── false-Critical no longer scores Critical ─────────────────────────────────
class TestFalseCriticalFixed:
    def test_capability_scores_informational_not_critical(self):
        scored = score_finding(_f(type='testssl_capability', severity='Informational'))
        assert scored['severity'] == 'Informational'
        assert scored['cvss_score'] == 0.0


# ── managed-platform detection ───────────────────────────────────────────────
class TestDetectPlatform:
    def test_detects_vercel_from_tech_evidence(self):
        findings = [_f(type='tech_detected', technology='HTTPServer',
                       evidence='{"string": ["Vercel"]}')]
        assert detect_platform(findings) == 'Vercel'

    def test_detects_cloudflare_from_waf(self):
        assert detect_platform([_f(type='waf_detected', waf_name='Cloudflare')]) == 'Cloudflare'

    def test_none_when_no_platform(self):
        assert detect_platform([_f(type='tech_detected', technology='nginx', evidence='nginx')]) is None


# ── the 4-lane strategy router ───────────────────────────────────────────────
class TestReportStrategy:
    def test_inventory(self):
        assert report_strategy(_f(type='tech_detected')) == STRATEGY_INVENTORY
        assert report_strategy(_f(type='dns_a_record')) == STRATEGY_INVENTORY
        assert report_strategy(_f(type='testssl_capability')) == STRATEGY_INVENTORY

    def test_template(self):
        assert report_strategy(_f(type='missing_csp')) == STRATEGY_TEMPLATE

    def test_hybrid_only_on_managed_platform(self):
        tls = _f(type='testssl_missing_extension')
        assert report_strategy(tls, platform=None) in (STRATEGY_TEMPLATE, STRATEGY_INVENTORY)
        assert report_strategy(tls, platform='Vercel') == STRATEGY_HYBRID
        assert report_strategy(_f(type='weak_cipher_rc4'), platform='Vercel') == STRATEGY_HYBRID

    def test_ai_for_open_ended(self):
        assert report_strategy(_f(type='zap_xss')) == STRATEGY_AI
        assert report_strategy(_f(type='nikto_finding')) == STRATEGY_AI
        # a self-hosted (no platform) unknown testssl config -> AI
        assert report_strategy(_f(type='testssl_something_new'), platform=None) == STRATEGY_AI

    def test_header_finding_not_tls_layer(self):
        # headers ARE user-controllable on managed hosts - stay template, not hybrid
        assert report_strategy(_f(type='missing_csp'), platform='Vercel') == STRATEGY_TEMPLATE
        assert not _is_tls_layer('missing_csp')


# ── platform-aware remediation (HYBRID) ──────────────────────────────────────
class TestApplyPlatformContext:
    def test_tls_finding_gets_next_step_remediation(self):
        f = _f(type='testssl_missing_extension', description='No extended master secret.',
               remediation='1) Update the server configuration...')
        apply_platform_context(f, 'Vercel')
        rem = f['remediation'].lower()
        assert 'vercel' in rem
        # The whole point: it must END with a concrete NEXT STEP, not a dead end.
        assert 'next steps:' in rem
        assert 'documentation' in rem          # review platform docs
        assert 'contact vercel support' in rem  # escalate with evidence
        assert 'no further action is required' in rem  # accept-if-expected path
        # Not the old generic advice, and not a bare "you cannot configure this".
        assert 'update the server configuration' not in rem
        assert f['actionability'] == ACTION_INDIRECT
        assert 'Vercel' in f['description']

    def test_kind_phrase_differs_by_platform(self):
        edge = _f(type='testssl_missing_extension', remediation='x')
        apply_platform_context(edge, 'Vercel')       # edge
        paas = _f(type='testssl_missing_extension', remediation='x')
        apply_platform_context(paas, 'Render')       # paas
        assert 'edge network' in edge['remediation']
        assert 'hosting platform' in paas['remediation']

    def test_header_finding_untouched(self):
        original = '1) add the CSP header'
        f = _f(type='missing_csp', module='headers', remediation=original, description='no csp')
        apply_platform_context(f, 'Vercel')
        assert f['remediation'] == original  # user controls headers on managed hosts

    def test_noop_without_platform(self):
        original = '1) update tls config'
        f = _f(type='testssl_capability', remediation=original)
        apply_platform_context(f, None)
        assert f['remediation'] == original


# ── routing: TLS findings on a managed host never reach the LLM ──────────────
class TestManagedTlsNotSentToLLM:
    def test_tls_layer_excluded_from_ai_on_managed_platform(self):
        vercel_sig = [_f(type='tech_detected', technology='HTTPServer',
                         evidence='{"string": ["Vercel"]}', finding_id='plat')]
        tls = _f(type='testssl_capability', finding_id='tls', priority=1)
        openended = _f(type='zap_xss', finding_id='zap', priority=1)
        with patch('analysis.ollama_client._call_ollama') as mock_call:
            mock_call.return_value = {'executive_summary': 'ok', 'findings': []}
            analyse(vercel_sig + [tls, openended], 'clinkl.in')
        sent = {f['finding_id'] for f in mock_call.call_args[0][0]}
        assert 'tls' not in sent          # HYBRID - handled deterministically
        assert 'zap' in sent              # genuinely open-ended -> AI


# ── actionability tri-state model ────────────────────────────────────────────
class TestActionabilityModel:
    def test_direct_for_user_controlled(self):
        assert classify_actionability(_f(type='missing_csp')) == ACTION_DIRECT
        assert classify_actionability(_f(type='missing_dmarc')) == ACTION_DIRECT
        # headers stay directly actionable even on a managed host
        assert classify_actionability(_f(type='missing_csp'), 'Vercel') == ACTION_DIRECT

    def test_indirect_for_managed_tls(self):
        assert classify_actionability(_f(type='testssl_missing_extension'), 'Vercel') == ACTION_INDIRECT
        assert classify_actionability(_f(type='weak_cipher_rc4'), 'Cloudflare') == ACTION_INDIRECT

    def test_none_for_inventory(self):
        assert classify_actionability(_f(type='tech_detected')) == ACTION_NONE
        assert classify_actionability(_f(type='testssl_capability'), platform=None) == ACTION_NONE
        assert classify_actionability(_f(type='dns_a_record')) == ACTION_NONE

    def test_tiers_agree_with_router(self):
        # actionability must never disagree with the strategy router.
        for ftype, plat, expect in [
            ('missing_csp', None, ACTION_DIRECT),
            ('testssl_missing_extension', 'Vercel', ACTION_INDIRECT),
            ('testssl_capability', 'Vercel', ACTION_NONE),  # informational capability line
            ('tech_detected', None, ACTION_NONE),
            ('zap_xss', None, ACTION_DIRECT),
        ]:
            assert classify_actionability(_f(type=ftype), plat) == expect
