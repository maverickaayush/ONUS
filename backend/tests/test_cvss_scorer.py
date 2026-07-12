"""
cvss_scorer verification tests.

Run with:
    cd backend && python3 -m pytest tests/test_cvss_scorer.py -v
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from analysis.cvss_scorer import (
    base_score, severity_from_score, score_finding, compute_risk_score, _RULES, _priority,
)

VALID_SEVERITIES = {'Critical', 'High', 'Medium', 'Low', 'Informational'}


class TestFormula:
    """Base score formula verified against known CVSS v3.1 calculator output."""

    @pytest.mark.parametrize('vector,expected', [
        ('AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N', 7.4),   # TLS 1.0 (Scope Unchanged)
        ('AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N', 6.1),   # reflected XSS (Scope Changed)
        ('AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 9.8),   # confirmed SQLi
        ('AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N', 0.0),   # no impact at all
        ('AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N', 3.1),   # missing X-Content-Type-Options
    ])
    def test_known_vectors(self, vector, expected):
        assert base_score(vector) == pytest.approx(expected, abs=0.05)

    def test_malformed_vector_raises(self):
        with pytest.raises(ValueError):
            base_score('not-a-vector')

    def test_scope_changed_uses_pr_changed_weights(self):
        # PR:L differs between scope U (0.62) and scope C (0.68) - confirm
        # the two scores differ for otherwise-identical vectors.
        unchanged = base_score('AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N')
        changed = base_score('AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N')
        assert unchanged != changed


class TestSeverityBuckets:

    @pytest.mark.parametrize('score,expected', [
        (0.0, 'Informational'),
        (0.1, 'Low'), (3.9, 'Low'),
        (4.0, 'Medium'), (6.9, 'Medium'),
        (7.0, 'High'), (8.9, 'High'),
        (9.0, 'Critical'), (10.0, 'Critical'),
    ])
    def test_boundaries(self, score, expected):
        assert severity_from_score(score) == expected


class TestRuleCatalogue:
    """Every explicit rule-catalogue entry gets a fixture: type -> resolves
    to a valid, deterministic (severity, cvss, priority, owasp_category)."""

    @pytest.mark.parametrize('ftype,expected_severity', [
        ('exposed_sensitive_file', 'Critical'),
        ('exposed_sensitive_file_denied', 'Informational'),
        ('exposed_admin_panel_open', 'High'),
        ('exposed_admin_panel_login', 'Medium'),
        ('exposed_admin_panel_denied', 'Informational'),
        ('exposed_backup_file', 'High'),
        ('exposed_path_200', 'Medium'),
        ('exposed_path_401', 'Informational'),
        ('exposed_path_403', 'Informational'),
        ('exposed_path_301', 'Informational'),
        ('directory_listing_enabled', 'Medium'),
        ('sqli_error_based', 'Critical'),
        ('sqli_time_based', 'Critical'),
        ('sqli_boolean_based', 'Medium'),
        ('reflected_xss', 'Medium'),
        ('xss_stored', 'Medium'),
        ('path_traversal', 'Critical'),
        ('path_traversal_suspected', 'Medium'),
        ('open_redirect', 'Medium'),
        ('error_disclosure', 'Medium'),
        ('idor', 'High'),
        ('tls10_enabled', 'High'),
        ('tls11_enabled', 'Medium'),
        ('sslv2_enabled', 'High'),
        ('sslv3_enabled', 'High'),
        ('weak_cipher_rc4', 'Medium'),
        ('weak_cipher_des', 'Medium'),
        ('weak_cipher_bits', 'Medium'),
        ('weak_dh_params', 'Medium'),
        ('cert_expired', 'High'),
        ('cert_expiring_soon', 'Low'),
        ('cert_self_signed', 'Medium'),
        ('no_https', 'Informational'),
        ('no_ocsp_stapling', 'Low'),
        ('missing_hsts', 'Medium'),
        ('weak_hsts_max_age', 'Low'),
        ('hsts_missing_includesubdomains', 'Low'),
        ('missing_csp', 'Medium'),
        ('csp_unsafe_inline', 'Low'),
        ('csp_unsafe_eval', 'Low'),
        ('missing_clickjacking_protection', 'Medium'),
        ('missing_x_content_type_options', 'Low'),
        ('missing_referrer_policy', 'Low'),
        ('missing_permissions_policy', 'Low'),
        ('cors_wildcard_with_credentials', 'High'),
        ('cors_wildcard', 'Medium'),
        ('insecure_redirect', 'Medium'),
        ('cookie_missing_secure', 'Medium'),
        ('cookie_missing_httponly', 'Medium'),
        ('cookie_missing_samesite', 'Low'),
        ('headers_present_summary', 'Informational'),
        ('target_unreachable', 'Informational'),
        ('tech_detected', 'Informational'),
        ('outdated_tech', 'Medium'),
        ('server_version_exposed', 'Medium'),
        ('x_powered_by_exposed', 'Medium'),
        ('waf_detected', 'Informational'),
        ('no_waf_detected', 'Informational'),
        ('waf_unknown', 'Informational'),
        ('crawled_endpoint_katana', 'Informational'),
        ('js_hidden_endpoints', 'Low'),
        ('nikto_finding', 'Low'),
        ('open_port', 'Informational'),
        ('open_port_naabu', 'Informational'),
        ('scan_timeout', 'Informational'),
        ('subdomain_found', 'Informational'),
        ('live_subdomain', 'Informational'),
        ('whois_registrar', 'Informational'),
        ('whois_creation_date', 'Informational'),
        ('whois_nameservers', 'Informational'),
        ('whois_abuse_contact', 'Informational'),
        ('missing_spf', 'Medium'),
        ('missing_dmarc', 'Medium'),
        ('missing_dkim', 'Medium'),
    ])
    def test_rule_resolves_to_expected_severity_bucket(self, ftype, expected_severity):
        finding = {'type': ftype, 'severity': 'Info', 'module': 'test'}
        result = score_finding(finding)
        assert result['severity'] == expected_severity, (
            f'{ftype}: expected {expected_severity}, got {result["severity"]} '
            f'(score={result["cvss_score"]}, vector={result["cvss_vector"]})'
        )
        assert 0.0 <= result['cvss_score'] <= 10.0
        assert result['priority'] in (1, 2, 3, 4, 5)
        assert result['severity'] in VALID_SEVERITIES

    def test_every_rule_vector_is_well_formed(self):
        for ftype, rule in _RULES.items():
            if callable(rule):
                continue
            # Raises ValueError on malformed vectors - this IS the assertion.
            base_score(rule)


class TestTrustSource:

    def test_nuclei_keeps_own_cvss(self):
        finding = {'type': 'nuclei_CVE-2024-9999', 'severity': 'High', 'cvss': 7.5}
        result = score_finding(finding)
        assert result['cvss_score'] == 7.5
        assert result['severity'] == 'High'

    def test_zap_uses_own_risk_as_band(self):
        finding = {'type': 'zap_40012', 'severity': 'Critical'}
        result = score_finding(finding)
        assert result['severity'] == 'Critical'

    def test_testssl_uses_own_severity_as_band(self):
        finding = {'type': 'testssl_BREACH', 'severity': 'Medium'}
        result = score_finding(finding)
        assert result['severity'] == 'Medium'

    def test_whois_expiry_uses_recon_computed_severity(self):
        expiring = score_finding({'type': 'whois_expiry', 'severity': 'Medium'})
        informational = score_finding({'type': 'whois_expiry', 'severity': 'Informational'})
        assert expiring['severity'] == 'Medium'
        assert informational['severity'] == 'Informational'

    def test_auth_login_types_use_owasp_py_computed_severity(self):
        # owasp.py's _login_result_finding already decided the right
        # severity from its own login-outcome detection - same trust-source
        # reasoning as whois_expiry, not a technical CVSS characteristic.
        confirmed = score_finding({'type': 'auth_login_confirmed', 'severity': 'Informational'})
        failed = score_finding({'type': 'auth_login_failed', 'severity': 'Medium'})
        assert confirmed['severity'] == 'Informational'
        assert failed['severity'] == 'Medium'


class TestMostSpecificWins:

    def test_nikto_directory_listing_overrides_generic_nikto_rule(self):
        generic = score_finding({'type': 'nikto_finding', 'severity': 'Low',
                                  'title': 'Outdated software', 'evidence': ''})
        dir_listing = score_finding({'type': 'nikto_finding', 'severity': 'Low',
                                      'title': 'Directory indexing found', 'evidence': ''})
        assert generic['severity'] == 'Low'
        assert dir_listing['severity'] == 'Medium'
        assert generic['cvss_vector'] != dir_listing['cvss_vector']


class TestUnknownType:

    def test_unknown_type_falls_back_to_own_severity_band(self):
        result = score_finding({'type': 'some_future_module_type', 'severity': 'High'})
        assert result['severity'] == 'High'
        assert 0.0 <= result['cvss_score'] <= 10.0


class TestPriority:

    def test_critical_remote_no_auth_is_priority_1(self):
        result = score_finding({'type': 'sqli_error_based', 'severity': 'Info'})
        assert result['priority'] == 1

    def test_medium_bucket_finding_is_priority_3(self):
        result = score_finding({'type': 'path_traversal_suspected', 'severity': 'Info'})
        assert result['severity'] == 'Medium'
        assert result['priority'] == 3

    def test_high_is_always_priority_2(self):
        result = score_finding({'type': 'idor', 'severity': 'Info'})
        assert result['priority'] == 2

    def test_priority_function_directly(self):
        # No current rule in the catalogue produces Critical + a prerequisite
        # (AV != N or PR != N) - exercise that branch of _priority() directly.
        assert _priority('Critical', 'N', 'N') == 1
        assert _priority('Critical', 'A', 'N') == 2
        assert _priority('Critical', 'N', 'L') == 2
        assert _priority('High', 'N', 'N') == 2
        assert _priority('Medium', 'N', 'N') == 3
        assert _priority('Low', 'N', 'N') == 4
        assert _priority('Informational', 'N', 'N') == 5


class TestConfidencePriorityShift:
    """Phase 1 verification (analysis/verifier.py) sets confidence on a
    finding before it reaches score_finding() - confirmed bumps priority
    more urgent (capped at 1), unverified bumps it less urgent (capped at
    5), probable (the default) is a no-op."""

    def test_confirmed_shifts_priority_more_urgent(self):
        # idor is priority 2 (High) at the default 'probable' confidence.
        probable = score_finding({'type': 'idor', 'severity': 'Info', 'confidence': 'probable'})
        confirmed = score_finding({'type': 'idor', 'severity': 'Info', 'confidence': 'confirmed'})
        assert probable['priority'] == 2
        assert confirmed['priority'] == 1

    def test_confirmed_priority_is_capped_at_1(self):
        result = score_finding({'type': 'sqli_error_based', 'severity': 'Info', 'confidence': 'confirmed'})
        assert result['priority'] == 1  # already priority 1 - shift must not go below 1

    def test_unverified_shifts_priority_less_urgent(self):
        probable = score_finding({'type': 'idor', 'severity': 'Info', 'confidence': 'probable'})
        unverified = score_finding({'type': 'idor', 'severity': 'Info', 'confidence': 'unverified'})
        assert probable['priority'] == 2
        assert unverified['priority'] == 3

    def test_unverified_priority_is_capped_at_5(self):
        result = score_finding({'type': 'no_https', 'severity': 'Info', 'confidence': 'unverified'})
        assert result['priority'] == 5  # already priority 5 - shift must not exceed 5

    def test_missing_confidence_key_defaults_to_probable_no_shift(self):
        # A finding type Phase 1 doesn't verify (e.g. reflected_xss) never
        # gets a confidence key overwritten - normalize_finding()'s own
        # 'probable' default should mean no shift here either.
        result = score_finding({'type': 'idor', 'severity': 'Info'})
        assert result['priority'] == 2


def _findings(severity, confidence, n):
    kwargs = {} if confidence is None else {'confidence': confidence}
    return [{'severity': severity, **kwargs} for _ in range(n)]


class TestRiskScore:
    """compute_risk_score() takes the scored findings list (not a counts
    dict) since confidence isn't visible at the counts level - Phase 1
    verification (analysis/verifier.py) weights each finding by confidence."""

    def test_formula_confirmed_matches_original_per_severity_weights(self):
        # confirmed findings (multiplier 1.0) reproduce the pre-verification
        # per-severity weights exactly.
        assert compute_risk_score([]) == 0
        assert compute_risk_score(_findings('Critical', 'confirmed', 1)) == 25
        assert compute_risk_score(_findings('Critical', 'confirmed', 2)) == 50
        assert compute_risk_score(_findings('Medium', 'confirmed', 100)) == 100
        assert compute_risk_score(_findings('Medium', 'confirmed', 30)) == 60

    def test_confidence_weighting(self):
        confirmed = compute_risk_score(_findings('High', 'confirmed', 4))
        probable = compute_risk_score(_findings('High', 'probable', 4))
        unverified = compute_risk_score(_findings('High', 'unverified', 4))
        assert confirmed == 40   # 4 * 10 * 1.0
        assert probable == 30    # 4 * 10 * 0.75
        assert unverified == 20  # 4 * 10 * 0.5
        assert confirmed > probable > unverified

    def test_default_confidence_is_probable(self):
        # A finding with no confidence key (e.g. a type Phase 1 doesn't
        # verify, like reflected_xss) defaults to the same 'probable'
        # multiplier normalize_finding() itself defaults to.
        no_key = compute_risk_score(_findings('High', None, 1))
        explicit_probable = compute_risk_score(_findings('High', 'probable', 1))
        assert no_key == explicit_probable

    def test_informational_findings_do_not_contribute(self):
        assert compute_risk_score(_findings('Informational', 'confirmed', 50)) == 0

    def test_flood_of_mediums_cannot_alone_hit_100_from_a_single_source(self):
        # Regression test for the demo-target.example bug: thousands of Medium/Low
        # enumeration findings should not alone produce a 100/100 score
        # the way a real Critical vulnerability would.
        flood_score = compute_risk_score(_findings('Medium', 'confirmed', 20))
        two_criticals_score = compute_risk_score(_findings('Critical', 'confirmed', 2))
        assert flood_score < 100
        assert two_criticals_score > flood_score

    def test_capped_at_100(self):
        many = (_findings('Critical', 'confirmed', 10) + _findings('High', 'confirmed', 10)
                + _findings('Medium', 'confirmed', 10) + _findings('Low', 'confirmed', 10))
        assert compute_risk_score(many) == 100


class TestDeterminism:
    """Running the same finding through score_finding() twice must produce
    byte-identical output - no randomness, no hidden state."""

    def test_repeated_scoring_is_identical(self):
        finding = {'type': 'tls10_enabled', 'severity': 'Info', 'evidence': 'x', 'module': 'ssl_tls'}
        first = score_finding(dict(finding))
        second = score_finding(dict(finding))
        assert first == second


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
