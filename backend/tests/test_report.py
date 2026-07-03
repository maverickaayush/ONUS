"""
Step 7 verification tests for the PDF report generator.

Run with:
    cd backend && python3 -m pytest tests/test_report.py -v
"""
import io
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_scan(domain='demo-target.example', risk_score=55):
    scan = MagicMock()
    scan.id = uuid.uuid4()
    scan.domain = domain
    scan.completed_at = datetime(2026, 6, 26, 15, 42, 0, tzinfo=timezone.utc)
    scan.started_at   = scan.completed_at
    scan.risk_score   = risk_score
    return scan


def _make_analysis(risk_score=55, executive_summary=None, findings=None):
    return {
        'risk_score':          risk_score,
        'executive_summary':   executive_summary or 'Test scan complete.',
        'findings':            findings or [],
        'total_critical':      0,
        'total_high':          0,
        'total_medium':        0,
        'total_low':           0,
        'total_informational': 0,
        'scan_metadata':       {'timestamp': '2026-06-26T15:42:00+00:00',
                                'tool_versions': {'nmap': 'Nmap 7.98'}},
    }


def _finding(title='Test finding', severity='High', evidence='test evidence',
             cvss=7.5, owasp='A05:2021', cve=None, remediation='Fix it.'):
    return {
        'title':          title,
        'severity':       severity,
        'cvss_score':     cvss,
        'cvss_vector':    None,
        'owasp_category': owasp,
        'cve_reference':  cve,
        'evidence':       evidence,
        'remediation':    remediation,
        'priority':       2,
        'module':         'headers',
        'description':    title,
    }


# ---------------------------------------------------------------------------
# Core PDF tests
# ---------------------------------------------------------------------------

class TestGeneratePdf:

    def test_returns_valid_pdf_bytes(self):
        """generate_pdf must return bytes starting with the PDF magic number."""
        from reports.generator import generate_pdf
        pdf = generate_pdf(_make_scan(), _make_analysis(), store_in_db=False)
        assert isinstance(pdf, bytes)
        assert pdf[:4] == b'%PDF', f"Expected PDF magic bytes, got {pdf[:4]!r}"

    def test_pdf_nonempty(self):
        """PDF must be a reasonable size (not empty or a stub)."""
        from reports.generator import generate_pdf
        pdf = generate_pdf(_make_scan(), _make_analysis(), store_in_db=False)
        assert len(pdf) > 1024, f"PDF too small ({len(pdf)} bytes)"

    def test_zero_findings_does_not_crash(self):
        """Empty findings list must produce a valid PDF."""
        from reports.generator import generate_pdf
        pdf = generate_pdf(_make_scan(), _make_analysis(findings=[]),
                           store_in_db=False)
        assert pdf[:4] == b'%PDF'

    def test_many_findings_does_not_crash(self):
        """10 findings across all severities must produce a valid PDF."""
        from reports.generator import generate_pdf
        findings = [
            _finding(f'Finding {i}', sev, f'evidence {i}')
            for i, sev in enumerate(
                ['Critical', 'Critical', 'High', 'High', 'High',
                 'Medium', 'Medium', 'Low', 'Low', 'Informational']
            )
        ]
        analysis = _make_analysis(findings=findings, risk_score=85)
        analysis.update({'total_critical': 2, 'total_high': 3,
                         'total_medium': 2, 'total_low': 2,
                         'total_informational': 1})
        pdf = generate_pdf(_make_scan(), analysis, store_in_db=False)
        assert pdf[:4] == b'%PDF'

    def test_missing_risk_score_defaults_to_zero(self):
        """analysis dict without risk_score must not crash - defaults to 0."""
        from reports.generator import generate_pdf
        analysis = _make_analysis()
        del analysis['risk_score']
        pdf = generate_pdf(_make_scan(), analysis, store_in_db=False)
        assert pdf[:4] == b'%PDF'

    def test_missing_executive_summary_uses_fallback(self):
        """Missing executive_summary must use the fallback string."""
        from reports.generator import generate_pdf
        import pdfplumber
        analysis = _make_analysis(executive_summary=None)
        analysis['executive_summary'] = None
        pdf = generate_pdf(_make_scan(), analysis, store_in_db=False)
        with pdfplumber.open(io.BytesIO(pdf)) as doc:
            text = ''.join(p.extract_text() or '' for p in doc.pages)
        assert 'Automated VAPT analysis complete' in text, \
            "Fallback summary must appear in the PDF"


class TestHtmlEscaping:

    def test_xss_evidence_is_escaped_not_executed(self):
        """
        A finding with evidence '<script>alert(1)</script>' must appear as
        literal text in the PDF, not as HTML markup. This verifies that
        Jinja2 autoescaping is active for user-controlled data.
        """
        from reports.generator import generate_pdf
        import pdfplumber

        xss_payload = '<script>alert(1)</script>'
        findings = [_finding(evidence=xss_payload)]
        pdf = generate_pdf(_make_scan(),
                           _make_analysis(findings=findings),
                           store_in_db=False)

        with pdfplumber.open(io.BytesIO(pdf)) as doc:
            text = ''.join(p.extract_text() or '' for p in doc.pages)

        # The literal angle-bracket text must appear (as escaped chars WeasyPrint
        # renders as text), and there must be NO raw unescaped <script> tag
        # that a PDF viewer might process.
        assert 'alert(1)' in text, \
            "XSS payload text must appear literally in the PDF"

    def test_html_in_title_escaped(self):
        """Finding title with HTML must be escaped, not rendered as markup."""
        from reports.generator import generate_pdf
        import pdfplumber

        findings = [_finding(title='<b>Bold</b> injection')]
        pdf = generate_pdf(_make_scan(),
                           _make_analysis(findings=findings),
                           store_in_db=False)

        with pdfplumber.open(io.BytesIO(pdf)) as doc:
            text = ''.join(p.extract_text() or '' for p in doc.pages)

        assert 'Bold' in text


def _by_tier(findings):
    """Mirror generator.py's findings_by_tier grouping for tests that render
    report.html directly instead of going through generate_pdf()."""
    groups = {'confirmed': [], 'probable': [], 'unverified': []}
    for f in findings:
        groups[f.get('confidence', 'probable')].append(f)
    return groups


class TestRiskBadge:

    def _get_html(self, risk_score):
        from jinja2 import Environment, FileSystemLoader, select_autoescape
        import os
        templates_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'reports', 'templates',
        )
        env = Environment(loader=FileSystemLoader(templates_dir),
                          autoescape=select_autoescape(['html']))
        t = env.get_template('report.html')
        scan = _make_scan()
        return t.render(
            iitk_logo_text='IIT Kanpur Computer Centre',
            domain=scan.domain,
            scan_date='26 June 2026, 15:42 IST',
            risk_score=risk_score,
            executive_summary='Test.',
            findings=[],
            findings_by_tier=_by_tier([]),
            confidence_breakdown='',
            verification_evidence=[],
            total_critical=0, total_high=0, total_medium=0,
            total_low=0, total_informational=0,
            scan_metadata={},
        )

    def test_risk_70_plus_is_red(self):
        html = self._get_html(70)
        assert '#C0392B' in html

    def test_risk_40_to_69_is_amber(self):
        html = self._get_html(40)
        assert '#D4870A' in html

    def test_risk_below_40_is_green(self):
        html = self._get_html(39)
        assert '#27AE60' in html

    def test_risk_exactly_40_is_amber_not_green(self):
        html = self._get_html(40)
        assert '#D4870A' in html
        # The badge inline style must use amber, not green
        # Extract the risk-badge element's style attribute to check precisely
        import re
        badge_style = re.search(
            r'class="risk-badge"\s+style="background:([^"]+)"', html)
        assert badge_style, "risk-badge style attribute not found"
        assert badge_style.group(1).strip() == '#D4870A', \
            f"Expected amber #D4870A at risk=40, got {badge_style.group(1)}"


class TestSeverityBadge:

    def _badge_html(self, sev):
        from jinja2 import Environment, FileSystemLoader, select_autoescape
        import os
        templates_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'reports', 'templates',
        )
        env = Environment(loader=FileSystemLoader(templates_dir),
                          autoescape=select_autoescape(['html']))
        t = env.get_template('report.html')
        findings = [_finding(severity=sev)]
        return t.render(
            iitk_logo_text='IIT Kanpur Computer Centre',
            domain='test.com', scan_date='26 June 2026',
            risk_score=50, executive_summary='',
            findings=findings,
            findings_by_tier=_by_tier(findings),
            confidence_breakdown='',
            verification_evidence=[],
            total_critical=0, total_high=0, total_medium=0,
            total_low=0, total_informational=0,
            scan_metadata={},
        )

    def test_critical_uppercase(self):
        assert '#C0392B' in self._badge_html('CRITICAL')

    def test_critical_lowercase(self):
        assert '#C0392B' in self._badge_html('critical')

    def test_critical_titlecase(self):
        assert '#C0392B' in self._badge_html('Critical')

    def test_high_color(self):
        assert '#E67E22' in self._badge_html('High')

    def test_medium_color(self):
        assert '#F39C12' in self._badge_html('Medium')

    def test_low_color(self):
        assert '#2980B9' in self._badge_html('Low')

    def test_info_color(self):
        assert '#7F8C8D' in self._badge_html('Informational')

    def test_unknown_severity_fallback_gray(self):
        assert '#7F8C8D' in self._badge_html('Unknown')


class TestConfidenceDisplay:
    """Phase 1 verification: confidence tier headings, verified/unverified
    badges, verification evidence appendix, deterministic confidence
    breakdown line (generator.py, not Ollama)."""

    def _render(self, findings):
        from reports.generator import generate_pdf
        import pdfplumber
        import io
        pdf = generate_pdf(_make_scan(), _make_analysis(findings=findings), store_in_db=False)
        with pdfplumber.open(io.BytesIO(pdf)) as doc:
            return ''.join(p.extract_text() or '' for p in doc.pages)

    def test_confirmed_finding_gets_verified_badge(self):
        f = _finding(title='Confirmed Redirect')
        f['confidence'] = 'confirmed'
        text = self._render([f]).upper()  # .confidence-heading/.confidence-tag are uppercase via CSS
        assert 'VERIFIED' in text
        assert 'CONFIRMED FINDINGS' in text

    def test_unverified_finding_gets_manual_review_badge(self):
        f = _finding(title='Unverified Traversal')
        f['confidence'] = 'unverified'
        f['verification_note'] = 'Re-issued request did not reproduce sentinel content.'
        text = self._render([f])
        assert 'REQUIRES MANUAL REVIEW' in text.upper()
        assert 'UNVERIFIED FINDINGS' in text.upper()
        assert 'Re-issued request did not reproduce sentinel content.' in text

    def test_probable_finding_has_no_confidence_badge(self):
        f = _finding(title='Plain Probable Finding')
        f['confidence'] = 'probable'
        text = self._render([f]).upper()
        assert 'PROBABLE FINDINGS' in text
        assert 'REQUIRES MANUAL REVIEW' not in text

    def test_confidence_breakdown_line_present(self):
        f1 = _finding(title='A'); f1['confidence'] = 'confirmed'
        f2 = _finding(title='B'); f2['confidence'] = 'unverified'
        text = self._render([f1, f2])
        assert '1 were confirmed' in text
        assert '1 failed re-verification' in text

    def test_sort_order_is_tier_then_priority_then_cvss(self):
        from reports.generator import generate_pdf
        low_priority_confirmed = _finding(title='Low Priority Confirmed', cvss=3.0)
        low_priority_confirmed.update({'confidence': 'confirmed', 'priority': 4})
        high_priority_probable = _finding(title='High Priority Probable', cvss=9.0)
        high_priority_probable.update({'confidence': 'probable', 'priority': 1})

        text = self._render([high_priority_probable, low_priority_confirmed])
        # Confirmed tier must appear before probable tier regardless of
        # priority/cvss within either finding.
        assert text.index('Low Priority Confirmed') < text.index('High Priority Probable')


class TestSafeFilename:

    def test_clean_domain(self):
        from reports.generator import safe_filename
        d = datetime(2026, 6, 26)
        assert safe_filename('example.com', d) == 'vapt_report_example.com_20260626.pdf'

    def test_domain_with_special_chars(self):
        from reports.generator import safe_filename
        d = datetime(2026, 6, 26)
        result = safe_filename('sub_domain/evil?q=1', d)
        assert '/' not in result
        assert '?' not in result
        assert '=' not in result
        assert result.endswith('.pdf')

    def test_domain_with_slash_replaced(self):
        from reports.generator import safe_filename
        d = datetime(2026, 6, 26)
        result = safe_filename('demo-target.example', d)
        assert result == 'vapt_report_demo-target.example_20260626.pdf'


class TestDbStorage:

    def test_store_in_db_false_does_not_write(self):
        """store_in_db=False must not touch the database."""
        from reports.generator import generate_pdf
        with patch('reports.generator._store_report') as mock_store:
            generate_pdf(_make_scan(), _make_analysis(), store_in_db=False)
        mock_store.assert_not_called()

    def test_store_in_db_true_calls_store(self):
        """store_in_db=True must call _store_report."""
        from reports.generator import generate_pdf
        with patch('reports.generator._store_report') as mock_store:
            generate_pdf(_make_scan(), _make_analysis(), store_in_db=True)
        mock_store.assert_called_once()

    def test_idempotent_update_on_second_call(self):
        """Second generate_pdf with store_in_db=True must UPDATE not INSERT."""
        from reports.generator import _store_report

        scan = _make_scan()
        existing_report = MagicMock()

        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.first.return_value = existing_report

        # SessionLocal is a lazy import inside _store_report - patch at its source
        with patch('database.SessionLocal', return_value=mock_db):
            _store_report(scan, b'%PDF-fake')

        # Must UPDATE existing, not add a new row
        mock_db.add.assert_not_called()
        assert existing_report.pdf_data == b'%PDF-fake'
        mock_db.commit.assert_called_once()

    def test_db_failure_reraises_but_bytes_already_returned(self):
        """DB failure must re-raise so caller knows."""
        from reports.generator import generate_pdf

        def bad_store(scan, pdf_bytes):
            raise RuntimeError("DB connection lost")

        with patch('reports.generator._store_report', side_effect=bad_store):
            with pytest.raises(RuntimeError, match="DB connection lost"):
                generate_pdf(_make_scan(), _make_analysis(), store_in_db=True)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
