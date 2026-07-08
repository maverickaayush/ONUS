import logging
import os
import re
from datetime import datetime, timezone

import weasyprint
from jinja2 import Environment, FileSystemLoader, select_autoescape

logger = logging.getLogger(__name__)

_TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), 'templates')

# Confirmed first (re-verified proof), then probable (default/unverified-by-
# omission), then unverified (failed to reproduce) - matches the confidence
# tier heading order in the Findings Catalogue.
_CONFIDENCE_TIER_ORDER = {'confirmed': 0, 'probable': 1, 'unverified': 2}


def _confidence_breakdown_line(counts: dict, total: int) -> str:
    """Deterministic confidence-breakdown sentence for the executive summary
    page - computed here, not by Ollama (ARCHITECTURE.md Section 4.6: Ollama never
    produces or overrides numeric/countable claims)."""
    if total == 0:
        return ''
    return (
        f"Of {total} finding(s) in this report, {counts['confirmed']} were confirmed via automated "
        f"re-verification, {counts['probable']} are probable findings not yet re-verified, and "
        f"{counts['unverified']} failed re-verification and are flagged for manual review."
    )


def safe_filename(domain: str, date) -> str:
    """
    Build a safe PDF filename from domain + date.
    Replaces any char not in [a-zA-Z0-9.-] with underscore.
    Example: demo-target.example  ->  vapt_report_demo_target_example_20260626.pdf
    """
    if isinstance(date, datetime):
        date_str = date.strftime('%Y%m%d')
    else:
        date_str = str(date)
    safe_domain = re.sub(r'[^a-zA-Z0-9.\-]', '_', domain)
    return f'vapt_report_{safe_domain}_{date_str}.pdf'


def generate_pdf(scan, analysis: dict, store_in_db: bool = True) -> bytes:
    """
    Render report.html via Jinja2, convert to PDF with WeasyPrint, optionally
    persist a Report row in PostgreSQL (idempotent - updates existing row).

    Args:
        scan:        SQLAlchemy Scan ORM instance
        analysis:   dict from ollama_client.analyse() or rule-based fallback
        store_in_db: if False, skip DB write (for tests and preview endpoints)

    Returns:
        Raw PDF bytes (always, even on DB failure)
    """
    # Suppress WeasyPrint / fontTools logging noise
    logging.getLogger('weasyprint').setLevel(logging.ERROR)
    logging.getLogger('fontTools').setLevel(logging.ERROR)

    # --- Template rendering ---
    env = Environment(
        loader=FileSystemLoader(_TEMPLATES_DIR),
        autoescape=select_autoescape(['html', 'xml']),
    )
    template = env.get_template('report.html')

    risk_score = int(analysis.get('risk_score', 0) or 0)
    scan_date = scan.completed_at or scan.started_at or datetime.now(timezone.utc)
    if scan_date.tzinfo is None:
        scan_date = scan_date.replace(tzinfo=timezone.utc)

    findings = analysis.get('findings', [])
    # Findings catalogue order: confidence tier (confirmed -> probable ->
    # unverified), then priority ascending, then CVSS descending - priority,
    # cvss_score and confidence are all computed deterministically upstream
    # (analysis/cvss_scorer.py, analysis/verifier.py), never by Ollama.
    findings_sorted = sorted(
        findings,
        key=lambda f: (
            _CONFIDENCE_TIER_ORDER.get(f.get('confidence', 'probable'), 1),
            f.get('priority', 5),
            -(f.get('cvss_score') or 0),
        ),
    )
    grouped_findings = [f for f in findings_sorted if f.get('details', {}).get('matched_paths')]
    verification_evidence = [f for f in findings_sorted if f.get('verification_note')]

    confidence_counts = {'confirmed': 0, 'probable': 0, 'unverified': 0}
    for f in findings:
        tier = f.get('confidence', 'probable')
        confidence_counts[tier if tier in confidence_counts else 'probable'] += 1
    confidence_breakdown = _confidence_breakdown_line(confidence_counts, len(findings))

    findings_by_tier = {
        tier: [f for f in findings_sorted if f.get('confidence', 'probable') == tier]
        for tier in ('confirmed', 'probable', 'unverified')
    }

    context = {
        'iitk_logo_text': 'IIT Kanpur Computer Centre',
        'domain':          scan.domain,
        'scan_date':       scan_date.strftime('%-d %B %Y, %H:%M IST'),
        'risk_score':      risk_score,
        'executive_summary': (
            analysis.get('executive_summary') or
            'Automated VAPT analysis complete.'
        ),
        'findings':           findings_sorted,
        'findings_by_tier':   findings_by_tier,
        'confidence_breakdown': confidence_breakdown,
        'grouped_findings':   grouped_findings,
        'verification_evidence': verification_evidence,
        'ai_unavailable':     bool(analysis.get('ai_unavailable')),
        'total_critical':     analysis.get('total_critical', 0),
        'total_high':         analysis.get('total_high', 0),
        'total_medium':       analysis.get('total_medium', 0),
        'total_low':          analysis.get('total_low', 0),
        'total_informational': analysis.get('total_informational', 0),
        'scan_metadata':      analysis.get('scan_metadata', {}),
        'module_execution':   analysis.get('module_execution', []),
        'incomplete_modules_warning': analysis.get('incomplete_modules_warning'),
    }

    html = template.render(**context)

    # --- PDF generation ---
    pdf_bytes = weasyprint.HTML(string=html).write_pdf()
    logger.info("PDF generated for scan %s (%d bytes)", scan.id, len(pdf_bytes))

    # --- DB persistence (idempotent) ---
    if store_in_db:
        _store_report(scan, pdf_bytes)

    return pdf_bytes


def _store_report(scan, pdf_bytes: bytes) -> None:
    """Upsert a Report row. Logs and re-raises on failure."""
    from database import SessionLocal
    from models import Report

    db = SessionLocal()
    try:
        existing = db.query(Report).filter(Report.scan_id == scan.id).first()
        if existing:
            existing.pdf_data = pdf_bytes
            existing.generated_at = datetime.now(timezone.utc)
            logger.info("PDF report updated for scan %s", scan.id)
        else:
            db.add(Report(scan_id=scan.id, pdf_data=pdf_bytes))
            logger.info("PDF report created for scan %s", scan.id)
        db.commit()
    except Exception as e:
        db.rollback()
        logger.error("Failed to store report for scan %s: %s", scan.id, e)
        raise
    finally:
        db.close()
