import logging
from datetime import datetime
from celery import group, chord
from tasks.celery_app import app

logger = logging.getLogger(__name__)


@app.task(bind=True, name='tasks.scan_orchestrator.scan_orchestrator')
def scan_orchestrator(self, scan_id: str, domain: str) -> None:
    """
    Main Celery task: sets scan status to running, dispatches the five
    scanning subtasks as a parallel group, then fires aggregate_and_analyse
    as a chord callback once all five complete.
    """
    from database import SessionLocal
    from models import Scan, ScanStatus

    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            logger.error("scan_orchestrator: scan %s not found", scan_id)
            return
        scan.status = ScanStatus.running
        scan.started_at = datetime.utcnow()
        scan.module_statuses = {
            'recon': 'queued',
            'webscan': 'queued',
            'ssl_tls': 'queued',
            'headers': 'queued',
            'owasp': 'queued',
        }
        db.commit()
        logger.info("scan_orchestrator: scan %s started for %s", scan_id, domain)
    finally:
        db.close()

    # Import scanning tasks here to avoid circular imports at module load time.
    from tasks.recon import run_recon
    from tasks.webscan import run_webscan
    from tasks.ssl_tls import run_ssl_tls
    from tasks.headers import run_headers
    from tasks.owasp import run_owasp

    scanning_group = group(
        run_recon.s(scan_id, domain),
        run_webscan.s(scan_id, domain),
        run_ssl_tls.s(scan_id, domain),
        run_headers.s(scan_id, domain),
        run_owasp.s(scan_id, domain),
    )

    chord(scanning_group)(aggregate_and_analyse.s(scan_id, domain))


@app.task(name='tasks.scan_orchestrator.aggregate_and_analyse')
def aggregate_and_analyse(results: list, scan_id: str, domain: str) -> None:
    """
    Chord callback: called once all five scanning subtasks complete.
    results is a list of per-module finding lists:
    [[recon_findings], [webscan_findings], [ssl_tls_findings], ...]
    """
    from database import SessionLocal
    from models import Scan, Report, ScanStatus

    logger.info("aggregate_and_analyse: scan %s received %d module results", scan_id, len(results))

    db = SessionLocal()
    scan = None
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            logger.error("aggregate_and_analyse: scan %s not found", scan_id)
            return

        scan.status = ScanStatus.analysing
        db.commit()

        # --- Step 6: aggregate raw findings from all modules ---
        try:
            from analysis.aggregator import aggregate
            aggregated = aggregate(results)
            scan.raw_findings = aggregated
            db.commit()
        except Exception as e:
            logger.error("Aggregation failed for scan %s: %s", scan_id, e)
            aggregated = {'findings': [], 'total': 0}

        # --- Step 6: AI analysis via Ollama ---
        try:
            from analysis.ollama_client import analyse
            ai_result = analyse(aggregated, domain)
        except Exception as e:
            logger.error("Ollama analysis failed for scan %s: %s", scan_id, e)
            ai_result = _rule_based_fallback(aggregated)

        scan.ai_analysis = ai_result
        scan.risk_score = ai_result.get('risk_score', 0)
        db.commit()

        # --- Step 7: PDF report generation ---
        try:
            from reports.generator import generate_pdf
            pdf_bytes = generate_pdf(scan, ai_result)
            report = Report(scan_id=scan.id, pdf_data=pdf_bytes)
            db.add(report)
        except Exception as e:
            logger.error("PDF generation failed for scan %s: %s", scan_id, e)

        scan.status = ScanStatus.complete
        scan.completed_at = datetime.utcnow()
        db.commit()
        logger.info("aggregate_and_analyse: scan %s complete, risk_score=%s", scan_id, scan.risk_score)

    except Exception:
        logger.exception("aggregate_and_analyse: unhandled error for scan %s", scan_id)
        try:
            if scan is not None:
                scan.status = ScanStatus.failed
                db.commit()
        except Exception:
            pass
    finally:
        db.close()


def _rule_based_fallback(aggregated: dict) -> dict:
    """
    Minimal rule-based analysis used when Ollama is unavailable.
    Counts findings by severity and returns a bare-bones response shape
    matching the Ollama output schema so the rest of the pipeline doesn't break.
    """
    findings = aggregated.get('findings', [])
    severity_scores = {'Critical': 10, 'High': 7, 'Medium': 4, 'Low': 2, 'Info': 0, 'Informational': 0}
    counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Informational': 0}

    enriched = []
    for f in findings:
        sev = f.get('severity', 'Informational')
        counts[sev if sev in counts else 'Informational'] += 1
        enriched.append({
            'title': f.get('title', 'Unknown'),
            'description': f.get('title', ''),
            'severity': sev,
            'cvss_score': severity_scores.get(sev, 0.0),
            'cvss_vector': None,
            'owasp_category': f.get('owasp_category'),
            'cve_reference': None,
            'evidence': f.get('evidence', ''),
            'remediation': 'Review and remediate this finding per security best practices.',
            'priority': 1 if sev == 'Critical' else (2 if sev == 'High' else 3),
            'module': f.get('module', ''),
        })

    total = counts['Critical'] * 10 + counts['High'] * 7 + counts['Medium'] * 4 + counts['Low'] * 2
    risk_score = min(100, total)

    return {
        'executive_summary': f'Rule-based analysis: {len(findings)} findings detected (Ollama unavailable).',
        'risk_score': risk_score,
        'findings': enriched,
        'total_critical': counts['Critical'],
        'total_high': counts['High'],
        'total_medium': counts['Medium'],
        'total_low': counts['Low'],
        'total_informational': counts['Informational'],
    }
