import logging
from datetime import datetime
from typing import Optional
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
            'tech_fingerprint': 'queued',
            'nuclei': 'queued',
            'enumeration': 'queued',
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
    from tasks.tech_fingerprint import run_tech_fingerprint
    from tasks.nuclei_scan import run_nuclei
    from tasks.enumeration import run_enumeration

    scanning_group = group(
        run_recon.s(scan_id, domain),
        run_webscan.s(scan_id, domain),
        run_ssl_tls.s(scan_id, domain),
        run_headers.s(scan_id, domain),
        run_owasp.s(scan_id, domain),
        run_tech_fingerprint.s(scan_id, domain),
        run_nuclei.s(scan_id, domain),
        run_enumeration.s(scan_id, domain),
    )

    chord(scanning_group)(aggregate_and_analyse.s(scan_id, domain))


# Per-task limit raised from the global 300s/360s default. With Ollama's
# own timeout raised to 240s (see ollama_client.py - empirically measured
# 130.2s for a 23-finding scan), the default 300s soft limit left only
# ~50-60s of margin over Ollama + aggregation + PDF generation - too tight
# given GPU/network run-to-run variance. Same pattern as recon (600/660)
# and webscan (480/540): the module doing genuinely variable-duration work
# gets a deliberately generous ceiling.
@app.task(name='tasks.scan_orchestrator.aggregate_and_analyse',
          soft_time_limit=360, time_limit=420)
def aggregate_and_analyse(results: list, scan_id: str, domain: str) -> None:
    """
    Chord callback: called once all 8 scanning subtasks complete.
    results is a list of per-module result envelopes (base_task.py's
    build_module_result()): [{module, status, findings, tool_versions,
    finding_count, duration_seconds, error}, ...] - one per module,
    regardless of whether that module found anything.
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

        # --- Step 6: deterministic scoring, then AI description pass ---
        try:
            ai_result = _score_and_describe(aggregated, domain)
        except Exception as e:
            logger.error("Scoring/analysis failed for scan %s: %s", scan_id, e)
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


def _incomplete_modules_warning(module_execution: list) -> Optional[str]:
    """
    Deterministic warning line for the report's executive summary page -
    never left to the AI to decide whether to mention. A report that hides
    a failed/timed-out module is actively misleading about the target's
    security posture (the project docs Section 4.4).
    """
    incomplete = [m for m in module_execution if m.get('status') not in ('success', 'partial')]
    if not incomplete:
        return None
    return (
        f'Note: {len(incomplete)} of {len(module_execution)} scan modules did not '
        f'complete successfully. Results may be incomplete - see Technical Appendix.'
    )


def _score_and_describe(aggregated: dict, domain: str) -> dict:
    """
    Deterministic scoring (analysis/cvss_scorer.py) followed by an AI
    description pass (analysis/ollama_client.py). Numbers - severity, cvss,
    priority, owasp_category, risk_score - are computed here and never
    touched by Ollama; Ollama only ever supplies description/remediation/
    executive_summary prose (the project docs Section 4.5/4.6).
    """
    from analysis.cvss_scorer import score_finding, compute_risk_score
    from analysis.ollama_client import analyse, _generic_remediation

    findings = aggregated.get('findings', [])
    counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Informational': 0}

    for f in findings:
        f.update(score_finding(f))
        sev = f['severity'] if f['severity'] in counts else 'Informational'
        counts[sev] += 1

    risk_score = compute_risk_score(counts)

    ai_result = analyse(findings, domain)
    descriptions = ai_result.get('descriptions', {})
    for f in findings:
        d = descriptions.get(f.get('finding_id', ''))
        if d:
            f['description'] = d['description']
            f['remediation'] = d['remediation']
        else:
            # Ollama succeeded overall but this finding was beyond the
            # top-priority cutoff sent to it - no error, just not individually
            # described. No "AI unavailable" badge for these (that's reserved
            # for a real ai_unavailable failure, checked scan-wide below).
            description, remediation = _generic_remediation(f)
            f['description'] = description
            f['remediation'] = remediation

    findings.sort(key=lambda f: (f.get('priority', 5), -f.get('cvss_score', 0)))

    module_execution = aggregated.get('module_execution', [])

    return {
        'executive_summary': ai_result.get('executive_summary', ''),
        'risk_score': risk_score,
        'findings': findings,
        'total_critical': counts['Critical'],
        'total_high': counts['High'],
        'total_medium': counts['Medium'],
        'total_low': counts['Low'],
        'total_informational': counts['Informational'],
        'ai_unavailable': ai_result.get('ai_unavailable', False),
        'scan_metadata': aggregated.get('scan_metadata', {}),
        'module_execution': module_execution,
        'incomplete_modules_warning': _incomplete_modules_warning(module_execution),
    }


def _rule_based_fallback(aggregated: dict) -> dict:
    """
    Outer safety net used only if _score_and_describe() itself raises (e.g.
    cvss_scorer import fails) - analyse()/score_finding() already have their
    own internal fallbacks, so this path is a last resort, not the common
    failure mode.
    """
    from analysis.cvss_scorer import score_finding, compute_risk_score
    from analysis.ollama_client import _generic_remediation

    findings = aggregated.get('findings', [])
    counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Informational': 0}

    for f in findings:
        try:
            f.update(score_finding(f))
        except Exception:
            f.setdefault('severity', 'Informational')
            f.setdefault('cvss_score', 0.0)
            f.setdefault('priority', 5)
        sev = f.get('severity', 'Informational')
        counts[sev if sev in counts else 'Informational'] += 1
        description, remediation = _generic_remediation(f)
        f['description'] = description
        f['remediation'] = remediation

    risk_score = compute_risk_score(counts)
    findings.sort(key=lambda f: (f.get('priority', 5), -f.get('cvss_score', 0)))

    module_execution = aggregated.get('module_execution', [])

    return {
        'executive_summary': f'Rule-based analysis: {len(findings)} findings detected (AI analysis unavailable).',
        'risk_score': risk_score,
        'findings': findings,
        'total_critical': counts['Critical'],
        'total_high': counts['High'],
        'total_medium': counts['Medium'],
        'total_low': counts['Low'],
        'total_informational': counts['Informational'],
        'ai_unavailable': True,
        'scan_metadata': aggregated.get('scan_metadata', {}),
        'module_execution': module_execution,
        'incomplete_modules_warning': _incomplete_modules_warning(module_execution),
    }
