import glob
import logging
import os
import shutil
from datetime import datetime
from typing import Dict, List, Optional
from celery import group, chord
from tasks.celery_app import app
from tasks.base_task import SCAN_MODULE_IDS, scaled_timeout

logger = logging.getLogger(__name__)

# Section: operator pause/retry/continue/cancel decision flow. A module's
# status is only ever 'failed'/'timeout' here if it already ran to
# completion and reported that itself (base_task.py) - a hard SIGKILL that
# never reports back is a different, unrelated failure mode handled by the
# stuck-scan reaper in routers/scan.py, not by this flow.
MAX_RETRIES_PER_MODULE = 1


def _failed_modules(results: List[dict]) -> List[str]:
    return [r.get('module') for r in results
            if isinstance(r, dict) and r.get('status') not in ('success', 'partial')]


def _prune_zap_session(scan_id: str) -> None:
    """
    Delete this scan's ZAP session files (webscan.py's `zap.core.new_session(
    name=scan_id)` writes `{scan_id}.session*` + a `.session.tmp/` dir into
    the shared zap-sessions volume). Safe to run once the PDF is generated -
    the session data has already been fully consumed into `ai_analysis`, so
    keeping it around only costs disk (observed up to ~2.4GB for one heavy
    scan - see docs/test_findings.md's Metasploitable2 entries). No-op if
    ZAP_SESSIONS_DIR isn't configured (e.g. native dev without the shared
    volume) or the directory doesn't exist.
    """
    from config import settings
    sessions_dir = settings.ZAP_SESSIONS_DIR
    if not sessions_dir or not os.path.isdir(sessions_dir):
        return
    for entry in glob.glob(os.path.join(sessions_dir, f'{scan_id}.session*')):
        try:
            if os.path.isdir(entry):
                shutil.rmtree(entry)
            else:
                os.remove(entry)
        except OSError as e:
            logger.warning("Failed to prune ZAP session file %s for scan %s: %s",
                           entry, scan_id, e)


def _can_retry(failed_modules: List[str], retry_counts: Dict[str, int]) -> bool:
    """True only if every currently-failed module still has its one retry
    available - one retry per module, not per scan (see conversation with
    the operator: a module that fails again after its retry blocks Retry
    entirely, forcing Continue or Cancel)."""
    return all(retry_counts.get(m, 0) < MAX_RETRIES_PER_MODULE for m in failed_modules)


@app.task(bind=True, name='tasks.scan_orchestrator.scan_orchestrator')
def scan_orchestrator(self, scan_id: str, domain: str, mode: str = 'full') -> None:
    """
    Main Celery task: sets scan status to running, dispatches the scanning
    subtasks as a parallel group, then fires aggregate_and_analyse as a chord
    callback once all complete.

    `mode` selects the module set (base_task.module_ids_for_mode):
      'full'  -> all 8 active modules (the existing pipeline).
      'quick' -> passive-only profile (headers, ssl_tls, tech_fingerprint in
                 WhatWeb-only submode). NEVER dispatches nmap/naabu/ZAP/Nikto/
                 owasp-payloads/active-nuclei/ffuf.
    """
    from database import SessionLocal
    from models import Scan, ScanStatus
    from tasks.base_task import module_ids_for_mode

    module_ids = module_ids_for_mode(mode)

    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            logger.error("scan_orchestrator: scan %s not found", scan_id)
            return
        scan.status = ScanStatus.running
        scan.started_at = datetime.utcnow()
        scan.module_statuses = {module_id: 'queued' for module_id in module_ids}
        db.commit()
        logger.info("scan_orchestrator: scan %s started for %s (mode=%s)", scan_id, domain, mode)
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

    # Map module id -> its dispatch signature. Quick mode selects a strict
    # subset; tech_fingerprint runs WhatWeb-only (quick=True skips WAFW00F).
    quick = mode == 'quick'
    all_sigs = {
        'recon': run_recon.s(scan_id, domain),
        'webscan': run_webscan.s(scan_id, domain),
        'ssl_tls': run_ssl_tls.s(scan_id, domain),
        'headers': run_headers.s(scan_id, domain),
        'owasp': run_owasp.s(scan_id, domain),
        'tech_fingerprint': run_tech_fingerprint.s(scan_id, domain, quick),
        'nuclei': run_nuclei.s(scan_id, domain),
        'enumeration': run_enumeration.s(scan_id, domain),
    }
    scanning_group = group(*(all_sigs[m] for m in module_ids))

    try:
        chord(scanning_group)(aggregate_and_analyse.s(scan_id, domain))
    except Exception as e:
        # A transient broker (Redis) failure right here would otherwise leave
        # the scan at status='running' with zero modules actually dispatched -
        # nothing ever reports back, so this is invisible until the blunt
        # time-based STUCK_SCAN_DEADLINE reaper eventually catches it (~2500s+).
        # Fail fast instead, same pattern as routers/scan.py's create_scan()
        # handling scan_orchestrator.delay() failing to enqueue.
        logger.error("scan_orchestrator: failed to dispatch scanning group for scan %s: %s", scan_id, e)
        db = SessionLocal()
        try:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = ScanStatus.failed
                db.commit()
        finally:
            db.close()


# Per-task limit raised from the global 300s/360s default. With Ollama's
# own timeout raised to 240s (see ollama_client.py - empirically measured
# 130.2s for a 23-finding scan), the default 300s soft limit left only
# ~50-60s of margin over Ollama + aggregation + PDF generation - too tight
# given GPU/network run-to-run variance. Same pattern as recon (600/660)
# and webscan (480/540): the module doing genuinely variable-duration work
# gets a deliberately generous ceiling.
#
# Raised again by +80s (60s measured verification budget + 20s margin) for
# the confidence-verification stage (analysis/verifier.py) - see docs/ai.md
# for the real median/p95 numbers measured against the approved demo-target.example
# target that this is based on. 440/500 keeps the same 60s soft->hard gap
# as the pre-verification 360/420 pair. Named constants (not inlined in the
# decorators below) so routers/scan.py's STUCK_SCAN_DEADLINE can import the
# real value instead of carrying a second hardcoded copy that can drift out
# of sync (real bug found live: it previously did exactly that).
_AGGREGATE_SOFT_LIMIT = scaled_timeout(440)
_AGGREGATE_HARD_LIMIT = scaled_timeout(500)


@app.task(name='tasks.scan_orchestrator.aggregate_and_analyse',
          soft_time_limit=_AGGREGATE_SOFT_LIMIT, time_limit=_AGGREGATE_HARD_LIMIT)
def aggregate_and_analyse(results: list, scan_id: str, domain: str) -> None:
    """
    Chord callback: called once all 8 scanning subtasks complete.
    results is a list of per-module result envelopes (base_task.py's
    build_module_result()): [{module, status, findings, tool_versions,
    finding_count, duration_seconds, error}, ...] - one per module,
    regardless of whether that module found anything.

    If any module reported failed/timeout, the scan pauses for an operator
    decision (retry/continue/cancel) instead of finalising immediately -
    see _pause_for_decision. 'partial' is not a pause trigger: it already
    carries usable data (Section 4.3), so it's treated like success here.
    """
    logger.info("aggregate_and_analyse: scan %s received %d module results", scan_id, len(results))

    if _failed_modules(results):
        _pause_for_decision(results, scan_id, retry_counts={})
        return

    _finalize(results, scan_id, domain)


def _pause_for_decision(results: list, scan_id: str, retry_counts: Dict[str, int]) -> None:
    """
    Stash the raw module envelopes + per-module retry counts in
    scans.raw_findings (unused until finalisation writes the real
    aggregated shape there) and set status so the operator's next status
    poll surfaces the decision modal.
    """
    from database import SessionLocal
    from models import Scan, ScanStatus

    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            logger.error("_pause_for_decision: scan %s not found", scan_id)
            return
        scan.status = ScanStatus.awaiting_user_decision
        scan.raw_findings = {
            'pending_decision': True,
            'module_results': results,
            'retry_counts': retry_counts,
        }
        db.commit()
        logger.info("scan %s paused for operator decision - failed modules: %s",
                    scan_id, _failed_modules(results))
    finally:
        db.close()


@app.task(name='tasks.scan_orchestrator.continue_after_decision',
          soft_time_limit=_AGGREGATE_SOFT_LIMIT, time_limit=_AGGREGATE_HARD_LIMIT)
def continue_after_decision(scan_id: str, domain: str) -> None:
    """
    Operator chose 'Continue Without Failed Modules' - finalise using
    whatever module results were already stashed, unchanged. Failed
    modules stay in module_execution as 'failed' (not dropped), so the
    existing incomplete_modules_warning still fires - Continue means
    'stop waiting for these', not 'pretend they succeeded'.
    """
    from database import SessionLocal
    from models import Scan, ScanStatus

    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan or scan.status != ScanStatus.awaiting_user_decision:
            logger.warning("continue_after_decision: scan %s not awaiting decision", scan_id)
            return
        results = (scan.raw_findings or {}).get('module_results', [])
    finally:
        db.close()

    _finalize(results, scan_id, domain)


@app.task(name='tasks.scan_orchestrator.retry_failed_modules')
def retry_failed_modules(scan_id: str, domain: str) -> None:
    """
    Operator chose 'Retry Failed Modules'. Re-dispatches only the modules
    still eligible for their one retry (defensive re-check - the router
    already validated can_retry before enqueuing this, but Celery dispatch
    is async relative to that check). Reuses the exact same run_X Celery
    tasks and group/chord mechanism scan_orchestrator() uses for the
    initial run - no parallel orchestration path.
    """
    from database import SessionLocal
    from models import Scan, ScanStatus
    from tasks.base_task import update_module_status

    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan or scan.status != ScanStatus.awaiting_user_decision:
            logger.warning("retry_failed_modules: scan %s not awaiting decision", scan_id)
            return
        stash = scan.raw_findings or {}
        results = stash.get('module_results', [])
        retry_counts = dict(stash.get('retry_counts', {}))
    finally:
        db.close()

    failed = _failed_modules(results)
    retryable = [m for m in failed if retry_counts.get(m, 0) < MAX_RETRIES_PER_MODULE]
    if not retryable:
        logger.info("retry_failed_modules: scan %s has no retry-eligible modules left", scan_id)
        return

    from tasks.recon import run_recon
    from tasks.webscan import run_webscan
    from tasks.ssl_tls import run_ssl_tls
    from tasks.headers import run_headers
    from tasks.owasp import run_owasp
    from tasks.tech_fingerprint import run_tech_fingerprint
    from tasks.nuclei_scan import run_nuclei
    from tasks.enumeration import run_enumeration

    task_map = {
        'recon': run_recon, 'webscan': run_webscan, 'ssl_tls': run_ssl_tls,
        'headers': run_headers, 'owasp': run_owasp,
        'tech_fingerprint': run_tech_fingerprint, 'nuclei': run_nuclei,
        'enumeration': run_enumeration,
    }

    for m in retryable:
        update_module_status(scan_id, m, 'queued')

    logger.info("scan %s retrying modules: %s", scan_id, retryable)
    retry_group = group(task_map[m].s(scan_id, domain) for m in retryable)
    try:
        chord(retry_group)(_merge_retry_results.s(scan_id, domain, results, retryable))
    except Exception as e:
        # Same broker-dispatch-failure concern as scan_orchestrator() above -
        # a failed chord() call here would otherwise leave the scan at
        # 'running' with the retry never actually dispatched. Put it back to
        # awaiting_user_decision (not 'failed') so the operator can retry
        # again or fall back to continue/cancel, rather than losing the scan
        # outright over what's likely a transient Redis blip.
        logger.error("retry_failed_modules: failed to dispatch retry group for scan %s: %s", scan_id, e)
        db = SessionLocal()
        try:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = ScanStatus.awaiting_user_decision
                db.commit()
        finally:
            db.close()
        return

    # Only record this retry attempt (consuming each module's one retry)
    # once the dispatch has actually succeeded. Real bug found live (Opus
    # review): retry_counts used to be incremented and persisted BEFORE the
    # chord() dispatch above - a transient broker failure there still
    # consumed the module's one-and-only retry even though nothing was ever
    # dispatched, contradicting the except block's own "operator can retry
    # again" comment (MAX_RETRIES_PER_MODULE=1 then permanently blocked
    # Retry for that module after a dispatch failure that wasn't the
    # operator's or the module's fault).
    for m in retryable:
        retry_counts[m] = retry_counts.get(m, 0) + 1

    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            stash = dict(scan.raw_findings or {})
            stash['retry_counts'] = retry_counts
            scan.raw_findings = stash
            scan.status = ScanStatus.running
            db.commit()
    finally:
        db.close()


@app.task(name='tasks.scan_orchestrator._merge_retry_results')
def _merge_retry_results(retry_results: list, scan_id: str, domain: str,
                          previous_results: list, retried_modules: list) -> None:
    """
    Chord callback for a retry batch. retry_results only covers the
    retried modules - splice them back into the full 8-module list by
    module name before re-running the same pause-or-finalise check the
    initial chord uses.
    """
    by_module = {r.get('module'): r for r in retry_results if isinstance(r, dict)}
    merged = [by_module.get(r.get('module'), r) for r in previous_results]

    if _failed_modules(merged):
        from database import SessionLocal
        from models import Scan, ScanStatus

        db = SessionLocal()
        try:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                stash = dict(scan.raw_findings or {})
                stash['module_results'] = merged
                scan.status = ScanStatus.awaiting_user_decision
                scan.raw_findings = stash
                db.commit()
        finally:
            db.close()
        return

    _finalize(merged, scan_id, domain)


def _finalize(results: list, scan_id: str, domain: str) -> None:
    """
    Aggregate -> deterministic score -> AI description -> PDF -> complete.
    The tail end of the pipeline, shared by the no-failures fast path,
    'Continue Without Failed Modules', and a fully-successful retry.
    """
    from database import SessionLocal
    from models import Scan, Report, ScanStatus

    db = SessionLocal()
    scan = None
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            logger.error("_finalize: scan %s not found", scan_id)
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

        # --- Step 6b: confidence verification (passive re-observation) ---
        # Runs after aggregation (which stays pure/deterministic) and before
        # scoring, so cvss_scorer.py's priority shift (Section 4.5) sees the
        # final confidence tier. No-ops when ENABLE_VERIFICATION=False.
        try:
            from analysis.verifier import verify_findings
            from config import settings
            # Real bug found live: verifiers used to always replay
            # unauthenticated, so any finding discovered behind an
            # authenticated crawl could never reach confidence='confirmed'.
            # Build the same session owasp.py's _make_session() would (auth
            # credential is still in Redis - deleted at Step 9 below, after
            # this) so verifiers replay with the same cookies/bearer token
            # the original detection used. None when the scan had no auth,
            # same as before this fix.
            verify_session = None
            try:
                from tasks.auth_store import get_scan_auth
                auth = get_scan_auth(scan_id)
                if auth:
                    from tasks.owasp import _make_session
                    verify_session = _make_session(auth)
            except Exception as e:
                logger.warning("Could not build authenticated verification session for scan %s: %s", scan_id, e)
            aggregated['findings'] = verify_findings(
                aggregated.get('findings', []), enabled=settings.ENABLE_VERIFICATION,
                session=verify_session,
            )
        except Exception as e:
            logger.error("Verification failed for scan %s: %s", scan_id, e)

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

        # --- Step 8: prune ZAP session data now that it's been consumed ---
        try:
            _prune_zap_session(scan_id)
        except Exception as e:
            logger.warning("ZAP session pruning failed for scan %s: %s", scan_id, e)

        # --- Step 9: discard the scan's auth credential (if any) - same
        # lifecycle point as the ZAP session prune above: fully consumed by
        # webscan.py/owasp.py, no reason to keep it past this point. The
        # Redis TTL in auth_store.py is only a backstop for paths that skip
        # this function entirely (e.g. the `cancel` decision, Section 4.3b).
        try:
            from tasks.auth_store import delete_scan_auth
            delete_scan_auth(scan_id)
        except Exception as e:
            logger.warning("Auth credential cleanup failed for scan %s: %s", scan_id, e)

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
        # This scan just reached a terminal state and freed its slot - start the
        # next queued scan (no-op when the hosted queue flag is off / nothing
        # waiting). Own session inside; must run after db.close() above.
        try:
            from tasks.queue_scheduler import promote_queued_scans
            promote_queued_scans()
        except Exception:
            logger.exception("post-finalize queue promotion failed for scan %s", scan_id)


def _incomplete_modules_warning(module_execution: list) -> Optional[str]:
    """
    Deterministic warning line for the report's executive summary page -
    never left to the AI to decide whether to mention. A report that hides
    a failed/timed-out module is actively misleading about the target's
    security posture (ARCHITECTURE.md Section 4.4).
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
    executive_summary prose (ARCHITECTURE.md Section 4.5/4.6).
    """
    from analysis.cvss_scorer import score_finding, compute_risk_score
    from analysis.ollama_client import analyse, _generic_remediation

    findings = aggregated.get('findings', [])
    counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Informational': 0}

    for f in findings:
        f.update(score_finding(f))
        sev = f['severity'] if f['severity'] in counts else 'Informational'
        counts[sev] += 1

    risk_score = compute_risk_score(findings)

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

    risk_score = compute_risk_score(findings)
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
