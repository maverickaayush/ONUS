from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import and_
from datetime import datetime, timedelta
from uuid import UUID
import logging

from database import get_db
from models import Scan, ScanStatus
from schemas import (
    ScanRequest, ScanResponse, ScanStatusResponse, FindingsResponse,
    ScanDecisionRequest, ScanModulesResponse,
)
from tasks.base_task import SCAN_MODULES, SCAN_MODULE_IDS
from config import settings

router = APIRouter(prefix="/api", tags=["scan"])
logger = logging.getLogger(__name__)

# A hard Celery time_limit SIGKILLs a module mid-task with no chance to report
# back, so the chord waiting on it never fires and the scan hangs at
# 'running' forever. Nothing can catch that from inside the task, so this is
# an outside check: if a scan is older than every module could plausibly take
# even in the worst case, the next status poll gives up on it instead of
# leaving it stuck. Deadline = slowest single module's hard time_limit
# (recon) + aggregate_and_analyse's hard time_limit + buffer, since modules
# run in parallel via group(), not sequentially. Imports the real constants
# (not a second hardcoded copy of recon.py/scan_orchestrator.py's numbers) so
# it can never drift out of sync when either module's own limit changes -
# real bug found live: this used to hardcode scaled_timeout(1080), which
# went stale the moment recon.py's own hard limit was raised past 1080.
from tasks.recon import _RECON_HARD_LIMIT
from tasks.scan_orchestrator import _AGGREGATE_HARD_LIMIT
STUCK_SCAN_DEADLINE = timedelta(seconds=_RECON_HARD_LIMIT + _AGGREGATE_HARD_LIMIT + 120)


def _reap_stuck_scans(db: Session) -> int:
    """
    Sweep every queued/running/analysing scan and fail the ones past
    STUCK_SCAN_DEADLINE, instead of relying solely on someone polling that
    specific scan's status (get_scan_status's per-scan check below - kept
    as-is, this is additive). Real bug found live: nothing ever swept scans
    nobody was polling anymore (an abandoned browser tab, a scan_id no
    frontend page references), so they sat in an active status forever,
    each one permanently occupying a MAX_CONCURRENT_SCANS slot - harmless
    while that cap was unenforced, but once enforced (this hardening pass)
    a handful of days-old zombie scans silently blocked every new scan
    indefinitely. Called before the concurrency count below so a request
    that would otherwise 429 against stale rows succeeds instead.
    `awaiting_user_decision` is deliberately excluded - that's an operator
    waiting on a human decision, not a timed-out task, so it has no
    deadline here (unchanged from before).
    """
    cutoff = datetime.utcnow() - STUCK_SCAN_DEADLINE
    stuck = db.query(Scan).filter(
        Scan.status.in_([ScanStatus.queued, ScanStatus.running, ScanStatus.analysing]),
    ).all()
    reaped = 0
    for scan in stuck:
        reference_time = scan.started_at or scan.created_at
        if reference_time and reference_time < cutoff:
            scan.status = ScanStatus.failed
            reaped += 1
    if reaped:
        db.commit()
        logger.warning("_reap_stuck_scans: marked %d stale scan(s) failed", reaped)
    return reaped


@router.post("/scan", response_model=ScanResponse, status_code=202)
def create_scan(request: ScanRequest, db: Session = Depends(get_db)):
    if not request.authorized:
        raise HTTPException(status_code=403, detail="Scan requires explicit authorization")

    # Duplicate detection - same domain, active scan in last 10 minutes.
    # Checked before the concurrency cap below since this path never creates
    # a new scan (returns the existing job_id), so it shouldn't be rejected
    # by a full worker pool.
    ten_minutes_ago = datetime.utcnow() - timedelta(minutes=10)
    existing = db.query(Scan).filter(
        and_(
            Scan.domain == request.domain,
            Scan.status.in_([ScanStatus.queued, ScanStatus.running, ScanStatus.analysing]),
            Scan.created_at >= ten_minutes_ago,
        )
    ).first()

    if existing:
        logger.info("Returning existing scan %s for domain %s", existing.id, request.domain)
        return ScanResponse(job_id=existing.id, status=existing.status.value, domain=existing.domain)

    # Rate limiting (Section 8) - resource-exhaustion guard, not a security
    # boundary. Counts scans still consuming worker/DB resources; 'complete'/
    # 'failed'/'cancelled' don't count. Previously documented but never
    # enforced in code.
    _reap_stuck_scans(db)
    active_count = db.query(Scan).filter(
        Scan.status.in_([
            ScanStatus.queued, ScanStatus.running,
            ScanStatus.analysing, ScanStatus.awaiting_user_decision,
        ])
    ).count()
    if active_count >= settings.MAX_CONCURRENT_SCANS:
        raise HTTPException(
            status_code=429,
            detail=f"Maximum concurrent scans ({settings.MAX_CONCURRENT_SCANS}) reached - try again shortly",
        )

    scan = Scan(
        domain=request.domain,
        authorized=request.authorized,
        notes=request.notes,
        status=ScanStatus.queued,
        module_statuses={module_id: "queued" for module_id in SCAN_MODULE_IDS},
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    logger.info("Scan %s created for domain %s", scan.id, scan.domain)

    # Auth credentials never touch the Scan row above or a Celery task arg
    # (Celery logs task args in plaintext at INFO) - stored in Redis, keyed
    # by scan_id, read directly by webscan.py/owasp.py. See auth_store.py.
    if request.auth:
        from tasks.auth_store import store_scan_auth
        store_scan_auth(str(scan.id), request.auth.model_dump())

    # Import here to avoid circular imports at module load time
    try:
        from tasks.scan_orchestrator import scan_orchestrator
        scan_orchestrator.delay(str(scan.id), scan.domain)
    except Exception as e:
        logger.error("Failed to enqueue scan task: %s", e)
        scan.status = ScanStatus.failed
        db.commit()
        raise HTTPException(status_code=500, detail="Failed to enqueue scan job")

    return ScanResponse(job_id=scan.id, status=scan.status.value, domain=scan.domain)


@router.get("/scan/modules", response_model=ScanModulesResponse)
def get_scan_modules():
    """
    Canonical list of scanning modules (id/label/icon_hint), sourced from
    tasks/base_task.py's SCAN_MODULES - the same constant that drives
    module_statuses initialization above and scan_orchestrator.py's actual
    dispatch. The frontend's landing-page "Covers:" badges and the Scan
    Status page's module list both fetch this instead of hardcoding their
    own copy, so they can never drift from what actually runs.
    """
    return ScanModulesResponse(modules=SCAN_MODULES)


@router.get("/scan/{scan_id}/status", response_model=ScanStatusResponse)
def get_scan_status(scan_id: UUID, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status in (ScanStatus.queued, ScanStatus.running, ScanStatus.analysing):
        reference_time = scan.started_at or scan.created_at
        if reference_time and datetime.utcnow() - reference_time > STUCK_SCAN_DEADLINE:
            logger.error(
                "Scan %s stuck in %s past deadline (reference=%s) - marking failed, "
                "likely a hard-timeout SIGKILL on one of the scanning modules",
                scan.id, scan.status.value, reference_time,
            )
            scan.status = ScanStatus.failed
            db.commit()

    status_order = {
        ScanStatus.queued: 0,
        ScanStatus.running: 20,
        ScanStatus.analysing: 80,
        ScanStatus.complete: 100,
        ScanStatus.failed: 0,
    }

    module_statuses = scan.module_statuses or {}
    completed_modules = sum(1 for s in module_statuses.values() if s == "complete")
    base_progress = status_order.get(scan.status, 0)

    if scan.status == ScanStatus.running:
        progress = 20 + int((completed_modules / len(SCAN_MODULE_IDS)) * 60)
    else:
        progress = base_progress

    module_errors = None
    can_retry = None
    if scan.status == ScanStatus.awaiting_user_decision:
        from tasks.scan_orchestrator import _failed_modules, _can_retry

        stash = scan.raw_findings or {}
        results = stash.get("module_results", [])
        retry_counts = stash.get("retry_counts", {})
        failed = _failed_modules(results)
        module_errors = {
            r["module"]: r.get("error") or f"{r.get('status')} with no error detail"
            for r in results if isinstance(r, dict) and r.get("module") in failed
        }
        can_retry = _can_retry(failed, retry_counts)

    return ScanStatusResponse(
        job_id=scan.id,
        domain=scan.domain,
        status=scan.status.value,
        progress=progress,
        started_at=scan.started_at,
        modules=module_statuses,
        module_errors=module_errors,
        can_retry=can_retry,
    )


@router.post("/scan/{scan_id}/decision", response_model=ScanStatusResponse)
def submit_scan_decision(scan_id: UUID, request: ScanDecisionRequest, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status != ScanStatus.awaiting_user_decision:
        raise HTTPException(status_code=409, detail="Scan is not awaiting a decision")

    # Dispatched as Celery tasks, never run inline - retry re-runs scanning
    # modules and continue/finalise runs Ollama + PDF generation, both far
    # too slow for a request/response cycle.
    from tasks.scan_orchestrator import retry_failed_modules, continue_after_decision, _failed_modules, _can_retry

    if request.action == "retry":
        stash = scan.raw_findings or {}
        failed = _failed_modules(stash.get("module_results", []))
        if not _can_retry(failed, stash.get("retry_counts", {})):
            raise HTTPException(status_code=409, detail="No retry-eligible modules left")
        retry_failed_modules.delay(str(scan.id), scan.domain)
    elif request.action == "continue":
        continue_after_decision.delay(str(scan.id), scan.domain)
    elif request.action == "cancel":
        scan.status = ScanStatus.cancelled
        db.commit()

    db.refresh(scan)
    return get_scan_status(scan_id, db)


@router.get("/scan/{scan_id}/findings", response_model=FindingsResponse)
def get_findings(scan_id: UUID, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status not in (ScanStatus.complete, ScanStatus.analysing):
        raise HTTPException(status_code=202, detail="Scan not yet complete")

    if not scan.ai_analysis:
        raise HTTPException(status_code=202, detail="Analysis still in progress")

    analysis = scan.ai_analysis
    findings = analysis.get("findings", [])

    return FindingsResponse(
        executive_summary=analysis.get("executive_summary", ""),
        risk_score=analysis.get("risk_score", 0),
        total_critical=analysis.get("total_critical", 0),
        total_high=analysis.get("total_high", 0),
        total_medium=analysis.get("total_medium", 0),
        total_low=analysis.get("total_low", 0),
        total_informational=analysis.get("total_informational", 0),
        findings=findings,
    )


@router.get("/health")
def health():
    return {"status": "ok"}
