from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from sqlalchemy import and_, func
from datetime import datetime, timedelta
from typing import Dict, Optional
from uuid import UUID
import logging

from database import get_db
from models import Scan, ScanStatus
from schemas import (
    ScanRequest, ScanResponse, ScanStatusResponse, FindingsResponse,
    ScanDecisionRequest, ScanModulesResponse, ScanListResponse, ScanListItem,
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


def _compute_progress(scan: Scan) -> int:
    """
    Shared by get_scan_status and GET /api/scans so both endpoints compute
    the same scan's % identically instead of two copies drifting apart.
    awaiting_user_decision maps to 80 (not the old missing-entry 0) - a
    paused-for-decision scan already finished all 8 modules, so showing 0%
    was misleading; confirmed as a deliberate fix, not just a refactor.
    """
    status_order = {
        ScanStatus.queued: 0,
        ScanStatus.running: 20,
        ScanStatus.analysing: 80,
        ScanStatus.awaiting_user_decision: 80,
        ScanStatus.complete: 100,
        ScanStatus.failed: 0,
    }
    module_statuses = scan.module_statuses or {}
    if scan.status == ScanStatus.running:
        completed = sum(1 for s in module_statuses.values() if s == "complete")
        # Divide by the modules THIS scan actually runs (quick = 3, full = 8),
        # not a hardcoded 8 - otherwise a quick scan caps at ~37%.
        divisor = len(module_statuses) or len(SCAN_MODULE_IDS)
        return 20 + int((completed / divisor) * 60)
    return status_order.get(scan.status, 0)


def _compute_module_errors(scan: Scan) -> Optional[Dict[str, str]]:
    """
    Shared by get_scan_status and GET /api/scans. Non-None only while
    awaiting_user_decision - dict keys are exactly the failed-module names.
    """
    if scan.status != ScanStatus.awaiting_user_decision:
        return None
    from tasks.scan_orchestrator import _failed_modules

    stash = scan.raw_findings or {}
    results = stash.get("module_results", [])
    failed = _failed_modules(results)
    return {
        r["module"]: r.get("error") or f"{r.get('status')} with no error detail"
        for r in results if isinstance(r, dict) and r.get("module") in failed
    }


def _current_module(scan: Scan) -> Optional[str]:
    """
    None unless something is actively in flight. Multiple modules can be
    'running' simultaneously (Celery group() dispatch) - picks the first by
    SCAN_MODULE_IDS' canonical order. 'Analysing' is a synthetic value (no
    module_statuses entry is 'running' during that aggregate/verify/score/
    describe/PDF phase).
    """
    if scan.status == ScanStatus.analysing:
        return "Analysing"
    if scan.status != ScanStatus.running:
        return None
    module_statuses = scan.module_statuses or {}
    for module_id in SCAN_MODULE_IDS:
        if module_statuses.get(module_id) == "running":
            return module_id
    return None


@router.post("/scan", response_model=ScanResponse, status_code=202)
def create_scan(request: ScanRequest, http_request: Request, db: Session = Depends(get_db)):
    if not request.authorized:
        raise HTTPException(status_code=403, detail="Scan requires explicit authorization")

    mode = request.mode  # schema-validated: 'quick' | 'full'
    current_user = None

    # Hosted-tier gate (routers/auth.py). Default OFF - a no-op for local/
    # single-operator deployments. When ON, BOTH modes require an authenticated,
    # email-verified user; a FULL VAPT scan ADDITIONALLY requires proven
    # ownership of the target (or an authorized subdomain). This block is THE
    # enforcement point - it runs BEFORE any Celery/Modal scanner dispatch, so an
    # unauthorized active scan never reaches nmap/naabu/ZAP/Nuclei/ffuf/Nikto.
    if settings.REQUIRE_AUTH:
        import security
        from routers.verify import user_owns_domain
        current_user = security.get_current_user(http_request, db)
        if current_user is None:
            raise HTTPException(status_code=401, detail="Authentication required.")
        if not current_user.email_verified:
            raise HTTPException(status_code=403, detail="Email address not verified.")

        # Per-mode rate limit (server-side, Redis).
        if mode == "quick":
            security.enforce_rate_limit(f"quick:{current_user.id}",
                                        settings.RATE_LIMIT_QUICK_SCAN,
                                        settings.RATE_LIMIT_QUICK_SCAN_WINDOW)
        else:
            security.enforce_rate_limit(f"full:{current_user.id}",
                                        settings.RATE_LIMIT_FULL_SCAN,
                                        settings.RATE_LIMIT_FULL_SCAN_WINDOW)

        # Monthly usage cap (both modes), counted from the DB.
        month_start = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        used = db.query(Scan).filter(
            Scan.user_id == current_user.id, Scan.created_at >= month_start
        ).count()
        if used >= settings.MAX_SCANS_PER_MONTH:
            raise HTTPException(
                status_code=429,
                detail=f"Monthly scan limit ({settings.MAX_SCANS_PER_MONTH}) reached.")

        # FULL requires verified target ownership. Return a STRUCTURED response
        # the frontend uses to open target verification and resume the scan.
        if mode == "full" and not user_owns_domain(db, current_user.id, request.domain):
            raise HTTPException(status_code=403, detail={
                "code": "TARGET_AUTHORIZATION_REQUIRED",
                "target": request.domain,
                "methods": ["meta_tag", "http_file"],
                "message": "Active scanning requires verified ownership of this target.",
            })

    # Account-less claim-key gate (REQUIRE_DOMAIN_VERIFICATION). FULL only -
    # a QUICK assessment is passive and never requires ownership.
    if settings.REQUIRE_DOMAIN_VERIFICATION and mode == "full":
        from routers.verify import domain_has_valid_claim
        if not domain_has_valid_claim(db, request.domain, request.claim_key):
            raise HTTPException(
                status_code=403,
                detail="Domain ownership not verified. Verify control of this domain "
                       "(POST /api/verify/domain) and pass the returned claim_key.",
            )

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

    from tasks.base_task import module_ids_for_mode
    scan = Scan(
        domain=request.domain,
        authorized=request.authorized,
        notes=request.notes,
        status=ScanStatus.queued,
        scan_type=mode,
        user_id=(current_user.id if current_user else None),
        module_statuses={module_id: "queued" for module_id in module_ids_for_mode(mode)},
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
        scan_orchestrator.delay(str(scan.id), scan.domain, mode)
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


# ---------------------------------------------------------------------------
# GET /api/scans - discovery/listing page (Scans dashboard). Read-only
# metadata only - never returns raw_findings/ai_analysis content, and never
# touches the retry/continue/cancel decision flow (submit_scan_decision
# above is the only writer of scan.status via an operator action).
# ---------------------------------------------------------------------------
STATUS_BUCKETS: Dict[str, set] = {
    "active": {ScanStatus.queued, ScanStatus.running, ScanStatus.analysing},
    "awaiting_user_decision": {ScanStatus.awaiting_user_decision},
    "completed": {ScanStatus.complete}, "complete": {ScanStatus.complete},
    "failed": {ScanStatus.failed}, "cancelled": {ScanStatus.cancelled},
    "queued": {ScanStatus.queued}, "running": {ScanStatus.running},
    "analysing": {ScanStatus.analysing},
}
SORT_COLUMNS = {
    "created_at": Scan.created_at, "updated_at": Scan.updated_at,
    "status": Scan.status, "target": Scan.domain,
}


def _to_list_item(scan: Scan) -> ScanListItem:
    module_statuses = scan.module_statuses or {}
    module_errors = _compute_module_errors(scan)
    return ScanListItem(
        job_id=scan.id,
        target=scan.domain,
        status=scan.status.value,
        created_at=scan.created_at,
        updated_at=scan.updated_at,
        progress=_compute_progress(scan),
        current_module=_current_module(scan),
        overall_score=scan.risk_score,
        awaiting_user_decision=scan.status == ScanStatus.awaiting_user_decision,
        module_errors=list(module_errors.keys()) if module_errors else None,
        modules_completed=sum(1 for s in module_statuses.values() if s == "complete"),
        modules_total=len(SCAN_MODULE_IDS),
    )


@router.get("/scans", response_model=ScanListResponse)
def list_scans(
    status: Optional[str] = None,
    search: Optional[str] = None,
    sort: str = "created_at",
    order: str = "desc",
    page: int = 1,
    page_size: int = 20,
    db: Session = Depends(get_db),
):
    """
    Paginated scan listing for the /scans discovery dashboard. status/
    search/sort/order/page all applied server-side so they compose
    correctly together (client-side sort/search over just one fetched page
    would be wrong once paginated). Exactly 2 queries regardless of dataset
    size: one GROUP BY aggregate for the always-global tab counts (never
    touches the heavy raw_findings/ai_analysis JSONB columns), one filtered/
    sorted/limited SELECT for the actual page - no N+1.
    """
    # Same rationale as create_scan's concurrency check reaping first - this
    # page is the one most likely to be left open unattended, and is the
    # exact page meant to surface a scan stuck past its deadline.
    _reap_stuck_scans(db)

    if status is not None and status not in STATUS_BUCKETS:
        raise HTTPException(status_code=422, detail=f"Unknown status filter '{status}'")
    if sort not in SORT_COLUMNS:
        raise HTTPException(status_code=422, detail=f"Unknown sort key '{sort}'")
    if order not in ("asc", "desc"):
        raise HTTPException(status_code=422, detail="order must be 'asc' or 'desc'")
    page = max(page, 1)
    page_size = min(max(page_size, 1), 100)

    # Query 1: global tab counts - always reflects the WHOLE table so tab
    # badges never zero out just because a filter/search is currently active.
    status_counts = dict(db.query(Scan.status, func.count(Scan.id)).group_by(Scan.status).all())
    counts = {
        "running": sum(status_counts.get(s, 0) for s in STATUS_BUCKETS["active"]),
        "awaiting_user_decision": status_counts.get(ScanStatus.awaiting_user_decision, 0),
        "completed": status_counts.get(ScanStatus.complete, 0),
        "failed": status_counts.get(ScanStatus.failed, 0),
        "total": sum(status_counts.values()),
    }

    # Query 2: the actual page.
    query = db.query(Scan)
    if status is not None:
        query = query.filter(Scan.status.in_(STATUS_BUCKETS[status]))
    if search:
        # Escape LIKE wildcards in user input so a literal "%"/"_" in a
        # domain search doesn't act as a pattern wildcard.
        escaped = search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        query = query.filter(Scan.domain.ilike(f"%{escaped}%", escape="\\"))

    total_matching = query.with_entities(func.count(Scan.id)).scalar()

    sort_col = SORT_COLUMNS[sort]
    query = query.order_by(sort_col.asc() if order == "asc" else sort_col.desc())
    scans = query.offset((page - 1) * page_size).limit(page_size).all()

    return ScanListResponse(
        scans=[_to_list_item(s) for s in scans],
        counts=counts,
        total=total_matching,
        page=page,
        page_size=page_size,
        total_pages=max(1, -(-total_matching // page_size)),
    )


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

    module_errors = _compute_module_errors(scan)
    can_retry = None
    if module_errors is not None:
        from tasks.scan_orchestrator import _can_retry

        stash = scan.raw_findings or {}
        can_retry = _can_retry(list(module_errors.keys()), stash.get("retry_counts", {}))

    return ScanStatusResponse(
        job_id=scan.id,
        domain=scan.domain,
        status=scan.status.value,
        progress=_compute_progress(scan),
        started_at=scan.started_at,
        modules=scan.module_statuses or {},
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
