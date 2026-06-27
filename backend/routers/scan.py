from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import and_
from datetime import datetime, timedelta
from uuid import UUID
import logging

from database import get_db
from models import Scan, ScanStatus
from schemas import ScanRequest, ScanResponse, ScanStatusResponse, FindingsResponse

router = APIRouter(prefix="/api", tags=["scan"])
logger = logging.getLogger(__name__)


@router.post("/scan", response_model=ScanResponse, status_code=202)
def create_scan(request: ScanRequest, db: Session = Depends(get_db)):
    if not request.authorized:
        raise HTTPException(status_code=403, detail="Scan requires explicit authorization")

    # Duplicate detection — same domain, active scan in last 10 minutes
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

    scan = Scan(
        domain=request.domain,
        authorized=request.authorized,
        notes=request.notes,
        status=ScanStatus.queued,
        module_statuses={
            "recon": "queued",
            "webscan": "queued",
            "ssl_tls": "queued",
            "headers": "queued",
            "owasp": "queued",
        },
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    logger.info("Scan %s created for domain %s", scan.id, scan.domain)

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


@router.get("/scan/{scan_id}/status", response_model=ScanStatusResponse)
def get_scan_status(scan_id: UUID, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

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
        progress = 20 + int((completed_modules / 5) * 60)
    else:
        progress = base_progress

    return ScanStatusResponse(
        job_id=scan.id,
        domain=scan.domain,
        status=scan.status.value,
        progress=progress,
        started_at=scan.started_at,
        modules=module_statuses,
    )


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
