from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from uuid import UUID

from database import get_db
from models import Scan, Report, ScanStatus
from reports.generator import safe_filename

router = APIRouter(prefix="/api", tags=["report"])


@router.get("/scan/{scan_id}/report")
def download_report(scan_id: UUID, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    report = db.query(Report).filter(Report.scan_id == scan_id).first()

    if report is None:
        if scan.status == ScanStatus.complete:
            # Scan finished but PDF still generating (or generation failed)
            raise HTTPException(
                status_code=202,
                detail={"status": "pending", "message": "Report generating"},
            )
        # Scan still running / queued / failed
        raise HTTPException(
            status_code=202,
            detail={"status": "pending", "message": "Scan not yet complete"},
        )

    date = (scan.completed_at or scan.started_at)
    filename = safe_filename(scan.domain, date)

    return StreamingResponse(
        iter([report.pdf_data]),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
