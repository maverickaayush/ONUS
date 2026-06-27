from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from uuid import UUID
import io

from database import get_db
from models import Scan, Report, ScanStatus

router = APIRouter(prefix="/api", tags=["report"])


@router.get("/scan/{scan_id}/report")
def download_report(scan_id: UUID, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status not in (ScanStatus.complete, ScanStatus.analysing):
        raise HTTPException(status_code=202, detail={"status": "pending"})

    report = db.query(Report).filter(Report.scan_id == scan_id).first()
    if not report:
        if scan.status == ScanStatus.complete:
            raise HTTPException(status_code=202, detail={"status": "pending"})
        raise HTTPException(status_code=404, detail="Report not found")

    from datetime import date
    filename = f"vapt_report_{scan.domain}_{date.today().isoformat()}.pdf"

    return StreamingResponse(
        io.BytesIO(report.pdf_data),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
