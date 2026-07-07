import uuid
from datetime import datetime
from sqlalchemy import (
    Column, String, Boolean, Integer, Enum as SAEnum,
    DateTime, LargeBinary, ForeignKey, Text
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
from database import Base
import enum


class ScanStatus(str, enum.Enum):
    queued = "queued"
    running = "running"
    analysing = "analysing"
    awaiting_user_decision = "awaiting_user_decision"
    complete = "complete"
    failed = "failed"
    cancelled = "cancelled"


class Scan(Base):
    __tablename__ = "scans"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    domain = Column(String(255), nullable=False)
    status = Column(SAEnum(ScanStatus), nullable=False, default=ScanStatus.queued)
    authorized = Column(Boolean, nullable=False, default=False)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    module_statuses = Column(JSONB, nullable=True, default=dict)
    raw_findings = Column(JSONB, nullable=True)
    ai_analysis = Column(JSONB, nullable=True)
    risk_score = Column(Integer, nullable=True)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    # Bumped on every ORM-level write (status transitions, risk_score, etc.)
    # via onupdate - not bumped by base_task.py's raw-SQL module_statuses
    # update (that's deliberately a separate, high-frequency, per-module
    # signal; this column is "when did the scan's own record last change,"
    # for the /api/scans listing page's "Last updated" column).
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=True)

    report = relationship("Report", back_populates="scan", uselist=False)


class Report(Base):
    __tablename__ = "reports"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)
    pdf_data = Column(LargeBinary, nullable=False)
    generated_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("Scan", back_populates="report")
