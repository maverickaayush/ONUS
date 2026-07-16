"""Hosted scan queue scheduler (config.HOSTED_QUEUE_ENABLED).

When the concurrency cap is full, routers/scan.py parks an over-capacity scan as
status='queued' with dispatched_at=NULL instead of returning HTTP 429. This
module promotes those waiting scans - dispatching them to Celery the moment a
slot frees. It is called at every slot-freeing event (a scan reaching a terminal
state in _finalize, a cancel, and opportunistically on every status poll).

Coordination is a single Postgres transaction-level advisory lock, so only one
promoter runs the claim-and-dispatch section at a time across all backend/worker
processes - no double-dispatch, no double-start, safe across restarts (an
un-dispatched scan simply stays queued until the next promote call). With that
global lock held, a plain SELECT of waiting scans is race-free (no SKIP LOCKED
needed). Durability is Postgres: an accepted scan is always a committed row.

Entirely inert when the flag is off (the self-hosted default): promote_queued_scans()
returns immediately, so none of this touches the DB and dispatched_at stays NULL.
"""
from __future__ import annotations

import logging
from datetime import datetime

from sqlalchemy import text

from config import settings
from models import Scan, ScanStatus

logger = logging.getLogger(__name__)

# Statuses that mean "dispatched and still occupying a concurrency slot".
# A WAITING scan is status='queued' AND dispatched_at IS NULL - not in a slot.
_OCCUPYING = [
    ScanStatus.queued, ScanStatus.running,
    ScanStatus.analysing, ScanStatus.awaiting_user_decision,
]

# Arbitrary fixed key for pg_advisory_xact_lock - serializes all promoters.
_PROMOTE_LOCK_KEY = 728_100


def count_occupied_slots(db) -> int:
    """Scans that have been dispatched and are not yet terminal."""
    return db.query(Scan).filter(
        Scan.dispatched_at.isnot(None),
        Scan.status.in_(_OCCUPYING),
    ).count()


def queue_position(db, scan: Scan) -> int | None:
    """1-based position of a waiting scan (FIFO by created_at), or None if the
    scan isn't actually waiting for capacity."""
    if scan.status != ScanStatus.queued or scan.dispatched_at is not None:
        return None
    ahead = db.query(Scan).filter(
        Scan.status == ScanStatus.queued,
        Scan.dispatched_at.is_(None),
        Scan.created_at < scan.created_at,
    ).count()
    return ahead + 1


def promote_queued_scans() -> int:
    """Dispatch as many oldest-waiting scans as there are free slots. Returns the
    number promoted. No-op (returns 0) when the queue feature is disabled."""
    if not settings.HOSTED_QUEUE_ENABLED:
        return 0

    from database import SessionLocal
    db = SessionLocal()
    promoted: list[tuple[str, str, str]] = []  # (scan_id, domain, mode)
    try:
        # Serialize every promoter; released automatically at commit/rollback.
        db.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": _PROMOTE_LOCK_KEY})

        free = settings.MAX_CONCURRENT_SCANS - count_occupied_slots(db)
        if free <= 0:
            db.rollback()
            return 0

        waiting = db.query(Scan).filter(
            Scan.status == ScanStatus.queued,
            Scan.dispatched_at.is_(None),
        ).order_by(Scan.created_at.asc()).limit(free).all()

        now = datetime.utcnow()
        for scan in waiting:
            scan.dispatched_at = now
            promoted.append((str(scan.id), scan.domain, scan.scan_type))
        db.commit()  # releases the advisory lock; slots are now claimed
    except Exception:
        logger.exception("promote_queued_scans: failed during claim")
        db.rollback()
        db.close()
        return 0
    finally:
        # (advisory lock already released by commit/rollback above)
        pass

    # Dispatch OUTSIDE the lock. A dispatch failure marks that one scan failed
    # (same policy as create_scan's enqueue-failure path), never blocks others.
    from tasks.scan_orchestrator import scan_orchestrator
    dispatched = 0
    for scan_id, domain, mode in promoted:
        try:
            scan_orchestrator.delay(scan_id, domain, mode)
            dispatched += 1
            logger.info("promote_queued_scans: started queued scan %s (%s)", scan_id, domain)
        except Exception as e:
            logger.error("promote_queued_scans: dispatch failed for %s: %s", scan_id, e)
            _mark_failed(db, scan_id)
    db.close()
    return dispatched


def _mark_failed(db, scan_id: str) -> None:
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            scan.status = ScanStatus.failed
            db.commit()
    except Exception:
        db.rollback()
