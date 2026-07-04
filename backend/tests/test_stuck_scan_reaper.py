"""
Stuck-scan reaper test: a scan hung past STUCK_SCAN_DEADLINE (e.g. a module
hard-timeout SIGKILL that leaves the chord waiting forever) must be flipped
to 'failed' on the next status poll, not left at 'running' indefinitely.

Run with:
    cd backend && python3 -m pytest tests/test_stuck_scan_reaper.py -v
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from datetime import datetime, timedelta
from unittest.mock import MagicMock

from routers.scan import get_scan_status, STUCK_SCAN_DEADLINE
from models import ScanStatus


def _fake_scan(status, started_at, created_at=None):
    scan = MagicMock()
    scan.id = "11111111-1111-1111-1111-111111111111"
    scan.domain = "example.com"
    scan.status = status
    scan.started_at = started_at
    scan.created_at = created_at or started_at
    scan.module_statuses = {}
    return scan


def _db_with(scan):
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = scan
    return db


class TestStuckScanReaper:

    def test_stuck_scan_marked_failed(self):
        scan = _fake_scan(ScanStatus.running, datetime.utcnow() - STUCK_SCAN_DEADLINE - timedelta(seconds=1))
        db = _db_with(scan)

        get_scan_status(scan.id, db)

        assert scan.status == ScanStatus.failed
        db.commit.assert_called_once()

    def test_running_within_deadline_untouched(self):
        scan = _fake_scan(ScanStatus.running, datetime.utcnow() - timedelta(seconds=60))
        db = _db_with(scan)

        get_scan_status(scan.id, db)

        assert scan.status == ScanStatus.running
        db.commit.assert_not_called()

    def test_completed_scan_never_reaped(self):
        scan = _fake_scan(ScanStatus.complete, datetime.utcnow() - STUCK_SCAN_DEADLINE - timedelta(days=1))
        db = _db_with(scan)

        get_scan_status(scan.id, db)

        assert scan.status == ScanStatus.complete
        db.commit.assert_not_called()

    def test_queued_forever_also_reaped(self):
        # started_at is only set once scan_orchestrator picks the job up -
        # if Celery itself is down, a scan can sit 'queued' forever with
        # started_at=None. created_at must still be used as the reference.
        scan = _fake_scan(ScanStatus.queued, started_at=None,
                           created_at=datetime.utcnow() - STUCK_SCAN_DEADLINE - timedelta(seconds=1))
        db = _db_with(scan)

        get_scan_status(scan.id, db)

        assert scan.status == ScanStatus.failed


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-v"]))
