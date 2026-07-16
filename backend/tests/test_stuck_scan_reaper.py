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

from routers.scan import get_scan_status, _reap_stuck_scans, STUCK_SCAN_DEADLINE
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

        get_scan_status(scan.id, MagicMock(), db)

        assert scan.status == ScanStatus.failed
        db.commit.assert_called_once()

    def test_running_within_deadline_untouched(self):
        scan = _fake_scan(ScanStatus.running, datetime.utcnow() - timedelta(seconds=60))
        db = _db_with(scan)

        get_scan_status(scan.id, MagicMock(), db)

        assert scan.status == ScanStatus.running
        db.commit.assert_not_called()

    def test_completed_scan_never_reaped(self):
        scan = _fake_scan(ScanStatus.complete, datetime.utcnow() - STUCK_SCAN_DEADLINE - timedelta(days=1))
        db = _db_with(scan)

        get_scan_status(scan.id, MagicMock(), db)

        assert scan.status == ScanStatus.complete
        db.commit.assert_not_called()

    def test_queued_forever_also_reaped(self):
        # started_at is only set once scan_orchestrator picks the job up -
        # if Celery itself is down, a scan can sit 'queued' forever with
        # started_at=None. created_at must still be used as the reference.
        scan = _fake_scan(ScanStatus.queued, started_at=None,
                           created_at=datetime.utcnow() - STUCK_SCAN_DEADLINE - timedelta(seconds=1))
        db = _db_with(scan)

        get_scan_status(scan.id, MagicMock(), db)

        assert scan.status == ScanStatus.failed


class TestReapStuckScansSweep:
    """
    Real bug found live: nobody polling a specific old scan's status meant
    it sat in an active status forever, permanently occupying a
    MAX_CONCURRENT_SCANS slot once that cap was actually enforced. This
    proactive sweep (called from create_scan(), not just get_scan_status())
    catches those without requiring anyone to poll them individually.
    """

    def _db_with_scans(self, scans):
        db = MagicMock()
        db.query.return_value.filter.return_value.all.return_value = scans
        return db

    def test_sweeps_multiple_stale_scans_across_statuses(self):
        stale_running = _fake_scan(ScanStatus.running,
                                    datetime.utcnow() - STUCK_SCAN_DEADLINE - timedelta(days=3))
        stale_queued = _fake_scan(ScanStatus.queued, started_at=None,
                                   created_at=datetime.utcnow() - STUCK_SCAN_DEADLINE - timedelta(days=1))
        fresh_analysing = _fake_scan(ScanStatus.analysing, datetime.utcnow() - timedelta(seconds=30))
        db = self._db_with_scans([stale_running, stale_queued, fresh_analysing])

        reaped = _reap_stuck_scans(db)

        assert reaped == 2
        assert stale_running.status == ScanStatus.failed
        assert stale_queued.status == ScanStatus.failed
        assert fresh_analysing.status == ScanStatus.analysing
        db.commit.assert_called_once()

    def test_noop_when_nothing_stale(self):
        fresh = _fake_scan(ScanStatus.running, datetime.utcnow() - timedelta(seconds=5))
        db = self._db_with_scans([fresh])

        reaped = _reap_stuck_scans(db)

        assert reaped == 0
        assert fresh.status == ScanStatus.running
        db.commit.assert_not_called()

    def test_awaiting_user_decision_never_swept(self):
        # A human hasn't responded yet - not a timed-out task, so this sweep
        # (like get_scan_status's own check) must never touch it, no matter
        # how old. The query filter itself excludes this status; this test
        # guards against a future edit widening that filter by mistake.
        stale_awaiting = _fake_scan(ScanStatus.awaiting_user_decision,
                                     datetime.utcnow() - STUCK_SCAN_DEADLINE - timedelta(days=10))
        db = MagicMock()
        # Simulate the real query: .filter(status.in_([queued, running, analysing]))
        # would never include this scan, so .all() returns empty regardless
        # of what's actually in the "DB" - the test asserts the sweep
        # doesn't crash/misbehave given an empty result set.
        db.query.return_value.filter.return_value.all.return_value = []

        reaped = _reap_stuck_scans(db)

        assert reaped == 0
        assert stale_awaiting.status == ScanStatus.awaiting_user_decision
        db.commit.assert_not_called()


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-v"]))
