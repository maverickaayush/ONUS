"""Hosted scan queue (config.HOSTED_QUEUE_ENABLED).

Unit-style: mocked DB/session, no live Postgres/Redis/Celery - same pattern as
test_scan_modes.py. Covers the two behaviors selected by the flag, the queue
helpers, the reaper exemption, and the self-hosted backward-compat guard.

Run with:
    cd backend && python3 -m pytest tests/test_queue.py -v
"""
import os
import sys
from datetime import datetime, timedelta
from unittest.mock import MagicMock
from uuid import uuid4

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import HTTPException

from config import settings
from models import ScanStatus
from schemas import ScanRequest
import routers.scan as scan_router
from tasks.queue_scheduler import (
    queue_position, count_occupied_slots, promote_queued_scans,
)


def _mock_db(count=0):
    db = MagicMock()
    chain = db.query.return_value.filter.return_value
    chain.all.return_value = []
    chain.first.return_value = None
    chain.count.return_value = count
    chain.order_by.return_value.limit.return_value.all.return_value = []
    # Real Postgres applies the created_at/id defaults on INSERT; db.refresh
    # then loads them. Simulate that so queue_position's created_at comparison
    # has a real value (the mock never actually flushes).
    def _refresh(s):
        if getattr(s, "created_at", None) is None:
            s.created_at = datetime.utcnow()
        if getattr(s, "id", None) is None:
            s.id = uuid4()
    db.refresh.side_effect = _refresh
    return db


def _mock_scan(status=ScanStatus.queued, dispatched_at=None):
    s = MagicMock()
    s.id = uuid4()
    s.domain = "clinkl.in"
    s.status = status
    s.dispatched_at = dispatched_at
    s.created_at = datetime.utcnow()
    s.started_at = None
    s.module_statuses = {}
    s.scan_type = "full"
    return s


# ── Backward compatibility: flag OFF keeps the 429 (self-hosted default) ──────
class TestFlagOffUnchanged:
    def test_overflow_still_429_when_disabled(self, monkeypatch):
        monkeypatch.setattr(settings, "HOSTED_QUEUE_ENABLED", False)
        monkeypatch.setattr(settings, "MAX_CONCURRENT_SCANS", 3)
        db = _mock_db(count=3)  # active_count == cap
        req = ScanRequest(domain="clinkl.in", authorized=True, mode="full")
        with pytest.raises(HTTPException) as ei:
            scan_router.create_scan(req, MagicMock(), db)
        assert ei.value.status_code == 429
        assert "Maximum concurrent scans" in ei.value.detail

    def test_capacity_free_starts_immediately_when_disabled(self, monkeypatch):
        monkeypatch.setattr(settings, "HOSTED_QUEUE_ENABLED", False)
        monkeypatch.setattr(settings, "MAX_CONCURRENT_SCANS", 3)
        orch = MagicMock()
        monkeypatch.setattr("tasks.scan_orchestrator.scan_orchestrator", orch)
        db = _mock_db(count=0)
        db.refresh.side_effect = lambda s: setattr(s, "id", uuid4())
        req = ScanRequest(domain="clinkl.in", authorized=True, mode="full")
        resp = scan_router.create_scan(req, MagicMock(), db)
        orch.delay.assert_called_once()
        assert resp.queue_position is None


# ── Flag ON: overflow queues instead of 429; free slot starts immediately ─────
class TestFlagOnQueues:
    def test_overflow_is_queued_not_429(self, monkeypatch):
        monkeypatch.setattr(settings, "HOSTED_QUEUE_ENABLED", True)
        monkeypatch.setattr(settings, "MAX_CONCURRENT_SCANS", 3)
        orch = MagicMock()
        monkeypatch.setattr("tasks.scan_orchestrator.scan_orchestrator", orch)
        db = _mock_db(count=3)  # 3 occupied == cap -> queue
        req = ScanRequest(domain="clinkl.in", authorized=True, mode="full")

        resp = scan_router.create_scan(req, MagicMock(), db)  # must NOT raise 429

        assert resp.status == ScanStatus.queued.value
        assert resp.queue_position is not None       # a place in line was returned
        orch.delay.assert_not_called()               # not dispatched while waiting

    def test_free_slot_dispatches_and_sets_dispatched_at(self, monkeypatch):
        monkeypatch.setattr(settings, "HOSTED_QUEUE_ENABLED", True)
        monkeypatch.setattr(settings, "MAX_CONCURRENT_SCANS", 3)
        orch = MagicMock()
        monkeypatch.setattr("tasks.scan_orchestrator.scan_orchestrator", orch)
        db = _mock_db(count=0)  # 0 occupied -> start now
        captured = {}
        db.add.side_effect = lambda s: captured.setdefault("scan", s)
        req = ScanRequest(domain="clinkl.in", authorized=True, mode="full")

        resp = scan_router.create_scan(req, MagicMock(), db)

        orch.delay.assert_called_once()
        assert resp.queue_position is None
        assert captured["scan"].dispatched_at is not None  # slot claimed at accept


# ── Queue helpers ─────────────────────────────────────────────────────────────
class TestQueueHelpers:
    def test_position_is_ahead_plus_one(self):
        db = _mock_db(count=3)  # 3 waiting scans created earlier
        waiting = _mock_scan(status=ScanStatus.queued, dispatched_at=None)
        assert queue_position(db, waiting) == 4

    def test_position_none_when_dispatched(self):
        db = _mock_db(count=3)
        dispatched = _mock_scan(status=ScanStatus.queued, dispatched_at=datetime.utcnow())
        assert queue_position(db, dispatched) is None

    def test_position_none_when_running(self):
        db = _mock_db(count=0)
        running = _mock_scan(status=ScanStatus.running, dispatched_at=datetime.utcnow())
        assert queue_position(db, running) is None

    def test_occupied_counts_dispatched_non_terminal(self):
        db = _mock_db(count=2)
        assert count_occupied_slots(db) == 2

    def test_promote_noop_when_disabled(self, monkeypatch):
        monkeypatch.setattr(settings, "HOSTED_QUEUE_ENABLED", False)
        # Must not touch the DB at all when the feature is off.
        assert promote_queued_scans() == 0


# ── Reaper must not kill a scan that is waiting BY DESIGN ─────────────────────
class TestReaperExemption:
    def test_waiting_scan_not_reaped(self, monkeypatch):
        monkeypatch.setattr(settings, "HOSTED_QUEUE_ENABLED", True)
        waiting = _mock_scan(status=ScanStatus.queued, dispatched_at=None)
        waiting.created_at = datetime.utcnow() - scan_router.STUCK_SCAN_DEADLINE - timedelta(hours=1)
        db = MagicMock()
        db.query.return_value.filter.return_value.all.return_value = [waiting]

        reaped = scan_router._reap_stuck_scans(db)

        assert reaped == 0
        assert waiting.status == ScanStatus.queued  # untouched

    def test_dispatched_stuck_scan_still_reaped(self, monkeypatch):
        monkeypatch.setattr(settings, "HOSTED_QUEUE_ENABLED", True)
        stuck = _mock_scan(status=ScanStatus.running, dispatched_at=datetime.utcnow())
        stuck.started_at = datetime.utcnow() - scan_router.STUCK_SCAN_DEADLINE - timedelta(hours=1)
        db = MagicMock()
        db.query.return_value.filter.return_value.all.return_value = [stuck]

        reaped = scan_router._reap_stuck_scans(db)

        assert reaped == 1
        assert stuck.status == ScanStatus.failed


# ── _is_waiting predicate ─────────────────────────────────────────────────────
class TestIsWaiting:
    def test_true_only_when_flag_on_queued_undispatched(self, monkeypatch):
        monkeypatch.setattr(settings, "HOSTED_QUEUE_ENABLED", True)
        assert scan_router._is_waiting(_mock_scan(ScanStatus.queued, None)) is True
        assert scan_router._is_waiting(_mock_scan(ScanStatus.queued, datetime.utcnow())) is False
        assert scan_router._is_waiting(_mock_scan(ScanStatus.running, None)) is False

    def test_false_when_flag_off(self, monkeypatch):
        monkeypatch.setattr(settings, "HOSTED_QUEUE_ENABLED", False)
        assert scan_router._is_waiting(_mock_scan(ScanStatus.queued, None)) is False
