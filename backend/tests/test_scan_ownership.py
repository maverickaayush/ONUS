"""Per-user scan ownership enforcement (hosted auth mode).

Regression tests for the Broken Access Control fix: when REQUIRE_AUTH=true a
user may only touch their OWN scans; another user's scan (or a non-existent /
ownerless one) returns 404, never leaking existence. When REQUIRE_AUTH=false
(self-hosted single operator) behavior is unchanged - scans are not owner-scoped.

Unit-style with mocked DB/session, same pattern as test_scan_modes.py.

Run with:
    cd backend && python3 -m pytest tests/test_scan_ownership.py -v
"""
import os
import sys
from unittest.mock import MagicMock
from uuid import uuid4

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import HTTPException

from config import settings
from models import ScanStatus
import routers.scan as scan_router
import routers.report as report_router
from routers.scan import get_owned_scan_or_404, _require_user


def _user(uid=None):
    u = MagicMock()
    u.id = uid or uuid4()
    u.email_verified = True
    return u


def _scan(owner_id, status=ScanStatus.complete):
    s = MagicMock()
    s.id = uuid4()
    s.user_id = owner_id
    s.status = status
    s.domain = "clinkl.in"
    s.ai_analysis = {"findings": [], "risk_score": 0}
    s.module_statuses = {}
    return s


def _db_returning(scan):
    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = scan
    return db


# ── The shared helper: get_owned_scan_or_404 ──────────────────────────────────
class TestOwnershipHelper:
    def test_self_hosted_returns_scan_unscoped(self, monkeypatch):
        monkeypatch.setattr(settings, "REQUIRE_AUTH", False)
        scan = _scan(owner_id=uuid4())
        got = get_owned_scan_or_404(scan.id, MagicMock(), _db_returning(scan))
        assert got is scan  # no ownership scoping when auth is off

    def test_hosted_no_session_401(self, monkeypatch):
        monkeypatch.setattr(settings, "REQUIRE_AUTH", True)
        monkeypatch.setattr("security.get_current_user", lambda req, db: None)
        with pytest.raises(HTTPException) as ei:
            get_owned_scan_or_404(uuid4(), MagicMock(), _db_returning(_scan(uuid4())))
        assert ei.value.status_code == 401

    def test_hosted_owner_ok(self, monkeypatch):
        monkeypatch.setattr(settings, "REQUIRE_AUTH", True)
        user = _user()
        monkeypatch.setattr("security.get_current_user", lambda req, db: user)
        scan = _scan(owner_id=user.id)
        got = get_owned_scan_or_404(scan.id, MagicMock(), _db_returning(scan))
        assert got is scan

    def test_hosted_other_user_404(self, monkeypatch):
        monkeypatch.setattr(settings, "REQUIRE_AUTH", True)
        userB = _user()
        monkeypatch.setattr("security.get_current_user", lambda req, db: userB)
        scan = _scan(owner_id=uuid4())  # owned by someone else (User A)
        with pytest.raises(HTTPException) as ei:
            get_owned_scan_or_404(scan.id, MagicMock(), _db_returning(scan))
        assert ei.value.status_code == 404  # NOT 403 - never leak existence

    def test_hosted_missing_scan_404(self, monkeypatch):
        monkeypatch.setattr(settings, "REQUIRE_AUTH", True)
        monkeypatch.setattr("security.get_current_user", lambda req, db: _user())
        with pytest.raises(HTTPException) as ei:
            get_owned_scan_or_404(uuid4(), MagicMock(), _db_returning(None))
        assert ei.value.status_code == 404  # same 404 as not-owned

    def test_hosted_ownerless_legacy_scan_404(self, monkeypatch):
        monkeypatch.setattr(settings, "REQUIRE_AUTH", True)
        monkeypatch.setattr("security.get_current_user", lambda req, db: _user())
        scan = _scan(owner_id=None)  # pre-auth scan, user_id NULL
        with pytest.raises(HTTPException) as ei:
            get_owned_scan_or_404(scan.id, MagicMock(), _db_returning(scan))
        assert ei.value.status_code == 404


# ── Every scan-scoped endpoint routes through the helper (User B -> 404) ──────
class TestEndpointsEnforceOwnership:
    def _setup_userB_vs_A(self, monkeypatch):
        monkeypatch.setattr(settings, "REQUIRE_AUTH", True)
        userB = _user()
        monkeypatch.setattr("security.get_current_user", lambda req, db: userB)
        return _db_returning(_scan(owner_id=uuid4()))  # scan owned by A

    def test_status_other_user_404(self, monkeypatch):
        db = self._setup_userB_vs_A(monkeypatch)
        with pytest.raises(HTTPException) as ei:
            scan_router.get_scan_status(uuid4(), MagicMock(), db)
        assert ei.value.status_code == 404

    def test_findings_other_user_404(self, monkeypatch):
        db = self._setup_userB_vs_A(monkeypatch)
        with pytest.raises(HTTPException) as ei:
            scan_router.get_findings(uuid4(), MagicMock(), db)
        assert ei.value.status_code == 404

    def test_decision_other_user_404(self, monkeypatch):
        db = self._setup_userB_vs_A(monkeypatch)
        req = MagicMock(); req.action = "cancel"
        with pytest.raises(HTTPException) as ei:
            scan_router.submit_scan_decision(uuid4(), req, MagicMock(), db)
        assert ei.value.status_code == 404

    def test_report_other_user_404(self, monkeypatch):
        db = self._setup_userB_vs_A(monkeypatch)
        with pytest.raises(HTTPException) as ei:
            report_router.download_report(uuid4(), MagicMock(), db)
        assert ei.value.status_code == 404


# ── /api/scans scoping ───────────────────────────────────────────────────────
class TestListScansScoping:
    def _mock_db_capture_filters(self, captured):
        db = MagicMock()
        q = db.query.return_value
        def cap(*args, **kw):
            captured.extend(str(a) for a in args)
            return q
        q.filter.side_effect = cap
        q.group_by.return_value.all.return_value = []
        q.order_by.return_value.offset.return_value.limit.return_value.all.return_value = []
        q.with_entities.return_value.scalar.return_value = 0  # total_matching
        q.all.return_value = []  # reaper
        return db

    def test_hosted_scopes_to_user(self, monkeypatch):
        monkeypatch.setattr(settings, "REQUIRE_AUTH", True)
        user = _user()
        monkeypatch.setattr("security.get_current_user", lambda req, db: user)
        captured = []
        db = self._mock_db_capture_filters(captured)
        scan_router.list_scans(MagicMock(), db=db)
        # both the counts query and the page query must be filtered by user_id
        assert any("user_id" in c for c in captured), captured

    def test_hosted_no_session_401(self, monkeypatch):
        monkeypatch.setattr(settings, "REQUIRE_AUTH", True)
        monkeypatch.setattr("security.get_current_user", lambda req, db: None)
        with pytest.raises(HTTPException) as ei:
            scan_router.list_scans(MagicMock(), db=self._mock_db_capture_filters([]))
        assert ei.value.status_code == 401

    def test_self_hosted_not_scoped(self, monkeypatch):
        monkeypatch.setattr(settings, "REQUIRE_AUTH", False)
        captured = []
        db = self._mock_db_capture_filters(captured)
        scan_router.list_scans(MagicMock(), db=db)  # must not raise
        assert not any("user_id" in c for c in captured), captured  # no user scoping
