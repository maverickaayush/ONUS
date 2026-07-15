"""Quick vs Full scan modes + the full-scan target-authorization gate.

Unit-style: create_scan is exercised directly with a mocked DB/session; no live
Postgres/Redis/Celery. Rate limiting fails open without Redis (by design), so
these run in CI unchanged.
"""
import os
import sys
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import HTTPException

from config import settings
from schemas import ScanRequest
from tasks.base_task import QUICK_MODULE_IDS, SCAN_MODULE_IDS, module_ids_for_mode
import routers.scan as scan_router
import routers.verify as verify_router


# ── Mode contract ────────────────────────────────────────────────────────────
class TestModeContract:
    def test_default_mode_is_full(self):
        assert ScanRequest(domain="example.com", authorized=True).mode == "full"

    def test_unknown_mode_rejected(self):
        with pytest.raises(Exception):  # pydantic ValidationError
            ScanRequest(domain="example.com", authorized=True, mode="aggressive")

    def test_quick_and_full_accepted(self):
        assert ScanRequest(domain="e.com", authorized=True, mode="quick").mode == "quick"
        assert ScanRequest(domain="e.com", authorized=True, mode="full").mode == "full"


# ── Quick profile: which modules run ─────────────────────────────────────────
class TestQuickProfile:
    ACTIVE = {"recon", "webscan", "owasp", "nuclei", "enumeration"}

    def test_quick_set(self):
        assert module_ids_for_mode("quick") == ["headers", "ssl_tls", "tech_fingerprint"]

    def test_full_set_is_all(self):
        assert module_ids_for_mode("full") == SCAN_MODULE_IDS

    def test_quick_excludes_every_active_module(self):
        # nmap(recon)/naabu(recon)/ZAP+Nikto(webscan)/active-nuclei/ffuf(enumeration)
        # and owasp payloads are all excluded.
        for m in self.ACTIVE:
            assert m not in QUICK_MODULE_IDS, f"{m} must not be in the quick profile"


# ── tech_fingerprint quick submode = WhatWeb only ────────────────────────────
class TestTechFingerprintQuick:
    def test_quick_runs_whatweb_only_not_wafw00f(self):
        from tasks import tech_fingerprint as tf
        with patch.object(tf, "_run_whatweb", return_value=[]) as ww, \
             patch.object(tf, "_run_wafw00f", return_value=[]) as wf, \
             patch.object(tf, "get_tool_version", return_value="x"):
            env = tf.scan_tech_fingerprint("sid", "example.com", None, quick=True)
        ww.assert_called_once()
        wf.assert_not_called()
        assert env["status"] == "success"
        assert "wafw00f" not in env["tool_versions"]

    def test_full_runs_both(self):
        from tasks import tech_fingerprint as tf
        with patch.object(tf, "_run_whatweb", return_value=[]) as ww, \
             patch.object(tf, "_run_wafw00f", return_value=[]) as wf, \
             patch.object(tf, "get_tool_version", return_value="x"):
            tf.scan_tech_fingerprint("sid", "example.com", None, quick=False)
        ww.assert_called_once()
        wf.assert_called_once()


# ── create_scan gating (direct call, mocked DB) ──────────────────────────────
def _mock_db():
    db = MagicMock()
    chain = db.query.return_value.filter.return_value
    chain.all.return_value = []
    chain.first.return_value = None
    chain.count.return_value = 0
    return db


def _verified_user():
    u = MagicMock()
    u.id = uuid4()
    u.email_verified = True
    return u


class TestFullScanAuthorizationGate:
    def test_full_unverified_target_returns_authorization_required(self, monkeypatch):
        monkeypatch.setattr(settings, "REQUIRE_AUTH", True)
        monkeypatch.setattr("security.get_current_user", lambda req, db: _verified_user())
        monkeypatch.setattr(verify_router, "user_owns_domain", lambda db, uid, target: False)

        req = ScanRequest(domain="clinkl.in", authorized=True, mode="full")
        with pytest.raises(HTTPException) as ei:
            scan_router.create_scan(req, MagicMock(), _mock_db())
        assert ei.value.status_code == 403
        assert ei.value.detail["code"] == "TARGET_AUTHORIZATION_REQUIRED"
        assert ei.value.detail["target"] == "clinkl.in"
        assert set(ei.value.detail["methods"]) == {"meta_tag", "http_file"}

    def test_full_unverified_never_dispatches_a_scanner(self, monkeypatch):
        monkeypatch.setattr(settings, "REQUIRE_AUTH", True)
        monkeypatch.setattr("security.get_current_user", lambda req, db: _verified_user())
        monkeypatch.setattr(verify_router, "user_owns_domain", lambda db, uid, target: False)
        dispatched = MagicMock()
        monkeypatch.setattr("tasks.scan_orchestrator.scan_orchestrator", dispatched)

        req = ScanRequest(domain="clinkl.in", authorized=True, mode="full")
        with pytest.raises(HTTPException):
            scan_router.create_scan(req, MagicMock(), _mock_db())
        dispatched.delay.assert_not_called()

    def test_full_verified_target_is_allowed(self, monkeypatch):
        monkeypatch.setattr(settings, "REQUIRE_AUTH", True)
        monkeypatch.setattr("security.get_current_user", lambda req, db: _verified_user())
        monkeypatch.setattr(verify_router, "user_owns_domain", lambda db, uid, target: True)
        orch = MagicMock()
        monkeypatch.setattr("tasks.scan_orchestrator.scan_orchestrator", orch)
        db = _mock_db()
        db.refresh.side_effect = lambda s: setattr(s, "id", uuid4())

        req = ScanRequest(domain="clinkl.in", authorized=True, mode="full")
        resp = scan_router.create_scan(req, MagicMock(), db)
        assert resp.domain == "clinkl.in"
        orch.delay.assert_called_once()
        assert orch.delay.call_args[0][2] == "full"  # mode threaded to orchestrator

    def test_quick_does_not_require_ownership(self, monkeypatch):
        monkeypatch.setattr(settings, "REQUIRE_AUTH", True)
        monkeypatch.setattr("security.get_current_user", lambda req, db: _verified_user())
        owns = MagicMock(return_value=False)
        monkeypatch.setattr(verify_router, "user_owns_domain", owns)
        orch = MagicMock()
        monkeypatch.setattr("tasks.scan_orchestrator.scan_orchestrator", orch)
        db = _mock_db()
        db.refresh.side_effect = lambda s: setattr(s, "id", uuid4())

        req = ScanRequest(domain="clinkl.in", authorized=True, mode="quick")
        resp = scan_router.create_scan(req, MagicMock(), db)
        assert resp.domain == "clinkl.in"
        owns.assert_not_called()               # quick never checks ownership
        assert orch.delay.call_args[0][2] == "quick"

    def test_quick_requires_verified_email(self, monkeypatch):
        monkeypatch.setattr(settings, "REQUIRE_AUTH", True)
        unverified = MagicMock(); unverified.id = uuid4(); unverified.email_verified = False
        monkeypatch.setattr("security.get_current_user", lambda req, db: unverified)
        req = ScanRequest(domain="clinkl.in", authorized=True, mode="quick")
        with pytest.raises(HTTPException) as ei:
            scan_router.create_scan(req, MagicMock(), _mock_db())
        assert ei.value.status_code == 403

    def test_local_mode_unaffected_tick_and_go(self, monkeypatch):
        # REQUIRE_AUTH off (open-source default): no auth, no ownership, just the tick.
        monkeypatch.setattr(settings, "REQUIRE_AUTH", False)
        orch = MagicMock()
        monkeypatch.setattr("tasks.scan_orchestrator.scan_orchestrator", orch)
        db = _mock_db()
        db.refresh.side_effect = lambda s: setattr(s, "id", uuid4())
        req = ScanRequest(domain="example.com", authorized=True)  # default full
        resp = scan_router.create_scan(req, MagicMock(), db)
        assert resp.domain == "example.com"
        orch.delay.assert_called_once()

    def test_unauthorized_tick_missing_is_403(self, monkeypatch):
        monkeypatch.setattr(settings, "REQUIRE_AUTH", False)
        req = ScanRequest(domain="example.com", authorized=False)
        with pytest.raises(HTTPException) as ei:
            scan_router.create_scan(req, MagicMock(), _mock_db())
        assert ei.value.status_code == 403


# ── Challenge format (new onus-verification scheme) ──────────────────────────
class TestChallengeFormat:
    def test_meta_tag_format(self):
        assert verify_router._meta_tag("TOK") == '<meta name="onus-verification" content="TOK">'

    def test_file_path_is_well_known_txt(self):
        assert verify_router._file_path() == "/.well-known/onus-challenge.txt"

    def test_file_contents_format(self):
        assert verify_router._file_contents("TOK") == "onus-verification=TOK"


# ── Rate limiting ────────────────────────────────────────────────────────────
class TestRateLimit:
    def test_allows_then_blocks(self):
        import fakeredis
        import security
        r = fakeredis.FakeRedis(decode_responses=True)
        results = [security.rate_limit("b", 3, 60, r=r)[0] for _ in range(5)]
        assert results == [True, True, True, False, False]

    def test_fails_open_without_redis(self):
        import security
        broken = MagicMock()
        broken.incr.side_effect = RuntimeError("no redis")
        allowed, _ = security.rate_limit("b", 1, 60, r=broken)
        assert allowed is True
