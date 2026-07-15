"""Hosted-tier auth (security.py, email_service.py, routers/verify.py helpers).

Unit-style like the rest of the suite: pure logic direct, Redis via fakeredis,
DB-touching helpers via a MagicMock query chain. No live Postgres/Redis/DNS/HTTP.
"""
import os
import sys
from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock

import fakeredis
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import security
from config import settings
import email_service


@pytest.fixture
def r():
    return fakeredis.FakeRedis(decode_responses=True)


# ── Passwords ────────────────────────────────────────────────────────────────
class TestPasswords:
    def test_hash_is_not_plaintext_and_verifies(self):
        h = security.hash_password("hunter2very-strong-1")
        assert h != "hunter2very-strong-1"
        assert h.startswith("$argon2")
        assert security.verify_password("hunter2very-strong-1", h)

    def test_wrong_password_fails(self):
        h = security.hash_password("correct-horse-9")
        assert not security.verify_password("wrong-horse-9", h)

    def test_verify_never_raises_on_garbage_hash(self):
        assert security.verify_password("x", "not-a-hash") is False

    def test_hashes_are_salted_unique(self):
        assert security.hash_password("same-pass-123") != security.hash_password("same-pass-123")

    def test_policy_rejects_short(self):
        assert security.password_policy_error("aB3") is not None

    def test_policy_rejects_all_letters(self):
        assert security.password_policy_error("abcdefghijkl") is not None

    def test_policy_rejects_all_digits(self):
        assert security.password_policy_error("1234567890123") is not None

    def test_policy_accepts_good(self):
        assert security.password_policy_error("goodPassw0rd") is None


# ── Email normalization ──────────────────────────────────────────────────────
class TestEmailNormalize:
    def test_lower_and_strip(self):
        assert security.normalize_email("  User@Example.COM ") == "user@example.com"


# ── OTP ──────────────────────────────────────────────────────────────────────
class TestOTP:
    def test_generate_is_six_numeric_digits(self):
        for _ in range(50):
            code = security.generate_otp()
            assert len(code) == settings.OTP_LENGTH and code.isdigit()

    def test_issue_then_verify_ok_single_use(self, r):
        # deterministic code
        code = security.issue_otp("a@b.com", r=r)
        assert security.verify_otp("a@b.com", code, r=r) == security.OTP_OK
        # single use: consumed
        assert security.verify_otp("a@b.com", code, r=r) == security.OTP_EXPIRED

    def test_incorrect_code(self, r):
        security.issue_otp("a@b.com", r=r)
        assert security.verify_otp("a@b.com", "000000", r=r) in (
            security.OTP_INCORRECT, security.OTP_OK)  # OK only on a 1-in-1e6 fluke

    def test_expired_when_absent(self, r):
        assert security.verify_otp("nobody@b.com", "123456", r=r) == security.OTP_EXPIRED

    def test_attempt_limit_burns_code(self, r):
        security.issue_otp("a@b.com", r=r)
        results = [security.verify_otp("a@b.com", "999999", r=r)
                   for _ in range(settings.OTP_MAX_ATTEMPTS)]
        # The final permitted attempt trips the limit and burns the code.
        assert results[-1] == security.OTP_TOO_MANY
        assert security.OTP_OK not in results
        # code is gone -> now reads as expired
        assert security.verify_otp("a@b.com", "999999", r=r) == security.OTP_EXPIRED

    def test_new_issue_invalidates_previous(self, r):
        old = security.issue_otp("a@b.com", r=r)
        new = security.issue_otp("a@b.com", r=r)
        if old != new:
            assert security.verify_otp("a@b.com", old, r=r) == security.OTP_INCORRECT
        assert security.verify_otp("a@b.com", new, r=r) == security.OTP_OK

    def test_resend_cooldown_active_after_issue(self, r):
        security.issue_otp("a@b.com", r=r)
        assert security.otp_resend_wait_seconds("a@b.com", r=r) > 0

    def test_ttl_reported(self, r):
        security.issue_otp("a@b.com", r=r)
        ttl = security.otp_ttl_seconds("a@b.com", r=r)
        assert 0 < ttl <= settings.OTP_TTL_SECONDS


# ── Sessions ─────────────────────────────────────────────────────────────────
class TestSessions:
    def test_create_resolve_destroy(self, r):
        tok = security.create_session("user-123", r=r)
        assert security.resolve_session(tok, r=r) == "user-123"
        security.destroy_session(tok, r=r)
        assert security.resolve_session(tok, r=r) is None

    def test_resolve_empty_token(self, r):
        assert security.resolve_session("", r=r) is None
        assert security.resolve_session(None, r=r) is None


# ── Hostname-boundary domain matching ────────────────────────────────────────
class TestDomainCovers:
    def test_exact(self):
        assert security.domain_covers("example.com", "example.com")

    def test_subdomains_authorized(self):
        assert security.domain_covers("example.com", "api.example.com")
        assert security.domain_covers("example.com", "a.b.staging.example.com")

    def test_case_and_trailing_dot(self):
        assert security.domain_covers("Example.com", "API.example.com.")

    def test_rejects_suffix_trick(self):
        assert not security.domain_covers("example.com", "attackerexample.com")

    def test_rejects_domain_as_prefix_of_other(self):
        assert not security.domain_covers("example.com", "example.com.attacker.net")

    def test_subdomain_verification_does_not_grant_parent(self):
        assert not security.domain_covers("api.example.com", "example.com")

    def test_empty_is_false(self):
        assert not security.domain_covers("", "example.com")
        assert not security.domain_covers("example.com", "")


# ── user_owns_domain (DB via MagicMock; exercises domain_covers integration) ──
def _mock_db_returning(domains):
    rows = [SimpleNamespace(domain=d) for d in domains]
    db = MagicMock()
    db.query.return_value.filter.return_value.all.return_value = rows
    db.query.return_value.filter.return_value.first.return_value = rows[0] if rows else None
    return db


class TestUserOwnsDomain:
    def test_authorized_subdomain(self):
        from routers.verify import user_owns_domain
        db = _mock_db_returning(["example.com"])
        assert user_owns_domain(db, "uid", "shop.example.com")

    def test_unauthorized_domain(self):
        from routers.verify import user_owns_domain
        db = _mock_db_returning(["example.com"])
        assert not user_owns_domain(db, "uid", "evil.net")

    def test_no_verified_rows(self):
        from routers.verify import user_owns_domain
        db = _mock_db_returning([])
        assert not user_owns_domain(db, "uid", "example.com")

    def test_has_verified_domain_true(self):
        from routers.verify import user_has_verified_domain
        db = _mock_db_returning(["example.com"])
        assert user_has_verified_domain(db, "uid")


# ── Email backend production gate ────────────────────────────────────────────
class TestEmailGate:
    def test_console_refused_under_require_auth(self, monkeypatch):
        monkeypatch.setattr(settings, "REQUIRE_AUTH", True)
        monkeypatch.setattr(settings, "EMAIL_DEV_CONSOLE_OK", False)
        with pytest.raises(email_service.EmailConfigError):
            email_service._send_console("a@b.com", "123456")

    def test_console_allowed_locally(self, monkeypatch):
        monkeypatch.setattr(settings, "REQUIRE_AUTH", False)
        # Should not raise.
        email_service._send_console("a@b.com", "123456")

    def test_console_allowed_when_explicitly_opted_in(self, monkeypatch):
        monkeypatch.setattr(settings, "REQUIRE_AUTH", True)
        monkeypatch.setattr(settings, "EMAIL_DEV_CONSOLE_OK", True)
        email_service._send_console("a@b.com", "123456")


# ── SSRF / target guardrail (schemas.normalize_domain, reused by verify.py) ──
class TestSSRFGuardrail:
    @pytest.mark.parametrize("bad", [
        "localhost", "sub.localhost",
        "127.0.0.1", "127.0.0.53",           # IPv4 loopback
        "::1",                                 # IPv6 loopback
        "10.0.0.5", "192.168.1.1", "172.16.9.9",  # private v4
        "169.254.169.254",                     # link-local / cloud metadata
        "fe80::1",                             # link-local v6
    ])
    def test_rejects_internal_targets(self, bad):
        from schemas import normalize_domain
        with pytest.raises(ValueError):
            normalize_domain(bad)

    def test_accepts_public_domain(self):
        from schemas import normalize_domain
        assert normalize_domain("Example.COM") == "example.com"


# ── Open-source default guarantee ────────────────────────────────────────────
def test_require_auth_defaults_off():
    """A public-repo clone with defaults must stay tick-and-go."""
    from config import Settings
    assert Settings().REQUIRE_AUTH is False
