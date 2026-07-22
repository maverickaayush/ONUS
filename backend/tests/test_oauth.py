"""OAuth (Google + GitHub): provider config, state/PKCE, code exchange +
userinfo normalization, and account-linking upsert. Outbound HTTP is mocked and
state lives in fakeredis — no network, no live Redis/Postgres."""
import json
import os
import sys
from urllib.parse import parse_qs, urlparse
from unittest.mock import MagicMock, patch
from uuid import uuid4

import fakeredis
import pytest
import requests as rq

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import oauth
from config import settings
from models import User, AuthProvider


@pytest.fixture
def r():
    return fakeredis.FakeRedis(decode_responses=True)


def _creds(monkeypatch, provider):
    monkeypatch.setattr(settings, f"{provider.upper()}_CLIENT_ID", "cid")
    monkeypatch.setattr(settings, f"{provider.upper()}_CLIENT_SECRET", "csecret")


# ── Provider config ──────────────────────────────────────────────────────────
class TestProviderEnabled:
    def test_disabled_without_creds(self, monkeypatch):
        monkeypatch.setattr(settings, "GOOGLE_CLIENT_ID", "")
        monkeypatch.setattr(settings, "GOOGLE_CLIENT_SECRET", "")
        assert oauth.provider_enabled("google") is False

    def test_enabled_with_creds(self, monkeypatch):
        _creds(monkeypatch, "github")
        assert oauth.provider_enabled("github") is True

    def test_enabled_providers_map(self, monkeypatch):
        _creds(monkeypatch, "google")
        monkeypatch.setattr(settings, "GITHUB_CLIENT_ID", "")
        monkeypatch.setattr(settings, "GITHUB_CLIENT_SECRET", "")
        assert oauth.enabled_providers() == {"google": True, "github": False}


# ── Authorize URL + state/PKCE ───────────────────────────────────────────────
class TestAuthorizeUrl:
    def test_google_has_pkce_and_stores_state(self, r, monkeypatch):
        _creds(monkeypatch, "google")
        url = oauth.build_authorize_url("google", "https://app/api/auth/google/callback", r=r)
        assert "accounts.google.com" in url
        assert "code_challenge=" in url and "code_challenge_method=S256" in url
        keys = r.keys("oauth_state:*")
        assert len(keys) == 1
        data = json.loads(r.get(keys[0]))
        assert data["provider"] == "google" and "code_verifier" in data

    def test_github_no_pkce(self, r, monkeypatch):
        _creds(monkeypatch, "github")
        url = oauth.build_authorize_url("github", "cb", r=r)
        assert "github.com/login/oauth/authorize" in url
        assert "code_challenge" not in url


# ── State validation ─────────────────────────────────────────────────────────
class TestStateValidation:
    def test_missing_state_raises(self, r):
        with pytest.raises(oauth.OAuthError):
            oauth.exchange_and_fetch("google", "code", "does-not-exist", r=r)

    def test_state_is_one_time(self, r, monkeypatch):
        _creds(monkeypatch, "github")
        url = oauth.build_authorize_url("github", "cb", r=r)
        state = parse_qs(urlparse(url).query)["state"][0]
        tok = MagicMock(); tok.json.return_value = {"access_token": "AT"}; tok.raise_for_status = MagicMock()
        u = MagicMock(); u.json.return_value = {"id": 1, "login": "d"}; u.raise_for_status = MagicMock()
        em = MagicMock(); em.json.return_value = [{"email": "d@x.com", "primary": True, "verified": True}]; em.raise_for_status = MagicMock()
        with patch("oauth.requests.post", return_value=tok), patch("oauth.requests.get", side_effect=[u, em]):
            oauth.exchange_and_fetch("github", "code", state, r=r)
        # second use of the same state must fail
        with pytest.raises(oauth.OAuthError):
            oauth.exchange_and_fetch("github", "code", state, r=r)


def _state_for(r, monkeypatch, provider):
    _creds(monkeypatch, provider)
    url = oauth.build_authorize_url(provider, "cb", r=r)
    return parse_qs(urlparse(url).query)["state"][0]


# ── Exchange + identity normalization ────────────────────────────────────────
class TestExchangeFetch:
    def test_google_identity_verified(self, r, monkeypatch):
        state = _state_for(r, monkeypatch, "google")
        tok = MagicMock(); tok.json.return_value = {"access_token": "AT"}; tok.raise_for_status = MagicMock()
        ui = MagicMock(); ui.json.return_value = {"sub": "G123", "email": "a@b.com", "email_verified": True, "name": "A"}; ui.raise_for_status = MagicMock()
        with patch("oauth.requests.post", return_value=tok), patch("oauth.requests.get", return_value=ui):
            ident = oauth.exchange_and_fetch("google", "code", state, r=r)
        assert ident == {
            "provider": "google", "provider_user_id": "G123", "email": "a@b.com",
            "email_verified": True, "metadata": {"name": "A", "picture": None},
        }

    def test_github_primary_verified_email(self, r, monkeypatch):
        state = _state_for(r, monkeypatch, "github")
        tok = MagicMock(); tok.json.return_value = {"access_token": "AT"}; tok.raise_for_status = MagicMock()
        user = MagicMock(); user.json.return_value = {"id": 555, "login": "dev", "name": "Dev"}; user.raise_for_status = MagicMock()
        emails = MagicMock(); emails.json.return_value = [
            {"email": "secondary@x.com", "primary": False, "verified": True},
            {"email": "dev@x.com", "primary": True, "verified": True},
        ]; emails.raise_for_status = MagicMock()
        with patch("oauth.requests.post", return_value=tok), patch("oauth.requests.get", side_effect=[user, emails]):
            ident = oauth.exchange_and_fetch("github", "code", state, r=r)
        assert ident["provider_user_id"] == "555"
        assert ident["email"] == "dev@x.com" and ident["email_verified"] is True

    def test_github_unverified_email_flagged(self, r, monkeypatch):
        state = _state_for(r, monkeypatch, "github")
        tok = MagicMock(); tok.json.return_value = {"access_token": "AT"}; tok.raise_for_status = MagicMock()
        user = MagicMock(); user.json.return_value = {"id": 9, "login": "u", "email": "pub@x.com"}; user.raise_for_status = MagicMock()
        emails = MagicMock(); emails.json.return_value = [{"email": "pub@x.com", "primary": True, "verified": False}]; emails.raise_for_status = MagicMock()
        with patch("oauth.requests.post", return_value=tok), patch("oauth.requests.get", side_effect=[user, emails]):
            ident = oauth.exchange_and_fetch("github", "code", state, r=r)
        assert ident["email_verified"] is False

    def test_token_exchange_failure_raises(self, r, monkeypatch):
        state = _state_for(r, monkeypatch, "google")
        with patch("oauth.requests.post", side_effect=rq.RequestException("boom")):
            with pytest.raises(oauth.OAuthError):
                oauth.exchange_and_fetch("google", "code", state, r=r)

    def test_no_access_token_raises(self, r, monkeypatch):
        state = _state_for(r, monkeypatch, "google")
        tok = MagicMock(); tok.json.return_value = {}; tok.raise_for_status = MagicMock()
        with patch("oauth.requests.post", return_value=tok):
            with pytest.raises(oauth.OAuthError):
                oauth.exchange_and_fetch("google", "code", state, r=r)


# ── Account-linking upsert (mocked DB) ───────────────────────────────────────
def _db(link=None, user=None):
    db = MagicMock()
    apq = MagicMock(); apq.filter.return_value.first.return_value = link
    uq = MagicMock(); uq.filter.return_value.first.return_value = user
    db.query.side_effect = lambda m: apq if m is AuthProvider else uq
    return db


def _ident(provider="google", pid="P1", email="new@x.com", verified=True):
    return {"provider": provider, "provider_user_id": pid, "email": email,
            "email_verified": verified, "metadata": {"k": "v"}}


class TestUpsert:
    def test_new_user_created_verified_no_password(self):
        db = _db(link=None, user=None)
        u = oauth.upsert_oauth_user(db, _ident())
        assert u.email == "new@x.com" and u.email_verified is True and u.password_hash is None
        added_types = [type(c.args[0]).__name__ for c in db.add.call_args_list]
        assert "User" in added_types and "AuthProvider" in added_types  # new account + provider link

    def test_existing_provider_link_logs_in(self):
        existing = User(email="a@b.com"); existing.id = uuid4(); existing.email_verified = True
        link = AuthProvider(user_id=existing.id, provider="google", provider_user_id="P1")
        db = _db(link=link, user=existing)
        u = oauth.upsert_oauth_user(db, _ident())
        assert u is existing
        # no NEW user created on a plain login
        assert not any(type(c.args[0]).__name__ == "User" for c in db.add.call_args_list)

    def test_account_linking_by_email_no_duplicate(self):
        existing = User(email="dev@x.com", password_hash="argon$hash"); existing.id = uuid4(); existing.email_verified = False
        db = _db(link=None, user=existing)
        u = oauth.upsert_oauth_user(db, _ident(provider="github", pid="GH9", email="dev@x.com", verified=True))
        assert u is existing and existing.email_verified is True  # linked + email now verified
        added = [c.args[0] for c in db.add.call_args_list]
        assert len(added) == 1 and isinstance(added[0], AuthProvider)  # only a link, no new user
        assert added[0].user_id == existing.id

    def test_unverified_email_rejected(self):
        db = _db(link=None, user=None)
        with pytest.raises(oauth.OAuthError):
            oauth.upsert_oauth_user(db, _ident(verified=False))

    def test_unverified_cannot_link_existing_account(self):
        existing = User(email="dev@x.com", password_hash="h"); existing.id = uuid4()
        db = _db(link=None, user=existing)
        with pytest.raises(oauth.OAuthError):  # takeover guard
            oauth.upsert_oauth_user(db, _ident(email="dev@x.com", verified=False))


# ── /providers endpoint gating ───────────────────────────────────────────────
class TestProvidersEndpoint:
    def test_self_hosted_reports_password_only(self, monkeypatch):
        from routers.auth import auth_providers
        monkeypatch.setattr(settings, "REQUIRE_AUTH", False)
        assert auth_providers() == {"password": True, "google": False, "github": False, "require_auth": False}

    def test_hosted_reports_configured(self, monkeypatch):
        from routers.auth import auth_providers
        monkeypatch.setattr(settings, "REQUIRE_AUTH", True)
        _creds(monkeypatch, "google")
        monkeypatch.setattr(settings, "GITHUB_CLIENT_ID", "")
        monkeypatch.setattr(settings, "GITHUB_CLIENT_SECRET", "")
        assert auth_providers() == {"password": True, "google": True, "github": False, "require_auth": True}
