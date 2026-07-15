"""OAuth 2.0 (Google + GitHub) for the hosted tier. Reuses the existing Redis
session + HttpOnly cookie — no JWT. Authorization-code flow, server-side token
exchange + userinfo; state (CSRF) and PKCE (Google) held one-time in Redis.
Account linking is by VERIFIED email so a user with Google + GitHub + password
resolves to ONE account. Only exercised when config.REQUIRE_AUTH is True.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import secrets
from typing import Optional
from urllib.parse import urlencode

import requests

from config import settings
from security import get_redis, normalize_email

logger = logging.getLogger(__name__)

SUPPORTED = ("google", "github")


class OAuthError(Exception):
    """Any OAuth failure; callers map it to a generic sign-in redirect (never
    leak provider/network internals to the browser)."""


_PROVIDERS = {
    "google": {
        "authorize": "https://accounts.google.com/o/oauth2/v2/auth",
        "token": "https://oauth2.googleapis.com/token",
        "userinfo": "https://openidconnect.googleapis.com/v1/userinfo",
        "scope": "openid email profile",
        "pkce": True,
    },
    "github": {
        "authorize": "https://github.com/login/oauth/authorize",
        "token": "https://github.com/login/oauth/access_token",
        "userinfo": "https://api.github.com/user",
        "emails": "https://api.github.com/user/emails",
        "scope": "read:user user:email",
        "pkce": False,
    },
}

_TIMEOUT = 10


def _creds(provider: str) -> tuple[str, str]:
    if provider == "google":
        return settings.GOOGLE_CLIENT_ID, settings.GOOGLE_CLIENT_SECRET
    if provider == "github":
        return settings.GITHUB_CLIENT_ID, settings.GITHUB_CLIENT_SECRET
    return "", ""


def provider_enabled(provider: str) -> bool:
    cid, cs = _creds(provider)
    return provider in _PROVIDERS and bool(cid) and bool(cs)


def enabled_providers() -> dict:
    return {p: provider_enabled(p) for p in SUPPORTED}


def _state_key(state: str) -> str:
    return f"oauth_state:{state}"


def build_authorize_url(provider: str, redirect_uri: str, r=None) -> str:
    """Mint a one-time state (+ PKCE verifier for Google), stash it in Redis, and
    return the provider's authorization URL."""
    r = r or get_redis()
    cfg = _PROVIDERS[provider]
    cid, _ = _creds(provider)
    state = secrets.token_urlsafe(24)
    params = {
        "client_id": cid, "redirect_uri": redirect_uri, "response_type": "code",
        "scope": cfg["scope"], "state": state,
    }
    stash = {"provider": provider, "redirect_uri": redirect_uri}
    if cfg["pkce"]:
        verifier = secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        params["code_challenge"] = challenge
        params["code_challenge_method"] = "S256"
        stash["code_verifier"] = verifier
    if provider == "google":
        params["access_type"] = "online"
        params["prompt"] = "select_account"
    r.setex(_state_key(state), settings.OAUTH_STATE_TTL_SECONDS, json.dumps(stash))
    return f"{cfg['authorize']}?{urlencode(params)}"


def _pop_state(state: str, provider: str, r) -> dict:
    raw = r.get(_state_key(state))
    if not raw:
        raise OAuthError("Invalid or expired state")
    r.delete(_state_key(state))  # one-time use
    data = json.loads(raw)
    if data.get("provider") != provider:
        raise OAuthError("State/provider mismatch")
    return data


def exchange_and_fetch(provider: str, code: str, state: str, r=None) -> dict:
    """Validate state, exchange the code (with PKCE verifier for Google), then
    fetch + normalize the user identity. Returns
    {provider, provider_user_id, email, email_verified, metadata}."""
    r = r or get_redis()
    if provider not in _PROVIDERS:
        raise OAuthError("Unknown provider")
    cfg = _PROVIDERS[provider]
    cid, cs = _creds(provider)
    stash = _pop_state(state, provider, r)

    data = {
        "client_id": cid, "client_secret": cs, "code": code,
        "redirect_uri": stash["redirect_uri"], "grant_type": "authorization_code",
    }
    if stash.get("code_verifier"):
        data["code_verifier"] = stash["code_verifier"]
    try:
        tok = requests.post(cfg["token"], data=data,
                            headers={"Accept": "application/json"}, timeout=_TIMEOUT)
        tok.raise_for_status()
        access_token = tok.json().get("access_token")
    except (requests.RequestException, ValueError) as e:
        raise OAuthError("Token exchange failed") from e
    if not access_token:
        raise OAuthError("No access token returned")
    return _fetch_identity(provider, access_token)


def _fetch_identity(provider: str, access_token: str) -> dict:
    cfg = _PROVIDERS[provider]
    headers = {"Authorization": f"Bearer {access_token}", "Accept": "application/json"}
    try:
        resp = requests.get(cfg["userinfo"], headers=headers, timeout=_TIMEOUT)
        resp.raise_for_status()
        info = resp.json()
    except (requests.RequestException, ValueError) as e:
        raise OAuthError("Userinfo request failed") from e

    if provider == "google":
        pid = info.get("sub")
        email = info.get("email")
        # Spec: emails returned from Google are considered verified.
        verified = True
        metadata = {"name": info.get("name"), "picture": info.get("picture")}
    else:  # github
        pid = info.get("id")
        email, verified = _github_primary_email(access_token, info)
        metadata = {"login": info.get("login"), "name": info.get("name"),
                    "avatar": info.get("avatar_url")}

    if not pid:
        raise OAuthError("Provider returned no user id")
    if not email:
        raise OAuthError("Provider returned no email")
    return {
        "provider": provider, "provider_user_id": str(pid),
        "email": normalize_email(email), "email_verified": bool(verified),
        "metadata": metadata,
    }


def _github_primary_email(access_token: str, info: dict) -> tuple[Optional[str], bool]:
    """GitHub's /user often omits a private email, so read /user/emails and pick
    the primary VERIFIED address. Verification matters: we only link/create on a
    verified email (see upsert_oauth_user)."""
    headers = {"Authorization": f"Bearer {access_token}", "Accept": "application/json"}
    try:
        r = requests.get(_PROVIDERS["github"]["emails"], headers=headers, timeout=_TIMEOUT)
        r.raise_for_status()
        emails = r.json()
    except (requests.RequestException, ValueError):
        emails = []
    for e in emails:
        if e.get("primary") and e.get("verified"):
            return e.get("email"), True
    for e in emails:
        if e.get("verified"):
            return e.get("email"), True
    if info.get("email"):  # public profile email — treat as unverified
        return info.get("email"), False
    return None, False


def upsert_oauth_user(db, identity: dict):
    """Resolve the OAuth identity to a single User (account linking), creating or
    linking as needed. Never creates a duplicate. Requires a verified email to
    create OR link — an unverified provider email can't take over an account.
    """
    from models import User, AuthProvider

    provider = identity["provider"]
    pid = identity["provider_user_id"]
    email = identity["email"]
    verified = identity["email_verified"]

    # 1. Known provider identity -> straight login.
    link = db.query(AuthProvider).filter(
        AuthProvider.provider == provider,
        AuthProvider.provider_user_id == pid,
    ).first()
    if link:
        link.provider_metadata = identity.get("metadata")
        db.commit()
        return db.query(User).filter(User.id == link.user_id).first()

    # From here we create or link an account, which requires a verified email.
    if not verified:
        raise OAuthError("Provider email is not verified")

    # 2. Existing account with this email -> LINK the provider (no duplicate).
    user = db.query(User).filter(User.email == email).first()
    if user:
        db.add(AuthProvider(user_id=user.id, provider=provider,
                            provider_user_id=pid, provider_metadata=identity.get("metadata")))
        if not user.email_verified:
            user.email_verified = True
        db.commit()
        return user

    # 3. New OAuth-only account (no password; email pre-verified).
    user = User(email=email, password_hash=None, email_verified=True)
    db.add(user)
    db.flush()
    db.add(AuthProvider(user_id=user.id, provider=provider,
                        provider_user_id=pid, provider_metadata=identity.get("metadata")))
    db.commit()
    return user
