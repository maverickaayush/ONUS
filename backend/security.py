"""Hosted-tier auth primitives (used only when config.REQUIRE_AUTH is True):

  * Argon2id password hashing + server-side password policy
  * Email normalization
  * Cryptographically-random 6-digit email OTP, stored *hashed* in Redis with
    TTL, single-use, per-code attempt limit, and resend cooldown
  * Opaque Redis-backed browser sessions (HttpOnly cookie -> session:<tok>)
  * Hostname-boundary domain matching for scan authorization
  * FastAPI current-user dependencies

Plaintext passwords and OTP codes are never stored or returned. OTP codes and
sessions live in Redis (not Postgres) so the only durable auth table is `users`.

Redis-touching helpers take an explicit `r` client (defaulting to the module
singleton) so tests can inject a fake without a live Redis.
"""
from __future__ import annotations

import hmac
import logging
import secrets
from hashlib import sha256
from typing import Optional
from uuid import UUID

import redis as _redis
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError
from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from config import settings
from database import get_db

logger = logging.getLogger(__name__)

# ── Passwords ──────────────────────────────────────────────────────────────
_ph = PasswordHasher()   # Argon2id defaults (maintained library; do not hand-roll)


def hash_password(plaintext: str) -> str:
    return _ph.hash(plaintext)


def verify_password(plaintext: str, stored_hash: str) -> bool:
    """Constant-time via the library. Never raises on a bad password/hash."""
    try:
        return _ph.verify(stored_hash, plaintext)
    except (VerifyMismatchError, InvalidHashError, Exception):
        return False


def password_policy_error(password: str) -> Optional[str]:
    """Server-side policy (the frontend meter is cosmetic). Returns an error
    string, or None if the password is acceptable."""
    if len(password) < settings.PASSWORD_MIN_LENGTH:
        return f"Password must be at least {settings.PASSWORD_MIN_LENGTH} characters."
    if not any(c.isalpha() for c in password):
        return "Password must contain at least one letter."
    if not any(c.isdigit() for c in password):
        return "Password must contain at least one number."
    return None


# ── Email ──────────────────────────────────────────────────────────────────
def normalize_email(email: str) -> str:
    return email.strip().lower()


# ── Redis singleton ──────────────────────────────────────────────────────────
_redis_client: Optional[_redis.Redis] = None


def get_redis() -> _redis.Redis:
    global _redis_client
    if _redis_client is None:
        _redis_client = _redis.Redis.from_url(settings.REDIS_URL, decode_responses=True)
    return _redis_client


# ── OTP ──────────────────────────────────────────────────────────────────────
def _otp_key(email: str) -> str:
    return f"otp:{email}"


def _cooldown_key(email: str) -> str:
    return f"otp_cooldown:{email}"


def _hash_code(code: str) -> str:
    # HMAC over SECRET_KEY so a Redis snapshot alone can't brute-force the
    # low-entropy 6-digit code offline. Short-lived + attempt-limited anyway.
    return hmac.new(settings.SECRET_KEY.encode(), code.encode(), sha256).hexdigest()


def generate_otp() -> str:
    """Cryptographically secure, zero-padded, exactly OTP_LENGTH digits."""
    upper = 10 ** settings.OTP_LENGTH
    return str(secrets.randbelow(upper)).zfill(settings.OTP_LENGTH)


def issue_otp(email: str, r: Optional[_redis.Redis] = None) -> str:
    """Mint a fresh code, invalidating any previous one for this email. Returns
    the plaintext code (for the email layer to send). Does NOT enforce cooldown
    — that's the resend endpoint's job; a first signup should always send."""
    r = r or get_redis()
    code = generate_otp()
    key = _otp_key(email)
    r.delete(key)  # invalidate previous active OTP
    r.hset(key, mapping={"hash": _hash_code(code), "attempts": "0"})
    r.expire(key, settings.OTP_TTL_SECONDS)
    r.setex(_cooldown_key(email), settings.OTP_RESEND_COOLDOWN_SECONDS, "1")
    return code


def otp_resend_wait_seconds(email: str, r: Optional[_redis.Redis] = None) -> int:
    """Seconds the caller must wait before a resend is allowed (0 = allowed)."""
    r = r or get_redis()
    ttl = r.ttl(_cooldown_key(email))
    return ttl if ttl and ttl > 0 else 0


def otp_ttl_seconds(email: str, r: Optional[_redis.Redis] = None) -> int:
    r = r or get_redis()
    ttl = r.ttl(_otp_key(email))
    return ttl if ttl and ttl > 0 else 0


# verify_otp outcomes
OTP_OK = "ok"
OTP_INCORRECT = "incorrect"
OTP_EXPIRED = "expired"
OTP_TOO_MANY = "too_many_attempts"


def verify_otp(email: str, code: str, r: Optional[_redis.Redis] = None) -> str:
    """Single-use verification. Returns one of the OTP_* constants. On success
    the code is consumed (deleted). Wrong guesses increment an attempt counter;
    past OTP_MAX_ATTEMPTS the code is burned and OTP_TOO_MANY is returned."""
    r = r or get_redis()
    key = _otp_key(email)
    data = r.hgetall(key)
    if not data:
        return OTP_EXPIRED
    attempts = int(data.get("attempts", "0"))
    if attempts >= settings.OTP_MAX_ATTEMPTS:
        r.delete(key)
        return OTP_TOO_MANY
    if hmac.compare_digest(data.get("hash", ""), _hash_code(code)):
        r.delete(key)
        return OTP_OK
    attempts += 1
    if attempts >= settings.OTP_MAX_ATTEMPTS:
        r.delete(key)
        return OTP_TOO_MANY
    r.hset(key, "attempts", str(attempts))
    return OTP_INCORRECT


# ── Sessions ─────────────────────────────────────────────────────────────────
def _session_key(token: str) -> str:
    return f"session:{token}"


def create_session(user_id, r: Optional[_redis.Redis] = None) -> str:
    r = r or get_redis()
    token = secrets.token_urlsafe(32)
    r.setex(_session_key(token), settings.SESSION_TTL_HOURS * 3600, str(user_id))
    return token


def resolve_session(token: str, r: Optional[_redis.Redis] = None) -> Optional[str]:
    if not token:
        return None
    r = r or get_redis()
    return r.get(_session_key(token))


def destroy_session(token: str, r: Optional[_redis.Redis] = None) -> None:
    if not token:
        return
    r = r or get_redis()
    r.delete(_session_key(token))


# ── Hostname-boundary domain matching (scan authorization) ───────────────────
def domain_covers(verified_domain: str, target: str) -> bool:
    """Does ownership of `verified_domain` authorize scanning `target`?

    Label-boundary match, NOT a naive suffix check:
      verified example.com  -> example.com, api.example.com, a.b.example.com  ✓
                            -> attackerexample.com, example.com.attacker.net  ✗
      verified api.example.com -> example.com  ✗  (a subdomain doesn't grant the parent)
    """
    v = (verified_domain or "").strip().lower().rstrip(".")
    t = (target or "").strip().lower().rstrip(".")
    if not v or not t:
        return False
    return t == v or t.endswith("." + v)


# ── FastAPI dependencies ─────────────────────────────────────────────────────
def get_current_user(request: Request, db: Session = Depends(get_db)):
    """Resolve the session cookie to a User, or None. Import models lazily to
    avoid a circular import at module load."""
    from models import User
    token = request.cookies.get(settings.SESSION_COOKIE_NAME)
    user_id = resolve_session(token)
    if not user_id:
        return None
    try:
        uid = UUID(user_id)
    except (ValueError, TypeError):
        return None
    return db.query(User).filter(User.id == uid).first()


def require_user(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication required.")
    return user


def require_verified_user(request: Request, db: Session = Depends(get_db)):
    user = require_user(request, db)
    if not user.email_verified:
        raise HTTPException(status_code=403, detail="Email address not verified.")
    return user
