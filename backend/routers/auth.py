"""Hosted-tier authentication (only mounted logic-wise when REQUIRE_AUTH is on;
the routes always exist but a local deployment simply never calls them).

Flow: signup -> email OTP verify (establishes session) -> domain ownership
(routers/verify.py) -> scan. Sessions are opaque Redis-backed HttpOnly cookies
(security.py). All error text is generic — no stack traces, no internals.
"""
import logging

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"

from config import settings
from database import get_db
from email_service import EmailConfigError, send_otp_email
from models import User
from schemas import (
    AuthUserResponse, LoginRequest, OTPChallengeResponse, OTPVerifyRequest,
    ResendOTPRequest, SignupRequest,
)
import security
import oauth
from routers.verify import user_has_verified_domain

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/auth", tags=["auth"])


# ── cookie / state helpers ───────────────────────────────────────────────────
def _samesite() -> str:
    ss = (settings.SESSION_COOKIE_SAMESITE or "lax").lower()
    if ss not in ("lax", "strict", "none"):
        ss = "lax"
    # SameSite=None is only valid on a Secure cookie; refuse to emit an invalid
    # combination that browsers would silently drop.
    if ss == "none" and not settings.SESSION_COOKIE_SECURE:
        logger.warning("SESSION_COOKIE_SAMESITE=none requires Secure; falling back to 'lax'.")
        return "lax"
    return ss


def _set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=settings.SESSION_COOKIE_NAME, value=token, httponly=True,
        secure=settings.SESSION_COOKIE_SECURE, samesite=_samesite(),
        max_age=settings.SESSION_TTL_HOURS * 3600, path="/",
        domain=settings.SESSION_COOKIE_DOMAIN or None,
    )


def _clear_session_cookie(response: Response) -> None:
    response.delete_cookie(
        key=settings.SESSION_COOKIE_NAME, path="/",
        domain=settings.SESSION_COOKIE_DOMAIN or None,
    )


def _auth_state(user: User, db: Session) -> AuthUserResponse:
    # Product decision: domain ownership is NOT part of onboarding. A verified
    # user goes straight to the dashboard regardless of whether they own any
    # verified domain - target authorization happens later, only when they
    # request a FULL VAPT scan. So next_step is only 'verify_email' or 'ready';
    # has_verified_domain is informational (dashboard display), never routing.
    has_domain = user_has_verified_domain(db, user.id)
    step = "ready" if user.email_verified else "verify_email"
    from datetime import datetime
    from models import Scan
    month_start = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    used = db.query(Scan).filter(Scan.user_id == user.id, Scan.created_at >= month_start).count()
    return AuthUserResponse(
        id=user.id, email=user.email, email_verified=user.email_verified,
        has_verified_domain=has_domain, next_step=step,
        scans_this_month=used, scan_limit=settings.MAX_SCANS_PER_MONTH,
    )


def _send_otp_or_503(email: str) -> None:
    code = security.issue_otp(email)
    try:
        send_otp_email(email, code)
    except EmailConfigError:
        # Generic to the client; the real reason is logged inside email_service.
        raise HTTPException(status_code=503, detail="Email delivery is currently unavailable.")


def _challenge_response(email: str) -> OTPChallengeResponse:
    return OTPChallengeResponse(
        email=email,
        expires_in=security.otp_ttl_seconds(email),
        resend_in=security.otp_resend_wait_seconds(email),
    )


# ── endpoints ────────────────────────────────────────────────────────────────
@router.post("/signup", response_model=OTPChallengeResponse, status_code=201)
def signup(request: SignupRequest, http_request: Request, db: Session = Depends(get_db)):
    security.enforce_rate_limit(f"signup:{_client_ip(http_request)}",
                                settings.RATE_LIMIT_SIGNUP, settings.RATE_LIMIT_SIGNUP_WINDOW)
    policy_error = security.password_policy_error(request.password)
    if policy_error:
        raise HTTPException(status_code=400, detail=policy_error)

    existing = db.query(User).filter(User.email == request.email).first()
    if existing and existing.email_verified:
        raise HTTPException(status_code=409, detail="An account with this email already exists.")

    if existing:
        # Abandoned/unverified signup — let them restart with a fresh password.
        existing.password_hash = security.hash_password(request.password)
        db.commit()
    else:
        db.add(User(email=request.email,
                    password_hash=security.hash_password(request.password)))
        db.commit()

    _send_otp_or_503(request.email)
    return _challenge_response(request.email)


@router.post("/verify-otp", response_model=AuthUserResponse)
def verify_otp(request: OTPVerifyRequest, response: Response, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == request.email).first()
    if user is None:
        # Don't confirm whether the email exists.
        raise HTTPException(status_code=400, detail="Incorrect or expired code.")

    result = security.verify_otp(request.email, request.code)
    if result == security.OTP_INCORRECT:
        raise HTTPException(status_code=400, detail="Incorrect code.")
    if result == security.OTP_EXPIRED:
        raise HTTPException(status_code=400, detail="Code expired. Request a new one.")
    if result == security.OTP_TOO_MANY:
        raise HTTPException(status_code=429, detail="Too many attempts. Request a new code.")

    if not user.email_verified:
        user.email_verified = True
        db.commit()
    token = security.create_session(user.id)
    _set_session_cookie(response, token)
    return _auth_state(user, db)


@router.post("/resend-otp", response_model=OTPChallengeResponse)
def resend_otp(request: ResendOTPRequest, db: Session = Depends(get_db)):
    security.enforce_rate_limit(f"otp_resend:{request.email}",
                                settings.RATE_LIMIT_OTP_RESEND, settings.RATE_LIMIT_OTP_RESEND_WINDOW)
    user = db.query(User).filter(User.email == request.email).first()
    if user is None:
        raise HTTPException(status_code=400, detail="Incorrect or expired code.")
    if user.email_verified:
        raise HTTPException(status_code=400, detail="Email already verified.")

    wait = security.otp_resend_wait_seconds(request.email)
    if wait > 0:
        raise HTTPException(status_code=429, detail=f"Please wait {wait}s before requesting another code.")

    _send_otp_or_503(request.email)
    return _challenge_response(request.email)


@router.post("/login", response_model=AuthUserResponse)
def login(request: LoginRequest, response: Response, http_request: Request,
          db: Session = Depends(get_db)):
    security.enforce_rate_limit(f"login:{_client_ip(http_request)}",
                                settings.RATE_LIMIT_LOGIN, settings.RATE_LIMIT_LOGIN_WINDOW)
    user = db.query(User).filter(User.email == request.email).first()
    if user is None or not security.verify_password(request.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    if not user.email_verified:
        # Route into the OTP flow; send a fresh code if the cooldown allows
        # (don't fail login just because a recent code is still live).
        if security.otp_resend_wait_seconds(request.email) == 0:
            _send_otp_or_503(request.email)
        return _auth_state(user, db)

    token = security.create_session(user.id)
    _set_session_cookie(response, token)
    return _auth_state(user, db)


@router.post("/logout")
def logout(request: Request, response: Response):
    security.destroy_session(request.cookies.get(settings.SESSION_COOKIE_NAME))
    _clear_session_cookie(response)
    return {"ok": True}


@router.get("/me", response_model=AuthUserResponse)
def me(request: Request, db: Session = Depends(get_db)):
    user = security.get_current_user(request, db)
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication required.")
    return _auth_state(user, db)


# ── OAuth (Google / GitHub) ──────────────────────────────────────────────────
@router.get("/providers")
def auth_providers():
    """Which login methods the frontend should render. Password is always
    available; OAuth providers appear only when configured AND REQUIRE_AUTH is
    on (self-hosted gets password only)."""
    if not settings.REQUIRE_AUTH:
        return {"password": True, "google": False, "github": False}
    return {"password": True, **oauth.enabled_providers()}


def _callback_uri(provider: str) -> str:
    # Callback routes back through the frontend origin's same-origin /api proxy,
    # so the session cookie is set first-party. Register this exact URL with the
    # provider: {APP_URL}/api/auth/{provider}/callback.
    return f"{settings.APP_URL.rstrip('/')}/api/auth/{provider}/callback"


@router.get("/{provider}/login")
def oauth_login(provider: str):
    if not settings.REQUIRE_AUTH:
        raise HTTPException(status_code=404, detail="Not found")
    if provider not in oauth.SUPPORTED or not oauth.provider_enabled(provider):
        raise HTTPException(status_code=404, detail=f"{provider} sign-in is not configured.")
    url = oauth.build_authorize_url(provider, _callback_uri(provider))
    return RedirectResponse(url, status_code=307)


@router.get("/{provider}/callback")
def oauth_callback(provider: str, request: Request, db: Session = Depends(get_db),
                   code: str | None = None, state: str | None = None,
                   error: str | None = None):
    front = settings.APP_URL.rstrip("/")
    if not settings.REQUIRE_AUTH:
        raise HTTPException(status_code=404, detail="Not found")
    if error or not code or not state or provider not in oauth.SUPPORTED:
        return RedirectResponse(f"{front}/sign-in?error=oauth", status_code=303)
    try:
        identity = oauth.exchange_and_fetch(provider, code, state)
        user = oauth.upsert_oauth_user(db, identity)
    except oauth.OAuthError as e:
        logger.warning("oauth %s callback failed: %s", provider, e)
        return RedirectResponse(f"{front}/sign-in?error=oauth", status_code=303)

    token = security.create_session(user.id)
    redirect = RedirectResponse(f"{front}/", status_code=303)
    _set_session_cookie(redirect, token)
    return redirect
