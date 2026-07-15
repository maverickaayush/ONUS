"""Hosted-tier authentication (only mounted logic-wise when REQUIRE_AUTH is on;
the routes always exist but a local deployment simply never calls them).

Flow: signup -> email OTP verify (establishes session) -> domain ownership
(routers/verify.py) -> scan. Sessions are opaque Redis-backed HttpOnly cookies
(security.py). All error text is generic — no stack traces, no internals.
"""
import logging

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.orm import Session

from config import settings
from database import get_db
from email_service import EmailConfigError, send_otp_email
from models import User
from schemas import (
    AuthUserResponse, LoginRequest, OTPChallengeResponse, OTPVerifyRequest,
    ResendOTPRequest, SignupRequest,
)
import security
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
    has_domain = user_has_verified_domain(db, user.id)
    if not user.email_verified:
        step = "verify_email"
    elif not has_domain:
        step = "verify_domain"
    else:
        step = "ready"
    return AuthUserResponse(
        id=user.id, email=user.email, email_verified=user.email_verified,
        has_verified_domain=has_domain, next_step=step,
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
def signup(request: SignupRequest, db: Session = Depends(get_db)):
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
def login(request: LoginRequest, response: Response, db: Session = Depends(get_db)):
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
