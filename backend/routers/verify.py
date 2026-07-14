"""
Domain-ownership verification (Domain Control Validation) - claim-key model.

Flow (only enforced when config.REQUIRE_DOMAIN_VERIFICATION is True):

  POST /api/verify/domain            -> issue a challenge token for `domain`
                                        (place it as a homepage <meta> tag or a
                                        file under /.well-known/).
  POST /api/verify/domain/{id}/check -> re-observe the domain; if the token is
                                        present, mint a secret claim key (only
                                        its SHA-256 hash is stored) and return it
                                        ONCE. The domain is then verified until
                                        expires_at.

A scan for the domain must then present that claim key (POST /api/scan's
`claim_key`), whose hash must match a non-expired verified row. This binds the
verification to whoever holds the key - closing the "A verifies, B rides it"
bypass a domain-only cache would have - without needing user accounts.

Verification is strictly passive, read-only re-observation (one HTTP GET),
non-destructive, and obeys the same private-IP guardrail as scanning (via
schemas.normalize_domain). Cross-host redirects are NOT followed, so an open
redirect on the target can never be used to fake ownership.
"""
import hashlib
import logging
import re
import secrets
from datetime import datetime, timedelta

import requests
import urllib3
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import and_
from sqlalchemy.orm import Session

from config import settings
from database import get_db
from models import DomainVerification
from schemas import DomainVerifyRequest, DomainVerifyIssueResponse, DomainVerifyCheckResponse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["verify"])

_TOKEN_PREFIX = "onus-verify"
_WELL_KNOWN = ".well-known/onus-verify"
_FETCH_TIMEOUT = 10        # seconds per HTTP GET (inline endpoint - keep short)
_MAX_HTML_BYTES = 512 * 1024   # only the homepage <head> matters; cap the read


def _hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def _meta_tag(token: str) -> str:
    return f'<meta name="onus-verify" content="{token}">'


def _file_path(token: str) -> str:
    return f"/{_WELL_KNOWN}/{token}"


# Match the meta tag regardless of attribute order / quoting style, but require
# our exact token in content.
def _meta_present(html: str, token: str) -> bool:
    esc = re.escape(token)
    patterns = (
        rf'<meta[^>]+name=["\']onus-verify["\'][^>]+content=["\']{esc}["\']',
        rf'<meta[^>]+content=["\']{esc}["\'][^>]+name=["\']onus-verify["\']',
    )
    return any(re.search(p, html, re.IGNORECASE) for p in patterns)


def _get(url: str) -> requests.Response:
    """Single read-only GET. allow_redirects=False so a redirect to another host
    (or an open redirect on the target) can never satisfy the challenge - only a
    direct 2xx from the domain itself counts."""
    return requests.get(
        url, timeout=_FETCH_TIMEOUT, verify=False, allow_redirects=False,
        headers={"User-Agent": "ONUS-DomainVerify/1.0"}, stream=True,
    )


def verify_domain_control(domain: str, method: str, token: str) -> tuple[bool, str]:
    """Re-observe `domain` for `token` via `method`. Returns (ok, reason).
    Tries HTTPS then HTTP. Never raises - network errors become (False, reason)."""
    if method == "http_file":
        target_suffix = f"{_WELL_KNOWN}/{token}"
        for scheme in ("https", "http"):
            try:
                r = _get(f"{scheme}://{domain}/{target_suffix}")
            except requests.RequestException as e:
                last = f"{scheme} request failed: {e.__class__.__name__}"
                continue
            if r.status_code == 200:
                body = r.raw.read(len(token) + 16, decode_content=True).decode("utf-8", "ignore")
                if body.strip() == token:
                    return True, "file present"
                last = f"{scheme}: file found but contents did not match"
            else:
                last = f"{scheme}: HTTP {r.status_code} (expected 200, redirects not followed)"
        return False, last

    # method == 'meta_tag'
    for scheme in ("https", "http"):
        try:
            r = _get(f"{scheme}://{domain}/")
        except requests.RequestException as e:
            last = f"{scheme} request failed: {e.__class__.__name__}"
            continue
        if r.status_code != 200:
            last = f"{scheme}: HTTP {r.status_code} (expected 200, redirects not followed)"
            continue
        html = r.raw.read(_MAX_HTML_BYTES, decode_content=True).decode("utf-8", "ignore")
        if _meta_present(html, token):
            return True, "meta tag present"
        last = f"{scheme}: homepage loaded but the onus-verify meta tag was not found"
    return False, last


def domain_has_valid_claim(db: Session, domain: str, claim_key: str | None) -> bool:
    """Gate used by routers/scan.py: does `claim_key` prove a live, unexpired
    ownership claim for `domain`? Compares the key's hash - the plaintext key is
    never stored."""
    if not claim_key:
        return False
    row = db.query(DomainVerification).filter(
        and_(
            DomainVerification.domain == domain,
            DomainVerification.status == "verified",
            DomainVerification.key_hash == _hash_key(claim_key),
            DomainVerification.expires_at > datetime.utcnow(),
        )
    ).first()
    return row is not None


@router.post("/verify/domain", response_model=DomainVerifyIssueResponse)
def issue_challenge(request: DomainVerifyRequest, db: Session = Depends(get_db)):
    """Issue (or re-use) a pending challenge for the domain. Re-using the latest
    pending row keeps the token stable if the caller re-requests instructions."""
    existing = db.query(DomainVerification).filter(
        and_(
            DomainVerification.domain == request.domain,
            DomainVerification.method == request.method,
            DomainVerification.status == "pending",
        )
    ).order_by(DomainVerification.created_at.desc()).first()

    if existing:
        row = existing
    else:
        token = f"{_TOKEN_PREFIX}-{secrets.token_hex(16)}"
        row = DomainVerification(domain=request.domain, method=request.method,
                                 token=token, status="pending")
        db.add(row)
        db.commit()
        db.refresh(row)

    return DomainVerifyIssueResponse(
        verification_id=row.id,
        domain=row.domain,
        method=row.method,
        token=row.token,
        meta_tag=_meta_tag(row.token),
        file_path=_file_path(row.token),
        file_contents=row.token,
        instructions=(
            f'Add this exact tag inside your homepage <head>: {_meta_tag(row.token)}'
            if row.method == "meta_tag" else
            f'Serve a file at {_file_path(row.token)} whose entire contents are: {row.token}'
        ) + '  Then POST to /api/verify/domain/{id}/check to complete verification.',
    )


@router.post("/verify/domain/{verification_id}/check", response_model=DomainVerifyCheckResponse)
def check_challenge(verification_id: str, db: Session = Depends(get_db)):
    row = db.query(DomainVerification).filter(DomainVerification.id == verification_id).first()
    if row is None:
        raise HTTPException(status_code=404, detail="Verification challenge not found")

    if row.status == "verified" and row.expires_at and row.expires_at > datetime.utcnow():
        # Already verified and still valid - do NOT re-mint the key (it is shown
        # exactly once). Re-issue + re-verify if the key was lost.
        return DomainVerifyCheckResponse(
            verified=True, domain=row.domain, expires_at=row.expires_at,
            detail="Already verified; claim key was issued once and is not shown again.",
        )

    ok, reason = verify_domain_control(row.domain, row.method, row.token)
    if not ok:
        return DomainVerifyCheckResponse(verified=False, domain=row.domain, detail=reason)

    claim_key = f"onus-key-{secrets.token_urlsafe(32)}"
    now = datetime.utcnow()
    row.status = "verified"
    row.key_hash = _hash_key(claim_key)
    row.verified_at = now
    row.expires_at = now + timedelta(days=settings.DOMAIN_VERIFICATION_TTL_DAYS)
    db.commit()
    logger.info("Domain %s verified via %s (expires %s)", row.domain, row.method, row.expires_at)

    return DomainVerifyCheckResponse(
        verified=True, domain=row.domain, claim_key=claim_key, expires_at=row.expires_at,
        detail="Verified. Save this claim key - it is shown only once and is required to start scans.",
    )
