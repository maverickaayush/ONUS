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
import ipaddress
import logging
import secrets
import socket
from datetime import datetime, timedelta
from html.parser import HTMLParser

import urllib3
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import and_
from sqlalchemy.orm import Session

from config import settings
from database import get_db
from models import DomainVerification
from schemas import DomainVerifyRequest, DomainVerifyIssueResponse, DomainVerifyCheckResponse
from security import domain_covers, get_current_user, enforce_rate_limit

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["verify"])

_META_NAME = "onus-verification"
_CHALLENGE_FILE = ".well-known/onus-challenge.txt"
_FETCH_TIMEOUT = 8             # seconds connect/read per GET
_MAX_HTML_BYTES = 512 * 1024   # only the homepage <head> matters; cap the read
_MAX_FILE_BYTES = 1024         # the challenge file is tiny; cap it hard


def _hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def _meta_tag(token: str) -> str:
    return f'<meta name="{_META_NAME}" content="{token}">'


def _file_path(_token: str = "") -> str:
    # Fixed public path (not token-based); the token lives in the file contents.
    return f"/{_CHALLENGE_FILE}"


def _file_contents(token: str) -> str:
    return f"onus-verification={token}"


class _MetaFinder(HTMLParser):
    """Collects the `content` of every <meta name="onus-verification"> — a real
    HTML parse, not a substring/regex match, so attribute order/quoting/comments
    can't fool it."""
    def __init__(self, name: str):
        super().__init__()
        self._name = name.lower()
        self.contents: list[str] = []

    def handle_starttag(self, tag: str, attrs):
        if tag.lower() != "meta":
            return
        d = {(k or "").lower(): (v or "") for k, v in attrs}
        if d.get("name", "").lower() == self._name:
            self.contents.append(d.get("content", ""))


def _meta_content_matches(html: str, token: str) -> bool:
    p = _MetaFinder(_META_NAME)
    try:
        p.feed(html)
    except Exception:  # noqa: BLE001 - malformed HTML must not raise
        pass
    return any(c.strip() == token for c in p.contents)


def _validate_resolved_host(host: str) -> str:
    """Resolve `host` and reject if ANY resolved address is internal/reserved
    (SSRF guard). Returns a single validated IP to pin the connection to
    (DNS-rebinding safe: we connect to THIS address, not re-resolve). Raises
    ValueError on resolution failure or a disallowed address."""
    # An IP literal that slipped past normalize_domain: validate directly.
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise ValueError("could not resolve host")
    ips = {info[4][0] for info in infos}
    if not ips:
        raise ValueError("host did not resolve to any address")
    for ip in ips:
        a = ipaddress.ip_address(ip.split("%")[0])  # strip zone id
        if (a.is_private or a.is_loopback or a.is_link_local or a.is_multicast
                or a.is_reserved or a.is_unspecified):
            # Covers loopback v4/v6, RFC1918, link-local incl. 169.254.169.254
            # (cloud metadata), multicast, reserved, 0.0.0.0/::.
            raise ValueError(f"host resolves to a disallowed address ({ip})")
    v4 = [ip for ip in ips if ipaddress.ip_address(ip.split('%')[0]).version == 4]
    return (v4 or sorted(ips))[0]


def _safe_get(scheme: str, host: str, path: str, max_bytes: int) -> tuple[int, str]:
    """SSRF-safe GET: resolves + validates the host, pins the connection to the
    validated IP (rebinding-safe), sends the real Host header, never follows
    redirects, and reads at most `max_bytes`. Returns (status, body_text).
    Raises ValueError if the host is disallowed."""
    ip = _validate_resolved_host(host)
    port = 443 if scheme == "https" else 80
    timeout = urllib3.Timeout(connect=_FETCH_TIMEOUT, read=_FETCH_TIMEOUT, total=_FETCH_TIMEOUT + 4)
    headers = {"Host": host, "User-Agent": "ONUS-DomainVerify/1.0"}
    if scheme == "https":
        pool = urllib3.HTTPSConnectionPool(
            ip, port=port, cert_reqs="CERT_NONE", assert_hostname=False,
            server_hostname=host, timeout=timeout, retries=False)
    else:
        pool = urllib3.HTTPConnectionPool(ip, port=port, timeout=timeout, retries=False)
    try:
        r = pool.request("GET", path, headers=headers, redirect=False, preload_content=False)
        body = r.read(max_bytes)
        r.release_conn()
        return r.status, body.decode("utf-8", "ignore")
    finally:
        pool.close()


def verify_domain_control(domain: str, method: str, token: str) -> tuple[bool, str]:
    """Re-observe `domain` for `token` via `method`. Returns (ok, reason). Tries
    HTTPS then HTTP. Never raises - resolution/SSRF/network problems become
    (False, reason). Redirects are never followed (an open redirect on the
    target can't satisfy the challenge)."""
    if method == "http_file":
        expected = _file_contents(token)
        last = "no response"
        for scheme in ("https", "http"):
            try:
                status, body = _safe_get(scheme, domain, f"/{_CHALLENGE_FILE}", _MAX_FILE_BYTES)
            except ValueError as e:
                return False, str(e)  # SSRF/resolution: same for both schemes
            except Exception as e:  # noqa: BLE001
                last = f"{scheme} request failed: {type(e).__name__}"
                continue
            if status == 200:
                if body.strip() == expected:
                    return True, "file present"
                last = f"{scheme}: file found but contents did not match"
            else:
                last = f"{scheme}: HTTP {status} (expected 200, redirects not followed)"
        return False, last

    # method == 'meta_tag'
    last = "no response"
    for scheme in ("https", "http"):
        try:
            status, body = _safe_get(scheme, domain, "/", _MAX_HTML_BYTES)
        except ValueError as e:
            return False, str(e)
        except Exception as e:  # noqa: BLE001
            last = f"{scheme} request failed: {type(e).__name__}"
            continue
        if status != 200:
            last = f"{scheme}: HTTP {status} (expected 200, redirects not followed)"
            continue
        if _meta_content_matches(body, token):
            return True, "meta tag present"
        last = f"{scheme}: homepage loaded but the {_META_NAME} meta tag was not found"
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


def user_has_verified_domain(db: Session, user_id) -> bool:
    """Does this user hold at least one live verified-domain row? Drives the
    frontend's 'verify_domain' vs 'ready' routing."""
    return db.query(DomainVerification).filter(
        and_(
            DomainVerification.user_id == user_id,
            DomainVerification.status == "verified",
            DomainVerification.expires_at > datetime.utcnow(),
        )
    ).first() is not None


def user_owns_domain(db: Session, user_id, target: str) -> bool:
    """Scan-authorization gate for REQUIRE_AUTH mode: does this user own a live
    verified domain that covers `target` (exact host or an authorized
    subdomain)? Uses label-boundary matching (security.domain_covers)."""
    rows = db.query(DomainVerification).filter(
        and_(
            DomainVerification.user_id == user_id,
            DomainVerification.status == "verified",
            DomainVerification.expires_at > datetime.utcnow(),
        )
    ).all()
    return any(domain_covers(r.domain, target) for r in rows)


def _require_hosted_user(user):
    """When REQUIRE_AUTH is on, domain challenges are per-user: caller must be
    authenticated with a verified email. Returns the user's id (or None in the
    account-less claim-key mode). Raises 401/403 otherwise."""
    if not settings.REQUIRE_AUTH:
        return None
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication required.")
    if not user.email_verified:
        raise HTTPException(status_code=403, detail="Email address not verified.")
    return user.id


@router.post("/verify/domain", response_model=DomainVerifyIssueResponse)
def issue_challenge(request: DomainVerifyRequest, db: Session = Depends(get_db),
                    user=Depends(get_current_user)):
    """Issue (or re-use) a pending challenge for the domain. Re-using the latest
    pending row keeps the token stable if the caller re-requests instructions.
    In REQUIRE_AUTH mode the row is bound to the authenticated user."""
    uid = _require_hosted_user(user)
    enforce_rate_limit(f"challenge:{uid or request.domain}",
                       settings.RATE_LIMIT_CHALLENGE, settings.RATE_LIMIT_CHALLENGE_WINDOW)
    existing = db.query(DomainVerification).filter(
        and_(
            DomainVerification.domain == request.domain,
            DomainVerification.method == request.method,
            DomainVerification.status == "pending",
            DomainVerification.user_id == uid,
        )
    ).order_by(DomainVerification.created_at.desc()).first()

    if existing:
        row = existing
    else:
        token = secrets.token_hex(24)   # the SECURE_TOKEN; backend-generated only
        row = DomainVerification(domain=request.domain, method=request.method,
                                 token=token, status="pending", user_id=uid)
        db.add(row)
        db.commit()
        db.refresh(row)

    return DomainVerifyIssueResponse(
        verification_id=row.id,
        domain=row.domain,
        method=row.method,
        token=row.token,
        meta_tag=_meta_tag(row.token),
        file_path=_file_path(),
        file_contents=_file_contents(row.token),
        instructions=(
            f'Add this exact tag inside your homepage <head>: {_meta_tag(row.token)}'
            if row.method == "meta_tag" else
            f'Serve a file at {_file_path()} whose entire contents are exactly: '
            f'{_file_contents(row.token)}'
        ) + '  Then POST to /api/verify/domain/{id}/check to complete verification.',
    )


@router.post("/verify/domain/{verification_id}/check", response_model=DomainVerifyCheckResponse)
def check_challenge(verification_id: str, db: Session = Depends(get_db),
                    user=Depends(get_current_user)):
    uid = _require_hosted_user(user)
    enforce_rate_limit(f"verify:{uid or verification_id}",
                       settings.RATE_LIMIT_VERIFY, settings.RATE_LIMIT_VERIFY_WINDOW)
    row = db.query(DomainVerification).filter(DomainVerification.id == verification_id).first()
    if row is None or (settings.REQUIRE_AUTH and row.user_id != uid):
        # In hosted mode, don't reveal challenges that aren't the caller's.
        raise HTTPException(status_code=404, detail="Verification challenge not found")

    if row.status == "verified" and row.expires_at and row.expires_at > datetime.utcnow():
        # Already verified and still valid - do NOT re-mint the key (it is shown
        # exactly once). Re-issue + re-verify if the key was lost.
        return DomainVerifyCheckResponse(
            verified=True, domain=row.domain, expires_at=row.expires_at,
            detail="Already verified; claim key was issued once and is not shown again.",
        )

    # Pending challenges expire; a stale token can't be verified. Re-issue to
    # get a fresh one.
    if row.status == "pending" and row.created_at and (
        datetime.utcnow() - row.created_at
    ).total_seconds() > settings.DOMAIN_CHALLENGE_TTL_SECONDS:
        return DomainVerifyCheckResponse(
            verified=False, domain=row.domain,
            detail="Challenge expired. Request a new challenge and try again.",
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
