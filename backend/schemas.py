from pydantic import BaseModel, Field, field_validator, field_serializer
from typing import Optional, Dict, List, Literal
from datetime import datetime, timezone
from uuid import UUID


class AuthConfig(BaseModel):
    """
    Optional form-based login for authenticated scanning - webscan.py (ZAP
    context/forcedUser) and owasp.py (its own requests.Session) log in once
    before crawling/testing, so real vulnerabilities behind a login wall
    (the dominant gap across this tool's practicality testing - see
    docs/test_findings.md) are actually reachable.

    Never persisted (see tasks/auth_store.py's docstring) - routers/scan.py
    writes this straight to Redis, never onto the Scan row in models.py.

    Two login shapes, selected by login_type ('auto' by default - the login
    URL is GETted and sniffed, so the common case needs only login_url +
    username + password; 'form'/'json' force it):
      - 'form': application/x-www-form-urlencoded POST. owasp.py and
        webscan.py's ZAP script both GET the login page, submit every field on
        it with username/password overridden (picks up CSRF tokens + submit-
        button fields with no special-casing).
      - 'json': JSON-API login (modern SPAs - e.g. Juice Shop POSTing
        {email, password} to /rest/user/login). POSTs the creds as a JSON body
        (username_field/password_field double as the JSON keys), reads a bearer
        token out of the response via token_json_path, and sends it as
        token_header (default 'Authorization: Bearer <token>') on every
        subsequent request - owasp.py as a Session header, webscan.py via ZAP's
        Replacer add-on. See tasks/auth_login.py.

    logged_in_indicator is used by owasp.py's _make_session() only, as a
    one-time, best-effort check right after login (log a warning if it
    doesn't match, nothing more). webscan.py's ZAP setup deliberately never
    touches this field - confirmed by direct testing that handing the same
    regex to zap.authentication.set_logged_in_indicator() makes ZAP check it
    against every single response the spider/active-scanner receives
    (including CSS/JS/image/redirect/error responses that legitimately don't
    contain it), and ZAP's "Insights" add-on counts each non-match as an
    auth failure - hit its self-shutdown threshold in ~1 second of real
    scanning in testing. See webscan.py's auth-setup comment for the full
    story. Do not wire this field into ZAP's authentication config.
    """
    login_url: str
    username: str
    password: str
    username_field: str = "username"
    password_field: str = "password"
    logged_in_indicator: Optional[str] = None  # regex; None = skip the check - owasp.py only, see above
    # 'auto' (default) GETs the login URL and sniffs form vs JSON; 'form'/'json'
    # force it. See tasks/auth_login.py's resolve_login_type/detect_login_type.
    login_type: Literal["auto", "form", "json"] = "auto"
    # JSON login only. Optional: if omitted, the token is auto-discovered from
    # the login response (most token-shaped/JWT value wins).
    token_json_path: Optional[str] = None       # dot-path to the token, e.g. 'authentication.token'
    token_header: str = "Authorization"         # header the token is sent in
    token_header_prefix: str = "Bearer "        # value prefix (note trailing space)


def normalize_domain(v: str) -> str:
    """Normalize + validate a target host string (shared by ScanRequest and the
    domain-verification endpoints so a scan and its ownership check agree on
    exactly what 'the domain' is). Strips scheme/path/port, rejects
    localhost/private/loopback/link-local, requires a valid public domain or IP."""
    import validators
    import ipaddress

    host = v.strip().lower()

    # Accept full-URL input (the frontend submits a URL) by stripping the
    # scheme, any path, and a trailing :port.
    if "://" in host:
        host = host.split("://", 1)[1]
    host = host.split("/", 1)[0]
    if host.count(":") == 1:  # host:port - but not an IPv6 literal
        host = host.split(":", 1)[0]

    if not host:
        raise ValueError("Domain cannot be empty")

    # Reject localhost variations
    if host == "localhost" or host.endswith(".localhost"):
        raise ValueError("Scanning localhost is not permitted")

    # Reject private / loopback / link-local IP literals (RFC 1918 etc.)
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            raise ValueError("Scanning private/internal IP addresses is not permitted")
        # Public IP literal - allow it through.
        return host

    # Otherwise it must be a syntactically valid domain name.
    if not validators.domain(host):
        raise ValueError(f"Invalid domain format: {v}")

    return host


class ScanRequest(BaseModel):
    domain: str
    # NOTE: authorization is enforced in routers/scan.py so an unauthorized
    # request returns HTTP 403 (per Section 4.1) rather than a 422 schema error.
    authorized: bool
    # Scan mode is part of the request contract, not inferred from which button
    # the frontend clicked. 'quick' = passive-only profile (no target ownership
    # required); 'full' = the active VAPT pipeline (requires verified ownership
    # in hosted mode). Default 'full' preserves prior local/self-hosted behavior.
    mode: Literal["quick", "full"] = "full"
    notes: Optional[str] = None
    auth: Optional[AuthConfig] = None
    # Domain-ownership claim key (routers/verify.py). Only consulted when
    # config.REQUIRE_DOMAIN_VERIFICATION is True; the secret the caller received
    # after proving control of `domain`. Ignored when verification is disabled.
    claim_key: Optional[str] = None

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        return normalize_domain(v)


class ScanResponse(BaseModel):
    job_id: UUID
    status: str
    domain: str
    # Set only when the hosted queue accepted a scan into a full pipeline
    # (status 'queued', waiting for capacity): its 1-based place in line.
    # None for an immediately-started scan and for all self-hosted responses.
    queue_position: Optional[int] = None


# --- Domain-ownership verification (routers/verify.py) ---

class DomainVerifyRequest(BaseModel):
    domain: str
    method: str = "meta_tag"   # 'meta_tag' | 'http_file'

    @field_validator("domain")
    @classmethod
    def _validate_domain(cls, v: str) -> str:
        return normalize_domain(v)

    @field_validator("method")
    @classmethod
    def _validate_method(cls, v: str) -> str:
        if v not in ("meta_tag", "http_file"):
            raise ValueError("method must be 'meta_tag' or 'http_file'")
        return v


class DomainVerifyIssueResponse(BaseModel):
    verification_id: UUID
    domain: str
    method: str
    token: str
    # Ready-to-paste instructions for whichever method was requested.
    meta_tag: str          # <meta name="onus-verify" content="TOKEN">
    file_path: str         # /.well-known/onus-verify/TOKEN
    file_contents: str     # what the file must contain (the token)
    instructions: str


class DomainVerifyCheckResponse(BaseModel):
    verified: bool
    domain: str
    # Present ONLY on the transition to verified - shown once, never stored in
    # plaintext. The caller must keep it to start scans for this domain.
    claim_key: Optional[str] = None
    expires_at: Optional[datetime] = None
    detail: Optional[str] = None   # why it failed, when verified is False


# --- Hosted-tier auth (routers/auth.py; only active when REQUIRE_AUTH) ---

def _normalize_email(v: str) -> str:
    import validators
    e = v.strip().lower()
    if not validators.email(e):
        raise ValueError("Invalid email address")
    return e


class SignupRequest(BaseModel):
    email: str
    password: str

    @field_validator("email")
    @classmethod
    def _v_email(cls, v: str) -> str:
        return _normalize_email(v)


class LoginRequest(BaseModel):
    email: str
    password: str

    @field_validator("email")
    @classmethod
    def _v_email(cls, v: str) -> str:
        return _normalize_email(v)


class OTPVerifyRequest(BaseModel):
    email: str
    code: str

    @field_validator("email")
    @classmethod
    def _v_email(cls, v: str) -> str:
        return _normalize_email(v)


class ResendOTPRequest(BaseModel):
    email: str

    @field_validator("email")
    @classmethod
    def _v_email(cls, v: str) -> str:
        return _normalize_email(v)


class OTPChallengeResponse(BaseModel):
    """Returned by signup / resend so the frontend countdown reflects real
    server expiry rather than a hardcoded 5:00."""
    email: str
    expires_in: int          # seconds until the current OTP expires
    resend_in: int           # seconds until a resend is permitted (cooldown)


class AuthUserResponse(BaseModel):
    """Current auth state; drives the frontend's step routing."""
    id: UUID
    email: str
    email_verified: bool
    has_verified_domain: bool
    # 'verify_email' | 'ready' — domain ownership is NOT part of onboarding, so
    # 'verify_domain' is never emitted (kept in the union for compatibility).
    next_step: Literal["verify_email", "verify_domain", "ready"]
    # Usage display (dashboard "SCANS THIS MONTH n / limit"). Server-authoritative.
    scans_this_month: int = 0
    scan_limit: int = 0


class ScanStatusResponse(BaseModel):
    job_id: UUID
    domain: str
    status: str
    progress: int
    started_at: Optional[datetime]
    modules: Dict[str, str]
    # Only populated while status == 'awaiting_user_decision' - the operator
    # decision modal's reason for existing is showing exactly what failed.
    module_errors: Optional[Dict[str, str]] = None
    can_retry: Optional[bool] = None
    # Hosted queue only. queue_position: 1-based place in line while waiting for
    # capacity (None once running or when not queued). waiting_for_capacity: True
    # iff the scan is accepted but parked for a slot. Both default to the
    # not-queued shape, so existing clients and self-hosted are unaffected.
    queue_position: Optional[int] = None
    waiting_for_capacity: bool = False

    @field_serializer('started_at')
    def _serialize_started_at(self, dt: Optional[datetime]) -> Optional[str]:
        """
        Always emit an explicit UTC-marked ISO8601 string, regardless of
        whether the underlying datetime is naive or aware. Real bug found
        in production use: scan_orchestrator.py writes datetime.utcnow()
        (naive) into a plain DateTime column, so this was being serialized
        without a timezone suffix - the browser's `new Date(...)` then
        parsed it as LOCAL time (IST, UTC+5:30), inflating the computed
        elapsed-time display by exactly the timezone offset (~330 minutes
        observed as "Running for 331m" on a scan that had run for ~1 minute).
        """
        if dt is None:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat()


class ScanDecisionRequest(BaseModel):
    action: Literal['retry', 'continue', 'cancel']


class ScanModuleInfo(BaseModel):
    id: str
    label: str
    icon_hint: str
    description: str


class ScanModulesResponse(BaseModel):
    modules: List[ScanModuleInfo]


class FindingSchema(BaseModel):
    title: str
    severity: str
    cvss_score: float
    cvss_vector: Optional[str] = None
    owasp_category: Optional[str] = None
    cve_reference: Optional[str] = None
    evidence: str
    description: Optional[str] = None
    remediation: str
    priority: int
    module: str
    # Confidence-verification stage (analysis/verifier.py) already computes
    # these on every finding dict stored in scans.ai_analysis - this model
    # just stopped silently dropping them at the API boundary. No new
    # computation, no behavior change to the verification pipeline itself.
    # New as of this field's addition - see CHANGELOG.md.
    confidence: Optional[Literal['confirmed', 'probable', 'unverified']] = Field(
        default=None,
        description=(
            "Result of passive re-observation verification (see ARCHITECTURE.md's "
            "Confidence Verification section). 'confirmed': re-verified proof, or a "
            "module-level definitive signal. 'probable': default - not yet re-checked, "
            "either not verifiable or verification hasn't run. 'unverified': a "
            "verifier ran and failed to reproduce the finding (never dropped, only "
            "demoted - see verification_note)."
        ),
    )
    verification_note: Optional[str] = Field(
        default=None,
        description=(
            "Human-readable explanation from the verifier, present only on findings "
            "a verifier actually touched (confirmed or unverified, not probable)."
        ),
    )


class FindingsResponse(BaseModel):
    executive_summary: str
    risk_score: int
    total_critical: int
    total_high: int
    total_medium: int
    total_low: int
    total_informational: int
    findings: List[FindingSchema]


class ScanListItem(BaseModel):
    """One row of the GET /api/scans discovery listing - metadata only,
    never raw_findings/ai_analysis content (Section 4.1)."""
    job_id: UUID
    target: str
    status: str
    created_at: datetime
    updated_at: Optional[datetime]
    progress: int
    current_module: Optional[str] = None
    overall_score: Optional[int] = None
    awaiting_user_decision: bool
    # Failed-module names only (no per-module error text) - kept light for
    # a listing page; full error text stays exclusive to
    # ScanStatusResponse.module_errors on the single-scan detail endpoint.
    module_errors: Optional[List[str]] = None
    modules_completed: int
    modules_total: int

    @field_serializer('created_at', 'updated_at')
    def _serialize_timestamps(self, dt: Optional[datetime]) -> Optional[str]:
        # Same UTC-marked ISO8601 fix as ScanStatusResponse._serialize_started_at -
        # models.py still writes naive datetime.utcnow() values.
        if dt is None:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat()


class ScanListResponse(BaseModel):
    scans: List[ScanListItem]
    counts: Dict[str, int]
    total: int
    page: int
    page_size: int
    total_pages: int
