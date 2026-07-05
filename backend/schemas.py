from pydantic import BaseModel, field_validator, field_serializer
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

    v1 scope: form-based (application/x-www-form-urlencoded) login only.
    JSON-API logins (e.g. Juice Shop's Angular SPA POSTing JSON to
    /rest/user/login) aren't handled by this shape and are a fair follow-up,
    not this pass.

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


class ScanRequest(BaseModel):
    domain: str
    # NOTE: authorization is enforced in routers/scan.py so an unauthorized
    # request returns HTTP 403 (per Section 4.1) rather than a 422 schema error.
    authorized: bool
    notes: Optional[str] = None
    auth: Optional[AuthConfig] = None

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
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


class ScanResponse(BaseModel):
    job_id: UUID
    status: str
    domain: str


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


class FindingsResponse(BaseModel):
    executive_summary: str
    risk_score: int
    total_critical: int
    total_high: int
    total_medium: int
    total_low: int
    total_informational: int
    findings: List[FindingSchema]
