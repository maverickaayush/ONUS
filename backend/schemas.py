from pydantic import BaseModel, field_validator
from typing import Optional, Dict, List
from datetime import datetime
from uuid import UUID


class ScanRequest(BaseModel):
    domain: str
    # NOTE: authorization is enforced in routers/scan.py so an unauthorized
    # request returns HTTP 403 (per Section 4.1) rather than a 422 schema error.
    authorized: bool
    notes: Optional[str] = None

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
        if host.count(":") == 1:  # host:port — but not an IPv6 literal
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
            # Public IP literal — allow it through.
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


class FindingSchema(BaseModel):
    title: str
    severity: str
    cvss_score: float
    cvss_vector: Optional[str] = None
    owasp_category: Optional[str] = None
    cve_reference: Optional[str] = None
    evidence: str
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
