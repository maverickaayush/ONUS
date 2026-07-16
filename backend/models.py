import uuid
from datetime import datetime
from sqlalchemy import (
    Column, String, Boolean, Integer, Enum as SAEnum,
    DateTime, LargeBinary, ForeignKey, Text, UniqueConstraint
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
from database import Base
import enum


class ScanStatus(str, enum.Enum):
    queued = "queued"
    running = "running"
    analysing = "analysing"
    awaiting_user_decision = "awaiting_user_decision"
    complete = "complete"
    failed = "failed"
    cancelled = "cancelled"


class User(Base):
    """Hosted-tier user account (routers/auth.py). Only used when
    config.REQUIRE_AUTH is True — local/self-hosted ONUS has no users.

    Passwords are Argon2id hashes (security.py); the plaintext is never stored
    or logged. OTP codes and browser sessions live in Redis, not here, so this
    table only carries durable identity + email-verification state.
    """
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String(255), nullable=False, unique=True, index=True)  # normalized
    # Nullable: OAuth-only users (Google/GitHub) have no password. Password
    # users still set it; verify_password treats None as "no password login".
    password_hash = Column(String(255), nullable=True)
    email_verified = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=True)

    providers = relationship("AuthProvider", back_populates="user",
                             cascade="all, delete-orphan")


class AuthProvider(Base):
    """External OAuth identity linked to a User (routers/auth.py + oauth.py).

    A single user may hold several providers PLUS a password — all resolving to
    ONE user via account-linking on a verified email, so no duplicate accounts.
    Password auth is NOT stored here (that's User.password_hash); this table is
    OAuth identities only. Only used when config.REQUIRE_AUTH is True.
    """
    __tablename__ = "auth_providers"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False, index=True)
    provider = Column(String(16), nullable=False)            # 'google' | 'github'
    provider_user_id = Column(String(255), nullable=False)   # stable id at the provider
    provider_metadata = Column(JSONB, nullable=True)         # login/name/avatar, non-secret
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="providers")

    __table_args__ = (
        UniqueConstraint("provider", "provider_user_id", name="uq_provider_identity"),
    )


class Scan(Base):
    __tablename__ = "scans"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    domain = Column(String(255), nullable=False)
    status = Column(SAEnum(ScanStatus), nullable=False, default=ScanStatus.queued)
    authorized = Column(Boolean, nullable=False, default=False)
    # 'quick' (passive-only profile) | 'full' (all 8 active modules). Default
    # 'full' preserves prior behavior for local/self-hosted callers that don't
    # send a mode.
    scan_type = Column(String(8), nullable=False, default='full')
    # Owner in hosted (REQUIRE_AUTH) mode; NULL for local/self-hosted scans.
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True, index=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    # Set the moment a scan is handed to Celery (immediately at acceptance, or
    # later by tasks/queue_scheduler.py when a slot frees). Distinguishes a scan
    # WAITING for capacity (status='queued' AND dispatched_at IS NULL) from one
    # already dispatched and occupying a slot. Only written/read when
    # config.HOSTED_QUEUE_ENABLED is True; stays NULL (and unused) otherwise, so
    # this column is inert for self-hosted deployments.
    dispatched_at = Column(DateTime, nullable=True)
    module_statuses = Column(JSONB, nullable=True, default=dict)
    raw_findings = Column(JSONB, nullable=True)
    ai_analysis = Column(JSONB, nullable=True)
    risk_score = Column(Integer, nullable=True)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    # Bumped on every ORM-level write (status transitions, risk_score, etc.)
    # via onupdate - not bumped by base_task.py's raw-SQL module_statuses
    # update (that's deliberately a separate, high-frequency, per-module
    # signal; this column is "when did the scan's own record last change,"
    # for the /api/scans listing page's "Last updated" column).
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=True)

    report = relationship("Report", back_populates="scan", uselist=False)


class Report(Base):
    __tablename__ = "reports"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)
    pdf_data = Column(LargeBinary, nullable=False)
    generated_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("Scan", back_populates="report")


class DomainVerification(Base):
    """Domain-ownership (Domain Control Validation) record - routers/verify.py.

    Two-step, claim-key model (deployment-scoped, no user accounts):
      1. issue  -> a `pending` row with a random `token` the owner must place
                   (meta tag on the homepage, or a file under /.well-known/).
      2. check  -> if the token is found, status flips to `verified`, a secret
                   claim key is minted and only its SHA-256 hash is stored here
                   (`key_hash`). The plaintext key is returned to the caller
                   exactly once and never persisted.

    A scan for this domain is then gated on presenting that claim key (its hash
    must match a non-expired verified row). This closes the "A verifies, B rides
    it" bypass a domain-only cache would have, without needing login/accounts.
    Only enforced when config.REQUIRE_DOMAIN_VERIFICATION is True.
    """
    __tablename__ = "domain_verifications"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    # Owner in hosted (REQUIRE_AUTH) mode; NULL for the account-less claim-key
    # flow (REQUIRE_DOMAIN_VERIFICATION) so that path keeps working unchanged.
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True, index=True)
    domain = Column(String(255), nullable=False, index=True)
    method = Column(String(16), nullable=False)          # 'meta_tag' | 'http_file'
    token = Column(String(96), nullable=False)           # challenge value to place
    key_hash = Column(String(64), nullable=True)         # sha256(claim_key), set on verify
    status = Column(String(16), nullable=False, default="pending")  # 'pending' | 'verified'
    created_at = Column(DateTime, default=datetime.utcnow)
    verified_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=True)         # verified_at + TTL
