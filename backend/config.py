from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    DATABASE_URL: str = "postgresql://vapt:vapt_secure_2025@localhost:5432/vapt"
    REDIS_URL: str = "redis://localhost:6379/0"
    OLLAMA_URL: str = "http://localhost:11434"
    SECRET_KEY: str = "change-me-in-production"
    ALLOWED_HOSTS: str = "localhost,127.0.0.1"
    # Deployment posture. 'development' (default) is the self-hosted, localhost,
    # single-operator path — weak/default secrets only warn, so a fresh clone
    # `docker compose up` still boots. 'production' (or any REQUIRE_AUTH /
    # SESSION_COOKIE_SECURE hosted signal) makes validate_startup_security()
    # REFUSE to boot on a default SECRET_KEY or the shipped Postgres password —
    # a documented warning turned into an enforced guarantee. See main.py.
    ONUS_ENV: str = "development"
    # Remote ZAP daemon (Docker sidecar). Empty = run a local ZAP process
    # instead (native dev workflow) — see tasks/webscan.py.
    ZAP_URL: str = ""
    # Confidence verification stage (analysis/verifier.py) - passive
    # re-observation of verifiable findings between aggregation and scoring.
    ENABLE_VERIFICATION: bool = True
    # ZAP's session-data bind mount (same host dir the zap service writes to,
    # per docker-compose.yml's `zap`/`worker` volumes) - the worker needs this
    # to prune a scan's session files after its own PDF is generated (Section
    # 4.4's disk-growth concern; see scan_orchestrator.py's _finalize()).
    # Empty = pruning is a no-op (e.g. native dev, no shared volume set up).
    ZAP_SESSIONS_DIR: str = ""
    # Every module's internal tool subprocess timeouts and Celery soft/hard
    # limits are lab-tuned (DVWA/testphp.vulnweb.com - fast, small, no WAF).
    # Real-world targets are slower (WAF rate-limiting, larger content,
    # network latency), so scale every budget by this one knob instead of
    # hand-tuning each module's constants - see tasks/base_task.py's
    # scaled_timeout(). 1.5 = default real-world headroom; raise further via
    # env for known-slow targets, or drop to 1.0 to reproduce the original
    # lab-tuned timings.
    SCAN_TIMEOUT_MULTIPLIER: float = 1.5
    # Concurrent-scan cap (Section 8). Historically a 12 GB-RAM guard (ZAP +
    # every scanner ran on the one box). Post-migration, scanners run on Modal
    # (isolated, autoscaling) - so this is now a Modal-budget + target-politeness
    # rate guard on the shared credit, not a memory limit. Default lowered 5 -> 3.
    MAX_CONCURRENT_SCANS: int = 3
    # Hosted-only scan queue. When False (the default, and the ONLY value
    # self-hosted users ever see) a scan request past MAX_CONCURRENT_SCANS is
    # rejected with HTTP 429 - the original, unchanged behavior. When True
    # (set only on the hosted deployment) an over-capacity scan is instead
    # ACCEPTED and parked as status='queued' with dispatched_at=NULL, then
    # auto-started by tasks/queue_scheduler.py the moment a slot frees. No 429
    # for ordinary overflow. Purely additive: flag off => byte-identical to
    # the pre-queue code path, dispatched_at stays NULL and is never read.
    HOSTED_QUEUE_ENABLED: bool = False
    # Where the 8 scanner modules actually execute (tasks/dispatch.py):
    #   'local'  - in-process subprocess tools (local Docker dev; needs the
    #              'full' Dockerfile target with all scanner binaries installed).
    #   'modal'  - dispatched to per-module Modal functions (production); the
    #              orchestrator backend image then needs none of the scanner
    #              binaries (slim 'backend' target; the DigitalOcean x86_64
    #              droplet only orchestrates, it never runs a scanner tool).
    SCANNER_BACKEND: str = "local"
    # Deployed Modal app name that tasks/dispatch.py looks scanner functions up
    # in (modal.Function.from_name). Only used when SCANNER_BACKEND='modal'.
    MODAL_APP_NAME: str = "onus-scanners"
    # Bearer token for the Modal-hosted Ollama endpoint (analysis/ollama_client.py
    # sends it as Authorization only when non-empty). Empty for a local/native
    # Ollama that needs no auth.
    OLLAMA_AUTH_TOKEN: str = ""
    # AI-prose provider (analysis/ollama_client.py): 'ollama' (self-hosted Qwen,
    # local or Modal) or 'github' (GitHub Models, OpenAI-compatible - free with a
    # GitHub token, faster, more reliable JSON). Only the prose step is affected;
    # deterministic CVSS scoring + templates never touch any LLM.
    LLM_PROVIDER: str = "ollama"
    GITHUB_MODELS_URL: str = "https://models.github.ai/inference"
    GITHUB_MODELS_MODEL: str = "openai/gpt-4o-mini"
    GITHUB_MODELS_TOKEN: str = ""
    # Comma-separated CORS allow-origins (main.py). Env-driven so a hosted
    # frontend origin can be added without a code change; defaults to local dev.
    CORS_ORIGINS: str = "http://localhost:3000,http://127.0.0.1:3000"
    # Domain-ownership verification (routers/verify.py). Default OFF: a local,
    # single-operator, air-gapped deployment trusts its operator, so forcing
    # DCV there is pure friction. Turn ON for a shared/hosted instance where
    # strangers could otherwise scan domains they don't control - it then
    # requires a per-domain claim key (issued after a meta-tag/file challenge)
    # on every scan request. See routers/verify.py.
    REQUIRE_DOMAIN_VERIFICATION: bool = False
    # How long a verified domain stays verified before the claim must be
    # re-proved (days).
    DOMAIN_VERIFICATION_TTL_DAYS: int = 30
    # How long a PENDING ownership challenge stays valid before it must be
    # re-issued (seconds). Prevents a stale token lingering forever.
    DOMAIN_CHALLENGE_TTL_SECONDS: int = 3600

    # ── Hosted multi-tenant auth (routers/auth.py). Default OFF, same spirit as
    # REQUIRE_DOMAIN_VERIFICATION above: local/self-hosted ONUS is single-
    # operator and trusts its operator, so it stays tick-and-go — no signup, no
    # login, no email. Turn ON only for the hosted (Vercel frontend +
    # DigitalOcean backend) deployment, where create_scan then additionally
    # requires an authenticated, email-verified user who has proven ownership of
    # the target domain (or an authorized subdomain of it). A public-repo
    # clone with defaults never hits any of this.
    REQUIRE_AUTH: bool = False
    # Server-side password policy (the frontend meter is cosmetic only).
    PASSWORD_MIN_LENGTH: int = 10

    # Browser session: opaque token in an HttpOnly cookie, mapped to a user in
    # Redis (session:<token> -> user_id, with TTL). No JWT, no localStorage.
    SESSION_TTL_HOURS: int = 72
    SESSION_COOKIE_NAME: str = "onus_session"
    # Cookie flags for the real Vercel<->DigitalOcean cross-site topology are set
    # via env; defaults suit same-origin local dev. SameSite='none' REQUIRES
    # Secure=True (enforced in routers/auth.py) — don't set 'none' without TLS.
    SESSION_COOKIE_SECURE: bool = False
    SESSION_COOKIE_SAMESITE: str = "lax"        # 'lax' | 'strict' | 'none'
    SESSION_COOKIE_DOMAIN: str = ""             # e.g. '.onus.app'; empty = host-only

    # Email OTP (signup email verification). Codes are hashed in Redis, never
    # stored/logged in plaintext outside the dev console backend below.
    OTP_TTL_SECONDS: int = 300
    OTP_LENGTH: int = 6
    OTP_MAX_ATTEMPTS: int = 5
    OTP_RESEND_COOLDOWN_SECONDS: int = 60

    # Email delivery (email_service.py). 'console' just logs the OTP and is
    # DEV-ONLY. It is refused whenever REQUIRE_AUTH is on unless
    # EMAIL_DEV_CONSOLE_OK is *also* explicitly set — so a hosted deployment can
    # never silently fall back to printing OTPs to its logs.
    EMAIL_BACKEND: str = "console"              # 'console' | 'smtp'
    EMAIL_DEV_CONSOLE_OK: bool = False
    EMAIL_FROM: str = "ONUS <no-reply@onus.local>"
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_STARTTLS: bool = True

    # ── OAuth (hosted only). A provider is ENABLED only when its client id AND
    # secret are both set; otherwise its buttons/routes are inert. Self-hosted
    # (REQUIRE_AUTH off) never touches any of this. Do not introduce JWT — OAuth
    # reuses the existing Redis session + HttpOnly cookie.
    GOOGLE_CLIENT_ID: str = ""
    GOOGLE_CLIENT_SECRET: str = ""
    GITHUB_CLIENT_ID: str = ""
    GITHUB_CLIENT_SECRET: str = ""
    # Frontend base URL. OAuth callbacks route back through it (same-origin
    # /api proxy), and users land here after login. The callback URL registered
    # with each provider is {APP_URL}/api/auth/{provider}/callback.
    APP_URL: str = "http://localhost:3002"
    # TTL for the one-time OAuth state + PKCE verifier held in Redis.
    OAUTH_STATE_TTL_SECONDS: int = 600

    # Usage + abuse controls (hosted mode). Enforced server-side via Redis
    # counters (security.py) / a DB monthly count; the dashboard only displays
    # them. All windows in seconds.
    MAX_SCANS_PER_MONTH: int = 100            # per user, across quick + full
    RATE_LIMIT_SIGNUP: int = 10               # per IP
    RATE_LIMIT_SIGNUP_WINDOW: int = 3600
    RATE_LIMIT_LOGIN: int = 10                # per IP
    RATE_LIMIT_LOGIN_WINDOW: int = 900
    RATE_LIMIT_OTP_RESEND: int = 5            # per email (in addition to cooldown)
    RATE_LIMIT_OTP_RESEND_WINDOW: int = 3600
    RATE_LIMIT_CHALLENGE: int = 20            # ownership challenge creation, per user
    RATE_LIMIT_CHALLENGE_WINDOW: int = 3600
    RATE_LIMIT_VERIFY: int = 30              # ownership verification attempts, per user
    RATE_LIMIT_VERIFY_WINDOW: int = 3600
    RATE_LIMIT_QUICK_SCAN: int = 20          # quick assessments per user
    RATE_LIMIT_QUICK_SCAN_WINDOW: int = 3600
    RATE_LIMIT_FULL_SCAN: int = 20           # full scans per user
    RATE_LIMIT_FULL_SCAN_WINDOW: int = 86400


settings = Settings()


# Secrets that ship in the repo as placeholders. If any of these survives into a
# production boot the deployment is unsafe, so validate_startup_security() below
# refuses to start. Kept as a set (not a regex) so it's obvious what's blocked.
_KNOWN_WEAK_SECRETS = {
    "change-me-in-production",
    "change_me_in_production",
    "change_me_to_a_long_random_string",
    "change_me",
    "change-me",
}
_KNOWN_WEAK_DB_PASSWORDS = ("vapt_secure_2025",)


def _secret_is_weak() -> bool:
    s = settings.SECRET_KEY.strip()
    return s in _KNOWN_WEAK_SECRETS or "change" in s.lower() or len(s) < 32


def _db_password_is_weak() -> bool:
    return any(pw in settings.DATABASE_URL for pw in _KNOWN_WEAK_DB_PASSWORDS)


def is_production() -> bool:
    """A production/exposed posture — the only mode where weak secrets are fatal.

    Any one signal is enough: an explicit ONUS_ENV, hosted auth being on, or a
    cross-site Secure cookie (which only makes sense behind TLS). Self-hosted
    localhost defaults hit none of these, so `docker compose up` still boots.
    """
    return (
        settings.ONUS_ENV.strip().lower() in {"production", "prod"}
        or settings.REQUIRE_AUTH
        or settings.SESSION_COOKIE_SECURE
    )


# Marks a key this process generated for self-hosted use. Prefixed so a key that
# leaks into a hosted deployment is detectable and rejected there, rather than
# silently becoming the thing that signs real sessions.
_AUTOGEN_PREFIX = "onus-autogen-"


def _secret_key_file() -> "Path":
    from pathlib import Path

    return Path(__file__).resolve().parent.parent / ".secret_key"


def secret_is_autogenerated() -> bool:
    return settings.SECRET_KEY.strip().startswith(_AUTOGEN_PREFIX)


def ensure_secret_key() -> None:
    """Self-hosted convenience: generate a SECRET_KEY on first boot.

    When REQUIRE_AUTH is off there are no accounts, no sessions and no cookies to
    forge, so the key protects nothing. Making a newcomer hand-generate one was
    pure friction on the `clone -> docker compose up` path, and shipping a
    placeholder meant every self-hosted instance ran the same value.

    Deliberately does nothing in a production posture: there, a real operator
    must set SECRET_KEY explicitly and validate_startup_security() still refuses
    to boot without it. Also does nothing if a strong key is already set.

    The key persists to a gitignored .secret_key beside the app. In a container
    that file lives on the writable layer, so recreating the container
    regenerates it - harmless when REQUIRE_AUTH is off, since nothing signed
    with the old key outlives the container.
    """
    import logging

    log = logging.getLogger("onus.startup")
    if not _secret_is_weak():
        return  # operator set a real key; never override it
    if is_production():
        return  # production must be explicit - the guard below will refuse to boot

    path = _secret_key_file()
    try:
        existing = path.read_text().strip() if path.exists() else ""
        if existing:
            settings.SECRET_KEY = existing
            return
        import secrets as _secrets

        value = _AUTOGEN_PREFIX + _secrets.token_urlsafe(48)
        path.write_text(value)
        try:
            path.chmod(0o600)
        except OSError:
            pass  # non-POSIX or restrictive FS; the key is still process-local
        settings.SECRET_KEY = value
        log.info(
            "Generated a SECRET_KEY for self-hosted use and saved it to %s. "
            "This is fine for a single-operator local instance. Set SECRET_KEY "
            "explicitly before exposing this deployment or enabling REQUIRE_AUTH.",
            path,
        )
    except OSError as e:
        # Read-only FS: fall through on the in-memory default. The guard below
        # still warns, and self-hosted has nothing to protect.
        log.warning("Could not persist a generated SECRET_KEY (%s); using an ephemeral one.", e)
        import secrets as _secrets

        settings.SECRET_KEY = _AUTOGEN_PREFIX + _secrets.token_urlsafe(48)


def validate_startup_security() -> None:
    """Fail hard on unsafe production secrets; warn (never block) self-hosted.

    Called once at process start by main.py (API) and celery_app.py (worker) so
    both entrypoints enforce the same contract. Idempotent and side-effect-free
    apart from logging / raising.
    """
    import logging

    log = logging.getLogger("onus.startup")
    problems = []
    if _secret_is_weak():
        problems.append(
            "SECRET_KEY is a default/placeholder or too short (<32 chars). "
            "Generate one with: python -c \"import secrets; print(secrets.token_urlsafe(48))\""
        )
    if _db_password_is_weak():
        problems.append(
            "DATABASE_URL still contains the shipped placeholder Postgres password "
            "(vapt_secure_2025). Set a strong POSTGRES_PASSWORD."
        )
    if secret_is_autogenerated() and is_production():
        problems.append(
            "SECRET_KEY was auto-generated for self-hosted use and must not be "
            "reused in a production posture. Set an explicit SECRET_KEY."
        )


    if not problems:
        return

    if is_production():
        raise RuntimeError(
            "Refusing to start with insecure secrets in a production posture "
            f"(ONUS_ENV={settings.ONUS_ENV}, REQUIRE_AUTH={settings.REQUIRE_AUTH}). "
            "Fix these and restart:\n  - " + "\n  - ".join(problems)
        )
    for p in problems:
        log.warning("INSECURE DEFAULT (ok for local self-hosted, NOT for a public deployment): %s", p)
