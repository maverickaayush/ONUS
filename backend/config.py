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
    # Where the 8 scanner modules actually execute (tasks/dispatch.py):
    #   'local'  - in-process subprocess tools (local Docker dev; needs the
    #              'full' Dockerfile target with all scanner binaries installed).
    #   'modal'  - dispatched to per-module Modal functions (production); the
    #              Oracle backend image then needs none of the amd64 scanner
    #              binaries (arm64-clean 'backend' target).
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
