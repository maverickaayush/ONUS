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


settings = Settings()
