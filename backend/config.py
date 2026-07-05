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


settings = Settings()
