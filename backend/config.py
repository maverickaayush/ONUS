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


settings = Settings()
