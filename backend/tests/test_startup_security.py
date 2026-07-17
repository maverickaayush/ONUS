"""Boot-time secret enforcement (config.validate_startup_security).

The contract: weak secrets only WARN under the self-hosted default posture, but
are a hard boot failure the moment any production signal is set — so a fresh
`docker compose up` still boots while a real deployment can't ship a footgun.
"""
import pytest

import config


@pytest.fixture
def s(monkeypatch):
    """Reset the relevant settings to the self-hosted defaults for each test."""
    monkeypatch.setattr(config.settings, "SECRET_KEY", "change-me-in-production")
    monkeypatch.setattr(config.settings, "DATABASE_URL",
                        "postgresql://vapt:vapt_secure_2025@localhost:5432/vapt")
    monkeypatch.setattr(config.settings, "ONUS_ENV", "development")
    monkeypatch.setattr(config.settings, "REQUIRE_AUTH", False)
    monkeypatch.setattr(config.settings, "SESSION_COOKIE_SECURE", False)
    return config.settings


def test_dev_default_warns_but_boots(s):
    # Weak secrets + development posture: must not raise.
    config.validate_startup_security()


def test_production_env_refuses_weak_secret(s, monkeypatch):
    monkeypatch.setattr(s, "ONUS_ENV", "production")
    with pytest.raises(RuntimeError, match="insecure secrets"):
        config.validate_startup_security()


def test_require_auth_refuses_weak_secret(s, monkeypatch):
    monkeypatch.setattr(s, "REQUIRE_AUTH", True)
    with pytest.raises(RuntimeError):
        config.validate_startup_security()


def test_strong_secrets_boot_in_production(s, monkeypatch):
    monkeypatch.setattr(s, "ONUS_ENV", "production")
    monkeypatch.setattr(s, "SECRET_KEY", "x9" * 30)  # 60 chars, no "change"
    monkeypatch.setattr(s, "DATABASE_URL",
                        "postgresql://vapt:A_Strong_Random_Pw_123@db:5432/vapt")
    config.validate_startup_security()


def test_short_secret_is_weak(s, monkeypatch):
    monkeypatch.setattr(s, "ONUS_ENV", "production")
    monkeypatch.setattr(s, "SECRET_KEY", "short123")  # <32 chars
    monkeypatch.setattr(s, "DATABASE_URL",
                        "postgresql://vapt:A_Strong_Random_Pw_123@db:5432/vapt")
    with pytest.raises(RuntimeError):
        config.validate_startup_security()
