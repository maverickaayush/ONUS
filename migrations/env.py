import sys
import os
from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool
from alembic import context

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from config import settings
from database import Base
import models  # noqa: F401 - ensures all models are registered

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Override alembic.ini's static sqlalchemy.url with the app's own env-driven
# DATABASE_URL (config.py / .env), so migrations always target the same DB
# the app connects to — critical in Docker, where the ini's hardcoded
# 'localhost' would never reach the 'postgres' service.
config.set_main_option('sqlalchemy.url', settings.DATABASE_URL)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
