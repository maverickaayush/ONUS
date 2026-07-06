from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase
from config import settings

# SQLAlchemy's default pool (size=5, max_overflow=10 => 15 connections/process)
# was sized for the old, never-enforced "~3 concurrent scans" assumption. Each
# scanning module opens its own short-lived SessionLocal() for status updates
# (base_task.py's update_module_status), so MAX_CONCURRENT_SCANS scans x up to
# 8 modules each can briefly want a connection at once, per worker process -
# a too-small pool doesn't error, it just blocks callers for up to
# pool_timeout (default 30s) waiting for a free connection, which reads as a
# mysterious intermittent stall rather than an obvious failure. Scaled off
# the same knob that actually governs real concurrent load.
_POOL_SIZE = max(10, settings.MAX_CONCURRENT_SCANS * 4)
engine = create_engine(
    settings.DATABASE_URL, pool_pre_ping=True,
    pool_size=_POOL_SIZE, max_overflow=_POOL_SIZE,
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
