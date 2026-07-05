"""
Ephemeral, per-scan credential store for authenticated scanning.

The password never becomes a Celery task argument: Celery's stock logging
(`--loglevel=info`, no custom filters exist anywhere in this codebase) reprs
full task args at INFO for every task-received/task-succeeded line, so
passing it as a `run_X.s(scan_id, domain, auth)` arg would put it in plaintext
worker logs on disk. Instead it's written here once (routers/scan.py's
create_scan()) and read directly by the two tasks that need it (webscan.py,
owasp.py) - never logged, never passed as a task arg.

Never persisted to Postgres (models.py's Scan table) either - there's no
legitimate reason to retain a scan credential after the scan completes.
Deleted explicitly in scan_orchestrator.py's _finalize(), alongside the
ZAP-session-pruning added earlier this session. The TTL below is only a
backstop for paths that skip _finalize() (e.g. the `cancel` decision, which
sets status=cancelled directly with no Celery dispatch - Section 4.3b).

Caveat worth knowing, not solved here: if Redis persistence (RDB/AOF) is ever
turned on in docker-compose.yml, a credential could still land on disk via a
snapshot before its TTL/explicit delete - that's a Redis config knob outside
this feature's scope.
"""
import json
from typing import Optional

import redis

from config import settings

_TTL_SECONDS = 2400  # comfortably past routers/scan.py's STUCK_SCAN_DEADLINE;
                     # deleted explicitly in _finalize() regardless
_r = redis.Redis.from_url(settings.REDIS_URL)


def _key(scan_id: str) -> str:
    return f"scan_auth:{scan_id}"


def store_scan_auth(scan_id: str, auth: dict) -> None:
    _r.setex(_key(scan_id), _TTL_SECONDS, json.dumps(auth))


def get_scan_auth(scan_id: str) -> Optional[dict]:
    raw = _r.get(_key(scan_id))
    return json.loads(raw) if raw else None


def delete_scan_auth(scan_id: str) -> None:
    _r.delete(_key(scan_id))
