"""
Scanner dispatch layer — the single seam between the Celery orchestrator (Oracle)
and where a module's work physically runs.

Each module is split into two halves (ARCHITECTURE.md / migration plan):

  - Pure half `scan_<module>(scan_id, domain, auth) -> build_module_result envelope`
    lives in tasks/<module>.py. It does ALL tool/subprocess work and returns the
    envelope. It touches NO DB and NO Redis, so it can run unchanged on a Modal
    container (which cannot reach Oracle's private Postgres/Redis).

  - Dispatcher: the `run_<module>` Celery task calls `dispatch_scan(...)` here,
    which owns the DB status writes and picks where the pure half runs:
      SCANNER_BACKEND=local  -> run it in-process (local Docker dev; the 'full'
                                image has the scanner binaries installed).
      SCANNER_BACKEND=modal  -> modal.Function.from_name(...).remote(...).

This keeps the finding (`normalize_finding`) and module-result
(`build_module_result`) contracts identical regardless of where a module ran,
and keeps Postgres/Redis private (Modal is stateless — the dispatcher reads auth
from Redis on Oracle and passes it in as an argument).
"""
import logging

from config import settings
from tasks.base_task import build_module_result

logger = logging.getLogger(__name__)

# Modules whose pure half actually uses an authenticated session (schemas.py's
# AuthConfig, stashed in Redis by routers/scan.py). The dispatcher fetches it
# once and passes it in, so the pure half never reads Redis itself. Every other
# module gets auth=None and ignores the param.
_AUTH_MODULES = {'webscan', 'owasp'}

# The one module whose id ('nuclei') differs from its file name ('nuclei_scan').
# The pure function is still `scan_<id>` (scan_nuclei) - only the import path
# differs. Modal function names also use `scan_<id>` (see modal_app/scanners.py).
_MODULE_FILE = {'nuclei': 'nuclei_scan'}


def _pure_fn(module: str):
    """Lazily import the module's pure `scan_<module>` half (avoids a circular
    import: tasks/<module>.py imports this module for its run_ task)."""
    import importlib
    mod = importlib.import_module(f'tasks.{_MODULE_FILE.get(module, module)}')
    return getattr(mod, f'scan_{module}')


def _get_auth(module: str, scan_id: str):
    if module not in _AUTH_MODULES:
        return None
    try:
        from tasks.auth_store import get_scan_auth
        return get_scan_auth(scan_id)
    except Exception as e:
        logger.warning("dispatch: could not fetch auth for scan %s: %s", scan_id, e)
        return None


def _run_modal(module: str, scan_id: str, domain: str, auth, quick: bool = False) -> dict:
    """Invoke the module's Modal function and return its envelope. Modal
    transport/timeout failures are turned into a failed/timeout envelope by the
    caller, so the existing decision-flow (retry/continue/cancel) still fires.

    quick only affects tech_fingerprint (WhatWeb-only). We pass the extra arg
    ONLY in that one quick case, so full scans keep calling the currently-
    deployed Modal functions with their existing 3-arg signature (no redeploy
    needed for full mode; a Modal redeploy is only required for hosted quick
    tech_fingerprint)."""
    import modal
    fn = modal.Function.from_name(settings.MODAL_APP_NAME, f'scan_{module}')
    if module == 'tech_fingerprint' and quick:
        return fn.remote(scan_id, domain, auth, True)
    return fn.remote(scan_id, domain, auth)


def dispatch_scan(module: str, scan_id: str, domain: str, quick: bool = False) -> dict:
    """Run a module's pure half locally or on Modal and return its
    build_module_result envelope. Pure routing - DB status writes stay in the
    run_<module> Celery task (module namespace). Never raises: a Modal
    transport/timeout failure becomes a failed/timeout envelope so the existing
    decision-flow (retry/continue/cancel) still fires.

    quick (tech_fingerprint only) selects WhatWeb-only, skipping WAFW00F's
    active WAF probes — the Quick Assessment profile."""
    auth = _get_auth(module, scan_id)
    try:
        if settings.SCANNER_BACKEND == 'modal':
            return _run_modal(module, scan_id, domain, auth, quick)
        if module == 'tech_fingerprint':
            return _pure_fn(module)(scan_id, domain, auth, quick)
        return _pure_fn(module)(scan_id, domain, auth)
    except Exception as e:
        # A Modal timeout (container hit its function timeout) reports as
        # status='timeout' so the operator sees a timeout, not a generic
        # failure; anything else is 'failed'. Both are non-'success'.
        is_timeout = 'timeout' in type(e).__name__.lower()
        status = 'timeout' if is_timeout else 'failed'
        logger.error("dispatch: module %s %s for scan %s (backend=%s): %s",
                     module, status, scan_id, settings.SCANNER_BACKEND, e)
        return build_module_result(module, [], {}, status=status,
                                   error=f'{type(e).__name__}: {e}')
