import logging
import shutil
import subprocess
from typing import Optional

from celery import Task

logger = logging.getLogger(__name__)


def get_tool_version(tool: str, *version_flags: str, timeout: int = 5) -> str:
    """
    Return the first line of `tool <version_flags>` output, 'not installed'
    if the binary isn't on PATH, or 'unknown' if it ran but produced nothing
    parseable. Every scanning module uses this to build its own
    tool_versions dict - call once per module run, not once per finding.
    """
    if not shutil.which(tool):
        return 'not installed'
    try:
        r = subprocess.run([tool, *version_flags], capture_output=True,
                            timeout=timeout, check=False)
        out = (r.stdout or r.stderr or b'').decode(errors='ignore').strip()
        return out.splitlines()[0] if out else 'unknown'
    except Exception:
        return 'unknown'


def build_module_result(module: str, findings: list, tool_versions: Optional[dict] = None,
                         status: str = 'success', error: Optional[str] = None,
                         duration_seconds: float = 0.0) -> dict:
    """
    Envelope every scanning module's Celery task returns, instead of a bare
    findings list. Lets the aggregator report which tools actually ran
    (Section 4.4) and makes module execution status visible instead of a
    failed module silently looking identical to a clean scan.

    status is one of 'success' | 'failed' | 'timeout' - never invented
    beyond what the module can actually observe about itself.
    """
    return {
        'module': module,
        'status': status,
        'findings': findings,
        'tool_versions': tool_versions or {},
        'finding_count': len(findings),
        'duration_seconds': round(duration_seconds, 2),
        'error': error,
    }


def update_module_status(scan_id: str, module_name: str, status: str) -> None:
    """Write a single module's status update directly to the DB."""
    from database import SessionLocal
    from models import Scan

    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            statuses = dict(scan.module_statuses or {})
            statuses[module_name] = status
            scan.module_statuses = statuses
            db.commit()
    except Exception as e:
        logger.error("update_module_status failed scan=%s module=%s: %s", scan_id, module_name, e)
    finally:
        db.close()


def normalize_finding(
    module: str,
    tool: str,
    type_: str,
    title: str,
    evidence: str,
    severity: str = 'Info',
    cvss: float = 0.0,
    target: str = '',
) -> dict:
    """
    Return a normalized finding dict matching the Section 4.3 schema.
    Every scanning module must use this helper - the aggregator depends on
    the presence of found_by and the exact field names.
    """
    return {
        'module': module,
        'tool': tool,
        'type': type_,
        'title': title,
        'evidence': str(evidence)[:500],
        'severity': severity,
        'cvss': cvss,
        'target': target,
        'found_by': [module],
    }


class BaseTask(Task):
    """
    Shared Celery base task for all five scanning modules.

    Scanning modules register with ``base=BaseTask`` and import the helpers
    via the contract line:

        from tasks.base_task import BaseTask, normalize_finding, update_module_status

    The helpers are also exposed as static methods (``self.normalize_finding``,
    ``self.update_module_status``). ``on_failure`` is a logging safety net -
    each module is still expected to catch its own exceptions, mark itself
    ``failed`` and return ``[]`` so the chord callback always fires with all
    five results.
    """
    abstract = True

    normalize_finding = staticmethod(normalize_finding)
    update_module_status = staticmethod(update_module_status)

    def on_failure(self, exc, task_id, args, kwargs, einfo):
        logger.error("Scanning task %s failed (task_id=%s): %s", self.name, task_id, exc)
