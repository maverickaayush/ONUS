import logging
from celery import Task

logger = logging.getLogger(__name__)


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
