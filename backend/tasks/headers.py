import logging
from tasks.celery_app import app
from tasks.base_task import BaseTask, normalize_finding, update_module_status

logger = logging.getLogger(__name__)


@app.task(base=BaseTask, name='tasks.headers.run_headers')
def run_headers(scan_id: str, domain: str) -> list:
    """HTTP headers module stub — replaced in Step 5 (security header analysis)."""
    update_module_status(scan_id, 'headers', 'running')
    try:
        findings = []
        update_module_status(scan_id, 'headers', 'complete')
        return findings
    except Exception as e:
        logger.error("headers failed scan=%s: %s", scan_id, e)
        update_module_status(scan_id, 'headers', 'failed')
        return []
