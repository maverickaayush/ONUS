import logging
from tasks.celery_app import app
from tasks.base_task import BaseTask, normalize_finding, update_module_status

logger = logging.getLogger(__name__)


@app.task(base=BaseTask, name='tasks.owasp.run_owasp')
def run_owasp(scan_id: str, domain: str) -> list:
    """OWASP Top 10 module stub — replaced in Step 5 (SQLi, XSS, IDOR, traversal, open redirect)."""
    update_module_status(scan_id, 'owasp', 'running')
    try:
        findings = []
        update_module_status(scan_id, 'owasp', 'complete')
        return findings
    except Exception as e:
        logger.error("owasp failed scan=%s: %s", scan_id, e)
        update_module_status(scan_id, 'owasp', 'failed')
        return []
