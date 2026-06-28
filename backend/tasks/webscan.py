import json
import logging
import os
import shutil
import subprocess
import time
from typing import List, Optional

import psutil
import requests
from zapv2 import ZAPv2

from tasks.base_task import BaseTask, normalize_finding, update_module_status
from tasks.celery_app import app

logger = logging.getLogger(__name__)
MODULE = 'webscan'

# ZAP risk string → normalized severity
_ZAP_RISK_MAP = {
    'High':           'High',
    'Medium':         'Medium',
    'Low':            'Low',
    'Informational':  'Informational',
    'False Positive': 'Informational',
}

# --- Timing budget -----------------------------------------------------------
# Webscan is the heaviest module: ZAP active scanning legitimately needs minutes.
# It therefore runs with a RAISED per-task Celery limit (see the run_webscan
# decorator) instead of the default 300/360 - otherwise the worst case below
# would be SIGKILL'd mid-scan, which breaks the chord and fails the whole scan.
#
#   ZAP readiness wait   : <= 60s   (_ZAP_READY_TIMEOUT)
#   ZAP spider + ascan   : <= 240s  (_ZAP_SCAN_BUDGET, combined hard cap)
#   Nikto                : <= 130s  (subprocess timeout; -maxtime 120s)
#   ----------------------------------------------------------------------
#   worst case           : <= ~430s  (well under the 480s soft / 540s hard limit)
_ZAP_READY_TIMEOUT = 60
_ZAP_SCAN_BUDGET = 240
_NIKTO_TIMEOUT = 130
_WEBSCAN_SOFT_LIMIT = 480
_WEBSCAN_HARD_LIMIT = 540


# ---------------------------------------------------------------------------
# ZAP process lifecycle helpers
# ---------------------------------------------------------------------------

def _zap_port(scan_id: str) -> int:
    """
    Derive a per-scan ZAP port so concurrent scans don't collide.
    Range 8090-8989. (hash() is per-process-randomized, but the port is computed
    and used within one task execution, so that's fine here.)
    """
    return 8090 + (hash(scan_id) % 900)


def _kill_zap(proc: Optional[subprocess.Popen]) -> None:
    """
    Terminate the ZAP daemon and all its children: graceful SIGTERM first,
    then SIGKILL after 5s, then reap the Popen so it can't become a zombie.
    Never raises - called from finally blocks.
    """
    if proc is None:
        return
    try:
        parent = psutil.Process(proc.pid)
        children = parent.children(recursive=True)
        for child in children:
            try:
                child.terminate()
            except psutil.NoSuchProcess:
                pass
        parent.terminate()

        gone, alive = psutil.wait_procs([parent] + children, timeout=5)
        for p in alive:
            try:
                p.kill()
            except psutil.NoSuchProcess:
                pass
    except psutil.NoSuchProcess:
        pass
    except Exception as e:
        logger.warning("ZAP kill warning (non-fatal): %s", e)
    finally:
        # Reap the subprocess handle so no zombie is left behind.
        try:
            proc.wait(timeout=3)
        except Exception:
            pass


def _start_zap(scan_id: str, port: int) -> Optional[subprocess.Popen]:
    """
    Start ZAP daemon and return the Popen handle, or None if zap.sh is missing.
    Does NOT wait for readiness - call _wait_for_zap() after this.
    """
    zap_cmd = None
    for candidate in ('zap.sh', 'zap', '/usr/share/zaproxy/zap.sh',
                      '/opt/zaproxy/zap.sh'):
        if shutil.which(candidate) or (os.path.isabs(candidate) and os.access(candidate, os.X_OK)):
            zap_cmd = candidate
            break

    if not zap_cmd:
        logger.warning("ZAP not found in PATH - web scan will use Nikto only")
        return None

    try:
        proc = subprocess.Popen(
            [
                zap_cmd, '-daemon',
                '-port', str(port),
                '-config', 'api.disablekey=true',
                '-config', 'connection.timeoutInSecs=60',
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        logger.info("ZAP daemon started (pid=%d) on port %d for scan %s",
                    proc.pid, port, scan_id)
        return proc
    except Exception as e:
        logger.error("Failed to start ZAP for scan %s: %s", scan_id, e)
        return None


def _wait_for_zap(port: int, timeout: int = _ZAP_READY_TIMEOUT) -> bool:
    """
    Poll ZAP's version endpoint every 2s for up to timeout seconds.
    Returns True when ZAP is ready, False if it never responds.
    """
    url = f'http://localhost:{port}/JSON/core/view/version/'
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            r = requests.get(url, timeout=2)
            if r.status_code == 200:
                logger.info("ZAP ready on port %d", port)
                return True
        except Exception:
            pass
        time.sleep(2)
    logger.warning("ZAP did not become ready within %ds on port %d", timeout, port)
    return False


# ---------------------------------------------------------------------------
# ZAP scanning
# ---------------------------------------------------------------------------

def _run_zap(scan_id: str, domain: str, target_url: str) -> List[dict]:
    """
    Run OWASP ZAP daemon: spider + active scan + collect alerts.
    Returns normalized findings. Kills the daemon even on exception.
    """
    findings = []
    port = _zap_port(scan_id)
    proc = None

    try:
        proc = _start_zap(scan_id, port)
        if proc is None:
            return findings

        if not _wait_for_zap(port, timeout=_ZAP_READY_TIMEOUT):
            logger.warning("ZAP not ready for scan %s - skipping ZAP", scan_id)
            return findings

        zap = ZAPv2(
            apikey='',
            proxies={
                'http': f'http://127.0.0.1:{port}',
                'https': f'http://127.0.0.1:{port}',
            },
        )

        scan_deadline = time.monotonic() + _ZAP_SCAN_BUDGET

        # --- Spider ---
        logger.info("ZAP spider starting for scan %s", scan_id)
        spider_id = zap.spider.scan(target_url)
        while time.monotonic() < scan_deadline:
            try:
                if int(zap.spider.status(spider_id)) >= 100:
                    break
            except Exception:
                break
            time.sleep(3)
        else:
            logger.warning("ZAP spider hit scan budget for scan %s", scan_id)

        # --- Active scan (only if budget remains) ---
        if time.monotonic() < scan_deadline:
            logger.info("ZAP active scan starting for scan %s", scan_id)
            ascan_id = zap.ascan.scan(target_url)
            while time.monotonic() < scan_deadline:
                try:
                    if int(zap.ascan.status(ascan_id)) >= 100:
                        break
                except Exception:
                    break
                time.sleep(5)
            else:
                logger.warning("ZAP active scan hit scan budget for scan %s - "
                               "collecting alerts found so far", scan_id)

        # --- Collect alerts (whatever exists, even on a budget cut) ---
        try:
            alerts = zap.core.alerts(baseurl=target_url)
            if not isinstance(alerts, list):
                alerts = []
        except Exception as e:
            logger.error("ZAP alert retrieval failed for scan %s: %s", scan_id, e)
            alerts = []

        logger.info("ZAP collected %d alerts for scan %s", len(alerts), scan_id)

        for alert in alerts:
            risk = alert.get('risk', 'Informational')
            severity = _ZAP_RISK_MAP.get(risk, 'Informational')
            evidence = alert.get('evidence', '') or alert.get('description', '')
            url = alert.get('url', target_url)
            findings.append(normalize_finding(
                module=MODULE,
                tool='zap',
                type_=f'zap_{alert.get("pluginId", "alert")}',
                title=alert.get('alert', 'ZAP Alert'),
                evidence=f'{url} | {evidence}',
                severity=severity,
                target=domain,
            ))

    except Exception as e:
        logger.error("ZAP unexpected error for scan %s: %s", scan_id, e)
    finally:
        _kill_zap(proc)
        logger.info("ZAP process cleaned up for scan %s", scan_id)

    return findings


# ---------------------------------------------------------------------------
# Nikto
# ---------------------------------------------------------------------------

def _run_nikto(scan_id: str, domain: str, target_url: str) -> List[dict]:
    """Run Nikto and return normalized findings."""
    findings = []
    out_path = f'/tmp/nikto_{scan_id}.json'
    try:
        subprocess.run(
            [
                'nikto', '-h', target_url,
                '-Format', 'json',
                '-o', out_path,
                '-Tuning', '1234578b',
                '-maxtime', '120s',
            ],
            timeout=_NIKTO_TIMEOUT,
            capture_output=True,
            check=False,
        )

        if not os.path.exists(out_path):
            logger.warning("Nikto produced no output for scan %s", scan_id)
            return findings

        with open(out_path) as f:
            raw = f.read().strip()
        if not raw:
            return findings

        data = json.loads(raw)

        # Nikto -Format json emits a list of host objects, each holding a
        # "vulnerabilities" list:  [{"host":..., "vulnerabilities":[{...}]}].
        # Handle that, a bare dict, and a flat list of vulns defensively.
        if isinstance(data, dict):
            hosts = [data]
        elif isinstance(data, list):
            hosts = data
        else:
            hosts = []

        for host in hosts:
            if not isinstance(host, dict):
                continue
            vulns = host.get('vulnerabilities', [])
            if not isinstance(vulns, list):
                continue
            for item in vulns:
                if not isinstance(item, dict):
                    continue
                msg = item.get('msg') or item.get('message') or ''
                uri = item.get('url') or item.get('uri') or ''
                method = item.get('method', '')
                parts = [p for p in (method, uri, msg) if p]
                evidence = ' | '.join(parts) if parts else str(item)
                findings.append(normalize_finding(
                    module=MODULE,
                    tool='nikto',
                    type_='nikto_finding',
                    title=(msg[:120] if msg else 'Nikto finding'),
                    evidence=evidence,
                    severity='Low',
                    target=domain,
                ))

    except subprocess.TimeoutExpired:
        logger.warning("Nikto timed out for scan %s", scan_id)
    except FileNotFoundError:
        logger.warning("Nikto not installed - skipping for scan %s", scan_id)
    except json.JSONDecodeError as e:
        logger.error("Nikto JSON parse error for scan %s: %s", scan_id, e)
    except Exception as e:
        logger.error("Nikto error for scan %s: %s", scan_id, e)
    finally:
        if os.path.exists(out_path):
            try:
                os.unlink(out_path)
            except OSError:
                pass

    return findings


# ---------------------------------------------------------------------------
# Main task
# ---------------------------------------------------------------------------

@app.task(
    base=BaseTask,
    name='tasks.webscan.run_webscan',
    soft_time_limit=_WEBSCAN_SOFT_LIMIT,
    time_limit=_WEBSCAN_HARD_LIMIT,
)
def run_webscan(scan_id: str, domain: str) -> list:
    """
    Web scan module: OWASP ZAP (spider + active scan) + Nikto.

    ZAP and Nikto are both optional - if either is missing the module continues
    with whatever is available. Partial results are still reported as 'complete'
    (not 'failed'). Runs with a raised per-task time limit because ZAP active
    scanning is the pipeline's long pole (see the timing-budget note above).
    """
    update_module_status(scan_id, MODULE, 'running')
    findings = []
    target_url = f'https://{domain}'

    try:
        findings.extend(_run_zap(scan_id, domain, target_url))
        findings.extend(_run_nikto(scan_id, domain, target_url))
        update_module_status(scan_id, MODULE, 'complete')
        return findings
    except Exception as e:
        logger.exception("webscan unexpected error scan=%s: %s", scan_id, e)
        update_module_status(scan_id, MODULE, 'failed')
        return findings
