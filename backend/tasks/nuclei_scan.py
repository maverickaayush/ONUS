import json
import logging
import os
import subprocess
import time
from typing import List

from celery.exceptions import SoftTimeLimitExceeded

from tasks.base_task import (
    BaseTask, normalize_finding, update_module_status,
    get_tool_version, build_module_result, resolve_target_url,
)
from tasks.celery_app import app

logger = logging.getLogger(__name__)
MODULE = 'nuclei'

# Measured against a real target (DVWP, docs/test_findings.md): the curated
# template set genuinely took 550s end-to-end at -rate-limit 20 against a
# single host - the old 240s/300s/360s budget meant this module was being
# killed before completion on essentially every real scan, not just slow
# ones. Raised with margin above the observed 550s, same calibrate-from-
# measurement approach as recon/webscan/enumeration's own timeout budgets.
_NUCLEI_TIMEOUT = 600
_SOFT_LIMIT = 660
_HARD_LIMIT = 720

# Nuclei's own template-authored severity is treated as authoritative (community
# researchers know the CVE better than a generic per-type table) - map it
# straight to severity + a representative CVSS band rather than re-deriving it.
_SEVERITY_MAP = {
    'critical': ('Critical', 9.0),
    'high':     ('High', 7.5),
    'medium':   ('Medium', 5.5),
    'low':      ('Low', 3.5),
    'info':     ('Informational', 0.0),
    'unknown':  ('Informational', 0.0),
}


def _load_results(out_path: str) -> List[dict]:
    """Nuclei `-o <path> -jsonl` output: NDJSON, flushed to disk as each
    match is found. Real bug found during practicality testing: the curated
    template set (cves/, vulnerabilities/, misconfiguration/, exposed-
    panels/, technologies/, exposures/) genuinely takes longer than
    _NUCLEI_TIMEOUT (240s) at -rate-limit 20 against even one host, so
    subprocess.run(timeout=...) was killing nuclei mid-scan every time.
    The two dedicated "export" flags (-json-export, -jsonl-export) both
    turned out to buffer and write only once the run completes - confirmed
    directly by killing nuclei mid-scan and finding the export file didn't
    exist at all - so every real match nuclei had already found (verified:
    critical CVEs, an exposed DB dump) was silently discarded every time.
    Plain `-o <path> -jsonl` (nuclei's normal streaming-output idiom, as
    opposed to the post-scan "export" feature) writes each line the moment
    a match is found - confirmed directly: a real match was already on disk
    30s into a run subprocess.run() would go on to kill at 240s."""
    if not os.path.exists(out_path):
        return []
    with open(out_path) as f:
        raw = f.read().strip()
    if not raw:
        return []

    try:
        parsed = json.loads(raw)
        if isinstance(parsed, list):
            return [r for r in parsed if isinstance(r, dict)]
        if isinstance(parsed, dict):
            return [parsed]
    except json.JSONDecodeError:
        pass

    results = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
            if isinstance(r, dict):
                results.append(r)
        except json.JSONDecodeError:
            continue
    return results


def _run_nuclei(scan_id: str, target: str, domain: str) -> List[dict]:
    findings: List[dict] = []
    out_path = f'/tmp/nuclei_{scan_id}.jsonl'
    try:
        subprocess.run(
            [
                'nuclei', '-u', target,
                '-t', 'cves/', '-t', 'vulnerabilities/', '-t', 'misconfiguration/',
                '-t', 'exposed-panels/', '-t', 'technologies/', '-t', 'exposures/',
                '-severity', 'critical,high,medium,low',
                '-o', out_path, '-jsonl',
                '-silent', '-duc',
                '-timeout', '10', '-retries', '1',
                '-rate-limit', '20', '-max-host-error', '5',
                '-stats-interval', '30',
            ],
            timeout=_NUCLEI_TIMEOUT,
            capture_output=True,
            check=False,
        )

        for result in _load_results(out_path):
            info = result.get('info', {}) if isinstance(result.get('info'), dict) else {}
            template_id = result.get('template-id', 'unknown')
            raw_severity = str(info.get('severity', 'unknown')).lower()
            severity, cvss = _SEVERITY_MAP.get(raw_severity, ('Informational', 0.0))

            extracted = result.get('extracted-results', '')
            if isinstance(extracted, list):
                extracted = ', '.join(str(x) for x in extracted)
            evidence = f'{result.get("matched-at", target)} | {extracted}'

            cve_ids = info.get('classification', {}).get('cve-id') \
                if isinstance(info.get('classification'), dict) else None
            cve_id = cve_ids[0] if isinstance(cve_ids, list) and cve_ids else None

            finding = normalize_finding(
                module=MODULE, tool='nuclei',
                type_=f'nuclei_{template_id}',
                title=info.get('name', 'Nuclei finding'),
                evidence=evidence,
                severity=severity,
                cvss=cvss,
                target=domain,
            )
            finding['template_id'] = template_id
            finding['cve_id'] = cve_id
            findings.append(finding)

    except subprocess.TimeoutExpired:
        logger.warning("Nuclei timed out for scan %s", scan_id)
    except FileNotFoundError:
        logger.warning("Nuclei not installed - skipping for scan %s", scan_id)
    except Exception as e:
        logger.error("Nuclei error for scan %s: %s", scan_id, e)
    finally:
        if os.path.exists(out_path):
            try:
                os.unlink(out_path)
            except OSError:
                pass

    return findings


@app.task(
    base=BaseTask,
    name='tasks.nuclei_scan.run_nuclei',
    soft_time_limit=_SOFT_LIMIT,
    time_limit=_HARD_LIMIT,
)
def run_nuclei(scan_id: str, domain: str) -> dict:
    """
    CVE/vulnerability template scanning via Nuclei (curated template subset).
    Returns a build_module_result() envelope (Section 4.3 schema note).
    """
    update_module_status(scan_id, MODULE, 'running')
    start = time.monotonic()
    findings = []
    target = resolve_target_url(domain)
    try:
        findings = _run_nuclei(scan_id, target, domain)
        tool_versions = {'nuclei': get_tool_version('nuclei', '-version')}
        update_module_status(scan_id, MODULE, 'complete')
        return build_module_result(MODULE, findings, tool_versions, status='success',
                                    duration_seconds=time.monotonic() - start)
    except SoftTimeLimitExceeded:
        logger.warning("nuclei hit its soft time limit for scan %s", scan_id)
        update_module_status(scan_id, MODULE, 'failed')
        return build_module_result(MODULE, findings, {}, status='timeout',
                                    error='Module exceeded its soft time limit',
                                    duration_seconds=time.monotonic() - start)
    except Exception as e:
        logger.exception("nuclei unexpected error scan=%s: %s", scan_id, e)
        update_module_status(scan_id, MODULE, 'failed')
        return build_module_result(MODULE, findings, {}, status='failed',
                                    error=str(e), duration_seconds=time.monotonic() - start)
