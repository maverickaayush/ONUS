import json
import logging
import os
import shutil
import socket
import ssl
import subprocess
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import List, Optional, Tuple

from celery.exceptions import SoftTimeLimitExceeded

from tasks.base_task import (
    BaseTask, normalize_finding, update_module_status,
    get_tool_version, build_module_result,
)
from tasks.celery_app import app

logger = logging.getLogger(__name__)
MODULE = 'ssl_tls'

# testssl.sh severity → normalized severity (skip INFO/OK - those are passing checks)
_TESTSSL_SEVERITY_MAP = {
    'CRITICAL': 'Critical',
    'HIGH':     'High',
    'MEDIUM':   'Medium',
    'LOW':      'Low',
    'WARN':     'Low',
}
# Values that represent passing checks - do NOT emit as findings
_TESTSSL_SKIP = {'INFO', 'OK', 'HINT', 'DEBUG', 'NOT_TESTED', 'NOT applicable'}


# ---------------------------------------------------------------------------
# HTTPS reachability pre-check
# ---------------------------------------------------------------------------

def _https_reachable(domain: str) -> bool:
    """Return True if port 443 is open and accepts a TCP connection."""
    try:
        with socket.create_connection((domain, 443), timeout=10):
            return True
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Certificate expiry check (pure Python fallback / enrichment)
# ---------------------------------------------------------------------------

def _cert_expiry_finding(domain: str) -> Optional[dict]:
    """
    Connect via ssl.getpeercert() and return an expiry finding if the cert
    expires within 30 days or is already expired. Returns None on any error
    (no connectivity, self-signed, etc.) - this is enrichment, not critical.
    """
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((domain, 443), timeout=10) as raw:
            with ctx.wrap_socket(raw, server_hostname=domain) as conn:
                cert = conn.getpeercert()

        not_after_str = cert.get('notAfter', '')
        if not not_after_str:
            return None

        not_after = datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z')
        not_after = not_after.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        days_left = (not_after - now).days

        if days_left < 0:
            return normalize_finding(
                module=MODULE, tool='python-ssl', type_='cert_expired',
                title='SSL certificate has expired',
                evidence=f'Certificate expired on {not_after.date()} ({abs(days_left)} days ago)',
                severity='Critical', target=domain,
            )
        if days_left <= 30:
            return normalize_finding(
                module=MODULE, tool='python-ssl', type_='cert_expiring_soon',
                title=f'SSL certificate expires in {days_left} days',
                evidence=f'Certificate expires on {not_after.date()} ({days_left} days remaining)',
                severity='Medium', target=domain,
            )
    except Exception as e:
        logger.debug("cert expiry check failed for %s: %s", domain, e)
    return None


# ---------------------------------------------------------------------------
# testssl.sh
# ---------------------------------------------------------------------------

def _run_testssl(scan_id: str, domain: str) -> List[dict]:
    findings = []
    out_path = f'/tmp/ssl_{scan_id}.json'

    if not shutil.which('testssl.sh'):
        logger.warning("testssl.sh not found - skipping for scan %s", scan_id)
        return findings

    try:
        # Real bug found live: this used to say `--connect-timeout`, a flag
        # that doesn't exist in this testssl.sh version (it's
        # `--socket-timeout`) - the bad flag made testssl.sh reject the
        # whole argument list and print its usage text instead of scanning,
        # exiting in under a second with no exception raised (check=False,
        # and the returncode was never inspected), so it silently produced
        # zero findings on every scan ever run.
        result = subprocess.run(
            [
                'testssl.sh',
                '--jsonfile', out_path,
                '--quiet',
                '--color', '0',
                '--warnings', 'off',
                '--socket-timeout', '30',
                '--openssl-timeout', '30',
                domain,
            ],
            timeout=180,
            capture_output=True,
            check=False,
        )
        if result.returncode != 0 and not os.path.exists(out_path):
            logger.warning("testssl.sh exited %s with no JSON output for scan %s: %s",
                            result.returncode, scan_id, result.stdout[-500:] if result.stdout else '')
    except subprocess.TimeoutExpired:
        logger.warning("testssl.sh timed out (180s) for scan %s - parsing partial output", scan_id)
    except Exception as e:
        logger.error("testssl.sh failed for scan %s: %s", scan_id, e)
        return findings
    finally:
        # Parse whatever JSON was written, even if the process was killed.
        findings = _parse_testssl_json(out_path, domain, scan_id)
        if os.path.exists(out_path):
            try:
                os.unlink(out_path)
            except OSError:
                pass

    return findings


def _parse_testssl_json(path: str, domain: str, scan_id: str) -> List[dict]:
    findings = []
    if not os.path.exists(path):
        return findings
    try:
        with open(path) as f:
            raw = f.read().strip()
        if not raw:
            return findings

        # testssl writes a JSON array of finding objects
        data = json.loads(raw)
        if isinstance(data, dict):
            # Newer testssl versions wrap in {"scanResult": [...]}
            items = data.get('scanResult', [{}])[0].get('findings', []) \
                    if 'scanResult' in data else [data]
        elif isinstance(data, list):
            items = data
        else:
            return findings

        for item in items:
            if not isinstance(item, dict):
                continue
            raw_sev = str(item.get('severity', '')).upper().strip()
            if raw_sev in _TESTSSL_SKIP or raw_sev not in _TESTSSL_SEVERITY_MAP:
                continue
            severity = _TESTSSL_SEVERITY_MAP[raw_sev]
            finding_text = item.get('finding', '') or item.get('id', '')
            item_id = item.get('id', 'ssl_finding')
            findings.append(normalize_finding(
                module=MODULE, tool='testssl',
                type_=f'testssl_{item_id}',
                title=f'{item_id}: {finding_text}'[:120],
                evidence=f'{item_id}: {finding_text}',
                severity=severity, target=domain,
            ))
    except json.JSONDecodeError as e:
        logger.error("testssl.sh JSON parse error for scan %s: %s", scan_id, e)
    except Exception as e:
        logger.error("testssl.sh result parse error for scan %s: %s", scan_id, e)
    return findings


# ---------------------------------------------------------------------------
# sslscan
# ---------------------------------------------------------------------------

def _run_sslscan(scan_id: str, domain: str) -> List[dict]:
    findings = []
    out_path = f'/tmp/sslscan_{scan_id}.xml'

    if not shutil.which('sslscan'):
        logger.warning("sslscan not found - skipping for scan %s", scan_id)
        return findings

    try:
        subprocess.run(
            ['sslscan', f'--xml={out_path}', domain],
            timeout=60,
            capture_output=True,
            check=False,
        )
        findings = _parse_sslscan_xml(out_path, domain, scan_id)
    except subprocess.TimeoutExpired:
        logger.warning("sslscan timed out (60s) for scan %s", scan_id)
        findings = _parse_sslscan_xml(out_path, domain, scan_id)
    except Exception as e:
        logger.error("sslscan error for scan %s: %s", scan_id, e)
    finally:
        if os.path.exists(out_path):
            try:
                os.unlink(out_path)
            except OSError:
                pass

    return findings


def _parse_sslscan_xml(path: str, domain: str, scan_id: str) -> List[dict]:
    findings = []
    if not os.path.exists(path):
        return findings

    try:
        tree = ET.parse(path)
        root = tree.getroot()
        _found = root.find('ssltest')
        ssltest = _found if _found is not None else root

        # --- Protocol checks ---
        for proto in ssltest.findall('.//protocol'):
            ptype = proto.get('type', '').lower()
            version = proto.get('version', '')
            enabled = proto.get('enabled', '0')
            if enabled != '1':
                continue

            if ptype in ('sslv2', 'ssl2'):
                findings.append(normalize_finding(
                    module=MODULE, tool='sslscan', type_='sslv2_enabled',
                    title='SSLv2 enabled',
                    evidence=f'SSLv2 is enabled on {domain}',
                    severity='High', target=domain,
                ))
            elif ptype in ('sslv3', 'ssl3'):
                findings.append(normalize_finding(
                    module=MODULE, tool='sslscan', type_='sslv3_enabled',
                    title='SSLv3 enabled (POODLE)',
                    evidence=f'SSLv3 is enabled on {domain}',
                    severity='High', target=domain,
                ))
            elif version in ('1.0', '1') and 'tls' in ptype:
                findings.append(normalize_finding(
                    module=MODULE, tool='sslscan', type_='tls10_enabled',
                    title='TLS 1.0 enabled',
                    evidence=f'TLS 1.0 is enabled on {domain}',
                    severity='High', target=domain,
                ))
            elif version in ('1.1',) and 'tls' in ptype:
                findings.append(normalize_finding(
                    module=MODULE, tool='sslscan', type_='tls11_enabled',
                    title='TLS 1.1 enabled',
                    evidence=f'TLS 1.1 is enabled on {domain}',
                    severity='Medium', target=domain,
                ))

        # --- Cipher checks ---
        for cipher in ssltest.findall('.//cipher'):
            cipher_name = cipher.get('cipher', '') or cipher.get('name', '')
            bits_str = cipher.get('bits', '0')
            status = cipher.get('status', '')
            if status == 'rejected':
                continue

            try:
                bits = int(bits_str)
            except ValueError:
                bits = 128

            # Each weakness is checked independently - a cipher can trigger
            # multiple findings (e.g. 40-bit RC4 is both RC4 AND weak-bits).
            cipher_upper = cipher_name.upper()
            if 'RC4' in cipher_upper:
                findings.append(normalize_finding(
                    module=MODULE, tool='sslscan', type_='weak_cipher_rc4',
                    title=f'RC4 cipher enabled: {cipher_name}',
                    evidence=f'Cipher {cipher_name} ({bits} bits) is enabled',
                    severity='High', target=domain,
                ))
            if 'DES' in cipher_upper:
                findings.append(normalize_finding(
                    module=MODULE, tool='sslscan', type_='weak_cipher_des',
                    title=f'DES/3DES cipher enabled: {cipher_name}',
                    evidence=f'Cipher {cipher_name} ({bits} bits) is enabled',
                    severity='High', target=domain,
                ))
            if 0 < bits < 128:
                findings.append(normalize_finding(
                    module=MODULE, tool='sslscan', type_='weak_cipher_bits',
                    title=f'Weak cipher key length: {cipher_name} ({bits} bits)',
                    evidence=f'Cipher {cipher_name} has only {bits}-bit key',
                    severity='High', target=domain,
                ))

        # --- Certificate checks ---
        for cert in ssltest.findall('.//certificate'):
            # Self-signed
            subject = cert.findtext('.//subject', '') or ''
            issuer = cert.findtext('.//issuer', '') or ''
            if subject and issuer and subject.strip() == issuer.strip():
                findings.append(normalize_finding(
                    module=MODULE, tool='sslscan', type_='cert_self_signed',
                    title='Self-signed certificate',
                    evidence=f'Certificate subject equals issuer: {subject[:100]}',
                    severity='High', target=domain,
                ))

            # Expiry
            not_after_str = cert.findtext('.//not-valid-after', '') \
                            or cert.findtext('.//expiry', '') \
                            or cert.findtext('.//notAfter', '')
            if not_after_str:
                for fmt in ('%Y-%m-%d %H:%M:%S', '%b %d %H:%M:%S %Y %Z',
                            '%Y-%m-%dT%H:%M:%S'):
                    try:
                        not_after = datetime.strptime(not_after_str.strip(), fmt)
                        not_after = not_after.replace(tzinfo=timezone.utc)
                        days_left = (not_after - datetime.now(timezone.utc)).days
                        if days_left < 0:
                            findings.append(normalize_finding(
                                module=MODULE, tool='sslscan', type_='cert_expired',
                                title='Certificate expired',
                                evidence=f'Expired {not_after.date()} ({abs(days_left)} days ago)',
                                severity='Critical', target=domain,
                            ))
                        elif days_left <= 30:
                            findings.append(normalize_finding(
                                module=MODULE, tool='sslscan', type_='cert_expiring_soon',
                                title=f'Certificate expires in {days_left} days',
                                evidence=f'Expires {not_after.date()} ({days_left} days remaining)',
                                severity='Medium', target=domain,
                            ))
                        break
                    except ValueError:
                        continue

        # --- DH key size ---
        for dh in ssltest.findall('.//group') + ssltest.findall('.//dhgroup'):
            bits_str = dh.get('bits', '0') or dh.get('dhbits', '0')
            try:
                bits = int(bits_str)
                if 0 < bits < 2048:
                    findings.append(normalize_finding(
                        module=MODULE, tool='sslscan', type_='weak_dh_params',
                        title=f'Weak DH parameters: {bits} bits',
                        evidence=f'DH key size is {bits} bits (minimum recommended: 2048)',
                        severity='High', target=domain,
                    ))
            except ValueError:
                pass

    except ET.ParseError as e:
        logger.error("sslscan XML parse error for scan %s: %s", scan_id, e)
    except Exception as e:
        logger.error("sslscan result parse error for scan %s: %s", scan_id, e)

    return findings


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

def _dedup(findings: List[dict]) -> List[dict]:
    """
    Dedup on (type, normalized_title). When both tools report the same
    weakness, keep one finding and note both tools in the evidence.
    """
    seen: dict = {}  # key -> index in `result`
    result: List[dict] = []

    for f in findings:
        key = (f.get('type', ''), f.get('title', '').lower().strip())
        if key in seen:
            # Merge: append the other tool's evidence if different tool
            existing = result[seen[key]]
            existing_tool = existing.get('tool', '')
            new_tool = f.get('tool', '')
            if existing_tool != new_tool:
                existing['evidence'] = (
                    f"{existing['evidence']} | also detected by {new_tool}: {f['evidence']}"
                )[:500]
        else:
            seen[key] = len(result)
            result.append(f)

    return result


# ---------------------------------------------------------------------------
# Main task
# ---------------------------------------------------------------------------

@app.task(base=BaseTask, name='tasks.ssl_tls.run_ssl_tls')
def run_ssl_tls(scan_id: str, domain: str) -> dict:
    """
    SSL/TLS module: testssl.sh + sslscan + pure-Python cert expiry check.
    Either tool can be missing - the module degrades gracefully.
    Returns a build_module_result() envelope (Section 4.3 schema note).
    """
    update_module_status(scan_id, MODULE, 'running')
    start = time.monotonic()
    findings = []

    testssl_avail = bool(shutil.which('testssl.sh'))
    sslscan_avail = bool(shutil.which('sslscan'))

    try:
        # Pre-check: if port 443 is unreachable this isn't an error
        if not _https_reachable(domain):
            findings.append(normalize_finding(
                module=MODULE, tool='python-ssl', type_='no_https',
                title='No HTTPS service detected on port 443',
                evidence=f'TCP connection to {domain}:443 refused or timed out',
                severity='Informational', target=domain,
            ))
            update_module_status(scan_id, MODULE, 'complete')
            return build_module_result(MODULE, findings, {}, status='success',
                                        duration_seconds=time.monotonic() - start)

        # Both tools missing → failed (a deployment problem, not a scan result)
        if not testssl_avail and not sslscan_avail:
            logger.error(
                "ssl_tls scan %s: both testssl.sh and sslscan missing - "
                "install them in the Docker image", scan_id,
            )
            update_module_status(scan_id, MODULE, 'failed')
            return build_module_result(
                MODULE, findings, {}, status='failed',
                error='testssl.sh and sslscan are both missing from the image',
                duration_seconds=time.monotonic() - start)

        # Run available tools
        if testssl_avail:
            findings.extend(_run_testssl(scan_id, domain))
        if sslscan_avail:
            findings.extend(_run_sslscan(scan_id, domain))

        # Python-level cert expiry enrichment (works without external tools)
        cert_finding = _cert_expiry_finding(domain)
        if cert_finding:
            findings.append(cert_finding)

        # Dedup cross-tool duplicates
        findings = _dedup(findings)

        tool_versions = {
            'testssl': get_tool_version('testssl.sh', '--version'),
            'sslscan': get_tool_version('sslscan', '--version'),
        }
        update_module_status(scan_id, MODULE, 'complete')
        return build_module_result(MODULE, findings, tool_versions, status='success',
                                    duration_seconds=time.monotonic() - start)

    except SoftTimeLimitExceeded:
        logger.warning("ssl_tls hit its soft time limit for scan %s", scan_id)
        update_module_status(scan_id, MODULE, 'failed')
        return build_module_result(MODULE, findings, {}, status='timeout',
                                    error='Module exceeded its soft time limit',
                                    duration_seconds=time.monotonic() - start)
    except Exception as e:
        logger.exception("ssl_tls unexpected error scan=%s: %s", scan_id, e)
        update_module_status(scan_id, MODULE, 'failed')
        return build_module_result(MODULE, findings, {}, status='failed',
                                    error=str(e), duration_seconds=time.monotonic() - start)
