import json
import logging
import os
import shutil
import socket
import ssl
import subprocess
import time
# Parses sslscan's own `--xml` output file (a trusted local binary writing to
# /tmp), never an attacker-supplied XML document, so stdlib ElementTree is safe
# here: there is no path for external-entity/XXE or billion-laughs content, which
# would require the attacker to control the XML document structure sslscan emits.
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import List, Optional, Tuple

from celery.exceptions import SoftTimeLimitExceeded

from tasks.base_task import (
    BaseTask, normalize_finding, update_module_status,
    get_tool_version, build_module_result, scaled_timeout,
)
from tasks.celery_app import app

logger = logging.getLogger(__name__)
MODULE = 'ssl_tls'
_TESTSSL_TIMEOUT = scaled_timeout(180)
# On timeout we SIGTERM testssl (not SIGKILL) so its own cleanup finalizes a
# valid JSON file, then allow this grace window before a hard kill. Without it,
# subprocess.run's SIGKILL truncates the JSON mid-array -> unparseable -> the
# whole TLS scan silently yields zero findings (a Critical expired cert included).
_TESTSSL_GRACE = scaled_timeout(25)
_SSLSCAN_TIMEOUT = scaled_timeout(60)

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

# testssl item ids that are scan mechanics / meta, never a target vulnerability.
_TESTSSL_NOISE_IDS = {
    'overall_grade', 'grade_cap_reason_1', 'grade_cap_reason_2', 'grade_cap_reason_3',
    'grade_cap_reason_4', 'grade_cap_reason_5', 'scanProblem', 'engine_problem',
    'HTTP_status_code', 'HTTP_headerTime', 'service', 'clientsimulation',
}
# testssl WARN-level lines whose text is a diagnostic about the SCAN (a failed
# probe, an unreachable check, an engine limitation), not a weakness of the
# target. testssl grades these WARN -> our map turns WARN into "Low", so without
# this they surface as bogus Low findings with useless remediation.
_TESTSSL_NOISE_PHRASES = (
    'check failed', "couldn't connect", 'could not connect', 'connect problem',
    'not tested', 'could not determine', 'pls report', 'please report',
    "didn't succeed", 'did not succeed', 'repeatedly zero', 'header reply empty',
    'no http status', 'no server certificate could be retrieved',
    'scan interrupted', 'handshake failed',
    # A testssl attack/feature test that could not complete (the request
    # stalled, was terminated, timed out, or was aborted mid-check) is a scan
    # artefact, not a weakness of the target - real report showed a "BREACH:
    # Test failed as first HTTP request stalled and was terminated" line
    # rendered as a scary Low finding with "investigate your server logs"
    # advice. Drop it like every other incomplete-check line.
    'stalled', 'was terminated', 'test failed', 'aborted', 'timed out',
    'timeout', 'incomplete',
)


def _classify_testssl(item_id: str, finding_text: str, raw_sev: str):
    """Map a raw testssl JSON item to an honest (report_type, severity), or None
    to skip it. Fixes the two failure modes seen in real reports: (1) testssl
    scan-mechanics / incomplete-check lines rendered as vulnerabilities, and (2)
    Forward-Secrecy signature-algorithm / KEM *capability* lines over-graded to
    High/Critical (testssl grades what the server offers, not always an
    actionable weakness). Everything genuinely graded keeps testssl's own
    severity - the trust-source contract (cvss_scorer.py) is unchanged for those.
    """
    text = (finding_text or '').lower()
    low = item_id.lower()

    # testssl's own "did my scan finish" signal - always kept as an
    # Informational coverage note (has its own template), never graded.
    if item_id == 'scanTime':
        return ('testssl_scanTime', 'Informational')

    # Scan-mechanics / incomplete-check artefacts - not a target weakness.
    if item_id in _TESTSSL_NOISE_IDS or any(p in text for p in _TESTSSL_NOISE_PHRASES):
        return None

    # Forward-Secrecy signature-algorithm / KEM capability lines: these describe
    # what the server *offers*, not a fixable weakness, and testssl's High/
    # Critical grade on them is noise. Cap at Informational with a dedicated,
    # honest template. (Deliberately narrow: cipher-strength and protocol IDs
    # are NOT swept in here - those can be real weaknesses and keep their grade.)
    if low.startswith('fs_') or 'sig_algs' in low or 'kems' in low:
        return ('testssl_capability', 'Informational')

    # A missing TLS extension (e.g. extended master secret, RFC 7627): a real
    # but minor hardening item, never Critical. Own template + platform-aware.
    if low.startswith('tls_misses_extension'):
        return ('testssl_missing_extension', 'Low')

    # Genuinely graded issue - trust testssl's severity (existing design).
    if raw_sev in _TESTSSL_SKIP or raw_sev not in _TESTSSL_SEVERITY_MAP:
        return None
    return (f'testssl_{item_id}', _TESTSSL_SEVERITY_MAP[raw_sev])


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
    except SoftTimeLimitExceeded:
        raise
    except Exception as e:
        logger.debug("cert expiry check failed for %s: %s", domain, e)
    return None


# ---------------------------------------------------------------------------
# testssl.sh
# ---------------------------------------------------------------------------

def _run_testssl(scan_id: str, domain: str) -> Tuple[List[dict], bool]:
    """Run testssl.sh and parse its JSON. Returns (findings, timed_out).

    `timed_out` lets the caller mark the module 'partial' rather than a clean
    'success', so a scan that ran out of time on a slow target isn't reported
    as if the TLS surface came back clean.
    """
    findings = []
    timed_out = False
    out_path = f'/tmp/ssl_{scan_id}.json'

    if not shutil.which('testssl.sh'):
        logger.warning("testssl.sh not found - skipping for scan %s", scan_id)
        return findings, timed_out

    # Real bug found live: this used to say `--connect-timeout`, a flag that
    # doesn't exist in this testssl.sh version (it's `--socket-timeout`) - the
    # bad flag made testssl.sh reject the whole argument list and print its
    # usage text instead of scanning, exiting in under a second with no
    # exception raised, so it silently produced zero findings on every scan.
    argv = [
        'testssl.sh', '--jsonfile', out_path, '--quiet', '--color', '0',
        '--warnings', 'off', '--socket-timeout', '30', '--openssl-timeout', '30',
        domain,
    ]
    proc = None
    try:
        # Popen (not subprocess.run) so a timeout can SIGTERM the child and let
        # testssl close its JSON array cleanly. subprocess.run's SIGKILL leaves
        # the file truncated mid-array -> JSONDecodeError -> silent zero findings.
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            _, stderr = proc.communicate(timeout=_TESTSSL_TIMEOUT)
            if proc.returncode != 0 and not os.path.exists(out_path):
                logger.warning("testssl.sh exited %s with no JSON output for scan %s: %s",
                                proc.returncode, scan_id, (stderr or b'')[-500:])
        except subprocess.TimeoutExpired:
            timed_out = True
            logger.warning("testssl.sh timed out (%ss) for scan %s - SIGTERM to salvage partial JSON",
                            _TESTSSL_TIMEOUT, scan_id)
            proc.terminate()  # SIGTERM: testssl finalizes a valid JSON file
            try:
                proc.communicate(timeout=_TESTSSL_GRACE)
            except subprocess.TimeoutExpired:
                proc.kill()   # last resort if cleanup itself hangs
                proc.communicate()
    except SoftTimeLimitExceeded:
        if proc and proc.poll() is None:
            proc.kill()       # don't leave the child running when Celery kills us
        raise
    except Exception as e:
        logger.error("testssl.sh failed for scan %s: %s", scan_id, e)
        return findings, timed_out
    finally:
        # Parse whatever JSON was written, even if the process was terminated.
        findings = _parse_testssl_json(out_path, domain, scan_id)
        if os.path.exists(out_path):
            try:
                os.unlink(out_path)
            except OSError:
                pass

    return findings, timed_out


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
            item_id = item.get('id', 'ssl_finding')
            finding_text = item.get('finding', '') or item_id
            raw_sev = str(item.get('severity', '')).upper().strip()
            # Single honest classification point (capability/artefact/graded) -
            # see _classify_testssl. None => skip (passing check, scan artefact,
            # or unmapped severity).
            classified = _classify_testssl(item_id, finding_text, raw_sev)
            if classified is None:
                continue
            report_type, severity = classified
            # Human title: testssl's `finding` text is usually a readable
            # sentence ("No ciphers supporting Forward Secrecy offered"); use it
            # alone and drop the raw scanner id prefix. Only fall back to the
            # id-prefixed form when the text is too terse to stand on its own.
            title = finding_text if len(finding_text) >= 18 else f'{item_id}: {finding_text}'
            findings.append(normalize_finding(
                module=MODULE, tool='testssl',
                type_=report_type,
                title=title[:120],
                evidence=f'{item_id}: {finding_text}',
                severity=severity, target=domain,
            ))
    except json.JSONDecodeError as e:
        logger.error("testssl.sh JSON parse error for scan %s: %s", scan_id, e)
    except SoftTimeLimitExceeded:
        raise
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
            timeout=_SSLSCAN_TIMEOUT,
            capture_output=True,
            check=False,
        )
        findings = _parse_sslscan_xml(out_path, domain, scan_id)
    except subprocess.TimeoutExpired:
        logger.warning("sslscan timed out (%ss) for scan %s", _SSLSCAN_TIMEOUT, scan_id)
        findings = _parse_sslscan_xml(out_path, domain, scan_id)
    except SoftTimeLimitExceeded:
        raise
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
    except SoftTimeLimitExceeded:
        raise
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

def scan_ssl_tls(scan_id: str, domain: str, auth: dict = None) -> dict:
    """
    Pure half (runs locally or on Modal via tasks.dispatch): SSL/TLS module -
    testssl.sh + sslscan + pure-Python cert expiry check. Either tool can be
    missing - degrades gracefully. No DB/Redis; returns a build_module_result()
    envelope (Section 4.3). `auth` unused.
    """
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
            return build_module_result(MODULE, findings, {}, status='success',
                                        duration_seconds=time.monotonic() - start)

        # Both tools missing → failed (a deployment problem, not a scan result)
        if not testssl_avail and not sslscan_avail:
            logger.error(
                "ssl_tls scan %s: both testssl.sh and sslscan missing - "
                "install them in the Docker image", scan_id,
            )
            return build_module_result(
                MODULE, findings, {}, status='failed',
                error='testssl.sh and sslscan are both missing from the image',
                duration_seconds=time.monotonic() - start)

        # Run available tools
        testssl_timed_out = False
        if testssl_avail:
            testssl_findings, testssl_timed_out = _run_testssl(scan_id, domain)
            findings.extend(testssl_findings)
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
        # testssl timing out on a slow target means the TLS surface was only
        # partially probed - report 'partial' (with whatever it salvaged), never
        # a clean 'success' that reads as "TLS is fine".
        status = 'partial' if testssl_timed_out else 'success'
        error = ('testssl.sh timed out; TLS results may be incomplete'
                 if testssl_timed_out else None)
        return build_module_result(MODULE, findings, tool_versions, status=status,
                                    error=error, duration_seconds=time.monotonic() - start)

    except SoftTimeLimitExceeded:
        logger.warning("ssl_tls hit its soft time limit for scan %s", scan_id)
        return build_module_result(MODULE, findings, {}, status='timeout',
                                    error='Module exceeded its soft time limit',
                                    duration_seconds=time.monotonic() - start)
    except Exception as e:
        logger.exception("ssl_tls unexpected error scan=%s: %s", scan_id, e)
        return build_module_result(MODULE, findings, {}, status='failed',
                                    error=str(e), duration_seconds=time.monotonic() - start)


@app.task(base=BaseTask, name='tasks.ssl_tls.run_ssl_tls')
def run_ssl_tls(scan_id: str, domain: str) -> dict:
    """Dispatcher: owns the DB status writes (module namespace); tasks.dispatch
    picks where the pure half runs (local subprocess vs Modal)."""
    update_module_status(scan_id, MODULE, 'running')
    from tasks.dispatch import dispatch_scan
    envelope = dispatch_scan(MODULE, scan_id, domain)
    update_module_status(scan_id, MODULE,
                         'complete' if envelope.get('status') in ('success', 'partial') else 'failed')
    return envelope
