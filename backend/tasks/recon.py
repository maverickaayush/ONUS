import logging
import os
import subprocess
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import List

import dns.exception
import dns.resolver
from whois.parser import WhoisEntry

from tasks.base_task import BaseTask, normalize_finding, update_module_status
from tasks.celery_app import app

logger = logging.getLogger(__name__)
MODULE = 'recon'


# ---------------------------------------------------------------------------
# nmap
# ---------------------------------------------------------------------------

def _parse_nmap_xml(xml_path: str, domain: str) -> dict:
    """Parse an nmap XML file into {portid: finding_dict} keyed by port."""
    ports = {}
    if not os.path.exists(xml_path):
        return ports

    tree = ET.parse(xml_path)
    root = tree.getroot()

    for host in root.findall('host'):
        os_match = host.find('.//osmatch')
        os_name = os_match.get('name', '') if os_match is not None else ''

        ports_elem = host.find('ports')
        if ports_elem is None:
            continue

        for port in ports_elem.findall('port'):
            state = port.find('state')
            if state is None or state.get('state') != 'open':
                continue

            portid = port.get('portid', '?')
            protocol = port.get('protocol', 'tcp')
            service = port.find('service')
            svc_name = service.get('name', 'unknown') if service is not None else 'unknown'
            product = service.get('product', '') if service is not None else ''
            version = service.get('version', '') if service is not None else ''

            svc_str = svc_name
            if product:
                svc_str += f' {product}'
            if version:
                svc_str += f' {version}'

            evidence = f'{portid}/{protocol} open {svc_str}'
            if os_name:
                evidence += f' | OS: {os_name}'

            ports[portid] = normalize_finding(
                module=MODULE, tool='nmap', type_='open_port',
                title=f'Port {portid} ({svc_name.upper()}) open',
                evidence=evidence,
                severity='Info',
                target=domain,
            )
    return ports


def _nmap_phase(scan_id: str, domain: str, port_args: List[str],
                subproc_timeout: int, tag: str, host_timeout: str = None) -> dict:
    """
    Run one nmap scan phase and return {portid: finding}. Never raises.

    host_timeout is OPTIONAL and used only for the best-effort full-range phase.
    A --host-timeout that fires mid port-scan makes nmap ABANDON the host and
    report zero ports, so the reliable common-port phase deliberately omits it
    and lets the scan run to completion under the subprocess timeout instead.
    """
    xml_path = f'/tmp/nmap_{tag}_{scan_id}.xml'
    cmd = ['nmap', '-sV', '-sC', '--open', '-T4', '--min-rate', '1000', *port_args]
    if host_timeout:
        cmd += ['--host-timeout', host_timeout]
    cmd += ['-oX', xml_path, domain]
    try:
        subprocess.run(cmd, timeout=subproc_timeout, capture_output=True, check=False)
        return _parse_nmap_xml(xml_path, domain)
    except subprocess.TimeoutExpired:
        logger.warning("nmap %s phase hit subprocess backstop for scan %s", tag, scan_id)
        return {}
    except FileNotFoundError:
        logger.error("nmap not found in PATH")
        return {}
    except Exception as e:
        logger.error("nmap %s phase error for scan %s: %s", tag, scan_id, e)
        return {}
    finally:
        if os.path.exists(xml_path):
            try:
                os.unlink(xml_path)
            except OSError:
                pass


# High-value ports scanned explicitly on filtered hosts (where a full -p- can't
# complete). Covers ports NOT reliably in nmap's top-100 - dev servers, modern
# infra, databases, message brokers, container orchestration, monitoring, CI/CD.
# ~50 ports complete in well under 60s even on a fully-filtered host.
_APP_PORTS = ','.join([
    # Dev servers
    '3000', '3001', '4000', '4200', '4567', '5000', '5173',
    '7000', '8000', '8001', '8081', '8082', '8083', '8085', '8888', '9001',
    # Databases
    '1433', '3306', '5432', '5984', '6379', '6380',
    '7474', '7687', '9042', '11211', '27017', '28017',
    # Message brokers / queues
    '2181', '5672', '9092', '15672', '61616',
    # Kubernetes / container orchestration
    '2375', '2376', '2379', '2380', '4243', '6443', '10250', '10255',
    # Service discovery / mesh
    '8500', '8600',
    # Monitoring / observability
    '3100', '5601', '9090', '9093', '9100', '9200',
    '16686', '19999', '9411',
    # Admin panels / dashboards
    '4444', '8161', '9000', '50000',
])


def _run_nmap(scan_id: str, domain: str) -> List[dict]:
    """
    Adaptive nmap scan, merged & de-duplicated by port number.

    A full ``-p-`` scan cannot complete against a filtered/CDN host (e.g. Vercel,
    which filters every port except 80/443): nmap waits on no-response probes for
    all 65k ports, and a --host-timeout that fires mid port-scan makes nmap ABANDON
    the host and report ZERO ports. The only scan that reliably returns results on
    such a host is one small enough to run to completion. So:

      Phase 1 (top 100 ports, NO host-timeout) - always runs; allowed to finish.
               Captures the services that matter (web/ssh/mail/db). Instant on a
               normal host; ~2 min on a fully-filtered host but it COMPLETES.

    Then, based on how Phase 1 behaved:
      - Phase 1 FAST (<30s) → host is responsive → Phase 2a full ``-p-`` for
        complete high-port coverage (finishes in seconds on a normal host).
      - Phase 1 SLOW (host filtered) → a full -p- can't complete, so instead run
        Phase 2b: an explicit scan of curated application/admin ports (_APP_PORTS)
        that aren't in the top-100. Small, bounded, and catches the high-port
        services a filtered host would otherwise hide.

    nmap stays bounded to ~180s worst case (filtered: Phase 1 ~130s + Phase 2b
    ~50s), within Celery's 300s soft limit.
    """
    ports = {}

    # Phase 1: top 100 ports, no host-timeout - must run to completion to report.
    # 180s cap (was 130s, barely above Vercel's ~122s): gives slower filtered
    # hosts room to finish instead of being SIGKILL'd mid-scan (→ zero ports).
    # Free now that recon has a generous per-task limit. Normal hosts finish in
    # seconds and are unaffected.
    t0 = time.monotonic()
    ports.update(_nmap_phase(
        scan_id, domain, port_args=['--top-ports', '100'],
        subproc_timeout=180, tag='top',
    ))
    phase1_elapsed = time.monotonic() - t0

    if phase1_elapsed < 30:
        # Phase 2a: responsive host - full port range for complete coverage.
        for portid, finding in _nmap_phase(
            scan_id, domain, port_args=['-p-'],
            host_timeout='60s', subproc_timeout=70, tag='full',
        ).items():
            ports.setdefault(portid, finding)
    else:
        # Phase 2b: filtered host - full -p- can't finish, so target high-value
        # application/admin ports explicitly instead of skipping coverage entirely.
        logger.info(
            "recon nmap: host appears filtered for scan %s (Phase 1 took %.0fs); "
            "scanning curated application ports instead of full -p-",
            scan_id, phase1_elapsed,
        )
        for portid, finding in _nmap_phase(
            scan_id, domain, port_args=['-p', _APP_PORTS],
            subproc_timeout=60, tag='app',
        ).items():
            ports.setdefault(portid, finding)

    findings = list(ports.values())
    if not findings:
        findings.append(normalize_finding(
            module=MODULE, tool='nmap', type_='scan_timeout',
            title='nmap found no open ports (or scan timed out)',
            evidence='No open ports confirmed within the scan budget - '
                     'host may be filtered/firewalled or behind a CDN.',
            severity='Info', target=domain,
        ))
    return findings


# ---------------------------------------------------------------------------
# subfinder
# ---------------------------------------------------------------------------

def _run_subfinder(scan_id: str, domain: str) -> List[dict]:
    findings = []
    out_path = f'/tmp/sub_{scan_id}.txt'
    try:
        result = subprocess.run(
            ['subfinder', '-d', domain, '-silent', '-o', out_path],
            timeout=60,
            capture_output=True,
            check=False,
        )

        if not os.path.exists(out_path):
            # subfinder might print to stdout even without -o on some versions
            subdomains = [
                line.strip()
                for line in result.stdout.decode(errors='ignore').splitlines()
                if line.strip()
            ]
        else:
            with open(out_path) as f:
                subdomains = [line.strip() for line in f if line.strip()]

        for sub in subdomains:
            findings.append(normalize_finding(
                module=MODULE, tool='subfinder', type_='subdomain_found',
                title=f'Subdomain discovered: {sub}',
                evidence=sub,
                severity='Info', target=domain,
            ))

    except subprocess.TimeoutExpired:
        logger.warning("subfinder timed out (30s) for scan %s", scan_id)
    except FileNotFoundError:
        logger.warning("subfinder not installed - subdomain enumeration skipped")
    except Exception as e:
        logger.error("subfinder error for scan %s: %s", scan_id, e)
    finally:
        if os.path.exists(out_path):
            try:
                os.unlink(out_path)
            except OSError:
                pass

    return findings


# ---------------------------------------------------------------------------
# WHOIS
# ---------------------------------------------------------------------------

def _run_whois(scan_id: str, domain: str) -> List[dict]:
    findings = []
    try:
        # Hard-bounded WHOIS: run the `whois` binary under a subprocess timeout
        # (SIGKILL-enforced) so a hung/rate-limiting WHOIS server can never stall
        # recon. python-whois's parser then turns the raw text into fields.
        proc = subprocess.run(
            ['whois', domain], timeout=20, capture_output=True, check=False,
        )
        text = proc.stdout.decode(errors='ignore')
        if not text.strip():
            logger.warning("whois returned no data for scan %s", scan_id)
            return findings
        w = WhoisEntry.load(domain, text)

        registrar = w.get('registrar')
        if registrar:
            findings.append(normalize_finding(
                module=MODULE, tool='whois', type_='whois_registrar',
                title=f'Registrar: {registrar}',
                evidence=f'Registrar: {registrar}',
                severity='Info', target=domain,
            ))

        creation_date = w.get('creation_date')
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date:
            findings.append(normalize_finding(
                module=MODULE, tool='whois', type_='whois_creation_date',
                title=f'Domain registered: {creation_date}',
                evidence=f'Creation date: {creation_date}',
                severity='Info', target=domain,
            ))

        expiry_date = w.get('expiration_date')
        if isinstance(expiry_date, list):
            expiry_date = expiry_date[0]
        if expiry_date and isinstance(expiry_date, datetime):
            # Normalize naive datetimes to UTC so the subtraction never mixes
            # naive/aware values (and avoid the deprecated datetime.utcnow()).
            if expiry_date.tzinfo is None:
                expiry_date = expiry_date.replace(tzinfo=timezone.utc)
            days_left = (expiry_date - datetime.now(timezone.utc)).days
            severity = 'Medium' if days_left <= 90 else 'Info'
            findings.append(normalize_finding(
                module=MODULE, tool='whois', type_='whois_expiry',
                title=f'Domain expiry: {expiry_date} ({days_left} days remaining)',
                evidence=f'Expiration date: {expiry_date} | Days remaining: {days_left}',
                severity=severity, target=domain,
            ))

        name_servers = w.get('name_servers')
        if name_servers:
            raw_ns = name_servers if isinstance(name_servers, list) else [name_servers]
            # WHOIS frequently returns duplicates (mixed case / repeated) - dedup.
            ns_list = sorted({str(ns).strip().lower().rstrip('.') for ns in raw_ns if ns})
            ns_str = ', '.join(ns_list[:5])
            findings.append(normalize_finding(
                module=MODULE, tool='whois', type_='whois_nameservers',
                title=f'Nameservers: {ns_str}',
                evidence=f'Name servers: {ns_str}',
                severity='Info', target=domain,
            ))

        abuse_contact = w.get('emails')
        if abuse_contact:
            if isinstance(abuse_contact, list):
                abuse_contact = ', '.join(abuse_contact[:3])
            findings.append(normalize_finding(
                module=MODULE, tool='whois', type_='whois_abuse_contact',
                title=f'Abuse contact: {abuse_contact}',
                evidence=f'Contact email(s): {abuse_contact}',
                severity='Info', target=domain,
            ))

    except subprocess.TimeoutExpired:
        logger.warning("whois timed out (20s) for scan %s", scan_id)
    except FileNotFoundError:
        # The `whois` binary is missing - findings would otherwise vanish silently.
        # The Step 9 Dockerfile MUST `apt install whois`.
        logger.error(
            "whois binary not found for scan %s - WHOIS recon skipped. "
            "Install it (apt install whois); the Docker image must include it.",
            scan_id,
        )
    except Exception as e:
        logger.error("whois error for scan %s: %s", scan_id, e)

    return findings


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------

def _run_dns(scan_id: str, domain: str) -> List[dict]:
    findings = []
    resolver = dns.resolver.Resolver()
    # Tight per-query bound so an unresponsive nameserver can't stall recon.
    # Worst case: 5 records + DMARC + 3 DKIM selectors = 9 queries x 4s = ~36s.
    resolver.timeout = 4
    resolver.lifetime = 4

    txt_records = []  # captured during the loop and reused for the SPF check

    for rtype in ('A', 'MX', 'TXT', 'NS', 'CNAME'):
        try:
            answers = resolver.resolve(domain, rtype)
            records = [str(r) for r in answers]
            if rtype == 'TXT':
                txt_records = records
            evidence = f'{rtype} records: {", ".join(records[:3])}'
            if len(records) > 3:
                evidence += f' (+{len(records) - 3} more)'
            findings.append(normalize_finding(
                module=MODULE, tool='dnspython', type_=f'dns_{rtype.lower()}_record',
                title=f'{rtype} record found for {domain}',
                evidence=evidence,
                severity='Info', target=domain,
            ))
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            pass
        except dns.exception.DNSException as e:
            logger.debug("DNS %s lookup failed for %s: %s", rtype, domain, e)

    # SPF check - reuse the TXT answers already fetched above (no extra query).
    spf_found = any(str(r).strip('"').startswith('v=spf1') for r in txt_records)
    if not spf_found:
        findings.append(normalize_finding(
            module=MODULE, tool='dnspython', type_='missing_spf',
            title='Missing SPF record',
            evidence=f'No v=spf1 TXT record found for {domain}',
            severity='Medium', target=domain,
        ))

    # DMARC check
    dmarc_found = False
    try:
        for r in resolver.resolve(f'_dmarc.{domain}', 'TXT'):
            if 'v=DMARC1' in str(r):
                dmarc_found = True
                break
    except dns.exception.DNSException:
        pass
    if not dmarc_found:
        findings.append(normalize_finding(
            module=MODULE, tool='dnspython', type_='missing_dmarc',
            title='Missing DMARC record',
            evidence=f'No v=DMARC1 TXT record found at _dmarc.{domain}',
            severity='Medium', target=domain,
        ))

    # DKIM check - probe a few common selectors (bounded).
    dkim_found = False
    for selector in ('default', 'google', 'selector1'):
        try:
            if resolver.resolve(f'{selector}._domainkey.{domain}', 'TXT'):
                dkim_found = True
                break
        except dns.exception.DNSException:
            pass
    if not dkim_found:
        findings.append(normalize_finding(
            module=MODULE, tool='dnspython', type_='missing_dkim',
            title='DKIM record not found (common selectors)',
            evidence=f'No DKIM TXT record found for common selectors at *._domainkey.{domain}',
            severity='Medium', target=domain,
        ))

    return findings


# ---------------------------------------------------------------------------
# Main task
# ---------------------------------------------------------------------------

# Recon's worst case grew past the default 300s soft limit after subfinder was
# raised to 60s (API sources) and the nmap app-ports phase was added. It runs
# with a generous per-task ceiling - free, because webscan (~430s) gates total
# scan time anyway, and recon's INTERNAL budgets (nmap/subfinder/whois/dns
# subprocess timeouts) hard-cap the real work at ~356s regardless. The high
# ceiling only adds safety headroom; it never changes normal-run behaviour.
#   Worst case: nmap (180s phase1 + 60s phase2b) + subfinder 60s + WHOIS 20s
#   + DNS 36s = ~356s, far under the 600s soft limit.
@app.task(base=BaseTask, name='tasks.recon.run_recon',
          soft_time_limit=600, time_limit=660)
def run_recon(scan_id: str, domain: str) -> list:
    """
    Recon module: nmap port scan, subfinder subdomain enumeration,
    WHOIS lookup, DNS record checks (SPF/DMARC/DKIM).
    Returns a list of normalized findings (Section 4.3 schema).
    """
    update_module_status(scan_id, MODULE, 'running')
    findings = []
    try:
        findings.extend(_run_nmap(scan_id, domain))
        findings.extend(_run_subfinder(scan_id, domain))
        findings.extend(_run_whois(scan_id, domain))
        findings.extend(_run_dns(scan_id, domain))
        update_module_status(scan_id, MODULE, 'complete')
        return findings
    except Exception as e:
        logger.exception("recon unexpected error scan=%s: %s", scan_id, e)
        update_module_status(scan_id, MODULE, 'failed')
        return findings
