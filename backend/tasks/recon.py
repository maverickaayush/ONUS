import json
import logging
import os
import subprocess
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import List
from urllib.parse import urlparse

import dns.exception
import dns.resolver
from celery.exceptions import SoftTimeLimitExceeded
from whois.parser import WhoisEntry

from tasks.base_task import (
    BaseTask, normalize_finding, update_module_status,
    get_tool_version, build_module_result, scaled_timeout,
)
from tasks.celery_app import app
from tasks.tech_fingerprint import _eol_threshold, _parse_version

logger = logging.getLogger(__name__)
MODULE = 'recon'

# Per-phase nmap/subfinder/amass/httpx/naabu/whois subprocess budgets, all
# scaled by SCAN_TIMEOUT_MULTIPLIER for real-world targets (more open ports,
# more subdomains, slower DNS/WHOIS servers) - see tasks/base_task.py's
# scaled_timeout().
_NMAP_TOP_PORTS_TIMEOUT = scaled_timeout(180)
_NMAP_FULL_RANGE_TIMEOUT = scaled_timeout(250)
_NMAP_FULL_RANGE_HOST_TIMEOUT = scaled_timeout(240)
_NMAP_APP_DETECT_TIMEOUT = scaled_timeout(60)
_SUBFINDER_TIMEOUT = scaled_timeout(60)
_AMASS_TIMEOUT = scaled_timeout(300)
_HTTPX_TIMEOUT = scaled_timeout(180)
_NAABU_TIMEOUT = scaled_timeout(240)
_WHOIS_TIMEOUT = scaled_timeout(20)

# Timeout headroom, not just a happy-path budget: the old soft=900/hard=1080
# base budget was tuned before Amass/httpx/Naabu were chained in as a
# sequential subdomain -> liveness -> port pipeline. Worst-case chain at
# multiplier=1.0 (nmap responsive-path 430s + subfinder 60s + amass 300s +
# httpx 180s + naabu 240s + whois 20s + dns ~24s ~= 1254s, or ~1494s if
# naabu's -sT CONNECT fallback fires and doubles that one stage) already
# exceeds the old 1080s hard limit before any SCAN_TIMEOUT_MULTIPLIER
# scaling. Raised with real margin over that recomputed worst case.
#
# Correction, found live: an earlier version of this comment claimed the
# CONNECT fallback "always fires in this deployment" because the worker's
# docker-compose.yml entry has no explicit `cap_add: NET_RAW`. Verified
# directly against the running container (`cat /proc/self/status | grep
# CapEff`, decoded the bitmask): CAP_NET_RAW **is** present - Docker grants
# it by default unless explicitly dropped, which this deployment doesn't
# do, so naabu's SYN scan actually succeeds here and the fallback is the
# rare case ARCHITECTURE.md originally assumed, not the routine one. The timeout
# headroom above is still worth keeping (a real deployment could easily
# run with `cap_drop: NET_RAW` or a hardened base image where this doesn't
# hold), but don't repeat the "always fires here" claim without re-checking
# CapEff on the actual target container first.
_RECON_SOFT_LIMIT = scaled_timeout(1650)
_RECON_HARD_LIMIT = scaled_timeout(1800)


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
    except SoftTimeLimitExceeded:
        raise
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

    nmap stays bounded to ~250s worst case (filtered: Phase 1 ~180s + Phase 2b
    ~60s; responsive-but-busy: Phase 1 ~30s + Phase 2a ~250s), well within
    this task's own soft/hard Celery limit (see _RECON_SOFT_LIMIT/
    _RECON_HARD_LIMIT and the @app.task decorator below).
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
        subproc_timeout=_NMAP_TOP_PORTS_TIMEOUT, tag='top',
    ))
    phase1_elapsed = time.monotonic() - t0

    if phase1_elapsed < 30:
        # Phase 2a: responsive host - full port range for complete coverage.
        for portid, finding in _nmap_phase(
            scan_id, domain, port_args=['-p-'],
            host_timeout=f'{_NMAP_FULL_RANGE_HOST_TIMEOUT}s', subproc_timeout=_NMAP_FULL_RANGE_TIMEOUT, tag='full',
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
            subproc_timeout=_NMAP_APP_DETECT_TIMEOUT, tag='app',
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
            timeout=_SUBFINDER_TIMEOUT,
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
    except SoftTimeLimitExceeded:
        raise
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
# Amass -> httpx -> Naabu (chained: deep subdomains -> liveness -> ports)
# ---------------------------------------------------------------------------

def _run_amass(scan_id: str, domain: str) -> List[str]:
    """
    Deep passive subdomain enumeration (CT logs, Wayback, passive DNS).
    Returns a deduplicated list of subdomain names - no findings are emitted
    here, the union of subfinder + Amass names feeds httpx, which is where
    the liveness-checked 'live_subdomain' findings get created.
    """
    out_path = f'/tmp/amass_{scan_id}.json'
    subdomains = []
    try:
        subprocess.run(
            ['amass', 'enum', '-passive', '-d', domain,
             '-json', out_path, '-timeout', '5'],
            timeout=_AMASS_TIMEOUT, capture_output=True, check=False,
        )
        if os.path.exists(out_path):
            with open(out_path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        name = json.loads(line).get('name')
                    except json.JSONDecodeError:
                        continue
                    if name:
                        subdomains.append(name)
    except subprocess.TimeoutExpired:
        logger.warning("amass timed out (300s) for scan %s", scan_id)
    except FileNotFoundError:
        logger.warning("amass not installed - deep subdomain enum skipped")
    except SoftTimeLimitExceeded:
        raise
    except Exception as e:
        logger.error("amass error for scan %s: %s", scan_id, e)
    finally:
        if os.path.exists(out_path):
            try:
                os.unlink(out_path)
            except OSError:
                pass
    return sorted(set(subdomains))


def _run_httpx(scan_id: str, domain: str, subdomains: List[str]) -> List[dict]:
    """
    Probe the subfinder+Amass subdomain union for live HTTP hosts + tech stack.
    Returns the live-host dicts (also consumed by _run_naabu next) -
    'live_subdomain'/'outdated_tech' findings are built separately by
    _httpx_findings() from this same return value.
    """
    if not subdomains:
        return []

    subs_path = f'/tmp/subs_{scan_id}.txt'
    out_path = f'/tmp/httpx_{scan_id}.json'
    live_hosts = []
    try:
        with open(subs_path, 'w') as f:
            f.write('\n'.join(subdomains))

        subprocess.run(
            ['httpx', '-l', subs_path, '-json', '-status-code', '-title',
             '-tech-detect', '-tls-probe', '-timeout', '10', '-threads', '20',
             '-silent', '-o', out_path],
            timeout=_HTTPX_TIMEOUT, capture_output=True, check=False,
        )

        if os.path.exists(out_path):
            with open(out_path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    live_hosts.append({
                        'url': entry.get('url', ''),
                        'status_code': entry.get('status_code', ''),
                        'title': entry.get('title', ''),
                        'tech': entry.get('tech') or [],
                        'tls_grade': entry.get('tls_grade'),
                    })
    except subprocess.TimeoutExpired:
        logger.warning("httpx timed out (180s) for scan %s", scan_id)
    except FileNotFoundError:
        logger.warning("httpx not installed - live-host probing skipped")
    except SoftTimeLimitExceeded:
        raise
    except Exception as e:
        logger.error("httpx error for scan %s: %s", scan_id, e)
    finally:
        for p in (subs_path, out_path):
            if os.path.exists(p):
                try:
                    os.unlink(p)
                except OSError:
                    pass

    return live_hosts


def _httpx_findings(live_hosts: List[dict], domain: str) -> List[dict]:
    """Convert httpx's live-host dicts into normalized findings. EOL/outdated
    tech detection reuses tech_fingerprint's threshold table (same 'outdated_tech'
    type key) rather than duplicating it - keeps scoring consistent."""
    findings = []
    for host in live_hosts:
        url = host.get('url', '')
        findings.append(normalize_finding(
            module=MODULE, tool='httpx', type_='live_subdomain',
            title=f'Live subdomain: {url}',
            evidence=f'HTTP {host.get("status_code", "")} - {host.get("title", "")}',
            severity='Informational', target=domain,
        ))
        for tech in host.get('tech') or []:
            threshold = _eol_threshold(tech)
            parsed = _parse_version(tech)
            if threshold and parsed and parsed < threshold:
                findings.append(normalize_finding(
                    module=MODULE, tool='httpx', type_='outdated_tech',
                    title=f'Outdated {tech} - end of life',
                    evidence=f'{tech} detected on {url} via httpx tech-detect',
                    severity='Medium', cvss=5.4, target=domain,
                ))
    return findings


def _run_naabu(scan_id: str, domain: str, live_hosts: List[dict]) -> List[dict]:
    """
    Fast top-1000-port pre-scan on live subdomains discovered by httpx.
    SYN mode needs CAP_NET_RAW; if the worker is unprivileged (permission
    denied), falls back to a CONNECT scan (-sT) and logs a warning.
    These are ADDITIONAL findings on newly-discovered subdomains - they
    supplement, not replace, nmap's scan of the primary domain.
    """
    hosts = sorted({
        urlparse(h['url']).hostname
        for h in live_hosts if h.get('url') and urlparse(h['url']).hostname
    })
    if not hosts:
        return []

    hosts_path = f'/tmp/naabu_hosts_{scan_id}.txt'
    out_path = f'/tmp/naabu_{scan_id}.json'
    findings = []
    seen = set()
    try:
        with open(hosts_path, 'w') as f:
            f.write('\n'.join(hosts))

        cmd = ['naabu', '-list', hosts_path, '-top-ports', '1000',
               '-rate', '1000', '-c', '25', '-json', '-o', out_path,
               '-silent', '-no-color']
        proc = subprocess.run(cmd, timeout=_NAABU_TIMEOUT, capture_output=True, check=False)
        stderr = (proc.stderr or b'').decode(errors='ignore').lower()

        if 'permission denied' in stderr or 'operation not permitted' in stderr:
            logger.warning(
                "naabu SYN scan unavailable (needs CAP_NET_RAW) for scan %s - "
                "falling back to CONNECT scan (-sT)", scan_id,
            )
            subprocess.run(cmd + ['-sT'], timeout=_NAABU_TIMEOUT, capture_output=True, check=False)

        if os.path.exists(out_path):
            with open(out_path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    host, port = entry.get('host'), entry.get('port')
                    if not host or not port or (host, port) in seen:
                        continue
                    seen.add((host, port))
                    findings.append(normalize_finding(
                        module=MODULE, tool='naabu', type_='open_port_naabu',
                        title=f'Open port {port} on {host}',
                        evidence=f'{host}:{port} discovered by Naabu SYN scan',
                        severity='Informational', target=domain,
                    ))
    except subprocess.TimeoutExpired:
        logger.warning("naabu timed out (240s) for scan %s", scan_id)
    except FileNotFoundError:
        logger.warning("naabu not installed - subdomain port pre-scan skipped")
    except SoftTimeLimitExceeded:
        raise
    except Exception as e:
        logger.error("naabu error for scan %s: %s", scan_id, e)
    finally:
        for p in (hosts_path, out_path):
            if os.path.exists(p):
                try:
                    os.unlink(p)
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
            ['whois', domain], timeout=_WHOIS_TIMEOUT, capture_output=True, check=False,
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
    except SoftTimeLimitExceeded:
        raise
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

# Recon's worst case was ~356s (nmap + subfinder + WHOIS + DNS) under the
# previous 600s/660s ceiling. Amass/httpx/Naabu were added as a chained
# subdomain -> liveness -> port pipeline (added post-Step 9). Recomputed
# worst case at multiplier=1.0: nmap responsive-path 430s + subfinder 60s +
# Amass 300s + httpx 180s + Naabu 240s (480s if the -sT CONNECT fallback
# fires - verified live this isn't the routine case here, since Docker
# grants CAP_NET_RAW by default and this deployment doesn't drop it, see
# the correction note above _RECON_SOFT_LIMIT) + whois 20s + DNS ~24s ~=
# 1254-1494s - already past the old 1080s hard limit before any
# SCAN_TIMEOUT_MULTIPLIER scaling, with or without the fallback. Raised to
# soft=1650s/hard=1800s (base, see _RECON_SOFT_LIMIT/_RECON_HARD_LIMIT
# above) for real headroom - still free (webscan is not the gating module
# anymore, but recon runs in
# parallel with it either way and is never on the pipeline's critical path
# for aggregation to start).
@app.task(base=BaseTask, name='tasks.recon.run_recon',
          soft_time_limit=_RECON_SOFT_LIMIT, time_limit=_RECON_HARD_LIMIT)
def run_recon(scan_id: str, domain: str) -> dict:
    """
    Recon module: nmap port scan, subfinder + Amass subdomain enumeration,
    httpx liveness/tech probing, Naabu port pre-scan on live subdomains,
    WHOIS lookup, DNS record checks (SPF/DMARC/DKIM).
    Returns a build_module_result() envelope (Section 4.3 schema note).
    """
    update_module_status(scan_id, MODULE, 'running')
    start = time.monotonic()
    findings = []
    try:
        findings.extend(_run_nmap(scan_id, domain))

        subfinder_findings = _run_subfinder(scan_id, domain)
        findings.extend(subfinder_findings)
        subfinder_subs = {f['evidence'] for f in subfinder_findings}

        amass_subs = _run_amass(scan_id, domain)
        combined_subs = sorted(subfinder_subs | set(amass_subs))

        live_hosts = _run_httpx(scan_id, domain, combined_subs)
        findings.extend(_httpx_findings(live_hosts, domain))
        findings.extend(_run_naabu(scan_id, domain, live_hosts))

        findings.extend(_run_whois(scan_id, domain))
        findings.extend(_run_dns(scan_id, domain))

        tool_versions = {
            'nmap':      get_tool_version('nmap', '--version'),
            'subfinder': get_tool_version('subfinder', '-version'),
            'amass':     get_tool_version('amass', '-version'),
            'httpx':     get_tool_version('httpx', '-version'),
            'naabu':     get_tool_version('naabu', '-version'),
            'whois':     get_tool_version('whois', '--version'),
        }
        update_module_status(scan_id, MODULE, 'complete')
        return build_module_result(MODULE, findings, tool_versions, status='success',
                                    duration_seconds=time.monotonic() - start)
    except SoftTimeLimitExceeded:
        logger.warning("recon hit its soft time limit (%ds) for scan %s", _RECON_SOFT_LIMIT, scan_id)
        update_module_status(scan_id, MODULE, 'failed')
        return build_module_result(MODULE, findings, {}, status='timeout',
                                    error=f'Module exceeded its soft time limit ({_RECON_SOFT_LIMIT}s)',
                                    duration_seconds=time.monotonic() - start)
    except Exception as e:
        logger.exception("recon unexpected error scan=%s: %s", scan_id, e)
        update_module_status(scan_id, MODULE, 'failed')
        return build_module_result(MODULE, findings, {}, status='failed',
                                    error=str(e), duration_seconds=time.monotonic() - start)
