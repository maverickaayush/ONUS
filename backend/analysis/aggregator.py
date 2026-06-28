import logging
import shutil
import subprocess
from datetime import datetime, timezone
from typing import List

logger = logging.getLogger(__name__)

_SEVERITY_ORDER = {
    'Critical': 0, 'High': 1, 'Medium': 2,
    'Low': 3, 'Informational': 4, 'Info': 4,
}

# OWASP Top 10 2021 — keyed by substring of finding type
_OWASP_MAP = {
    'sqli':                   'A03:2021 - Injection',
    'xss':                    'A03:2021 - Injection',
    'reflected_xss':          'A03:2021 - Injection',
    'path_traversal':         'A01:2021 - Broken Access Control',
    'open_redirect':          'A01:2021 - Broken Access Control',
    'idor':                   'A01:2021 - Broken Access Control',
    'error_disclosure':       'A05:2021 - Security Misconfiguration',
    'missing_hsts':           'A05:2021 - Security Misconfiguration',
    'weak_hsts':              'A05:2021 - Security Misconfiguration',
    'hsts_missing':           'A05:2021 - Security Misconfiguration',
    'missing_csp':            'A05:2021 - Security Misconfiguration',
    'csp_unsafe':             'A05:2021 - Security Misconfiguration',
    'missing_clickjacking':   'A05:2021 - Security Misconfiguration',
    'missing_x_content':      'A05:2021 - Security Misconfiguration',
    'missing_referrer':       'A05:2021 - Security Misconfiguration',
    'missing_permissions':    'A05:2021 - Security Misconfiguration',
    'cors_wildcard':          'A05:2021 - Security Misconfiguration',
    'insecure_redirect':      'A05:2021 - Security Misconfiguration',
    'server_version':         'A05:2021 - Security Misconfiguration',
    'x_powered_by':           'A05:2021 - Security Misconfiguration',
    'cookie_missing':         'A05:2021 - Security Misconfiguration',
    'open_port':              'A05:2021 - Security Misconfiguration',
    'subdomain_found':        'A05:2021 - Security Misconfiguration',
    'nikto_finding':          'A05:2021 - Security Misconfiguration',
    'tls10_enabled':          'A02:2021 - Cryptographic Failures',
    'tls11_enabled':          'A02:2021 - Cryptographic Failures',
    'sslv2_enabled':          'A02:2021 - Cryptographic Failures',
    'sslv3_enabled':          'A02:2021 - Cryptographic Failures',
    'weak_cipher':            'A02:2021 - Cryptographic Failures',
    'weak_dh':                'A02:2021 - Cryptographic Failures',
    'cert_expired':           'A02:2021 - Cryptographic Failures',
    'cert_self_signed':       'A02:2021 - Cryptographic Failures',
    'cert_expiring':          'A02:2021 - Cryptographic Failures',
    'missing_spf':            'A05:2021 - Security Misconfiguration',
    'missing_dmarc':          'A05:2021 - Security Misconfiguration',
    'missing_dkim':           'A05:2021 - Security Misconfiguration',
    'zap_':                   'A03:2021 - Injection',
}


def _owasp_category(finding_type: str) -> str:
    t = finding_type.lower()
    for key, cat in _OWASP_MAP.items():
        if key in t:
            return cat
    return ''


def _tool_version(tool: str, *flags: str) -> str:
    """Return first line of tool version output, or 'not installed'."""
    if not shutil.which(tool):
        return 'not installed'
    try:
        r = subprocess.run([tool, *flags], capture_output=True,
                           timeout=5, check=False)
        out = (r.stdout or r.stderr or b'').decode(errors='ignore').strip()
        return out.splitlines()[0] if out else 'unknown'
    except Exception:
        return 'unknown'


def aggregate(findings_list: List[List[dict]]) -> dict:
    """
    Merge, deduplicate, enrich and sort findings from all five scanning modules.

    Args:
        findings_list: list of per-module finding lists in any order
                       e.g. [[recon_findings], [webscan], [ssl], [headers], [owasp]]

    Returns:
        {
            'findings': [...],       # deduplicated, sorted, enriched
            'total': int,
            'scan_metadata': { 'timestamp': ISO8601, 'tool_versions': {...} }
        }
    """
    # 1. Flatten — skip None / non-list module results gracefully
    flat: List[dict] = []
    for module_result in findings_list:
        if isinstance(module_result, list):
            flat.extend(f for f in module_result if isinstance(f, dict))

    logger.info("aggregator: %d raw findings from %d modules",
                len(flat), len(findings_list))

    # 2. Deduplicate on (type, evidence[:100])
    #    When the same vuln is found by multiple modules, merge their
    #    names into found_by and keep the higher-severity instance.
    seen: dict = {}    # key -> index in `merged`
    merged: List[dict] = []

    for f in flat:
        key = (f.get('type', ''), f.get('evidence', '')[:100])
        if key in seen:
            existing = merged[seen[key]]
            # Merge found_by lists
            for source in f.get('found_by', [f.get('module', 'unknown')]):
                if source not in existing.setdefault('found_by', []):
                    existing['found_by'].append(source)
            # Keep the higher severity of the two
            if (_SEVERITY_ORDER.get(f.get('severity', 'Info'), 4) <
                    _SEVERITY_ORDER.get(existing.get('severity', 'Info'), 4)):
                existing['severity'] = f['severity']
        else:
            entry = dict(f)
            # Guarantee found_by is always a list
            if not isinstance(entry.get('found_by'), list):
                entry['found_by'] = [entry.get('module', 'unknown')]
            seen[key] = len(merged)
            merged.append(entry)

    # 3. OWASP category enrichment
    for f in merged:
        if not f.get('owasp_category'):
            f['owasp_category'] = _owasp_category(f.get('type', ''))

    # 4. Sort Critical → High → Medium → Low → Informational
    merged.sort(key=lambda f: _SEVERITY_ORDER.get(f.get('severity', 'Info'), 4))

    # 5. Truncate evidence to 500 chars
    for f in merged:
        if len(f.get('evidence', '')) > 500:
            f['evidence'] = f['evidence'][:500]

    return {
        'findings': merged,
        'total': len(merged),
        'scan_metadata': {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'tool_versions': {
                'nmap':      _tool_version('nmap', '--version'),
                'subfinder': _tool_version('subfinder', '-version'),
                'testssl':   _tool_version('testssl.sh', '--version'),
                'sslscan':   _tool_version('sslscan', '--version'),
                'nikto':     _tool_version('nikto', '-Version'),
            },
        },
    }
