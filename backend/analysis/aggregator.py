import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Groups larger than this are collapsed into one finding (Fix 2) - a single
# WAF/catch-all deny page hit by every wordlist entry should not become
# thousands of "distinct" findings.
_FINGERPRINT_COLLAPSE_THRESHOLD = 5

_SEVERITY_ORDER = {
    'Critical': 0, 'High': 1, 'Medium': 2,
    'Low': 3, 'Informational': 4, 'Info': 4,
}

# OWASP Top 10 2021 - keyed by substring of finding type
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
    # Added for the deterministic CVSS scorer (analysis/cvss_scorer.py) -
    # substring matching already covers every type variant below without
    # needing a separate entry per variant, e.g. 'exposed_admin_panel'
    # matches 'exposed_admin_panel_open'/'_login'/'_denied' alike.
    'exposed_sensitive_file': 'A05:2021 - Security Misconfiguration',
    'exposed_backup_file':    'A05:2021 - Security Misconfiguration',
    'exposed_admin_panel':    'A01:2021 - Broken Access Control',
    'exposed_path':           'A05:2021 - Security Misconfiguration',
    'directory_listing':      'A05:2021 - Security Misconfiguration',
    'outdated_tech':          'A06:2021 - Vulnerable and Outdated Components',
    'nuclei_':                'A06:2021 - Vulnerable and Outdated Components',
    'js_hidden_endpoints':    'A05:2021 - Security Misconfiguration',
}


def _owasp_category(finding_type: str) -> str:
    t = finding_type.lower()
    for key, cat in _OWASP_MAP.items():
        if key in t:
            return cat
    return ''


def _http_fingerprint(f: dict) -> Optional[Tuple[str, int, int]]:
    """
    (finding_type, status_code, size_bucket) for findings carrying
    http_status/http_size (set directly on the finding dict by
    tasks/enumeration.py - see normalize_finding call sites there).
    Findings without HTTP response data return None and are left ungrouped;
    not every finding type has - or needs - this signal.
    """
    status = f.get('http_status')
    size = f.get('http_size')
    if status is None or size is None:
        return None
    bucket = round(size / 100) * 100
    return (f.get('type', ''), status, bucket)


def _collapse_response_fingerprints(findings: List[dict]) -> List[dict]:
    """
    Collapse >5 findings sharing the same (type, status, ~size) signature
    into a single finding. Defense-in-depth against a WAF/catch-all deny
    page being logged as one "finding" per wordlist entry - independent of
    enumeration.py's own baseline filtering, since any module could in
    principle produce a flood.
    """
    groups: Dict[Tuple[str, int, int], List[dict]] = {}
    ungrouped: List[dict] = []

    for f in findings:
        fp = _http_fingerprint(f)
        if fp is None:
            ungrouped.append(f)
            continue
        groups.setdefault(fp, []).append(f)

    result = list(ungrouped)
    for (_, status, _bucket), members in groups.items():
        if len(members) <= _FINGERPRINT_COLLAPSE_THRESHOLD:
            result.extend(members)
            continue

        sizes = [m.get('http_size', 0) for m in members]
        size_avg = round(sum(sizes) / len(sizes))
        paths = [m.get('evidence', '') for m in members]
        example_paths = paths[:3]

        # Inherit everything from the representative member (type, severity,
        # module, http_status, http_size, etc.) - the CVSS scorer keys off
        # `type`, so it must survive the collapse. Only title/evidence/
        # details/found_by are overridden below.
        collapsed = dict(members[0])
        collapsed['title'] = (
            f'{len(members)} paths returned identical HTTP {status} '
            f'response (~{size_avg} bytes)'
        )
        collapsed['evidence'] = (
            '; '.join(example_paths) +
            (f'; ...and {len(members) - 3} others (full list in appendix)'
             if len(members) > 3 else '')
        )[:500]
        collapsed['details'] = {'matched_paths': paths}
        collapsed['found_by'] = sorted({
            source for m in members for source in m.get('found_by', [])
        })
        result.append(collapsed)

    return result


def aggregate(module_results: List[dict]) -> dict:
    """
    Merge, deduplicate, enrich and sort findings from all 8 scanning modules,
    and roll up their tool_versions + execution status.

    Args:
        module_results: list of per-module result dicts, each built by
            tasks/base_task.py's build_module_result() -
            {module, status, findings, tool_versions, finding_count,
             duration_seconds, error}. A bare list (the pre-Fix-1 module
             contract) is tolerated defensively but logged as unexpected -
             every module should emit the envelope shape now.

    Returns:
        {
            'findings': [...],       # deduplicated, collapsed, sorted, enriched
            'total': int,
            'scan_metadata': { 'timestamp': ISO8601, 'tool_versions': {...} },
            'module_execution': [ {module, status, finding_count,
                                    duration_seconds, error}, ... ],
        }
    """
    # 1. Flatten findings + roll up tool_versions/module_execution from every
    #    module's envelope - including modules that produced zero findings,
    #    so a module that ran cleanly still shows up in both tables.
    flat: List[dict] = []
    tool_versions: Dict[str, str] = {}
    module_execution: List[dict] = []

    for result in module_results:
        if isinstance(result, dict) and 'findings' in result:
            module_findings = result.get('findings', [])
            if isinstance(module_findings, list):
                flat.extend(f for f in module_findings if isinstance(f, dict))
            tool_versions.update(result.get('tool_versions') or {})
            module_execution.append({
                'module': result.get('module', 'unknown'),
                'status': result.get('status', 'success'),
                'finding_count': result.get('finding_count', len(module_findings)),
                'duration_seconds': result.get('duration_seconds', 0.0),
                'error': result.get('error'),
            })
        elif isinstance(result, list):
            # Defensive fallback for a module not yet updated to the new
            # envelope - findings still get aggregated, just without
            # tool_versions/execution visibility for that module.
            logger.warning("aggregator: module result is a bare list, not the "
                            "build_module_result() envelope - update that module")
            flat.extend(f for f in result if isinstance(f, dict))

    logger.info("aggregator: %d raw findings from %d modules",
                len(flat), len(module_results))

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

    # 2b. Collapse near-duplicate HTTP findings (>5 sharing type+status+size)
    #     into one grouped finding - independent second dedup pass, see
    #     _collapse_response_fingerprints docstring.
    merged = _collapse_response_fingerprints(merged)

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

    # 6. Stable finding_id - lets the CVSS scorer and the Ollama description
    #    merge (analysis/ollama_client.py) match findings back up after the
    #    list gets trimmed/reshaped downstream.
    for i, f in enumerate(merged):
        f['finding_id'] = f'f{i}'

    return {
        'findings': merged,
        'total': len(merged),
        'scan_metadata': {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'tool_versions': tool_versions,
        },
        'module_execution': module_execution,
    }
