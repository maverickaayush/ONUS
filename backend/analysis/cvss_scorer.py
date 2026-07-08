"""
Deterministic CVSS v3.1 scoring engine.

Architecture invariant (ARCHITECTURE.md Section 4.5/4.6): deterministic code owns
every number in a report - severity, cvss_score, cvss_vector, owasp_category,
priority, risk_score. Ollama only ever produces prose. score_finding() is the
single entry point that turns a raw finding's `type` into those five numbers,
using the official CVSS v3.1 base-score formula (implemented below, not
hardcoded score-to-vector pairs) plus a rule catalogue that assigns a vector
per finding type.

Two runs of the same scan must produce byte-identical severity/cvss/priority
output - this module has no I/O and no randomness.
"""
import re
from typing import Callable, Dict, Optional, Tuple, Union

from analysis.aggregator import _owasp_category

# ---------------------------------------------------------------------------
# Official CVSS v3.1 base score formula (first.org/cvss/v3-1/specification-document)
# ---------------------------------------------------------------------------

_AV_WEIGHT = {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.20}
_AC_WEIGHT = {'L': 0.77, 'H': 0.44}
_PR_WEIGHT_UNCHANGED = {'N': 0.85, 'L': 0.62, 'H': 0.27}
_PR_WEIGHT_CHANGED = {'N': 0.85, 'L': 0.68, 'H': 0.50}
_UI_WEIGHT = {'N': 0.85, 'R': 0.62}
_CIA_WEIGHT = {'H': 0.56, 'L': 0.22, 'N': 0.0}

_VECTOR_RE = re.compile(
    r'AV:(?P<AV>[NALP])/AC:(?P<AC>[LH])/PR:(?P<PR>[NLH])/UI:(?P<UI>[NR])/'
    r'S:(?P<S>[UC])/C:(?P<C>[NLH])/I:(?P<I>[NLH])/A:(?P<A>[NLH])'
)


def parse_vector(vector: str) -> Dict[str, str]:
    m = _VECTOR_RE.match(vector.strip())
    if not m:
        raise ValueError(f'Malformed CVSS v3.1 vector: {vector!r}')
    return m.groupdict()


def _roundup(x: float) -> float:
    """Official CVSS 'round up to 1 decimal' - avoids naive float rounding
    errors (e.g. round(4.02, 1) == 4.0 would be wrong; this always rounds
    UP to the next 0.1 unless x already lands exactly on one)."""
    int_input = round(x * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (int_input // 10000 + 1) / 10.0


def base_score(vector: str) -> float:
    """Compute the CVSS v3.1 base score from a vector string via the
    official formula - never hardcode a score for a given vector."""
    m = parse_vector(vector)
    scope = m['S']

    av = _AV_WEIGHT[m['AV']]
    ac = _AC_WEIGHT[m['AC']]
    pr = (_PR_WEIGHT_CHANGED if scope == 'C' else _PR_WEIGHT_UNCHANGED)[m['PR']]
    ui = _UI_WEIGHT[m['UI']]
    c = _CIA_WEIGHT[m['C']]
    i = _CIA_WEIGHT[m['I']]
    a = _CIA_WEIGHT[m['A']]

    isc_base = 1 - (1 - c) * (1 - i) * (1 - a)
    if isc_base <= 0:
        return 0.0

    if scope == 'U':
        isc = 6.42 * isc_base
    else:
        isc = 7.52 * (isc_base - 0.029) - 3.25 * ((isc_base - 0.02) ** 15)

    exploitability = 8.22 * av * ac * pr * ui

    if scope == 'U':
        return _roundup(min(isc + exploitability, 10.0))
    return _roundup(min(1.08 * (isc + exploitability), 10.0))


def severity_from_score(score: float) -> str:
    """Official CVSS v3.1 qualitative severity rating scale."""
    if score <= 0.0:
        return 'Informational'
    if score < 4.0:
        return 'Low'
    if score < 7.0:
        return 'Medium'
    if score < 9.0:
        return 'High'
    return 'Critical'


# ---------------------------------------------------------------------------
# Representative vectors per severity band - used only for finding types
# where an external tool has ALREADY made an authoritative severity call
# (nuclei templates, ZAP alert risk, Nikto, testssl.sh) and re-deriving a
# per-finding vector from scratch would be guessing. The band vector still
# goes through the same base_score() formula above - only vector SELECTION
# is severity-based here, the arithmetic is not hardcoded.
# ---------------------------------------------------------------------------

_BAND_VECTOR = {
    'Critical':      'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    'High':          'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N',
    'Medium':        'AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N',
    'Low':           'AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N',
    'Informational': 'AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N',
}
_TRUST_SOURCE_TYPES = {'whois_expiry'}  # real domain-specific logic already computed upstream
# zap_*: ZAP's own alert `risk` field, per-alert (webscan.py _ZAP_RISK_MAP).
# testssl_*: testssl.sh's own per-item `severity` field (ssl_tls.py
# _TESTSSL_SEVERITY_MAP). Both are genuine per-finding external signals.
# Nikto is NOT in this list - webscan.py hardcodes severity='Low' for every
# nikto_finding rather than reading a per-finding signal from Nikto's own
# output, so there is nothing to "trust" there; it gets a fixed Low-band
# rule in _RULES below instead (same resulting vector, honest framing).
_TRUST_SOURCE_PREFIXES = ('zap_', 'testssl_')

# nuclei keeps its own pre-computed cvss float directly (template authors
# know the specific CVE better than a generic band) - never re-derive.
_NUCLEI_PREFIX = 'nuclei_'

_DIRECTORY_LISTING_RE = re.compile(r'directory index|autoindex|index of /', re.IGNORECASE)


# ---------------------------------------------------------------------------
# Rule catalogue - finding type -> CVSS v3.1 vector. Every rule here was
# reasoned through metric-by-metric (AV/AC/PR/UI/S/C/I/A), not guessed.
# Vectors are the source of truth; base_score() computes the actual number,
# which may differ slightly from any score mentioned in code comments -
# that's expected, the formula is authoritative, not the comment.
# ---------------------------------------------------------------------------

Rule = Union[str, Callable[[dict], str]]

_RULES: Dict[str, Rule] = {
    # --- Enumeration (tasks/enumeration.py) ---
    'exposed_sensitive_file':        'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    'exposed_sensitive_file_denied': 'AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N',
    'exposed_admin_panel_open':      'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N',
    'exposed_admin_panel_login':     'AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
    'exposed_admin_panel_denied':    'AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N',
    'exposed_path_200':              'AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
    'exposed_path_401':              'AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N',
    'exposed_path_403':              'AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N',
    'exposed_path_301':              'AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N',
    'exposed_path_302':              'AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N',
    'exposed_backup_file':           'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N',
    'directory_listing_enabled':     'AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',

    # --- OWASP Top 10 (tasks/owasp.py) ---
    'sqli_error_based':       'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    'sqli_time_based':        'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',   # not yet emitted - forward-compat
    'sqli_boolean_based':     'AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N',
    'reflected_xss':          'AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
    'xss_stored':             'AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N',   # not yet emitted - forward-compat
    'path_traversal':         'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    'path_traversal_suspected': 'AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N',  # not yet emitted - forward-compat
    'open_redirect':          'AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
    'error_disclosure':       'AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
    'idor':                   'AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N',

    # --- SSL/TLS (tasks/ssl_tls.py) ---
    'tls10_enabled':      'AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N',
    'tls11_enabled':      'AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N',
    'sslv2_enabled':      'AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N',
    'sslv3_enabled':      'AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N',
    'weak_cipher_rc4':    'AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N',
    'weak_cipher_des':    'AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N',
    'weak_cipher_bits':   'AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N',
    'weak_dh_params':     'AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N',
    'cert_expired':       'AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N',
    'cert_expiring_soon': 'AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N',
    'cert_self_signed':   'AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N',
    'no_https':            'AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N',
    'no_ocsp_stapling':    'AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N',  # not yet emitted - forward-compat

    # --- HTTP headers (tasks/headers.py) ---
    'missing_hsts':                    'AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N',
    'weak_hsts_max_age':               'AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N',
    'hsts_missing_includesubdomains':  'AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N',
    'missing_csp':                     'AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N',
    'csp_unsafe_inline':               'AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N',
    'csp_unsafe_eval':                 'AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N',
    'missing_clickjacking_protection': 'AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N',
    'missing_x_content_type_options':  'AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N',
    'missing_referrer_policy':         'AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N',
    'missing_permissions_policy':      'AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N',
    'cors_wildcard_with_credentials':  'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N',
    'cors_wildcard':                   'AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',
    'insecure_redirect':               'AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N',
    'cookie_missing_secure':           'AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N',
    'cookie_missing_httponly':         'AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N',
    'cookie_missing_samesite':         'AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N',
    'headers_present_summary':         'AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N',
    'target_unreachable':              'AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N',

    # --- Tech fingerprint / WAF (tasks/tech_fingerprint.py) ---
    'tech_detected':     'AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N',
    'outdated_tech':     'AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N',   # info disclosure, no known-CVE lookup available (air-gapped)
    'waf_detected':      'AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N',   # a control, not a vulnerability
    'no_waf_detected':   'AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N',
    'waf_unknown':       'AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N',

    # --- Web scan (tasks/webscan.py) - non-authoritative extras ---
    'crawled_endpoint_katana': 'AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N',
    'js_hidden_endpoints':     'AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N',
    # Fixed Low-band vector, not TRUST_SOURCE - webscan.py hardcodes
    # severity='Low' for every Nikto hit rather than reading a per-finding
    # signal from Nikto's own output, so there's no real severity to trust.
    'nikto_finding':           'AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N',

    # --- Recon (tasks/recon.py) - attack-surface data, not vulnerabilities ---
    'open_port':            'AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N',
    'open_port_naabu':      'AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N',
    'scan_timeout':          'AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N',
    'subdomain_found':       'AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N',
    'live_subdomain':        'AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N',
    'whois_registrar':       'AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N',
    'whois_creation_date':   'AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N',
    'whois_nameservers':     'AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N',
    'whois_abuse_contact':   'AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N',
    'missing_spf':           'AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N',
    'missing_dmarc':         'AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N',
    'missing_dkim':          'AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N',
}

# server/framework/x-powered-by version disclosure shares one vector
_RULES['server_version_exposed'] = _RULES['outdated_tech']
_RULES['x_powered_by_exposed'] = _RULES['outdated_tech']


# ---------------------------------------------------------------------------
# Priority - independent of severity, per ARCHITECTURE.md/spec: driven by
# exploitability (AV/PR), not just the score bucket.
# ---------------------------------------------------------------------------

def _priority(severity: str, av: str, pr: str) -> int:
    if severity == 'Critical':
        return 1 if (av == 'N' and pr == 'N') else 2
    return {'High': 2, 'Medium': 3, 'Low': 4, 'Informational': 5}.get(severity, 5)


# ---------------------------------------------------------------------------
# Confidence-driven priority shift (Phase 1 verification, analysis/verifier.py).
# A confirmed finding (re-verified proof) is more urgent than the severity
# band alone suggests; an unverified one (failed to reproduce, or never
# dispatched to a verifier) is less urgent. 'probable' - the default for
# every finding a verifier didn't touch - is unchanged, so this is a no-op
# for any finding type Phase 1 doesn't verify yet (e.g. reflected_xss).
# ---------------------------------------------------------------------------

def _shift_priority_by_confidence(priority: int, confidence: str) -> int:
    if confidence == 'confirmed':
        return max(1, priority - 1)
    if confidence == 'unverified':
        return min(5, priority + 1)
    return priority


# ---------------------------------------------------------------------------
# Rule resolution
# ---------------------------------------------------------------------------

def _resolve_vector(ftype: str, finding: dict) -> Tuple[str, Optional[float]]:
    """
    Return (vector, trusted_score_or_None). trusted_score is only set for
    nuclei_* findings, where the template's own pre-computed cvss is kept
    verbatim instead of being re-derived from a band vector.
    """
    # Nikto genuinely reports "Directory indexing found"-style messages -
    # reuse that real signal instead of inventing detection.
    if ftype == 'nikto_finding':
        text = f"{finding.get('title', '')} {finding.get('evidence', '')}"
        if _DIRECTORY_LISTING_RE.search(text):
            return _RULES['directory_listing_enabled'], None

    if ftype in _RULES:
        rule = _RULES[ftype]
        vector = rule(finding) if callable(rule) else rule
        return vector, None

    if ftype.startswith(_NUCLEI_PREFIX):
        severity = finding.get('severity', 'Informational')
        band_vector = _BAND_VECTOR.get(severity, _BAND_VECTOR['Informational'])
        trusted_score = float(finding.get('cvss', 0.0) or 0.0)
        return band_vector, trusted_score

    if ftype.startswith(_TRUST_SOURCE_PREFIXES) or ftype in _TRUST_SOURCE_TYPES:
        severity = finding.get('severity', 'Informational')
        return _BAND_VECTOR.get(severity, _BAND_VECTOR['Informational']), None

    # Unknown type - safety net. Use whatever severity the scanning module
    # already assigned as the band selector, so every finding still gets a
    # deterministic, formula-derived score rather than an error.
    severity = finding.get('severity', 'Informational')
    return _BAND_VECTOR.get(severity, _BAND_VECTOR['Informational']), None


def score_finding(finding: dict, target_context: Optional[dict] = None) -> dict:
    """
    Deterministically score one finding. Returns
    {cvss_score, cvss_vector, severity, priority, owasp_category}.

    target_context is accepted for interface stability / future per-target
    tuning (e.g. "is this a production target") but unused today - no
    reliable signal exists yet to act on it.
    """
    ftype = finding.get('type', '')
    vector, trusted_score = _resolve_vector(ftype, finding)
    metrics = parse_vector(vector)

    score = trusted_score if trusted_score is not None else base_score(vector)
    severity = severity_from_score(score)
    priority = _priority(severity, metrics['AV'], metrics['PR'])
    priority = _shift_priority_by_confidence(priority, finding.get('confidence', 'probable'))
    owasp = _owasp_category(ftype) or ''

    return {
        'cvss_score': round(score, 1),
        'cvss_vector': vector,
        'severity': severity,
        'priority': priority,
        'owasp_category': owasp,
    }


# ---------------------------------------------------------------------------
# Overall risk score - deliberately non-linear on the low end so a flood of
# Mediums (the demo-target.example bug) cannot alone drive the score to 100.
#
# Confidence-weighted (Phase 1 verification): a confirmed finding counts at
# full severity weight, an unverified one at half - a scan full of
# unverified Criticals should not read as identically dangerous as one
# where those Criticals were actually re-confirmed. Signature takes the
# scored findings list, not counts - confidence isn't visible at the
# counts-dict level.
# ---------------------------------------------------------------------------

_RISK_SEVERITY_WEIGHT = {'Critical': 25, 'High': 10, 'Medium': 2, 'Low': 0.5}
_RISK_CONFIDENCE_MULTIPLIER = {'confirmed': 1.0, 'probable': 0.75, 'unverified': 0.5}


def compute_risk_score(findings: list) -> int:
    raw = 0.0
    for f in findings:
        weight = _RISK_SEVERITY_WEIGHT.get(f.get('severity', 'Informational'), 0)
        if not weight:
            continue
        multiplier = _RISK_CONFIDENCE_MULTIPLIER.get(f.get('confidence', 'probable'), 0.75)
        raw += weight * multiplier
    return int(min(100, raw))
