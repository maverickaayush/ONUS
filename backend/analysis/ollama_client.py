import json
import logging
from typing import Dict, List, Optional, Tuple

import requests

from config import settings

logger = logging.getLogger(__name__)

# Descriptive-only prompt (verbatim, do not paraphrase or reorder). Ollama no
# longer produces severity/cvss/priority/risk_score - those are computed
# deterministically by analysis/cvss_scorer.py before this module ever runs.
_SYSTEM_PROMPT = (
    "You are a security writer explaining vulnerability findings to a non-technical\n"
    "audience. You will receive a JSON list of vulnerability findings that have\n"
    "already been scored and categorized by a separate system. Your ONLY job is to\n"
    "produce plain-English descriptions and actionable remediation steps.\n"
    "\n"
    "For each finding, produce:\n"
    "- description: 2 to 3 sentences explaining what this vulnerability is in plain\n"
    "  English, as if explaining to a project manager. Avoid jargon; when a\n"
    "  technical term is unavoidable, briefly explain it in the same sentence. Do\n"
    "  NOT mention CVSS scores, severity levels, priority numbers, or any numeric\n"
    "  ratings. Those are handled elsewhere.\n"
    "- remediation: 3 to 5 concrete steps a developer should take to fix this.\n"
    "  Technical language is fine here; the audience is a developer.\n"
    "\n"
    "Also produce:\n"
    "- executive_summary: 3 to 4 sentences overviewing the scan results in plain\n"
    "  English, suitable for a non-technical stakeholder. Mention the target, the\n"
    "  general categories of issues found, and the overall security posture in\n"
    "  qualitative terms. Do NOT invent numbers, counts, or percentages.\n"
    "\n"
    "Return valid JSON only, no markdown, no explanation outside the JSON:\n"
    "{\n"
    '  "executive_summary": "...",\n'
    '  "findings": [\n'
    '    { "finding_id": "...", "description": "...", "remediation": "..." },\n'
    "    ...\n"
    "  ]\n"
    "}"
)

_REQUIRED_KEYS = {'executive_summary', 'findings'}
_MAX_SENT_TO_AI = 50
_JSON_RETRY_ATTEMPTS = 3  # 1 initial attempt + 2 retries, per spec
_OLLAMA_TIMEOUT = round(240 * settings.SCAN_TIMEOUT_MULTIPLIER)  # docs/ai.md baseline, scaled by SCAN_TIMEOUT_MULTIPLIER

# Generic per-category remediation, used whenever a finding doesn't have an
# AI-generated description: either Ollama failed outright (ai_unavailable),
# or the finding was beyond the top-50-by-priority cutoff sent to the model.
_GENERIC_REMEDIATION = {
    'A01:2021 - Broken Access Control': (
        'Review this endpoint or file for unintended public exposure.',
        'Restrict access via authentication/authorization checks, remove the '
        'resource from the web root if it should not be served, and audit '
        'related paths for the same misconfiguration.',
    ),
    'A02:2021 - Cryptographic Failures': (
        'This finding relates to weak or misconfigured transport encryption.',
        'Disable outdated protocol versions and weak cipher suites, renew or '
        'replace the certificate as needed, and re-scan with testssl.sh/sslscan '
        'to confirm the fix.',
    ),
    'A03:2021 - Injection': (
        'This finding indicates unsanitized input may reach a sensitive sink.',
        'Use parameterized queries/prepared statements, apply context-aware '
        'output encoding, and validate all user input server-side before use.',
    ),
    'A05:2021 - Security Misconfiguration': (
        'This finding reflects a configuration gap rather than a code defect.',
        'Apply the missing security header or configuration directive at the '
        'web server/application level, and add a regression test or config '
        'check so it does not silently regress.',
    ),
    'A06:2021 - Vulnerable and Outdated Components': (
        'This finding flags software running an outdated or end-of-life version.',
        'Upgrade the affected component to a supported version, subscribe to '
        'its security advisories, and track it in a dependency inventory.',
    ),
}
_DEFAULT_REMEDIATION = (
    'See the evidence above for details on this finding.',
    'Review this finding against current security best practices for its '
    'category and remediate accordingly.',
)

# Real bug found live (user-reported, against an approved real target -
# demo-target.example): the aggregator's response-fingerprint collapse (>5 paths
# sharing an identical HTTP status+size - typically a WAF/catch-all deny
# page hit by most of the enumeration wordlist) inherits its owasp_category
# from whichever individual finding happened to be the group's first member,
# so it fell into the generic per-category templates above - text written
# for a single distinct vulnerability at one endpoint ("review this endpoint
# for unintended exposure"), not for "N paths all got the same blanket deny
# response." That's actively misleading here: it reads like N separate
# findings needing individual remediation, when the real, useful takeaway is
# the opposite - the target uniformly rejected the probe, which is usually a
# sign the control is *working*, not N misconfigurations.
_COLLAPSE_DESCRIPTION = (
    'This is not {count} separate findings - it means {count} different '
    'probed paths all received the exact same HTTP response (status and '
    'size), which almost always indicates a single catch-all page (a WAF '
    'block page, a custom 404/403, or a login-wall redirect) rather than '
    '{count} distinct exposures. The full list of paths that hit this '
    'response is in the Technical Appendix.'
)
_COLLAPSE_REMEDIATION = (
    'No per-path action is needed for this entry specifically - it exists '
    'to show the enumeration scan was mostly answered by one blanket '
    'response, which is expected behind a WAF or a consistent 403/404 '
    'handler. Check the appendix\'s path list for anything unexpected '
    '(e.g. a sensitive filename that should return a different status), '
    'and confirm the blanket response itself does not leak information '
    '(verbose error pages, stack traces) beyond the status code.'
)


def _generic_remediation(finding: dict) -> Tuple[str, str]:
    matched_paths = (finding.get('details') or {}).get('matched_paths')
    if matched_paths:
        count = len(matched_paths)
        return (_COLLAPSE_DESCRIPTION.format(count=count), _COLLAPSE_REMEDIATION)
    category = finding.get('owasp_category', '')
    return _GENERIC_REMEDIATION.get(category, _DEFAULT_REMEDIATION)


def _strip_emdashes(obj):
    """
    Recursively replace em-dashes (U+2014) with hyphens in every string of a
    nested dict/list structure. Qwen 2.5 frequently emits em-dashes in the
    free-text fields it generates, which would otherwise reach the PDF and
    dashboard.
    """
    if isinstance(obj, str):
        return obj.replace('—', '-')
    if isinstance(obj, list):
        return [_strip_emdashes(x) for x in obj]
    if isinstance(obj, dict):
        return {k: _strip_emdashes(v) for k, v in obj.items()}
    return obj


def _shape_for_prompt(findings: List[dict]) -> List[dict]:
    return [
        {
            'finding_id': f.get('finding_id', ''),
            'title': f.get('title', ''),
            'evidence': str(f.get('evidence', ''))[:300],
            'owasp_category': f.get('owasp_category', ''),
            'severity_hint': str(f.get('severity', 'Informational')).lower(),
        }
        for f in findings
    ]


def _call_ollama(shaped: List[dict], overflow: int, domain: str) -> dict:
    """One HTTP round-trip to Ollama. Raises on any failure - callers handle
    retry/fallback. Returns the parsed {'executive_summary','findings'} dict."""
    note = ''
    if overflow:
        note = (
            f'NOTE: {overflow} additional lower-severity findings exist and '
            f'are grouped in the appendix; do not describe them individually. '
        )
    user_content = f'{note}Analyze these VAPT findings for {domain}: {json.dumps(shaped)}'

    payload = {
        'model': 'qwen2.5:7b',
        'format': 'json',
        'stream': False,
        'options': {
            'temperature': 0.1,
            'num_predict': 4096,
            'num_ctx': 8192,
        },
        'messages': [
            {'role': 'system', 'content': _SYSTEM_PROMPT},
            {'role': 'user', 'content': user_content},
        ],
    }

    resp = requests.post(
        f'{settings.OLLAMA_URL}/api/chat',
        json=payload,
        timeout=_OLLAMA_TIMEOUT,
    )
    resp.raise_for_status()

    content = resp.json()['message']['content']
    result = json.loads(content)

    missing = _REQUIRED_KEYS - set(result.keys())
    if missing:
        raise ValueError(f'Ollama response missing required keys: {missing}')
    if not isinstance(result.get('findings'), list):
        raise ValueError('Ollama response "findings" is not a list')

    return result


def analyse(findings: List[dict], domain: str) -> dict:
    """
    Generate plain-English description/remediation text for already-scored
    findings (severity/cvss/priority/owasp_category must already be set by
    analysis/cvss_scorer.py before this is called - this function never
    computes or overrides those).

    Sends only the top _MAX_SENT_TO_AI findings by priority to keep the
    prompt within Ollama's context window (the root cause of the original
    demo-target.example bug: 4658 findings blew past num_ctx=8192 and silently forced
    every scan onto the rule-based fallback).

    Returns:
        {
            'executive_summary': str,
            'descriptions': {finding_id: {'description': str, 'remediation': str}},
            'ai_unavailable': bool,
        }
    Never raises - on any failure, falls back to a deterministic per-category
    template so the pipeline never hard-fails here.
    """
    ordered = sorted(findings, key=lambda f: f.get('priority', 5))
    top = ordered[:_MAX_SENT_TO_AI]
    overflow = max(0, len(ordered) - _MAX_SENT_TO_AI)
    shaped = _shape_for_prompt(top)

    last_error: Optional[Exception] = None
    for attempt in range(1, _JSON_RETRY_ATTEMPTS + 1):
        try:
            result = _call_ollama(shaped, overflow, domain)
            descriptions = {
                f.get('finding_id', ''): {
                    'description': f.get('description', ''),
                    'remediation': f.get('remediation', ''),
                }
                for f in result['findings']
                if f.get('finding_id')
            }
            logger.info("Ollama description pass complete for %s - %d/%d findings described",
                        domain, len(descriptions), len(findings))
            return _strip_emdashes({
                'executive_summary': result.get('executive_summary', ''),
                'descriptions': descriptions,
                'ai_unavailable': False,
            })

        except requests.exceptions.Timeout:
            logger.warning("Ollama timed out for %s - using rule-based fallback", domain)
            break  # don't retry a slow/hung Ollama - fail straight to fallback
        except requests.exceptions.ConnectionError:
            logger.warning("Ollama not reachable for %s - using rule-based fallback", domain)
            break  # don't retry an unreachable Ollama
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            last_error = e
            logger.warning("Ollama response invalid for %s (attempt %d/%d): %s",
                            domain, attempt, _JSON_RETRY_ATTEMPTS, e)
            continue  # malformed JSON from a 7B model is often worth retrying
        except Exception as e:
            logger.error("Ollama unexpected error for %s: %s - using fallback", domain, e)
            break

    if last_error:
        logger.warning("Ollama gave up after %d attempts for %s - using rule-based fallback",
                        _JSON_RETRY_ATTEMPTS, domain)

    return _strip_emdashes(_rule_based_fallback(findings, domain))


def _rule_based_fallback(findings: List[dict], domain: str) -> dict:
    """
    Used when Ollama is unreachable, times out, or never returns valid JSON.
    Every finding gets a placeholder description (so nobody mistakes this for
    real AI analysis) and a generic per-category remediation template.
    """
    descriptions = {}
    for f in findings:
        fid = f.get('finding_id', '')
        if not fid:
            continue
        _, remediation = _generic_remediation(f)
        descriptions[fid] = {
            'description': 'AI-generated description unavailable | see remediation and evidence below.',
            'remediation': remediation,
        }

    counts: Dict[str, int] = {}
    for f in findings:
        sev = f.get('severity', 'Informational')
        counts[sev] = counts.get(sev, 0) + 1
    top_titles = [f.get('title', '') for f in findings if f.get('severity') == 'Critical'][:3]

    summary_parts = [f'Automated VAPT scan of {domain} identified {len(findings)} findings.']
    if top_titles:
        summary_parts.append(f'Top issues: {", ".join(top_titles)}.')
    summary_parts.append('(AI analysis unavailable - rule-based descriptions applied.)')

    return {
        'executive_summary': ' '.join(summary_parts),
        'descriptions': descriptions,
        'ai_unavailable': True,
    }
