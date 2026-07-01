import json
import logging

import requests

from config import settings

logger = logging.getLogger(__name__)

# Section 4.5 - byte-for-byte. Do NOT paraphrase or reorder.
_SYSTEM_PROMPT = (
    "You are a professional cybersecurity analyst. You will be given raw vulnerability\n"
    "findings from an automated VAPT scan in JSON format. Your task is to analyze\n"
    "these findings and return ONLY valid JSON with no markdown, no explanation,\n"
    "and no text outside the JSON object.\n"
    "\n"
    "For each finding, provide:\n"
    "- title: concise vulnerability name\n"
    "- description: what this vulnerability is and why it matters\n"
    "- severity: one of Critical / High / Medium / Low / Informational\n"
    "- cvss_score: CVSS v3.1 base score (0.0-10.0)\n"
    "- cvss_vector: CVSS v3.1 vector string\n"
    "- owasp_category: OWASP Top 10 2021 category if applicable\n"
    "- cve_reference: most relevant CVE if known, else null\n"
    "- evidence: the most significant evidence snippet\n"
    "- remediation: specific, actionable remediation steps\n"
    "- priority: 1 (fix immediately) to 5 (fix when convenient)\n"
    "\n"
    "Return: { executive_summary, risk_score (0-100), findings[], total_critical,\n"
    "total_high, total_medium, total_low, total_informational }"
)

_REQUIRED_KEYS = {'executive_summary', 'findings', 'risk_score'}

_SEVERITY_SCORES = {
    'Critical': 10.0, 'High': 7.5, 'Medium': 5.0,
    'Low': 2.5, 'Informational': 0.0, 'Info': 0.0,
}


def _backfill_module(ai_result: dict, aggregated: dict) -> dict:
    """
    Add the 'module' field to each AI-returned finding.

    Real bug, only surfaced once a genuine (non-fallback) Ollama response was
    obtained for the first time: the system prompt (the project docs Section 4.5,
    byte-for-byte, cannot be reworded) never asks the model for a 'module'
    field per finding, but schemas.FindingSchema requires one (and the
    frontend's findings table displays it). The rule-based fallback happened
    to work because it manually copies 'module' from the raw finding - the
    real AI path had no equivalent step. Match AI findings back to the input
    aggregated findings by title (the field most likely to survive the model's
    pass-through) and copy 'module' across; default to '' if no match is
    found rather than raising - this is enrichment, not validation.
    """
    title_to_module = {
        f.get('title', ''): f.get('module', '')
        for f in aggregated.get('findings', [])
        if f.get('title')
    }
    for finding in ai_result.get('findings', []):
        if not finding.get('module'):
            finding['module'] = title_to_module.get(finding.get('title', ''), '')
    return ai_result


def _strip_emdashes(obj):
    """
    Recursively replace em-dashes (U+2014) with hyphens in every string of a
    nested dict/list structure. Qwen 2.5 frequently emits em-dashes in the
    free-text fields it generates (executive_summary, description, remediation),
    which would otherwise reach the PDF and dashboard. Applied to whatever
    analyse() returns so the AI output is always em-dash free.
    """
    if isinstance(obj, str):
        return obj.replace('—', '-')
    if isinstance(obj, list):
        return [_strip_emdashes(x) for x in obj]
    if isinstance(obj, dict):
        return {k: _strip_emdashes(v) for k, v in obj.items()}
    return obj


def analyse(aggregated: dict, domain: str) -> dict:
    """
    Send aggregated findings to Ollama (Qwen 2.5 7B) for AI analysis.

    On timeout (120s) or invalid JSON, falls back to rule-based scoring so
    the pipeline never hard-fails here regardless of Ollama availability.

    Returns a dict matching the schema expected by the PDF generator and the
    /api/scan/{id}/findings endpoint.
    """
    try:
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
                {'role': 'user',
                 'content': f'Analyze these VAPT findings for {domain}: '
                            f'{json.dumps(aggregated)}'},
            ],
        }

        # Timeout raised from the project docs Section 4.5's stated 120s to 240s -
        # empirically measured: a real analysis call for a 23-finding scan
        # took 130.2s on the reference hardware (RTX 4060 Laptop, 8GB VRAM,
        # qwen2.5:7b Q4), so 120s was routinely triggering the rule-based
        # fallback instead of genuine AI analysis. 240s gives headroom for
        # run-to-run variance and larger finding sets. Same category of
        # deliberate, measured deviation as the nmap/webscan timing tuning
        # elsewhere in this build.
        resp = requests.post(
            f'{settings.OLLAMA_URL}/api/chat',
            json=payload,
            timeout=240,
        )
        resp.raise_for_status()

        content = resp.json()['message']['content']
        result = json.loads(content)

        missing = _REQUIRED_KEYS - set(result.keys())
        if missing:
            raise ValueError(f"Ollama response missing required keys: {missing}")

        logger.info("Ollama analysis complete for %s - risk_score=%s",
                    domain, result.get('risk_score'))
        result = _backfill_module(result, aggregated)
        return _strip_emdashes(result)

    except requests.exceptions.Timeout:
        logger.warning("Ollama timed out for %s - using rule-based fallback", domain)
    except requests.exceptions.ConnectionError:
        logger.warning("Ollama not reachable for %s - using rule-based fallback", domain)
    except (json.JSONDecodeError, KeyError, ValueError) as e:
        logger.warning("Ollama response invalid for %s (%s) - using fallback", domain, e)
    except Exception as e:
        logger.error("Ollama unexpected error for %s: %s - using fallback", domain, e)

    return _strip_emdashes(_rule_based_fallback(aggregated, domain))


def _rule_based_fallback(aggregated: dict, domain: str) -> dict:
    """
    Rule-based analysis used when Ollama is unavailable or returns bad output.
    Produces the same output shape as the Ollama response so the rest of the
    pipeline (PDF generator, findings endpoint) works identically either way.
    """
    findings = aggregated.get('findings', [])

    counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Informational': 0}
    enriched = []

    for f in findings:
        raw_sev = f.get('severity', 'Informational')
        sev = raw_sev if raw_sev in counts else 'Informational'
        counts[sev] += 1

        cvss = _SEVERITY_SCORES.get(sev, 0.0)
        priority = (1 if sev == 'Critical' else
                    2 if sev == 'High' else
                    3 if sev == 'Medium' else
                    4 if sev == 'Low' else 5)

        enriched.append({
            'title':          f.get('title', 'Unknown finding'),
            'description':    f.get('title', ''),
            'severity':       sev,
            'cvss_score':     cvss,
            'cvss_vector':    None,
            'owasp_category': f.get('owasp_category', ''),
            'cve_reference':  None,
            'evidence':       f.get('evidence', ''),
            'remediation':    'Review and remediate this finding per security best practices.',
            'priority':       priority,
            'module':         f.get('module', ''),
        })

    # Risk score: weighted sum capped at 100
    raw_score = (counts['Critical'] * 10 + counts['High'] * 7 +
                 counts['Medium'] * 4 + counts['Low'] * 1)
    risk_score = min(100, raw_score)

    top_issues = [f['title'] for f in enriched
                  if f['severity'] in ('Critical', 'High')][:3]
    summary_parts = [f'Automated VAPT scan of {domain} identified '
                     f'{len(findings)} findings.']
    if top_issues:
        summary_parts.append(f'Top issues: {", ".join(top_issues)}.')
    summary_parts.append('(AI analysis unavailable - rule-based scoring applied.)')

    return {
        'executive_summary':   ' '.join(summary_parts),
        'risk_score':          risk_score,
        'findings':            enriched,
        'total_critical':      counts['Critical'],
        'total_high':          counts['High'],
        'total_medium':        counts['Medium'],
        'total_low':           counts['Low'],
        'total_informational': counts['Informational'],
    }
