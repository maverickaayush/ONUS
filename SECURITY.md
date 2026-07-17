# Security Policy

This is a security assessment tool, so its own security matters more than
most projects'.

## Reporting a vulnerability

Please report security issues privately via GitHub's "Report a vulnerability"
button under this repo's Security tab, rather than opening a public issue.
Include steps to reproduce and, if relevant, which scanning module or API
endpoint is affected.

## Scope

In scope: the FastAPI backend, Celery tasks, the aggregation/scoring/report
pipeline, and the Next.js frontend. Vulnerabilities in third-party tools this
project wraps (nmap, ZAP, Nikto, Nuclei, etc.) should be reported upstream to
those projects instead.

## LLM prompt injection

The optional AI step only ever writes prose. Severity, CVSS score, priority, and
OWASP category are all fixed by the deterministic scorer (`analysis/cvss_scorer.py`)
*before* any finding reaches the LLM, so adversarial content in a scanned target
cannot change what gets reported or how severe it is rated — the worst-case
"a malicious target talks its way out of a real finding" is structurally closed
off. The residual, lower risk is that untrusted content reflected into a finding's
evidence field could influence the model's *description/remediation wording*. This
is bounded (prose only, never numbers or classification) and acceptable given the
architecture; it is called out here so the boundary is explicit rather than implied.

## Authorized use only

This tool is built to scan only targets the operator is explicitly authorized
to test - see the "Authorized use only" section in `README.md`. Reports of
"this tool can be used to scan unauthorized targets" are not considered
vulnerabilities in the tool itself; the authorization checkbox and audit
logging are the intended controls.
