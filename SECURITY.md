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

## Authorized use only

This tool is built to scan only targets the operator is explicitly authorized
to test - see the "Authorized use only" section in `README.md`. Reports of
"this tool can be used to scan unauthorized targets" are not considered
vulnerabilities in the tool itself; the authorization checkbox and audit
logging are the intended controls.
