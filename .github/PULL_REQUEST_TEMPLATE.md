## What changed and why



## Impacted area(s)

<!-- Helps a solo maintainer triage fast. Delete what doesn't apply. -->
Scanning module(s): <!-- recon / webscan / ssl_tls / headers / owasp / tech_fingerprint / nuclei / enumeration / none -->
Other: <!-- aggregator / cvss_scorer / verifier / ollama_client / reports / api / frontend / docs / ci -->

## Checklist

- [ ] `pytest backend/tests` passes locally
- [ ] Finding schema / safety guardrails (see `CONTRIBUTING.md`) are intact
- [ ] No new external API calls or dependencies added without discussion
- [ ] Docs/comments updated if behavior or config changed
