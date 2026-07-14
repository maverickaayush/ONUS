# Architecture & Contributor Reference

This is the detailed technical reference for the VAPT Tool: architecture,
schemas, and the invariants a change should never break. `README.md` covers
installation and quick start; `docs/QUICK_REF.md` is a shorter cheat sheet
for common changes; the other files under `docs/` cover specific reasoning
(scanner timing, AI tuning, Docker setup) in more depth. This file is the
one place all of that ties together.

---

## What This Tool Does

An automated Vulnerability Assessment and Penetration Testing (VAPT)
platform: locally hosted and air-gapped. It accepts a target domain, runs 8
scanning modules in parallel via Celery, sends aggregated findings to a
local LLM (Ollama + Qwen 2.5 7B) for descriptive analysis, and produces a
PDF report plus a live web dashboard.

**Design principles:** air-gapped/local (no external API calls, no data
leaves the network) - parallel execution (Celery, not sequential) -
AI-enhanced analysis over raw tool dumps - zero operational cost (all
open-source) - authorized-only (explicit confirmation required before any
scan).

**Scope:** network recon (ports/services/subdomains/DNS/WHOIS) - web app
scanning (ZAP + Nikto) - SSL/TLS config - HTTP security headers - OWASP Top
10 checks - tech fingerprinting/WAF detection - CVE scanning (Nuclei) -
directory enumeration (FFUF).

---

## System Architecture

Six-layer pipeline:

| Layer | Component | Responsibility |
|---|---|---|
| 1 - Input | Next.js Frontend | Domain entry form, authorization checkbox, live scan status |
| 2 - Backend | FastAPI + PostgreSQL | Request validation, job creation, status API, report delivery |
| 3 - Queue | Celery + Redis | Async dispatch, parallel worker orchestration, task state |
| 4 - Scanning | 8 Python modules | Execute external tools, normalize output to shared JSON schema |
| 5 - Intelligence | Ollama + Qwen 2.5 7B | CVSS scoring, risk ranking, remediation generation |
| 6 - Output | WeasyPrint + Next.js | PDF report, interactive vulnerability dashboard |

**Data flow:** domain submitted (authorized-scope confirmed) -> FastAPI
validates + creates a `Scan` row (`queued`) -> job pushed to Redis -> Celery
dispatches 8 parallel subtasks (group) -> each normalizes findings via
`subprocess` -> chord callback checks for any failed/timed-out module and,
if found, pauses at `awaiting_user_decision` for an operator retry/continue/
cancel choice instead of proceeding -> aggregates/dedupes/sorts ->
confidence verification (passive re-observation) -> deterministic CVSS
scoring -> Ollama analysis (description/remediation prose) -> WeasyPrint
renders PDF, `Scan.status = complete` -> frontend polls and displays
dashboard.

---

## Technology Stack

| Category | Technology | Purpose |
|---|---|---|
| Backend API | FastAPI 0.111+ | REST API, async, OpenAPI docs |
| Task Queue | Celery 5.3+ | Parallel scan execution |
| Broker | Redis 7.2+ | Celery broker + result backend |
| Database | PostgreSQL 16+ | Scan records, reports |
| ORM | SQLAlchemy + Alembic 2.0+ | Models, migrations |
| Recon | nmap, subfinder, Amass v4.2.0, Naabu v2.3.3, httpx v1.6.9 | Ports, services, subdomains, DNS, live-host probing |
| Web Scanner | OWASP ZAP, Nikto, Katana v1.1.2 | Active vuln scanning, JS-aware crawling |
| SSL Scanner | testssl.sh, sslscan | TLS config, cert analysis |
| CVE Scanner | Nuclei | Template-based CVE scanning |
| Tech Fingerprint | WhatWeb, WAFW00F | CMS/framework detection, WAF presence |
| Directory Enum | FFUF | Path/file brute-forcing |
| Confidence Verification | Playwright + headless Chromium | Browser-based reflected-XSS re-verification |
| AI Engine | Ollama + Qwen 2.5 7B | Local LLM, descriptive analysis + remediation |
| PDF | WeasyPrint 60+, Jinja2 3.1+ | HTML-to-PDF report rendering |
| Frontend | Next.js 16 App Router, TypeScript, Tailwind v4, Recharts | Dashboard |
| Containerization | Docker + Compose | Deployment |
| Language | Python 3.11+ | Backend |

**Hardware:** GPU >=8GB VRAM recommended for Ollama (Qwen 2.5 7B Q4_K_M
uses roughly 4.5GB VRAM).

---

## Project File Structure

```
vapt-tool/
├── backend/
│   ├── main.py                  # FastAPI app entry point
│   ├── config.py                # Environment config (DB URL, Redis, Ollama, ZAP_URL)
│   ├── models.py                # SQLAlchemy ORM models
│   ├── schemas.py                # Pydantic request/response schemas
│   ├── database.py               # DB session and engine setup
│   ├── routers/
│   │   ├── scan.py               # POST /api/scan, GET /api/scan/{id}/status, /findings
│   │   └── report.py             # GET /api/scan/{id}/report (PDF download)
│   ├── tasks/
│   │   ├── celery_app.py         # Celery app configuration
│   │   ├── base_task.py          # Shared helpers (status updates, normalize_finding)
│   │   ├── scan_orchestrator.py  # Main Celery task: dispatches all 8 subtasks (group/chord)
│   │   ├── recon.py              # nmap + subfinder + Amass + httpx + Naabu + WHOIS + DNS
│   │   ├── webscan.py            # ZAP + Nikto + Katana (parallel via ThreadPoolExecutor)
│   │   ├── ssl_tls.py             # testssl.sh + sslscan
│   │   ├── headers.py            # HTTP security headers (pure Python)
│   │   ├── owasp.py              # SQLi, XSS, IDOR, traversal, open redirect, error disclosure
│   │   ├── tech_fingerprint.py    # WhatWeb + WAFW00F
│   │   ├── nuclei_scan.py        # Nuclei CVE templates
│   │   └── enumeration.py        # FFUF directory brute-forcing
│   ├── analysis/
│   │   ├── aggregator.py         # Merges + deduplicates + collapses 8 module outputs
│   │   ├── verifier.py           # Confidence verification - passive re-observation only
│   │   ├── cvss_scorer.py        # Deterministic severity/CVSS/priority/risk_score (CVSS v3.1)
│   │   └── ollama_client.py      # Ollama description/remediation prose + fallback
│   ├── reports/
│   │   ├── generator.py          # WeasyPrint PDF generation
│   │   └── templates/report.html # Jinja2 PDF template
│   ├── subfinder-config/         # provider-config.yaml (gitignored) + .example
│   └── requirements.txt
├── frontend/                     # Next.js 16 App Router ("Command Center" UI)
│   ├── app/                      # layout.tsx, page.tsx, globals.css
│   ├── components/               # app-shell, new-scan, scan-status, decision-modal, report-dashboard, scans-list, command-palette, ambient-background, ui
│   └── lib/                      # api.ts (typed fetch helpers), format.ts
├── migrations/                   # Alembic - repo-root sibling of backend/, not inside it
├── docker-compose.yml
├── alembic.ini
└── README.md
```

---

## Component Contracts

### Backend API

| Method | Endpoint | Description | Response |
|---|---|---|---|
| POST | `/api/scan` | Validate, create DB record, enqueue Celery task | `{ job_id, status: 'queued' }` |
| GET | `/api/scan/modules` | Canonical module list (id/label/icon_hint/description) | `{ modules: [...] }` |
| GET | `/api/scans` | Paginated scan discovery/listing | `{ scans: [...], counts: {...}, total, page, page_size, total_pages }` |
| GET | `/api/scan/{id}/status` | Module statuses + completion % | `{ status, modules, progress, module_errors?, can_retry? }` |
| POST | `/api/scan/{id}/decision` | Operator's retry/continue/cancel choice while `status == awaiting_user_decision` | `{ action: 'retry'\|'continue'\|'cancel' }` |
| GET | `/api/scan/{id}/report` | Download PDF | `application/pdf`; 404 if none yet, 202 `{status:"pending"}` if still generating |
| GET | `/api/scan/{id}/findings` | Structured findings for dashboard | `{ findings[], summary }` |
| GET | `/api/health` | Healthcheck | `{ status: 'ok' }` |

**Validation before dispatching any scan:** domain format via `validators`
(rejects IP ranges, `localhost`, internal hostnames); `authorized: true`
required else HTTP 403; duplicate active scan for same domain within 10 min
returns the existing job_id instead of starting a new one.

**Canonical module list** lives in `backend/tasks/base_task.py`'s
`SCAN_MODULES` (a list of `{id, label, icon_hint, description}` dicts,
`SCAN_MODULE_IDS` derived from it) - the single source of truth for "what
modules exist." Everything else (scan orchestrator's status init, the
`/api/scan/modules` endpoint, the frontend's module list) derives from it
rather than hardcoding its own copy. To register a 9th module: add one
entry to `SCAN_MODULES` and nothing else needs to change.

### Redis + Celery

```
CELERY_BROKER_URL / CELERY_RESULT_BACKEND = 'redis://...' (from config.py, never hardcoded)
CELERY_TASK_SERIALIZER = 'json'
CELERY_WORKER_CONCURRENCY = 5
```

`scan_orchestrator.py` dispatches a Celery **group** of all 8 scanning
subtasks, gated by a **chord** callback (`aggregate_and_analyse`) that fires
once all 8 complete - triggers aggregation -> Ollama -> PDF generation.

### Operator Decision Flow - pause / retry / continue / cancel

When the chord callback sees any module report `failed`/`timeout`, it does
**not** proceed to aggregation - it stashes the raw module envelopes + per-
module retry counts and sets `scan.status = awaiting_user_decision`. The
next status poll returns `module_errors` and `can_retry`, driving the
frontend's decision modal.

`POST /api/scan/{id}/decision` dispatches the choice as a Celery task:

- **retry** -> re-dispatches only the still-failed modules. `MAX_RETRIES_PER_MODULE = 1`, tracked per module - a module that fails again after its one retry blocks Retry for that scan entirely (forces Continue or Cancel).
- **continue** -> finalizes with whatever module results were already stashed. Failed modules stay `failed` (never silently marked success).
- **cancel** -> sets `scan.status = cancelled` directly, no further processing.

### Scanning Engine - the pipeline's one contract

8 independent Celery tasks, each wrapping external tools via `subprocess`
with a controlled timeout. **Every finding must match this exact schema:**

```json
{
  "module": "recon", "tool": "nmap", "type": "open_port",
  "title": "Port 22 (SSH) open", "evidence": "22/tcp open ssh",
  "severity": "Info", "cvss": 0.0, "target": "example.com",
  "found_by": ["recon"],
  "confidence": "probable", "verifiable": false, "verification_target": null
}
```

- `severity`/`cvss` set here are placeholders - `analysis/cvss_scorer.py`
  deterministically overwrites `severity`/`cvss_score`/`cvss_vector`/
  `priority`/`owasp_category` during aggregation.
- `found_by` starts as `[module_name]`; the aggregator extends it (e.g.
  `["recon","webscan"]`) when multiple modules find the same thing.
- `confidence`/`verifiable`/`verification_target` default to
  `'probable'`/`False`/`None`. A module sets `confidence='confirmed'`
  directly only when it already has definitive proof with no re-check
  needed. A module sets `verifiable=True` + `verification_target={...}`
  when the finding type has a verifier in `analysis/verifier.py`.

Each scanning task's outer function returns an envelope (not a bare finding
list) via `tasks/base_task.py`'s `build_module_result()`:

```json
{
  "module": "recon", "status": "success", "findings": [ /* schema above */ ],
  "tool_versions": {"nmap": "7.94", "subfinder": "2.6.3"},
  "finding_count": 12, "duration_seconds": 45.2, "error": null
}
```

`status` is `success` | `failed` | `timeout` | `partial`.

| # | Module | File | Tools | Finds |
|---|---|---|---|---|
| 1 | Recon | `recon.py` | nmap (two-phase), subfinder, Amass, httpx, Naabu, whois, dnspython | Ports/services, subdomains, live-host tech, WHOIS, DNS/SPF/DMARC/DKIM |
| 2 | Web Scan | `webscan.py` | ZAP (daemon, primary), Nikto, Katana | XSS/SQLi/CSRF/broken auth, misconfigs, JS-aware endpoints |
| 3 | SSL/TLS | `ssl_tls.py` | testssl.sh, sslscan | Protocol/cipher issues, cert validity, HSTS |
| 4 | Headers | `headers.py` | pure `requests`, no external tool | CSP/HSTS/X-Frame-Options/CORS/cookie flags |
| 5 | OWASP Top 10 | `owasp.py` | `requests`, 5 read-only test functions | SQLi, XSS, IDOR, path traversal, open redirect, error disclosure |
| 6 | Tech Fingerprint | `tech_fingerprint.py` | WhatWeb, WAFW00F | CMS/framework/server detection, WAF presence, outdated-tech flags |
| 7 | Nuclei CVE | `nuclei_scan.py` | Nuclei (curated template subset) | Known CVEs, misconfigs, exposed panels |
| 8 | Dir Enum | `enumeration.py` | FFUF, baseline calibration | Exposed files (`.env`, `.git/config`), admin panels, auth-gated paths |

Every module's internal tool timeout and every Celery soft/hard limit is a
*base value* multiplied by `config.SCAN_TIMEOUT_MULTIPLIER` (default 1.5)
via `tasks/base_task.py`'s `scaled_timeout()` helper - real-world targets
are slower than lab targets, so this scales every budget uniformly instead
of hand-editing each module.

### Results Aggregator (`backend/analysis/aggregator.py`)

Triggered once all 8 tasks complete:

1. Flatten every module's findings, roll up tool_versions and execution
   status - even for modules that found nothing (a clean result and a
   silently-failed module must not render identically absent).
2. Dedupe on `(type, evidence[:100])`, merging `found_by` lists.
3. **Response-fingerprint collapse:** group findings by `(type, http_status,
   size_bucket)`; groups of >5 collapse into a single finding (a WAF/
   catch-all deny page hit by every wordlist entry doesn't become
   thousands of "findings").
4. Enrich with OWASP Top 10 category mapping.
5. Sort by severity, assign a stable `finding_id` to every finding.
6. Return `{ findings[], total, scan_metadata, module_execution[] }`.

### Confidence Verification (`backend/analysis/verifier.py`)

Runs between aggregation and CVSS scoring. **Hard constraint: passive
re-observation only.** Every verifier re-issues the exact same non-
destructive, read-only payload the originating module already sent once,
and checks whether the same evidence still reproduces - never a new
exploitation technique.

Three confidence tiers: `confirmed` (re-verified proof), `probable`
(default, not yet re-checked), `unverified` (a verifier ran and failed to
reproduce the finding - demoted with a `verification_note`, **never
dropped** from the findings list).

### Deterministic CVSS Scoring (`backend/analysis/cvss_scorer.py`)

The single source of truth for every number in a report.
`score_finding(finding) -> {cvss_score, cvss_vector, severity, priority,
owasp_category}`, called on every finding during aggregation, overwriting
whatever placeholder the scanning module set.

- Implements the official CVSS v3.1 base score formula from scratch - never
  a hardcoded score-to-vector lookup.
- A rule catalogue maps finding `type` to a CVSS v3.1 vector, reasoned
  metric-by-metric per type.
- `compute_risk_score(findings)`: per finding, `severity_weight x
  confidence_multiplier`, summed and capped at 100 - deliberately
  non-linear on the low end so a flood of Mediums (or unverified
  Criticals) can't alone drive the score to 100.

### Ollama AI Analysis (`backend/analysis/ollama_client.py`)

Local Ollama, Qwen 2.5 7B Instruct. **Descriptive-only** - Ollama receives
already-scored findings and produces prose, never numbers.

System prompt:
```
You are a security writer explaining vulnerability findings to a non-technical
audience. You will receive a JSON list of vulnerability findings that have
already been scored and categorized by a separate system. Your ONLY job is to
produce plain-English descriptions and actionable remediation steps.

For each finding, produce:
- description: 2 to 3 sentences explaining what this vulnerability is in plain
  English, as if explaining to a project manager. Avoid jargon; when a
  technical term is unavoidable, briefly explain it in the same sentence. Do
  NOT mention CVSS scores, severity levels, priority numbers, or any numeric
  ratings. Those are handled elsewhere.
- remediation: 3 to 5 concrete steps a developer should take to fix this.
  Technical language is fine here; the audience is a developer.

Also produce:
- executive_summary: 3 to 4 sentences overviewing the scan results in plain
  English, suitable for a non-technical stakeholder. Mention the target, the
  general categories of issues found, and the overall security posture in
  qualitative terms. Do NOT invent numbers, counts, or percentages.

Return valid JSON only, no markdown, no explanation outside the JSON:
{
  "executive_summary": "...",
  "findings": [
    { "finding_id": "...", "description": "...", "remediation": "..." },
    ...
  ]
}
```

Finding types the deterministic scorer already recognizes (~80 types, the
`_TYPE_REMEDIATION` catalogue) get a fixed, hand-written description and
remediation and are excluded from the Ollama batch entirely - guaranteed
concrete text every time, not a maybe depending on priority ranking. Of the
remaining findings, only the top 50 by priority are sent to Ollama. Invalid
JSON gets up to 2 retries; timeout/connection errors, and any exhausted
retry, fail straight to a deterministic per-category fallback (the same one
a beyond-cutoff finding already gets on the happy path - no hardcoded
placeholder text), flagged with `ai_unavailable: True` so fallback output is
never mistaken for real analysis.

A single Ollama request batching up to 50 findings can occasionally exhaust
the fixed `num_predict: 4096` output-token budget before finishing valid
JSON for the last few items - not a context-window problem (input stays
well under `num_ctx: 8192`), just a fixed output ceiling. Handled by the
existing retry/fallback with no data loss.

### Report Generation (`backend/reports/generator.py`)

Jinja2 -> `weasyprint.HTML(string=html).write_pdf()` (inline CSS only, no
external deps - renders identically offline). Stored as `BYTEA` in
`reports.pdf_data`.

Sections: cover - severity breakdown - executive summary (Ollama prose +
deterministic confidence-breakdown sentence) - findings catalogue grouped
by confidence tier, sorted by priority/CVSS - technical appendix (scan
config, verification evidence, tool versions, module execution status).

### Frontend (`frontend/`)

Next.js 16 App Router, a dark "Command Center" interface communicating with
the FastAPI backend via `lib/api.ts` (native `fetch`). Four views: New Scan
(domain entry, authorization checkbox), Scan Status (live module progress,
decision modal), Report (risk gauge, severity chart, findings catalogue, PDF
download), and the Scans discovery dashboard (tracking many scans at once).

---

## Data Schemas

**POST `/api/scan`:**
```json
{ "domain": "example.com", "authorized": true, "notes": "Optional scope notes" }
```

**GET `/api/scan/{id}/status`:**
```json
{
  "job_id": "uuid", "domain": "example.com", "status": "running", "progress": 60,
  "started_at": "ISO8601",
  "modules": { "recon": "complete", "webscan": "running", "ssl_tls": "complete", "headers": "complete", "owasp": "queued" }
}
```

**GET `/api/scan/{id}/findings`:**
```json
{
  "executive_summary": "string", "risk_score": 72,
  "total_critical": 2, "total_high": 5, "total_medium": 8, "total_low": 4, "total_informational": 11,
  "findings": [
    {
      "title": "TLS 1.0 Enabled", "severity": "High", "cvss_score": 7.4,
      "cvss_vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
      "owasp_category": "A02:2021 - Cryptographic Failures", "cve_reference": "CVE-2014-3566",
      "evidence": "TLS 1.0 accepted on port 443",
      "description": "The server accepts an outdated encryption protocol that no longer protects data in transit.",
      "remediation": "Disable TLS 1.0 and 1.1 in server config.",
      "priority": 2, "module": "ssl_tls",
      "confidence": "probable", "verification_note": null
    }
  ]
}
```
`confidence` (`"confirmed"|"probable"|"unverified"`) and `verification_note` (string, only non-null on findings a verifier actually re-checked) are additive/optional - see the "Confidence Verification" section above for full semantics.

---

## Database Schema (PostgreSQL)

| Table | Column | Type | Description |
|---|---|---|---|
| scans | id | UUID (PK) | Unique scan job identifier |
| scans | domain | VARCHAR(255) | Target domain submitted |
| scans | status | ENUM | queued / running / analysing / awaiting_user_decision / complete / failed / cancelled |
| scans | authorized | BOOLEAN | Authorization confirmation flag |
| scans | started_at / completed_at | TIMESTAMP | Job pickup / AI analysis finish |
| scans | module_statuses | JSONB | Per-module status map |
| scans | raw_findings | JSONB | Aggregated findings before AI analysis |
| scans | ai_analysis | JSONB | Full scored+described analysis - **never** put PDF bytes here |
| scans | risk_score | INTEGER | Overall risk score 0-100 |
| scans | updated_at | TIMESTAMP | Bumped on ORM-level writes (status transitions, etc.) |
| reports | id | UUID (PK) | Report identifier |
| reports | scan_id | UUID (FK) | References `scans.id` |
| reports | pdf_data | BYTEA | PDF binary content - this is where PDF bytes go |
| reports | generated_at | TIMESTAMP | PDF generation timestamp |

---

## Docker Architecture

Six services: PostgreSQL, Redis, OWASP ZAP sidecar, FastAPI backend, Celery
worker, Next.js frontend (standalone, no Nginx). **Ollama runs natively on
the host**, not in Docker - reached via `host.docker.internal:11434`
(requires `OLLAMA_HOST=0.0.0.0:11434` on the host, see `README.md`).

Twelve additional intentionally-vulnerable practice-target services are
gated behind Compose's `targets` profile so a plain `docker compose up -d`
never builds/starts them by default - see `README.md`'s "Optional: practice
targets" section.

Key facts, easy to accidentally regress:

- Backend/worker build `context: .` (repo root) - `alembic.ini`/`migrations/`
  are root siblings of `backend/`.
- `backend/Dockerfile` pins `python:3.11-slim-bookworm`; installs `nikto`
  from source; needs `libpango-1.0-0`/`libpangoft2-1.0-0` for WeasyPrint;
  the `httpx` CLI binary must install **after** `pip install` or pip's
  Python-`httpx` shim wins the name collision.
- ZAP runs as a shared sidecar (`http://zap:8090`); isolation is
  `zap.core.new_session(name=scan_id)`.
- Frontend's `NEXT_INTERNAL_API_URL` must be a Docker build **ARG**, not a
  runtime env var - Next.js rewrites are baked in at build time.
- Naabu SYN scanning needs `CAP_NET_RAW` - Docker grants it by default.

---

## Security & Ethical Guardrails (non-negotiable)

- **Authorization** - every scan requires `authorized: true`; every
  authorization is logged with a timestamp.
- **Network isolation** - rejects RFC 1918 private ranges and `localhost`.
- **Non-destructive testing** - active tests use read-only payloads only.
  No writes, no data modification, no DoS payloads, ever.
- **Proof-of-concept only** - the tool confirms a vulnerability *exists*
  via non-destructive proof-of-concept only; it never performs data
  extraction, privilege escalation, or service exploitation, even when
  technically reachable. This is why the CVE scanner runs HTTP-protocol
  templates only, never exploit templates that complete a handshake.
- **Audit trail** - every scan (target, timestamp, operator) is permanently
  logged.
- **Rate limiting** - `config.MAX_CONCURRENT_SCANS` (default 5) concurrent
  scans across active statuses, enforced at scan creation.
- **Data privacy** - zero external API calls; all analysis stays local.

Authorized assessments only - unauthorized scanning is illegal under most
jurisdictions' computer-crime statutes. When in doubt about a feature
request, default to the more conservative, more clearly-authorized-only
behavior.

**Target scope - what's actually enforced in code:** `schemas.py`'s
`ScanRequest.validate_domain()` rejects `localhost`/`.localhost`, RFC 1918/
loopback/link-local IP literals, and malformed input; anything else is
accepted once `authorized: true` is set. There is no code-level allowlist
of specific target domains - that's a deliberate choice matching the
`authorized` checkbox + audit log model: a real deployment points this tool
at whatever domain the operator has actually been authorized to test.

Self-hostable practice apps this repo bundles or has been validated against
during development: OWASP Juice Shop, DVWA, bWAPP, Mutillidae II, NodeGoat,
WebGoat, Metasploitable2, DVWP (Damn Vulnerable WordPress behind a
ModSecurity WAF). These are self-hosted, deliberately-vulnerable practice
apps run by the operator themselves - no third-party terms of service is in
play, unlike scanning a live internet target.

**Before pointing this at any third-party "practice" site** (CTF platforms,
"hack me" services, etc.), check that site's current terms of service -
several well-known ones explicitly prohibit or rate-limit automated
scanning even for "ethical hacking practice." Never scan anything without
prior written authorization.

---

## Common Pitfalls

- Hardcoding `localhost:6379`/`localhost:11434` instead of using
  `config.REDIS_URL`/`config.OLLAMA_URL`.
- Running nmap/ZAP/Nuclei etc. in the main FastAPI process - heavy tools
  always run inside Celery tasks with timeouts.
- Letting the ZAP daemon linger - kill it in a `finally:` block, not just
  the happy path.
- Using `verify=True` for HTTPS requests against test targets with
  self-signed certs - use `verify=False` + `urllib3.disable_warnings()` as
  a scanner-design choice, not a security one.
- Omitting `found_by` from module output - breaks the aggregator's dedup
  silently.
- Storing PDF bytes in `scans.ai_analysis` JSONB - PDF data goes in
  `reports.pdf_data` (BYTEA).
- Skipping temp-file cleanup in `/tmp/{tool}_{scan_id}.*` - clean up in a
  `finally:` block.
- Calling `ollama_client.analyse()` before aggregation or before
  `cvss_scorer.score_finding()` has run - it must receive deduplicated,
  already-scored findings, not raw per-module output.
- Adding a new finding type without a `cvss_scorer.py` rule - unmatched
  types silently fall back to a generic band vector, which is safe but
  usually not the intended CVSS reasoning for a new check.
- Dropping a finding when its verifier fails to reproduce it - demote to
  `confidence='unverified'` with a `verification_note` instead.
- Calling `compute_risk_score()` with a severity-counts dict - it takes the
  scored findings list, since confidence isn't visible at the counts level.

---

## Further Reading

| Doc | When to read |
|---|---|
| [`docs/QUICK_REF.md`](docs/QUICK_REF.md) | Run commands, folder responsibilities, "where do I make this change" |
| [`docs/scanners.md`](docs/scanners.md) | Full reasoning behind nmap two-phase scan, per-module timeout budgets, subfinder API keys, webscan/ZAP timing, enumeration's baseline-probe calibration |
| [`docs/ai.md`](docs/ai.md) | Why the Ollama timeout is 240s, chord-callback timeout consequence, why scoring moved off Ollama entirely |
| [`docs/docker.md`](docs/docker.md) | Full Docker deviation notes and build gotchas |
| [`docs/troubleshooting.md`](docs/troubleshooting.md) | How to manually test any module/stage in isolation |
| [`docs/roadmap.md`](docs/roadmap.md) | Historical build sequence |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Dev setup, tests, PR expectations |
