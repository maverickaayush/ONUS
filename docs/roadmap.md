# Build Roadmap (historical — initial 9-step build complete, project still evolving)

This project's initial build ran 9 sequential steps over a 15-day sprint,
each done and verified end-to-end (real scan + real Ollama analysis +
`docker-compose up --build`). That initial sequence is complete, but the
project keeps evolving past it - this doc is kept for historical reference
only, not as a claim that development has stopped. Current architecture/
contracts live in [`docs/QUICK_REF.md`](QUICK_REF.md).

## 15-Day Timeline (reference pacing, not enforced)

| Day | Focus | Deliverable |
|---|---|---|
| 1 | Project setup | Docker Compose skeleton, FastAPI entry point, PostgreSQL models, Alembic migrations, `.env` config |
| 2 | Celery + Redis | Celery app config, scan orchestrator, group/chord pattern, status polling |
| 3 | Recon module | nmap wrapper, subfinder, WHOIS parser, DNS lookup, normalized output |
| 4 | Web scan module | ZAP daemon setup + client, Nikto subprocess, alert normalization |
| 5 | SSL/TLS module | testssl.sh integration, sslscan XML parser, cipher mapper |
| 6 | Headers module | Header fetcher, per-header policy checker, CORS/cookie checks |
| 7 | OWASP module | SQLi/XSS/IDOR/traversal/open-redirect testers |
| 8 | Aggregator | 5-module merger, dedup, OWASP mapper, severity pre-sort |
| 9 | Ollama AI layer | Client, prompt engineering, JSON parsing, CVSS extraction |
| 10 | PDF report | Jinja2 template, WeasyPrint integration, badges, storage |
| 11 | React frontend | Domain form, auth checkbox, API client, status polling |
| 12 | Dashboard UI | Recharts chart, vuln table, filter/sort, expandable cards |
| 13 | End-to-end test | Full scan against test target, bug fixes, edge cases |
| 14 | Docker + deployment | `docker-compose up`, hardening, healthchecks |
| 15 | Demo prep | README, demo flow, sample report, summary slide |

## Step 1 — Project Setup & FastAPI Skeleton
`backend/config.py` (Pydantic `BaseSettings`: `DATABASE_URL`, `REDIS_URL`,
`OLLAMA_URL`), `database.py` (engine/`SessionLocal`/`Base`/`get_db`),
`models.py` (`Scan`, `Report` ORM models), `schemas.py` (`ScanRequest`,
`ScanResponse`, `ScanStatus`, `FindingSchema`), `main.py` (FastAPI app, CORS
for `localhost:3000`), `routers/scan.py` + `routers/report.py`,
`requirements.txt`, `alembic.ini` + `migrations/env.py`.

## Step 2 — Celery Configuration & Scan Orchestrator
`tasks/celery_app.py` (Celery app `vapt`, Redis broker/backend, concurrency
5, soft/hard 300s/360s, autodiscover the 5 original task modules),
`tasks/scan_orchestrator.py` (group of subtasks → chord callback
`aggregate_and_analyse`), `tasks/base_task.py` (`update_module_status`,
`normalize_finding` — always sets `found_by=[module]`).

## Step 3 — Recon Module
`backend/tasks/recon.py`: nmap (two-phase, see `docs/scanners.md`),
subfinder, WHOIS (`python-whois`, expiry <90 days → Medium), DNS
(`dnspython`, missing SPF/DMARC/DKIM → Medium each). Full timing budget in
`docs/scanners.md`.

## Step 4 — Web Scan Module (ZAP + Nikto)
`backend/tasks/webscan.py`: ZAP daemon (spider → active scan → alerts →
kill), Nikto (`-Format json`). Full timing budget in `docs/scanners.md`.

## Step 5 — SSL/TLS, Headers, OWASP Modules
`ssl_tls.py` (testssl.sh + sslscan), `headers.py` (pure `requests`, no
external tool), `owasp.py` (5 non-destructive test functions: SQLi, XSS,
path traversal, open redirect, error disclosure — 30s timeout each).

## Step 6 — Aggregator + Ollama AI Analysis
`analysis/aggregator.py`: flatten → dedupe on `(type, evidence[:100])` →
OWASP-map → sort → truncate evidence to 500 chars.
`analysis/ollama_client.py`: system prompt (ARCHITECTURE.md §4.5, verbatim) →
`POST /api/chat` → parse → validate required keys → rule-based fallback on
timeout/invalid JSON. Full timeout reasoning in `docs/ai.md`.

## Step 7 — PDF Report Generator
`reports/generator.py` (Jinja2 render → `weasyprint.HTML(string=html).write_pdf()`),
`reports/templates/report.html` (cover, exec summary, severity table,
per-finding cards, print CSS, footer).

## Step 8 — Frontend
Originally spec'd as React Router (`Home.jsx`/`ScanStatus.jsx`/`Report.jsx`).
**Superseded**: actual frontend is v0-generated Next.js 16 App Router +
TypeScript + Tailwind v4, file-based routing, `lib/api.ts` typed fetch
helpers. See `docs/QUICK_REF.md` for the real component layout.

## Step 9 — Docker Compose & Final Setup
`docker-compose.yml`, `backend/Dockerfile`, `frontend/Dockerfile`,
`ZAP_URL` config branch, hand-written initial Alembic migration,
`.env.example`, README quick-start. Full deviation notes and build gotchas
in `docs/docker.md`.

## Post-Step-9 additions
Recon pipeline extended with Amass + httpx + Naabu (subdomain
enrichment chain); webscan extended with Katana (parallel JS-aware
crawler); three new scanning modules added — `tech_fingerprint.py`
(WhatWeb + WAFW00F), `nuclei_scan.py` (CVE templates), `enumeration.py`
(FFUF directory brute-force) — bringing the scan orchestrator's group/chord
to 8 parallel subtasks total.
