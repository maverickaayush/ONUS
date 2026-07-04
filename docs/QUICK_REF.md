# Quick Reference — VAPT Tool

Fast lookup for an already-oriented developer/agent. For full architecture,
schemas, and the build sequence, see [`the project docs`](../the project docs).

---

## Architecture (one line)

```
domain → [recon | webscan | ssl_tls | headers | owasp | tech_fingerprint | nuclei | enumeration] (parallel, Celery)
       → any module failed/timed out? → pause at awaiting_user_decision (operator retry/continue/cancel, the project docs §4.3b)
       → aggregator (dedup + OWASP-map + sort)
       → confidence verification (passive re-observation, §4.4b)
       → deterministic CVSS scoring (§4.5)
       → Ollama (Qwen 2.5 7B) AI analysis
       → WeasyPrint PDF + PostgreSQL
       → dashboard / PDF download
```

8 scanning modules run **in parallel** via a Celery `group`, gated by a
`chord` callback (`aggregate_and_analyse`) that fires once all 8 complete.

---

## Run commands

### Docker (full stack)
```bash
cp .env.example .env
cp backend/subfinder-config/provider-config.yaml.example backend/subfinder-config/provider-config.yaml
docker compose up -d
docker compose ps                  # check health
docker compose logs -f backend worker
```

### Native dev — backend
```bash
cd backend
uvicorn main:app --reload --port 8000
```

### Native dev — Celery worker
```bash
cd backend
celery -A tasks.celery_app worker --loglevel=info -c 5
```

### Native dev — frontend
```bash
cd frontend
npm run dev          # localhost:3000
```

### Ollama
```bash
ollama serve                       # if not already running as a service
ollama pull qwen2.5:7b
ollama list                        # confirm model is present
curl http://localhost:11434/api/tags
```

### Database migrations
```bash
cd /path/to/vapt-tool              # repo root — alembic.ini lives here
alembic upgrade head
alembic revision --autogenerate -m "description"
```

---

## Folder responsibilities

| Folder | Responsibility |
|---|---|
| `backend/tasks/` | The 8 Celery scanning modules (`recon.py`, `webscan.py`, `ssl_tls.py`, `headers.py`, `owasp.py`, `tech_fingerprint.py`, `nuclei_scan.py`, `enumeration.py`) + `scan_orchestrator.py` (dispatch, plus the pause/retry/continue/cancel decision flow — the project docs §4.3b) + `base_task.py` (shared `normalize_finding`/`update_module_status`/`SCAN_MODULES`) |
| `backend/analysis/` | `aggregator.py` (merge/dedup/collapse/sort findings) + `verifier.py` (passive re-observation, confidence tiers, incl. Playwright-based `verify_reflected_xss`) + `cvss_scorer.py` (deterministic severity/CVSS/priority/risk_score, confidence-shifted) + `ollama_client.py` (AI description/remediation prose + fallback) |
| `backend/reports/` | `generator.py` (WeasyPrint PDF) + `templates/report.html` (Jinja2, autoescaped) |
| `backend/routers/` | FastAPI HTTP endpoints (`scan.py`, `report.py`) — validation + DB only, no scanning logic |
| `backend/models.py` / `schemas.py` | SQLAlchemy ORM (`Scan`, `Report`) / Pydantic request-response schemas |
| `migrations/` | Alembic migrations — lives at **repo root**, sibling of `backend/` (not inside it) |
| `frontend/` | Next.js 16 App Router — `components/vapt/` has the 3 main pages, `lib/api.ts` has typed fetch helpers |

---

## The one contract that must never break

Every scanning module returns findings via `normalize_finding()` from
`base_task.py`, which guarantees this exact schema:

```json
{"module": "...", "tool": "...", "type": "...", "title": "...",
 "evidence": "...", "severity": "...", "cvss": 0.0, "target": "...",
 "found_by": ["module_name"]}
```

The aggregator's dedup logic depends on `found_by` being present on every
finding. Missing it breaks dedup silently.

---

## Cheat sheet — where do I make a change?

| I want to... | Edit this file |
|---|---|
| Add a new check to an existing scanner | `backend/tasks/{module}.py` — then add a matching rule in `backend/analysis/cvss_scorer.py`, or the new type falls back to a generic band vector |
| Change how findings are deduplicated/collapsed | `backend/analysis/aggregator.py` |
| Change severity/CVSS/priority/risk_score logic | `backend/analysis/cvss_scorer.py` — deterministic only, per the project docs §4.5. Never let Ollama produce these |
| Add/change a confidence verifier | `backend/analysis/verifier.py` — passive re-observation only (the project docs §4.4b); on failure, demote to `confidence='unverified'` with a note, never drop the finding |
| Change the AI prompt or model config | `backend/analysis/ollama_client.py` — prompt is byte-for-byte per the project docs §4.6, don't reword it; it must never ask for numbers |
| Change PDF layout/styling | `backend/reports/templates/report.html` (all CSS inline — WeasyPrint can't load external resources) |
| Add an API endpoint | `backend/routers/scan.py` or `report.py` |
| Change the retry/continue/cancel decision flow or its retry limit | `backend/tasks/scan_orchestrator.py` (`MAX_RETRIES_PER_MODULE`, `_pause_for_decision`, `retry_failed_modules`, `continue_after_decision`) — the project docs §4.3b |
| Change the stuck-scan (hard-SIGKILL) reaper deadline | `backend/routers/scan.py`'s `STUCK_SCAN_DEADLINE` |
| Add a DB column | `backend/models.py` + new Alembic migration |
| Change frontend page behavior | `frontend/components/vapt/*.tsx` |
| Change Docker service config | `docker-compose.yml` (root) |
