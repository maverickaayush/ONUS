# ONUS Deployment — Oracle (backend) · Modal (scanners + LLM)

Production topology after the Modal migration:

| Workload | Runs on | Notes |
|---|---|---|
| FastAPI + Postgres + Redis + Celery orchestrator + aggregator/verifier/CVSS/PDF | **Oracle Cloud Free Tier** — Ampere A1 (ARM64) | slim `backend` Docker target, no scanner binaries |
| 8 scanner modules | **Modal** — one CPU function per module | `SCANNER_BACKEND=modal`; `modal_app/scanners.py` |
| Qwen 2.5 7B | **Modal** — T4 GPU, scale-to-zero | Ollama-compatible endpoint; `modal_app/llm.py` |

Local dev is unchanged: `docker compose up` builds the `full` image and runs
everything in-container with `SCANNER_BACKEND=local`.

---

## 1. Deploy the Modal apps (from a machine with the Modal CLI authed)

```bash
cd /path/to/vapt-tool            # repo root - image.py paths are repo-relative

# One-time: auth token for the LLM endpoint
modal secret create onus-llm-auth OLLAMA_AUTH_TOKEN=$(openssl rand -hex 24)

modal deploy modal_app/scanners.py     # 8 functions: scan_recon ... scan_headers
modal deploy modal_app/llm.py          # onus-llm: the Qwen endpoint

# Smoke-test one scanner and note the LLM URL:
modal run modal_app/scanners.py --module ssl_tls --domain testfire.net
modal app list          # find the onus-llm web URL (…--onus-llm-ollama-api.modal.run)
```

Record for the backend env:
- `MODAL_APP_NAME=onus-scanners`
- `OLLAMA_URL=https://<workspace>--onus-llm-ollama-api.modal.run`
- `OLLAMA_AUTH_TOKEN=<the token from the secret above>`
- Modal API creds for the backend host: `MODAL_TOKEN_ID` / `MODAL_TOKEN_SECRET`
  (from `modal token new`, or copy `~/.modal.toml`).

---

## 2. Build the Oracle ARM64 backend image

On the Ampere A1 instance (arm64), or cross-build with buildx:

```bash
# slim, arm64-clean target (no scanner binaries - those are on Modal)
docker build --target backend --platform linux/arm64 -t onus-backend:arm64 -f backend/Dockerfile .
```

All of the slim image's deps have arm64 builds (Python wheels, Playwright/Chromium
for the XSS verifier, WeasyPrint's libpango). No scanner-binary arm64 fight.

---

## 3. Oracle runtime (docker-compose override) — keep Postgres/Redis PRIVATE

Run only Postgres + Redis + backend + a Celery worker on Oracle. **Do not publish
5432 or 6379** (Modal is stateless and never connects to them; the backend reaches
them over the internal Docker network). Only FastAPI (8000) is public, behind a TLS
reverse proxy (Caddy/nginx/Cloudflare Tunnel).

`docker-compose.prod.yml` (sketch — no `ports:` on postgres/redis):

```yaml
services:
  postgres: { image: postgres:16-alpine, volumes: [postgres_data:/var/lib/postgresql/data] }  # NO ports:
  redis:    { image: redis:7-alpine }                                                          # NO ports:
  backend:
    image: onus-backend:arm64
    environment:
      SCANNER_BACKEND: modal
      MODAL_APP_NAME: onus-scanners
      OLLAMA_URL: https://<workspace>--onus-llm-ollama-api.modal.run
      OLLAMA_AUTH_TOKEN: <token>
      MODAL_TOKEN_ID: <...>
      MODAL_TOKEN_SECRET: <...>
      DATABASE_URL: postgresql://vapt:<pw>@postgres:5432/vapt
      REDIS_URL: redis://redis:6379/0
      CORS_ORIGINS: https://<your-frontend-origin>
      MAX_CONCURRENT_SCANS: 3
    ports: ["8000:8000"]        # only public port; put TLS in front
    command: sh -c "cd /app && alembic upgrade head && cd /app/backend && uvicorn main:app --host 0.0.0.0 --port 8000"
  worker:
    image: onus-backend:arm64
    environment: *same-as-backend
    # I/O-bound dispatch (each task waits on Modal .remote()) -> THREADS pool,
    # high concurrency. NOT gevent (gevent monkey-patches subprocess and breaks
    # the Playwright sync-API XSS verifier in _finalize). Threads run Playwright/
    # WeasyPrint fine; MAX_CONCURRENT_SCANS still bounds the CPU/mem work.
    command: celery -A tasks.celery_app worker -P threads -c 40 --loglevel=info
```

There is **no ZAP sidecar** on Oracle anymore — webscan's ZAP runs inside its
Modal container.

---

## 4. Verify

```bash
curl https://<backend>/api/health           # {"status":"ok"}
# submit a scan (authorized); watch modules go running->complete; download the PDF.
```

---

## Known limitations / notes (addressed by design, or accepted)

- **Naabu SYN scan:** Modal has no `CAP_NET_RAW` → Naabu's SYN→CONNECT (`-sT`)
  fallback fires automatically (already handled in `recon.py`). Expected.
- **Scanner egress IP / reverse DNS:** Modal IPs are shared/dynamic — no PTR
  record. Self-identification is the scanner `User-Agent` + an info/opt-out page
  + the domain-ownership check (`routers/verify.py`), not rDNS.
- **Celery pool = threads, not gevent** (see §3) — the one deviation from the
  original plan, because gevent breaks the Playwright verifier.
- **T4 vs the RTX 4060 in docs/ai.md:** re-check the Ollama 240s timeout under
  real load; bump `SCAN_TIMEOUT_MULTIPLIER` (scales the Ollama budget too) if the
  T4 is slower.
- **Shared $30 Modal credit (scanners + LLM):** `MAX_CONCURRENT_SCANS=3` +
  per-domain dedup is the throttle; a spike beyond the credit pauses (Modal
  Starter = hard stop, no card).
- **Auth to Modal scanner functions:** login creds are passed as a Modal function
  arg (visible in the Modal dashboard's function-input view). Fine for the
  authorized-assessment model; a one-shot fetch token is a future hardening.
