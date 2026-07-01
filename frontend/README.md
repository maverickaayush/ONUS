# VAPT Tool - Frontend

Next.js 16 App Router frontend for the IIT Kanpur Computer Centre VAPT Tool.

## Dev workflow (5 terminals)

**Terminal 1 - FastAPI backend:**
```bash
cd vapt-tool/backend && uvicorn main:app --reload --port 8000
```

**Terminal 2 - Celery worker:**
```bash
cd vapt-tool/backend && celery -A tasks.celery_app worker --loglevel=info -c 5
```

**Terminal 3 - Ollama (skip if already running as systemd service):**
```bash
ollama serve
```

**Terminal 4 - Frontend:**
```bash
cd vapt-tool/frontend && pnpm dev
```

Open http://localhost:3000

The `next.config.mjs` proxy rewrites `/api/*` to `http://localhost:8000/api/*`
so no CORS configuration is needed during development.

## Tech stack

Next.js 16 App Router | TypeScript | Tailwind v4 | Recharts

## Project structure

```
app/
  page.tsx                     - Home page (domain form)
  scan/[id]/status/page.tsx    - Live polling status page
  scan/[id]/report/page.tsx    - Findings dashboard

components/vapt/
  home-form.tsx                - Domain input + auth + API call
  scan-status.tsx              - Real-time polling with API
  report-dashboard.tsx         - Live findings from API
  shared.tsx                   - SeverityBadge, StatusChip, RiskScoreRing
  navbar.tsx                   - Top navigation bar
  background.tsx               - Animated background

lib/
  api.ts                       - Typed fetch helpers + ApiError class
  utils.ts                     - cn() utility

next.config.mjs                - API proxy: /api/* -> localhost:8000
```
