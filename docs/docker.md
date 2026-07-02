# Docker Architecture — Deviations & Build Gotchas

Full reasoning behind the Docker setup summarized in `the project docs` §7. Not
needed every session — read this when touching `docker-compose.yml`,
`backend/Dockerfile`, or `frontend/Dockerfile`.

## Services (as actually built, verified end-to-end)

Six services: PostgreSQL, Redis, **OWASP ZAP** sidecar, FastAPI backend,
Celery worker, Next.js frontend (standalone Node server, not Nginx). Ollama
runs **natively on the host**, not in Docker.

```yaml
services:
  postgres:
    image: postgres:16-alpine
  redis:
    image: redis:7-alpine
  zap:
    image: zaproxy/zap-stable:latest   # sidecar, not bundled into backend
  backend:
    build:
      context: .                       # repo ROOT, not ./backend
      dockerfile: backend/Dockerfile
  worker:
    build:
      context: .
      dockerfile: backend/Dockerfile
    command: celery -A tasks.celery_app worker --loglevel=info -c 5
  frontend:
    build:
      context: ./frontend
      args:
        NEXT_INTERNAL_API_URL: http://backend:8000   # build ARG, not env — see below
```

## Ollama runs natively on the host, not in Docker

The reference machine already has Ollama installed as a systemd service
with `qwen2.5:7b` pulled and GPU passthrough working bare-metal — simpler
than configuring `nvidia-container-toolkit` for an equivalent containerized
setup. Containers reach it via `host.docker.internal` (mapped through
`extra_hosts: ["host.docker.internal:host-gateway"]` on `backend`/`worker`)
at `OLLAMA_URL=http://host.docker.internal:11434`.

**Required host-level change** (security-relevant — widens Ollama's network
exposure, confirm with the user before applying): Ollama's default bind is
`127.0.0.1:11434` — loopback only, unreachable from Docker's bridge network
even via `host.docker.internal` (verified: `connect ECONNREFUSED` against
the bridge gateway IP). Fixed via systemd override:

```bash
sudo systemctl edit ollama
# add under [Service]:
#   Environment="OLLAMA_HOST=0.0.0.0:11434"
sudo systemctl daemon-reload && sudo systemctl restart ollama
```

This makes Ollama reachable from the local network, not just Docker —
acceptable on a personal/dev workstation, worth a firewall rule (block
11434 from non-Docker sources) on a shared machine. The `ollama_data`
volume in `docker-compose.yml` is unused while Ollama stays native —
reserved for a future fully-containerized migration.

## ZAP runs as a sidecar container, not a local daemon

`backend/config.py` has `ZAP_URL` (empty string = native dev, falls back to
the per-scan-port local-daemon spawn/kill behavior in `_run_zap()`). When
`ZAP_URL` is set (Docker: `http://zap:8090`), `_run_zap()` skips the local
process entirely and calls `zap.core.new_session(name=scan_id)` for
per-scan isolation instead — the port-hash isolation scheme doesn't apply
to a daemon shared across concurrent scans. The spider/active-scan/alert
logic in the middle of `_run_zap()` is unchanged in both branches.

## backend Dockerfile — real issues found by building, not guessed

- **Base image pinned to `python:3.11-slim-bookworm`**, not bare
  `python:3.11-slim`. The unpinned tag resolves to Debian "trixie"
  (testing), where `nikto` isn't in apt's repos at all (neither trixie nor
  bookworm has it — Ubuntu-`universe`-only). Bookworm pin needed regardless
  for everything else `apt-get install`s.
- **`nikto` installed from GitHub source** (`git clone
  https://github.com/sullo/nikto.git`, symlinked to `/usr/local/bin/nikto`),
  same pattern as `testssl.sh`. Requires `libjson-perl` and
  `libxml-writer-perl` from apt — `webscan.py` calls nikto with
  `-Format json`, so `libjson-perl` is load-bearing.
- **`libpango-1.0-0` + `libpangoft2-1.0-0` required from apt** for
  WeasyPrint's PDF rendering. Without them, `import weasyprint` fails with
  `OSError: cannot load library 'libgobject-2.0-0'`.
- **`psutil` in `requirements.txt`** — used in `webscan.py` for ZAP process
  lifecycle management; was a real omission from the pinned dependency list.
- **Build context is the repo root**, not `./backend`. `alembic.ini` and
  `migrations/` live at the repo root as siblings of `backend/` (per
  `migrations/env.py`'s `sys.path.insert(..., '..', 'backend')` logic) — a
  context scoped to `./backend` alone can't see them. Root `.dockerignore`
  excludes `frontend/`, `.git/`, etc.
- **`migrations/env.py` overrides `alembic.ini`'s static `sqlalchemy.url`**
  with `settings.DATABASE_URL` right after `config = context.config` — the
  ini's hardcoded `localhost` URL never resolves to the `postgres` Docker
  service.
- **`unzip -o`, not plain `unzip`**, for httpx/Naabu/Katana. Those
  ProjectDiscovery zips bundle `LICENSE.md`/`README.md` alongside the
  binary; a plain `unzip` prompts interactively to overwrite once an
  earlier tool's zip already dropped a same-named file in `/tmp`, and a
  non-interactive Docker build has no stdin to answer with (confirmed via
  an actual failed build).
- **httpx binary installed AFTER `pip install -r requirements.txt`**, not
  alongside amass/Naabu/Katana. The Python `httpx` package (a `fastapi`
  dependency) ships a `console_scripts` shim also named `httpx` in
  `/usr/local/bin`. Installing the binary before `pip install` let pip's
  shim silently overwrite the ProjectDiscovery CLI (confirmed: `httpx
  -version` returned the Python client's usage text, not the version
  banner). Installing after `pip install` makes the binary win.
- **Initial Alembic migration was hand-written**, not autogenerated — no
  native PostgreSQL was available earlier in the build to run
  `alembic revision --autogenerate` against. One bug caught while writing
  it: calling `scan_status.create(op.get_bind(), checkfirst=True)`
  explicitly *and* using the same enum object as a column type in
  `create_table()` double-creates the type (`create_table`'s
  `before_create` DDL event auto-creates it too) → raises `DuplicateObject`.
  Fix: don't call `.create()` explicitly, let the column handle it.

`whois` is required — `backend/tasks/recon.py` shells out to the `whois`
binary (bounded subprocess); without it WHOIS recon is skipped (logged,
non-fatal).

## frontend — Next.js standalone, proxy URL must be a build ARG

`next.config.mjs`'s `rewrites()` is evaluated **once at `next build` time**
and baked into `.next/standalone`'s `routes-manifest.json` — it is not
re-evaluated per-request at container runtime, even with `output:
'standalone'`. A runtime-only `environment:
NEXT_INTERNAL_API_URL: http://backend:8000` was silently ignored (confirmed
via `connect ECONNREFUSED ::1:8000` in frontend logs despite the runtime
var being set correctly). Fix: pass it as a Docker build `ARG` (default
matching the compose service name, `http://backend:8000`) so it's present
while `npm run build` executes `rewrites()`.

## subfinder API keys reach the container via a repo-relative file

Not a direct host-path bind mount — `~/.config/subfinder/provider-config.yaml`
may not exist on whoever's machine runs `docker compose up`, and Docker
would silently mount an empty *directory* there instead of a file,
breaking subfinder ungracefully. Instead:
`backend/subfinder-config/provider-config.yaml.example` is committed
(template); `backend/subfinder-config/provider-config.yaml` (real keys) is
gitignored and excluded from the Docker build context, reaching the
container only via the runtime bind mount
`./backend/subfinder-config/provider-config.yaml:/root/.config/subfinder/provider-config.yaml:ro`.
First-time setup copies `.example` to the real filename.

## Naabu SYN scan requires CAP_NET_RAW

Same privilege class as nmap's `-O` OS fingerprint. Naabu's helper detects
permission-denied at runtime and falls back to CONNECT scan (`-sT`). The
worker container runs unprivileged; add `cap_add: [NET_RAW]` to `worker:`
if Naabu SYN performance becomes a bottleneck. Not enabled by default —
NET_RAW broadens the container's kernel-level attack surface.
