# VAPT Tool — Automated Vulnerability Assessment

Built for IIT Kanpur Computer Centre under Navpreet Singh.

## Architecture

Six-layer pipeline: Next.js frontend → FastAPI → Celery/Redis → parallel
scanners (nmap, ZAP, Nikto, testssl.sh, custom OWASP) → Ollama (Qwen 2.5 7B)
→ PostgreSQL + PDF report.

Ollama runs **natively on the host** (not in Docker) — it's already
installed as a systemd service with the model pulled, and GPU passthrough is
simpler bare-metal. Containers reach it via `host.docker.internal`.

## Quick start

1. Install Ollama on the host: https://ollama.com/install.sh
2. Pull the model: `ollama pull qwen2.5:7b`
3. **Make Ollama reachable from Docker containers** (required — Ollama
   defaults to `127.0.0.1`-only, which Docker's bridge network cannot
   reach; without this, scans complete but always fall back to rule-based
   scoring instead of real AI analysis):
   ```bash
   sudo systemctl edit ollama
   ```
   Add under `[Service]`:
   ```ini
   [Service]
   Environment="OLLAMA_HOST=0.0.0.0:11434"
   ```
   Save, then:
   ```bash
   sudo systemctl daemon-reload && sudo systemctl restart ollama
   ```
   Note: this makes Ollama reachable from your local network, not just
   Docker — fine on a personal machine, worth a firewall rule on a shared one.
4. Verify Ollama: `curl http://localhost:11434/api/tags`
5. Clone and set up:
   ```bash
   cp .env.example .env
   cp backend/subfinder-config/provider-config.yaml.example backend/subfinder-config/provider-config.yaml
   docker compose up -d
   ```
   The subfinder config file is optional — leaving it as the empty template
   is fine, subfinder just runs with free/public sources only. To deepen
   subdomain enumeration, add free API keys (GitHub, Chaos) to that file
   before starting — see the comments inside it.
6. Wait ~2 minutes for the ZAP daemon to become healthy.
7. Open http://localhost:3000

## Stop

```bash
docker compose down
```

## Logs

```bash
docker compose logs -f backend worker
```

## Authorized use only

Scanning targets without explicit written authorization is illegal under the
IT Act 2000 (India) and equivalent international statutes. This tool
requires authorization confirmation on every scan and logs the operator +
timestamp for accountability.
