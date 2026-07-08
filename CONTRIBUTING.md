# Contributing

Thanks for considering a contribution to the VAPT Tool.

## Dev setup

Full stack (Docker):
```bash
cp .env.example .env
cp backend/subfinder-config/provider-config.yaml.example backend/subfinder-config/provider-config.yaml
docker compose up -d
```

Or run pieces natively - see [`docs/QUICK_REF.md`](docs/QUICK_REF.md)'s "Run
commands" section for the `uvicorn --reload`, `celery worker`, and `npm run
dev` commands.

## Tests

```bash
pip install -r backend/requirements-dev.txt
pytest backend/tests
```

Some tests need a local Redis instance reachable at `REDIS_URL` (default
`redis://localhost:6379/0`) - `redis-cli ping` should return `PONG` before
running the suite. CI runs a Redis service container automatically.

## Known gaps

- No frontend test suite yet (backend has 400+ tests, frontend has none) -
  contributions adding Vitest/RTL coverage for the dashboard are welcome.

## Before you touch a scanning module

Read [`ARCHITECTURE.md`](ARCHITECTURE.md) first - it's the architectural
contract for this project, not background reading. In particular:
- Every scanning module must emit the exact finding schema (see "Scanning
  Engine" in `ARCHITECTURE.md`), including `found_by` - the aggregator's
  dedup depends on it.
- The safety guardrails ("Security & Ethical Guardrails" in
  `ARCHITECTURE.md`) - authorization checks, private-IP rejection,
  non-destructive-only payloads - are non-negotiable. Ask before relaxing
  anything, even for convenience during testing.

## Opening a PR

- Keep the finding schema and safety guardrails intact.
- Run the test suite (`pytest backend/tests`) before opening a PR.
- Describe what changed and why in the PR description.
