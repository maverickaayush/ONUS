# Manual Module Verification

How to test each part of the pipeline in isolation when something breaks.
Not needed every session — reach for this when debugging a specific stage.

## Prerequisites
Confirm external tools are installed and on PATH before suspecting Python
code: `which nmap subfinder whois testssl.sh sslscan nikto`. A missing tool
fails silently or hangs rather than raising a clear error.

## FastAPI skeleton
```bash
uvicorn main:app --reload
```
Look for `Uvicorn running on http://127.0.0.1:8000` with no traceback. Open
`/docs` and try `GET /api/health` → expect `{"status": "ok"}`.

## Celery + Redis
```bash
docker run -d -p 6379:6379 redis:7-alpine   # if no local Redis
celery -A tasks.celery_app worker --loglevel=info
```
Should print all 8 recognized task modules and `celery@... ready` with no
crash.

## Any scanning module, in isolation
Bypass Celery entirely and call the module function directly against an
approved test target (`testphp.vulnweb.com` — see ARCHITECTURE.md §9):
```python
from tasks.recon import run_recon
results = run_recon("scan_id_test_123", "testphp.vulnweb.com")
print(results)
```
Check the output is a list of dicts, each matching the normalized schema
(ARCHITECTURE.md §4.3) — no missing keys, no `None` where a string is expected,
`found_by` present on every finding.

For ZAP specifically: curl `http://localhost:8090/JSON/core/view/version/`
manually before trusting the Python side, and confirm the process actually
dies afterward (`ps aux | grep zap` should show nothing lingering).

For `headers.py`: near-instant, no external tool — cross-check findings
against the same site's response headers in browser devtools.

For `owasp.py`: re-read the code (not just the prompt) to confirm it's only
sending GET-style read-only payloads.

## Confidence verification (analysis/verifier.py)
Feed it a hand-built finding with `verifiable=True` and a `verification_target`
matching one of the HTTP-based types (`open_redirect`, `path_traversal`,
`exposed_sensitive_file`, or a `nikto_finding` whose evidence contains a
directory-listing phrase):
```python
from analysis.verifier import verify_findings
findings = [{
    'type': 'open_redirect', 'severity': 'Medium', 'confidence': 'probable',
    'verifiable': True,
    'verification_target': {'url': 'https://testphp.vulnweb.com', 'param': 'next',
                             'payload': 'https://evil-vapt-test.example.com'},
}]
verify_findings(findings, enabled=True)
print(findings[0]['confidence'], findings[0].get('verification_note'))
```
Expect `confidence` to end up `confirmed` or `unverified` (never for the
finding to disappear from the list — that's the one behavior that must
never regress, see ARCHITECTURE.md §4.4b). Set `config.ENABLE_VERIFICATION=False`
(or pass `enabled=False`) and confirm it's a full no-op — `requests.get`
never called, `confidence` stays at its module-assigned baseline.

For `reflected_xss` (Playwright-based, `verify_reflected_xss`), confirm
Chromium is actually installed first — `playwright install --with-deps
chromium` inside the container (`docker compose exec worker playwright
install --with-deps chromium` if it's ever missing) — then feed a
`reflected_xss` finding with a real `verification_target`
(`{url, params, payload, marker}`, matching `owasp.py`'s `test_xss` shape)
through `verify_findings`. A browser/Chromium failure (not installed,
crashed, OOM) must demote to `unverified` with a note starting
"Headless-browser verification failed", never raise out of
`verify_findings()`.

## Operator decision flow (pause / retry / continue / cancel)
Force a pause without a real failing module — hand-build the chord's input
(ARCHITECTURE.md §4.3b):
```python
from tasks.scan_orchestrator import aggregate_and_analyse
results = [{"module": "recon", "status": "failed", "error": "nmap timed out",
            "findings": [], "tool_versions": {}, "finding_count": 0, "duration_seconds": 1.0}]
# ...plus success envelopes for the other 7 modules
aggregate_and_analyse(results, scan_id, domain)
```
Confirm `scan.status` becomes `awaiting_user_decision` and `GET
/api/scan/{id}/status` returns `module_errors`/`can_retry`. Then walk all
three decisions via `POST /api/scan/{id}/decision`: `retry` (re-dispatches
only the failed module, `can_retry` flips `False` after its one allowed
retry fails again), `continue` (finalizes, failed module stays `failed` in
`module_execution`, PDF still generates), `cancel` (`status` →
`cancelled`, no PDF). `backend/tests/test_decision_flow.py` covers this
without needing a live Celery/Redis stack — run that first if something
regresses here.

## Stuck-scan reaper
Set a scan's `started_at` further back than `STUCK_SCAN_DEADLINE`
(`routers/scan.py`) while `status` is `queued`/`running`/`analysing`, then
hit `GET /api/scan/{id}/status` — it should flip to `failed` on that same
request (this is a hard Celery `time_limit` SIGKILL safety net, distinct
from the decision flow above, which only fires for failures a module
reported about itself). `backend/tests/test_stuck_scan_reaper.py` covers
the boundary cases (just under/over deadline, already-complete scans never
reaped).

## Aggregator + Ollama
Feed the aggregator a small hand-written list of findings first — confirms
dedup/sort/OWASP-mapping without burning Ollama calls. Then:
```bash
ollama list                        # confirm qwen2.5:7b is present
curl http://localhost:11434/api/chat -d '{"model":"qwen2.5:7b","messages":[{"role":"user","content":"say hello in JSON: {\"msg\": ...}"}],"format":"json","stream":false}'
```
Run `ollama_client.analyse()` against real aggregated output and confirm
`executive_summary`, `risk_score`, `findings` are all populated. Then
deliberately stop Ollama (`systemctl stop ollama`) and confirm the
rule-based fallback kicks in instead of crashing the pipeline.

## PDF report
```python
pdf_bytes = generate_pdf(scan, analysis)
assert pdf_bytes[:4] == b'%PDF'
```
Write to a file and actually open it — check cover page, badge color,
severity table, and that finding cards don't overlap at page breaks. Test
with zero findings and with 10+ findings.

## Frontend
```bash
cd frontend && npm run dev
```
Walk the flow manually: domain input → auth checkbox gates submit → lands
on scan-status page → polling shows friendly errors if backend isn't wired
yet (not a blank crash) → report page renders chart, sortable table, PDF
download.

## Docker Compose
```bash
docker-compose up --build
docker-compose ps          # every service Up/healthy, no restart loops
```
Do one full scan through the actual UI against an approved test target,
confirm a PDF downloads. Check `docker system df` for disk bloat afterward.
