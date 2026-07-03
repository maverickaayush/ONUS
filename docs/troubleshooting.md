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
approved test target (`testphp.vulnweb.com` — see the project docs §9):
```python
from tasks.recon import run_recon
results = run_recon("scan_id_test_123", "testphp.vulnweb.com")
print(results)
```
Check the output is a list of dicts, each matching the normalized schema
(the project docs §4.3) — no missing keys, no `None` where a string is expected,
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
never regress, see the project docs §4.4b). Set `config.ENABLE_VERIFICATION=False`
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
