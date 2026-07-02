# Scanner Module Deep Notes

Full reasoning behind the timing/flag decisions summarized in `the project docs` §4.3.
Not needed every session — read this when touching `recon.py` or `webscan.py`
timing/flags specifically.

---

## nmap two-phase scan (`recon.py`)

Deliberate deviation from a single `-p-` scan. A single full `-p-` scan can't
return results against a filtered/CDN host (e.g. Vercel, which filters every
port except 80/443): nmap must wait out no-response probes on ~65k filtered
ports, and two things go wrong:
- a hard `subprocess` SIGKILL leaves an empty/truncated XML → zero findings
- `--host-timeout`, when it fires mid-scan, makes nmap **abandon the host
  and report zero ports** — it is not a partial-results mechanism for a
  single host (verified)

Only a scan small enough to **run to completion** reliably reports on such a
host. So nmap runs in two phases, merged & de-duplicated by port:

- **Phase 1** — `--top-ports 100`, no `--host-timeout`, `subprocess(timeout=130)`.
  Allowed to finish; captures the services that matter (web/ssh/mail/db).
  Instant on a normal host; ~2 min on a fully-filtered host but it completes
  and reports (verified: found 80/443 on Vercel in ~120s).
- **Phase 2** — `-p- --host-timeout 60s`, `subprocess(timeout=70)`. Best-effort
  extra coverage: a normal host finishes in seconds and adds high-port
  services; a filtered host times out harmlessly since Phase 1 already has
  the real ports.
- **Adaptive skip** — Phase 2 is skipped when Phase 1 took >30s (a slow
  Phase 1 means the host is filtered, so `-p-` can't complete anyway and
  would only waste ~70s). Bounds nmap to ≤130s.

Both phases: `-sV -sC --open -T4 --min-rate 1000`.

## Recon timing budget

Recon runs its tools *sequentially* in one task, so every external call is
hard-bounded. Per-task limit: **soft 900s / hard 1080s** (raised from 600/660
to accommodate the Amass/httpx/Naabu subdomain-enrichment chain).

| Stage | Worst case | Bound |
|---|---|---|
| nmap | 240s | Phase 1 cap 180s (run-to-completion on filtered hosts) + Phase 2b app-ports cap 60s. Phase 2a full `-p-` (≤70s) only runs on responsive hosts, mutually exclusive with the 240s branch. |
| subfinder | 60s | `subprocess(timeout=60)` — raised from 30s for API sources (GitHub token etc.) |
| WHOIS | 20s | `subprocess(['whois', domain], timeout=20)`, SIGKILL-enforced; parsed via `whois.parser.WhoisEntry.load`. **Never call `python_whois.whois()` directly — no timeout, a hung WHOIS server stalls recon.** |
| DNS | 36s | `resolver.timeout/lifetime = 4`; 9 queries max (5 records + DMARC + 3 DKIM selectors; SPF reuses TXT answers) |

Per-task limits are set per module, not globally: fast modules (headers,
owasp) keep the tight 300/360 default so a hang is caught quickly. Only
legitimately-slow modules get raised ceilings: **recon 900/1080, webscan
480/540**. Every stage degrades to "no findings" on failure; the top-level
`run_recon` try/except is the final backstop (marks module `failed`, returns
partial findings).

## subfinder free API keys (optional, improves subdomain coverage)

Without keys, subfinder only queries free/public sources.

| Source | Free tier | Get key at |
|---|---|---|
| Chaos (ProjectDiscovery) | Completely free | chaos.projectdiscovery.io |
| GitHub | Free with account | github.com → Settings → Developer settings → tokens |
| VirusTotal | 1,000 req/day free | virustotal.com |
| SecurityTrails | 50 req/month free | securitytrails.com |
| Censys | Free tier | censys.io |
| WhoisXMLAPI | 500 req/month free | whoisxmlapi.com |

Wire in via `~/.config/subfinder/provider-config.yaml` (see
`docs/docker.md` for how the container reaches this file). Chaos + GitHub
are the highest-value free pair.

## webscan timing (ZAP + Nikto + Katana)

Worst case: ZAP wait (≤60s) + ZAP spider+ascan (≤240s) + Nikto (≤130s) =
~430s, which exceeds the default Celery 300s/360s limit — the task would be
SIGKILL'd mid-scan, breaking the chord and failing the whole scan. Since ZAP
active scanning is the pipeline's intended long pole, `run_webscan`
overrides its per-task limit to **soft 480s / hard 540s**. Internal budgets
(`_ZAP_READY_TIMEOUT=60`, `_ZAP_SCAN_BUDGET=240`, `_NIKTO_TIMEOUT=130`) keep
the real worst case ~430s, a ~50s margin. Does not affect the orchestrator —
it dispatches the chord and returns immediately, never blocking on
webscan's runtime.

ZAP and Katana run in parallel via `ThreadPoolExecutor(max_workers=2)`
inside the task, so Katana adds no wall-clock overhead. Nikto runs
sequentially after both crawlers finish. Katana's endpoint list is diffed
against ZAP's; Katana-only endpoints are flagged `js_hidden_endpoints`
(Low) to signal manual review of JS-heavy routes.

## Enumeration baseline calibration (`enumeration.py`)

Added after a real scan against a WAF-fronted target produced 4636 FFUF
"findings" that were all the same generic 403 deny page — see `docs/ai.md`
for the downstream Ollama-context-window half of that bug.

Before FFUF runs the real wordlist, `_calibrate_baseline()` probes 3-5
guaranteed-nonexistent paths (mixed formats: raw UUID, `nonexistent-{hex}`,
`does-not-exist-{int}`, a `.php` path, a directory-style path) **concurrently**
via `ThreadPoolExecutor` — not sequentially. Sequential probing at
`_BASELINE_TIMEOUT=10` each would add up to 50s of pure wait time before
FFUF (up to 130s) even starts, on top of a handful of sequential
admin-panel login-form verification requests later in the same task —
enough to threaten the module's own soft time limit. Running them
concurrently bounds the whole calibration step to ~10s regardless of probe
count.

If the probe responses cluster (same status code, sizes within 5% of the
median, or within 20 bytes for tiny bodies), the target has a wildcard/
catch-all page and a `baseline` signature (`status`, `size_range`,
`size_median`, `body_hash_set`) is returned. Real FFUF hits are then
filtered against `_within_baseline()` (status match + size within
`(min-50, max+50)`) before ever becoming a finding. The probes' own
first-1KB body hash (`body_hash_set`) is captured but **not** usable
against real FFUF hits — FFUF's `-of json` output doesn't include response
bodies, only status/length. Status+size filtering already collapses the
observed flood (a single WAF page hit by hundreds of wordlist entries);
add `-or`/a body-fetch step later if a future scan needs finer precision
than size alone provides.

Admin-panel path matches (`/admin`, `/wp-admin`, etc.) additionally get one
follow-up GET to check for a login-form signature (`type="password"`,
`<form...login`, etc.) — only for the small number of confirmed admin-panel
hits, not the whole wordlist — to distinguish an open panel (High) from a
login-gated one (Medium). A request failure here defaults to "open" (the
conservative assumption when the check itself can't run).

Enumeration's per-task timeout was raised from 180s/240s to **220s/280s**
to give this calibration + verification overhead headroom on top of FFUF's
own 130s subprocess budget.
