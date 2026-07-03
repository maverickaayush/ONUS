# Ollama AI Layer — Timing & Scoring-Split Notes

Full reasoning behind the timeout values and the deterministic/AI split
summarized in `the project docs` §4.5/§4.6. Not needed every session — read this
when touching `ollama_client.py`, `analysis/cvss_scorer.py`, or
`scan_orchestrator.py`'s `aggregate_and_analyse` timing.

## Why scoring moved off Ollama entirely

A real scan against a WAF-fronted target produced a 1168-page report with
4658 findings and a 100/100 CRITICAL risk score. Two compounding bugs:

1. **4636 of the 4658 findings were near-duplicate FFUF hits** (a single
   WAF/catch-all deny page, every wordlist entry returning the same
   HTTP 403 with a body size within a 17-byte range) — fixed by
   enumeration.py's baseline calibration and the aggregator's
   response-fingerprint collapse (see `docs/scanners.md` and
   `the project docs` §4.4).
2. **Ollama never actually ran.** 4658 findings serialized to JSON blew
   past `num_ctx=8192` before the request even reached the model, so
   every scan silently landed on the rule-based fallback - which
   flat-classified every HTTP 403 as Medium severity via keyword matching
   on the URL path. A 403 usually means access control is *working*; it
   should not default to being treated as a vulnerability.

Even with the finding-count bug fixed, the deeper problem is architectural:
**a 7B local model is not a reliable, reproducible source of CVSS numbers.**
Two runs of the same scan producing different severity ratings is
unacceptable for a security tool - a report's numeric findings need to be
an auditable, deterministic function of the finding's characteristics, not
a temperature-0.1-but-still-nondeterministic-enough LLM sample.

**Fix:** `analysis/cvss_scorer.py` now owns every number (`severity`,
`cvss_score`, `cvss_vector`, `priority`, `owasp_category`, overall
`risk_score`) via the official CVSS v3.1 base-score formula, computed
before Ollama is ever called. Ollama's role narrowed to prose only -
`description`, `remediation`, `executive_summary` - and its input is
capped at the top 50 findings by priority (shaped to
`{finding_id, title, evidence[:300], owasp_category, severity_hint}`),
which also incidentally fixes the original context-window overflow: 50
trimmed findings comfortably fit in `num_ctx=8192` even in the worst case.

## Why the Ollama timeout is 240s, not 120s

A real `/api/chat` analysis call for a 23-finding scan was directly timed at
**130.2s** on the reference hardware (RTX 4060 Laptop, 8GB VRAM, qwen2.5:7b
Q4_K_M) — already past the originally-specified 120s, so real scans were
routinely hitting the rule-based fallback instead of genuine AI analysis.
240s gives headroom for run-to-run variance and larger finding sets, while
staying well short of leaving a scan hanging. Measured against real
hardware, not guessed — same category of decision as the nmap two-phase
scan and webscan per-task tuning (see `docs/scanners.md`).

## Downstream consequence

`aggregate_and_analyse` (the Celery chord callback in `scan_orchestrator.py`
that calls Ollama) needed its own per-task limit raised from the global
300s/360s default to **soft 360s / hard 420s** — the default 300s soft
limit left only ~50-60s of margin over a 240s Ollama call plus aggregation
and PDF generation, too tight given GPU/network variance. Same pattern as
recon (900s/1080s) and webscan (480s/540s): the stage doing genuinely
variable-duration work gets a deliberately generous, documented ceiling
rather than the tight default.

## Phase 1 confidence verification (`analysis/verifier.py`) timing

Same measure-don't-guess discipline as the Ollama timeout above. Two
measurements, both real:

**Verifier logic overhead (localhost fixture):** a stdlib `http.server`
fixture standing in for a target with known instances of each Phase 1
finding type, timed 15 runs per verifier. All four checks (`open_redirect`,
`path_traversal`, `exposed_sensitive_file`, `directory_listing`) came back
at **median ~1ms, p95 ~3ms** — negligible. This confirms the verifiers
themselves add essentially no cost; the real cost is network round-trip
time to the actual scan target, which a local fixture can't simulate.

**Real network cost (measured against the approved `demo-target.example` target):**
20 live GET requests mixing root-path and off-path probes (the same
request shape the verifiers issue - a plain GET, `allow_redirects=False`)
came back at **median 0.39s, p95 0.93s** per request (one outlier at
1.7s). This is the real binding constraint. It also **contradicts** the
original sum-of-medians/rate-limiter design assumption: at this RTT, a
self-imposed rate limit (e.g. 5 req/s = 200ms spacing) would be *slower*
than the network already is — so Phase 1 does **not** add an artificial
throttle. `# ponytail:` note in `verifier.py`'s module docstring calls
this out — add real rate limiting only if a future fast/local target ever
floods the verifier; not needed for `demo-target.example`-class targets, where
network latency alone keeps request rate well under any sane limit.

**Time budget:** `_TIME_BUDGET_SECONDS = 60` in `verifier.py`, dispatched
sequentially. At the measured p95 (0.93s/request), 60s covers ~65
verifiable findings — comfortably above realistic Phase 1 counts, since
`open_redirect`/`path_traversal`/`exposed_sensitive_file`/Nikto
directory-listing hits are inherently rare after the aggregator's own
dedup/response-fingerprint collapse (Section 4.4). Findings not reached
before the budget expires are demoted to `unverified` with a
`verification_note` — the same mechanism as any other verification
failure, not new logic.

**Celery limit:** existing `aggregate_and_analyse` soft 360s/hard 420s +
60s measured verification budget + 20s margin = **soft 440s / hard 500s**
(same 60s soft→hard gap as before). `continue_after_decision` (the other
caller of `_finalize()`) got the identical bump for consistency.
