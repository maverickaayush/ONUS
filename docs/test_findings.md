# Practicality Test Findings

Scans run against self-hosted, deliberately-vulnerable practice apps to validate
the tool's actual detection behavior (Section 8 approved targets). One target
at a time due to local disk space constraints: scan → document → remove
container/image → next target.

---

## DVWA (`vulnerables/web-dvwa`)

- **Job ID:** `00cc5738-cefe-4a41-bac9-f3b7d1b15e5e`
- **Date:** 2026-07-04
- **Target:** `dvwa.local` (docker-network alias, port 8081 published)
- **Result:** `complete`, all 8 modules `complete`, no errors, no retries needed.
- **Risk score:** 36/100. Critical=0, High=0, Medium=19, Low=21, Informational=21 (61 total).

**By module:** webscan 33, headers 9, enumeration 9, recon 8, ssl_tls 1, tech_fingerprint 1,
**owasp 0**.

**What it found:** all misconfiguration-class issues — missing CSP, missing
anti-clickjacking header, directory browsing enabled, `HttpOnly`/`SameSite`
cookie flags missing, server version disclosure via the `Server` header,
plain HTTP (no HSTS/SPF/DMARC/DKIM).

**Notable gap — 0 OWASP Top 10 findings and 0 Critical/High:** DVWA's actual
SQLi/XSS/command-injection vulnerabilities live behind a login form at
`/vulnerabilities/*`. Both the `owasp.py` module and ZAP's scan here only
reached unauthenticated pages (DVWA redirects to `/login.php` for everything
else), so the well-known DVWA vulnerabilities were never exercised — this
scan only characterizes the *unauthenticated* attack surface. This is an
expected finding about current tool scope (no authenticated-session/login-flow
support yet), not a bug in the scan itself.

**Action:** container + image removed after this scan to free disk space
(see git history / current `docker-compose.yml` for what's live now).

---

## Juice Shop (`bkimminich/juice-shop`)

- **Job ID:** `6c92d05d-50aa-4de9-a453-f259658e1603`
- **Date:** 2026-07-04
- **Target:** `juiceshop.local` (docker-network alias, port 3001 published)
- **Result:** `complete`, all 8 modules `success`, no errors, no retries needed.
- **Risk score:** 100/100 (capped). Critical=0, High=0, Medium=262, Low=231, Informational=115 (608 total after aggregator dedup; raw per-module count was 660).

**By module (raw finding_count, pre-dedup):** webscan 639, enumeration 9,
recon 5, headers 5, tech_fingerprint 1, ssl_tls 1, **owasp 0, nuclei 0**.
webscan duration 308s — the scan's long pole, as expected (Section 4.3.2).

**What it found:** almost entirely ZAP alerts repeated per-URL across Juice
Shop's many Angular JS chunk files — `Timestamp Disclosure - Unix` (205),
`Cross-Domain Misconfiguration` / CORS wildcard `Access-Control-Allow-Origin: *`
(136+), `CSP Header Not Set` (112+), plus headers-module findings (missing
HSTS/SPF/DMARC/DKIM, no CSP) and enumeration hits (exposed paths). No
per-URL response-fingerprint collapse applies here since that mechanism keys
off `http_status`/`http_size`, which only `enumeration.py` attaches (Section
4.4.3) — so a SPA with many static assets producing the same header-level
alert legitimately shows up as one finding per file, not a bug.

**Notable gap — 0 OWASP Top 10 and 0 Critical/High, risk score still maxes
at 100:** same root cause as DVWA — Juice Shop's actual injection/broken-auth
challenges live behind API calls and authenticated flows that an
unauthenticated `owasp.py`/ZAP crawl doesn't reach, so this scan again only
characterizes the *unauthenticated* surface (no login-flow support yet). The
100/100 risk score with no Critical/High present illustrates
`compute_risk_score`'s non-linear low end (Section 4.5) working as designed:
262 Mediums × 2 alone is enough to saturate the 0–100 cap — expected given
the volume of repeated per-URL Medium alerts above, not a scoring bug.

**Action:** container + image removed after this scan to free disk space
(see git history / current `docker-compose.yml` for what's live now).

---

## WebGoat (`webgoat/webgoat`)

- **Job ID:** `49ac28a5-6ab8-4764-9ea6-9ca329b80011`
- **Date:** 2026-07-04
- **Target:** `webgoat.local` (docker-network alias, port 8082 published)
- **Result:** `complete`, all 8 modules `success`, no errors, no retries needed.
- **Risk score:** 54/100. Critical=0, High=1, Medium=23, Low=33, Informational=21 (78 total).

**Deployment note — WebGoat needed remapping to fit the tool's bare-domain
scan model:** the upstream image defaults to port 8080 under context path
`/WebGoat`, and runs as a non-root `webgoat` user that can't bind `:80`.
`docker-compose.yml`'s `webgoat` service sets `WEBGOAT_PORT=80` +
`WEBGOAT_CONTEXT=/` + `cap_add: [NET_BIND_SERVICE]` so the app lands at
`http://webgoat.local/` directly, matching every scanning module's
`https://{domain}` assumption (Section 3). `WEBWOLF_PORT` was left at its
own default (9090) - only WebGoat's own port/context needed remapping, since
the two run as separate embedded Tomcat instances in the same container and
share no other config. Confirmed working: the SQLi finding below is on
`/register.mvc`, real WebGoat content, not a 404 stub.

**By module:** webscan 61, headers 7, recon 6, enumeration 2, ssl_tls 1,
tech_fingerprint 1, **owasp 0, nuclei 0**.

**What it found:** one genuine High — ZAP's `SQL Injection` alert on
`GET /register.mvc` (CVSS 8.2). Everything else is misconfiguration-class:
`User Agent Fuzzer` (11, ZAP's fuzzing noise, Informational-shaped),
missing `X-Content-Type-Options` (9), missing anti-clickjacking header (4),
no CSP (4), missing anti-CSRF tokens (4), cookies without `SameSite` (3),
a Spring Boot Actuator information-leak hit (exposed `/actuator/env` /
`/actuator/configprops` - matches WebGoat's own `application-webgoat.properties`
which explicitly enables `management.endpoints.web.exposure.include=env,
health,configprops`).

**No tool bug found — but a real fallback fired:** `ai_unavailable: true`
this run. Worker logs show Ollama returned a truncated/invalid JSON response
on all 3 attempts (`Unterminated string starting at: line 237...`) before
falling back to rule-based descriptions - Ollama itself was up and reachable
(`ollama list` showed `qwen2.5:7b` loaded, `curl` to
`host.docker.internal:11434` from the worker returned 200) the whole time.
This is the `num_predict: 4096` output-length ceiling (Section 4.6) getting
hit mid-generation on a verbose response, not a connectivity or code defect
- the documented fallback path (Section 4.6/`ai_unavailable` badge) handled
it exactly as designed. Not treated as a bug to fix; noted here as an
observed data point on how often this ceiling actually gets hit in practice.

**Action:** container + image removed after this scan to free disk space
(see git history / current `docker-compose.yml` for what's live now).

---

## Metasploitable2 (`tleemcjr/metasploitable2`)

- **Job ID:** `3062b79b-0925-403f-b74f-4ca5eee3ed76`
- **Date:** 2026-07-04
- **Target:** `metasploitable.local` (docker-network alias only, no published host
  port - a deliberately-backdoored multi-service host, not a single web app,
  see `docker-compose.yml`'s `metasploitable2` service comment).
- **Result:** `complete`, all 8 modules `success`, no errors, no retries needed,
  `ai_unavailable: false`.
- **Risk score:** 100/100 (capped). Critical=0, High=18, Medium=6112, Low=7279,
  Informational=3526 (16,935 total after aggregator dedup; raw per-module count
  was 17,708 - webscan alone raised 17,670 raw findings against the bundled
  DVWA/Mutillidae-alike apps on port 80, same per-URL ZAP-alert volume pattern
  as Juice Shop).

**Deployment note - the image's default `CMD` doesn't survive as a daemon:**
`tleemcjr/metasploitable2`'s `CMD` is `services.sh && bash` - a bare `bash`
with no controlling tty/stdin hits EOF and exits immediately, which under
`restart: unless-stopped` produced a restart loop (`RestartCount` hit 4 within
the first minute) and never left the services up long enough to scan. Fixed
by adding `tty: true` + `stdin_open: true` to the compose service (the
`-it`-equivalent) - confirmed `RestartCount` stayed at 0 for the rest of the
run once added.

**By module:** webscan 17670 (raw), recon 20, headers 8, enumeration 8,
ssl_tls 1, tech_fingerprint 1, **owasp 0, nuclei 0**.

**What it found:** `recon` correctly identified 16 open services via nmap
`-sV -sC` (vsftpd 2.3.4, OpenSSH 4.7p1, Linux telnetd, Postfix smtpd, Apache
2.2.8, rpcbind, Samba 3.X-4.X on 139/445, `login`/`tcpwrapped` on 513/514,
ProFTPD 2121, MySQL 5.0.51a, PostgreSQL 8.3, VNC, X11, AJP13) - by far the
richest port/service surface of any target so far (every prior target showed
1-2 open ports). `webscan` found 18 genuine **High** `Path Traversal` hits
against the bundled web apps on port 80 - the first real, unauthenticated,
High-severity injection-class finding in this whole test phase that isn't a
misconfig or a single one-off (WebGoat's SQLi was one hit; this is 18).

**Notable gap - recon's full-port phase silently missed 6 real open ports,
including the IRC backdoor the whole target was chosen for:** a direct
`netstat -tlnp` inside the container (and a `python3 socket.connect` probe
from the worker container) confirmed **IRC is genuinely listening on 6667 and
6697** (`unrealircd`), plus rmiregistry (1099), the classic `ingreslock`
backdoor (1524), and Tomcat (8180) - none of which appear anywhere in this
scan's findings. Root cause, read directly from `recon.py`: Phase 2a's full
`-p-` sweep only runs when Phase 1 (`--top-ports 100`) finishes in under 30s,
on the assumption that a fast Phase 1 means the host is "responsive" and a
full 65k-port sweep will also finish quickly. That assumption holds for every
other target tested (1-2 open ports, so `-sV -sC` version/script detection is
cheap) but breaks for a host like this one with 15-20 *concurrently open*
ports needing per-port service-detection probing - Phase 2a's `--host-timeout
60s`/`subproc_timeout 70s` (sized for a filtered/mostly-closed host, per the
module's own docstring) isn't enough time to service-probe every open port on
a busy multi-service host, so it silently times out and contributes zero new
ports, leaving the final result as whatever Phase 1's top-100 pass already
had. Not a crash or schema violation (`status: success`, no error, no
`incomplete_modules_warning`) - a genuine coverage blind spot on
many-open-port targets, surfaced for the first time by this specific target.
**Fixed and verified same-session:** `recon.py`'s Phase 2a budget raised from
`host_timeout='60s'/subproc_timeout=70` to `'240s'/250` (recon's actual task
limit is 900s/1080s soft/hard - see `@app.task` - so this has ample headroom;
the old 70s figure was never revisited after being sized for a filtered/
mostly-closed host). Re-ran the identical scan against the identical target
after rebuilding the worker/backend images: **job `debda06d-44cb-4214-a029-354a78a6d427`**,
recon duration went from 92-109s to **213s**, and open-port count went from
**16 to 25** - every previously-missed port now appears (`1099/tcp java-rmi`,
`1524/tcp ingreslock`, **`6667/tcp irc UnrealIRCd`, `6697/tcp irc UnrealIRCd`**,
`8180/tcp Apache Tomcat`), plus ports the first scan didn't even know existed
(`512/tcp exec`, `3632/tcp distccd` - a well-known unauthenticated-RCE
service, `8787/tcp Ruby DRb`, a second `32985/tcp java-rmi`). Confirms the fix
closes the gap rather than just widening it partially.

**Note (unrelated to the fix, caught during re-verification):** ZAP's
`RestartCount` went from 0 to 1 between this run and the previous one -
timestamped to 19:28:35 UTC, about 12 minutes *before* this second scan
started, so it didn't affect these results. `OOMKilled: false`, `ExitCode: 0`
- a clean exit, not a cgroup memory-limit kill, so it doesn't change the
mem_limit verdict below. Root cause undetermined: ZAP's own container logs
for that window are empty, most likely because the log driver's `max-size:
50m` rotated away whatever message explained it, given the first scan's
unusually high 17,670-alert volume. Worth keeping an eye on across future
targets, but not evidence of an OOM problem on its own.

**`nuclei` still at 0 - correction to the root cause below.** Initially
attributed to "curated template subset doesn't cover CVEs this old" - that
guess was wrong. Reading `nuclei_scan.py` directly: it always calls `nuclei -u
<http(s)-url>` against only the HTTP-protocol template folders (`cves/`,
`vulnerabilities/`, `misconfiguration/`, `exposed-panels/`, `technologies/`,
`exposures/`) and never nuclei's `network/` template category, where raw-TCP
protocol templates (the ones that would actually apply to vsftpd/UnrealIRCd)
live. Against an HTTP-only target this is invisible; against a genuinely
multi-service host like this one it means nuclei was structurally never going
to find anything here regardless of CVE age. **Deliberately not fixed as part
of this pass:** nuclei's official `network/` backdoor templates for vsftpd
and UnrealIRCd don't just banner-check, they complete the actual backdoor
handshake (e.g. vsftpd's `:)`-suffixed username opens a live bind shell on
port 6200) - wiring those in would mean *triggering* the backdoor, not
detecting it, which breaks Section 8's non-destructive-only guardrail.
Flagged for the operator to decide, not something to silently expand.
`owasp.py` also stayed at 0 here, expected - its 5 test functions target
OWASP-Top-10-style web parameters, not network services, so an HTTP-only
scope is the correct behavior for that module (unlike nuclei's gap above).

**ZAP `mem_limit: 4g` verdict - not too tight, no action needed:** monitored
`docker stats`/`docker inspect` every ~30s for the full run (baseline →
completion). Peak ZAP memory usage was **2.001 GiB (~50% of the 4GiB limit)**
at 00:44:52, during `webscan`'s active-scan phase against the 17,670-finding
surface - the largest finding volume of any target tested. `RestartCount`
stayed at 0 throughout (baseline and final both 0), `OOMKilled: false`,
`ExitCode: 0`, no `killed`/`heap`/`gc overhead`/`outofmemory` strings in
container logs for the scan window. Comfortable headroom at the current
limit; no reason to raise it based on this run.

**Disk note (secondary to the memory question, but relevant to the ongoing
space constraint):** free space dropped from 12GB to 7.2GB over the course of
this single scan (~4.8GB consumed), driven by ZAP's session data for the
17,670-alert volume - the largest disk delta of any target tested. Worth
factoring into planning for the next 1-2 targets before a resize.

**Action:** container + image removed after this scan to free disk space
(see git history / current `docker-compose.yml` for what's live now).

---

## Mutillidae II (`citizenstig/nowasp`)

- **Job ID:** `71e35243-3c07-40f7-85b7-c5572fe6530b`
- **Date:** 2026-07-04
- **Target:** `mutillidae.local` (docker-network alias, port 8084 published).
  Deployment note: `citizenstig/nowasp` (tutum/lamp-based, Apache+MySQL
  bundled in one container) is self-contained like `bwapp` - no separate DB
  sidecar needed, unlike the original plan doc's assumption. One-time DB init
  required (`GET /set-up-database.php`, same as a fresh DVWA/bwapp) before the
  app served anything but a "database offline" page - done manually before
  scanning, not part of the scan itself.
- **Result:** `complete`, all 8 modules `success`, no errors, no retries needed,
  `ai_unavailable: false`.
- **Risk score:** 100/100 (capped). Critical=2, High=6, Medium=735, Low=1605,
  Informational=527 (2875 total after dedup; webscan raised 5305 raw).

**By module:** webscan 5305 (raw), enumeration 21, recon 6, headers 15,
ssl_tls 1, tech_fingerprint 1, **owasp 0, nuclei 0**.

**What it found - the first genuine Critical findings in this whole test
phase:** `enumeration` caught `.git/HEAD`, `.git/config` (Critical - matches
the tool's own severity mapping for exposed VCS metadata, Section 4.3.8) and
`.git/logs/`, `.git/index` (High) - the `citizenstig/nowasp` image ships with
its own `.git` directory exposed in the web root, a real, common
misconfiguration class this tool is specifically designed to catch.
`webscan` (ZAP) found 4 genuine High **Off-site Redirect** hits on the
bundled phpMyAdmin's `url.php?url=...` parameter - a real open-redirect
vulnerability, not a one-off like WebGoat's SQLi or a misconfig like every
prior target's headers findings.

**Notable gap - `owasp.py` stayed at 0 even here, despite Mutillidae's
anon-reachable vulnerable pages being exactly why this target was chosen:**
its 5 test functions appear to only probe the pages actually discovered
during the scan's own shallow crawl, and neither `owasp.py` nor ZAP's spider
wandered into Mutillidae's classic `index.php?page=<vulnerable-page>.php`
navigation structure deeply enough to reach its well-known SQLi/XSS teaching
pages within the scan's time budget - those pages exist but aren't linked
from the homepage in a way a shallow crawl finds quickly. Not a crash or
schema issue; a real reach limitation worth knowing about (the hypothesis
that "anon-reachable" alone would be enough to exercise `owasp.py` was only
half right - reachable *and discoverable by a shallow crawl* both matter).

**`nuclei` still at 0**, consistent with its documented HTTP-template-only
scope (see the Metasploitable2 entry above) applied to a plain LAMP app with
no unusual CVE-worthy service.

**ZAP note:** `RestartCount` is now at 2 (was 1 after the Metasploitable2 re-
verification run) - another restart happened somewhere between then and this
scan's completion. Still `OOMKilled: false`, memory comfortably under the 4GB
limit during this run (peak observed 1.93GiB). Root cause still undetermined
across both restarts; flagging as a pattern worth watching rather than a
solved question - two clean-exit restarts in one session is enough to not be
pure coincidence, but not enough evidence yet to point at a specific cause.

**Action:** container + image removed after this scan to free disk space
(see git history / current `docker-compose.yml` for what's live now).

---

## NodeGoat (built from source, `github.com/OWASP/NodeGoat`)

- **Job ID:** `f0027814-19bd-4706-8ff6-59b93c7370c1`
- **Date:** 2026-07-04
- **Target:** `nodegoat.local` (docker-network alias, port 8085 published).
  Deployment note: no usable prebuilt image exists - `vulnerables/web-owasp-
  nodegoat` on Docker Hub has zero pushed tags (confirmed via its own API).
  Built from OWASP's own `Dockerfile`/`docker-compose.yml` pattern instead,
  vendored into `./nodegoat-src` (gitignored, `git clone` of the official
  repo) with a `mongo:4.4` sidecar - the first target needing an actual
  `build:` context rather than a plain `image:` pull. `PORT=80` +
  `NET_BIND_SERVICE` for the same bare-root reason as webgoat/juice-shop
  (its Dockerfile runs as a non-root `node` user).
- **Result:** `complete`, all 8 modules `success`, no errors, no retries needed,
  `ai_unavailable: false`.
- **Risk score:** 23/100. Critical=0, High=0, Medium=13, Low=11,
  Informational=9 (33 total - by far the smallest finding volume of any
  target tested, since NodeGoat is a small, minimal Express app rather than
  an SPA or a bundled-multi-app image).

**By module:** enumeration 15 (raw), headers 8, recon 5, webscan 8, ssl_tls 1,
tech_fingerprint 1, **owasp 0, nuclei 0**.

**What it found:** same auth-wall pattern as DVWA - the app redirects
everything to `/login`, so every finding is misconfig-class (missing CSP/
HSTS/Permissions-Policy, `X-Powered-By: Express` disclosure, missing SPF/
DMARC/DKIM). `enumeration` correctly found `/login`, `/signup`, `/tutorial`,
`/dashboard` (redirects to login) via its wordlist, and correctly collapsed 6
identically-shaped 302 responses into one grouped finding (Section 4.4's
response-fingerprint dedup working as designed on a different stack for the
first time). No IDOR/SSRF/ReDoS reached, for the same root reason as every
other target - confirms this is a systemic gap (no authenticated-session
support yet), not something specific to PHP-shaped auth walls.

**`tech_fingerprint`/`recon` confirm the intended stack-diversity value of
this target:** `X-Powered-By: Express` and plain HTTP-only (no TLS, matching
`server.js`'s HTTPS block being commented out in the actual source) are
genuinely different signals than every PHP/Java target tested so far -
`whatweb`/`wafw00f` and the header fingerprint correctly characterize a
Node/Express stack rather than defaulting to PHP-shaped assumptions anywhere.

**ZAP note - the restart pattern continues:** `RestartCount` is now at 4 (was
2 after Mutillidae). Checked ZAP's own logs directly this time; they only show
a fresh, clean startup sequence with no error/exception preceding it - not
informative about the cause. Still `OOMKilled: false` every time, and memory
at check time was low (604MiB - this was the lightest scan of the three).
**Conclusion on the original question:** across all three targets (heaviest:
17,670 raw findings/2.6GiB peak; lightest: 8 raw findings/604MiB), the 4GB
`mem_limit` was never remotely threatened - peak observed usage across this
entire practicality-test phase was ~2.6GiB (~65% of the limit), and
`OOMKilled` was false on every single check. **The restarts are real but
demonstrably not a memory problem** - happening at both high and low memory
points, with clean exit codes, not OOM kills. Worth a dedicated investigation
if it becomes disruptive (e.g. correlate with `docker compose up` runs
against *other* services, which is when all four restarts happened to
coincide), but it's a separate question from "is 4GB enough," which this
phase answers clearly: yes.

**Action:** container + image removed after this scan to free disk space
(see git history / current `docker-compose.yml` for what's live now).

---

## Practicality-test queue: complete

All three kept targets (Mutillidae II, NodeGoat, Metasploitable2) have been
deployed, scanned, documented, and torn down; bWAPP/Security Shepherd/
Hackazon/BWA VM remain skipped-as-redundant per
`docs/practicality_test_plan.md`. Combined with the earlier DVWA/Juice Shop/
WebGoat entries, this closes out the practicality-test phase for every
approved self-hostable target. Cross-target patterns worth carrying forward:
`owasp.py`/`nuclei`'s near-total silence across every web-app target traces
to two distinct, now-understood causes (authenticated-content walls, and
nuclei's HTTP-only template scope) rather than one; the recon full-port
timeout gap was the one genuine bug found and it's fixed and verified; the
ZAP `mem_limit` question is answered (4GB is fine); the ZAP restart pattern
is a new, still-open observation for future attention.

---

## Detection-gap fixes: authenticated scanning + owasp.py crawl depth

Direct follow-up to the pattern above: `owasp.py`/`nuclei` returned 0 real
findings on every target this whole phase. Two root causes were already
identified (auth walls on DVWA/NodeGoat, crawl depth on Mutillidae) and both
were fixed and verified live.

**Crawl depth (`owasp.py`'s new `_discover_urls()`):** a self-contained,
stdlib-only same-origin BFS crawl (capped at 20 pages/60s) now feeds real
discovered URLs into the 5 existing test functions, instead of only ever
testing the bare domain root. Re-ran against Mutillidae (job
`02c4a9f1-5a9c-427f-944c-881395ee661a`) - `owasp` went from 0 findings to
**12**, including a genuine **Critical** path traversal hit (`/etc/passwd`
via the `page` parameter) reproduced across two different crawled pages,
plus SQLi and reflected XSS - all via Mutillidae's `page=`/`do=` navigation
parameters, exactly the gap identified earlier in this document. Confirmed
the findings span multiple distinct URLs, not repeated homepage hits.

**Authenticated scanning:** `ScanRequest.auth` (optional, form-based login
only) flows through Redis (`tasks/auth_store.py`, keyed by `scan_id`, never
a Celery task arg - Celery logs task args in plaintext at INFO level, this
was confirmed and deliberately avoided) rather than ever touching the `Scan`
Postgres row or a task argument. `owasp.py`'s `_make_session()` logs in once
before crawling/testing; `webscan.py`'s `_run_zap()` sets up a ZAP context/
forced-user for the same purpose.

- **`owasp.py`'s side: confirmed working.** Re-ran against DVWA (job
  `56861a5a-0f43-41d4-96da-615102df2022`) with real credentials -
  `finding_count` went from the 0 documented throughout this entire phase to
  **1** (a SQLi hit via the `page` parameter), on a target that was
  previously 100% behind `/login`. Verified the full credential lifecycle:
  present in Redis during the run (`redis-cli GET scan_auth:{id}`), zero
  occurrences of the literal password anywhere in worker logs, and gone from
  Redis after `_finalize()` completes.
- **A real bug found and fixed mid-verification:** the first login attempt
  against DVWA silently failed (redirected back to the login page, no
  error) even with correct credentials. Root cause: DVWA's login form has a
  CSRF token (`user_token`) *and* requires its submit button's own
  `Login=Login` field to be present server-side - a naive username/password-
  only POST satisfies neither. Fixed by having `_make_session()` fetch the
  login page first and submit every field already on the form
  (`_FormFieldExtractor`, stdlib `html.parser`), with username/password
  overridden to the configured values - this submits "what a browser would"
  rather than special-casing known CSRF field names, and incidentally also
  covers NodeGoat's `_csrf` field the same way (checked NodeGoat's actual
  login form HTML directly; not yet scanned end-to-end - DVWA's result was
  sufficient to verify the mechanism).
- **`webscan.py`/ZAP's side: fixed, and confirmed fully working end-to-end.**
  The simpler `formBasedAuthentication` config was confirmed not to work
  (proxying a request through ZAP with forced-user mode enabled still
  returned DVWA's login form) - it only sends a static username/password
  template with no mechanism for a submit-button field or fresh CSRF token.
  Replaced with ZAP **script-based authentication**: a new
  `zap-scripts/vapt_form_auth.js`, mounted read-only into the `zap` service,
  mirroring `owasp.py`'s own `_make_session()`/`_FormFieldExtractor` logic in
  JavaScript (GET the login page fresh, submit every field on the form with
  username/password overridden). Loaded via `zap.script.load()` and wired in
  as `scriptBasedAuthentication`.

  This surfaced a second, much harder bug: even with the script working
  correctly (confirmed via direct, isolated calls), real scans still hit ZAP's
  own "Insights" self-protective watchdog mid-scan
  (`Shutting down ZAP due to High Level Insight: ... insight.auth.failure :
  100`) - not a crash or OOM (`OOMKilled: false`, `ExitCode: 0` every time),
  a deliberate daemon shutdown. Chased two false leads before finding the
  real cause: (1) reducing spider/active-scan thread concurrency looked like
  a fix in isolated tests but didn't hold up under the real pipeline; (2) the
  actual root cause, found by timing a failure to just ~1 second after
  session creation (far too fast to be 100 genuine failed logins): ZAP was
  checking the configured `logged_in_indicator` regex (`"Logout"`) against
  **every single response** the spider/active-scanner received - including
  CSS/JS/image/redirect/error responses that legitimately never contain that
  text - and counting each non-match as an authentication failure. Fixed by
  never calling `zap.authentication.set_logged_in_indicator()` from
  `webscan.py` at all (confirmed via a direct call to `_run_zap()` with the
  indicator omitted: 95 real findings, zero disconnects). `owasp.py`'s own
  use of the same field is unaffected and stays as-is - it's a one-time,
  best-effort check right after login, not a per-response check ZAP performs
  internally.

  **Final end-to-end verification** (job
  `359f519c-be32-489b-9d96-413ccf971cb8`, full API→Celery pipeline, not a
  direct/isolated call): `webscan` reported `status: 'success'` (not
  `'partial'`) with **108 real findings** from authenticated pages, all 8
  modules succeeded, and ZAP's `RestartCount` did not increase during the
  run.

**ZAP restart pattern - root-caused and closed for the auth-related
instances.** `RestartCount` reached 7 during this investigation (was 4 at
the end of the earlier practicality-test phase) before the
`logged_in_indicator` fix above; it has not increased since. Important
distinction for future reference: this specific `insight.auth.failure`
mechanism only exists in ZAP's daemon when authentication is configured, so
it explains the restarts *during this authenticated-scanning work*
specifically - it does not explain the earlier, still-unresolved restarts
observed during unauthenticated scans (Metasploitable2, Mutillidae,
NodeGoat, see above), where no authentication was configured at all. That
earlier pattern remains open.

**Spot-check beyond DVWA: the pattern holds.** Re-ran authenticated scanning
against both remaining kept targets to confirm the fix generalizes, not just
works for one login form's specific shape.

- **Mutillidae** (job `b5b9c587-1288-4b15-80a4-196759ec3ce6`, `admin`/
  `adminpass` - no CSRF token on this form, structurally different from
  DVWA's): all 8 modules `success`, `RestartCount` unchanged, `webscan` 5773
  raw findings including 3 Critical/8 High, `owasp` 10 findings (1 Critical
  path traversal, SQLi, XSS, open redirects). Mostly overlaps what the
  crawl-depth fix already found unauthenticated, which is expected -
  Mutillidae keeps most content anon-reachable by design - but confirms auth
  doesn't break anything and coexists cleanly with the crawl feature.
- **NodeGoat** (job `559b31db-bc7f-49a4-905c-b9c060f4e12d`, seeded default
  `admin`/`Admin_123` account found in `nodegoat-src/artifacts/db-reset.js`;
  login field is `userName` not `username`; its CSRF token field exists but
  ships with an empty value and isn't actually validated - a real, deliberate
  NodeGoat vulnerability, not a bug in the login flow): all 8 modules
  `success`, `RestartCount` unchanged, `webscan` went from 8 raw findings
  (earlier unauthenticated scan, misconfig-only) to **238**, including
  genuine High-severity **Persistent XSS, Reflected XSS, SQL Injection, Path
  Traversal, External Redirect, and Off-site Redirect** - all previously
  unreachable behind `/login`. `owasp` found 0 here on this first pass (see
  below - fixed in the same session).

Both targets deployed, scanned, and torn down to free disk immediately
after.

---

## IDOR detection added, and a real crawl bug found while building it

Prompted by the NodeGoat spot-check above finding 0 `owasp` results:
NodeGoat's signature vulnerability class is IDOR (`/allocations/:userId` -
confirmed directly in `nodegoat-src/app/routes/allocations.js`, which takes
`userId` from the URL param, not the session; the fix is literally commented
out in the source), and no existing test function looked for it. Added a
6th `test_idor` to `owasp.py`: for any crawled URL with a numeric or MongoDB-
ObjectId-shaped path segment, nudge it to a few nearby values and compare
against the baseline - a 200 response with different, non-"access denied"-
shaped content at the mutated id (same session, so no re-login involved)
means the server handed back a different object without checking the
session is entitled to it. `cvss_scorer.py`/`aggregator.py` already had rules
for `type: 'idor'` waiting for exactly this ("registered so the rule exists
the day a module starts emitting that type" - see Section 4.5) - no scoring
changes needed.

**Verified directly against NodeGoat's real vulnerability first, outside the
tool**, before trusting the detector: logged in as `admin` (seeded `_id: 1`),
fetched `/allocations/1` (own data), then `/allocations/2` (`user1`'s data,
`_id: 2`) with the *same* session - both returned 200 with different,
valid-looking content. Confirmed the exploit is real before building a
detector for it.

**First integration attempt found 0 findings despite this - a real,
separate bug in the crawl, not the detector.** `test_idor` worked correctly
in every isolated/manual test. Tracing why the full `run_owasp()` pipeline
still returned nothing: `_discover_urls`'s same-origin crawl was following
*every* link it found, including NodeGoat's nav-bar `/logout` link - and
`GET /logout` genuinely destroys the session server-side (a common, if not
best-practice, pattern). The crawl was logging its own authenticated session
out in under a second, silently turning every one of the 6 tests (not just
the new IDOR one) into an unauthenticated probe for the rest of the run, no
warning anywhere. Fixed by excluding any link matching a logout/sign-out
pattern before it's ever fetched or recorded - confirmed after the fix that
the session survives the full crawl.

**Final verification, full API->Celery pipeline** (job
`f72a260a-3234-49ce-85e8-7cdd2bc22c92`): all 8 modules `success`, `owasp`
finding_count 2 - the real **IDOR on `/allocations/1`** (High) plus a
genuine open redirect. This closes the caveat from the spot-check above:
NodeGoat's signature vulnerability class is no longer outside this tool's
detection surface.

**Known ceiling of this detector** (documented in `owasp.py`'s own
`# ponytail:` comment): adjacent-id guessing only catches sequential/auto-
increment-shaped ids or ids created moments apart in the same ObjectId
counter window - it won't find anything using genuinely random/UUID-style
identifiers. A real upgrade path (feeding it a second real user's id
instead of guessing) exists but wasn't needed here since NodeGoat's own ids
are plain sequential integers.

---

## Coverage audit: closing the remaining detection gaps for real

After the auth + IDOR work above, an honest audit of every scan run this
whole phase showed 3 modules had never produced a real, non-fallback
signal: **ssl_tls** (every target was plain HTTP - the finding was always
the same "No HTTPS on port 443" line), **tech_fingerprint** (WAFW00F never
saw an actual WAF, and WhatWeb was - unnoticed - completely non-functional),
and **nuclei** (0 findings across every single scan this whole phase,
including Metasploitable2/DVWA/WebGoat/Mutillidae/NodeGoat/Juice Shop).
`recon`'s subfinder/amass/WHOIS/DNS-record logic had also only ever run
against synthetic `.local` Docker aliases, never a real public domain.

### Real bug #1: WhatWeb silently non-functional the entire time

`whatweb --version` on the live worker: `"WhatWeb is not installed and is
missing dependencies... missing gems: addressable"`. The binary was cloned
from source correctly (`backend/Dockerfile`), but its own `Gemfile`
(`ipaddr`, `addressable`, `json`) was never installed - `tech_fingerprint.py`
treats a WhatWeb failure as tolerable partial success (Section 4.3), so this
never surfaced as an error anywhere, just quietly produced nothing useful on
every scan. Fixed: `gem install ipaddr addressable json --no-document`
(plus `build-essential` for native extensions) right after the clone.
Confirmed post-fix: `WhatWeb version 0.6.4`.

### New target: DVWP (WordPress) behind a real WAF+TLS proxy

Added `vavkamil/dvwp` ("Damn Vulnerable WordPress" - real GitHub repo,
active CI, explicit "DO NOT EXPOSE TO INTERNET" self-hosted-only warning)
behind `owasp/modsecurity-crs:nginx-alpine` (official OWASP image, real
ModSecurity + CRS, TLS on :443 with a self-signed cert out of the box).
One target closing three gaps at once: a real TLS handshake, a real WAF,
and DVWP's own genuinely outdated WordPress + vulnerable plugins
(`social-warfare`, `wp-file-upload`, `iwp-client`, `wp-advanced-search`,
`wp-time-capsule`). `dvwp-wordpress` has no plain-HTTP alias of its own -
reachable only through the WAF/TLS proxy (`dvwp.local`), which is the whole
point of the target.

Deploy note: `owasp/modsecurity-crs:nginx-alpine` runs as an unprivileged
user and its own entrypoint hard-rejects `PORT=80`/`SSL_PORT=443` with a
static check unconditioned on actual capabilities - neutralized with
`cap_add: NET_BIND_SERVICE` plus a no-op bind-mounted over that one check
script (needed because `ssl_tls.py` hardcodes checking `domain:443`
directly, so remapping to a high port wasn't an option).

**Scan against `dvwp.local`** (job `437dc1b4-2d52-44e5-8513-eb4919ff89ae`),
all 8 modules `success`:
- **`ssl_tls` - real analysis for the first time**: self-signed certificate
  (High), weak DH parameters at 128 and 192 bits (High) - genuine
  testssl.sh/sslscan output, not the "no HTTPS" fallback.
- **`tech_fingerprint` - real WAF detection for the first time**:
  `wafw00f` → `"WAF detected: Generic"`. WhatWeb's own probe, however, got
  `403 Forbidden` from ModSecurity itself - a real, honest interaction, not
  a bug: the WAF is doing its job blocking a scanner-shaped request, which
  also means active fingerprinting through a WAF is inherently limited.
  Confirmed directly against the unobstructed backend (below) that WhatWeb
  correctly identifies `WordPress[5.3]`/`PHP[7.1.33]` when not blocked.
- **`nuclei` - still 0**, and this trail led to two more real bugs below.

**Control scan, same backend with no WAF in front** (`dvwp-direct.local`
alias added directly to `dvwp-wordpress`, job
`3da4433d-a4cf-45d3-b470-d207774e1703`): `tech_fingerprint` finding_count
16 (up from 8 through the WAF) - confirms the WAF-blocking theory rather
than a WhatWeb regression.

### Real bug #2: nuclei was silently discarding every result, every scan, this whole phase

Manual `nuclei -u http://dvwp-direct.local/` (same template flags as
`nuclei_scan.py`) found real, serious findings in minutes: `CVE-2020-8772`
(Critical, WordPress InfiniteWP auth bypass), `CVE-2024-9047` (Critical,
wp-file-upload arbitrary file read), `CVE-2023-5561` (Medium, WP user email
disclosure), an exposed `/dump.sql` (High - genuine DB dump), `wp-user-enum`
(Low). Yet the tool's own `nuclei_scan.py` pipeline still returned 0 against
the identical target.

Root cause, found by timing the exact same invocation: the curated template
set (`cves/`, `vulnerabilities/`, `misconfiguration/`, `exposed-panels/`,
`technologies/`, `exposures/`) genuinely takes **~550 seconds** end-to-end
at `-rate-limit 20` against even a single host - `_NUCLEI_TIMEOUT` was
**240s**, so `subprocess.run(timeout=240)` was killing nuclei mid-scan on
essentially every real run, not just slow ones. That alone would only lose
the *tail* of the results - but `nuclei_scan.py` used `-json-export` (and,
in one intermediate fix attempt, `-jsonl-export`), and **both dedicated
"export" flags turned out to buffer and write their output file only once
the run completes** - confirmed directly by killing nuclei mid-scan under
each flag and finding the export file didn't exist at all. So every real
finding nuclei had already found before the kill was silently discarded,
every time, for the whole phase.

Fixed at the source: plain `-o <path> -jsonl` (nuclei's normal streaming-
output idiom, as opposed to the post-scan "export" feature) writes each
match to disk the instant it's found - confirmed directly: a real match was
already on disk 30 seconds into a run that `subprocess.run()` would go on to
kill at 240s. Also raised `_NUCLEI_TIMEOUT`/soft/hard limits from
240s/300s/360s to **600s/660s/720s** (measured-550s-plus-margin, same
calibrate-from-real-numbers approach as recon/webscan/enumeration's own
budgets) so the common case doesn't need the streaming fix as a safety net
at all.

**Re-verified through the tool's own real pipeline** (job
`68077306-a921-44a6-a6c9-71c8e82c2ea7`, `dvwp-direct.local`): `nuclei`
finding_count **8** (up from 0), completing in 549.45s - including
`CVE-2020-8772` (Critical) and `CVE-2024-9047` flowing through correctly
end to end. All 8 modules `success`.

### `testphp.vulnweb.com`: recon against a real public domain

Section 8's one pre-approved external target, re-scanned specifically to
exercise `recon`'s subdomain/WHOIS/DNS logic against real internet
infrastructure rather than a synthetic `.local` alias (job
`7232c44c-6e45-4a80-832d-a20609451ce1`, later re-run as
`3a357552-60bc-4d98-87d6-3f74a6260b0c` after the fix below). Real findings
appeared that no Docker-local target could ever produce: an A record
(`44.228.249.3`) and a genuine Google site-verification TXT record.

subfinder/amass/WHOIS produced no findings here - checked directly and
confirmed this is correct, not a bug: `subfinder -d vulnweb.com` (the apex
domain) finds dozens of real subdomains, and `whois testphp.vulnweb.com`
correctly returns "No match" - both subdomain enumeration and WHOIS
operate at the apex-registrable-domain level, and `testphp.vulnweb.com` is
already a specific leaf hostname with nothing further to enumerate beneath
it. Scanning the bare `vulnweb.com` apex was not attempted - Section 8's
authorization names `testphp.vulnweb.com` specifically, not the wider
domain.

### Real bug #3: a soft-timeout that could never do its job, found live against this real target

The first `testphp.vulnweb.com` run exposed a serious, previously-invisible
bug: `owasp` hit its 360s soft time limit, then its 420s hard time limit a
minute later, and the scan hung at `running` for over 20 minutes with no
progress - a live instance of the exact "hard `time_limit` SIGKILL the
orchestrator can't see" gap Section 4.3b already documents, except
triggering on what should have been a routine graceful soft-timeout, not a
genuine runaway.

Root cause: `celery.exceptions.SoftTimeLimitExceeded.__mro__` confirms it's
a plain `Exception` subclass. Every one of `owasp.py`'s 6 test functions
(plus the crawl loop, plus the outer per-URL loop in `run_owasp` itself)
wraps its body in a broad `except Exception as e: logger.debug(...)` -
whichever one happened to be running when Celery raised the signal caught
it, logged a debug line, and let execution carry on to the next URL/test as
if nothing happened, so the signal never reached `run_owasp`'s own
`except SoftTimeLimitExceeded` handler at all. The task ran straight into
the un-catchable hard SIGKILL every time instead of gracefully saving
partial results at the soft limit.

Fixed by adding `except SoftTimeLimitExceeded: raise` before all 8 of those
broad catches, so the signal now always unwinds to `run_owasp`'s own
handler. **Re-verified directly**: same target, same conditions - this time
the soft limit fired and the task returned `status: 'timeout'` **17
milliseconds later**, no hard-limit warning at all (previously: soft and
hard limits fired a full minute apart, then the scan hung for 20+ more
minutes). The scan then correctly paused at `awaiting_user_decision` with
`module_errors: {"owasp": "Module exceeded its soft time limit"}` and
`can_retry: true` - confirmed the full pause/continue/finalize flow (Section
4.3b) end to end by issuing `continue`, which finalized cleanly with the
other 7 modules' real results and the deterministic "1 of 8 scan modules
did not complete successfully" banner.

Separately observed on this same run, not investigated further: `webscan`
reported `status: 'partial'` with `"ZAP became unreachable mid-scan"` - this
is the pre-existing, already-documented, deliberately-deferred ZAP-restart
pattern from earlier in this session (distinct from the auth-specific
`insight.auth.failure` mechanism, which only applies when authentication is
configured), not a new bug introduced by this pass.

### Summary

| Gap | Status |
|---|---|
| `ssl_tls` real TLS analysis | Closed - real findings against DVWP's WAF/TLS proxy |
| `tech_fingerprint` WAF detection | Closed - real `wafw00f` positive hit |
| `tech_fingerprint` CMS detection | Closed - WhatWeb gem fix + confirmed against unobstructed backend |
| `nuclei` real CVE matching | Closed - two real bugs found and fixed (streaming output, timeout budget) |
| `recon` real-domain subdomain/WHOIS/DNS | Closed - real DNS records confirmed against `testphp.vulnweb.com`; subfinder/WHOIS scope correctly bounded to apex domain |
| `owasp` graceful soft-timeout | Closed - real bug found and fixed (SoftTimeLimitExceeded being swallowed) |

DVWP + its WAF/TLS proxy torn down after scanning (containers, images,
vendored `dvwp-src/` clone, ZAP session files) to free disk.

---

## Limitation-fix pass: ZAP resilience, JSON-API login, test coverage

A follow-on "fix every limitation / increase real-life functioning" pass.
Three previously-open items, each verified against a live target.

### ZAP "unreachable mid-scan" - real root cause found (it was never a disconnect)

The pre-existing, long-open pattern where `webscan` reported `partial` with 0
ZAP findings. The live log finally showed the actual cause on the
`testphp.vulnweb.com` run:

```
ZAP active scan status check failed ... invalid literal for int() with base 10: 'does_not_exist'
```

ZAP was perfectly reachable (`RestartCount` never moved, container up for
hours). `zap.ascan.status(ascan_id)` returned the **string** `'does_not_exist'`
because the active scan never validly started - testphp had nothing in ZAP's
scope - so the scan handle was invalid. The old code did `int('does_not_exist')`,
caught the `ValueError` in a generic `except`, and mislabeled a healthy-but-idle
ZAP as "unreachable", discarding everything.

Two distinct failure modes were being conflated; `webscan.py` now separates
them (`_poll_zap_scan` + `_is_zap_scan_id`):
- **status call *raises*** (ConnectionError/timeout) = genuinely unreachable.
  A single one is no longer fatal - ZAP's API blips under active-scan load
  while the daemon is alive. Only `_ZAP_POLL_MAX_CONSECUTIVE_FAILURES` (4) in
  a row, with backoff, concludes it's actually gone.
- **status call *returns a non-numeric string*** (`'does_not_exist'`) =
  reachable ZAP, invalid/absent scan handle. Treated as "this phase produced
  nothing", NOT a disconnect - collect whatever alerts exist and report
  success. The scan handle is also validated up front (`_is_zap_scan_id`) so a
  spider/ascan that can't start is skipped cleanly instead of poisoning the poll.

Verified: `mutillidae.local` unauth webscan → `status: success`; 3 new unit
regression tests (transient blip recovers, sustained failures still report
disconnect, `'does_not_exist'` is not a disconnect). All 23 webscan tests pass.

### JSON-API login (modern SPAs) - full stack

`AuthConfig` gained `login_type: 'form' | 'json'`. JSON mode (`tasks/auth_login.py`,
shared by owasp.py and webscan.py) POSTs credentials as a JSON body, pulls a
bearer token out of the response by dot-path (`token_json_path`, e.g.
`authentication.token`), and sends it as `Authorization: Bearer <token>` -
owasp.py as a `requests.Session` header, ZAP via the **Replacer add-on** (no
auth script/forced-user needed for a static token).

Real bug caught during verification: the Replacer rule is **global** on the
shared ZAP sidecar, so it would leak the token into every later scan. Fixed by
scoping the rule to the target URL (`url=` param) *and* removing it in the
`finally` block (scan-scoped description).

Verified live against **Juice Shop** (`admin@juice-sh.op`, JSON login to
`/rest/user/login`): token extracted through the tool's own code, injection
logged, `webscan` `success` with **577 authenticated findings**, and post-scan
check confirmed **no `vapt-json-auth` rule left in ZAP** (leak fix works).
Frontend `home-form` gained a Form/JSON toggle, field-name overrides, and the
token-path input; `tsc --noEmit` clean. 13 new tests (auth_login + owasp JSON
session + webscan replacer/cleanup). owasp found 0 on Juice Shop - expected,
its non-JS crawler under-reaches an Angular SPA (ZAP covers it), not a regression.

Still out of scope (documented, not half-supported): cookie-only JSON logins
(no token in the body) and JS-rendered login forms.

### Report test coverage restored

The 8 `test_report.py` tests errored at `import pdfplumber` (a test-only dep
never installed). Added `backend/requirements-dev.txt` (pytest + pdfplumber,
kept out of the lean prod image); all 8 now actually parse the generated PDF
and pass.

---

## Full module audit: which finding types have never actually fired, and why

A different kind of pass from everything above: instead of scanning a new
target, every scan ever run (39 completed scans, live Postgres data) was
queried directly for its `module_execution` status and every finding `type`
it ever produced, cross-referenced against every `type_=` string each
scanning module's source can possibly emit. The question wasn't "does the
module run" (already known-yes) but "has every documented detection path
actually fired for real, with real evidence, at least once" - a much
stricter bar. This turned up six real, confirmed, previously-invisible bugs
- all found by reading actual finding evidence text and actual detection/
verification source code, not by re-reading documentation.

### Bug 1 - testssl.sh completely non-functional (two missing packages)

`docker compose exec worker testssl.sh --version` failed with
`Fatal error: You need to install hexdump for this program to work`, then
(after adding that) `...install ps...`. Two Debian packages
(`bsdextrautils`, `procps`) were never installed in `backend/Dockerfile`.
This silently explained **zero `testssl_*` findings across all 39 scans ever
run** - `sslv2/sslv3/tls10/tls11_enabled`, weak ciphers, `cert_expired`/
`expiring_soon`, all sourced from testssl.sh's parsed output, none had ever
fired (the two `ssl_tls` findings that did fire for real, `cert_self_signed`/
`weak_dh_params` on DVWP, came from `sslscan`, a separate tool that works
fine). `ssl_tls.py` treats a testssl.sh failure as tolerable partial output
(same shape as the earlier WhatWeb-gem bug), so this never surfaced.

**Fixed:** added both packages to `backend/Dockerfile`. Confirmed live:
`testssl.sh --fast` against `demo-target.example` now completes end-to-end with a
real SSL-Labs-style grade (A+).

### Bug 1b - testssl.sh still produced nothing after Bug 1's fix, for a second, independent reason

Re-scanning `demo-target.example` after Bug 1's fix still showed `ssl_tls` finishing
in 15s with zero `testssl_*` findings. Manually running the exact
subprocess command `ssl_tls.py` uses reproduced it: testssl.sh printed its
own usage/help text and exited, because `--connect-timeout` **is not a real
flag in this testssl.sh version** (it's `--socket-timeout`). The bad flag
made testssl.sh reject its whole argument list instead of scanning, in
under a second, with no exception raised (`subprocess.run(check=False)`
never inspected the return code) - silently zero findings, every scan,
even after Bug 1 was fixed.

**Fixed:** `--connect-timeout` -> `--socket-timeout` in `ssl_tls.py`'s
`_run_testssl()`, plus a new warning log when testssl.sh exits non-zero
with no JSON output, so a similar silent failure can't hide again.
Confirmed live: the corrected flag produces a real 71-second run with real
JSON findings; re-verified through the full scan pipeline against
`demo-target.example` (job with real `weak_dh_params` etc. already covered above).

### Bug 2 - WHOIS silently returned nothing for every real-world domain

Root cause was **not** what it first looked like. Original hypothesis
(`python-whois`'s `WhoisEntry.load()` lacking a `.in` TLD regex profile) was
directly disproven: fed real WHOIS text through it and the regexes matched
fine. The actual bug was one layer earlier - `whois demo-target.example` inside the
worker returned **empty stdout** with `getaddrinfo(whois.registry.in): Name
or service not known`. That hostname is genuinely dead everywhere (checked
via `strace` on a working host `whois` + direct `nslookup ... 8.8.8.8` -
NXDOMAIN globally, not a container-networking issue). Debian bookworm/main's
`whois` package (5.5.17) ships a **stale hardcoded `.in` TLD-server table**;
NIXI (the `.in` registry) migrated to `whois.nixiregistry.in` after 5.5.17
was packaged - confirmed by comparing `strings $(which whois) | grep
registry.in` between the container (`whois.registry.in`) and a host with a
newer `whois` package (`whois.nixiregistry.in`).

**Fixed:** install `whois` from `bookworm-backports` (5.6.2) instead of
bookworm/main. **No `recon.py` code change needed at all** - the existing
`subprocess(timeout=20)` + `WhoisEntry.load()` pattern (required by
`docs/scanners.md`) was always correct once given real data. Confirmed live
against `demo-target.example`: `whois_registrar` (GoDaddy.com, LLC), `whois_creation_date`,
`whois_expiry` (28 days remaining - a real Medium-severity finding),
`whois_nameservers`, `whois_abuse_contact` all now appear with real data,
first time ever across 13+ scans against this domain.

### Bug 3 - `verify_reflected_xss` built a malformed replay URL

`analysis/verifier.py`'s `_xss_payload_fires()` did
`page.goto(f'{url}?{urlencode(params)}')` - always appending `?params`,
even when `url` already carried its own query string, which it usually
does (a crawled page like Mutillidae's
`index.php?page=home.php&popUpNotificationCode=HPH0`). Confirmed from a
real stored `verification_note`: the actual replayed URL had **two `?`
characters and a duplicated parameter**. Structurally broken before
Chromium even navigated - one of the two reasons `reflected_xss` could
never verify as `confirmed`.

**Fixed:** proper query-string merge (`_merge_url_params`, `urlsplit`/
`parse_qsl`/`urlunsplit`) instead of naive string formatting.

### Bug 4 - the confidence-verification stage had no authentication at all

`analysis/verifier.py` had zero references to auth/cookies/session anywhere
- every verifier replayed with a bare, unauthenticated `requests.get()` /
fresh Chromium navigation. But the original detections for these finding
types, on every target where they'd ever fired (Mutillidae, NodeGoat - both
scanned with auth), ran through `owasp.py`'s authenticated session.
Structurally, any finding discovered behind an authenticated crawl could
never verify - the replay had no session and would hit a login redirect
or a generic response instead.

**Fixed:** `verify_findings()` and every verifier function now accept an
optional `session`; `scan_orchestrator.py`'s `_finalize()` builds one via
`owasp.py`'s `_make_session(auth)` (the auth credential is still in Redis
at Step 6b - only deleted later at Step 9) and threads it through.

**Bugs 3 and 4, confirmed live together** against a real, freshly-detected
reflected-XSS finding on DVWA (`vulnerabilities/xss_r/?name=<script>...`):
the merged replay URL was well-formed (single `?`), and
`verify_reflected_xss(finding, session=<real authenticated session>)`
returned `confidence: 'confirmed'` - **the first time `reflected_xss` has
ever reached `confirmed` in this project's history.**

### Bug 5 - `test_open_redirect` false-positive (found while testing Bug 4, not originally planned)

Every single `open_redirect` finding across the whole project history
(checked: 14/14 on one fresh Mutillidae run) turned out to be the exact
same shape - the app's own `index.php?page=X&next=<value>` "return to this
page" pattern echoing the injected payload back into its own same-site URL,
never actually redirecting there. `owasp.py`'s old check
(`if payload_string in location`) only verified the payload substring
appeared somewhere in the Location header - not that the redirect's actual
destination was external. This is *why* `open_redirect` could never verify
as `confirmed`: there was never a genuine open redirect to reproduce. The
verifier was working correctly the whole time; the detector was wrong.

**Fixed:** `test_open_redirect` now resolves the Location header against
the request URL (`urljoin` + `urlsplit().netloc`) and requires it to
genuinely match the injected external host. New regression test
(`test_open_redirect_same_site_echo_is_not_a_finding`).

### Suspects 5 & 6 (owasp.py's `sqli_error_based` and `error_disclosure`, never fired on any target)

Both had never fired across the whole project history. Root-caused by
hand-testing DVWA's classic SQLi page directly (same "verify outside the
tool before trusting the detector" discipline as the IDOR fix):

- **`sqli_error_based`**: original hypothesis (payload-order early-return
  starving the error-based branch) was checked and found wrong - the
  boolean payload only produces a 205-byte diff on DVWA, below the
  500-byte threshold, so it never short-circuits. The real bug:
  `_get_params()`'s fallback dict for a query-string-less URL
  (`{'id':'1','q':'test','search':'test'}`) doesn't include DVWA's `Submit`
  button field - `isset($_REQUEST['Submit'])` gates the whole page, so
  every injection attempt was silently ignored (200 OK, empty form,
  no error, no evidence anything was tried). Confirmed directly: identical
  request with vs without `Submit=Submit` is the difference between DVWA
  processing the payload and no-op'ing.
- **`error_disclosure`**: the old `resp.status_code == 500 and
  _TRACE_RE.search(...)` gate excluded the far more common real-world case
  - PHP renders `Warning:`/`Parse error:` text (exactly what
  `_TRACE_PATTERNS` targets) inline on a normal 200 OK page by default;
  only an uncaught fatal becomes a 500, and not always even then.

**Fixed:** added `'Submit': 'Submit'` to `_get_params()`'s fallback
(documented as a known ceiling - covers DVWA/bWAPP's convention specifically,
not every app's submit-button name; real upgrade path is extracting actual
`<form>` input names via the existing `_FormFieldExtractor`, same as the
login form already does); dropped `error_disclosure`'s status-code
requirement so the trace-pattern match itself is the signal. New regression
tests for both.

**`sqli_error_based` re-verified through the real full API->Celery
pipeline** (DVWA, authenticated): fired with `confidence: 'confirmed'`
(a module-level definitive signal, no verifier needed) - first time ever.
**`error_disclosure` remains logically fixed and unit-tested but not yet
seen firing live** - this specific DVWA container has `display_errors` off
in PHP, so no currently-available target actually exposes a PHP warning in
its output to prove it. Documented honestly rather than claimed as closed.

### Decision flow: `retry` and `cancel`, driven live for the first time

`continue` had been exercised live once before (the original `owasp`
timeout investigation). `retry` and `cancel` had only ever been
unit-tested. Both driven live this pass:

- **`retry`**, against a real second `owasp` timeout on `testphp.vulnweb.com`
  (recon/webscan/ssl_tls/headers/tech_fingerprint/nuclei/enumeration all
  genuinely `success`, `owasp` genuinely hit its 360s soft limit again -
  this target is just slow, a real, understood, pre-existing condition, not
  a regression): `POST .../decision {"action":"retry"}` correctly
  re-dispatched only `owasp` (`retry_failed_modules` log confirmed), and
  after the retry *also* timed out, `can_retry` correctly flipped to
  `false` (the one-retry-per-module cap). Finalized cleanly with
  `{"action":"continue"}` - `complete`, 7/8 modules, real PDF.
- **`cancel`**, against a hand-built paused scan (`docs/troubleshooting.md`'s
  documented shortcut - a forged `failed`-module envelope fed into
  `aggregate_and_analyse` for a real `Scan` row, no need to wait out a
  genuine failure): `POST .../decision {"action":"cancel"}` correctly set
  `status: 'cancelled'`, no Celery dispatch, and `GET .../report` never
  returns a PDF (`202 {"status":"pending","message":"Scan not yet
  complete"}` - technically matches the documented contract, though a `404`
  might read more precisely for a scan that will never complete; a minor
  API-semantics observation, not a bug).

### Ollama real output, spot-read

`ai_unavailable: false` on the `testphp.vulnweb.com` re-run; read the
actual `executive_summary` text (not just the flag) - genuinely coherent,
correctly-scoped prose ("lacks essential email authentication records...
absence of an HTTPS service... no web application firewall...").

### Accepted, documented-only limitations (not fixed this pass, not silently dropped)

- Naabu's `open_port_naabu` - needs `cap_add: NET_RAW` on the `worker`
  service (a deliberate capability grant, out of scope for a test pass);
  already documented in the project docs §7.
- `headers.py`'s `weak_hsts_max_age`/`csp_unsafe_inline`/`csp_unsafe_eval`/
  `cors_wildcard_with_credentials` and `tech_fingerprint.py`'s
  `waf_unknown` - no tested target happens to have these exact
  header/WAF-response shapes.
- `error_disclosure`'s live confirmation (see above).

### Summary

| Bug | Status |
|---|---|
| testssl.sh missing packages (hexdump, ps) | Fixed, confirmed live |
| testssl.sh bad `--connect-timeout` flag | Fixed, confirmed live |
| WHOIS stale `.in` TLD server table | Fixed, confirmed live |
| `verify_reflected_xss` malformed replay URL | Fixed, confirmed live |
| Verifier stage had no authentication | Fixed, confirmed live |
| `test_open_redirect` false-positive | Fixed, confirmed (regression test) |
| `sqli_error_based` never fired (missing Submit param) | Fixed, confirmed live |
| `error_disclosure` never fired (500-only gate) | Fixed, unit-tested, live confirmation still open |
| Decision-flow `retry`/`cancel` never driven live | Confirmed live |

All self-hosted targets (Mutillidae, DVWA) deployed one at a time, torn
down (container + image) immediately after use per this project's ongoing
disk-space discipline. 410/410 backend tests pass.
