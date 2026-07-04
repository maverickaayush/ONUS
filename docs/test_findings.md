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
Flagging for a possible follow-up (e.g. detecting "many open ports found in
Phase 1" and widening Phase 2a's timeout budget accordingly) rather than
fixing now, since it's a scan-tuning tradeoff against Celery's per-task time
budget, not a bug.

**`nuclei` still at 0** despite the genuinely vulnerable/backdoored services
present (vsftpd 2.3.4, UnrealIRCd) - the curated template subset (Section
4.3.7) doesn't include templates for CVEs this old. Consistent with the
`owasp`/`nuclei` dead-module pattern from every prior target, now confirmed
for a different reason (template curation scope, not an auth wall - `owasp.py`
still hit 0 here too since its 5 test functions target OWASP-Top-10-style web
parameters, not network services).

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
