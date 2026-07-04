# Practicality Test Plan — Remaining Self-Hosted Targets

Tracks the rollout of the remaining Section 8 approved self-hostable practice
apps, one at a time. `docs/test_findings.md` holds the actual scan results;
this doc is just the queue and the per-target workflow.

## Workflow (repeat per target)

1. **Deploy** — add/enable the target as a `docker-compose.yml` service
   (own network alias, published port, any DB/sidecar it needs), bring it up,
   confirm it's reachable.
2. **Scan** — submit a scan via `POST /api/scan` against the target's alias,
   poll to completion.
3. **Fix any bugs** — if the scan surfaces a real tool bug (crash, wrong
   schema, module error), fix it before moving on.
4. **Document findings** — append a section to `docs/test_findings.md` in
   the same format as the DVWA/Juice Shop entries (job id, date, target,
   result, risk score, by-module counts, notable gaps).
5. **Remove target** — stop/remove the container + image to free disk
   (service block stays in `docker-compose.yml`, same pattern as DVWA/Juice
   Shop, so it can be redeployed later).
6. **Commit** — one commit per completed target cycle (compose change +
   findings doc update, and any bugfix as its own commit if one was needed).
7. Move to the next target in the queue below.

## Target queue

| # | Target | Status | Notes |
|---|---|---|---|
| 1 | WebGoat (`webgoat/webgoat`) | Done | Needed `WEBGOAT_PORT=80` + `WEBGOAT_CONTEXT=/` + `cap_add: [NET_BIND_SERVICE]` to land at bare root/port 80 — see `docs/test_findings.md`. |
| 2 | bWAPP | Skipped — redundant | Same PHP+MySQL LAMP stack as DVWA with the same login-then-menu gating — expected to hit the same auth-wall problem that already zeroed out `owasp.py` on DVWA, no new module signal. |
| 3 | OWASP Mutillidae II | Queued | Same LAMP stack as DVWA, but several vulnerable pages are reachable without login (anon blog injection point, exposed phpMyAdmin, `includes/` source disclosure) — first real shot at `owasp.py`/webscan hitting a genuine unauthenticated injection instead of just misconfig findings. Needs a MySQL/MariaDB sidecar. |
| 4 | OWASP NodeGoat | Queued | Node.js+Express+MongoDB — untested DB shape (NoSQL) and untested vuln classes (IDOR, SSRF, ReDoS) not seen in any completed scan. Needs a MongoDB sidecar. |
| 5 | OWASP Security Shepherd | Skipped — redundant | Java+JSP+MySQL on Tomcat — stack is a subset of WebGoat (Java/Tomcat) + DVWA (MySQL) combined, and its gamified/scored design implies the same account-gating problem; heaviest upstream setup of the remaining options for no new signal. |
| 6 | Rapid7 Hackazon | Skipped — redundant | Same PHP+MySQL LAMP surface as DVWA/Mutillidae; its distinguishing feature (e-commerce business-logic flaws — price tampering, workflow bypass) isn't something any of the tool's 8 modules test. |
| 7 | Metasploitable2 | Queued | Whole vulnerable OS (vsftpd backdoor, Samba, IRC, Telnet, NFS, etc.), not a single web app — only remaining target that meaningfully exercises `recon` (real multi-service surface) and gives `nuclei_scan` a genuine shot at a CVE hit, both dead across every scan so far. Ships as a full vulnerable-OS VM image, not a typical single-service web app container — needs research on a docker-compatible route before deploying. |
| 8 | OWASP Broken Web Apps (BWA) VM | Skipped — redundant | Confirmed to bundle DVWA, Mutillidae, WebGoat, bWAPP, and Juice Shop into one VM — a repackaging of apps already tested or already decided on individually, plus the heaviest deployment lift (full VM, no Docker image) of anything in the queue. |

Targets 7–8 are VM-shaped, not container-shaped — their deploy step may
turn into "document why this doesn't fit the docker-compose pattern" rather
than an actual scan, depending on what's feasible on this hardware.
