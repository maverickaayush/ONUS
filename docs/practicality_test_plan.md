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
| 1 | WebGoat (`webgoat/webgoat`) | Next up | Serves under a context path (`/WebGoat`), not root — may need scan-target/path handling to check before assuming bare-domain scanning works cleanly. |
| 2 | bWAPP | Queued | Needs a MySQL sidecar + one-time DB init click-through; no official actively-maintained image, may need a community image. |
| 3 | OWASP Mutillidae II | Queued | Needs a MySQL/MariaDB sidecar. |
| 4 | OWASP NodeGoat | Queued | Needs a MongoDB sidecar. |
| 5 | OWASP Security Shepherd | Queued | Needs a MySQL sidecar; multi-container upstream compose exists to reference. |
| 6 | Rapid7 Hackazon | Queued | Full LAMP + Solr stack; upstream Docker setup should be checked before hand-rolling one. |
| 7 | Metasploitable2 | Queued | Ships as a full vulnerable-OS VM image, not a typical single-service web app container — needs research on a docker-compatible route (or flag as out-of-scope for the docker-compose pattern) before deploying. |
| 8 | OWASP Broken Web Apps (BWA) VM | Queued | Ships as a VirtualBox/VMware VM image, not a Docker image at all — needs a deployment-approach decision (e.g. skip, or run under a VM layer outside docker-compose) before it fits this workflow. |

Targets 7–8 are VM-shaped, not container-shaped — their deploy step may
turn into "document why this doesn't fit the docker-compose pattern" rather
than an actual scan, depending on what's feasible on this hardware.
