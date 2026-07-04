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

_Pending._
