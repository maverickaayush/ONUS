# Changelog

Format loosely follows [Keep a Changelog](https://keepachangelog.com/).

## Unreleased

### Fixed
- Remediation text in the PDF/dashboard could be vague and non-actionable
  for several finding types (e.g. "Review and secure all paths..." with no
  concrete step) - fine for a security specialist, not enough for a
  developer with only basic security knowledge to actually resolve the
  issue, which is this tool's stated audience. `analysis/ollama_client.py`
  now has a `_TYPE_REMEDIATION` template (fixed, numbered, concrete-action
  description + remediation) for every finding type `analysis/
  cvss_scorer.py` can score deterministically - about 80 types across all 8
  scanning modules - instead of falling back to a generic per-OWASP-category
  paragraph or, worse, a "didn't fit any category" placeholder. The
  system prompt sent to Ollama for the remaining open-ended, tool-generated
  types (`zap_*`, `testssl_*`, `nuclei_*`, `nikto_finding` - hundreds of
  distinct checks, infeasible to hand-template) was also tightened to
  require numbered steps naming a specific setting/header/file/command,
  and to explicitly forbid a step that just says "review"/"ensure"/"verify"
  without saying how.
- `backend/tasks/enumeration.py`'s FFUF path-probing and
  `backend/tasks/webscan.py`'s Katana crawl results specifically were
  missing 7 of the above templates (`exposed_admin_panel_denied`,
  `exposed_path_401/403/301/302/201`, `crawled_endpoint_katana`,
  `js_hidden_endpoints`) even though `cvss_scorer.py` already scored them
  correctly - these silently fell through to the generic fallback text.
  Added a regression test (`tests/test_ollama_client.py::
  TestTypeRemediationCompleteness`) that cross-checks every type
  `cvss_scorer.py`'s `_RULES` catalogue can score against
  `_TYPE_REMEDIATION`'s keys, so a future type added to one but not the
  other fails CI instead of shipping silently vague text again.
- `analysis/ollama_client.py`'s total-Ollama-failure fallback
  (`_rule_based_fallback`) hardcoded a generic "AI-generated description
  unavailable" placeholder for every finding's description, discarding the
  perfectly good `_TYPE_REMEDIATION` description a templated finding type
  already has - even though that finding was never going to need Ollama in
  the first place (templated types are excluded from the AI batch entirely).
  Found by replaying real historical scan data (14 distinct targets) through
  the current pipeline: one target's AI batch genuinely exhausted Ollama's
  `num_predict` output budget (see the "Ollama AI Analysis" section in
  `ARCHITECTURE.md`), which surfaced the bug live. Now uses the same
  `_generic_remediation()` call the happy-path "beyond the AI cutoff" case
  already uses - templated types keep their guaranteed-concrete text even
  when Ollama is completely down. The report's "AI analysis unavailable"
  badge is driven by the scan-level `ai_unavailable` flag, not per-finding
  text, so nothing is lost by the change.
- `backend/tasks/ssl_tls.py` let testssl.sh's own `scanTime` housekeeping
  entry (its own "did my scan finish" signal, not a graded vulnerability
  about the target) through as a real "Low"/"Medium" finding. Real bug
  found live against clinkl.in: since it had no remediation template at the
  time, it became the sole input to the AI executive summary on a
  38-finding scan, which then described the whole scan as "a single
  low-severity issue" about an "interruption". Now hardcoded to
  `Informational` and excluded from AI scoring input.
- `frontend/components/vapt/home-form.tsx`'s client-side domain validation
  had drifted from the backend's actual `ScanRequest.validate_domain()` in
  several ways, found by running the same input set through both and
  diffing (47 real-world cases tested, 47/47 now match): `sub.localhost`
  (and any `*.localhost`) passed the client-side gate despite a
  localhost-specific error message existing for exactly that case; three
  RFC 5737 TEST-NET ranges were accepted client-side but rejected by the
  backend, contradicting the code's own "kept in sync" comment; IPv6 was
  not recognized at all (a legitimate public IPv6 target like
  `2606:4700:4700::1111` was rejected as "invalid domain format"); and a
  trailing `:port` or full URL (scheme/path/port, e.g.
  `https://example.com:8080/path`) was rejected client-side even though the
  backend explicitly strips and accepts it. Fixed all four - IPv6 syntax
  parsing is delegated to the platform's own `URL` constructor (via a
  bracketed host) rather than a hand-rolled regex, since IPv6 has too many
  valid compressed/expanded/IPv4-mapped forms to get right by hand.

- `tasks/owasp.py`'s crawler (`_discover_urls`) only ever followed real
  `<a href>`/`<form action>` links, so a target whose homepage navigates
  purely via `<meta http-equiv="refresh">` (a static landing-page shell
  bouncing into the real app) was invisible to every OWASP Top 10 test -
  `discovered` stayed at just the starting URL, and the whole module
  completed in well under a second reporting a clean 0-finding "success"
  with zero real coverage. Found live against oa.iitk.ac.in. Now follows
  meta-refresh redirects too, through the same same-origin/session-
  destroying-link filtering every other discovered URL already goes
  through.
- `requests.get(url, params=X)` appends to a URL's existing query string
  rather than replacing it - a request for `target?q=test` with
  `params={'q': injected}` actually sent both values, and whichever one the
  target server preferred for the duplicate key silently decided whether
  the injection was ever evaluated. Invisible before the meta-refresh fix
  above (the crawler previously only ever re-tested the bare domain root,
  which normally has no query string of its own); now that real discovered
  pages carry their own query strings, `test_sqli`, `test_xss`,
  `test_path_traversal`'s parameter branch, `test_open_redirect`, and
  `test_error_disclosure` all now request a query-free base URL with the
  full corrected param set instead. `analysis/verifier.py` had the same bug
  in its own re-request calls, plus a second variant in its
  `_merge_url_params()` helper (concatenating instead of overriding a
  shared key) - fixed there too, for defense-in-depth independent of what
  a calling module hands it.
- `tasks/owasp.py`'s authenticated-scan login (`_make_session`) had three
  compounding bugs, each found live against a different real external
  target: (1) it POSTed to the configured `login_url` unconditionally
  instead of the login form's own `action` attribute, so a form whose
  action differs from the page hosting it (e.g. `login.jsp` displaying a
  form that posts to `doLogin`) never even reached the real endpoint -
  found against testfire.net (Altoro Mutual); (2) it merged form fields
  from *every* form on the login page into one flat dict, not just the
  login form specifically, so an unrelated form's field (e.g. a search
  box) could leak into the login POST - also found against testfire.net,
  which has a search form above its login form; (3) it always POSTed
  regardless of the form's declared `method`, so a form using
  `method="get"` had its credentials sent as a POST body the server never
  reads as login parameters - found against Google Gruyere, whose login
  form deliberately uses GET as one of its own teaching points. All three
  fixed; verified end-to-end with a genuine successful authenticated login
  against a real, self-registered account on Gruyere.

### Added
- `GET /api/scan/{id}/findings` now includes two optional fields per finding
  that were already computed internally but previously dropped before
  reaching the API response: `confidence` (`"confirmed" | "probable" |
  "unverified"`) and `verification_note` (string, present only on findings a
  verifier actually re-checked). Both are additive and optional - existing
  API consumers are unaffected. See `/docs` (FastAPI/Swagger) for the field
  descriptions, or `ARCHITECTURE.md`'s "Confidence Verification" section for
  the full semantics.
- Authenticated-scan login success/failure was previously invisible outside
  worker logs - a scan configured with credentials that silently failed to
  log in would still report a "clean" result with no indication the
  authenticated tests actually ran as an anonymous visitor.
  `tasks/owasp.py`'s `_make_session` now determines an outcome
  (`confirmed` via an operator-configured `logged_in_indicator`,
  `probable`/`failed` via a best-effort heuristic when no indicator is
  set, or `error` on a request failure) and emits a normal finding for it
  (`auth_login_confirmed`/`auth_login_probable`/`auth_login_failed` -
  Informational for the first two, Medium for a failure, since a silently-
  unauthenticated "authenticated" scan is a materially incomplete result).
  Shows up in the dashboard/PDF report like any other finding - no new UI
  surface needed.
