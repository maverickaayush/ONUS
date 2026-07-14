import json
import logging
from typing import Dict, List, Optional, Tuple

import requests

from config import settings

logger = logging.getLogger(__name__)

# Descriptive-only prompt (verbatim, do not paraphrase or reorder). Ollama no
# longer produces severity/cvss/priority/risk_score - those are computed
# deterministically by analysis/cvss_scorer.py before this module ever runs.
_SYSTEM_PROMPT = (
    "You are a security writer explaining vulnerability findings to a non-technical\n"
    "audience. You will receive a JSON list of vulnerability findings that have\n"
    "already been scored and categorized by a separate system. Your ONLY job is to\n"
    "produce plain-English descriptions and actionable remediation steps.\n"
    "\n"
    "For each finding, produce:\n"
    "- description: 2 to 3 sentences explaining what this vulnerability is in plain\n"
    "  English, as if explaining to a project manager. Avoid jargon; when a\n"
    "  technical term is unavoidable, briefly explain it in the same sentence. Do\n"
    "  NOT mention CVSS scores, severity levels, priority numbers, or any numeric\n"
    "  ratings. Those are handled elsewhere.\n"
    "- remediation: 3 to 5 numbered steps (\"1) ... 2) ...\") a developer should\n"
    "  take to fix this. Each step must name a specific, concrete action -\n"
    "  which setting, header, file, or command to change - not a restatement\n"
    "  of the problem. Never write a step that just says to \"review\",\n"
    "  \"ensure\", or \"verify\" something is secure without also saying exactly\n"
    "  how to check or fix it. Technical language is fine here; the audience\n"
    "  is a developer.\n"
    "\n"
    "If a 'Target environment' block is provided, prefer remediation steps "
    "specific to what it names (the actual server, framework, or WAF) over "
    "generic multi-platform advice - but only where it's actually relevant "
    "to the finding.\n"
    "\n"
    "Also produce:\n"
    "- executive_summary: 3 to 4 sentences overviewing the scan results in plain\n"
    "  English, suitable for a non-technical stakeholder. Mention the target, the\n"
    "  general categories of issues found, and the overall security posture in\n"
    "  qualitative terms. Do NOT invent numbers, counts, or percentages. Base\n"
    "  the overall posture on the full scan totals provided below, not only on\n"
    "  the individual findings listed above them - that list may be a small or\n"
    "  even empty sample of the full scan, so a short list does NOT mean a\n"
    "  clean scan.\n"
    "\n"
    "Return valid JSON only, no markdown, no explanation outside the JSON:\n"
    "{\n"
    '  "executive_summary": "...",\n'
    '  "findings": [\n'
    '    { "finding_id": "...", "description": "...", "remediation": "..." },\n'
    "    ...\n"
    "  ]\n"
    "}"
)

_REQUIRED_KEYS = {'executive_summary', 'findings'}
_MAX_SENT_TO_AI = 50
_JSON_RETRY_ATTEMPTS = 3  # 1 initial attempt + 2 retries, per spec
_OLLAMA_TIMEOUT = round(240 * settings.SCAN_TIMEOUT_MULTIPLIER)  # docs/ai.md baseline, scaled by SCAN_TIMEOUT_MULTIPLIER

# Generic per-category remediation, used whenever a finding doesn't have an
# AI-generated description: either Ollama failed outright (ai_unavailable),
# or the finding was beyond the top-50-by-priority cutoff sent to the model.
_GENERIC_REMEDIATION = {
    'A01:2021 - Broken Access Control': (
        "Something on this site is reachable without the permission checks it "
        "should have - a file, page, or action that should require being "
        "logged in (or logged in as a specific user) can be reached by anyone.",
        "1) Open the URL or evidence for this finding and confirm what it "
        "actually exposes. 2) Add a server-side check that rejects the "
        "request unless the visitor is properly logged in and authorized for "
        "that specific resource (not just logged in as *someone* - as the "
        "*right* someone). 3) If the resource shouldn't be public at all, "
        "remove it or move it outside the web-accessible folder. 4) Re-test "
        "by requesting the URL while logged out (or as a different user) to "
        "confirm it's now blocked.",
    ),
    'A02:2021 - Cryptographic Failures': (
        "This finding is about how the site protects data in transit (its "
        "HTTPS/TLS setup) - an outdated protocol, a weak cipher, or a "
        "certificate problem that weakens or breaks that protection.",
        "1) Open your web server's TLS/SSL configuration file (e.g. Apache's "
        "`ssl.conf`, nginx's `server` block, or your load balancer's TLS "
        "policy). 2) Disable the specific outdated protocol/cipher named in "
        "the evidence, or renew/replace the certificate if that's what's "
        "flagged. 3) Restart the web server and re-run `testssl.sh` or "
        "`sslscan` against the same host to confirm the specific issue is "
        "gone.",
    ),
    'A03:2021 - Injection': (
        "User-supplied input (a form field, URL parameter, or similar) may "
        "reach a part of the application that runs it as a command or query "
        "instead of treating it as plain data - this is how attacks like SQL "
        "injection and cross-site scripting work.",
        "1) Find the exact input field or parameter named in the evidence. "
        "2) If it feeds a database query, switch that query to parameterized "
        "queries/prepared statements (never build SQL by joining strings "
        "together). 3) If it feeds a web page, apply output encoding for the "
        "context it's rendered in (HTML-escape for HTML, JS-escape for "
        "`<script>` blocks). 4) Add server-side input validation (allow-list "
        "expected formats) as a second layer of defense. 5) Re-test the same "
        "input to confirm it's now handled safely.",
    ),
    'A05:2021 - Security Misconfiguration': (
        "This is a configuration gap, not a coding bug - something is set up "
        "in a less secure way than it should be, but no code needs to change "
        "to fix it.",
        "1) Identify the specific header, setting, or directive named in the "
        "evidence. 2) Add or correct it in your web server or application "
        "configuration file (not in application code). 3) Restart/reload the "
        "web server so the change takes effect. 4) Re-run the scan or check "
        "the response headers yourself (e.g. via your browser's dev tools) "
        "to confirm the fix took effect.",
    ),
    'A06:2021 - Vulnerable and Outdated Components': (
        "Software (a framework, library, plugin, or server) running on this "
        "site is on a version with known security fixes it hasn't received "
        "yet, or is past its official end-of-life support date.",
        "1) Identify the exact component and version named in the evidence. "
        "2) Check that component's official site/changelog for the latest "
        "stable version and its security advisories. 3) Upgrade to the latest "
        "supported version in a staging environment first, test that nothing "
        "breaks, then deploy to production. 4) If you can't upgrade "
        "immediately, check whether the vendor publishes a specific patch or "
        "workaround for the known issue.",
    ),
}
_DEFAULT_REMEDIATION = (
    "This finding didn't fit one of the standard categories this tool "
    "recognizes, so no tailored guidance was generated for it - the raw "
    "evidence above is the most reliable source of what was actually found.",
    "1) Read the evidence line for this finding carefully - it shows exactly "
    "what was detected. 2) Search for the finding's title along with your "
    "software/platform name (e.g. \"<finding title> WordPress fix\") to find "
    "guidance specific to your setup. 3) If you're unsure whether this needs "
    "action, treat it as informational unless the evidence shows something "
    "clearly sensitive (credentials, source code, internal paths).",
)

# testssl.sh emits hundreds of distinct, open-ended TLS check ids, so they go to
# the AI pass rather than a per-id template (see _TYPE_REMEDIATION's note). When
# the AI is unavailable, or a testssl finding falls beyond the AI cutoff, this
# is what it lands on instead of the generic default above - genuinely useful,
# plain-language TLS guidance a normal operator can follow, not a "search for a
# WordPress fix" placeholder (the exact gap in a real clinkl.in report).
_TLS_DEFAULT_REMEDIATION = (
    "Your site's HTTPS/TLS configuration has a weakness flagged by the SSL/TLS "
    "scanner - the evidence line above names the exact protocol, cipher, "
    "certificate, or extension involved. Individually most of these are low-to-"
    "medium risk, but together they weaken how safely browsers negotiate a "
    "secure connection to your site.",
    "1) Don't hand-pick individual ciphers - regenerate a known-good config with "
    "the free Mozilla SSL Configuration Generator (ssl-config.mozilla.org): "
    "choose your web server (nginx, Apache, etc.) and the \"Intermediate\" "
    "profile, which disables outdated protocols and weak ciphers and turns on "
    "Forward Secrecy and HSTS for you. 2) Apply the generated config and reload "
    "the server (for example `nginx -t && systemctl reload nginx`). 3) Confirm "
    "your certificate is current and issued by a trusted CA - renew it through "
    "your Let's Encrypt/ACME client if it is close to expiry. 4) Re-test for "
    "free at ssllabs.com/ssltest and aim for grade A; it re-lists anything still "
    "outstanding in plain language with the specific fix.",
)

# Real bug found live (user-reported, against an approved real target -
# clinkl.in): the aggregator's response-fingerprint collapse (>5 paths
# sharing an identical HTTP status+size - typically a WAF/catch-all deny
# page hit by most of the enumeration wordlist) inherits its owasp_category
# from whichever individual finding happened to be the group's first member,
# so it fell into the generic per-category templates above - text written
# for a single distinct vulnerability at one endpoint ("review this endpoint
# for unintended exposure"), not for "N paths all got the same blanket deny
# response." That's actively misleading here: it reads like N separate
# findings needing individual remediation, when the real, useful takeaway is
# the opposite - the target uniformly rejected the probe, which is usually a
# sign the control is *working*, not N misconfigurations.
_COLLAPSE_DESCRIPTION = (
    'This is not {count} separate findings - it means {count} different '
    'probed paths all received the exact same HTTP response (status and '
    'size), which almost always indicates a single catch-all page (a WAF '
    'block page, a custom 404/403, or a login-wall redirect) rather than '
    '{count} distinct exposures. The full list of paths that hit this '
    'response is in the Technical Appendix.'
)
_COLLAPSE_REMEDIATION = (
    'No per-path action is needed for this entry specifically - it exists '
    'to show the enumeration scan was mostly answered by one blanket '
    'response, which is expected behind a WAF or a consistent 403/404 '
    'handler. Check the appendix\'s path list for anything unexpected '
    '(e.g. a sensitive filename that should return a different status), '
    'and confirm the blanket response itself does not leak information '
    '(verbose error pages, stack traces) beyond the status code.'
)


# Every finding type below is "always the same explanation regardless of
# which specific instance was found" - a missing HSTS header means the same
# thing and needs the same fix whether it's example.com or example.org. For
# types like this, a fixed, numbered, plain-English template is more
# reliable than hoping the LLM phrases it well every time (real user report,
# the case that started this table: "Review and secure all paths to ensure
# they are not exposing sensitive files" for a plain exposed_path_200 -
# grammatically fine, told the reader nothing they could actually act on).
# See analyse()'s exclusion of every type in this dict from the batch sent
# to Ollama, so this template is what every scan shows, not a maybe.
# Genuinely per-instance types (zap_*, testssl_*, nuclei_*, nikto_finding -
# open-ended, tool-generated, hundreds of distinct checks) are deliberately
# NOT here and still go through the AI pass; see _SYSTEM_PROMPT instead.
_TYPE_REMEDIATION = {
    # --- enumeration.py ---
    'exposed_sensitive_file': (
        "A file that should never be reachable from the internet - things "
        "like `.env`, `.git/config`, or a database dump - is publicly "
        "accessible. These files routinely contain database passwords, API "
        "keys, or full application source code.",
        "1) Open the URL in the evidence line to confirm exactly what's "
        "exposed. 2) Remove the file from the public web folder immediately "
        "(don't just block access - delete or relocate it, since a copy may "
        "already be cached or indexed). 3) Treat every credential in that "
        "file as compromised - rotate all passwords, API keys, and secrets it "
        "contained, right now, not after investigating further. 4) Add a "
        "server config rule (e.g. deny access to dotfiles) so this class of "
        "file can never be served again, and check your deployment process "
        "for why it ended up in the public folder in the first place.",
    ),
    'exposed_path_200': (
        "A file or folder at this address is publicly viewable by anyone with "
        "the link. That alone isn't necessarily a problem - many pages are "
        "meant to be public - but it's worth a quick check to confirm this "
        "one should be.",
        "1) Open the URL shown in the evidence line yourself and look at what "
        "it actually returns. 2) If it's an ordinary public page (your "
        "homepage, a documented feature, an asset file), no action is needed "
        "- this finding can be ignored. 3) If it shows source code, "
        "configuration values, a directory listing, or anything not meant "
        "for visitors, remove the file or move it outside the public web "
        "folder, or block direct access to it in your web server's "
        "configuration. 4) Re-run the scan afterward to confirm the URL no "
        "longer returns this response.",
    ),
    'exposed_backup_file': (
        "A file that looks like a backup or an old/legacy copy (its name "
        "contains a word like 'backup' or 'old') is publicly accessible. "
        "Backup files often contain source code, credentials, or database "
        "dumps that were never meant to be reachable from the internet.",
        "1) Open the URL in the evidence line to see exactly what it "
        "contains. 2) Delete it from the live web server if it's no longer "
        "needed, or move it outside the public web folder if you need to "
        "keep it. 3) If it contained any passwords, API keys, or database "
        "credentials, rotate them now - the exposure is no longer "
        "theoretical. 4) Make sure your deployment process never copies "
        "backup or old files into the folder your web server serves.",
    ),
    'exposed_admin_panel_login': (
        "An administrative login page was found at this address. A login "
        "screen itself isn't a vulnerability - it's doing its job by asking "
        "for credentials - but being reachable from the public internet "
        "makes it a visible target for password-guessing attempts.",
        "1) Make sure every account that can log in here uses a strong, "
        "unique password, and turn on multi-factor authentication if the "
        "software supports it. 2) If this panel doesn't need to be reachable "
        "from the public internet, restrict access to specific IP addresses "
        "(your office network or a VPN) at the firewall or web server level. "
        "3) Turn on login rate-limiting or account lockout if the software "
        "behind this panel offers it, so repeated password guesses get "
        "blocked automatically.",
    ),
    'exposed_admin_panel_open': (
        "An administrative panel was found at this address, and unlike a "
        "normal admin login, it does not appear to be protected by a login "
        "form at all - meaning anyone who finds this link may be able to use "
        "it directly, with no password required.",
        "1) Visit the URL yourself right away to confirm it truly requires "
        "no login - if it doesn't, treat this as urgent. 2) Add "
        "authentication in front of it immediately (a login page, HTTP basic "
        "auth, or blocking public access via firewall/VPN) until it's "
        "confirmed protected. 3) Check your access logs for this path to see "
        "if anyone else has already used it. 4) Re-scan after fixing it to "
        "confirm the panel now requires authentication.",
    ),
    'exposed_admin_panel_denied': (
        "An administrative panel was found at this address, but it returned "
        "a 401/403 (access denied) response - this is a positive result: "
        "the panel exists but is already rejecting unauthenticated access, "
        "which is exactly what should happen.",
        "No action needed for this entry. Just make sure the accounts that "
        "can actually log in here still use strong, unique passwords and "
        "multi-factor authentication where supported - the access control "
        "is working, but it's only as strong as the credentials behind it.",
    ),
    'exposed_path_401': (
        "A path was probed during directory enumeration and returned a 401 "
        "(Unauthorized) response - this is a positive result: something "
        "exists at this address, but it's already requiring authentication "
        "before showing anything.",
        "No action needed for this entry. It's listed so the report shows "
        "the complete picture of what was probed, not just what was "
        "exposed - access control is doing its job here.",
    ),
    'exposed_path_403': (
        "A path was probed during directory enumeration and returned a 403 "
        "(Forbidden) response - this is a positive result: something exists "
        "at this address, but access to it is already being blocked.",
        "No action needed for this entry. It's listed so the report shows "
        "the complete picture of what was probed, not just what was "
        "exposed - access control is doing its job here.",
    ),
    'exposed_path_301': (
        "A path was probed during directory enumeration and returned a 301 "
        "(permanent redirect) response - this just means the path exists "
        "and forwards visitors elsewhere, not that anything is exposed.",
        "No action needed for this entry unless the redirect destination "
        "surprises you. Open the URL in the evidence line yourself and "
        "confirm it forwards somewhere you expect and intend.",
    ),
    'exposed_path_302': (
        "A path was probed during directory enumeration and returned a 302 "
        "(temporary redirect) response - this just means the path exists "
        "and forwards visitors elsewhere, not that anything is exposed.",
        "No action needed for this entry unless the redirect destination "
        "surprises you. Open the URL in the evidence line yourself and "
        "confirm it forwards somewhere you expect and intend.",
    ),
    'exposed_path_201': (
        "A path was probed during directory enumeration and returned a 201 "
        "(Created) response - an unusual result for a simple probe request, "
        "worth a quick look since it can mean the request itself caused the "
        "server to create something.",
        "1) Open the URL in the evidence line and check what it actually "
        "returns. 2) If the probe request appears to have created a "
        "resource (a file, a record, an account), confirm that's expected "
        "behavior for an unauthenticated GET/HEAD request - if not, that "
        "endpoint needs an authentication check before it accepts requests "
        "that create anything. 3) Clean up any unintended resource the "
        "probe may have created.",
    ),

    # --- headers.py (every one of these runs on every scan) ---
    'missing_hsts': (
        "The site doesn't tell browsers to always use HTTPS for it (a "
        "missing `Strict-Transport-Security` header). Without it, a visitor "
        "who types the site's address without \"https://\" - or clicks an old "
        "http:// link - can be silently downgraded to an insecure connection "
        "an attacker on the same network could intercept.",
        "1) In your web server config (Apache/nginx) or application code, add "
        "the response header `Strict-Transport-Security: max-age=31536000; "
        "includeSubDomains`. 2) Restart/reload the web server. 3) Confirm the "
        "header appears using your browser's dev tools (Network tab) or "
        "`curl -I https://yoursite`. 4) Only add `preload` once you've "
        "confirmed HTTPS works correctly site-wide - it's hard to undo.",
    ),
    'weak_hsts_max_age': (
        "The site does send the `Strict-Transport-Security` header, but its "
        "`max-age` value is set too low - meaning browsers only remember to "
        "force HTTPS for a short time before falling back to the insecure "
        "default.",
        "1) Find where this header is set (web server config or application "
        "code). 2) Increase `max-age` to at least `31536000` (one year), e.g. "
        "`Strict-Transport-Security: max-age=31536000; includeSubDomains`. "
        "3) Restart/reload the web server. 4) Re-check the header value with "
        "`curl -I https://yoursite` to confirm the new value is live.",
    ),
    'hsts_missing_includesubdomains': (
        "The `Strict-Transport-Security` header is present but doesn't "
        "include `includeSubDomains`, so the HTTPS-only protection only "
        "applies to this exact hostname - any subdomain (e.g. `mail.` or "
        "`admin.` in front of it) is left unprotected.",
        "1) Find where the HSTS header is set. 2) Add `includeSubDomains` to "
        "the value, e.g. `Strict-Transport-Security: max-age=31536000; "
        "includeSubDomains`. 3) Before deploying, confirm every subdomain "
        "you control actually supports HTTPS - this setting will break any "
        "subdomain that's still HTTP-only. 4) Restart/reload and re-check "
        "with `curl -I`.",
    ),
    'missing_csp': (
        "The site has no Content-Security-Policy header, which is a browser-"
        "enforced allow-list of where scripts, styles, and other content are "
        "permitted to load from. Without it, if an attacker manages to "
        "inject a malicious script (e.g. via a cross-site scripting bug), "
        "the browser has no extra layer stopping it from running.",
        "1) Start with a reporting-only policy so you can see what would "
        "break before enforcing it: add the header `Content-Security-Policy-"
        "Report-Only: default-src 'self'`. 2) Check your browser console for "
        "violation reports over a few days of normal use and adjust the "
        "policy to allow legitimate sources. 3) Once it's not blocking "
        "anything legitimate, switch to the enforcing header `Content-"
        "Security-Policy` (drop `-Report-Only`). 4) Re-check with your "
        "browser's dev tools that the header is present and scripts still "
        "load correctly.",
    ),
    'csp_unsafe_inline': (
        "A Content-Security-Policy header is present, but it includes "
        "`'unsafe-inline'`, which allows any inline `<script>` tag to run - "
        "this defeats most of what CSP is supposed to prevent, since an "
        "injected inline script would be allowed to execute too.",
        "1) Find the CSP header's `script-src` (or `default-src`) directive "
        "in your web server or application config. 2) Move inline `<script>` "
        "code into separate `.js` files loaded via `<script src=...>`, or "
        "use a per-request nonce (`script-src 'nonce-<random-value>'`) if "
        "inline scripts are unavoidable. 3) Remove `'unsafe-inline'` from the "
        "directive once inline scripts are gone or nonce-protected. 4) Test "
        "the site thoroughly afterward - this is the change most likely to "
        "visibly break something if scripts still rely on being inline.",
    ),
    'csp_unsafe_eval': (
        "The Content-Security-Policy header includes `'unsafe-eval'`, which "
        "allows JavaScript's `eval()` and similar dynamic-code-execution "
        "functions to run - a common way injected malicious code executes.",
        "1) Find the CSP header's `script-src` directive. 2) Search your "
        "codebase (and any third-party libraries) for `eval(`, `new "
        "Function(`, or `setTimeout`/`setInterval` called with a string "
        "argument - these are what require `'unsafe-eval'`. 3) Replace them "
        "with safer equivalents (most modern frameworks don't need `eval` at "
        "all). 4) Remove `'unsafe-eval'` from the CSP directive once nothing "
        "depends on it, and test the site still works.",
    ),
    'missing_clickjacking_protection': (
        "The site doesn't prevent itself from being loaded inside an "
        "invisible `<iframe>` on another attacker-controlled page - a "
        "technique called clickjacking, where a visitor thinks they're "
        "clicking something on the attacker's page but is actually clicking "
        "a button on your site underneath it.",
        "1) Add the response header `X-Frame-Options: DENY` (or `SAMEORIGIN` "
        "if you legitimately need to frame your own pages) in your web "
        "server config. 2) Alternatively/additionally, add a "
        "`Content-Security-Policy` header with `frame-ancestors 'none'` (or "
        "`'self'`), which is the modern replacement for `X-Frame-Options`. "
        "3) Restart/reload the web server. 4) Confirm with `curl -I` that "
        "the header now appears.",
    ),
    'cors_wildcard': (
        "The site's CORS (Cross-Origin Resource Sharing) configuration "
        "allows `Access-Control-Allow-Origin: *`, meaning any website on the "
        "internet can make browser-based requests to this site's API and "
        "read the response.",
        "1) Find where CORS is configured (application code or a middleware/"
        "library setting, not usually the web server itself). 2) Replace the "
        "wildcard `*` with an explicit list of the specific origins that "
        "actually need access (your own frontend's domain, for example). "
        "3) If truly any origin needs read access to this specific endpoint "
        "(a public API), confirm no sensitive per-user data is returned by "
        "it. 4) Restart the application and re-check the header with "
        "`curl -I -H \"Origin: https://example.com\" <url>`.",
    ),
    'cors_wildcard_with_credentials': (
        "The site allows CORS requests from any origin (`Access-Control-"
        "Allow-Origin: *`) *and* allows credentials (cookies/auth headers) to "
        "be sent with those requests. This combination lets any other "
        "website make authenticated requests to this site on a logged-in "
        "visitor's behalf and read the response - a serious, directly "
        "exploitable issue, not just a theoretical one.",
        "1) Find where CORS is configured in your application. 2) Replace "
        "the wildcard origin with an explicit list of trusted origins - "
        "browsers reject wildcard-plus-credentials combinations from working "
        "correctly anyway, so this is also likely a functional bug, not just "
        "a security one. 3) For each trusted origin, reflect it back "
        "specifically in `Access-Control-Allow-Origin` rather than using `*`. "
        "4) Restart the application and re-test that only your intended "
        "origins can make authenticated cross-origin requests.",
    ),
    'server_version_exposed': (
        "The `Server` response header reveals the exact web server software "
        "and version running (e.g. \"Apache/2.4.41\"). This doesn't create a "
        "vulnerability by itself, but it hands an attacker a shortcut to "
        "know exactly which known vulnerabilities to try.",
        "1) In your web server config, turn off detailed version reporting - "
        "for Apache, set `ServerTokens Prod` and `ServerSignature Off` in "
        "`httpd.conf`; for nginx, set `server_tokens off;` in the `http` "
        "block. 2) Restart the web server. 3) Confirm with `curl -I` that "
        "the `Server` header no longer shows a version number.",
    ),
    'x_powered_by_exposed': (
        "The `X-Powered-By` response header reveals the application "
        "framework or language running the site (e.g. \"PHP/8.1\" or "
        "\"Express\"). Like an exposed server version, this hands an "
        "attacker a shortcut to known vulnerabilities for that specific "
        "framework version.",
        "1) Identify your framework's setting for this - for PHP, set "
        "`expose_php = Off` in `php.ini`; for Express.js, call "
        "`app.disable('x-powered-by')`; for ASP.NET, set "
        "`<httpRuntime enableVersionHeader=\"false\" />`. 2) Restart the "
        "application. 3) Confirm with `curl -I` that the header is gone.",
    ),
    'missing_x_content_type_options': (
        "The `X-Content-Type-Options` header is missing, which normally "
        "stops browsers from \"MIME-sniffing\" a response into a different "
        "content type than the server declared - without it, a file "
        "uploaded as an image, for example, could in some cases be "
        "interpreted and executed as a script by the browser.",
        "1) Add the response header `X-Content-Type-Options: nosniff` in "
        "your web server or application config. 2) Restart/reload the web "
        "server. 3) Confirm with `curl -I` that the header is now present.",
    ),
    'missing_referrer_policy': (
        "No `Referrer-Policy` header is set, so the browser falls back to "
        "sending the full originating URL (which can include sensitive query "
        "parameters, session tokens, or internal paths) to every external "
        "site a visitor clicks a link to.",
        "1) Add the response header `Referrer-Policy: strict-origin-when-"
        "cross-origin` (a safe, widely-recommended default) in your web "
        "server or application config. 2) Restart/reload the web server. "
        "3) Confirm with `curl -I` that the header now appears.",
    ),
    'missing_permissions_policy': (
        "No `Permissions-Policy` header is set, so there's no explicit "
        "restriction on which browser features (camera, microphone, "
        "geolocation, etc.) pages on this site are allowed to request access "
        "to - including from any third-party embedded content.",
        "1) Add a `Permissions-Policy` header that disables features your "
        "site doesn't use, e.g. `Permissions-Policy: camera=(), "
        "microphone=(), geolocation=()`. 2) If your site does use one of "
        "these features, list it as `geolocation=(self)` instead of "
        "disabling it. 3) Restart/reload the web server and confirm the "
        "header with `curl -I`.",
    ),
    'insecure_redirect': (
        "A redirect on this site sends visitors to an insecure (`http://`) "
        "destination, or otherwise redirects in a way that drops the secure "
        "connection - undoing HTTPS protection partway through the request.",
        "1) Find the redirect referenced in the evidence line (check your "
        "web server's redirect/rewrite rules or application routing code). "
        "2) Change its destination to the `https://` version of the URL. "
        "3) Restart/reload the web server. 4) Re-test the redirect with "
        "`curl -I <url>` and confirm the `Location` header now points to an "
        "`https://` address.",
    ),
    'cookie_missing_secure': (
        "A cookie is set without the `Secure` flag, meaning the browser is "
        "willing to send it over an unencrypted `http://` connection too - "
        "if a visitor ever ends up on the http:// version of the site "
        "(even briefly, before a redirect), the cookie can be intercepted.",
        "1) Find where this cookie is set in your application code (session/"
        "auth middleware, or a framework config setting). 2) Add the "
        "`Secure` attribute to it, e.g. `Set-Cookie: name=value; Secure`. "
        "3) Restart the application and confirm with your browser's dev "
        "tools (Application/Storage tab) that the cookie now shows `Secure`.",
    ),
    'cookie_missing_httponly': (
        "A cookie is set without the `HttpOnly` flag, meaning JavaScript "
        "running on the page can read it - if the site ever has a cross-"
        "site scripting bug, an injected script could steal this cookie "
        "(commonly a session cookie) directly.",
        "1) Find where this cookie is set in your application code. "
        "2) Add the `HttpOnly` attribute, e.g. `Set-Cookie: name=value; "
        "HttpOnly`. 3) If any of your own JavaScript legitimately reads this "
        "cookie by name, you'll need an alternative (e.g. a separate non-"
        "sensitive value, or an API endpoint) since HttpOnly cookies are "
        "invisible to JavaScript by design. 4) Restart the application and "
        "confirm the flag in your browser's dev tools.",
    ),
    'cookie_missing_samesite': (
        "A cookie is set without a `SameSite` attribute, meaning the browser "
        "may still send it along with requests originating from other "
        "websites - a key ingredient in cross-site request forgery (CSRF) "
        "attacks.",
        "1) Find where this cookie is set in your application code. "
        "2) Add `SameSite=Lax` (a safe default for most cookies) or "
        "`SameSite=Strict` for highly sensitive ones, e.g. `Set-Cookie: "
        "name=value; SameSite=Lax; Secure`. 3) Restart the application and "
        "test that logins/forms still work correctly - `SameSite=Strict` can "
        "occasionally break legitimate cross-site login flows. 4) Confirm "
        "the attribute in your browser's dev tools.",
    ),
    'target_unreachable': (
        "This check could not connect to the target at all, so no header "
        "analysis could be performed - this is a connectivity result, not a "
        "vulnerability finding.",
        "1) Confirm the domain is correct and currently online (try loading "
        "it in a browser). 2) Check whether a firewall, VPN requirement, or "
        "maintenance window is blocking outside connections at the time of "
        "the scan. 3) Re-run the scan once you've confirmed the site is "
        "reachable from the network the scan runs on.",
    ),
    'headers_present_summary': (
        "This lists the security headers that ARE already present and "
        "correctly configured on this target - it's a positive result, not "
        "a problem to fix.",
        "No action needed for this entry. It exists so the report shows a "
        "complete picture of what was checked, not just what's missing - "
        "compare it against the other findings in this report to see which "
        "headers (if any) still need attention.",
    ),

    # --- recon.py ---
    'open_port': (
        "A network port on this host is open and accepting connections. An "
        "open port isn't automatically a problem - it's how any service "
        "(a website, a mail server, etc.) is reached at all - but every open "
        "port is worth confirming you actually intend to expose.",
        "1) Check the port and service name in the evidence line against the "
        "services you actually intend to run publicly. 2) If it's expected "
        "(e.g. port 443 for HTTPS), no action is needed. 3) If it's a service "
        "that should only be reachable internally (databases, admin "
        "interfaces, dev/debug ports), block it at the firewall for external "
        "traffic and only allow specific trusted IP addresses or a VPN. "
        "4) Re-scan afterward to confirm unexpected ports are now closed to "
        "the public internet.",
    ),
    'open_port_naabu': (
        "A network port on this host is open (found via a fast port-scan "
        "pass) and accepting connections. As with any open port, this isn't "
        "automatically a problem - it's worth confirming it's intentional.",
        "1) Check the port number in the evidence line against the services "
        "you actually intend to expose. 2) If expected, no action is needed. "
        "3) If it's an internal-only service (database, admin panel, dev "
        "port), block external access to it at the firewall and restrict it "
        "to specific trusted IP addresses or a VPN. 4) Re-scan to confirm.",
    ),
    'scan_timeout': (
        "The port scan against this host did not finish within its time "
        "budget - this is a scan-methodology note, not a vulnerability. Some "
        "ports may not have been checked.",
        "No action is needed for this entry itself. If you want complete "
        "port coverage, consider re-running the scan when the target and "
        "network path are less congested, or narrowing the scan to specific "
        "ports you care about.",
    ),
    'subdomain_found': (
        "A subdomain of this site was discovered - this is an inventory "
        "result (part of mapping the site's attack surface), not a "
        "vulnerability by itself.",
        "No action is needed for this entry alone. Confirm the subdomain is "
        "one you recognize and still actively maintain - a forgotten "
        "subdomain still pointing at an old, unmaintained service is a "
        "common real risk, so any subdomain you don't recognize is worth "
        "investigating separately.",
    ),
    'live_subdomain': (
        "This discovered subdomain is actively responding to web requests - "
        "an inventory result confirming it's a live, reachable service, not "
        "a vulnerability by itself.",
        "No action is needed for this entry alone. Make sure this subdomain "
        "is included in your regular security scanning and patching routine "
        "- forgotten-but-live subdomains are a common way outdated, "
        "unmaintained services stay exposed without anyone noticing.",
    ),
    'outdated_tech': (
        "Software running on this host (named in the evidence) is on a "
        "version that's outdated or past its official support/end-of-life "
        "date, meaning it may be missing security fixes released after that "
        "version.",
        "1) Identify the exact software and version named in the evidence. "
        "2) Check the vendor's site for the latest supported version and any "
        "security advisories affecting your version specifically. 3) Upgrade "
        "in a staging/test environment first, confirm nothing breaks, then "
        "deploy to production. 4) If immediate upgrade isn't possible, check "
        "whether the vendor offers a specific security patch or documented "
        "workaround for your version.",
    ),
    'whois_registrar': (
        "This shows which registrar the domain is registered through - "
        "public record-keeping information, not a vulnerability.",
        "No action needed. Just confirm this is the registrar you actually "
        "use, as a sanity check against a domain that may have been "
        "transferred without your knowledge.",
    ),
    'whois_creation_date': (
        "This shows when the domain was originally registered - public "
        "record-keeping information, not a vulnerability.",
        "No action needed - informational only.",
    ),
    'whois_nameservers': (
        "This lists the domain's authoritative nameservers - public record-"
        "keeping information, not a vulnerability.",
        "No action needed. Confirm these are the nameservers you actually "
        "manage, as a sanity check against unauthorized DNS changes.",
    ),
    'whois_abuse_contact': (
        "This is the domain's registered abuse-report contact address - "
        "public record-keeping information, not a vulnerability.",
        "No action needed. Worth confirming this address is still monitored "
        "so legitimate abuse reports about your domain actually reach "
        "someone.",
    ),
    'whois_expiry': (
        "This domain's registration is approaching its expiry date. If a "
        "domain expires and isn't renewed in time, it can be re-registered "
        "by anyone else - including an attacker who then controls your "
        "site's identity and any email addresses on that domain.",
        "1) Log in to your domain registrar account now and confirm the "
        "renewal/expiry date shown there matches this finding. 2) Renew the "
        "domain immediately, or confirm auto-renewal is enabled and the "
        "payment method on file is valid. 3) Consider extending the "
        "registration by multiple years and enabling registry lock if your "
        "registrar offers it, to prevent this from recurring.",
    ),
    'dns_a_record': (
        "This is the domain's IPv4 address record - standard DNS "
        "information confirming where the domain points, not a "
        "vulnerability.",
        "No action needed. Confirm the listed IP address is one you "
        "actually control, as a sanity check against unauthorized DNS "
        "changes.",
    ),
    'dns_mx_record': (
        "This lists the domain's mail server(s) - standard DNS information, "
        "not a vulnerability.",
        "No action needed. Confirm these are your actual mail servers, as a "
        "sanity check against unauthorized DNS changes.",
    ),
    'dns_txt_record': (
        "This shows a DNS TXT record on the domain (often used for domain "
        "verification, SPF, or similar) - standard DNS information, not a "
        "vulnerability by itself.",
        "No action needed unless the content looks unfamiliar to you, in "
        "which case confirm who added it and why.",
    ),
    'dns_ns_record': (
        "This lists the domain's nameservers as seen in DNS - standard "
        "information, not a vulnerability.",
        "No action needed. Confirm these match the nameservers you actually "
        "manage.",
    ),
    'dns_cname_record': (
        "This shows a CNAME (alias) record on the domain - standard DNS "
        "information, not a vulnerability by itself.",
        "No action needed unless it points somewhere unfamiliar, in which "
        "case confirm who set it up. A CNAME pointing at a decommissioned "
        "third-party service (an unclaimed cloud storage bucket, an old "
        "SaaS account) is a known real risk worth checking specifically.",
    ),
    'missing_spf': (
        "This domain has no SPF (Sender Policy Framework) DNS record, which "
        "normally tells receiving mail servers which servers are allowed to "
        "send email claiming to be from this domain. Without it, it's "
        "easier for attackers to send forged/spoofed email that appears to "
        "come from you.",
        "1) List every mail server and service that legitimately sends email "
        "on your domain's behalf (your mail provider, marketing tools, "
        "etc.). 2) Add a TXT record at your domain's DNS: `v=spf1 "
        "include:_spf.yourmailprovider.com ~all` (replace with your actual "
        "provider(s)). 3) Use an online SPF checker to validate the record's "
        "syntax. 4) Wait for DNS to propagate (up to 24-48 hours) and "
        "re-check.",
    ),
    'missing_dmarc': (
        "This domain has no DMARC DNS record, which normally tells "
        "receiving mail servers what to do with email that fails SPF/DKIM "
        "checks (reject it, quarantine it, or allow it) and where to send "
        "reports about spoofing attempts. Without it, forged email "
        "impersonating your domain is more likely to reach recipients.",
        "1) Add a TXT record at `_dmarc.yourdomain.com`: start with "
        "`v=DMARC1; p=none; rua=mailto:you@yourdomain.com` (monitor-only "
        "mode first, so you see reports without blocking any real mail). "
        "2) Review the reports you receive over a few weeks to confirm all "
        "your legitimate mail sources pass. 3) Once confident, tighten the "
        "policy to `p=quarantine` and eventually `p=reject`.",
    ),
    'missing_dkim': (
        "No DKIM (DomainKeys Identified Mail) record was found under the "
        "common selector names this scan checked. DKIM lets receiving mail "
        "servers cryptographically verify that an email genuinely came from "
        "your domain and wasn't altered in transit.",
        "1) Check your email provider's admin panel for DKIM setup "
        "instructions (most major providers - Google Workspace, Microsoft "
        "365, etc. - generate the key for you). 2) Add the TXT record it "
        "gives you at the specified selector (e.g. "
        "`selector._domainkey.yourdomain.com`). 3) Enable DKIM signing in "
        "your mail provider's settings. 4) Send a test email to a service "
        "like mail-tester.com to confirm DKIM now passes.",
    ),

    # --- ssl_tls.py (non-testssl_* checks - the fixed protocol/cert types) ---
    'no_https': (
        "This site doesn't offer HTTPS at all - every visitor's connection "
        "to it is unencrypted, meaning anything they send (including "
        "passwords or form data) can potentially be read or altered by "
        "anyone on the same network path.",
        "1) Get a TLS certificate for the domain - Let's Encrypt "
        "(letsencrypt.org) provides one free, and most hosting providers can "
        "issue and renew it automatically. 2) Configure your web server to "
        "listen on port 443 with that certificate. 3) Redirect all http:// "
        "traffic to https://. 4) Add the `Strict-Transport-Security` header "
        "once HTTPS is confirmed working site-wide.",
    ),
    'cert_expired': (
        "This site's TLS/SSL certificate has already expired. Browsers will "
        "show visitors a hard security warning (and many will simply leave) "
        "until it's renewed.",
        "1) Log in to wherever the certificate was issued (your hosting "
        "provider, Let's Encrypt, or your certificate authority). 2) Renew "
        "the certificate immediately - this is urgent since visitors are "
        "actively seeing warnings right now. 3) Install the renewed "
        "certificate on your web server and restart it. 4) Set up "
        "auto-renewal (e.g. certbot's automatic renewal) so this doesn't "
        "happen again.",
    ),
    'cert_expiring_soon': (
        "This site's TLS/SSL certificate is still valid but will expire "
        "soon. If it lapses, visitors will start seeing security warnings "
        "and many will leave the site.",
        "1) Renew the certificate now, before it expires - don't wait for "
        "the deadline. 2) Install the renewed certificate and restart the "
        "web server. 3) Set up automatic renewal (e.g. `certbot renew` on a "
        "scheduled job) so future certificates renew themselves well before "
        "expiry.",
    ),
    'cert_self_signed': (
        "This site's TLS/SSL certificate is self-signed rather than issued "
        "by a trusted certificate authority. Browsers will show visitors a "
        "security warning because they have no way to verify a self-signed "
        "certificate's authenticity.",
        "1) Get a certificate from a trusted certificate authority instead - "
        "Let's Encrypt (letsencrypt.org) is free and widely trusted. "
        "2) Install it on your web server in place of the self-signed one. "
        "3) Restart the web server and confirm in a browser that the "
        "warning is gone. 4) Set up auto-renewal so it doesn't lapse later.",
    ),
    'sslv2_enabled': (
        "This server still accepts SSLv2 connections. SSLv2 is a decades-old "
        "protocol with well-known, practically exploitable flaws - modern "
        "clients don't need it, and its presence is a real weakness, not "
        "just an outdated setting.",
        "1) Open your web server's TLS configuration (Apache's `ssl.conf`, "
        "nginx's `ssl_protocols` directive, or your load balancer's TLS "
        "policy). 2) Explicitly disable SSLv2 (e.g. nginx: "
        "`ssl_protocols TLSv1.2 TLSv1.3;` which excludes it by omission). "
        "3) Restart the web server. 4) Re-run `testssl.sh` or `sslscan` "
        "against the same host to confirm SSLv2 is no longer accepted.",
    ),
    'sslv3_enabled': (
        "This server still accepts SSLv3 connections. SSLv3 is vulnerable to "
        "the POODLE attack and is considered broken - modern clients don't "
        "need it.",
        "1) Open your web server's TLS configuration. 2) Explicitly disable "
        "SSLv3 (e.g. nginx: `ssl_protocols TLSv1.2 TLSv1.3;`). 3) Restart "
        "the web server. 4) Re-run `testssl.sh` or `sslscan` to confirm "
        "SSLv3 is no longer accepted.",
    ),
    'tls10_enabled': (
        "This server still accepts TLS 1.0 connections. TLS 1.0 is an "
        "outdated protocol version with known weaknesses and is being "
        "phased out industry-wide (major browsers and payment standards no "
        "longer support it).",
        "1) Open your web server's TLS configuration. 2) Set the minimum "
        "supported protocol to TLS 1.2, e.g. nginx: `ssl_protocols TLSv1.2 "
        "TLSv1.3;`. 3) Restart the web server. 4) Re-run `testssl.sh` to "
        "confirm TLS 1.0 is no longer accepted, and check your site still "
        "works for your actual visitor base (very old browsers may lose "
        "access, which is expected).",
    ),
    'tls11_enabled': (
        "This server still accepts TLS 1.1 connections. Like TLS 1.0, this "
        "is an outdated protocol version being phased out industry-wide.",
        "1) Open your web server's TLS configuration. 2) Set the minimum "
        "supported protocol to TLS 1.2, e.g. nginx: `ssl_protocols TLSv1.2 "
        "TLSv1.3;`. 3) Restart the web server. 4) Re-run `testssl.sh` to "
        "confirm TLS 1.1 is no longer accepted.",
    ),
    'weak_cipher_rc4': (
        "This server still offers the RC4 cipher, which has known "
        "cryptographic weaknesses that can allow an attacker to recover "
        "parts of encrypted data.",
        "1) Open your web server's TLS cipher configuration. 2) Remove RC4 "
        "from the allowed cipher list (e.g. nginx: set `ssl_ciphers` to a "
        "modern list such as Mozilla's \"Intermediate\" configuration, which "
        "excludes RC4). 3) Restart the web server. 4) Re-run `testssl.sh` to "
        "confirm RC4 is no longer offered.",
    ),
    'weak_cipher_des': (
        "This server still offers DES or 3DES ciphers, which use a small "
        "enough key/block size to be practically breakable with modern "
        "computing power (the Sweet32 attack targets exactly this).",
        "1) Open your web server's TLS cipher configuration. 2) Remove DES/"
        "3DES from the allowed cipher list, e.g. nginx: set `ssl_ciphers` to "
        "a modern list such as Mozilla's \"Intermediate\" configuration. "
        "3) Restart the web server. 4) Re-run `testssl.sh` to confirm DES/"
        "3DES ciphers are no longer offered.",
    ),
    'weak_cipher_bits': (
        "This server offers a cipher with a weak key length (evidence shows "
        "the specific bit size), which is crackable with enough computing "
        "power in a realistic timeframe.",
        "1) Open your web server's TLS cipher configuration. 2) Replace the "
        "cipher list with a modern, strong-only configuration (e.g. "
        "Mozilla's \"Intermediate\" or \"Modern\" cipher configuration "
        "generator at ssl-config.mozilla.org). 3) Restart the web server. "
        "4) Re-run `testssl.sh` to confirm only strong ciphers are offered.",
    ),
    'weak_dh_params': (
        "This server uses a Diffie-Hellman key-exchange parameter with a "
        "weak bit size (shown in the evidence), which weakens the "
        "cryptographic strength of the key exchange and can make certain "
        "attacks (like Logjam) more feasible.",
        "1) Generate a strong DH parameter file: `openssl dhparam -out "
        "dhparams.pem 2048` (or 4096 for extra margin). 2) Point your web "
        "server's TLS config at the new file (e.g. nginx: `ssl_dhparam "
        "/path/to/dhparams.pem;`). 3) Restart the web server. 4) Re-run "
        "`testssl.sh` to confirm the DH parameter size is now adequate.",
    ),
    'testssl_scanTime': (
        "This isn't a vulnerability in the target - it's testssl.sh (the "
        "scanning tool itself) reporting that its TLS scan against this "
        "host didn't run to completion, usually from a network blip, rate-"
        "limiting, or the target closing the connection mid-scan. Some TLS/"
        "cipher checks elsewhere in this report may be incomplete as a "
        "result.",
        "No action is needed on the target for this entry itself. If you "
        "want complete TLS/cipher coverage, re-run the scan - a transient "
        "network issue during the original run is the most common cause "
        "and often doesn't repeat.",
    ),

    # --- tech_fingerprint.py ---
    'tech_detected': (
        "This identifies a specific technology, framework, or platform this "
        "site runs on (shown in the evidence) - an inventory result, not a "
        "vulnerability by itself.",
        "No action is needed for this entry alone. Cross-check the version "
        "shown (if any) against the vendor's current release and security "
        "advisories - if it's outdated, that will also appear as a separate "
        "'outdated software' finding in this report with its own guidance.",
    ),
    'waf_detected': (
        "A Web Application Firewall (WAF) was detected in front of this "
        "site (named in the evidence) - this is a positive result, meaning "
        "there's an extra layer of protection filtering malicious traffic "
        "before it reaches the application.",
        "No action needed - this finding confirms protection is in place. "
        "Keep in mind a WAF reduces risk but doesn't replace fixing the "
        "underlying issues found elsewhere in this report; treat it as "
        "defense-in-depth, not a substitute for patching.",
    ),
    'waf_unknown': (
        "A Web Application Firewall (WAF) appears to be present, but its "
        "specific product/vendor couldn't be identified - still a broadly "
        "positive result (some filtering protection exists), just less "
        "specific.",
        "No action needed. If you know which WAF you actually run, no "
        "further investigation is necessary - this is just a detection "
        "limitation, not a gap in your protection.",
    ),
    'no_waf_detected': (
        "No Web Application Firewall was detected in front of this site. "
        "This isn't automatically a problem - many secure sites run "
        "without one - but it means there's no extra filtering layer "
        "catching malicious requests before they reach the application "
        "itself, so the application's own defenses matter more.",
        "1) If you don't already have one, consider putting a WAF or a "
        "reverse-proxy-based filtering service in front of the site "
        "(options range from free/open-source like ModSecurity to managed "
        "services from most CDN providers). 2) Whether or not you add a "
        "WAF, make sure the specific vulnerabilities in this report are "
        "fixed directly - a WAF is a second layer, not a fix for the "
        "underlying issues.",
    ),

    # --- owasp.py ---
    'sqli_error_based': (
        "A database error message was triggered by sending unexpected input "
        "to a parameter (shown in the evidence), and the site displayed "
        "database-specific error text back - a strong, confirmed sign that "
        "attacker-controlled input reaches a SQL query without being safely "
        "handled first (SQL injection).",
        "1) Find the exact parameter/field named in the evidence in your "
        "application code. 2) Rewrite the query that uses it to a "
        "parameterized query or prepared statement (never build SQL by "
        "concatenating strings together, even with escaping). 3) Turn off "
        "detailed database error messages in production so errors are never "
        "shown to visitors. 4) Re-test the same parameter with the same "
        "input to confirm no database error appears anymore.",
    ),
    'sqli_boolean_based': (
        "The page responded differently to two inputs that only differ in "
        "their true/false database logic (shown in the evidence) - a sign "
        "that attacker-controlled input reaches a SQL query and can "
        "influence its logic, even without a visible error message (SQL "
        "injection).",
        "1) Find the exact parameter/field named in the evidence in your "
        "application code. 2) Rewrite the query that uses it to a "
        "parameterized query or prepared statement. 3) Add server-side "
        "input validation (e.g. enforce that a numeric ID field only "
        "accepts numbers) as a second layer of defense. 4) Re-test with the "
        "same two inputs from the evidence and confirm the responses are "
        "now identical.",
    ),
    'reflected_xss': (
        "Input submitted in a request (shown in the evidence) was echoed "
        "back into the page in a way that would let injected JavaScript "
        "run in another visitor's browser - if an attacker tricks someone "
        "into clicking a crafted link, code could execute as if it were "
        "part of this site (reflected cross-site scripting).",
        "1) Find the exact parameter named in the evidence in your "
        "application code. 2) Apply output encoding appropriate to where "
        "it's rendered (HTML-escape for HTML body content, JavaScript-"
        "escape if it's placed inside a `<script>` block, URL-encode if "
        "placed in a URL). 3) Add a Content-Security-Policy header "
        "(`script-src 'self'`) as a second layer of defense - see this "
        "report's CSP-related findings if present. 4) Re-test the same "
        "input and confirm it's now displayed as plain text, not executed.",
    ),
    'path_traversal': (
        "A request using `../` (or similar) sequences (shown in the "
        "evidence) was able to access a file outside the folder it should "
        "have been restricted to - meaning an attacker may be able to read "
        "arbitrary files on the server, including configuration files or "
        "source code.",
        "1) Find the exact file-handling code path named in the evidence. "
        "2) Never build a file path directly from user input - instead, "
        "validate the requested filename against an allow-list of what's "
        "actually permitted, and reject anything containing `../` or "
        "similar sequences outright. 3) Additionally, ensure the web "
        "server process's file-system permissions don't allow it to read "
        "sensitive files even if a traversal did occur. 4) Re-test the "
        "same request and confirm it's now rejected.",
    ),
    'open_redirect': (
        "This site will redirect a visitor to an external URL supplied in "
        "the request itself (shown in the evidence), rather than only to "
        "URLs it controls - attackers can abuse this to craft a link that "
        "looks like it points at this trusted site but actually sends "
        "visitors to a phishing page.",
        "1) Find the redirect logic named in the evidence in your "
        "application code. 2) Replace free-form redirect targets with an "
        "allow-list of specific permitted destinations (or internal page "
        "identifiers rather than raw URLs). 3) If external redirects are "
        "genuinely needed, show an interstitial \"you are leaving this "
        "site\" warning page instead of redirecting silently. 4) Re-test the "
        "same request with a different external URL and confirm it's now "
        "rejected or warned about.",
    ),
    'error_disclosure': (
        "The site returned a detailed technical error message (a stack "
        "trace, database error, or internal file path, shown in the "
        "evidence) instead of a generic error page - this can hand an "
        "attacker useful details about your technology stack, file "
        "structure, or database schema.",
        "1) Find your application framework's error-handling/debug-mode "
        "setting (e.g. Django's `DEBUG = False`, Laravel's `APP_DEBUG=false`, "
        "Flask's `debug=False`) and confirm it's off in production. "
        "2) Configure a generic custom error page to show instead. 3) Make "
        "sure detailed errors still get logged somewhere you can see them "
        "(just not shown to visitors). 4) Re-trigger the same error and "
        "confirm only the generic page is shown now.",
    ),
    'idor': (
        "Changing an ID or reference number in a request (shown in the "
        "evidence) returned another user's or record's data, without any "
        "authorization check confirming the requester should be allowed to "
        "see it - an Insecure Direct Object Reference.",
        "1) Find the endpoint named in the evidence in your application "
        "code. 2) Add a server-side check on every request that confirms "
        "the logged-in user actually owns or has permission to access the "
        "specific record being requested - not just that they're logged in "
        "at all. 3) Consider using non-guessable identifiers (random tokens/"
        "UUIDs instead of sequential numbers) as a second layer of defense, "
        "though the authorization check is the real fix. 4) Re-test with a "
        "different ID belonging to another user/record and confirm access "
        "is now denied.",
    ),
    'auth_login_confirmed': (
        "This scan was configured to log in before testing, and the login "
        "was confirmed to work - the operator-provided \"logged in\" check "
        "matched the response after submitting credentials, so the "
        "authenticated tests in this report ran against real, logged-in "
        "content as intended.",
        "No action needed - this confirms the scan's authenticated tests "
        "actually ran as configured. If findings behind login were expected "
        "but are missing from this report, that reflects the application's "
        "actual state, not a scanning gap.",
    ),
    'auth_login_probable': (
        "This scan was configured to log in before testing, and the login "
        "response no longer showed a login form - a reasonable but "
        "unconfirmed sign that it worked, since no explicit \"logged in\" "
        "check was configured to verify it directly.",
        "1) Identify a piece of text or element that only appears after a "
        "real successful login on this application (e.g. \"Welcome back\", "
        "\"Log out\", an account name). 2) Set that as the scan's "
        "logged_in_indicator so future scans confirm login instead of "
        "guessing. 3) Re-run the scan and confirm this finding upgrades to "
        "a definite \"login confirmed\" result.",
    ),
    'auth_login_failed': (
        "This scan was configured to log in before testing, but the login "
        "did not succeed (either an explicit \"logged in\" check failed to "
        "match, the response still showed a login form, or the login "
        "request itself errored - see the evidence for which). Every "
        "\"authenticated\" test in this report therefore actually ran "
        "against the site as an anonymous visitor, so findings that only "
        "exist behind a login were not tested at all.",
        "1) Check the evidence for the specific reason (wrong credentials, "
        "a changed login form, an unexpected redirect, or a network/"
        "timeout error). 2) Manually log in to the application with the "
        "configured username/password to confirm the credentials "
        "themselves are still valid. 3) If the login form uses a CSRF "
        "token or extra hidden fields, confirm the scan's login_url points "
        "at the page that actually hosts the login form, not a different "
        "page. 4) Re-run the scan and confirm this finding upgrades to a "
        "confirmed or probable login before trusting any \"clean\" result "
        "on authenticated content.",
    ),

    # --- webscan.py (katana) ---
    'crawled_endpoint_katana': (
        "A page or API endpoint was discovered by the JavaScript-aware "
        "crawler (Katana) while mapping this site's structure - an "
        "inventory result confirming the endpoint exists, not a "
        "vulnerability by itself.",
        "No action is needed for this entry alone. If it's an endpoint you "
        "don't recognize as part of your intended application, investigate "
        "separately - an unexpected endpoint can indicate leftover debug/"
        "admin routes, or a route another finding in this report already "
        "flags with its own guidance.",
    ),
    'js_hidden_endpoints': (
        "One or more pages/endpoints were only reachable by following "
        "JavaScript-driven navigation (shown by the Katana crawler), and "
        "were not found by the standard HTML-spider crawl that fed this "
        "scan's active vulnerability tests - meaning these routes may not "
        "have actually been tested for the vulnerabilities checked "
        "elsewhere in this report.",
        "1) Open the evidence/appendix list of routes for this finding. "
        "2) Manually browse to each one and confirm what it does and who "
        "should be able to reach it. 3) If your scanning setup allows "
        "manually seeding extra URLs into its scope (most active scanners, "
        "including ZAP, do), add these specific routes so they get the same "
        "vulnerability testing as the rest of the site on the next scan.",
    ),
}


def _generic_remediation(finding: dict) -> Tuple[str, str]:
    matched_paths = (finding.get('details') or {}).get('matched_paths')
    if matched_paths:
        count = len(matched_paths)
        return (_COLLAPSE_DESCRIPTION.format(count=count), _COLLAPSE_REMEDIATION)
    type_template = _TYPE_REMEDIATION.get(finding.get('type', ''))
    if type_template:
        return type_template
    # TLS/SSL findings (testssl.sh, open-ended ids) get a security-appropriate
    # default rather than the generic "search for a WordPress fix" one.
    if str(finding.get('type', '')).startswith('testssl_') or finding.get('module') == 'ssl_tls':
        return _TLS_DEFAULT_REMEDIATION
    category = finding.get('owasp_category', '')
    return _GENERIC_REMEDIATION.get(category, _DEFAULT_REMEDIATION)


# Deterministic (no AI) target-environment summary, built from the same
# tech_fingerprint.py/headers.py findings that are themselves templated (and
# so never reach the AI batch) - decouples "who writes this finding's own
# remediation" from "this finding's data can still inform other findings'
# remediation". Kept to a handful of fields so it costs ~nothing against the
# 8192-token context budget even though it's prepended once per batch.
_MAX_PROFILE_TECHNOLOGIES = 5

# WhatWeb plugin names that identify response *metadata*, not a technology -
# excluded so the profile isn't padded with noise. Found live: regenerating
# real oa.iitk.ac.in/clinkl.in scans surfaced "Country"/"IP"/
# "Meta-Refresh-Redirect" filling the technologies list ahead of anything
# actually useful.
_NON_TECH_WHATWEB_PLUGINS = {
    'Country', 'IP', 'RedirectLocation', 'Meta-Refresh-Redirect', 'Title',
    'UncommonHeaders', 'Strict-Transport-Security', 'Cookies', 'Email',
    'HttpOnly', 'Script', 'X-Frame-Options', 'Content-Security-Policy',
    'X-XSS-Protection', 'X-Content-Type-Options', 'Access-Control-Allow-Origin',
}


def _whatweb_technology_label(finding: dict) -> Optional[str]:
    """
    WhatWeb's plugin *name* is usually the actual product (technology=
    'Apache'), but its generic 'HTTPServer' plugin carries the real value
    inside `evidence` instead (technology='HTTPServer', evidence=
    '{"string": ["Vercel"]}') - unwrap that one case rather than surface the
    meaningless literal string "HTTPServer" (also found live, on clinkl.in).
    """
    plugin = finding.get('technology', '')
    if plugin in _NON_TECH_WHATWEB_PLUGINS:
        return None
    if plugin == 'HTTPServer':
        try:
            strings = json.loads(finding.get('evidence') or '{}').get('string')
        except (json.JSONDecodeError, AttributeError):
            strings = None
        plugin = str(strings[0]) if strings else None
        if not plugin:
            return None
    version = finding.get('version')
    return plugin + (f' {version}' if version else '')


def _extract_target_profile(findings: List[dict]) -> dict:
    profile: dict = {}
    technologies: List[str] = []
    for f in findings:
        ftype = f.get('type')
        if ftype == 'waf_detected' and f.get('waf_name'):
            profile['waf'] = f['waf_name']
        elif ftype == 'server_version_exposed' and f.get('server_value'):
            profile['server'] = f['server_value']
        elif ftype == 'x_powered_by_exposed' and f.get('powered_by_value'):
            profile['framework'] = f['powered_by_value']
        elif ftype in ('tech_detected', 'outdated_tech') and f.get('technology'):
            label = _whatweb_technology_label(f)
            if label and label not in technologies:
                technologies.append(label)
    if technologies:
        profile['technologies'] = technologies[:_MAX_PROFILE_TECHNOLOGIES]
    return profile


def _full_scan_stats(findings: List[dict]) -> dict:
    """
    Deterministic totals across the WHOLE scan, not just the (possibly much
    smaller, or even empty) subset of findings sent to the model for
    individual description. Real bug found live against clinkl.in: every
    real finding in a 38-finding scan had its own fixed template, leaving
    one leftover non-vulnerability meta finding (testssl_scanTime) as the
    ONLY thing in the AI batch - the model wrote an executive_summary
    entirely about that one item, describing a 38-finding scan as "a single
    low-severity issue". Grounds the summary in real scope regardless of how
    much of the batch got excluded as separately-templated.
    """
    counts: Dict[str, int] = {}
    for f in findings:
        sev = f.get('severity', 'Informational')
        counts[sev] = counts.get(sev, 0) + 1
    return {'total_findings': len(findings), 'counts_by_severity': counts}


# Mirrors the instruction _SYSTEM_PROMPT gives the model (never a bare
# "review"/"ensure"/"verify" with nothing concrete after it) - applied here
# to live Ollama output too, not just the hand-written _TYPE_REMEDIATION
# templates, since the prompt is a strong nudge, not an enforced contract.
_VAGUE_OPENERS = ('review', 'ensure', 'verify', 'check that')


def _coerce_to_text(value) -> str:
    """
    Qwen 2.5 (via `format: json`) sometimes emits `remediation`/`description`
    as a JSON array of step strings instead of the single string the prompt
    asks for - real bug found live: the report template does a plain
    `{{ finding.remediation }}`, so an unnormalized list rendered as raw
    Python-list syntax (brackets and quotes) straight into the PDF. The
    report's remediation-block CSS is `white-space: pre-wrap`, so newline-
    joining renders each step on its own line, matching the intended
    numbered-step format.
    """
    if isinstance(value, list):
        return '\n'.join(str(v) for v in value)
    return str(value or '')


def _looks_vague(remediation: str) -> bool:
    text = str(remediation or '').strip().lower()
    if not text:
        return True
    # Strip a leading "1) " / "1. " style numbering before checking the
    # opening words, same normalization as the static-template quality test.
    stripped = text.split(') ', 1)[-1]
    return any(stripped.startswith(w) for w in _VAGUE_OPENERS)


def _strip_emdashes(obj):
    """
    Recursively replace em-dashes (U+2014) with hyphens in every string of a
    nested dict/list structure. Qwen 2.5 frequently emits em-dashes in the
    free-text fields it generates, which would otherwise reach the PDF and
    dashboard.
    """
    if isinstance(obj, str):
        return obj.replace('—', '-')
    if isinstance(obj, list):
        return [_strip_emdashes(x) for x in obj]
    if isinstance(obj, dict):
        return {k: _strip_emdashes(v) for k, v in obj.items()}
    return obj


def _shape_for_prompt(findings: List[dict]) -> List[dict]:
    return [
        {
            'finding_id': f.get('finding_id', ''),
            'title': f.get('title', ''),
            'evidence': str(f.get('evidence', ''))[:300],
            'owasp_category': f.get('owasp_category', ''),
            'severity_hint': str(f.get('severity', 'Informational')).lower(),
        }
        for f in findings
    ]


def _call_ollama(shaped: List[dict], overflow: int, domain: str,
                  target_profile: Optional[dict] = None,
                  scan_stats: Optional[dict] = None) -> dict:
    """One HTTP round-trip to Ollama. Raises on any failure - callers handle
    retry/fallback. Returns the parsed {'executive_summary','findings'} dict."""
    note = ''
    if overflow:
        note = (
            f'NOTE: {overflow} additional lower-severity findings exist and '
            f'are grouped in the appendix; do not describe them individually. '
        )
    if target_profile:
        note += f'Target environment: {json.dumps(target_profile)}. '
    user_content = f'{note}Analyze these VAPT findings for {domain}: {json.dumps(shaped)}'
    if scan_stats:
        user_content += f' Full scan totals: {json.dumps(scan_stats)}.'

    payload = {
        'model': 'qwen2.5:7b',
        'format': 'json',
        'stream': False,
        'options': {
            'temperature': 0.1,
            'num_predict': 4096,
            'num_ctx': 8192,
        },
        'messages': [
            {'role': 'system', 'content': _SYSTEM_PROMPT},
            {'role': 'user', 'content': user_content},
        ],
    }

    resp = requests.post(
        f'{settings.OLLAMA_URL}/api/chat',
        json=payload,
        timeout=_OLLAMA_TIMEOUT,
    )
    resp.raise_for_status()

    content = resp.json()['message']['content']
    result = json.loads(content)

    missing = _REQUIRED_KEYS - set(result.keys())
    if missing:
        raise ValueError(f'Ollama response missing required keys: {missing}')
    if not isinstance(result.get('findings'), list):
        raise ValueError('Ollama response "findings" is not a list')

    return result


def analyse(findings: List[dict], domain: str) -> dict:
    """
    Generate plain-English description/remediation text for already-scored
    findings (severity/cvss/priority/owasp_category must already be set by
    analysis/cvss_scorer.py before this is called - this function never
    computes or overrides those).

    Sends only the top _MAX_SENT_TO_AI findings by priority to keep the
    prompt within Ollama's context window (the root cause of the original
    clinkl.in bug: 4658 findings blew past num_ctx=8192 and silently forced
    every scan onto the rule-based fallback).

    Returns:
        {
            'executive_summary': str,
            'descriptions': {finding_id: {'description': str, 'remediation': str}},
            'ai_unavailable': bool,
        }
    Never raises - on any failure, falls back to a deterministic per-category
    template so the pipeline never hard-fails here.
    """
    ordered = sorted(findings, key=lambda f: f.get('priority', 5))
    # Types with their own fixed, always-correct template (_ENUMERATION_TYPE_
    # REMEDIATION above) are never sent to the LLM at all - the deterministic
    # template is what every scan shows for these, not a maybe depending on
    # whether the finding happened to rank in the top _MAX_SENT_TO_AI.
    candidates = [f for f in ordered if f.get('type') not in _TYPE_REMEDIATION]
    top = candidates[:_MAX_SENT_TO_AI]
    overflow = max(0, len(candidates) - _MAX_SENT_TO_AI)
    shaped = _shape_for_prompt(top)
    # Built from the FULL findings list, not just `candidates` - the tech
    # stack/WAF signal comes from finding types that are themselves excluded
    # from the AI batch (they have their own templates), so this must run
    # before that exclusion to still see them.
    target_profile = _extract_target_profile(findings)
    # Same reasoning as target_profile - built from the FULL list so the
    # executive_summary reflects the real scan even when `shaped` is a tiny
    # or empty slice of it.
    scan_stats = _full_scan_stats(findings)
    by_id = {f.get('finding_id'): f for f in findings if f.get('finding_id')}

    last_error: Optional[Exception] = None
    for attempt in range(1, _JSON_RETRY_ATTEMPTS + 1):
        try:
            result = _call_ollama(shaped, overflow, domain, target_profile, scan_stats)
            descriptions = {}
            for f in result['findings']:
                if not isinstance(f, dict):
                    # Malformed item from a 7B model's JSON - skip just this
                    # one rather than let it discard the whole batch's
                    # otherwise-successful descriptions (real crash found
                    # live: 'str' object has no attribute 'get').
                    logger.warning("Ollama returned a non-dict findings item for %s: %r",
                                    domain, f)
                    continue
                fid = f.get('finding_id')
                if not fid:
                    continue
                remediation = _coerce_to_text(f.get('remediation', ''))
                if _looks_vague(remediation):
                    # Strong prompt, not an enforced contract - fall back to
                    # the deterministic template for just this finding's
                    # remediation rather than trust an unactionable step.
                    source = by_id.get(fid, {'owasp_category': f.get('owasp_category', '')})
                    _, remediation = _generic_remediation(source)
                descriptions[fid] = {
                    'description': _coerce_to_text(f.get('description', '')),
                    'remediation': remediation,
                }
            logger.info("Ollama description pass complete for %s - %d/%d findings described",
                        domain, len(descriptions), len(findings))
            return _strip_emdashes({
                'executive_summary': result.get('executive_summary', ''),
                'descriptions': descriptions,
                'ai_unavailable': False,
            })

        except requests.exceptions.Timeout:
            logger.warning("Ollama timed out for %s - using rule-based fallback", domain)
            break  # don't retry a slow/hung Ollama - fail straight to fallback
        except requests.exceptions.ConnectionError:
            logger.warning("Ollama not reachable for %s - using rule-based fallback", domain)
            break  # don't retry an unreachable Ollama
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            last_error = e
            logger.warning("Ollama response invalid for %s (attempt %d/%d): %s",
                            domain, attempt, _JSON_RETRY_ATTEMPTS, e)
            continue  # malformed JSON from a 7B model is often worth retrying
        except Exception as e:
            logger.error("Ollama unexpected error for %s: %s - using fallback", domain, e)
            break

    if last_error:
        logger.warning("Ollama gave up after %d attempts for %s - using rule-based fallback",
                        _JSON_RETRY_ATTEMPTS, domain)

    return _strip_emdashes(_rule_based_fallback(findings, domain))


def _rule_based_fallback(findings: List[dict], domain: str) -> dict:
    """
    Used when Ollama is unreachable, times out, or never returns valid JSON.
    Every finding gets the same deterministic (description, remediation) pair
    _score_and_describe() already gives any finding that never reaches the AI
    batch in the first place - a templated type (never sent to Ollama at all),
    or one that ranked outside the top-50 cutoff despite Ollama succeeding
    overall. A total Ollama outage is just the same "no AI text for this
    finding" situation for every finding at once, not a reason to discard the
    perfectly good, non-hallucinated templates that already exist for it.
    Real bug found live: this used to hardcode a generic "AI-generated
    description unavailable" placeholder for every finding regardless of
    type, which meant a scan whose findings were entirely templated types
    (guaranteed-concrete text "every time" per the module's own docstring)
    still lost that text the moment Ollama happened to be down - reproduced
    against a real historical scan (bwapp.local) during the AI+template
    pipeline replay. The scan-level ai_unavailable flag (not per-finding
    text) is what actually drives the report's "AI analysis unavailable"
    badge, so nothing is lost by using the real description here.
    """
    descriptions = {}
    for f in findings:
        fid = f.get('finding_id', '')
        if not fid:
            continue
        description, remediation = _generic_remediation(f)
        descriptions[fid] = {'description': description, 'remediation': remediation}

    counts: Dict[str, int] = {}
    for f in findings:
        sev = f.get('severity', 'Informational')
        counts[sev] = counts.get(sev, 0) + 1
    top_titles = [f.get('title', '') for f in findings if f.get('severity') == 'Critical'][:3]

    summary_parts = [f'Automated VAPT scan of {domain} identified {len(findings)} findings.']
    if top_titles:
        summary_parts.append(f'Top issues: {", ".join(top_titles)}.')
    summary_parts.append('(AI analysis unavailable - rule-based descriptions applied.)')

    return {
        'executive_summary': ' '.join(summary_parts),
        'descriptions': descriptions,
        'ai_unavailable': True,
    }
