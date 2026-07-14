import logging
import re
import time
import urllib.parse
import urllib3
from html.parser import HTMLParser
from typing import List, Optional

import requests
from celery.exceptions import SoftTimeLimitExceeded

from tasks.base_task import (
    BaseTask, normalize_finding, update_module_status, build_module_result,
    resolve_target_url, scaled_timeout, mount_retry_adapter,
)
from tasks.celery_app import app

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)
MODULE = 'owasp'

_TIMEOUT = scaled_timeout(30)
_SESSION_KWARGS = dict(timeout=_TIMEOUT, verify=False, allow_redirects=False)

# SQL error patterns that indicate injection vulnerability
_SQL_ERRORS = [
    r"sql syntax", r"mysql_fetch", r"ORA-\d{5}", r"pg_query\(\)",
    r"sqlite3?\.OperationalError", r"SQLSTATE", r"syntax error.*SQL",
    r"Unclosed quotation mark", r"Microsoft OLE DB",
    r"supplied argument is not a valid MySQL",
    r"You have an error in your SQL syntax",
]
_SQL_ERROR_RE = re.compile('|'.join(_SQL_ERRORS), re.IGNORECASE)

# Patterns that suggest stack trace / error disclosure
_TRACE_PATTERNS = [
    r"Traceback \(most recent call last\)",
    r"at .+\(.+\.java:\d+\)",
    r"System\.Exception",
    r"stack overflow",
    r"Fatal error.*on line",
    r"Warning:.*in.*on line",
    r"Parse error:.*in.*on line",
    r"SQLSTATE\[",
    r"ORA-\d{5}",
    r"Microsoft.*\.NET Framework",
]
_TRACE_RE = re.compile('|'.join(_TRACE_PATTERNS), re.IGNORECASE)


def _get_params(target: str) -> dict:
    """Extract existing GET params from the URL, or return a safe default."""
    parsed = urllib.parse.urlparse(target)
    params = dict(urllib.parse.parse_qsl(parsed.query))
    if not params:
        # Real bug found live: DVWA's classic vulnerable pages (SQLi, XSS
        # reflected, etc.) are GET-form-gated behind `isset($_REQUEST['Submit'])`
        # - without a submit-button-shaped param, the app renders the empty
        # form and never processes `id` at all, so every injection here was
        # silently a no-op (no error, 0 findings, no evidence anything was
        # even attempted). Confirmed directly: the exact same request with
        # vs without `Submit=Submit` is the difference between DVWA
        # processing the payload and silently ignoring it.
        # ponytail: `Submit` covers DVWA/bWAPP's own convention, not every
        # app's submit-button name - a real upgrade path (extracting actual
        # <form> input names via _FormFieldExtractor, already used for the
        # login form) exists if a future target needs it.
        params = {'id': '1', 'q': 'test', 'search': 'test', 'Submit': 'Submit'}
    return params


def _strip_query(target: str) -> str:
    """
    Base URL for a re-request that supplies its own complete `params=` dict.
    Real bug found live (reproduced against a local mock server built to
    verify the crawl-depth fix above): requests.get(url, params=X) APPENDS
    to a URL's existing query string rather than replacing it - a request
    for "target?q=test" with params={'q': "' OR '1'='1"} actually sends
    "?q=test&q=%27+OR+%271%27%3D%271", both values present. Whether the
    injected payload even gets evaluated then depends on which duplicate key
    the target framework happens to prefer. Invisible before the crawl-depth
    fix, since owasp.py only ever re-tested the bare domain root (which
    normally has no query string of its own) - now that real discovered
    pages like "/search?q=..." are reachable, this directly blunts every
    param-based test below unless the base URL is query-free first.
    """
    return urllib.parse.urlsplit(target)._replace(query='').geturl()


# ---------------------------------------------------------------------------
# Same-origin crawl - so the 5 test functions below reach more than just the
# bare domain root. Real vulnerable pages are often a click or two deep (e.g.
# Mutillidae's index.php?page=... navigation - see docs/test_findings.md's
# "owasp.py stayed at 0 even here" entry, which is exactly this gap). Kept
# self-contained (stdlib html.parser + requests, no new dependency) rather
# than consuming webscan/Katana's crawl output: webscan runs as a separate,
# fully-parallel Celery task with no ordering guarantee relative to this one
# (scan_orchestrator.py's group()), so there's nothing to consume yet at the
# point this module runs. owasp.py doesn't need webscan's *specific* URLs,
# just *some* same-origin ones - cheap to get itself.
# ---------------------------------------------------------------------------
_MAX_CRAWL_PAGES = 20
_CRAWL_PAGE_TIMEOUT = scaled_timeout(10)
_CRAWL_BUDGET_SECONDS = scaled_timeout(60)


_META_REFRESH_URL_RE = re.compile(r'url\s*=\s*[\'"]?([^\'";]+)', re.IGNORECASE)


class _LinkExtractor(HTMLParser):
    """
    Collects <a href=...>, <form action=...>, and <meta http-equiv="refresh">
    redirect targets from one page. Same-origin and session-destroying-link
    filtering happens uniformly in _discover_urls() for everything collected
    here, regardless of source - this class only extracts candidate URLs, it
    never decides which ones are safe to follow.

    Real gap found live: a page whose only navigation is a meta-refresh (a
    static landing-page shell that bounces into the real app - e.g.
    oa.iitk.ac.in's homepage refreshing into /Oa/) was invisible to this
    crawler when it only looked at <a>/<form> - `discovered` stayed at just
    the single starting URL, so every test function had nothing to inject
    into and the whole module completed in well under a second reporting a
    clean 0-finding "success" with zero real coverage of the actual
    application. The refresh delay in `content="N;url=..."` is deliberately
    ignored - this is a crawler, not a browser simulating a human waiting it
    out.
    """

    def __init__(self):
        super().__init__()
        self.links: List[str] = []

    def handle_starttag(self, tag: str, attrs: list) -> None:
        attrs_dict = dict(attrs)
        if tag == 'a' and attrs_dict.get('href'):
            self.links.append(attrs_dict['href'])
        elif tag == 'form' and attrs_dict.get('action'):
            self.links.append(attrs_dict['action'])
        elif tag == 'meta' and (attrs_dict.get('http-equiv') or '').lower() == 'refresh':
            match = _META_REFRESH_URL_RE.search(attrs_dict.get('content') or '')
            if match:
                self.links.append(match.group(1).strip())


def _normalize_url(url: str) -> str:
    """Drop the fragment for dedup - a #section link isn't a distinct page."""
    return urllib.parse.urlsplit(url)._replace(fragment='').geturl()


class _FormFieldExtractor(HTMLParser):
    """
    Collects every <input name=...> (with its default value=) inside a
    <form> on the login page - not just a CSRF token. Real login forms often
    also require their submit button's own name=value pair to be present in
    the POST body (a common server-side pattern: PHP's `isset($_POST['Login'])`
    - DVWA is exactly this) - a naive username/password(+token)-only POST
    still silently fails without it. This submits "everything a browser
    would", then _make_session layers the configured username/password on
    top of these defaults (which naturally picks up CSRF tokens too, under
    whatever name the app uses, with no special-casing needed).
    """

    def __init__(self):
        super().__init__()
        self.fields: dict = {}
        self.action: Optional[str] = None
        self.method: Optional[str] = None
        self.found_login_form = False
        self._in_form = False
        self._current_fields: dict = {}
        self._current_action: Optional[str] = None
        self._current_method: Optional[str] = None
        self._current_has_password = False

    def handle_starttag(self, tag: str, attrs: list) -> None:
        attrs_dict = dict(attrs)
        if tag == 'form':
            self._in_form = True
            self._current_fields = {}
            self._current_action = attrs_dict.get('action')
            self._current_method = attrs_dict.get('method')
            self._current_has_password = False
        elif tag == 'input' and self._in_form:
            name = attrs_dict.get('name')
            if name:
                self._current_fields[name] = attrs_dict.get('value', '')
            if (attrs_dict.get('type') or '').lower() == 'password':
                self._current_has_password = True

    def handle_endtag(self, tag: str) -> None:
        if tag == 'form':
            self._in_form = False
            if self._current_has_password:
                # The login form specifically - keep its own fields/action,
                # discarding any other form on the same page (e.g. a search
                # box). Real bug found live against testfire.net (Altoro
                # Mutual): its login page also has a search form earlier in
                # the HTML, and the previous version merged both forms'
                # fields into one flat dict regardless of source, with no
                # way to know which form the CSRF-token-shaped fields
                # actually belonged to.
                self.fields = self._current_fields
                self.action = self._current_action
                self.method = self._current_method
                self.found_login_form = True


def _response_looks_like_login_form(text: str) -> bool:
    """True if a password-type input is present anywhere in the response -
    used as a best-effort "did the login actually work" signal when no
    logged_in_indicator is configured. Reuses _FormFieldExtractor's own
    password-detection rather than a separate regex, so both places agree
    on what counts as a login form."""
    extractor = _FormFieldExtractor()
    extractor.feed(text)
    return extractor.found_login_form


def _make_session(auth: Optional[dict]) -> requests.Session:
    """
    A plain, unauthenticated Session when `auth` is None (today's behavior,
    unchanged). When `auth` is set (schemas.py's AuthConfig, fetched via
    tasks.auth_store.get_scan_auth - never a Celery task arg, see that
    module's docstring for why), logs in once and returns the session with
    whatever cookies that login set - every subsequent call in run_owasp()
    reuses this same session, carrying the authenticated cookie into all 5
    test functions and the crawl.

    GETs the login page first and submits every field found on its <form>
    (_FormFieldExtractor), with username/password overridden to the
    configured values - confirmed necessary against this feature's own
    verification targets: a naive two-field POST (username+password only)
    silently fails against both DVWA (missing CSRF token AND its `Login`
    submit-button field) and NodeGoat (missing its `_csrf` token), even with
    correct credentials - both just redirect back to the login page with no
    error, which is why this submits the whole form rather than special-
    casing known CSRF field names.

    Best-effort on `logged_in_indicator`: if set and it doesn't match the
    post-login response, this logs a warning and continues anyway rather
    than aborting the scan - a wrong indicator regex shouldn't turn an
    otherwise-working authenticated scan into a hard failure.

    Sets `session.login_result` to a dict the caller can turn into a
    finding (see run_owasp) - `{'attempted': bool, 'outcome': str, 'detail':
    str}`, `outcome` one of 'confirmed'/'probable'/'failed'/'error'. Added
    because a silently-degraded authenticated scan (auth configured, login
    actually failed, every "authenticated" test then ran unauthenticated
    against nothing but public content) was completely invisible anywhere
    in the report before this - the operator had no way to tell "0 findings
    behind login" apart from "0 findings, and also the login never worked."
    """
    session = requests.Session()
    session.login_result = {'attempted': False, 'outcome': None, 'detail': None}
    # GET-only retry/backoff on 429/502/503/504 - a real WAF throttling mid-scan
    # would otherwise silently read as "clean" on whatever page it hit next,
    # indistinguishable from a genuinely non-vulnerable result (see
    # mount_retry_adapter's docstring). Login POSTs below intentionally aren't
    # retried by this adapter (GET/HEAD/OPTIONS only).
    mount_retry_adapter(session)
    if not auth:
        return session

    session.login_result['attempted'] = True

    # JSON-API login (modern SPAs): POST creds as JSON, set the returned bearer
    # token as a Session header. Cookies the login sets are kept by the Session
    # too. login_type defaults to auto-detection (resolve_login_type GETs the
    # login URL and sniffs form vs JSON). See tasks/auth_login.py.
    from tasks.auth_login import resolve_login_type
    if resolve_login_type(auth) == 'json':
        from tasks.auth_login import fetch_json_auth_token, auth_header_from
        token = fetch_json_auth_token(auth)
        if token:
            header, value = auth_header_from(auth, token)
            session.headers[header] = value
            session.login_result.update(outcome='confirmed',
                                         detail='JSON login returned a usable auth token.')
        else:
            logger.warning("owasp JSON login failed for %s (continuing "
                            "unauthenticated)", auth.get('login_url'))
            session.login_result.update(
                outcome='failed',
                detail='JSON login POST did not return an extractable token - see '
                       'worker logs for the specific failure (request error, non-2xx '
                       'status, or no token found in the response body).')
        return session

    try:
        login_page = session.get(auth['login_url'], timeout=_TIMEOUT, verify=False)
        extractor = _FormFieldExtractor()
        extractor.feed(login_page.text)
        form_data = dict(extractor.fields)
        form_data[auth['username_field']] = auth['username']
        form_data[auth['password_field']] = auth['password']

        # Real bug found live against testfire.net (Altoro Mutual): its
        # login form's action ("doLogin") is a different endpoint than the
        # page hosting it ("login.jsp") - POSTing to login_url unconditionally
        # (the old behavior) silently hit the wrong URL and never even
        # attempted authentication (confirmed directly: it returns a 200
        # that just re-serves the login page, vs. the real endpoint's 302 +
        # explicit "Login Failed" on bad creds). Resolve the form's own
        # action relative to login_url when the login form declared one;
        # fall back to login_url itself when it didn't (a form with no
        # explicit action submits back to its own page - the previous,
        # still-correct assumption for that case).
        post_url = urllib.parse.urljoin(auth['login_url'], extractor.action) \
            if extractor.action else auth['login_url']

        # Real bug found live against Google Gruyere (an intentionally
        # insecure app whose login form deliberately uses GET, credentials
        # visible in the URL, as one of its own teaching points): this
        # unconditionally used session.post(), so a GET-method login form's
        # credentials were sent as a POST body the server never reads as
        # login parameters at all - a silent failure, same failure class as
        # the wrong-endpoint bug above, just via HTTP method instead of URL.
        # Defaults to POST when the form doesn't declare a method (or none
        # was found at all) - HTML technically defaults an absent method to
        # GET, but every real login form seen in this feature's other
        # verification targets (DVWA, NodeGoat, Altoro Mutual) uses POST
        # explicitly, so POST remains the safer default for the unknown case
        # rather than flipping behavior those already-working targets rely on.
        if (extractor.method or '').lower() == 'get':
            # Same duplicate-query-string trap as the OWASP test functions'
            # own fix (_strip_query) - params= appends to an existing query
            # string rather than replacing it, so post_url must be
            # query-free before combining it with the full form_data here.
            resp = session.get(
                _strip_query(post_url), params=form_data,
                timeout=_TIMEOUT, verify=False, allow_redirects=True,
            )
        else:
            resp = session.post(
                post_url, data=form_data,
                timeout=_TIMEOUT, verify=False, allow_redirects=True,
            )
        indicator = auth.get('logged_in_indicator')
        if indicator:
            # Deterministic - the operator told us exactly what "logged in"
            # looks like for this app.
            if re.search(indicator, resp.text):
                session.login_result.update(
                    outcome='confirmed',
                    detail=f'logged_in_indicator {indicator!r} matched the post-login response.')
            else:
                logger.warning("owasp login for domain may have failed - "
                                "logged_in_indicator %r not found in post-login "
                                "response", indicator)
                session.login_result.update(
                    outcome='failed',
                    detail=f'logged_in_indicator {indicator!r} did not match the '
                           f'post-login response - login likely failed, or the '
                           f'indicator itself needs adjusting.')
        else:
            # No operator-provided indicator - best-effort heuristic only.
            # A login FORM (a password-type input) still present in the
            # response strongly suggests we're looking at the login page
            # again, i.e. it failed; its absence is a reasonable but not
            # certain signal of success, so it's reported as "probable",
            # never "confirmed", without an explicit indicator.
            if _response_looks_like_login_form(resp.text):
                session.login_result.update(
                    outcome='failed',
                    detail='No logged_in_indicator configured; the post-login response '
                           'still contains a password field, which usually means the '
                           'login form was shown again (login likely failed).')
            else:
                session.login_result.update(
                    outcome='probable',
                    detail='No logged_in_indicator configured, so this is a best-effort '
                           'guess: the post-login response no longer shows a login form, '
                           'which is consistent with (but does not confirm) success. '
                           'Set logged_in_indicator for a reliable check.')
    except requests.RequestException as e:
        logger.warning("owasp login POST to %s failed (continuing "
                        "unauthenticated): %s", auth.get('login_url'), e)
        session.login_result.update(outcome='error', detail=f'Login request failed: {e}')
    return session


_SESSION_DESTROYING_LINK_RE = re.compile(
    r'log[-_]?out|sign[-_]?out|sign[-_]?off', re.IGNORECASE)


def _discover_urls(session: requests.Session, target: str, domain: str) -> List[str]:
    """
    Same-origin BFS crawl, capped at _MAX_CRAWL_PAGES / _CRAWL_BUDGET_SECONDS
    (monotonic deadline loop, same pattern as webscan.py's _ZAP_SCAN_BUDGET).
    Always returns `target` as element 0, even if the crawl finds nothing
    else - existing single-target behavior is a strict subset of this.

    Deliberately never follows/records a link matching
    _SESSION_DESTROYING_LINK_RE. Real bug found during this feature's own
    verification: NodeGoat's nav bar links to GET /logout, and that route
    genuinely destroys the session server-side (a common, if not best-
    practice, real-world pattern) - a same-origin crawl that dutifully
    visits every link it finds was logging its own authenticated session out
    within under a second, silently turning every subsequent test in
    run_owasp() (not just the new IDOR one) into an unauthenticated probe
    with zero warning. Filtering by URL text before ever fetching the link is
    cheap and avoids this entirely, at the cost of also skipping a genuine
    "logout" link if a target names it something this pattern doesn't catch -
    an acceptable tradeoff for never blowing away the very session this
    module depends on for the rest of its run.
    """
    deadline = time.monotonic() + _CRAWL_BUDGET_SECONDS
    origin = urllib.parse.urlsplit(target)
    seen = {_normalize_url(target)}
    discovered = [target]
    queue = [target]

    while queue and len(discovered) < _MAX_CRAWL_PAGES and time.monotonic() < deadline:
        url = queue.pop(0)
        try:
            resp = session.get(url, timeout=_CRAWL_PAGE_TIMEOUT, verify=False)
            if 'text/html' not in resp.headers.get('Content-Type', ''):
                continue
            parser = _LinkExtractor()
            parser.feed(resp.text)
        except SoftTimeLimitExceeded:
            raise
        except Exception as e:
            logger.debug("crawl fetch failed for %s: %s", url, e)
            continue

        for link in parser.links:
            if _SESSION_DESTROYING_LINK_RE.search(link):
                continue
            absolute = urllib.parse.urljoin(url, link)
            if _SESSION_DESTROYING_LINK_RE.search(absolute):
                continue
            parsed = urllib.parse.urlsplit(absolute)
            if parsed.scheme not in ('http', 'https') or parsed.netloc != origin.netloc:
                continue
            normalized = _normalize_url(absolute)
            if normalized in seen:
                continue
            seen.add(normalized)
            discovered.append(absolute)
            queue.append(absolute)
            if len(discovered) >= _MAX_CRAWL_PAGES:
                break

    return discovered


def test_sqli(session: requests.Session, target: str, domain: str) -> List[dict]:
    """
    Inject SQL payloads into GET parameters.
    Non-destructive: read-only payloads only (boolean-based, no DROP/UPDATE).
    """
    findings = []
    payloads = ["' OR '1'='1", "'", "' OR 1=1--", "1 AND 1=1", "1 AND 1=2"]
    base_params = _get_params(target)
    base_url = _strip_query(target)

    try:
        # Baseline response for boolean comparison
        baseline = session.get(base_url, params=base_params, **_SESSION_KWARGS)
        baseline_len = len(baseline.text)

        for param in list(base_params.keys())[:3]:  # limit to first 3 params
            for payload in payloads[:2]:  # 2 payloads per param
                injected = dict(base_params)
                injected[param] = payload
                try:
                    resp = session.get(base_url, params=injected, **_SESSION_KWARGS)
                    body = resp.text

                    if _SQL_ERROR_RE.search(body):
                        findings.append(normalize_finding(
                            module=MODULE, tool='owasp', type_='sqli_error_based',
                            title='Potential SQL Injection (error-based)',
                            evidence=f'Parameter "{param}" with payload {payload!r} '
                                     f'triggered SQL error in response',
                            severity='High', target=domain,
                            # A DBMS error string in the response IS the proof -
                            # no verifier dispatch needed, unlike boolean-based.
                            confidence='confirmed',
                        ))
                        return findings  # one confirmed finding is enough

                    # Boolean-based: significantly different response length
                    if abs(len(body) - baseline_len) > 500 and resp.status_code == 200:
                        findings.append(normalize_finding(
                            module=MODULE, tool='owasp', type_='sqli_boolean_based',
                            title='Potential SQL Injection (boolean-based response diff)',
                            evidence=f'Parameter "{param}" with payload {payload!r} '
                                     f'produced {abs(len(body) - baseline_len)}-byte diff',
                            severity='Medium', target=domain,
                        ))
                        return findings
                except requests.RequestException:
                    pass
    except SoftTimeLimitExceeded:
        raise
    except Exception as e:
        logger.debug("sqli test error for %s: %s", domain, e)
    return findings


def test_xss(session: requests.Session, target: str, domain: str) -> List[dict]:
    """
    Inject XSS payloads into GET parameters and check if reflected unsanitized.
    Non-destructive: read-only GET requests.
    """
    findings = []
    marker = 'VAPT_XSS_8675309'
    payloads = [
        f'<script>alert("{marker}")</script>',
        f'"><img src=x onerror=alert("{marker}")>',
        f"'{marker}",
    ]
    base_params = _get_params(target)
    base_url = _strip_query(target)

    try:
        for param in list(base_params.keys())[:3]:
            for payload in payloads[:2]:
                injected = dict(base_params)
                injected[param] = payload
                try:
                    resp = session.get(base_url, params=injected, **_SESSION_KWARGS)
                    if marker in resp.text and payload in resp.text:
                        findings.append(normalize_finding(
                            module=MODULE, tool='owasp', type_='reflected_xss',
                            title='Reflected XSS - payload reflected unsanitized',
                            evidence=f'Parameter "{param}" reflects '
                                     f'payload {payload[:60]!r} verbatim',
                            severity='High', target=domain,
                            # Phase 2: both payloads tried here (payloads[:2])
                            # call alert(marker) - verify_reflected_xss
                            # (analysis/verifier.py) re-issues this exact
                            # request in headless Chromium and checks whether
                            # the alert dialog actually fires, not just
                            # whether the string is present in the response.
                            confidence='probable', verifiable=True,
                            verification_target={'url': base_url, 'params': injected,
                                                  'payload': payload, 'marker': marker},
                        ))
                        return findings
                except requests.RequestException:
                    pass
    except SoftTimeLimitExceeded:
        raise
    except Exception as e:
        logger.debug("xss test error for %s: %s", domain, e)
    return findings


def test_path_traversal(session: requests.Session, target: str, domain: str) -> List[dict]:
    """
    Inject path traversal sequences into URL path and params.
    Non-destructive: read-only GET requests.
    """
    findings = []
    traversals = [
        '/../../../etc/passwd',
        '/../../../../etc/passwd',
        '/%2e%2e/%2e%2e/%2e%2e/etc/passwd',
    ]
    # Real false positive found live (Opus review): '/bin/bash'/'/bin/sh'
    # are common substrings in ordinary page content (shell tutorials, docs,
    # sysadmin blog posts) - a traversal probe landing on any normal 200 page
    # that happens to mention a shell path was flagged Critical. Require the
    # UID-0 root passwd-line shape instead ('root:x:0:'/'root:!:0:' - the
    # real /etc/passwd format is `root:x:0:0:root:/root:/bin/bash`), which
    # essentially never appears outside an actual passwd file dump.
    indicators = ['root:x:0:', 'root:!:0:']

    try:
        parsed = urllib.parse.urlparse(target)
        for trav in traversals:
            probe_url = f'{parsed.scheme}://{parsed.netloc}{trav}'
            try:
                resp = session.get(probe_url, **_SESSION_KWARGS)
                if any(ind in resp.text for ind in indicators):
                    findings.append(normalize_finding(
                        module=MODULE, tool='owasp', type_='path_traversal',
                        title='Path traversal - /etc/passwd accessible',
                        evidence=f'GET {probe_url} returned /etc/passwd content',
                        severity='Critical', target=domain,
                        confidence='probable', verifiable=True,
                        verification_target={'url': probe_url, 'param': None, 'payload': trav},
                    ))
                    return findings
            except requests.RequestException:
                pass

        # Also try file= / path= params
        base_params = _get_params(target)
        base_url = _strip_query(target)
        for param in [p for p in base_params if any(
                k in p.lower() for k in ('file', 'path', 'page', 'doc', 'view'))]:
            injected = dict(base_params)
            injected[param] = '../../../../etc/passwd'
            try:
                resp = session.get(base_url, params=injected, **_SESSION_KWARGS)
                if any(ind in resp.text for ind in indicators):
                    findings.append(normalize_finding(
                        module=MODULE, tool='owasp', type_='path_traversal',
                        title='Path traversal via parameter - /etc/passwd readable',
                        evidence=f'Parameter "{param}" with traversal payload '
                                 f'returned /etc/passwd content',
                        severity='Critical', target=domain,
                        confidence='probable', verifiable=True,
                        verification_target={'url': base_url, 'param': param,
                                              'payload': injected[param]},
                    ))
                    return findings
            except requests.RequestException:
                pass
    except SoftTimeLimitExceeded:
        raise
    except Exception as e:
        logger.debug("path traversal test error for %s: %s", domain, e)
    return findings


def test_open_redirect(session: requests.Session, target: str, domain: str) -> List[dict]:
    """
    Inject external URLs into common redirect parameters.
    Non-destructive: read-only GET requests, allow_redirects=False.
    """
    findings = []
    redirect_params = ['next', 'redirect', 'url', 'return', 'returnUrl',
                       'redirect_uri', 'continue', 'goto', 'dest', 'destination']
    external_url = 'https://evil-vapt-test.example.com'
    base_url = _strip_query(target)

    try:
        for param in redirect_params:
            try:
                resp = session.get(
                    base_url,
                    params={param: external_url},
                    timeout=_TIMEOUT,
                    verify=False,
                    allow_redirects=False,
                )
                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get('Location', '')
                    # Real false-positive bug found live: a plain substring
                    # check on the raw Location header matches plenty of
                    # apps' own "return to this page" pattern (e.g.
                    # Mutillidae's `index.php?page=X&next=<value>`, which
                    # echoes the payload back into its OWN same-site URL
                    # verbatim rather than ever redirecting there) - the
                    # payload string is present, but the browser is never
                    # actually sent to the external host. Resolve the
                    # Location against the request URL (handles relative
                    # paths) and require its netloc to genuinely be the
                    # injected external host.
                    resolved_netloc = urllib.parse.urlsplit(
                        urllib.parse.urljoin(base_url, location)).netloc
                    external_netloc = urllib.parse.urlsplit(external_url).netloc
                    if resolved_netloc == external_netloc:
                        findings.append(normalize_finding(
                            module=MODULE, tool='owasp', type_='open_redirect',
                            title='Open Redirect vulnerability',
                            evidence=f'Parameter "{param}" redirects to '
                                     f'injected URL: {location}',
                            severity='Medium', target=domain,
                            confidence='probable', verifiable=True,
                            verification_target={'url': base_url, 'param': param,
                                                  'payload': external_url},
                        ))
                        return findings
            except requests.RequestException:
                pass
    except SoftTimeLimitExceeded:
        raise
    except Exception as e:
        logger.debug("open redirect test error for %s: %s", domain, e)
    return findings


def test_error_disclosure(session: requests.Session, target: str, domain: str) -> List[dict]:
    """
    Send malformed requests to probe for stack trace / error disclosure.
    Non-destructive: read-only, no data modification.
    """
    findings = []
    probes = [
        # Invalid parameter type
        {'id': "' INVALID", 'page': '-1', 'Submit': 'Submit'},
        # Extremely long value
        {'q': 'A' * 4096, 'Submit': 'Submit'},
        # Null bytes / special chars
        {'id': '\x00\x01\x02', 'Submit': 'Submit'},
    ]

    base_url = _strip_query(target)
    try:
        for params in probes:
            try:
                resp = session.get(base_url, params=params,
                                    timeout=_TIMEOUT, verify=False,
                                    allow_redirects=True)
                # Real bug found live: requiring status_code==500 excludes
                # the far more common real-world case - PHP renders a
                # Warning/Notice (exactly what _TRACE_PATTERNS looks for)
                # inline on a normal 200 OK page by default; only an
                # uncaught fatal error becomes a 500, and not always even
                # then depending on server config. The trace pattern match
                # itself is the actual signal (a specific, low-false-
                # positive-rate set of real framework/DBMS error strings) -
                # the status code was an over-restrictive additional gate
                # that contradicted the pattern list's own intent.
                match = _TRACE_RE.search(resp.text)
                if match:
                    snippet = resp.text[max(0, match.start()-30):match.end()+80]
                    findings.append(normalize_finding(
                        module=MODULE, tool='owasp', type_='error_disclosure',
                        title=f'Error/stack trace disclosure (HTTP {resp.status_code})',
                        evidence=f'Stack trace or framework error exposed: ...{snippet[:200]}...',
                        severity='Medium', target=domain,
                    ))
                    return findings
            except requests.RequestException:
                pass
    except SoftTimeLimitExceeded:
        raise
    except Exception as e:
        logger.debug("error disclosure test error for %s: %s", domain, e)
    return findings


# Numeric path segment, e.g. /allocations/2 - most common object-ID shape
# (auto-increment DB ids, simple sequence counters).
_NUMERIC_ID_RE = re.compile(r'/(\d+)(?=/|$|\?)')
# MongoDB ObjectId-shaped path segment, e.g. /users/507f1f77bcf86cd799439011 -
# 4-byte timestamp + 5-byte random + 3-byte counter, hex-encoded.
_OBJECTID_ID_RE = re.compile(r'/([0-9a-fA-F]{24})(?=/|$|\?)')
# Response bodies matching these are far more likely a legitimate "you can't
# see this" page than someone else's real data - excluded from the diff-based
# IDOR heuristic below to keep the false-positive rate down.
_ACCESS_DENIED_RE = re.compile(
    r'not found|access denied|forbidden|unauthorized|permission denied|'
    r'invalid (user|id)|no such', re.IGNORECASE)


def test_idor(session: requests.Session, target: str, domain: str) -> List[dict]:
    """
    Best-effort Insecure Direct Object Reference check: if the URL contains
    what looks like an object id (a numeric path segment, or a MongoDB
    ObjectId), nudge it to a handful of nearby values and compare against the
    baseline response. A 200 response with substantially different, non-
    "access denied"-shaped content at a *different* id - using the exact same
    (possibly authenticated) session that fetched the baseline - means the
    server handed back someone/something else's data without checking that
    the session is entitled to it.

    Only meaningful with authenticated scanning (schemas.py's AuthConfig) -
    without a login, "my resource" vs. "someone else's resource" mostly
    doesn't apply. run_owasp only dispatches this test when the scan has
    auth configured (real false positive found live otherwise: any site with
    sequential-looking IDs and distinct-but-public per-ID content - product
    pages, blog posts - reads as a High IDOR with no login involved at all).

    # ponytail: adjacent-id guessing only catches sequential/auto-increment-
    # shaped ids (confirmed effective against NodeGoat's own textbook IDOR at
    # /allocations/:userId, where seeded demo users get ids 1/2/3) or ids
    # created moments apart in the same ObjectId counter window - it will
    # miss anything using genuinely random/UUID-style ids. Upgrade path: feed
    # this a second real user's id (e.g. from a signup response) instead of
    # guessing, if a target's ids don't happen to be sequential.
    """
    findings = []
    try:
        baseline = session.get(target, **_SESSION_KWARGS)
        if baseline.status_code != 200 or len(baseline.text.strip()) < 50:
            return findings

        parsed = urllib.parse.urlparse(target)
        path = parsed.path
        candidates = []

        m = _NUMERIC_ID_RE.search(path)
        if m:
            original = int(m.group(1))
            for delta in (1, -1, 2, -2):
                new_id = original + delta
                if new_id < 0:
                    continue
                new_path = path[:m.start(1)] + str(new_id) + path[m.end(1):]
                candidates.append(parsed._replace(path=new_path).geturl())

        m = _OBJECTID_ID_RE.search(path)
        if m:
            original_hex = m.group(1)
            counter = int(original_hex[-6:], 16)
            for delta in (1, -1, 2, -2):
                new_counter = (counter + delta) % 0xFFFFFF
                new_hex = original_hex[:-6] + format(new_counter, '06x')
                new_path = path[:m.start(1)] + new_hex + path[m.end(1):]
                candidates.append(parsed._replace(path=new_path).geturl())

        for candidate_url in candidates[:6]:
            try:
                resp = session.get(candidate_url, **_SESSION_KWARGS)
                if (resp.status_code == 200
                        and len(resp.text.strip()) >= 50
                        and resp.text != baseline.text
                        and not _ACCESS_DENIED_RE.search(resp.text)):
                    findings.append(normalize_finding(
                        module=MODULE, tool='owasp', type_='idor',
                        title='Potential Insecure Direct Object Reference (IDOR)',
                        evidence=f'Same session that fetched {target} also got '
                                 f'a different, valid-looking 200 response from '
                                 f'{candidate_url} (object id changed, no '
                                 f'authorization rejection observed)',
                        severity='High', target=domain,
                        confidence='probable', verifiable=True,
                        verification_target={'url': candidate_url, 'baseline_url': target},
                    ))
                    return findings
            except requests.RequestException:
                pass
    except SoftTimeLimitExceeded:
        raise
    except Exception as e:
        logger.debug("idor test error for %s: %s", domain, e)
    return findings


# outcome -> (type, severity). 'confirmed'/'probable' are informational (the
# scan proceeded as intended); 'failed'/'error' are Medium - an authenticated
# scan that silently ran unauthenticated is a materially incomplete result,
# not just a footnote, and deserves the same visibility a failed module gets.
_LOGIN_OUTCOME_FINDING = {
    'confirmed': ('auth_login_confirmed', 'Informational'),
    'probable': ('auth_login_probable', 'Informational'),
    'failed': ('auth_login_failed', 'Medium'),
    'error': ('auth_login_failed', 'Medium'),
}


def _login_result_finding(login_result: dict, domain: str) -> Optional[dict]:
    """
    Turns _make_session's session.login_result into a normal finding, so
    "did the authenticated scan actually authenticate" is visible in the
    dashboard/PDF report like everything else, instead of only ever showing
    up as a log line on the worker's own disk. Returns None when auth
    wasn't configured for this scan at all (nothing to report).
    """
    if not login_result.get('attempted'):
        return None
    outcome = login_result.get('outcome') or 'failed'
    type_, severity = _LOGIN_OUTCOME_FINDING.get(outcome, _LOGIN_OUTCOME_FINDING['failed'])
    title = {
        'auth_login_confirmed': 'Authenticated scan: login confirmed',
        'auth_login_probable': 'Authenticated scan: login probably succeeded (unverified)',
        'auth_login_failed': 'Authenticated scan: login failed - tests ran unauthenticated',
    }[type_]
    return normalize_finding(
        module=MODULE, tool='owasp', type_=type_, title=title,
        evidence=login_result.get('detail') or 'No further detail available.',
        severity=severity, target=domain,
        confidence='confirmed' if outcome == 'confirmed' else 'probable',
    )


def scan_owasp(scan_id: str, domain: str, auth: dict = None) -> dict:
    """
    Pure half (runs locally or on Modal via tasks.dispatch). `auth` is passed in
    by the dispatcher (fetched from Redis on Oracle) - the pure half never reads
    Redis itself, so it can run on a stateless Modal container.

    OWASP Top 10 module: 6 non-destructive active tests (SQLi, XSS, path
    traversal, open redirect, error disclosure, IDOR), run against a
    same-origin crawl of up to _MAX_CRAWL_PAGES pages rather than just the
    bare domain root (see _discover_urls' docstring for why).
    All payloads are read-only GET requests - no data modification ever.
    Pure Python (requests) - tool_versions is always empty for this module.
    Returns a build_module_result() envelope (Section 4.3 schema note).

    Time budget: raised from the inherited 300s/360s default. Fast (~1-2s)
    against local Docker targets, but real, measured behavior against a real
    external target (testphp.vulnweb.com, docs/test_findings.md) genuinely
    exceeded both this soft (360s) and hard (420s) limit - real internet
    latency across ~800 worst-case requests adds up fast, unlike near-instant
    local containers.

    Real bug found and fixed alongside this measurement, not just a timeout
    number: SoftTimeLimitExceeded is a plain Exception subclass (confirmed:
    `SoftTimeLimitExceeded.__mro__` includes Exception), so every one of this
    module's `except Exception` blocks - all 6 test functions, the crawl
    loop, and the outer per-URL loop below - was silently swallowing Celery's
    graceful-shutdown signal the instant it landed inside whichever one
    happened to be running, letting execution carry on to the next URL/test
    instead of unwinding. The task then ran straight into the hard time_limit
    SIGKILL every time instead of ever reaching this function's own
    `except SoftTimeLimitExceeded` handler below - exactly the "hard kill
    the orchestrator can't see" gap Section 4.3b already documents, just
    triggered every single time instead of only on a genuine runaway. Fixed
    by re-raising SoftTimeLimitExceeded before each of those broad catches,
    so it now actually reaches this function and returns a proper
    status='timeout' envelope with whatever findings were already collected,
    instead of vanishing under a SIGKILL the scan orchestrator has to wait
    out via the coarse stuck-scan reaper.
    """
    start = time.monotonic()
    findings = []
    target = resolve_target_url(domain)
    session = _make_session(auth)
    login_finding = _login_result_finding(session.login_result, domain)
    if login_finding:
        findings.append(login_finding)

    # test_idor is only meaningful with an authenticated session (its own
    # docstring says so) - real false-positive found live (Opus review): run
    # unconditionally, it flags any site with sequential-looking numeric IDs
    # and distinct-but-public content per ID (product pages, blog posts,
    # news articles) as a High IDOR, since there's no "someone else's data"
    # concept to violate without a login. Gate it on auth actually being
    # configured for this scan instead of always dispatching it.
    active_tests = (test_sqli, test_xss, test_path_traversal,
                     test_open_redirect, test_error_disclosure)
    if auth:
        active_tests = active_tests + (test_idor,)

    try:
        discovered = _discover_urls(session, target, domain)
        for url in discovered:
            for test_fn in active_tests:
                try:
                    findings.extend(test_fn(session, url, domain))
                except SoftTimeLimitExceeded:
                    raise
                except Exception as e:
                    logger.error("owasp %s failed for scan %s (url=%s): %s",
                                 test_fn.__name__, scan_id, url, e)

        return build_module_result(MODULE, findings, {}, status='success',
                                    duration_seconds=time.monotonic() - start)
    except SoftTimeLimitExceeded:
        logger.warning("owasp hit its soft time limit for scan %s", scan_id)
        return build_module_result(MODULE, findings, {}, status='timeout',
                                    error='Module exceeded its soft time limit',
                                    duration_seconds=time.monotonic() - start)
    except Exception as e:
        logger.exception("owasp unexpected error scan=%s: %s", scan_id, e)
        return build_module_result(MODULE, findings, {}, status='failed',
                                    error=str(e), duration_seconds=time.monotonic() - start)


@app.task(base=BaseTask, name='tasks.owasp.run_owasp',
          soft_time_limit=scaled_timeout(360), time_limit=scaled_timeout(420))
def run_owasp(scan_id: str, domain: str) -> dict:
    """Dispatcher: owns the DB status writes (module namespace); tasks.dispatch
    picks where the pure half runs (local subprocess vs Modal)."""
    update_module_status(scan_id, MODULE, 'running')
    from tasks.dispatch import dispatch_scan
    envelope = dispatch_scan(MODULE, scan_id, domain)
    update_module_status(scan_id, MODULE,
                         'complete' if envelope.get('status') in ('success', 'partial') else 'failed')
    return envelope
