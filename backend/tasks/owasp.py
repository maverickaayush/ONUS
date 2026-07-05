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
    BaseTask, normalize_finding, update_module_status, build_module_result, resolve_target_url,
)
from tasks.celery_app import app

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)
MODULE = 'owasp'

_TIMEOUT = 30
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
        params = {'id': '1', 'q': 'test', 'search': 'test'}
    return params


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
_CRAWL_PAGE_TIMEOUT = 10
_CRAWL_BUDGET_SECONDS = 60


class _LinkExtractor(HTMLParser):
    """Collects <a href=...> and <form action=...> targets from one page."""

    def __init__(self):
        super().__init__()
        self.links: List[str] = []

    def handle_starttag(self, tag: str, attrs: list) -> None:
        attrs_dict = dict(attrs)
        if tag == 'a' and attrs_dict.get('href'):
            self.links.append(attrs_dict['href'])
        elif tag == 'form' and attrs_dict.get('action'):
            self.links.append(attrs_dict['action'])


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
        self._in_form = False

    def handle_starttag(self, tag: str, attrs: list) -> None:
        attrs_dict = dict(attrs)
        if tag == 'form':
            self._in_form = True
        elif tag == 'input' and self._in_form:
            name = attrs_dict.get('name')
            if name:
                self.fields[name] = attrs_dict.get('value', '')

    def handle_endtag(self, tag: str) -> None:
        if tag == 'form':
            self._in_form = False


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
    """
    session = requests.Session()
    if not auth:
        return session
    try:
        login_page = session.get(auth['login_url'], timeout=_TIMEOUT, verify=False)
        extractor = _FormFieldExtractor()
        extractor.feed(login_page.text)
        form_data = dict(extractor.fields)
        form_data[auth['username_field']] = auth['username']
        form_data[auth['password_field']] = auth['password']

        resp = session.post(
            auth['login_url'], data=form_data,
            timeout=_TIMEOUT, verify=False, allow_redirects=True,
        )
        indicator = auth.get('logged_in_indicator')
        if indicator and not re.search(indicator, resp.text):
            logger.warning("owasp login for domain may have failed - "
                            "logged_in_indicator %r not found in post-login "
                            "response", indicator)
    except requests.RequestException as e:
        logger.warning("owasp login POST to %s failed (continuing "
                        "unauthenticated): %s", auth.get('login_url'), e)
    return session


def _discover_urls(session: requests.Session, target: str, domain: str) -> List[str]:
    """
    Same-origin BFS crawl, capped at _MAX_CRAWL_PAGES / _CRAWL_BUDGET_SECONDS
    (monotonic deadline loop, same pattern as webscan.py's _ZAP_SCAN_BUDGET).
    Always returns `target` as element 0, even if the crawl finds nothing
    else - existing single-target behavior is a strict subset of this.
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
        except Exception as e:
            logger.debug("crawl fetch failed for %s: %s", url, e)
            continue

        for link in parser.links:
            absolute = urllib.parse.urljoin(url, link)
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

    try:
        # Baseline response for boolean comparison
        baseline = session.get(target, params=base_params, **_SESSION_KWARGS)
        baseline_len = len(baseline.text)

        for param in list(base_params.keys())[:3]:  # limit to first 3 params
            for payload in payloads[:2]:  # 2 payloads per param
                injected = dict(base_params)
                injected[param] = payload
                try:
                    resp = session.get(target, params=injected, **_SESSION_KWARGS)
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

    try:
        for param in list(base_params.keys())[:3]:
            for payload in payloads[:2]:
                injected = dict(base_params)
                injected[param] = payload
                try:
                    resp = session.get(target, params=injected, **_SESSION_KWARGS)
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
                            verification_target={'url': target, 'params': injected,
                                                  'payload': payload, 'marker': marker},
                        ))
                        return findings
                except requests.RequestException:
                    pass
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
    indicators = ['root:x:', 'root:!:', '/bin/bash', '/bin/sh']

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
        for param in [p for p in base_params if any(
                k in p.lower() for k in ('file', 'path', 'page', 'doc', 'view'))]:
            injected = dict(base_params)
            injected[param] = '../../../../etc/passwd'
            try:
                resp = session.get(target, params=injected, **_SESSION_KWARGS)
                if any(ind in resp.text for ind in indicators):
                    findings.append(normalize_finding(
                        module=MODULE, tool='owasp', type_='path_traversal',
                        title='Path traversal via parameter - /etc/passwd readable',
                        evidence=f'Parameter "{param}" with traversal payload '
                                 f'returned /etc/passwd content',
                        severity='Critical', target=domain,
                        confidence='probable', verifiable=True,
                        verification_target={'url': target, 'param': param,
                                              'payload': injected[param]},
                    ))
                    return findings
            except requests.RequestException:
                pass
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

    try:
        for param in redirect_params:
            try:
                resp = session.get(
                    target,
                    params={param: external_url},
                    timeout=_TIMEOUT,
                    verify=False,
                    allow_redirects=False,
                )
                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get('Location', '')
                    if 'evil-vapt-test.example.com' in location:
                        findings.append(normalize_finding(
                            module=MODULE, tool='owasp', type_='open_redirect',
                            title='Open Redirect vulnerability',
                            evidence=f'Parameter "{param}" redirects to '
                                     f'injected URL: {location}',
                            severity='Medium', target=domain,
                            confidence='probable', verifiable=True,
                            verification_target={'url': target, 'param': param,
                                                  'payload': external_url},
                        ))
                        return findings
            except requests.RequestException:
                pass
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
        {'id': "' INVALID", 'page': '-1'},
        # Extremely long value
        {'q': 'A' * 4096},
        # Null bytes / special chars
        {'id': '\x00\x01\x02'},
    ]

    try:
        for params in probes:
            try:
                resp = session.get(target, params=params,
                                    timeout=_TIMEOUT, verify=False,
                                    allow_redirects=True)
                if resp.status_code == 500 and _TRACE_RE.search(resp.text):
                    # Find the matched pattern for evidence
                    match = _TRACE_RE.search(resp.text)
                    snippet = resp.text[max(0, match.start()-30):match.end()+80]
                    findings.append(normalize_finding(
                        module=MODULE, tool='owasp', type_='error_disclosure',
                        title='Error/stack trace disclosure on 500 response',
                        evidence=f'Stack trace or framework error exposed: ...{snippet[:200]}...',
                        severity='Medium', target=domain,
                    ))
                    return findings
            except requests.RequestException:
                pass
    except Exception as e:
        logger.debug("error disclosure test error for %s: %s", domain, e)
    return findings


@app.task(base=BaseTask, name='tasks.owasp.run_owasp',
          soft_time_limit=360, time_limit=420)
def run_owasp(scan_id: str, domain: str) -> dict:
    """
    OWASP Top 10 module: 5 non-destructive active tests, run against a
    same-origin crawl of up to _MAX_CRAWL_PAGES pages rather than just the
    bare domain root (see _discover_urls' docstring for why).
    All payloads are read-only GET requests - no data modification ever.
    Pure Python (requests) - tool_versions is always empty for this module.
    Returns a build_module_result() envelope (Section 4.3 schema note).

    Time budget: raised from the inherited 300s/360s default. Worst case is
    ~34 requests/URL (5 test functions' payload counts) x up to 20 crawled
    URLs =~ 680 requests; realistically 1-3 minutes against small local
    targets, plus the crawl's own 60s ceiling.
    # ponytail: sized from worst-case request-count math, not measured -
    # recalibrate against real numbers once this has run against a live target.
    """
    update_module_status(scan_id, MODULE, 'running')
    start = time.monotonic()
    findings = []
    target = resolve_target_url(domain)
    from tasks.auth_store import get_scan_auth
    session = _make_session(get_scan_auth(scan_id))

    try:
        discovered = _discover_urls(session, target, domain)
        for url in discovered:
            for test_fn in (test_sqli, test_xss, test_path_traversal,
                            test_open_redirect, test_error_disclosure):
                try:
                    findings.extend(test_fn(session, url, domain))
                except Exception as e:
                    logger.error("owasp %s failed for scan %s (url=%s): %s",
                                 test_fn.__name__, scan_id, url, e)

        update_module_status(scan_id, MODULE, 'complete')
        return build_module_result(MODULE, findings, {}, status='success',
                                    duration_seconds=time.monotonic() - start)
    except SoftTimeLimitExceeded:
        logger.warning("owasp hit its soft time limit for scan %s", scan_id)
        update_module_status(scan_id, MODULE, 'failed')
        return build_module_result(MODULE, findings, {}, status='timeout',
                                    error='Module exceeded its soft time limit',
                                    duration_seconds=time.monotonic() - start)
    except Exception as e:
        logger.exception("owasp unexpected error scan=%s: %s", scan_id, e)
        update_module_status(scan_id, MODULE, 'failed')
        return build_module_result(MODULE, findings, {}, status='failed',
                                    error=str(e), duration_seconds=time.monotonic() - start)
