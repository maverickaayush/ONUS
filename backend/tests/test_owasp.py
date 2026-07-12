"""
Step 5 verification tests for the owasp module.

Run with:
    cd backend && python3 -m pytest tests/test_owasp.py -v
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unittest.mock import patch, MagicMock
import pytest
import requests

REQUIRED_FIELDS = {'module', 'tool', 'type', 'title', 'evidence',
                   'severity', 'cvss', 'target', 'found_by'}
VALID_SEVERITIES = {'Critical', 'High', 'Medium', 'Low', 'Informational', 'Info'}
MODULE = 'owasp'
TEST_DOMAIN = 'testphp.vulnweb.com'
TEST_SCAN_ID = 'test-owasp-step5'


def _mock_resp(text='', status=200, headers=None, location=None):
    resp = MagicMock()
    resp.text = text
    resp.status_code = status
    resp.headers = headers or {}
    if location:
        resp.headers['Location'] = location
    return resp


def _mock_session(get_side_effect=None, get_return_value=None):
    """A MagicMock standing in for requests.Session - every test function
    below now takes `session` as its first arg and calls session.get(...)
    instead of the old module-level requests.get(...)."""
    session = MagicMock()
    if get_side_effect is not None:
        session.get.side_effect = get_side_effect
    else:
        session.get.return_value = get_return_value or _mock_resp()
    return session


class TestOwaspSchema:

    def test_all_required_fields(self):
        from tasks.base_task import normalize_finding
        f = normalize_finding(MODULE, 'owasp', 'sqli_error_based',
                              'SQL Injection', 'evidence', 'High',
                              target=TEST_DOMAIN)
        assert not (REQUIRED_FIELDS - set(f.keys()))
        assert f['found_by'] == [MODULE]

    def test_sqli_error_based_detected(self):
        """SQL error pattern in response must produce a High finding."""
        from tasks.owasp import test_sqli

        def mock_get(url, **kwargs):
            params = kwargs.get('params', {})
            if "' OR '1'='1" in str(params.values()):
                return _mock_resp("You have an error in your SQL syntax near")
            return _mock_resp("normal response " * 10)

        session = _mock_session(get_side_effect=mock_get)
        findings = test_sqli(session, f'https://{TEST_DOMAIN}?id=1', TEST_DOMAIN)

        assert findings, "SQL error pattern must produce a finding"
        assert findings[0]['severity'] == 'High'
        assert findings[0]['type'] == 'sqli_error_based'
        assert REQUIRED_FIELDS <= set(findings[0].keys())
        assert findings[0]['found_by'] == [MODULE]
        # A DBMS error string IS the proof - confirmed directly, no verifier dispatch.
        assert findings[0]['confidence'] == 'confirmed'
        assert findings[0]['verifiable'] is False

    def test_sqli_no_finding_on_clean_response(self):
        """Clean response must produce no SQLi findings."""
        from tasks.owasp import test_sqli

        session = _mock_session(get_return_value=_mock_resp("Welcome to our site"))
        findings = test_sqli(session, f'https://{TEST_DOMAIN}?id=1', TEST_DOMAIN)

        assert findings == []

    def test_strip_query_removes_existing_query_string(self):
        from tasks.owasp import _strip_query
        assert _strip_query(f'https://{TEST_DOMAIN}/search?q=test') == f'https://{TEST_DOMAIN}/search'
        assert _strip_query(f'https://{TEST_DOMAIN}/search') == f'https://{TEST_DOMAIN}/search'

    def test_sqli_detects_injection_when_target_already_has_query_string(self):
        """
        Real bug found live (reproduced against a local mock server while
        verifying the crawl-depth fix, docs/test_findings.md-style): calling
        requests.get(url, params=X) when `url` already has its own query
        string APPENDS to it rather than replacing it - a request for
        "target?q=test" with params={'q': injected} actually sent both
        "q=test" AND "q=<injected>", so whichever one the target server
        preferred (often the first) could silently win, defeating the
        injection. Invisible before the crawl-depth fix, since owasp.py
        used to only ever re-test the bare domain root (no query string of
        its own) - now that real discovered pages carry their own query
        strings, this must actually work.
        """
        from tasks.owasp import test_sqli

        seen_urls = []

        def mock_get(url, **kwargs):
            seen_urls.append(url)
            params = kwargs.get('params', {})
            if "' OR '1'='1" in str(params.values()):
                return _mock_resp("You have an error in your SQL syntax near")
            return _mock_resp("normal response " * 10)

        session = _mock_session(get_side_effect=mock_get)
        target = f'https://{TEST_DOMAIN}/search?q=test'
        findings = test_sqli(session, target, TEST_DOMAIN)

        assert findings, "injection must be detected even when target already has a query string"
        assert findings[0]['type'] == 'sqli_error_based'
        # every request must go out against a query-free base URL, with the
        # full (original + injected) param set supplied via params= instead -
        # otherwise the injected param just gets appended as a duplicate key
        # alongside the original, untouched value.
        assert all('?' not in u for u in seen_urls), \
            f"requests must use a query-free base URL, got {seen_urls}"

    def test_xss_reflected_detected(self):
        """XSS payload reflected verbatim must produce a High finding."""
        from tasks.owasp import test_xss
        marker = 'VAPT_XSS_8675309'

        def mock_get(url, **kwargs):
            params = kwargs.get('params', {})
            for v in params.values():
                if marker in str(v):
                    return _mock_resp(str(v))  # reflect the payload
            return _mock_resp("clean")

        session = _mock_session(get_side_effect=mock_get)
        findings = test_xss(session, f'https://{TEST_DOMAIN}?q=hello', TEST_DOMAIN)

        assert findings, "Reflected payload must produce a finding"
        assert findings[0]['severity'] == 'High'
        assert findings[0]['type'] == 'reflected_xss'
        assert findings[0]['found_by'] == [MODULE]
        # Phase 2: verifiable via headless-browser re-check
        # (analysis/verifier.py's verify_reflected_xss).
        assert findings[0]['confidence'] == 'probable'
        assert findings[0]['verifiable'] is True
        vt = findings[0]['verification_target']
        assert vt['marker'] == marker
        assert vt['payload'] in (
            f'<script>alert("{marker}")</script>',
            f'"><img src=x onerror=alert("{marker}")>',
        )
        assert vt['url'] and isinstance(vt['params'], dict)

    def test_xss_no_finding_on_escaped_response(self):
        """HTML-escaped payload must NOT produce an XSS finding."""
        from tasks.owasp import test_xss

        session = _mock_session(get_return_value=_mock_resp('&lt;script&gt;alert&lt;/script&gt;'))
        findings = test_xss(session, f'https://{TEST_DOMAIN}?q=x', TEST_DOMAIN)

        assert findings == []

    def test_open_redirect_detected(self):
        """302 to injected external URL must produce a Medium finding."""
        from tasks.owasp import test_open_redirect

        def mock_get(url, **kwargs):
            params = kwargs.get('params', {})
            if 'evil-vapt-test.example.com' in str(params.values()):
                return _mock_resp(status=302,
                                  location='https://evil-vapt-test.example.com/pwned')
            return _mock_resp()

        session = _mock_session(get_side_effect=mock_get)
        findings = test_open_redirect(session, f'https://{TEST_DOMAIN}', TEST_DOMAIN)

        assert findings, "Redirect to injected URL must produce a finding"
        assert findings[0]['type'] == 'open_redirect'
        assert findings[0]['severity'] == 'Medium'
        assert findings[0]['found_by'] == [MODULE]
        assert findings[0]['confidence'] == 'probable'
        assert findings[0]['verifiable'] is True
        vt = findings[0]['verification_target']
        assert vt['payload'] == 'https://evil-vapt-test.example.com'
        assert vt['param'] and vt['url']

    def test_open_redirect_same_site_echo_is_not_a_finding(self):
        """Real false positive found live: a same-site redirect that merely
        echoes the payload back as a query-string substring (e.g. Mutillidae's
        `index.php?page=X&next=<value>` "return to this page" pattern) must
        NOT be reported - only a Location that actually resolves to the
        injected external host counts."""
        from tasks.owasp import test_open_redirect

        def mock_get(url, **kwargs):
            params = kwargs.get('params', {})
            if 'evil-vapt-test.example.com' in str(params.values()):
                return _mock_resp(status=302,
                                  location=f'https://{TEST_DOMAIN}/index.php'
                                           f'?next=https%3A%2F%2Fevil-vapt-test.example.com')
            return _mock_resp()

        session = _mock_session(get_side_effect=mock_get)
        findings = test_open_redirect(session, f'https://{TEST_DOMAIN}', TEST_DOMAIN)

        assert findings == []

    def test_path_traversal_via_url_path_detected(self):
        """/etc/passwd content in response to a direct URL traversal probe
        must produce a Critical finding with a verification_target."""
        from tasks.owasp import test_path_traversal

        def mock_get(url, **kwargs):
            if 'etc/passwd' in url:
                return _mock_resp('root:x:0:0:root:/root:/bin/bash')
            return _mock_resp('clean')

        session = _mock_session(get_side_effect=mock_get)
        findings = test_path_traversal(session, f'https://{TEST_DOMAIN}', TEST_DOMAIN)

        assert findings, "passwd content must produce a finding"
        assert findings[0]['type'] == 'path_traversal'
        assert findings[0]['severity'] == 'Critical'
        assert findings[0]['confidence'] == 'probable'
        assert findings[0]['verifiable'] is True
        assert findings[0]['verification_target']['param'] is None
        assert 'etc/passwd' in findings[0]['verification_target']['url']

    def test_error_disclosure_detected(self):
        """Stack trace in 500 response must produce a Medium finding."""
        from tasks.owasp import test_error_disclosure

        trace = "Traceback (most recent call last):\n  File app.py line 42\nKeyError: 'id'"
        session = _mock_session(get_return_value=_mock_resp(trace, status=500))
        findings = test_error_disclosure(session, f'https://{TEST_DOMAIN}', TEST_DOMAIN)

        assert findings, "Stack trace in 500 must produce a finding"
        assert findings[0]['type'] == 'error_disclosure'
        assert findings[0]['severity'] == 'Medium'

    def test_error_disclosure_no_finding_on_clean_500(self):
        """Generic 500 with no trace must NOT produce a finding."""
        from tasks.owasp import test_error_disclosure

        session = _mock_session(get_return_value=_mock_resp("Internal Server Error", status=500))
        findings = test_error_disclosure(session, f'https://{TEST_DOMAIN}', TEST_DOMAIN)

        assert findings == []

    def test_error_disclosure_detected_on_200(self):
        """Real bug found live: PHP renders Warning/Notice text inline on a
        normal 200 OK page by default (only an uncaught fatal becomes a 500,
        and not always even then) - a status_code==500 requirement excluded
        this, the far more common real-world shape. The trace pattern match
        itself must be the signal, regardless of status code."""
        from tasks.owasp import test_error_disclosure

        trace = "PHP Warning:  mysqli::query(): in /app/db.php on line 42"
        session = _mock_session(get_return_value=_mock_resp(trace, status=200))
        findings = test_error_disclosure(session, f'https://{TEST_DOMAIN}', TEST_DOMAIN)

        assert findings, "Warning text on a 200 response must produce a finding"
        assert findings[0]['type'] == 'error_disclosure'

    def test_network_error_returns_empty(self):
        """Any network error in a test must return [] gracefully."""
        from tasks.owasp import test_sqli

        session = _mock_session(get_side_effect=requests.exceptions.ConnectionError("refused"))
        findings = test_sqli(session, f'https://unreachable.invalid?id=1',
                             'unreachable.invalid')

        assert findings == []

    def test_idor_detects_different_valid_content_at_adjacent_numeric_id(self):
        """Regression test for the real NodeGoat /allocations/:userId IDOR
        this was built for: same session, numeric id nudged by 1, server
        returns different-but-valid (not access-denied-shaped) content ->
        must flag it."""
        from tasks.owasp import test_idor

        def mock_get(url, **kwargs):
            if url.endswith('/allocations/1'):
                return _mock_resp('<html>Allocations for user 1: stocks 60%, bonds 40%</html>')
            if url.endswith('/allocations/2'):
                return _mock_resp('<html>Allocations for user 2: stocks 20%, bonds 80%</html>')
            return _mock_resp(status=404)

        session = _mock_session(get_side_effect=mock_get)
        findings = test_idor(session, f'https://{TEST_DOMAIN}/allocations/1', TEST_DOMAIN)

        assert findings, "Different valid content at an adjacent id must be flagged"
        assert findings[0]['type'] == 'idor'
        assert findings[0]['severity'] == 'High'
        assert REQUIRED_FIELDS <= set(findings[0].keys())
        assert findings[0]['verifiable'] is True
        assert findings[0]['verification_target']['baseline_url'].endswith('/allocations/1')

    def test_idor_no_finding_when_adjacent_id_denied(self):
        """An access-denied-shaped response at the adjacent id (proper
        authorization check) must NOT be flagged."""
        from tasks.owasp import test_idor

        def mock_get(url, **kwargs):
            if url.endswith('/allocations/1'):
                return _mock_resp('<html>Allocations for user 1: stocks 60%, bonds 40%</html>')
            return _mock_resp('<html>Access Denied - Forbidden</html>', status=403)

        session = _mock_session(get_side_effect=mock_get)
        findings = test_idor(session, f'https://{TEST_DOMAIN}/allocations/1', TEST_DOMAIN)

        assert findings == []

    def test_idor_no_finding_when_no_id_shaped_segment(self):
        """A URL with no numeric/ObjectId-shaped path segment has nothing to
        mutate - must return [] without erroring."""
        from tasks.owasp import test_idor

        session = _mock_session(get_return_value=_mock_resp('<html>Dashboard</html>'))
        findings = test_idor(session, f'https://{TEST_DOMAIN}/dashboard', TEST_DOMAIN)

        assert findings == []


class TestOwaspCrawl:
    """_discover_urls: same-origin BFS crawl feeding the 5 test functions
    (Section: closing the crawl-depth gap documented against Mutillidae in
    docs/test_findings.md - owasp.py used to only ever test the bare domain
    root)."""

    def test_dedup_cap_and_same_origin_filtering(self):
        """A canned page linking to: itself again (dup), a fragment-only
        variant of itself (dup after normalization), an off-origin link
        (must be excluded), and one genuine same-origin page - must return
        exactly the origin root + the one genuine same-origin page, in that
        order, with the off-origin link excluded entirely."""
        from tasks.owasp import _discover_urls

        target = f'https://{TEST_DOMAIN}/'
        home_html = f'''
        <html><body>
            <a href="/">Home again</a>
            <a href="/#section">Home with fragment</a>
            <a href="https://evil.example.com/">Off-origin link</a>
            <a href="/about.php">About page</a>
        </body></html>
        '''
        about_html = '<html><body>No further links here.</body></html>'

        def mock_get(url, **kwargs):
            if url.rstrip('/') == target.rstrip('/'):
                return _mock_resp(home_html, headers={'Content-Type': 'text/html'})
            if 'about.php' in url:
                return _mock_resp(about_html, headers={'Content-Type': 'text/html'})
            return _mock_resp(status=404)

        session = _mock_session(get_side_effect=mock_get)
        discovered = _discover_urls(session, target, TEST_DOMAIN)

        assert discovered[0] == target, "target must always be element 0"
        assert len(discovered) == 2, \
            f"expected exactly [target, about.php], got {discovered}"
        assert any('about.php' in u for u in discovered)
        assert not any('evil.example.com' in u for u in discovered), \
            "off-origin links must never be followed"

    def test_never_follows_or_records_logout_link(self):
        """Regression test for the real bug this found against NodeGoat: a
        same-origin /logout link must never be fetched or recorded, since
        visiting it destroys the session the rest of the module depends on."""
        from tasks.owasp import _discover_urls

        target = f'https://{TEST_DOMAIN}/'
        home_html = '''
        <html><body>
            <a href="/dashboard">Dashboard</a>
            <a href="/logout">Logout</a>
            <a href="/signout">Sign Out</a>
        </body></html>
        '''

        def mock_get(url, **kwargs):
            if url.rstrip('/') == target.rstrip('/'):
                return _mock_resp(home_html, headers={'Content-Type': 'text/html'})
            if '/logout' in url or '/signout' in url:
                pytest.fail(f"crawl must never fetch a logout-shaped link, got {url}")
            return _mock_resp('<html>ok</html>', headers={'Content-Type': 'text/html'})

        session = _mock_session(get_side_effect=mock_get)
        discovered = _discover_urls(session, target, TEST_DOMAIN)

        assert any('dashboard' in u for u in discovered)
        assert not any('logout' in u.lower() for u in discovered)
        assert not any('signout' in u.lower() for u in discovered)

    def test_respects_max_page_cap(self):
        """A page that link-bombs itself with many unique same-origin URLs
        must stop discovering once _MAX_CRAWL_PAGES is reached."""
        from tasks.owasp import _discover_urls, _MAX_CRAWL_PAGES

        target = f'https://{TEST_DOMAIN}/'
        many_links = ''.join(f'<a href="/page{i}.php">p{i}</a>' for i in range(50))
        html = f'<html><body>{many_links}</body></html>'

        def mock_get(url, **kwargs):
            return _mock_resp(html, headers={'Content-Type': 'text/html'})

        session = _mock_session(get_side_effect=mock_get)
        discovered = _discover_urls(session, target, TEST_DOMAIN)

        assert len(discovered) <= _MAX_CRAWL_PAGES

    def test_non_html_response_is_not_parsed(self):
        """A non-HTML content-type must be skipped rather than fed to the
        HTML parser."""
        from tasks.owasp import _discover_urls

        target = f'https://{TEST_DOMAIN}/data.json'
        session = _mock_session(get_return_value=_mock_resp(
            '{"not": "html"}', headers={'Content-Type': 'application/json'}))
        discovered = _discover_urls(session, target, TEST_DOMAIN)

        assert discovered == [target]

    def test_follows_meta_refresh_when_it_is_the_only_navigation(self):
        """Real bug found live against oa.iitk.ac.in: a landing page whose
        only navigation is a meta-refresh into the real app (no <a>/<form>
        at all) used to leave `discovered` at just the target, silently
        giving the whole module zero real coverage while still reporting
        status: success."""
        from tasks.owasp import _discover_urls

        target = f'https://{TEST_DOMAIN}/'
        landing_html = f'''
        <html><head>
            <meta http-equiv="refresh" content="0;url=https://{TEST_DOMAIN}/Oa/">
        </head><body>Redirecting...</body></html>
        '''
        app_html = '<html><body><a href="/Oa/dashboard">Dashboard</a></body></html>'

        def mock_get(url, **kwargs):
            if url.rstrip('/') == target.rstrip('/'):
                return _mock_resp(landing_html, headers={'Content-Type': 'text/html'})
            if '/Oa/dashboard' in url:
                return _mock_resp('<html>ok</html>', headers={'Content-Type': 'text/html'})
            if url.rstrip('/').endswith('/Oa'):
                return _mock_resp(app_html, headers={'Content-Type': 'text/html'})
            return _mock_resp(status=404)

        session = _mock_session(get_side_effect=mock_get)
        discovered = _discover_urls(session, target, TEST_DOMAIN)

        assert len(discovered) > 1, \
            "meta-refresh target must be followed, not left undiscovered"
        assert any('/Oa' in u for u in discovered)
        assert any('dashboard' in u for u in discovered)

    def test_meta_refresh_content_format_variants(self):
        """Real-world meta-refresh content values vary: quoted/unquoted URL,
        spacing, and case of the 'url=' key - all must parse."""
        from tasks.owasp import _discover_urls

        target = f'https://{TEST_DOMAIN}/'
        for content in (
            "0;url=/dashboard",
            "5; URL='/dashboard'",
            "0 ; url = /dashboard",
        ):
            html = f'<html><head><meta http-equiv="refresh" content="{content}"></head></html>'

            def mock_get(url, **kwargs):
                if url.rstrip('/') == target.rstrip('/'):
                    return _mock_resp(html, headers={'Content-Type': 'text/html'})
                return _mock_resp('<html>ok</html>', headers={'Content-Type': 'text/html'})

            session = _mock_session(get_side_effect=mock_get)
            discovered = _discover_urls(session, target, TEST_DOMAIN)
            assert any('dashboard' in u for u in discovered), \
                f"failed to parse meta-refresh content={content!r}"

    def test_off_origin_meta_refresh_is_not_followed(self):
        """Same same-origin guard that already applies to <a href> must also
        apply to a meta-refresh target - a page must never be able to send
        this crawler to an unauthorized third-party host."""
        from tasks.owasp import _discover_urls

        target = f'https://{TEST_DOMAIN}/'
        html = '''
        <html><head>
            <meta http-equiv="refresh" content="0;url=https://evil.example.com/">
        </head></html>
        '''
        session = _mock_session(get_return_value=_mock_resp(
            html, headers={'Content-Type': 'text/html'}))
        discovered = _discover_urls(session, target, TEST_DOMAIN)

        assert discovered == [target]
        assert not any('evil.example.com' in u for u in discovered)

    def test_meta_refresh_to_logout_link_is_not_followed(self):
        """Same session-destroying-link guard that already applies to
        <a href> must also apply to a meta-refresh target."""
        from tasks.owasp import _discover_urls

        target = f'https://{TEST_DOMAIN}/'
        html = f'''
        <html><head>
            <meta http-equiv="refresh" content="0;url=https://{TEST_DOMAIN}/logout">
        </head></html>
        '''

        def mock_get(url, **kwargs):
            if '/logout' in url:
                pytest.fail(f"crawl must never fetch a logout-shaped meta-refresh target, got {url}")
            return _mock_resp(html, headers={'Content-Type': 'text/html'})

        session = _mock_session(get_side_effect=mock_get)
        discovered = _discover_urls(session, target, TEST_DOMAIN)

        assert discovered == [target]
        assert not any('logout' in u.lower() for u in discovered)


class TestMakeSessionFormLogin:
    """
    _make_session's form-login path (GET login page, extract every <form>
    field via _FormFieldExtractor, override username/password, POST) had no
    dedicated test coverage at all - TestOwaspJsonSession in
    test_auth_login.py covers the JSON-login branch of the same function,
    but the older, more common form-login branch was only ever exercised
    live against real targets (DVWA, NodeGoat, ...), never in CI. Added
    after verifying the mechanism live against a local mock server that
    requires a real CSRF token + submit-button field to succeed.
    """

    def test_successful_login_submits_csrf_token_and_credentials(self):
        from tasks.owasp import _make_session

        login_page = _mock_resp('''
        <form action="/login" method="POST">
        <input type="hidden" name="csrf_token" value="tok-abc123">
        <input type="text" name="username">
        <input type="password" name="password">
        <input type="submit" name="Login" value="Login">
        </form>
        ''')
        post_calls = []

        def fake_post(self, url, data=None, **kwargs):
            post_calls.append(data)
            return _mock_resp('Welcome!')

        auth = {'login_url': 'https://x.test/login', 'username_field': 'username',
                'password_field': 'password', 'username': 'realuser', 'password': 'realpass',
                'logged_in_indicator': 'Welcome'}
        with patch.object(requests.Session, 'get', return_value=login_page), \
             patch.object(requests.Session, 'post', fake_post):
            session = _make_session(auth)

        assert session is not None
        assert len(post_calls) == 1
        posted = post_calls[0]
        # the real submitted username/password, not the page's own defaults
        assert posted['username'] == 'realuser'
        assert posted['password'] == 'realpass'
        # non-credential form fields (CSRF token, submit button) must still
        # be present - a naive username/password-only POST silently fails
        # against real CSRF-protected login forms (DVWA, NodeGoat).
        assert posted['csrf_token'] == 'tok-abc123'
        assert posted['Login'] == 'Login'
        assert session.login_result == {
            'attempted': True, 'outcome': 'confirmed',
            'detail': "logged_in_indicator 'Welcome' matched the post-login response.",
        }

    def test_login_form_action_differs_from_login_url(self):
        """
        Real bug found live against testfire.net (Altoro Mutual): its login
        form's action ("doLogin") is a different endpoint than the page
        hosting it ("login.jsp"). The old code POSTed unconditionally to
        login_url and never even reached the real endpoint - confirmed
        directly against the live site.
        """
        from tasks.owasp import _make_session

        login_page = _mock_resp('''
        <form action="doLogin" method="POST">
        <input type="text" name="uid">
        <input type="password" name="passw">
        </form>
        ''')
        post_calls = []

        def fake_post(self, url, data=None, **kwargs):
            post_calls.append(url)
            return _mock_resp('Login Failed')

        auth = {'login_url': 'https://x.test/login.jsp', 'username_field': 'uid',
                'password_field': 'passw', 'username': 'admin', 'password': 'admin'}
        with patch.object(requests.Session, 'get', return_value=login_page), \
             patch.object(requests.Session, 'post', fake_post):
            _make_session(auth)

        assert post_calls == ['https://x.test/doLogin']  # not login.jsp

    def test_get_method_login_form_uses_get_not_post(self):
        """
        Real bug found live against Google Gruyere (an intentionally
        insecure app whose login form deliberately uses GET as one of its
        own teaching points): the old code called session.post()
        unconditionally regardless of the form's declared method, so a
        GET-method login form's credentials were sent as a POST body the
        server never reads as login parameters at all - confirmed directly:
        self-registered a real account and it failed to authenticate until
        this fix.
        """
        from tasks.owasp import _make_session

        login_page = _mock_resp('''
        <form action="login" method="get">
        <input type="text" name="uid">
        <input type="password" name="pw">
        </form>
        ''')
        get_calls = []
        post_calls = []

        def fake_get(self, url, **kwargs):
            if 'params' in kwargs:
                get_calls.append((url, kwargs['params']))
                return _mock_resp('Sign out')
            return login_page  # the initial GET of the login page itself

        def fake_post(self, url, **kwargs):
            post_calls.append(url)
            return _mock_resp('should not happen')

        auth = {'login_url': 'https://x.test/login', 'username_field': 'uid',
                'password_field': 'pw', 'username': 'realuser', 'password': 'realpass',
                'logged_in_indicator': 'Sign out'}
        with patch.object(requests.Session, 'get', fake_get), \
             patch.object(requests.Session, 'post', fake_post):
            session = _make_session(auth)

        assert post_calls == []  # never POSTed
        assert len(get_calls) == 1
        url, params = get_calls[0]
        assert url == 'https://x.test/login'
        assert params['uid'] == 'realuser'
        assert params['pw'] == 'realpass'
        assert session.login_result['outcome'] == 'confirmed'

    def test_multiple_forms_on_page_only_login_form_fields_used(self):
        """
        Real bug found live against testfire.net: its login page also has a
        search form earlier in the HTML. The old _FormFieldExtractor merged
        ALL forms' fields into one flat dict regardless of source - a
        search box's field would get submitted alongside the real login
        fields, and if the search form happened to come first, its action
        would win over the actual login form's.
        """
        from tasks.owasp import _make_session

        login_page = _mock_resp('''
        <form action="/search" method="GET">
        <input type="text" name="query">
        </form>
        <form action="doLogin" method="POST">
        <input type="hidden" name="csrf_token" value="tok-xyz">
        <input type="text" name="uid">
        <input type="password" name="passw">
        </form>
        ''')
        post_calls = []

        def fake_post(self, url, data=None, **kwargs):
            post_calls.append((url, data))
            return _mock_resp('ok')

        auth = {'login_url': 'https://x.test/login.jsp', 'username_field': 'uid',
                'password_field': 'passw', 'username': 'admin', 'password': 'admin'}
        with patch.object(requests.Session, 'get', return_value=login_page), \
             patch.object(requests.Session, 'post', fake_post):
            _make_session(auth)

        assert len(post_calls) == 1
        url, data = post_calls[0]
        assert url == 'https://x.test/doLogin'
        assert 'query' not in data  # the search form's field must not leak in
        assert data['csrf_token'] == 'tok-xyz'

    def test_logged_in_indicator_mismatch_marks_failed_but_still_returns_session(self):
        """A wrong logged_in_indicator regex must not turn an otherwise-
        working authenticated scan into a hard failure - best-effort only -
        but it must be visible in login_result, not just a log line."""
        from tasks.owasp import _make_session

        login_page = _mock_resp('<form action="/login" method="POST"><input type="password" name="p"></form>')
        auth = {'login_url': 'https://x.test/login', 'username_field': 'username',
                'password_field': 'password', 'username': 'realuser', 'password': 'realpass',
                'logged_in_indicator': 'this-string-will-never-appear'}
        with patch.object(requests.Session, 'get', return_value=login_page), \
             patch.object(requests.Session, 'post', return_value=_mock_resp('Welcome!')):
            session = _make_session(auth)

        assert session is not None  # degrades to a warning, not a hard failure
        assert session.login_result['attempted'] is True
        assert session.login_result['outcome'] == 'failed'

    def test_no_indicator_password_field_still_present_marks_failed(self):
        """Best-effort heuristic when no logged_in_indicator is configured:
        a password field still present in the post-login response strongly
        suggests we're looking at the login page again."""
        from tasks.owasp import _make_session

        login_page = _mock_resp('<form action="/login" method="POST"><input type="password" name="p"></form>')
        still_login_form = _mock_resp('<form action="/login" method="POST"><input type="password" name="p"></form>')
        auth = {'login_url': 'https://x.test/login', 'username_field': 'username',
                'password_field': 'password', 'username': 'realuser', 'password': 'wrongpass'}
        with patch.object(requests.Session, 'get', return_value=login_page), \
             patch.object(requests.Session, 'post', return_value=still_login_form):
            session = _make_session(auth)

        assert session.login_result['outcome'] == 'failed'

    def test_no_indicator_password_field_gone_marks_probable(self):
        """Best-effort heuristic when no logged_in_indicator is configured:
        no password field in the response is a reasonable but unconfirmed
        sign of success - reported as 'probable', never 'confirmed'."""
        from tasks.owasp import _make_session

        login_page = _mock_resp('<form action="/login" method="POST"><input type="password" name="p"></form>')
        dashboard = _mock_resp('<html>Welcome to your dashboard</html>')
        auth = {'login_url': 'https://x.test/login', 'username_field': 'username',
                'password_field': 'password', 'username': 'realuser', 'password': 'realpass'}
        with patch.object(requests.Session, 'get', return_value=login_page), \
             patch.object(requests.Session, 'post', return_value=dashboard):
            session = _make_session(auth)

        assert session.login_result['outcome'] == 'probable'

    def test_login_page_fetch_failure_falls_back_unauthenticated(self):
        """A network error fetching the login page must not crash the
        module - continue unauthenticated, same non-fatal posture as the
        JSON-login branch."""
        from tasks.owasp import _make_session

        auth = {'login_url': 'https://x.test/login', 'username_field': 'username',
                'password_field': 'password', 'username': 'realuser', 'password': 'realpass'}
        with patch.object(requests.Session, 'get',
                          side_effect=requests.exceptions.ConnectionError('refused')):
            session = _make_session(auth)

        assert session is not None
        assert 'session' not in session.cookies  # never got a real cookie
        assert session.login_result['outcome'] == 'error'

    def test_no_auth_returns_plain_session(self):
        from tasks.owasp import _make_session
        session = _make_session(None)
        assert isinstance(session, requests.Session)
        assert not session.cookies
        assert 'Authorization' not in session.headers
        assert session.login_result == {'attempted': False, 'outcome': None, 'detail': None}


class TestLoginResultFinding:
    """_login_result_finding turns _make_session's login_result into a
    normal finding, so authentication success/failure is visible in the
    dashboard/PDF report - previously invisible anywhere outside worker
    logs."""

    def test_not_attempted_produces_no_finding(self):
        from tasks.owasp import _login_result_finding
        result = _login_result_finding({'attempted': False, 'outcome': None, 'detail': None}, TEST_DOMAIN)
        assert result is None

    def test_confirmed_produces_informational_finding(self):
        from tasks.owasp import _login_result_finding
        f = _login_result_finding(
            {'attempted': True, 'outcome': 'confirmed', 'detail': 'matched'}, TEST_DOMAIN)
        assert f['type'] == 'auth_login_confirmed'
        assert f['severity'] == 'Informational'
        assert f['confidence'] == 'confirmed'
        assert REQUIRED_FIELDS <= set(f.keys())

    def test_probable_produces_informational_finding(self):
        from tasks.owasp import _login_result_finding
        f = _login_result_finding(
            {'attempted': True, 'outcome': 'probable', 'detail': 'no indicator'}, TEST_DOMAIN)
        assert f['type'] == 'auth_login_probable'
        assert f['severity'] == 'Informational'
        assert f['confidence'] == 'probable'

    def test_failed_produces_medium_finding(self):
        from tasks.owasp import _login_result_finding
        f = _login_result_finding(
            {'attempted': True, 'outcome': 'failed', 'detail': 'still a login form'}, TEST_DOMAIN)
        assert f['type'] == 'auth_login_failed'
        assert f['severity'] == 'Medium'
        assert f['confidence'] == 'probable'

    def test_error_also_produces_medium_failed_finding(self):
        from tasks.owasp import _login_result_finding
        f = _login_result_finding(
            {'attempted': True, 'outcome': 'error', 'detail': 'connection refused'}, TEST_DOMAIN)
        assert f['type'] == 'auth_login_failed'
        assert f['severity'] == 'Medium'
        assert 'connection refused' in f['evidence']


class TestOwaspModuleStatus:

    def test_complete_on_success(self):
        status_calls = []

        def record(sid, mod, status):
            status_calls.append(status)

        with patch('tasks.owasp.update_module_status', side_effect=record), \
             patch('tasks.owasp.requests.Session.get', return_value=_mock_resp("clean")):
            from tasks.owasp import run_owasp
            run_owasp.run(TEST_SCAN_ID, TEST_DOMAIN)

        assert status_calls[0] == 'running'
        assert status_calls[-1] == 'complete'

    def test_one_test_failure_does_not_stop_others(self):
        """If one test function raises, remaining tests still run."""
        call_count = [0]

        def mock_get(url, **kwargs):
            call_count[0] += 1
            if call_count[0] <= 2:
                raise requests.exceptions.Timeout("timeout")
            return _mock_resp("clean")

        status_calls = []

        def record(sid, mod, status):
            status_calls.append(status)

        with patch('tasks.owasp.update_module_status', side_effect=record), \
             patch('tasks.owasp.requests.Session.get', side_effect=mock_get):
            from tasks.owasp import run_owasp
            result = run_owasp.run(TEST_SCAN_ID, TEST_DOMAIN)

        assert status_calls[-1] == 'complete', \
            "Module must still complete even when some tests time out"
        assert isinstance(result, dict)
        assert result['status'] == 'success'
        assert isinstance(result['findings'], list)

    def test_soft_time_limit_reaches_run_owasp_not_swallowed(self):
        """Regression test for a real bug: SoftTimeLimitExceeded is a plain
        Exception subclass, so it used to get silently caught by whichever
        test function's own broad `except Exception` happened to be running
        when Celery raised it - execution would then carry on to the next
        URL/test instead of unwinding, running straight into the un-catchable
        hard time_limit SIGKILL every time. Every test function (and the
        crawl loop, and the outer per-URL loop) must re-raise it instead."""
        from celery.exceptions import SoftTimeLimitExceeded

        def mock_get(url, **kwargs):
            raise SoftTimeLimitExceeded()

        status_calls = []

        def record(sid, mod, status):
            status_calls.append(status)

        with patch('tasks.owasp.update_module_status', side_effect=record), \
             patch('tasks.owasp.requests.Session.get', side_effect=mock_get):
            from tasks.owasp import run_owasp
            result = run_owasp.run(TEST_SCAN_ID, TEST_DOMAIN)

        assert result['status'] == 'timeout', \
            "SoftTimeLimitExceeded must reach run_owasp's own handler, not be swallowed"
        assert status_calls[-1] == 'failed'

    def test_all_findings_have_required_fields(self):
        """Every finding from a full run must match Section 4.3 schema."""
        from tasks.owasp import test_sqli, test_xss, test_error_disclosure

        marker = 'VAPT_XSS_8675309'

        def mock_get(url, **kwargs):
            params = kwargs.get('params', {})
            vals = str(params.values())
            if 'OR' in vals and "1'='1" in vals:
                return _mock_resp("You have an error in your SQL syntax")
            if marker in vals:
                for v in params.values():
                    if marker in str(v):
                        return _mock_resp(str(v))
            return _mock_resp("clean " * 5)

        target = f'https://{TEST_DOMAIN}?id=1'
        session = _mock_session(get_side_effect=mock_get)
        findings = test_sqli(session, target, TEST_DOMAIN)

        for f in findings:
            missing = REQUIRED_FIELDS - set(f.keys())
            assert not missing, f"Missing keys {missing} in {f.get('title')}"
            assert f['found_by'] == [MODULE]
            assert f['severity'] in VALID_SEVERITIES
            assert f['module'] == MODULE


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
