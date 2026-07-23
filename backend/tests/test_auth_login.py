"""
JSON-API login helper tests (tasks/auth_login.py) + owasp.py's JSON session
branch. Run with:  cd backend && python3 -m pytest tests/test_auth_login.py -v
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unittest.mock import patch, MagicMock
import pytest

@pytest.fixture(autouse=True)
def _bypass_ssrf_pin():
    # These tests exercise module LOGIC (form parsing, crawling, type detection),
    # not the SSRF guard - that is covered in test_net_guard.py. Bypass
    # net_guard's resolve+IP-pin transport so the existing HTTP-layer mocks see
    # the original URL instead of a pinned-IP rewrite.
    import net_guard, requests as _rq
    from unittest.mock import patch as _patch
    def _pass(method, url, *, session=None, follow=None, max_redirects=5, **kw):
        kw.setdefault("verify", False)
        return getattr(session or _rq, method.lower())(url, **kw)
    with _patch.object(net_guard, "guarded_request", _pass), \
         _patch.object(net_guard, "assert_public_host", lambda *_a, **_k: None), \
         _patch.object(net_guard, "guarded_get", lambda url, **kw: _pass("get", url, **kw)):
        yield


JUICE_AUTH = {
    'login_url': 'https://juiceshop.local/rest/user/login',
    'username': 'admin@juice-sh.op', 'password': 'admin123',
    'username_field': 'email', 'password_field': 'password',
    'login_type': 'json', 'token_json_path': 'authentication.token',
    'token_header': 'Authorization', 'token_header_prefix': 'Bearer ',
}


def _mock_post(json_body, status=200):
    resp = MagicMock()
    resp.json.return_value = json_body
    resp.raise_for_status.return_value = None
    resp.status_code = status
    return resp


class TestExtractByPath:
    def test_nested_dict_path(self):
        from tasks.auth_login import extract_by_path
        assert extract_by_path({'authentication': {'token': 'abc'}},
                               'authentication.token') == 'abc'

    def test_list_index_segment(self):
        from tasks.auth_login import extract_by_path
        assert extract_by_path({'data': [{'token': 'zzz'}]}, 'data.0.token') == 'zzz'

    def test_missing_key_raises(self):
        from tasks.auth_login import extract_by_path
        with pytest.raises((KeyError, IndexError, TypeError)):
            extract_by_path({'a': 1}, 'a.b.c')


class TestFetchJsonAuthToken:
    def test_extracts_token_from_juice_shop_shape(self):
        from tasks.auth_login import fetch_json_auth_token
        body = {'authentication': {'token': 'JWT_TOKEN_HERE', 'umail': 'x'}}
        with patch('tasks.auth_login.requests.post', return_value=_mock_post(body)):
            token = fetch_json_auth_token(JUICE_AUTH)
        assert token == 'JWT_TOKEN_HERE'

    def test_posts_credentials_as_json_body(self):
        from tasks.auth_login import fetch_json_auth_token
        body = {'authentication': {'token': 't'}}
        with patch('tasks.auth_login.requests.post',
                   return_value=_mock_post(body)) as mock_post:
            fetch_json_auth_token(JUICE_AUTH)
        _, kwargs = mock_post.call_args
        assert kwargs['json'] == {'email': 'admin@juice-sh.op', 'password': 'admin123'}

    def test_missing_token_path_returns_none(self):
        from tasks.auth_login import fetch_json_auth_token
        auth = dict(JUICE_AUTH); auth.pop('token_json_path')
        with patch('tasks.auth_login.requests.post',
                   return_value=_mock_post({'authentication': {'token': 't'}})):
            assert fetch_json_auth_token(auth) is None

    def test_wrong_path_returns_none_not_raises(self):
        from tasks.auth_login import fetch_json_auth_token
        auth = dict(JUICE_AUTH); auth['token_json_path'] = 'nope.missing'
        with patch('tasks.auth_login.requests.post',
                   return_value=_mock_post({'authentication': {'token': 't'}})):
            assert fetch_json_auth_token(auth) is None

    def test_network_error_returns_none(self):
        from tasks.auth_login import fetch_json_auth_token
        import requests
        with patch('tasks.auth_login.requests.post',
                   side_effect=requests.exceptions.ConnectionError("refused")):
            assert fetch_json_auth_token(JUICE_AUTH) is None


def _mock_get(text='', ctype='text/html', status=200):
    resp = MagicMock()
    resp.text = text
    resp.headers = {'Content-Type': ctype}
    resp.status_code = status
    return resp


class TestDetectLoginType:
    def test_html_password_form_is_form(self):
        from tasks.auth_login import detect_login_type
        html = '<html><form><input name="user"><input type="password" name="pass"></form></html>'
        with patch('tasks.auth_login.requests.get', return_value=_mock_get(html)):
            assert detect_login_type('https://x/login') == 'form'

    def test_json_content_type_is_json(self):
        from tasks.auth_login import detect_login_type
        with patch('tasks.auth_login.requests.get',
                   return_value=_mock_get('{"error":"use POST"}', ctype='application/json', status=405)):
            assert detect_login_type('https://x/rest/user/login') == 'json'

    def test_non_html_endpoint_is_json(self):
        from tasks.auth_login import detect_login_type
        with patch('tasks.auth_login.requests.get',
                   return_value=_mock_get('', ctype='', status=405)):
            assert detect_login_type('https://x/api/login') == 'json'

    def test_html_without_password_field_defaults_form(self):
        from tasks.auth_login import detect_login_type
        with patch('tasks.auth_login.requests.get',
                   return_value=_mock_get('<html>hi</html>', ctype='text/html')):
            assert detect_login_type('https://x/login') == 'form'

    def test_network_error_defaults_form(self):
        from tasks.auth_login import detect_login_type
        import requests
        with patch('tasks.auth_login.requests.get',
                   side_effect=requests.exceptions.ConnectionError("x")):
            assert detect_login_type('https://x/login') == 'form'


class TestResolveLoginType:
    def test_explicit_json_passthrough_no_network(self):
        from tasks.auth_login import resolve_login_type
        with patch('tasks.auth_login.requests.get') as g:
            assert resolve_login_type({'login_url': 'u', 'login_type': 'json'}) == 'json'
            g.assert_not_called()

    def test_auto_detects(self):
        from tasks.auth_login import resolve_login_type
        with patch('tasks.auth_login.requests.get',
                   return_value=_mock_get('', ctype='application/json')):
            assert resolve_login_type({'login_url': 'u', 'login_type': 'auto'}) == 'json'

    def test_unset_login_type_detects(self):
        from tasks.auth_login import resolve_login_type
        html = '<input type="password">'
        with patch('tasks.auth_login.requests.get', return_value=_mock_get(html)):
            assert resolve_login_type({'login_url': 'u'}) == 'form'


class TestTokenAutoDiscovery:
    def test_discovers_nested_jwt_without_path(self):
        from tasks.auth_login import fetch_json_auth_token
        jwt = 'eyJhbGci.' + 'a' * 30 + '.' + 'b' * 30
        body = {'authentication': {'token': jwt, 'umail': 'x@y.z'}}
        auth = dict(JUICE_AUTH); auth.pop('token_json_path')
        with patch('tasks.auth_login.requests.post', return_value=_mock_post(body)):
            assert fetch_json_auth_token(auth) == jwt

    def test_discovers_token_key_when_not_jwt(self):
        from tasks.auth_login import fetch_json_auth_token
        body = {'data': {'access_token': 'A' * 40, 'name': 'admin'}}
        auth = dict(JUICE_AUTH); auth.pop('token_json_path')
        with patch('tasks.auth_login.requests.post', return_value=_mock_post(body)):
            assert fetch_json_auth_token(auth) == 'A' * 40

    def test_no_token_shape_returns_none(self):
        from tasks.auth_login import fetch_json_auth_token
        body = {'user': {'name': 'admin', 'role': 'x'}}
        auth = dict(JUICE_AUTH); auth.pop('token_json_path')
        with patch('tasks.auth_login.requests.post', return_value=_mock_post(body)):
            assert fetch_json_auth_token(auth) is None


class TestAuthHeaderFrom:
    def test_default_bearer(self):
        from tasks.auth_login import auth_header_from
        assert auth_header_from({}, 'TKN') == ('Authorization', 'Bearer TKN')

    def test_custom_header_and_prefix(self):
        from tasks.auth_login import auth_header_from
        auth = {'token_header': 'X-Auth', 'token_header_prefix': ''}
        assert auth_header_from(auth, 'TKN') == ('X-Auth', 'TKN')


class TestOwaspJsonSession:
    def test_make_session_sets_bearer_header_on_json_login(self):
        from tasks.owasp import _make_session
        body = {'authentication': {'token': 'SESSION_JWT'}}
        with patch('tasks.auth_login.requests.post', return_value=_mock_post(body)):
            session = _make_session(JUICE_AUTH)
        assert session.headers.get('Authorization') == 'Bearer SESSION_JWT'

    def test_make_session_json_login_failure_stays_unauthenticated(self):
        from tasks.owasp import _make_session
        import requests
        with patch('tasks.auth_login.requests.post',
                   side_effect=requests.exceptions.ConnectionError("x")):
            session = _make_session(JUICE_AUTH)
        assert 'Authorization' not in session.headers


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
