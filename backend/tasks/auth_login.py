"""
JSON-API login for authenticated scanning (schemas.py's AuthConfig,
login_type == 'json') - the modern-SPA counterpart to the form login handled
directly in owasp.py/_make_session and webscan.py's ZAP script auth.

Shared by both owasp.py (sets the returned token as a requests.Session header)
and webscan.py (injects it into every ZAP request via the Replacer add-on), so
the "POST JSON creds -> pull a bearer token out of the response" logic lives in
exactly one place.

Scope (ponytail): bearer-token JSON logins - POST creds as JSON, read a token
out of the JSON response by dot-path, send it as an Authorization: Bearer
header. That covers the dominant modern pattern (Juice Shop, most REST APIs).
Cookie-only JSON logins (the login just sets a Set-Cookie and returns no token)
are a fair follow-up: owasp.py's session already keeps those cookies, but the
ZAP side would need forced-user handling, so they're out of scope here rather
than half-supported.
"""
import logging
import re
from typing import Optional

import requests
import urllib3
import net_guard

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger(__name__)

_TIMEOUT = 30

# A password input on the fetched page => it's a real HTML login form.
_PASSWORD_INPUT_RE = re.compile(r"<input[^>]+type=[\"']?password", re.IGNORECASE)
# Keys whose value is likely the auth token, for auto-discovery when the
# caller didn't give an explicit token_json_path.
_TOKEN_KEY_RE = re.compile(r"token|jwt|access|auth|bearer", re.IGNORECASE)


def detect_login_type(login_url: str) -> str:
    """
    Best-effort classify a login endpoint as 'form' or 'json' by GETting it,
    so the operator doesn't have to say which it is:
      - an HTML page carrying an <input type="password"> => 'form'
      - a JSON content-type, or any non-HTML response (REST endpoints commonly
        answer GET with 405/JSON) => 'json'
    Defaults to 'form' on anything ambiguous or on error - the older, more
    common shape, and the one whose scan-time login is itself resilient
    (it just submits the page's own fields).
    """
    try:
        resp = net_guard.guarded_get(login_url, timeout=_TIMEOUT, allow_redirects=True)
    except Exception as e:
        logger.warning("login-type auto-detect GET %s failed, defaulting to "
                        "'form': %s", login_url, e)
        return 'form'
    ctype = (resp.headers.get('Content-Type') or '').lower()
    body = resp.text or ''
    if _PASSWORD_INPUT_RE.search(body):
        return 'form'
    if 'application/json' in ctype:
        return 'json'
    if 'text/html' not in ctype:
        # A login endpoint that answers GET with non-HTML (JSON error, 405,
        # empty) is an API endpoint, not a form page.
        return 'json'
    return 'form'


def resolve_login_type(auth: dict) -> str:
    """Return the explicit login_type if the operator set 'form'/'json',
    otherwise ('auto' or unset) auto-detect it from the login URL."""
    lt = auth.get('login_type')
    if lt in ('form', 'json'):
        return lt
    return detect_login_type(auth['login_url'])


def _discover_token(data) -> Optional[str]:
    """
    Recursively hunt the login response for the most token-shaped string, so
    JSON login works without an explicit token_json_path in the common case.
    Scoring: a JWT (three non-empty dot-separated segments) beats a plain long
    string; a token-ish key name ('token','access_token',...) adds to the
    score. Returns the highest-scoring string, or None.
    """
    best_score = 0
    best_val = None

    def walk(obj, key_hint=''):
        nonlocal best_score, best_val
        if isinstance(obj, dict):
            for k, v in obj.items():
                walk(v, str(k))
        elif isinstance(obj, list):
            for v in obj:
                walk(v, key_hint)
        elif isinstance(obj, str) and len(obj) >= 20:
            is_jwt = obj.count('.') == 2 and all(obj.split('.'))
            key_ish = bool(_TOKEN_KEY_RE.search(key_hint))
            score = (2 if is_jwt else 0) + (1 if key_ish else 0)
            if score > best_score:
                best_score, best_val = score, obj

    walk(data)
    return best_val


def extract_by_path(data, dotpath: str):
    """
    Walk a dot-separated path into nested JSON.
    'authentication.token' -> data['authentication']['token'].
    Integer segments index into lists: 'data.0.token' -> data['data'][0]['token'].
    Raises KeyError/IndexError/TypeError if the path doesn't resolve.
    """
    cur = data
    for part in dotpath.split('.'):
        if isinstance(cur, list):
            cur = cur[int(part)]
        else:
            cur = cur[part]
    return cur


def fetch_json_auth_token(auth: dict) -> Optional[str]:
    """
    Perform a JSON-API login and return the bearer token string, or None on
    any failure (callers then just stay unauthenticated - same non-fatal
    posture as the form-login path).

    POSTs {username_field: username, password_field: password} as a JSON body
    to login_url (username_field/password_field double as the JSON keys, e.g.
    'email'/'password' for Juice Shop), then extracts the token from the JSON
    response via token_json_path (e.g. 'authentication.token').
    """
    login_url = auth['login_url']
    body = {
        auth['username_field']: auth['username'],
        auth['password_field']: auth['password'],
    }
    try:
        resp = net_guard.guarded_request('post', login_url, json=body, timeout=_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        logger.warning("JSON login POST to %s failed: %s", login_url, e)
        return None

    token_path = auth.get('token_json_path')
    if token_path:
        try:
            token = extract_by_path(data, token_path)
            return str(token) if token is not None else None
        except Exception as e:
            logger.warning("JSON login token path %r not found in response "
                           "from %s: %s", token_path, login_url, e)
            return None

    # No explicit path - auto-discover the token from the response shape.
    token = _discover_token(data)
    if token is None:
        logger.warning("JSON login for %s: no token_json_path given and could "
                       "not auto-discover a token in the response", login_url)
    return token


def auth_header_from(auth: dict, token: str) -> tuple:
    """(header_name, header_value) for a fetched token, honoring the optional
    token_header / token_header_prefix overrides (default Authorization: Bearer)."""
    header = auth.get('token_header') or 'Authorization'
    prefix = auth.get('token_header_prefix')
    if prefix is None:
        prefix = 'Bearer '
    return header, f'{prefix}{token}'
