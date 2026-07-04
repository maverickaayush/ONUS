"""
resolve_target_url() tests - shared https-then-http target resolver
(base_task.py). Covers the redirect-scheme bug: a probe that starts on one
scheme but 301s to the other must report the scheme it actually landed on.

Run with:
    cd backend && python3 -m pytest tests/test_base_task_resolve_target.py -v
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unittest.mock import patch, MagicMock
import requests

from tasks.base_task import resolve_target_url

DOMAIN = "example.com"


def _resp(url):
    r = MagicMock()
    r.url = url
    return r


class TestResolveTargetUrl:
    def test_https_succeeds_directly(self):
        with patch("requests.get", return_value=_resp(f"https://{DOMAIN}/")):
            assert resolve_target_url(DOMAIN) == f"https://{DOMAIN}"

    def test_https_fails_http_succeeds_no_redirect(self):
        def fake_get(url, **kwargs):
            if url.startswith("https://"):
                raise requests.exceptions.ConnectionError("refused")
            return _resp(f"http://{DOMAIN}/")
        with patch("requests.get", side_effect=fake_get):
            assert resolve_target_url(DOMAIN) == f"http://{DOMAIN}"

    def test_http_redirects_to_https_returns_https(self):
        # The bug this guards: https probe fails outright, http probe is
        # issued and 301s to https - requests follows it (allow_redirects=
        # True) and resp.url ends up https, so the returned target must be
        # https even though the http scheme is the one that "worked".
        def fake_get(url, **kwargs):
            if url.startswith("https://"):
                raise requests.exceptions.ConnectionError("refused")
            return _resp(f"https://{DOMAIN}/")
        with patch("requests.get", side_effect=fake_get):
            assert resolve_target_url(DOMAIN) == f"https://{DOMAIN}"

    def test_https_redirects_down_to_http_returns_http(self):
        # The mirror case: https succeeds on the very first attempt (no
        # exception raised at all) but its own redirect chain lands on
        # http - the scheme that "worked" (https, no exception) must not
        # be blindly trusted; resp.url's final scheme (http) wins.
        with patch("requests.get", return_value=_resp(f"http://{DOMAIN}/")):
            assert resolve_target_url(DOMAIN) == f"http://{DOMAIN}"

    def test_both_fail_falls_back_to_https(self):
        with patch("requests.get", side_effect=requests.exceptions.ConnectionError("refused")):
            assert resolve_target_url(DOMAIN) == f"https://{DOMAIN}"

    def test_ssl_error_falls_through_to_http(self):
        def fake_get(url, **kwargs):
            if url.startswith("https://"):
                raise requests.exceptions.SSLError("bad handshake")
            return _resp(f"http://{DOMAIN}/")
        with patch("requests.get", side_effect=fake_get):
            assert resolve_target_url(DOMAIN) == f"http://{DOMAIN}"


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-v"]))
