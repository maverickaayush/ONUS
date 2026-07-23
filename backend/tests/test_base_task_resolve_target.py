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
import pytest
import requests
import net_guard

from tasks.base_task import resolve_target_url

DOMAIN = "example.com"

# resolve_target_url calls net_guard.guarded_get (the SNI-preserving pinned
# client), so these mock that seam directly - fully hermetic, no DNS/socket.


def _resp(url):
    r = MagicMock()
    r.url = url
    return r


class TestResolveTargetUrl:
    def test_https_succeeds_directly(self):
        with patch("net_guard.guarded_get", return_value=_resp(f"https://{DOMAIN}/")):
            assert resolve_target_url(DOMAIN) == f"https://{DOMAIN}"

    def test_https_fails_http_succeeds_no_redirect(self):
        def fake_get(url, **kwargs):
            if url.startswith("https://"):
                raise requests.exceptions.ConnectionError("refused")
            return _resp(f"http://{DOMAIN}/")
        with patch("net_guard.guarded_get", side_effect=fake_get):
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
        with patch("net_guard.guarded_get", side_effect=fake_get):
            assert resolve_target_url(DOMAIN) == f"https://{DOMAIN}"

    def test_https_redirects_down_to_http_returns_http(self):
        # The mirror case: https succeeds on the very first attempt (no
        # exception raised at all) but its own redirect chain lands on
        # http - the scheme that "worked" (https, no exception) must not
        # be blindly trusted; resp.url's final scheme (http) wins.
        with patch("net_guard.guarded_get", return_value=_resp(f"http://{DOMAIN}/")):
            assert resolve_target_url(DOMAIN) == f"http://{DOMAIN}"

    def test_both_fail_falls_back_to_https(self):
        with patch("net_guard.guarded_get", side_effect=requests.exceptions.ConnectionError("refused")):
            assert resolve_target_url(DOMAIN) == f"https://{DOMAIN}"

    def test_ssl_error_falls_through_to_http(self):
        def fake_get(url, **kwargs):
            if url.startswith("https://"):
                raise requests.exceptions.SSLError("bad handshake")
            return _resp(f"http://{DOMAIN}/")
        with patch("net_guard.guarded_get", side_effect=fake_get):
            assert resolve_target_url(DOMAIN) == f"http://{DOMAIN}"


class TestUpdateModuleStatusIsAtomic:
    """
    Real bug found live (browser-driven test against a real scan): the old
    implementation did a Python read-modify-write (read the whole
    module_statuses dict, mutate one key, write the whole dict back) - under
    8 modules updating concurrently, a slower module's write (based on an
    older snapshot) could clobber a faster module's newer status. Confirmed
    live: a scan showed overall status='complete' while module_statuses
    still had one module stuck at 'running' forever.

    Fixed via a single atomic SQL UPDATE (jsonb_set) instead of a read-then-
    write round trip - assert the SQL is actually issued that way, so a
    regression back to the read-modify-write pattern gets caught.
    """

    def test_issues_single_atomic_sql_update_not_read_then_write(self):
        from tasks.base_task import update_module_status

        db = MagicMock()
        with patch("database.SessionLocal", return_value=db):
            update_module_status("scan-1", "headers", "complete")

        # No read-then-write: never queries the row first via .query()/.first()
        db.query.assert_not_called()
        db.execute.assert_called_once()
        sql_text = str(db.execute.call_args.args[0])
        assert "jsonb_set" in sql_text
        params = db.execute.call_args.args[1]
        assert params == {"module_name": "headers", "status": "complete", "scan_id": "scan-1"}
        db.commit.assert_called_once()

    def test_failure_logged_not_raised(self):
        from tasks.base_task import update_module_status

        db = MagicMock()
        db.execute.side_effect = RuntimeError("db down")
        # Must not raise - a status-update failure shouldn't crash the
        # scanning task itself.
        with patch("database.SessionLocal", return_value=db):
            update_module_status("scan-1", "headers", "complete")
        db.close.assert_called_once()


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-v"]))
