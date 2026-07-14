"""Domain-ownership verification (routers/verify.py) - the security-critical bits:
token detection, cross-host-redirect resistance, and the claim-key gate."""
import os
import sys
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from routers.verify import (
    _meta_present, _hash_key, verify_domain_control, domain_has_valid_claim,
)

TOKEN = "onus-verify-deadbeefdeadbeefdeadbeefdeadbeef"


def _resp(status=200, body=""):
    r = MagicMock()
    r.status_code = status
    r.raw.read.return_value = body.encode()
    return r


class TestMetaDetection:
    def test_finds_tag_name_then_content(self):
        html = f'<head><meta name="onus-verify" content="{TOKEN}"></head>'
        assert _meta_present(html, TOKEN)

    def test_finds_tag_content_then_name(self):
        html = f"<head><meta content='{TOKEN}' name='onus-verify'></head>"
        assert _meta_present(html, TOKEN)

    def test_rejects_wrong_token(self):
        html = '<meta name="onus-verify" content="onus-verify-0000">'
        assert not _meta_present(html, TOKEN)

    def test_rejects_absent(self):
        assert not _meta_present("<html><body>hi</body></html>", TOKEN)


class TestVerifyControl:
    def test_meta_tag_success(self):
        html = f'<html><head>{"x"*10}<meta name="onus-verify" content="{TOKEN}"></head></html>'
        with patch("routers.verify._get", return_value=_resp(200, html)):
            ok, _ = verify_domain_control("example.com", "meta_tag", TOKEN)
        assert ok

    def test_redirect_is_not_accepted(self):
        # A 302 (e.g. an open redirect on the target) must NOT satisfy the
        # challenge - only a direct 200 counts.
        with patch("routers.verify._get", return_value=_resp(302, "")):
            ok, reason = verify_domain_control("example.com", "meta_tag", TOKEN)
        assert not ok and "302" in reason

    def test_http_file_exact_match(self):
        with patch("routers.verify._get", return_value=_resp(200, TOKEN + "\n")):
            ok, _ = verify_domain_control("example.com", "http_file", TOKEN)
        assert ok

    def test_http_file_wrong_contents(self):
        with patch("routers.verify._get", return_value=_resp(200, "nope")):
            ok, _ = verify_domain_control("example.com", "http_file", TOKEN)
        assert not ok

    def test_network_error_is_false_not_raise(self):
        import requests
        with patch("routers.verify._get", side_effect=requests.ConnectionError()):
            ok, _ = verify_domain_control("example.com", "meta_tag", TOKEN)
        assert not ok


class TestClaimGate:
    def _db_with(self, row):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = row
        return db

    def test_no_key_is_rejected_without_query(self):
        db = MagicMock()
        assert domain_has_valid_claim(db, "example.com", None) is False
        db.query.assert_not_called()

    def test_valid_row_passes(self):
        assert domain_has_valid_claim(self._db_with(MagicMock()), "example.com", "onus-key-x") is True

    def test_no_matching_row_fails(self):
        # wrong/expired key -> query returns nothing
        assert domain_has_valid_claim(self._db_with(None), "example.com", "onus-key-bad") is False

    def test_key_is_hashed_not_stored_plaintext(self):
        assert _hash_key("onus-key-secret") != "onus-key-secret"
        assert len(_hash_key("x")) == 64  # sha256 hex


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
