"""Domain-ownership verification (routers/verify.py) - the security-critical bits:
meta detection via a real HTML parse, redirect resistance, SSRF rejection, and
the claim-key gate. Outbound HTTP is mocked (no real network / DNS)."""
import os
import sys
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from routers.verify import (
    _meta_content_matches, _file_contents, _hash_key, verify_domain_control,
    domain_has_valid_claim,
)

TOKEN = "deadbeefdeadbeefdeadbeefdeadbeef0badc0de"


class TestMetaDetection:
    def test_finds_tag_name_then_content(self):
        html = f'<head><meta name="onus-verification" content="{TOKEN}"></head>'
        assert _meta_content_matches(html, TOKEN)

    def test_finds_tag_content_then_name(self):
        html = f"<head><meta content='{TOKEN}' name='onus-verification'></head>"
        assert _meta_content_matches(html, TOKEN)

    def test_rejects_wrong_token(self):
        html = '<meta name="onus-verification" content="not-the-token">'
        assert not _meta_content_matches(html, TOKEN)

    def test_rejects_absent(self):
        assert not _meta_content_matches("<html><body>hi</body></html>", TOKEN)

    def test_rejects_substring_in_body_text(self):
        # A naive substring search would false-positive here; the HTML parser must not.
        assert not _meta_content_matches(f"<body>onus-verification {TOKEN}</body>", TOKEN)


class TestVerifyControl:
    def test_meta_tag_success(self):
        html = f'<html><head><meta name="onus-verification" content="{TOKEN}"></head></html>'
        with patch("routers.verify._safe_get", return_value=(200, html)):
            ok, _ = verify_domain_control("example.com", "meta_tag", TOKEN)
        assert ok

    def test_redirect_is_not_accepted(self):
        with patch("routers.verify._safe_get", return_value=(302, "")):
            ok, reason = verify_domain_control("example.com", "meta_tag", TOKEN)
        assert not ok and "302" in reason

    def test_http_file_exact_match(self):
        with patch("routers.verify._safe_get", return_value=(200, _file_contents(TOKEN) + "\n")):
            ok, _ = verify_domain_control("example.com", "http_file", TOKEN)
        assert ok

    def test_http_file_wrong_contents(self):
        with patch("routers.verify._safe_get", return_value=(200, "nope")):
            ok, _ = verify_domain_control("example.com", "http_file", TOKEN)
        assert not ok

    def test_http_file_missing_is_404(self):
        with patch("routers.verify._safe_get", return_value=(404, "")):
            ok, reason = verify_domain_control("example.com", "http_file", TOKEN)
        assert not ok and "404" in reason

    def test_network_error_is_false_not_raise(self):
        with patch("routers.verify._safe_get", side_effect=OSError("conn refused")):
            ok, _ = verify_domain_control("example.com", "meta_tag", TOKEN)
        assert not ok

    def test_ssrf_valueerror_rejects_immediately(self):
        # _safe_get raises ValueError when the host resolves to an internal addr.
        with patch("routers.verify._safe_get", side_effect=ValueError("disallowed address")):
            ok, reason = verify_domain_control("example.com", "meta_tag", TOKEN)
        assert not ok and "disallowed" in reason


class TestSSRFResolution:
    """_validate_resolved_host must reject internal/reserved destinations."""
    def _mock_getaddrinfo(self, ip):
        return [(2, 1, 6, "", (ip, 0))]

    def _assert_rejected(self, ip):
        from routers import verify
        with patch("routers.verify.socket.getaddrinfo", return_value=self._mock_getaddrinfo(ip)):
            try:
                verify._validate_resolved_host("evil.example")
                raise AssertionError(f"{ip} should have been rejected")
            except ValueError:
                pass

    def test_ipv4_loopback(self):
        self._assert_rejected("127.0.0.1")

    def test_ipv6_loopback(self):
        self._assert_rejected("::1")

    def test_private_10(self):
        self._assert_rejected("10.1.2.3")

    def test_private_192(self):
        self._assert_rejected("192.168.1.1")

    def test_link_local_metadata(self):
        self._assert_rejected("169.254.169.254")  # cloud metadata

    def test_unspecified(self):
        self._assert_rejected("0.0.0.0")

    def test_public_ip_allowed(self):
        from routers import verify
        with patch("routers.verify.socket.getaddrinfo", return_value=self._mock_getaddrinfo("93.184.216.34")):
            assert verify._validate_resolved_host("example.com") == "93.184.216.34"

    def test_any_bad_address_rejects_even_if_one_public(self):
        # split-horizon: a public + an internal address must still be rejected.
        from routers import verify
        infos = [(2, 1, 6, "", ("93.184.216.34", 0)), (2, 1, 6, "", ("127.0.0.1", 0))]
        with patch("routers.verify.socket.getaddrinfo", return_value=infos):
            try:
                verify._validate_resolved_host("mixed.example")
                raise AssertionError("mixed public/internal must be rejected")
            except ValueError:
                pass


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
        assert domain_has_valid_claim(self._db_with(None), "example.com", "onus-key-bad") is False

    def test_key_is_hashed_not_stored_plaintext(self):
        assert _hash_key("onus-key-secret") != "onus-key-secret"
        assert len(_hash_key("x")) == 64


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
