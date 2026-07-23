"""SSRF guard tests (finding H1).

Two layers:
  1. Behavioural matrix on net_guard itself - the guard logic every call site
     routes through: reject metadata/RFC1918/loopback/CGNAT/reserved, mixed
     records, IP pinning (rebinding), and redirect re-validation.
  2. Wiring proofs - drive the real module entrypoints and confirm they refuse
     a private target *before* any socket/HTTP happens (i.e. they actually go
     through the guard, not raw requests).

Run with:
    cd backend && python3 -m pytest tests/test_net_guard.py -v
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unittest.mock import patch, MagicMock
import socket

import pytest
from requests.structures import CaseInsensitiveDict

import net_guard
from net_guard import resolve_public_ips, guarded_get, SsrfBlocked


def _addrinfo(*ips):
    """socket.getaddrinfo-shaped result: only info[4][0] (the IP) is read."""
    return [(0, 0, 0, "", (ip, 0)) for ip in ips]


def _resp(status=200, location=None):
    r = MagicMock()
    r.status_code = status
    r.headers = CaseInsensitiveDict({"Location": location} if location else {})
    r.url = "http://x/"
    return r


# --- 1. resolution matrix ---------------------------------------------------

# literal path needs no DNS mock
@pytest.mark.parametrize("ip", [
    "169.254.169.254",   # cloud metadata
    "10.0.0.5", "172.16.0.1", "192.168.1.1",   # RFC1918
    "127.0.0.1", "::1",   # loopback v4/v6
    "100.64.0.1",   # CGNAT
    "198.18.0.1",   # benchmarking / reserved
    "::ffff:10.0.0.1",   # IPv4-mapped private
])
def test_rejects_private_literal(ip):
    with pytest.raises(SsrfBlocked):
        resolve_public_ips(ip)


def test_accepts_public_literal():
    assert resolve_public_ips("8.8.8.8") == ["8.8.8.8"]


def test_rejects_hostname_resolving_private():
    with patch("socket.getaddrinfo", return_value=_addrinfo("10.1.2.3")):
        with pytest.raises(SsrfBlocked):
            resolve_public_ips("sneaky.example")


def test_rejects_mixed_records_one_private():
    # one public + one private A record -> whole host rejected
    with patch("socket.getaddrinfo", return_value=_addrinfo("93.184.216.34", "192.168.0.9")):
        with pytest.raises(SsrfBlocked):
            resolve_public_ips("mixed.example")


def test_accepts_all_public():
    with patch("socket.getaddrinfo", return_value=_addrinfo("93.184.216.34", "1.1.1.1")):
        assert resolve_public_ips("ok.example") == ["1.1.1.1", "93.184.216.34"]


# --- 2. pinning / rebinding -------------------------------------------------

def test_pins_resolved_ip_and_preserves_host():
    with patch("socket.getaddrinfo", return_value=_addrinfo("93.184.216.34")), \
         patch("requests.get", return_value=_resp()) as m:
        guarded_get("http://target.example/path")
    url = m.call_args.args[0]
    assert "93.184.216.34" in url and "target.example" not in url  # connected to IP, not name
    assert m.call_args.kwargs["headers"]["Host"] == "target.example"


def test_rebinding_uses_first_resolution_only():
    # public on the first lookup, private on the second: pinning must connect to
    # the public IP and never consult the second (private) answer. If this passed
    # without pinning, the request would carry the hostname and re-resolve.
    with patch("socket.getaddrinfo", side_effect=[_addrinfo("93.184.216.34"),
                                                  _addrinfo("10.0.0.1")]) as gai, \
         patch("requests.get", return_value=_resp()) as m:
        guarded_get("http://rebind.example/")
    assert gai.call_count == 1                       # resolved once, then pinned
    assert "93.184.216.34" in m.call_args.args[0]


# --- 3. redirect re-validation ----------------------------------------------

def test_redirect_into_private_is_blocked():
    with patch("socket.getaddrinfo", side_effect=[_addrinfo("93.184.216.34"),   # initial host
                                                  _addrinfo("169.254.169.254")]), \
         patch("requests.get", return_value=_resp(302, "http://metadata.internal/")):
        with pytest.raises(SsrfBlocked):
            guarded_get("http://public.example/")


def test_multi_hop_redirect_hop3_private_is_blocked():
    reqs = [_resp(302, "http://h2/"), _resp(302, "http://h3/"), _resp(302, "http://h4/")]
    gai = [_addrinfo("93.184.216.34"), _addrinfo("1.1.1.1"),
           _addrinfo("8.8.8.8"), _addrinfo("192.168.5.5")]   # hop 3's target is private
    with patch("socket.getaddrinfo", side_effect=gai), \
         patch("requests.get", side_effect=reqs) as m:
        with pytest.raises(SsrfBlocked):
            guarded_get("http://h1/")
    assert m.call_count == 3                          # stopped before the 4th hop


def test_redirect_to_public_is_followed():
    with patch("socket.getaddrinfo", side_effect=[_addrinfo("93.184.216.34"),
                                                  _addrinfo("1.1.1.1")]), \
         patch("requests.get", side_effect=[_resp(302, "http://next.example/"),
                                            _resp(200)]) as m:
        out = guarded_get("http://public.example/")
    assert out.status_code == 200 and m.call_count == 2


# --- 4. wiring proofs: real module entrypoints refuse before connecting ------
# Technique: point resolution at a private IP; a wired module raises/aborts at
# the guard and never calls its HTTP/socket primitive. An UNwired module would.

def test_base_task_resolve_target_is_guarded():
    from tasks.base_task import resolve_target_url
    with patch("socket.getaddrinfo", return_value=_addrinfo("10.0.0.1")), \
         patch("requests.get") as m:
        resolve_target_url("private.example")        # swallows SsrfBlocked -> fallback
    assert not m.called                              # guard fired before any HTTP


def test_owasp_open_redirect_is_guarded():
    import requests
    from tasks.owasp import test_open_redirect
    session = requests.Session()
    with patch("socket.getaddrinfo", return_value=_addrinfo("192.168.1.1")), \
         patch.object(session, "get") as m:
        findings = test_open_redirect(session, "http://private.example/", "private.example")
    assert findings == [] and not m.called


def test_ssl_tls_https_reachable_is_guarded():
    from tasks.ssl_tls import _https_reachable
    with patch("socket.getaddrinfo", return_value=_addrinfo("127.0.0.1")), \
         patch("socket.create_connection") as m:
        assert _https_reachable("private.example") is False
    assert not m.called                              # never opened a socket to the private IP


@pytest.mark.parametrize("modname", [
    "tasks.headers", "tasks.enumeration", "tasks.auth_login", "tasks.ssl_tls",
])
def test_module_imports_the_guard(modname):
    import importlib
    mod = importlib.import_module(modname)
    assert getattr(mod, "net_guard", None) is net_guard


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
