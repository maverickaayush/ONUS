"""SSRF guard tests (finding H1 + the SNI-preserving connection-level pin).

The pin is an HTTPAdapter that connects to the host's validated public IP while
keeping the URL/SNI/Host as the real hostname. So the tests assert two things
that must BOTH hold:
  1. it's still a pin - private/rebinding/redirect-into-private are rejected,
     at the get_connection seam every request+redirect-hop routes through;
  2. it's SNI-correct - the pool connects to the IP but carries
     server_hostname = the real name (the thing the URL-rewrite pin broke on
     SNI-routing CDNs like Vercel/Cloudflare).

Run with:
    cd backend && python3 -m pytest tests/test_net_guard.py -v
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from unittest.mock import patch, MagicMock

import pytest

import net_guard
from net_guard import (resolve_public_ips, SsrfBlocked, _PinnedPoolAdapter)


def _addrinfo(*ips):
    """socket.getaddrinfo-shaped result: only info[4][0] (the IP) is read."""
    return [(0, 0, 0, "", (ip, 0)) for ip in ips]


# --- 1. resolution matrix ---------------------------------------------------

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
    with patch("socket.getaddrinfo", return_value=_addrinfo("93.184.216.34", "192.168.0.9")):
        with pytest.raises(SsrfBlocked):
            resolve_public_ips("mixed.example")


def test_accepts_all_public():
    with patch("socket.getaddrinfo", return_value=_addrinfo("93.184.216.34", "1.1.1.1")):
        assert resolve_public_ips("ok.example") == ["1.1.1.1", "93.184.216.34"]


def test_dual_stack_prefers_ipv4():
    # string sort puts "2606:..." before "93..."; the pin ([0]) must still be
    # the IPv4 so an IPv4-only network isn't false-failed as "unreachable".
    with patch("socket.getaddrinfo", return_value=_addrinfo("2606:2800:220:1::1", "93.184.216.34")):
        assert resolve_public_ips("dual.example")[0] == "93.184.216.34"


def test_pin_selects_ipv4_on_dual_stack():
    ad = _PinnedPoolAdapter()
    with patch("socket.getaddrinfo", return_value=_addrinfo("2606:2800:220:1::1", "93.184.216.34")):
        pool = ad.get_connection("https://dual.example/")
    assert pool.host == "93.184.216.34"           # connection pinned to the v4, not the v6


# --- 2. connection-level pin: connect to IP, SNI stays the hostname ----------

def test_pool_connects_to_ip_but_sni_is_hostname():
    ad = _PinnedPoolAdapter()
    with patch("socket.getaddrinfo", return_value=_addrinfo("93.184.216.34")):
        pool = ad.get_connection("https://target.example/path")
    assert pool.host == "93.184.216.34"                      # socket goes to the IP
    assert pool.conn_kw.get("server_hostname") == "target.example"  # SNI = real name (the CDN fix)


def test_http_pool_also_pins_to_ip():
    ad = _PinnedPoolAdapter()
    with patch("socket.getaddrinfo", return_value=_addrinfo("93.184.216.34")):
        pool = ad.get_connection("http://target.example/")
    assert pool.host == "93.184.216.34"


def test_send_forces_host_header_to_hostname():
    # pool connects to an IP; Host must be the hostname, not <ip>.
    ad = _PinnedPoolAdapter()
    req = MagicMock(); req.url = "https://target.example/x"; req.headers = {}
    with patch("requests.adapters.HTTPAdapter.send", return_value="sentinel") as sup:
        out = ad.send(req)
    assert out == "sentinel"
    assert req.headers["Host"] == "target.example"


# --- 3. still a pin: private + rebinding + redirect-hop rejection ------------

def test_get_connection_rejects_private_host():
    # every request AND every redirect hop routes through get_connection, so a
    # private target here == a redirect-into-private being blocked mid-chain.
    ad = _PinnedPoolAdapter()
    with patch("socket.getaddrinfo", return_value=_addrinfo("169.254.169.254")):
        with pytest.raises(SsrfBlocked):
            ad.get_connection("http://metadata.internal/latest/")


def test_rebinding_pins_first_resolution():
    # public on the first lookup, private on the second: the cached pool must
    # stay pinned to the public IP and never re-resolve to the private one.
    ad = _PinnedPoolAdapter()
    with patch("socket.getaddrinfo", side_effect=[_addrinfo("93.184.216.34"),
                                                  _addrinfo("10.0.0.1")]) as gai:
        p1 = ad.get_connection("https://rebind.example/")
        p2 = ad.get_connection("https://rebind.example/other")
    assert gai.call_count == 1                    # resolved once, pool cached
    assert p1 is p2 and p1.host == "93.184.216.34"


def test_guarded_get_end_to_end_blocks_metadata():
    # full path through requests: a metadata host raises before any bytes leave.
    with patch("socket.getaddrinfo", return_value=_addrinfo("169.254.169.254")):
        with pytest.raises(SsrfBlocked):
            net_guard.guarded_get("https://metadata.example/", timeout=5)


def test_follow_inferred_from_allow_redirects():
    # allow_redirects=False must not follow; sess.request is called with it.
    captured = {}
    real_session = net_guard.requests.Session
    class _S(real_session):
        def request(self, method, url, **kw):
            captured.update(kw); r = MagicMock(); r.status_code = 302; return r
    with patch.object(net_guard.requests, "Session", _S), \
         patch("socket.getaddrinfo", return_value=_addrinfo("93.184.216.34")):
        net_guard.guarded_request("get", "https://x.example/", allow_redirects=False)
    assert captured.get("allow_redirects") is False


# --- 4. wiring: real module entrypoints abort when resolution is blocked -----

def test_base_task_resolve_target_is_guarded():
    from tasks.base_task import resolve_target_url
    with patch("net_guard.resolve_public_ips", side_effect=SsrfBlocked("blocked")):
        # swallows SsrfBlocked per scheme, falls back to https://<domain>
        assert resolve_target_url("private.example") == "https://private.example"


def test_owasp_open_redirect_is_guarded():
    import requests
    from tasks.owasp import test_open_redirect
    session = requests.Session()
    with patch("net_guard.resolve_public_ips", side_effect=SsrfBlocked("blocked")):
        findings = test_open_redirect(session, "http://private.example/", "private.example")
    assert findings == []


def test_ssl_tls_https_reachable_is_guarded():
    from tasks.ssl_tls import _https_reachable
    with patch("net_guard.resolve_public_ips", side_effect=SsrfBlocked("blocked")), \
         patch("socket.create_connection") as m:
        assert _https_reachable("private.example") is False
    assert not m.called


@pytest.mark.parametrize("modname", [
    "tasks.headers", "tasks.enumeration", "tasks.auth_login", "tasks.ssl_tls",
])
def test_module_imports_the_guard(modname):
    import importlib
    mod = importlib.import_module(modname)
    assert getattr(mod, "net_guard", None) is net_guard


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
