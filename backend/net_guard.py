"""SSRF guard for every outbound request a scan makes (finding H1).

The domain the operator submits is validated as a *string* in schemas.py, but a
name can still resolve to a private/loopback/link-local/metadata address (DNS
rebinding, `metadata.google.internal`, an attacker A-record -> 169.254.169.254),
and a legitimately-public target can 302 into a private range. This module is
the one place that turns "a host string" into "a safe connection":

  - resolve_public_ips(host): resolve ALL A/AAAA and reject if any is non-public.
  - assert_public_host(host): the dispatch-time gate (used by subprocess-tool
    modules that resolve internally - nmap/nuclei/ffuf/etc; a small resolve->
    connect TOCTOU window remains for those, documented at the call site).
  - guarded_get(url): resolve + validate + PIN the validated IP for the actual
    connection (defeats rebinding), and re-validate every redirect hop. This is
    what the requests-based modules use instead of raw requests.get.

ponytail: subprocess tools (nmap, whatweb, nuclei, ffuf, testssl...) do their
own DNS at connect time, so they get the dispatch-time assert_public_host gate,
not per-connection pinning - closing that fully means teaching each tool to
target-by-IP-with-Host, which is a much larger change. The pin is applied to
every client we control directly (plain `requests`).
"""
import ipaddress
import socket
from urllib.parse import urlsplit, urlunsplit, urljoin

import requests

# Networks ipaddress' category flags don't all cover: CGNAT, IETF protocol
# assignments, benchmarking. is_private/is_loopback/is_link_local/is_reserved/
# is_multicast/is_unspecified handle the rest (incl. IPv6 ULA/loopback/ll).
_EXTRA_BLOCKED = [
    ipaddress.ip_network("100.64.0.0/10"),   # CGNAT (RFC 6598)
    ipaddress.ip_network("192.0.0.0/24"),    # IETF protocol assignments
    ipaddress.ip_network("198.18.0.0/15"),   # benchmarking (RFC 2544)
]

_REDIRECT_CODES = {301, 302, 303, 307, 308}
_MAX_REDIRECTS = 5


class SsrfBlocked(ValueError):
    """Raised when a host resolves to, or redirects into, a non-public address."""


def _ip_is_disallowed(ip_str: str) -> bool:
    ip = ipaddress.ip_address(ip_str)
    # Unwrap IPv4-mapped IPv6 (::ffff:10.0.0.1 must be judged as 10.0.0.1).
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return (
        ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
        or ip.is_multicast or ip.is_unspecified
        or any(ip in net for net in _EXTRA_BLOCKED)
    )


def resolve_public_ips(host: str) -> list[str]:
    """Every A/AAAA for `host`, or raise SsrfBlocked if ANY is non-public.
    Accepts an IP literal too (validated directly). Empty resolution -> raise."""
    try:
        ip = ipaddress.ip_address(host)
        if _ip_is_disallowed(str(ip)):
            raise SsrfBlocked(f"{host} is a non-public address")
        return [str(ip)]
    except ValueError:
        pass  # not a literal; resolve it below

    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as e:
        raise SsrfBlocked(f"{host} does not resolve ({e})")
    ips = sorted({info[4][0] for info in infos})
    if not ips:
        raise SsrfBlocked(f"{host} does not resolve")
    bad = [ip for ip in ips if _ip_is_disallowed(ip)]
    if bad:
        raise SsrfBlocked(f"{host} resolves to non-public address(es): {', '.join(bad)}")
    return ips


def assert_public_host(host: str) -> None:
    """Dispatch-time gate: raise SsrfBlocked unless `host` resolves entirely to
    public addresses. Used by modules whose external tool does its own connect."""
    resolve_public_ips(host)


def _pin_netloc(netloc: str, ip: str) -> str:
    """Replace the host in a netloc with `ip` (bracketing IPv6), keeping the port
    so the connection goes to the address we just validated, not a re-lookup."""
    userinfo = ""
    if "@" in netloc:
        userinfo, netloc = netloc.rsplit("@", 1)
        userinfo += "@"
    port = ""
    if netloc.startswith("["):                       # [ipv6]:port
        port = netloc.split("]", 1)[1]
    elif netloc.count(":") == 1:
        port = ":" + netloc.rsplit(":", 1)[1]
    host_part = f"[{ip}]" if ":" in ip else ip
    return f"{userinfo}{host_part}{port}"


def guarded_request(method: str, url: str, *, session: requests.Session | None = None,
                    follow: bool | None = None, max_redirects: int = _MAX_REDIRECTS,
                    **kwargs) -> requests.Response:
    """Drop-in for requests.<method> that (1) resolves+validates the host, (2)
    pins the validated IP for the connection (rebinding-safe), and (3) when
    following, re-validates every redirect hop. `verify=False` and manual redirect
    control are forced - the scanner talks to hostile hosts, so cert trust is not
    the point and hop control is. `follow` defaults to the caller's own
    `allow_redirects` kwarg (True if unset, matching requests), so existing call
    sites are drop-in: `allow_redirects=False` (owasp's open-redirect / injection
    probes) => inspect a single response unfollowed; pass `follow=` to override."""
    if follow is None:
        follow = kwargs.get("allow_redirects", True)
    kwargs["verify"] = False
    kwargs["allow_redirects"] = False
    original_headers = dict(kwargs.pop("headers", {}) or {})

    for _ in range(max_redirects + 1):
        parsed = urlsplit(url)
        host = parsed.hostname
        if not host:
            raise SsrfBlocked(f"no host in URL: {url!r}")
        ip = resolve_public_ips(host)[0]                 # raises if non-public
        pinned = urlunsplit((parsed.scheme, _pin_netloc(parsed.netloc, ip),
                             parsed.path, parsed.query, ""))
        # Preserve the real Host so vhosts/TLS-SNI-by-name targets still answer.
        headers = {**original_headers, "Host": parsed.netloc.rsplit("@", 1)[-1]}
        caller = getattr(session or requests, method.lower())  # re-bound: method flips to get on redirect
        resp = caller(pinned, headers=headers, **kwargs)
        if follow and resp.status_code in _REDIRECT_CODES and "location" in resp.headers:
            url = urljoin(url, resp.headers["location"])  # validated next loop
            kwargs.pop("data", None); kwargs.pop("json", None)  # don't replay a body on GET-redirect
            method = "get"
            continue
        return resp
    raise SsrfBlocked(f"too many redirects (> {max_redirects})")


def guarded_get(url: str, **kwargs) -> requests.Response:
    """GET convenience wrapper over guarded_request (see it for semantics)."""
    return guarded_request("get", url, **kwargs)


def _demo() -> None:
    """Self-check: run `python -m net_guard`. No network needed for the IP logic."""
    bad = ["127.0.0.1", "10.0.0.5", "169.254.169.254", "192.168.1.1", "::1",
           "fe80::1", "100.64.0.1", "0.0.0.0", "::ffff:10.0.0.1", "224.0.0.1"]
    good = ["8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"]
    for ip in bad:
        assert _ip_is_disallowed(ip), f"should block {ip}"
    for ip in good:
        assert not _ip_is_disallowed(ip), f"should allow {ip}"
    # literal path of resolve_public_ips
    for ip in bad:
        try:
            resolve_public_ips(ip); assert False, f"resolve should reject {ip}"
        except SsrfBlocked:
            pass
    assert resolve_public_ips("8.8.8.8") == ["8.8.8.8"]
    print("net_guard self-check OK")


if __name__ == "__main__":
    _demo()
