"""
ONUS scanner functions on Modal — one function per module so CPU/memory/timeout
differ (lightweight modules must not get ZAP-sized resources).

Each function runs the module's PURE half (tasks.<module>.scan_<module>) inside
the amd64 scanner_image and returns the exact same build_module_result envelope
the local path returns — so the aggregator/scorer/PDF pipeline is unaffected.
The backend's tasks.dispatch.dispatch_scan looks these up by name
(`scan_<module>`) via modal.Function.from_name(MODAL_APP_NAME, ...).

Deploy from the repo ROOT (so the backend/ and requirements paths resolve):
    cd /path/to/vapt-tool && modal deploy modal_app/scanners.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

import modal
from image import scanner_image

app = modal.App("onus-scanners")

# Per-module resource profiles. `base` is the module's base hard-timeout (see
# ARCHITECTURE.md §4.3); the Modal function timeout is base * the same
# SCAN_TIMEOUT_MULTIPLIER the modules' internal tool budgets use (default 1.5),
# plus a 60s margin so Modal never kills a scan the module would have finished.
_MULT = float(os.environ.get("SCAN_TIMEOUT_MULTIPLIER", "1.5"))


def _timeout(base: int) -> int:
    return int(base * _MULT) + 60


_PROFILES = {
    "recon":            dict(cpu=2.0, memory=2048, base=1080),
    "webscan":          dict(cpu=2.0, memory=4096, base=540),   # ZAP in-container
    "nuclei":           dict(cpu=2.0, memory=2048, base=720),
    "enumeration":      dict(cpu=1.0, memory=2048, base=280),
    "tech_fingerprint": dict(cpu=1.0, memory=1024, base=150),
    "owasp":            dict(cpu=1.0, memory=1024, base=420),
    "ssl_tls":          dict(cpu=1.0, memory=1024, base=360),
    "headers":          dict(cpu=0.5, memory=512,  base=360),
}


def _run(module: str, scan_id: str, domain: str, auth):
    """Run the module's pure half inside the Modal container."""
    if "/app/backend" not in sys.path:
        sys.path.insert(0, "/app/backend")
    from tasks.dispatch import _pure_fn
    return _pure_fn(module)(scan_id, domain, auth)


# One decorated function per module. Explicit (not a loop) so Modal's deploy-time
# introspection reliably registers each with its own profile + `scan_<module>` name.
_p = _PROFILES["recon"]
@app.function(image=scanner_image, cpu=_p["cpu"], memory=_p["memory"], timeout=_timeout(_p["base"]), name="scan_recon")
def scan_recon(scan_id, domain, auth=None):
    return _run("recon", scan_id, domain, auth)


_p = _PROFILES["webscan"]
@app.function(image=scanner_image, cpu=_p["cpu"], memory=_p["memory"], timeout=_timeout(_p["base"]), name="scan_webscan")
def scan_webscan(scan_id, domain, auth=None):
    return _run("webscan", scan_id, domain, auth)


_p = _PROFILES["nuclei"]
@app.function(image=scanner_image, cpu=_p["cpu"], memory=_p["memory"], timeout=_timeout(_p["base"]), name="scan_nuclei")
def scan_nuclei(scan_id, domain, auth=None):
    return _run("nuclei", scan_id, domain, auth)


_p = _PROFILES["enumeration"]
@app.function(image=scanner_image, cpu=_p["cpu"], memory=_p["memory"], timeout=_timeout(_p["base"]), name="scan_enumeration")
def scan_enumeration(scan_id, domain, auth=None):
    return _run("enumeration", scan_id, domain, auth)


_p = _PROFILES["tech_fingerprint"]
@app.function(image=scanner_image, cpu=_p["cpu"], memory=_p["memory"], timeout=_timeout(_p["base"]), name="scan_tech_fingerprint")
def scan_tech_fingerprint(scan_id, domain, auth=None):
    return _run("tech_fingerprint", scan_id, domain, auth)


_p = _PROFILES["owasp"]
@app.function(image=scanner_image, cpu=_p["cpu"], memory=_p["memory"], timeout=_timeout(_p["base"]), name="scan_owasp")
def scan_owasp(scan_id, domain, auth=None):
    return _run("owasp", scan_id, domain, auth)


_p = _PROFILES["ssl_tls"]
@app.function(image=scanner_image, cpu=_p["cpu"], memory=_p["memory"], timeout=_timeout(_p["base"]), name="scan_ssl_tls")
def scan_ssl_tls(scan_id, domain, auth=None):
    return _run("ssl_tls", scan_id, domain, auth)


_p = _PROFILES["headers"]
@app.function(image=scanner_image, cpu=_p["cpu"], memory=_p["memory"], timeout=_timeout(_p["base"]), name="scan_headers")
def scan_headers(scan_id, domain, auth=None):
    return _run("headers", scan_id, domain, auth)


@app.local_entrypoint()
def main(module: str = "headers", domain: str = "testphp.vulnweb.com"):
    """Quick manual check: `modal run modal_app/scanners.py --module ssl_tls --domain testfire.net`"""
    fn = modal.Function.from_name("onus-scanners", f"scan_{module}")
    env = fn.remote("modal-smoke-test", domain, None)
    print(f"[{module}] status={env.get('status')} findings={env.get('finding_count')} "
          f"tools={list((env.get('tool_versions') or {}).keys())} error={env.get('error')}")
