"""
ONUS scanner functions on Modal — one function per module so CPU/memory/timeout
differ (lightweight modules must not get ZAP-sized resources).

Each function runs the module's PURE half (tasks.<module>.scan_<module>) inside
the amd64 scanner image and returns the exact same build_module_result envelope
the local path returns — so the aggregator/scorer/PDF pipeline is unaffected.
The backend's tasks.dispatch.dispatch_scan looks these up by name
(`scan_<module>`) via modal.Function.from_name(MODAL_APP_NAME, ...).

The image is defined INLINE here (not imported from a sibling module) so the
container - which re-imports this file to hydrate a function - has no local
cross-file import to resolve.

Deploy from the repo ROOT (so backend/ and requirements paths resolve):
    cd /path/to/vapt-tool && modal deploy modal_app/scanners.py
"""
import os
import sys

import modal

# ── Scanner image: amd64 (Modal-native), mirrors backend/Dockerfile's fulltools
# stage PLUS an in-container ZAP + JRE (no ZAP sidecar on Modal). public.ecr.aws
# base to dodge Docker Hub pull limits. Backend code added last so a module edit
# re-uploads only that thin layer. ──────────────────────────────────────────────
_BASE = "public.ecr.aws/docker/library/python:3.11-slim-bookworm"
_ZAP_VERSION = "2.17.0"
_APT = [
    "nmap", "sslscan", "curl", "wget", "ca-certificates", "dnsutils", "git",
    "unzip", "perl", "libjson-perl", "libxml-writer-perl", "libpango-1.0-0",
    "libpangoft2-1.0-0", "bsdextrautils", "procps", "libpcap-dev",
    "ruby", "ruby-dev", "build-essential",
    "default-jre-headless",  # ZAP in-container
]
_TOOLS = [
    'echo "deb http://deb.debian.org/debian bookworm-backports main" > /etc/apt/sources.list.d/backports.list',
    "apt-get update && apt-get install -y -t bookworm-backports --no-install-recommends whois && rm -rf /var/lib/apt/lists/*",
    "git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl.sh && ln -s /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh",
    "git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto && ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto && chmod +x /opt/nikto/program/nikto.pl",
    "gem install ipaddr addressable json --no-document && git clone --depth 1 https://github.com/urbanadventurer/WhatWeb.git /opt/whatweb && ln -s /opt/whatweb/whatweb /usr/local/bin/whatweb && chmod +x /opt/whatweb/whatweb",
    "curl -L -o /tmp/subfinder.zip https://github.com/projectdiscovery/subfinder/releases/download/v2.6.6/subfinder_2.6.6_linux_amd64.zip && cd /tmp && unzip subfinder.zip && mv subfinder /usr/local/bin/ && chmod +x /usr/local/bin/subfinder && rm subfinder.zip",
    "curl -L -o /tmp/nuclei.zip https://github.com/projectdiscovery/nuclei/releases/download/v3.3.7/nuclei_3.3.7_linux_amd64.zip && cd /tmp && unzip nuclei.zip && mv nuclei /usr/local/bin/ && chmod +x /usr/local/bin/nuclei && rm nuclei.zip",
    "nuclei -update-templates -silent || true",
    "curl -L -o /tmp/ffuf.tar.gz https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz && cd /tmp && tar xzf ffuf.tar.gz && mv ffuf /usr/local/bin/ && chmod +x /usr/local/bin/ffuf && rm ffuf.tar.gz",
    "curl -sL -o /tmp/amass.zip https://github.com/owasp-amass/amass/releases/download/v4.2.0/amass_Linux_amd64.zip && cd /tmp && unzip amass.zip && mv amass_Linux_amd64/amass /usr/local/bin/ && chmod +x /usr/local/bin/amass && rm -rf amass.zip amass_Linux_amd64",
    "curl -sL -o /tmp/naabu.zip https://github.com/projectdiscovery/naabu/releases/download/v2.3.3/naabu_2.3.3_linux_amd64.zip && cd /tmp && unzip -o naabu.zip && mv naabu /usr/local/bin/ && chmod +x /usr/local/bin/naabu && rm naabu.zip",
    "curl -sL -o /tmp/katana.zip https://github.com/projectdiscovery/katana/releases/download/v1.1.2/katana_1.1.2_linux_amd64.zip && cd /tmp && unzip -o katana.zip && mv katana /usr/local/bin/ && chmod +x /usr/local/bin/katana && rm katana.zip",
    "mkdir -p /opt/wordlists && curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt -o /opt/wordlists/common.txt && curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-small.txt -o /opt/wordlists/directories.txt",
    f"curl -fsSL -o /tmp/zap.tar.gz https://github.com/zaproxy/zaproxy/releases/download/v{_ZAP_VERSION}/ZAP_{_ZAP_VERSION}_Linux.tar.gz && cd /opt && tar xzf /tmp/zap.tar.gz && mv ZAP_{_ZAP_VERSION} zaproxy && ln -s /opt/zaproxy/zap.sh /usr/local/bin/zap.sh && rm /tmp/zap.tar.gz",
]

scanner_image = (
    modal.Image.from_registry(_BASE)   # base already ships python 3.11 (no add_python)
    .apt_install(*_APT)
    .run_commands(*_TOOLS)
    .pip_install_from_requirements("backend/requirements.txt")
    # httpx binary AFTER pip (Python httpx ships a same-named shim - see Dockerfile)
    .run_commands(
        "curl -sL -o /tmp/httpx.zip https://github.com/projectdiscovery/httpx/releases/download/v1.6.9/httpx_1.6.9_linux_amd64.zip && cd /tmp && unzip -o httpx.zip && mv httpx /usr/local/bin/ && chmod +x /usr/local/bin/httpx && rm httpx.zip",
    )
    .env({"ZAP_URL": "", "SCANNER_BACKEND": "local"})   # local -> webscan spawns ZAP in-container
    .add_local_dir("backend", "/app/backend")
)

app = modal.App("onus-scanners")

# Per-module profiles. Modal timeout = base * SCAN_TIMEOUT_MULTIPLIER (same knob
# the modules' internal tool budgets use, default 1.5) + 60s margin.
_MULT = float(os.environ.get("SCAN_TIMEOUT_MULTIPLIER", "1.5"))


def _timeout(base: int) -> int:
    return int(base * _MULT) + 60


_PROFILES = {
    "recon":            dict(cpu=2.0, memory=2048, base=1080),
    "webscan":          dict(cpu=2.0, memory=4096, base=540),
    "nuclei":           dict(cpu=2.0, memory=2048, base=720),
    "enumeration":      dict(cpu=1.0, memory=2048, base=280),
    "tech_fingerprint": dict(cpu=1.0, memory=1024, base=150),
    "owasp":            dict(cpu=1.0, memory=1024, base=540),  # >owasp's internal 480s budget + margin
    "ssl_tls":          dict(cpu=1.0, memory=1024, base=360),
    "headers":          dict(cpu=0.5, memory=512,  base=360),
}


def _run(module: str, scan_id: str, domain: str, auth):
    if "/app/backend" not in sys.path:
        sys.path.insert(0, "/app/backend")
    from tasks.dispatch import _pure_fn
    return _pure_fn(module)(scan_id, domain, auth)


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
    fn = modal.Function.from_name("onus-scanners", f"scan_{module}")
    env = fn.remote("modal-smoke-test", domain, None)
    print(f"[{module}] status={env.get('status')} findings={env.get('finding_count')} "
          f"tools={list((env.get('tool_versions') or {}).keys())} error={env.get('error')}")
