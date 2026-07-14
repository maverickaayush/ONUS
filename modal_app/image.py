"""
Shared Modal images for ONUS.

`scanner_image` — amd64 image with every scanner binary the 8 modules shell out
to, mirroring backend/Dockerfile's `fulltools` stage, PLUS an in-container ZAP +
JRE (there is no ZAP sidecar on Modal — webscan's `_run_zap` local-daemon branch
spawns it, triggered by config.ZAP_URL being empty). The backend Python code is
added last (add_local_dir) so editing a module doesn't rebuild the tool layers.

Deploy from the repo root:  modal deploy modal_app/scanners.py
"""
import modal

# amd64 base = Modal-native (the ProjectDiscovery/Go binaries below are amd64).
# public.ecr.aws mirror to avoid Docker Hub anonymous pull limits.
_BASE = "public.ecr.aws/docker/library/python:3.11-slim-bookworm"

_APT = [
    "nmap", "sslscan", "curl", "wget", "ca-certificates", "dnsutils", "git",
    "unzip", "perl", "libjson-perl", "libxml-writer-perl", "libpango-1.0-0",
    "libpangoft2-1.0-0", "bsdextrautils", "procps", "libpcap-dev",
    "ruby", "ruby-dev", "build-essential",
    "default-jre-headless",  # ZAP (in-container on Modal, no sidecar)
]

_ZAP_VERSION = "2.17.0"


def _tool_commands():
    v = _ZAP_VERSION   # ZAP's Linux tarball asset uses dotted version: ZAP_2.15.0_Linux.tar.gz
    return [
        # whois from bookworm-backports (current TLD table - see backend/Dockerfile)
        'echo "deb http://deb.debian.org/debian bookworm-backports main" > /etc/apt/sources.list.d/backports.list',
        "apt-get update && apt-get install -y -t bookworm-backports --no-install-recommends whois && rm -rf /var/lib/apt/lists/*",
        # testssl.sh + nikto + WhatWeb (source)
        "git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl.sh && ln -s /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh",
        "git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto && ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto && chmod +x /opt/nikto/program/nikto.pl",
        "gem install ipaddr addressable json --no-document && git clone --depth 1 https://github.com/urbanadventurer/WhatWeb.git /opt/whatweb && ln -s /opt/whatweb/whatweb /usr/local/bin/whatweb && chmod +x /opt/whatweb/whatweb",
        # ProjectDiscovery / Go binaries (pinned, amd64)
        "curl -L -o /tmp/subfinder.zip https://github.com/projectdiscovery/subfinder/releases/download/v2.6.6/subfinder_2.6.6_linux_amd64.zip && cd /tmp && unzip subfinder.zip && mv subfinder /usr/local/bin/ && chmod +x /usr/local/bin/subfinder && rm subfinder.zip",
        "curl -L -o /tmp/nuclei.zip https://github.com/projectdiscovery/nuclei/releases/download/v3.3.7/nuclei_3.3.7_linux_amd64.zip && cd /tmp && unzip nuclei.zip && mv nuclei /usr/local/bin/ && chmod +x /usr/local/bin/nuclei && rm nuclei.zip",
        "nuclei -update-templates -silent || true",
        "curl -L -o /tmp/ffuf.tar.gz https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz && cd /tmp && tar xzf ffuf.tar.gz && mv ffuf /usr/local/bin/ && chmod +x /usr/local/bin/ffuf && rm ffuf.tar.gz",
        "curl -sL -o /tmp/amass.zip https://github.com/owasp-amass/amass/releases/download/v4.2.0/amass_Linux_amd64.zip && cd /tmp && unzip amass.zip && mv amass_Linux_amd64/amass /usr/local/bin/ && chmod +x /usr/local/bin/amass && rm -rf amass.zip amass_Linux_amd64",
        "curl -sL -o /tmp/naabu.zip https://github.com/projectdiscovery/naabu/releases/download/v2.3.3/naabu_2.3.3_linux_amd64.zip && cd /tmp && unzip -o naabu.zip && mv naabu /usr/local/bin/ && chmod +x /usr/local/bin/naabu && rm naabu.zip",
        "curl -sL -o /tmp/katana.zip https://github.com/projectdiscovery/katana/releases/download/v1.1.2/katana_1.1.2_linux_amd64.zip && cd /tmp && unzip -o katana.zip && mv katana /usr/local/bin/ && chmod +x /usr/local/bin/katana && rm katana.zip",
        # SecLists subset for FFUF
        "mkdir -p /opt/wordlists && curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt -o /opt/wordlists/common.txt && curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-small.txt -o /opt/wordlists/directories.txt",
        # OWASP ZAP (in-container; webscan._run_zap spawns it when ZAP_URL is empty)
        f"curl -fsSL -o /tmp/zap.tar.gz https://github.com/zaproxy/zaproxy/releases/download/v{v}/ZAP_{v}_Linux.tar.gz && cd /opt && tar xzf /tmp/zap.tar.gz && mv ZAP_{v} zaproxy && ln -s /opt/zaproxy/zap.sh /usr/local/bin/zap.sh && rm /tmp/zap.tar.gz",
    ]


# httpx binary must install AFTER pip (the Python httpx package ships a same-named
# console-script shim) — see backend/Dockerfile. So: base+tools -> pip -> httpx.
scanner_image = (
    # No add_python: the base image already ships Python 3.11 (adding Modal's
    # own python collides on /usr/local/bin/python).
    modal.Image.from_registry(_BASE)
    .apt_install(*_APT)
    .run_commands(*_tool_commands())
    .pip_install_from_requirements("backend/requirements.txt")
    .run_commands(
        "curl -sL -o /tmp/httpx.zip https://github.com/projectdiscovery/httpx/releases/download/v1.6.9/httpx_1.6.9_linux_amd64.zip && cd /tmp && unzip -o httpx.zip && mv httpx /usr/local/bin/ && chmod +x /usr/local/bin/httpx && rm httpx.zip",
    )
    # Scanner modules read config with defaults on Modal. ZAP_URL empty ->
    # webscan spawns ZAP locally in this container. FFUF wordlists live where
    # enumeration.py expects them.
    .env({"ZAP_URL": "", "SCANNER_BACKEND": "local"})
    # Backend code last, so a module edit re-uploads only this thin layer.
    .add_local_dir("backend", "/app/backend")
)
