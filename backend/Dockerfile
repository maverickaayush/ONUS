# Base image pulled from AWS's public ECR mirror of Docker Hub's official images
# (public.ecr.aws/docker/library/*) rather than docker.io directly: identical
# image, but not subject to Docker Hub's anonymous pull rate limit, which was
# failing CI's `docker compose build` at pull time on shared runner IPs.
FROM public.ecr.aws/docker/library/python:3.11-slim-bookworm AS base

# System tools the scanner modules need (ZAP runs as a separate sidecar
# container — see docker-compose.yml — not installed here).
# NOTE: nikto is NOT in Debian's apt repos (verified — neither trixie nor
# bookworm; it's only packaged for Ubuntu's universe repo). perl is already
# present in the base image, so nikto is installed from source below instead,
# the same pattern already used for testssl.sh. libjson-perl and
# libxml-writer-perl are nikto's runtime deps for -Format json/xml output
# (verified missing via `nikto -Version`, confirmed available in bookworm).
#
# libpango-1.0-0 + libpangoft2-1.0-0 are WeasyPrint's runtime dependency for
# PDF rendering (pulls in libgobject/libcairo transitively) — the weasyprint
# pip package only ships Python bindings, not these system libs (verified
# via the actual ImportError: "cannot load library 'libgobject-2.0-0'").
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    sslscan \
    curl \
    wget \
    ca-certificates \
    dnsutils \
    git \
    unzip \
    perl \
    libjson-perl \
    libxml-writer-perl \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    bsdextrautils \
    procps \
    && rm -rf /var/lib/apt/lists/*

# whois - from bookworm-backports, NOT plain bookworm/main. Real bug found
# by actually running `whois` against a real domain (demo-target.example) inside the
# built image: bookworm/main's whois 5.5.17 ships a stale hardcoded TLD
# server table - `.in` still points at `whois.registry.in`, a hostname
# that no longer resolves anywhere (confirmed via strace: NIXI, the .in
# registry, migrated to `whois.nixiregistry.in` at some point after
# 5.5.17 was packaged). Every real-world non-.com/.net/.org domain this
# tool has ever scanned silently got zero WHOIS findings because of this -
# not a python-whois parsing bug (WhoisEntry.load's regexes are fine and
# correctly extract every field once the binary actually returns text).
# 5.6.2~bpo12+1 has the current table - confirmed live.
RUN echo "deb http://deb.debian.org/debian bookworm-backports main" \
    > /etc/apt/sources.list.d/backports.list && \
    apt-get update && apt-get install -y -t bookworm-backports --no-install-recommends whois \
    && rm -rf /var/lib/apt/lists/*

# testssl.sh - needs `hexdump` (bsdextrautils) and `ps` (procps) above, real
# bug found by running it live: both were missing and it failed with
# "Fatal error: You need to install hexdump/ps for this program to work",
# so it silently never produced a finding on any scan, ever (same silent-
# failure shape as the WhatWeb gem bug below).
RUN git clone --depth 1 https://github.com/drwetter/testssl.sh.git \
    /opt/testssl.sh && \
    ln -s /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh

# nikto (Perl script, not packaged for Debian — install from source)
RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto && \
    ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto && \
    chmod +x /opt/nikto/program/nikto.pl

# subfinder (pinned for reproducibility)
RUN curl -L -o /tmp/subfinder.zip \
    https://github.com/projectdiscovery/subfinder/releases/download/v2.6.6/subfinder_2.6.6_linux_amd64.zip && \
    cd /tmp && unzip subfinder.zip && \
    mv subfinder /usr/local/bin/ && \
    chmod +x /usr/local/bin/subfinder && \
    rm subfinder.zip

# nuclei (pinned prebuilt release binary - same download/unzip/chmod pattern
# as subfinder above; avoids pulling in a full Go toolchain just to build one
# binary from source)
RUN curl -L -o /tmp/nuclei.zip \
    https://github.com/projectdiscovery/nuclei/releases/download/v3.3.7/nuclei_3.3.7_linux_amd64.zip && \
    cd /tmp && unzip nuclei.zip && \
    mv nuclei /usr/local/bin/ && \
    chmod +x /usr/local/bin/nuclei && \
    rm nuclei.zip

# nuclei templates - pulled at build time, not runtime (air-gapped: the tool
# has no internet access once deployed).
RUN nuclei -update-templates -silent || true

# ffuf (pinned prebuilt release binary, same pattern as nuclei/subfinder)
RUN curl -L -o /tmp/ffuf.tar.gz \
    https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz && \
    cd /tmp && tar xzf ffuf.tar.gz && \
    mv ffuf /usr/local/bin/ && \
    chmod +x /usr/local/bin/ffuf && \
    rm ffuf.tar.gz

# WhatWeb - not published as a Rubygem, installed from source same as nikto/
# testssl.sh above (verified: no "whatweb" gem on rubygems.org). Its own
# Gemfile requires ipaddr/addressable/json (the mongo/rchardet/test/dev
# groups are optional and skipped) - installed directly via `gem install`
# rather than `bundle install` to avoid pulling in those optional groups.
# Real bug found during practicality testing: this step was missing
# entirely, so the binary existed but `whatweb --version` reported
# "missing dependencies" on every scan - silently non-functional the whole
# time, never caught because tech_fingerprint treats a WhatWeb failure as
# tolerable partial success (Section 4.3).
RUN apt-get update && apt-get install -y --no-install-recommends ruby ruby-dev build-essential \
    && rm -rf /var/lib/apt/lists/* \
    && gem install ipaddr addressable json --no-document \
    && git clone --depth 1 https://github.com/urbanadventurer/WhatWeb.git /opt/whatweb \
    && ln -s /opt/whatweb/whatweb /usr/local/bin/whatweb \
    && chmod +x /opt/whatweb/whatweb

# WAFW00F is installed via requirements.txt (pip, same as every other Python
# dependency in this image) - no separate install step needed here.

# SecLists wordlist for FFUF (subset only - full list is too large for the image)
RUN mkdir -p /opt/wordlists && \
    curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt \
    -o /opt/wordlists/common.txt && \
    curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-small.txt \
    -o /opt/wordlists/directories.txt

# Amass (pinned) - deep passive subdomain enumeration, recon.py
RUN curl -sL -o /tmp/amass.zip \
    https://github.com/owasp-amass/amass/releases/download/v4.2.0/amass_Linux_amd64.zip && \
    cd /tmp && unzip amass.zip && \
    mv amass_Linux_amd64/amass /usr/local/bin/ && \
    chmod +x /usr/local/bin/amass && \
    rm -rf amass.zip amass_Linux_amd64

# Naabu (pinned) - fast SYN pre-scan on discovered subdomains, recon.py
RUN curl -sL -o /tmp/naabu.zip \
    https://github.com/projectdiscovery/naabu/releases/download/v2.3.3/naabu_2.3.3_linux_amd64.zip && \
    cd /tmp && unzip -o naabu.zip && \
    mv naabu /usr/local/bin/ && \
    chmod +x /usr/local/bin/naabu && \
    rm naabu.zip

# Katana (pinned) - JS-aware crawler supplementing ZAP's spider, webscan.py
# unzip -o for the same reason as httpx above (bundled LICENSE.md/README.md).
RUN curl -sL -o /tmp/katana.zip \
    https://github.com/projectdiscovery/katana/releases/download/v1.1.2/katana_1.1.2_linux_amd64.zip && \
    cd /tmp && unzip -o katana.zip && \
    mv katana /usr/local/bin/ && \
    chmod +x /usr/local/bin/katana && \
    rm katana.zip

# libpcap (Naabu SYN scan dependency)
RUN apt-get update && apt-get install -y --no-install-recommends libpcap-dev && \
    rm -rf /var/lib/apt/lists/*

# Build context is the REPO ROOT (see docker-compose.yml: context: .,
# dockerfile: backend/Dockerfile) — not ./backend. This is required because
# alembic.ini and migrations/ live at the repo root, as siblings of backend/,
# and migrations/env.py locates backend/ via a relative '../backend' path.
# The image mirrors that exact native layout (/app/backend, /app/migrations,
# /app/alembic.ini) so env.py's path logic works unchanged in both contexts.
WORKDIR /app
COPY backend/requirements.txt backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt

# Playwright + headless Chromium - Phase 2 confidence verification
# (analysis/verifier.py's verify_reflected_xss, the only consumer). ~293MB
# (measured) - --with-deps pulls in Chromium's runtime libs via apt, same
# as testssl.sh/nikto/WhatWeb needing apt packages installed above; must
# run after `pip install` since it needs the playwright package's own CLI.
RUN playwright install --with-deps chromium

# httpx (pinned) - live-host probing + tech-detect, recon.py
# Installed AFTER pip, not alongside amass/naabu/katana above (real build bug,
# not stylistic): the Python `httpx` package (requirements.txt, pulled in as a
# fastapi dependency) ships a console_scripts shim also named `httpx`, at the
# same /usr/local/bin path. Since pip previously ran BEFORE this block, its
# shim silently overwrote the ProjectDiscovery binary - confirmed by actually
# running the built image: `httpx -version` returned the Python HTTP client
# CLI's usage text ("No such option '-e'"), not ProjectDiscovery's version
# banner. Installing the binary after pip makes it win the collision instead.
# unzip -o: httpx's release zip also bundles LICENSE.md/README.md alongside
# the binary - a plain `unzip` prompts interactively to overwrite once an
# earlier tool's zip has already dropped a same-named file in /tmp, and a
# non-interactive Docker build has no stdin to answer with (verified by an
# actual failed build: "replace LICENSE.md? ... EOF ... exit code 1").
RUN curl -sL -o /tmp/httpx.zip \
    https://github.com/projectdiscovery/httpx/releases/download/v1.6.9/httpx_1.6.9_linux_amd64.zip && \
    cd /tmp && unzip -o httpx.zip && \
    mv httpx /usr/local/bin/ && \
    chmod +x /usr/local/bin/httpx && \
    rm httpx.zip

COPY backend/ backend/
COPY alembic.ini .
COPY migrations/ migrations/

WORKDIR /app/backend
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
