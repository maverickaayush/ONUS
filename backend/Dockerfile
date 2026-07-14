# ═══════════════════════════════════════════════════════════════════════════
# Multi-target backend image.
#
#   backend  - arm64-CLEAN production image for Oracle Cloud (Ampere A1). Runs
#              FastAPI + Celery orchestrator + aggregator/verifier/CVSS-scorer/
#              PDF. Contains NO scanner binaries (those run on Modal), so it
#              builds cleanly on arm64. Includes Playwright/Chromium (the XSS
#              verifier) + WeasyPrint libs, both arm64-supported.
#              Build: docker build --target backend --platform linux/arm64 ...
#
#   full     - backend + every scanner tool (amd64). This is the local-dev
#              all-in-one image used when SCANNER_BACKEND=local. docker-compose
#              builds this target. amd64 only (the Go/ProjectDiscovery binaries).
#
# Base images come from public.ecr.aws (AWS's mirror of Docker Hub official
# images) to avoid Docker Hub's anonymous pull rate limit failing CI at pull
# time. Dockerfiles/local dev unaffected in behavior.
# ═══════════════════════════════════════════════════════════════════════════

# ── base: python + shared runtime libs + pip deps + Playwright ──────────────
# Everything here is arch-neutral (pip wheels / apt libs exist for arm64 too).
FROM public.ecr.aws/docker/library/python:3.11-slim-bookworm AS base

# Shared system deps:
#   - libpango-1.0-0/libpangoft2-1.0-0: WeasyPrint PDF rendering (pulls
#     libgobject/libcairo transitively) - the weasyprint pip package ships only
#     Python bindings, not these libs (verified via the ImportError).
#   - build-essential: some pip packages compile a native extension when no
#     wheel matches the platform (notably on arm64); present during pip install.
#   - git/curl/ca-certificates: pip VCS installs + Playwright download.
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    git \
    build-essential \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY backend/requirements.txt backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt

# Playwright + headless Chromium - Phase 2 confidence verification
# (analysis/verifier.py's verify_reflected_xss). ~1.56GB on disk; must run
# after pip (needs the playwright package's own CLI). arm64-supported.
RUN playwright install --with-deps chromium

# ── backend (final): Oracle arm64 image, no scanner binaries ────────────────
FROM base AS backend
# Build context is the REPO ROOT (docker-compose: context: ., dockerfile:
# backend/Dockerfile) - alembic.ini and migrations/ live at the repo root as
# siblings of backend/, and migrations/env.py locates backend/ via '../backend'.
COPY backend/ backend/
COPY alembic.ini .
COPY migrations/ migrations/
WORKDIR /app/backend
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]

# ── fulltools: base + every scanner tool (amd64, local dev only) ────────────
FROM base AS fulltools

# NOTE: nikto is NOT in Debian's apt repos (Ubuntu-universe only) - installed
# from source below (same as testssl.sh/WhatWeb). libjson-perl/libxml-writer-perl
# are nikto's runtime deps for -Format json/xml. bsdextrautils(hexdump)/procps(ps)
# are testssl.sh's runtime deps (it fatally errors without them).
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    sslscan \
    wget \
    dnsutils \
    unzip \
    perl \
    libjson-perl \
    libxml-writer-perl \
    bsdextrautils \
    procps \
    && rm -rf /var/lib/apt/lists/*

# whois - from bookworm-backports (5.6.2), NOT bookworm/main (5.5.17): main's
# stale hardcoded TLD server table points .in at a hostname that no longer
# resolves, so every non-.com/.net/.org domain silently got zero WHOIS findings.
RUN echo "deb http://deb.debian.org/debian bookworm-backports main" \
    > /etc/apt/sources.list.d/backports.list && \
    apt-get update && apt-get install -y -t bookworm-backports --no-install-recommends whois \
    && rm -rf /var/lib/apt/lists/*

# testssl.sh (source)
RUN git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl.sh && \
    ln -s /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh

# nikto (Perl, source)
RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto && \
    ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto && \
    chmod +x /opt/nikto/program/nikto.pl

# subfinder (pinned amd64 binary)
RUN curl -L -o /tmp/subfinder.zip \
    https://github.com/projectdiscovery/subfinder/releases/download/v2.6.6/subfinder_2.6.6_linux_amd64.zip && \
    cd /tmp && unzip subfinder.zip && mv subfinder /usr/local/bin/ && \
    chmod +x /usr/local/bin/subfinder && rm subfinder.zip

# nuclei (pinned amd64 binary) + templates (baked at build - air-gapped runtime)
RUN curl -L -o /tmp/nuclei.zip \
    https://github.com/projectdiscovery/nuclei/releases/download/v3.3.7/nuclei_3.3.7_linux_amd64.zip && \
    cd /tmp && unzip nuclei.zip && mv nuclei /usr/local/bin/ && \
    chmod +x /usr/local/bin/nuclei && rm nuclei.zip
RUN nuclei -update-templates -silent || true

# ffuf (pinned amd64 binary)
RUN curl -L -o /tmp/ffuf.tar.gz \
    https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz && \
    cd /tmp && tar xzf ffuf.tar.gz && mv ffuf /usr/local/bin/ && \
    chmod +x /usr/local/bin/ffuf && rm ffuf.tar.gz

# WhatWeb (Ruby, source - not a published gem). Its Gemfile needs
# ipaddr/addressable/json; gem install directly to skip optional groups.
RUN apt-get update && apt-get install -y --no-install-recommends ruby ruby-dev \
    && rm -rf /var/lib/apt/lists/* \
    && gem install ipaddr addressable json --no-document \
    && git clone --depth 1 https://github.com/urbanadventurer/WhatWeb.git /opt/whatweb \
    && ln -s /opt/whatweb/whatweb /usr/local/bin/whatweb \
    && chmod +x /opt/whatweb/whatweb

# SecLists wordlist subset for FFUF (full list too large for the image)
RUN mkdir -p /opt/wordlists && \
    curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt \
    -o /opt/wordlists/common.txt && \
    curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-small.txt \
    -o /opt/wordlists/directories.txt

# Amass (pinned amd64 binary) - deep passive subdomain enumeration
RUN curl -sL -o /tmp/amass.zip \
    https://github.com/owasp-amass/amass/releases/download/v4.2.0/amass_Linux_amd64.zip && \
    cd /tmp && unzip amass.zip && mv amass_Linux_amd64/amass /usr/local/bin/ && \
    chmod +x /usr/local/bin/amass && rm -rf amass.zip amass_Linux_amd64

# Naabu (pinned amd64 binary) - SYN pre-scan (falls back to CONNECT w/o CAP_NET_RAW)
RUN curl -sL -o /tmp/naabu.zip \
    https://github.com/projectdiscovery/naabu/releases/download/v2.3.3/naabu_2.3.3_linux_amd64.zip && \
    cd /tmp && unzip -o naabu.zip && mv naabu /usr/local/bin/ && \
    chmod +x /usr/local/bin/naabu && rm naabu.zip

# Katana (pinned amd64 binary) - JS-aware crawler
RUN curl -sL -o /tmp/katana.zip \
    https://github.com/projectdiscovery/katana/releases/download/v1.1.2/katana_1.1.2_linux_amd64.zip && \
    cd /tmp && unzip -o katana.zip && mv katana /usr/local/bin/ && \
    chmod +x /usr/local/bin/katana && rm katana.zip

# libpcap (Naabu SYN scan dependency)
RUN apt-get update && apt-get install -y --no-install-recommends libpcap-dev && \
    rm -rf /var/lib/apt/lists/*

# httpx binary AFTER pip (base already ran pip): the Python `httpx` package ships
# a console_scripts shim at the same /usr/local/bin path; installing the
# ProjectDiscovery binary now makes it win the name collision. unzip -o: the
# release zip bundles LICENSE.md/README.md (plain unzip prompts, no stdin in build).
RUN curl -sL -o /tmp/httpx.zip \
    https://github.com/projectdiscovery/httpx/releases/download/v1.6.9/httpx_1.6.9_linux_amd64.zip && \
    cd /tmp && unzip -o httpx.zip && mv httpx /usr/local/bin/ && \
    chmod +x /usr/local/bin/httpx && rm httpx.zip

# ── full (final): fulltools + app code (local dev SCANNER_BACKEND=local) ─────
FROM fulltools AS full
COPY backend/ backend/
COPY alembic.ini .
COPY migrations/ migrations/
WORKDIR /app/backend
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
