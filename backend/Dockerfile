FROM python:3.11-slim-bookworm AS base

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
    whois \
    git \
    unzip \
    perl \
    libjson-perl \
    libxml-writer-perl \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    && rm -rf /var/lib/apt/lists/*

# testssl.sh
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

# Build context is the REPO ROOT (see docker-compose.yml: context: .,
# dockerfile: backend/Dockerfile) — not ./backend. This is required because
# alembic.ini and migrations/ live at the repo root, as siblings of backend/,
# and migrations/env.py locates backend/ via a relative '../backend' path.
# The image mirrors that exact native layout (/app/backend, /app/migrations,
# /app/alembic.ini) so env.py's path logic works unchanged in both contexts.
WORKDIR /app
COPY backend/requirements.txt backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt

COPY backend/ backend/
COPY alembic.ini .
COPY migrations/ migrations/

WORKDIR /app/backend
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
