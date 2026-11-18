# VulnScan image: API + worker + every CLI scanner.  Build: docker compose build
#
# Layer order = slowest/least-changed first, so a normal rebuild only reruns the last steps:
#   system packages -> AI runtime (torch, the big one) -> python scanners -> scanner binaries
#   (one layer each, ARG declared right before use) -> VulnScan code.
# Bumping e.g. GRYPE_VERSION only rebuilds from that line down (~1-2 min).
ARG BASE_IMAGE=python:3.12-slim-bookworm
FROM ${BASE_IMAGE}

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PATH="/opt/tools/bin:/opt/tools/nikto/program:/opt/tools/testssl:${PATH}" \
    HF_HOME=/data/hf GRYPE_DB_CACHE_DIR=/data/cache/grype TRIVY_CACHE_DIR=/data/cache/trivy \
    XDG_CONFIG_HOME=/data/cache/config XDG_CACHE_HOME=/data/cache/xdg \
    GRYPE_DB_UPDATE_DOWNLOAD_TIMEOUT=30m

# System packages: nmap, perl (nikto), testssl deps, git, WeasyPrint (PDF) libs
RUN apt-get update && apt-get install -y --no-install-recommends \
      git curl ca-certificates unzip xz-utils nmap perl libnet-ssleay-perl libjson-perl libxml-writer-perl \
      bsdmainutils dnsutils procps openssl iputils-ping gosu \
      libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz0b libharfbuzz-subset0 fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/* && mkdir -p /opt/tools/bin

# Prompt Guard 2 runtime (CPU-only torch keeps the image ~1.5 GB smaller than CUDA builds)
ARG INSTALL_AI=true
RUN if [ "$INSTALL_AI" = "true" ]; then pip install --index-url https://download.pytorch.org/whl/cpu "torch>=2.3" && pip install "transformers>=4.44"; fi

# Python-based scanners each get their own virtualenv so their pinned deps never clash with ours
RUN set -eux; \
    python -m venv /opt/venvs/semgrep && /opt/venvs/semgrep/bin/pip install "semgrep>=1.100,<2" && ln -s /opt/venvs/semgrep/bin/semgrep /opt/tools/bin/semgrep; \
    python -m venv /opt/venvs/pytools && /opt/venvs/pytools/bin/pip install "bandit[toml]>=1.7" "sqlmap>=1.8" "modelscan>=0.8"; \
    for b in bandit sqlmap modelscan; do ln -s /opt/venvs/pytools/bin/$b /opt/tools/bin/$b; done

# Pinned scanner binaries - one layer each so changing one version doesn't redo the others
ARG TESTSSL_VERSION=v3.2.2
RUN git clone --depth 1 --branch "${TESTSSL_VERSION}" https://github.com/testssl/testssl.sh /opt/tools/testssl && chmod +x /opt/tools/testssl/testssl.sh
ARG NIKTO_REF=pre-pro-cutover-20260209
RUN git clone --depth 1 --branch "${NIKTO_REF}" https://github.com/sullo/nikto /opt/tools/nikto && chmod +x /opt/tools/nikto/program/nikto.pl
ARG GITLEAKS_VERSION=8.21.2
RUN curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" | tar -xz -C /opt/tools/bin gitleaks
ARG NUCLEI_VERSION=3.3.7
RUN curl -fsSL -o /tmp/nuclei.zip "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" \
    && unzip -o /tmp/nuclei.zip nuclei -d /opt/tools/bin && rm /tmp/nuclei.zip
ARG TRIVY_VERSION=0.70.0
RUN curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" | tar -xz -C /opt/tools/bin trivy
ARG SYFT_VERSION=1.17.0
RUN curl -fsSL "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_amd64.tar.gz" | tar -xz -C /opt/tools/bin syft
ARG GRYPE_VERSION=0.100.0
RUN curl -fsSL "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_amd64.tar.gz" | tar -xz -C /opt/tools/bin grype

# Optional extras
ARG INSTALL_GARAK=false
RUN if [ "$INSTALL_GARAK" = "true" ]; then python -m venv /opt/venvs/garak && /opt/venvs/garak/bin/pip install "garak>=0.10" && ln -s /opt/venvs/garak/bin/garak /opt/tools/bin/garak; fi
ARG INSTALL_PROWLER=false
RUN if [ "$INSTALL_PROWLER" = "true" ]; then python -m venv /opt/venvs/prowler && /opt/venvs/prowler/bin/pip install "prowler>=5" && ln -s /opt/venvs/prowler/bin/prowler /opt/tools/bin/prowler; fi

# VulnScan itself (changes most often -> last)
WORKDIR /app
COPY pyproject.toml README.md ./
# dependencies first (cached until pyproject.toml changes), then the code itself
RUN mkdir vulnscan && touch vulnscan/__init__.py && pip install ".[postgres,pdf,openvas,mcp]" && rm -rf vulnscan build
COPY vulnscan ./vulnscan
RUN pip install --no-deps --force-reinstall .

# Run the process as a non-root user (defence in depth). The entrypoint fixes the data
# volume's ownership as root, then drops to 'scanner' via gosu. Nmap falls back to TCP
# connect scans without root, so scanning still works unprivileged.
RUN useradd -m scanner && mkdir -p /data && chown -R scanner:scanner /data /app /opt/tools
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
VOLUME ["/data"]
ENV DATA_DIR=/data
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=5 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health').status==200 else 1)" || exit 1
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["uvicorn", "vulnscan.api:app", "--host", "0.0.0.0", "--port", "8000"]
