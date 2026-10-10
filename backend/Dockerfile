# syntax=docker/dockerfile:1.7
FROM python:3.14-slim AS builder
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN python -m venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH
COPY requirements.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt \
 # No package manager in the runtime image (attack surface + vendored CVEs).
 && pip uninstall -y pip

# LAUREL (GPL-3.0, unmodified upstream release) groups raw auditd records into JSON events.
# Pinned release, checked against the SHA-256 digests published on GitHub.
FROM python:3.14-slim AS laurel
ARG TARGETARCH
ARG LAUREL_VERSION=0.8.2
RUN set -eu; \
    case "${TARGETARCH:-amd64}" in \
      amd64) asset=x86_64-musl; sum=89f6bfbed42a5b6824aa847cecf43abc55dafe6778515c3514be43c037ef2662 ;; \
      arm64) asset=aarch64-glibc; sum=fb15e9ff013a9ec65b8c81e76aed684a13d4f72ba68dcd8fdf8c1ba4e35c6a50 ;; \
      *) echo "no LAUREL build for ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    name="laurel-${LAUREL_VERSION}-${asset}"; \
    python -c "import sys, urllib.request; urllib.request.urlretrieve(sys.argv[1], '/tmp/laurel.tgz')" \
      "https://github.com/threathunters-io/laurel/releases/download/v${LAUREL_VERSION}/${name}.tar.gz"; \
    echo "${sum}  /tmp/laurel.tgz" | sha256sum -c -; \
    tar -xzf /tmp/laurel.tgz -C /tmp; \
    install -m 0755 "/tmp/${name}/bin/laurel" /usr/local/bin/laurel; \
    /usr/local/bin/laurel --version

FROM python:3.14-slim
LABEL org.opencontainers.image.title="logstash-explorer-backend"
# postgresql-client: pg_dump for the encrypted daily backups.
RUN apt-get update \
 && apt-get install -y --no-install-recommends postgresql-client \
 && apt-get purge -y --auto-remove \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd -g 1000 app \
 && useradd -u 1000 -g 1000 -M -d /nonexistent -s /usr/sbin/nologin app \
 # Mount points pre-created with the right owner: named volumes inherit it on first use.
 && mkdir -p /run/lsx-secrets/db /run/lsx-secrets/app /run/lsx-secrets/runner /backups /pki \
 && chown -R 1000:1000 /run/lsx-secrets /backups /pki \
 && chmod 0700 /run/lsx-secrets/app /backups \
 && chmod 0755 /run/lsx-secrets/db /run/lsx-secrets/runner /pki \
 && python -m pip uninstall -y pip && rm -rf /root/.cache

COPY --from=builder /opt/venv /opt/venv
COPY --from=laurel /usr/local/bin/laurel /usr/local/bin/laurel
COPY app /srv/app
WORKDIR /srv
USER 1000:1000
ENV PATH=/opt/venv/bin:$PATH PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/api/health',timeout=3)"
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", \
     "--forwarded-allow-ips", "*", "--no-server-header", "--timeout-graceful-shutdown", "10"]
