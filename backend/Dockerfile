# syntax=docker/dockerfile:1.7
FROM python:3.14-slim AS builder
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN python -m venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH
COPY requirements.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt \
 # No package manager in the runtime image (attack surface + vendored CVEs).
 && pip uninstall -y pip

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
COPY app /srv/app
WORKDIR /srv
USER 1000:1000
ENV PATH=/opt/venv/bin:$PATH PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/api/health',timeout=3)"
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", \
     "--forwarded-allow-ips", "*", "--no-server-header", "--timeout-graceful-shutdown", "10"]
