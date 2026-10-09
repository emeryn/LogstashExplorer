# syntax=docker/dockerfile:1.7
# Isolated Logstash runner: official Logstash distribution (with its bundled JDK) on a minimal
# Python base, executed as an unprivileged user. Files copied from the Logstash image are owned
# by root and therefore immutable for the runtime user.
ARG LOGSTASH_VERSION=9.5.5
FROM logstash:${LOGSTASH_VERSION} AS logstash
# Remove bundled plugins that the sandbox never allows (network integrations) — smaller attack
# surface and no CVEs from their vendored jars.
RUN bin/logstash-plugin remove logstash-filter-elastic_integration logstash-integration-kafka \
      logstash-input-azure_event_hubs \
 # Syslog output: executed against a local capture listener to verify the exact wire format.
 && bin/logstash-plugin install --version 3.1.0 logstash-output-syslog

FROM python:3.14-slim
ARG LOGSTASH_VERSION
LABEL org.opencontainers.image.title="logstash-explorer-runner" \
      org.opencontainers.image.description="Sandboxed ephemeral Logstash executor" \
      org.logstash.version="${LOGSTASH_VERSION}"

COPY --from=logstash /usr/share/logstash /usr/share/logstash
RUN groupadd -g 1000 runner \
 && useradd -u 1000 -g 1000 -M -d /tmp -s /usr/sbin/nologin runner \
 && mkdir -p /opt/ls-settings /run/lsx-secrets/runner \
 && cp /usr/share/logstash/config/jvm.options /usr/share/logstash/config/log4j2.properties /opt/ls-settings/ \
 && chown 1000:1000 /run/lsx-secrets/runner \
 && rm -f /usr/share/logstash/config/logstash.yml \
 # Default path.data must exist (validated at boot) even though each run uses its own tmp dir.
 && rm -rf /usr/share/logstash/data && mkdir -m 0555 /usr/share/logstash/data \
 && python -m pip uninstall -y pip

COPY log4j2.properties /opt/ls-settings/log4j2.properties
COPY runner.py syslog_check.py /srv/

USER 1000:1000
ENV LOGSTASH_HOME=/usr/share/logstash PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HOME=/tmp
EXPOSE 8700
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8700/health',timeout=3)"
CMD ["python", "/srv/runner.py"]
