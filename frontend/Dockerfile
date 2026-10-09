# syntax=docker/dockerfile:1.7
# ---- Build stage (unprivileged) -------------------------------------------------------------
FROM node:24-alpine AS build
RUN mkdir /app && chown node:node /app
USER node
WORKDIR /app
COPY --chown=node:node package.json package-lock.json ./
# --ignore-scripts: no install-time code execution from dependencies (supply chain hardening).
RUN npm ci --ignore-scripts --no-fund --no-audit
COPY --chown=node:node . .
# `npm run build` triggers `prebuild` = `npm audit --audit-level=critical`: the build fails (exit > 0)
# before any compilation if a critical vulnerability is present.
RUN npm run build

# ---- Runtime stage: unprivileged nginx (uid 101), read-only root filesystem compatible ----------
FROM nginxinc/nginx-unprivileged:stable-alpine
LABEL org.opencontainers.image.title="logstash-explorer-frontend"
COPY --chown=root:root nginx/default.conf /etc/nginx/conf.d/default.conf
COPY --chown=root:root nginx/security-headers.conf nginx/proxy.conf /etc/nginx/snippets/
COPY --chown=root:root --from=build /app/dist /usr/share/nginx/html
USER 101:101
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD wget -q -O /dev/null http://127.0.0.1:8080/healthz || exit 1
