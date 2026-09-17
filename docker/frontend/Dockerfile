# syntax=docker/dockerfile:1.7
# Web app + reverse proxy (build context: ./frontend). Caddy serves the built SPA,
# proxies /api, /health and /ready to the API, sets security headers and caps request
# bodies before they reach Python.

FROM node:22-bookworm-slim AS build
WORKDIR /src
COPY package.json package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci --no-audit --no-fund
COPY . .
RUN npm run build

FROM caddy:2.10-alpine AS runtime
COPY --from=build /src/dist /srv
COPY Caddyfile /etc/caddy/Caddyfile
# Caddy needs no root inside the container: it listens on 8080 and the platform (or a
# port mapping) exposes 80/443.
# The stock binary carries cap_net_bind_service, which exec refuses once all capabilities
# are dropped; port 8080 doesn't need it, so ship a copy without file capabilities.
RUN cp /usr/bin/caddy /tmp/caddy && mv /tmp/caddy /usr/bin/caddy \
    && addgroup -S -g 10002 web && adduser -S -u 10002 -G web web \
    && mkdir -p /data /config && chown -R web:web /data /config
USER web
EXPOSE 8080
