# Secure Deployment Guide

This guide summarizes recommended settings to run the Zero‑Trust Infrastructure Scanner securely in production.

## Goals

- Enforce authenticated, encrypted access to the real‑time monitor and dashboard
- Protect secrets and configuration at rest and in transit
- Reduce attack surface and operational risk

## Transport security (TLS / wss)

- Terminate TLS at a reverse proxy or ingress (e.g., Nginx, Envoy, Traefik, cloud LB). Serve the WebSocket endpoint over wss://.
- Recommended minimums:
  - TLS v1.2+ with modern ciphers; prefer v1.3 where supported
  - HSTS with preload in public deployments
  - HTTP→HTTPS redirects only; disable clear‑text WebSocket (ws://)
- Example Nginx snippet:

```nginx
server {
  listen 443 ssl http2;
  server_name scanner.example.com;

  # TLS config elided; use your org’s hardened baseline

  location /ws {
    proxy_pass <http://127.0.0.1:8080>; # internal scanner monitor
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto https;
  }
}
```

## Authentication and authorization

- Require JWT by default for WebSocket connections.
  - Set `websocket.require_jwt: true`.
  - Validate issuer/audience; rotate signing keys regularly.
- Use origin and IP allowlists:
  - `websocket.allowed_origins`: UIs allowed to connect
  - `websocket.allowed_ips`: operator networks or jump hosts
- Enforce rate limiting for auth failures:
  - `websocket.auth_rate_limit`: thresholds and backoff window

## Secrets management

- Provide secrets via environment variables or a secrets manager (Azure Key Vault, AWS Secrets Manager, etc.). Avoid committing secrets.
- Minimum environment hardening:
  - Store JWT secrets/keys outside the repo
  - Use per‑environment `.env` files only for local dev; never in CI/CD artifacts
  - Scope access tokens; prefer short lifetimes

## Logging and data handling

- Logging: sensitive fields are redacted by the logger; avoid logging request bodies with secrets.
- Data retention: rotate logs and reports; configure retention per policy.
- Output path safety: outputs are constrained and sanitized to prevent traversal; prefer a dedicated non‑privileged directory.

## Deployment hardening checklist

- [ ] TLS termination configured; only wss exposed publicly
- [ ] JWT required and validated (issuer/audience, key rotation)
- [ ] Origin and IP allowlists enabled
- [ ] Auth rate limiting enforced
- [ ] Secrets from environment or vault; no secrets in code
- [ ] Logs redact sensitive keys; retention configured
- [ ] Output directory is non‑privileged and write‑only for the service user

## Troubleshooting

- 403 on WebSocket connect: check origin/IP allowlists and JWT validity
- Frequent disconnects: tune `ping_interval_ms` and `pong_timeout_ms`
- Dropped alerts: inspect `alerting.max_queue_size` and monitor dropped counters
