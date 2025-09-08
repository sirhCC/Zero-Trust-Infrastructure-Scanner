# Zero-Trust Infrastructure Scanner — Project Review and Prioritized Improvements

Date: 2025-09-08

## Executive summary

This is a well-structured TypeScript mono-service with a clean CLI, modular scanners, strong config validation (Joi + Ajv), a pragmatic logger with redaction, and a real-time monitoring subsystem. The project builds cleanly, tests are green, and the developer ergonomics (lint-staged, scripts, typedoc) are solid. The scanners currently simulate work; for production hardening, security controls around the WebSocket monitor, dependency hygiene, and a few refactors will deliver the biggest returns.

## High priority (security and stability)

- Harden WebSocket auth (+ transport security)
  - Require JWT by default when `websocket.authentication` is enabled; treat static tokens as legacy-only and warn at startup. ✅ Implemented (`require_jwt`, default true)
  - Enforce origin checks and recommend TLS (wss) via reverse proxy/ingress; document secure deployment. ✅ Origin allowlist added (`allowed_origins`)
  - Rate-limit connection attempts; add simple lockout/backoff for repeated auth failures; log with IP but avoid PII. ✅ Implemented (`websocket.auth_rate_limit`)
  - Add per-connection message budget/backpressure handling to avoid slow-consumer memory growth; drop or coalesce updates. ✅ Implemented (`websocket.backpressure`)
  - Validate and bound header/query token lengths; reject unusually large tokens. ✅ Max token length (`max_token_length`, default 4096)

- Dependency and toolchain hygiene
  - Address `npm audit` findings; keep Jest/ts-jest compatibility in mind (Jest 30 + ts-jest 29 worked here but watch upstream support).
  - Plan upgrades: ESLint 9 (flat config), migrate deprecated transitive packages via Renovate/Dependabot.
  - Pin critical runtime deps to ranges you test (axios, ws, winston) and avoid unexpected major bumps in production builds.

- Output/file-system safety
  - Sanitize CLI output paths to prevent accidental directory traversal or overwrites outside allowed roots; confirm behavior on Windows paths.
  - Continue CSV injection protection (already implemented); add unit tests for edge cases (leading tabs/Unicode control chars).

- Operational robustness in monitor
  - Implement heartbeat ping with disconnect on missed pongs; expose configurable timeouts. ✅ Added `ping_interval_ms` and `pong_timeout_ms`
  - Guard against unbounded `alertQueue` growth; cap and drop oldest with metrics. ✅ Implemented (`alerting.max_queue_size` + dropped counter)
  - Add origin/IP allowlist (configurable) for admin/operator UIs. ✅ `allowed_ips` added (enforced)

- Security posture docs
  - Add a short “Secure Deployment Guide” covering TLS termination, secrets handling (env vars), JWT issuer/audience config, and logging redaction guarantees.

## Medium priority (refactoring, quality, performance)

- DRY up scanner implementations
  - Introduce a `BaseScanner` with shared `addFinding`, remediation catalogs, and compliance impact mapping.
  - Centralize remediation and compliance mappings in a small registry to avoid drift across modules.

- Cancellation/timeout propagation
  - Scanners mostly simulate work today; ensure future real integrations accept `AbortSignal` and honor timeouts from `ZeroTrustScanner.scan({ signal, timeoutMs })`.

- Real-time monitor resilience
  - Debounce/coalesce frequent updates (e.g., send status at most every N ms per target).
  - Add metrics (Prometheus) for connections, dropped messages, queue sizes, scan durations.

- Tests to add
  - Logger redaction for broader key set (e.g., variations of secret/token headers); fuzz test nested objects.
  - WebSocket auth: success/failure paths, JWT claim checks (issuer/audience), missing/invalid tokens, connection limit behavior.
  - CSV export: verify formula injection protection for = + - @ and tricky cases (leading tabs, 0x1D, quotes).
  - Path handling tests for CLI `--out-file` on Windows and POSIX.

- Developer experience
  - Adopt ESLint v9 flat config; enable import rules to catch unused/duplicate imports.
  - Consider Biome or Rome for faster formatting/lint on large repos.

## Low priority (features and polish)

- Feature breadth
  - Exporters: add SARIF and JUnit for CI pipelines; NDJSON streaming for large result sets.
  - Rules engine: allow external rules (JSON/OPA/Rego) for compliance and scanner checks; hot-reloadable in dev.
  - API: expose a small REST/HTTP interface around scans/results in addition to WebSocket.

- Packaging and delivery
  - Provide a Dockerfile and sample Kubernetes manifests; document how to run with TLS and JWT.
  - Expand `pkg` assets as more schemas/rules are added.

- Docs
  - Threat model & data classification page; enumerate what’s logged, stored, and recommended retention.
  - Quickstart for the monitor/dashboard, including secure auth examples.

## Observations from local verification

- Build: PASS (npm run build)
- Typecheck: PASS (npm run typecheck)
- Tests: PASS (11/11 suites, 28 tests) with coverage collection enabled in config
- Logger: redaction in place for common keys; consider adding variants like `authorization` bearer token in nested headers (already covered), and `private_key`.
- CSV export: includes formula-injection mitigation.
- Dynamic scanner loading is constrained to known modules, which is good for packaged binaries.

## Targeted recommendations (actionable)

- WebSocket security hardening
  - Add config: `requireJwt: true` when `authentication` is on; log warning if only static token is set. ✅
  - Implement origin check: accept list via `websocket.allowed_origins`. ✅
  - Add optional IP allowlist: `websocket.allowed_ips`. ✅
  - Introduce simple rate limiter on auth failures (per-IP, sliding window). ✅ (`auth_rate_limit`)

- DRY scanners
  - Create `src/scanners/base-scanner.ts` with shared `addFinding`, remediation, compliance impact.
  - Replace duplicated methods in the four scanners; unit-test the base class.

- Tests and CI
  - Add unit tests for logger redaction and CSV export edge cases; add WebSocket auth tests (can run with an ephemeral port in Jest).
  - Ensure GitHub Actions workflows exist and pin Node 18/20 matrix; publish coverage as artifact.

- Dependency management
  - Enable Renovate/Dependabot; configure group rules for minor/patch bumps.
  - Track Jest/ts-jest compatibility; plan the upgrade path to swc/jest with TS preset if needed.

## Nice-to-haves

- Metrics/observability: expose `/metrics` for Prometheus; add winston transport to ship logs (optional).
- Performance: batch findings in monitor messages and compress only above a size threshold; consider zlib window tuning or disabling per-message deflate if CPU-bound.
- tsconfig cleanup: remove unused `experimentalDecorators`/`emitDecoratorMetadata` if not used to slightly speed compilation.

## Security notes checklist

- [x] JWT required when auth enabled; static tokens discouraged
- [x] Origin/IP allowlists configured in production
- [x] TLS termination (wss) documented and tested
- [ ] Rate limiting for WS connects/auth failures
- [x] Output path sanitization and safe defaults (sanitizeOutputPath utility; applied to CLI out-file, exportReport, saveBaseline, and config save)
- [ ] `npm audit` zero known high/critical

## Appendix: Requirements coverage

- Real opinion provided (summary and observations): Done
- High→low prioritized list including security: Done
- Concrete code quality/perf/refactor/feature items: Done
- Delivered as a root markdown file: Done (`PROJECT_REVIEW.md`)

---

If you want, I can tackle a couple of the high-priority items (WS hardening + base scanner refactor) behind feature flags and add tests.
