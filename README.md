# 🛡️ Zero‑Trust Infrastructure Scanner

Enterprise‑grade security scanning for networks, identities, supply chains, and compliance — with a live dashboard and behavioral analytics.

[![CI](https://img.shields.io/github/actions/workflow/status/sirhCC/Zero-Trust-Infrastructure-Scanner/ci.yml?branch=main&label=CI&logo=github)](https://github.com/sirhCC/Zero-Trust-Infrastructure-Scanner/actions/workflows/ci.yml)
![Node](https://img.shields.io/badge/Node-%3E%3D18-3C873A?logo=node.js)
![TypeScript](https://img.shields.io/badge/TypeScript-5.x-3178C6?logo=typescript)
![Tests](https://img.shields.io/badge/tests-100%25%20pass-brightgreen)
![License](https://img.shields.io/badge/License-MIT-blue)

— secure by default, fast to try, fun to extend.

## 📚 Table of contents

- Features
- Architecture
- Quickstart (Windows PowerShell)
- Usage and common tasks
- Configuration
- Real‑time dashboard
- Security hardening
- Output path safety
- Development
- CI & Releases
- Contributing
- Resources

## ✨ Features

- 🔍 Network micro‑segmentation analysis
- 👤 Identity permission mining (over‑privilege detection)
- 📦 Supply chain vulnerability scanning (images, deps)
- 📋 Compliance automation (SOC2, PCI, HIPAA, ISO27001)
- 📡 Real‑time monitoring + live web dashboard
- 🧠 Behavioral/ML risk scoring (experimental modules)
- ⚙️ Strong config validation (Joi defaults + Ajv schema)
- 🧪 Jest test suite and typed API (TypeScript)

## 🧭 Architecture

```mermaid
flowchart LR
	CLI[CLI / Commands] --> Core[Core Scanner Engine]
	Core --> Scanners{{Network | Identity | Supply-Chain | Compliance}}
	Core --> Processor[Result Processor]
	Core -->|events| Monitor[Real-Time Monitor]
	Monitor -->|ws| Dashboard[Web Dashboard]
	Config[(JTIS Config\nJoi + Ajv)] --> Core
	Logger[(Winston\nredaction)] --> Core
	Behavior[Behavioral Analytics\nML scoring] --> Core
```

## 🚀 Quickstart (Windows PowerShell)

Prereqs: Node.js >= 18

```powershell
# Clone & install
git clone https://github.com/sirhCC/Zero-Trust-Infrastructure-Scanner.git
cd Zero-Trust-Infrastructure-Scanner
npm ci

# Build
npm run build

# CLI help
node dist/cli.js --help

# Or dev-friendly scripts
npm run scan:network -- --help
```

Binary builds (no Node required):

```powershell
# Windows only
npm run build:bin:win

# Cross-platform binaries
npm run build:bin
```

Notes:

- Binaries bundle built-in scanners and the config schema.
- Use Node builds to add custom scanners.

## 🛠️ Usage and common tasks

```powershell
# One-shot scan (demo)
npm run scan-all

# Targeted scans
npm run scan:network -- --scan-depth 3 --target 10.0.0.0/16
npm run scan:identity -- --provider aws-iam
npm run scan:supply-chain -- --image alpine:3.19
npm run scan:compliance -- --standard soc2

# Global timeout (all subcommands)
node dist/cli.js network --timeout 10000
```

## ⚙️ Configuration

Default file: `./ztis.config.json` (YAML supported). Validation:

- Joi applies sane defaults
- Ajv enforces structure via `src/config/ztis.schema.json`

CLI helpers:

```powershell
# Create a default config
node dist/cli.js config --init -c .\ztis.config.json

# Validate (Joi + Ajv)
node dist/cli.js config --validate -c .\ztis.config.json

# Show effective config (json|yaml)
node dist/cli.js config --show -c .\ztis.config.json --output yaml
```

Minimal JSON example:

```json
{
  "scanner": { "parallelScans": 3, "scanTimeout": 300000, "retryAttempts": 3 },
  "network": { "defaultScanDepth": 3 },
  "identity": { "providers": [] },
  "supplyChain": { "packageManagers": ["npm"], "severityThreshold": "medium" },
  "compliance": { "standards": [] },
  "logging": { "level": "info", "outputs": ["console", "file"], "retentionDays": 30 },
  "server": { "port": 3000, "host": "localhost", "apiEnabled": true, "webInterfaceEnabled": true },
  "security": { "encryption": { "algorithm": "aes-256-gcm", "keyLength": 256 } }
}
```

Samples in `examples/`:

- `examples/ztis.config.min.json`
- `examples/ztis.config.min.yaml`
- `test-data/` (sample findings and context)

## 📡 Real‑time dashboard

```powershell
# Start monitor (WebSocket)
npm run monitor -- --port 3001 --interval 30 --targets localhost

# Start dashboard (HTML)
npm run dashboard -- --port 3000 --monitor-port 3001
# Visit: http://localhost:3000
```

Status API: `http://localhost:3002/api/status` (port = monitorPort + 1)

## 🔐 Security hardening

Transport:

## 🗂️ Output path safety

By default, file outputs are constrained to safe directories. The CLI and core exporters validate paths and prevent writing outside allowed roots.

- The base output directory is configured via `scanner.outputDirectory` (default: `./reports`).
- `--out-file` paths are resolved under this directory and sanitized to block traversal (e.g., `..\..\` on Windows).

Example (PowerShell):

```powershell
# Configure output directory
Set-Content -Path .\ztis.config.json -Value '{"scanner":{"outputDirectory":".\\reports"}}'

# Write YAML to a file inside the output directory
node dist/cli.js network --output yaml --out-file results\\net.yaml
```

If a provided path resolves outside the configured output directory, the command will fail with a safety error.

- Run behind TLS (wss) via reverse proxy/ingress.
- Restrict access at the network layer to trusted admin IPs.

WebSocket server options (in `monitor` config):

- `authentication`: true|false (enable auth)
- `require_jwt`: default true; JWT required when auth is enabled
- `jwt_secret`, `jwt_issuer`, `jwt_audience`: JWT validation
- `token_header`: custom header name if not using Authorization Bearer
- `allowed_origins`: explicit Origin allowlist
- `allowed_ips`: IP allowlist
- `max_token_length`: default 4096
- `ping_interval_ms`, `pong_timeout_ms`: heartbeat
- `auth_rate_limit`: `{ window_ms, max_attempts, block_duration_ms }`
- `backpressure`: `{ max_buffered_bytes, warn_buffered_bytes, drop_if_exceeds, close_after_drops }`

Tips:

- Prefer short‑lived JWTs over static tokens.
- Don’t log sensitive claims; the logger redacts common secrets.
- Consider an auth proxy (e.g., OAuth2/OIDC) in front of the dashboard.

## 🧰 Development

```powershell
# Typecheck, lint, format
npm run typecheck
npm run lint
npm run format:check

# Build & test
npm run build
npm test

# Coverage (local) / CI
npm run test:coverage
npm run test:coverage:ci
```

Notes:

- Node >= 18
- Logger is test‑safe (no lingering file handles in Jest)
- CLI has a global `--timeout <ms>` respected by scans

## 🧪 CI & Releases

GitHub Actions runs lint, typecheck, build, tests, and uploads coverage artifacts. Coverage thresholds can be tuned in `jest.config.js`.

Releases:

- Tag a version (vX.Y.Z) to build Windows/Linux/macOS binaries via `.github/workflows/release.yml`.

## 🤝 Contributing

PRs welcome. Suggested flow:

1. Fork and create a feature branch
2. `npm ci; npm run lint; npm run typecheck; npm run build; npm test`
3. Include tests for changes in public behavior
4. Open a PR with a concise summary and screenshots/logs

## � Resources

- Advanced docs: `docs/` (see also Wiki)
- Roadmap: `docs/ENHANCEMENT_ROADMAP.md`
- Examples: `examples/`
- Issues: <https://github.com/sirhCC/Zero-Trust-Infrastructure-Scanner/issues>
- Discussions: <https://github.com/sirhCC/Zero-Trust-Infrastructure-Scanner/discussions>

---

Made with ❤️ for security and platform teams.
