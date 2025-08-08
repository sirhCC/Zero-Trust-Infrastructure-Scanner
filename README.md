# 🛡️ Zero‑Trust Infrastructure Scanner

Enterprise-grade security scanning for networks, identities, supply chains, and compliance.

[![CI](https://img.shields.io/github/actions/workflow/status/sirhCC/Zero-Trust-Infrastructure-Scanner/ci.yml?branch=main&label=CI&logo=github)](https://github.com/sirhCC/Zero-Trust-Infrastructure-Scanner/actions/workflows/ci.yml)
![Node](https://img.shields.io/badge/Node-%3E%3D18-3C873A?logo=node.js)
![TypeScript](https://img.shields.io/badge/TypeScript-5.x-3178C6?logo=typescript)
![License](https://img.shields.io/badge/License-MIT-blue)

## ✨ Features

- 🔍 Network micro‑segmentation analysis
- 👤 Identity permission mining (over‑privilege detection)
- 📦 Supply chain vulnerability scanning (images, deps)
- 📋 Compliance automation (SOC2, PCI, HIPAA, ISO27001)
- 📡 Real‑time monitoring + live web dashboard
- 🧠 Behavioral/ML risk scoring (experimental modules)
- ⚙️ Strong config validation (Joi for defaults + Ajv JSON Schema)
- 🧪 Jest test suite, TypeScript build, and GitHub Actions CI

## 🚀 Quick start

Prereqs: Node.js >= 18

```bash
# Clone & install
git clone https://github.com/sirhCC/Zero-Trust-Infrastructure-Scanner.git
cd Zero-Trust-Infrastructure-Scanner
npm ci

# Build
npm run build

# Show CLI help
node dist/cli.js --help

# Or use package scripts (dev-friendly)
npm run scan:network -- --help
```

Common commands:

```bash
# One‑shot "scan everything" (placeholder implementation)
npm run scan-all

# Targeted scans
npm run scan:network -- --scan-depth 3 --target 10.0.0.0/16
npm run scan:identity -- --provider aws-iam
npm run scan:supply-chain -- --image alpine:3.19
npm run scan:compliance -- --standard soc2

# Global timeout (applies to all subcommands)
node dist/cli.js network --timeout 10000
```

Dashboard + Monitor:

```bash
# Real‑time monitoring (WebSocket)
npm run monitor -- --port 3001 --interval 30 --targets localhost

# Live dashboard (HTML)
npm run dashboard -- --port 3000 --monitor-port 3001
# Visit: http://localhost:3000
```

## ⚙️ Configuration

Config file default: `./ztis.config.json` (YAML also supported). Validation uses:

- Joi (sets sane defaults)
- Ajv + `src/config/ztis.schema.json` (enforces structure)

CLI helpers:

```bash
# Create a default config
node dist/cli.js config --init -c ./ztis.config.json

# Validate current config (Joi + Ajv)
node dist/cli.js config --validate -c ./ztis.config.json

# Show effective config (json|yaml)
node dist/cli.js config --show -c ./ztis.config.json --output yaml
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

Environment overrides (precedence: env > file):

- `ZTIS_SERVER_PORT=4000`
- `ZTIS_SERVER_HOST=0.0.0.0`
- `ZTIS_API_ENABLED=true|false`
- `ZTIS_WEB_ENABLED=true|false`
- `ZTIS_LOGGING_LEVEL=debug|info|warn|error`
- `ZTIS_LOG_RETENTION_DAYS=30`
- `ZTIS_SCANNER_PARALLEL=4`
- `ZTIS_SCANNER_TIMEOUT=60000`
- `ZTIS_SCANNER_RETRIES=2`

Schema file: `src/config/ztis.schema.json`

## 🧰 Development

Scripts:

```bash
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

- Node >= 18 is required.
- Logger is test‑safe (no lingering file handles during Jest runs).
- The CLI exposes a global `--timeout <ms>`; scans respect cancellation.

## 📦 Project structure

- `src/cli.ts` – Commander‑based CLI and subcommands
- `src/core/` – Scan engine, result processing, scanner registry
- `src/scanners/` – Built‑in scanners (network/identity/supply‑chain/compliance)
- `src/monitoring/` – Real‑time monitor and dashboard server
- `src/config/` – Config manager (Joi + Ajv), JSON Schema
- `tests/` – Jest tests and setup

## 🧪 CI

GitHub Actions runs lint, typecheck, build, and tests with coverage artifact upload. The CI config avoids hard coverage thresholds to keep PR feedback fast. You can tighten `jest.config.js` locally.

## 🤝 Contributing

PRs welcome! Suggested flow:

1) Fork and create a feature branch
2) Run: `npm ci; npm run lint; npm run typecheck; npm run build; npm test`
3) Include tests for changes in public behavior
4) Open a PR with a concise summary and screenshots/logs if relevant

## 🔒 Security

If you discover a vulnerability, please open a private issue with clear reproduction steps. Avoid posting sensitive details in public threads.

## 📚 Resources

- Docs: `docs/` folder (advanced notes) and the project Wiki
- Issues: [GitHub Issues](https://github.com/sirhCC/Zero-Trust-Infrastructure-Scanner/issues)
- Discussions: [GitHub Discussions](https://github.com/sirhCC/Zero-Trust-Infrastructure-Scanner/discussions)

---

Made with ❤️ for security and platform teams.
