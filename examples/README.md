# Examples

This folder contains minimal configuration and sample data to quickly try the CLI.

- `ztis.config.min.json` / `ztis.config.min.yaml` — Minimal config files.
- `test-data/` — Sample inputs used by some tests and for quick manual runs:
  - `business-context.json`
  - `sample-findings.json`
  - `sample-historical-scores.json`

Try it:

- Validate config:
  - node dist/cli.js config --validate -c ./examples/ztis.config.min.json
- Write scan output to YAML:
  - node dist/cli.js network --output yaml --out-file ./examples/test-data/scan.yaml --scan-depth 1
- Fail on severity threshold:
  - node dist/cli.js network --fail-on medium

Notes:

- JSON/YAML outputs are machine-readable; banners are suppressed in these modes.
- Use `--quiet` to reduce non-essential logs, or `--log-file` to route logs to a file.
