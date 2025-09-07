# Developer Experience (DX) Guide

This project is set up for a fast, reliable developer loop.

## Quick commands

- Verify everything fast (lint + types): `npm run verify:fast`
- Full verify (format check + lint + types + tests): `npm run verify`
- Generate API docs: `npm run docs:api` (outputs to `docs/api`)

## Git hooks

- pre-commit: Runs lint-staged (ESLint fix + Prettier) only on staged files.
- pre-push: Runs a fast verification (lint + types).

Hooks are managed by simple-git-hooks and are installed on `postinstall`.

## VS Code

Recommended extensions are in `.vscode/extensions.json`.
Workspace settings ensure consistent TypeScript and LF line endings.

## Notes

- Formatting uses Prettier. Run `npm run format` to rewrite files.
- ESLint catches common issues; fix automatically with `npm run lint:fix`.
- TypeDoc generates current API docs; consider publishing `docs/api` via GitHub Pages.
