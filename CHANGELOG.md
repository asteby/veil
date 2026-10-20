# Changelog

All notable changes to this project are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning: [SemVer](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-10-19

### Added
- MCP stdio server with 13 tools: `secret_request`, `blind_input`, `blind_input_preview`, `secret_list`, `secret_delete`, `secret_rotate`, `secret_use`, `secret_write`, `secret_wait`, `web_capture`, `web_login`, `ssh_key_provision`, `ssh_exec`.
- Local intake/approval pages on `127.0.0.1` (single-use 256-bit token bound by cookie, CSRF, Origin/Host checks, nonce CSP, TTL, es/en, light/dark, accessible labels and errors).
- MCP URL-mode elicitation when the client supports it; otherwise URL returned + `secret_wait`.
- Destinations: OS keychain (secret-tool / macOS security), AES-256-GCM encrypted file, `.env` (local or SSH), one-file-per-secret over SSH, remote `http-api` stores (generic, Vault KV v2, Infisical, 1Password Connect, OPS addon settings).
- Blind input sinks: store, HTTP (per-row), SQL via psql (`COPY FROM STDIN` + `INSERT … SELECT`, dry-run, upsert, table/column allowlist), file, OPS dataload, callback.
- Write targets: `.env` (local/SSH), JSON, YAML (block mappings), systemd `EnvironmentFile` drop-in, GitHub Actions secrets (`gh`, stdin), clipboard with auto-clear.
- Output redactor (raw, base64/base64url at any offset, hex, URL/form encoding, JSON/HTML/shell escaping, truncated tails, PEM lines) and a final scrub of every tool response.
- Approvals by exact fingerprint with optional "remember"; hash-chained JSONL audit (`verify-audit`).
- Metadata per secret: destination, created/updated/last used, use count, expiry, rotation, tags, project.
- Tests: vitest (unit, property, simulated APIs, loopback sshd, disposable Postgres, Playwright-driven web capture, MCP wire) and Playwright E2E for the pages.
