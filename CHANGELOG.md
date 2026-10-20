# Changelog

All notable changes to this project are documented here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning: [SemVer](https://semver.org/).

## [0.2.0] - Unreleased

### Renamed to Veil
- Package `@asteby/veil` (was `veilform`, never published), repository `asteby/veil`, command `veil`, MCP server name `veil`, visible name "Veil" on the local pages, CLI and messages. Re-register the server: `claude mcp remove veilform && claude mcp add veil -- node /path/to/dist/cli.js`.
- Environment `VEIL_*` (`VEIL_HOME`, `VEIL_CONFIG`, `VEIL_AGENT`, `VEIL_QUIET`, `VEIL_LANG`, `VEIL_KEY_FILE`, `VEIL_CREDENTIAL`, `VEIL_AGENT_SOCK`, `VEIL_POSTINSTALL`, default `VEIL_PASSPHRASE`); config directory `~/.config/veil`; systemd credential `veil-key`; agent socket `$XDG_RUNTIME_DIR/veil/agent.sock`.
- Encrypted `.env`: new files use `#/veil-env v1` and `veil:1:` (docs/FORMAT-VEIL-SPEC.md §10.2).

### Kept for compatibility (read as before)
- Command `veilform` (bin alias). `VEILFORM_*` variables (deprecated aliases; one warning per name, never the value). `~/.config/veilform` while `~/.config/veil` does not exist (`veil doctor` suggests the `mv`). systemd credential `veilform-key`.
- Persisted formats, unchanged on purpose: `encrypted-file` check `veilform:v1`; default keychain service `veilform` (reads also try the service `veil`, and a destination configured with `veil` also finds secrets stored under `veilform`; writes go to the configured service; deletes clear both); crypto domain labels `veilform-env/v1/…`, `veilform-bundle…`, `veilform-share…`, `veilform/kek/v1`, `veilform/key-id/v1`; tokens `vfs1://` and key files `vfk1:`; encrypted `.env` `#/veilform-env v1` + `enc:v1:` (editing keeps a file's spelling for minimal diffs, `env rotate` upgrades it).
- Remote defaults already deployed: systemd `EnvironmentFile` `/etc/veilform/<unit>.env` and drop-in `50-veilform.conf`; sync defaults git `path: "veilform"` and S3 `prefix: "veilform/"`. New SSH keys are labelled `veil:<alias>` (existing keys are not touched).
- Format fixtures written by the pre-rename code live in `test/fixtures/veilform-0.2` and are decrypted by `test/compat.test.ts`.


### Added
- Encrypted vault backup/sync: `vault_export`, `vault_sync`, `vault_import`, `vault_rekey` and `veil export|import|sync|rekey`. Envelope encryption (per-secret AES-256-GCM DEK wrapped by an argon2id/scrypt + optional key-file/keychain KEK), encrypted index (names hidden from storage), anti-rollback `seq`, vector clocks with explicit conflict strategies, KEK rotation without re-encrypting values.
- Sync targets: local folder, SSH, private git repo, S3/R2/MinIO (own SigV4), WebDAV, generic HTTP; single-file `.vfb` layout.
- Share by token: `share_create`, `share_list`, `share_revoke`, `share_import`, `veil share open|list|revoke`. Fresh key per share in the URL fragment, optional passphrase factor, authenticated expiry and max views, burn after read, revocation with rotation hint, attempt limits, local reveal page with copy button and auto-hide.
- Encrypted `.env` files: `env_status`, `env_unlock`, `env_encrypt`, `env_edit`, `env_diff`, `env_rotate` and `veil env encrypt|decrypt|edit|run|diff|rotate|recipients|unlock|share|keygen|hook`, `veil run --env`. Per-value encryption keeping comments/order, whole-file MAC, multiple recipients, unlock by key file / keychain / systemd credential / session agent (`veil agent`, `veil lock`) / passphrase / token; pre-commit hook; example systemd unit.
- `secret_use` accepts `env_file`; `secret_write` accepts `from: {kind: "env-enc", file, keys, as_is}`.
- Local pages: reveal panel (show/copy, auto-hide), token taken from the URL fragment and removed from history, non-terminal "show current values" action.
- Works without installing anything: Veil's own encrypted store (the `encrypted-file` format with `key: {source: "master"}`; argon2id/scrypt master password defined on the local page on first use, unlocked in memory via the session agent or the MCP process, optional `--save-keychain`, password change, attempt limits). Keychain destinations fall back to it (`fallback: ask | auto | never`; default `ask`): the `secret_request` page offers it instead of failing.
- `veil doctor` and MCP tool `doctor` (read-only): Node/argon2id, keychain backend per OS (secret-tool, D-Bus, Secret Service provider and lock state; macOS `security`; Windows plan), default destination, encrypted store, session agent, permissions, ssh/git/gh/psql/Chromium; impact + exact fix command per distribution (apt/dnf/pacman/zypper/apk/brew/winget).
- `veil init [--yes] [--dry-run] [--master]`: doctor + plan + user-level config only (never sudo); `veil unlock [--save-keychain|--forget-keychain|--change-password|--status]`; MCP tool `local_unlock`; optional `postinstall` hint.
- Actionable errors: `keychain_unavailable` (reason `missing_tool`/`no_dbus`/`no_service`), `keychain_locked`, `keychain_unsupported`, `passphrase_required`, `master_password_not_set`, `destination_not_configured`… with `help` and `fix` (text + command, en/es) in MCP responses and on the local page, never values.
- Docs: README with animated hero, real screenshots (light/dark, en/es) and a comparison table, regenerated by `scripts/readme-assets/`; next-generation engineering plan and draft `.veil` format spec in `docs/`.

### Changed
- `destination_not_allowed` is now `destination_not_configured`. The keychain backends no longer crash when `secret-tool` is missing and report locked/unavailable keyrings instead of a generic `sink_failed`.

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
