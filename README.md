# veilform

**Let an AI agent ask for, store and use credentials — without ever seeing them.**

[Español](README.es.md) · [Threat model](THREAT-MODEL.md) · [Security policy](SECURITY.md) · [Changelog](CHANGELOG.md)

`veilform` is an open-source [Model Context Protocol](https://modelcontextprotocol.io) server (stdio, TypeScript). When the agent needs an API key, a password or any sensitive data, it sends **only metadata** (a form schema). A page served on `http://127.0.0.1` opens in your browser; you type the values there; they go straight to a destination you configured (OS keychain, encrypted file, `.env`, remote server over SSH, Vault/Infisical/1Password/OPS, an HTTP API, a Postgres table…). The agent only gets back `{request_id, status, stored:[names]}`.

Later the agent says `${secret:STRIPE_KEY}` and this server resolves it **inside its own process, at the moment of use**, after you approve the exact action on another local page.

```
 agent ──metadata──▶ veilform ──opens──▶ http://127.0.0.1:PORT/p/<one-time token>
   ▲                       │                                  │ you type values
   │  names / status       │◀──────────── values (local) ─────┘
   └───────────────────────┤
                           ├──▶ keychain / encrypted file / .env / ssh / Vault / Infisical / 1Password / OPS
                           ├──▶ secret_use: exec / http with ${secret:x}  (approval page shows the literal action)
                           └──▶ secret_write: .env, JSON/YAML, systemd, GitHub Actions, clipboard
```

## Tools

| Tool | What the model sends | What the model gets |
|---|---|---|
| `secret_request` | title, fields (`secret`/`text`/`select`/`textarea`), destination | `{request_id, status, stored}` |
| `blind_input` | rich schema (sections, number/money/date/select/multiselect/boolean/file, `showIf`, repeaters with CSV/spreadsheet paste) + sink (`store`, `http`, `sql`, `file`, `ops-dataload`, `callback`) | `{status, rows_written, ids, field_errors:[{field, code}]}` |
| `blind_input_preview` | schema (+ sink) | validation result + local mock-up URL |
| `secret_list` / `secret_delete` / `secret_rotate` | name / filters | names + metadata (created, last used, expiry, rotation due, tags, project) |
| `secret_use` | `exec` (argv or approved shell) / `http`, with `${secret:name}` | exit code + **redacted** output |
| `secret_write` | names + target (`env-file` local/SSH, `json`, `yaml`, `systemd`, `github`, `clipboard`), `dry_run` | `{written, target, keys:[{key, action: created/updated}]}` |
| `secret_wait` | id | final structural result |
| `web_capture` / `web_login` | site, steps (`navigate/click/wait/fill/press`), extractor | `{stored:[name]}` or `{failed_step, error_code}` — never page text |
| `ssh_key_provision` / `ssh_exec` | host alias, key alias / command + env with `${secret:x}` | fingerprints, access test / redacted output |

## Install

Requirements: Node ≥ 20.11 — nothing else. The OS keychain is used when it works (Linux: `secret-tool` from `libsecret-tools` + GNOME Keyring/KWallet; macOS: the built-in `security`); when it does not, Veil uses its own encrypted store and needs no extra package (see [First use](#first-use)). Optional: `playwright-core` + Chromium for `web_capture`, `psql` for SQL sinks, `gh` for GitHub secrets, OpenSSH for SSH features. `veilform doctor` tells you exactly what is missing and the command to install it.

```bash
# from a clone (not published to npm yet)
pnpm install && pnpm build

# Claude Code
claude mcp add veilform -- node /path/to/veilform/dist/cli.js
# once published:  claude mcp add veilform -- npx -y veilform
```

## First use

```bash
npx veilform init          # once published as @asteby/veil: npx @asteby/veil init
```

`init` runs the doctor, shows a plan and, after you confirm (`--yes` to skip the question, `--dry-run` to only look), applies **user-level changes only**: it creates `~/.config/veilform` (0700), tightens permissions and writes a `config.json` whose default destination **works without installing anything**:

- OS keychain usable → `local` = keychain with `fallback: "auto"` (if the keychain later breaks, values go to Veil's encrypted store).
- OS keychain missing/locked/unsupported → `local` = Veil's encrypted store (`encrypted-file` with `key: {source: "master"}`, file `~/.config/veilform/local-vault.json`).

It never runs `sudo` and never asks for a secret. Commands that need privileges (e.g. `sudo apt install -y libsecret-tools`) are printed for you to copy. An optional `postinstall` only prints a hint; set `VEILFORM_POSTINSTALL=init` to run `init --dry-run` right after installing.

**Veil's encrypted store** is one file in the existing `encrypted-file` format: AES-256-GCM per value (the name is the AAD), key derived with argon2id (Node ≥ 24.7; scrypt N=2^17 otherwise) from a **master password**:

1. The first time a value has to go there, the local page (127.0.0.1) asks you to **define the master password right there** — never in the chat, MCP arguments or argv. You can also do it ahead of time: `veilform unlock`, `veilform init --master`, or the MCP tool `local_unlock`.
2. Unlocking keeps only the **derived key** in memory: in the session agent (`veilform agent`) when it runs — then every Veil process shares it and `veilform lock` forgets it — or inside the MCP process, for `localVault.unlockMinutes` (default 15).
3. Later, when the keychain works, you can save the derived key there so the store opens without typing the password: `veilform unlock --save-keychain` (`--forget-keychain` undoes it). `veilform unlock --change-password` re-encrypts everything under a new password.
4. No plaintext is ever written to disk; values and the master password are registered in the scrub list before anything else and never reach responses, logs or the audit trail.

> **If you forget the master password the data cannot be recovered** — by design, there is no back door. Keep the password in your password manager or on paper, and back up `local-vault.json` (it is useless without the password). For an off-machine encrypted copy use `veilform export` / `vault_sync`.

When the default destination is the keychain and it fails during a `secret_request`, the page **offers to continue with the encrypted store** (asking for — or creating — the master password on that same page) instead of failing, and shows the exact command to fix the keychain for good. Set `fallback: "never"` on a keychain destination to forbid that.

## Troubleshooting

Run `veilform doctor` (or the read-only MCP tool `doctor`; `--json` for machines). It checks Node/crypto (argon2id), the keychain backend (secret-tool, D-Bus session, Secret Service provider and whether the default keyring is unlocked on Linux; `security` on macOS; on Windows the Credential Manager backend is planned and the encrypted store is used), the default destination, the encrypted store and session agent, permissions of `~/.config/veilform`, and ssh/git/gh/psql/Chromium for the features that use them. Every problem lists its impact and the exact command for your distribution (apt, dnf, pacman, zypper, apk, brew, winget). It runs nothing privileged and asks for nothing secret.

Errors are structured — `{error, code, help:{en,es}, fix:{en,es,command, alternative}}` — in MCP responses, and translated on the local page:

| Code | Meaning | Fix |
|---|---|---|
| `keychain_unavailable` | `secret-tool` not installed (`reason: missing_tool`), no D-Bus session (`no_dbus`, SSH/headless) or no Secret Service (`no_service`) | `sudo apt install -y libsecret-tools` (or dnf/pacman/…), `dbus-run-session -- $SHELL`, `gnome-keyring-daemon --start --components=secrets` — or `veilform init` |
| `keychain_locked` | the keyring is locked / waiting for an unlock prompt | unlock "Login" in Passwords and Keys (`seahorse`); macOS: `security unlock-keychain` |
| `keychain_unsupported` | no keychain backend on this OS yet (Windows) | `veilform init` (encrypted store) |
| `passphrase_required` | the encrypted store is locked | MCP `local_unlock` or `veilform unlock` |
| `master_password_not_set` | the encrypted store has no master password yet | define it on the local page (`veilform unlock`) |
| `destination_not_configured` | the destination is not in `config.json` | `veilform init` or add it |
| `wrong_key` / `too_many_attempts` | wrong master password / temporary lockout after 5 failures | try again later |

Optional environment: `VEILFORM_HOME` (default `~/.config/veilform`), `VEILFORM_CONFIG`, `VEILFORM_AGENT` (label written to the audit log).

Configuration is an **allowlist**: copy [`examples/config.example.json`](examples/config.example.json) to `~/.config/veilform/config.json` and keep only what you need. Without a config file there is one destination, `local` (OS keychain, `fallback: "ask"`: the page offers Veil's encrypted store if the keychain fails). Check it with `veilform check-config` and `veilform doctor`.

Recommended Claude Code hardening (`.claude/settings.json`): deny the agent's own tools access to what this server protects, e.g. `"deny": ["Read(~/.config/veilform/**)", "Bash(secret-tool:*)", "Bash(security:*)", "Read(**/.env)"]`.

## Examples

**Stripe key, then a call:**

> “I need your Stripe secret key.” → `secret_request({title:"Stripe", fields:[{name:"STRIPE_KEY", label:"Secret key", pattern:"sk_(live|test)_[A-Za-z0-9]+"}]})`
> → you paste it in the local page → `{stored:["STRIPE_KEY"]}`
> → `secret_use({action:"http", method:"GET", url:"https://api.stripe.com/v1/balance", headers:{Authorization:"Bearer ${secret:STRIPE_KEY}"}})`
> → approval page shows exactly that request → `{http_status:200, body:"…"}` (the key is redacted if the API echoes it).

**Mercado Pago token to production `.env` over SSH:**

```json
{"name":"MP_ACCESS_TOKEN","target":{"kind":"env-file","host":"prod-vps","path":"/etc/myapp/myapp.env","key":"MP_ACCESS_TOKEN"},"dry_run":true}
```
→ `{changes:[{key:"MP_ACCESS_TOKEN", action:"updated"}]}`; without `dry_run`, after your approval, the server reads the remote file over SSH, changes only that key (comments and other keys kept), uploads it on stdin to a temp file, `chmod 0600`, optional `chown`/backup, and `mv` atomically. The model gets `{written:true, target, keys}`.

**Capture the token from the Mercado Pago panel without the model seeing it:** `web_capture({site:"mercadopago", name:"MP_ACCESS_TOKEN", steps:[{wait:"text=Credenciales de producción", timeout_ms:600000},{click:"text=Mostrar"}], extract:{selector:"[data-testid=access-token]", regex:"(APP_USR-[\\w-]+)"}})` — a Chromium window owned by this server opens; **you** log in (password/2FA never touch the model); you can edit the steps on the approval page; the value goes DOM → store.

**SSH key for a new VPS:** `ssh_key_provision({host:"prod-vps", alias:"deploy_key", password:true})` → the page shows the host-key fingerprint to compare with your provider, asks the one-time root password, installs the public key, tests access. Then `ssh_exec({host:"prod-vps", command:"systemctl restart myapp"})`.

**Batch of USD prices into Postgres:** `blind_input` with a repeater `rows:[sku, price(money USD)]` and sink `{type:"sql", database:"appdb", table:"public.product_prices", mode:"upsert", rows:"rows", columns:{sku:"${sku}", price_usd:"${price}", list:"wholesale"}, dry_run:true}`. You paste the rows from a spreadsheet; values travel as `COPY … FROM STDIN` data into a typed temp table and `INSERT … SELECT` in one transaction; the model gets `{rows_validated: 120}` and then `{rows_written:120, ids:[…]}`.

**Sensitive customer data:** `blind_input` with fields `name, email, rfc (pattern), phone` and an `http` sink to your CRM; the model receives only the created ids.

## Security flow

1. The model calls a tool with metadata only. Destinations, hosts, paths, tables, sites must be in your config.
2. A one-time link `http://127.0.0.1:<port>/p/<256-bit token>` is delivered by **MCP URL elicitation** when the client supports it, otherwise returned for the client/agent to show (and opened with `xdg-open`/`open` if `ui.openBrowser`). The first browser that opens it binds it with an HttpOnly cookie; it expires in 10 min.
3. You fill/approve. CSRF token + Origin/Host checks + strict nonce CSP; nothing third-party; no autocomplete.
4. Values go to the destination from this process (stdin/env, never argv; never logged).
5. Tool results are structural; a last-line scrub removes any handled value and its encodings.
6. Every use is audited (hash-chained JSONL: session, agent, client, action, fingerprint, names). `veilform verify-audit` checks the chain.

Read [THREAT-MODEL.md](THREAT-MODEL.md) for what is **not** protected — notably: an approved command that exfiltrates the value, same-user malware, and **using another browser the model can see** (e.g. a browser extension the agent drives) to open a page that shows a secret.

## Development

```bash
pnpm install
pnpm typecheck && pnpm lint && pnpm test   # vitest: unit, property, simulated APIs, sshd loopback, Postgres (docker) if available
pnpm test:e2e                              # Playwright: form, repeater/CSV, approval, clipboard, preview, single-use link
SHOTS_DIR=/tmp/shots pnpm test:e2e         # also writes screenshots
```

Deviations from the original design brief (documented): the keychain uses the platform CLIs instead of `@napi-rs/keyring` (no native addon); `encrypted-file` uses Node's AES-256-GCM + scrypt instead of age/libsodium; property tests use a small seeded PRNG instead of `fast-check`. All three because the build had to work offline with the cached dependencies, and they keep the runtime dependency list to the MCP SDK and zod.

## License

[MIT](LICENSE)

## Sync y compartir

*(encrypted backup/sync, token sharing and encrypted `.env` files — added in 0.2.0)*

**New MCP tools** (results are names, counts and ids only; passphrases and tokens are typed/shown on the local page):

| Tool | What it does |
|---|---|
| `vault_export` / `vault_sync` / `vault_import` / `vault_rekey` | Encrypted bundle of the vault to a `.vfb` file or a sync target; restore with integrity, anti-rollback and conflict detection; KEK rotation |
| `share_create` / `share_list` / `share_revoke` / `share_import` | Share chosen secrets by token (expiry, max views, optional passphrase); revoke (+ rotate); import into another agent's vault blindly |
| `env_status` / `env_unlock` / `env_encrypt` / `env_edit` / `env_diff` / `env_rotate` | Git-friendly encrypted `.env` files; `secret_use({env_file})` and `secret_write({from:{kind:"env-enc"}})` use them without the model seeing values |

**Bundle** (`manifest.json` + `o/<random id>` per secret, or one `.vfb` file): one random AES-256-GCM data key (DEK) per secret, wrapped by a KEK = HKDF(argon2id/scrypt(passphrase) ‖ optional key file / keychain secret). Names and metadata live only in the encrypted index; the header (format version, bundle id, monotonic `seq`, key parameters, sha256 of each object) is the AAD of the index, so swapped, truncated, edited or older (rollback) bundles are rejected. Each secret carries a vector clock: `vault_sync` never overwrites a concurrent change silently (`strategy`: `report`, `keep-local`, `take-remote`, `keep-both`).

**Targets** (`sync.targets` in the config, allowlist): `dir`, `ssh` (host from `ssh.hosts`), `git` (private repo; `git` spawned by argv, credentials from your ssh-agent/credential helper), `s3` (S3/R2/MinIO, built-in SigV4), `webdav`, `http`. Credentials for targets are references to the local store (`tokenRef`, `accessKeyRef`…), never inline.

```json
"sync": {
  "targets": { "r2": { "type": "s3", "endpoint": "https://<account>.r2.cloudflarestorage.com", "bucket": "vault", "accessKeyRef": "R2_ID", "secretKeyRef": "R2_SECRET" },
               "repo": { "type": "git", "url": "git@github.com:me/vault-backup.git" } },
  "secondFactor": { "type": "key-file", "path": "~/.config/veilform/sync.key" },
  "shareTarget": "r2"
}
```

**Token** = `vfs1://<target>/<share_id>#<key>` — the key is in the URL fragment (never sent to any server). The bundle is encrypted with HKDF(key ‖ argon2id(passphrase)) when `require_passphrase`; expiry and max views are inside the authenticated header. A person opens it with `veilform share open` (local page, token in the fragment or pasted, values hidden again after N s); another agent uses `share_import({token_file})` and then `secret_use`.

**Encrypted `.env`** (`#/veilform-env v1` header, `KEY="enc:v1:…"` per value, comments/order kept, whole-file MAC, N recipients):

```bash
veilform env keygen ~/.config/veilform/keys/myapp.key        # 0600, outside the repo
veilform env encrypt .env.production --key-file ~/.config/veilform/keys/myapp.key   # + passphrase on TTY
veilform env hook install                                     # pre-commit refuses plaintext .env
veilform run --env .env.production -- node server.js           # values only in the child env; output redacted
veilform env unlock .env.production --status                  # which unlock methods work here (no values)
veilform env share .env.production --expires 1h --max-views 1 # token that unlocks ONLY this file
```

Unlock methods: key file (`--key-file`, `VEILFORM_KEY_FILE`, `env.keyFiles`), OS keychain (`env.keychain`), systemd credential (`LoadCredential=veilform-key:…`, see [`examples/systemd/`](examples/systemd/)), session agent (`veilform agent`, `veilform lock`), passphrase (TTY or local page, attempts limited), share token. Limits and comparison with age/sops/1Password/Vault: [THREAT-MODEL.md §8](THREAT-MODEL.md#8-sync-sharing-and-encrypted-env-files).
