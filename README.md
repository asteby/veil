# blindkey

**Let an AI agent ask for, store and use credentials — without ever seeing them.**

[Español](README.es.md) · [Threat model](THREAT-MODEL.md) · [Security policy](SECURITY.md) · [Changelog](CHANGELOG.md)

`blindkey` is an open-source [Model Context Protocol](https://modelcontextprotocol.io) server (stdio, TypeScript). When the agent needs an API key, a password or any sensitive data, it sends **only metadata** (a form schema). A page served on `http://127.0.0.1` opens in your browser; you type the values there; they go straight to a destination you configured (OS keychain, encrypted file, `.env`, remote server over SSH, Vault/Infisical/1Password/OPS, an HTTP API, a Postgres table…). The agent only gets back `{request_id, status, stored:[names]}`.

Later the agent says `${secret:STRIPE_KEY}` and this server resolves it **inside its own process, at the moment of use**, after you approve the exact action on another local page.

```
 agent ──metadata──▶ blindkey ──opens──▶ http://127.0.0.1:PORT/p/<one-time token>
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

Requirements: Node ≥ 20.11. Linux needs `secret-tool` (package `libsecret-tools`) for the keychain destination; macOS uses the built-in `security`. Optional: `playwright-core` + Chromium for `web_capture`, `psql` for SQL sinks, `gh` for GitHub secrets, OpenSSH for SSH features.

```bash
# from a clone (not published to npm yet)
pnpm install && pnpm build

# Claude Code
claude mcp add blindkey -- node /path/to/blindkey/dist/cli.js
# once published:  claude mcp add blindkey -- npx -y blindkey
```

Optional environment: `BLINDKEY_HOME` (default `~/.config/blindkey`), `BLINDKEY_CONFIG`, `BLINDKEY_AGENT` (label written to the audit log).

Configuration is an **allowlist**: copy [`examples/config.example.json`](examples/config.example.json) to `~/.config/blindkey/config.json` and keep only what you need. Without a config file there is one destination, `local` (OS keychain). Check it with `blindkey check-config`.

Recommended Claude Code hardening (`.claude/settings.json`): deny the agent's own tools access to what this server protects, e.g. `"deny": ["Read(~/.config/blindkey/**)", "Bash(secret-tool:*)", "Bash(security:*)", "Read(**/.env)"]`.

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
6. Every use is audited (hash-chained JSONL: session, agent, client, action, fingerprint, names). `blindkey verify-audit` checks the chain.

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
