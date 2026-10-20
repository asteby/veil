import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { App, Inputs } from './app.js';
import { VaultInputs } from './vaulttools.js';
import type { SafeResult } from './ops.js';
import { fixOf } from './errors.js';
import { log, UserError } from './util.js';
import { VERSION } from './version.js';

export { VERSION };

const SECURITY_NOTE =
  'You will NEVER receive secret values: only names, statuses, counts, ids and fingerprints. Do not ask the person to paste secrets in chat; use these tools instead. Do not try to read the stores, the .env files written by this server, or the veilform directory with other tools.';

/** Flat input for secret_use (a top-level JSON object schema is friendlier to clients than a union). */
const SecretUseInput = z.object({
  action: z.enum(['exec', 'http']),
  names: z.array(z.string()).optional().describe('secrets used (optional; derived from ${secret:...} references)'),
  command: z.array(z.string()).optional().describe('exec: argv, run WITHOUT a shell; ${secret:..} not allowed here'),
  shell: z.string().optional().describe('exec: POSIX sh script; ${secret:name} becomes an env var reference inside the child'),
  env: z.record(z.string(), z.string()).optional().describe('exec: env vars for the child; values may contain ${secret:name}'),
  stdin: z.string().optional().describe('exec: stdin for the child; may contain ${secret:name}'),
  cwd: z.string().optional(),
  timeout_ms: z.number().int().positive().optional(),
  redact_env_files: z.array(z.string()).optional(),
  method: z.string().optional().describe('http: method (default GET)'),
  url: z.string().optional().describe('http: https URL on an allowlisted host'),
  headers: z.record(z.string(), z.string()).optional().describe('http: headers; values may contain ${secret:name}'),
  body: z.string().optional().describe('http: body; may contain ${secret:name}'),
  env_file: z.object({ file: z.string(), keys: z.array(z.string()).optional() }).optional().describe('exec: also inject keys of an encrypted .env (decrypted in memory into the child env only)'),
});

type Handler = (args: unknown) => Promise<SafeResult> | SafeResult;

export function createServer(app: App): McpServer {
  const server = new McpServer({ name: 'veilform', version: VERSION }, { instructions: `veilform: ask people for credentials and other sensitive values through a local page, store them, and use them without seeing them. ${SECURITY_NOTE}` });

  app.elicitor = {
    supportsUrl: () => Boolean((server.server.getClientCapabilities()?.elicitation as { url?: unknown } | undefined)?.url),
    elicitUrl: async (id, url, message) => {
      const r = await server.server.elicitInput({ mode: 'url', message, url, elicitationId: id });
      return r.action;
    },
    complete: async (id) => {
      await server.server.createElicitationCompletionNotifier(id)();
    },
  };
  server.server.oninitialized = () => {
    const v = server.server.getClientVersion();
    app.audit.setClient(v ? `${v.name}/${v.version}` : undefined);
  };

  const wrap = (name: string, fn: Handler) => async (args: unknown) => {
    try {
      const result = await fn(args);
      return { content: [{ type: 'text' as const, text: app.safe(result) }] };
    } catch (e) {
      let message: string;
      if (e instanceof UserError) {
        // structured, value-free: code + what happened + fix (text and exact command), en/es
        return { isError: true, content: [{ type: 'text' as const, text: app.safe({ error: `${e.code}: ${e.message}`, code: e.code, ...fixOf(e) }) }] };
      }
      else if (e instanceof z.ZodError) message = `invalid_args: ${e.issues.map((i) => `${i.path.join('.') || '(root)'}: ${i.code}`).join('; ')}`;
      else {
        message = 'internal error (details withheld to protect values)';
        log.warn(`tool ${name} failed: ${(e as Error)?.name ?? 'Error'}`);
      }
      return { isError: true, content: [{ type: 'text' as const, text: app.safe({ error: message }) }] };
    }
  };

  server.registerTool(
    'secret_request',
    {
      title: 'Ask the person for credentials',
      description: `Opens a LOCAL page (http://127.0.0.1) with the given fields so the person can type API keys, tokens or passwords. Values go straight from the browser to the configured destination (OS keychain, encrypted file, .env, remote store...). Returns {request_id, status, stored:[names]} (plus url when the client cannot open it: show the url to the person, then call secret_wait). Use the stored names later as \${secret:name}. ${SECURITY_NOTE}`,
      inputSchema: Inputs.secret_request,
      annotations: { destructiveHint: false, openWorldHint: false },
    },
    wrap('secret_request', (a) => app.secretRequest(a)),
  );

  server.registerTool(
    'blind_input',
    {
      title: 'Collect any values blindly (forms, tables, CSV)',
      description:
        'Generic blind input: send ONLY a schema (sections, typed fields, validations, showIf conditions, repeaters/tables with CSV import) and a sink (store, http, sql, file, ops-dataload, callback). The person fills the local page; values go directly to the sink. You receive {request_id, status, rows_written, ids, stored, keys, field_errors:[{field, code}]} and never values. Non-store sinks need the person\'s explicit approval on the same page (it shows the template with ${field} placeholders). Use blind_input_preview first to validate a complex schema.',
      inputSchema: Inputs.blind_input,
    },
    wrap('blind_input', (a) => app.blindInput(a)),
  );

  server.registerTool(
    'blind_input_preview',
    {
      title: 'Validate a blind_input schema',
      description: 'Validates a schema (and optional sink) and returns a structural summary plus a local preview URL with a disabled mock-up of the form. No values involved.',
      inputSchema: Inputs.blind_input_preview,
      annotations: { readOnlyHint: true },
    },
    wrap('blind_input_preview', (a) => app.blindInputPreview(a)),
  );

  server.registerTool(
    'secret_list',
    {
      title: 'List stored secrets (names only)',
      description: 'Lists secret names with metadata (destination, created/updated/last used, expiry, rotation due, tags, project) and what this server is allowed to use (destinations, ssh hosts, databases, web sites, write targets). Never values.',
      inputSchema: Inputs.secret_list,
      annotations: { readOnlyHint: true },
    },
    wrap('secret_list', (a) => app.secretList(a)),
  );

  server.registerTool(
    'secret_delete',
    {
      title: 'Delete a stored secret',
      description: 'Deletes a secret by name (optionally only from one destination).',
      inputSchema: Inputs.secret_delete,
      annotations: { destructiveHint: true },
    },
    wrap('secret_delete', (a) => app.secretDelete(a)),
  );

  server.registerTool(
    'secret_rotate',
    {
      title: 'Ask the person for a new value of an existing secret',
      description: 'Re-opens the intake page for an existing secret (same label, destination and metadata). Use when secret_list shows expired or rotation_due.',
      inputSchema: Inputs.secret_rotate,
    },
    wrap('secret_rotate', (a) => app.secretRotate(a)),
  );

  server.registerTool(
    'secret_use',
    {
      title: 'Use secrets without seeing them (exec / http)',
      description:
        'Runs an action with secrets resolved inside this server at the moment of use. exec: argv without shell (secrets via env or stdin), or a shell script where ${secret:name} becomes an env var. http: request to an allowlisted https host with ${secret:name} in url/headers/body. Every NEW action (exact fingerprint) needs the person\'s approval on a local page that shows the literal action; they may choose to remember it. Output is redacted (raw, base64, hex, url-encoded, quoted variants) and size-limited.',
      inputSchema: SecretUseInput,
    },
    wrap('secret_use', (a) => app.secretUse(a)),
  );

  server.registerTool(
    'secret_write',
    {
      title: 'Copy a stored secret to a file or service',
      description:
        'Writes stored values (or, with from:{kind:"env-enc", file, keys}, values of an encrypted .env; with as_is:true the encrypted file itself) to an allowlisted target without exposing them: env-file (local or ssh host; updates only that key, keeps comments, 0600, atomic, optional backup), json/yaml by key path, systemd EnvironmentFile drop-in, GitHub Actions secret (gh, via stdin) or the clipboard (only after the person clicks, auto-cleared). First use of each target needs approval. dry_run tells which keys would be created/updated. Returns {written, target, keys:[{key, action}]}.',
      inputSchema: Inputs.secret_write,
    },
    wrap('secret_write', (a) => app.secretWrite(a)),
  );

  server.registerTool(
    'secret_wait',
    {
      title: 'Wait for the person',
      description: 'Waits (default 120 s) for a pending request/approval and returns its structural result.',
      inputSchema: Inputs.secret_wait,
      annotations: { readOnlyHint: true },
    },
    wrap('secret_wait', (a) => app.secretWait(a)),
  );

  server.registerTool(
    'web_capture',
    {
      title: 'Capture a credential from a web panel (blind)',
      description:
        'Opens a browser window OWNED BY THIS SERVER (not yours) on an allowlisted site. The person logs in there (password/2FA never reach you). Declared steps (navigate/click/wait/wait_for_url/fill/press) run after approval (the person can edit them), then the extractor reads the value from the DOM straight into the store. You get only {stored:[name]} or {failed_step, error_code}; never page text, HTML or screenshots. Prefer this over any browser tool you control when a page shows a secret.',
      inputSchema: Inputs.web_capture,
    },
    wrap('web_capture', (a) => app.webCapture(a)),
  );

  server.registerTool(
    'web_login',
    {
      title: 'Log in to a site with stored credentials (blind)',
      description: 'Fills a login form inside this server\'s own browser using ${secret:name} values (only on allowlisted origins) and saves the session encrypted with a TTL for later web_capture calls.',
      inputSchema: Inputs.web_login,
    },
    wrap('web_login', (a) => app.webLogin(a)),
  );

  server.registerTool(
    'ssh_key_provision',
    {
      title: 'Create and install an SSH key (blind)',
      description:
        'Generates an ed25519 key locally (private key in the secret store + private ssh-agent, or a 0600 file), shows the host key fingerprint to the person for confirmation, optionally asks them for a one-time SSH password on the local page, installs the public key in authorized_keys and tests access. Returns only alias and fingerprints.',
      inputSchema: Inputs.ssh_key_provision,
    },
    wrap('ssh_key_provision', (a) => app.sshKeyProvision(a)),
  );

  server.registerTool(
    'ssh_exec',
    {
      title: 'Run a remote command with stored secrets',
      description: 'Runs a shell command on an allowlisted SSH host (using the provisioned key). env values may contain ${secret:name}; they are delivered through stdin as exports, never argv. Needs approval per exact command; output redacted.',
      inputSchema: Inputs.ssh_exec,
    },
    wrap('ssh_exec', (a) => app.sshExec(a)),
  );

  server.registerTool(
    'doctor',
    {
      title: 'Diagnose what Veil needs on this machine',
      description:
        'Read-only diagnosis: Node/crypto (argon2id), OS keychain backend (secret-tool + D-Bus + Secret Service lock state on Linux, security on macOS, Windows plan), the default destination and Veil\'s encrypted store, session agent, permissions of the veilform directory and optional tools (ssh, git, gh, psql, Chromium). Each problem has impact and the exact fix command for the detected distribution (apt/dnf/pacman/zypper/brew). Runs nothing privileged, needs no secret. Show the fix commands to the person; never run sudo yourself.',
      inputSchema: Inputs.doctor,
      annotations: { readOnlyHint: true, openWorldHint: false },
    },
    wrap('doctor', () => app.doctor()),
  );

  server.registerTool(
    'local_unlock',
    {
      title: "Create or unlock Veil's encrypted store",
      description: `Opens a LOCAL page where the person defines (first use) or types the master password of Veil's own encrypted store (used when the OS keychain is unavailable). The password never passes through you. It stays unlocked in memory for N minutes (session agent when running). Returns {status, unlocked, created, via}. Use it when another tool answers passphrase_required. ${SECURITY_NOTE}`,
      inputSchema: Inputs.local_unlock,
      annotations: { destructiveHint: false, openWorldHint: false },
    },
    wrap('local_unlock', (a) => app.localUnlock(a)),
  );

  const reg = (name: string, title: string, description: string, input: z.ZodObject, fn: Handler, annotations?: Record<string, boolean>) =>
    server.registerTool(name, { title, description: `${description} ${SECURITY_NOTE}`, inputSchema: input, annotations }, wrap(name, fn));
  const T = app.tools;

  reg('vault_export', 'Encrypted backup of the vault to a file', 'Writes a single-file encrypted bundle (.vfb) of every secret (envelope encryption: one data key per secret, wrapped by a key derived from a passphrase the person types on a local page, plus an optional key file / keychain factor). Names are encrypted too. Returns {file, seq, count, names}.', VaultInputs.vault_export, (a) => T.vaultExport(a));
  reg('vault_sync', 'Sync the encrypted vault to a storage target', 'Pulls (when the target is ahead) and pushes the encrypted bundle to an allowlisted target (folder, ssh, private git repo, S3/R2, WebDAV, HTTP). The target only sees opaque blobs. Conflicts are never overwritten silently: choose strategy keep-local / take-remote / keep-both. Returns counts and names.', VaultInputs.vault_sync, (a) => T.vaultSync(a));
  reg('vault_import', 'Restore secrets from an encrypted bundle', 'Imports a bundle from a target or a .vfb file after verifying integrity and anti-rollback (seq). Reports created/updated/unchanged/kept_local/conflicts (names only).', VaultInputs.vault_import, (a) => T.vaultImport(a));
  reg('vault_rekey', 'Rotate the backup key (KEK)', 'The person types the current and the new passphrase on a local page; every data key is re-wrapped, values are not re-encrypted.', VaultInputs.vault_rekey, (a) => T.vaultRekey(a));
  reg('share_create', 'Share secrets by token', 'Opens a local page that shows the person WHICH names will be shared (never values), expiry and max views, and optionally asks for a share passphrase (second factor). On approval an encrypted bundle with a fresh key is uploaded to a sync target; the TOKEN (key in the URL fragment) is shown ONLY on that page. You get {share_id, names, expires_at, max_views}.', VaultInputs.share_create, (a) => T.shareCreate(a));
  reg('share_list', 'List shares created here', 'Share ids, names, expiry, views, revocation (no tokens).', VaultInputs.share_list, (a) => T.shareList(a), { readOnlyHint: true });
  reg('share_revoke', 'Revoke a share', 'Deletes the share bundle from its target. Revoking does not make a reader forget: if it was read, rotate the secrets (rotate:true opens secret_rotate for each).', VaultInputs.share_revoke, (a) => T.shareRevoke(a), { destructiveHint: true });
  reg('share_import', 'Import a shared secret into this vault (blind)', 'For a receiving agent: the token is read from token_file or pasted by the person on a local page (with the passphrase, if any). Values go straight into the local vault; use them later with secret_use / secret_write. Returns stored names only.', VaultInputs.share_import, (a) => T.shareImport(a));
  reg('env_status', 'Status of an encrypted .env', 'Keys (names), recipients, which unlock methods work here, locked/unlocked. No values.', VaultInputs.env_status, (a) => T.envStatus(a), { readOnlyHint: true });
  reg('env_unlock', 'Unlock an encrypted .env for a while', 'The person types the passphrase or pastes a share token on a local page; the data key stays in this server memory for N minutes.', VaultInputs.env_unlock, (a) => T.envUnlock(a));
  reg('env_encrypt', 'Encrypt a plaintext .env', 'Per-value encryption keeping keys, comments and order (git friendly). Recipients: a passphrase typed on the local page and/or key files / keychain. Optional best-effort shredding of the original.', VaultInputs.env_encrypt, (a) => T.envEncrypt(a));
  reg('env_edit', 'Edit an encrypted .env (blind)', 'Opens a local form listing the keys; the person types new values, deletes or adds keys; values are re-encrypted. You get which keys changed.', VaultInputs.env_edit, (a) => T.envEdit(a));
  reg('env_diff', 'Which keys changed in an encrypted .env', 'Compares with another file or a git revision (default git:HEAD). Names only.', VaultInputs.env_diff, (a) => T.envDiff(a), { readOnlyHint: true });
  reg('env_rotate', 'Rotate the data key of an encrypted .env', 'New data key, every value re-encrypted, recipients re-wrapped.', VaultInputs.env_rotate, (a) => T.envRotate(a));

  return server;
}
