import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { App, Inputs } from './app.js';
import type { SafeResult } from './ops.js';
import { log, UserError } from './util.js';

export const VERSION = '0.1.0';

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
      if (e instanceof UserError) message = `${e.code}: ${e.message}`;
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
        'Writes stored values to an allowlisted target without exposing them: env-file (local or ssh host; updates only that key, keeps comments, 0600, atomic, optional backup), json/yaml by key path, systemd EnvironmentFile drop-in, GitHub Actions secret (gh, via stdin) or the clipboard (only after the person clicks, auto-cleared). First use of each target needs approval. dry_run tells which keys would be created/updated. Returns {written, target, keys:[{key, action}]}.',
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

  return server;
}
