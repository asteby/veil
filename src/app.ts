import { spawn } from 'node:child_process';
import path from 'node:path';
import { z } from 'zod';
import { actionLiteral, actionPlan, actionSecretRefs, actionWarnings, runExec, runHttp, UseAction } from './actions.js';
import { AuditLog } from './audit.js';
import { loadConfig, resolvePaths, type Config, type Paths } from './config.js';
import { Approvals, Operations, type Operation, type SafeResult } from './ops.js';
import { run as defaultRunner, type Runner } from './proc.js';
import { Redactor, SensitiveRegistry } from './redact.js';
import { flattenStrings, FormSchema, normalizeSchema, secretFieldNames, validateValues, type NormalizedSchema, type FieldDef } from './schema.js';
import { planSink, SinkSchema, type SinkPlan } from './sinks.js';
import { Ssh } from './ssh.js';
import { SshKeys } from './sshkeys.js';
import type { KeychainBackend } from './stores/keychain.js';
import { checkTargetAllowed, describeTarget, TargetSchema, TargetWriter, type Target } from './targets.js';
import { secretRefs, secretRefsDeep } from './templates.js';
import { UiServer, type PageSpec, type SubmitPayload, type SubmitResult } from './ui/server.js';
import { STRINGS, type Lang } from './ui/i18n.js';
import { fingerprint, log, newId, UserError } from './util.js';
import { Vault, type MetaInput } from './vault.js';
import { agentSocketPath } from './crypto/keysource.js';
import { EnvFiles } from './envenc/service.js';
import { Shares } from './share/share.js';
import { VaultSync } from './sync/service.js';
import { VaultTools } from './vaulttools.js';
import { checkWebPlan, Extractor, stepsLiteral, siteOf, WebRunner, WebStep, type WebStepT } from './web.js';

// ------------------------------------------------------------------ tool input schemas

const SecretField = z.object({
  name: z.string().regex(/^[A-Za-z_][A-Za-z0-9_]{0,63}$/),
  label: z.string().min(1).max(200),
  kind: z.enum(['secret', 'text', 'select', 'textarea']).default('secret'),
  required: z.boolean().optional(),
  help: z.string().max(1000).optional(),
  options: z.array(z.union([z.string(), z.object({ value: z.string(), label: z.string() })])).optional(),
  pattern: z.string().max(500).optional(),
});

export const Metadata = z
  .object({
    tags: z.array(z.string().max(50)).max(20).optional(),
    project: z.string().max(100).optional(),
    expires_at: z.string().optional().describe('ISO date-time'),
    expires_in_days: z.number().positive().optional(),
    rotate_after_days: z.number().int().positive().optional(),
  })
  .optional();

export const Inputs = {
  secret_request: z.object({
    title: z.string().min(1).max(200),
    description: z.string().max(2000).optional(),
    fields: z.array(SecretField).min(1).max(50),
    destination: z.union([z.string(), z.array(z.string()).min(1)]).optional(),
    metadata: Metadata,
  }),
  blind_input: z.object({
    title: z.string().min(1).max(200),
    description: z.string().max(4000).optional(),
    schema: FormSchema,
    sink: SinkSchema,
    submit_label: z.string().max(60).optional(),
    metadata: Metadata,
  }),
  blind_input_preview: z.object({ title: z.string().max(200).optional(), schema: FormSchema, sink: SinkSchema.optional() }),
  secret_list: z.object({ project: z.string().optional(), tag: z.string().optional(), destination: z.string().optional() }),
  secret_delete: z.object({ name: z.string(), destination: z.string().optional() }),
  secret_rotate: z.object({ name: z.string(), title: z.string().optional() }),
  secret_use: z.object({ names: z.array(z.string()).optional(), env_file: z.object({ file: z.string(), keys: z.array(z.string()).optional() }).optional() }).and(UseAction),
  secret_write: z.object({
    name: z.string().optional(),
    names: z.array(z.string()).optional(),
    from: z
      .object({ kind: z.literal('env-enc'), file: z.string(), keys: z.array(z.string()).optional(), as_is: z.boolean().optional().describe('deploy the encrypted file unchanged (the key stays separate)') })
      .optional()
      .describe('take the values from an encrypted .env instead of the vault'),
    target: TargetSchema,
    keys: z.record(z.string(), z.string()).optional().describe('secret name → key in the target (default: the target key or the secret name)'),
    dry_run: z.boolean().optional(),
  }),
  secret_wait: z.object({ id: z.string(), timeout_seconds: z.number().int().min(0).max(600).optional() }),
  web_capture: z.object({
    site: z.string(),
    url: z.string().optional(),
    name: z.string().regex(/^[A-Za-z_][A-Za-z0-9_]{0,63}$/),
    destination: z.string().optional(),
    steps: z.array(WebStep).max(50).default([]),
    extract: Extractor,
    metadata: Metadata,
  }),
  web_login: z.object({ site: z.string(), url: z.string().optional(), steps: z.array(WebStep).min(1).max(50), save_session: z.boolean().default(true) }),
  ssh_key_provision: z.object({
    host: z.string().describe('key of ssh.hosts in config'),
    alias: z.string().regex(/^[A-Za-z0-9_-]{1,64}$/),
    storage: z.enum(['store', 'file']).default('store'),
    password: z.boolean().default(false).describe('ask the person for a one-time SSH password to install the key'),
  }),
  ssh_exec: z.object({
    host: z.string(),
    command: z.string().min(1).max(20_000),
    env: z.record(z.string(), z.string()).optional().describe('remote env vars; values may contain ${secret:name}; delivered via stdin, not argv'),
    timeout_ms: z.number().int().positive().optional(),
  }),
};

// ------------------------------------------------------------------ app

export interface Elicitor {
  supportsUrl(): boolean;
  elicitUrl(id: string, url: string, message: string): Promise<'accept' | 'decline' | 'cancel'>;
  complete(id: string): Promise<void>;
}

export interface AppDeps {
  cfg?: Config;
  paths?: Paths;
  runner?: Runner;
  keychainBackend?: KeychainBackend;
  openUrl?: (url: string) => Promise<boolean>;
  webLoader?: () => Promise<unknown>;
  agent?: string;
  /** cheap KDF parameters (tests only) */
  testKdf?: boolean;
  /** clock for sync/share expiry (tests) */
  now?: () => Date;
  /** session agent socket; null disables it */
  agentSocket?: string | null;
}

function defaultOpenUrl(url: string): Promise<boolean> {
  const cmd = process.platform === 'darwin' ? ['open', url] : process.platform === 'win32' ? ['cmd', '/c', 'start', '""', url] : ['xdg-open', url];
  return new Promise((resolve) => {
    try {
      const child = spawn(cmd[0]!, cmd.slice(1), { stdio: 'ignore', detached: true });
      child.on('error', () => resolve(false));
      child.on('spawn', () => {
        child.unref();
        resolve(true);
      });
    } catch {
      resolve(false);
    }
  });
}

export class App {
  readonly cfg: Config;
  readonly paths: Paths;
  readonly runner: Runner;
  readonly sensitive = new SensitiveRegistry();
  readonly ops = new Operations();
  readonly approvals: Approvals;
  readonly ui: UiServer;
  readonly audit: AuditLog;
  readonly vault: Vault;
  readonly ssh: Ssh;
  readonly keys: SshKeys;
  readonly writer: TargetWriter;
  readonly web: WebRunner;
  readonly sync: VaultSync;
  readonly shares: Shares;
  readonly envFiles: EnvFiles;
  readonly tools: VaultTools;
  readonly session = newId('sess');
  elicitor?: Elicitor;
  private readonly openUrl: (url: string) => Promise<boolean>;

  constructor(deps: AppDeps = {}) {
    this.paths = deps.paths ?? resolvePaths();
    this.cfg = deps.cfg ?? loadConfig(this.paths);
    this.runner = deps.runner ?? defaultRunner;
    this.audit = new AuditLog(this.paths.auditFile, { session: this.session, agent: deps.agent ?? process.env.VEILFORM_AGENT });
    this.approvals = new Approvals(this.paths.approvalsFile);
    this.ui = new UiServer({ lang: this.cfg.ui.lang });
    this.ssh = new Ssh(this.cfg, this.runner, path.join(this.paths.home, 'known_hosts'));
    this.vault = new Vault({ cfg: this.cfg, paths: this.paths, runner: this.runner, ssh: this.ssh, sensitive: this.sensitive, keychainBackend: deps.keychainBackend });
    this.keys = new SshKeys(this.cfg, this.vault, this.ssh, this.runner, this.paths.home);
    this.ssh.keys = this.keys;
    this.writer = new TargetWriter(this.cfg, this.ssh, this.runner);
    this.web = new WebRunner(this.cfg, this.vault, deps.webLoader);
    this.openUrl = deps.openUrl ?? defaultOpenUrl;
    this.sync = new VaultSync({ cfg: this.cfg, paths: this.paths, vault: this.vault, ssh: this.ssh, runner: this.runner, keychain: this.vault.keychain, audit: this.audit, now: deps.now, testKdf: deps.testKdf });
    this.shares = new Shares({ home: this.paths.home, target: (id) => this.sync.target(id), now: deps.now, testKdf: deps.testKdf, maxAttempts: this.cfg.env.maxAttempts });
    this.envFiles = new EnvFiles({
      home: this.paths.home,
      keychain: this.vault.keychain,
      keychainEntry: this.cfg.env.keychain,
      keyFiles: this.cfg.env.keyFiles,
      kdf: this.cfg.env.kdf,
      maxAttempts: this.cfg.env.maxAttempts,
      agentSocket: deps.agentSocket === null ? undefined : (deps.agentSocket ?? agentSocketPath(this.paths.home)),
      testKdf: deps.testKdf,
    });
    this.tools = new VaultTools(this);
  }

  async shutdown(): Promise<void> {
    this.vault.clearCache();
    this.sync.lock();
    this.envFiles.lock();
    this.sensitive.clear();
    this.keys.stop();
    await this.ui.stop();
  }

  // ------------------------------------------------------------ response guard

  /** Every tool response passes here: scrubbed against every value this process has handled. */
  safe(result: SafeResult): string {
    const text = JSON.stringify(result, null, 1);
    const scrubbed = this.sensitive.scrub(text);
    if (scrubbed !== text) {
      this.audit.write('response_scrubbed', {});
      log.warn('a protected value was scrubbed from a tool response');
    }
    return scrubbed;
  }

  private opResult(op: Operation): SafeResult {
    return { request_id: op.id, status: op.status, ...(op.result ?? {}) };
  }

  ttl(): number {
    return this.cfg.ui.ttlSeconds * 1000;
  }

  async present(op: Operation, url: string, message: string): Promise<SafeResult> {
    op.url = url;
    if (this.elicitor?.supportsUrl()) {
      let action: string;
      try {
        action = await this.elicitor.elicitUrl(op.id, url, message);
      } catch {
        action = 'error';
      }
      if (action === 'accept') {
        await this.ops.wait(op.id, this.ttl() + 5000);
        if (this.ops.isTerminal(op)) {
          await this.elicitor.complete(op.id).catch(() => undefined);
          return this.opResult(op);
        }
        return { request_id: op.id, status: op.status, next: 'call secret_wait with this request_id' };
      }
      if (action === 'decline' || action === 'cancel') {
        this.ui.close(url);
        this.ops.finish(op.id, 'cancelled');
        this.audit.write('op_cancelled', { op: op.id, via: 'elicitation' });
        return this.opResult(op);
      }
    }
    const opened = this.cfg.ui.openBrowser ? await this.openUrl(url) : false;
    if (this.cfg.ui.blockSeconds > 0) {
      await this.ops.wait(op.id, this.cfg.ui.blockSeconds * 1000);
      if (this.ops.isTerminal(op)) return this.opResult(op);
    }
    return {
      request_id: op.id,
      status: 'awaiting_user',
      url,
      browser_opened: opened,
      next: `${message} Show this local URL to the person (it only works on this computer, once, for ${this.cfg.ui.ttlSeconds}s). Then call secret_wait({id: "${op.id}"}). You will never receive the values.`,
    };
  }

  register(op: Operation, spec: Omit<PageSpec, 'opId' | 'ttlMs' | 'onExpire'>): Promise<{ url: string }> {
    return this.ui.register({
      ...spec,
      opId: op.id,
      ttlMs: this.ttl(),
      onExpire: () => {
        this.ops.finish(op.id, 'expired');
        this.audit.write('op_expired', { op: op.id, kind: op.kind });
      },
    });
  }

  // ------------------------------------------------------------ blind input core

  private metaFrom(m: z.infer<typeof Metadata>): MetaInput {
    if (!m) return {};
    const expiresAt = m.expires_at ?? (m.expires_in_days ? new Date(Date.now() + m.expires_in_days * 86_400_000).toISOString() : undefined);
    if (expiresAt && Number.isNaN(Date.parse(expiresAt))) throw new UserError('metadata.expires_at must be an ISO date', 'invalid_args');
    return { tags: m.tags, project: m.project, expiresAt, rotateAfterDays: m.rotate_after_days };
  }

  private async formOperation(kind: string, args: { title: string; description?: string; schema: NormalizedSchema; sink: SinkPlan; meta: MetaInput; submitLabel?: string }): Promise<SafeResult> {
    const fp = fingerprint(args.sink.plan);
    const needsConfirm = args.sink.requiresApproval && !this.approvals.isApproved(fp);
    const op = this.ops.create(kind);
    const secretNames = new Set(secretFieldNames(args.schema));
    this.audit.write('input_requested', { op: op.id, tool: kind, sink: args.sink.type, sink_fingerprint: fp, fields: args.schema.sections.flatMap((s) => s.fields.map((f) => f.name)) });
    const handle = async (p: SubmitPayload, lang: Lang): Promise<SubmitResult> => {
      const t = STRINGS[lang];
      if (p.action === 'cancel') {
        this.ops.finish(op.id, 'cancelled');
        this.audit.write('op_cancelled', { op: op.id });
        return { ok: false, message: t.cancelled };
      }
      if (p.action !== 'submit') return { ok: false, message: 'invalid' };
      const { values, errors } = validateValues(args.schema, p.values ?? {});
      // Register every handled value BEFORE anything else can echo it.
      for (const s of flattenStrings(values, secretNames, 1)) this.sensitive.add(s.label, s.value);
      for (const s of flattenStrings(values, undefined, 8)) this.sensitive.add(s.label, s.value);
      if (errors.length) return { ok: false, errors };
      if (needsConfirm && !p.confirm) return { ok: false, errors: [{ field: '__confirm', code: 'confirm' }] };
      this.ops.setStatus(op.id, 'running');
      try {
        const res = await args.sink.execute(values, op.id, args.meta);
        if (needsConfirm && p.remember) await this.approvals.remember(fp, `sink:${args.sink.type}`, JSON.stringify(args.sink.plan).slice(0, 300));
        const failed = Boolean(res.field_errors?.length) && !res.rows_written && !res.stored?.length;
        this.ops.finish(op.id, failed ? 'failed' : 'completed', { ...res });
        this.audit.write(failed ? 'input_failed' : 'input_stored', { op: op.id, sink: args.sink.type, sink_fingerprint: fp, stored: res.stored, rows_written: res.rows_written, errors: res.field_errors?.map((e) => e.code) });
        return failed ? { ok: false, message: `${t.err_type} (${res.field_errors!.map((e) => e.code).join(', ')})` } : { ok: true, message: t.saved };
      } catch (e) {
        const code = e instanceof UserError ? e.code : 'sink_failed';
        this.ops.finish(op.id, 'failed', { error: code, message: e instanceof UserError ? this.sensitive.scrub(e.message) : 'destination failed' });
        this.audit.write('input_failed', { op: op.id, sink: args.sink.type, error: code });
        return { ok: false, message: `Error: ${code}` };
      }
    };
    const { url } = await this.register(op, {
      kind: 'form',
      title: args.title,
      description: args.description,
      schema: args.schema,
      destination: { lines: args.sink.lines, needsConfirm, rememberable: needsConfirm },
      submitLabel: args.submitLabel,
      handle,
    });
    return this.present(op, url, `Waiting for the person to fill "${args.title}".`);
  }

  private sinkDeps() {
    return { cfg: this.cfg, vault: this.vault, runner: this.runner, ssh: this.ssh, writer: this.writer };
  }

  async blindInput(raw: unknown): Promise<SafeResult> {
    const a = Inputs.blind_input.parse(raw);
    const schema = normalizeSchema(a.schema);
    const sink = planSink(a.sink, schema, this.sinkDeps());
    return this.formOperation('blind_input', { title: a.title, description: a.description, schema, sink, meta: this.metaFrom(a.metadata), submitLabel: a.submit_label });
  }

  async blindInputPreview(raw: unknown): Promise<SafeResult> {
    const a = Inputs.blind_input_preview.parse(raw);
    let schema: NormalizedSchema;
    try {
      schema = normalizeSchema(a.schema);
    } catch (e) {
      return { valid: false, errors: [(e as Error).message] };
    }
    let sinkInfo: SafeResult | undefined;
    if (a.sink) {
      try {
        const sp = planSink(a.sink, schema, this.sinkDeps());
        sinkInfo = { type: sp.type, requires_approval: sp.requiresApproval && !this.approvals.isApproved(fingerprint(sp.plan)), fingerprint: fingerprint(sp.plan).slice(0, 16) };
      } catch (e) {
        return { valid: false, errors: [(e as Error).message] };
      }
    }
    const op = this.ops.create('preview', 'pv');
    const { url } = await this.register(op, { kind: 'preview', title: a.title ?? 'Preview', schema, handle: async () => ({ ok: false }) });
    const fields = schema.sections.flatMap((s) => s.fields);
    return {
      valid: true,
      sections: schema.sections.length,
      fields: fields.length,
      repeaters: fields.filter((f) => f.kind === 'repeater').map((f) => ({ name: f.name, columns: (f.fields ?? []).map((c) => c.name) })),
      secret_fields: secretFieldNames(schema),
      sink: sinkInfo,
      preview_url: url,
    };
  }

  // ------------------------------------------------------------ secrets

  async secretRequest(raw: unknown): Promise<SafeResult> {
    const a = Inputs.secret_request.parse(raw);
    const schema = normalizeSchema({ fields: a.fields.map((f) => ({ ...f, required: f.required ?? true })) as FieldDef[] });
    const sink = planSink({ type: 'store', destination: a.destination }, schema, this.sinkDeps());
    const r = await this.formOperation('secret_request', { title: a.title, description: a.description, schema, sink, meta: this.metaFrom(a.metadata) });
    return { request_id: r.request_id, status: r.status, stored: r.stored ?? [], ...(r.url ? { url: r.url, browser_opened: r.browser_opened, next: r.next } : {}), ...(r.error ? { error: r.error } : {}) };
  }

  secretList(raw: unknown): SafeResult {
    const a = Inputs.secret_list.parse(raw ?? {});
    return {
      secrets: this.vault.list(a).map((m) => ({
        name: m.name,
        destination: m.destination,
        created_at: m.createdAt,
        updated_at: m.updatedAt,
        last_used_at: m.lastUsedAt,
        use_count: m.useCount,
        expires_at: m.expiresAt,
        expired: m.expired,
        rotation_due: m.rotationDue,
        tags: m.tags,
        project: m.project,
        source: m.source,
      })),
      available: {
        destinations: [...this.vault.stores.values()].map((s) => ({ id: s.id, type: s.type, readable: s.readable })),
        default_destination: this.cfg.defaultDestination,
        ssh_hosts: Object.keys(this.cfg.ssh.hosts),
        databases: Object.fromEntries(Object.entries(this.cfg.databases).map(([k, v]) => [k, Object.keys(v.tables)])),
        web_sites: Object.keys(this.cfg.web.sites),
        write_targets: this.cfg.writeTargets,
        http_hosts: this.cfg.http.allowedHosts,
        ssh_keys: Object.values(this.keys.records()).map((r) => ({ alias: r.alias, host: r.host, fingerprint: r.fingerprint })),
      },
    };
  }

  async secretDelete(raw: unknown): Promise<SafeResult> {
    const a = Inputs.secret_delete.parse(raw);
    const r = await this.vault.delete(a.name, a.destination);
    this.audit.write('secret_deleted', { name: a.name, destinations: r.deleted });
    return { name: a.name, deleted_from: r.deleted, status: r.deleted.length ? 'deleted' : 'not_found' };
  }

  async secretRotate(raw: unknown): Promise<SafeResult> {
    const a = Inputs.secret_rotate.parse(raw);
    const m = this.vault.meta(a.name);
    if (!m) throw new UserError(`secret "${a.name}" not found`, 'not_found');
    const kind = (['secret', 'text', 'select', 'textarea'] as const).find((k) => k === m.field?.kind) ?? 'secret';
    if (!/^[A-Za-z_][A-Za-z0-9_]{0,63}$/.test(m.name)) throw new UserError('this secret was not created by a form and cannot be rotated here', 'unsupported');
    this.audit.write('rotation_requested', { name: m.name, destination: m.destination });
    return this.secretRequest({
      title: a.title ?? `Rotate ${m.name}`,
      description: `New value for ${m.name}. The previous value will be replaced in ${m.destination}.`,
      fields: [{ name: m.name, label: m.field?.label ?? m.name, kind, help: m.field?.help, pattern: m.field?.pattern, required: true }],
      destination: m.destination,
      metadata: { tags: m.tags, project: m.project, rotate_after_days: m.rotateAfterDays },
    });
  }

  /** True while config.autoMode is on, not past `until`, and lists this operation kind. */
  private autoModeCovers(kind: string): boolean {
    const m = this.cfg.autoMode;
    if (!m.enabled || !(m.kinds as string[]).includes(kind)) return false;
    return !m.until || Date.parse(m.until) > Date.now();
  }

  /** Runs `fn` after approval (or immediately if auto mode covers it or this exact fingerprint was remembered). */
  private async withApproval(
    kind: string,
    plan: Record<string, unknown>,
    page: { title: string; items: { label: string; value: string }[]; literal: string; warnings: string[]; rememberable: boolean; editable?: { label: string; value: string } },
    fn: (edited?: string) => Promise<SafeResult>,
    opts: { clipboard?: { seconds: number; value: () => Promise<string>; result: SafeResult } } = {},
  ): Promise<SafeResult> {
    const fp = fingerprint(plan);
    const auto = page.rememberable && !opts.clipboard && this.autoModeCovers(kind);
    if (page.rememberable && !opts.clipboard && (auto || this.approvals.isApproved(fp))) {
      this.audit.write('use_approved', { kind, fingerprint: fp, via: auto ? 'auto' : 'remembered' });
      const op = this.ops.create(kind, 'use');
      try {
        const res = await fn();
        this.ops.finish(op.id, 'completed', res);
      } catch (e) {
        this.ops.finish(op.id, 'failed', this.errorResult(e));
      }
      return { ...this.opResult(op), fingerprint: fp.slice(0, 16), approval: auto ? 'auto' : 'remembered' };
    }
    const op = this.ops.create(kind, 'use');
    this.audit.write('approval_requested', { op: op.id, kind, fingerprint: fp });
    const { url } = await this.register(op, {
      kind: opts.clipboard ? 'clipboard' : 'approval',
      title: page.title,
      approval: { items: [...page.items, { label: 'fingerprint', value: fp.slice(0, 16) }], literal: page.literal, warnings: page.warnings, rememberable: page.rememberable && !opts.clipboard, editable: page.editable },
      clipboardSeconds: opts.clipboard?.seconds,
      handle: async (p, lang) => {
        const t = STRINGS[lang];
        if (p.action === 'deny' || p.action === 'cancel') {
          this.ops.finish(op.id, 'denied');
          this.audit.write('approval_denied', { op: op.id, kind, fingerprint: fp });
          return { ok: false, message: t.denied };
        }
        if (p.action !== 'approve') return { ok: false };
        if (page.editable && p.edited !== undefined && p.edited !== page.editable.value) {
          // the person adjusted the plan: validate it now so errors stay on the page
          try {
            JSON.parse(p.edited);
          } catch {
            return { ok: false, errors: [{ field: '__edit', code: 'type' }] };
          }
        }
        if (p.remember && page.rememberable && !opts.clipboard && (!page.editable || p.edited === undefined || p.edited === page.editable.value)) await this.approvals.remember(fp, kind, page.literal.slice(0, 300));
        this.audit.write('approval_granted', { op: op.id, kind, fingerprint: fp, remembered: Boolean(p.remember), edited: Boolean(page.editable && p.edited !== page.editable.value) });
        if (opts.clipboard) {
          const value = await opts.clipboard.value();
          this.ops.finish(op.id, 'completed', opts.clipboard.result);
          return { ok: true, clipboard: { value, clearAfter: opts.clipboard.seconds } };
        }
        this.ops.setStatus(op.id, 'running');
        void fn(page.editable ? p.edited : undefined).then(
          (res) => this.ops.finish(op.id, 'completed', res),
          (e) => this.ops.finish(op.id, 'failed', this.errorResult(e)),
        );
        return { ok: true, message: t.approved };
      },
    });
    const r = await this.present(op, url, `Waiting for the person to approve: ${page.title}.`);
    return { ...r, fingerprint: fp.slice(0, 16) };
  }

  errorResult(e: unknown): SafeResult {
    if (e instanceof UserError) return { error: e.code, message: this.sensitive.scrub(e.message) };
    return { error: 'internal', message: 'internal error (details withheld)' };
  }

  async preflight(refs: string[]): Promise<string[]> {
    const warnings: string[] = [];
    for (const r of refs) {
      const m = this.vault.meta(r);
      if (!m) throw new UserError(`secret "${r}" not found; ask the person with secret_request first`, 'not_found');
      const l = this.vault.list({}).find((x) => x.name === m.name && x.destination === m.destination);
      if (l?.expired) throw new UserError(`secret "${m.name}" has expired; use secret_rotate`, 'expired');
      if (l?.rotationDue) warnings.push(`${m.name} is due for rotation`);
    }
    return warnings;
  }

  async secretUse(raw: unknown): Promise<SafeResult> {
    const a = Inputs.secret_use.parse(raw);
    const { names, env_file, ...rest } = a as typeof a & { names?: string[]; env_file?: { file: string; keys?: string[] } };
    const action = UseAction.parse(rest);
    const refs = actionSecretRefs(action);
    if (env_file && action.action !== 'exec') throw new UserError('env_file works with exec actions (variables go to the child environment)', 'invalid_args');
    const envKeys = env_file ? (env_file.keys ?? this.tools.envKeys(env_file.file)) : [];
    if (env_file) for (const k of envKeys) if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(k)) throw new UserError(`key ${k} cannot be an environment variable`, 'invalid_args');
    if (!refs.length && !env_file) throw new UserError('the action does not reference any ${secret:name}', 'invalid_args');
    if (names && names.some((n) => !refs.includes(n))) throw new UserError('names lists secrets that the action does not use', 'invalid_args');
    const warnings = await this.preflight(refs);
    const plan = env_file ? { ...actionPlan(action), env_file: { file: path.resolve(env_file.file), keys: envKeys } } : actionPlan(action);
    const lang = this.cfg.ui.lang === 'es' ? 'es' : 'en';
    return this.withApproval(
      'secret_use',
      plan,
      {
        title: action.action === 'exec' ? 'Run a command with stored secrets' : 'Send an HTTP request with stored secrets',
        items: [
          { label: 'secrets', value: refs.join(', ') || '(none)' },
          ...(env_file ? [{ label: 'encrypted .env (decrypted in memory, child env only)', value: `${path.resolve(env_file.file)}: ${envKeys.join(', ')}` }] : []),
          { label: 'action', value: action.action === 'exec' ? (action.shell ? 'exec (shell)' : 'exec (argv, no shell)') : 'http' },
          ...(action.action === 'exec' && action.cwd ? [{ label: 'cwd', value: action.cwd }] : []),
          { label: 'agent session', value: `${this.session}${process.env.VEILFORM_AGENT ? ` (${process.env.VEILFORM_AGENT})` : ''}` },
        ],
        literal: actionLiteral(action) + (env_file ? `\n+ env from ${path.resolve(env_file.file)}: ${envKeys.join(', ')}` : ''),
        warnings: actionWarnings(action, lang),
        rememberable: true,
      },
      async () => {
        const secrets = new Map<string, string>();
        for (const r of refs) secrets.set(r, (await this.vault.resolve(r)).value);
        let act = action;
        if (env_file && action.action === 'exec') {
          const vals = await this.tools.envValues(env_file.file, envKeys);
          const env = { ...(action.env ?? {}) };
          for (const [k, v] of vals) {
            secrets.set(`envfile:${k}`, v);
            env[k] = `\${secret:envfile:${k}}`;
          }
          act = { ...action, env };
        }
        const fp = fingerprint(plan);
        const res = act.action === 'exec' ? await runExec(act, secrets, this.cfg, this.runner) : await runHttp(act, secrets, this.cfg);
        this.audit.write('secret_used', { action: action.action, secrets: refs, fingerprint: fp, exit_code: (res as { exit_code?: unknown }).exit_code, http_status: (res as { http_status?: unknown }).http_status });
        return { ...res, warnings: warnings.length ? warnings : undefined };
      },
    );
  }

  async secretWrite(raw: unknown): Promise<SafeResult> {
    const a = Inputs.secret_write.parse(raw);
    if (a.from) return this.secretWriteFromEnv(a as typeof a & { from: NonNullable<typeof a.from> });
    const names = a.names ?? (a.name ? [a.name] : []);
    if (!names.length) throw new UserError('name or names is required', 'invalid_args');
    const t: Target = a.target;
    const targetKey = (t as { key?: string }).key;
    if (targetKey && names.length > 1) throw new UserError('target.key only works with a single name; use keys for several', 'invalid_args');
    const keyOf = (n: string) => a.keys?.[n] ?? targetKey ?? this.vault.meta(n)?.name ?? n;
    const keys = names.map(keyOf);
    if ((t.kind === 'json' || t.kind === 'yaml') && !targetKey && !a.keys) throw new UserError(`${t.kind} targets need target.key (path)`, 'invalid_args');
    checkTargetAllowed(this.cfg, t, keys);
    await this.preflight(names);
    const target = describeTarget(t);
    if (a.dry_run) {
      const changes = await this.writer.plan(t, keys);
      return { dry_run: true, target, changes };
    }
    if (t.kind === 'clipboard') {
      if (names.length !== 1) throw new UserError('clipboard takes exactly one name', 'invalid_args');
      return this.withApproval(
        'secret_write',
        { kind: 'clipboard', names },
        { title: `Copy ${names[0]} to the clipboard`, items: [{ label: 'secret', value: names[0]! }], literal: `clipboard ← ${names[0]} (cleared after ${t.clear_after_seconds}s)`, warnings: [], rememberable: false },
        async () => ({}),
        {
          clipboard: {
            seconds: t.clear_after_seconds,
            value: async () => (await this.vault.resolve(names[0]!)).value,
            result: { written: true, target, keys: [{ key: names[0], action: 'copied' }] },
          },
        },
      );
    }
    const plan = { kind: 'secret_write', target: t, names, keys };
    return this.withApproval(
      'secret_write',
      plan,
      {
        title: 'Copy stored values to a file or service',
        items: [...Object.entries(target).filter(([, v]) => v !== undefined).map(([k, v]) => ({ label: k, value: String(v) })), { label: 'keys', value: names.map((n, i) => `${keys[i]} ← ${n}`).join('\n') }],
        literal: `write ${JSON.stringify(target)}\n${names.map((n, i) => `${keys[i]}=<value of ${n}>`).join('\n')}`,
        warnings: [],
        rememberable: true,
      },
      async () => {
        const entries: { key: string; value: string }[] = [];
        for (let i = 0; i < names.length; i++) entries.push({ key: keys[i]!, value: (await this.vault.resolve(names[i]!)).value });
        const changes = await this.writer.write(t, entries);
        this.audit.write('secret_written', { target, keys, names, fingerprint: fingerprint(plan) });
        return { written: true, target, keys: changes };
      },
    );
  }

  /** secret_write with values from an encrypted .env (decrypted in memory) or the encrypted file as is. */
  private async secretWriteFromEnv(a: z.infer<typeof Inputs.secret_write> & { from: { kind: 'env-enc'; file: string; keys?: string[]; as_is?: boolean } }): Promise<SafeResult> {
    const t: Target = a.target;
    const file = path.resolve(a.from.file);
    const keys = a.from.keys ?? this.tools.envKeys(file);
    const outKeys = keys.map((k) => a.keys?.[k] ?? k);
    if (t.kind === 'clipboard' || t.kind === 'github' || t.kind === 'systemd' || t.kind === 'json' || t.kind === 'yaml') {
      if (a.from.as_is) throw new UserError('as_is deploys only to env-file targets', 'invalid_args');
    }
    if (t.kind === 'clipboard') throw new UserError('use the local env_edit page to see values; clipboard is not supported from env files', 'invalid_args');
    checkTargetAllowed(this.cfg, t, outKeys);
    const target = describeTarget(t);
    if (a.dry_run) return { dry_run: true, target, ...(a.from.as_is ? { deploy: 'encrypted file as is', keys } : { changes: await this.writer.plan(t, outKeys) }) };
    const plan = { kind: 'secret_write', from: { file, keys, as_is: Boolean(a.from.as_is) }, target: t, keys: outKeys };
    return this.withApproval(
      'secret_write',
      plan,
      {
        title: a.from.as_is ? 'Deploy an encrypted .env as is' : 'Copy values from an encrypted .env',
        items: [{ label: 'from', value: file }, ...Object.entries(target).filter(([, v]) => v !== undefined).map(([k, v]) => ({ label: k, value: String(v) })), { label: 'keys', value: keys.map((k, i) => `${outKeys[i]} ← ${k}`).join('\n') }],
        literal: a.from.as_is ? `copy ${file} (ciphertext, unchanged) → ${JSON.stringify(target)}\nthe decryption key is NOT copied` : `write ${JSON.stringify(target)}\n${keys.map((k, i) => `${outKeys[i]}=<value of ${k} from ${path.basename(file)}>`).join('\n')}`,
        warnings: [],
        rememberable: true,
      },
      async () => {
        if (a.from.as_is) {
          const r = await this.tools.deployEncrypted(file, t);
          this.audit.write('env_deployed_encrypted', { file, target, keys: r.keys, fingerprint: fingerprint(plan) });
          return { written: true, target, deployed: 'encrypted', bytes: r.bytes, keys: r.keys };
        }
        const vals = await this.tools.envValues(file, keys);
        const changes = await this.writer.write(t, keys.map((k, i) => ({ key: outKeys[i]!, value: vals.get(k)! })));
        this.audit.write('secret_written', { target, keys: outKeys, from: file, fingerprint: fingerprint(plan) });
        return { written: true, target, keys: changes };
      },
    );
  }

  async secretWait(raw: unknown): Promise<SafeResult> {
    const a = Inputs.secret_wait.parse(raw);
    const op = await this.ops.wait(a.id, (a.timeout_seconds ?? 120) * 1000);
    if (!op) throw new UserError(`unknown id ${a.id} (ids live in memory for one hour)`, 'not_found');
    if (!this.ops.isTerminal(op)) return { request_id: op.id, status: op.status, url: op.url, next: 'still waiting for the person; call secret_wait again' };
    if (this.elicitor?.supportsUrl()) await this.elicitor.complete(op.id).catch(() => undefined);
    return this.opResult(op);
  }

  // ------------------------------------------------------------ web

  async webCapture(raw: unknown): Promise<SafeResult> {
    const a = Inputs.web_capture.parse(raw);
    const site = siteOf(this.cfg, a.site);
    const url = a.url ?? site.startUrl ?? site.origins[0]!;
    checkWebPlan(this.cfg, a.site, url, a.steps);
    const destination = a.destination ?? this.cfg.defaultDestination;
    const store = this.vault.store(destination);
    const meta = { ...this.metaFrom(a.metadata), source: `web:${a.site}` };
    const plan = { tool: 'web_capture', site: a.site, url, steps: a.steps, extract: a.extract, name: a.name, destination };
    return this.withApproval(
      'web_capture',
      plan,
      {
        title: `Capture ${a.name} from ${a.site}`,
        items: [
          { label: 'site', value: `${a.site} (${site.origins.join(', ')})` },
          { label: 'stores as', value: `${a.name} → ${store.describe()}` },
          { label: 'browser', value: this.cfg.web.headless ? 'headless' : 'visible window owned by veilform (log in there yourself)' },
        ],
        literal: stepsLiteral(url, a.steps, a.extract),
        warnings: [],
        rememberable: true,
        editable: { label: 'Steps (JSON, editable)', value: JSON.stringify(a.steps, null, 2) },
      },
      async (edited) => {
        const steps = edited ? z.array(WebStep).parse(JSON.parse(edited)) : a.steps;
        const r = await this.web.run(a.site, url, steps, a.extract, { saveSession: true });
        if (r.status !== 'completed' || r.value === undefined) {
          this.audit.write('web_capture_failed', { site: a.site, name: a.name, step: r.failed_step, error: r.error_code });
          return { stored: [], status_detail: 'failed', failed_step: r.failed_step, error_code: r.error_code, steps_completed: r.steps_completed };
        }
        this.sensitive.add(a.name, r.value);
        await this.vault.put(destination, a.name, r.value, meta);
        this.audit.write('web_captured', { site: a.site, name: a.name, destination, fingerprint: fingerprint(plan) });
        return { stored: [a.name], steps_completed: r.steps_completed };
      },
    );
  }

  async webLogin(raw: unknown): Promise<SafeResult> {
    const a = Inputs.web_login.parse(raw);
    const site = siteOf(this.cfg, a.site);
    const url = a.url ?? site.startUrl ?? site.origins[0]!;
    checkWebPlan(this.cfg, a.site, url, a.steps);
    const refs = secretRefsDeep(a.steps);
    await this.preflight(refs);
    const plan = { tool: 'web_login', site: a.site, url, steps: a.steps, save_session: a.save_session };
    return this.withApproval(
      'web_login',
      plan,
      {
        title: `Log in to ${a.site} with stored credentials`,
        items: [
          { label: 'site', value: `${a.site} (${site.origins.join(', ')})` },
          { label: 'secrets', value: refs.join(', ') || '(none)' },
          { label: 'session', value: a.save_session ? `saved encrypted, ${this.cfg.web.sessionTtlHours} h` : 'not saved' },
        ],
        literal: stepsLiteral(url, a.steps),
        warnings: [],
        rememberable: true,
        editable: { label: 'Steps (JSON, editable)', value: JSON.stringify(a.steps, null, 2) },
      },
      async (edited) => {
        const steps: WebStepT[] = edited ? z.array(WebStep).parse(JSON.parse(edited)) : a.steps;
        const r = await this.web.run(a.site, url, steps, undefined, { saveSession: a.save_session });
        this.audit.write(r.status === 'completed' ? 'web_login' : 'web_login_failed', { site: a.site, secrets: refs, step: r.failed_step, error: r.error_code });
        return { logged_in: r.status === 'completed', session_saved: r.status === 'completed' && a.save_session, failed_step: r.failed_step, error_code: r.error_code, steps_completed: r.steps_completed };
      },
    );
  }

  // ------------------------------------------------------------ ssh

  async sshKeyProvision(raw: unknown): Promise<SafeResult> {
    const a = Inputs.ssh_key_provision.parse(raw);
    const target = this.keys.hostTarget(a.host);
    const scan = await this.keys.scanHost(a.host);
    const fields: FieldDef[] = [];
    if (!scan.known) fields.push({ name: 'trust_host', label: 'The host key fingerprint shown below matches my server', kind: 'boolean', required: true });
    if (a.password) fields.push({ name: 'password', label: `One-time SSH password for ${target.user ?? '(default user)'}@${target.hostname}`, kind: 'secret', required: true, help: 'Used once to install the new public key. It is not stored.' });
    fields.push({ name: 'confirm', label: `Create key "${a.alias}" and install it on ${a.host}`, kind: 'boolean', required: true });
    const schema = normalizeSchema({ fields });
    const op = this.ops.create('ssh_key_provision', 'ssh');
    this.audit.write('ssh_provision_requested', { op: op.id, host: a.host, alias: a.alias, host_known: scan.known });
    const { url } = await this.register(op, {
      kind: 'form',
      title: `SSH key for ${a.host}`,
      schema,
      destination: {
        lines: [
          { label: 'host', value: `${target.user ? target.user + '@' : ''}${target.hostname}:${target.port}` },
          { label: 'host key fingerprints', value: scan.fingerprints.join('\n') },
          { label: 'known host', value: scan.known ? 'yes (already in known_hosts)' : 'NO: compare these fingerprints with your provider panel / server console' },
          { label: 'private key storage', value: a.storage === 'store' ? `secret store (${this.vault.internalDestination}), loaded into a private ssh-agent` : 'file 0600 in the veilform directory' },
        ],
        needsConfirm: false,
        rememberable: false,
      },
      submitLabel: 'Create and install key',
      handle: async (p, lang) => {
        const t = STRINGS[lang];
        if (p.action === 'cancel') {
          this.ops.finish(op.id, 'cancelled');
          return { ok: false, message: t.cancelled };
        }
        const { values, errors } = validateValues(schema, p.values ?? {});
        if (typeof values.password === 'string') this.sensitive.add('ssh_password', values.password);
        if (errors.length) return { ok: false, errors };
        this.ops.setStatus(op.id, 'running');
        try {
          if (!scan.known) this.keys.trustHost(scan);
          const rec = await this.keys.generate(a.alias, a.host, a.storage);
          await this.keys.install(a.host, rec, typeof values.password === 'string' ? values.password : undefined);
          const ok = await this.keys.testAccess(a.host, a.alias);
          const result = { alias: a.alias, host: a.host, public_key_fingerprint: rec.fingerprint, host_key_fingerprints: scan.fingerprints.map((f) => f.split(' ')[1]), access_test: ok ? 'ok' : 'failed' };
          this.ops.finish(op.id, ok ? 'completed' : 'failed', result);
          this.audit.write('ssh_key_provisioned', { op: op.id, host: a.host, alias: a.alias, fingerprint: rec.fingerprint, access_test: ok });
          return ok ? { ok: true, message: t.done } : { ok: false, message: 'access test failed' };
        } catch (e) {
          this.ops.finish(op.id, 'failed', this.errorResult(e));
          this.audit.write('ssh_provision_failed', { op: op.id, host: a.host, error: e instanceof UserError ? e.code : 'internal' });
          return { ok: false, message: `Error: ${e instanceof UserError ? e.code : 'internal'}` };
        }
      },
    });
    return this.present(op, url, `Waiting for the person to confirm the SSH key for ${a.host}.`);
  }

  async sshExec(raw: unknown): Promise<SafeResult> {
    const a = Inputs.ssh_exec.parse(raw);
    this.ssh.hostConfig(a.host);
    if (secretRefs(a.command).length) throw new UserError('put ${secret:..} in env, not in the command text', 'secret_in_argv');
    const refs = secretRefs(...Object.values(a.env ?? {}));
    await this.preflight(refs);
    for (const k of Object.keys(a.env ?? {})) if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(k)) throw new UserError(`invalid env name ${k}`, 'invalid_args');
    const plan = { tool: 'ssh_exec', host: a.host, command: a.command, env: a.env };
    return this.withApproval(
      'ssh_exec',
      plan,
      {
        title: `Run a command on ${a.host}`,
        items: [{ label: 'host', value: a.host }, { label: 'secrets', value: refs.join(', ') || '(none)' }],
        literal: [...Object.entries(a.env ?? {}).map(([k, v]) => `export ${k}=${v}`), a.command].join('\n'),
        warnings: [],
        rememberable: true,
      },
      async () => {
        const secrets = new Map<string, string>();
        for (const r of refs) secrets.set(r, (await this.vault.resolve(r)).value);
        const exports = Object.entries(a.env ?? {})
          .map(([k, v]) => `export ${k}='${v.replace(/\$\{secret:([^}]+)\}/g, (_m, r: string) => secrets.get(r) ?? '').replace(/'/g, `'\\''`)}'`)
          .join('\n');
        const res = await this.ssh.script(a.host, 'exec sh -s', [], { stdin: `${exports}\n${a.command}\n`, timeoutMs: Math.min(a.timeout_ms ?? this.cfg.exec.defaultTimeoutMs, this.cfg.exec.maxTimeoutMs), maxOutputBytes: this.cfg.exec.maxOutputBytes });
        const red = new Redactor([...secrets].map(([label, value]) => ({ label, value })));
        this.audit.write('ssh_exec', { host: a.host, secrets: refs, fingerprint: fingerprint(plan), exit_code: res.code });
        return {
          exit_code: res.code,
          timed_out: res.timedOut,
          stdout: red.redact(res.stdout.toString('utf8'), { truncated: res.stdoutTruncated }),
          stderr: red.redact(res.stderr.toString('utf8'), { truncated: res.stderrTruncated }),
          stdout_truncated: res.stdoutTruncated,
          stderr_truncated: res.stderrTruncated,
        };
      },
    );
  }
}
