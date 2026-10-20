/**
 * MCP tools for encrypted sync/backup, token sharing and encrypted .env files.
 * Every result is structural (names, counts, ids, codes). Passphrases, tokens and values are
 * typed/shown ONLY on local pages; tokens passed as arguments are registered as sensitive so
 * that no response can echo them.
 */
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { z } from 'zod';
import type { App } from './app.js';
import { parseDoc, type EnvDoc } from './envenc/format.js';
import { contextOf } from './envenc/service.js';
import { LocalFileIO, SshFileIO } from './fileio.js';
import type { Operation, SafeResult } from './ops.js';
import { normalizeSchema, validateValues, type FieldDef } from './schema.js';
import { parseDuration, parseToken, TOKEN_RE } from './share/share.js';
import type { Strategy } from './sync/service.js';
import { checkTargetAllowed, describeTarget, TargetSchema } from './targets.js';
import type { RevealInfo, SubmitResult } from './ui/server.js';
import { STRINGS } from './ui/i18n.js';
import { expandHome, UserError } from './util.js';

const StrategyS = z.enum(['report', 'keep-local', 'take-remote', 'keep-both']);
const FileS = z.string().min(1).max(1000);

export const VaultInputs = {
  vault_export: z.object({ file: FileS.describe('path of the single-file encrypted bundle to write (.vfb)') }),
  vault_sync: z.object({ target: z.string().describe('sync target id from config (sync.targets)'), strategy: StrategyS.optional().describe('conflict policy when the target has concurrent changes (default report = never overwrite)') }),
  vault_import: z.object({ target: z.string().optional(), file: FileS.optional(), strategy: StrategyS.optional(), destination: z.string().optional(), allow_rollback: z.boolean().optional() }),
  vault_rekey: z.object({ target: z.string().optional(), file: FileS.optional() }),
  share_create: z.object({
    names: z.array(z.string()).min(1).max(50),
    expires_in: z.union([z.string(), z.number()]).default('1h').describe('90s, 15m, 2h, 7d or seconds'),
    max_views: z.number().int().min(1).max(100).default(1),
    require_passphrase: z.boolean().default(false).describe('second factor typed by the person on the local page and sent by another channel'),
    note: z.string().max(500).optional(),
    target: z.string().optional(),
  }),
  share_list: z.object({}),
  share_revoke: z.object({ share_id: z.string(), rotate: z.boolean().default(false).describe('open secret_rotate for each shared name') }),
  share_import: z.object({
    token_file: FileS.optional().describe('file holding the token (read by this server, never returned)'),
    token: z.string().optional().describe('discouraged: you would see the key; prefer token_file or let the person paste it on the local page'),
    destination: z.string().optional(),
    target: z.string().optional().describe('override the target id embedded in the token'),
    on_conflict: z.enum(['rename', 'fail']).default('rename'),
  }),
  env_status: z.object({ file: FileS }),
  env_unlock: z.object({ file: FileS, minutes: z.number().int().min(1).max(480).default(15) }),
  env_encrypt: z.object({
    file: FileS,
    out: FileS.optional(),
    passphrase: z.boolean().default(true).describe('ask the person for a passphrase recipient on the local page'),
    key_files: z.array(FileS).optional().describe('key files to add as recipients (e.g. yours and the server one)'),
    keychain: z.boolean().optional().describe('add the OS keychain key (config env.keychain) as recipient'),
    shred: z.boolean().default(false).describe('overwrite the plaintext original (best effort)'),
  }),
  env_edit: z.object({ file: FileS, title: z.string().max(200).optional() }),
  env_diff: z.object({ file: FileS, against: z.string().optional().describe('another file, or git:<rev> (default git:HEAD)') }),
  env_rotate: z.object({ file: FileS }),
};

const passField = (name: string, label: string, help?: string): FieldDef => ({ name, label, kind: 'secret', required: true, help });

export class VaultTools {
  constructor(private readonly app: App) {}

  private get cfg() {
    return this.app.cfg;
  }

  /**
   * Runs `run` right away when no person input is needed, otherwise on a local page with
   * the given secret fields. Wrong passphrases keep the page open (limited attempts).
   */
  private async personStep(
    kind: string,
    a: { title: string; description?: string; lines: { label: string; value: string }[]; fields: FieldDef[]; confirm?: boolean; submitLabel?: string; fragmentField?: string; check?: (v: Record<string, string>) => { field: string; code: string } | undefined },
    run: (v: Record<string, string>) => Promise<SafeResult & { __reveal?: RevealInfo }>,
  ): Promise<SafeResult> {
    if (!a.fields.length && !a.confirm) {
      const { __reveal: _r, ...res } = await run({});
      return { status: 'completed', ...res };
    }
    const op: Operation = this.app.ops.create(kind, 'vf');
    const schema = normalizeSchema({ fields: a.fields.length ? a.fields : [{ name: '_none', label: '-', kind: 'text', required: false }] });
    if (!a.fields.length) schema.sections[0]!.fields = [];
    let fails = 0;
    this.app.audit.write('person_step_requested', { op: op.id, kind });
    const handle = async (p: { action: string; values?: Record<string, unknown>; confirm?: boolean }, lang: 'en' | 'es'): Promise<SubmitResult> => {
      const t = STRINGS[lang];
      if (p.action === 'cancel') {
        this.app.ops.finish(op.id, 'cancelled');
        return { ok: false, message: t.cancelled };
      }
      if (p.action !== 'submit') return { ok: false, message: 'invalid' };
      const { values, errors } = validateValues(schema, p.values ?? {});
      for (const [k, v] of Object.entries(values)) if (typeof v === 'string') this.app.sensitive.add(k, v, { minLength: 3 });
      if (errors.length) return { ok: false, errors };
      if (a.confirm && !p.confirm) return { ok: false, errors: [{ field: '__confirm', code: 'confirm' }] };
      const v = values as Record<string, string>;
      const bad = a.check?.(v);
      if (bad) return { ok: false, errors: [bad] };
      this.app.ops.setStatus(op.id, 'running');
      try {
        const { __reveal, ...res } = await run(v);
        this.app.ops.finish(op.id, 'completed', res);
        return { ok: true, message: t.done, reveal: __reveal };
      } catch (e) {
        const code = e instanceof UserError ? e.code : 'internal';
        const field = a.fields.find((f) => f.kind === 'secret')?.name;
        const retry = ['wrong_key', 'passphrase_required', 'bad_token', 'weak_passphrase'].includes(code) && field && ++fails < this.cfg.env.maxAttempts;
        if (retry) {
          this.app.ops.setStatus(op.id, 'awaiting_user');
          return { ok: false, errors: [{ field: code === 'bad_token' ? (a.fragmentField ?? field) : field, code: code === 'wrong_key' ? 'wrong' : code === 'weak_passphrase' ? 'weak' : code === 'bad_token' ? 'bad_token' : 'required' }] };
        }
        this.app.ops.finish(op.id, 'failed', this.app.errorResult(e));
        this.app.audit.write(`${kind}_failed`, { op: op.id, error: code });
        const mapped = ['too_many_attempts', 'gone', 'expired', 'consumed'].includes(code) ? (t as Record<string, string>)[`err_${code === 'too_many_attempts' ? 'locked' : code}`] : undefined;
        return { ok: false, message: mapped ?? `Error: ${code}` };
      }
    };
    const { url } = await this.app.register(op, {
      kind: 'form',
      title: a.title,
      description: a.description,
      schema,
      destination: { lines: a.lines, needsConfirm: Boolean(a.confirm), rememberable: false },
      submitLabel: a.submitLabel,
      fragmentField: a.fragmentField,
      handle,
    });
    return this.app.present(op, url, `Waiting for the person on the local page: ${a.title}.`);
  }

  // ------------------------------------------------------------ vault sync

  private passFields(confirm: boolean): FieldDef[] {
    if (!this.cfg.sync.passphrase || this.app.sync.unlocked()) return [];
    const f = [passField('passphrase', 'Vault backup passphrase', confirm ? 'New passphrase (min 10 chars). Losing it means losing the backup.' : undefined)];
    if (confirm) f.push(passField('passphrase2', 'Repeat the passphrase'));
    return f;
  }

  private mismatch = (v: Record<string, string>) => (v.passphrase2 !== undefined && v.passphrase !== v.passphrase2 ? { field: 'passphrase2', code: 'mismatch' } : undefined);

  async vaultExport(raw: unknown): Promise<SafeResult> {
    const a = VaultInputs.vault_export.parse(raw);
    if (!a.file.endsWith('.vfb')) throw new UserError('bundle files must end with .vfb', 'invalid_args');
    const first = !this.app.sync.state().key;
    return this.personStep(
      'vault_export',
      { title: 'Encrypted vault backup', lines: [{ label: 'file', value: a.file }, { label: 'content', value: 'every secret of the included destinations, encrypted (names too)' }], fields: this.passFields(first), check: this.mismatch },
      async (v) => {
        const r = await this.app.sync.exportToFile(a.file, async () => v.passphrase);
        return { file: r.file, seq: r.seq, count: r.count, names: r.names };
      },
    );
  }

  async vaultSync(raw: unknown): Promise<SafeResult> {
    const a = VaultInputs.vault_sync.parse(raw);
    const t = this.app.sync.target(a.target);
    const first = !this.app.sync.state().key;
    return this.personStep(
      'vault_sync',
      { title: 'Sync the encrypted vault', lines: [{ label: 'target', value: t.describe() }, { label: 'the target receives', value: 'opaque encrypted blobs only (no names, no values)' }], fields: this.passFields(first), check: this.mismatch },
      async (v) => {
        try {
          return { ...(await this.app.sync.sync(a.target, async () => v.passphrase, (a.strategy ?? 'report') as Strategy)) };
        } catch (e) {
          const rep = (e as { report?: unknown }).report;
          if (rep) return { error: 'conflict', pulled: rep, next: 'call vault_sync again with strategy keep-local, take-remote or keep-both' };
          throw e;
        }
      },
    );
  }

  async vaultImport(raw: unknown): Promise<SafeResult> {
    const a = VaultInputs.vault_import.parse(raw);
    if (!a.target === !a.file) throw new UserError('give either target or file', 'invalid_args');
    if (a.destination) this.app.vault.store(a.destination);
    const fields = this.cfg.sync.passphrase && !this.app.sync.unlocked() ? [passField('passphrase', 'Passphrase of the vault backup')] : [];
    return this.personStep(
      'vault_import',
      { title: 'Restore the encrypted vault', lines: [{ label: 'from', value: a.target ? this.app.sync.target(a.target).describe() : a.file! }, { label: 'conflicts', value: a.strategy ?? 'report (never overwrite silently)' }], fields },
      async (v) => {
        const ask = async () => v.passphrase;
        const opts = { strategy: a.strategy as Strategy | undefined, destination: a.destination, allowRollback: a.allow_rollback };
        return { ...(a.target ? await this.app.sync.pull(a.target, ask, opts) : await this.app.sync.importFile(a.file!, ask, opts)) };
      },
    );
  }

  async vaultRekey(raw: unknown): Promise<SafeResult> {
    const a = VaultInputs.vault_rekey.parse(raw);
    if (!a.target === !a.file) throw new UserError('give either target or file', 'invalid_args');
    const fields = this.cfg.sync.passphrase ? [passField('passphrase', 'Current backup passphrase'), passField('new_passphrase', 'New backup passphrase', 'min 10 chars'), passField('passphrase2', 'Repeat the new passphrase')] : [];
    return this.personStep(
      'vault_rekey',
      { title: 'Rotate the vault backup key (KEK)', lines: [{ label: 'bundle', value: a.target ? this.app.sync.target(a.target).describe() : a.file! }, { label: 'effect', value: 're-wraps every data key; values are not re-encrypted' }], fields, confirm: !fields.length, check: (v) => (v.new_passphrase !== v.passphrase2 ? { field: 'passphrase2', code: 'mismatch' } : undefined) },
      async (v) => ({ ...(await this.app.sync.rekey({ target: a.target, file: a.file }, async () => v.passphrase, async () => v.new_passphrase)) }),
    );
  }

  // ------------------------------------------------------------ shares

  private shareTarget(t?: string): string {
    const id = t ?? this.cfg.sync.shareTarget ?? Object.keys(this.cfg.sync.targets)[0];
    if (!id) throw new UserError('no sync target configured for shares (config sync.targets / sync.shareTarget)', 'invalid_config');
    this.app.sync.target(id);
    return id;
  }

  async shareCreate(raw: unknown): Promise<SafeResult> {
    const a = VaultInputs.share_create.parse(raw);
    const seconds = parseDuration(a.expires_in);
    if (seconds < 60 || seconds > this.cfg.sync.maxShareSeconds) throw new UserError(`expires_in must be between 60 s and ${this.cfg.sync.maxShareSeconds} s`, 'invalid_args');
    await this.app.preflight(a.names);
    const target = this.shareTarget(a.target);
    const metas = a.names.map((n) => this.app.vault.meta(n)!);
    const fields: FieldDef[] = a.require_passphrase ? [passField('passphrase', 'Share passphrase (send it through ANOTHER channel)', 'min 8 chars; the token alone will not open the share'), passField('passphrase2', 'Repeat the share passphrase')] : [];
    const expiresAt = new Date(Date.now() + seconds * 1000).toISOString();
    return this.personStep(
      'share_create',
      {
        title: `Share ${a.names.length} secret(s) by token`,
        description: a.note,
        lines: [
          { label: 'names (values are never shown to the agent)', value: metas.map((m) => `${m.name} (${m.destination})`).join('\n') },
          { label: 'stored encrypted on', value: this.app.sync.target(target).describe() },
          { label: 'expires', value: `${expiresAt} (in ${seconds} s)` },
          { label: 'max views', value: String(a.max_views) },
          { label: 'second factor', value: a.require_passphrase ? 'passphrase (you type it here)' : 'none: anyone with the token can open it' },
        ],
        fields,
        confirm: true,
        submitLabel: 'Create share and show the token',
        check: this.mismatch,
      },
      async (v) => {
        const items = [];
        for (const m of metas) items.push({ name: m.name, kind: 'secret' as const, value: (await this.app.vault.resolve(`${m.destination}:${m.name}`)).value });
        const { record, token } = await this.app.shares.create({ targetId: target, items, expiresInSeconds: seconds, maxViews: a.max_views, passphrase: v.passphrase, note: a.note });
        this.app.sensitive.add('share_token', token);
        this.app.sensitive.add('share_key', token.split('#')[1]!);
        this.app.audit.write('share_created', { share: record.share_id, names: record.names, target, expires_at: record.expires_at, max_views: record.max_views, passphrase: record.passphrase });
        return {
          share_id: record.share_id,
          names: record.names,
          target,
          expires_at: record.expires_at,
          max_views: record.max_views,
          passphrase_required: record.passphrase,
          next: 'The person copies the token from the local page and sends it (and the passphrase, by another channel) to the recipient. You never receive the token.',
          __reveal: { items: [{ label: 'Token', value: token }], hideAfter: 300, note: 'Send the token by one channel and, if set, the passphrase by another. After the recipient reads it, consider rotating the secret.' },
        };
      },
    );
  }

  async shareList(raw: unknown): Promise<SafeResult> {
    VaultInputs.share_list.parse(raw ?? {});
    const now = Date.now();
    return { shares: this.app.shares.records().map((r) => ({ share_id: r.share_id, names: r.names, target: r.target, created_at: r.created_at, expires_at: r.expires_at, expired: Date.parse(r.expires_at) <= now, max_views: r.max_views, passphrase: r.passphrase, revoked_at: r.revoked_at })) };
  }

  async shareRevoke(raw: unknown): Promise<SafeResult> {
    const a = VaultInputs.share_revoke.parse(raw);
    const r = await this.app.shares.revoke(a.share_id);
    this.app.audit.write('share_revoked', { share: a.share_id, names: r.names, was_read: r.was_read });
    const res: SafeResult = { share_id: a.share_id, revoked: r.revoked, was_read: r.was_read, names: r.names };
    if (r.history_kept) res.warning = 'the target keeps history (git): the encrypted bundle stays in old commits; rotate the secrets if the token may have leaked';
    if (r.was_read !== false) res.recommendation = 'the share may have been read: revoking does not make anyone forget it. Rotate the secret(s) (secret_rotate).';
    if (a.rotate) {
      const rot: SafeResult[] = [];
      for (const n of r.names) rot.push(await this.app.secretRotate({ name: n }));
      res.rotations = rot.map((x) => ({ request_id: x.request_id, status: x.status, url: x.url }));
    }
    return res;
  }

  /** Receiving agent: the token is read from a file or pasted by the person on the local page. */
  async shareImport(raw: unknown): Promise<SafeResult> {
    const a = VaultInputs.share_import.parse(raw);
    let token: string | undefined;
    if (a.token_file) {
      const f = expandHome(a.token_file);
      if (!existsSync(f)) throw new UserError('token file not found', 'not_found');
      token = readFileSync(f, 'utf8').trim();
    } else if (a.token) token = a.token.trim();
    if (token) {
      this.app.sensitive.add('share_token', token);
      if (!TOKEN_RE.test(token)) throw new UserError('not a veil share token', 'bad_token');
      this.app.sensitive.add('share_key', token.split('#')[1]!);
    }
    const destination = a.destination ?? this.cfg.defaultDestination;
    this.app.vault.store(destination);
    let needsPass = false;
    if (token) needsPass = (await this.app.shares.peek(token, a.target)).needsPassphrase;
    const fields: FieldDef[] = [];
    if (!token) fields.push(passField('token', 'Share token (vfs1://...)', 'Paste the token you received. It stays on this computer.'));
    if (!token || needsPass) fields.push({ ...passField('passphrase', 'Share passphrase (if the sender set one)'), required: Boolean(token && needsPass) });
    return this.personStep(
      'share_import',
      { title: 'Import shared secrets into this vault', lines: [{ label: 'destination', value: this.app.vault.store(destination).describe() }, { label: 'note', value: 'the values go straight into the vault; the agent only learns the names' }], fields, fragmentField: !token ? 'token' : undefined },
      async (v) => {
        const tk = token ?? v.token!;
        parseToken(tk);
        this.app.sensitive.add('share_token', tk);
        const r = await this.app.shares.open(tk, { passphrase: v.passphrase || undefined, targetOverride: a.target });
        const stored: string[] = [];
        const renamed: { name: string; as: string }[] = [];
        const envUnlocked: string[] = [];
        for (const it of r.items) {
          this.app.sensitive.add(it.name, it.value);
          if (it.kind === 'env-dek') {
            this.app.envFiles.cacheDekByContext(it.name.replace(/^env:/, ''), Buffer.from(it.value, 'base64url'), this.cfg.sync.unlockMinutes || 15);
            envUnlocked.push(it.name);
            continue;
          }
          let name = it.name;
          if (this.app.vault.meta(`${destination}:${name}`)) {
            if (a.on_conflict === 'fail') throw new UserError(`secret ${name} already exists in ${destination}`, 'conflict');
            name = `${it.name}.shared-${r.shareId.slice(0, 6).replace(/[^A-Za-z0-9_]/g, '_')}`;
            renamed.push({ name: it.name, as: name });
          }
          await this.app.vault.put(destination, name, it.value, { source: `share:${r.shareId}` });
          stored.push(name);
        }
        this.app.audit.write('share_imported', { share: r.shareId, stored, renamed: renamed.map((x) => x.as), env: envUnlocked, views_left: r.viewsLeft, burned: r.burned });
        return { share_id: r.shareId, stored, renamed, env_unlocked: envUnlocked, views_left: r.viewsLeft, burned: r.burned };
      },
    );
  }

  // ------------------------------------------------------------ encrypted .env

  private envFile(file: string): string {
    const abs = path.resolve(expandHome(file));
    if (!this.app.envFiles.allowed(this.cfg.env.files, abs)) throw new UserError(`${file} is not allowed by config env.files`, 'file_not_allowed');
    return abs;
  }

  private async needsPass(doc: EnvDoc): Promise<boolean> {
    try {
      await this.app.envFiles.open(doc, {});
      return false;
    } catch (e) {
      if (doc.recipients.some((r) => r.type === 'pass')) return true;
      throw new UserError('no key available here for this file: configure a key file (env.keyFiles / VEIL_KEY_FILE) or unlock it with a share token (env_unlock)', e instanceof UserError ? e.code : 'wrong_key');
    }
  }

  async envStatus(raw: unknown): Promise<SafeResult> {
    const a = VaultInputs.env_status.parse(raw);
    return { ...(await this.app.envFiles.status(this.envFile(a.file))) };
  }

  async envUnlock(raw: unknown): Promise<SafeResult> {
    const a = VaultInputs.env_unlock.parse(raw);
    const file = this.envFile(a.file);
    const doc = await this.app.envFiles.read(file);
    if (!doc.encrypted) throw new UserError('file is not encrypted', 'not_encrypted');
    const hasPass = doc.recipients.some((r) => r.type === 'pass');
    const fields: FieldDef[] = [
      ...(hasPass ? [{ ...passField('passphrase', `Passphrase for ${doc.context}`), required: false }] : []),
      { ...passField('token', 'or a share token (vfs1://...)', 'A token created with "veil env share"'), required: false },
    ];
    return this.personStep('env_unlock', { title: `Unlock ${doc.context}`, lines: [{ label: 'file', value: file }, { label: 'unlocked for', value: `${a.minutes} min, in this server's memory only` }], fields, fragmentField: 'token' }, async (v) => {
      let dek: Buffer | undefined;
      if (v.token) {
        this.app.sensitive.add('share_token', v.token);
        const r = await this.app.shares.open(v.token);
        const it = r.items.find((x) => x.kind === 'env-dek' && x.name === `env:${doc.context}`);
        if (!it) throw new UserError('this token does not unlock this file', 'wrong_key');
        dek = Buffer.from(it.value, 'base64url');
      }
      const { dek: d, via } = await this.app.envFiles.open(doc, { dek, passphrase: v.passphrase ? async () => v.passphrase : undefined });
      await this.app.envFiles.remember(doc, d, a.minutes);
      this.app.audit.write('env_unlocked', { file, context: doc.context, via: via.startsWith('key:') ? 'key' : via, minutes: a.minutes });
      return { file, unlocked: true, via: v.token ? 'token' : via.startsWith('pass') ? 'passphrase' : via, minutes: a.minutes };
    });
  }

  async envEncrypt(raw: unknown): Promise<SafeResult> {
    const a = VaultInputs.env_encrypt.parse(raw);
    const file = this.envFile(a.file);
    const out = a.out ? this.envFile(a.out) : file;
    const doc = await this.app.envFiles.read(file);
    if (doc.encrypted) throw new UserError('file is already encrypted', 'already_encrypted');
    const fields = a.passphrase ? [passField('passphrase', `Passphrase for ${contextOf(out)}`, 'min 8 chars; also add a key file for servers/CI'), passField('passphrase2', 'Repeat the passphrase')] : [];
    return this.personStep(
      'env_encrypt',
      { title: `Encrypt ${path.basename(file)}`, lines: [{ label: 'file', value: file }, { label: 'output', value: out }, { label: 'keys (names stay visible)', value: doc.lines.filter((l) => l.t === 'kv').map((l) => (l as { key: string }).key).join(', ') }, { label: 'recipients', value: [a.passphrase ? 'passphrase' : '', ...(a.key_files ?? []), a.keychain ? 'OS keychain' : ''].filter(Boolean).join(', ') }, { label: 'plaintext original', value: a.shred ? 'overwritten (best effort)' : 'replaced' }], fields, confirm: !fields.length, check: this.mismatch },
      async (v) => {
        const r = await this.app.envFiles.encrypt(file, { passphrase: v.passphrase, keyFiles: a.key_files, keychain: a.keychain }, { out, shred: a.shred });
        this.app.audit.write('env_encrypted', { file: out, keys: r.keys, recipients: r.recipients, shredded: r.shredded });
        return { ...r };
      },
    );
  }

  async envEdit(raw: unknown): Promise<SafeResult> {
    const a = VaultInputs.env_edit.parse(raw);
    const file = this.envFile(a.file);
    const doc = await this.app.envFiles.read(file);
    const needs = await this.needsPass(doc);
    const keys = doc.lines.filter((l) => l.t === 'kv').map((l) => (l as { key: string }).key);
    const fieldOf = new Map(keys.map((k, i) => [k, `k${i}`]));
    const fields: FieldDef[] = [
      ...(needs ? [passField('passphrase', `Passphrase for ${doc.context}`)] : []),
      ...[...new Set(keys)].map((k): FieldDef => ({ name: fieldOf.get(k)!, label: k, kind: 'secret', required: false, help: 'leave empty to keep the current value' })),
      { name: 'delete', label: 'Delete keys', kind: 'multiselect', required: false, options: [...new Set(keys)] },
      { name: 'add', label: 'New keys', kind: 'repeater', required: false, fields: [{ name: 'key', label: 'Key', kind: 'text', pattern: '[A-Za-z_][A-Za-z0-9_.-]*' }, { name: 'value', label: 'Value', kind: 'secret' }] },
    ];
    const op = this.app.ops.create('env_edit', 'vf');
    const schema = normalizeSchema({ fields });
    let fails = 0;
    const getDek = async (v: Record<string, unknown>) => (await this.app.envFiles.open(await this.app.envFiles.read(file), { passphrase: typeof v.passphrase === 'string' && v.passphrase ? async () => v.passphrase as string : undefined })).dek;
    const { url } = await this.app.register(op, {
      kind: 'form',
      title: a.title ?? `Edit ${doc.context}`,
      description: 'Values you type go straight into the encrypted file. The agent only learns which keys changed.',
      schema,
      destination: { lines: [{ label: 'file', value: file }], needsConfirm: false, rememberable: false },
      revealLabel: needs ? undefined : 'Show current values (only here)',
      submitLabel: 'Encrypt and save',
      handle: async (p, lang) => {
        const t = STRINGS[lang];
        if (p.action === 'cancel') {
          this.app.ops.finish(op.id, 'cancelled');
          return { ok: false, message: t.cancelled };
        }
        if (p.action === 'reveal') {
          try {
            const { entries } = await this.app.envFiles.decrypt(file, { dek: await getDek({}) });
            for (const e of entries) this.app.sensitive.add(e.key, e.value);
            this.app.audit.write('env_values_shown_locally', { op: op.id, file, keys: entries.map((e) => e.key) });
            return { ok: true, reveal: { items: entries.map((e) => ({ label: e.key, value: e.value })), hideAfter: 60 } };
          } catch {
            return { ok: false, message: 'locked' };
          }
        }
        if (p.action !== 'submit') return { ok: false };
        const { values, errors } = validateValues(schema, p.values ?? {});
        for (const [k, v] of Object.entries(values)) if (typeof v === 'string') this.app.sensitive.add(k, v);
        for (const row of (values.add as { value?: string }[] | undefined) ?? []) if (row.value) this.app.sensitive.add('new', row.value);
        if (errors.length) return { ok: false, errors };
        const changes: Record<string, string | null> = {};
        for (const k of new Set(keys)) {
          const v = values[fieldOf.get(k)!];
          if (typeof v === 'string' && v !== '') changes[k] = v;
        }
        for (const k of (values.delete as string[] | undefined) ?? []) changes[k] = null;
        for (const row of (values.add as { key: string; value: string }[] | undefined) ?? []) if (row.key) changes[row.key] = row.value ?? '';
        try {
          const dek = await getDek(values);
          const r = await this.app.envFiles.edit(file, changes, { dek });
          this.app.ops.finish(op.id, 'completed', { file, ...r });
          this.app.audit.write('env_edited', { op: op.id, file, ...r });
          return { ok: true, message: t.saved };
        } catch (e) {
          if (e instanceof UserError && e.code === 'wrong_key' && ++fails < this.cfg.env.maxAttempts) return { ok: false, errors: [{ field: 'passphrase', code: 'wrong' }] };
          this.app.ops.finish(op.id, 'failed', this.app.errorResult(e));
          return { ok: false, message: `Error: ${e instanceof UserError ? e.code : 'internal'}` };
        }
      },
    });
    return this.app.present(op, url, `Waiting for the person to edit ${doc.context}.`);
  }

  async envDiff(raw: unknown): Promise<SafeResult> {
    const a = VaultInputs.env_diff.parse(raw);
    const file = this.envFile(a.file);
    const against = a.against ?? 'git:HEAD';
    let other: { file?: string; text?: string };
    if (against.startsWith('git:')) {
      const rev = against.slice(4);
      if (!/^[A-Za-z0-9_.\/~^-]{1,100}$/.test(rev) || rev.startsWith('-')) throw new UserError('invalid git revision', 'invalid_args');
      const dir = path.dirname(file);
      const top = await this.app.runner(['git', '-C', dir, 'rev-parse', '--show-toplevel']);
      if (top.code !== 0) throw new UserError('not inside a git repository', 'not_git');
      const relp = path.relative(top.stdout.toString().trim(), file);
      const r = await this.app.runner(['git', '-C', dir, 'show', `${rev}:${relp}`]);
      if (r.code !== 0) throw new UserError(`${relp} does not exist at ${rev}`, 'not_found');
      other = { text: r.stdout.toString('utf8'), file };
    } else other = { file: this.envFile(against) };
    const d = await this.app.envFiles.diff(other, { file });
    return { file, against, ...d };
  }

  async envRotate(raw: unknown): Promise<SafeResult> {
    const a = VaultInputs.env_rotate.parse(raw);
    const file = this.envFile(a.file);
    const doc = await this.app.envFiles.read(file);
    const hasPass = doc.recipients.some((r) => r.type === 'pass');
    const needs = await this.needsPass(doc);
    const fields = [...(needs ? [passField('passphrase', `Current passphrase for ${doc.context}`)] : []), ...(hasPass ? [passField('new_passphrase', 'New passphrase'), passField('passphrase2', 'Repeat the new passphrase')] : [])];
    return this.personStep(
      'env_rotate',
      { title: `Rotate the key of ${doc.context}`, lines: [{ label: 'file', value: file }, { label: 'effect', value: 'new data key, every value re-encrypted; recipients whose key is not available here are dropped' }], fields, confirm: !fields.length, check: (v) => (v.new_passphrase !== v.passphrase2 ? { field: 'passphrase2', code: 'mismatch' } : undefined) },
      async (v) => {
        const r = await this.app.envFiles.rotate(file, { passphrase: v.passphrase ? async () => v.passphrase : undefined }, undefined, v.new_passphrase ? async () => v.new_passphrase : undefined);
        this.app.audit.write('env_rotated', { file, recipients: r.recipients, dropped: r.dropped });
        return { file, ...r };
      },
    );
  }

  // ------------------------------------------------------------ helpers for secret_use / secret_write

  /** Decrypts selected keys of an encrypted .env for an approved action (never returned). */
  async envValues(fileArg: string, keys?: string[]): Promise<Map<string, string>> {
    const file = this.envFile(fileArg);
    const { entries } = await this.app.envFiles.decrypt(file, {});
    const out = new Map<string, string>();
    for (const e of entries) {
      if (keys && !keys.includes(e.key)) continue;
      this.app.sensitive.add(e.key, e.value);
      out.set(e.key, e.value);
    }
    for (const k of keys ?? []) if (!out.has(k)) throw new UserError(`key ${k} not in ${path.basename(file)}`, 'not_found');
    return out;
  }

  envKeys(fileArg: string): string[] {
    const file = this.envFile(fileArg);
    const buf = readFileSync(file, 'utf8');
    return parseDoc(buf, contextOf(file))
      .lines.filter((l) => l.t === 'kv')
      .map((l) => (l as { key: string }).key);
  }

  /** secret_write from:{kind:'env-enc', as_is:true}: copy the ciphertext file as is (no key needed). */
  async deployEncrypted(fileArg: string, rawTarget: unknown): Promise<{ target: Record<string, unknown>; bytes: number; keys: string[] }> {
    const file = this.envFile(fileArg);
    const t = TargetSchema.parse(rawTarget);
    if (t.kind !== 'env-file') throw new UserError('as_is deploys only to env-file targets', 'invalid_args');
    const keys = this.envKeys(file);
    checkTargetAllowed(this.cfg, t, keys);
    const doc = parseDoc(readFileSync(file, 'utf8'));
    if (!doc.encrypted) throw new UserError('as_is needs an encrypted file', 'not_encrypted');
    const data = readFileSync(file);
    const io = t.host ? new SshFileIO(this.app.ssh, t.host) : new LocalFileIO();
    await io.writeAtomic(t.path, data, { mode: t.mode ?? '0600', owner: t.owner, group: t.group, backup: t.backup });
    return { target: describeTarget(t), bytes: data.length, keys };
  }
}

/**
 * Local reveal page for a PERSON receiving a share (`veil share open`): the token comes in
 * the URL fragment (or is pasted), the passphrase is typed there, values are shown only on that
 * page with copy buttons and hidden again after `hideAfter` seconds. Nothing is printed, logged
 * or returned through MCP.
 */
export async function registerRevealPage(app: App, opts: { targetOverride?: string; hideAfter?: number; ttlMs?: number } = {}): Promise<{ url: string; done: Promise<{ status: string; names?: string[] }> }> {
  const schema = normalizeSchema({
    fields: [
      { ...passField('token', 'Share token (vfs1://...)', 'Pasted or taken from the link fragment; it never leaves this computer.'), required: true },
      { ...passField('passphrase', 'Passphrase (only if the sender gave you one by another channel)'), required: false },
    ],
  });
  let resolveDone!: (v: { status: string; names?: string[] }) => void;
  const done = new Promise<{ status: string; names?: string[] }>((r) => (resolveDone = r));
  let fails = 0;
  const op = app.ops.create('share_open', 'so');
  const { url } = await app.ui.register({
    kind: 'form',
    opId: op.id,
    title: 'Open a shared secret',
    description: 'The values appear only on this page, for a limited time. Each opening consumes one view.',
    schema,
    submitLabel: 'Open',
    fragmentField: 'token',
    ttlMs: opts.ttlMs ?? app.cfg.ui.ttlSeconds * 1000,
    onExpire: () => resolveDone({ status: 'expired' }),
    handle: async (p, lang) => {
      const t = STRINGS[lang];
      if (p.action === 'cancel') {
        resolveDone({ status: 'cancelled' });
        return { ok: false, message: t.cancelled };
      }
      if (p.action !== 'submit') return { ok: false };
      const { values, errors } = validateValues(schema, p.values ?? {});
      if (errors.length) return { ok: false, errors };
      const v = values as Record<string, string>;
      app.sensitive.add('share_token', v.token!);
      try {
        parseToken(v.token!);
        const r = await app.shares.open(v.token!, { passphrase: v.passphrase || undefined, targetOverride: opts.targetOverride });
        for (const it of r.items) app.sensitive.add(it.name, it.value);
        app.audit.write('share_read', { share: r.shareId, names: r.items.map((i) => i.name), views_left: r.viewsLeft, burned: r.burned, via: 'reveal_page' });
        resolveDone({ status: 'completed', names: r.items.map((i) => i.name) });
        const items = r.items.map((it) => (it.kind === 'env-dek' ? { label: `${it.name} (data key of an encrypted .env)`, value: it.value } : { label: it.name, value: it.value }));
        return {
          ok: true,
          reveal: {
            items,
            hideAfter: opts.hideAfter ?? 60,
            note: [r.note, r.burned ? 'This share is now consumed and was deleted from storage.' : `${r.viewsLeft} view(s) left.`, 'If you keep the value, store it in your own password manager / vault.'].filter(Boolean).join(' '),
          },
        };
      } catch (e) {
        const code = e instanceof UserError ? e.code : 'internal';
        app.audit.write('share_read_failed', { error: code, via: 'reveal_page' });
        if ((code === 'wrong_key' || code === 'passphrase_required' || code === 'bad_token') && ++fails < app.cfg.env.maxAttempts)
          return { ok: false, errors: [{ field: code === 'bad_token' ? 'token' : 'passphrase', code: code === 'wrong_key' ? 'wrong' : code === 'bad_token' ? 'bad_token' : 'required' }] };
        resolveDone({ status: 'failed' });
        const key = code === 'too_many_attempts' ? 'err_locked' : `err_${code}`;
        return { ok: false, message: (t as Record<string, string>)[key] ?? `Error: ${code}` };
      }
    },
  });
  return { url, done };
}
