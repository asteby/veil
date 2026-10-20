import { spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { closeSync, existsSync, fsyncSync, openSync, readFileSync, statSync, unlinkSync, writeSync } from 'node:fs';
import path from 'node:path';
import { AttemptLimiter } from '../crypto/attempts.js';
import { agentGet, agentPut, ambientKeys, keychainKey, type NamedKey } from '../crypto/keysource.js';
import { newKdfParams, type KdfParams } from '../crypto/primitives.js';
import { LocalFileIO } from '../fileio.js';
import { Redactor } from '../redact.js';
import type { KeychainBackend } from '../stores/keychain.js';
import { expandHome, globMatch, UserError } from '../util.js';
import { applyChanges, decryptDoc, encryptDoc, keysOf, kvLines, parseDoc, rhsValue, plaintextKeys, serialize, setRecipients, unlock, type EnvDoc, type PlainEntry, type RecipientSpec } from './format.js';

export interface EnvDeps {
  home: string;
  keychain?: KeychainBackend;
  keychainEntry?: { service: string; account: string };
  keyFiles?: string[];
  kdf?: 'argon2id' | 'scrypt';
  maxAttempts?: number;
  agentSocket?: string;
  env?: NodeJS.ProcessEnv;
  testKdf?: boolean;
}

export interface OpenOpts {
  keyFiles?: string[];
  /** typed by the person (TTY or local page); never argv / MCP */
  passphrase?: () => Promise<string | undefined>;
  /** DEK from a share token */
  dek?: Buffer;
  /** skip OS keychain lookup */
  noKeychain?: boolean;
}

export interface RecipientsInput {
  passphrase?: string;
  passphraseLabel?: string;
  keyFiles?: string[];
  keys?: Buffer[];
  keychain?: boolean;
}

/** Default context = file name (".env.production"); it is bound into every ciphertext. */
export const contextOf = (file: string) => path.basename(file);

/** Session-cache id: changes whenever recipients (and thus the DEK) change. */
export function docCacheId(doc: EnvDoc): string {
  return 'env:' + createHash('sha256').update(doc.context).update('\0').update(doc.recipients.map((r) => r.w).join('\0')).digest('hex').slice(0, 24);
}

/** Encrypted .env files: encrypt / decrypt / edit / rotate / diff / run / status. */
export class EnvFiles {
  private readonly io = new LocalFileIO();
  readonly limiter: AttemptLimiter;
  /** in-process DEK cache (MCP server "unlock session") */
  private cache = new Map<string, { dek: Buffer; expires: number }>();
  /** DEKs received through share tokens, by file context (verified against the MAC on use) */
  private byContext = new Map<string, { dek: Buffer; expires: number }>();

  constructor(private readonly d: EnvDeps) {
    this.limiter = new AttemptLimiter(path.join(d.home, 'unlock-attempts.json'), d.maxAttempts ?? 5);
  }

  async read(file: string): Promise<EnvDoc> {
    const buf = await this.io.read(file);
    if (!buf) throw new UserError(`file ${file} not found`, 'not_found');
    return parseDoc(buf.toString('utf8'), contextOf(file));
  }

  async keys(opts: OpenOpts = {}): Promise<NamedKey[]> {
    const out = ambientKeys({ keyFiles: [...(this.d.keyFiles ?? []), ...(opts.keyFiles ?? [])], env: this.d.env });
    if (!opts.noKeychain && this.d.keychain && this.d.keychainEntry) {
      const k = await keychainKey(this.d.keychain, this.d.keychainEntry.service, this.d.keychainEntry.account).catch(() => undefined);
      if (k) out.push(k);
    }
    return out;
  }

  cacheDek(doc: EnvDoc, dek: Buffer, minutes: number): void {
    this.cache.set(docCacheId(doc), { dek, expires: Date.now() + minutes * 60_000 });
  }

  cacheDekByContext(context: string, dek: Buffer, minutes: number): void {
    this.byContext.set(context, { dek, expires: Date.now() + minutes * 60_000 });
  }

  lock(): void {
    for (const v of [...this.cache.values(), ...this.byContext.values()]) v.dek.fill(0);
    this.cache.clear();
    this.byContext.clear();
  }

  isUnlocked(doc: EnvDoc): boolean {
    const c = this.cache.get(docCacheId(doc));
    return Boolean(c && c.expires > Date.now());
  }

  /** Unlocks a document with, in order: given DEK, in-process cache, session agent, keys, passphrase. */
  async open(doc: EnvDoc, opts: OpenOpts = {}): Promise<{ dek: Buffer; via: string }> {
    const id = docCacheId(doc);
    if (opts.dek) return unlock(doc, { dek: opts.dek });
    const c = this.cache.get(id);
    if (c && c.expires > Date.now()) return { dek: c.dek, via: 'session' };
    const bc = this.byContext.get(doc.context);
    if (bc && bc.expires > Date.now()) {
      try {
        return { ...(await unlock(doc, { dek: bc.dek })), via: 'token' };
      } catch {
        /* other file with the same name */
      }
    }
    if (this.d.agentSocket) {
      const k = await agentGet(this.d.agentSocket, id);
      if (k) {
        try {
          return { ...(await unlock(doc, { dek: k })), via: 'agent' };
        } catch {
          /* stale */
        }
      }
    }
    const keys = (await this.keys(opts)).map((k) => k.key);
    try {
      return await unlock(doc, { keys });
    } catch (e) {
      if (!opts.passphrase || !doc.recipients.some((r) => r.type === 'pass')) throw e;
    }
    const lid = `env:${doc.context}:${id}`;
    this.limiter.check(lid);
    try {
      const r = await unlock(doc, { passphrase: opts.passphrase });
      await this.limiter.ok(lid);
      return r;
    } catch (e) {
      if (e instanceof UserError && e.code === 'wrong_key') {
        const left = await this.limiter.fail(lid);
        throw new UserError(`cannot decrypt: wrong passphrase (${left} attempts left before a temporary lock)`, 'wrong_key');
      }
      throw e;
    }
  }

  /** Puts a DEK into the session agent for `minutes` (veilform env unlock). */
  async remember(doc: EnvDoc, dek: Buffer, minutes: number): Promise<boolean> {
    this.cacheDek(doc, dek, minutes);
    return this.d.agentSocket ? agentPut(this.d.agentSocket, docCacheId(doc), dek, minutes * 60) : false;
  }

  async recipientSpecs(r: RecipientsInput): Promise<RecipientSpec[]> {
    const specs: RecipientSpec[] = [];
    if (r.passphrase !== undefined) specs.push({ type: 'pass', passphrase: r.passphrase, kdf: this.kdf(), label: r.passphraseLabel });
    for (const f of r.keyFiles ?? []) specs.push({ type: 'key', key: ambientKeys({ keyFiles: [f], env: {} })[0]!.key });
    for (const k of r.keys ?? []) specs.push({ type: 'key', key: k });
    if (r.keychain && this.d.keychain && this.d.keychainEntry) {
      const k = await keychainKey(this.d.keychain, this.d.keychainEntry.service, this.d.keychainEntry.account, true);
      specs.push({ type: 'key', key: k!.key });
    }
    if (!specs.length) throw new UserError('choose at least one recipient: a passphrase, a key file or the OS keychain', 'invalid_args');
    return specs;
  }

  kdf(): KdfParams {
    return newKdfParams(this.d.kdf, { test: this.d.testKdf });
  }

  /** Plain .env → encrypted (in place unless `out`). `shred` overwrites the plaintext original. */
  async encrypt(file: string, r: RecipientsInput, opts: { out?: string; shred?: boolean; context?: string } = {}): Promise<{ file: string; keys: string[]; recipients: string[]; shredded: boolean; gitignore_warning?: string }> {
    const doc = await this.read(file);
    if (doc.encrypted) throw new UserError('file is already encrypted', 'already_encrypted');
    const out = opts.out ?? file;
    const ctx = opts.context ?? contextOf(out);
    const { doc: enc } = await encryptDoc(doc, { context: ctx, recipients: await this.recipientSpecs(r) });
    let shredded = false;
    if (opts.shred && path.resolve(expandHome(out)) !== path.resolve(expandHome(file))) {
      await this.io.writeAtomic(out, serialize(enc), { mode: '0600' });
      shred(expandHome(file));
      shredded = true;
    } else {
      if (opts.shred) overwriteInPlace(expandHome(file));
      await this.io.writeAtomic(out, serialize(enc), { mode: '0600' });
      shredded = Boolean(opts.shred);
    }
    return { file: out, keys: keysOf(enc), recipients: enc.recipients.map((x) => x.id), shredded, gitignore_warning: gitignoreWarning(file) };
  }

  async decrypt(file: string, o: OpenOpts = {}): Promise<{ text: string; entries: PlainEntry[]; doc: EnvDoc; dek: Buffer }> {
    const doc = await this.read(file);
    const { dek } = await this.open(doc, o);
    const r = await decryptDoc(doc, dek);
    return { ...r, doc, dek };
  }

  /** Applies changes (null deletes) and re-encrypts; unchanged values keep their ciphertext. */
  async edit(file: string, changes: Record<string, string | null>, o: OpenOpts = {}): Promise<{ changed: string[]; added: string[]; removed: string[] }> {
    const { text, doc, dek } = await this.decrypt(file, o);
    const plain = parseDoc(text, doc.context);
    const before = new Set(keysOf(plain));
    const next = applyChanges(plain, changes);
    const { doc: enc } = await encryptDoc(next, { context: doc.context, dek, recipients: doc.recipients, prev: { doc, dek } });
    await this.io.writeAtomic(file, serialize(enc), { mode: modeOf(file) });
    const after = new Set(keysOf(next));
    return {
      changed: Object.keys(changes).filter((k) => changes[k] !== null && before.has(k)),
      added: [...after].filter((k) => !before.has(k)),
      removed: [...before].filter((k) => !after.has(k)),
    };
  }

  /**
   * Rotation: new DEK, every value re-encrypted, recipients re-wrapped. Recipients we cannot
   * re-wrap (their key is not available here) are dropped and reported, unless `recipients` is
   * given explicitly.
   */
  async rotate(file: string, o: OpenOpts, recipients?: RecipientsInput, keepPassphrase?: () => Promise<string | undefined>): Promise<{ recipients: string[]; dropped: string[]; keys: string[] }> {
    const { text, doc } = await this.decrypt(file, o);
    let specs: RecipientSpec[];
    if (recipients) specs = await this.recipientSpecs(recipients);
    else {
      specs = [];
      const avail = await this.keys(o);
      for (const r of doc.recipients) {
        if (r.type === 'key') {
          const k = avail.find((x) => `key:${x.id}` === r.id);
          if (k) specs.push({ type: 'key', key: k.key });
        } else if (keepPassphrase) {
          const p = await keepPassphrase();
          if (p !== undefined) specs.push({ type: 'pass', passphrase: p, kdf: this.kdf(), label: r.id.startsWith('pass:') ? r.id.slice(5) : undefined });
        }
      }
      if (!specs.length) throw new UserError('no recipient could be re-wrapped; pass recipients explicitly', 'invalid_args');
    }
    const { doc: enc } = await encryptDoc(parseDoc(text, doc.context), { context: doc.context, recipients: specs });
    await this.io.writeAtomic(file, serialize(enc), { mode: modeOf(file) });
    this.cache.delete(docCacheId(doc));
    const ids = enc.recipients.map((r) => r.id);
    return { recipients: ids, dropped: doc.recipients.map((r) => r.id).filter((id) => !ids.includes(id)), keys: keysOf(enc) };
  }

  async addRecipients(file: string, o: OpenOpts, add: RecipientsInput, removeIds: string[] = []): Promise<{ recipients: string[] }> {
    const doc = await this.read(file);
    const { dek } = await this.open(doc, o);
    const next = await setRecipients(doc, dek, add.passphrase !== undefined || add.keyFiles?.length || add.keys?.length || add.keychain ? await this.recipientSpecs(add) : [], removeIds);
    await this.io.writeAtomic(file, serialize(next), { mode: modeOf(file) });
    return { recipients: next.recipients.map((r) => r.id) };
  }

  /** Which keys changed between two versions (names only). */
  async diff(a: { file?: string; text?: string }, b: { file?: string; text?: string }, o: OpenOpts = {}): Promise<{ added: string[]; removed: string[]; changed: string[]; unchanged: string[] }> {
    const load = async (x: { file?: string; text?: string }) => {
      const doc = x.text !== undefined ? parseDoc(x.text, contextOf(x.file ?? '.env')) : await this.read(x.file!);
      if (!doc.encrypted) return new Map(parseEnvEntries(serialize(doc)));
      const { dek } = await this.open(doc, o);
      return new Map((await decryptDoc(doc, dek)).entries.map((e) => [e.key, e.value] as const));
    };
    const A = await load(a);
    const B = await load(b);
    const keys = [...new Set([...A.keys(), ...B.keys()])].sort();
    const r = { added: [] as string[], removed: [] as string[], changed: [] as string[], unchanged: [] as string[] };
    for (const k of keys) {
      if (!A.has(k)) r.added.push(k);
      else if (!B.has(k)) r.removed.push(k);
      else (A.get(k) === B.get(k) ? r.unchanged : r.changed).push(k);
    }
    return r;
  }

  /** What can open this file here (no values, no passphrase prompts). */
  async status(file: string, o: OpenOpts = {}): Promise<{ file: string; encrypted: boolean; context: string; keys: string[]; recipients: { id: string; type: string; available_here: boolean }[]; methods: string[]; unlocked: boolean; plaintext_keys: string[] }> {
    const doc = await this.read(file);
    const avail = new Set((await this.keys(o)).map((k) => `key:${k.id}`));
    const unlocked = this.isUnlocked(doc) || Boolean(this.d.agentSocket && (await agentGet(this.d.agentSocket, docCacheId(doc))));
    const recipients = doc.recipients.map((r) => ({ id: r.id, type: r.type === 'pass' ? 'passphrase' : 'key', available_here: r.type === 'key' ? avail.has(r.id) : true }));
    const methods: string[] = [];
    if (unlocked) methods.push('session (already unlocked)');
    for (const k of await this.keys(o)) if (avail.has(`key:${k.id}`) && doc.recipients.some((r) => r.id === `key:${k.id}`)) methods.push(`${k.kind} ${k.where}`);
    if (doc.recipients.some((r) => r.type === 'pass')) methods.push('passphrase (local page or TTY)');
    if (doc.encrypted) methods.push('share token (veilform env unlock --token)');
    return { file, encrypted: doc.encrypted, context: doc.context, keys: keysOf(doc), recipients, methods, unlocked, plaintext_keys: doc.encrypted ? [] : plaintextKeys(doc) };
  }

  /**
   * Runs a command with the decrypted variables injected into the CHILD's environment only.
   * Not in argv, not on disk, not in this process' env. stdout/stderr pass through a
   * line-buffered redactor unless `raw`.
   */
  async run(file: string, argv: string[], o: OpenOpts & { raw?: boolean; only?: string[]; stdio?: { stdout: NodeJS.WritableStream; stderr: NodeJS.WritableStream } } = {}): Promise<number> {
    if (!argv.length) throw new UserError('missing command after --', 'invalid_args');
    const { entries } = await this.decrypt(file, o);
    const env: NodeJS.ProcessEnv = { ...process.env };
    for (const k of Object.keys(env)) if (k.startsWith('VEILFORM') && k !== 'VEILFORM_AGENT') delete env[k];
    const used = entries.filter((e) => !o.only || o.only.includes(e.key));
    for (const e of used) env[e.key] = e.value;
    const red = new Redactor(used.filter((e) => e.value.length >= 4).map((e) => ({ label: e.key, value: e.value })));
    const out = o.stdio ?? { stdout: process.stdout, stderr: process.stderr };
    return new Promise((resolve, reject) => {
      const child = spawn(argv[0]!, argv.slice(1), { env, stdio: ['inherit', o.raw ? 'inherit' : 'pipe', o.raw ? 'inherit' : 'pipe'] });
      const pipe = (src: NodeJS.ReadableStream | null, dst: NodeJS.WritableStream) => {
        if (!src) return;
        let buf = '';
        src.setEncoding('utf8');
        src.on('data', (d: string) => {
          buf += d;
          const nl = buf.lastIndexOf('\n');
          if (nl >= 0) {
            dst.write(red.redact(buf.slice(0, nl + 1)));
            buf = buf.slice(nl + 1);
          } else if (buf.length > 65536) {
            dst.write(red.redact(buf));
            buf = '';
          }
        });
        src.on('end', () => {
          if (buf) dst.write(red.redact(buf));
        });
      };
      pipe(child.stdout, out.stdout);
      pipe(child.stderr, out.stderr);
      const fwd = (sig: NodeJS.Signals) => () => child.kill(sig);
      const handlers = (['SIGINT', 'SIGTERM', 'SIGHUP'] as const).map((s) => [s, fwd(s)] as const);
      for (const [s, h] of handlers) process.on(s, h);
      child.on('error', (e) => reject(new UserError(`cannot start command: ${(e as NodeJS.ErrnoException).code ?? 'error'}`, 'exec_failed')));
      child.on('close', (code, signal) => {
        for (const [s, h] of handlers) process.off(s, h);
        resolve(code ?? (signal ? 128 + 1 : 1));
      });
    });
  }

  allowed(globs: string[], file: string): boolean {
    const abs = path.resolve(expandHome(file));
    return globs.some((g) => globMatch(g, abs) || globMatch(g, path.basename(abs)));
  }
}

function parseEnvEntries(text: string): [string, string][] {
  return kvLines(parseDoc(text)).map((l) => [l.key, rhsValue(l.key, l.rhs)]);
}

function modeOf(file: string): string {
  try {
    return '0' + (statSync(expandHome(file)).mode & 0o777).toString(8);
  } catch {
    return '0600';
  }
}

/** Overwrites the file content with random bytes (same length) and fsyncs. */
function overwriteInPlace(file: string): void {
  if (!existsSync(file)) return;
  const size = statSync(file).size;
  const fd = openSync(file, 'r+');
  try {
    let off = 0;
    while (off < size) {
      const chunk = randomBytes(Math.min(65536, size - off));
      off += writeSync(fd, chunk, 0, chunk.length, off);
    }
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

/**
 * Best-effort secure delete: overwrite + fsync + unlink. On SSDs (wear levelling), copy-on-write
 * filesystems (btrfs, ZFS, APFS), journaling, snapshots and backups old blocks may survive.
 */
export function shred(file: string): void {
  overwriteInPlace(file);
  if (existsSync(file)) unlinkSync(file);
}

/** Warns when the plaintext file is inside a git work tree and not ignored by a simple .gitignore rule. */
export function gitignoreWarning(file: string): string | undefined {
  let dir = path.dirname(path.resolve(expandHome(file)));
  for (let i = 0; i < 40; i++) {
    if (existsSync(path.join(dir, '.git'))) {
      const gi = existsSync(path.join(dir, '.gitignore')) ? readFileSync(path.join(dir, '.gitignore'), 'utf8') : '';
      const ignored = gi.split('\n').some((l) => /^\/?\.env(\*|\.\*)?$/.test(l.trim()) || l.trim() === path.basename(file));
      return ignored ? undefined : `add plaintext .env files to ${path.join(dir, '.gitignore')} (e.g. ".env.local"), and consider "veilform env hook install"`;
    }
    const up = path.dirname(dir);
    if (up === dir) break;
    dir = up;
  }
  return undefined;
}

/** For the pre-commit hook: names of staged .env files that hold plaintext values. */
export function plaintextEnvFiles(files: { path: string; content: string }[]): string[] {
  return files
    .filter((f) => /(^|\/)\.env(\.[A-Za-z0-9_.-]+)?$/.test(f.path) && !/\.(example|sample|template|dist)$/.test(f.path))
    .filter((f) => {
      try {
        const d = parseDoc(f.content);
        return !d.encrypted && plaintextKeys(d).length > 0;
      } catch {
        return true;
      }
    })
    .map((f) => f.path);
}
