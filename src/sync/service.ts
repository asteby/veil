import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import type { AuditLog } from '../audit.js';
import type { Config, Paths } from '../config.js';
import { keychainKey, readKeyFile } from '../crypto/keysource.js';
import { newKdfParams, type KdfParams } from '../crypto/primitives.js';
import { LocalFileIO } from '../fileio.js';
import type { Runner } from '../proc.js';
import type { Ssh } from '../ssh.js';
import type { KeychainBackend } from '../stores/keychain.js';
import { KeyedMutex, newId, UserError } from '../util.js';
import type { Vault } from '../vault.js';
import {
  buildBundle,
  clockVersion,
  compareClocks,
  deriveKek,
  keyHeader,
  MANIFEST,
  mergeClocks,
  newBundleId,
  newOid,
  objectPath,
  openBundle,
  packSingle,
  parseManifest,
  rekeyBundle,
  unpackSingle,
  verifyKek,
  type BundleEntry,
  type Clock,
  type Getter,
  type Manifest,
  type SecondFactor,
} from './bundle.js';
import { buildTarget, type BlobTarget } from './targets.js';

export type Strategy = 'report' | 'keep-local' | 'take-remote' | 'keep-both';

/** Asks the person for a passphrase (local page or TTY). `confirm` = new passphrase, ask twice. */
export type AskPassphrase = (purpose: string, opts: { confirm?: boolean }) => Promise<string | undefined>;

interface SyncState {
  v: 1;
  device: string;
  bundle_id?: string;
  /** key parameters of the bundle; `check` lets us reject a mistyped passphrase before exporting */
  key?: { kdf: KdfParams | null; second: SecondFactor; check?: string };
  seen: Record<string, number>;
  entries: Record<string, { oid: string; clock: Clock; updatedAt: string }>;
}

export interface ImportReport {
  bundle_seq: number;
  created: string[];
  updated: string[];
  unchanged: string[];
  kept_local: string[];
  conflicts: { name: string; reason: 'concurrent_change' }[];
  renamed: { name: string; as: string }[];
}

export interface SyncDeps {
  cfg: Config;
  paths: Paths;
  vault: Vault;
  ssh: Ssh;
  runner: Runner;
  keychain: KeychainBackend;
  audit: AuditLog;
  now?: () => Date;
  /** test hook: cheap KDF parameters */
  testKdf?: boolean;
}

/**
 * Encrypted backup / sync of the vault (see bundle.ts for the format). Holds a small local
 * state file (no values, no keys): device id, bundle id, KDF parameters, highest seq seen
 * per bundle (anti-rollback) and a logical clock per secret (conflict detection).
 */
export class VaultSync {
  private readonly io = new LocalFileIO();
  private readonly mutex = new KeyedMutex();
  private kekCache = new Map<string, { kek: Buffer; expires: number }>();
  private readonly now: () => Date;
  readonly stateFile: string;

  constructor(private readonly d: SyncDeps) {
    this.now = d.now ?? (() => new Date());
    this.stateFile = path.join(d.paths.home, 'sync-state.json');
  }

  // ------------------------------------------------------------ state

  state(): SyncState {
    if (!existsSync(this.stateFile)) return { v: 1, device: newId('dev').slice(4), seen: {}, entries: {} };
    return JSON.parse(readFileSync(this.stateFile, 'utf8')) as SyncState;
  }

  private saveState(s: SyncState): Promise<void> {
    return this.io.writeAtomic(this.stateFile, JSON.stringify(s, null, 1) + '\n', { mode: '0600' });
  }

  target(id: string): BlobTarget {
    const c = this.d.cfg.sync.targets[id];
    if (!c) throw new UserError(`sync target "${id}" is not configured (allowlist)`, 'target_not_allowed');
    return buildTarget(id, c, { ssh: this.d.ssh, runner: this.d.runner, resolve: (r) => this.d.vault.resolveLocal(r), home: this.d.paths.home, now: this.now });
  }

  // ------------------------------------------------------------ keys

  private secondFactorKind(): SecondFactor {
    const t = this.d.cfg.sync.secondFactor.type;
    return t === 'none' ? 'none' : t;
  }

  private async secondFactor(kind: SecondFactor): Promise<Buffer | undefined> {
    const sf = this.d.cfg.sync.secondFactor;
    if (kind === 'none') return undefined;
    if (kind === 'key-file' && sf.type === 'key-file') return readKeyFile(sf.path).key;
    if (kind === 'keychain' && sf.type === 'keychain') return (await keychainKey(this.d.keychain, sf.service, sf.account, true))?.key;
    throw new UserError(`the bundle needs a ${kind} second factor that is not configured here`, 'missing_key');
  }

  /** True when no passphrase prompt is needed right now (cached KEK or passphrase-less config). */
  unlocked(): boolean {
    const st = this.state();
    if (!this.d.cfg.sync.passphrase) return true;
    if (!st.bundle_id || !st.key) return false;
    const c = this.kekCache.get(this.cacheKey(st.bundle_id, st.key.kdf));
    return Boolean(c && c.expires > Date.now());
  }

  private cacheKey(bid: string, kdf: KdfParams | null) {
    return `${bid}:${kdf?.salt ?? '-'}`;
  }

  private async kek(bid: string, kdf: KdfParams | null, second: SecondFactor, ask: AskPassphrase | undefined, purpose: string, confirm = false, check?: string): Promise<Buffer> {
    const ck = this.cacheKey(bid, kdf);
    const c = this.kekCache.get(ck);
    if (c && c.expires > Date.now()) return c.kek;
    let passphrase: string | undefined;
    if (kdf) {
      passphrase = ask ? await ask(purpose, { confirm }) : undefined;
      if (passphrase === undefined) throw new UserError('this operation needs the vault backup passphrase', 'passphrase_required');
      if (confirm && passphrase.length < 10) throw new UserError('backup passphrase too short (min 10 chars)', 'weak_passphrase');
    }
    const kek = await deriveKek(bid, kdf, second, { passphrase, second: await this.secondFactor(second) });
    // only a verified KEK is cached (a typo must not stick for N minutes)
    if (check) verifyKek({ bundle_id: bid, key: { kdf, second, check } }, kek);
    if (this.d.cfg.sync.unlockMinutes > 0 && (check || confirm)) this.kekCache.set(ck, { kek, expires: Date.now() + this.d.cfg.sync.unlockMinutes * 60_000 });
    return kek;
  }

  lock(): void {
    for (const v of this.kekCache.values()) v.kek.fill(0);
    this.kekCache.clear();
  }

  // ------------------------------------------------------------ export

  private includedDestinations(): string[] {
    const inc = this.d.cfg.sync.include;
    return [...this.d.vault.stores.values()].filter((s) => s.readable && s.type !== 'http-api' && (!inc || inc.includes(s.id))).map((s) => s.id);
  }

  /** Builds an encrypted bundle of every included secret. */
  async exportFiles(ask: AskPassphrase | undefined, opts: { minSeq?: number; bundleId?: string } = {}): Promise<{ files: Map<string, Buffer>; manifest: Manifest; names: string[] }> {
    return this.mutex.run('sync', async () => {
      const st = this.state();
      const first = !st.bundle_id || !st.key;
      if (opts.bundleId && st.bundle_id && opts.bundleId !== st.bundle_id) throw new UserError('the target holds a different vault bundle; import it first or use another target', 'different_bundle');
      st.bundle_id ??= opts.bundleId ?? newBundleId();
      st.key ??= { kdf: this.d.cfg.sync.passphrase ? newKdfParams(this.d.cfg.sync.kdf, { test: this.d.testKdf }) : null, second: this.secondFactorKind() };
      if (!st.key.kdf && st.key.second === 'none') throw new UserError('sync needs a passphrase and/or a second factor', 'invalid_config');
      const kek = await this.kek(st.bundle_id, st.key.kdf, st.key.second, ask, 'Create the backup passphrase for your vault', first, st.key.check);
      const dests = new Set(this.includedDestinations());
      const entries: BundleEntry[] = [];
      for (const m of this.d.vault.list()) {
        if (!dests.has(m.destination)) continue;
        const value = await this.d.vault.readForBackup(m.destination, m.name);
        if (value === undefined) continue;
        const k = `${m.destination}:${m.name}`;
        let e = st.entries[k];
        if (!e) e = st.entries[k] = { oid: newOid(), clock: { [st.device]: 1 }, updatedAt: m.updatedAt };
        else if (e.updatedAt !== m.updatedAt) e.clock = { ...e.clock, [st.device]: (e.clock[st.device] ?? 0) + 1 };
        e.updatedAt = m.updatedAt;
        entries.push({
          oid: e.oid,
          name: m.name,
          destination: m.destination,
          clock: e.clock,
          version: clockVersion(e.clock),
          meta: { createdAt: m.createdAt, updatedAt: m.updatedAt, expiresAt: m.expiresAt, rotateAfterDays: m.rotateAfterDays, tags: m.tags, project: m.project, field: m.field, source: m.source },
          value,
        });
      }
      const seq = Math.max(st.seen[st.bundle_id] ?? 0, opts.minSeq ?? 0) + 1;
      const kh = keyHeader(st.bundle_id, kek, st.key.kdf, st.key.second);
      st.key.check ??= kh.check;
      const out = buildBundle({ bundleId: st.bundle_id, seq, kek, key: kh, device: st.device, entries, now: this.now() });
      st.seen[st.bundle_id] = seq;
      await this.saveState(st);
      this.d.audit.write('vault_exported', { bundle: st.bundle_id, seq, count: entries.length, names: entries.map((e) => e.name) });
      return { ...out, names: entries.map((e) => e.name) };
    });
  }

  async exportToFile(file: string, ask: AskPassphrase | undefined): Promise<{ file: string; seq: number; count: number; names: string[] }> {
    const { files, manifest, names } = await this.exportFiles(ask);
    await this.io.writeAtomic(file, packSingle(files), { mode: '0600' });
    return { file, seq: manifest.seq, count: names.length, names };
  }

  /** Pull (if the target is ahead) then push a fresh bundle; garbage-collects old objects. */
  async sync(targetId: string, ask: AskPassphrase | undefined, strategy: Strategy = 'report'): Promise<{ target: string; pulled?: ImportReport; pushed: { seq: number; count: number }; removed_objects: number }> {
    const t = this.target(targetId);
    await t.begin();
    const remoteRaw = await t.get(MANIFEST);
    let remote: Manifest | undefined;
    let pulled: ImportReport | undefined;
    if (remoteRaw) {
      remote = parseManifest(remoteRaw);
      const st = this.state();
      if (st.bundle_id && remote.bundle_id !== st.bundle_id) throw new UserError('the target holds a different vault bundle; import it first or use another target', 'different_bundle');
      if (remote.seq > (st.seen[remote.bundle_id] ?? 0)) {
        pulled = await this.importFrom((p) => t.get(p), ask, { strategy });
        if (pulled.conflicts.length && strategy === 'report') throw Object.assign(new UserError(`conflicts in ${pulled.conflicts.map((c) => c.name).join(', ')}: resolve with strategy keep-local, take-remote or keep-both`, 'conflict'), { report: pulled });
      }
    }
    const { files, manifest, names } = await this.exportFiles(ask, { minSeq: remote?.seq, bundleId: remote?.bundle_id });
    // objects first, manifest last: a reader never sees a manifest pointing to missing objects
    for (const [p, b] of files) if (p !== MANIFEST) await t.put(p, b);
    await t.put(MANIFEST, files.get(MANIFEST)!);
    let removed = 0;
    for (const o of remote?.objects ?? []) if (!files.has(objectPath(o.id)) && (await t.delete(objectPath(o.id)))) removed++;
    await t.commit(`veil sync seq ${manifest.seq}`);
    this.d.audit.write('vault_synced', { target: targetId, bundle: manifest.bundle_id, seq: manifest.seq, count: names.length, pulled: Boolean(pulled) });
    return { target: targetId, pulled, pushed: { seq: manifest.seq, count: names.length }, removed_objects: removed };
  }

  // ------------------------------------------------------------ import

  async pull(targetId: string, ask: AskPassphrase | undefined, opts: { strategy?: Strategy; destination?: string; allowRollback?: boolean } = {}): Promise<ImportReport> {
    const t = this.target(targetId);
    await t.begin();
    return this.importFrom((p) => t.get(p), ask, opts);
  }

  async importFile(file: string, ask: AskPassphrase | undefined, opts: { strategy?: Strategy; destination?: string; allowRollback?: boolean } = {}): Promise<ImportReport> {
    const buf = await this.io.read(file);
    if (!buf) throw new UserError('bundle file not found', 'not_found');
    const files = unpackSingle(buf);
    return this.importFrom(async (p) => files.get(p) ?? null, ask, opts);
  }

  async importFrom(get: Getter, ask: AskPassphrase | undefined, opts: { strategy?: Strategy; destination?: string; allowRollback?: boolean } = {}): Promise<ImportReport> {
    const strategy = opts.strategy ?? 'report';
    const st0 = this.state();
    const opened = await openBundle(get, (m) => this.kek(m.bundle_id, m.key.kdf, m.key.second, ask, 'Passphrase of the vault backup', false, m.key.check), {
      minSeq: opts.allowRollback ? undefined : (st0.seen[parseManifest(await get(MANIFEST)).bundle_id] ?? 0),
    });
    return this.mutex.run('sync', async () => {
      const st = this.state();
      const m = opened.manifest;
      const report: ImportReport = { bundle_seq: m.seq, created: [], updated: [], unchanged: [], kept_local: [], conflicts: [], renamed: [] };
      for (const e of opened.entries) {
        const dest = opts.destination ?? (this.d.vault.stores.get(e.destination)?.readable ? e.destination : this.d.cfg.defaultDestination);
        const key = `${dest}:${e.name}`;
        const local = this.d.vault.meta(key);
        const s = st.entries[key];
        const meta = { tags: e.meta.tags, project: e.meta.project, expiresAt: e.meta.expiresAt, rotateAfterDays: e.meta.rotateAfterDays, field: e.meta.field, source: e.meta.source ?? `bundle:${m.bundle_id.slice(0, 8)}` };
        const record = (clock: Clock) => {
          const nm = this.d.vault.meta(key);
          st.entries[key] = { oid: s?.oid ?? e.oid, clock, updatedAt: nm?.updatedAt ?? this.now().toISOString() };
        };
        if (!local) {
          await this.d.vault.put(dest, e.name, e.value, meta);
          record(e.clock);
          report.created.push(e.name);
          continue;
        }
        const localChanged = !s || local.updatedAt !== s.updatedAt;
        const lc: Clock = localChanged ? { ...(s?.clock ?? {}), [st.device]: ((s?.clock ?? {})[st.device] ?? 0) + 1 } : (s?.clock ?? {});
        const cmp = compareClocks(e.clock, lc);
        if (cmp === 'equal' || cmp === 'b_newer') {
          (cmp === 'equal' ? report.unchanged : report.kept_local).push(e.name);
          if (!localChanged) record(mergeClocks(e.clock, lc));
          continue;
        }
        if (cmp === 'a_newer' && !localChanged) {
          await this.d.vault.put(dest, e.name, e.value, meta);
          record(e.clock);
          report.updated.push(e.name);
          continue;
        }
        // concurrent change (or local edits we never exported): never overwrite silently
        const current = await this.d.vault.readForBackup(dest, e.name);
        if (current === e.value) {
          record(mergeClocks(e.clock, s?.clock ?? {}));
          report.unchanged.push(e.name);
          continue;
        }
        if (strategy === 'take-remote') {
          await this.d.vault.put(dest, e.name, e.value, meta);
          record(mergeClocks(e.clock, lc));
          report.updated.push(e.name);
        } else if (strategy === 'keep-local') {
          const merged = mergeClocks(e.clock, lc);
          st.entries[key] = { oid: s?.oid ?? e.oid, clock: { ...merged, [st.device]: (merged[st.device] ?? 0) + 1 }, updatedAt: local.updatedAt };
          report.kept_local.push(e.name);
        } else if (strategy === 'keep-both') {
          const as = `${e.name}.conflict-${opened.device.slice(0, 8).replace(/[^A-Za-z0-9_-]/g, '_')}`.slice(0, 128);
          await this.d.vault.put(dest, as, e.value, meta);
          // the local value keeps the name and now dominates both histories
          const merged = mergeClocks(e.clock, lc);
          st.entries[key] = { oid: s?.oid ?? e.oid, clock: { ...merged, [st.device]: (merged[st.device] ?? 0) + 1 }, updatedAt: local.updatedAt };
          report.renamed.push({ name: e.name, as });
          report.conflicts.push({ name: e.name, reason: 'concurrent_change' });
        } else report.conflicts.push({ name: e.name, reason: 'concurrent_change' });
      }
      st.bundle_id ??= m.bundle_id;
      st.key ??= { kdf: m.key.kdf, second: m.key.second, check: m.key.check };
      // unresolved conflicts: do not mark this seq as seen, so the next sync pulls again
      if (!(report.conflicts.length && strategy === 'report')) st.seen[m.bundle_id] = Math.max(st.seen[m.bundle_id] ?? 0, m.seq);
      await this.saveState(st);
      this.d.audit.write('vault_imported', { bundle: m.bundle_id, seq: m.seq, created: report.created, updated: report.updated, conflicts: report.conflicts.map((c) => c.name), strategy });
      return report;
    });
  }

  // ------------------------------------------------------------ rekey

  /**
   * KEK rotation: new passphrase (new salt) and/or second factor. Re-wraps every DEK of the
   * bundle on `targetId` (or of a bundle file) without decrypting values, bumps seq, and
   * updates the local key parameters.
   */
  async rekey(where: { target?: string; file?: string }, askOld: AskPassphrase, askNew: AskPassphrase): Promise<{ seq: number; objects: number }> {
    const st = this.state();
    let get: Getter;
    let put: (files: Map<string, Buffer>) => Promise<void>;
    let t: BlobTarget | undefined;
    if (where.target) {
      t = this.target(where.target);
      await t.begin();
      get = (p) => t!.get(p);
      put = async (files) => {
        for (const [p, b] of files) if (p !== MANIFEST) await t!.put(p, b);
        await t!.put(MANIFEST, files.get(MANIFEST)!);
        await t!.commit('veil rekey');
      };
    } else if (where.file) {
      const buf = await this.io.read(where.file);
      if (!buf) throw new UserError('bundle file not found', 'not_found');
      const files = unpackSingle(buf);
      get = async (p) => files.get(p) ?? null;
      put = (nf) => this.io.writeAtomic(where.file!, packSingle(nf), { mode: '0600' });
    } else throw new UserError('rekey needs a target or a file', 'invalid_args');
    const m = parseManifest(await get(MANIFEST));
    if ((st.seen[m.bundle_id] ?? 0) > m.seq) throw new UserError('this bundle is older than one already seen (rollback?)', 'rollback');
    this.kekCache.delete(this.cacheKey(m.bundle_id, m.key.kdf));
    const oldKek = await this.kek(m.bundle_id, m.key.kdf, m.key.second, askOld, 'Current backup passphrase', false, m.key.check);
    const kdf = this.d.cfg.sync.passphrase ? newKdfParams(this.d.cfg.sync.kdf, { test: this.d.testKdf }) : null;
    const second = this.secondFactorKind();
    const newKek = await this.kek(m.bundle_id, kdf, second, askNew, 'New backup passphrase', true);
    const seq = Math.max(m.seq, st.seen[m.bundle_id] ?? 0) + 1;
    const out = await rekeyBundle(get, oldKek, newKek, { kdf, second }, seq);
    await put(out.files);
    this.kekCache.delete(this.cacheKey(m.bundle_id, m.key.kdf));
    oldKek.fill(0);
    st.bundle_id ??= m.bundle_id;
    if (st.bundle_id === m.bundle_id) st.key = { kdf, second, check: out.manifest.key.check };
    st.seen[m.bundle_id] = seq;
    await this.saveState(st);
    this.d.audit.write('vault_rekeyed', { bundle: m.bundle_id, seq, objects: out.manifest.objects.length, kdf: kdf?.alg ?? 'none', second });
    return { seq, objects: out.manifest.objects.length };
  }
}
