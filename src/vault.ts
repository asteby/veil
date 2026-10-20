import { randomBytes } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import type { Config, Paths } from './config.js';
import { LocalFileIO, SshFileIO } from './fileio.js';
import type { Runner } from './proc.js';
import type { SensitiveRegistry } from './redact.js';
import type { Ssh } from './ssh.js';
import { EncryptedFileStore } from './stores/encrypted-file.js';
import { EnvFileStore, SshFileStore } from './stores/file-stores.js';
import { HttpApiStore } from './stores/http-api.js';
import { defaultKeychainBackend, KeychainStore, type KeychainBackend } from './stores/keychain.js';
import type { SecretStore } from './stores/types.js';
import { assertName, KeyedMutex, UserError } from './util.js';

export interface SecretMeta {
  name: string;
  destination: string;
  createdAt: string;
  updatedAt: string;
  lastUsedAt?: string;
  useCount: number;
  expiresAt?: string;
  rotateAfterDays?: number;
  tags: string[];
  project?: string;
  /** Field definition used to re-ask the person on rotation (never the value). */
  field?: { label: string; kind: string; help?: string; pattern?: string };
  source?: string;
}

export interface MetaInput {
  tags?: string[];
  project?: string;
  expiresAt?: string;
  rotateAfterDays?: number;
  field?: SecretMeta['field'];
  source?: string;
}

interface IndexShape {
  v: 1;
  secrets: Record<string, SecretMeta>;
}

export interface VaultDeps {
  cfg: Config;
  paths: Paths;
  runner: Runner;
  ssh: Ssh;
  sensitive: SensitiveRegistry;
  keychainBackend?: KeychainBackend;
  now?: () => Date;
}

/**
 * Named secrets with metadata. Values are fetched from the backing store at the
 * moment of use (`resolve`), kept in an in-memory cache for `cacheTtlSeconds` at
 * most, and never written to disk in clear by this layer.
 */
export class Vault {
  readonly stores = new Map<string, SecretStore>();
  private cache = new Map<string, { value: string; expires: number }>();
  private readonly io = new LocalFileIO();
  private readonly mutex = new KeyedMutex();
  private readonly now: () => Date;
  readonly keychain: KeychainBackend;

  constructor(private readonly d: VaultDeps) {
    this.now = d.now ?? (() => new Date());
    this.keychain = d.keychainBackend ?? defaultKeychainBackend(d.runner);
    for (const [id, dc] of Object.entries(d.cfg.destinations)) this.stores.set(id, this.build(id, dc));
  }

  private build(id: string, dc: Config['destinations'][string]): SecretStore {
    switch (dc.type) {
      case 'keychain':
        return new KeychainStore(id, dc.service, this.keychain);
      case 'encrypted-file': {
        const key = dc.key;
        return new EncryptedFileStore(id, dc.path, async () => {
          if (key.source === 'env') {
            const p = process.env[key.env];
            if (!p) throw new UserError(`environment variable ${key.env} (passphrase for ${id}) is not set`, 'missing_key');
            return { kind: 'passphrase', passphrase: p };
          }
          let hex = await this.keychain.get(key.service, key.account);
          if (!hex) {
            hex = randomBytes(32).toString('hex');
            await this.keychain.set(key.service, key.account, hex);
          }
          return { kind: 'raw', key: Buffer.from(hex, 'hex') };
        });
      }
      case 'env-file': {
        const io = dc.host ? new SshFileIO(this.d.ssh, dc.host) : this.io;
        return new EnvFileStore(id, io, dc.path, { mode: dc.mode, owner: dc.owner, group: dc.group, backup: dc.backup });
      }
      case 'ssh-file':
        this.d.ssh.hostConfig(dc.host);
        return new SshFileStore(id, new SshFileIO(this.d.ssh, dc.host), dc.path, { mode: dc.mode, owner: dc.owner, group: dc.group });
      case 'http-api':
        return new HttpApiStore(id, dc, (ref) => this.resolveLocal(ref));
    }
  }

  store(id: string): SecretStore {
    const s = this.stores.get(id);
    if (!s) throw new UserError(`destination "${id}" is not configured (allowlist)`, 'destination_not_allowed');
    return s;
  }

  // ------------------------------------------------------------ index

  private loadIndex(): IndexShape {
    if (!existsSync(this.d.paths.indexFile)) return { v: 1, secrets: {} };
    return JSON.parse(readFileSync(this.d.paths.indexFile, 'utf8')) as IndexShape;
  }

  private async saveIndex(ix: IndexShape): Promise<void> {
    await this.io.writeAtomic(this.d.paths.indexFile, JSON.stringify(ix, null, 1) + '\n', { mode: '0600' });
  }

  private updateIndex(fn: (ix: IndexShape) => void): Promise<void> {
    return this.mutex.run('index', async () => {
      const ix = this.loadIndex();
      fn(ix);
      await this.saveIndex(ix);
    });
  }

  list(filter: { project?: string; tag?: string; destination?: string } = {}): (SecretMeta & { expired: boolean; rotationDue: boolean })[] {
    const now = this.now().getTime();
    return Object.values(this.loadIndex().secrets)
      .filter((m) => (!filter.project || m.project === filter.project) && (!filter.tag || m.tags.includes(filter.tag)) && (!filter.destination || m.destination === filter.destination))
      .map((m) => ({ ...m, expired: this.isExpired(m, now), rotationDue: this.isRotationDue(m, now) }))
      .sort((a, b) => a.name.localeCompare(b.name));
  }

  meta(ref: string): SecretMeta | undefined {
    return this.findMeta(ref);
  }

  private isExpired(m: SecretMeta, now: number): boolean {
    return Boolean(m.expiresAt && Date.parse(m.expiresAt) <= now);
  }

  private isRotationDue(m: SecretMeta, now: number): boolean {
    return Boolean(m.rotateAfterDays && Date.parse(m.updatedAt) + m.rotateAfterDays * 86_400_000 <= now);
  }

  private findMeta(ref: string): SecretMeta | undefined {
    const ix = this.loadIndex();
    const [a, b] = ref.includes(':') ? ref.split(':', 2) : [undefined, ref];
    if (a) return ix.secrets[`${a}:${b}`];
    const cands = Object.values(ix.secrets).filter((m) => m.name === b && this.stores.get(m.destination)?.readable);
    cands.sort((x, y) => y.updatedAt.localeCompare(x.updatedAt));
    return cands[0] ?? Object.values(ix.secrets).find((m) => m.name === b);
  }

  // ------------------------------------------------------------ values

  async put(destination: string, name: string, value: string, meta: MetaInput = {}): Promise<{ action: 'created' | 'updated' }> {
    assertName(name, 'secret name');
    const store = this.store(destination);
    this.d.sensitive.add(name, value);
    const res = await store.put(name, value);
    this.cache.delete(`${destination}:${name}`);
    const ts = this.now().toISOString();
    await this.updateIndex((ix) => {
      const key = `${destination}:${name}`;
      const prev = ix.secrets[key];
      ix.secrets[key] = {
        name,
        destination,
        createdAt: prev?.createdAt ?? ts,
        updatedAt: ts,
        lastUsedAt: prev?.lastUsedAt,
        useCount: prev?.useCount ?? 0,
        expiresAt: meta.expiresAt ?? prev?.expiresAt,
        rotateAfterDays: meta.rotateAfterDays ?? prev?.rotateAfterDays,
        tags: meta.tags ?? prev?.tags ?? [],
        project: meta.project ?? prev?.project,
        field: meta.field ?? prev?.field,
        source: meta.source ?? prev?.source,
      };
    });
    return res;
  }

  /** Resolves a secret value at the moment of use. Throws UserError (no value) on failure. */
  async resolve(ref: string, opts: { allowExpired?: boolean } = {}): Promise<{ value: string; meta: SecretMeta; warnings: string[] }> {
    const meta = this.findMeta(ref);
    if (!meta) throw new UserError(`secret "${ref}" not found (use secret_request to ask the person for it)`, 'not_found');
    const now = this.now().getTime();
    const warnings: string[] = [];
    if (this.isExpired(meta, now)) {
      if (!opts.allowExpired) throw new UserError(`secret "${meta.name}" expired at ${meta.expiresAt}; ask the person to rotate it (secret_rotate)`, 'expired');
      warnings.push(`${meta.name} expired`);
    } else if (this.isRotationDue(meta, now)) warnings.push(`${meta.name} is due for rotation (secret_rotate)`);
    const key = `${meta.destination}:${meta.name}`;
    const cached = this.cache.get(key);
    let value: string | undefined;
    if (cached && cached.expires > now) value = cached.value;
    else {
      const store = this.store(meta.destination);
      if (!store.readable) throw new UserError(`secret "${meta.name}" lives in write-only destination ${meta.destination}`, 'not_readable');
      value = await store.get(meta.name);
      if (value === undefined) throw new UserError(`secret "${meta.name}" is indexed but missing from ${meta.destination}`, 'missing_value');
      if (this.d.cfg.cacheTtlSeconds > 0) this.cache.set(key, { value, expires: now + this.d.cfg.cacheTtlSeconds * 1000 });
    }
    this.d.sensitive.add(meta.name, value);
    await this.updateIndex((ix) => {
      const m = ix.secrets[key];
      if (m) {
        m.lastUsedAt = this.now().toISOString();
        m.useCount = (m.useCount ?? 0) + 1;
      }
    });
    return { value, meta, warnings };
  }

  /** For bootstrap tokens of remote stores: only local, readable destinations. */
  async resolveLocal(ref: string): Promise<string> {
    const meta = this.findMeta(ref);
    if (meta && this.stores.get(meta.destination)?.type === 'http-api') throw new UserError('bootstrap tokens must live in a local store', 'invalid_config');
    if (!meta) {
      // allow direct keychain/encrypted-file references not present in the index
      const [dest, name] = ref.includes(':') ? ref.split(':', 2) : [this.d.cfg.defaultDestination, ref];
      const store = this.store(dest!);
      if (store.type === 'http-api') throw new UserError('bootstrap tokens must live in a local store', 'invalid_config');
      const v = await store.get(name!);
      if (v === undefined) throw new UserError(`bootstrap secret "${ref}" not found`, 'not_found');
      this.d.sensitive.add(name!, v);
      return v;
    }
    return (await this.resolve(ref)).value;
  }

  async delete(name: string, destination?: string): Promise<{ deleted: string[] }> {
    const ix = this.loadIndex();
    const keys = Object.keys(ix.secrets).filter((k) => ix.secrets[k]!.name === name && (!destination || ix.secrets[k]!.destination === destination));
    const deleted: string[] = [];
    for (const k of keys) {
      const m = ix.secrets[k]!;
      await this.store(m.destination).delete(m.name);
      this.cache.delete(k);
      deleted.push(m.destination);
    }
    await this.updateIndex((i) => {
      for (const k of keys) delete i.secrets[k];
    });
    return { deleted };
  }

  clearCache(): void {
    this.cache.clear();
  }

  get internalDestination(): string {
    return this.d.cfg.internalDestination ?? this.d.cfg.defaultDestination;
  }

  runDir(): string {
    return path.join(this.d.paths.home, 'run');
  }
}
