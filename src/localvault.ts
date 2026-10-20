/**
 * Veil's own encrypted store: ONE file (the `encrypted-file` v1 format: AES-256-GCM per entry
 * with the entry name as AAD, key derived with argon2id — or scrypt on older Node — from a
 * master password). It is what makes Veil work WITHOUT installing anything: when the OS
 * keychain is missing, locked or unsupported, values land here instead.
 *
 *  - The master password is defined on the LOCAL page (127.0.0.1) the first time it is needed,
 *    never in the chat, MCP arguments or argv. It is never written anywhere.
 *  - Unlocking keeps only the DERIVED key in memory: in the session agent when one is running
 *    (`veilform agent`; `veilform lock` forgets it everywhere) or in this process for
 *    `unlockMinutes`.
 *  - Optionally the derived key can be saved in the OS keychain later (`veilform unlock
 *    --save-keychain`) so the store opens without typing the password.
 *  - Forgotten master password = unrecoverable data (by design). See THREAT-MODEL.md §9.
 */
import { createHash } from 'node:crypto';
import { existsSync, statSync } from 'node:fs';
import path from 'node:path';
import { AttemptLimiter } from './crypto/attempts.js';
import { agentGet, agentPut, agentRequest, formatKey } from './crypto/keysource.js';
import { unb64, wipe } from './crypto/primitives.js';
import { LocalFileIO } from './fileio.js';
import { deriveFileKey, EncryptedFileStore, newPassphraseShape, readEncryptedFile, reencryptShape, verifyFileKey, type FileShape } from './stores/encrypted-file.js';
import type { KeychainBackend } from './stores/keychain.js';
import { expandHome, KeyedMutex, UserError } from './util.js';

export const MIN_MASTER_LENGTH = 10;

export interface LocalVaultOptions {
  file: string;
  /** directory for the failed-attempts file */
  home: string;
  keychain: KeychainBackend;
  keychainEntry: { service: string; account: string };
  agentSocket?: string;
  unlockMinutes: number;
  kdf?: 'argon2id' | 'scrypt';
  testKdf?: boolean;
  maxAttempts?: number;
  now?: () => number;
}

export interface LocalVaultStatus {
  path: string;
  exists: boolean;
  unlocked: boolean;
  via?: 'memory' | 'agent' | 'keychain';
  kdf?: string;
  entries?: number;
  permissions_ok?: boolean;
}

export class LocalVault {
  readonly file: string;
  private cache?: { key: Buffer; salt: string; expires: number };
  private readonly limiter: AttemptLimiter;
  private readonly mutex = new KeyedMutex();
  private readonly io = new LocalFileIO();
  private readonly now: () => number;

  constructor(private readonly o: LocalVaultOptions) {
    this.file = path.resolve(expandHome(o.file));
    this.now = o.now ?? Date.now;
    this.limiter = new AttemptLimiter(path.join(o.home, 'local-vault.attempts.json'), o.maxAttempts ?? 5, 15 * 60_000, this.now);
  }

  exists(): boolean {
    return existsSync(this.file);
  }

  private async shape(): Promise<FileShape | undefined> {
    return readEncryptedFile(this.file);
  }

  private saltOf(s: FileShape): string {
    return s.kdf.name === 'raw' ? 'raw' : s.kdf.salt;
  }

  /** Public id used for the session agent and the attempt limiter (never the key). */
  private idFor(s: FileShape): string {
    return `local-vault:${createHash('sha256').update(this.file).update('\0').update(this.saltOf(s)).digest('hex').slice(0, 24)}`;
  }

  /** The derived key, from memory, the session agent or the keychain; else a structured error. */
  async key(): Promise<Buffer> {
    const s = await this.shape();
    if (!s) throw new UserError("Veil's encrypted store has no master password yet", 'master_password_not_set');
    const k = await this.tryKey(s);
    if (!k) throw new UserError("Veil's encrypted store is locked", 'passphrase_required');
    return k.key;
  }

  private async tryKey(s: FileShape): Promise<{ key: Buffer; via: 'memory' | 'agent' | 'keychain' } | undefined> {
    const salt = this.saltOf(s);
    if (this.cache && this.cache.salt === salt && this.cache.expires > this.now()) return { key: this.cache.key, via: 'memory' };
    if (this.cache && this.cache.expires <= this.now()) this.lock();
    if (this.o.agentSocket) {
      const k = await agentGet(this.o.agentSocket, this.idFor(s));
      if (k && verifyFileKey(s, k)) return { key: k, via: 'agent' };
    }
    try {
      const v = await this.o.keychain.get(this.o.keychainEntry.service, this.o.keychainEntry.account);
      if (v && /^vfk1:[A-Za-z0-9_-]{43}$/.test(v.trim())) {
        const k = unb64(v.trim().slice(5), 'key');
        if (verifyFileKey(s, k)) return { key: k, via: 'keychain' };
      }
    } catch {
      /* keychain unavailable: that is the reason this store exists */
    }
    return undefined;
  }

  /** Keeps the derived key: in the session agent when available, else in this process. */
  private async remember(key: Buffer, s: FileShape, minutes: number): Promise<'agent' | 'memory'> {
    const ttl = Math.max(1, minutes) * 60;
    if (this.o.agentSocket && (await agentPut(this.o.agentSocket, this.idFor(s), key, ttl))) {
      // short in-process copy so the operation that just unlocked does not depend on the socket;
      // `veilform lock` (agent) takes effect for every process within seconds
      this.cache = { key: Buffer.from(key), salt: this.saltOf(s), expires: this.now() + 10_000 };
      return 'agent';
    }
    this.cache = { key: Buffer.from(key), salt: this.saltOf(s), expires: this.now() + (minutes > 0 ? minutes * 60_000 : 10_000) };
    return 'memory';
  }

  /** First use: defines the master password and creates the empty store (0600). */
  create(passphrase: string, minutes = this.o.unlockMinutes): Promise<{ created: true; kdf: string; cached: 'agent' | 'memory' }> {
    return this.mutex.run('v', async () => {
      if (this.exists()) throw new UserError('the encrypted store already exists; unlock it instead', 'exists');
      if (passphrase.length < MIN_MASTER_LENGTH) throw new UserError(`master password too short (min ${MIN_MASTER_LENGTH} characters)`, 'weak_passphrase');
      const { shape, key } = await newPassphraseShape(passphrase, { kdf: this.o.kdf, test: this.o.testKdf });
      await this.io.writeAtomic(this.file, JSON.stringify(shape, null, 1) + '\n', { mode: '0600' });
      const cached = await this.remember(key, shape, minutes);
      wipe(key);
      return { created: true as const, kdf: shape.kdf.name, cached };
    });
  }

  /** Unlocks with the master password (attempts limited, then a growing lockout). */
  async unlock(passphrase: string, minutes = this.o.unlockMinutes): Promise<{ unlocked: true; cached: 'agent' | 'memory' }> {
    const s = await this.shape();
    if (!s) throw new UserError("Veil's encrypted store has no master password yet", 'master_password_not_set');
    const id = this.idFor(s);
    this.limiter.check(id);
    const key = await deriveFileKey(s.kdf, passphrase);
    if (!verifyFileKey(s, key)) {
      wipe(key);
      const left = await this.limiter.fail(id);
      throw new UserError(`wrong master password (${left} attempts left before a lockout)`, 'wrong_key');
    }
    await this.limiter.ok(id);
    const cached = await this.remember(key, s, minutes);
    wipe(key);
    return { unlocked: true, cached };
  }

  /** Forgets the key in this process and, when running, in the session agent. */
  lock(): void {
    if (this.cache) wipe(this.cache.key);
    this.cache = undefined;
  }

  async lockEverywhere(): Promise<boolean> {
    this.lock();
    if (!this.o.agentSocket) return false;
    try {
      return Boolean((await agentRequest(this.o.agentSocket, { op: 'lock' })).ok);
    } catch {
      return false;
    }
  }

  /** Saves the derived key in the OS keychain (opt-in; requires an unlocked store and a working keychain). */
  async saveKeyToKeychain(): Promise<{ saved: string }> {
    const key = await this.key();
    await this.o.keychain.set(this.o.keychainEntry.service, this.o.keychainEntry.account, formatKey(key));
    return { saved: `${this.o.keychainEntry.service}/${this.o.keychainEntry.account}` };
  }

  async forgetKeychainKey(): Promise<boolean> {
    return this.o.keychain.delete(this.o.keychainEntry.service, this.o.keychainEntry.account);
  }

  /** New master password: every entry is re-encrypted under a key derived from it. */
  changePassword(current: string, next: string): Promise<{ changed: true; entries: number }> {
    return this.mutex.run('v', async () => {
      const s = await this.shape();
      if (!s) throw new UserError("Veil's encrypted store has no master password yet", 'master_password_not_set');
      if (next.length < MIN_MASTER_LENGTH) throw new UserError(`master password too short (min ${MIN_MASTER_LENGTH} characters)`, 'weak_passphrase');
      const old = await deriveFileKey(s.kdf, current);
      if (!verifyFileKey(s, old)) throw new UserError('wrong master password', 'wrong_key');
      const fresh = await newPassphraseShape(next, { kdf: this.o.kdf, test: this.o.testKdf });
      const shape = reencryptShape(s, old, fresh);
      await this.io.writeAtomic(this.file, JSON.stringify(shape, null, 1) + '\n', { mode: '0600' });
      await this.lockEverywhere();
      await this.remember(fresh.key, shape, this.o.unlockMinutes);
      wipe(old, fresh.key);
      return { changed: true as const, entries: Object.keys(shape.entries).length };
    });
  }

  async status(): Promise<LocalVaultStatus> {
    const s = await this.shape().catch(() => undefined);
    if (!s) return { path: this.file, exists: this.exists(), unlocked: false };
    const k = await this.tryKey(s);
    let permissionsOk: boolean | undefined;
    if (process.platform !== 'win32') permissionsOk = (statSync(this.file).mode & 0o077) === 0;
    return { path: this.file, exists: true, unlocked: Boolean(k), via: k?.via, kdf: s.kdf.name, entries: Object.keys(s.entries).length, permissions_ok: permissionsOk };
  }

  /** A SecretStore view of this file for destination `id` (entries are namespaced by the caller). */
  storeFor(id: string): EncryptedFileStore {
    return new EncryptedFileStore(id, this.file, async () => ({ kind: 'derived', key: await this.key() }));
  }
}
