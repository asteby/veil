import { createCipheriv, createDecipheriv, randomBytes, scrypt as scryptCb, type ScryptOptions } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { checkKdfParams, deriveFromPassphrase, newKdfParams } from '../crypto/primitives.js';
import { LocalFileIO } from '../fileio.js';
import { expandHome, KeyedMutex, UserError } from '../util.js';
import type { PutResult, SecretStore } from './types.js';

const scrypt = (pw: string, salt: Buffer, len: number, o: ScryptOptions) =>
  new Promise<Buffer>((res, rej) => scryptCb(pw, salt, len, o, (e, k) => (e ? rej(e) : res(k))));

/**
 * Encrypted JSON file. Each entry is AES-256-GCM encrypted with the entry name as
 * associated data (entries cannot be swapped). The key is either derived from a
 * passphrase with scrypt (N=2^17, r=8, p=1) or argon2id (Veil's local store, created by
 * `LocalVault`), or is a random 32-byte key held in the OS keychain. With `derived` key
 * material the caller supplies the already-derived key (kept unlocked in memory / in the
 * session agent), so the passphrase itself is not needed on every access.
 *
 * Deviation from the suggested age/libsodium: neither was available offline; Node's
 * built-in OpenSSL AES-GCM + scrypt are audited primitives and add no dependency.
 */
interface Entry {
  iv: string;
  ct: string;
  tag: string;
}
type FileKdf =
  | { name: 'scrypt'; salt: string; N: number; r: number; p: number }
  /** salt is base64url (primitives.ts); m KiB, t passes, p lanes */
  | { name: 'argon2id'; salt: string; m: number; t: number; p: number }
  | { name: 'raw' };
export interface FileShape {
  v: 1;
  kdf: FileKdf;
  check: Entry; // encrypts a constant: detects a wrong passphrase
  entries: Record<string, Entry>;
}

export type KeyMaterial = { kind: 'passphrase'; passphrase: string } | { kind: 'raw'; key: Buffer } | { kind: 'derived'; key: Buffer };
export type KeyProvider = () => Promise<KeyMaterial>;

const SCRYPT = { N: 1 << 17, r: 8, p: 1 };
const CHECK = 'veilform:v1';

function enc(key: Buffer, plaintext: string, aad: string): Entry {
  const iv = randomBytes(12);
  const c = createCipheriv('aes-256-gcm', key, iv);
  c.setAAD(Buffer.from(aad));
  const ct = Buffer.concat([c.update(plaintext, 'utf8'), c.final()]);
  return { iv: iv.toString('base64'), ct: ct.toString('base64'), tag: c.getAuthTag().toString('base64') };
}

function dec(key: Buffer, e: Entry, aad: string): string {
  const d = createDecipheriv('aes-256-gcm', key, Buffer.from(e.iv, 'base64'));
  d.setAAD(Buffer.from(aad));
  d.setAuthTag(Buffer.from(e.tag, 'base64'));
  return Buffer.concat([d.update(Buffer.from(e.ct, 'base64')), d.final()]).toString('utf8');
}

export class EncryptedFileStore implements SecretStore {
  readonly type = 'encrypted-file';
  readonly readable = true;
  private readonly io = new LocalFileIO();
  private readonly mutex = new KeyedMutex();
  private cachedKey?: { salt: string; key: Buffer };

  constructor(
    readonly id: string,
    private readonly file: string,
    private readonly keyProvider: KeyProvider,
    private readonly scryptParams = SCRYPT,
  ) {}

  private load(): Promise<FileShape | undefined> {
    return readEncryptedFile(expandHome(this.file));
  }

  /** Entry names (not secret; the index already lists them). */
  async names(): Promise<string[]> {
    return Object.keys((await this.load())?.entries ?? {});
  }

  private async keyFor(shape: FileShape): Promise<Buffer> {
    const km = await this.keyProvider();
    let key: Buffer;
    if (shape.kdf.name === 'raw') {
      if (km.kind !== 'raw') throw new UserError('encrypted-file expects a raw key', 'key_mismatch');
      key = km.key;
    } else if (km.kind === 'derived') {
      key = km.key;
    } else if (shape.kdf.name === 'argon2id') {
      if (km.kind !== 'passphrase') throw new UserError('encrypted-file expects a passphrase', 'key_mismatch');
      key = await deriveFileKey(shape.kdf, km.passphrase);
    } else {
      if (km.kind !== 'passphrase') throw new UserError('encrypted-file expects a passphrase', 'key_mismatch');
      if (this.cachedKey?.salt === shape.kdf.salt) key = this.cachedKey.key;
      else {
        const { N, r, p } = shape.kdf;
        key = await scrypt(km.passphrase, Buffer.from(shape.kdf.salt, 'base64'), 32, { N, r, p, maxmem: 256 * N * r });
        this.cachedKey = { salt: shape.kdf.salt, key };
      }
    }
    if (!verifyFileKey(shape, key)) throw new UserError('cannot decrypt store: wrong passphrase/key', 'wrong_key');
    return key;
  }

  private async init(): Promise<{ shape: FileShape; key: Buffer }> {
    const km = await this.keyProvider();
    let shape: FileShape;
    let key: Buffer;
    if (km.kind === 'derived') throw new UserError('encrypted store has not been created yet', 'master_password_not_set');
    if (km.kind === 'raw') {
      key = km.key;
      shape = { v: 1, kdf: { name: 'raw' }, check: enc(key, CHECK, '__check__'), entries: {} };
    } else {
      if (km.passphrase.length < 8) throw new UserError('passphrase too short (min 8 chars)', 'weak_passphrase');
      const salt = randomBytes(16).toString('base64');
      const { N, r, p } = this.scryptParams;
      key = await scrypt(km.passphrase, Buffer.from(salt, 'base64'), 32, { N, r, p, maxmem: 256 * N * r });
      this.cachedKey = { salt, key };
      shape = { v: 1, kdf: { name: 'scrypt', salt, N, r, p }, check: enc(key, CHECK, '__check__'), entries: {} };
    }
    return { shape, key };
  }

  private save(shape: FileShape): Promise<void> {
    return this.io.writeAtomic(expandHome(this.file), JSON.stringify(shape, null, 1) + '\n', { mode: '0600' });
  }

  put(name: string, value: string): Promise<PutResult> {
    return this.mutex.run('f', async () => {
      const existing = await this.load();
      const { shape, key } = existing ? { shape: existing, key: await this.keyFor(existing) } : await this.init();
      const action = shape.entries[name] ? 'updated' : 'created';
      shape.entries[name] = enc(key, value, name);
      await this.save(shape);
      return { action };
    });
  }

  async get(name: string): Promise<string | undefined> {
    const shape = await this.load();
    const e = shape?.entries[name];
    if (!shape || !e) return undefined;
    return dec(await this.keyFor(shape), e, name);
  }

  delete(name: string): Promise<boolean> {
    return this.mutex.run('f', async () => {
      const shape = await this.load();
      if (!shape?.entries[name]) return false;
      await this.keyFor(shape); // require the key to modify
      delete shape.entries[name];
      await this.save(shape);
      return true;
    });
  }

  describe(): string {
    return `encrypted file ${expandHome(this.file)}`;
  }
}

// ------------------------------------------------------------------ helpers shared with LocalVault

export async function readEncryptedFile(file: string): Promise<FileShape | undefined> {
  let raw: string;
  try {
    raw = await readFile(file, 'utf8');
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
    throw new UserError('cannot read encrypted store', 'invalid_store');
  }
  let parsed: FileShape;
  try {
    parsed = JSON.parse(raw) as FileShape;
  } catch {
    throw new UserError('encrypted store is not valid JSON', 'invalid_store');
  }
  if (parsed.v !== 1) throw new UserError('unsupported encrypted-file version', 'invalid_store');
  return parsed;
}

/** Derives the file key from a passphrase using the KDF recorded in the header (bounded parameters). */
export async function deriveFileKey(kdf: FileKdf, passphrase: string): Promise<Buffer> {
  if (kdf.name === 'raw') throw new UserError('this store uses a raw key, not a passphrase', 'key_mismatch');
  if (kdf.name === 'argon2id') return deriveFromPassphrase(passphrase, { alg: 'argon2id', salt: kdf.salt, m: kdf.m, t: kdf.t, p: kdf.p });
  checkKdfParams({ alg: 'scrypt', salt: Buffer.from(kdf.salt, 'base64').toString('base64url'), N: kdf.N, r: kdf.r, p: kdf.p });
  return scrypt(passphrase, Buffer.from(kdf.salt, 'base64'), 32, { N: kdf.N, r: kdf.r, p: kdf.p, maxmem: 256 * kdf.N * kdf.r + 1024 * 1024 });
}

export function verifyFileKey(shape: FileShape, key: Buffer): boolean {
  try {
    return dec(key, shape.check, '__check__') === CHECK;
  } catch {
    return false;
  }
}

/** New empty store protected by a passphrase (argon2id when available, else scrypt). Returns the shape and its key. */
export async function newPassphraseShape(passphrase: string, opts: { kdf?: 'argon2id' | 'scrypt'; test?: boolean } = {}): Promise<{ shape: FileShape; key: Buffer }> {
  const k = newKdfParams(opts.kdf, { test: opts.test });
  const kdf: FileKdf = k.alg === 'argon2id' ? { name: 'argon2id', salt: k.salt, m: k.m, t: k.t, p: k.p } : { name: 'scrypt', salt: Buffer.from(k.salt, 'base64url').toString('base64'), N: k.N, r: k.r, p: k.p };
  const key = await deriveFileKey(kdf, passphrase);
  return { shape: { v: 1, kdf, check: enc(key, CHECK, '__check__'), entries: {} }, key };
}

/** Re-encrypts every entry under a new key (master password change). */
export function reencryptShape(shape: FileShape, oldKey: Buffer, next: { shape: FileShape; key: Buffer }): FileShape {
  const entries: Record<string, Entry> = {};
  for (const [name, e] of Object.entries(shape.entries)) {
    const plain = dec(oldKey, e, name);
    entries[name] = enc(next.key, plain, name);
  }
  return { ...next.shape, entries };
}
