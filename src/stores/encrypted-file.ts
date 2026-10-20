import { createCipheriv, createDecipheriv, randomBytes, scrypt as scryptCb, type ScryptOptions } from 'node:crypto';

const scrypt = (pw: string, salt: Buffer, len: number, o: ScryptOptions) =>
  new Promise<Buffer>((res, rej) => scryptCb(pw, salt, len, o, (e, k) => (e ? rej(e) : res(k))));
import { LocalFileIO } from '../fileio.js';
import { expandHome, KeyedMutex, UserError } from '../util.js';
import type { PutResult, SecretStore } from './types.js';

/**
 * Encrypted JSON file. Each entry is AES-256-GCM encrypted with the entry name as
 * associated data (entries cannot be swapped). The key is either derived from a
 * passphrase with scrypt (N=2^17, r=8, p=1) or is a random 32-byte key held in the
 * OS keychain.
 *
 * Deviation from the suggested age/libsodium: neither was available offline; Node's
 * built-in OpenSSL AES-GCM + scrypt are audited primitives and add no dependency.
 */
interface Entry {
  iv: string;
  ct: string;
  tag: string;
}
interface FileShape {
  v: 1;
  kdf: { name: 'scrypt'; salt: string; N: number; r: number; p: number } | { name: 'raw' };
  check: Entry; // encrypts a constant: detects a wrong passphrase
  entries: Record<string, Entry>;
}

export type KeyMaterial = { kind: 'passphrase'; passphrase: string } | { kind: 'raw'; key: Buffer };
export type KeyProvider = () => Promise<KeyMaterial>;

const SCRYPT = { N: 1 << 17, r: 8, p: 1 };
const CHECK = 'blindkey:v1';

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

  private async load(): Promise<FileShape | undefined> {
    const raw = await this.io.read(this.file);
    if (!raw) return undefined;
    const parsed = JSON.parse(raw.toString('utf8')) as FileShape;
    if (parsed.v !== 1) throw new UserError('unsupported encrypted-file version', 'invalid_store');
    return parsed;
  }

  private async keyFor(shape: FileShape): Promise<Buffer> {
    const km = await this.keyProvider();
    let key: Buffer;
    if (shape.kdf.name === 'raw') {
      if (km.kind !== 'raw') throw new UserError('encrypted-file expects a raw key', 'key_mismatch');
      key = km.key;
    } else {
      if (km.kind !== 'passphrase') throw new UserError('encrypted-file expects a passphrase', 'key_mismatch');
      if (this.cachedKey?.salt === shape.kdf.salt) key = this.cachedKey.key;
      else {
        const { N, r, p } = shape.kdf;
        key = await scrypt(km.passphrase, Buffer.from(shape.kdf.salt, 'base64'), 32, { N, r, p, maxmem: 256 * N * r });
        this.cachedKey = { salt: shape.kdf.salt, key };
      }
    }
    try {
      if (dec(key, shape.check, '__check__') !== CHECK) throw new Error('bad');
    } catch {
      throw new UserError('cannot decrypt store: wrong passphrase/key', 'wrong_key');
    }
    return key;
  }

  private async init(): Promise<{ shape: FileShape; key: Buffer }> {
    const km = await this.keyProvider();
    let shape: FileShape;
    let key: Buffer;
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
    return this.io.writeAtomic(this.file, JSON.stringify(shape, null, 1) + '\n', { mode: '0600' });
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
