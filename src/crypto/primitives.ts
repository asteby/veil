/**
 * Cryptographic building blocks for bundles, shares and encrypted .env files.
 *
 * Only `node:crypto` primitives are used (no hand-rolled crypto):
 *  - AEAD: AES-256-GCM, 96-bit random nonce per encryption, 128-bit tag.
 *  - KDF for passphrases: argon2id (node:crypto >= 24.7) or scrypt.
 *  - Key combination / sub-keys: HKDF-SHA256.
 *  - Whole-structure integrity: HMAC-SHA256.
 *
 * Nonces are random (never counters) and every key encrypts a bounded number of
 * messages (one DEK per secret value / per file), far below the 2^32 limit for
 * random GCM nonces.
 */
import * as nodeCrypto from 'node:crypto';
import { createCipheriv, createDecipheriv, createHmac, hkdf as hkdfCb, randomBytes, scrypt as scryptCb, timingSafeEqual } from 'node:crypto';
import { UserError } from '../util.js';

export const KEY_LEN = 32;
const NONCE_LEN = 12;
const TAG_LEN = 16;

export type KdfParams =
  | { alg: 'argon2id'; salt: string; m: number; t: number; p: number }
  | { alg: 'scrypt'; salt: string; N: number; r: number; p: number };

/** Defaults: argon2id 64 MiB/3 passes (RFC 9106 second recommendation), scrypt N=2^17. */
export const KDF_DEFAULTS = {
  argon2id: { m: 65536, t: 3, p: 1 },
  scrypt: { N: 1 << 17, r: 8, p: 1 },
} as const;

/** Lower bounds accepted when reading a header (an attacker-controlled header must not downgrade the KDF). */
const KDF_MIN = { argon2id: { m: 19456, t: 2 }, scrypt: { N: 1 << 14 } };
/** Upper bounds (a hostile header must not make us allocate gigabytes). */
const KDF_MAX = { argon2id: { m: 1 << 21, t: 10, p: 8 }, scrypt: { N: 1 << 20, r: 16, p: 4 } };

type Argon2Fn = (alg: string, params: Record<string, unknown>, cb: (err: Error | null, key: Buffer) => void) => void;
const argon2Fn = (nodeCrypto as unknown as { argon2?: Argon2Fn }).argon2;

export function hasArgon2(): boolean {
  return typeof argon2Fn === 'function';
}

export function b64(b: Buffer): string {
  return b.toString('base64url');
}

export function unb64(s: string, what = 'field'): Buffer {
  if (typeof s !== 'string' || !/^[A-Za-z0-9_-]*$/.test(s)) throw new UserError(`malformed ${what}`, 'malformed');
  return Buffer.from(s, 'base64url');
}

export function randomKey(): Buffer {
  return randomBytes(KEY_LEN);
}

/** Fresh KDF parameters (new random salt). `test` lowers the cost for unit tests only. */
export function newKdfParams(alg?: 'argon2id' | 'scrypt', opts: { test?: boolean } = {}): KdfParams {
  const a = alg ?? (hasArgon2() ? 'argon2id' : 'scrypt');
  const salt = b64(randomBytes(16));
  if (a === 'argon2id') {
    if (!hasArgon2()) throw new UserError('argon2id is not available in this Node.js version; use scrypt', 'kdf_unavailable');
    return opts.test ? { alg: 'argon2id', salt, m: KDF_MIN.argon2id.m, t: KDF_MIN.argon2id.t, p: 1 } : { alg: 'argon2id', salt, ...KDF_DEFAULTS.argon2id };
  }
  return opts.test ? { alg: 'scrypt', salt, N: KDF_MIN.scrypt.N, r: 8, p: 1 } : { alg: 'scrypt', salt, ...KDF_DEFAULTS.scrypt };
}

export function checkKdfParams(k: KdfParams): void {
  if (k.alg === 'argon2id') {
    if (!(k.m >= KDF_MIN.argon2id.m && k.m <= KDF_MAX.argon2id.m && k.t >= KDF_MIN.argon2id.t && k.t <= KDF_MAX.argon2id.t && k.p >= 1 && k.p <= KDF_MAX.argon2id.p)) throw new UserError('KDF parameters out of the accepted range', 'kdf_params');
  } else if (k.alg === 'scrypt') {
    if (!(k.N >= KDF_MIN.scrypt.N && k.N <= KDF_MAX.scrypt.N && (k.N & (k.N - 1)) === 0 && k.r >= 1 && k.r <= KDF_MAX.scrypt.r && k.p >= 1 && k.p <= KDF_MAX.scrypt.p)) throw new UserError('KDF parameters out of the accepted range', 'kdf_params');
  } else throw new UserError('unknown KDF', 'kdf_params');
  if (unb64(k.salt, 'salt').length < 8) throw new UserError('KDF salt too short', 'kdf_params');
}

/** Derives 32 bytes from a passphrase. Async (libuv thread pool), never blocks the event loop. */
export async function deriveFromPassphrase(passphrase: string, k: KdfParams): Promise<Buffer> {
  checkKdfParams(k);
  const salt = unb64(k.salt, 'salt');
  if (k.alg === 'argon2id') {
    if (!argon2Fn) throw new UserError('argon2id is not available in this Node.js version', 'kdf_unavailable');
    return new Promise((res, rej) =>
      argon2Fn('argon2id', { message: Buffer.from(passphrase.normalize('NFC'), 'utf8'), nonce: salt, parallelism: k.p, tagLength: KEY_LEN, memory: k.m, passes: k.t }, (e, key) => (e ? rej(e) : res(Buffer.from(key)))),
    );
  }
  return new Promise((res, rej) => scryptCb(passphrase.normalize('NFC'), salt, KEY_LEN, { N: k.N, r: k.r, p: k.p, maxmem: 256 * k.N * k.r + 1024 * 1024 }, (e, key) => (e ? rej(e) : res(key))));
}

/** HKDF-SHA256. `info` gives domain separation between sub-keys. */
export function hkdf(ikm: Buffer, salt: Buffer | string, info: Buffer | string, len = KEY_LEN): Promise<Buffer> {
  return new Promise((res, rej) => hkdfCb('sha256', ikm, typeof salt === 'string' ? Buffer.from(salt) : salt, typeof info === 'string' ? Buffer.from(info) : info, len, (e, k) => (e ? rej(e) : res(Buffer.from(k)))));
}

/**
 * Combines a passphrase-derived key with an optional second factor (key file,
 * keychain secret, systemd credential): KEK = HKDF(pk || second, salt, info).
 * Both are needed; knowing one of them gives nothing about the KEK.
 */
export function combineKek(passKey: Buffer | undefined, second: Buffer | undefined, context: string): Promise<Buffer> {
  if (!passKey && !second) throw new UserError('no key material', 'missing_key');
  const parts = [Buffer.from([passKey ? 1 : 0, second ? 1 : 0]), passKey ?? Buffer.alloc(0), second ?? Buffer.alloc(0)];
  return hkdf(Buffer.concat(parts), 'veilform/kek/v1', context);
}

/** AES-256-GCM encrypt. Output: base64url(nonce(12) || ciphertext || tag(16)). `aad` binds the ciphertext to its context (name, version, ids...). */
export function seal(key: Buffer, plaintext: Buffer | string, aad: string): string {
  if (key.length !== KEY_LEN) throw new Error('bad key length');
  const nonce = randomBytes(NONCE_LEN);
  const c = createCipheriv('aes-256-gcm', key, nonce, { authTagLength: TAG_LEN });
  c.setAAD(Buffer.from(aad, 'utf8'));
  const ct = Buffer.concat([c.update(typeof plaintext === 'string' ? Buffer.from(plaintext, 'utf8') : plaintext), c.final()]);
  return b64(Buffer.concat([nonce, ct, c.getAuthTag()]));
}

/** AES-256-GCM decrypt. Throws UserError('tampered') on any authentication failure (no detail). */
export function open(key: Buffer, sealed: string, aad: string, code = 'tampered'): Buffer {
  const raw = unb64(sealed, 'ciphertext');
  if (raw.length < NONCE_LEN + TAG_LEN) throw new UserError('ciphertext truncated', code);
  try {
    const d = createDecipheriv('aes-256-gcm', key, raw.subarray(0, NONCE_LEN), { authTagLength: TAG_LEN });
    d.setAAD(Buffer.from(aad, 'utf8'));
    d.setAuthTag(raw.subarray(raw.length - TAG_LEN));
    return Buffer.concat([d.update(raw.subarray(NONCE_LEN, raw.length - TAG_LEN)), d.final()]);
  } catch {
    throw new UserError('authentication failed (wrong key or modified data)', code);
  }
}

export function hmac(key: Buffer, data: string | Buffer): string {
  return b64(createHmac('sha256', key).update(data).digest());
}

export function hmacEqual(a: string, b: string): boolean {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}

/** Short public identifier of a raw key (not reversible, domain separated). */
export function keyId(key: Buffer): string {
  return createHmac('sha256', 'veilform/key-id/v1').update(key).digest('hex').slice(0, 16);
}

/** Overwrites a buffer holding key material (best effort: JS may have copies). */
export function wipe(...bufs: (Buffer | undefined)[]): void {
  for (const b of bufs) b?.fill(0);
}
