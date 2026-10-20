import * as nodeCrypto from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { b64, combineKek, deriveFromPassphrase, hasArgon2, hkdf, newKdfParams, open, seal, unb64 } from '../src/crypto/primitives.js';
import { sigv4 } from '../src/sync/targets.js';

const hex = (s: string) => Buffer.from(s, 'hex');

describe('known-answer vectors', () => {
  it('AES-256-GCM (McGrew-Viega test case 14) through our open() framing', () => {
    const key = Buffer.alloc(32);
    const sealed = b64(Buffer.concat([Buffer.alloc(12), hex('cea7403d4d606b6e074ec5d3baf39d18'), hex('d0d1c8a799996bf0265b98b5d48ab919')]));
    expect(open(key, sealed, '').equals(Buffer.alloc(16))).toBe(true);
  });

  it('scrypt (RFC 7914 §12, third vector; first 32 bytes)', async () => {
    const k = await deriveFromPassphrase('pleaseletmein', { alg: 'scrypt', salt: b64(Buffer.from('SodiumChloride')), N: 16384, r: 8, p: 1 });
    expect(k.toString('hex')).toBe('7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2');
  });

  it.skipIf(!hasArgon2())('argon2id (RFC 9106 §5.3) from node:crypto', async () => {
    const argon2 = (nodeCrypto as unknown as { argon2: (a: string, p: object, cb: (e: Error | null, k: Buffer) => void) => void }).argon2;
    const k = await new Promise<Buffer>((res, rej) =>
      argon2('argon2id', { message: Buffer.alloc(32, 1), nonce: Buffer.alloc(16, 2), secret: Buffer.alloc(8, 3), associatedData: Buffer.alloc(12, 4), parallelism: 4, tagLength: 32, memory: 32, passes: 3 }, (e, key) => (e ? rej(e) : res(key))),
    );
    expect(Buffer.from(k).toString('hex')).toBe('0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659');
  });

  it('HKDF-SHA256 (RFC 5869 test case 1)', async () => {
    const okm = await hkdf(Buffer.alloc(22, 0x0b), hex('000102030405060708090a0b0c'), hex('f0f1f2f3f4f5f6f7f8f9'), 42);
    expect(okm.toString('hex')).toBe('3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865');
  });

  it('AWS SigV4 (S3 documentation example: GET /test.txt with Range)', () => {
    const h = sigv4({
      method: 'GET',
      url: new URL('https://examplebucket.s3.amazonaws.com/test.txt'),
      region: 'us-east-1',
      service: 's3',
      accessKey: 'AKIAIOSFODNN7EXAMPLE',
      secretKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
      headers: { range: 'bytes=0-9' },
      payloadHash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      date: new Date('2013-05-24T00:00:00Z'),
    });
    expect(h.authorization).toBe(
      'AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41',
    );
  });
});

describe('AEAD framing and KDF guards', () => {
  it('unique nonces, AAD binding, bit flips and truncation fail', () => {
    const key = nodeCrypto.randomBytes(32);
    const a = seal(key, 'value', 'ctx');
    const b = seal(key, 'value', 'ctx');
    expect(a).not.toBe(b);
    expect(open(key, a, 'ctx').toString()).toBe('value');
    expect(() => open(key, a, 'other')).toThrow(/authentication failed/);
    const raw = unb64(a);
    for (let i = 0; i < raw.length; i++) {
      const c = Buffer.from(raw);
      c[i]! ^= 1;
      expect(() => open(key, b64(c), 'ctx')).toThrow();
    }
    expect(() => open(key, b64(raw.subarray(0, raw.length - 1)), 'ctx')).toThrow();
    expect(() => open(key, b64(raw.subarray(0, 20)), 'ctx')).toThrow();
  });

  it('rejects downgraded or absurd KDF parameters from a hostile header', async () => {
    const salt = b64(Buffer.alloc(16, 7));
    await expect(deriveFromPassphrase('x', { alg: 'scrypt', salt, N: 1024, r: 8, p: 1 })).rejects.toThrow(/range/);
    await expect(deriveFromPassphrase('x', { alg: 'scrypt', salt, N: 1 << 24, r: 8, p: 1 })).rejects.toThrow(/range/);
    await expect(deriveFromPassphrase('x', { alg: 'argon2id', salt, m: 8, t: 1, p: 1 })).rejects.toThrow(/range/);
    await expect(deriveFromPassphrase('x', { alg: 'scrypt', salt: b64(Buffer.alloc(4)), N: 16384, r: 8, p: 1 })).rejects.toThrow(/salt/);
  });

  it('combined KEK needs both factors', async () => {
    const p = await deriveFromPassphrase('correct horse', newKdfParams('scrypt', { test: true }));
    const f = nodeCrypto.randomBytes(32);
    const both = await combineKek(p, f, 'x');
    expect(both.equals(await combineKek(p, undefined, 'x'))).toBe(false);
    expect(both.equals(await combineKek(undefined, f, 'x'))).toBe(false);
    expect(both.equals(await combineKek(p, f, 'y'))).toBe(false);
    expect(both.equals(await combineKek(p, f, 'x'))).toBe(true);
  });
});
