import { describe, expect, it } from 'vitest';
import { Redactor, SensitiveRegistry, variantsOf } from '../src/redact.js';
import { prng, randomSecret } from './helpers.js';

const SECRET = 'sk_live_51Hx"q/+=ñ$`tok';

describe('Redactor', () => {
  const r = new Redactor([{ label: 'stripe', value: SECRET }]);

  it('removes the raw value', () => {
    expect(r.redact(`key=${SECRET}!`)).toBe('key=[REDACTED:stripe]!');
  });

  it.each([
    ['base64', Buffer.from(SECRET).toString('base64')],
    ['base64 without padding', Buffer.from(SECRET).toString('base64').replace(/=+$/, '')],
    ['base64url', Buffer.from(SECRET).toString('base64url')],
    ['hex', Buffer.from(SECRET).toString('hex')],
    ['HEX', Buffer.from(SECRET).toString('hex').toUpperCase()],
    ['url-encoded', encodeURIComponent(SECRET)],
    ['form-encoded', encodeURIComponent(SECRET).replace(/%20/g, '+')],
    ['json-escaped', JSON.stringify(SECRET).slice(1, -1)],
    ['double json-escaped', JSON.stringify(JSON.stringify(SECRET)).slice(1, -1)],
    ['shell double-quote escaped', SECRET.replace(/(["\\$`])/g, '\\$1')],
    ['html-escaped', SECRET.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;')],
  ])('removes the %s variant', (_n, variant) => {
    const out = r.redact(`before ${variant} after`);
    expect(out).not.toContain(variant);
    expect(out).toContain('[REDACTED:stripe]');
  });

  it('removes the secret inside HTTP Basic auth (base64 at any byte offset)', () => {
    for (const user of ['', 'a', 'ab', 'abc', 'user', 'admin:']) {
      const header = Buffer.from(`${user}:${SECRET}`).toString('base64');
      const out = r.redact(`Authorization: Basic ${header}`);
      expect(r.contains(out)).toBe(false);
      expect(out).toContain('[REDACTED:stripe]');
    }
  });

  it('removes a trailing partial secret when output was truncated', () => {
    const out = r.redact(`token: ${SECRET.slice(0, 10)}`, { truncated: true });
    expect(out).not.toContain(SECRET.slice(0, 10));
    expect(out).toContain('[REDACTED:stripe]');
  });

  it('redacts each long line of multi-line secrets (PEM)', () => {
    const pem = '-----BEGIN KEY-----\nMIIBVgIBADANBgkqhkiG9w0BAQEFAASC\nAUAwggE8AgEAAkEAq7BFUpkGp3+Xq\n-----END KEY-----';
    const rr = new Redactor([{ label: 'pem', value: pem }]);
    const out = rr.redact('line: AUAwggE8AgEAAkEAq7BFUpkGp3+Xq');
    expect(out).not.toContain('AUAwggE8AgEAAkEAq7BFUpkGp3+Xq');
  });

  it('property: no variant survives redaction for random secrets in random surroundings', () => {
    const rnd = prng(42);
    for (let i = 0; i < 300; i++) {
      const secret = randomSecret(rnd);
      const red = new Redactor([{ label: 's', value: secret }]);
      const variants = variantsOf(secret);
      const v = variants[Math.floor(rnd() * variants.length)]!;
      const text = `xx${'\n'.repeat(Math.floor(rnd() * 2))}${v} yy ${secret}`;
      const out = red.redact(text);
      expect(red.contains(out), `seed iteration ${i}`).toBe(false);
    }
  });

  it('SensitiveRegistry scrubs everything that was registered', () => {
    const reg = new SensitiveRegistry();
    reg.add('a', 'first-secret-value');
    reg.add('b', 'second-secret-value');
    const out = reg.scrub(JSON.stringify({ x: 'first-secret-value', y: Buffer.from('second-secret-value').toString('base64') }));
    expect(out).not.toContain('first-secret-value');
    expect(reg.contains(out)).toBe(false);
  });
});
