import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { readFileSync, statSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { parseConfig } from '../src/config.js';
import type { RunOptions, RunResult, Runner } from '../src/proc.js';
import { EncryptedFileStore } from '../src/stores/encrypted-file.js';
import { EnvFileStore } from '../src/stores/file-stores.js';
import { HttpApiStore } from '../src/stores/http-api.js';
import { KeychainStore, MacSecurityBackend, SecretToolBackend } from '../src/stores/keychain.js';
import { LocalFileIO } from '../src/fileio.js';
import { memKeychain, tmpDir } from './helpers.js';

const SECRET = 'APP_USR-77"$`\\ñ-secret';

function fakeRunner(handler: (argv: string[], o: RunOptions) => Partial<RunResult>): Runner & { calls: { argv: string[]; stdin?: string }[] } {
  const calls: { argv: string[]; stdin?: string }[] = [];
  const fn = (async (argv: string[], o: RunOptions = {}) => {
    calls.push({ argv, stdin: o.stdin?.toString() });
    return { code: 0, signal: null, stdout: Buffer.alloc(0), stderr: Buffer.alloc(0), stdoutTruncated: false, stderrTruncated: false, timedOut: false, ...handler(argv, o) };
  }) as Runner & { calls: typeof calls };
  fn.calls = calls;
  return fn;
}

describe('keychain backends never put the value in argv', () => {
  it('secret-tool: value only on stdin', async () => {
    const stored = new Map<string, string>();
    const runner = fakeRunner((argv, o) => {
      if (argv[1] === 'store') stored.set(argv.at(-1)!, o.stdin!.toString());
      if (argv[1] === 'lookup') return stored.has(argv.at(-1)!) ? { stdout: Buffer.from(stored.get(argv.at(-1)!)!) } : { code: 1 };
      return {};
    });
    const store = new KeychainStore('local', 'svc', new SecretToolBackend(runner));
    expect((await store.put('MP_TOKEN', SECRET)).action).toBe('created');
    expect(await store.get('MP_TOKEN')).toBe(SECRET);
    expect((await store.put('MP_TOKEN', SECRET)).action).toBe('updated');
    for (const c of runner.calls) expect(c.argv.join(' ')).not.toContain(SECRET);
    expect(runner.calls.some((c) => c.stdin === SECRET)).toBe(true);
  });

  it('macOS security: value only inside the stdin command of `security -i`', async () => {
    const runner = fakeRunner(() => ({ code: 44 }));
    await new MacSecurityBackend(runner).set('svc', 'acct', 'a"b\\c').catch(() => undefined);
    const call = runner.calls[0]!;
    expect(call.argv).toEqual(['security', '-i']);
    expect(call.stdin).toContain('-w "a\\"b\\\\c"');
  });
});

describe('encrypted-file store', () => {
  const dir = tmpDir();
  const file = path.join(dir, 's.enc');
  const fast = { N: 1 << 10, r: 8, p: 1 };

  it('encrypts at rest, roundtrips, and rejects a wrong passphrase', async () => {
    const s = new EncryptedFileStore('v', file, async () => ({ kind: 'passphrase', passphrase: 'correct horse' }), fast);
    expect((await s.put('A', SECRET)).action).toBe('created');
    expect(await s.get('A')).toBe(SECRET);
    const raw = readFileSync(file, 'utf8');
    expect(raw).not.toContain(SECRET);
    expect(raw).not.toContain(Buffer.from(SECRET).toString('base64'));
    expect(statSync(file).mode & 0o777).toBe(0o600);
    const wrong = new EncryptedFileStore('v', file, async () => ({ kind: 'passphrase', passphrase: 'wrong passphrase' }), fast);
    await expect(wrong.get('A')).rejects.toThrow(/wrong passphrase/);
  });

  it('detects entries swapped between names (AAD)', async () => {
    const s = new EncryptedFileStore('v', file, async () => ({ kind: 'passphrase', passphrase: 'correct horse' }), fast);
    await s.put('B', 'other-value');
    const j = JSON.parse(readFileSync(file, 'utf8'));
    [j.entries.A, j.entries.B] = [j.entries.B, j.entries.A];
    writeFileSync(file, JSON.stringify(j));
    await expect(s.get('A')).rejects.toThrow();
  });

  it('works with a random key kept in the (mock) keychain', async () => {
    const kc = memKeychain();
    const f2 = path.join(dir, 'k.enc');
    const provider = async () => {
      let hex = await kc.get('svc', 'k');
      if (!hex) {
        hex = 'ab'.repeat(32);
        await kc.set('svc', 'k', hex);
      }
      return { kind: 'raw' as const, key: Buffer.from(hex, 'hex') };
    };
    const s = new EncryptedFileStore('v', f2, provider);
    await s.put('X', SECRET);
    expect(await s.get('X')).toBe(SECRET);
    expect(await s.delete('X')).toBe(true);
    expect(await s.get('X')).toBeUndefined();
  });
});

describe('env-file store (local)', () => {
  it('writes 0600 atomically and preserves the rest of the file', async () => {
    const dir = tmpDir();
    const f = path.join(dir, '.env');
    writeFileSync(f, '# keep me\nOTHER=1\n');
    const s = new EnvFileStore('e', new LocalFileIO(), f, { mode: '0600' });
    expect((await s.put('MP_ACCESS_TOKEN', SECRET)).action).toBe('created');
    expect(readFileSync(f, 'utf8')).toContain('# keep me\nOTHER=1\n');
    expect(await s.get('MP_ACCESS_TOKEN')).toBe(SECRET);
    expect(statSync(f).mode & 0o777).toBe(0o600);
  });
});

// ------------------------------------------------------------------ http-api adapters against simulated servers

interface Seen {
  method: string;
  url: string;
  headers: http.IncomingHttpHeaders;
  body: string;
}

function mockServer(handler: (s: Seen, res: http.ServerResponse) => void) {
  const seen: Seen[] = [];
  const srv = http.createServer((req, res) => {
    let body = '';
    req.on('data', (d) => (body += d));
    req.on('end', () => {
      const s = { method: req.method!, url: req.url!, headers: req.headers, body };
      seen.push(s);
      handler(s, res);
    });
  });
  return {
    seen,
    srv,
    async start() {
      await new Promise<void>((r) => srv.listen(0, '127.0.0.1', r));
      return `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
    },
    stop: () => new Promise<void>((r) => srv.close(() => r())),
  };
}

function json(res: http.ServerResponse, status: number, body: unknown) {
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(JSON.stringify(body));
}

const TOKEN = 'remote-store-bootstrap-token-123';
const resolveLocal = async () => TOKEN;

function apiStore(adapter: string, base: string, options: Record<string, unknown>, auth: Record<string, unknown> = { tokenRef: 'local:t', scheme: 'bearer' }) {
  const cfg = parseConfig({ destinations: { r: { type: 'http-api', adapter, baseUrl: base, allowInsecureLoopback: true, auth, options } } });
  return new HttpApiStore('r', cfg.destinations.r as never, resolveLocal);
}

describe('http-api remote stores (simulated servers)', () => {
  const kv = new Map<string, string>();
  const vault = mockServer((s, res) => {
    const m = /^\/v1\/secret\/(data|metadata)\/(.+)$/.exec(s.url);
    if (s.headers['x-vault-token'] !== TOKEN) return json(res, 403, { errors: ['permission denied'] });
    if (!m) return json(res, 404, {});
    const key = decodeURIComponent(m[2]!);
    if (s.method === 'GET') return kv.has(key) ? json(res, 200, { data: { data: { value: kv.get(key) } } }) : json(res, 404, {});
    if (s.method === 'POST') {
      kv.set(key, JSON.parse(s.body).data.value);
      return json(res, 200, {});
    }
    if (s.method === 'DELETE') return kv.delete(key) ? json(res, 204, {}) : json(res, 404, {});
    json(res, 405, {});
  });
  let vaultUrl = '';
  beforeAll(async () => {
    vaultUrl = await vault.start();
  });
  afterAll(async () => vault.stop());

  it('vault-kv2: write, read, delete; token in header from the local store; value never in errors', async () => {
    const s = apiStore('vault-kv2', vaultUrl, {}, { tokenRef: 'local:vault_token', scheme: 'header', header: 'X-Vault-Token' });
    expect((await s.put('MP_TOKEN', SECRET)).action).toBe('created');
    expect(await s.get('MP_TOKEN')).toBe(SECRET);
    expect((await s.put('MP_TOKEN', SECRET + '2')).action).toBe('updated');
    expect(await s.delete('MP_TOKEN')).toBe(true);
    expect(await s.get('MP_TOKEN')).toBeUndefined();
    const bad = apiStore('vault-kv2', vaultUrl, {}, { tokenRef: 'x', scheme: 'header', header: 'X-Other' });
    const err = await bad.put('K', SECRET).catch((e: Error) => e);
    expect(String((err as Error).message)).toMatch(/HTTP 403/);
    expect(String((err as Error).message)).not.toContain(SECRET);
  });

  it('requires TLS unless loopback is explicitly allowed, and enforces the host allowlist', () => {
    const mk = (baseUrl: string, extra: Record<string, unknown> = {}) => () =>
      new HttpApiStore('r', parseConfig({ destinations: { r: { type: 'http-api', adapter: 'vault-kv2', baseUrl, ...extra } } }).destinations.r as never, resolveLocal);
    expect(mk('http://vault.example.com')).toThrow(/TLS/);
    expect(mk('http://127.0.0.1:8200')).toThrow(/TLS/);
    expect(mk('https://vault.example.com', { allowedHosts: ['other.example.com'] })).toThrow(/allowlist/);
    expect(mk('https://vault.example.com')).not.toThrow();
  });

  it('infisical: POST to create, PATCH to update, reads secretValue', async () => {
    const data = new Map<string, string>();
    const srv = mockServer((s, res) => {
      const m = /^\/api\/v3\/secrets\/raw\/([^?]+)/.exec(s.url);
      const key = decodeURIComponent(m![1]!);
      if (s.headers.authorization !== `Bearer ${TOKEN}`) return json(res, 401, {});
      if (s.method === 'GET') {
        if (!s.url.includes('workspaceId=ws1') || !s.url.includes('environment=prod')) return json(res, 400, {});
        return data.has(key) ? json(res, 200, { secret: { secretValue: data.get(key) } }) : json(res, 404, {});
      }
      const b = JSON.parse(s.body);
      if (s.method === 'POST' || s.method === 'PATCH') {
        data.set(key, b.secretValue);
        return json(res, 200, {});
      }
      if (s.method === 'DELETE') return data.delete(key) ? json(res, 200, {}) : json(res, 404, {});
    });
    const base = await srv.start();
    const s = apiStore('infisical', base, { workspaceId: 'ws1', environment: 'prod' });
    expect((await s.put('STRIPE_KEY', SECRET)).action).toBe('created');
    expect((await s.put('STRIPE_KEY', SECRET)).action).toBe('updated');
    expect(srv.seen.map((x) => x.method)).toEqual(['GET', 'POST', 'GET', 'PATCH']);
    expect(await s.get('STRIPE_KEY')).toBe(SECRET);
    expect(await s.delete('STRIPE_KEY')).toBe(true);
    await srv.stop();
  });

  it('1password-connect: finds by title, creates and updates the concealed field', async () => {
    const items = new Map<string, { id: string; title: string; fields: { id?: string; label?: string; value?: string }[] }>();
    const srv = mockServer((s, res) => {
      if (s.headers.authorization !== `Bearer ${TOKEN}`) return json(res, 401, {});
      if (s.method === 'GET' && s.url.startsWith('/v1/vaults/v1/items?filter=')) {
        const title = /title eq "(.*)"/.exec(decodeURIComponent(s.url.split('filter=')[1]!))![1];
        return json(res, 200, [...items.values()].filter((i) => i.title === title).map((i) => ({ id: i.id })));
      }
      const m = /^\/v1\/vaults\/v1\/items(?:\/(.+))?$/.exec(s.url)!;
      if (s.method === 'GET') return json(res, 200, items.get(m[1]!));
      if (s.method === 'POST') {
        const b = JSON.parse(s.body);
        const id = `it${items.size + 1}`;
        items.set(id, { id, title: b.title, fields: b.fields });
        return json(res, 200, { id });
      }
      if (s.method === 'PUT') {
        items.set(m[1]!, JSON.parse(s.body));
        return json(res, 200, {});
      }
      if (s.method === 'DELETE') return json(res, items.delete(m[1]!) ? 204 : 404, {});
    });
    const base = await srv.start();
    const s = apiStore('1password-connect', base, { vaultId: 'v1' });
    expect((await s.put('MP_TOKEN', SECRET)).action).toBe('created');
    expect(await s.get('MP_TOKEN')).toBe(SECRET);
    expect((await s.put('MP_TOKEN', 'second-value')).action).toBe('updated');
    expect(await s.get('MP_TOKEN')).toBe('second-value');
    expect(await s.delete('MP_TOKEN')).toBe(true);
    await srv.stop();
  });

  it('ops-addon-settings: GET/PUT /api/addons/:key/settings scoped by bearer token', async () => {
    const settings: Record<string, unknown> = { public_key: 'pk' };
    const srv = mockServer((s, res) => {
      if (s.headers.authorization !== `Bearer ${TOKEN}`) return json(res, 401, {});
      if (s.url !== '/api/addons/mercadopago/settings') return json(res, 404, {});
      if (s.method === 'GET') return json(res, 200, { success: true, data: settings });
      Object.assign(settings, JSON.parse(s.body));
      return json(res, 200, { success: true });
    });
    const base = await srv.start();
    const s = apiStore('ops-addon-settings', base, { addon: 'mercadopago' });
    expect((await s.put('access_token', SECRET)).action).toBe('created');
    expect(settings.public_key).toBe('pk');
    expect(await s.get('access_token')).toBe(SECRET);
    expect(await s.delete('access_token')).toBe(true);
    expect(await s.get('access_token')).toBeUndefined();
    await srv.stop();
  });

  it('generic adapter with JSON pointer and body template', async () => {
    const store = new Map<string, string>();
    const srv = mockServer((s, res) => {
      const key = decodeURIComponent(s.url.split('/').pop()!);
      if (s.method === 'GET') return store.has(key) ? json(res, 200, { result: { secret: store.get(key) } }) : json(res, 404, {});
      store.set(key, JSON.parse(s.body).payload.v);
      json(res, 201, {});
    });
    const base = await srv.start();
    const s = apiStore('generic', base + '/api', { read: { method: 'GET', path: '/kv/{name}', pointer: '/result/secret' }, write: { method: 'PUT', path: '/kv/{name}', body: { payload: { v: '{value}', n: '{name}' } } } });
    expect((await s.put('a/b', SECRET)).action).toBe('created');
    expect(srv.seen[0]!.url).toBe('/api/kv/a%2Fb');
    expect(await s.get('a/b')).toBe(SECRET);
    await srv.stop();
  });
});
