import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import path from 'node:path';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { verifyAuditLog } from '../src/audit.js';
import { b64 } from '../src/crypto/primitives.js';
import { variantsOf } from '../src/redact.js';
import { deriveKek, MANIFEST, packSingle, parseManifest, unpackSingle } from '../src/sync/bundle.js';
import { sigv4 } from '../src/sync/targets.js';
import { makeApp, openPage, post, prng, randomSecret, submit, tmpDir, type TestApp } from './helpers.js';

const PASS = 'correct horse battery staple';

let stderr: string[] = [];
beforeAll(() => {
  vi.spyOn(console, 'error').mockImplementation((...a: unknown[]) => {
    stderr.push(a.join(' '));
  });
});
afterEach(() => {
  stderr = [];
});

function collect(t: TestApp) {
  const responses: string[] = [];
  const call = async (fn: () => unknown) => {
    const r = (await fn()) as Record<string, unknown>;
    responses.push(t.app.safe(r));
    return JSON.parse(responses.at(-1)!) as Record<string, unknown>;
  };
  return { responses, call };
}

/** Runs a tool that may need the person: fills the local page when it returns a url. */
async function person(t: TestApp, r: Record<string, unknown>, values: Record<string, unknown> = {}, extra: Record<string, unknown> = { confirm: true }) {
  if (r.status !== 'awaiting_user') return { result: r, page: undefined };
  const page = await submit(String(r.url), values, extra);
  const w = (await t.app.secretWait({ id: r.request_id })) as Record<string, unknown>;
  return { result: w, page };
}

function expectAbsent(haystacks: string[], needles: string[]) {
  for (const h of haystacks) for (const n of needles) for (const v of variantsOf(n)) expect(h.includes(v), `found ${JSON.stringify(v)}`).toBe(false);
}

function filesUnder(dir: string): string[] {
  if (!existsSync(dir)) return [];
  return readdirSync(dir, { recursive: true, withFileTypes: true })
    .filter((d) => d.isFile())
    .map((d) => readFileSync(path.join(d.parentPath, d.name), 'utf8'));
}

// ------------------------------------------------------------------ simulated HTTP storage

interface Store {
  url: string;
  objects: Map<string, Buffer>;
  bodies: string[];
  urls: string[];
  close(): Promise<void>;
}

async function blobServer(mode: 'http' | 'webdav' | 's3'): Promise<Store> {
  const objects = new Map<string, Buffer>();
  const cols = new Set<string>(['/dav']);
  const bodies: string[] = [];
  const urls: string[] = [];
  const srv = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (d) => chunks.push(d));
    req.on('end', () => {
      const body = Buffer.concat(chunks);
      const u = new URL(req.url!, 'http://x');
      urls.push(`${req.method} ${u.pathname}`);
      if (body.length) bodies.push(body.toString('utf8'));
      const auth = req.headers.authorization ?? '';
      if (mode === 'http' && auth !== 'Bearer tok-http-123') return res.writeHead(401).end();
      if (mode === 'webdav' && auth !== `Basic ${Buffer.from('alice:dav-pass-456').toString('base64')}`) return res.writeHead(401).end();
      if (mode === 's3') {
        const expected = sigv4({ method: req.method!, url: new URL(`http://${req.headers.host}${req.url}`), region: 'auto', service: 's3', accessKey: 'AKIDTEST', secretKey: 's3-secret-789', headers: {}, payloadHash: createHash('sha256').update(body).digest('hex'), date: new Date(Date.parse(String(req.headers['x-amz-date']).replace(/^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z$/, '$1-$2-$3T$4:$5:$6Z'))) });
        if (auth !== expected.authorization || req.headers['x-amz-content-sha256'] !== createHash('sha256').update(body).digest('hex')) return res.writeHead(403).end();
      }
      const p = u.pathname.replace(/\/$/, '');
      if (req.method === 'MKCOL') {
        if (cols.has(p)) return res.writeHead(405).end();
        cols.add(p);
        return res.writeHead(201).end();
      }
      if (req.method === 'PUT') {
        if (mode === 'webdav' && !cols.has(path.posix.dirname(p))) return res.writeHead(409).end();
        objects.set(p, body);
        return res.writeHead(201).end();
      }
      if (req.method === 'GET') {
        const o = objects.get(p);
        return o ? res.writeHead(200).end(o) : res.writeHead(404).end();
      }
      if (req.method === 'DELETE') return res.writeHead(objects.delete(p) ? 204 : 404).end();
      res.writeHead(405).end();
    });
  });
  await new Promise<void>((r) => srv.listen(0, '127.0.0.1', () => r()));
  const port = (srv.address() as AddressInfo).port;
  return { url: `http://127.0.0.1:${port}`, objects, bodies, urls, close: () => new Promise((r) => srv.close(() => r())) };
}

// ------------------------------------------------------------------ export / import

describe('vault bundle: export → import, tampering, rollback, wrong key, rekey', () => {
  const apps: TestApp[] = [];
  afterAll(async () => {
    for (const a of apps) await a.cleanup();
  });
  const mk = (cfg: Record<string, unknown> = {}) => {
    const t = makeApp(cfg);
    apps.push(t);
    return t;
  };

  it('round trip between two devices via a .vfb file; nothing readable in the bundle', async () => {
    const A = mk();
    const B = mk();
    const V1 = 'sk_live_round-trip-value-1';
    const V2 = 'pg://user:p4ss@db/x';
    await A.app.vault.put('local', 'STRIPE_KEY', V1, { tags: ['pay'], project: 'shop' });
    await A.app.vault.put('vault', 'DB_URL', V2);
    const { call, responses } = collect(A);
    const file = path.join(A.home, 'backup.vfb');
    const r = await call(() => A.app.tools.vaultExport({ file }));
    expect(r.status).toBe('awaiting_user');
    const p = await openPage(String(r.url));
    expect(JSON.stringify(p.data.schema)).toContain('passphrase2');
    expect((await post(p, { action: 'submit', values: { passphrase: PASS, passphrase2: 'different passphrase' } })).json.errors).toEqual([{ field: 'passphrase2', code: 'mismatch' }]);
    expect((await post(p, { action: 'submit', values: { passphrase: PASS, passphrase2: PASS } })).json.ok).toBe(true);
    const w = await call(() => A.app.secretWait({ id: r.request_id }));
    expect(w).toMatchObject({ status: 'completed', count: 2, names: ['DB_URL', 'STRIPE_KEY'] });
    const raw = readFileSync(file, 'utf8');
    expectAbsent([raw, ...[...unpackSingle(Buffer.from(raw)).values()].map((b) => b.toString())], [V1, V2, 'STRIPE_KEY', 'DB_URL', 'shop']);

    const rb = collect(B);
    const ir = await rb.call(() => B.app.tools.vaultImport({ file }));
    const { result } = await person(B, ir, { passphrase: PASS });
    expect(result).toMatchObject({ status: 'completed', created: ['DB_URL', 'STRIPE_KEY'] });
    expect(B.keychain.data.get('veilform/STRIPE_KEY')).toBe(V1);
    expect((await B.app.vault.resolve('DB_URL')).value).toBe(V2);
    expect(B.app.vault.meta('STRIPE_KEY')).toMatchObject({ project: 'shop', tags: ['pay'] });
    // second import: everything unchanged, no silent overwrite
    const again = await B.app.sync.importFile(file, async () => PASS);
    expect(again.unchanged.sort()).toEqual(['DB_URL', 'STRIPE_KEY']);
    expectAbsent([...responses, ...rb.responses, readFileSync(path.join(A.home, 'audit.jsonl'), 'utf8'), readFileSync(path.join(B.home, 'audit.jsonl'), 'utf8'), stderr.join('\n'), readFileSync(A.app.sync.stateFile, 'utf8')], [V1, V2, PASS]);
    expect(verifyAuditLog(path.join(B.home, 'audit.jsonl'))).toBe(0);
  });

  it('detects bit flips, swapped/missing objects, edited header, rollback and wrong key', async () => {
    const A = mk();
    await A.app.vault.put('local', 'ONE', 'value-one-1111');
    await A.app.vault.put('local', 'TWO', 'value-two-2222');
    const file = path.join(A.home, 'b.vfb');
    await A.app.sync.exportToFile(file, async () => PASS);
    const files = unpackSingle(readFileSync(file));
    const objs = [...files.keys()].filter((k) => k.startsWith('o/'));
    const write = (m: Map<string, Buffer>, name: string) => {
      const f = path.join(A.home, name);
      writeFileSync(f, packSingle(m));
      return f;
    };
    const variants: Record<string, Map<string, Buffer>> = {};
    const flip = new Map(files);
    const o0 = Buffer.from(flip.get(objs[0]!)!);
    o0[o0.length - 5]! ^= 1;
    flip.set(objs[0]!, o0);
    variants.bitflip_object = flip;
    const swap = new Map(files);
    swap.set(objs[0]!, files.get(objs[1]!)!);
    swap.set(objs[1]!, files.get(objs[0]!)!);
    variants.swapped = swap;
    const trunc = new Map(files);
    trunc.delete(objs[1]!);
    variants.truncated = trunc;
    const hdr = new Map(files);
    const m = JSON.parse(files.get(MANIFEST)!.toString());
    m.seq += 10;
    hdr.set(MANIFEST, Buffer.from(JSON.stringify(m)));
    variants.header_seq_edited = hdr;
    const idx = new Map(files);
    const m2 = JSON.parse(files.get(MANIFEST)!.toString());
    m2.index = m2.index.slice(0, -4) + (m2.index.endsWith('AAAA') ? 'BBBB' : 'AAAA');
    idx.set(MANIFEST, Buffer.from(JSON.stringify(m2)));
    variants.index_flipped = idx;
    for (const [name, v] of Object.entries(variants)) {
      const B = mk();
      await expect(B.app.sync.importFile(write(v, `${name}.vfb`), async () => PASS), name).rejects.toMatchObject({ code: expect.stringMatching(/tampered|truncated/) });
      expect(B.keychain.data.size, name).toBe(0);
    }
    const B = mk();
    await expect(B.app.sync.importFile(file, async () => 'wrong passphrase here')).rejects.toMatchObject({ code: 'wrong_key' });
    // rollback: B sees seq 2, then an attacker serves the old seq 1 bundle
    await B.app.sync.importFile(file, async () => PASS);
    await A.app.vault.put('local', 'ONE', 'value-one-NEW');
    const newer = path.join(A.home, 'newer.vfb');
    await A.app.sync.exportToFile(newer, async () => PASS);
    expect(parseManifest(unpackSingle(readFileSync(newer)).get(MANIFEST)!).seq).toBe(2);
    const rep = await B.app.sync.importFile(newer, async () => PASS);
    expect(rep.updated).toEqual(['ONE']);
    await expect(B.app.sync.importFile(file, async () => PASS)).rejects.toMatchObject({ code: 'rollback' });
  });

  it('rekey: re-wraps DEKs (ciphertexts unchanged), old passphrase stops working, new one works', async () => {
    const A = mk();
    await A.app.vault.put('local', 'K', 'rekey-value-xyz');
    const file = path.join(A.home, 'r.vfb');
    await A.app.sync.exportToFile(file, async () => PASS);
    const before = unpackSingle(readFileSync(file));
    const ctOf = (m: Map<string, Buffer>) => [...m].filter(([k]) => k.startsWith('o/')).map(([, b]) => JSON.parse(b.toString()).ct);
    const r = await A.app.tools.vaultRekey({ file });
    const { result } = await person(A, r, { passphrase: PASS, new_passphrase: 'a brand new passphrase', passphrase2: 'a brand new passphrase' });
    expect(result).toMatchObject({ status: 'completed', seq: 2, objects: 1 });
    const after = unpackSingle(readFileSync(file));
    expect(ctOf(after)).toEqual(ctOf(before));
    expect(after.get(MANIFEST)!.equals(before.get(MANIFEST)!)).toBe(false);
    const B = mk();
    await expect(B.app.sync.importFile(file, async () => PASS)).rejects.toMatchObject({ code: 'wrong_key' });
    expect((await B.app.sync.importFile(file, async () => 'a brand new passphrase')).created).toEqual(['K']);
    expect(B.keychain.data.get('veilform/K')).toBe('rekey-value-xyz');
  });

  it('second factor: passphrase + key file are both required', async () => {
    const keyFile = path.join(tmpDir(), 'sync.key');
    const { createKeyFile } = await import('../src/crypto/keysource.js');
    createKeyFile(keyFile);
    const A = mk({ sync: { secondFactor: { type: 'key-file', path: keyFile } } });
    await A.app.vault.put('local', 'K2', 'two-factor-value');
    const file = path.join(A.home, 'tf.vfb');
    await A.app.sync.exportToFile(file, async () => PASS);
    const noKey = mk();
    await expect(noKey.app.sync.importFile(file, async () => PASS)).rejects.toMatchObject({ code: 'missing_key' });
    const withKey = mk({ sync: { secondFactor: { type: 'key-file', path: keyFile } } });
    expect((await withKey.app.sync.importFile(file, async () => PASS)).created).toEqual(['K2']);
  });
});

// ------------------------------------------------------------------ targets + conflicts

describe('sync targets (only opaque blobs reach them) and conflicts', () => {
  const stores: Store[] = [];
  const apps: TestApp[] = [];
  afterAll(async () => {
    for (const s of stores) await s.close();
    for (const a of apps) await a.cleanup();
  });

  const SECRETS = { API_TOKEN: 'tok-target-AAAA-1111', DB_PASSWORD: 'db-pass-BBBB-2222' };

  async function roundTrip(targetCfg: Record<string, unknown>, extraDest: Record<string, unknown> = {}, seed?: (t: TestApp) => Promise<void>) {
    const cfg = { sync: { targets: { remote: targetCfg } }, ...extraDest };
    const A = makeApp(cfg);
    const B = makeApp(cfg);
    apps.push(A, B);
    for (const t of [A, B]) await seed?.(t);
    for (const [k, v] of Object.entries(SECRETS)) await A.app.vault.put('local', k, v);
    const r = await A.app.tools.vaultSync({ target: 'remote' });
    const { result } = await person(A, r, { passphrase: PASS, passphrase2: PASS });
    expect(result).toMatchObject({ status: 'completed', pushed: { seq: 1 } });
    const ri = await B.app.tools.vaultImport({ target: 'remote' });
    const imp = await person(B, ri, { passphrase: PASS });
    expect(imp.result).toMatchObject({ status: 'completed', created: expect.arrayContaining(['API_TOKEN', 'DB_PASSWORD']) });
    expect(B.keychain.data.get('veilform/API_TOKEN')).toBe(SECRETS.API_TOKEN);
    return { A, B };
  }

  it('dir target + conflict detection (never silent) + strategies', async () => {
    const dir = path.join(tmpDir(), 'drop');
    const { A, B } = await roundTrip({ type: 'dir', path: dir });
    expectAbsent(filesUnder(dir), [...Object.values(SECRETS), ...Object.keys(SECRETS), PASS]);
    // concurrent edits on both devices
    await A.app.vault.put('local', 'API_TOKEN', 'edited-on-A-123');
    await B.app.vault.put('local', 'API_TOKEN', 'edited-on-B-456');
    expect((await A.app.sync.sync('remote', async () => PASS)).pushed.seq).toBe(2);
    await expect(B.app.sync.sync('remote', async () => PASS)).rejects.toMatchObject({ code: 'conflict' });
    expect(B.keychain.data.get('veilform/API_TOKEN')).toBe('edited-on-B-456');
    const kb = await B.app.sync.sync('remote', async () => PASS, 'keep-both');
    expect(kb.pulled!.renamed[0]!.name).toBe('API_TOKEN');
    expect(B.keychain.data.get('veilform/API_TOKEN')).toBe('edited-on-B-456');
    expect(B.keychain.data.get(`veilform/${kb.pulled!.renamed[0]!.as}`)).toBe('edited-on-A-123');
    // A pulls B's resolution: B's clock dominates now → plain update, no conflict
    const pa = await A.app.sync.pull('remote', async () => PASS);
    expect(pa.updated).toContain('API_TOKEN');
    expect(A.keychain.data.get('veilform/API_TOKEN')).toBe('edited-on-B-456');
  });

  it('http target (bearer token from the local keychain, never argv)', async () => {
    const s = await blobServer('http');
    stores.push(s);
    await roundTrip({ type: 'http', baseUrl: `${s.url}/blobs`, auth: { scheme: 'bearer', tokenRef: 'HTTP_TOKEN' }, allowInsecureLoopback: true }, {}, async (t) => {
      await t.app.vault.put('local', 'HTTP_TOKEN', 'tok-http-123');
    });
    expect(s.urls.some((u) => u.startsWith('PUT /blobs/manifest.json'))).toBe(true);
    expectAbsent([...s.bodies, ...s.urls], [...Object.values(SECRETS), ...Object.keys(SECRETS)]);
  });

  it('webdav target (basic auth, MKCOL)', async () => {
    const s = await blobServer('webdav');
    stores.push(s);
    await roundTrip({ type: 'webdav', url: `${s.url}/dav/vf`, auth: { scheme: 'basic', user: 'alice', passwordRef: 'DAV_PASS' }, allowInsecureLoopback: true }, {}, async (t) => {
      await t.app.vault.put('local', 'DAV_PASS', 'dav-pass-456');
    });
    expect(s.urls).toContain('MKCOL /dav/vf/');
    expectAbsent([...s.bodies, ...s.urls], [...Object.values(SECRETS), ...Object.keys(SECRETS)]);
  });

  it('s3 target (SigV4 verified by the simulated server)', async () => {
    const s = await blobServer('s3');
    stores.push(s);
    await roundTrip({ type: 's3', endpoint: s.url, bucket: 'backups', region: 'auto', prefix: 'team/', accessKeyRef: 'S3_ID', secretKeyRef: 'S3_SECRET', allowInsecureLoopback: true }, {}, async (t) => {
      await t.app.vault.put('local', 'S3_ID', 'AKIDTEST');
      await t.app.vault.put('local', 'S3_SECRET', 's3-secret-789');
    });
    expect([...s.objects.keys()].some((k) => k === '/backups/team/manifest.json')).toBe(true);
    expectAbsent([...s.bodies, ...s.urls], [...Object.values(SECRETS), ...Object.keys(SECRETS), 's3-secret-789']);
  });

  it('git target (bare repo, clone/commit/push via argv)', async () => {
    const bare = path.join(tmpDir(), 'vault.git');
    execFileSync('git', ['init', '-q', '--bare', bare]);
    await roundTrip({ type: 'git', url: bare, branch: 'main', path: 'vf' });
    const log = execFileSync('git', ['--git-dir', bare, 'log', '--format=%s', 'main']).toString();
    expect(log).toContain('veilform sync seq 1');
    const tree = execFileSync('git', ['--git-dir', bare, 'ls-tree', '-r', '--name-only', 'main']).toString();
    expect(tree).toContain('vf/manifest.json');
    const all = execFileSync('git', ['--git-dir', bare, 'log', '-p', 'main']).toString();
    expectAbsent([all], [...Object.values(SECRETS), ...Object.keys(SECRETS)]);
  });

  const SSHD = '/usr/sbin/sshd';
  it.skipIf(!(existsSync(SSHD) && spawnSync('ssh', ['-V']).status === 0))('ssh target against a loopback sshd', async () => {
    const dir = tmpDir('vf-sshd-');
    const net = await import('node:net');
    const port = await new Promise<number>((res) => {
      const s = net.createServer();
      s.listen(0, '127.0.0.1', () => {
        const p = (s.address() as AddressInfo).port;
        s.close(() => res(p));
      });
    });
    execFileSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-f', path.join(dir, 'hostkey')]);
    execFileSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-f', path.join(dir, 'client')]);
    writeFileSync(path.join(dir, 'authorized_keys'), readFileSync(path.join(dir, 'client.pub')), { mode: 0o600 });
    writeFileSync(path.join(dir, 'sshd_config'), [`Port ${port}`, 'ListenAddress 127.0.0.1', `HostKey ${dir}/hostkey`, `AuthorizedKeysFile ${dir}/authorized_keys`, 'PasswordAuthentication no', 'KbdInteractiveAuthentication no', 'UsePAM no', 'StrictModes no', `PidFile ${dir}/sshd.pid`].join('\n') + '\n');
    const { spawn } = await import('node:child_process');
    const sshd = spawn(SSHD, ['-D', '-f', path.join(dir, 'sshd_config')], { stdio: 'ignore' });
    try {
      for (let i = 0; i < 50; i++) {
        if (spawnSync('ssh-keyscan', ['-p', String(port), '127.0.0.1']).stdout?.length) break;
        await new Promise((r) => setTimeout(r, 100));
      }
      const remote = path.join(dir, 'remote-vault');
      const seed = async (t: TestApp) => {
        const kh = spawnSync('ssh-keyscan', ['-p', String(port), '127.0.0.1']).stdout.toString();
        mkdirSync(t.home, { recursive: true });
        writeFileSync(path.join(t.home, 'known_hosts'), kh);
      };
      await roundTrip({ type: 'ssh', host: 'loop', path: remote }, { ssh: { hosts: { loop: { host: '127.0.0.1', port, identityFile: path.join(dir, 'client') } } } }, seed);
      expect(existsSync(path.join(remote, 'manifest.json'))).toBe(true);
      expectAbsent(filesUnder(remote), [...Object.values(SECRETS), ...Object.keys(SECRETS)]);
    } finally {
      sshd.kill();
    }
  });
});

// ------------------------------------------------------------------ shares

describe('share by token', () => {
  const apps: TestApp[] = [];
  afterAll(async () => {
    for (const a of apps) await a.cleanup();
  });
  let clock = Date.parse('2026-10-19T12:00:00Z');
  const now = () => new Date(clock);
  const shared = path.join(tmpDir(), 'shared-drop');
  const mk = () => {
    const t = makeApp({ sync: { targets: { team: { type: 'dir', path: shared } }, shareTarget: 'team' } }, { now });
    apps.push(t);
    return t;
  };

  async function createShare(S: TestApp, args: Record<string, unknown>, values: Record<string, unknown> = {}) {
    const { call, responses } = collect(S);
    const r = await call(() => S.app.tools.shareCreate(args));
    expect(r.status).toBe('awaiting_user');
    const page = await openPage(String(r.url));
    const lines = JSON.stringify(page.data.destination);
    for (const n of args.names as string[]) expect(lines).toContain(n);
    expect((await post(page, { action: 'submit', values })).json.errors).toEqual([{ field: '__confirm', code: 'confirm' }]);
    const res = await post(page, { action: 'submit', values, confirm: true });
    expect(res.json.ok).toBe(true);
    const token = (res.json.reveal as { items: { value: string }[] }).items[0]!.value;
    const w = await call(() => S.app.secretWait({ id: r.request_id }));
    return { token, w, responses };
  }

  it('person flow: reveal page, max_views, expiry with a simulated clock, replay refused', async () => {
    const S = mk();
    const V = 'shared-secret-value-777';
    await S.app.vault.put('local', 'PARTNER_KEY', V);
    const { token, w, responses } = await createShare(S, { names: ['PARTNER_KEY'], expires_in: '1h', max_views: 2, note: 'for Ana' });
    expect(token).toMatch(/^vfs1:\/\/team\/[A-Za-z0-9_-]{22}#[A-Za-z0-9_-]{43}$/);
    expect(w).toMatchObject({ status: 'completed', names: ['PARTNER_KEY'], max_views: 2, passphrase_required: false });
    const key = token.split('#')[1]!;
    expectAbsent([...responses, readFileSync(path.join(S.home, 'audit.jsonl'), 'utf8'), readFileSync(path.join(S.home, 'shares.json'), 'utf8'), stderr.join('\n'), ...filesUnder(shared)], [V, token, key]);
    expect(filesUnder(shared).join('')).not.toContain('PARTNER_KEY');

    const R = mk();
    const { registerRevealPage } = await import('../src/vaulttools.js');
    const p1 = await registerRevealPage(R.app);
    const r1 = await submit(p1.url, { token });
    expect((r1.json.reveal as { items: { label: string; value: string }[] }).items).toEqual([{ label: 'PARTNER_KEY', value: V }]);
    expect(await p1.done).toEqual({ status: 'completed', names: ['PARTNER_KEY'] });
    // replay on the same machine after max views is refused locally; another machine gets the 2nd view
    const R2 = mk();
    const second = await R2.app.shares.open(token);
    expect(second).toMatchObject({ viewsLeft: 0, burned: true });
    await expect(R2.app.shares.open(token)).rejects.toMatchObject({ code: expect.stringMatching(/consumed|gone/) });
    await expect(mk().app.shares.open(token)).rejects.toMatchObject({ code: 'gone' });
    expect(filesUnder(shared).length).toBe(0);
    // expiry
    await S.app.vault.put('local', 'SHORT', 'short-lived-value');
    const s2 = await createShare(S, { names: ['SHORT'], expires_in: '10m' });
    clock += 11 * 60_000;
    await expect(mk().app.shares.open(s2.token)).rejects.toMatchObject({ code: 'expired' });
    clock -= 11 * 60_000;
  });

  it('passphrase second factor: token alone fails, wrong passphrase limited, right one works; tampered bundle rejected', async () => {
    const S = mk();
    await S.app.vault.put('local', 'TWO_FA', 'needs-both-factors-1');
    const { token } = await createShare(S, { names: ['TWO_FA'], require_passphrase: true, max_views: 1 }, { passphrase: 'share pass 123', passphrase2: 'share pass 123' });
    const R = mk();
    await expect(R.app.shares.open(token)).rejects.toMatchObject({ code: 'passphrase_required' });
    for (let i = 0; i < 4; i++) await expect(R.app.shares.open(token, { passphrase: `wrong ${i} guess` })).rejects.toMatchObject({ code: 'wrong_key' });
    // tampering with the signed expiry
    const id = token.split('/')[3]!.split('#')[0]!;
    const f = path.join(shared, 'shares', `${id}.json`);
    const orig = readFileSync(f, 'utf8');
    const j = JSON.parse(orig);
    j.expires_at = '2099-01-01T00:00:00.000Z';
    writeFileSync(f, JSON.stringify(j));
    await expect(R.app.shares.open(token, { passphrase: 'share pass 123' })).rejects.toMatchObject({ code: 'wrong_key' });
    writeFileSync(f, orig);
    // 5th failure above locked this share id on R; a fresh machine with the right passphrase works
    await expect(R.app.shares.open(token, { passphrase: 'share pass 123' })).rejects.toMatchObject({ code: 'too_many_attempts' });
    const ok = await mk().app.shares.open(token, { passphrase: 'share pass 123' });
    expect(ok.items[0]).toMatchObject({ name: 'TWO_FA', value: 'needs-both-factors-1' });
  });

  it('revoke: bundle deleted, was_read reported, rotation offered', async () => {
    const S = mk();
    await S.app.vault.put('local', 'REV', 'revocable-value-9', { field: { label: 'Rev', kind: 'secret' } });
    const { token, w } = await createShare(S, { names: ['REV'], max_views: 3 });
    await mk().app.shares.open(token);
    const r = (await S.app.tools.shareRevoke({ share_id: w.share_id, rotate: true })) as Record<string, unknown>;
    expect(r).toMatchObject({ revoked: true, was_read: true, names: ['REV'] });
    expect(String(r.recommendation)).toMatch(/rotate/i);
    expect((r.rotations as { status: string }[])[0]!.status).toBe('awaiting_user');
    await expect(mk().app.shares.open(token)).rejects.toMatchObject({ code: 'gone' });
    const audit = readFileSync(path.join(S.home, 'audit.jsonl'), 'utf8');
    expect(audit).toContain('"event":"share_created"');
    expect(audit).toContain('"event":"share_revoked"');
    expect(verifyAuditLog(path.join(S.home, 'audit.jsonl'))).toBe(0);
  });

  it('agent import: token_file → value straight into the vault, then used blindly with secret_use', async () => {
    const S = mk();
    const V = 'agent-to-agent-value-55';
    await S.app.vault.put('local', 'SVC_TOKEN', V);
    const { token } = await createShare(S, { names: ['SVC_TOKEN'] });
    const R = mk();
    const tf = path.join(R.home, 'token.txt');
    writeFileSync(tf, token + '\n', { mode: 0o600 });
    const { call, responses } = collect(R);
    const r = await call(() => R.app.tools.shareImport({ token_file: tf }));
    expect(r).toMatchObject({ status: 'completed', stored: ['SVC_TOKEN'], burned: true });
    expect(R.keychain.data.get('veilform/SVC_TOKEN')).toBe(V);
    const u = await call(() => R.app.secretUse({ action: 'exec', command: [process.execPath, '-e', 'process.stdout.write(process.env.T)'], env: { T: '${secret:SVC_TOKEN}' } }));
    const { approve } = await import('./helpers.js');
    await approve(String(u.url));
    const done = await call(() => R.app.secretWait({ id: u.request_id }));
    expect(done.stdout).toBe('[REDACTED:SVC_TOKEN]');
    // a second import of the same token conflicts → renamed, never overwritten
    expectAbsent([...responses, readFileSync(path.join(R.home, 'audit.jsonl'), 'utf8'), stderr.join('\n')], [V, token, token.split('#')[1]!]);
    // pasted on the local page instead (fragment field)
    await S.app.vault.put('local', 'PASTED', 'pasted-value-66');
    const s2 = await createShare(S, { names: ['PASTED'] });
    const r2 = await R.app.tools.shareImport({});
    const p = await openPage(String(r2.url));
    expect(p.data.fragmentField).toBe('token');
    await post(p, { action: 'submit', values: { token: s2.token } });
    expect(await R.app.secretWait({ id: r2.request_id })).toMatchObject({ status: 'completed', stored: ['PASTED'] });
  });
});

// ------------------------------------------------------------------ property

describe('property: no MCP response, audit, log, state or blob contains values, tokens or keys', () => {
  it('random values through export, sync, share and import', async () => {
    const rnd = prng(4242);
    for (let i = 0; i < 6; i++) {
      const drop = path.join(tmpDir(), 'p');
      const cfg = { sync: { targets: { d: { type: 'dir', path: drop } } } };
      const A = makeApp(cfg);
      const B = makeApp(cfg);
      try {
        const V = randomSecret(rnd);
        const P = 'pp-' + randomSecret(rnd);
        const a = collect(A);
        const b = collect(B);
        await A.app.vault.put('local', 'S', V);
        const r = await a.call(() => A.app.tools.vaultSync({ target: 'd' }));
        await person(A, r, { passphrase: P, passphrase2: P });
        const sc = await a.call(() => A.app.tools.shareCreate({ names: ['S'], target: 'd' }));
        const page = await submit(String(sc.url), {}, { confirm: true });
        const token = (page.json.reveal as { items: { value: string }[] }).items[0]!.value;
        await a.call(() => A.app.secretWait({ id: sc.request_id }));
        const tf = path.join(B.home, 't');
        mkdirSync(B.home, { recursive: true });
        writeFileSync(tf, token);
        await b.call(() => B.app.tools.shareImport({ token_file: tf, destination: 'vault' }));
        const ri = await b.call(() => B.app.tools.vaultImport({ target: 'd' }));
        await person(B, ri, { passphrase: P });
        await b.call(() => B.app.tools.shareList({}));
        expect(B.keychain.data.get('veilform/S')).toBe(V);
        const st = A.app.sync.state();
        const m = parseManifest(readFileSync(path.join(drop, MANIFEST)));
        const kek = await deriveKek(st.bundle_id!, m.key.kdf, m.key.second, { passphrase: P });
        const secretsOut = [V, P, token, token.split('#')[1]!, b64(kek), kek.toString('hex'), kek.toString('base64')];
        const hay = [
          ...a.responses,
          ...b.responses,
          stderr.join('\n'),
          ...[A, B].flatMap((t) => ['audit.jsonl', 'index.json', 'sync-state.json', 'shares.json', 'shares-received.json'].filter((f) => existsSync(path.join(t.home, f))).map((f) => readFileSync(path.join(t.home, f), 'utf8'))),
          ...filesUnder(drop),
        ];
        expectAbsent(hay, secretsOut);
      } finally {
        await A.cleanup();
        await B.cleanup();
      }
    }
  }, 180_000);
});
