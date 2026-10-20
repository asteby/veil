import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { runVaultCli } from '../src/cli-vault.js';
import { createKeyFile } from '../src/crypto/keysource.js';
import { b64 } from '../src/crypto/primitives.js';
import { variantsOf } from '../src/redact.js';
import { approve, makeApp, openPage, post, prng, randomSecret, tmpDir, type TestApp } from './helpers.js';

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

function expectAbsent(haystacks: string[], needles: string[]) {
  for (const h of haystacks) for (const n of needles) for (const v of variantsOf(n)) expect(h.includes(v), `found ${JSON.stringify(v)}`).toBe(false);
}

const apps: TestApp[] = [];
afterAll(async () => {
  for (const a of apps) await a.cleanup();
});

function setup(extra: Record<string, unknown> = {}) {
  const proj = tmpDir('vf-proj-');
  const shared = path.join(tmpDir(), 'drop');
  const t = makeApp({ writeTargets: [{ kind: 'env-file', path: path.join(proj, 'deploy', '*') }], sync: { targets: { team: { type: 'dir', path: shared } } }, ...extra });
  apps.push(t);
  return { t, proj, shared };
}

describe('encrypted .env through MCP tools (values never reach the model)', () => {
  it('env_encrypt (passphrase on the page + key file) → status → edit page (reveal locally) → diff', async () => {
    const { t, proj } = setup();
    const { call, responses } = collect(t);
    const f = path.join(proj, '.env.production');
    const DB = 'postgres://app:Sup3r-S3cret@db:5432/app';
    writeFileSync(f, `# prod\nDB_URL=${DB}\nPORT=8080\n`);
    const key = createKeyFile(path.join(tmpDir(), 'server.key'));
    const r = await call(() => t.app.tools.envEncrypt({ file: f, key_files: [key.where] }));
    const p = await openPage(String(r.url));
    expect(JSON.stringify(p.data.destination)).toContain('DB_URL, PORT');
    await post(p, { action: 'submit', values: { passphrase: 'env pass 1234', passphrase2: 'env pass 1234' } });
    const w = await call(() => t.app.secretWait({ id: r.request_id }));
    expect(w).toMatchObject({ status: 'completed', keys: ['DB_URL', 'PORT'], recipients: ['pass', `key:${key.id}`] });
    expect(readFileSync(f, 'utf8')).not.toContain('Sup3r');
    const st = await call(() => t.app.tools.envStatus({ file: f }));
    expect(st).toMatchObject({ encrypted: true, keys: ['DB_URL', 'PORT'], unlocked: false });

    // edit: needs the passphrase (no key configured for this app) → typed on the page
    const e = await call(() => t.app.tools.envEdit({ file: f }));
    const ep = await openPage(String(e.url));
    const fields = (ep.data.schema as { sections: { fields: { name: string; label: string }[] }[] }).sections[0]!.fields;
    expect(fields.map((x) => x.label)).toEqual(['Passphrase for .env.production', 'DB_URL', 'PORT', 'Delete keys', 'New keys']);
    const NEWDB = 'postgres://app:R0tated-pass@db:5432/app';
    expect((await post(ep, { action: 'submit', values: { passphrase: 'wrong pass 0000', k0: NEWDB } })).json.errors).toEqual([{ field: 'passphrase', code: 'wrong' }]);
    expect((await post(ep, { action: 'submit', values: { passphrase: 'env pass 1234', k0: NEWDB, add: [{ key: 'REDIS_URL', value: 'redis://:pw-9@r:6379' }] } })).json.ok).toBe(true);
    const ew = await call(() => t.app.secretWait({ id: e.request_id }));
    expect(ew).toMatchObject({ status: 'completed', changed: ['DB_URL'], added: ['REDIS_URL'], removed: [] });
    // with a key available, the edit page offers "show current values" (local page only)
    const t2 = makeApp({ env: { keyFiles: [key.where] } });
    apps.push(t2);
    const e2 = await t2.app.tools.envEdit({ file: f });
    const ep2 = await openPage(String(e2.url));
    expect(ep2.data.revealLabel).toBeTruthy();
    const rv = await post(ep2, { action: 'reveal' });
    expect((rv.json.reveal as { items: { label: string; value: string }[] }).items.find((i) => i.label === 'DB_URL')!.value).toBe(NEWDB);
    await post(ep2, { action: 'cancel' });
    // diff against a copy
    const old = path.join(proj, '.env.old');
    writeFileSync(old, `DB_URL=${DB}\nPORT=8080\nGONE=1\n`);
    const d = await call(() => t2.app.tools.envDiff({ file: f, against: old }));
    expect(d).toMatchObject({ added: ['REDIS_URL'], removed: ['GONE'], changed: ['DB_URL'], unchanged: ['PORT'] });
    expectAbsent([...responses, readFileSync(path.join(t.home, 'audit.jsonl'), 'utf8'), stderr.join('\n')], [DB, NEWDB, 'env pass 1234', 'redis://:pw-9@r:6379']);
  });

  it('secret_use with env_file and secret_write from env-enc (decrypted values and as-is ciphertext)', async () => {
    const { t, proj } = setup();
    const key = createKeyFile(path.join(tmpDir(), 'k.key'));
    const t2 = makeApp({ env: { keyFiles: [key.where] }, writeTargets: [{ kind: 'env-file', path: path.join(proj, 'deploy', '*') }] });
    apps.push(t2);
    const f = path.join(proj, '.env.staging');
    const V = 'stg-api-token-ABC123xyz';
    writeFileSync(f, `API_TOKEN=${V}\nMODE=staging\n`);
    await t.app.envFiles.encrypt(f, { keyFiles: [key.where] });
    const { call, responses } = collect(t2);
    const u = await call(() => t2.app.secretUse({ action: 'exec', command: [process.execPath, '-e', 'console.log(process.env.API_TOKEN, process.env.MODE)'], env_file: { file: f } }));
    const ap = await openPage(String(u.url));
    expect((ap.data.approval as { literal: string }).literal).toContain('API_TOKEN, MODE');
    await post(ap, { action: 'approve' });
    const uw = await call(() => t2.app.secretWait({ id: u.request_id }));
    expect(uw.stdout).toBe('[REDACTED:envfile:API_TOKEN] [REDACTED:envfile:MODE]\n');
    // decrypted copy to a deployment .env
    const dst = path.join(proj, 'deploy', 'app.env');
    const wr = await call(() => t2.app.secretWrite({ from: { kind: 'env-enc', file: f, keys: ['API_TOKEN'] }, target: { kind: 'env-file', path: dst } }));
    await approve(String(wr.url));
    expect(await call(() => t2.app.secretWait({ id: wr.request_id }))).toMatchObject({ status: 'completed', written: true, keys: [{ key: 'API_TOKEN', action: 'created' }] });
    expect(readFileSync(dst, 'utf8')).toBe(`API_TOKEN=${V}\n`);
    // ciphertext as is, no key needed
    const t3 = makeApp({ writeTargets: [{ kind: 'env-file', path: path.join(proj, 'deploy', '*') }] });
    apps.push(t3);
    const dst2 = path.join(proj, 'deploy', '.env.staging');
    const wr2 = await t3.app.secretWrite({ from: { kind: 'env-enc', file: f, as_is: true }, target: { kind: 'env-file', path: dst2 } });
    const ap2 = await openPage(String(wr2.url));
    expect((ap2.data.approval as { literal: string }).literal).toContain('the decryption key is NOT copied');
    await post(ap2, { action: 'approve' });
    expect(await t3.app.secretWait({ id: wr2.request_id })).toMatchObject({ written: true, deployed: 'encrypted' });
    expect(readFileSync(dst2, 'utf8')).toBe(readFileSync(f, 'utf8'));
    expectAbsent([...responses, readFileSync(path.join(t2.home, 'audit.jsonl'), 'utf8'), stderr.join('\n')], [V]);
  });

  it('env_unlock with a share token: only that file, expiry and max uses enforced', async () => {
    let clock = Date.now();
    const { t, proj, shared } = setup();
    const owner = t;
    const f = path.join(proj, '.env.production');
    writeFileSync(f, 'SECRET=only-this-file-1\n');
    await owner.app.envFiles.encrypt(f, { passphrase: 'owner pass 123' });
    const { doc, dek } = await owner.app.envFiles.decrypt(f, { passphrase: async () => 'owner pass 123' });
    const mkShare = async (expires: number, views: number) => (await owner.app.shares.create({ targetId: 'team', items: [{ name: `env:${doc.context}`, kind: 'env-dek', value: b64(dek) }], expiresInSeconds: expires, maxViews: views })).token;
    const token = await mkShare(600, 1);
    const R = makeApp({ sync: { targets: { team: { type: 'dir', path: shared } } } }, { now: () => new Date(clock) });
    apps.push(R);
    const { call, responses } = collect(R);
    const u = await call(() => R.app.tools.envUnlock({ file: f, minutes: 5 }));
    const p = await openPage(String(u.url));
    expect(p.data.fragmentField).toBe('token');
    await post(p, { action: 'submit', values: { token } });
    expect(await call(() => R.app.secretWait({ id: u.request_id }))).toMatchObject({ status: 'completed', unlocked: true, via: 'token' });
    expect((await R.app.envFiles.decrypt(f)).entries[0]!.value).toBe('only-this-file-1');
    // another file with the same name but another key is NOT opened by that DEK
    const other = path.join(tmpDir(), '.env.production');
    writeFileSync(other, 'SECRET=different\n');
    await owner.app.envFiles.encrypt(other, { passphrase: 'other pass 123' });
    await expect(R.app.envFiles.decrypt(other)).rejects.toMatchObject({ code: 'wrong_key' });
    // consumed token
    const R2 = makeApp({ sync: { targets: { team: { type: 'dir', path: shared } } } });
    apps.push(R2);
    await expect(R2.app.shares.open(token)).rejects.toMatchObject({ code: 'gone' });
    // expired token
    const t2 = await mkShare(120, 3);
    clock += 10 * 60_000;
    await expect(R.app.shares.open(t2)).rejects.toMatchObject({ code: 'expired' });
    expectAbsent([...responses, readFileSync(path.join(R.home, 'audit.jsonl'), 'utf8')], ['only-this-file-1', token, token.split('#')[1]!]);
  });

  it('property: random values in an encrypted .env never reach responses, audit or logs', async () => {
    const rnd = prng(77);
    for (let i = 0; i < 5; i++) {
      const { t, proj } = setup();
      const key = createKeyFile(path.join(tmpDir(), 'p.key'));
      const t2 = makeApp({ env: { keyFiles: [key.where] }, writeTargets: [{ kind: 'env-file', path: path.join(proj, 'deploy', '*') }] });
      apps.push(t2);
      const V = randomSecret(rnd).replace(/[\n\r]/g, '');
      const f = path.join(proj, '.env');
      writeFileSync(f, `X_SECRET=${JSON.stringify(V)}\n`);
      await t.app.envFiles.encrypt(f, { keyFiles: [key.where] });
      const { call, responses } = collect(t2);
      await call(() => t2.app.tools.envStatus({ file: f }));
      await call(() => t2.app.tools.envDiff({ file: f, against: f }));
      const u = await call(() => t2.app.secretUse({ action: 'exec', command: [process.execPath, '-e', 'const v=process.env.X_SECRET;for(const e of ["utf8","base64","hex"])console.log(Buffer.from(v).toString(e))'], env_file: { file: f } }));
      await approve(String(u.url));
      await call(() => t2.app.secretWait({ id: u.request_id }));
      const wr = await call(() => t2.app.secretWrite({ from: { kind: 'env-enc', file: f }, target: { kind: 'env-file', path: path.join(proj, 'deploy', 'x.env') } }));
      await approve(String(wr.url));
      await call(() => t2.app.secretWait({ id: wr.request_id }));
      await call(() => t2.app.tools.envRotate({ file: f }));
      expectAbsent([...responses, readFileSync(path.join(t2.home, 'audit.jsonl'), 'utf8'), stderr.join('\n'), readFileSync(f, 'utf8')], [V]);
      expect((await t2.app.envFiles.decrypt(f)).entries[0]!.value).toBe(V);
    }
  }, 120_000);
});

describe('CLI (in process) and deployment helpers', () => {
  let out: string[] = [];
  beforeAll(() => {
    vi.spyOn(process.stdout, 'write').mockImplementation(((c: string | Uint8Array) => {
      out.push(String(c));
      return true;
    }) as typeof process.stdout.write);
  });
  afterEach(() => {
    out = [];
  });

  it('veil run with a systemd credential; env unlock --status lists methods (no values)', async () => {
    const { t, proj } = setup();
    const f = path.join(proj, '.env.production');
    const V = 'systemd-cred-value-42';
    writeFileSync(f, `APP_SECRET=${V}\n`);
    const key = createKeyFile(path.join(tmpDir(), 'server.key'));
    await t.app.envFiles.encrypt(f, { keyFiles: [key.where] });
    const cred = tmpDir('vf-cred-');
    writeFileSync(path.join(cred, 'veil-key'), readFileSync(key.where));
    const prev = process.env.CREDENTIALS_DIRECTORY;
    process.env.CREDENTIALS_DIRECTORY = cred;
    try {
      const mk = () => makeApp().app;
      expect(await runVaultCli(['env', 'unlock', f, '--status'], mk)).toBe(0);
      const status = JSON.parse(out.join(''));
      expect(status.methods).toContain('systemd-credential veil-key');
      out = [];
      const code = await runVaultCli(['run', '--env', f, '--', process.execPath, '-e', 'console.log("len=" + process.env.APP_SECRET.length, process.env.APP_SECRET)'], mk);
      expect(code).toBe(0);
      expect(out.join('')).toBe(`len=${V.length} [REDACTED:APP_SECRET]\n`);
    } finally {
      if (prev === undefined) delete process.env.CREDENTIALS_DIRECTORY;
      else process.env.CREDENTIALS_DIRECTORY = prev;
    }
    expect(process.env.APP_SECRET).toBeUndefined();
    // wrong key: fails without leaking anything
    const wrong = createKeyFile(path.join(tmpDir(), 'wrong.key'));
    expect(await runVaultCli(['run', '--env', f, '--key-file', wrong.where, '--', 'true'], () => makeApp().app)).toBe(1);
    expect(out.join('')).not.toContain(V);
  });

  it.skipIf(!existsSync('/usr/bin/systemd-analyze'))('example systemd unit and drop-in are valid (systemd-analyze verify)', () => {
    const dir = tmpDir('vf-unit-');
    const unit = readFileSync(path.resolve('examples/systemd/myapp.service'), 'utf8').replaceAll('/usr/bin/veil', process.execPath).replaceAll('/usr/bin/node', process.execPath);
    writeFileSync(path.join(dir, 'myapp.service'), unit);
    mkdirSync(path.join(dir, 'myapp.service.d'));
    writeFileSync(path.join(dir, 'myapp.service.d', 'veil.conf'), readFileSync(path.resolve('examples/systemd/myapp.service.d/veil.conf'), 'utf8').replaceAll('/usr/bin/veil', process.execPath).replaceAll('/usr/bin/node', process.execPath));
    const r = spawnSync('systemd-analyze', ['verify', path.join(dir, 'myapp.service')], { encoding: 'utf8' });
    expect(r.stderr).toBe('');
    expect(r.status).toBe(0);
  });

  it('pre-commit hook blocks plaintext .env and lets encrypted ones through', async () => {
    const repo = tmpDir('vf-repo-');
    const g = (...a: string[]) => spawnSync('git', ['-C', repo, ...a], { encoding: 'utf8' });
    g('init', '-q');
    const cwd = process.cwd();
    process.chdir(repo);
    try {
      writeFileSync(path.join(repo, '.env'), 'TOKEN=plaintext-oops\n');
      g('add', '.env');
      expect(await runVaultCli(['env', 'check-staged'], () => makeApp().app)).toBe(1);
      const k = createKeyFile(path.join(tmpDir(), 'h.key'));
      const t = makeApp();
      apps.push(t);
      await t.app.envFiles.encrypt(path.join(repo, '.env'), { keyFiles: [k.where] });
      g('add', '.env');
      expect(await runVaultCli(['env', 'check-staged'], () => makeApp().app)).toBe(0);
    } finally {
      process.chdir(cwd);
    }
  });
});
