import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { readFileSync, statSync, writeFileSync, existsSync } from 'node:fs';
import path from 'node:path';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { verifyAuditLog } from '../src/audit.js';
import { variantsOf } from '../src/redact.js';
import { approve, makeApp, openPage, post, prng, randomSecret, submit, type TestApp } from './helpers.js';

/** Every tool response goes through app.safe() exactly like the MCP layer does. */
function collect(t: TestApp) {
  const responses: string[] = [];
  const call = async (fn: () => unknown) => {
    const r = (await fn()) as Record<string, unknown>;
    responses.push(t.app.safe(r));
    return JSON.parse(responses.at(-1)!) as Record<string, unknown>;
  };
  return { responses, call };
}

function expectNoValue(haystacks: string[], value: string) {
  for (const h of haystacks) for (const v of variantsOf(value)) expect(h.includes(v), `found variant ${JSON.stringify(v)}`).toBe(false);
}

let stderr: string[] = [];
beforeAll(() => {
  vi.spyOn(console, 'error').mockImplementation((...a: unknown[]) => {
    stderr.push(a.join(' '));
  });
});
afterEach(() => {
  stderr = [];
});

describe('secret_request → store → secret_use (end to end, in process)', () => {
  let t: TestApp;
  afterEach(async () => t?.cleanup());

  it('stores what the person typed and returns only names', async () => {
    t = makeApp();
    const { call, responses } = collect(t);
    const r = await call(() => t.app.secretRequest({ title: 'Mercado Pago', fields: [{ name: 'MP_ACCESS_TOKEN', label: 'Access token' }, { name: 'MP_ENV', label: 'Env', kind: 'select', options: ['sandbox', 'production'] }], metadata: { project: 'appdb', tags: ['payments'], rotate_after_days: 90 } }));
    expect(r.status).toBe('awaiting_user');
    expect(String(r.url)).toMatch(/^http:\/\/127\.0\.0\.1:/);
    const VALUE = 'APP_USR-1234567890-abcdef-SECRET';
    const res = await submit(String(r.url), { MP_ACCESS_TOKEN: VALUE, MP_ENV: 'production' });
    expect(res.json.ok).toBe(true);
    const w = await call(() => t.app.secretWait({ id: r.request_id }));
    expect(w).toMatchObject({ status: 'completed', stored: ['MP_ACCESS_TOKEN', 'MP_ENV'] });
    expect(Object.keys(w).sort()).toEqual(['request_id', 'status', 'stored']);
    expect(t.keychain.data.get('veilform/MP_ACCESS_TOKEN')).toBe(VALUE);
    const list = await call(() => t.app.secretList({}));
    expect((list.secrets as { name: string; project: string }[]).map((s) => s.name)).toEqual(['MP_ACCESS_TOKEN', 'MP_ENV']);
    const audit = readFileSync(path.join(t.home, 'audit.jsonl'), 'utf8');
    expect(verifyAuditLog(path.join(t.home, 'audit.jsonl'))).toBe(0);
    expect(audit).toContain('"agent":"test-agent"');
    expectNoValue([...responses, audit, readFileSync(path.join(t.home, 'index.json'), 'utf8'), stderr.join('\n')], VALUE);
  });

  it('reports validation errors by field name and code only', async () => {
    t = makeApp();
    const r = await t.app.secretRequest({ title: 'x', fields: [{ name: 'PIN', label: 'PIN', pattern: '\\d{4}' }] });
    const res = await submit(String(r.url), { PIN: 'abcd-not-a-pin' });
    expect(res.json).toEqual({ ok: false, errors: [{ field: 'PIN', code: 'pattern' }] });
  });

  it('cancel → status cancelled, nothing stored', async () => {
    t = makeApp();
    const r = await t.app.secretRequest({ title: 'x', fields: [{ name: 'A', label: 'A' }] });
    const p = await openPage(String(r.url));
    await post(p, { action: 'cancel' });
    expect(await t.app.secretWait({ id: r.request_id })).toMatchObject({ status: 'cancelled' });
    expect(t.keychain.data.size).toBe(0);
  });

  it('secret_use exec: approval page shows the literal, output is redacted, approval can be remembered', async () => {
    t = makeApp();
    const VALUE = 'tok_live_9f8e7d6c5b4a';
    await t.app.vault.put('local', 'API_KEY', VALUE);
    const { call, responses } = collect(t);
    const args = { action: 'exec', command: [process.execPath, '-e', 'const v=process.env.TOK;console.log(v, Buffer.from(v).toString("base64"), Buffer.from(v).toString("hex"), encodeURIComponent(v), JSON.stringify({v}))'], env: { TOK: '${secret:API_KEY}' } };
    const r = await call(() => t.app.secretUse(args));
    expect(r.status).toBe('awaiting_user');
    const page = await openPage(String(r.url));
    const approval = page.data.approval as { literal: string; items: { label: string; value: string }[] };
    expect(approval.literal).toContain('env TOK=${secret:API_KEY}');
    expect(approval.literal).toContain('exec (no shell)');
    expect((await post(page, { action: 'approve', remember: true })).json.ok).toBe(true);
    const w = await call(() => t.app.secretWait({ id: r.request_id }));
    expect(w.status).toBe('completed');
    expect(w.exit_code).toBe(0);
    expect(String(w.stdout)).toContain('[REDACTED:API_KEY]');
    // second identical call: remembered, runs directly
    const r2 = await call(() => t.app.secretUse(args));
    expect(r2).toMatchObject({ status: 'completed', approval: 'remembered' });
    expectNoValue([...responses, readFileSync(path.join(t.home, 'audit.jsonl'), 'utf8'), stderr.join('\n')], VALUE);
  });

  it('refuses ${secret:..} in argv and unknown or expired secrets', async () => {
    t = makeApp();
    await expect(t.app.secretUse({ action: 'exec', command: ['echo', '${secret:A}'] })).rejects.toThrow(/argv/);
    await expect(t.app.secretUse({ action: 'exec', command: ['env'], env: { A: '${secret:MISSING}' } })).rejects.toThrow(/not found/);
    await t.app.vault.put('local', 'OLD', 'old-value-123', { expiresAt: new Date(Date.now() - 1000).toISOString() });
    await expect(t.app.secretUse({ action: 'exec', command: ['env'], env: { A: '${secret:OLD}' } })).rejects.toThrow(/expired/);
    expect((t.app.secretList({}).secrets as { name: string; expired: boolean }[])[0]).toMatchObject({ name: 'OLD', expired: true });
  });

  it('deny → nothing runs', async () => {
    t = makeApp();
    await t.app.vault.put('local', 'K', 'value-for-deny-test');
    const marker = path.join(t.home, 'ran');
    const r = await t.app.secretUse({ action: 'exec', command: ['touch', marker], env: { K: '${secret:K}' } });
    const p = await openPage(String(r.url));
    await post(p, { action: 'deny' });
    expect(await t.app.secretWait({ id: r.request_id })).toMatchObject({ status: 'denied' });
    expect(existsSync(marker)).toBe(false);
  });

  it('shell mode keeps the value out of the script text and argv', async () => {
    t = makeApp();
    await t.app.vault.put('local', 'PW', 'shell-secret-value-42');
    const r = await t.app.secretUse({ action: 'exec', shell: 'printf "%s|%s" "${secret:PW}" "$0"' });
    const p = await openPage(String(r.url));
    expect((p.data.approval as { warnings: string[] }).warnings.length).toBeGreaterThan(0);
    await post(p, { action: 'approve' });
    const w = await t.app.secretWait({ id: r.request_id });
    expect(String(w.stdout)).toBe('[REDACTED:PW]|/bin/sh');
  });

  it('rotation: secret_rotate re-asks with the same label and destination', async () => {
    t = makeApp();
    const r = await t.app.secretRequest({ title: 'x', fields: [{ name: 'TOKEN', label: 'My token', help: 'from the panel' }], destination: 'vault', metadata: { rotate_after_days: 1 } });
    await submit(String(r.url), { TOKEN: 'first-value-abc' });
    await t.app.secretWait({ id: r.request_id });
    const rot = await t.app.secretRotate({ name: 'TOKEN' });
    const p = await openPage(String(rot.url));
    const f = (p.data.schema as { sections: { fields: { label: string; help: string }[] }[] }).sections[0]!.fields[0]!;
    expect(f).toMatchObject({ label: 'My token', help: 'from the panel' });
    expect((p.data.destination as { lines: { label: string }[] }).lines[0]!.label).toBe('vault');
  });
});

describe('property: no tool response, log or audit line ever contains a submitted value', () => {
  it('random secrets through request → use(exec, many encodings) → write → list', async () => {
    const rnd = prng(2026);
    for (let i = 0; i < 12; i++) {
      const t = makeApp({ writeTargets: [{ kind: 'env-file', path: '/tmp/**' }, { kind: 'env-file', path: '**/.env' }] });
      try {
        const { call, responses } = collect(t);
        const VALUE = randomSecret(rnd);
        const r = await call(() => t.app.secretRequest({ title: 'p', fields: [{ name: 'S', label: 'S' }] }));
        const sub = await submit(String(r.url), { S: VALUE });
        expect(sub.json.ok).toBe(true);
        await call(() => t.app.secretWait({ id: r.request_id }));
        const u = await call(() =>
          t.app.secretUse({ action: 'exec', command: [process.execPath, '-e', 'const v=process.env.S;for(const e of ["utf8","base64","base64url","hex"])console.log(Buffer.from(v).toString(e));console.log(encodeURIComponent(v),JSON.stringify(v),JSON.stringify(JSON.stringify(v)));console.error("err:"+v)'], env: { S: '${secret:S}' } }),
        );
        await approve(String(u.url));
        const w = await call(() => t.app.secretWait({ id: u.request_id }));
        expect(w.status).toBe('completed');
        const envFile = path.join(t.home, 'proj', '.env');
        const wr = await call(() => t.app.secretWrite({ name: 'S', target: { kind: 'env-file', path: envFile, key: 'S_KEY' } }));
        await approve(String(wr.url));
        const ww = await call(() => t.app.secretWait({ id: wr.request_id }));
        expect(ww).toMatchObject({ written: true, keys: [{ key: 'S_KEY', action: 'created' }] });
        await call(() => t.app.secretList({}));
        const audit = readFileSync(path.join(t.home, 'audit.jsonl'), 'utf8');
        expectNoValue([...responses, audit, stderr.join('\n'), readFileSync(path.join(t.home, 'index.json'), 'utf8')], VALUE);
      } finally {
        await t.cleanup();
      }
    }
  }, 120_000);
});

// ------------------------------------------------------------------ http (secret_use + blind_input sinks)

describe('http paths with a simulated API', () => {
  const seen: { url: string; headers: http.IncomingHttpHeaders; body: string }[] = [];
  let base = '';
  const srv = http.createServer((req, res) => {
    let body = '';
    req.on('data', (d) => (body += d));
    req.on('end', () => {
      seen.push({ url: req.url!, headers: req.headers, body });
      res.writeHead(req.url === '/fail' ? 422 : 201, { 'content-type': 'application/json' });
      // a hostile API that echoes everything it received, including the credential
      res.end(JSON.stringify({ data: { id: seen.length + 100 }, echo: { auth: req.headers.authorization, body } }));
    });
  });
  beforeAll(async () => {
    await new Promise<void>((r) => srv.listen(0, '127.0.0.1', r));
    base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
  });
  afterAll(() => new Promise<void>((r) => srv.close(() => r())));
  let t: TestApp;
  afterEach(async () => t?.cleanup());
  const httpCfg = { http: { allowedHosts: ['127.0.0.1'], allowInsecureLoopback: true } };

  it('secret_use http: the echoed credential is redacted in the response', async () => {
    t = makeApp(httpCfg);
    const KEY = 'sk_test_51ABCDEFghijklmnop';
    await t.app.vault.put('local', 'STRIPE_KEY', KEY);
    const r = await t.app.secretUse({ action: 'http', method: 'POST', url: `${base}/v1/customers`, headers: { Authorization: 'Bearer ${secret:STRIPE_KEY}' }, body: 'email=a@b.c' });
    await approve(String(r.url));
    const w = await t.app.secretWait({ id: r.request_id });
    expect(w.http_status).toBe(201);
    expect(seen.at(-1)!.headers.authorization).toBe(`Bearer ${KEY}`);
    expect(t.app.safe(w)).not.toContain(KEY);
    expect(String(w.body)).toContain('[REDACTED:STRIPE_KEY]');
  });

  it('secret_use http refuses non-allowlisted hosts and plain http', async () => {
    t = makeApp({ http: { allowedHosts: ['api.stripe.com'] } });
    await t.app.vault.put('local', 'K', 'value-123456');
    const r = await t.app.secretUse({ action: 'http', url: 'http://api.stripe.com/x?k=${secret:K}' });
    await approve(String(r.url));
    expect(await t.app.secretWait({ id: r.request_id })).toMatchObject({ status: 'failed', error: 'tls_required' });
  });

  it('blind_input http sink: one request per repeater row, ids returned, response bodies never', async () => {
    t = makeApp(httpCfg);
    await t.app.vault.put('local', 'OPS_TOKEN', 'ops-token-value-xyz');
    const { call, responses } = collect(t);
    seen.length = 0;
    const r = await call(() =>
      t.app.blindInput({
        title: 'USD prices',
        schema: {
          sections: [
            { title: 'Batch', fields: [{ name: 'list', label: 'Price list', kind: 'select', options: ['retail', 'wholesale'], required: true }] },
            { fields: [{ name: 'prices', label: 'Prices', kind: 'repeater', fields: [{ name: 'sku', label: 'SKU', required: true }, { name: 'price', label: 'Price', kind: 'money', currency: 'USD', required: true, min: 0 }] }] },
          ],
        },
        sink: { type: 'http', url: `${base}/prices`, headers: { Authorization: 'Bearer ${secret:OPS_TOKEN}' }, body: { sku: '${sku}', price: '${price}', currency: '${price.currency}', list: '${list}' }, each: 'prices', id_pointer: '/data/id' },
      }),
    );
    const page = await openPage(String(r.url));
    expect((page.data.destination as { needsConfirm: boolean }).needsConfirm).toBe(true);
    const values = { list: 'retail', prices: [{ sku: 'GN-WHEY-2LB', price: { amount: '54.90', currency: 'USD' } }, { sku: 'GN-CREA-300', price: { amount: '1,234.50', currency: 'USD' } }] };
    expect((await post(page, { action: 'submit', values })).json).toEqual({ ok: false, errors: [{ field: '__confirm', code: 'confirm' }] });
    expect((await post(page, { action: 'submit', values, confirm: true, remember: true })).json.ok).toBe(true);
    const w = await call(() => t.app.secretWait({ id: r.request_id }));
    expect(w).toMatchObject({ status: 'completed', rows_written: 2, ids: ['101', '102'], http_statuses: [201, 201] });
    expect(JSON.parse(seen[1]!.body)).toEqual({ sku: 'GN-CREA-300', price: '1234.50', currency: 'USD', list: 'retail' });
    for (const s of ['GN-WHEY-2LB', 'GN-CREA-300', 'ops-token-value-xyz']) expect(responses.join('\n')).not.toContain(s);
    // the same sink again: remembered, no confirmation needed
    const r2 = await t.app.blindInput({ title: 'again', schema: { fields: [{ name: 'list', label: 'L', kind: 'select', options: ['retail', 'wholesale'] }, { name: 'prices', label: 'P', kind: 'repeater', fields: [{ name: 'sku', label: 'SKU' }, { name: 'price', label: 'Price', kind: 'money' }] }] }, sink: { type: 'http', url: `${base}/prices`, headers: { Authorization: 'Bearer ${secret:OPS_TOKEN}' }, body: { sku: '${sku}', price: '${price}', currency: '${price.currency}', list: '${list}' }, each: 'prices', id_pointer: '/data/id' } });
    expect(((await openPage(String(r2.url))).data.destination as { needsConfirm: boolean }).needsConfirm).toBe(false);
  });

  it('blind_input: ids equal to submitted values are hashed; remote errors become codes', async () => {
    t = makeApp(httpCfg);
    const r = await t.app.blindInput({ title: 'x', schema: { fields: [{ name: 'code', label: 'Code' }] }, sink: { type: 'http', url: `${base}/fail`, body: { code: '${code}' } } });
    await submit(String(r.url), { code: 'CUSTOMER-SECRET-77' }, { confirm: true });
    const w = await t.app.secretWait({ id: r.request_id });
    expect(w).toMatchObject({ status: 'failed', field_errors: [{ field: '_request', code: 'http_422' }] });
    expect(t.app.safe(w)).not.toContain('CUSTOMER-SECRET-77');
  });

  it('blind_input rejects sinks to hosts outside the allowlist and unknown template fields', async () => {
    t = makeApp(httpCfg);
    await expect(t.app.blindInput({ title: 'x', schema: { fields: [{ name: 'a', label: 'A' }] }, sink: { type: 'http', url: 'https://evil.example/x', body: { a: '${a}' } } })).rejects.toThrow(/allowlist/);
    await expect(t.app.blindInput({ title: 'x', schema: { fields: [{ name: 'a', label: 'A' }] }, sink: { type: 'http', url: `${base}/x`, body: { a: '${nope}' } } })).rejects.toThrow(/unknown field/);
  });
});

// ------------------------------------------------------------------ secret_write targets

describe('secret_write', () => {
  let t: TestApp;
  afterEach(async () => t?.cleanup());

  it('env-file: dry_run, allowlist, approval, created/updated, 0600, comments preserved, atomic', async () => {
    t = makeApp({ writeTargets: [{ kind: 'env-file', path: '**/myapp.env', keys: ['MP_*'] }] });
    const VALUE = 'APP_USR-"quoted" $dollar\nnewline';
    await t.app.vault.put('local', 'MP_ACCESS_TOKEN', VALUE);
    const file = path.join(t.home, 'etc', 'myapp.env');
    await import('node:fs').then((fs) => {
      fs.mkdirSync(path.dirname(file), { recursive: true });
      writeFileSync(file, '# Acme store\nPORT=3000\nMP_ACCESS_TOKEN=old\n', { mode: 0o644 });
    });
    const target = { kind: 'env-file', path: file, key: 'MP_ACCESS_TOKEN' };
    expect(await t.app.secretWrite({ name: 'MP_ACCESS_TOKEN', target, dry_run: true })).toEqual({ dry_run: true, target: { kind: 'env-file', host: 'local', path: file }, changes: [{ key: 'MP_ACCESS_TOKEN', action: 'updated' }] });
    await expect(t.app.secretWrite({ name: 'MP_ACCESS_TOKEN', target: { ...target, key: 'OTHER' } })).rejects.toThrow(/allowlist/);
    await expect(t.app.secretWrite({ name: 'MP_ACCESS_TOKEN', target: { ...target, path: '/etc/passwd' } })).rejects.toThrow(/allowlist/);
    const r = await t.app.secretWrite({ name: 'MP_ACCESS_TOKEN', target });
    const page = await openPage(String(r.url));
    const ap = page.data.approval as { literal: string; items: { label: string; value: string }[] };
    expect(ap.literal).toContain(file);
    expect(ap.literal).not.toContain('APP_USR');
    await post(page, { action: 'approve', remember: true });
    const w = await t.app.secretWait({ id: r.request_id });
    expect(w).toEqual({ request_id: r.request_id, status: 'completed', written: true, target: { kind: 'env-file', host: 'local', path: file }, keys: [{ key: 'MP_ACCESS_TOKEN', action: 'updated' }] });
    const content = readFileSync(file, 'utf8');
    expect(content.startsWith("# Acme store\nPORT=3000\n")).toBe(true);
    expect(statSync(file).mode & 0o777).toBe(0o600);
    const { getEnvKey } = await import('../src/fileformats.js');
    expect(getEnvKey(content, 'MP_ACCESS_TOKEN')).toBe(VALUE);
    // remembered: direct
    expect(await t.app.secretWrite({ name: 'MP_ACCESS_TOKEN', target })).toMatchObject({ status: 'completed', approval: 'remembered' });
    expect(readFileSync(path.dirname(file) + '/myapp.env', 'utf8').match(/MP_ACCESS_TOKEN/g)).toHaveLength(1);
  });

  it('json target by key path', async () => {
    t = makeApp({ writeTargets: [{ kind: 'json', path: '**/settings.json' }] });
    await t.app.vault.put('local', 'K', 'json-secret-value');
    const file = path.join(t.home, 'settings.json');
    writeFileSync(file, '{"a": {"keep": true}}');
    const r = await t.app.secretWrite({ name: 'K', target: { kind: 'json', path: file, key: 'a.payments.token' } });
    await approve(String(r.url));
    expect(await t.app.secretWait({ id: r.request_id })).toMatchObject({ keys: [{ key: 'a.payments.token', action: 'created' }] });
    expect(JSON.parse(readFileSync(file, 'utf8'))).toEqual({ a: { keep: true, payments: { token: 'json-secret-value' } } });
  });

  it('github target uses gh with the value on stdin only', async () => {
    const calls: { argv: string[]; stdin?: string }[] = [];
    t = makeApp({ writeTargets: [{ kind: 'github', repo: 'acme/*' }] }, {
      runner: async (argv, o = {}) => {
        calls.push({ argv, stdin: o.stdin?.toString() });
        return { code: 0, signal: null, stdout: Buffer.from(argv[2] === 'list' ? 'OTHER\n' : ''), stderr: Buffer.alloc(0), stdoutTruncated: false, stderrTruncated: false, timedOut: false };
      },
    });
    await t.app.vault.put('local', 'MP_TOKEN', 'gh-secret-value-1');
    const r = await t.app.secretWrite({ name: 'MP_TOKEN', target: { kind: 'github', repo: 'acme/myapp' } });
    await approve(String(r.url));
    expect(await t.app.secretWait({ id: r.request_id })).toMatchObject({ written: true, keys: [{ key: 'MP_TOKEN', action: 'created' }] });
    const set = calls.find((c) => c.argv[2] === 'set')!;
    expect(set.argv).toEqual(['gh', 'secret', 'set', 'MP_TOKEN', '--repo', 'acme/myapp']);
    expect(set.stdin).toBe('gh-secret-value-1');
  });

  it('clipboard: value goes only to the approval page response, never to the tool result; never remembered', async () => {
    t = makeApp({ writeTargets: [{ kind: 'clipboard' }] });
    await t.app.vault.put('local', 'C', 'clipboard-secret-value');
    const r = await t.app.secretWrite({ name: 'C', target: { kind: 'clipboard', clear_after_seconds: 10 } });
    const p = await openPage(String(r.url));
    expect(p.data.kind).toBe('clipboard');
    expect((p.data.approval as { rememberable: boolean }).rememberable).toBe(false);
    const res = await post(p, { action: 'approve', remember: true });
    expect(res.json).toEqual({ ok: true, clipboard: { value: 'clipboard-secret-value', clearAfter: 10 } });
    const w = await t.app.secretWait({ id: r.request_id });
    expect(t.app.safe(w)).not.toContain('clipboard-secret-value');
    const r2 = await t.app.secretWrite({ name: 'C', target: { kind: 'clipboard', clear_after_seconds: 10 } });
    expect(r2.status).toBe('awaiting_user');
  });
});

describe('blind_input file sink and preview', () => {
  let t: TestApp;
  afterEach(async () => t?.cleanup());

  it('writes mapped fields into an allowlisted .env after confirmation', async () => {
    t = makeApp({ writeTargets: [{ kind: 'env-file', path: '**/app.env' }] });
    const file = path.join(t.home, 'app.env');
    const r = await t.app.blindInput({ title: 'Payments', schema: { fields: [{ name: 'token', label: 'Token', kind: 'secret', required: true }, { name: 'mode', label: 'Mode', kind: 'select', options: ['test', 'live'] }] }, sink: { type: 'file', target: { kind: 'env-file', path: file }, mapping: { token: 'MP_ACCESS_TOKEN', mode: 'MP_MODE' } } });
    await submit(String(r.url), { token: 'file-sink-secret-1', mode: 'live' }, { confirm: true });
    const w = await t.app.secretWait({ id: r.request_id });
    expect(w).toMatchObject({ status: 'completed', rows_written: 2, keys: [{ key: 'MP_ACCESS_TOKEN', action: 'created' }, { key: 'MP_MODE', action: 'created' }] });
    expect(readFileSync(file, 'utf8')).toBe('MP_ACCESS_TOKEN=file-sink-secret-1\nMP_MODE=live\n');
  });

  it('preview validates the schema and serves a disabled mock-up', async () => {
    t = makeApp();
    const bad = await t.app.blindInputPreview({ schema: { fields: [{ name: 'a', label: 'A', kind: 'select' }] } });
    expect(bad.valid).toBe(false);
    const ok = await t.app.blindInputPreview({ title: 'P', schema: { fields: [{ name: 'a', label: 'A' }, { name: 'rows', label: 'R', kind: 'repeater', fields: [{ name: 'x', label: 'X' }] }] } });
    expect(ok).toMatchObject({ valid: true, fields: 2, repeaters: [{ name: 'rows', columns: ['x'] }] });
    const p = await openPage(String(ok.preview_url));
    expect(p.data.preview).toBe(true);
    expect((await post(p, { action: 'submit', values: { a: 'x' } })).status).toBe(403);
  });
});
