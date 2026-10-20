import { execFileSync, spawnSync } from 'node:child_process';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { buildSqlScript, csvCell } from '../src/sinks.js';
import { makeApp, openPage, post, type TestApp } from './helpers.js';

describe('SQL script builder (values never become SQL text)', () => {
  it('statement part contains only quoted identifiers; values travel as COPY CSV data', () => {
    const s = buildSqlScript('public.products', ['sku', 'price_usd'], 'upsert', ['sku'], 'id', false);
    const evil = `x'); DROP TABLE products;--`;
    const script = s.script([csvCell(evil), csvCell('1.50')].join(','));
    const [before, after] = script.split(/COPY si_in \("sku", "price_usd"\) FROM STDIN WITH \(FORMAT csv\);\n/);
    expect(before).not.toContain(evil);
    const [data, rest] = after!.split('\n\\.\n');
    expect(data).toBe(`"x'); DROP TABLE products;--","1.50"`);
    expect(rest).not.toContain(evil);
    expect(rest).toContain('INSERT INTO "public"."products" ("sku", "price_usd") SELECT "sku", "price_usd" FROM si_in ON CONFLICT ("sku") DO UPDATE SET "price_usd" = EXCLUDED."price_usd" RETURNING "id"');
    expect(script).toContain('\\set VERBOSITY sqlstate');
  });

  it('CSV cells: NULL is unquoted empty, quotes doubled, booleans and arrays typed', () => {
    expect(csvCell(null)).toBe('');
    expect(csvCell('')).toBe('""');
    expect(csvCell('a"b,c\nd')).toBe('"a""b,c\nd"');
    expect(csvCell(true)).toBe('"t"');
    expect(csvCell(['a', 'b"c'])).toBe('"{""a"",""b\\""c""}"');
  });

  it('rejects unsafe identifiers', () => {
    expect(() => buildSqlScript('products; drop', ['sku'], 'insert', undefined, undefined, false)).toThrow();
  });
});

function dockerOk(): boolean {
  if (process.env.SKIP_DOCKER === '1') return false;
  const r = spawnSync('docker', ['image', 'inspect', 'pgvector/pgvector:pg17'], { stdio: 'ignore' });
  const psql = spawnSync('psql', ['--version'], { stdio: 'ignore' });
  return r.status === 0 && psql.status === 0;
}

describe.skipIf(!dockerOk())('sql sink against a disposable Postgres (pgvector/pgvector:pg17)', () => {
  let container = '';
  let port = '';
  const PW = 'pg-test-password-5f2a';
  const psql = (sql: string) => execFileSync('psql', ['-X', '-q', '-At', '-c', sql], { env: { ...process.env, PGHOST: '127.0.0.1', PGPORT: port, PGUSER: 'postgres', PGPASSWORD: PW, PGDATABASE: 'postgres' }, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
  let t: TestApp;

  beforeAll(async () => {
    container = execFileSync('docker', ['run', '-d', '--rm', '-e', `POSTGRES_PASSWORD=${PW}`, '-p', '127.0.0.1::5432', 'pgvector/pgvector:pg17'], { encoding: 'utf8' }).trim();
    port = execFileSync('docker', ['port', container, '5432/tcp'], { encoding: 'utf8' }).trim().split(':').pop()!;
    for (let i = 0; i < 60; i++) {
      try {
        psql('select 1');
        break;
      } catch {
        await new Promise((r) => setTimeout(r, 500));
      }
    }
    // the image restarts once during init; wait for a stable server
    await new Promise((r) => setTimeout(r, 1500));
    for (let i = 0; i < 60; i++) {
      try {
        psql('select 1');
        break;
      } catch {
        await new Promise((r) => setTimeout(r, 500));
      }
    }
    psql('create table products (id serial primary key, sku text unique not null, name text, price_usd numeric(12,2) not null check (price_usd >= 0), active boolean default true, secret_note text)');
    t = makeApp({
      databases: { appdb: { psql: ['psql'], dsnSecret: 'local:pg_dsn', tables: { 'public.products': { columns: ['sku', 'name', 'price_usd', 'active'], conflict: ['sku'], returning: 'id' } }, maxRows: 100 } },
    });
    await t.app.vault.put('local', 'pg_dsn', `postgresql://postgres:${encodeURIComponent(PW)}@127.0.0.1:${port}/postgres`);
  }, 120_000);

  afterAll(async () => {
    await t?.cleanup();
    if (container) spawnSync('docker', ['rm', '-f', container], { stdio: 'ignore' });
  });

  const schema = { fields: [{ name: 'rows', label: 'Products', kind: 'repeater', fields: [{ name: 'sku', label: 'SKU', required: true }, { name: 'name', label: 'Name' }, { name: 'price', label: 'USD', kind: 'money', currency: 'USD', required: true }, { name: 'active', label: 'Active', kind: 'boolean' }] }] };
  const sink = (extra: Record<string, unknown> = {}) => ({ type: 'sql', database: 'appdb', table: 'public.products', mode: 'upsert', rows: 'rows', columns: { sku: '${sku}', name: '${name}', price_usd: '${price}', active: '${active}' }, ...extra });

  async function fill(rows: Record<string, unknown>[], extra: Record<string, unknown> = {}) {
    const r = await t.app.blindInput({ title: 'Load', schema, sink: sink(extra) });
    const p = await openPage(String(r.url));
    const res = await post(p, { action: 'submit', values: { rows }, confirm: true });
    return { res, w: await t.app.secretWait({ id: r.request_id }) };
  }

  it('inserts rows with parameters only (injection payloads stored literally), returns ids', async () => {
    const evil = `x'); DROP TABLE products;--`;
    const { w } = await fill([
      { sku: 'GN-1', name: evil, price: { amount: '54.90', currency: 'USD' }, active: true },
      { sku: 'GN-2', name: 'Creatina "300g", sabor\nnatural', price: { amount: '19.5', currency: 'USD' }, active: false },
    ]);
    expect(w).toMatchObject({ status: 'completed', rows_written: 2 });
    expect((w.ids as string[]).length).toBe(2);
    expect(psql("select name from products where sku='GN-1'")).toBe(evil);
    expect(psql("select price_usd||'|'||active from products where sku='GN-2'")).toBe('19.50|false');
    expect(t.app.safe(w)).not.toContain('GN-1');
  });

  it('dry_run validates in a transaction and writes nothing', async () => {
    const { w } = await fill([{ sku: 'DRY-1', price: { amount: '1', currency: 'USD' } }], { dry_run: true });
    expect(w).toMatchObject({ status: 'completed', rows_validated: 1, rows_written: 0, dry_run: true });
    expect(psql("select count(*) from products where sku='DRY-1'")).toBe('0');
  });

  it('upsert updates existing rows', async () => {
    const { w } = await fill([{ sku: 'GN-1', name: 'Whey 2lb', price: { amount: '49.00', currency: 'USD' }, active: true }]);
    expect(w).toMatchObject({ rows_written: 1 });
    expect(psql("select price_usd from products where sku='GN-1'")).toBe('49.00');
  });

  it('constraint errors come back as SQLSTATE codes without values, and roll back the batch', async () => {
    const before = psql('select count(*) from products');
    const r = await t.app.blindInput({ title: 'x', schema, sink: sink({ mode: 'insert' }) });
    const p = await openPage(String(r.url));
    await post(p, { action: 'submit', values: { rows: [{ sku: 'NEW-OK', price: { amount: '5', currency: 'USD' } }, { sku: 'GN-2', name: 'dup-sensitive-name', price: { amount: '5', currency: 'USD' } }] }, confirm: true });
    const w = await t.app.secretWait({ id: r.request_id });
    expect(w).toMatchObject({ status: 'failed', field_errors: [{ field: '_sql', code: 'sql_23505' }] });
    expect(t.app.safe(w)).not.toContain('GN-2');
    expect(t.app.safe(w)).not.toContain('dup-sensitive-name');
    expect(psql('select count(*) from products')).toBe(before);
  });

  it('negative price fails the CHECK constraint (23514) and a non-allowlisted column is refused up front', async () => {
    const { w } = await fill([{ sku: 'NEG', price: { amount: '-1', currency: 'USD' } }]);
    expect(w).toMatchObject({ field_errors: [{ code: 'sql_23514' }] });
    await expect(t.app.blindInput({ title: 'x', schema: { fields: [{ name: 'a', label: 'A' }] }, sink: { type: 'sql', database: 'appdb', table: 'public.products', columns: { secret_note: '${a}' } } })).rejects.toThrow(/not allowed/);
    await expect(t.app.blindInput({ title: 'x', schema: { fields: [{ name: 'a', label: 'A' }] }, sink: { type: 'sql', database: 'appdb', table: 'pg_catalog.pg_authid', columns: { rolname: '${a}' } } })).rejects.toThrow(/not allowed/);
  });
});
