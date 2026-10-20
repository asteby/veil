import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { mkdirSync } from 'node:fs';
import path from 'node:path';
import { expect, test, type Page } from '@playwright/test';
import { makeApp, type TestApp } from '../test/helpers.js';

const SHOTS = process.env.SHOTS_DIR ?? path.join('test-results', 'shots');
mkdirSync(SHOTS, { recursive: true });
const shot = (page: Page, name: string) => page.screenshot({ path: path.join(SHOTS, `${name}.png`), fullPage: true });

let t: TestApp;
test.afterEach(async () => t?.cleanup());

test('secret_request form (English, light): show/hide, validation, submit', async ({ page }) => {
  t = makeApp({ ui: { openBrowser: false, lang: 'en' } });
  const r = await t.app.secretRequest({
    title: 'Stripe API keys',
    description: 'Paste the keys from dashboard.stripe.com → Developers → API keys.',
    fields: [
      { name: 'STRIPE_SECRET_KEY', label: 'Secret key', help: 'Starts with sk_live_ or sk_test_', pattern: 'sk_(live|test)_[A-Za-z0-9]+' },
      { name: 'STRIPE_MODE', label: 'Mode', kind: 'select', options: [{ value: 'test', label: 'Test' }, { value: 'live', label: 'Live' }] },
    ],
  });
  await page.goto(String(r.url));
  await expect(page.getByRole('heading', { name: 'Stripe API keys' })).toBeVisible();
  const secret = page.getByLabel('Secret key');
  await expect(secret).toHaveAttribute('type', 'password');
  await expect(secret).toHaveAttribute('autocomplete', 'new-password');
  await secret.fill('not-a-stripe-key');
  await page.getByRole('button', { name: 'Save securely' }).click();
  await expect(page.getByText('The value does not have the expected format.')).toBeVisible();
  await expect(secret).toHaveAttribute('aria-invalid', 'true');
  await expect(page.getByText('This field is required.')).toBeVisible();
  await shot(page, '01-secret-request-en-errors');
  await secret.fill('sk_test_51ABCdefGHIjkl');
  await page.getByRole('button', { name: 'Show' }).click();
  await expect(secret).toHaveAttribute('type', 'text');
  await page.getByRole('button', { name: 'Hide' }).click();
  await page.getByLabel('Mode').selectOption('test');
  await shot(page, '02-secret-request-en-filled');
  await page.getByRole('button', { name: 'Save securely' }).click();
  await expect(page.getByRole('status')).toContainText('never the values');
  await expect(page.locator('input')).toHaveCount(0); // form removed from the DOM
  await shot(page, '03-secret-request-en-saved');
  const w = await t.app.secretWait({ id: r.request_id });
  expect(w).toEqual({ request_id: r.request_id, status: 'completed', stored: ['STRIPE_SECRET_KEY', 'STRIPE_MODE'] });
});

test('secret_request form (Spanish, dark): Mercado Pago', async ({ browser }) => {
  t = makeApp();
  const ctx = await browser.newContext({ colorScheme: 'dark', locale: 'es-MX', viewport: { width: 420, height: 900 } });
  const page = await ctx.newPage();
  const r = await t.app.secretRequest({
    title: 'Credenciales de Mercado Pago',
    description: 'Tu panel → Tus integraciones → Credenciales de producción.',
    fields: [
      { name: 'MP_ACCESS_TOKEN', label: 'Access token', help: 'Empieza con APP_USR-' },
      { name: 'MP_PUBLIC_KEY', label: 'Public key', kind: 'text' },
    ],
    metadata: { project: 'myapp', rotate_after_days: 180 },
  });
  await page.goto(String(r.url));
  await expect(page.getByRole('button', { name: 'Guardar de forma segura' })).toBeVisible();
  await expect(page.locator('html')).toHaveAttribute('lang', 'es');
  await page.getByLabel('Access token').fill('APP_USR-1234-5678');
  await page.getByLabel('Public key').fill('APP_USR-pub-0000');
  await shot(page, '04-secret-request-es-dark-mobile');
  await page.getByRole('button', { name: 'Guardar de forma segura' }).click();
  await expect(page.getByRole('status')).toContainText('Guardado');
  await ctx.close();
  expect((await t.app.secretWait({ id: r.request_id })).stored).toEqual(['MP_ACCESS_TOKEN', 'MP_PUBLIC_KEY']);
});

test('blind_input: sections, money, conditional field, repeater with spreadsheet paste, http sink confirmation', async ({ page }) => {
  const received: unknown[] = [];
  const api = http.createServer((req, res) => {
    let b = '';
    req.on('data', (d) => (b += d));
    req.on('end', () => {
      received.push(JSON.parse(b));
      res.writeHead(201, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ data: { id: received.length } }));
    });
  });
  await new Promise<void>((r) => api.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${(api.address() as AddressInfo).port}`;
  t = makeApp({ ui: { openBrowser: false, lang: 'es' }, http: { allowedHosts: ['127.0.0.1'], allowInsecureLoopback: true } });
  const r = await t.app.blindInput({
    title: "Precios USD — Acme Store",
    description: 'Lista de precios en dólares. Puedes pegar desde Excel/Sheets.',
    schema: {
      sections: [
        { title: 'Lote', fields: [{ name: 'list', label: 'Lista de precios', kind: 'select', options: ['menudeo', 'mayoreo'], required: true }, { name: 'effective', label: 'Vigente desde', kind: 'date', required: true }, { name: 'has_promo', label: '¿Incluye promoción?', kind: 'boolean' }, { name: 'promo_code', label: 'Código de promoción', showIf: { field: 'has_promo', equals: true }, required: true }, { name: 'channels', label: 'Canales', kind: 'multiselect', options: ['tienda', 'whatsapp', 'mercadolibre'] }] },
        { title: 'Productos', fields: [{ name: 'rows', label: 'Precios', kind: 'repeater', minRows: 1, fields: [{ name: 'sku', label: 'SKU', required: true, pattern: '[A-Z0-9-]+' }, { name: 'price', label: 'Precio', kind: 'money', currencies: ['USD', 'MXN'], required: true, min: 0 }] }] },
      ],
    },
    sink: { type: 'http', url: `${base}/api/prices`, body: { list: '${list}', sku: '${sku}', price: '${price}', currency: '${price.currency}', since: '${effective}' }, each: 'rows', id_pointer: '/data/id' },
    submit_label: 'Enviar precios',
  });
  await page.goto(String(r.url));
  await page.getByLabel('Lista de precios').selectOption('mayoreo');
  await page.getByLabel('Vigente desde').fill('2026-11-01');
  await expect(page.getByLabel('Código de promoción')).toBeHidden();
  await page.getByLabel('¿Incluye promoción?').check();
  await expect(page.getByLabel('Código de promoción')).toBeVisible();
  await page.getByLabel('Código de promoción').fill('BUENFIN');
  await page.getByLabel('whatsapp').check();
  await page.getByLabel(/Pega filas/).fill('sku\tprecio\nGN-WHEY-2LB\t54.90\nGN-CREA-300\t19.50\nGN-BCAA-30\t1,234.00');
  await page.getByRole('button', { name: 'Importar filas pegadas' }).click();
  await expect(page.getByText('Se importaron 3 filas.')).toBeVisible();
  await expect(page.getByText('3 filas', { exact: true })).toBeVisible();
  // the CSV picker speaks the page language (not the browser's native "Choose File")
  await expect(page.getByText('Elegir archivo')).toBeVisible();
  await expect(page.getByText('Ningún archivo seleccionado')).toBeVisible();
  await expect(page.getByText('Choose File')).toHaveCount(0);
  await page.getByRole('button', { name: 'Agregar fila' }).click();
  await shot(page, '05-blind-input-repeater-es');
  await page.getByRole('button', { name: 'Enviar precios' }).click();
  await expect(page.getByText('Confirma el destino.')).toBeVisible();
  await page.getByLabel('Apruebo enviar estos valores a este destino').check();
  await shot(page, '06-blind-input-destination-confirm');
  await page.getByRole('button', { name: 'Enviar precios' }).click();
  await expect(page.getByRole('status')).toContainText('Guardado');
  const w = await t.app.secretWait({ id: r.request_id });
  expect(w).toMatchObject({ status: 'completed', rows_written: 3, ids: ['1', '2', '3'] });
  expect(received[2]).toEqual({ list: 'mayoreo', sku: 'GN-BCAA-30', price: '1234.00', currency: 'USD', since: '2026-11-01' });
  await new Promise<void>((res) => api.close(() => res()));
});

test('approval page for secret_use shows the literal action and warnings', async ({ page }) => {
  t = makeApp({ ui: { openBrowser: false, lang: 'en' } });
  await t.app.vault.put('local', 'DEPLOY_TOKEN', 'deploy-token-value-123');
  const r = await t.app.secretUse({ action: 'exec', shell: 'curl -fsS -H "Authorization: Bearer ${secret:DEPLOY_TOKEN}" https://api.example.com/deploy', cwd: '/srv/app' });
  await page.goto(String(r.url));
  await expect(page.getByRole('heading', { name: 'Run a command with stored secrets' })).toBeVisible();
  await expect(page.locator('pre.literal')).toContainText('Bearer ${secret:DEPLOY_TOKEN}');
  await expect(page.getByText('The script uses network or encoding tools.')).toBeVisible();
  await expect(page.locator('body')).not.toContainText('deploy-token-value-123');
  await shot(page, '07-approval-secret-use');
  await page.getByRole('button', { name: 'Deny' }).click();
  await expect(page.getByRole('status')).toContainText('Denied');
  expect((await t.app.secretWait({ id: r.request_id })).status).toBe('denied');
});

test('clipboard: copied only after the click and cleared automatically', async ({ browser }) => {
  t = makeApp({ ui: { openBrowser: false, lang: 'en' }, writeTargets: [{ kind: 'clipboard' }] });
  await t.app.vault.put('local', 'WIFI_PASSWORD', 'clipboard-value-XYZ');
  const r = await t.app.secretWrite({ name: 'WIFI_PASSWORD', target: { kind: 'clipboard', clear_after_seconds: 5 } });
  const ctx = await browser.newContext();
  await ctx.grantPermissions(['clipboard-read', 'clipboard-write'], { origin: new URL(String(r.url)).origin });
  const page = await ctx.newPage();
  await page.goto(String(r.url));
  await expect(page.locator('body')).not.toContainText('clipboard-value-XYZ');
  await shot(page, '08-clipboard-before');
  await page.getByRole('button', { name: 'Approve' }).click();
  await expect(page.getByRole('status')).toContainText('Clipboard will be cleared');
  // The intake page itself is forbidden to READ the clipboard (Permissions-Policy), so read it from another local page.
  const reader = http.createServer((_q, s) => s.end('<!doctype html><title>reader</title>'));
  await new Promise<void>((res) => reader.listen(0, '127.0.0.1', res));
  const readerUrl = `http://127.0.0.1:${(reader.address() as AddressInfo).port}/`;
  await ctx.grantPermissions(['clipboard-read', 'clipboard-write'], { origin: readerUrl.slice(0, -1) });
  const rp = await ctx.newPage();
  await rp.goto(readerUrl);
  expect(await rp.evaluate(() => navigator.clipboard.readText())).toBe('clipboard-value-XYZ');
  await page.bringToFront();
  await expect(page.getByRole('status')).toContainText('Clipboard cleared.', { timeout: 10_000 });
  await rp.bringToFront();
  expect(await rp.evaluate(() => navigator.clipboard.readText())).toBe('');
  await new Promise<void>((res) => reader.close(() => res()));
  await shot(page, '09-clipboard-cleared');
  await ctx.close();
});

test('preview page renders a disabled mock-up', async ({ page }) => {
  t = makeApp({ ui: { openBrowser: false, lang: 'en' } });
  const r = await t.app.blindInputPreview({ title: 'Customer data (preview)', schema: { fields: [{ name: 'rfc', label: 'RFC', pattern: '[A-Z&Ñ]{3,4}[0-9]{6}[A-Z0-9]{3}' }, { name: 'email', label: 'Email' }, { name: 'contacts', label: 'Contacts', kind: 'repeater', fields: [{ name: 'name', label: 'Name' }, { name: 'phone', label: 'Phone' }] }] } });
  await page.goto(String(r.preview_url));
  await expect(page.getByText('Preview: this is how the form will look')).toBeVisible();
  await expect(page.getByLabel('RFC')).toBeDisabled();
  await shot(page, '10-preview');
});

test('the link is single-use: a second browser cannot open it', async ({ browser }) => {
  t = makeApp({ ui: { openBrowser: false, lang: 'en' } });
  const r = await t.app.secretRequest({ title: 'One time', fields: [{ name: 'X', label: 'X' }] });
  const a = await browser.newContext();
  const b = await browser.newContext();
  await (await a.newPage()).goto(String(r.url));
  const pb = await b.newPage();
  const resp = await pb.goto(String(r.url));
  expect(resp?.status()).toBe(410);
  await expect(pb.getByText('This link has expired or was already used.')).toBeVisible();
  await shot(pb, '11-link-already-used');
  await a.close();
  await b.close();
});
