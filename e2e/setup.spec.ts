import { existsSync, mkdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { expect, test, type Page } from '@playwright/test';
import { KeychainError } from '../src/errors.js';
import type { KeychainBackend } from '../src/stores/keychain.js';
import { makeApp, type TestApp } from '../test/helpers.js';

const SHOTS = process.env.SHOTS_DIR ?? path.join('test-results', 'shots');
mkdirSync(SHOTS, { recursive: true });
const shot = (page: Page, name: string) => page.screenshot({ path: path.join(SHOTS, `${name}.png`), fullPage: true });

const VALUE = 'APP_USR-8812-secret-e2e-value';
const MASTER = 'tres tristes tigres 2026';

/** A machine without secret-tool (the incident on Linux Mint). */
const noSecretTool: KeychainBackend = {
  name: 'secret-tool',
  set: async () => {
    throw new KeychainError('secret-tool is not installed or not executable', 'keychain_unavailable', 'missing_tool');
  },
  get: async () => {
    throw new KeychainError('secret-tool is not installed or not executable', 'keychain_unavailable', 'missing_tool');
  },
  delete: async () => false,
};

let t: TestApp;
test.afterEach(async () => t?.cleanup());

test('keychain missing (Spanish): the page offers the encrypted store and defines the master password there', async ({ browser }) => {
  t = makeApp({ destinations: { local: { type: 'keychain' } }, ui: { openBrowser: false, lang: 'es' } }, { keychainBackend: noSecretTool });
  const ctx = await browser.newContext({ locale: 'es-MX' });
  const page = await ctx.newPage();
  const r = await t.app.secretRequest({ title: 'Credenciales de Mercado Pago', description: 'Tu panel → Credenciales de producción.', fields: [{ name: 'MP_ACCESS_TOKEN', label: 'Access token' }] });
  await page.goto(String(r.url));
  await page.getByLabel('Access token').fill(VALUE);
  await page.getByRole('button', { name: 'Guardar de forma segura' }).click();

  // the warning: what failed, the exact command to fix it, and the offer
  const fb = page.locator('section.fallback');
  await expect(fb.getByRole('heading', { name: 'No se pudo usar el llavero del sistema' })).toBeVisible();
  await expect(fb).toContainText('secret-tool (libsecret) no está instalado');
  await expect(fb.locator('.cmd code')).toHaveText(/install .*libsecret|secret-tool/);
  await expect(fb).toContainText('Define aquí la contraseña maestra');
  await expect(page.getByRole('button', { name: 'Guardar de forma segura' })).toBeHidden();
  await shot(page, '10-es-llavero-no-disponible-aviso');

  // client-side checks before anything is sent
  await page.getByLabel('Contraseña maestra', { exact: true }).fill('corta');
  await page.getByRole('button', { name: 'Continuar con el almacén cifrado' }).click();
  await expect(fb.locator('.error')).toHaveText('Demasiado corta.');

  await page.getByLabel('Contraseña maestra', { exact: true }).fill(MASTER);
  await page.getByLabel('Repite la contraseña maestra').fill(MASTER);
  await page.getByLabel('Entiendo, y guardo una copia').check();
  await expect(fb.locator('.backup')).toContainText('nadie puede recuperar');
  await shot(page, '11-es-alta-contrasena-maestra');
  await page.getByRole('button', { name: 'Continuar con el almacén cifrado' }).click();
  await expect(page.getByRole('status')).toContainText('Guardado en el almacén cifrado de Veil');
  await expect(page.locator('input')).toHaveCount(0);
  await shot(page, '12-es-guardado-en-almacen-cifrado');
  await ctx.close();

  const w = await t.app.secretWait({ id: r.request_id });
  expect(w).toMatchObject({ status: 'completed', stored: ['MP_ACCESS_TOKEN'], stored_in_local_vault: ['MP_ACCESS_TOKEN'] });
  expect((await t.app.vault.resolve('MP_ACCESS_TOKEN')).value).toBe(VALUE);
  for (const f of ['audit.jsonl', 'index.json', 'local-vault.json']) {
    const p = path.join(t.home, f);
    if (!existsSync(p)) continue;
    const text = readFileSync(p, 'utf8');
    expect(text).not.toContain(VALUE);
    expect(text).not.toContain(MASTER);
  }
});

test('keychain missing (English, dark): mismatch error, then unlock mode for an existing store', async ({ browser }) => {
  t = makeApp({ destinations: { local: { type: 'keychain' } }, ui: { openBrowser: false, lang: 'en' } }, { keychainBackend: noSecretTool });
  const ctx = await browser.newContext({ colorScheme: 'dark', viewport: { width: 420, height: 1000 } });
  const page = await ctx.newPage();
  const r = await t.app.secretRequest({ title: 'Stripe API key', fields: [{ name: 'STRIPE_SECRET_KEY', label: 'Secret key' }] });
  await page.goto(String(r.url));
  await page.getByLabel('Secret key').fill('sk_test_e2e_value_123');
  await page.getByRole('button', { name: 'Save securely' }).click();
  await page.getByLabel('Master password', { exact: true }).fill(MASTER);
  await page.getByLabel('Repeat the master password').fill(MASTER + '!');
  await page.getByLabel('I understand').check();
  await page.getByRole('button', { name: 'Continue with the encrypted store' }).click();
  await expect(page.locator('section.fallback .error')).toHaveText('The two passphrases do not match.');
  await shot(page, '13-en-dark-mobile-mismatch');
  await page.getByLabel('Master password', { exact: true }).fill(MASTER);
  await page.getByLabel('Repeat the master password').fill(MASTER);
  await page.getByRole('button', { name: 'Continue with the encrypted store' }).click();
  await expect(page.getByRole('status')).toContainText("Veil's encrypted store");
  await ctx.close();

  // a later request after a restart: the store exists but is locked -> unlock mode
  t.app.vault.lockLocalVaults();
  const page2 = await browser.newPage();
  const r2 = await t.app.secretRequest({ title: 'GitHub token', fields: [{ name: 'GH_TOKEN', label: 'Token' }] });
  await page2.goto(String(r2.url));
  await page2.getByLabel('Token').fill('ghp_e2e_value_456');
  await page2.getByRole('button', { name: 'Save securely' }).click();
  await expect(page2.locator('section.fallback')).toContainText('type its master password');
  await expect(page2.getByLabel('Repeat the master password')).toHaveCount(0);
  await page2.getByLabel('Master password').fill('not the password');
  await page2.getByRole('button', { name: 'Continue with the encrypted store' }).click();
  await expect(page2.locator('section.fallback .error')).toContainText('Wrong passphrase');
  await shot(page2, '14-en-unlock-wrong-password');
  await page2.getByLabel('Master password').fill(MASTER);
  await page2.getByRole('button', { name: 'Continue with the encrypted store' }).click();
  await expect(page2.getByRole('status')).toContainText('Saved');
  expect((await t.app.secretWait({ id: r2.request_id })).status).toBe('completed');
  await page2.close();
});

test('fallback "never": an actionable error page (help + exact command), never a bare sink_failed', async ({ page }) => {
  t = makeApp({ destinations: { local: { type: 'keychain', fallback: 'never' } }, ui: { openBrowser: false, lang: 'es' } }, { keychainBackend: noSecretTool });
  const r = await t.app.secretRequest({ title: 'Token de despliegue', fields: [{ name: 'DEPLOY_TOKEN', label: 'Token' }] });
  await page.goto(String(r.url) + '?lang=es');
  await page.getByLabel('Token').fill('deploy-e2e-value');
  await page.getByRole('button', { name: 'Guardar de forma segura' }).click();
  await expect(page.getByRole('status')).toContainText('secret-tool (libsecret) no está instalado');
  await expect(page.getByRole('heading', { name: 'Cómo arreglarlo' })).toBeVisible();
  await expect(page.locator('.cmd code').last()).toHaveText('veilform init');
  await expect(page.locator('body')).not.toContainText('sink_failed');
  await shot(page, '15-es-error-accionable');
});

test('local_unlock page (Spanish): define the master password outside any request', async ({ browser }) => {
  t = makeApp({ destinations: { local: { type: 'keychain' } }, ui: { openBrowser: false, lang: 'es' } }, { keychainBackend: noSecretTool });
  const page = await browser.newPage({ locale: 'es-MX' });
  const r = await t.app.localUnlock({});
  await page.goto(String(r.url));
  await expect(page.getByRole('heading', { name: 'Crear el almacén cifrado de Veil' })).toBeVisible();
  await page.getByLabel(/^Contraseña maestra/).fill(MASTER);
  await page.getByLabel('Repite la contraseña maestra').fill(MASTER);
  await page.getByLabel('Entiendo').check();
  await shot(page, '16-es-local-unlock-crear');
  await page.getByRole('button', { name: 'Crear' }).click();
  await expect(page.getByRole('status')).toContainText('Listo');
  expect(await t.app.secretWait({ id: r.request_id })).toMatchObject({ status: 'completed', created: true, unlocked: true });
  await page.close();
});
