import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { expect, test, type Page } from '@playwright/test';
import { createKeyFile } from '../src/crypto/keysource.js';
import { registerRevealPage } from '../src/vaulttools.js';
import { makeApp, tmpDir, type TestApp } from '../test/helpers.js';

const SHOTS = process.env.SHOTS_DIR ?? path.join('test-results', 'shots');
mkdirSync(SHOTS, { recursive: true });
const shot = (page: Page, name: string) => page.screenshot({ path: path.join(SHOTS, `${name}.png`), fullPage: true });

const apps: TestApp[] = [];
test.afterAll(async () => {
  for (const a of apps) await a.cleanup();
});

function onlyLocal(page: Page, origin: string): string[] {
  const outside: string[] = [];
  page.on('request', (r) => {
    if (!r.url().startsWith(origin)) outside.push(r.url());
  });
  return outside;
}

test('share by token: create (names only, passphrase), person reveal page via URL fragment, auto-hide', async ({ browser }) => {
  const drop = path.join(tmpDir(), 'drop');
  const cfg = { ui: { openBrowser: false, lang: 'en' }, sync: { targets: { team: { type: 'dir', path: drop } }, shareTarget: 'team' } };
  const S = makeApp(cfg);
  const R = makeApp(cfg);
  apps.push(S, R);
  const VALUE = 'sk_live_51Hshared-e2e-VALUE';
  await S.app.vault.put('local', 'STRIPE_SECRET_KEY', VALUE);
  await S.app.vault.put('local', 'STRIPE_WEBHOOK_SECRET', 'whsec_e2e_value_2');

  const ctx = await browser.newContext({ permissions: ['clipboard-read', 'clipboard-write'] });
  const page = await ctx.newPage();
  const r = await S.app.tools.shareCreate({ names: ['STRIPE_SECRET_KEY', 'STRIPE_WEBHOOK_SECRET'], expires_in: '2h', max_views: 1, require_passphrase: true, note: 'Stripe keys for Ana (staging deploy)' });
  const origin = new URL(String(r.url)).origin;
  const outside = onlyLocal(page, origin);
  await page.goto(String(r.url));
  await expect(page.getByRole('heading', { name: 'Share 2 secret(s) by token' })).toBeVisible();
  await expect(page.getByText('STRIPE_SECRET_KEY (local)')).toBeVisible();
  await expect(page.locator('body')).not.toContainText(VALUE);
  await page.getByLabel('Share passphrase (send it through ANOTHER channel)').fill('blue-river-42-share');
  await page.getByLabel('Repeat the share passphrase').fill('blue-river-42-share');
  await page.getByLabel('I approve sending these values to this destination').check();
  await shot(page, 'share-01-create');
  await page.getByRole('button', { name: 'Create share and show the token' }).click();
  await expect(page.getByRole('heading', { name: 'Only on this page' })).toBeVisible();
  await page.getByRole('button', { name: 'Show' }).click();
  const token = (await page.locator('code.secret-val').textContent())!;
  expect(token).toMatch(/^vfs1:\/\/team\//);
  await page.getByRole('button', { name: 'Copy value' }).click();
  await expect(page.getByRole('button', { name: 'Copied' })).toBeVisible();
  await shot(page, 'share-02-token-shown');
  const w = await S.app.secretWait({ id: r.request_id });
  expect(JSON.stringify(w)).not.toContain(token.split('#')[1]!);
  expect(outside).toEqual([]);
  await ctx.close();

  // the person who receives it: token in the URL fragment, passphrase typed on the page
  const ctx2 = await browser.newContext({ colorScheme: 'dark', permissions: ['clipboard-read', 'clipboard-write'] });
  const p2 = await ctx2.newPage();
  const { url, done } = await registerRevealPage(R.app, { hideAfter: 4 });
  const outside2 = onlyLocal(p2, new URL(url).origin);
  await p2.goto(`${url}#${token}`);
  expect(p2.url()).not.toContain('#');
  expect(p2.url()).not.toContain('vfs1');
  await expect(p2.getByLabel('Share token (vfs1://...)')).toHaveValue(token);
  await p2.getByLabel(/Passphrase/).fill('wrong-guess-123');
  await p2.getByRole('button', { name: 'Open' }).click();
  await expect(p2.getByText('Wrong passphrase or token (attempts are limited).')).toBeVisible();
  await shot(p2, 'share-03-reveal-wrong-passphrase');
  await p2.getByLabel(/Passphrase/).fill('blue-river-42-share');
  await p2.getByRole('button', { name: 'Open' }).click();
  await expect(p2.getByText('STRIPE_SECRET_KEY', { exact: true })).toBeVisible();
  await expect(p2.locator('body')).not.toContainText(VALUE);
  await p2.getByRole('button', { name: 'Show' }).first().click();
  await expect(p2.locator('code.secret-val').first()).toHaveText(VALUE);
  await expect(p2.getByText(/consumed and was deleted from storage/)).toBeVisible();
  await shot(p2, 'share-04-reveal-shown-dark');
  await expect(p2.getByText('Values hidden. This single-use page cannot show them again.')).toBeVisible({ timeout: 8000 });
  await expect(p2.locator('body')).not.toContainText(VALUE);
  await shot(p2, 'share-05-reveal-hidden');
  expect(await done).toEqual({ status: 'completed', names: ['STRIPE_SECRET_KEY', 'STRIPE_WEBHOOK_SECRET'] });
  expect(outside2).toEqual([]);
  // the link is single use
  const p3 = await ctx2.newPage();
  await p3.goto(url);
  await expect(p3.getByText('This link has expired or was already used.')).toBeVisible();
  await ctx2.close();
  const audit = readFileSync(path.join(R.home, 'audit.jsonl'), 'utf8');
  expect(audit).toContain('"event":"share_read"');
  expect(audit).not.toContain(VALUE);
});

test('env_edit page (Spanish): keys listed, current values only on request, re-encrypt on save', async ({ browser }) => {
  const proj = tmpDir('vf-e2e-env-');
  const key = createKeyFile(path.join(tmpDir(), 'e2e.key'));
  const t = makeApp({ ui: { openBrowser: false, lang: 'es' }, env: { keyFiles: [key.where] } });
  apps.push(t);
  const f = path.join(proj, '.env.production');
  writeFileSync(f, '# producción\nDATABASE_URL=postgres://app:Pr0d-pass@db/app\nMP_ACCESS_TOKEN=APP_USR-111-222\nPORT=8080\n');
  await t.app.envFiles.encrypt(f, { keyFiles: [key.where] });
  const ctx = await browser.newContext({ locale: 'es-MX', viewport: { width: 760, height: 1000 } });
  const page = await ctx.newPage();
  const r = await t.app.tools.envEdit({ file: f });
  await page.goto(String(r.url));
  await expect(page.getByRole('textbox', { name: 'MP_ACCESS_TOKEN' })).toHaveAttribute('type', 'password');
  await expect(page.locator('body')).not.toContainText('APP_USR-111-222');
  await shot(page, 'env-01-edit-form-es');
  await page.getByRole('button', { name: 'Show current values (only here)' }).click();
  await expect(page.getByRole('heading', { name: 'Solo en esta página' })).toBeVisible();
  await page.locator('.reveal-item', { hasText: 'MP_ACCESS_TOKEN' }).getByRole('button', { name: 'Mostrar' }).click();
  await expect(page.locator('.reveal-item', { hasText: 'MP_ACCESS_TOKEN' }).locator('code')).toHaveText('APP_USR-111-222');
  await shot(page, 'env-02-edit-reveal-es');
  await page.getByRole('textbox', { name: 'MP_ACCESS_TOKEN' }).fill('APP_USR-333-444-rotated');
  await page.getByRole('button', { name: 'Encrypt and save' }).click();
  await expect(page.getByRole('status')).toContainText('Guardado');
  await shot(page, 'env-03-edit-saved-es');
  const w = await t.app.secretWait({ id: r.request_id });
  expect(w).toMatchObject({ status: 'completed', changed: ['MP_ACCESS_TOKEN'] });
  expect(readFileSync(f, 'utf8')).not.toContain('APP_USR');
  expect((await t.app.envFiles.decrypt(f)).entries.find((e) => e.key === 'MP_ACCESS_TOKEN')!.value).toBe('APP_USR-333-444-rotated');
  await ctx.close();
});
