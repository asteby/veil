/*
 * README visuals: screenshots and a short recording of the REAL local pages,
 * driven through the same App the MCP server uses (test helpers, in-memory keychain).
 * Generic sample data ("Acme"); no real credentials.
 *
 *   npx playwright test --config scripts/readme-assets/playwright.config.ts
 *
 * Requires ffmpeg with libwebp on PATH (PNG/WebM -> WebP).
 */
import { execFileSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { expect, test, type Browser, type Page } from '@playwright/test';
import { makeApp, memKeychain, type TestApp } from '../../test/helpers.js';

const ROOT = path.resolve(import.meta.dirname, '../..');
const OUT = path.join(ROOT, 'docs/assets');
const WORK = mkdtempSync(path.join(tmpdir(), 'veil-readme-'));
const LANGS = ['en', 'es'] as const;
const THEMES = ['light', 'dark'] as const;
type Lang = (typeof LANGS)[number];
type Theme = (typeof THEMES)[number];

const TXT = {
  en: {
    formTitle: 'Acme Store — payment credentials',
    formDesc: 'Paste the production credentials from your payment provider dashboard.',
    token: 'Access token',
    tokenHelp: 'Starts with APP_USR-',
    pub: 'Public key',
    env: 'Environment',
    tableTitle: 'Acme Store — wholesale prices (USD)',
    tableDesc: 'Paste the rows straight from Excel or Google Sheets.',
    list: 'Price list',
    rows: 'Prices',
    sku: 'SKU',
    price: 'Price',
    submitPrices: 'Send prices',
    listOpts: ['retail', 'wholesale'],
    paste: /Paste rows/,
    importBtn: 'Import pasted rows',
    imported: 'Imported 4 rows.',
    save: 'Save securely',
    approve: 'Approve',
    confirm: 'I approve sending these values to this destination',
  },
  es: {
    formTitle: 'Acme Store — credenciales de pago',
    formDesc: 'Pega las credenciales de producción del panel de tu proveedor de pagos.',
    token: 'Access token',
    tokenHelp: 'Empieza con APP_USR-',
    pub: 'Public key',
    env: 'Entorno',
    tableTitle: 'Acme Store — precios de mayoreo (USD)',
    tableDesc: 'Pega las filas tal cual desde Excel o Google Sheets.',
    list: 'Lista de precios',
    rows: 'Precios',
    sku: 'SKU',
    price: 'Precio',
    submitPrices: 'Enviar precios',
    listOpts: ['menudeo', 'mayoreo'],
    paste: /Pega filas/,
    importBtn: 'Importar filas pegadas',
    imported: 'Se importaron 4 filas.',
    save: 'Guardar de forma segura',
    approve: 'Aprobar',
    confirm: 'Apruebo enviar estos valores a este destino',
  },
} as const;

const SAMPLE_ROWS = 'sku\tprice\nACME-TSHIRT-M\t12.90\nACME-HOODIE-L\t34.50\nACME-MUG-11OZ\t8.75\nACME-CAP-OS\t1,150.00';

let t: TestApp | undefined;
test.afterEach(async () => {
  await t?.cleanup();
  t = undefined;
});
test.afterAll(() => rmSync(WORK, { recursive: true, force: true }));

function app(lang: Lang, extra: Record<string, unknown> = {}): TestApp {
  t = makeApp({
    ui: { openBrowser: false, lang },
    databases: {
      appdb: {
        psql: ['psql', '-d', 'appdb'],
        tables: { 'public.product_prices': { columns: ['sku', 'price_usd', 'list'], conflict: ['sku', 'list'], returning: 'id' } },
      },
    },
    ...extra,
  }, {
    // In-memory keychain, labelled like the real Linux backend so the destination box reads as it would.
    keychainBackend: Object.assign(memKeychain(), { name: 'secret-tool' }),
  });
  return t;
}

/** "http://127.0.0.1:41234/p/AbCdEf…" -> "127.0.0.1:41234/p/AbCdEf…" (token shortened). */
function shortUrl(u: string): string {
  const x = new URL(u);
  const tok = x.pathname.split('/')[2] ?? '';
  return `${x.host}/p/${tok.slice(0, 6)}…`;
}

function toWebp(png: string, out: string, quality = 82): number {
  mkdirSync(path.dirname(out), { recursive: true });
  execFileSync('ffmpeg', ['-y', '-loglevel', 'error', '-i', png, '-c:v', 'libwebp', '-pix_fmt', 'yuva420p', '-quality', String(quality), '-compression_level', '6', out]);
  return statSync(out).size;
}

const FRAME_CSS = `
*{box-sizing:border-box}html,body{margin:0;background:transparent}
body{font:13px/1.2 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.stage{display:inline-block;padding:22px 26px 34px}
.win{border-radius:12px;overflow:hidden;box-shadow:0 1px 2px rgba(0,0,0,.18),0 12px 32px rgba(15,23,42,.18);border:1px solid var(--edge)}
.bar{height:42px;display:flex;align-items:center;gap:14px;padding:0 14px;background:var(--bar);border-bottom:1px solid var(--edge)}
.dots{display:flex;gap:7px}.dots i{width:12px;height:12px;border-radius:50%;display:block}
.dots i:nth-child(1){background:#ff5f57}.dots i:nth-child(2){background:#febc2e}.dots i:nth-child(3){background:#28c840}
.addr{flex:1;max-width:520px;margin:0 auto;height:26px;border-radius:7px;background:var(--addr);color:var(--addrText);display:flex;align-items:center;justify-content:center;gap:6px;font-size:12.5px;letter-spacing:.01em}
.addr b{font-weight:600;color:var(--host)}
.pad{width:52px}
img{display:block}
.phone{border-radius:46px;padding:12px;background:#0d0f13;box-shadow:0 0 0 1.5px #3a3f4a inset,0 16px 40px rgba(15,23,42,.28)}
.screen{border-radius:36px;overflow:hidden;background:var(--bar)}
.mbar{padding:34px 14px 10px;background:var(--bar);border-bottom:1px solid var(--edge)}
.mbar .addr{max-width:none;height:32px;border-radius:10px;font-size:13px}
.light{--bar:#eceef2;--edge:#d3d7de;--addr:#ffffff;--addrText:#4a5260;--host:#16181d}
.dark{--bar:#20242c;--edge:#343a46;--addr:#151820;--addrText:#a7aebb;--host:#e8eaef}
`;

// Neutral "info" glyph (plain http on loopback: no padlock, that would be a lie).
function infoSvg(): string {
  return '<svg width="13" height="13" viewBox="0 0 16 16" aria-hidden="true"><circle cx="8" cy="8" r="6.6" fill="none" stroke="currentColor" stroke-width="1.4"/><rect x="7.3" y="7" width="1.4" height="4.6" rx=".7" fill="currentColor"/><circle cx="8" cy="4.9" r=".9" fill="currentColor"/></svg>';
}

function addrHtml(url: string): string {
  const [host, ...rest] = url.split('/');
  return `${infoSvg()}<span><b>${host}</b>/${rest.join('/')}</span>`;
}

/** Puts a raw page screenshot inside a clean browser window (or phone) and writes a WebP. */
async function frame(browser: Browser, raw: string, opts: { url: string; theme: Theme; mobile?: boolean; width: number; height: number }, out: string): Promise<number> {
  const ctx = await browser.newContext({ deviceScaleFactor: 2, viewport: { width: 1400, height: 1400 } });
  const page = await ctx.newPage();
  const img = `data:image/png;base64,${readFileSync(raw).toString('base64')}`;
  const body = opts.mobile
    ? `<div class="stage ${opts.theme}"><div class="phone"><div class="screen"><div class="mbar"><div class="addr">${addrHtml(opts.url)}</div></div><img src="${img}" width="${opts.width}" height="${opts.height}" alt=""></div></div></div>`
    : `<div class="stage ${opts.theme}"><div class="win"><div class="bar"><div class="dots"><i></i><i></i><i></i></div><div class="addr">${addrHtml(opts.url)}</div><div class="pad"></div></div><img src="${img}" width="${opts.width}" height="${opts.height}" alt=""></div></div>`;
  await page.setContent(`<!doctype html><meta charset="utf-8"><style>${FRAME_CSS}</style>${body}`);
  const png = raw.replace(/\.png$/, '.framed.png');
  await page.locator('.stage').screenshot({ path: png, omitBackground: true });
  await ctx.close();
  return toWebp(png, out);
}

const sizes: Record<string, number> = {};
function record(out: string, bytes: number) {
  sizes[path.relative(ROOT, out)] = bytes;
}
test.afterAll(() => {
  for (const [k, v] of Object.entries(sizes)) console.log(`${(v / 1024).toFixed(1).padStart(7)} KB  ${k}`);
});

async function newPage(browser: Browser, lang: Lang, theme: Theme, viewport: { width: number; height: number }, dsf = 2) {
  const ctx = await browser.newContext({ colorScheme: theme, locale: lang === 'es' ? 'es-MX' : 'en-US', viewport, deviceScaleFactor: dsf });
  return { ctx, page: await ctx.newPage() };
}

/** Screenshot of a vertical slice of the page (document coordinates). Returns its CSS size. */
async function shotSlice(page: Page, file: string, from: string | null, to: string, padTop = 16, padBottom = 20) {
  await page.evaluate(() => {
    (document.activeElement as HTMLElement | null)?.blur();
    window.scrollTo(0, 0);
  });
  await page.mouse.move(0, 0);
  const top = from ? Math.max(0, Math.floor((await page.locator(from).first().boundingBox())!.y - padTop)) : 0;
  const b = (await page.locator(to).first().boundingBox())!;
  const width = page.viewportSize()!.width;
  const height = Math.ceil(b.y + b.height + padBottom - top);
  await page.screenshot({ path: file, fullPage: true, clip: { x: 0, y: top, width, height } });
  return { width, height };
}

async function openForm(a: TestApp, lang: Lang) {
  const s = TXT[lang];
  return a.app.secretRequest({
    title: s.formTitle,
    description: s.formDesc,
    fields: [
      { name: 'MP_ACCESS_TOKEN', label: s.token, help: s.tokenHelp, pattern: 'APP_USR-[A-Za-z0-9-]+' },
      { name: 'MP_PUBLIC_KEY', label: s.pub, kind: 'text', required: false },
      { name: 'MP_ENV', label: s.env, kind: 'select', options: [{ value: 'production', label: 'production' }, { value: 'sandbox', label: 'sandbox' }] },
    ],
  });
}

async function fillForm(page: Page, lang: Lang, typeDelay = 0) {
  const s = TXT[lang];
  const tok = page.getByLabel(s.token);
  await tok.click();
  await tok.pressSequentially('APP_USR-4821-acme-demo-0000-token', { delay: typeDelay });
  await page.getByLabel(s.pub).pressSequentially('APP_USR-pub-acme-0000', { delay: typeDelay ? typeDelay / 2 : 0 });
  await page.getByLabel(s.env).selectOption('production');
}

for (const lang of LANGS) {
  for (const theme of THEMES) {
    test(`shots ${lang} ${theme}`, async ({ browser }) => {
      const s = TXT[lang];
      const dir = path.join(OUT, 'shots', lang);
      const raw = (n: string) => path.join(WORK, `${lang}-${theme}-${n}.png`);
      const out = (n: string) => path.join(dir, `${n}-${theme}.webp`);

      const save = async (n: string, url: string, size: { width: number; height: number }, mobile = false) =>
        record(out(n), await frame(browser, raw(n), { url: shortUrl(url), theme, mobile, ...size }, out(n)));

      // 1. Secret form (desktop): whole page, values typed (the secret shows as dots)
      {
        const a = app(lang);
        const r = await openForm(a, lang);
        const { ctx, page } = await newPage(browser, lang, theme, { width: 900, height: 700 });
        await page.goto(String(r.url));
        await fillForm(page, lang);
        await save('form', String(r.url), await shotSlice(page, raw('form'), null, '.actions', 0, 28));
        await ctx.close();
        await a.cleanup();
        t = undefined;
      }

      // 2 + 3. Table with rows pasted from a spreadsheet, then the destination confirmation (SQL upsert, dry run)
      {
        const a = app(lang);
        const r = await a.app.blindInput({
          title: s.tableTitle,
          description: s.tableDesc,
          schema: {
            fields: [
              { name: 'list', label: s.list, kind: 'select', options: [...s.listOpts], required: true },
              { name: 'rows', label: s.rows, kind: 'repeater', minRows: 1, fields: [{ name: 'sku', label: s.sku, required: true, pattern: '[A-Z0-9-]+' }, { name: 'price', label: s.price, kind: 'money', currencies: ['USD'], required: true, min: 0 }] },
            ],
          },
          sink: { type: 'sql', database: 'appdb', table: 'public.product_prices', mode: 'upsert', rows: 'rows', columns: { sku: '${sku}', price_usd: '${price}', list: '${list}' }, dry_run: true },
          submit_label: s.submitPrices,
        });
        const { ctx, page } = await newPage(browser, lang, theme, { width: 900, height: 700 });
        await page.goto(String(r.url));
        await page.getByLabel(s.list).selectOption(s.listOpts[1]);
        await page.getByLabel(s.paste).fill(SAMPLE_ROWS);
        await page.getByRole('button', { name: s.importBtn }).click();
        await expect(page.getByText(s.imported)).toBeVisible();
        await save('table', String(r.url), await shotSlice(page, raw('table'), '.card', `text=${s.imported}`, 14, 22));

        await page.getByLabel(s.confirm).check();
        await save('destination', String(r.url), await shotSlice(page, raw('destination'), 'section.dest', '.actions', 22, 28));
        await ctx.close();
        await a.cleanup();
        t = undefined;
      }

      // 4. Approval page showing the literal command (the value never appears)
      {
        const a = app(lang);
        await a.app.vault.put('local', 'ACME_DEPLOY_TOKEN', 'acme-demo-deploy-token');
        const r = await a.app.secretUse({ action: 'exec', shell: 'curl -fsS -X POST -H "Authorization: Bearer ${secret:ACME_DEPLOY_TOKEN}" https://deploy.acme.example/v1/releases', cwd: '/srv/acme-store' });
        const { ctx, page } = await newPage(browser, lang, theme, { width: 900, height: 700 });
        await page.goto(String(r.url));
        await expect(page.locator('pre.literal')).toContainText('${secret:ACME_DEPLOY_TOKEN}');
        await expect(page.locator('body')).not.toContainText('acme-demo-deploy-token');
        await save('approval', String(r.url), await shotSlice(page, raw('approval'), '.card', '.actions', 14, 28));
        await ctx.close();
        await a.cleanup();
        t = undefined;
      }

      // 5. Mobile
      {
        const a = app(lang);
        const r = await openForm(a, lang);
        const { ctx, page } = await newPage(browser, lang, theme, { width: 390, height: 780 });
        await page.goto(String(r.url));
        await fillForm(page, lang);
        await page.evaluate(() => (document.activeElement as HTMLElement | null)?.blur());
        await page.getByLabel(s.token).scrollIntoViewIfNeeded();
        await page.evaluate(() => window.scrollTo(0, 0));
        await page.screenshot({ path: raw('mobile') });
        await save('mobile', String(r.url), { width: 390, height: 780 }, true);
        await ctx.close();
      }
    });
  }
}

// Short recording of the real flow: form -> saved -> approval to write it into a .env -> done.
for (const lang of LANGS) {
  test(`flow recording ${lang}`, async ({ browser }) => {
    const s = TXT[lang];
    const envDir = mkdtempSync(path.join(tmpdir(), 'acme-store-'));
    const envFile = path.join(envDir, '.env');
    writeFileSync(envFile, '# Acme Store\nNODE_ENV=production\n', { mode: 0o600 });
    const a = app(lang, { writeTargets: [{ kind: 'env-file', path: `${envDir}/.env` }] });
    const vidDir = path.join(WORK, `video-${lang}`);
    const W = 900;
    const H = 680;
    const ctx = await browser.newContext({ colorScheme: 'light', locale: lang === 'es' ? 'es-MX' : 'en-US', viewport: { width: W, height: H }, recordVideo: { dir: vidDir, size: { width: W, height: H } } });
    const page = await ctx.newPage();
    const r = await openForm(a, lang);
    await page.goto(String(r.url));
    await page.waitForTimeout(900);
    await fillForm(page, lang, 55);
    await page.waitForTimeout(500);
    await page.getByRole('button', { name: s.save }).click();
    await expect(page.getByRole('status')).toBeVisible();
    await page.waitForTimeout(1600);
    const w = await a.app.secretWait({ id: r.request_id });
    expect(w).toMatchObject({ status: 'completed', stored: ['MP_ACCESS_TOKEN', 'MP_PUBLIC_KEY', 'MP_ENV'] });
    const wr = await a.app.secretWrite({ name: 'MP_ACCESS_TOKEN', target: { kind: 'env-file', path: envFile, key: 'MP_ACCESS_TOKEN' } });
    await page.goto(String(wr.url));
    await page.waitForTimeout(1800);
    await page.getByRole('button', { name: s.approve }).hover();
    await page.waitForTimeout(500);
    await page.getByRole('button', { name: s.approve }).click();
    await expect(page.getByRole('status')).toBeVisible();
    await page.waitForTimeout(2200);
    await ctx.close();
    expect(readFileSync(envFile, 'utf8')).toContain('MP_ACCESS_TOKEN=APP_USR-4821-acme-demo-0000-token');
    rmSync(envDir, { recursive: true, force: true });

    const webm = path.join(vidDir, readdirSync(vidDir).find((f) => f.endsWith('.webm'))!);
    // Window frame (light) with an empty content area; the video is overlaid inside it.
    const fctx = await browser.newContext({ deviceScaleFactor: 1, viewport: { width: 1200, height: 900 } });
    const fp = await fctx.newPage();
    await fp.setContent(`<!doctype html><meta charset="utf-8"><style>${FRAME_CSS}</style><div class="stage light" style="background:#f6f7f9;padding:18px"><div class="win"><div class="bar"><div class="dots"><i></i><i></i><i></i></div><div class="addr">${addrHtml('127.0.0.1:41723/p/…')}</div><div class="pad"></div></div><div style="width:${W}px;height:${H}px;background:#fff"></div></div></div>`);
    const framePng = path.join(WORK, `flow-frame-${lang}.png`);
    await fp.locator('.stage').screenshot({ path: framePng });
    const box = await fp.evaluate(() => {
      const st = document.querySelector('.stage')!.getBoundingClientRect();
      const c = document.querySelector('.win > div:last-child')!.getBoundingClientRect();
      return { x: Math.round(c.left - st.left), y: Math.round(c.top - st.top) };
    });
    await fctx.close();
    const out = path.join(OUT, `flow-${lang}.webp`);
    execFileSync('ffmpeg', [
      '-y', '-loglevel', 'error', '-loop', '1', '-i', framePng, '-i', webm,
      '-filter_complex', `[0][1]overlay=${box.x}:${box.y}:shortest=1,fps=12,scale=760:-1:flags=lanczos`,
      '-c:v', 'libwebp_anim', '-loop', '0', '-quality', '78', '-compression_level', '6', '-an', out,
    ]);
    record(out, statSync(out).size);
  });
}
