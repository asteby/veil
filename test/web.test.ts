import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { existsSync, readdirSync } from 'node:fs';
import { homedir } from 'node:os';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { makeApp, openPage, post, type TestApp } from './helpers.js';

const TOKEN = 'APP_USR-8812391-102938-abcdef0123456789-55512';
const USER = 'juan@example.com';
const PASS = 'panel-pass-Very$ecret1';

const hasBrowser = (() => {
  const dir = path.join(homedir(), '.cache', 'ms-playwright');
  return existsSync(dir) && readdirSync(dir).some((d) => d.startsWith('chromium'));
})();

/** A tiny "payments panel": login form, then a dashboard where "Mostrar" reveals the token. */
function panel() {
  const sessions = new Set<string>();
  return http.createServer((req, res) => {
    const cookie = /sid=([a-z0-9]+)/.exec(req.headers.cookie ?? '')?.[1];
    const html = (b: string) => {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      res.end(`<!doctype html><html><body>${b}</body></html>`);
    };
    if (req.url === '/login' && req.method === 'GET') return html(`<h1>Panel</h1><form method="post" action="/login"><input id="user" name="user"><input id="pass" name="pass" type="password"><button id="go">Entrar</button></form>`);
    if (req.url === '/login' && req.method === 'POST') {
      let body = '';
      req.on('data', (d) => (body += d));
      req.on('end', () => {
        const p = new URLSearchParams(body);
        if (p.get('user') === USER && p.get('pass') === PASS) {
          const sid = Math.random().toString(36).slice(2);
          sessions.add(sid);
          res.writeHead(302, { location: '/dashboard', 'set-cookie': `sid=${sid}; Path=/; HttpOnly` });
          return res.end();
        }
        res.writeHead(401);
        res.end('bad credentials');
      });
      return;
    }
    if (req.url === '/dashboard') {
      if (!cookie || !sessions.has(cookie)) {
        res.writeHead(302, { location: '/login' });
        return res.end();
      }
      return html(
        `<h1>Bienvenido Juan</h1><p id="balance">Saldo: $1,234.56 MXN</p><p>Credenciales de producción</p><code id="token">••••••••</code><button id="show" onclick="document.getElementById('token').textContent='${TOKEN}'">Mostrar</button>`,
      );
    }
    res.writeHead(404);
    res.end();
  });
}

describe.skipIf(!hasBrowser)('blind web actions in the MCP-owned browser (Playwright, headless in tests)', () => {
  const srv = panel();
  let origin = '';
  let t: TestApp;
  const responses: string[] = [];
  const keep = (r: Record<string, unknown>) => {
    responses.push(t.app.safe(r));
    return r;
  };

  beforeAll(async () => {
    await new Promise<void>((r) => srv.listen(0, '127.0.0.1', r));
    origin = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
    t = makeApp({ web: { headless: true, stepTimeoutMs: 8000, sites: { panel: { origins: [origin], startUrl: `${origin}/login` } } } });
    await t.app.vault.put('local', 'panel_user', USER);
    await t.app.vault.put('local', 'panel_pass', PASS);
  });
  afterAll(async () => {
    await t?.cleanup();
    await new Promise<void>((r) => srv.close(() => r()));
  });

  it('web_login fills the form with stored credentials and saves an encrypted session', async () => {
    const r = keep(await t.app.webLogin({ site: 'panel', steps: [{ fill: '#user', value: '${secret:panel_user}' }, { fill: '#pass', value: '${secret:panel_pass}' }, { click: '#go' }, { wait_for_url: `${origin}/dashboard` }] }));
    const p = await openPage(String(r.url));
    const ap = p.data.approval as { literal: string };
    expect(ap.literal).toContain('${secret:panel_pass}');
    expect(ap.literal).not.toContain(PASS);
    await post(p, { action: 'approve' });
    const w = keep(await t.app.secretWait({ id: r.request_id }));
    expect(w).toMatchObject({ status: 'completed', logged_in: true, session_saved: true });
    expect(t.app.vault.meta('local:web_session.panel')).toBeDefined();
  }, 60_000);

  it('web_capture clicks "Mostrar", extracts the token straight into the store and returns only {stored}', async () => {
    const r = keep(await t.app.webCapture({ site: 'panel', url: `${origin}/dashboard`, name: 'MP_ACCESS_TOKEN', steps: [{ click: '#show' }, { wait: 'code#token:text("APP_USR")' }], extract: { selector: '#token', regex: '(APP_USR-[0-9a-f-]+)' } }));
    await post(await openPage(String(r.url)), { action: 'approve' });
    const w = keep(await t.app.secretWait({ id: r.request_id }));
    expect(w).toMatchObject({ status: 'completed', stored: ['MP_ACCESS_TOKEN'], steps_completed: 2 });
    expect((await t.app.vault.resolve('MP_ACCESS_TOKEN')).value).toBe(TOKEN);
  }, 60_000);

  it('failures report only the step index and a code (no page text, no Playwright messages)', async () => {
    const r = keep(await t.app.webCapture({ site: 'panel', url: `${origin}/dashboard`, name: 'X', steps: [{ click: '#show' }, { click: '#does-not-exist' }], extract: { selector: '#token' } }));
    await post(await openPage(String(r.url)), { action: 'approve' });
    const w = keep(await t.app.secretWait({ id: r.request_id }));
    expect(w).toMatchObject({ stored: [], failed_step: 2, error_code: 'timeout', steps_completed: 1 });
  }, 60_000);

  it('the person can edit the steps on the approval page', async () => {
    const r = keep(await t.app.webCapture({ site: 'panel', url: `${origin}/dashboard`, name: 'MP_EDITED', steps: [{ click: '#wrong-button' }], extract: { selector: '#token' } }));
    const p = await openPage(String(r.url));
    expect((p.data.approval as { editable: { value: string } }).editable.value).toContain('#wrong-button');
    await post(p, { action: 'approve', edited: JSON.stringify([{ click: '#show' }]) });
    const w = keep(await t.app.secretWait({ id: r.request_id }));
    expect(w).toMatchObject({ stored: ['MP_EDITED'] });
  }, 60_000);

  it('refuses origins outside the allowlist', async () => {
    await expect(t.app.webCapture({ site: 'panel', url: 'https://evil.example/', name: 'X', extract: { selector: 'body' } })).rejects.toThrow(/origin|allowlist/);
    await expect(t.app.webCapture({ site: 'nope', name: 'X', extract: { selector: 'body' } })).rejects.toThrow(/allowlist/);
    const r = await t.app.webLogin({ site: 'panel', steps: [{ navigate: 'https://evil.example/login' }] }).catch((e: Error) => e);
    expect(String(r)).toMatch(/origin/);
  });

  it('no tool response ever contained the token, the credentials or page content', () => {
    const all = responses.join('\n');
    for (const s of [TOKEN, USER, PASS, 'Bienvenido', 'Saldo', '1,234.56', '<html', '<h1', 'Mostrar']) expect(all, s).not.toContain(s);
  });
});
