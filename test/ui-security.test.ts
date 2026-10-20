import http from 'node:http';
import { afterEach, describe, expect, it } from 'vitest';
import { UiServer, jsonForScript } from '../src/ui/server.js';
import { normalizeSchema } from '../src/schema.js';
import { openPage, post } from './helpers.js';

const schema = normalizeSchema({ fields: [{ name: 'TOKEN', label: 'Token', kind: 'secret', required: true }] });

function rawRequest(url: string, headers: Record<string, string>, method = 'GET', body?: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const req = http.request({ host: u.hostname, port: u.port, path: u.pathname, method, headers }, (res) => {
      let b = '';
      res.on('data', (d) => (b += d));
      res.on('end', () => resolve({ status: res.statusCode ?? 0, body: b }));
    });
    req.on('error', reject);
    req.end(body);
  });
}

describe('local UI server', () => {
  let ui: UiServer;
  afterEach(async () => ui?.stop());

  async function page(ttlMs = 60_000, onSubmit?: (v: unknown) => void) {
    ui = new UiServer({ lang: 'en' });
    let expired = false;
    const reg = await ui.register({
      kind: 'form',
      opId: 'req_test',
      title: 'T',
      schema,
      ttlMs,
      onExpire: () => (expired = true),
      handle: async (p) => {
        onSubmit?.(p.values);
        return { ok: true };
      },
    });
    return { ...reg, expired: () => expired };
  }

  it('binds to 127.0.0.1 on an ephemeral port with a 256-bit token', async () => {
    const { url } = await page();
    expect(url).toMatch(/^http:\/\/127\.0\.0\.1:\d+\/p\/[A-Za-z0-9_-]{43}$/);
  });

  it('serves a strict CSP with a nonce, no third parties, no caching, no referrer', async () => {
    const { url } = await page();
    const p = await openPage(url);
    const csp = p.headers.get('content-security-policy')!;
    expect(csp).toContain("default-src 'none'");
    expect(csp).toMatch(/script-src 'nonce-[A-Za-z0-9_-]+'/);
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).toContain("connect-src 'self'");
    expect(csp).not.toMatch(/https?:/);
    expect(p.headers.get('cache-control')).toContain('no-store');
    expect(p.headers.get('referrer-policy')).toBe('no-referrer');
    expect(p.headers.get('x-frame-options')).toBe('DENY');
    expect(p.html).not.toMatch(/<script[^>]+src=/);
    expect(p.headers.get('set-cookie')).toMatch(/HttpOnly; SameSite=Strict; Path=\/p\//);
  });

  it('single use: a second browser (no cookie) gets 410; the bound browser can reload', async () => {
    const { url } = await page();
    const first = await openPage(url);
    await expect(openPage(url)).rejects.toMatchObject({ status: 410 });
    const reload = await openPage(url, first.cookie);
    expect(reload.csrf).toBe(first.csrf);
  });

  it('the token is dead after a successful submit', async () => {
    const { url } = await page();
    const p = await openPage(url);
    expect((await post(p, { action: 'submit', values: { TOKEN: 'x' } })).json.ok).toBe(true);
    await expect(openPage(url, p.cookie)).rejects.toMatchObject({ status: 410 });
    expect((await post(p, { action: 'submit', values: { TOKEN: 'y' } })).status).toBe(410);
  });

  it('expires after the TTL', async () => {
    const pg = await page(150);
    await new Promise((r) => setTimeout(r, 300));
    await expect(openPage(pg.url)).rejects.toMatchObject({ status: 410 });
    expect(pg.expired()).toBe(true);
  });

  it('rejects POSTs without the CSRF header, with a wrong token, or without the session cookie', async () => {
    const { url } = await page();
    const p = await openPage(url);
    expect((await post(p, { action: 'submit', values: {} }, { csrfHeader: null })).status).toBe(403);
    expect((await post(p, { action: 'submit', values: {} }, { csrfHeader: 'x'.repeat(43) })).status).toBe(403);
    expect((await post(p, { action: 'submit', values: {}, csrf: 'bad' })).status).toBe(403);
    expect((await post(p, { action: 'submit', values: {} }, { cookie: null })).status).toBe(403);
  });

  it('enforces Origin and Sec-Fetch-Site on POST', async () => {
    const { url } = await page();
    const p = await openPage(url);
    expect((await post(p, { action: 'submit', values: {} }, { origin: 'http://evil.example' })).status).toBe(403);
    expect((await post(p, { action: 'submit', values: {} }, { origin: null })).status).toBe(403);
    expect((await post(p, { action: 'submit', values: {} }, { secFetchSite: 'cross-site' })).status).toBe(403);
    expect((await post(p, { action: 'submit', values: {} }, { contentType: 'text/plain' })).status).toBe(415);
  });

  it('rejects foreign Host headers (DNS rebinding)', async () => {
    const { url } = await page();
    const r = await rawRequest(url, { host: 'attacker.example:80' });
    expect(r.status).toBe(421);
    const r2 = await rawRequest(url, { host: `evil.127.0.0.1.nip.io:${new URL(url).port}` });
    expect(r2.status).toBe(421);
  });

  it('unknown paths and tokens get 404/410 without leaking anything', async () => {
    const { url } = await page();
    const base = new URL(url).origin;
    expect((await fetch(base + '/')).status).toBe(404);
    expect((await fetch(base + '/p/' + 'A'.repeat(43))).status).toBe(410);
  });

  it('embeds model-provided text safely (no </script> breakout)', () => {
    const s = jsonForScript({ label: '</script><script>alert(1)</script>' });
    expect(s).not.toContain('<');
    expect(JSON.parse(s).label).toBe('</script><script>alert(1)</script>');
  });
});
