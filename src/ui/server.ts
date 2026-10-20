import http from 'node:http';
import type { AddressInfo } from 'node:net';
import type { NormalizedSchema, FieldError } from '../schema.js';
import { log, newId, randomToken, safeEqual } from '../util.js';
import { CLIENT_JS, CSS } from './assets.js';
import { pickLang, STRINGS, type Lang, type Strings } from './i18n.js';

export type PageKind = 'form' | 'approval' | 'preview' | 'clipboard';

export interface DestinationInfo {
  lines: { label: string; value: string }[];
  needsConfirm: boolean;
  rememberable: boolean;
}

export interface ApprovalInfo {
  items: { label: string; value: string }[];
  literal?: string;
  warnings?: string[];
  rememberable: boolean;
  approveLabel?: string;
  /** Lets the person adjust a JSON document (e.g. web steps) before approving. */
  editable?: { label: string; value: string };
}

export interface SubmitPayload {
  /** 'reveal' = ask for values to be shown on THIS page only (never terminal). */
  action: 'submit' | 'cancel' | 'approve' | 'deny' | 'reveal';
  values?: Record<string, unknown>;
  remember?: boolean;
  confirm?: boolean;
  edited?: string;
  /** master password for Veil's encrypted store, typed on this page (create or unlock) */
  fallback?: { passphrase?: string; passphrase2?: string };
}

/** Localized, value-free fix shown on the page. */
export interface PageFix {
  text: string;
  command?: string;
  alternative?: { text: string; command?: string };
}

/** The OS keychain failed: offer Veil's encrypted store right on the page. */
export interface FallbackOffer {
  reason: string;
  /** create = define the master password now; unlock = type it; confirm = already unlocked, consent only */
  mode: 'create' | 'unlock' | 'confirm';
  problem: string;
  fix?: PageFix;
  minLength: number;
  unlockMinutes: number;
  path: string;
}

/** Values shown only on the local page, with copy buttons, hidden again after `hideAfter` seconds. */
export interface RevealInfo {
  items: { label: string; value: string }[];
  hideAfter: number;
  note?: string;
}

export type SubmitResult =
  | { ok: true; message?: string; clipboard?: { value: string; clearAfter: number }; reveal?: RevealInfo }
  | { ok: false; errors?: FieldError[]; message?: string; fix?: PageFix; fallback?: FallbackOffer };

export interface PageSpec {
  kind: PageKind;
  /** Operation id shown to the person so they can match it with the chat. */
  opId: string;
  title: string;
  description?: string;
  schema?: NormalizedSchema;
  destination?: DestinationInfo;
  approval?: ApprovalInfo;
  submitLabel?: string;
  clipboardSeconds?: number;
  /** form field filled from the URL fragment (#...) on load; the fragment is then removed from history */
  fragmentField?: string;
  /** label of a button that posts action 'reveal' (e.g. show current values) */
  revealLabel?: string;
  ttlMs: number;
  handle(p: SubmitPayload, lang: Lang): Promise<SubmitResult>;
  onExpire?(): void;
}

interface Page {
  id: string;
  token: string;
  csrf: string;
  cookieName: string;
  cookieValue?: string;
  expiresAt: number;
  done: boolean;
  busy: boolean;
  spec: PageSpec;
  timer: NodeJS.Timeout;
}

const MAX_BODY = 12 * 1024 * 1024;

/**
 * Local-only HTTP server for intake/approval pages.
 *  - binds 127.0.0.1 on an ephemeral port
 *  - each page has a 256-bit single-use URL token; the first browser that opens it
 *    gets an HttpOnly SameSite=Strict cookie and the token is bound to it
 *  - every POST needs: matching cookie, CSRF token (body + header), JSON content type,
 *    Origin = this server, Host = this server, Sec-Fetch-Site same-origin (when sent)
 *  - strict CSP with a per-response nonce; no third-party anything
 */
export class UiServer {
  private server?: http.Server;
  private port = 0;
  private pages = new Map<string, Page>();
  private starting?: Promise<void>;

  constructor(private readonly opts: { lang: 'auto' | Lang; host?: string } = { lang: 'auto' }) {}

  get origin(): string {
    return `http://127.0.0.1:${this.port}`;
  }

  async start(): Promise<void> {
    if (this.server) return;
    if (!this.starting) {
      this.starting = new Promise((resolve, reject) => {
        const srv = http.createServer((req, res) => {
          this.handle(req, res).catch(() => {
            if (!res.headersSent) this.send(res, 500, 'text/plain', 'error');
          });
        });
        srv.headersTimeout = 20_000;
        srv.requestTimeout = 60_000;
        srv.on('error', reject);
        srv.listen(0, '127.0.0.1', () => {
          this.port = (srv.address() as AddressInfo).port;
          this.server = srv;
          srv.unref();
          resolve();
        });
      });
    }
    await this.starting;
  }

  async register(spec: PageSpec): Promise<{ url: string; pageId: string }> {
    await this.start();
    const token = randomToken(32);
    const id = newId('pg');
    const page: Page = {
      id,
      token,
      csrf: randomToken(32),
      cookieName: `si_${id.slice(3).replace(/[^A-Za-z0-9]/g, '')}`,
      expiresAt: Date.now() + spec.ttlMs,
      done: false,
      busy: false,
      spec,
      timer: setTimeout(() => this.expire(token), spec.ttlMs),
    };
    page.timer.unref();
    this.pages.set(token, page);
    return { url: `${this.origin}/p/${token}`, pageId: id };
  }

  private expire(token: string): void {
    const p = this.pages.get(token);
    if (!p) return;
    this.pages.delete(token);
    if (!p.done) {
      p.done = true;
      p.spec.onExpire?.();
    }
  }

  /** Closes a page programmatically (e.g. op cancelled from the agent side). */
  close(url: string): void {
    const token = url.split('/p/')[1];
    if (!token) return;
    const p = this.pages.get(token);
    if (p) {
      clearTimeout(p.timer);
      p.done = true;
      this.pages.delete(token);
    }
  }

  async stop(): Promise<void> {
    for (const p of this.pages.values()) clearTimeout(p.timer);
    this.pages.clear();
    await new Promise<void>((r) => (this.server ? this.server.close(() => r()) : r()));
    this.server = undefined;
    this.starting = undefined;
  }

  // ------------------------------------------------------------------ http

  private securityHeaders(nonce?: string): Record<string, string> {
    const csp = [
      "default-src 'none'",
      nonce ? `script-src 'nonce-${nonce}'` : "script-src 'none'",
      nonce ? `style-src 'nonce-${nonce}'` : "style-src 'none'",
      "connect-src 'self'",
      "img-src 'none'",
      "font-src 'none'",
      "form-action 'none'",
      "frame-ancestors 'none'",
      "base-uri 'none'",
      "object-src 'none'",
      "manifest-src 'none'",
      "worker-src 'none'",
    ].join('; ');
    return {
      'Content-Security-Policy': csp,
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'no-referrer',
      'Cache-Control': 'no-store, max-age=0',
      Pragma: 'no-cache',
      'Cross-Origin-Opener-Policy': 'same-origin',
      'Cross-Origin-Resource-Policy': 'same-origin',
      'Cross-Origin-Embedder-Policy': 'require-corp',
      'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), clipboard-read=()',
      'X-Robots-Tag': 'noindex, nofollow',
    };
  }

  private send(res: http.ServerResponse, status: number, type: string, body: string, extra: Record<string, string> = {}, nonce?: string): void {
    res.writeHead(status, { ...this.securityHeaders(nonce), 'Content-Type': `${type}; charset=utf-8`, ...extra });
    res.end(body);
  }

  private hostOk(req: http.IncomingMessage): boolean {
    const host = req.headers.host;
    return host === `127.0.0.1:${this.port}` || host === `localhost:${this.port}`;
  }

  private originOk(req: http.IncomingMessage): boolean {
    const origin = req.headers.origin;
    if (origin !== `http://127.0.0.1:${this.port}` && origin !== `http://localhost:${this.port}`) return false;
    const sfs = req.headers['sec-fetch-site'];
    return sfs === undefined || sfs === 'same-origin';
  }

  private cookie(req: http.IncomingMessage, name: string): string | undefined {
    const raw = req.headers.cookie ?? '';
    for (const part of raw.split(';')) {
      const [k, ...v] = part.trim().split('=');
      if (k === name) return v.join('=');
    }
    return undefined;
  }

  private lang(req: http.IncomingMessage, url: URL): Lang {
    return pickLang(this.opts.lang, url.searchParams.get('lang'), req.headers['accept-language']);
  }

  private async handle(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    if (!this.hostOk(req)) return this.send(res, 421, 'text/plain', 'misdirected request');
    const url = new URL(req.url ?? '/', this.origin);
    if (url.pathname === '/favicon.ico') return this.send(res, 204, 'text/plain', '');
    const m = /^\/p\/([A-Za-z0-9_-]{43})(\/action)?$/.exec(url.pathname);
    const page = m ? this.pages.get(m[1]!) : undefined;
    const lang = this.lang(req, url);
    const t = STRINGS[lang];
    if (!m || !page || page.done || page.expiresAt < Date.now()) {
      if (m && req.method === 'POST') return this.send(res, 410, 'application/json', JSON.stringify({ ok: false, message: t.expired }));
      return this.sendMessage(res, m ? 410 : 404, t, lang, t.expired);
    }
    if (!m[2]) {
      if (req.method !== 'GET') return this.send(res, 405, 'text/plain', 'method not allowed', { Allow: 'GET' });
      // Single use: the first visit binds the page to this browser via cookie.
      const presented = this.cookie(req, page.cookieName);
      const extra: Record<string, string> = {};
      if (!page.cookieValue) {
        page.cookieValue = randomToken(32);
        extra['Set-Cookie'] = `${page.cookieName}=${page.cookieValue}; HttpOnly; SameSite=Strict; Path=/p/${page.token}`;
      } else if (!safeEqual(presented, page.cookieValue)) {
        return this.sendMessage(res, 410, t, lang, t.expired);
      }
      const nonce = randomToken(18);
      return this.send(res, 200, 'text/html', this.pageHtml(page, t, lang, nonce), extra, nonce);
    }
    // POST /p/<token>/action
    if (req.method !== 'POST') return this.send(res, 405, 'text/plain', 'method not allowed', { Allow: 'POST' });
    if (!this.originOk(req)) return this.send(res, 403, 'application/json', JSON.stringify({ ok: false, message: 'bad origin' }));
    if (!(req.headers['content-type'] ?? '').startsWith('application/json')) return this.send(res, 415, 'application/json', JSON.stringify({ ok: false }));
    if (!page.cookieValue || !safeEqual(this.cookie(req, page.cookieName), page.cookieValue)) return this.send(res, 403, 'application/json', JSON.stringify({ ok: false, message: 'bad session' }));
    if (!safeEqual(String(req.headers['x-si-csrf'] ?? ''), page.csrf)) return this.send(res, 403, 'application/json', JSON.stringify({ ok: false, message: 'bad csrf' }));
    let body: SubmitPayload & { csrf?: string };
    try {
      body = JSON.parse(await readBody(req, MAX_BODY));
    } catch {
      return this.send(res, 400, 'application/json', JSON.stringify({ ok: false }));
    }
    if (!safeEqual(body.csrf, page.csrf)) return this.send(res, 403, 'application/json', JSON.stringify({ ok: false, message: 'bad csrf' }));
    if (!['submit', 'cancel', 'approve', 'deny', 'reveal'].includes(body.action)) return this.send(res, 400, 'application/json', JSON.stringify({ ok: false }));
    if (page.spec.kind === 'preview') return this.send(res, 403, 'application/json', JSON.stringify({ ok: false }));
    if (page.busy) return this.send(res, 409, 'application/json', JSON.stringify({ ok: false }));
    page.busy = true;
    let result: SubmitResult;
    try {
      result = await page.spec.handle(body, lang);
    } catch {
      result = { ok: false, message: 'error' };
    } finally {
      page.busy = false;
    }
    const terminal = body.action !== 'reveal' && (result.ok || body.action === 'cancel' || body.action === 'deny' || (!result.ok && !result.errors && !result.fallback));
    if (terminal) {
      page.done = true;
      clearTimeout(page.timer);
      this.pages.delete(page.token);
    }
    log.info(`page ${page.id} action=${body.action} ok=${result.ok}`);
    return this.send(res, 200, 'application/json', JSON.stringify(result));
  }

  // ------------------------------------------------------------------ html

  private sendMessage(res: http.ServerResponse, status: number, t: Strings, lang: Lang, msg: string): void {
    const nonce = randomToken(18);
    const html = `<!doctype html><html lang="${lang}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="referrer" content="no-referrer"><title>${esc(t.appName)}</title><style nonce="${nonce}">${CSS}</style></head><body><main><div class="card"><p class="status err" role="status">${esc(msg)}</p></div></main></body></html>`;
    this.send(res, status, 'text/html', html, {}, nonce);
  }

  private pageHtml(page: Page, t: Strings, lang: Lang, nonce: string): string {
    const s = page.spec;
    const data = {
      kind: s.kind,
      preview: s.kind === 'preview',
      csrf: page.csrf,
      action: `/p/${page.token}/action`,
      strings: t,
      schema: s.schema ?? { sections: [] },
      destination: s.destination,
      approval: s.approval,
      submitLabel: s.submitLabel,
      fragmentField: s.fragmentField,
      revealLabel: s.revealLabel,
    };
    const other = lang === 'es' ? 'en' : 'es';
    const heading = s.kind === 'approval' ? t.approvalTitle : s.kind === 'clipboard' ? t.clipboardTitle : '';
    return `<!doctype html>
<html lang="${lang}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<meta name="robots" content="noindex, nofollow">
<title>${esc(s.title)} · ${esc(t.appName)}</title>
<style nonce="${nonce}">${CSS}</style>
</head>
<body>
<main>
<header class="si">
  <span class="brand">${esc(t.appName)}</span>
  <a class="lang" href="?lang=${other}" hreflang="${other}">${esc(t.language)}</a>
</header>
<p class="notice">${esc(t.localNotice)}</p>
<div class="card">
  ${heading ? `<p class="meta">${esc(heading)}</p>` : ''}
  <h1>${esc(s.title)}</h1>
  ${s.description ? `<p class="desc">${esc(s.description)}</p>` : ''}
  <p class="meta">${esc(t.requestId)}: <code>${esc(s.opId)}</code></p>
  ${s.kind === 'preview' ? `<p class="banner" role="note">${esc(t.previewBanner)}</p>` : ''}
  ${s.kind === 'approval' ? `<p>${esc(t.approvalIntro)}</p>` : ''}
  ${s.kind === 'clipboard' ? `<p>${esc(t.clipboardIntro.replace('{n}', String(s.clipboardSeconds ?? 30)))}</p>` : ''}
  <div id="app"></div>
  <noscript><p class="status err">JavaScript is required for this local page.</p></noscript>
</div>
</main>
<script type="application/json" id="si-data">${jsonForScript(data)}</script>
<script nonce="${nonce}">${CLIENT_JS}</script>
</body>
</html>`;
  }
}

function readBody(req: http.IncomingMessage, max: number): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let len = 0;
    req.on('data', (d: Buffer) => {
      len += d.length;
      if (len > max) {
        reject(new Error('too large'));
        req.destroy();
        return;
      }
      chunks.push(d);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

export function esc(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

/** JSON safe to embed inside <script type="application/json">. */
export function jsonForScript(v: unknown): string {
  return JSON.stringify(v).replace(/</g, '\\u003c').replace(/>/g, '\\u003e').replace(/&/g, '\\u0026').replace(/\u2028/g, '\\u2028').replace(/\u2029/g, '\\u2029');
}
