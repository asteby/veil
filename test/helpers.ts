import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { App, type AppDeps } from '../src/app.js';
import { parseConfig } from '../src/config.js';
import type { KeychainBackend } from '../src/stores/keychain.js';

export function tmpDir(prefix = 'si-test-'): string {
  return mkdtempSync(path.join(tmpdir(), prefix));
}

/** In-memory keychain (mock of the OS keychain). */
export function memKeychain(): KeychainBackend & { data: Map<string, string> } {
  const data = new Map<string, string>();
  return {
    name: 'memory',
    data,
    async set(s, a, v) {
      data.set(`${s}/${a}`, v);
    },
    async get(s, a) {
      return data.get(`${s}/${a}`);
    },
    async delete(s, a) {
      return data.delete(`${s}/${a}`);
    },
  };
}

export interface TestApp {
  app: App;
  home: string;
  keychain: ReturnType<typeof memKeychain>;
  opened: string[];
  cleanup(): Promise<void>;
}

export function makeApp(cfg: Record<string, unknown> = {}, deps: Partial<AppDeps> = {}): TestApp {
  const home = tmpDir();
  const keychain = memKeychain();
  const opened: string[] = [];
  const config = parseConfig({
    defaultDestination: 'local',
    destinations: { local: { type: 'keychain' }, vault: { type: 'encrypted-file', path: path.join(home, 'secrets.enc') } },
    ui: { openBrowser: false, ttlSeconds: 120 },
    ...cfg,
  });
  const app = new App({
    cfg: config,
    paths: { home, configFile: path.join(home, 'config.json'), auditFile: path.join(home, 'audit.jsonl'), indexFile: path.join(home, 'index.json'), approvalsFile: path.join(home, 'approvals.json'), dataDir: path.join(home, 'data') },
    keychainBackend: keychain,
    openUrl: async (u) => {
      opened.push(u);
      return false;
    },
    agent: 'test-agent',
    ...deps,
  });
  return {
    app,
    home,
    keychain,
    opened,
    async cleanup() {
      await app.shutdown();
      rmSync(home, { recursive: true, force: true });
    },
  };
}

export interface BrowserPage {
  url: string;
  origin: string;
  cookie: string;
  csrf: string;
  data: Record<string, unknown>;
  html: string;
  headers: Headers;
}

/** Simulates the person's browser: GET the page (binding the cookie). */
export async function openPage(url: string, cookie?: string): Promise<BrowserPage> {
  const res = await fetch(url, { headers: cookie ? { cookie } : {} });
  if (res.status !== 200) throw Object.assign(new Error(`GET ${res.status}`), { status: res.status });
  const html = await res.text();
  const setCookie = res.headers.get('set-cookie') ?? '';
  const ck = cookie ?? setCookie.split(';')[0]!;
  const json = /<script type="application\/json" id="si-data">([\s\S]*?)<\/script>/.exec(html)![1]!;
  const data = JSON.parse(json) as Record<string, unknown>;
  return { url, origin: new URL(url).origin, cookie: ck, csrf: data.csrf as string, data, html, headers: res.headers };
}

export async function post(page: BrowserPage, body: Record<string, unknown>, override: { origin?: string | null; csrfHeader?: string | null; cookie?: string | null; contentType?: string; host?: string; secFetchSite?: string } = {}) {
  const headers: Record<string, string> = { 'content-type': override.contentType ?? 'application/json' };
  if (override.origin !== null) headers.origin = override.origin ?? page.origin;
  if (override.csrfHeader !== null) headers['x-si-csrf'] = override.csrfHeader ?? page.csrf;
  if (override.cookie !== null) headers.cookie = override.cookie ?? page.cookie;
  if (override.secFetchSite) headers['sec-fetch-site'] = override.secFetchSite;
  const res = await fetch(page.origin + (page.data.action as string), { method: 'POST', headers, body: JSON.stringify({ csrf: page.csrf, ...body }) });
  let json: Record<string, unknown> = {};
  try {
    json = (await res.json()) as Record<string, unknown>;
  } catch {
    /* non-json */
  }
  return { status: res.status, json };
}

export async function submit(url: string, values: Record<string, unknown>, extra: Record<string, unknown> = {}) {
  const page = await openPage(url);
  return post(page, { action: 'submit', values, ...extra });
}

export async function approve(url: string, extra: Record<string, unknown> = {}) {
  const page = await openPage(url);
  return post(page, { action: 'approve', ...extra });
}

/** Deterministic PRNG (mulberry32) for property tests without extra deps. */
export function prng(seed: number) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const ALPHABETS = [
  'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
  'abcdefghijklmnopqrstuvwxyz0123456789_-',
  `!"#$%&'()*+,-./:;<=>?@[\\]^_\`{|}~ abcXYZ019`,
  'ñáéíóúü€漢字🔑',
];

/** Random secret-like string (8..64 chars) from a mix of alphabets. */
export function randomSecret(rnd: () => number): string {
  const len = 8 + Math.floor(rnd() * 56);
  const alpha = ALPHABETS[Math.floor(rnd() * ALPHABETS.length)]!;
  const chars = [...alpha];
  let s = '';
  for (let i = 0; i < len; i++) s += chars[Math.floor(rnd() * chars.length)];
  // keep it from being trivially short after trim
  return s.trim().length >= 6 ? s : s + 'Zz9_kq';
}
