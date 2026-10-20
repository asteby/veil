/**
 * Storage targets for encrypted bundles and shares. They only ever receive opaque blobs
 * (bundle objects, manifest, share bundles); never keys, names or values in clear.
 *
 *  dir     local folder (e.g. a synced Dropbox/Syncthing folder or a USB drive)
 *  ssh     remote folder over ssh (content on stdin, path in argv; no sftp subsystem needed)
 *  git     private git repo: clone → write → commit → push, `git` spawned by argv;
 *          credentials come from your ssh-agent / git credential helper, never argv
 *  s3      S3 / R2 / MinIO compatible, own minimal AWS SigV4 signer
 *  webdav  WebDAV (Nextcloud, ownCloud, Apache mod_dav...)
 *  http    generic PUT/GET/DELETE endpoint
 */
import { createHash, createHmac } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, rmSync } from 'node:fs';
import path from 'node:path';
import { z } from 'zod';
import { LocalFileIO, SshFileIO } from '../fileio.js';
import type { Runner } from '../proc.js';
import type { Ssh } from '../ssh.js';
import { expandHome, UserError } from '../util.js';
import { packSingle, unpackSingle } from './bundle.js';

const SecretRef = z.string();
const Layout = z.enum(['objects', 'single']).default('objects');
const Auth = z
  .discriminatedUnion('scheme', [
    z.object({ scheme: z.literal('none') }),
    z.object({ scheme: z.literal('bearer'), tokenRef: SecretRef }),
    z.object({ scheme: z.literal('basic'), user: z.string().optional(), userRef: SecretRef.optional(), passwordRef: SecretRef }),
  ])
  .default({ scheme: 'none' });

export const SyncTargetSchema = z.discriminatedUnion('type', [
  z.object({ type: z.literal('dir'), path: z.string(), layout: Layout }),
  z.object({ type: z.literal('ssh'), host: z.string(), path: z.string(), layout: Layout }),
  z.object({ type: z.literal('git'), url: z.string(), branch: z.string().regex(/^[A-Za-z0-9._/-]+$/).default('main'), path: z.string().default('veilform'), layout: Layout }),
  z.object({
    type: z.literal('s3'),
    endpoint: z.string().describe('https://s3.<region>.amazonaws.com, https://<account>.r2.cloudflarestorage.com, MinIO...'),
    bucket: z.string(),
    region: z.string().default('auto'),
    prefix: z.string().default('veilform/'),
    accessKeyRef: SecretRef,
    secretKeyRef: SecretRef,
    allowInsecureLoopback: z.boolean().default(false),
    layout: Layout,
  }),
  z.object({ type: z.literal('webdav'), url: z.string(), auth: Auth, allowInsecureLoopback: z.boolean().default(false), layout: Layout }),
  z.object({ type: z.literal('http'), baseUrl: z.string(), auth: Auth, allowInsecureLoopback: z.boolean().default(false), layout: Layout }),
]);
export type SyncTargetConfig = z.infer<typeof SyncTargetSchema>;

export interface BlobTarget {
  readonly id: string;
  readonly type: string;
  /** whether `delete` really removes data (false: a git history keeps it) */
  readonly deletesForReal: boolean;
  describe(): string;
  begin(): Promise<void>;
  get(p: string): Promise<Buffer | null>;
  put(p: string, data: Buffer): Promise<void>;
  delete(p: string): Promise<boolean>;
  commit(message: string): Promise<void>;
}

const REL_RE = /^(?!.*\.\.)(?!\/)[A-Za-z0-9_.\-/]{1,300}$/;
function rel(p: string): string {
  if (!REL_RE.test(p)) throw new UserError('invalid blob path', 'invalid_path');
  return p;
}

// ------------------------------------------------------------------ dir / ssh

export class DirTarget implements BlobTarget {
  readonly type = 'dir';
  readonly deletesForReal = true;
  private readonly io = new LocalFileIO();
  constructor(
    readonly id: string,
    private readonly base: string,
  ) {}
  describe() {
    return `folder ${expandHome(this.base)}`;
  }
  async begin() {}
  get(p: string) {
    return this.io.read(path.join(this.base, rel(p)));
  }
  put(p: string, data: Buffer) {
    return this.io.writeAtomic(path.join(this.base, rel(p)), data, { mode: '0600' });
  }
  delete(p: string) {
    return this.io.remove(path.join(this.base, rel(p)));
  }
  async commit() {}
}

export class SshTarget implements BlobTarget {
  readonly type = 'ssh';
  readonly deletesForReal = true;
  private readonly io: SshFileIO;
  constructor(
    readonly id: string,
    ssh: Ssh,
    private readonly host: string,
    private readonly base: string,
  ) {
    ssh.hostConfig(host);
    this.io = new SshFileIO(ssh, host);
  }
  describe() {
    return `ssh ${this.host}:${this.base}`;
  }
  async begin() {}
  get(p: string) {
    return this.io.read(path.posix.join(this.base, rel(p)));
  }
  put(p: string, data: Buffer) {
    return this.io.writeAtomic(path.posix.join(this.base, rel(p)), data, { mode: '0600' });
  }
  delete(p: string) {
    return this.io.remove(path.posix.join(this.base, rel(p)));
  }
  async commit() {}
}

// ------------------------------------------------------------------ git

export class GitTarget implements BlobTarget {
  readonly type = 'git';
  readonly deletesForReal = false;
  private dirty = false;
  constructor(
    readonly id: string,
    private readonly runner: Runner,
    private readonly url: string,
    private readonly branch: string,
    private readonly sub: string,
    private readonly work: string,
  ) {
    if (/^[a-z][a-z0-9+.-]*:\/\/[^/@]*:[^/@]*@/i.test(url)) throw new UserError('git url must not embed credentials; use ssh keys or a credential helper', 'invalid_config');
    if (url.startsWith('-')) throw new UserError('invalid git url', 'invalid_config');
    rel(sub);
  }
  describe() {
    return `git ${this.url.replace(/\/\/[^/@]*@/, '//')} (${this.branch})`;
  }
  private async git(args: string[], cwd?: string): Promise<{ code: number | null; out: string }> {
    const env: NodeJS.ProcessEnv = { ...process.env, GIT_TERMINAL_PROMPT: '0', GIT_ASKPASS: '/bin/false', LC_ALL: 'C' };
    for (const k of Object.keys(env)) if (k.startsWith('VEILFORM')) delete env[k];
    const r = await this.runner(['git', ...args], { cwd, env, timeoutMs: 120_000 });
    return { code: r.code, out: r.stdout.toString('utf8') };
  }
  private async must(args: string[], cwd?: string, code = 'git_failed'): Promise<string> {
    const r = await this.git(args, cwd);
    if (r.code !== 0) throw new UserError(`git ${args[0]} failed (exit ${r.code})`, code);
    return r.out;
  }
  async begin() {
    if (!existsSync(path.join(this.work, '.git'))) {
      rmSync(this.work, { recursive: true, force: true });
      mkdirSync(path.dirname(this.work), { recursive: true, mode: 0o700 });
      await this.must(['clone', '-q', '--no-hardlinks', '--', this.url, this.work]);
    } else await this.must(['fetch', '-q', 'origin'], this.work);
    const has = await this.git(['rev-parse', '--verify', '-q', `refs/remotes/origin/${this.branch}`], this.work);
    if (has.code === 0) {
      await this.must(['checkout', '-q', '-B', this.branch, `origin/${this.branch}`], this.work);
      await this.must(['reset', '-q', '--hard', `origin/${this.branch}`], this.work);
    } else await this.must(['checkout', '-q', '--orphan', this.branch], this.work).catch(() => this.must(['checkout', '-q', this.branch], this.work));
    this.dirty = false;
  }
  private file(p: string) {
    return path.join(this.work, this.sub, rel(p));
  }
  async get(p: string) {
    const f = this.file(p);
    return existsSync(f) ? readFileSync(f) : null;
  }
  async put(p: string, data: Buffer) {
    await new LocalFileIO().writeAtomic(this.file(p), data, { mode: '0600' });
    this.dirty = true;
  }
  async delete(p: string) {
    const f = this.file(p);
    if (!existsSync(f)) return false;
    rmSync(f);
    this.dirty = true;
    return true;
  }
  async commit(message: string) {
    if (!this.dirty) return;
    await this.must(['add', '-A', '--', this.sub], this.work);
    const st = await this.must(['status', '--porcelain'], this.work);
    if (st.trim()) {
      await this.must(['-c', 'user.name=veilform', '-c', 'user.email=veilform@localhost', '-c', 'commit.gpgsign=false', 'commit', '-q', '-m', message], this.work);
      await this.must(['push', '-q', 'origin', `HEAD:refs/heads/${this.branch}`], this.work, 'git_push_failed');
    }
    this.dirty = false;
  }
}

// ------------------------------------------------------------------ http helpers

function checkUrl(u: string, allowInsecureLoopback: boolean): URL {
  let url: URL;
  try {
    url = new URL(u);
  } catch {
    throw new UserError('invalid URL in sync target', 'invalid_config');
  }
  if (url.username || url.password) throw new UserError('sync target URL must not embed credentials', 'invalid_config');
  const loop = ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname);
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && loop && allowInsecureLoopback)) throw new UserError('sync targets need https (plain http only on loopback with allowInsecureLoopback)', 'insecure_url');
  return url;
}

async function request(url: string, init: { method: string; headers?: Record<string, string>; body?: Buffer }, timeoutMs = 60_000): Promise<{ status: number; body: Buffer }> {
  let res: Response;
  try {
    res = await fetch(url, { method: init.method, headers: init.headers, body: init.body ? new Uint8Array(init.body) : undefined, redirect: 'manual', signal: AbortSignal.timeout(timeoutMs) });
  } catch {
    throw new UserError('sync target unreachable', 'target_unreachable');
  }
  const body = Buffer.from(await res.arrayBuffer());
  if (body.length > 64 * 1024 * 1024) throw new UserError('response too large', 'target_failed');
  return { status: res.status, body };
}

type Resolve = (ref: string) => Promise<string>;

async function authHeader(auth: z.infer<typeof Auth>, resolve: Resolve): Promise<Record<string, string>> {
  if (auth.scheme === 'bearer') return { authorization: `Bearer ${await resolve(auth.tokenRef)}` };
  if (auth.scheme === 'basic') {
    const user = auth.user ?? (auth.userRef ? await resolve(auth.userRef) : '');
    return { authorization: `Basic ${Buffer.from(`${user}:${await resolve(auth.passwordRef)}`).toString('base64')}` };
  }
  return {};
}

abstract class HttpLike implements BlobTarget {
  abstract readonly type: string;
  readonly deletesForReal = true;
  constructor(
    readonly id: string,
    protected readonly base: URL,
  ) {}
  abstract describe(): string;
  protected abstract headers(method: string, url: URL, body?: Buffer): Promise<Record<string, string>>;
  protected urlFor(p: string): URL {
    const u = new URL(this.base.href);
    u.pathname = (u.pathname.endsWith('/') ? u.pathname : u.pathname + '/') + rel(p).split('/').map(encodeURIComponent).join('/');
    return u;
  }
  async begin() {}
  async commit() {}
  protected async ensureParents(_p: string): Promise<void> {}
  async get(p: string) {
    const u = this.urlFor(p);
    const r = await request(u.href, { method: 'GET', headers: await this.headers('GET', u) });
    if (r.status === 404) return null;
    if (r.status !== 200) throw new UserError(`sync target GET failed: http_${r.status}`, 'target_failed');
    return r.body;
  }
  async put(p: string, data: Buffer) {
    await this.ensureParents(p);
    const u = this.urlFor(p);
    const r = await request(u.href, { method: 'PUT', headers: { 'content-type': 'application/octet-stream', ...(await this.headers('PUT', u, data)) }, body: data });
    if (r.status < 200 || r.status >= 300) throw new UserError(`sync target PUT failed: http_${r.status}`, 'target_failed');
  }
  async delete(p: string) {
    const u = this.urlFor(p);
    const r = await request(u.href, { method: 'DELETE', headers: await this.headers('DELETE', u) });
    if (r.status === 404) return false;
    if (r.status < 200 || r.status >= 300) throw new UserError(`sync target DELETE failed: http_${r.status}`, 'target_failed');
    return true;
  }
}

export class HttpTarget extends HttpLike {
  readonly type: string = 'http';
  constructor(
    id: string,
    base: string,
    private readonly auth: z.infer<typeof Auth>,
    private readonly resolve: Resolve,
    insecure: boolean,
  ) {
    super(id, checkUrl(base, insecure));
  }
  describe() {
    return `http ${this.base.origin}${this.base.pathname}`;
  }
  protected headers() {
    return authHeader(this.auth, this.resolve);
  }
}

export class WebDavTarget extends HttpTarget {
  override readonly type = 'webdav';
  private made = new Set<string>();
  override describe() {
    return `webdav ${this.base.origin}${this.base.pathname}`;
  }
  protected override async ensureParents(p: string) {
    const parts = rel(p).split('/').slice(0, -1);
    if (!this.made.has('')) {
      const r = await request(this.base.href.endsWith('/') ? this.base.href : this.base.href + '/', { method: 'MKCOL', headers: await this.headers() });
      if (![201, 405, 301].includes(r.status)) throw new UserError(`webdav MKCOL failed: http_${r.status}`, 'target_failed');
      this.made.add('');
    }
    for (let i = 1; i <= parts.length; i++) {
      const dir = parts.slice(0, i).join('/');
      if (this.made.has(dir)) continue;
      const u = this.urlFor(dir);
      u.pathname += '/';
      const r = await request(u.href, { method: 'MKCOL', headers: await this.headers() });
      if (![201, 405, 301].includes(r.status)) throw new UserError(`webdav MKCOL failed: http_${r.status}`, 'target_failed');
      this.made.add(dir);
    }
  }
}

// ------------------------------------------------------------------ S3 (SigV4)

const sha256hex = (b: Buffer | string) => createHash('sha256').update(b).digest('hex');
const hmacB = (k: Buffer | string, s: string) => createHmac('sha256', k).update(s).digest();

/** RFC 3986 encoding as AWS wants it (keeps / in paths when asked). */
function awsEncode(s: string, keepSlash: boolean): string {
  const e = encodeURIComponent(s).replace(/[!'()*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase());
  return keepSlash ? e.replace(/%2F/g, '/') : e;
}

/**
 * Minimal AWS Signature Version 4 (header auth). Returns the headers to add, including
 * `authorization`. Verified against the AWS documentation example (see test/sync.test.ts).
 */
export function sigv4(a: { method: string; url: URL; region: string; service: string; accessKey: string; secretKey: string; headers: Record<string, string>; payloadHash: string; date: Date }): Record<string, string> {
  const amzDate = a.date.toISOString().replace(/[-:]/g, '').replace(/\.\d{3}/, '');
  const day = amzDate.slice(0, 8);
  const headers: Record<string, string> = { ...a.headers, host: a.url.host, 'x-amz-date': amzDate, 'x-amz-content-sha256': a.payloadHash };
  const names = Object.keys(headers)
    .map((h) => h.toLowerCase())
    .sort();
  const lower = Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), String(v).trim().replace(/\s+/g, ' ')]));
  const canonHeaders = names.map((n) => `${n}:${lower[n]}\n`).join('');
  const signed = names.join(';');
  const query = [...a.url.searchParams]
    .map(([k, v]) => [awsEncode(k, false), awsEncode(v, false)])
    .sort(([x, y], [z2, w]) => (x === z2 ? y!.localeCompare(w!) : x!.localeCompare(z2!)))
    .map(([k, v]) => `${k}=${v}`)
    .join('&');
  const canonPath = a.url.pathname
    .split('/')
    .map((s) => awsEncode(decodeURIComponent(s), false))
    .join('/');
  const canonical = [a.method, canonPath || '/', query, canonHeaders, signed, a.payloadHash].join('\n');
  const scope = `${day}/${a.region}/${a.service}/aws4_request`;
  const toSign = ['AWS4-HMAC-SHA256', amzDate, scope, sha256hex(canonical)].join('\n');
  const kSigning = hmacB(hmacB(hmacB(hmacB(`AWS4${a.secretKey}`, day), a.region), a.service), 'aws4_request');
  const signature = createHmac('sha256', kSigning).update(toSign).digest('hex');
  const out: Record<string, string> = { ...headers, authorization: `AWS4-HMAC-SHA256 Credential=${a.accessKey}/${scope}, SignedHeaders=${signed}, Signature=${signature}` };
  delete out.host;
  return out;
}

export class S3Target extends HttpLike {
  readonly type = 's3';
  constructor(
    id: string,
    private readonly c: Extract<SyncTargetConfig, { type: 's3' }>,
    private readonly resolve: Resolve,
    private readonly now: () => Date = () => new Date(),
  ) {
    const ep = checkUrl(c.endpoint, c.allowInsecureLoopback);
    if (!/^[a-z0-9][a-z0-9.-]{1,62}$/.test(c.bucket)) throw new UserError('invalid bucket name', 'invalid_config');
    ep.pathname = `/${c.bucket}/${c.prefix.replace(/^\/+/, '')}`;
    super(id, ep);
  }
  describe() {
    return `s3 ${this.c.endpoint} bucket ${this.c.bucket}/${this.c.prefix}`;
  }
  protected async headers(method: string, url: URL, body?: Buffer) {
    return sigv4({ method, url, region: this.c.region, service: 's3', accessKey: await this.resolve(this.c.accessKeyRef), secretKey: await this.resolve(this.c.secretKeyRef), headers: {}, payloadHash: sha256hex(body ?? Buffer.alloc(0)), date: this.now() });
  }
}

// ------------------------------------------------------------------ single-file layout

/** Keeps manifest + objects inside one `bundle.vfb` file on the underlying target (shares stay separate files). */
export class SingleFileLayout implements BlobTarget {
  private files = new Map<string, Buffer>();
  private dirty = false;
  constructor(private readonly inner: BlobTarget) {}
  get id() {
    return this.inner.id;
  }
  get type() {
    return this.inner.type;
  }
  get deletesForReal() {
    return this.inner.deletesForReal;
  }
  describe() {
    return `${this.inner.describe()} (single file bundle.vfb)`;
  }
  private passthrough(p: string) {
    return p.startsWith('shares/');
  }
  async begin() {
    await this.inner.begin();
    const b = await this.inner.get('bundle.vfb');
    this.files = b ? unpackSingle(b) : new Map();
    this.dirty = false;
  }
  async get(p: string) {
    return this.passthrough(p) ? this.inner.get(p) : (this.files.get(p) ?? null);
  }
  async put(p: string, data: Buffer) {
    if (this.passthrough(p)) return this.inner.put(p, data);
    this.files.set(p, data);
    this.dirty = true;
  }
  async delete(p: string) {
    if (this.passthrough(p)) return this.inner.delete(p);
    this.dirty = true;
    return this.files.delete(p);
  }
  async commit(message: string) {
    if (this.dirty) await this.inner.put('bundle.vfb', packSingle(this.files));
    this.dirty = false;
    await this.inner.commit(message);
  }
}

export function buildTarget(id: string, c: SyncTargetConfig, deps: { ssh: Ssh; runner: Runner; resolve: Resolve; home: string; now?: () => Date }): BlobTarget {
  let t: BlobTarget;
  switch (c.type) {
    case 'dir':
      t = new DirTarget(id, c.path);
      break;
    case 'ssh':
      t = new SshTarget(id, deps.ssh, c.host, c.path);
      break;
    case 'git':
      t = new GitTarget(id, deps.runner, c.url, c.branch, c.path, path.join(deps.home, 'sync', 'git', id.replace(/[^A-Za-z0-9_-]/g, '_')));
      break;
    case 's3':
      t = new S3Target(id, c, deps.resolve, deps.now);
      break;
    case 'webdav':
      t = new WebDavTarget(id, c.url, c.auth, deps.resolve, c.allowInsecureLoopback);
      break;
    case 'http':
      t = new HttpTarget(id, c.baseUrl, c.auth, deps.resolve, c.allowInsecureLoopback);
      break;
  }
  return c.layout === 'single' ? new SingleFileLayout(t) : t;
}
