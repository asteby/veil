/**
 * Share secrets by TOKEN.
 *
 * Token:   vfs1://<target>/<share_id>#<K>
 *          K = 32 random bytes (base64url) — lives in the URL FRAGMENT, which browsers and
 *          HTTP clients never send to a server. <target> is the sync target id that holds the
 *          bundle (the receiver needs the same target configured, or passes --target).
 *
 * Bundle (stored at shares/<share_id>.json on the target):
 *   {format:"veilform-share", v:1, share_id, created_at, expires_at, max_views, kdf|null, payload}
 *   key      = HKDF( [argon2id|scrypt(passphrase)] || K, "share:<share_id>" )   (passphrase optional)
 *   payload  = AES-256-GCM(key, {note, items:[{name, kind, wdek, ct}]}, AAD = canonical(header))
 *   per item: DEK random; ct = GCM(DEK, value, AAD=share_id|name); wdek = GCM(key, DEK, AAD=share_id|name)
 * The header (expiry, max views, KDF) is authenticated by the payload AEAD: editing the
 * expiry or the view count makes the bundle undecryptable.
 *
 * Views (shares/<share_id>.views) = GCM(key, {views}) — maintained by honest receivers; when
 * views reach max_views the receiver deletes the bundle (burn after read). Storage that keeps
 * history (git) or a receiver that ignores the rules can still keep a copy: see THREAT-MODEL.md.
 */
import { randomBytes } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { AttemptLimiter } from '../crypto/attempts.js';
import { b64, checkKdfParams, combineKek, deriveFromPassphrase, newKdfParams, open, randomKey, seal, unb64, type KdfParams } from '../crypto/primitives.js';
import { LocalFileIO } from '../fileio.js';
import type { BlobTarget } from '../sync/targets.js';
import { canonicalJson, KeyedMutex, UserError } from '../util.js';

export const TOKEN_RE = /^vfs1:\/\/([A-Za-z0-9_-]{1,64})\/([A-Za-z0-9_-]{22})#([A-Za-z0-9_-]{43})$/;

export interface ShareItem {
  name: string;
  kind: 'secret' | 'env-dek';
  value: string;
}

interface Header {
  format: 'veilform-share';
  v: 1;
  share_id: string;
  created_at: string;
  expires_at: string;
  max_views: number;
  kdf: KdfParams | null;
}

export interface ShareRecord {
  share_id: string;
  names: string[];
  target: string;
  created_at: string;
  expires_at: string;
  max_views: number;
  passphrase: boolean;
  note?: string;
  revoked_at?: string;
}

export interface ParsedToken {
  target: string;
  shareId: string;
  key: Buffer;
}

export function parseToken(token: string): ParsedToken {
  const m = TOKEN_RE.exec(token.trim());
  if (!m) throw new UserError('not a veilform share token', 'bad_token');
  return { target: m[1]!, shareId: m[2]!, key: unb64(m[3]!) };
}

export const formatToken = (target: string, shareId: string, key: Buffer) => `vfs1://${target}/${shareId}#${b64(key)}`;

const bundlePath = (id: string) => `shares/${id}.json`;
const viewsPath = (id: string) => `shares/${id}.views`;
const itemAad = (id: string, name: string) => `veilform-share/v1/item\0${id}\0${name}`;
const dekAad = (id: string, name: string) => `veilform-share/v1/dek\0${id}\0${name}`;
const viewsAad = (id: string) => `veilform-share/v1/views\0${id}`;
const headerAad = (h: Header) => canonicalJson(h);

async function shareKey(h: Header, tokenKey: Buffer, passphrase: string | undefined): Promise<Buffer> {
  if (h.kdf && passphrase === undefined) throw new UserError('this share also needs its passphrase (sent to you through another channel)', 'passphrase_required');
  const pk = h.kdf ? await deriveFromPassphrase(passphrase!, h.kdf) : undefined;
  const k = await combineKek(pk, tokenKey, `share:${h.share_id}`);
  pk?.fill(0);
  return k;
}

export interface ShareDeps {
  home: string;
  target: (id: string) => BlobTarget;
  now?: () => Date;
  testKdf?: boolean;
  maxAttempts?: number;
}

export class Shares {
  private readonly io = new LocalFileIO();
  private readonly mutex = new KeyedMutex();
  private readonly now: () => Date;
  readonly limiter: AttemptLimiter;
  private readonly sentFile: string;
  private readonly receivedFile: string;

  constructor(private readonly d: ShareDeps) {
    this.now = d.now ?? (() => new Date());
    this.sentFile = path.join(d.home, 'shares.json');
    this.receivedFile = path.join(d.home, 'shares-received.json');
    this.limiter = new AttemptLimiter(path.join(d.home, 'unlock-attempts.json'), d.maxAttempts ?? 5, 15 * 60_000, () => this.now().getTime());
  }

  // ------------------------------------------------------------ sender

  records(): ShareRecord[] {
    if (!existsSync(this.sentFile)) return [];
    return Object.values(JSON.parse(readFileSync(this.sentFile, 'utf8')) as Record<string, ShareRecord>);
  }

  private async saveRecord(r: ShareRecord): Promise<void> {
    await this.mutex.run('sent', async () => {
      const all: Record<string, ShareRecord> = existsSync(this.sentFile) ? JSON.parse(readFileSync(this.sentFile, 'utf8')) : {};
      all[r.share_id] = r;
      await this.io.writeAtomic(this.sentFile, JSON.stringify(all, null, 1) + '\n', { mode: '0600' });
    });
  }

  /** Builds and uploads a share bundle. Returns the token (show it ONLY to the person). */
  async create(a: { targetId: string; items: ShareItem[]; expiresInSeconds: number; maxViews: number; passphrase?: string; note?: string }): Promise<{ record: ShareRecord; token: string }> {
    if (!a.items.length) throw new UserError('nothing to share', 'invalid_args');
    if (a.passphrase !== undefined && a.passphrase.length < 8) throw new UserError('share passphrase too short (min 8 chars)', 'weak_passphrase');
    const shareId = b64(randomBytes(16));
    const tokenKey = randomKey();
    const created = this.now();
    const h: Header = {
      format: 'veilform-share',
      v: 1,
      share_id: shareId,
      created_at: created.toISOString(),
      expires_at: new Date(created.getTime() + a.expiresInSeconds * 1000).toISOString(),
      max_views: a.maxViews,
      kdf: a.passphrase !== undefined ? newKdfParams(undefined, { test: this.d.testKdf }) : null,
    };
    const key = await shareKey(h, tokenKey, a.passphrase);
    const items = a.items.map((it) => {
      const dek = randomKey();
      const out = { name: it.name, kind: it.kind, wdek: seal(key, dek, dekAad(shareId, it.name)), ct: seal(dek, it.value, itemAad(shareId, it.name)) };
      dek.fill(0);
      return out;
    });
    const payload = seal(key, JSON.stringify({ note: a.note, items }), headerAad(h));
    key.fill(0);
    const t = this.d.target(a.targetId);
    await t.begin();
    await t.put(bundlePath(shareId), Buffer.from(JSON.stringify({ ...h, payload }) + '\n'));
    await t.commit(`veilform share ${shareId}`);
    const record: ShareRecord = { share_id: shareId, names: a.items.map((i) => i.name), target: a.targetId, created_at: h.created_at, expires_at: h.expires_at, max_views: a.maxViews, passphrase: Boolean(h.kdf), note: a.note };
    await this.saveRecord(record);
    return { record, token: formatToken(a.targetId, shareId, tokenKey) };
  }

  /** Read status without the key: has anyone consumed a view? (views file present or bundle burnt) */
  async status(shareId: string): Promise<{ record?: ShareRecord; present: boolean; read: boolean | 'unknown'; expired: boolean }> {
    const record = this.records().find((r) => r.share_id === shareId);
    if (!record) throw new UserError('unknown share id (not created on this machine)', 'not_found');
    const t = this.d.target(record.target);
    await t.begin();
    const present = (await t.get(bundlePath(shareId))) !== null;
    const views = (await t.get(viewsPath(shareId))) !== null;
    const read = views ? true : !present && !record.revoked_at ? true : record.revoked_at ? 'unknown' : false;
    return { record, present, read, expired: Date.parse(record.expires_at) <= this.now().getTime() };
  }

  async revoke(shareId: string): Promise<{ revoked: boolean; was_read: boolean | 'unknown'; names: string[]; history_kept: boolean }> {
    const st = await this.status(shareId);
    const t = this.d.target(st.record!.target);
    await t.begin();
    const a = await t.delete(bundlePath(shareId));
    await t.delete(viewsPath(shareId));
    await t.commit(`veilform revoke ${shareId}`);
    await this.saveRecord({ ...st.record!, revoked_at: this.now().toISOString() });
    return { revoked: a || !st.present, was_read: st.read, names: st.record!.names, history_kept: !t.deletesForReal };
  }

  // ------------------------------------------------------------ receiver

  private received(): Record<string, { views: number; at: string }> {
    return existsSync(this.receivedFile) ? JSON.parse(readFileSync(this.receivedFile, 'utf8')) : {};
  }

  /** Header without decrypting (expiry, needs passphrase) — for the reveal page. */
  async peek(token: string, targetOverride?: string): Promise<{ needsPassphrase: boolean; expiresAt: string; maxViews: number }> {
    const tk = parseToken(token);
    const h = await this.fetchHeader(targetOverride ?? tk.target, tk.shareId);
    return { needsPassphrase: Boolean(h.header.kdf), expiresAt: h.header.expires_at, maxViews: h.header.max_views };
  }

  private async fetchHeader(targetId: string, shareId: string): Promise<{ header: Header; payload: string; t: BlobTarget }> {
    const t = this.d.target(targetId);
    await t.begin();
    const raw = await t.get(bundlePath(shareId));
    if (!raw) throw new UserError('share not found: revoked, already consumed, or never uploaded', 'gone');
    let j: Header & { payload: string };
    try {
      j = JSON.parse(raw.toString('utf8'));
    } catch {
      throw new UserError('malformed share bundle', 'tampered');
    }
    const { payload, ...header } = j;
    if (header.format !== 'veilform-share' || header.v !== 1 || header.share_id !== shareId || typeof payload !== 'string' || !Number.isInteger(header.max_views) || header.max_views < 1) throw new UserError('malformed share bundle', 'tampered');
    if (header.kdf) checkKdfParams(header.kdf);
    return { header: { format: header.format, v: header.v, share_id: header.share_id, created_at: header.created_at, expires_at: header.expires_at, max_views: header.max_views, kdf: header.kdf }, payload, t };
  }

  /**
   * Opens a share and CONSUMES one view. Checks, in order: local replay list, attempt lock,
   * presence, authenticity (wrong key/passphrase vs tampered are not distinguished), signed
   * expiry, view counter; then increments the counter or burns the bundle.
   */
  async open(token: string, opts: { passphrase?: string; targetOverride?: string } = {}): Promise<{ shareId: string; items: ShareItem[]; note?: string; viewsLeft: number; burned: boolean }> {
    const tk = parseToken(token);
    const rec = this.received()[tk.shareId];
    this.limiter.check(`share:${tk.shareId}`);
    const { header, payload, t } = await this.fetchHeader(opts.targetOverride ?? tk.target, tk.shareId);
    if (rec && rec.views >= header.max_views) throw new UserError('this share was already consumed on this machine', 'consumed');
    let key: Buffer;
    let body: { note?: string; items: { name: string; kind: ShareItem['kind']; wdek: string; ct: string }[] };
    try {
      key = await shareKey(header, tk.key, opts.passphrase);
      body = JSON.parse(open(key, payload, headerAad(header), 'wrong_key').toString('utf8'));
    } catch (e) {
      if (e instanceof UserError && e.code === 'passphrase_required') throw e;
      const left = await this.limiter.fail(`share:${tk.shareId}`);
      throw new UserError(`cannot open share: wrong passphrase/token or modified bundle (${left} attempts left)`, 'wrong_key');
    }
    await this.limiter.ok(`share:${tk.shareId}`);
    if (Date.parse(header.expires_at) <= this.now().getTime()) {
      key.fill(0);
      throw new UserError('this share has expired', 'expired');
    }
    return this.mutex.run(`open:${tk.shareId}`, async () => {
      let views = 0;
      const vraw = await t.get(viewsPath(tk.shareId));
      if (vraw) views = (JSON.parse(open(key, vraw.toString('utf8').trim(), viewsAad(tk.shareId)).toString('utf8')) as { views: number }).views;
      if (views >= header.max_views) throw new UserError('this share has already been consumed', 'consumed');
      views++;
      const burned = views >= header.max_views;
      if (burned) {
        await t.delete(bundlePath(tk.shareId));
        await t.delete(viewsPath(tk.shareId));
      } else await t.put(viewsPath(tk.shareId), Buffer.from(seal(key, JSON.stringify({ views }), viewsAad(tk.shareId))));
      await t.commit(`veilform share view ${tk.shareId}`);
      const items = body.items.map((it) => {
        const dek = open(key, it.wdek, dekAad(tk.shareId, it.name));
        const value = open(dek, it.ct, itemAad(tk.shareId, it.name)).toString('utf8');
        dek.fill(0);
        return { name: it.name, kind: it.kind, value };
      });
      key.fill(0);
      await this.mutex.run('recv', async () => {
        const all = this.received();
        all[tk.shareId] = { views, at: this.now().toISOString() };
        await this.io.writeAtomic(this.receivedFile, JSON.stringify(all, null, 1) + '\n', { mode: '0600' });
      });
      return { shareId: tk.shareId, items, note: body.note, viewsLeft: header.max_views - views, burned };
    });
  }
}

/** "90s", "15m", "2h", "7d" or a number of seconds. */
export function parseDuration(v: string | number): number {
  if (typeof v === 'number') return Math.floor(v);
  const m = /^(\d+)\s*([smhd]?)$/.exec(v.trim());
  if (!m) throw new UserError('invalid duration (use 90s, 15m, 2h, 7d)', 'invalid_args');
  return Number(m[1]) * ({ '': 1, s: 1, m: 60, h: 3600, d: 86400 } as Record<string, number>)[m[2]!]!;
}
