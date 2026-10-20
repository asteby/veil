/**
 * Encrypted .env format (git friendly, dotenvx/sops style). Example:
 *
 *   #/veilform-env v1
 *   #/context .env.production
 *   #/recipient key:3f1c0a9e5b7d2c44 eyJ3Ijoi...
 *   #/recipient pass eyJrZGYiOnsi...
 *   #/mac 5mW0...
 *   # database
 *   export DB_URL="enc:v1:Qm9..."    ← one AES-256-GCM ciphertext per value
 *   API_KEY="enc:v1:x1Z..." # comment kept
 *
 *  - Every line that is not a KEY=value keeps its text (comments, blank lines, order).
 *  - Each value is encrypted with the file DEK (random 32 bytes), a fresh 96-bit nonce
 *    and AAD = "veilform-env/v1/value\0<context>\0<KEY>": a value moved to another key or
 *    to another file/environment does not decrypt.
 *  - What is encrypted is the original right-hand side text (quotes, escapes, multi-line),
 *    so decrypt restores the file byte for byte.
 *  - #/mac = HMAC-SHA256(HKDF(DEK,"mac"), canonical {context, recipients, [(KEY, ciphertext)...] in order}):
 *    keys added/removed/reordered/duplicated or ciphertexts swapped between lines are detected.
 *  - The DEK is wrapped (AES-256-GCM) once per recipient: a passphrase (argon2id/scrypt) and/or
 *    raw keys (key file, OS keychain, server key). Any one recipient opens the file.
 *  - Re-encrypting after an edit keeps the ciphertext of unchanged values, so git diffs only
 *    touch the changed lines (+ the #/mac line).
 *
 * Comments and key NAMES stay in clear on purpose (reviewable diffs). See THREAT-MODEL.md.
 */
import { canonicalJson, UserError } from '../util.js';
import { parseEnv, quoteEnvValue } from '../fileformats.js';
import { b64, checkKdfParams, deriveFromPassphrase, hkdf, hmac, hmacEqual, keyId, open, randomKey, seal, unb64, type KdfParams } from '../crypto/primitives.js';

export const HEADER = '#/veilform-env v1';
const ENC_PREFIX = 'enc:v1:';
const KV_RE = /^(\s*)(export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)(\s*=\s*)(.*)$/;
const ENC_RHS_RE = /^"?enc:v1:([A-Za-z0-9_-]+)"?$/;

export type Recipient = { type: 'pass'; id: string; kdf: KdfParams; w: string } | { type: 'key'; id: string; w: string };

export type Line = { t: 'raw'; text: string } | { t: 'kv'; indent: string; exp: string; key: string; eq: string; rhs: string; trailing: string };

export interface EnvDoc {
  encrypted: boolean;
  context: string;
  recipients: Recipient[];
  mac?: string;
  lines: Line[];
}

export interface PlainEntry {
  key: string;
  value: string;
}

// ------------------------------------------------------------------ parsing

function closing(s: string, quote: '"' | "'"): number {
  for (let i = 1; i < s.length; i++) {
    if (quote === '"' && s[i] === '\\') {
      i++;
      continue;
    }
    if (s[i] === quote) return i;
  }
  return -1;
}

export function parseDoc(text: string, defaultContext = '.env'): EnvDoc {
  const src = text.split('\n');
  const doc: EnvDoc = { encrypted: false, context: defaultContext, recipients: [], lines: [] };
  let headerSeen = false;
  for (let i = 0; i < src.length; i++) {
    const line = src[i]!;
    if (line.startsWith('#/')) {
      const body = line.slice(2).replace(/\r$/, '');
      if (line.replace(/\r$/, '') === HEADER) {
        headerSeen = true;
        doc.encrypted = true;
        continue;
      }
      if (headerSeen) {
        const [k, ...rest] = body.split(' ');
        const v = rest.join(' ');
        if (k === 'context') doc.context = v;
        else if (k === 'mac') doc.mac = v;
        else if (k === 'recipient') doc.recipients.push(parseRecipient(v));
        else throw new UserError(`unknown header line #/${k}`, 'malformed');
        continue;
      }
    }
    const m = KV_RE.exec(line.replace(/\r$/, ''));
    if (!m || /^\s*#/.test(line)) {
      doc.lines.push({ t: 'raw', text: line });
      continue;
    }
    const [, indent, exp, key, eq] = m as unknown as [string, string, string | undefined, string, string];
    let rest = m[5]!;
    let rhs: string;
    let trailing = '';
    const q = rest[0];
    if (q === '"' || q === "'") {
      let end = closing(rest, q);
      while (end < 0 && i + 1 < src.length) {
        i++;
        rest += '\n' + src[i]!;
        end = closing(rest, q);
      }
      rhs = end < 0 ? rest : rest.slice(0, end + 1);
      trailing = end < 0 ? '' : rest.slice(end + 1);
      // only a comment may stay in clear after the closing quote; anything else is part of the value
      if (!/^\s*(#.*)?$/.test(trailing)) {
        rhs = rest;
        trailing = '';
      }
    } else {
      const h = rest.search(/\s#/);
      const body = h >= 0 ? rest.slice(0, h) : rest;
      rhs = body.replace(/\s+$/, '');
      trailing = rest.slice(rhs.length);
    }
    doc.lines.push({ t: 'kv', indent, exp: exp ?? '', key, eq, rhs, trailing });
  }
  if (doc.encrypted && !doc.recipients.length) throw new UserError('encrypted .env without recipients', 'malformed');
  return doc;
}

function parseRecipient(v: string): Recipient {
  const [id, blob] = v.split(' ');
  if (!id || !blob) throw new UserError('malformed recipient line', 'malformed');
  let j: { kdf?: KdfParams; w?: string };
  try {
    j = JSON.parse(unb64(blob, 'recipient').toString('utf8'));
  } catch {
    throw new UserError('malformed recipient line', 'malformed');
  }
  if (typeof j.w !== 'string') throw new UserError('malformed recipient line', 'malformed');
  if (id === 'pass' || id.startsWith('pass:')) {
    if (!j.kdf) throw new UserError('malformed recipient line', 'malformed');
    checkKdfParams(j.kdf);
    return { type: 'pass', id, kdf: j.kdf, w: j.w };
  }
  if (id.startsWith('key:')) return { type: 'key', id, w: j.w };
  throw new UserError('unknown recipient type', 'malformed');
}

export function serialize(doc: EnvDoc): string {
  const out: string[] = [];
  if (doc.encrypted) {
    out.push(HEADER, `#/context ${doc.context}`);
    for (const r of doc.recipients) out.push(`#/recipient ${r.id} ${b64(Buffer.from(JSON.stringify(r.type === 'pass' ? { kdf: r.kdf, w: r.w } : { w: r.w })))}`);
    out.push(`#/mac ${doc.mac ?? ''}`);
  }
  for (const l of doc.lines) out.push(l.t === 'raw' ? l.text : `${l.indent}${l.exp}${l.key}${l.eq}${l.rhs}${l.trailing}`);
  return out.join('\n');
}

export function kvLines(doc: EnvDoc): Extract<Line, { t: 'kv' }>[] {
  return doc.lines.filter((l): l is Extract<Line, { t: 'kv' }> => l.t === 'kv');
}

/** Key names in file order (no values). */
export function keysOf(doc: EnvDoc): string[] {
  return kvLines(doc).map((l) => l.key);
}

/** Heuristic used by the pre-commit hook: a .env-like file with values not in enc:v1 form. */
export function plaintextKeys(doc: EnvDoc): string[] {
  return kvLines(doc)
    .filter((l) => !ENC_RHS_RE.test(l.rhs) && l.rhs !== '' && l.rhs !== '""' && l.rhs !== "''")
    .map((l) => l.key);
}

// ------------------------------------------------------------------ crypto

const valueAad = (ctx: string, key: string) => `veilform-env/v1/value\0${ctx}\0${key}`;
const wrapAad = (ctx: string, rid: string) => `veilform-env/v1/wrap\0${ctx}\0${rid}`;

async function macOf(dek: Buffer, doc: EnvDoc): Promise<string> {
  const mk = await hkdf(dek, 'veilform-env/v1', `mac\0${doc.context}`);
  const body = canonicalJson({ v: 1, context: doc.context, recipients: doc.recipients.map((r) => r.id).sort(), entries: kvLines(doc).map((l) => [l.key, l.rhs]) });
  return hmac(mk, body);
}

export type RecipientSpec = { type: 'pass'; passphrase: string; kdf: KdfParams; label?: string } | { type: 'key'; key: Buffer };

async function wrapFor(spec: RecipientSpec, dek: Buffer, ctx: string): Promise<Recipient> {
  if (spec.type === 'pass') {
    if (spec.passphrase.length < 8) throw new UserError('passphrase too short (min 8 chars)', 'weak_passphrase');
    const id = spec.label ? `pass:${spec.label}` : 'pass';
    const kek = await deriveFromPassphrase(spec.passphrase, spec.kdf);
    const w = seal(kek, dek, wrapAad(ctx, id));
    kek.fill(0);
    return { type: 'pass', id, kdf: spec.kdf, w };
  }
  const id = `key:${keyId(spec.key)}`;
  return { type: 'key', id, w: seal(spec.key, dek, wrapAad(ctx, id)) };
}

export interface UnlockMaterial {
  /** raw keys available (key files, keychain, systemd credential) */
  keys?: Buffer[];
  /** asked lazily, only if a passphrase recipient exists and no key matched */
  passphrase?: () => Promise<string | undefined>;
  /** a DEK obtained otherwise (share token, session agent); verified with the MAC */
  dek?: Buffer;
}

export interface Unlocked {
  dek: Buffer;
  via: string;
}

/** Finds the DEK using any matching recipient. Wrong keys fail with `wrong_key` and no detail. */
export async function unlock(doc: EnvDoc, m: UnlockMaterial): Promise<Unlocked> {
  if (!doc.encrypted) throw new UserError('file is not a veilform encrypted .env', 'not_encrypted');
  if (m.dek) {
    if (doc.mac && hmacEqual(await macOf(m.dek, doc), doc.mac)) return { dek: m.dek, via: 'dek' };
    throw new UserError('cannot decrypt: wrong key or modified file', 'wrong_key');
  }
  for (const k of m.keys ?? []) {
    const id = `key:${keyId(k)}`;
    const r = doc.recipients.find((x) => x.id === id);
    if (!r) continue;
    try {
      return { dek: open(k, r.w, wrapAad(doc.context, r.id), 'wrong_key'), via: id };
    } catch {
      /* try next */
    }
  }
  const pass = doc.recipients.filter((r): r is Extract<Recipient, { type: 'pass' }> => r.type === 'pass');
  if (pass.length && m.passphrase) {
    const p = await m.passphrase();
    if (p !== undefined) {
      for (const r of pass) {
        const kek = await deriveFromPassphrase(p, r.kdf);
        try {
          return { dek: open(kek, r.w, wrapAad(doc.context, r.id), 'wrong_key'), via: r.id };
        } catch {
          /* next */
        } finally {
          kek.fill(0);
        }
      }
    }
  }
  throw new UserError('cannot decrypt: no matching key (wrong passphrase/key, or this key is not a recipient)', 'wrong_key');
}

/** Verifies the whole-file MAC and decrypts every value. Throws `tampered` without detail. */
export async function decryptDoc(doc: EnvDoc, dek: Buffer): Promise<{ text: string; entries: PlainEntry[] }> {
  if (!doc.mac || !hmacEqual(await macOf(dek, doc), doc.mac)) throw new UserError('integrity check failed: the encrypted .env was modified (keys added/removed/reordered or values changed)', 'tampered');
  const entries: PlainEntry[] = [];
  const lines: Line[] = [];
  for (const l of doc.lines) {
    if (l.t === 'raw') {
      lines.push(l);
      continue;
    }
    const m = ENC_RHS_RE.exec(l.rhs);
    if (!m) throw new UserError(`value of ${l.key} is not encrypted`, 'tampered');
    const rhs = open(dek, m[1]!, valueAad(doc.context, l.key)).toString('utf8');
    lines.push({ ...l, rhs });
    entries.push({ key: l.key, value: rhsValue(l.key, rhs) });
  }
  return { text: serialize({ ...doc, encrypted: false, lines }), entries };
}

/** Value of a right-hand side as dotenv would read it (quotes/escapes resolved). */
export function rhsValue(key: string, rhs: string): string {
  return parseEnv(`${key}=${rhs}`)[0]?.value ?? '';
}

/**
 * Encrypts a plaintext .env document. With `prev` (same DEK), unchanged values keep their
 * previous ciphertext so that git diffs stay minimal.
 */
export async function encryptDoc(plain: EnvDoc, opts: { context: string; dek?: Buffer; recipients: Recipient[] | RecipientSpec[]; prev?: { doc: EnvDoc; dek: Buffer } }): Promise<{ doc: EnvDoc; dek: Buffer }> {
  const dek = opts.dek ?? randomKey();
  const ctx = opts.context;
  const prevPlain = new Map<string, { rhs: string; enc: string }[]>();
  if (opts.prev && opts.prev.dek.equals(dek) && opts.prev.doc.context === ctx) {
    for (const l of kvLines(opts.prev.doc)) {
      const m = ENC_RHS_RE.exec(l.rhs);
      if (!m) continue;
      const rhs = open(dek, m[1]!, valueAad(ctx, l.key)).toString('utf8');
      prevPlain.set(l.key, [...(prevPlain.get(l.key) ?? []), { rhs, enc: l.rhs }]);
    }
  }
  const recipients: Recipient[] = [];
  for (const r of opts.recipients) recipients.push('w' in r ? r : await wrapFor(r, dek, ctx));
  if (!recipients.length) throw new UserError('at least one recipient (passphrase or key) is needed', 'invalid_args');
  if (new Set(recipients.map((r) => r.id)).size !== recipients.length) throw new UserError('duplicate recipient', 'invalid_args');
  const lines: Line[] = plain.lines.map((l) => {
    if (l.t === 'raw') return l;
    const reuse = prevPlain.get(l.key)?.find((p) => p.rhs === l.rhs);
    const enc = reuse ? reuse.enc : `"${ENC_PREFIX}${seal(dek, l.rhs, valueAad(ctx, l.key))}"`;
    return { ...l, rhs: enc };
  });
  const doc: EnvDoc = { encrypted: true, context: ctx, recipients, lines };
  doc.mac = await macOf(dek, doc);
  return { doc, dek };
}

/** Applies value changes (string = set, null = delete) to a plaintext doc, appending new keys. */
export function applyChanges(plain: EnvDoc, changes: Record<string, string | null>): EnvDoc {
  const seen = new Set<string>();
  const lines: Line[] = [];
  for (const l of plain.lines) {
    if (l.t === 'kv' && l.key in changes) {
      const v = changes[l.key];
      seen.add(l.key);
      if (v === null) continue;
      lines.push({ ...l, rhs: quoteEnvValue(v!) });
      continue;
    }
    lines.push(l);
  }
  const add = Object.entries(changes).filter(([k, v]) => !seen.has(k) && v !== null);
  if (add.length) {
    // insert before trailing empty line(s) so that the file keeps its final newline
    let at = lines.length;
    while (at > 0 && lines[at - 1]!.t === 'raw' && (lines[at - 1] as { text: string }).text === '') at--;
    lines.splice(at, 0, ...add.map(([k, v]): Line => ({ t: 'kv', indent: '', exp: '', key: k, eq: '=', rhs: quoteEnvValue(v!), trailing: '' })));
  }
  return { ...plain, lines };
}

/** Adds/removes recipients (needs the DEK). Values are untouched; the MAC is recomputed. */
export async function setRecipients(doc: EnvDoc, dek: Buffer, add: RecipientSpec[], removeIds: string[] = []): Promise<EnvDoc> {
  const recipients = doc.recipients.filter((r) => !removeIds.includes(r.id));
  for (const s of add) {
    const r = await wrapFor(s, dek, doc.context);
    const i = recipients.findIndex((x) => x.id === r.id);
    if (i >= 0) recipients[i] = r;
    else recipients.push(r);
  }
  if (!recipients.length) throw new UserError('cannot remove the last recipient', 'invalid_args');
  const out: EnvDoc = { ...doc, recipients };
  out.mac = await macOf(dek, out);
  return out;
}

