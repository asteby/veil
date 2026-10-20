import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { homedir } from 'node:os';
import path from 'node:path';

/** Random URL-safe token (default 32 bytes = 256 bits). */
export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString('base64url');
}

/** Short random id for requests/operations, e.g. `req_3k9...`. Not a credential. */
export function newId(prefix: string): string {
  return `${prefix}_${randomBytes(9).toString('base64url')}`;
}

/** Constant-time comparison for tokens. */
export function safeEqual(a: string | undefined, b: string | undefined): boolean {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const ba = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ba.length !== bb.length) return false;
  return timingSafeEqual(ba, bb);
}

/** Deterministic JSON (sorted object keys) used for fingerprints. */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortDeep(value));
}

function sortDeep(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortDeep);
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      const v = (value as Record<string, unknown>)[key];
      if (v !== undefined) out[key] = sortDeep(v);
    }
    return out;
  }
  return value;
}

/** sha256 hex of the canonical JSON form. Never feed secret values into this. */
export function fingerprint(plan: unknown): string {
  return createHash('sha256').update(canonicalJson(plan)).digest('hex');
}

export function sha256Hex(data: string | Buffer): string {
  return createHash('sha256').update(data).digest('hex');
}

/** Expand a leading `~/`. */
export function expandHome(p: string): string {
  if (p === '~') return homedir();
  if (p.startsWith('~/')) return path.join(homedir(), p.slice(2));
  return p;
}

/**
 * Glob match with `*` (no slash) and `**` (anything). Everything else literal.
 * Used for allowlists of paths, keys and repositories.
 */
export function globMatch(pattern: string, value: string): boolean {
  let re = '^';
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i]!;
    if (c === '*') {
      if (pattern[i + 1] === '*') {
        re += '.*';
        i++;
      } else re += '[^/]*';
    } else if (c === '?') re += '[^/]';
    else re += c.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  }
  re += '$';
  return new RegExp(re).test(value);
}

/** Names usable as secret names / env keys. */
export const NAME_RE = /^[A-Za-z_][A-Za-z0-9_.-]{0,127}$/;
export const ENV_KEY_RE = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;

export function assertName(name: string, what = 'name'): void {
  if (!NAME_RE.test(name)) throw new UserError(`invalid ${what}: must match ${NAME_RE.source}`);
}

/**
 * An error whose message is safe to show to the model. Messages MUST NOT contain
 * secret values; construct them only from names, codes and configuration.
 */
export class UserError extends Error {
  constructor(
    message: string,
    public readonly code = 'error',
  ) {
    super(message);
    this.name = 'UserError';
  }
}

/** Single-process async mutex keyed by string. */
export class KeyedMutex {
  private tails = new Map<string, Promise<unknown>>();
  async run<T>(key: string, fn: () => Promise<T>): Promise<T> {
    const prev = this.tails.get(key) ?? Promise.resolve();
    let release!: () => void;
    const next = new Promise<void>((r) => (release = r));
    const tail = prev.then(() => next);
    this.tails.set(key, tail);
    await prev.catch(() => undefined);
    try {
      return await fn();
    } finally {
      release();
      if (this.tails.get(key) === tail) this.tails.delete(key);
    }
  }
}

/** Logger to stderr. Only ever pass ids, names and codes. */
export const log = {
  info: (msg: string) => {
    if ((process.env.VEIL_QUIET ?? process.env.VEILFORM_QUIET) !== '1') console.error(`[veil] ${msg}`);
  },
  warn: (msg: string) => console.error(`[veil] WARN ${msg}`),
};

/** Shell-quote one argument for POSIX sh (single quotes). Not for secrets. */
export function shQuote(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

export function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}
