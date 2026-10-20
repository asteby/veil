/**
 * Output redactor. Given the secret values that were in play, removes them and
 * common encodings of them from any text that is about to be returned to the
 * model (command output, HTTP responses, error messages).
 *
 * This is a best-effort defence-in-depth layer, NOT a guarantee: a command that
 * deliberately transforms the secret (encrypts it, reverses it, prints every
 * other character...) will defeat it. See THREAT-MODEL.md.
 */

export interface RedactSource {
  /** Label used in the replacement marker, e.g. the secret name. Must not be secret. */
  label: string;
  value: string;
}

const MIN_LEN = 3;

function htmlEscape(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

/**
 * Base64 of the value as it would appear when embedded at byte offset k (mod 3)
 * inside a larger base64-encoded blob (e.g. HTTP Basic `user:secret`). Returns
 * only the characters that depend exclusively on the value's bytes.
 */
function embeddedBase64(value: Buffer, k: number, url: boolean): string {
  const enc = Buffer.concat([Buffer.alloc(k), value]).toString(url ? 'base64url' : 'base64').replace(/=+$/, '');
  const start = Math.ceil((8 * k) / 6);
  const end = Math.floor((8 * (k + value.length)) / 6); // exclusive
  return enc.slice(start, end);
}

/** All textual variants of one value that we try to remove. */
export function variantsOf(value: string): string[] {
  const out = new Set<string>();
  const add = (s: string | undefined) => {
    if (s && s.length >= MIN_LEN) out.add(s);
  };
  const buf = Buffer.from(value, 'utf8');
  add(value);
  add(value.trim());
  add(JSON.stringify(value).slice(1, -1)); // JSON / JS string escaped
  add(JSON.stringify(JSON.stringify(value)).slice(1, -1)); // double-escaped (JSON inside JSON)
  try {
    add(encodeURIComponent(value));
    add(encodeURIComponent(value).replace(/%20/g, '+'));
    add(encodeURI(value));
    add(encodeURIComponent(value).toLowerCase() === encodeURIComponent(value) ? undefined : lowerPercent(encodeURIComponent(value)));
  } catch {
    /* lone surrogates: ignore */
  }
  add(htmlEscape(value));
  add(value.replace(/'/g, `'\\''`)); // POSIX single-quote escaped
  add(value.replace(/(["\\$`])/g, '\\$1')); // double-quote escaped
  add(buf.toString('hex'));
  add(buf.toString('hex').toUpperCase());
  for (const url of [false, true]) {
    add(buf.toString(url ? 'base64url' : 'base64'));
    add(buf.toString('base64').replace(/=+$/, ''));
    for (const k of [0, 1, 2]) add(embeddedBase64(buf, k, url));
  }
  // Multi-line values (PEM keys, JSON service accounts): also redact each long line.
  if (value.includes('\n')) {
    for (const line of value.split(/\r?\n/)) if (line.trim().length >= 12) add(line.trim());
  }
  return [...out];
}

function lowerPercent(s: string): string {
  return s.replace(/%[0-9A-F]{2}/g, (m) => m.toLowerCase());
}

export class Redactor {
  private patterns: { text: string; label: string }[] = [];

  constructor(sources: RedactSource[] = []) {
    for (const s of sources) this.add(s);
  }

  add(source: RedactSource): void {
    if (!source.value) return;
    for (const v of variantsOf(source.value)) this.patterns.push({ text: v, label: source.label });
    // Longest first so that encodings containing the raw value are removed whole.
    this.patterns.sort((a, b) => b.text.length - a.text.length);
  }

  get size(): number {
    return this.patterns.length;
  }

  /**
   * Redacts all known variants. If `truncated` is true the text was cut at the end,
   * so any trailing prefix (>= 4 chars) of a variant is removed as well.
   */
  redact(text: string, opts: { truncated?: boolean } = {}): string {
    let out = text;
    for (const p of this.patterns) {
      if (out.includes(p.text)) out = out.split(p.text).join(`[REDACTED:${p.label}]`);
    }
    if (opts.truncated) {
      for (const p of this.patterns) {
        for (let n = Math.min(p.text.length - 1, out.length); n >= 4; n--) {
          if (out.endsWith(p.text.slice(0, n))) {
            out = out.slice(0, out.length - n) + `[REDACTED:${p.label}]`;
            break;
          }
        }
      }
    }
    return out;
  }

  /** True if any variant is present (used by tests and as a final guard). */
  contains(text: string): boolean {
    return this.patterns.some((p) => text.includes(p.text));
  }
}

/**
 * Process-wide registry of every protected value this server has handled
 * (form submissions, resolved secrets, captured values). Every tool response is
 * scrubbed against it as a last line of defence. Bounded in size; held only in
 * memory and cleared on exit.
 */
export class SensitiveRegistry {
  private entries: RedactSource[] = [];
  private redactor = new Redactor();

  constructor(private readonly max = 5000) {}

  add(label: string, value: string, opts: { minLength?: number } = {}): void {
    if (!value || value.length < (opts.minLength ?? MIN_LEN)) return;
    if (this.entries.some((e) => e.value === value)) return;
    this.entries.push({ label, value });
    if (this.entries.length > this.max) {
      this.entries.shift();
      this.redactor = new Redactor(this.entries);
    } else this.redactor.add({ label, value });
  }

  scrub(text: string): string {
    return this.redactor.redact(text);
  }

  contains(text: string): boolean {
    return this.redactor.contains(text);
  }

  clear(): void {
    this.entries = [];
    this.redactor = new Redactor();
  }
}

/**
 * Final guard applied to every tool response: if a value slipped through
 * redaction we refuse to return the payload at all.
 */
export function assertClean(payload: string, redactor: Redactor): void {
  if (redactor.contains(payload)) {
    throw new Error('internal: a protected value reached a tool response; response suppressed');
  }
}
