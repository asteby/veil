import { appendFileSync, existsSync, mkdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { sha256Hex } from './util.js';

/**
 * Append-only JSONL audit log. Each line carries `prev`, the sha256 of the previous
 * line, so truncation or edits in the middle are detectable (`verifyAuditLog`).
 * Entries contain ONLY ids, names, fingerprints, codes and metadata — never values.
 */
export interface AuditContext {
  session: string;
  agent?: string;
  client?: string;
}

export class AuditLog {
  private lastHash: string;

  constructor(
    private readonly file: string,
    private readonly ctx: AuditContext,
  ) {
    mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
    this.lastHash = 'genesis';
    if (existsSync(file)) {
      const lines = readFileSync(file, 'utf8').split('\n').filter(Boolean);
      const last = lines[lines.length - 1];
      if (last) this.lastHash = sha256Hex(last);
    }
  }

  setClient(client: string | undefined): void {
    this.ctx.client = client;
  }

  write(event: string, data: Record<string, unknown> = {}): void {
    const entry = {
      ts: new Date().toISOString(),
      event,
      session: this.ctx.session,
      agent: this.ctx.agent,
      client: this.ctx.client,
      ...data,
      prev: this.lastHash,
    };
    const line = JSON.stringify(entry);
    // 'a' flag = O_APPEND; mode applies on creation only.
    appendFileSync(this.file, line + '\n', { flag: 'a', mode: 0o600 });
    this.lastHash = sha256Hex(line);
  }
}

/** Verifies the hash chain. Returns the 1-based line number of the first broken link, or 0. */
export function verifyAuditLog(file: string): number {
  if (!existsSync(file)) return 0;
  const lines = readFileSync(file, 'utf8').split('\n').filter(Boolean);
  let prev = 'genesis';
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    let parsed: { prev?: string };
    try {
      parsed = JSON.parse(line);
    } catch {
      return i + 1;
    }
    if (parsed.prev !== prev) return i + 1;
    prev = sha256Hex(line);
  }
  return 0;
}
