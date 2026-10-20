import { existsSync, readFileSync } from 'node:fs';
import { LocalFileIO } from './fileio.js';
import { KeyedMutex, newId } from './util.js';

export type OpStatus = 'awaiting_user' | 'running' | 'completed' | 'cancelled' | 'denied' | 'expired' | 'failed';

/** Structural result returned to the model. MUST NOT contain values. */
export type SafeResult = Record<string, unknown>;

export interface Operation {
  id: string;
  kind: string;
  status: OpStatus;
  url?: string;
  result?: SafeResult;
  createdAt: number;
  done: Promise<void>;
}

interface OpInternal extends Operation {
  resolve: () => void;
}

const TERMINAL: OpStatus[] = ['completed', 'cancelled', 'denied', 'expired', 'failed'];

/** In-memory registry of operations that wait for the person. */
export class Operations {
  private ops = new Map<string, OpInternal>();

  create(kind: string, prefix = 'req'): Operation {
    let resolve!: () => void;
    const done = new Promise<void>((r) => (resolve = r));
    const op: OpInternal = { id: newId(prefix), kind, status: 'awaiting_user', createdAt: Date.now(), done, resolve };
    this.ops.set(op.id, op);
    // forget finished operations after an hour
    setTimeout(() => this.ops.delete(op.id), 3_600_000).unref();
    return op;
  }

  get(id: string): Operation | undefined {
    return this.ops.get(id);
  }

  setStatus(id: string, status: OpStatus): void {
    const op = this.ops.get(id);
    if (op && !TERMINAL.includes(op.status)) op.status = status;
  }

  finish(id: string, status: OpStatus, result: SafeResult = {}): void {
    const op = this.ops.get(id);
    if (!op || TERMINAL.includes(op.status)) return;
    op.status = status;
    op.result = { ...result };
    op.resolve();
  }

  isTerminal(op: Operation): boolean {
    return TERMINAL.includes(op.status);
  }

  async wait(id: string, timeoutMs: number): Promise<Operation | undefined> {
    const op = this.ops.get(id);
    if (!op) return undefined;
    if (!this.isTerminal(op) && timeoutMs > 0) {
      let t: NodeJS.Timeout | undefined;
      await Promise.race([op.done, new Promise<void>((r) => (t = setTimeout(r, timeoutMs)))]);
      if (t) clearTimeout(t);
    }
    return op;
  }
}

interface ApprovalsShape {
  v: 1;
  approved: Record<string, { kind: string; summary: string; at: string }>;
}

/** Persisted "remember this exact action" approvals, keyed by fingerprint. */
export class Approvals {
  private readonly io = new LocalFileIO();
  private readonly mutex = new KeyedMutex();

  constructor(private readonly file: string) {}

  private load(): ApprovalsShape {
    if (!existsSync(this.file)) return { v: 1, approved: {} };
    return JSON.parse(readFileSync(this.file, 'utf8')) as ApprovalsShape;
  }

  isApproved(fp: string): boolean {
    return Boolean(this.load().approved[fp]);
  }

  remember(fp: string, kind: string, summary: string): Promise<void> {
    return this.mutex.run('a', async () => {
      const s = this.load();
      s.approved[fp] = { kind, summary: summary.slice(0, 500), at: new Date().toISOString() };
      await this.io.writeAtomic(this.file, JSON.stringify(s, null, 1) + '\n', { mode: '0600' });
    });
  }

  forget(fp: string): Promise<boolean> {
    return this.mutex.run('a', async () => {
      const s = this.load();
      if (!s.approved[fp]) return false;
      delete s.approved[fp];
      await this.io.writeAtomic(this.file, JSON.stringify(s, null, 1) + '\n', { mode: '0600' });
      return true;
    });
  }
}
