import { existsSync, readFileSync } from 'node:fs';
import { LocalFileIO } from '../fileio.js';
import { KeyedMutex, UserError } from '../util.js';

/**
 * Persistent failed-attempt counter for passphrase prompts (local pages and CLI), keyed by a
 * public id (share id, encrypted file id). After `max` failures the id is locked for
 * `lockMs`; the lock doubles each time it is hit again. Complements the KDF cost: it slows
 * down online guessing through our own UI; it cannot stop an offline attack on a copied
 * bundle (only the passphrase strength and the KDF cost do — see THREAT-MODEL.md).
 */
export class AttemptLimiter {
  private readonly io = new LocalFileIO();
  private readonly mutex = new KeyedMutex();
  constructor(
    private readonly file: string,
    private readonly max = 5,
    private readonly lockMs = 15 * 60_000,
    private readonly now: () => number = Date.now,
  ) {}

  private load(): Record<string, { fails: number; lockedUntil?: number; locks?: number }> {
    if (!existsSync(this.file)) return {};
    try {
      return JSON.parse(readFileSync(this.file, 'utf8'));
    } catch {
      return {};
    }
  }

  check(id: string): void {
    const e = this.load()[id];
    if (e?.lockedUntil && e.lockedUntil > this.now()) throw new UserError(`too many failed attempts; locked until ${new Date(e.lockedUntil).toISOString()}`, 'too_many_attempts');
  }

  remaining(id: string): number {
    const e = this.load()[id];
    return Math.max(0, this.max - (e?.fails ?? 0));
  }

  fail(id: string): Promise<number> {
    return this.mutex.run('a', async () => {
      const s = this.load();
      const e = (s[id] ??= { fails: 0 });
      if (e.lockedUntil && e.lockedUntil <= this.now()) {
        e.fails = 0;
        e.lockedUntil = undefined;
      }
      e.fails++;
      if (e.fails >= this.max) {
        e.locks = (e.locks ?? 0) + 1;
        e.lockedUntil = this.now() + this.lockMs * 2 ** Math.min(e.locks - 1, 6);
      }
      await this.io.writeAtomic(this.file, JSON.stringify(s), { mode: '0600' });
      return Math.max(0, this.max - e.fails);
    });
  }

  ok(id: string): Promise<void> {
    return this.mutex.run('a', async () => {
      const s = this.load();
      if (!s[id]) return;
      delete s[id];
      await this.io.writeAtomic(this.file, JSON.stringify(s), { mode: '0600' });
    });
  }
}
