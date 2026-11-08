import { describe, expect, it } from 'vitest';
import { WindowsCredentialBackend } from '../src/stores/keychain.js';
import { run } from '../src/proc.js';

describe.skipIf(process.platform !== 'win32')('WindowsCredentialBackend (real Credential Manager)', () => {
  it('round-trips, overwrites and deletes a value', async () => {
    const b = new WindowsCredentialBackend(run);
    const svc = 'veil-test-' + process.pid;
    const v = 'línea1\nline2 "q" $x `t`';
    expect(await b.get(svc, 'probe')).toBeUndefined();
    await b.set(svc, 'probe', v);
    expect(await b.get(svc, 'probe')).toBe(v);
    await b.set(svc, 'probe', 'otro');
    expect(await b.get(svc, 'probe')).toBe('otro');
    expect(await b.delete(svc, 'probe')).toBe(true);
    expect(await b.get(svc, 'probe')).toBeUndefined();
  }, 120_000);

  it('rejects values over the 2560-byte limit', async () => {
    const b = new WindowsCredentialBackend(run);
    await expect(b.set('veil-test-big', 'x', 'a'.repeat(2561))).rejects.toThrow(/2560/);
  });
});
