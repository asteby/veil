import type { Runner } from '../proc.js';
import { UserError } from '../util.js';
import type { PutResult, SecretStore } from './types.js';

/**
 * OS keychain through the platform CLI, so no native addon is required:
 *  - Linux: `secret-tool` (libsecret / GNOME Keyring / KWallet via Secret Service)
 *  - macOS: `security` (the value is passed on stdin to `security -i`, never argv)
 * Windows is not supported in this MVP (use `encrypted-file`).
 *
 * Deviation from the suggested `@napi-rs/keyring`: it was not available offline and
 * a native addon adds install friction; the CLI backends keep values off argv.
 */
export interface KeychainBackend {
  readonly name: string;
  set(service: string, account: string, value: string): Promise<void>;
  get(service: string, account: string): Promise<string | undefined>;
  delete(service: string, account: string): Promise<boolean>;
}

export class SecretToolBackend implements KeychainBackend {
  readonly name = 'secret-tool';
  constructor(private readonly runner: Runner) {}

  async set(service: string, account: string, value: string): Promise<void> {
    const r = await this.runner(['secret-tool', 'store', `--label=secret-intake: ${account}`, 'service', service, 'account', account], {
      stdin: value,
      timeoutMs: 30_000,
    });
    if (r.code !== 0) throw new UserError('keychain write failed (secret-tool)', 'keychain_failed');
  }

  async get(service: string, account: string): Promise<string | undefined> {
    const r = await this.runner(['secret-tool', 'lookup', 'service', service, 'account', account], { timeoutMs: 30_000 });
    if (r.code !== 0) return undefined;
    return r.stdout.toString('utf8');
  }

  async delete(service: string, account: string): Promise<boolean> {
    const r = await this.runner(['secret-tool', 'clear', 'service', service, 'account', account], { timeoutMs: 30_000 });
    return r.code === 0;
  }
}

/** Escapes a token for `security -i` (double-quoted, backslash escapes). */
function securityQuote(s: string): string {
  return `"${s.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
}

export class MacSecurityBackend implements KeychainBackend {
  readonly name = 'macos-security';
  constructor(private readonly runner: Runner) {}

  async set(service: string, account: string, value: string): Promise<void> {
    if (/[\r\n]/.test(value)) throw new UserError('macOS keychain backend does not support multi-line values; use encrypted-file', 'unsupported_value');
    const cmd = `add-generic-password -U -s ${securityQuote(service)} -a ${securityQuote(account)} -w ${securityQuote(value)}\n`;
    const r = await this.runner(['security', '-i'], { stdin: cmd, timeoutMs: 30_000 });
    if (r.code !== 0) throw new UserError('keychain write failed (security)', 'keychain_failed');
  }

  async get(service: string, account: string): Promise<string | undefined> {
    const r = await this.runner(['security', 'find-generic-password', '-s', service, '-a', account, '-w'], { timeoutMs: 30_000 });
    if (r.code !== 0) return undefined;
    return r.stdout.toString('utf8').replace(/\n$/, '');
  }

  async delete(service: string, account: string): Promise<boolean> {
    const r = await this.runner(['security', 'delete-generic-password', '-s', service, '-a', account], { timeoutMs: 30_000 });
    return r.code === 0;
  }
}

export function defaultKeychainBackend(runner: Runner): KeychainBackend {
  if (process.platform === 'darwin') return new MacSecurityBackend(runner);
  if (process.platform === 'linux' || process.platform === 'freebsd') return new SecretToolBackend(runner);
  return {
    name: 'unsupported',
    set: async () => {
      throw new UserError('OS keychain is not supported on this platform yet; use an encrypted-file destination', 'keychain_unsupported');
    },
    get: async () => undefined,
    delete: async () => false,
  };
}

export class KeychainStore implements SecretStore {
  readonly type = 'keychain';
  readonly readable = true;

  constructor(
    readonly id: string,
    private readonly service: string,
    private readonly backend: KeychainBackend,
  ) {}

  async put(name: string, value: string): Promise<PutResult> {
    const existed = (await this.backend.get(this.service, name)) !== undefined;
    await this.backend.set(this.service, name, value);
    return { action: existed ? 'updated' : 'created' };
  }

  get(name: string): Promise<string | undefined> {
    return this.backend.get(this.service, name);
  }

  delete(name: string): Promise<boolean> {
    return this.backend.delete(this.service, name);
  }

  describe(): string {
    return `OS keychain (${this.backend.name}, service "${this.service}")`;
  }
}
