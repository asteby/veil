import { KeychainError, type KeychainReason } from '../errors.js';
import type { Runner, RunOptions, RunResult } from '../proc.js';
import { keychainServiceAliases } from '../naming.js';
import { UserError } from '../util.js';
import type { PutResult, SecretStore } from './types.js';

/**
 * OS keychain through the platform CLI, so no native addon is required:
 *  - Linux: `secret-tool` (libsecret / GNOME Keyring / KWallet via Secret Service)
 *  - macOS: `security` (the value is passed on stdin to `security -i`, never argv)
 *  - Windows: Credential Manager through PowerShell (P/Invoke to advapi32), value on stdin.
 * Other platforms fall back to Veil's own encrypted store (see LocalVault).
 *
 * Failures are classified into structured, value-free codes (keychain_unavailable /
 * keychain_locked / keychain_failed) with a sub-cause so the person gets the exact fix.
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

/** Maps libsecret / secret-tool stderr to a structured failure (stderr never contains values). */
export function classifySecretToolError(stderr: string, op: string): KeychainError {
  if (/locked|dismiss|unlock/i.test(stderr)) return new KeychainError(`keychain is locked (secret-tool ${op})`, 'keychain_locked');
  if (/autolaunch|Cannot spawn a message bus|Could not connect|Failed to connect to (the )?bus|DBUS_SESSION_BUS_ADDRESS/i.test(stderr)) return new KeychainError(`no D-Bus session for the keychain (secret-tool ${op})`, 'keychain_unavailable', 'no_dbus');
  if (/not provided by any \.service|ServiceUnknown|org\.freedesktop\.secrets|No such interface|was not provided/i.test(stderr)) return new KeychainError(`no Secret Service provider answers (secret-tool ${op})`, 'keychain_unavailable', 'no_service');
  return new KeychainError(`keychain ${op} failed (secret-tool)`, 'keychain_failed');
}

/** Runs a keychain CLI; a missing binary becomes keychain_unavailable instead of a crash. */
async function runKeychainTool(runner: Runner, argv: string[], opts: RunOptions, reason: KeychainReason = 'missing_tool'): Promise<RunResult> {
  try {
    return await runner(argv, opts);
  } catch (e) {
    const code = (e as NodeJS.ErrnoException)?.code;
    if (code === 'ENOENT' || code === 'EACCES') throw new KeychainError(`${argv[0]} is not installed or not executable`, 'keychain_unavailable', reason);
    throw new KeychainError(`${argv[0]} could not be started`, 'keychain_failed');
  }
}

export class SecretToolBackend implements KeychainBackend {
  readonly name = 'secret-tool';
  constructor(private readonly runner: Runner) {}

  async set(service: string, account: string, value: string): Promise<void> {
    const r = await runKeychainTool(this.runner, ['secret-tool', 'store', `--label=Veil: ${account}`, 'service', service, 'account', account], {
      stdin: value,
      timeoutMs: 30_000,
    });
    if (r.timedOut) throw new KeychainError('keychain did not answer (locked or waiting for an unlock prompt)', 'keychain_locked');
    if (r.code !== 0) throw classifySecretToolError(r.stderr.toString('utf8'), 'store');
  }

  async get(service: string, account: string): Promise<string | undefined> {
    const r = await runKeychainTool(this.runner, ['secret-tool', 'lookup', 'service', service, 'account', account], { timeoutMs: 30_000 });
    if (r.timedOut) throw new KeychainError('keychain did not answer (locked or waiting for an unlock prompt)', 'keychain_locked');
    if (r.code !== 0) {
      // exit 1 with empty stderr = no such item; anything on stderr is a real failure
      const err = r.stderr.toString('utf8').trim();
      if (!err) return undefined;
      throw classifySecretToolError(err, 'lookup');
    }
    return r.stdout.toString('utf8');
  }

  async delete(service: string, account: string): Promise<boolean> {
    const r = await runKeychainTool(this.runner, ['secret-tool', 'clear', 'service', service, 'account', account], { timeoutMs: 30_000 });
    return r.code === 0;
  }
}

/** Escapes a token for `security -i` (double-quoted, backslash escapes). */
function securityQuote(s: string): string {
  return `"${s.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
}

function macError(r: RunResult, op: string): KeychainError {
  const err = r.stderr.toString('utf8');
  // 36 = errSecInteractionNotAllowed / 51 = errSecAuthFailed / 25308: user interaction not allowed (locked)
  if (r.code === 36 || r.code === 51 || /interaction is not allowed|locked/i.test(err)) return new KeychainError(`keychain is locked (security ${op})`, 'keychain_locked');
  return new KeychainError(`keychain ${op} failed (security)`, 'keychain_failed');
}

export class MacSecurityBackend implements KeychainBackend {
  readonly name = 'macos-security';
  constructor(private readonly runner: Runner) {}

  async set(service: string, account: string, value: string): Promise<void> {
    if (/[\r\n]/.test(value)) throw new UserError('macOS keychain backend does not support multi-line values; use encrypted-file', 'unsupported_value');
    const cmd = `add-generic-password -U -s ${securityQuote(service)} -a ${securityQuote(account)} -w ${securityQuote(value)}\n`;
    const r = await runKeychainTool(this.runner, ['security', '-i'], { stdin: cmd, timeoutMs: 30_000 });
    if (r.code !== 0) throw macError(r, 'write');
  }

  async get(service: string, account: string): Promise<string | undefined> {
    const r = await runKeychainTool(this.runner, ['security', 'find-generic-password', '-s', service, '-a', account, '-w'], { timeoutMs: 30_000 });
    if (r.code === 44) return undefined; // errSecItemNotFound
    if (r.code !== 0) {
      if (/could not be found/i.test(r.stderr.toString('utf8'))) return undefined;
      throw macError(r, 'read');
    }
    return r.stdout.toString('utf8').replace(/\n$/, '');
  }

  async delete(service: string, account: string): Promise<boolean> {
    const r = await runKeychainTool(this.runner, ['security', 'delete-generic-password', '-s', service, '-a', account], { timeoutMs: 30_000 });
    return r.code === 0;
  }
}

/**
 * Windows Credential Manager through PowerShell + P/Invoke (advapi32 CredRead/CredWrite/CredDelete):
 * no native addon or extra module. The script goes in with -EncodedCommand; the operation,
 * service, account and value travel base64-encoded on stdin, never on argv.
 */
const WIN_CRED_SCRIPT = String.raw`
$ErrorActionPreference = 'Stop'
Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices;
public static class VeilCred {
  [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
  struct CREDENTIAL { public uint Flags; public uint Type; public string TargetName; public string Comment; public long LastWritten; public uint CredentialBlobSize; public IntPtr CredentialBlob; public uint Persist; public uint AttributeCount; public IntPtr Attributes; public string TargetAlias; public string UserName; }
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool CredWrite(ref CREDENTIAL c, uint f);
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool CredRead(string t, uint type, uint f, out IntPtr p);
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool CredDelete(string t, uint type, uint f);
  [DllImport("advapi32.dll")] static extern void CredFree(IntPtr p);
  public static int Write(string target, byte[] blob) {
    var c = new CREDENTIAL { Type = 1, TargetName = target, UserName = "veil", Persist = 2, CredentialBlobSize = (uint)blob.Length };
    c.CredentialBlob = Marshal.AllocHGlobal(blob.Length);
    try { Marshal.Copy(blob, 0, c.CredentialBlob, blob.Length); return CredWrite(ref c, 0) ? 0 : Marshal.GetLastWin32Error(); }
    finally { Marshal.FreeHGlobal(c.CredentialBlob); }
  }
  public static int Read(string target, out byte[] blob) {
    blob = null; IntPtr p;
    if (!CredRead(target, 1, 0, out p)) return Marshal.GetLastWin32Error();
    try { var c = (CREDENTIAL)Marshal.PtrToStructure(p, typeof(CREDENTIAL)); blob = new byte[c.CredentialBlobSize]; Marshal.Copy(c.CredentialBlob, blob, 0, blob.Length); return 0; }
    finally { CredFree(p); }
  }
  public static int Delete(string target) { return CredDelete(target, 1, 0) ? 0 : Marshal.GetLastWin32Error(); }
}
'@
function D([string]$s) { [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($s)) }
$l = [Console]::In.ReadToEnd() -split "\r?\n"
$target = (D $l[1]) + '/' + (D $l[2])
switch ($l[0]) {
  'set' { exit [VeilCred]::Write($target, [Convert]::FromBase64String($l[3])) }
  'delete' { exit [VeilCred]::Delete($target) }
  default {
    $b = $null
    $rc = [VeilCred]::Read($target, [ref]$b)
    if ($rc -ne 0) { exit $rc }
    [Console]::Out.Write([Convert]::ToBase64String($b))
  }
}
`;

const ERROR_NOT_FOUND = 1168;
const WIN_CRED_ARGV = ['powershell.exe', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', Buffer.from(WIN_CRED_SCRIPT, 'utf16le').toString('base64')];

const b64 = (s: string) => Buffer.from(s, 'utf8').toString('base64');

export class WindowsCredentialBackend implements KeychainBackend {
  readonly name = 'windows-credential-manager';
  constructor(private readonly runner: Runner) {}

  private async call(op: 'set' | 'get' | 'delete', service: string, account: string, value?: string): Promise<RunResult> {
    const stdin = [op, b64(service), b64(account), ...(value === undefined ? [] : [b64(value)])].join('\n');
    const r = await runKeychainTool(this.runner, WIN_CRED_ARGV, { stdin, timeoutMs: 60_000 });
    if (r.timedOut) throw new KeychainError('Credential Manager did not answer', 'keychain_failed');
    return r;
  }

  async set(service: string, account: string, value: string): Promise<void> {
    const bytes = Buffer.byteLength(value, 'utf8');
    if (bytes > 2560) throw new UserError('Windows Credential Manager limits a value to 2560 bytes; use encrypted-file', 'unsupported_value');
    const r = await this.call('set', service, account, value);
    if (r.code !== 0) throw new KeychainError('keychain write failed (Credential Manager)', 'keychain_failed');
  }

  async get(service: string, account: string): Promise<string | undefined> {
    const r = await this.call('get', service, account);
    if (r.code === ERROR_NOT_FOUND) return undefined;
    if (r.code !== 0) throw new KeychainError('keychain read failed (Credential Manager)', 'keychain_failed');
    return Buffer.from(r.stdout.toString('utf8').trim(), 'base64').toString('utf8');
  }

  async delete(service: string, account: string): Promise<boolean> {
    const r = await this.call('delete', service, account);
    return r.code === 0;
  }
}

export function defaultKeychainBackend(runner: Runner): KeychainBackend {
  if (process.platform === 'darwin') return new MacSecurityBackend(runner);
  if (process.platform === 'linux' || process.platform === 'freebsd') return new SecretToolBackend(runner);
  if (process.platform === 'win32') return new WindowsCredentialBackend(runner);
  return {
    name: 'unsupported',
    set: async () => {
      throw new KeychainError('OS keychain is not supported on this platform', 'keychain_unsupported', 'unsupported_os');
    },
    get: async () => {
      throw new KeychainError('OS keychain is not supported on this platform', 'keychain_unsupported', 'unsupported_os');
    },
    delete: async () => false,
  };
}

/**
 * Compatibility with the former product name: reads that miss under the configured service
 * retry under its alias (`veilform` <-> `veil`), so secrets stored by either name keep being
 * found whichever service is configured. Writes go to the configured service only; deletes
 * clear both, so a deleted secret cannot reappear from the alias.
 */
export function withServiceAliases(b: KeychainBackend, aliases: (service: string) => string[] = keychainServiceAliases): KeychainBackend {
  return {
    name: b.name,
    set: (service, account, value) => b.set(service, account, value),
    async get(service, account) {
      const v = await b.get(service, account);
      if (v !== undefined) return v;
      for (const alt of aliases(service)) {
        const w = await b.get(alt, account);
        if (w !== undefined) return w;
      }
      return undefined;
    },
    async delete(service, account) {
      let deleted = await b.delete(service, account);
      for (const alt of aliases(service)) deleted = (await b.delete(alt, account)) || deleted;
      return deleted;
    },
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
