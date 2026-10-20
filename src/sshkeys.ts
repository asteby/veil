import { closeSync, constants, existsSync, mkdtempSync, openSync, readFileSync, rmSync, writeFileSync, writeSync, chmodSync, mkdirSync, appendFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import type { Config } from './config.js';
import type { Runner, RunResult } from './proc.js';
import { PrivateAgent, type Ssh, type SshKeyProvider } from './ssh.js';
import { expandHome, sleep, UserError } from './util.js';
import type { Vault } from './vault.js';

export interface KeyRecord {
  alias: string;
  host: string;
  publicKeyFile: string;
  fingerprint: string;
  storage: 'store' | 'file';
  privateKeyFile?: string;
  createdAt: string;
}

export interface HostKeyScan {
  lines: string[];
  fingerprints: string[];
  known: boolean;
}

const ALIAS_RE = /^[A-Za-z0-9_-]{1,64}$/;

/**
 * SSH key provisioning: generates ed25519 keys locally, keeps the private key in the
 * secret store (loaded into a private ssh-agent via stdin) or in a 0600 file, installs
 * the public key using a one-time password typed by the person in the local page,
 * and never exposes key material or passwords to the model.
 */
export class SshKeys implements SshKeyProvider {
  private readonly dir: string;
  private agent?: PrivateAgent;
  private loaded = new Set<string>();

  constructor(
    private readonly cfg: Config,
    private readonly vault: Vault,
    private readonly ssh: Ssh,
    private readonly runner: Runner,
    home: string,
  ) {
    this.dir = path.join(home, 'ssh');
    mkdirSync(this.dir, { recursive: true, mode: 0o700 });
  }

  private registryFile(): string {
    return path.join(this.dir, 'keys.json');
  }

  records(): Record<string, KeyRecord> {
    return existsSync(this.registryFile()) ? (JSON.parse(readFileSync(this.registryFile(), 'utf8')) as Record<string, KeyRecord>) : {};
  }

  aliasForHost(hostKey: string): string | undefined {
    const recs = Object.values(this.records()).filter((r) => r.host === hostKey);
    recs.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
    return recs[0]?.alias;
  }

  record(alias: string): KeyRecord {
    const r = this.records()[alias];
    if (!r) throw new UserError(`ssh key alias "${alias}" not found`, 'not_found');
    return r;
  }

  async ensureLoaded(alias: string): Promise<{ publicKeyFile: string; agentSocket: string }> {
    const rec = this.record(alias);
    this.agent ??= new PrivateAgent(this.vault.runDir());
    if (!this.loaded.has(alias)) {
      const priv = rec.storage === 'file' ? readFileSync(rec.privateKeyFile!, 'utf8') : (await this.vault.resolve(`${this.vault.internalDestination}:ssh_key.${alias}`)).value;
      await this.agent.add(this.runner, priv);
      this.loaded.add(alias);
    }
    return { publicKeyFile: rec.publicKeyFile, agentSocket: this.agent.socket };
  }

  stop(): void {
    this.agent?.stop();
  }

  hostTarget(hostKey: string): { hostname: string; port: number; user?: string } {
    const h = this.ssh.hostConfig(hostKey);
    return { hostname: h.host ?? hostKey, port: h.port ?? 22, user: h.user };
  }

  async scanHost(hostKey: string): Promise<HostKeyScan> {
    const { hostname, port } = this.hostTarget(hostKey);
    const r = await this.runner(['ssh-keyscan', '-T', '10', '-p', String(port), '-t', 'ed25519,ecdsa,rsa', hostname], { timeoutMs: 20_000 });
    const lines = r.stdout.toString('utf8').split('\n').filter((l) => l && !l.startsWith('#'));
    if (!lines.length) throw new UserError(`could not read host keys from ${hostKey}`, 'host_unreachable');
    const fp = await this.runner(['ssh-keygen', '-l', '-f', '-'], { stdin: lines.join('\n') + '\n', timeoutMs: 10_000 });
    const fingerprints = fp.stdout.toString('utf8').split('\n').filter(Boolean);
    const known = await this.isKnown(hostname, port);
    return { lines, fingerprints, known };
  }

  private async isKnown(hostname: string, port: number): Promise<boolean> {
    const name = port === 22 ? hostname : `[${hostname}]:${port}`;
    for (const f of [expandHome('~/.ssh/known_hosts'), this.ssh.knownHostsFile]) {
      if (!existsSync(f)) continue;
      const r = await this.runner(['ssh-keygen', '-F', name, '-f', f], { timeoutMs: 10_000 });
      if (r.code === 0 && r.stdout.length) return true;
    }
    return false;
  }

  trustHost(scan: HostKeyScan): void {
    mkdirSync(path.dirname(this.ssh.knownHostsFile), { recursive: true, mode: 0o700 });
    appendFileSync(this.ssh.knownHostsFile, scan.lines.join('\n') + '\n', { mode: 0o600 });
  }

  /** Generates the key pair; the private key never touches disk outside a 0700 temp dir (removed immediately) when storage = store. */
  async generate(alias: string, hostKey: string, storage: 'store' | 'file'): Promise<KeyRecord> {
    if (!ALIAS_RE.test(alias)) throw new UserError('invalid alias', 'invalid_args');
    const tmp = mkdtempSync(path.join(tmpdir(), 'si-key-'));
    chmodSync(tmp, 0o700);
    try {
      const keyPath = path.join(tmp, 'id');
      const r = await this.runner(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', `secret-intake:${alias}`, '-f', keyPath], { timeoutMs: 20_000 });
      if (r.code !== 0) throw new UserError('ssh-keygen failed', 'keygen_failed');
      const priv = readFileSync(keyPath, 'utf8');
      const pub = readFileSync(keyPath + '.pub', 'utf8').trim();
      const publicKeyFile = path.join(this.dir, `${alias}.pub`);
      writeFileSync(publicKeyFile, pub + '\n', { mode: 0o644 });
      const fp = await this.runner(['ssh-keygen', '-l', '-f', publicKeyFile], { timeoutMs: 10_000 });
      const rec: KeyRecord = { alias, host: hostKey, publicKeyFile, fingerprint: fp.stdout.toString('utf8').trim().split(' ')[1] ?? '', storage, createdAt: new Date().toISOString() };
      if (storage === 'file') {
        rec.privateKeyFile = path.join(this.dir, alias);
        writeFileSync(rec.privateKeyFile, priv, { mode: 0o600 });
      } else {
        await this.vault.put(this.vault.internalDestination, `ssh_key.${alias}`, priv, { tags: ['ssh-key'], source: 'ssh_key_provision' });
      }
      const all = this.records();
      all[alias] = rec;
      writeFileSync(this.registryFile(), JSON.stringify(all, null, 1) + '\n', { mode: 0o600 });
      this.loaded.delete(alias);
      return rec;
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  }

  private installScript = 'umask 077; mkdir -p "$HOME/.ssh"; touch "$HOME/.ssh/authorized_keys"; chmod 700 "$HOME/.ssh"; chmod 600 "$HOME/.ssh/authorized_keys"; k=$(cat); grep -qxF "$k" "$HOME/.ssh/authorized_keys" || printf "%s\\n" "$k" >> "$HOME/.ssh/authorized_keys"';

  /**
   * Installs the public key. With a password: ssh asks our SSH_ASKPASS helper, which
   * reads it from a FIFO in a 0700 temp dir (the password never touches disk, argv or env).
   * Without a password: uses whatever access the host config already has.
   */
  async install(hostKey: string, rec: KeyRecord, password?: string): Promise<void> {
    const pub = readFileSync(rec.publicKeyFile, 'utf8').trim();
    if (!password) {
      const r = await this.ssh.script(hostKey, this.installScript, [], { stdin: pub + '\n', timeoutMs: 60_000 });
      if (r.code !== 0) throw new UserError('could not install the public key (no existing access?)', 'install_failed');
      return;
    }
    const tmp = mkdtempSync(path.join(tmpdir(), 'si-askpass-'));
    chmodSync(tmp, 0o700);
    const fifo = path.join(tmp, 'pw');
    const helper = path.join(tmp, 'askpass.sh');
    try {
      const mk = await this.runner(['mkfifo', '-m', '600', fifo], { timeoutMs: 5000 });
      if (mk.code !== 0) throw new UserError('mkfifo failed', 'install_failed');
      writeFileSync(helper, '#!/bin/sh\nexec cat "$SI_ASKPASS_FIFO"\n', { mode: 0o700 });
      const { hostname, port, user } = this.hostTarget(hostKey);
      const argv = [
        this.cfg.ssh.binary,
        '-o', 'StrictHostKeyChecking=yes',
        '-o', `UserKnownHostsFile=${['~/.ssh/known_hosts', this.ssh.knownHostsFile].join(' ')}`,
        '-o', 'PreferredAuthentications=password,keyboard-interactive',
        '-o', 'PubkeyAuthentication=no',
        '-o', 'NumberOfPasswordPrompts=1',
        '-o', `ConnectTimeout=${this.cfg.ssh.connectTimeoutSeconds}`,
        '-p', String(port),
        ...(user ? ['-l', user] : []),
        hostname,
        '--',
        `sh -c '${this.installScript.replace(/'/g, `'\\''`)}'`,
      ];
      const env = { ...process.env, SSH_ASKPASS: helper, SSH_ASKPASS_REQUIRE: 'force', DISPLAY: process.env.DISPLAY ?? ':0', SI_ASKPASS_FIFO: fifo };
      const running: Promise<RunResult> = this.runner(argv, { stdin: pub + '\n', env, timeoutMs: 60_000 });
      let finished = false;
      void running.finally(() => (finished = true));
      // Feed the password to the FIFO once ssh's askpass opens it for reading.
      const deadline = Date.now() + 60_000;
      while (!finished && Date.now() < deadline) {
        let fd: number | undefined;
        try {
          fd = openSync(fifo, constants.O_WRONLY | constants.O_NONBLOCK);
        } catch {
          await sleep(50);
          continue;
        }
        try {
          writeSync(fd, password + '\n');
        } finally {
          closeSync(fd);
        }
        break;
      }
      const r = await running;
      if (r.code !== 0) throw new UserError('password authentication or key installation failed', 'install_failed');
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  }

  async testAccess(hostKey: string, alias: string): Promise<boolean> {
    const k = await this.ensureLoaded(alias);
    const { argv } = await this.ssh.baseArgv(hostKey, ['-o', `IdentityAgent=${k.agentSocket}`, '-o', 'IdentitiesOnly=yes', '-i', k.publicKeyFile]);
    const r = await this.runner([...argv, '--', 'true'], { timeoutMs: 30_000 });
    return r.code === 0;
  }
}
