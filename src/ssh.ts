import { spawn, type ChildProcess } from 'node:child_process';
import { existsSync, mkdirSync, rmSync } from 'node:fs';
import path from 'node:path';
import type { Config, SshHostConfig } from './config.js';
import type { RunOptions, RunResult, Runner } from './proc.js';
import { expandHome, shQuote, sleep, UserError } from './util.js';

export interface SshKeyProvider {
  /** Returns the public key file for `alias` after making sure the private key is loaded in the private agent. */
  ensureLoaded(alias: string): Promise<{ publicKeyFile: string; agentSocket: string }>;
  /** Alias of a key provisioned for this host by ssh_key_provision, if any. */
  aliasForHost(hostKey: string): string | undefined;
}

/**
 * Thin wrapper over the system `ssh` client. Hosts must be in `ssh.hosts`.
 * Host keys are verified strictly (BatchMode, StrictHostKeyChecking=yes) against
 * ~/.ssh/known_hosts plus our own known_hosts file (populated only after the
 * person confirms a fingerprint in ssh_key_provision).
 */
export class Ssh {
  keys?: SshKeyProvider;

  constructor(
    private readonly cfg: Config,
    private readonly runner: Runner,
    readonly knownHostsFile: string,
  ) {}

  hostConfig(hostKey: string): SshHostConfig {
    const h = this.cfg.ssh.hosts[hostKey];
    if (!h) throw new UserError(`ssh host "${hostKey}" is not in the ssh.hosts allowlist`, 'host_not_allowed');
    return h;
  }

  async baseArgv(hostKey: string, extraOpts: string[] = []): Promise<{ argv: string[]; env: NodeJS.ProcessEnv }> {
    const h = this.hostConfig(hostKey);
    const argv = [
      this.cfg.ssh.binary,
      '-o', 'BatchMode=yes',
      '-o', 'StrictHostKeyChecking=yes',
      '-o', `UserKnownHostsFile=${['~/.ssh/known_hosts', this.knownHostsFile].join(' ')}`,
      '-o', `ConnectTimeout=${this.cfg.ssh.connectTimeoutSeconds}`,
      '-o', 'LogLevel=ERROR',
      ...extraOpts,
    ];
    const env: NodeJS.ProcessEnv = { ...process.env };
    if (h.port) argv.push('-p', String(h.port));
    if (h.user) argv.push('-l', h.user);
    const alias = h.keyAlias ?? (h.identityFile ? undefined : this.keys?.aliasForHost(hostKey));
    if (alias) {
      if (!this.keys) throw new UserError('ssh key manager unavailable', 'internal');
      const k = await this.keys.ensureLoaded(alias);
      argv.push('-o', `IdentityAgent=${k.agentSocket}`, '-o', 'IdentitiesOnly=yes', '-i', k.publicKeyFile);
    } else if (h.identityFile) {
      argv.push('-o', 'IdentitiesOnly=yes', '-i', expandHome(h.identityFile));
    }
    argv.push(h.host ?? hostKey);
    return { argv, env };
  }

  /**
   * Runs a POSIX sh script remotely with positional args. The script and args are
   * NOT secret (paths, modes, names). Secret material goes through `opts.stdin`.
   */
  async script(hostKey: string, script: string, args: string[] = [], opts: RunOptions = {}): Promise<RunResult> {
    const h = this.hostConfig(hostKey);
    const remote = [h.sudo ? 'sudo -n sh -c' : 'sh -c', shQuote(script), 'sh', ...args.map(shQuote)].join(' ');
    const { argv, env } = await this.baseArgv(hostKey);
    return this.runner([...argv, '--', remote], { timeoutMs: 120_000, ...opts, env: { ...env, ...(opts.env ?? {}) } });
  }
}

/** A private ssh-agent owned by this process; keys are added from stdin (`ssh-add -`). */
export class PrivateAgent {
  private child?: ChildProcess;
  readonly socket: string;

  constructor(runDir: string) {
    mkdirSync(runDir, { recursive: true, mode: 0o700 });
    this.socket = path.join(runDir, `agent.${process.pid}.sock`);
  }

  async start(): Promise<void> {
    if (this.child) return;
    if (existsSync(this.socket)) rmSync(this.socket);
    this.child = spawn('ssh-agent', ['-D', '-a', this.socket], { stdio: 'ignore' });
    this.child.on('exit', () => (this.child = undefined));
    for (let i = 0; i < 50 && !existsSync(this.socket); i++) await sleep(50);
    if (!existsSync(this.socket)) throw new UserError('could not start private ssh-agent', 'ssh_agent');
  }

  async add(runner: Runner, privateKey: string, lifetimeSeconds = 3600): Promise<void> {
    await this.start();
    const r = await runner(['ssh-add', '-q', '-t', String(lifetimeSeconds), '-'], {
      stdin: privateKey.endsWith('\n') ? privateKey : privateKey + '\n',
      env: { ...process.env, SSH_AUTH_SOCK: this.socket, SSH_ASKPASS: '', DISPLAY: '' },
      timeoutMs: 10_000,
    });
    if (r.code !== 0) throw new UserError('ssh-add failed', 'ssh_agent');
  }

  stop(): void {
    try {
      this.child?.kill('SIGTERM');
    } catch {
      /* ignore */
    }
    try {
      if (existsSync(this.socket)) rmSync(this.socket);
    } catch {
      /* ignore */
    }
  }
}
