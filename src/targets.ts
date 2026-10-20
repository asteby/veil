import { z } from 'zod';
import type { Config, WriteTargetRule } from './config.js';
import { LocalFileIO, SshFileIO, type FileIO } from './fileio.js';
import { getEnvKey, getJsonPath, setEnvKey, setJsonPath, setYamlPath, type WriteAction } from './fileformats.js';
import type { Runner } from './proc.js';
import type { Ssh } from './ssh.js';
import path from 'node:path';
import { ENV_KEY_RE, expandHome, globMatch, KeyedMutex, shQuote, UserError } from './util.js';

/**
 * Write targets: places where a stored value is COPIED (deployed) without the model
 * seeing it. Every target must match a rule in `writeTargets` (allowlist).
 */
export const TargetSchema = z.discriminatedUnion('kind', [
  z.object({
    kind: z.literal('env-file'),
    host: z.string().optional().describe('ssh.hosts key; omit for local'),
    path: z.string(),
    key: z.string().optional().describe('env key (default: secret name)'),
    mode: z.string().optional(),
    owner: z.string().optional(),
    group: z.string().optional(),
    backup: z.boolean().optional(),
  }),
  z.object({ kind: z.literal('json'), host: z.string().optional(), path: z.string(), key: z.string().describe('JSON pointer (/a/b) or dotted path (a.b)'), mode: z.string().optional(), backup: z.boolean().optional() }),
  z.object({ kind: z.literal('yaml'), host: z.string().optional(), path: z.string(), key: z.string().describe('dotted path a.b.c (block mappings only)'), mode: z.string().optional(), backup: z.boolean().optional() }),
  z.object({
    kind: z.literal('systemd'),
    host: z.string().optional(),
    unit: z.string().regex(/^[A-Za-z0-9@_.-]+\.service$/),
    key: z.string().optional(),
    env_file: z.string().optional().describe('default /etc/veilform/<unit>.env'),
    restart: z.boolean().optional(),
  }),
  z.object({ kind: z.literal('github'), repo: z.string().regex(/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/), key: z.string().optional(), environment: z.string().optional() }),
  z.object({ kind: z.literal('clipboard'), clear_after_seconds: z.number().int().min(5).max(600).default(30) }),
]);
export type Target = z.infer<typeof TargetSchema>;

export interface Change {
  key: string;
  action: WriteAction;
}

const mutex = new KeyedMutex();

export function targetPath(t: Target): string | undefined {
  if (t.kind === 'env-file' || t.kind === 'json' || t.kind === 'yaml') return t.path;
  if (t.kind === 'systemd') return t.env_file ?? `/etc/veilform/${t.unit.replace(/\.service$/, '')}.env`;
  return undefined;
}

/** Public, value-free description of a target (returned to the model and shown to the person). */
export function describeTarget(t: Target): Record<string, unknown> {
  switch (t.kind) {
    case 'github':
      return { kind: t.kind, repo: t.repo, environment: t.environment };
    case 'clipboard':
      return { kind: t.kind, clear_after_seconds: t.clear_after_seconds };
    case 'systemd':
      return { kind: t.kind, host: t.host ?? 'local', unit: t.unit, env_file: targetPath(t), restart: Boolean(t.restart) };
    default:
      return { kind: t.kind, host: t.host ?? 'local', path: t.path };
  }
}

export function checkTargetAllowed(cfg: Config, t: Target, keys: string[]): void {
  const tp = targetPath(t);
  if (tp && (tp.split('/').includes('..') || !(tp.startsWith('/') || tp.startsWith('~/')))) throw new UserError('target path must be absolute and must not contain ".." segments', 'invalid_path');
  const ok = cfg.writeTargets.some((r: WriteTargetRule) => {
    const ruleKind = r.kind;
    if (ruleKind !== t.kind) return false;
    if (t.kind === 'clipboard') return true;
    if (t.kind === 'github') return Boolean(r.repo && globMatch(r.repo, t.repo)) && (!r.keys || keys.every((k) => r.keys!.some((p) => globMatch(p, k))));
    const host = (t as { host?: string }).host;
    if ((r.host ?? undefined) !== (host ?? undefined)) return false;
    if (t.kind === 'systemd' && !(r.unit && globMatch(r.unit, t.unit))) return false;
    const raw = targetPath(t);
    // ~ is expanded for local targets only; remote paths are compared literally
    const p = raw && !host ? path.resolve(expandHome(raw)) : raw;
    const rulePath = r.path && !host ? expandHome(r.path) : r.path;
    if (rulePath && p && !globMatch(rulePath, p)) return false;
    if (!r.path && t.kind !== 'systemd') return false;
    if (r.keys && !keys.every((k) => r.keys!.some((pat) => globMatch(pat, k)))) return false;
    return true;
  });
  if (!ok) throw new UserError(`write target ${JSON.stringify(describeTarget(t))} with keys [${keys.join(', ')}] is not in the writeTargets allowlist`, 'target_not_allowed');
  const host = (t as { host?: string }).host;
  if (host && !cfg.ssh.hosts[host]) throw new UserError(`ssh host "${host}" is not in ssh.hosts`, 'host_not_allowed');
}

export class TargetWriter {
  private readonly local = new LocalFileIO();

  constructor(
    private readonly cfg: Config,
    private readonly ssh: Ssh,
    private readonly runner: Runner,
  ) {}

  private io(host?: string): FileIO {
    return host ? new SshFileIO(this.ssh, host) : this.local;
  }

  /** Computes which keys would be created/updated, without writing. */
  async plan(t: Target, keys: string[]): Promise<Change[]> {
    switch (t.kind) {
      case 'env-file':
      case 'systemd': {
        const cur = (await this.io(t.host).read(targetPath(t)!))?.toString('utf8') ?? '';
        return keys.map((key) => ({ key, action: getEnvKey(cur, key) === undefined ? 'created' : 'updated' }));
      }
      case 'json': {
        const cur = (await this.io(t.host).read(t.path))?.toString('utf8') ?? '';
        return keys.map((key) => {
          let exists = false;
          try {
            exists = cur.trim() !== '' && getJsonPath(cur, key) !== undefined;
          } catch {
            exists = false;
          }
          return { key, action: exists ? 'updated' : 'created' };
        });
      }
      case 'yaml': {
        const cur = (await this.io(t.host).read(t.path))?.toString('utf8') ?? '';
        return keys.map((key) => ({ key, action: setYamlPath(cur, key, '').action }));
      }
      case 'github': {
        const existing = await this.githubList(t);
        return keys.map((key) => ({ key, action: existing.has(key) ? 'updated' : 'created' }));
      }
      case 'clipboard':
        return keys.map((key) => ({ key, action: 'created' }));
    }
  }

  private async githubList(t: Extract<Target, { kind: 'github' }>): Promise<Set<string>> {
    const argv = ['gh', 'secret', 'list', '--repo', t.repo, '--json', 'name', '--jq', '.[].name'];
    if (t.environment) argv.push('--env', t.environment);
    const r = await this.runner(argv, { timeoutMs: 30_000 });
    if (r.code !== 0) throw new UserError('gh secret list failed (is gh authenticated?)', 'gh_failed');
    return new Set(r.stdout.toString('utf8').split('\n').filter(Boolean));
  }

  /** Writes entries (key → value). Values never reach argv, logs or the return value. */
  async write(t: Target, entries: { key: string; value: string }[]): Promise<Change[]> {
    switch (t.kind) {
      case 'env-file':
      case 'systemd': {
        for (const e of entries) if (!ENV_KEY_RE.test(e.key)) throw new UserError(`invalid env key ${e.key}`, 'invalid_key');
        const p = targetPath(t)!;
        const io = this.io(t.host);
        const changes = await mutex.run(`${io.where}:${p}`, async () => {
          let cur = (await io.read(p))?.toString('utf8') ?? '';
          const ch: Change[] = [];
          for (const e of entries) {
            const r = setEnvKey(cur, e.key, e.value);
            cur = r.content;
            ch.push({ key: e.key, action: r.action });
          }
          const opts = t.kind === 'env-file' ? { mode: t.mode ?? '0600', owner: t.owner, group: t.group, backup: t.backup } : { mode: '0600' };
          await io.writeAtomic(p, cur, opts);
          return ch;
        });
        if (t.kind === 'systemd') await this.systemdDropIn(t);
        return changes;
      }
      case 'json':
      case 'yaml': {
        const io = this.io(t.host);
        return mutex.run(`${io.where}:${t.path}`, async () => {
          let cur = (await io.read(t.path))?.toString('utf8') ?? '';
          const ch: Change[] = [];
          for (const e of entries) {
            const r = t.kind === 'json' ? setJsonPath(cur, e.key, e.value) : setYamlPath(cur, e.key, e.value);
            cur = r.content;
            ch.push({ key: e.key, action: r.action });
          }
          await io.writeAtomic(t.path, cur, { mode: t.mode ?? '0600', backup: t.backup });
          return ch;
        });
      }
      case 'github': {
        const existing = await this.githubList(t);
        const ch: Change[] = [];
        for (const e of entries) {
          if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(e.key)) throw new UserError(`invalid GitHub secret name ${e.key}`, 'invalid_key');
          const argv = ['gh', 'secret', 'set', e.key, '--repo', t.repo];
          if (t.environment) argv.push('--env', t.environment);
          // gh reads the value from stdin when --body is not given.
          const r = await this.runner(argv, { stdin: e.value, timeoutMs: 60_000 });
          if (r.code !== 0) throw new UserError(`gh secret set ${e.key} failed`, 'gh_failed');
          ch.push({ key: e.key, action: existing.has(e.key) ? 'updated' : 'created' });
        }
        return ch;
      }
      case 'clipboard':
        throw new UserError('clipboard writes are performed by the approval page', 'internal');
    }
  }

  private async systemdDropIn(t: Extract<Target, { kind: 'systemd' }>): Promise<void> {
    const envFile = targetPath(t)!;
    const dropInDir = `/etc/systemd/system/${t.unit}.d`;
    const content = `# Managed by veilform\n[Service]\nEnvironmentFile=${envFile}\n`;
    const io = this.io(t.host);
    await io.writeAtomic(`${dropInDir}/50-veilform.conf`, content, { mode: '0644' });
    const cmds = ['systemctl daemon-reload', ...(t.restart ? [`systemctl restart ${shQuote(t.unit)}`] : [])].join(' && ');
    if (t.host) {
      const r = await this.ssh.script(t.host, cmds);
      if (r.code !== 0) throw new UserError('systemctl failed on remote host', 'systemd_failed');
    } else {
      const r1 = await this.runner(['systemctl', 'daemon-reload'], { timeoutMs: 60_000 });
      if (r1.code !== 0) throw new UserError('systemctl daemon-reload failed', 'systemd_failed');
      if (t.restart) {
        const r2 = await this.runner(['systemctl', 'restart', t.unit], { timeoutMs: 120_000 });
        if (r2.code !== 0) throw new UserError('systemctl restart failed', 'systemd_failed');
      }
    }
  }
}
