import { chmodSync, chownSync, closeSync, copyFileSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, unlinkSync, writeSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import type { Ssh } from './ssh.js';
import { expandHome, UserError } from './util.js';

export interface WriteOpts {
  mode?: string; // octal string, default 0600
  owner?: string;
  group?: string;
  backup?: boolean;
}

/** Read/atomic-write abstraction over local disk and SSH. Never logs content. */
export interface FileIO {
  readonly where: string;
  read(p: string): Promise<Buffer | null>;
  writeAtomic(p: string, data: string | Buffer, opts?: WriteOpts): Promise<void>;
  remove(p: string): Promise<boolean>;
}

function parseMode(mode: string | undefined): number {
  const m = mode ?? '0600';
  if (!/^0?[0-7]{3}$/.test(m)) throw new UserError(`invalid file mode ${m}`, 'invalid_mode');
  return parseInt(m, 8);
}

function lookupId(kind: 'u' | 'g', name: string): number {
  if (/^\d+$/.test(name)) return Number(name);
  try {
    return Number(execFileSync('id', [kind === 'u' ? '-u' : '-g', name], { encoding: 'utf8' }).trim());
  } catch {
    if (kind === 'g') {
      const line = readFileSync('/etc/group', 'utf8').split('\n').find((l) => l.startsWith(name + ':'));
      if (line) return Number(line.split(':')[2]);
    }
    throw new UserError(`unknown ${kind === 'u' ? 'user' : 'group'} ${name}`, 'invalid_owner');
  }
}

export class LocalFileIO implements FileIO {
  readonly where = 'local';

  async read(p: string): Promise<Buffer | null> {
    const file = expandHome(p);
    return existsSync(file) ? readFileSync(file) : null;
  }

  async writeAtomic(p: string, data: string | Buffer, opts: WriteOpts = {}): Promise<void> {
    const file = expandHome(p);
    const dir = path.dirname(file);
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    const mode = parseMode(opts.mode);
    const tmp = path.join(dir, `.${path.basename(file)}.si-${randomBytes(6).toString('hex')}`);
    const fd = openSync(tmp, 'wx', 0o600);
    try {
      writeSync(fd, typeof data === 'string' ? Buffer.from(data) : data);
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    try {
      chmodSync(tmp, mode);
      if (opts.owner || opts.group) {
        const uid = opts.owner ? lookupId('u', opts.owner) : -1;
        const gid = opts.group ? lookupId('g', opts.group) : -1;
        chownSync(tmp, uid, gid);
      }
      if (opts.backup && existsSync(file)) copyFileSync(file, `${file}.bak.${new Date().toISOString().replace(/[:.]/g, '')}`);
      renameSync(tmp, file);
    } catch (e) {
      try {
        unlinkSync(tmp);
      } catch {
        /* ignore */
      }
      throw e;
    }
  }

  async remove(p: string): Promise<boolean> {
    const file = expandHome(p);
    if (!existsSync(file)) return false;
    unlinkSync(file);
    return true;
  }
}

const REMOTE_READ = 'if [ -f "$1" ]; then printf 1; cat -- "$1"; else printf 0; fi';

const REMOTE_WRITE = [
  'set -eu',
  'f="$1"; mode="$2"; owner="$3"; group="$4"; backup="$5"',
  'd=$(dirname -- "$f")',
  'umask 077',
  'mkdir -p -- "$d"',
  't=$(mktemp "$d/.si-tmp.XXXXXX")',
  'trap \'rm -f -- "$t"\' EXIT',
  'cat > "$t"',
  'chmod "$mode" "$t"',
  'if [ -n "$owner" ]; then chown -- "$owner${group:+:$group}" "$t"; elif [ -n "$group" ]; then chgrp -- "$group" "$t"; fi',
  'if [ "$backup" = 1 ] && [ -f "$f" ]; then cp -p -- "$f" "$f.bak.$(date +%Y%m%dT%H%M%S)"; fi',
  'mv -f -- "$t" "$f"',
  'trap - EXIT',
].join('\n');

/** Remote files over SSH. Content travels on stdin; only the path is in the remote argv. */
export class SshFileIO implements FileIO {
  constructor(
    private readonly ssh: Ssh,
    private readonly hostKey: string,
  ) {}

  get where(): string {
    return `ssh:${this.hostKey}`;
  }

  async read(p: string): Promise<Buffer | null> {
    const r = await this.ssh.script(this.hostKey, REMOTE_READ, [p]);
    if (r.code !== 0) throw new UserError(`remote read failed on ${this.hostKey} (exit ${r.code})`, 'ssh_failed');
    if (r.stdout[0] === 0x30) return null; // '0'
    return r.stdout.subarray(1);
  }

  async writeAtomic(p: string, data: string | Buffer, opts: WriteOpts = {}): Promise<void> {
    const mode = (opts.mode ?? '0600').replace(/^0?/, '0');
    parseMode(mode);
    for (const v of [opts.owner, opts.group]) if (v && !/^[A-Za-z0-9_.-]+$/.test(v)) throw new UserError('invalid owner/group', 'invalid_owner');
    const r = await this.ssh.script(this.hostKey, REMOTE_WRITE, [p, mode, opts.owner ?? '', opts.group ?? '', opts.backup ? '1' : '0'], { stdin: data });
    if (r.code !== 0) throw new UserError(`remote write failed on ${this.hostKey} (exit ${r.code})`, 'ssh_failed');
  }

  async remove(p: string): Promise<boolean> {
    const r = await this.ssh.script(this.hostKey, 'if [ -f "$1" ]; then rm -f -- "$1"; printf 1; else printf 0; fi', [p]);
    if (r.code !== 0) throw new UserError(`remote delete failed on ${this.hostKey} (exit ${r.code})`, 'ssh_failed');
    return r.stdout.toString() === '1';
  }
}
