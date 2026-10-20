/**
 * Where key material comes from, OUTSIDE the encrypted artefacts:
 *  - key files (0600, outside the repo): `--key-file`, VEILFORM_KEY_FILE
 *  - the OS keychain (via the existing KeychainBackend)
 *  - systemd credentials ($CREDENTIALS_DIRECTORY/<name>, LoadCredential=)
 *  - the optional session agent (KEK/DEK cache in memory behind a 0600 unix socket)
 * Passphrases are never read from argv; they are typed on the local page or on the TTY.
 */
import { chmodSync, closeSync, existsSync, mkdirSync, openSync, readFileSync, statSync, unlinkSync, writeSync } from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import type { KeychainBackend } from '../stores/keychain.js';
import { expandHome, UserError } from '../util.js';
import { b64, KEY_LEN, keyId, randomKey, unb64 } from './primitives.js';

export interface NamedKey {
  kind: 'key-file' | 'keychain' | 'systemd-credential' | 'raw';
  /** where it came from (path / service:account / credential name) — never the key */
  where: string;
  id: string;
  key: Buffer;
}

function parseKeyText(raw: Buffer, where: string): Buffer {
  const s = raw.toString('utf8').trim();
  if (/^[0-9a-fA-F]{64}$/.test(s)) return Buffer.from(s, 'hex');
  if (/^vfk1:[A-Za-z0-9_-]{43}$/.test(s)) return unb64(s.slice(5), 'key');
  if (raw.length === KEY_LEN) return Buffer.from(raw);
  throw new UserError(`${where} is not a veilform key (expected 64 hex chars or vfk1:<base64url>)`, 'bad_key_file');
}

/** Reads a key file; refuses files readable by group/others (like ssh does for private keys). */
export function readKeyFile(p: string, opts: { allowLoosePerms?: boolean } = {}): NamedKey {
  const file = expandHome(p);
  if (!existsSync(file)) throw new UserError(`key file ${file} not found`, 'missing_key');
  const st = statSync(file);
  if (process.platform !== 'win32' && !opts.allowLoosePerms && (st.mode & 0o077) !== 0) throw new UserError(`key file ${file} is accessible by group/others; chmod 600 it`, 'key_file_permissions');
  const key = parseKeyText(readFileSync(file), file);
  return { kind: 'key-file', where: file, id: keyId(key), key };
}

/** Creates a new random key file (0600, refuses to overwrite). Returns its public id. */
export function createKeyFile(p: string): NamedKey {
  const file = expandHome(p);
  mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const key = randomKey();
  const fd = openSync(file, 'wx', 0o600);
  try {
    writeSync(fd, `vfk1:${b64(key)}\n`);
  } finally {
    closeSync(fd);
  }
  chmodSync(file, 0o600);
  return { kind: 'key-file', where: file, id: keyId(key), key };
}

export function formatKey(key: Buffer): string {
  return `vfk1:${b64(key)}`;
}

/** Keychain-held key (created on first use when `create`). */
export async function keychainKey(kc: KeychainBackend, service: string, account: string, create = false): Promise<NamedKey | undefined> {
  let s = await kc.get(service, account);
  if (!s && create) {
    s = formatKey(randomKey());
    await kc.set(service, account, s);
  }
  if (!s) return undefined;
  const key = parseKeyText(Buffer.from(s), `keychain ${service}/${account}`);
  return { kind: 'keychain', where: `${service}/${account}`, id: keyId(key), key };
}

/** systemd `LoadCredential=<name>:<path>` → $CREDENTIALS_DIRECTORY/<name>. */
export function systemdCredential(name = 'veilform-key', env: NodeJS.ProcessEnv = process.env): NamedKey | undefined {
  const dir = env.CREDENTIALS_DIRECTORY;
  if (!dir) return undefined;
  const file = path.join(dir, name);
  if (!existsSync(file)) return undefined;
  // systemd already restricts the credentials directory to the service; it is 0400/0440 by design.
  const key = parseKeyText(readFileSync(file), `credential ${name}`);
  return { kind: 'systemd-credential', where: name, id: keyId(key), key };
}

/** All non-interactive keys available to this process (key files, env, systemd). */
export function ambientKeys(opts: { keyFiles?: string[]; env?: NodeJS.ProcessEnv } = {}): NamedKey[] {
  const env = opts.env ?? process.env;
  const out: NamedKey[] = [];
  const files = [...(opts.keyFiles ?? [])];
  if (env.VEILFORM_KEY_FILE) files.push(...env.VEILFORM_KEY_FILE.split(path.delimiter).filter(Boolean));
  for (const f of files) out.push(readKeyFile(f));
  const cred = systemdCredential(env.VEILFORM_CREDENTIAL ?? 'veilform-key', env);
  if (cred) out.push(cred);
  return out;
}

// ------------------------------------------------------------------ session agent

/** Default socket path: $XDG_RUNTIME_DIR/veilform/agent.sock (fallback: <home>/run/agent.sock). */
export function agentSocketPath(home: string, env: NodeJS.ProcessEnv = process.env): string {
  if (env.VEILFORM_AGENT_SOCK) return env.VEILFORM_AGENT_SOCK;
  return env.XDG_RUNTIME_DIR ? path.join(env.XDG_RUNTIME_DIR, 'veilform', 'agent.sock') : path.join(home, 'run', 'agent.sock');
}

/**
 * Tiny in-memory key cache behind a 0600 unix socket in a 0700 directory, for
 * "unlock once for N minutes". Holds DEKs/KEKs (never values). Same-user processes can
 * talk to it — exactly the same trust boundary as the keychain (see THREAT-MODEL.md).
 */
export class SessionAgent {
  private keys = new Map<string, { key: Buffer; expires: number }>();
  private server?: net.Server;

  constructor(
    readonly socket: string,
    private readonly maxTtlSeconds = 8 * 3600,
    private readonly now: () => number = Date.now,
  ) {}

  async start(): Promise<void> {
    mkdirSync(path.dirname(this.socket), { recursive: true, mode: 0o700 });
    chmodSync(path.dirname(this.socket), 0o700);
    if (existsSync(this.socket)) {
      if (await agentRequest(this.socket, { op: 'ping' }).catch(() => undefined)) throw new UserError('a veilform agent is already running', 'agent_running');
      unlinkSync(this.socket);
    }
    this.server = net.createServer((c) => {
      let buf = '';
      c.setEncoding('utf8');
      c.on('data', (d: string) => {
        buf += d;
        if (buf.length > 64 * 1024) return c.destroy();
        const nl = buf.indexOf('\n');
        if (nl < 0) return;
        let req: { op?: string; id?: string; key?: string; ttl?: number };
        try {
          req = JSON.parse(buf.slice(0, nl));
        } catch {
          return c.end('{"ok":false}\n');
        }
        c.end(JSON.stringify(this.handle(req)) + '\n');
      });
      c.on('error', () => undefined);
    });
    const old = process.umask(0o177);
    try {
      await new Promise<void>((res, rej) => {
        this.server!.once('error', rej);
        this.server!.listen(this.socket, () => res());
      });
    } finally {
      process.umask(old);
    }
    chmodSync(this.socket, 0o600);
  }

  private handle(req: { op?: string; id?: string; key?: string; ttl?: number }): Record<string, unknown> {
    const now = this.now();
    for (const [k, v] of this.keys) if (v.expires <= now) this.drop(k);
    switch (req.op) {
      case 'ping':
        return { ok: true };
      case 'put': {
        if (!req.id || !req.key) return { ok: false };
        const ttl = Math.min(Math.max(1, req.ttl ?? 900), this.maxTtlSeconds);
        this.keys.set(req.id, { key: unb64(req.key), expires: now + ttl * 1000 });
        return { ok: true, expires_in: ttl };
      }
      case 'get': {
        const e = req.id ? this.keys.get(req.id) : undefined;
        return e ? { ok: true, key: b64(e.key) } : { ok: false };
      }
      case 'status':
        return { ok: true, ids: [...this.keys.keys()], count: this.keys.size };
      case 'lock':
        for (const k of [...this.keys.keys()]) this.drop(k);
        return { ok: true };
      default:
        return { ok: false };
    }
  }

  private drop(id: string): void {
    this.keys.get(id)?.key.fill(0);
    this.keys.delete(id);
  }

  async stop(): Promise<void> {
    for (const k of [...this.keys.keys()]) this.drop(k);
    await new Promise<void>((r) => (this.server ? this.server.close(() => r()) : r()));
    try {
      unlinkSync(this.socket);
    } catch {
      /* gone */
    }
  }
}

export function agentRequest(socket: string, req: Record<string, unknown>, timeoutMs = 2000): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    if (!existsSync(socket)) return reject(new UserError('no veilform agent running', 'no_agent'));
    const c = net.createConnection(socket);
    let buf = '';
    const t = setTimeout(() => {
      c.destroy();
      reject(new UserError('agent timeout', 'no_agent'));
    }, timeoutMs);
    c.setEncoding('utf8');
    c.on('connect', () => c.write(JSON.stringify(req) + '\n'));
    c.on('data', (d: string) => (buf += d));
    c.on('end', () => {
      clearTimeout(t);
      try {
        resolve(JSON.parse(buf));
      } catch {
        reject(new UserError('bad agent reply', 'no_agent'));
      }
    });
    c.on('error', () => {
      clearTimeout(t);
      reject(new UserError('no veilform agent running', 'no_agent'));
    });
  });
}

export async function agentGet(socket: string, id: string): Promise<Buffer | undefined> {
  try {
    const r = await agentRequest(socket, { op: 'get', id });
    return r.ok && typeof r.key === 'string' ? unb64(r.key) : undefined;
  } catch {
    return undefined;
  }
}

export async function agentPut(socket: string, id: string, key: Buffer, ttlSeconds: number): Promise<boolean> {
  try {
    return Boolean((await agentRequest(socket, { op: 'put', id, key: b64(key), ttl: ttlSeconds })).ok);
  } catch {
    return false;
  }
}
