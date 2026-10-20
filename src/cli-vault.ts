/**
 * CLI for encrypted sync, shares and encrypted .env files. Run by the PERSON (or by a service
 * manager). Rules: no passphrase/token/value in argv by design (tokens may be given as a file
 * or pasted on the local page; `--token` exists for scripts and warns), plaintext only to a
 * TTY or to an explicit --out file.
 */
import { execFileSync, spawn } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { App } from './app.js';
import { agentRequest, agentSocketPath, createKeyFile, SessionAgent } from './crypto/keysource.js';
import { b64 } from './crypto/primitives.js';
import { contextOf, plaintextEnvFiles } from './envenc/service.js';
import { normalizeSchema, validateValues, type FieldDef } from './schema.js';
import { parseDuration } from './share/share.js';
import type { Strategy } from './sync/service.js';
import { registerRevealPage } from './vaulttools.js';
import { UserError } from './util.js';

interface Args {
  pos: string[];
  flags: Map<string, string[]>;
  rest: string[];
}

export function parseArgs(argv: string[]): Args {
  const pos: string[] = [];
  const flags = new Map<string, string[]>();
  let rest: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === '--') {
      rest = argv.slice(i + 1);
      break;
    }
    if (a.startsWith('--')) {
      const [k, v] = a.slice(2).split('=', 2) as [string, string | undefined];
      const takesValue = VALUE_FLAGS.has(k);
      const val = v ?? (takesValue ? argv[++i] : 'true');
      if (takesValue && val === undefined) throw new UserError(`--${k} needs a value`, 'invalid_args');
      flags.set(k, [...(flags.get(k) ?? []), val!]);
    } else pos.push(a);
  }
  return { pos, flags, rest };
}

const VALUE_FLAGS = new Set(['out', 'file', 'target', 'strategy', 'destination', 'key-file', 'new-key-file', 'token', 'token-file', 'minutes', 'expires', 'max-views', 'note', 'against', 'only', 'env', 'remove', 'repo', 'add-key-file', 'context', 'hide-after']);

const flag = (a: Args, k: string) => a.flags.get(k)?.at(-1);
const flags = (a: Args, k: string) => a.flags.get(k) ?? [];
const has = (a: Args, k: string) => a.flags.has(k);

const out = (o: unknown) => process.stdout.write((typeof o === 'string' ? o : JSON.stringify(o, null, 2)) + '\n');
const err = (s: string) => process.stderr.write(`[veilform] ${s}\n`);

/** Reads a line from the controlling TTY without echo. */
async function askTty(prompt: string): Promise<string | undefined> {
  if (!process.stdin.isTTY) return undefined;
  process.stderr.write(prompt);
  const stdin = process.stdin;
  stdin.setRawMode(true);
  stdin.resume();
  stdin.setEncoding('utf8');
  return new Promise((resolve) => {
    let buf = '';
    const onData = (d: string) => {
      for (const ch of d) {
        if (ch === '\r' || ch === '\n') {
          stdin.off('data', onData);
          stdin.setRawMode(false);
          stdin.pause();
          process.stderr.write('\n');
          return resolve(buf);
        }
        if (ch === '\u0003') {
          stdin.setRawMode(false);
          process.stderr.write('\n');
          process.exit(130);
        }
        if (ch === '\u007f' || ch === '\b') buf = buf.slice(0, -1);
        else buf += ch;
      }
    };
    stdin.on('data', onData);
  });
}

/** Asks on the local page (127.0.0.1) and waits; used with --ui or when there is no TTY. */
async function askPage(app: App, title: string, fields: FieldDef[], lines: { label: string; value: string }[] = []): Promise<Record<string, string> | undefined> {
  const schema = normalizeSchema({ fields });
  let done!: (v: Record<string, string> | undefined) => void;
  const p = new Promise<Record<string, string> | undefined>((r) => (done = r));
  const op = app.ops.create('cli', 'cli');
  const { url } = await app.ui.register({
    kind: 'form',
    opId: op.id,
    title,
    schema,
    destination: lines.length ? { lines, needsConfirm: false, rememberable: false } : undefined,
    ttlMs: app.cfg.ui.ttlSeconds * 1000,
    onExpire: () => done(undefined),
    handle: async (sp) => {
      if (sp.action === 'cancel') {
        done(undefined);
        return { ok: false, message: 'cancelled' };
      }
      const { values, errors } = validateValues(schema, sp.values ?? {});
      if (errors.length) return { ok: false, errors };
      done(values as Record<string, string>);
      return { ok: true, message: 'OK. You can close this tab.' };
    },
  });
  err(`open ${url} in your browser on this computer`);
  if (app.cfg.ui.openBrowser) spawn(process.platform === 'darwin' ? 'open' : 'xdg-open', [url], { stdio: 'ignore', detached: true }).on('error', () => undefined).unref();
  return p;
}

function passAsker(app: App, a: Args) {
  return async (purpose: string, o: { confirm?: boolean } = {}): Promise<string | undefined> => {
    if (!has(a, 'ui') && process.stdin.isTTY) {
      const p1 = await askTty(`${purpose}: `);
      if (o.confirm && p1 !== undefined && (await askTty('Repeat: ')) !== p1) throw new UserError('passphrases do not match', 'mismatch');
      return p1;
    }
    const f: FieldDef[] = [{ name: 'passphrase', label: purpose, kind: 'secret', required: true }];
    if (o.confirm) f.push({ name: 'passphrase2', label: 'Repeat', kind: 'secret', required: true });
    const v = await askPage(app, purpose, f);
    if (v && o.confirm && v.passphrase !== v.passphrase2) throw new UserError('passphrases do not match', 'mismatch');
    return v?.passphrase;
  };
}

function readToken(a: Args): string | undefined {
  const tf = flag(a, 'token-file');
  if (tf) return readFileSync(tf, 'utf8').trim();
  const t = flag(a, 'token');
  if (t) err('warning: a token in argv is visible to other local processes (ps) and in your shell history; prefer --token-file or the local page');
  return t;
}

async function envOpenOpts(app: App, a: Args, file: string) {
  const token = readToken(a);
  let dek: Buffer | undefined;
  if (token) {
    const r = await app.shares.open(token, { targetOverride: flag(a, 'target') });
    const doc = await app.envFiles.read(file);
    const it = r.items.find((x) => x.kind === 'env-dek' && x.name === `env:${doc.context}`);
    if (!it) throw new UserError('this token does not unlock this file', 'wrong_key');
    dek = Buffer.from(it.value, 'base64url');
    app.audit.write('share_read', { share: r.shareId, names: [it.name], via: 'cli', views_left: r.viewsLeft });
  }
  return { keyFiles: flags(a, 'key-file'), dek, passphrase: () => passAsker(app, a)(`Passphrase for ${path.basename(file)}`) };
}

function hookScript(): string {
  const cli = fileURLToPath(new URL('./cli.js', import.meta.url));
  return `#!/bin/sh\n# veilform: refuse to commit plaintext .env files\nexec "${process.execPath}" "${cli}" env check-staged\n`;
}

export const VAULT_HELP = `veilform — encrypted sync, shares and encrypted .env files

  export --out FILE.vfb                       encrypted backup of the vault
  import (--file F | --target T) [--strategy report|keep-local|take-remote|keep-both] [--destination D] [--allow-rollback]
  sync --target T [--strategy S]              pull if needed, then push the encrypted bundle
  rekey (--file F | --target T)               new backup passphrase / KEK (re-wraps data keys)
  share open [--token-file F] [--target T]    local reveal page (paste the token or it comes in the URL fragment)
  share list | share revoke ID
  env encrypt FILE [--out F] [--key-file K]... [--new-key-file K] [--keychain] [--no-passphrase] [--shred]
  env decrypt FILE (--out F | to a TTY)        plaintext only to a terminal or an explicit file
  env edit FILE                                local page: change values without showing them to anyone else
  env run FILE [--only K1,K2] [--raw] -- CMD   also: veilform run --env FILE -- CMD
  env diff FILE [--against F|git:REV]          names of added/removed/changed keys
  env rotate FILE                              new data key, everything re-encrypted
  env recipients FILE [--add-key-file K]... [--passphrase] [--remove ID]   (unlock with --key-file / passphrase)
  env unlock FILE [--token-file F] [--minutes N] | env unlock FILE --status
  env share FILE [--target T] [--expires 1h] [--max-views 1] [--passphrase]
  env keygen PATH                              new 0600 key file (keep it OUT of the repo)
  env hook install [--repo DIR] | env check-staged
  agent                                        session agent (in-memory key cache, 0600 socket)
  lock                                         forget every cached key (agent + this process)

Unlock methods for env files: --key-file / VEILFORM_KEY_FILE, OS keychain (config env.keychain),
systemd LoadCredential=veilform-key, session agent, passphrase (TTY or --ui local page), --token-file.`;

/** Returns an exit code, or undefined when argv is not a vault command. */
export async function runVaultCli(argv: string[], makeApp: () => App): Promise<number | undefined> {
  const [cmd, sub] = argv;
  const known = ['export', 'import', 'sync', 'rekey', 'share', 'env', 'run', 'agent', 'lock', 'help'];
  if (!cmd || !known.includes(cmd)) return undefined;
  if (cmd === 'help') {
    out(VAULT_HELP);
    return 0;
  }
  if (cmd === 'agent') {
    const { resolvePaths } = await import('./config.js');
    const sock = agentSocketPath(resolvePaths().home);
    const ag = new SessionAgent(sock);
    await ag.start();
    err(`session agent listening on ${sock} (Ctrl-C or "veilform lock" + kill to stop)`);
    await new Promise<void>((r) => {
      process.on('SIGINT', r);
      process.on('SIGTERM', r);
    });
    await ag.stop();
    return 0;
  }
  const app = makeApp();
  try {
    const a = parseArgs(argv.slice(cmd === 'share' || cmd === 'env' ? 2 : 1));
    switch (cmd) {
      case 'lock': {
        app.envFiles.lock();
        app.sync.lock();
        try {
          await agentRequest(agentSocketPath(app.paths.home), { op: 'lock' });
          out('locked (agent keys forgotten)');
        } catch {
          out('no session agent running; nothing cached');
        }
        return 0;
      }
      case 'export': {
        const file = flag(a, 'out') ?? a.pos[0];
        if (!file) throw new UserError('--out FILE.vfb is required', 'invalid_args');
        out(await app.sync.exportToFile(file, passAsker(app, a)));
        return 0;
      }
      case 'import': {
        const opts = { strategy: flag(a, 'strategy') as Strategy | undefined, destination: flag(a, 'destination'), allowRollback: has(a, 'allow-rollback') };
        const t = flag(a, 'target');
        out(t ? await app.sync.pull(t, passAsker(app, a), opts) : await app.sync.importFile(flag(a, 'file') ?? a.pos[0]!, passAsker(app, a), opts));
        return 0;
      }
      case 'sync':
        out(await app.sync.sync(flag(a, 'target') ?? a.pos[0]!, passAsker(app, a), (flag(a, 'strategy') ?? 'report') as Strategy));
        return 0;
      case 'rekey': {
        const ask = passAsker(app, a);
        out(await app.sync.rekey({ target: flag(a, 'target'), file: flag(a, 'file') }, (p) => ask(p), (p) => ask(p, { confirm: true })));
        return 0;
      }
      case 'share':
        return await shareCmd(app, sub, a);
      case 'env':
        return await envCmd(app, sub, a);
      case 'run': {
        const ra = parseArgs(argv.slice(1));
        const file = flag(ra, 'env');
        if (!file) throw new UserError('veilform run --env FILE -- CMD', 'invalid_args');
        return await app.envFiles.run(file, ra.rest, { ...(await envOpenOpts(app, ra, file)), raw: has(ra, 'raw'), only: flag(ra, 'only')?.split(',') });
      }
    }
    return undefined;
  } catch (e) {
    err(e instanceof UserError ? `${e.code}: ${e.message}` : 'failed (details withheld to protect values)');
    return 1;
  } finally {
    if (cmd !== 'run') await app.shutdown();
  }
}

async function shareCmd(app: App, sub: string | undefined, a: Args): Promise<number> {
  if (sub === 'list') {
    out(app.shares.records());
    return 0;
  }
  if (sub === 'revoke') {
    const r = await app.shares.revoke(a.pos[0]!);
    app.audit.write('share_revoked', { share: a.pos[0], names: r.names, was_read: r.was_read, via: 'cli' });
    out(r);
    if (r.was_read !== false) err('it may have been read: revoking does not make anyone forget. Rotate: ' + r.names.join(', '));
    return 0;
  }
  if (sub === 'open') {
    const { url, done } = await registerRevealPage(app, { targetOverride: flag(a, 'target'), hideAfter: Number(flag(a, 'hide-after') ?? 60) });
    const token = readToken(a);
    const full = token ? `${url}#${token}` : url;
    err(token ? 'opening the local reveal page (the token travels in the URL fragment, never to a server)' : `open ${url} and paste the token there`);
    if (app.cfg.ui.openBrowser) spawn(process.platform === 'darwin' ? 'open' : 'xdg-open', [full], { stdio: 'ignore', detached: true }).on('error', () => undefined).unref();
    else if (token) err('ui.openBrowser is false: open the page and paste the token in the field');
    const r = await done;
    // keep the page alive a little so the person can copy before the server exits
    if (r.status === 'completed') await new Promise((res) => setTimeout(res, Number(flag(a, 'hide-after') ?? 60) * 1000));
    out({ status: r.status, names: r.names });
    return r.status === 'completed' ? 0 : 1;
  }
  throw new UserError('share open | list | revoke ID', 'invalid_args');
}

async function envCmd(app: App, sub: string | undefined, a: Args): Promise<number> {
  const file = a.pos[0];
  const E = app.envFiles;
  if (sub === 'keygen') {
    if (!file) throw new UserError('env keygen PATH', 'invalid_args');
    const k = createKeyFile(file);
    out({ key_file: k.where, key_id: k.id, note: 'keep it out of the repository; copy it to the server out of band (e.g. LoadCredential=veilform-key:/etc/veilform/app.key)' });
    return 0;
  }
  if (sub === 'check-staged') {
    const names = execFileSync('git', ['diff', '--cached', '--name-only', '-z', '--diff-filter=ACM']).toString().split('\0').filter(Boolean);
    const files = names.filter((n) => /(^|\/)\.env(\.[A-Za-z0-9_.-]+)?$/.test(n)).map((n) => ({ path: n, content: execFileSync('git', ['show', `:${n}`]).toString('utf8') }));
    const bad = plaintextEnvFiles(files);
    if (bad.length) {
      err(`refusing to commit plaintext env files: ${bad.join(', ')} — encrypt them (veilform env encrypt) or add them to .gitignore`);
      return 1;
    }
    return 0;
  }
  if (sub === 'hook') {
    const repo = flag(a, 'repo') ?? '.';
    const gitDir = execFileSync('git', ['-C', repo, 'rev-parse', '--git-path', 'hooks']).toString().trim();
    const hooks = path.isAbsolute(gitDir) ? gitDir : path.join(repo, gitDir);
    mkdirSync(hooks, { recursive: true });
    const f = path.join(hooks, 'pre-commit');
    if (existsSync(f) && !readFileSync(f, 'utf8').includes('veilform')) throw new UserError(`${f} exists; add "veilform env check-staged" to it yourself`, 'exists');
    writeFileSync(f, hookScript());
    chmodSync(f, 0o755);
    out({ installed: f });
    return 0;
  }
  if (!file) throw new UserError(`env ${sub ?? ''} FILE`, 'invalid_args');
  switch (sub) {
    case 'encrypt': {
      const usePass = !has(a, 'no-passphrase');
      const keyFiles = [...flags(a, 'key-file')];
      if (flag(a, 'new-key-file')) keyFiles.push(createKeyFile(flag(a, 'new-key-file')!).where);
      const passphrase = usePass ? await passAsker(app, a)(`New passphrase for ${contextOf(flag(a, 'out') ?? file)}`, { confirm: true }) : undefined;
      if (usePass && passphrase === undefined) throw new UserError('no passphrase (no TTY: use --ui or --no-passphrase with --key-file)', 'passphrase_required');
      const r = await E.encrypt(file, { passphrase, keyFiles, keychain: has(a, 'keychain') }, { out: flag(a, 'out'), shred: has(a, 'shred'), context: flag(a, 'context') });
      app.audit.write('env_encrypted', { file: r.file, keys: r.keys, recipients: r.recipients, via: 'cli' });
      out(r);
      if (r.gitignore_warning) err(r.gitignore_warning);
      return 0;
    }
    case 'decrypt': {
      const o = flag(a, 'out');
      if (!o && !process.stdout.isTTY) throw new UserError('refusing to print plaintext to a pipe/file descriptor (an agent could capture it); use --out FILE', 'not_a_tty');
      const { text } = await E.decrypt(file, await envOpenOpts(app, a, file));
      if (o) writeFileSync(o, text, { mode: 0o600 });
      else process.stdout.write(text);
      return 0;
    }
    case 'edit': {
      const r = (await app.tools.envEdit({ file })) as { url?: string; request_id?: string };
      if (r.url) err(`edit on the local page: ${r.url}`);
      const w = await app.secretWait({ id: r.request_id, timeout_seconds: app.cfg.ui.ttlSeconds });
      out(w);
      return 0;
    }
    case 'run':
      return await E.run(file, a.rest, { ...(await envOpenOpts(app, a, file)), raw: has(a, 'raw'), only: flag(a, 'only')?.split(',') });
    case 'diff': {
      const r = await app.tools.envDiff({ file, against: flag(a, 'against') }).catch(async (e) => {
        if (e instanceof UserError && e.code === 'file_not_allowed') return E.diff({ file: flag(a, 'against') }, { file }, await envOpenOpts(app, a, file));
        throw e;
      });
      out(r);
      return 0;
    }
    case 'rotate': {
      const o = await envOpenOpts(app, a, file);
      const ask = passAsker(app, a);
      out(await E.rotate(file, o, undefined, () => ask('New passphrase', { confirm: true })));
      return 0;
    }
    case 'recipients': {
      const passphrase = has(a, 'passphrase') ? await passAsker(app, a)('Passphrase to add', { confirm: true }) : undefined;
      out(await E.addRecipients(file, await envOpenOpts(app, a, file), { passphrase, keyFiles: flags(a, 'add-key-file') }, flags(a, 'remove')));
      return 0;
    }
    case 'unlock': {
      if (has(a, 'status')) {
        out(await E.status(file, { keyFiles: flags(a, 'key-file') }));
        return 0;
      }
      const doc = await E.read(file);
      const { dek, via } = await E.open(doc, await envOpenOpts(app, a, file));
      const minutes = Number(flag(a, 'minutes') ?? 15);
      const agent = await E.remember(doc, dek, minutes);
      app.audit.write('env_unlocked', { file, context: doc.context, via: via.startsWith('key:') ? 'key' : via, minutes, agent });
      out({ file, unlocked: agent, minutes, via: via.startsWith('key:') ? 'key' : via, note: agent ? 'cached in the session agent' : 'no session agent running (start one with "veilform agent"); nothing cached' });
      return agent ? 0 : 1;
    }
    case 'share': {
      const doc = await E.read(file);
      const { dek } = await E.open(doc, await envOpenOpts(app, a, file));
      const target = flag(a, 'target') ?? app.cfg.sync.shareTarget ?? Object.keys(app.cfg.sync.targets)[0];
      if (!target) throw new UserError('no sync target for shares (config sync.targets)', 'invalid_config');
      const passphrase = has(a, 'passphrase') ? await passAsker(app, a)('Share passphrase (send it by another channel)', { confirm: true }) : undefined;
      const { record, token } = await app.shares.create({ targetId: target, items: [{ name: `env:${doc.context}`, kind: 'env-dek', value: b64(dek) }], expiresInSeconds: parseDuration(flag(a, 'expires') ?? '1h'), maxViews: Number(flag(a, 'max-views') ?? 1), passphrase, note: flag(a, 'note') });
      app.audit.write('share_created', { share: record.share_id, names: record.names, target, via: 'cli' });
      if (has(a, 'print') && process.stdout.isTTY) out(token);
      else {
        let shown!: () => void;
        const seen = new Promise<void>((r) => (shown = r));
        const op = app.ops.create('cli', 'cli');
        const { url } = await app.ui.register({
          kind: 'form',
          opId: op.id,
          title: `Token for ${doc.context}`,
          schema: normalizeSchema({ fields: [{ name: 'show', label: 'Show the token on this page now', kind: 'boolean', required: true }] }),
          ttlMs: app.cfg.ui.ttlSeconds * 1000,
          onExpire: () => shown(),
          handle: async () => {
            shown();
            return { ok: true, reveal: { items: [{ label: 'Token', value: token }], hideAfter: 120, note: `Unlocks ONLY ${doc.context}, until ${record.expires_at}, ${record.max_views} use(s).` } };
          },
        });
        err(`the token is shown on the local page only: ${url}`);
        await seen;
        await new Promise((r) => setTimeout(r, 2000));
      }
      out({ share_id: record.share_id, expires_at: record.expires_at, max_views: record.max_views });
      return 0;
    }
    default:
      throw new UserError(`unknown env command ${sub}`, 'invalid_args');
  }
}
