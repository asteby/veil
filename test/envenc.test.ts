import { createHash, randomBytes } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { Writable } from 'node:stream';
import { afterAll, describe, expect, it } from 'vitest';
import { agentGet, createKeyFile, SessionAgent } from '../src/crypto/keysource.js';
import { decryptDoc, encryptDoc, parseDoc, serialize, unlock } from '../src/envenc/format.js';
import { EnvFiles, plaintextEnvFiles } from '../src/envenc/service.js';
import { tmpDir } from './helpers.js';

const SAMPLE = [
  '# app config',
  'export DB_URL="postgres://u:p@h:5432/db?sslmode=require"',
  '',
  "SINGLE='it''s literal $HOME'",
  'MULTI="line1',
  'line2 with # hash',
  'line3"',
  'EQ=a=b=c # trailing comment',
  'HASH=abc#notacomment',
  'EMPTY=',
  '  INDENTED = spaced value  # c',
  'ESC="tab\\tnew\\nq\\"x"',
  'not a kv line',
  '',
].join('\n');

const dir = tmpDir('vf-env-');
afterAll(() => undefined);

function env(extra: Partial<ConstructorParameters<typeof EnvFiles>[0]> = {}) {
  return new EnvFiles({ home: dir, testKdf: true, env: {}, ...extra });
}

const pass = (p: string) => async () => p;

describe('encrypted .env format', () => {
  it('round trip keeps comments, quotes, multi-line, export, = and #, byte for byte', async () => {
    const plain = parseDoc(SAMPLE, '.env.production');
    const key = randomBytes(32);
    const { doc, dek } = await encryptDoc(plain, { context: '.env.production', recipients: [{ type: 'key', key }] });
    const text = serialize(doc);
    expect(text).toContain('#/veilform-env v1');
    expect(text).toContain('# app config');
    expect(text).toContain('not a kv line');
    expect(text).not.toContain('postgres://');
    expect(text).not.toContain('line2');
    expect(text).not.toContain('literal');
    expect(text).not.toContain('spaced');
    expect(text).toMatch(/^export DB_URL="enc:v1:/m);
    expect(text).toMatch(/^EQ="enc:v1:[A-Za-z0-9_-]+" # trailing comment$/m);
    const back = parseDoc(text, 'x');
    expect(back.context).toBe('.env.production');
    const u = await unlock(back, { keys: [key] });
    expect(u.dek.equals(dek)).toBe(true);
    const dec = await decryptDoc(back, u.dek);
    expect(dec.text).toBe(SAMPLE);
    const m = Object.fromEntries(dec.entries.map((e) => [e.key, e.value]));
    expect(m).toMatchObject({ DB_URL: 'postgres://u:p@h:5432/db?sslmode=require', MULTI: 'line1\nline2 with # hash\nline3', EQ: 'a=b=c', HASH: 'abc#notacomment', EMPTY: '', INDENTED: 'spaced value', ESC: 'tab\tnew\nq"x' });
  });

  it('detects tampering: edited value, moved value, removed/added/reordered line, swapped context; wrong key fails cleanly', async () => {
    const key = randomBytes(32);
    const { doc } = await encryptDoc(parseDoc('A=alpha\nB=bravo\nC=charlie\n'), { context: '.env', recipients: [{ type: 'key', key }] });
    const text = serialize(doc);
    const lines = text.split('\n');
    const idx = (k: string) => lines.findIndex((l) => l.startsWith(`${k}=`));
    const variants: Record<string, string> = {};
    // flip one character inside A's ciphertext
    const a = lines[idx('A')]!;
    const pos = a.indexOf('enc:v1:') + 12;
    variants.bitflip = lines.map((l, i) => (i === idx('A') ? a.slice(0, pos) + (a[pos] === 'A' ? 'B' : 'A') + a.slice(pos + 1) : l)).join('\n');
    // move B's ciphertext to A
    variants.moved = lines.map((l, i) => (i === idx('A') ? 'A=' + lines[idx('B')]!.slice(2) : l)).join('\n');
    variants.removed = lines.filter((_, i) => i !== idx('C')).join('\n');
    variants.reordered = lines.map((l, i) => (i === idx('A') ? lines[idx('B')] : i === idx('B') ? lines[idx('A')] : l)).join('\n');
    variants.added = text + '\nD=' + lines[idx('C')]!.slice(2);
    variants.context = text.replace('#/context .env', '#/context .env.staging');
    for (const [name, t] of Object.entries(variants)) {
      const d = parseDoc(t);
      const u = await unlock(d, { keys: [key] }).catch((e: Error) => e);
      if (u instanceof Error) {
        expect(u.message, name).toMatch(/cannot decrypt/);
        continue;
      }
      await expect(decryptDoc(d, u.dek), name).rejects.toThrow(/integrity check failed/);
    }
    const wrong = await unlock(parseDoc(text), { keys: [randomBytes(32)] }).catch((e: Error & { code: string }) => e);
    expect((wrong as { code: string }).code).toBe('wrong_key');
    expect((wrong as Error).message).not.toMatch(/alpha|bravo/);
  });

  it('multiple recipients: passphrase, key file and server key each open the file; removing one locks it out', async () => {
    const f = path.join(dir, 'multi', '.env.production');
    const kMine = createKeyFile(path.join(dir, 'keys', 'mine.key'));
    const kServer = createKeyFile(path.join(dir, 'keys', 'server.key'));
    execFileSync('mkdir', ['-p', path.dirname(f)]);
    writeFileSync(f, 'TOKEN=s3cr3t-value-1\nOTHER=x\n');
    const e = env();
    const r = await e.encrypt(f, { passphrase: 'correct horse battery', keyFiles: [kMine.where, kServer.where] });
    expect(r.recipients).toEqual(['pass', `key:${kMine.id}`, `key:${kServer.id}`]);
    expect(statSync(f).mode & 0o777).toBe(0o600);
    for (const o of [{ passphrase: pass('correct horse battery') }, { keyFiles: [kMine.where] }, { keyFiles: [kServer.where] }]) {
      const fresh = env();
      const { entries } = await fresh.decrypt(f, o);
      expect(entries.find((x) => x.key === 'TOKEN')!.value).toBe('s3cr3t-value-1');
    }
    // systemd credential directory
    const cred = tmpDir('vf-cred-');
    writeFileSync(path.join(cred, 'veilform-key'), readFileSync(kServer.where));
    expect((await env({ env: { CREDENTIALS_DIRECTORY: cred } }).decrypt(f)).entries[0]!.value).toBe('s3cr3t-value-1');
    // VEILFORM_KEY_FILE
    expect((await env({ env: { VEILFORM_KEY_FILE: kMine.where } }).decrypt(f)).entries[0]!.value).toBe('s3cr3t-value-1');
    await env().addRecipients(f, { keyFiles: [kMine.where] }, {}, [`key:${kServer.id}`]);
    await expect(env().decrypt(f, { keyFiles: [kServer.where] })).rejects.toMatchObject({ code: 'wrong_key' });
    expect((await env().decrypt(f, { keyFiles: [kMine.where] })).entries[0]!.value).toBe('s3cr3t-value-1');
  });

  it('edit keeps ciphertext of unchanged values (minimal git diff); rotate changes everything; diff reports names only', async () => {
    const f = path.join(dir, 'edit', '.env');
    execFileSync('mkdir', ['-p', path.dirname(f)]);
    writeFileSync(f, '# c\nA=1111\nB=2222\nC=3333\n');
    const k = createKeyFile(path.join(dir, 'keys', 'edit.key'));
    const e = env({ keyFiles: [k.where] });
    await e.encrypt(f, { keyFiles: [k.where] });
    const before = readFileSync(f, 'utf8');
    const res = await e.edit(f, { B: 'new-bbbb', C: null, D: 'dddd' });
    expect(res).toEqual({ changed: ['B'], added: ['D'], removed: ['C'] });
    const after = readFileSync(f, 'utf8');
    const changedLines = after.split('\n').filter((l) => !before.split('\n').includes(l));
    expect(changedLines.map((l) => l.split(/[= ]/)[0]).sort()).toEqual(['#/mac', 'B', 'D']);
    const d = await e.diff({ text: before, file: f }, { file: f });
    expect(d).toEqual({ added: ['D'], removed: ['C'], changed: ['B'], unchanged: ['A'] });
    expect(JSON.stringify(d)).not.toMatch(/1111|2222|new-bbbb|dddd/);
    const rot = await e.rotate(f, {});
    expect(rot.dropped).toEqual([]);
    const rotated = readFileSync(f, 'utf8');
    const aLine = (t: string) => t.split('\n').find((l) => l.startsWith('A='));
    expect(aLine(rotated)).not.toBe(aLine(after));
    expect((await e.decrypt(f)).entries.map((x) => `${x.key}=${x.value}`)).toEqual(['A=1111', 'B=new-bbbb', 'D=dddd']);
  });

  it('passphrase attempts are limited per file', async () => {
    const f = path.join(dir, 'lim', '.env');
    execFileSync('mkdir', ['-p', path.dirname(f)]);
    writeFileSync(f, 'A=aaaaaaa\n');
    await env().encrypt(f, { passphrase: 'the right passphrase' });
    const e = env({ maxAttempts: 3 });
    for (let i = 0; i < 3; i++) await expect(e.decrypt(f, { passphrase: pass('wrong passphrase!') })).rejects.toMatchObject({ code: 'wrong_key' });
    await expect(e.decrypt(f, { passphrase: pass('the right passphrase') })).rejects.toMatchObject({ code: 'too_many_attempts' });
  });

  it('run injects variables only into the child (not argv, not the parent env, output redacted)', async () => {
    const f = path.join(dir, 'run', '.env');
    execFileSync('mkdir', ['-p', path.dirname(f)]);
    const VALUE = 'run-secret-' + randomBytes(8).toString('hex');
    writeFileSync(f, `API_TOKEN=${VALUE}\n`);
    const k = createKeyFile(path.join(dir, 'keys', 'run.key'));
    await env().encrypt(f, { keyFiles: [k.where] });
    let out = '';
    const sink = new Writable({ write: (c, _e, cb) => ((out += c.toString()), cb()) });
    const code = await env({ keyFiles: [k.where] }).run(f, [process.execPath, '-e', 'const v=process.env.API_TOKEN;console.log(v);console.log("sha:"+require("crypto").createHash("sha256").update(v).digest("hex"));console.log("argv:"+JSON.stringify(process.argv))'], { stdio: { stdout: sink, stderr: sink } });
    expect(code).toBe(0);
    expect(out).toContain('[REDACTED:API_TOKEN]');
    expect(out).toContain('sha:' + createHash('sha256').update(VALUE).digest('hex'));
    expect(out).not.toContain(VALUE);
    expect(out.split('\n').find((l) => l.startsWith('argv:'))).not.toContain('run-secret');
    expect(process.env.API_TOKEN).toBeUndefined();
    expect(existsSync(f)).toBe(true);
    expect(readFileSync(f, 'utf8')).not.toContain(VALUE);
  });

  it('session agent caches the DEK behind a 0600 socket; lock forgets it', async () => {
    const sock = path.join(tmpDir('vf-ag-'), 'a', 'agent.sock');
    const agent = new SessionAgent(sock);
    await agent.start();
    try {
      expect(statSync(sock).mode & 0o777).toBe(0o600);
      const f = path.join(dir, 'agent', '.env');
      execFileSync('mkdir', ['-p', path.dirname(f)]);
      writeFileSync(f, 'A=agent-value\n');
      await env().encrypt(f, { passphrase: 'agent passphrase 1' });
      const e1 = env({ agentSocket: sock });
      const { doc, dek } = await e1.decrypt(f, { passphrase: pass('agent passphrase 1') });
      expect(await e1.remember(doc, dek, 5)).toBe(true);
      const e2 = env({ agentSocket: sock });
      expect((await e2.decrypt(f)).entries[0]!.value).toBe('agent-value');
      expect((await e2.status(f)).unlocked).toBe(true);
      const { agentRequest } = await import('../src/crypto/keysource.js');
      await agentRequest(sock, { op: 'lock' });
      expect(await agentGet(sock, 'whatever')).toBeUndefined();
      await expect(env({ agentSocket: sock }).decrypt(f)).rejects.toMatchObject({ code: 'wrong_key' });
    } finally {
      await agent.stop();
    }
  });

  it('pre-commit check flags plaintext .env files only', () => {
    expect(
      plaintextEnvFiles([
        { path: '.env', content: 'A=plain\n' },
        { path: 'app/.env.production', content: '#/veilform-env v1\n#/context .env.production\n#/recipient key:aa eyJ3IjoieCJ9\n#/mac x\nA="enc:v1:AAAA"\n' },
        { path: '.env.example', content: 'A=changeme\n' },
        { path: 'README.md', content: 'A=b' },
        { path: 'b/.env.local', content: '# only comments\nEMPTY=\n' },
      ]),
    ).toEqual(['.env']);
  });
});
