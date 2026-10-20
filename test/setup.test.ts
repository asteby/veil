import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { existsSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { App } from '../src/app.js';
import { parseConfig } from '../src/config.js';
import { SessionAgent, agentRequest } from '../src/crypto/keysource.js';
import { errorHelp, KeychainError } from '../src/errors.js';
import { detectPlatform } from '../src/platform.js';
import type { RunResult, Runner } from '../src/proc.js';
import { createServer } from '../src/server.js';
import { SecretToolBackend, type KeychainBackend } from '../src/stores/keychain.js';
import { makeApp, memKeychain, openPage, post, tmpDir, type TestApp } from './helpers.js';

const VALUE = 'sk_live_Zq81-unique-VALUE-7788';
const MASTER = 'correct horse battery staple 42';

function res(code: number, stdout = '', stderr = ''): RunResult {
  return { code, signal: null, stdout: Buffer.from(stdout), stderr: Buffer.from(stderr), stdoutTruncated: false, stderrTruncated: false, timedOut: false };
}

/** Keychain whose every call fails like a machine without secret-tool / D-Bus / an unlocked keyring. */
function brokenKeychain(err: () => Error): KeychainBackend {
  return {
    name: 'broken',
    set: async () => {
      throw err();
    },
    get: async () => {
      throw err();
    },
    delete: async () => false,
  };
}

const missingTool = () => new KeychainError('secret-tool is not installed or not executable', 'keychain_unavailable', 'missing_tool');
const lockedKeyring = () => new KeychainError('keychain is locked (secret-tool store)', 'keychain_locked');

/** Everything Veil wrote to disk for this home (config, index, audit, vault...). */
function diskText(home: string): string {
  let all = '';
  for (const f of ['audit.jsonl', 'index.json', 'local-vault.json', 'approvals.json', 'local-vault.attempts.json']) {
    const p = path.join(home, f);
    if (existsSync(p)) all += readFileSync(p, 'utf8');
  }
  return all;
}

async function request(t: TestApp, name = 'STRIPE_KEY') {
  const r = await t.app.secretRequest({ title: 'Stripe', fields: [{ name, label: 'Secret key' }] });
  expect(r.status).toBe('awaiting_user');
  return r;
}

describe('keychain failures are classified (never a bare sink_failed)', () => {
  it('missing binary, no D-Bus, no Secret Service, locked keyring, not found', async () => {
    const enoent: Runner = async () => {
      throw Object.assign(new Error('spawn secret-tool ENOENT'), { code: 'ENOENT' });
    };
    await expect(new SecretToolBackend(enoent).set('s', 'a', VALUE)).rejects.toMatchObject({ code: 'keychain_unavailable', reason: 'missing_tool' });
    await expect(new SecretToolBackend(enoent).get('s', 'a')).rejects.toMatchObject({ code: 'keychain_unavailable', reason: 'missing_tool' });
    const stderr = (msg: string): Runner => async () => res(1, '', msg);
    await expect(new SecretToolBackend(stderr('secret-tool: Cannot autolaunch D-Bus without X11 $DISPLAY')).set('s', 'a', VALUE)).rejects.toMatchObject({ code: 'keychain_unavailable', reason: 'no_dbus' });
    await expect(new SecretToolBackend(stderr('The name org.freedesktop.secrets was not provided by any .service files')).set('s', 'a', VALUE)).rejects.toMatchObject({ code: 'keychain_unavailable', reason: 'no_service' });
    await expect(new SecretToolBackend(stderr('Cannot create an item in a locked collection')).set('s', 'a', VALUE)).rejects.toMatchObject({ code: 'keychain_locked' });
    await expect(new SecretToolBackend(async () => ({ ...res(0), timedOut: true, code: null })).set('s', 'a', VALUE)).rejects.toMatchObject({ code: 'keychain_locked' });
    expect(await new SecretToolBackend(async () => res(1)).get('s', 'a')).toBeUndefined();
    // the value never appears in any error message
    try {
      await new SecretToolBackend(stderr('weird failure')).set('s', 'a', VALUE);
    } catch (e) {
      expect((e as Error).message).not.toContain(VALUE);
      expect((e as KeychainError).code).toBe('keychain_failed');
    }
  });

  it('fix commands follow the distribution (apt/dnf/pacman/zypper/brew)', () => {
    const cmd = (osRelease: string) => errorHelp('keychain_unavailable', { reason: 'missing_tool', platform: detectPlatform({ platform: 'linux', osRelease }) })!.fix!.command;
    expect(cmd('ID=linuxmint\nID_LIKE="ubuntu debian"')).toBe('sudo apt install -y libsecret-tools');
    expect(cmd('ID=fedora')).toBe('sudo dnf install -y libsecret');
    expect(cmd('ID=arch')).toBe('sudo pacman -S --needed libsecret');
    expect(cmd('ID=endeavouros\nID_LIKE=arch')).toBe('sudo pacman -S --needed libsecret');
    expect(cmd('ID="opensuse-tumbleweed"\nID_LIKE="opensuse suse"')).toBe('sudo zypper install -y libsecret-tools');
    expect(errorHelp('keychain_unavailable', { reason: 'no_dbus' })!.fix!.command).toBe('dbus-run-session -- $SHELL');
    expect(errorHelp('keychain_locked', { platform: detectPlatform({ platform: 'darwin' }) })!.fix!.command).toContain('security unlock-keychain');
    expect(errorHelp('keychain_unsupported', { platform: detectPlatform({ platform: 'win32' }) })!.fix!.command).toBe('veilform init');
    for (const code of ['keychain_unavailable', 'keychain_locked', 'passphrase_required', 'master_password_not_set', 'destination_not_configured']) {
      const h = errorHelp(code)!;
      expect(h.en.length).toBeGreaterThan(10);
      expect(h.es.length).toBeGreaterThan(10);
      expect(h.fix?.en && h.fix.es).toBeTruthy();
    }
  });
});

describe('secret_request with the OS keychain unavailable completes through the encrypted store', () => {
  let t: TestApp;
  let t2: TestApp | undefined;
  afterEach(async () => {
    await t2?.app.shutdown();
    t2 = undefined;
    await t?.cleanup();
  });

  it('page offers the store, first use defines the master password there, value is usable, nothing leaks', async () => {
    t = makeApp({ destinations: { local: { type: 'keychain' } } }, { keychainBackend: brokenKeychain(missingTool) });
    const r = await request(t);
    const page = await openPage(String(r.url));
    const first = await post(page, { action: 'submit', values: { STRIPE_KEY: VALUE } });
    expect(first.status).toBe(200);
    expect(first.json.ok).toBe(false);
    const fb = first.json.fallback as Record<string, unknown>;
    expect(fb).toMatchObject({ reason: 'keychain_unavailable', mode: 'create', minLength: 10 });
    expect((fb.fix as { command?: string }).command).toBeTruthy();
    // page still open, op still waiting
    expect((await t.app.secretWait({ id: r.request_id, timeout_seconds: 0 })).status).toBe('awaiting_user');

    // validation on the page: too short, mismatch
    expect((await post(page, { action: 'submit', values: { STRIPE_KEY: VALUE }, fallback: { passphrase: 'short', passphrase2: 'short' } })).json.errors).toEqual([{ field: '__fallback', code: 'weak' }]);
    expect((await post(page, { action: 'submit', values: { STRIPE_KEY: VALUE }, fallback: { passphrase: MASTER, passphrase2: MASTER + 'x' } })).json.errors).toEqual([{ field: '__fallback', code: 'mismatch' }]);
    expect(existsSync(path.join(t.home, 'local-vault.json'))).toBe(false);

    const ok = await post(page, { action: 'submit', values: { STRIPE_KEY: VALUE }, fallback: { passphrase: MASTER, passphrase2: MASTER } });
    expect(ok.json.ok).toBe(true);
    expect(String(ok.json.message)).toMatch(/encrypted store|almacén cifrado/);
    const w = await t.app.secretWait({ id: r.request_id });
    expect(w).toMatchObject({ status: 'completed', stored: ['STRIPE_KEY'], stored_in_local_vault: ['STRIPE_KEY'] });

    const vf = path.join(t.home, 'local-vault.json');
    expect(statSync(vf).mode & 0o777).toBe(0o600);
    expect(JSON.parse(readFileSync(vf, 'utf8')).kdf.name).toMatch(/argon2id|scrypt/);
    expect(t.app.vault.list()[0]).toMatchObject({ name: 'STRIPE_KEY', destination: 'local', backend: 'vault' });
    expect((await t.app.vault.resolve('STRIPE_KEY')).value).toBe(VALUE);

    // no plaintext value or master password anywhere on disk, in responses or in the audit log
    const disk = diskText(t.home);
    expect(disk).not.toContain(VALUE);
    expect(disk).not.toContain(MASTER);
    expect(JSON.stringify(w)).not.toContain(VALUE);
    const audit = readFileSync(path.join(t.home, 'audit.jsonl'), 'utf8');
    expect(audit).toContain('local_vault_offered');
    expect(audit).toContain('local_vault_created');
    expect(t.app.safe({ x: `pw=${MASTER}` })).not.toContain(MASTER);

    // a new process (restart) finds the store locked: structured error with fix, never a value
    t2 = { ...t, app: new App({ cfg: t.app.cfg, paths: t.app.paths, keychainBackend: brokenKeychain(missingTool), openUrl: async () => false, testKdf: true, agentSocket: null }) } as TestApp;
    await expect(t2.app.vault.resolve('STRIPE_KEY')).rejects.toMatchObject({ code: 'passphrase_required' });
    expect(t2.app.errorResult(await t2.app.vault.resolve('STRIPE_KEY').catch((e) => e))).toMatchObject({ error: 'passphrase_required', fix: { command: 'veilform unlock' } });

    // local_unlock page: wrong password is limited, right one unlocks
    const u = await t2.app.localUnlock({});
    const up = await openPage(String(u.url));
    expect((await post(up, { action: 'submit', values: { master_password: 'wrong password!!' } })).json.errors).toEqual([{ field: 'master_password', code: 'type' }]);
    expect((await post(up, { action: 'submit', values: { master_password: MASTER } })).json.ok).toBe(true);
    expect(await t2.app.secretWait({ id: u.request_id })).toMatchObject({ status: 'completed', unlocked: true, created: false });
    expect((await t2.app.vault.resolve('STRIPE_KEY')).value).toBe(VALUE);
    expect(diskText(t.home)).not.toContain(MASTER);
  });

  it('locked keyring and missing D-Bus are offered too; fallback "never" fails with an actionable error', async () => {
    t = makeApp({ destinations: { local: { type: 'keychain' } } }, { keychainBackend: brokenKeychain(lockedKeyring) });
    let page = await openPage(String((await request(t)).url));
    let j = (await post(page, { action: 'submit', values: { STRIPE_KEY: VALUE } })).json;
    expect(j.fallback).toMatchObject({ reason: 'keychain_locked', mode: 'create' });
    await t.cleanup();

    const noDbus: Runner = async (argv) => (argv[0] === 'secret-tool' ? res(1, '', 'secret-tool: Cannot autolaunch D-Bus without X11 $DISPLAY') : res(0));
    t = makeApp({ destinations: { local: { type: 'keychain' } } }, { keychainBackend: new SecretToolBackend(noDbus) });
    page = await openPage(String((await request(t)).url));
    j = (await post(page, { action: 'submit', values: { STRIPE_KEY: VALUE } })).json;
    expect(j.fallback).toMatchObject({ reason: 'keychain_unavailable', fix: { command: 'dbus-run-session -- $SHELL' } });
    await t.cleanup();

    t = makeApp({ destinations: { local: { type: 'keychain', fallback: 'never' } } }, { keychainBackend: brokenKeychain(missingTool) });
    const r = await request(t);
    page = await openPage(String(r.url));
    j = (await post(page, { action: 'submit', values: { STRIPE_KEY: VALUE } })).json;
    expect(j.ok).toBe(false);
    expect(j.fallback).toBeUndefined();
    expect((j.fix as { command?: string }).command).toBeTruthy();
    const w = await t.app.secretWait({ id: r.request_id });
    expect(w).toMatchObject({ status: 'failed', error: 'keychain_unavailable', help: { en: expect.any(String), es: expect.any(String) }, fix: { command: expect.any(String) } });
    expect(JSON.stringify(w)).not.toContain(VALUE);
    expect(JSON.stringify(w)).not.toContain('sink_failed');
  });

  it('fallback "auto" with an unlocked store stores directly; "ask" with an unlocked store only asks for consent', async () => {
    t = makeApp({ destinations: { local: { type: 'keychain', fallback: 'auto' } } }, { keychainBackend: brokenKeychain(missingTool) });
    await t.app.vault.localVault.create(MASTER);
    let r = await request(t);
    let page = await openPage(String(r.url));
    expect((await post(page, { action: 'submit', values: { STRIPE_KEY: VALUE } })).json.ok).toBe(true);
    expect(await t.app.secretWait({ id: r.request_id })).toMatchObject({ status: 'completed', stored_in_local_vault: ['STRIPE_KEY'] });
    await t.cleanup();

    t = makeApp({ destinations: { local: { type: 'keychain' } } }, { keychainBackend: brokenKeychain(missingTool) });
    await t.app.vault.localVault.create(MASTER);
    r = await request(t, 'OTHER');
    page = await openPage(String(r.url));
    const first = (await post(page, { action: 'submit', values: { OTHER: VALUE } })).json;
    expect(first.fallback).toMatchObject({ mode: 'confirm' });
    expect((await post(page, { action: 'submit', values: { OTHER: VALUE }, fallback: {} })).json.ok).toBe(true);
    expect((await t.app.vault.resolve('OTHER')).value).toBe(VALUE);
  });

  it('init-style config (encrypted-file + master) works with no keychain at all', async () => {
    const home = tmpDir();
    t = makeApp({ destinations: { local: { type: 'encrypted-file', path: path.join(home, 'v.json'), key: { source: 'master' } } } }, { keychainBackend: brokenKeychain(missingTool) });
    const r = await request(t);
    const page = await openPage(String(r.url));
    const first = (await post(page, { action: 'submit', values: { STRIPE_KEY: VALUE } })).json;
    expect(first.fallback).toMatchObject({ reason: 'master_password_not_set', mode: 'create', path: path.join(home, 'v.json') });
    expect(first.fallback).not.toHaveProperty('fix.command');
    expect((await post(page, { action: 'submit', values: { STRIPE_KEY: VALUE }, fallback: { passphrase: MASTER, passphrase2: MASTER } })).json.ok).toBe(true);
    expect(await t.app.secretWait({ id: r.request_id })).toMatchObject({ status: 'completed', stored: ['STRIPE_KEY'] });
    expect((await t.app.vault.resolve('STRIPE_KEY')).value).toBe(VALUE);
    expect(readFileSync(path.join(home, 'v.json'), 'utf8')).not.toContain(VALUE);
    rmSync(home, { recursive: true, force: true });
  });

  it('session agent: unlock is shared across processes and "lock" forgets it', async () => {
    const sockDir = tmpDir('vf-agent-');
    const sock = path.join(sockDir, 'agent.sock');
    const agent = new SessionAgent(sock);
    await agent.start();
    try {
      t = makeApp({ destinations: { local: { type: 'keychain', fallback: 'auto' } } }, { keychainBackend: brokenKeychain(missingTool), agentSocket: sock });
      const created = await t.app.vault.localVault.create(MASTER);
      expect(created.cached).toBe('agent');
      await t.app.vault.put('local', 'TOKEN', VALUE);
      // another Veil process with the same home and agent: no password needed
      const other = new App({ cfg: t.app.cfg, paths: t.app.paths, keychainBackend: brokenKeychain(missingTool), openUrl: async () => false, testKdf: true, agentSocket: sock });
      expect((await other.vault.resolve('TOKEN')).value).toBe(VALUE);
      expect((await other.vault.localVault.status()).via).toBe('agent');
      await agentRequest(sock, { op: 'lock' });
      other.vault.clearCache();
      await expect(other.vault.resolve('TOKEN')).rejects.toMatchObject({ code: 'passphrase_required' });
      await other.shutdown();
    } finally {
      await agent.stop();
      rmSync(sockDir, { recursive: true, force: true });
    }
  });
});

describe('MCP surface: structured errors with fix', () => {
  let t: TestApp;
  afterEach(async () => t?.cleanup());

  it('tool errors carry code + help + fix (en/es), doctor is read-only and value-free', async () => {
    t = makeApp({ destinations: { local: { type: 'keychain' } } }, { keychainBackend: brokenKeychain(missingTool) });
    await t.app.vault.localVault.create(MASTER);
    await t.app.vault.put('local', 'TOKEN', VALUE, {}, { allowFallback: true });
    t.app.vault.lockLocalVaults();
    t.app.vault.clearCache();
    const server = createServer(t.app);
    const [ct, st] = InMemoryTransport.createLinkedPair();
    await server.connect(st);
    const client = new Client({ name: 'c', version: '1' });
    await client.connect(ct);
    const r = await client.callTool({ name: 'secret_request', arguments: { title: 'x', fields: [{ name: 'A', label: 'A' }], destination: 'nope' } });
    const body = JSON.parse((r.content as { text: string }[])[0]!.text);
    expect(r.isError).toBe(true);
    expect(body).toMatchObject({ code: 'destination_not_configured', help: { en: expect.any(String), es: expect.any(String) }, fix: { command: 'veilform init' } });

    const d = await client.callTool({ name: 'doctor', arguments: {} });
    const rep = JSON.parse((d.content as { text: string }[])[0]!.text);
    expect(rep.checks.length).toBeGreaterThan(5);
    expect(rep.default_destination.id).toBe('local');
    expect(JSON.stringify(rep)).not.toContain(VALUE);
    expect(JSON.stringify(rep)).not.toContain(MASTER);
    await client.close();
  });
});

describe('config', () => {
  it('defaults: local keychain with fallback "ask"; master key source parses', () => {
    const c = parseConfig({});
    expect(c.destinations.local).toEqual({ type: 'keychain', service: 'veilform', fallback: 'ask' });
    expect(c.localVault.unlockMinutes).toBe(15);
    expect(parseConfig({ destinations: { v: { type: 'encrypted-file', path: '/x', key: { source: 'master' } } } }).destinations.v).toMatchObject({ key: { source: 'master' } });
  });

  it('a value file written by the old encrypted-file format still opens (compatibility)', async () => {
    const t = makeApp({}, { keychainBackend: memKeychain() });
    await t.app.vault.put('vault', 'OLD', VALUE);
    expect((await t.app.vault.resolve('OLD')).value).toBe(VALUE);
    writeFileSync(path.join(t.home, 'noop'), '');
    await t.cleanup();
  });
});
