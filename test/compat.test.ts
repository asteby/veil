/**
 * Rename veilform -> Veil: everything that was persisted or configured with the former name
 * keeps working (see src/naming.ts and CHANGELOG "Renamed to Veil").
 */
import { randomBytes } from 'node:crypto';
import { copyFileSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { defaultHome, parseConfig, resolvePaths } from '../src/config.js';
import { decryptDoc, encryptDoc, HEADER, LEGACY_HEADER, parseDoc, serialize, unlock } from '../src/envenc/format.js';
import { envVar, isOwnEnvVar, keychainServiceAliases, resetEnvWarnings } from '../src/naming.js';
import { createServer, VERSION } from '../src/server.js';
import { EncryptedFileStore } from '../src/stores/encrypted-file.js';
import { KeychainStore, withServiceAliases } from '../src/stores/keychain.js';
import { STRINGS } from '../src/ui/i18n.js';
import { makeApp, memKeychain, tmpDir } from './helpers.js';

const FX = path.resolve('test/fixtures/veilform-0.2');
const FX_KEY = Buffer.from(readFileSync(path.join(FX, 'fixture.key'), 'utf8').trim(), 'hex');

afterEach(() => {
  vi.restoreAllMocks();
  resetEnvWarnings();
});

describe('environment variables', () => {
  it('VEIL_* wins; VEILFORM_* is a deprecated alias warned once per name, without the value', () => {
    const spy = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    expect(envVar('HOME', { VEIL_HOME: '/new', VEILFORM_HOME: '/old' })).toBe('/new');
    expect(spy).not.toHaveBeenCalled();
    expect(envVar('AGENT', { VEILFORM_AGENT: 'secret-looking-label' })).toBe('secret-looking-label');
    expect(envVar('AGENT', { VEILFORM_AGENT: 'secret-looking-label' })).toBe('secret-looking-label');
    expect(spy).toHaveBeenCalledTimes(1);
    expect(String(spy.mock.calls[0]![0])).toMatch(/VEILFORM_AGENT is deprecated; use VEIL_AGENT/);
    expect(String(spy.mock.calls[0]![0])).not.toContain('secret-looking-label');
    expect(envVar('CONFIG', {})).toBeUndefined();
  });

  it('children never inherit this program variables, old or new prefix', () => {
    expect(['VEIL_HOME', 'VEILFORM_PASSPHRASE', 'VEIL_KEY_FILE'].every(isOwnEnvVar)).toBe(true);
    expect(['VEILED', 'PATH', 'MY_VEIL_X'].some(isOwnEnvVar)).toBe(false);
  });

  it('encrypted-file key from env: the default name is VEIL_PASSPHRASE and VEILFORM_PASSPHRASE still works', async () => {
    const c = parseConfig({ destinations: { v: { type: 'encrypted-file', path: '/x', key: { source: 'env' } } } });
    expect(c.destinations.v).toMatchObject({ key: { source: 'env', env: 'VEIL_PASSPHRASE' } });
    vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    const home = tmpDir('vf-compat-');
    const t = makeApp({ defaultDestination: 'v', destinations: { v: { type: 'encrypted-file', path: path.join(home, 's.enc'), key: { source: 'env' } } } });
    const prev = { a: process.env.VEIL_PASSPHRASE, b: process.env.VEILFORM_PASSPHRASE };
    try {
      delete process.env.VEIL_PASSPHRASE;
      process.env.VEILFORM_PASSPHRASE = 'legacy passphrase 1234';
      await t.app.vault.put('v', 'K', 'value-under-legacy-env');
      expect((await t.app.vault.resolve('K')).value).toBe('value-under-legacy-env');
    } finally {
      if (prev.a === undefined) delete process.env.VEIL_PASSPHRASE;
      else process.env.VEIL_PASSPHRASE = prev.a;
      if (prev.b === undefined) delete process.env.VEILFORM_PASSPHRASE;
      else process.env.VEILFORM_PASSPHRASE = prev.b;
      await t.cleanup();
    }
  });
});

describe('config directory', () => {
  it('~/.config/veil by default; the former ~/.config/veilform is used while the new one does not exist', () => {
    const xdg = tmpDir('vf-xdg-');
    expect(defaultHome({ XDG_CONFIG_HOME: xdg })).toEqual({ home: path.join(xdg, 'veil'), legacy: false });
    mkdirSync(path.join(xdg, 'veilform'));
    expect(defaultHome({ XDG_CONFIG_HOME: xdg })).toEqual({ home: path.join(xdg, 'veilform'), legacy: true });
    vi.spyOn(console, 'error').mockImplementation(() => undefined);
    expect(resolvePaths({ XDG_CONFIG_HOME: xdg }).configFile).toBe(path.join(xdg, 'veilform', 'config.json'));
    mkdirSync(path.join(xdg, 'veil'));
    expect(defaultHome({ XDG_CONFIG_HOME: xdg })).toEqual({ home: path.join(xdg, 'veil'), legacy: false });
  });

  it('VEIL_HOME / VEIL_CONFIG, with VEILFORM_HOME / VEILFORM_CONFIG as aliases', () => {
    vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    expect(resolvePaths({ VEIL_HOME: '/srv/a' }).home).toBe('/srv/a');
    expect(resolvePaths({ VEILFORM_HOME: '/srv/b' }).home).toBe('/srv/b');
    expect(resolvePaths({ VEIL_HOME: '/srv/a', VEILFORM_HOME: '/srv/b' }).home).toBe('/srv/a');
    expect(resolvePaths({ VEIL_HOME: '/srv/a', VEILFORM_CONFIG: '/etc/c.json' }).configFile).toBe('/etc/c.json');
  });
});

describe('keychain service', () => {
  it('the default service stays "veilform" so existing secrets are found', () => {
    const c = parseConfig({});
    expect(c.destinations.local).toEqual({ type: 'keychain', service: 'veilform', fallback: 'ask' });
    expect(c.localVault.keychain.service).toBe('veilform');
    expect(keychainServiceAliases('veilform')).toEqual(['veil']);
    expect(keychainServiceAliases('veil')).toEqual(['veilform']);
    expect(keychainServiceAliases('other')).toEqual([]);
  });

  it('reads fall back to the alias service in both directions; writes go to the configured one; delete clears both', async () => {
    const mem = memKeychain();
    mem.data.set('veilform/OLD', 'stored-by-veilform');
    mem.data.set('veil/NEW', 'stored-as-veil');
    const kc = withServiceAliases(mem);
    const configuredNew = new KeychainStore('local', 'veil', kc);
    const configuredOld = new KeychainStore('local', 'veilform', kc);
    expect(await configuredNew.get('OLD')).toBe('stored-by-veilform');
    expect(await configuredOld.get('NEW')).toBe('stored-as-veil');
    expect(await configuredNew.get('MISSING')).toBeUndefined();
    // updating a value found under the alias writes the configured service: a soft migration
    expect(await configuredNew.put('OLD', 'rotated')).toEqual({ action: 'updated' });
    expect(mem.data.get('veil/OLD')).toBe('rotated');
    expect(await configuredNew.get('OLD')).toBe('rotated');
    expect(await configuredNew.delete('OLD')).toBe(true);
    expect(mem.data.has('veil/OLD') || mem.data.has('veilform/OLD')).toBe(false);
    // unrelated services have no alias
    mem.data.set('other/X', 'x');
    expect(await new KeychainStore('o', 'veil', kc).get('X')).toBeUndefined();
  });

  it('the app wires the alias: a secret stored under service "veilform" resolves from a destination configured as "veil"', async () => {
    const t = makeApp({ destinations: { local: { type: 'keychain', service: 'veil' } } });
    try {
      t.keychain.data.set('veilform/MP_ACCESS_TOKEN', 'legacy-keychain-value');
      expect(await t.app.vault.store('local').get('MP_ACCESS_TOKEN')).toBe('legacy-keychain-value');
    } finally {
      await t.cleanup();
    }
  });
});

describe('persisted formats written before the rename', () => {
  it('encrypted-file v1 (check "veilform:v1"): raw key and passphrase files still decrypt', async () => {
    const dir = tmpDir('vf-fx-');
    for (const f of ['secrets-raw.enc', 'secrets-passphrase.enc']) copyFileSync(path.join(FX, f), path.join(dir, f));
    const raw = new EncryptedFileStore('fx', path.join(dir, 'secrets-raw.enc'), async () => ({ kind: 'raw', key: FX_KEY }));
    expect(await raw.get('FIXTURE_TOKEN')).toBe('fixture-value-raw-1');
    const pass = new EncryptedFileStore('fx', path.join(dir, 'secrets-passphrase.enc'), async () => ({ kind: 'passphrase', passphrase: 'fixture passphrase 1234' }));
    expect(await pass.get('FIXTURE_TOKEN')).toBe('fixture-value-pass-1');
    // and it can still be written (same check constant)
    await raw.put('SECOND', 'v2');
    expect(await new EncryptedFileStore('fx', path.join(dir, 'secrets-raw.enc'), async () => ({ kind: 'raw', key: FX_KEY })).get('SECOND')).toBe('v2');
    const wrong = new EncryptedFileStore('fx', path.join(dir, 'secrets-raw.enc'), async () => ({ kind: 'raw', key: randomBytes(32) }));
    await expect(wrong.get('FIXTURE_TOKEN')).rejects.toThrow();
  });

  it('encrypted .env with the former spelling (#/veilform-env v1, enc:v1:) decrypts; editing keeps its spelling; rotating upgrades it', async () => {
    const text = readFileSync(path.join(FX, 'legacy-env.production'), 'utf8');
    expect(text.startsWith(LEGACY_HEADER)).toBe(true);
    const doc = parseDoc(text);
    expect(doc.legacy).toBe(true);
    const u = await unlock(doc, { keys: [FX_KEY] });
    const dec = await decryptDoc(doc, u.dek);
    expect(dec.entries).toEqual([
      { key: 'DB_URL', value: 'postgres://fixture' },
      { key: 'PORT', value: '3000' },
    ]);
    // serializing the parsed document reproduces the file byte for byte (no silent rewrite)
    expect(serialize(doc)).toBe(text);
    // edit (same data key): unchanged values keep their ciphertext, new ones use the same spelling
    const edited = await encryptDoc(parseDoc(dec.text.replace('PORT=3000', 'PORT=3000\nNEW=added'), doc.context), { context: doc.context, dek: u.dek, recipients: doc.recipients, prev: { doc, dek: u.dek } });
    const editedText = serialize(edited.doc);
    expect(editedText.startsWith(LEGACY_HEADER + '\n')).toBe(true);
    expect(editedText).toContain(text.split('\n').find((l) => l.startsWith('export DB_URL='))!);
    expect(editedText).toMatch(/^NEW="enc:v1:/m);
    expect(editedText).not.toContain('veil:1:');
    // rotate (new data key): the current spelling
    const rotated = await encryptDoc(parseDoc(dec.text, doc.context), { context: doc.context, recipients: [{ type: 'key', key: FX_KEY }] });
    const rotatedText = serialize(rotated.doc);
    expect(rotatedText.startsWith(HEADER + '\n')).toBe(true);
    expect(rotatedText).not.toContain('enc:v1:');
    const back = parseDoc(rotatedText);
    expect((await decryptDoc(back, (await unlock(back, { keys: [FX_KEY] })).dek)).entries[0]!.value).toBe('postgres://fixture');
  });

  it('the pre-commit heuristic treats both spellings as encrypted', async () => {
    const { plaintextKeys } = await import('../src/envenc/format.js');
    expect(plaintextKeys(parseDoc('A="enc:v1:QUJD"\nB="veil:1:QUJD"\nC=plain\n'))).toEqual(['C']);
  });
});

describe('visible name', () => {
  it('MCP server is "veil", pages say Veil, version matches package.json', async () => {
    const pkg = JSON.parse(readFileSync('package.json', 'utf8')) as { name: string; version: string; bin: Record<string, string> };
    expect(pkg.name).toBe('@asteby/veil');
    expect(pkg.bin).toEqual({ veil: 'dist/cli.js', veilform: 'dist/cli.js' });
    expect(VERSION).toBe(pkg.version);
    expect(STRINGS.en.appName).toBe('Veil');
    expect(STRINGS.es.appName).toBe('Veil');
    const t = makeApp();
    try {
      const server = createServer(t.app) as unknown as { server: { _serverInfo: { name: string } } };
      expect(server.server._serverInfo.name).toBe('veil');
    } finally {
      await t.cleanup();
    }
  });

  it('the example config parses', () => {
    const home = tmpDir('vf-ex-');
    writeFileSync(path.join(home, 'c.json'), readFileSync('examples/config.example.json'));
    expect(() => parseConfig(JSON.parse(readFileSync(path.join(home, 'c.json'), 'utf8')))).not.toThrow();
  });
});
