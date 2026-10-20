import { chmodSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { formatReport, runDoctor, type DoctorDeps, type DoctorReport } from '../src/doctor.js';
import { planInit } from '../src/init.js';
import { detectPlatform, installCommand, parseOsRelease } from '../src/platform.js';
import type { RunResult } from '../src/proc.js';
import { tmpDir } from './helpers.js';

const OS: Record<string, string> = {
  mint: 'NAME="Linux Mint"\nID=linuxmint\nID_LIKE="ubuntu debian"\nPRETTY_NAME="Linux Mint 22.3"',
  ubuntu: 'ID=ubuntu\nID_LIKE=debian',
  debian: 'ID=debian',
  fedora: 'ID=fedora',
  rocky: 'ID="rocky"\nID_LIKE="rhel centos fedora"',
  arch: 'ID=arch',
  manjaro: 'ID=manjaro\nID_LIKE=arch',
  suse: 'ID="opensuse-leap"\nID_LIKE="suse opensuse"',
  alpine: 'ID=alpine',
};

function res(code: number, stdout = '', stderr = ''): RunResult {
  return { code, signal: null, stdout: Buffer.from(stdout), stderr: Buffer.from(stderr), stdoutTruncated: false, stderrTruncated: false, timedOut: false };
}

const ALL_BINS = ['secret-tool', 'busctl', 'gnome-keyring-daemon', 'ssh', 'ssh-keygen', 'git', 'gh', 'psql', 'xdg-open', 'chromium', 'security'];

let home: string | undefined;
const extra: string[] = [];
afterEach(() => {
  for (const d of [home, ...extra.splice(0)]) if (d) rmSync(d, { recursive: true, force: true });
  home = undefined;
});

function deps(over: Partial<DoctorDeps> & { bins?: string[] } = {}): DoctorDeps {
  home = home ?? tmpDir('vf-doc-');
  const bins = over.bins ?? ALL_BINS;
  const busDir = tmpDir('vf-bus-');
  extra.push(busDir);
  writeFileSync(path.join(busDir, 'bus'), '');
  return {
    paths: { home: home!, configFile: path.join(home, 'config.json'), auditFile: '', indexFile: '', approvalsFile: '', dataDir: '' },
    version: 'test',
    platform: 'linux',
    osRelease: OS.mint,
    env: { XDG_RUNTIME_DIR: busDir, PATH: '/usr/bin' },
    which: (c) => (bins.includes(c) ? `/usr/bin/${c}` : undefined),
    procNames: () => ['bash', 'gnome-keyring-d'],
    runner: async (argv) => (argv[0] === 'busctl' ? res(0, 'b false\n') : res(1)),
    nodeVersion: 'v24.8.0',
    argon2: true,
    configText: null,
    agentRunning: false,
    moduleAvailable: () => true,
    ...over,
  };
}

const check = (r: DoctorReport, id: string) => r.checks.find((c) => c.id === id)!;

describe('platform detection', () => {
  it('maps distributions to package managers and exact commands', () => {
    const pm = (k: string) => detectPlatform({ platform: 'linux', osRelease: OS[k] }).packageManager;
    expect([pm('mint'), pm('ubuntu'), pm('debian')]).toEqual(['apt', 'apt', 'apt']);
    expect([pm('fedora'), pm('rocky')]).toEqual(['dnf', 'dnf']);
    expect([pm('arch'), pm('manjaro')]).toEqual(['pacman', 'pacman']);
    expect(pm('suse')).toBe('zypper');
    expect(pm('alpine')).toBe('apk');
    expect(detectPlatform({ platform: 'darwin' }).packageManager).toBe('brew');
    expect(parseOsRelease(OS.mint!).PRETTY_NAME).toBe('Linux Mint 22.3');
    const p = (k: string) => detectPlatform({ platform: 'linux', osRelease: OS[k] });
    expect(installCommand('gh', p('arch'))).toBe('sudo pacman -S --needed github-cli');
    expect(installCommand('psql', p('mint'))).toBe('sudo apt install -y postgresql-client');
    expect(installCommand('psql', detectPlatform({ platform: 'darwin' }))).toBe('brew install libpq');
    expect(installCommand('chromium', p('fedora'))).toBe('npx playwright install chromium');
  });
});

describe('doctor', () => {
  it('healthy Linux desktop: keychain usable, ready', async () => {
    const r = await runDoctor(deps());
    expect(r.ready).toBe(true);
    expect(r.keychain).toMatchObject({ usable: true });
    expect(r.default_destination).toMatchObject({ id: 'local', effective: 'keychain' });
    expect(check(r, 'keychain.unlocked').status).toBe('ok');
    expect(r.summary.error).toBe(0);
  });

  it.each([
    ['mint', 'sudo apt install -y libsecret-tools'],
    ['fedora', 'sudo dnf install -y libsecret'],
    ['arch', 'sudo pacman -S --needed libsecret'],
    ['suse', 'sudo zypper install -y libsecret-tools'],
  ])('secret-tool missing on %s: exact install command, still ready via the encrypted store', async (distro, command) => {
    const r = await runDoctor(deps({ osRelease: OS[distro], bins: ALL_BINS.filter((b) => b !== 'secret-tool') }));
    const c = check(r, 'keychain.secret-tool');
    expect(c.status).toBe('warn');
    expect(c.fix?.command).toBe(command);
    expect(c.impact?.es).toMatch(/archivo cifrado/);
    expect(r.keychain).toMatchObject({ usable: false, reason: 'missing_tool' });
    expect(r.default_destination.effective).toBe('local-vault');
    expect(r.ready).toBe(true);
    const text = formatReport(r, 'es');
    expect(text).toContain(`$ ${command}`);
    expect(text).toContain('Veil no ejecutó nada con privilegios');
  });

  it('locked keyring (probe says Locked=true) and no Secret Service', async () => {
    let r = await runDoctor(deps({ runner: async () => res(0, 'b true\n') }));
    expect(check(r, 'keychain.unlocked')).toMatchObject({ status: 'warn', fix: { command: 'seahorse' } });
    expect(r.keychain).toMatchObject({ usable: false, reason: 'locked' });
    r = await runDoctor(deps({ procNames: () => [], runner: async () => res(1, '', 'Failed: The name org.freedesktop.secrets was not provided by any .service files') }));
    expect(check(r, 'keychain.daemon')).toMatchObject({ status: 'warn', fix: { command: 'gnome-keyring-daemon --start --components=secrets' } });
    expect(r.keychain).toMatchObject({ usable: false, reason: 'no_service' });
  });

  it('no D-Bus session (SSH/headless): warns with dbus-run-session and skips the probe', async () => {
    let probed = false;
    const r = await runDoctor(
      deps({
        env: { PATH: '/usr/bin' },
        runner: async () => {
          probed = true;
          return res(0, 'b false');
        },
      }),
    );
    expect(check(r, 'keychain.dbus')).toMatchObject({ status: 'warn', fix: { command: 'dbus-run-session -- $SHELL' } });
    expect(probed).toBe(false);
    expect(r.keychain.reason).toBe('no_dbus');
  });

  it('macOS (brew) and Windows (planned backend)', async () => {
    let r = await runDoctor(deps({ platform: 'darwin', bins: ['security', 'git'], runner: async () => res(36, '', 'User interaction is not allowed.') }));
    expect(r.platform.packageManager).toBe('brew');
    expect(check(r, 'keychain.unlocked')).toMatchObject({ status: 'warn' });
    expect(check(r, 'keychain.unlocked').fix?.command).toContain('security unlock-keychain');
    expect(check(r, 'tools.gh').fix?.command).toBe('brew install gh');
    r = await runDoctor(deps({ platform: 'win32', bins: [] }));
    expect(check(r, 'keychain.unsupported')).toMatchObject({ status: 'warn', fix: { command: 'veil init' } });
    expect(check(r, 'keychain.unsupported').title.en).toMatch(/Credential Manager/);
    expect(r.default_destination.effective).toBe('local-vault');
    expect(r.ready).toBe(true);
  });

  it('tools only become errors when a feature that needs them is configured', async () => {
    const cfg = { ssh: { hosts: { prod: { host: 'example.org' } } }, databases: { app: { tables: { t: { columns: ['a'] } } } } };
    const r = await runDoctor(deps({ bins: ['secret-tool', 'busctl'], configText: JSON.stringify(cfg) }));
    expect(check(r, 'tools.ssh')).toMatchObject({ status: 'error', fix: { command: 'sudo apt install -y openssh-client' } });
    expect(check(r, 'tools.psql').status).toBe('error');
    expect(check(r, 'tools.gh').status).toBe('info');
    expect(check(r, 'tools.browser')).toMatchObject({ status: 'info', fix: { command: 'npx playwright install chromium' } });
  });

  it('old Node, invalid config, loose permissions and fallback "never" are errors', async () => {
    home = tmpDir('vf-doc-');
    chmodSync(home, 0o755);
    writeFileSync(path.join(home, 'index.json'), '{}', { mode: 0o644 });
    let r = await runDoctor(deps({ nodeVersion: 'v18.19.0', configText: '{"destinations": 5}' }));
    expect(check(r, 'node.version').status).toBe('error');
    expect(check(r, 'config').status).toBe('error');
    expect(check(r, 'permissions.home')).toMatchObject({ status: 'warn' });
    expect(check(r, 'permissions.home').fix?.command).toMatch(/^chmod 700 .* && chmod 600 .*index\.json$/);
    expect(r.ready).toBe(false);
    r = await runDoctor(deps({ bins: [], configText: JSON.stringify({ destinations: { local: { type: 'keychain', fallback: 'never' } } }) }));
    expect(check(r, 'destination.default').status).toBe('error');
    expect(r.ready).toBe(false);
  });
});

describe('init plan (user-level only)', () => {
  it('no config + no keychain: encrypted store as default; with keychain: keychain + auto fallback', async () => {
    let r = await runDoctor(deps({ bins: [] }));
    let plan = planInit(deps().paths, r, { configText: null });
    expect(plan.config).toMatchObject({ destinations: { local: { type: 'encrypted-file', key: { source: 'master' } } } });
    expect(plan.manual.map((m) => m.command)).toContain('sudo apt install -y libsecret-tools');
    for (const m of plan.manual) expect(plan.steps.map((s) => s.title.en).join('\n')).not.toContain(m.command);
    r = await runDoctor(deps());
    plan = planInit(deps().paths, r, { configText: null });
    expect(plan.config).toMatchObject({ destinations: { local: { type: 'keychain', fallback: 'auto' } } });
  });

  it('existing keychain config gets fallback "auto" (with a backup); invalid config is left alone', async () => {
    const d = deps({ bins: [] });
    mkdirSync(d.paths.home, { recursive: true });
    const orig = JSON.stringify({ destinations: { local: { type: 'keychain' } }, ui: { lang: 'es' } });
    writeFileSync(d.paths.configFile, orig, { mode: 0o600 });
    const r = await runDoctor({ ...d, configText: orig });
    const plan = planInit(d.paths, r);
    expect(plan.config).toMatchObject({ destinations: { local: { type: 'keychain', fallback: 'auto' } }, ui: { lang: 'es' } });
    for (const s of plan.steps) await s.apply();
    expect(JSON.parse(readFileSync(d.paths.configFile, 'utf8')).destinations.local.fallback).toBe('auto');
    expect(readFileSync(d.paths.configFile + '.bak', 'utf8')).toBe(orig);
    writeFileSync(d.paths.configFile, '{bad json');
    const p2 = planInit(d.paths, r);
    expect(p2.steps.find((s) => s.id === 'config')).toBeUndefined();
    expect(p2.notes.map((n) => n.en).join(' ')).toMatch(/invalid/);
  });
});

describe('rename to Veil', () => {
  it('suggests moving the former ~/.config/veilform directory (info, never an error)', async () => {
    const base = tmpDir('vf-legacy-');
    extra.push(base);
    const legacy = path.join(base, 'veilform');
    mkdirSync(legacy, { mode: 0o700 });
    const r = await runDoctor(deps({ paths: { home: legacy, configFile: path.join(legacy, 'config.json'), auditFile: '', indexFile: '', approvalsFile: '', dataDir: '' } }));
    expect(check(r, 'config.legacy_dir')).toMatchObject({ status: 'info', fix: { command: `mv ${legacy} ${path.join(base, 'veil')}` } });
    const fresh = await runDoctor(deps());
    expect(fresh.checks.find((c) => c.id === 'config.legacy_dir')).toBeUndefined();
  });
});
