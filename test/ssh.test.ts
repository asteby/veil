import { execFileSync, spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { makeApp, openPage, post, submit, tmpDir, type TestApp } from './helpers.js';

const SSHD = '/usr/sbin/sshd';
const canRun = existsSync(SSHD) && spawnSync('ssh', ['-V']).status === 0 && process.platform !== 'win32';

async function freePort(): Promise<number> {
  return new Promise((resolve) => {
    const s = net.createServer();
    s.listen(0, '127.0.0.1', () => {
      const p = (s.address() as net.AddressInfo).port;
      s.close(() => resolve(p));
    });
  });
}

describe.skipIf(!canRun)('SSH against a loopback sshd (non-root, key auth)', () => {
  const dir = tmpDir('si-sshd-');
  const authFile = path.join(dir, 'authorized_keys');
  let sshd: ChildProcess;
  let port = 0;
  let t: TestApp;
  const clientKey = path.join(dir, 'client');

  beforeAll(async () => {
    port = await freePort();
    execFileSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-f', path.join(dir, 'hostkey')]);
    execFileSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-f', clientKey]);
    writeFileSync(authFile, readFileSync(clientKey + '.pub'), { mode: 0o600 });
    writeFileSync(
      path.join(dir, 'sshd_config'),
      [`Port ${port}`, 'ListenAddress 127.0.0.1', `HostKey ${dir}/hostkey`, `AuthorizedKeysFile ${authFile}`, 'PasswordAuthentication no', 'KbdInteractiveAuthentication no', 'UsePAM no', 'StrictModes no', `PidFile ${dir}/sshd.pid`].join('\n') + '\n',
    );
    sshd = spawn(SSHD, ['-D', '-f', path.join(dir, 'sshd_config'), '-E', path.join(dir, 'sshd.log')], { stdio: 'ignore' });
    for (let i = 0; i < 50; i++) {
      if (spawnSync('ssh-keyscan', ['-p', String(port), '127.0.0.1']).stdout?.length) break;
      await new Promise((r) => setTimeout(r, 100));
    }
    t = makeApp({
      ssh: {
        hosts: {
          loop: { host: '127.0.0.1', port, identityFile: clientKey, authorizedKeysFile: authFile },
          loop_newkey: { host: '127.0.0.1', port, keyAlias: 'deploy' },
        },
      },
      destinations: {
        local: { type: 'keychain' },
        remote_env: { type: 'env-file', host: 'loop', path: path.join(dir, 'srv', 'app.env'), owner: undefined },
        remote_files: { type: 'ssh-file', host: 'loop', path: path.join(dir, 'srv', 'secrets', '{name}'), mode: '0640' },
      },
      writeTargets: [{ kind: 'env-file', host: 'loop', path: path.join(dir, 'srv', '*.env'), keys: ['MP_*'] }],
    });
  }, 30_000);

  afterAll(async () => {
    sshd?.kill();
    await t?.cleanup();
  });

  it('ssh_key_provision: shows host fingerprint, generates a key kept in the store, installs and tests it', async () => {
    const r = await t.app.sshKeyProvision({ host: 'loop', alias: 'deploy' });
    expect(r.status).toBe('awaiting_user');
    const page = await openPage(String(r.url));
    const lines = (page.data.destination as { lines: { label: string; value: string }[] }).lines;
    const fp = execFileSync('ssh-keygen', ['-lf', path.join(dir, 'hostkey.pub')], { encoding: 'utf8' }).split(' ')[1]!;
    expect(lines.find((l) => l.label === 'host key fingerprints')!.value).toContain(fp);
    expect(lines.find((l) => l.label === 'known host')!.value).toMatch(/^NO/);
    const fields = (page.data.schema as { sections: { fields: { name: string }[] }[] }).sections[0]!.fields.map((f) => f.name);
    expect(fields).toEqual(['trust_host', 'confirm']);
    // submitting without confirming the fingerprint is refused
    expect((await post(page, { action: 'submit', values: { confirm: true } })).json.errors).toEqual([{ field: 'trust_host', code: 'required' }]);
    expect((await post(page, { action: 'submit', values: { confirm: true, trust_host: true } })).json.ok).toBe(true);
    const w = await t.app.secretWait({ id: r.request_id });
    expect(w).toMatchObject({ status: 'completed', alias: 'deploy', host: 'loop', access_test: 'ok' });
    expect(String(w.public_key_fingerprint)).toMatch(/^SHA256:/);
    const priv = t.keychain.data.get('veilform/ssh_key.deploy')!;
    expect(priv).toContain('OPENSSH PRIVATE KEY');
    expect(t.app.safe(w)).not.toContain(priv.split('\n')[1]!);
    expect(readFileSync(authFile, 'utf8')).toContain('veilform:deploy');
    expect(existsSync(path.join(t.home, 'ssh', 'deploy'))).toBe(false); // no private key file on disk
  });

  it('ssh_exec with the provisioned key (private agent); secrets delivered via stdin and redacted', async () => {
    await t.app.vault.put('local', 'DB_PASSWORD', 'remote-db-pass-91x');
    const r = await t.app.sshExec({ host: 'loop_newkey', command: 'printf "user=%s pw=%s" "$(whoami)" "$DB_PASSWORD"; ps -o args= -u "$(whoami)" | grep -c remote-db-pass-91x || true', env: { DB_PASSWORD: '${secret:DB_PASSWORD}' } });
    const p = await openPage(String(r.url));
    expect((p.data.approval as { literal: string }).literal).toContain('export DB_PASSWORD=${secret:DB_PASSWORD}');
    await post(p, { action: 'approve' });
    const w = await t.app.secretWait({ id: r.request_id });
    expect(w.exit_code).toBe(0);
    expect(String(w.stdout)).toMatch(/^user=\S+ pw=\[REDACTED:DB_PASSWORD\]/);
    expect(t.app.safe(w)).not.toContain('remote-db-pass-91x');
  });

  it('env-file destination over SSH: merges the key, keeps the rest, 0600, value only on stdin', async () => {
    const f = path.join(dir, 'srv', 'app.env');
    execFileSync('mkdir', ['-p', path.dirname(f)]);
    writeFileSync(f, '# remote file\nPORT=8080\n');
    const r = await t.app.secretRequest({ title: 'deploy', fields: [{ name: 'MP_ACCESS_TOKEN', label: 'MP' }], destination: 'remote_env' });
    await submit(String(r.url), { MP_ACCESS_TOKEN: 'APP_USR-remote "quoted" $x' });
    expect(await t.app.secretWait({ id: r.request_id })).toMatchObject({ status: 'completed', stored: ['MP_ACCESS_TOKEN'] });
    expect(readFileSync(f, 'utf8')).toBe(`# remote file\nPORT=8080\nMP_ACCESS_TOKEN='APP_USR-remote "quoted" $x'\n`);
    expect(statSync(f).mode & 0o777).toBe(0o600);
  });

  it('ssh-file destination: one file per secret with the configured mode, write-only', async () => {
    const r = await t.app.secretRequest({ title: 'cert', fields: [{ name: 'TLS_KEY', label: 'Key', kind: 'textarea' }], destination: 'remote_files' });
    await submit(String(r.url), { TLS_KEY: '-----BEGIN-----\nabc\n-----END-----' });
    await t.app.secretWait({ id: r.request_id });
    const f = path.join(dir, 'srv', 'secrets', 'TLS_KEY');
    expect(readFileSync(f, 'utf8')).toBe('-----BEGIN-----\nabc\n-----END-----');
    expect(statSync(f).mode & 0o777).toBe(0o640);
    await expect(t.app.vault.resolve('remote_files:TLS_KEY')).rejects.toThrow(/write-only/);
  });

  it('secret_write to a remote .env (dry_run, then approved write) and refuses hosts outside ssh.hosts', async () => {
    await t.app.vault.put('local', 'MP_PUBLIC_KEY', 'APP_USR-pub-123');
    const target = { kind: 'env-file', host: 'loop', path: path.join(dir, 'srv', 'app.env'), key: 'MP_PUBLIC_KEY' };
    expect(await t.app.secretWrite({ name: 'MP_PUBLIC_KEY', target, dry_run: true })).toMatchObject({ changes: [{ key: 'MP_PUBLIC_KEY', action: 'created' }] });
    const r = await t.app.secretWrite({ name: 'MP_PUBLIC_KEY', target });
    await post(await openPage(String(r.url)), { action: 'approve' });
    expect(await t.app.secretWait({ id: r.request_id })).toMatchObject({ written: true, target: { kind: 'env-file', host: 'loop' } });
    expect(readFileSync(path.join(dir, 'srv', 'app.env'), 'utf8')).toContain('MP_PUBLIC_KEY=APP_USR-pub-123');
    await expect(t.app.secretWrite({ name: 'MP_PUBLIC_KEY', target: { ...target, host: 'prod' } })).rejects.toThrow(/allowlist/);
  });
});

describe.skipIf(!canRun)('ssh_key_provision with a one-time password (fake ssh client)', () => {
  it('feeds the password through SSH_ASKPASS + FIFO: never argv, env or disk', async () => {
    const dir = tmpDir('si-fakessh-');
    const log = path.join(dir, 'log');
    const fake = path.join(dir, 'fake-ssh');
    // Fake ssh: on password auth, asks SSH_ASKPASS like OpenSSH does and installs stdin.
    writeFileSync(
      fake,
      `#!/bin/sh
echo "ARGV $*" >> ${log}
env | grep -i -e pass -e fifo | sed 's/^/ENV /' >> ${log}
case "$*" in
  *PreferredAuthentications=password*)
    pw=$("$SSH_ASKPASS" "password:")
    [ "$pw" = "$(cat ${dir}/expected)" ] || exit 5
    cat >> ${dir}/installed
    ls -la "$(dirname "$SI_ASKPASS_FIFO")" >> ${dir}/tmp-listing
    exit 0;;
  *) exit 0;;
esac
`,
    );
    chmodSync(fake, 0o755);
    const port = await freePort();
    const hostDir = tmpDir('si-sshd2-');
    execFileSync('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-f', path.join(hostDir, 'hostkey')]);
    writeFileSync(path.join(hostDir, 'cfg'), [`Port ${port}`, 'ListenAddress 127.0.0.1', `HostKey ${hostDir}/hostkey`, 'UsePAM no', `PidFile ${hostDir}/pid`].join('\n') + '\n');
    const sshd = spawn(SSHD, ['-D', '-f', path.join(hostDir, 'cfg')], { stdio: 'ignore' });
    for (let i = 0; i < 50 && !spawnSync('ssh-keyscan', ['-p', String(port), '127.0.0.1']).stdout?.length; i++) await new Promise((r) => setTimeout(r, 100));
    const PW = 'one-time-root-pass-Zq9';
    writeFileSync(path.join(dir, 'expected'), PW);
    const t = makeApp({ ssh: { binary: fake, hosts: { vps: { host: '127.0.0.1', port, user: 'root' } } } });
    try {
      const r = await t.app.sshKeyProvision({ host: 'vps', alias: 'vps_root', password: true, storage: 'file' });
      const p = await openPage(String(r.url));
      const pwField = (p.data.schema as { sections: { fields: { name: string; kind: string }[] }[] }).sections[0]!.fields.find((f) => f.name === 'password')!;
      expect(pwField.kind).toBe('secret');
      expect((await post(p, { action: 'submit', values: { trust_host: true, password: PW, confirm: true } })).json.ok).toBe(true);
      const w = await t.app.secretWait({ id: r.request_id });
      expect(w).toMatchObject({ status: 'completed', alias: 'vps_root', access_test: 'ok' });
      expect(readFileSync(path.join(dir, 'installed'), 'utf8')).toContain('veilform:vps_root');
      const logged = readFileSync(log, 'utf8');
      expect(logged).not.toContain(PW); // never in argv/env of ssh
      expect(logged).toContain('SSH_ASKPASS_REQUIRE=force');
      expect(readFileSync(path.join(dir, 'tmp-listing'), 'utf8')).toMatch(/^p.*pw$/m); // a FIFO, not a file
      expect(statSync(path.join(t.home, 'ssh', 'vps_root')).mode & 0o777).toBe(0o600);
      expect(t.app.safe(w)).not.toContain(PW);
    } finally {
      sshd.kill();
      await t.cleanup();
    }
  });
});

describe('autoMode: ssh hosts from ~/.ssh/config', () => {
  it('allows a literal Host of ~/.ssh/config only while autoMode is on; never wildcards or unknown names', async () => {
    const home = tmpDir('si-sshcfg-');
    mkdirSync(path.join(home, '.ssh'));
    writeFileSync(path.join(home, '.ssh', 'config'), 'Host *\n  ServerAliveInterval 30\nHost miserver otro\n  User ubuntu\n');
    const prev = process.env.HOME;
    process.env.HOME = home;
    try {
      const on = makeApp({ autoMode: { enabled: true } });
      expect(() => on.app.ssh.hostConfig('miserver')).not.toThrow();
      expect(() => on.app.ssh.hostConfig('otro')).not.toThrow();
      expect(() => on.app.ssh.hostConfig('evil.example.com')).toThrow(/allowlist/);
      expect(() => on.app.ssh.hostConfig('*')).toThrow(/allowlist/);
      await on.cleanup();
      const off = makeApp({});
      expect(() => off.app.ssh.hostConfig('miserver')).toThrow(/allowlist/);
      await off.cleanup();
      const noFlag = makeApp({ autoMode: { enabled: true, sshConfigHosts: false } });
      expect(() => noFlag.app.ssh.hostConfig('miserver')).toThrow(/allowlist/);
      await noFlag.cleanup();
    } finally {
      process.env.HOME = prev;
    }
  });
});
