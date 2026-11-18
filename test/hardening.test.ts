import { describe, expect, it } from 'vitest';
import { parseConfig } from '../src/config.js';
import { WIN_ASKPASS_CMD } from '../src/sshkeys.js';
import { globMatch } from '../src/util.js';

const in1h = () => new Date(Date.now() + 3600e3).toISOString();
const in60d = () => new Date(Date.now() + 60 * 24 * 3600e3).toISOString();

describe('autoMode validation', () => {
  it('refuses enabled without until', () => {
    expect(() => parseConfig({ autoMode: { enabled: true } })).toThrow(/autoMode\.until/);
  });

  it('refuses until more than 30 days ahead', () => {
    expect(() => parseConfig({ autoMode: { enabled: true, until: in60d() } })).toThrow(/30 days/);
  });

  it('accepts a short window', () => {
    expect(parseConfig({ autoMode: { enabled: true, until: in1h() } }).autoMode.enabled).toBe(true);
  });

  it('does not put secret_use in the default kinds', () => {
    const cfg = parseConfig({ autoMode: { enabled: true, until: in1h() } });
    expect(cfg.autoMode.kinds).not.toContain('secret_use');
    expect(cfg.autoMode.kinds).toEqual(['ssh_exec', 'secret_write']);
  });

  it('disabled needs no until', () => {
    expect(parseConfig({ autoMode: { enabled: false } }).autoMode.enabled).toBe(false);
  });
});

describe('Windows askpass helper', () => {
  it('never expands the password through cmd', () => {
    // cmd expands %VAR% before parsing; the password must only be read by PowerShell from the environment.
    expect(WIN_ASKPASS_CMD).not.toMatch(/%SI_ASKPASS_PW%/);
    expect(WIN_ASKPASS_CMD).not.toMatch(/echo\s+%/);
    expect(WIN_ASKPASS_CMD).toContain('$env:SI_ASKPASS_PW');
  });
});

describe('globMatch with Windows paths', () => {
  it('matches backslash paths against forward-slash globs', () => {
    expect(globMatch('C:/work/**/.env.production', 'C:\\work\\app\\.env.production')).toBe(true);
    expect(globMatch('C:/work/*.env', 'C:\\other\\a.env')).toBe(false);
  });
});
