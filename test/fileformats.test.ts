import { describe, expect, it } from 'vitest';
import { deleteEnvKey, getEnvKey, getJsonPath, parseEnv, quoteEnvValue, setEnvKey, setJsonPath, setYamlPath } from '../src/fileformats.js';
import { prng, randomSecret } from './helpers.js';

const ENV = `# Production settings
APP_ENV=production
export DB_URL="postgres://u:p@h/db" # inline comment kept

# Payments
MP_ACCESS_TOKEN='old-token'
MULTI="line1
line2"
LAST=1`;

describe('.env editor', () => {
  it('updates only the requested key and keeps comments and other keys', () => {
    const { content, action } = setEnvKey(ENV, 'MP_ACCESS_TOKEN', 'APP_USR-123');
    expect(action).toBe('updated');
    expect(content).toContain('# Production settings');
    expect(content).toContain('# Payments');
    expect(content).toContain('export DB_URL="postgres://u:p@h/db" # inline comment kept');
    expect(content).toContain('MP_ACCESS_TOKEN=APP_USR-123');
    expect(content).not.toContain('old-token');
    expect(getEnvKey(content, 'MULTI')).toBe('line1\nline2');
    expect(getEnvKey(content, 'LAST')).toBe('1');
  });

  it('creates a missing key at the end', () => {
    const { content, action } = setEnvKey(ENV, 'NEW_KEY', 'v');
    expect(action).toBe('created');
    expect(content.endsWith('NEW_KEY=v\n')).toBe(true);
  });

  it('keeps the export prefix and replaces multi-line values entirely', () => {
    const a = setEnvKey(ENV, 'DB_URL', 'x y');
    expect(a.content).toContain("export DB_URL='x y'");
    const b = setEnvKey(ENV, 'MULTI', 'single');
    expect(b.content).not.toContain('line2');
    expect(getEnvKey(b.content, 'LAST')).toBe('1');
  });

  it('quotes special characters, quotes and newlines correctly', () => {
    for (const v of ['plain', 'with space', "it's", 'a"b', 'dollar $HOME', 'back`tick`', 'line\nbreak', 'tab\tch', '#hash', 'trailing\\']) {
      const { content } = setEnvKey('', 'K', v);
      expect(getEnvKey(content, 'K'), JSON.stringify(v)).toBe(v);
    }
    expect(quoteEnvValue('abc_DEF-1.2:/@+=,%')).toBe('abc_DEF-1.2:/@+=,%');
    expect(quoteEnvValue('has space')).toBe("'has space'");
  });

  it('property: set → parse roundtrips random values and never touches other keys', () => {
    const rnd = prng(7);
    for (let i = 0; i < 200; i++) {
      const value = randomSecret(rnd) + (rnd() < 0.3 ? '\n' + randomSecret(rnd) : '') + (rnd() < 0.2 ? '"\'`$\\' : '');
      const { content } = setEnvKey(ENV, 'MP_ACCESS_TOKEN', value);
      expect(getEnvKey(content, 'MP_ACCESS_TOKEN')).toBe(value);
      expect(getEnvKey(content, 'APP_ENV')).toBe('production');
      expect(getEnvKey(content, 'MULTI')).toBe('line1\nline2');
      expect(parseEnv(content).filter((e) => e.key === 'MP_ACCESS_TOKEN')).toHaveLength(1);
    }
  });

  it('deletes keys', () => {
    const { content, removed } = deleteEnvKey(ENV, 'MULTI');
    expect(removed).toBe(true);
    expect(content).not.toContain('line2');
    expect(getEnvKey(content, 'LAST')).toBe('1');
  });

  it('rejects invalid keys', () => {
    expect(() => setEnvKey('', 'BAD KEY', 'x')).toThrow();
  });
});

describe('JSON editor', () => {
  it('sets nested keys by dotted path or JSON pointer and reports created/updated', () => {
    const a = setJsonPath('{\n    "app": {"name": "x"}\n}', 'app.mp.token', 's3cr3t');
    expect(a.action).toBe('created');
    expect(getJsonPath(a.content, '/app/mp/token')).toBe('s3cr3t');
    expect(getJsonPath(a.content, 'app.name')).toBe('x');
    expect(a.content).toContain('    "app"'); // indentation preserved
    const b = setJsonPath(a.content, '/app/mp/token', 'new');
    expect(b.action).toBe('updated');
  });

  it('refuses prototype pollution and crossing scalars', () => {
    expect(() => setJsonPath('{}', '__proto__.x', 'v')).toThrow();
    expect(() => setJsonPath('{"a": 1}', 'a.b', 'v')).toThrow();
  });
});

describe('YAML editor (block mappings)', () => {
  const Y = `# config\nserver:\n  port: 8080 # keep\n  payments:\n    provider: mercadopago\n    token: "old"\nlogging:\n  level: info\n`;

  it('updates a nested scalar and keeps comments/other keys', () => {
    const { content, action } = setYamlPath(Y, 'server.payments.token', 'new "tok"\nline');
    expect(action).toBe('updated');
    expect(content).toContain('# config');
    expect(content).toContain('port: 8080 # keep');
    expect(content).toContain('token: "new \\"tok\\"\\nline"');
    expect(content).toContain('level: info');
    expect(content).not.toContain('"old"');
  });

  it('creates missing keys under the right parent', () => {
    const { content, action } = setYamlPath(Y, 'server.payments.public_key', 'pk');
    expect(action).toBe('created');
    const lines = content.split('\n');
    const i = lines.findIndex((l) => l.includes('public_key'));
    expect(lines[i]).toBe('    public_key: "pk"');
    expect(lines.slice(i + 1).join('\n')).toContain('logging:');
    const c = setYamlPath(Y, 'cache.ttl', '60');
    expect(c.content.trimEnd().endsWith('cache:\n  ttl: "60"')).toBe(true);
  });

  it('rejects unsupported YAML instead of corrupting it', () => {
    expect(() => setYamlPath('{a: 1}', 'a', 'x')).toThrow(/flow/);
    expect(() => setYamlPath('items:\n  - a: 1\n', 'items.a', 'x')).toThrow();
  });
});
