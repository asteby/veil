/**
 * Minimal, dependency-free editors for .env, JSON and (block-style) YAML files.
 * Editors change only the requested key and preserve everything else
 * (comments, ordering, unrelated keys).
 */
import { ENV_KEY_RE, UserError } from './util.js';

export type WriteAction = 'created' | 'updated';

// ---------------------------------------------------------------- .env

interface EnvEntry {
  key: string;
  value: string;
  startLine: number;
  endLine: number; // inclusive
  exported: boolean;
}

const LINE_RE = /^(\s*)(export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*=\s*(.*)$/;

function unescapeDouble(s: string): string {
  return s.replace(/\\([\\"$`nrt])/g, (_m, c: string) => ({ n: '\n', r: '\r', t: '\t' })[c] ?? c);
}

export function parseEnv(content: string): EnvEntry[] {
  const lines = content.split('\n');
  const out: EnvEntry[] = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!.replace(/\r$/, '');
    if (/^\s*(#|$)/.test(line)) continue;
    const m = LINE_RE.exec(line);
    if (!m) continue;
    const exported = Boolean(m[2]);
    const key = m[3]!;
    let rest = m[4]!;
    const start = i;
    let value: string;
    if (rest.startsWith('"')) {
      // double-quoted, may span lines
      let buf = rest.slice(1);
      let closed = findClosingDouble(buf);
      while (closed < 0 && i + 1 < lines.length) {
        i++;
        buf += '\n' + lines[i]!.replace(/\r$/, '');
        closed = findClosingDouble(buf);
      }
      value = unescapeDouble(closed < 0 ? buf : buf.slice(0, closed));
    } else if (rest.startsWith("'")) {
      let buf = rest.slice(1);
      let closed = buf.indexOf("'");
      while (closed < 0 && i + 1 < lines.length) {
        i++;
        buf += '\n' + lines[i]!.replace(/\r$/, '');
        closed = buf.indexOf("'");
      }
      value = closed < 0 ? buf : buf.slice(0, closed);
    } else {
      const hash = rest.search(/\s#/);
      if (hash >= 0) rest = rest.slice(0, hash);
      value = rest.trim();
    }
    out.push({ key, value, startLine: start, endLine: i, exported });
  }
  return out;
}

function findClosingDouble(s: string): number {
  for (let i = 0; i < s.length; i++) {
    if (s[i] === '\\') {
      i++;
      continue;
    }
    if (s[i] === '"') return i;
  }
  return -1;
}

/** Quote a value for .env files compatible with dotenv, docker compose and systemd. */
export function quoteEnvValue(value: string): string {
  if (/^[A-Za-z0-9_\-.:/@+=,%]*$/.test(value)) return value;
  if (!value.includes("'") && !value.includes('\n') && !value.includes('\r')) return `'${value}'`;
  return `"${value.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\$/g, '\\$').replace(/`/g, '\\`').replace(/\n/g, '\\n').replace(/\r/g, '\\r')}"`;
}

export function getEnvKey(content: string, key: string): string | undefined {
  const entries = parseEnv(content).filter((e) => e.key === key);
  return entries.length ? entries[entries.length - 1]!.value : undefined;
}

export function setEnvKey(content: string, key: string, value: string): { content: string; action: WriteAction } {
  if (!ENV_KEY_RE.test(key)) throw new UserError(`invalid env key: ${key}`, 'invalid_key');
  const entries = parseEnv(content).filter((e) => e.key === key);
  const lines = content.length ? content.split('\n') : [];
  if (!entries.length) {
    const nl = content.length && !content.endsWith('\n') ? '\n' : '';
    return { content: content + nl + `${key}=${quoteEnvValue(value)}\n`, action: 'created' };
  }
  // Replace every occurrence (bottom-up so indexes stay valid).
  for (const e of [...entries].reverse()) {
    const indent = /^\s*/.exec(lines[e.startLine] ?? '')?.[0] ?? '';
    lines.splice(e.startLine, e.endLine - e.startLine + 1, `${indent}${e.exported ? 'export ' : ''}${key}=${quoteEnvValue(value)}`);
  }
  return { content: lines.join('\n'), action: 'updated' };
}

export function deleteEnvKey(content: string, key: string): { content: string; removed: boolean } {
  const entries = parseEnv(content).filter((e) => e.key === key);
  if (!entries.length) return { content, removed: false };
  const lines = content.split('\n');
  for (const e of [...entries].reverse()) lines.splice(e.startLine, e.endLine - e.startLine + 1);
  return { content: lines.join('\n'), removed: true };
}

// ---------------------------------------------------------------- JSON

/** Accepts JSON Pointer ("/a/b") or dotted path ("a.b"). */
export function parseKeyPath(p: string): string[] {
  if (p.startsWith('/')) return p.slice(1).split('/').map((s) => s.replace(/~1/g, '/').replace(/~0/g, '~'));
  return p.split('.').filter(Boolean);
}

const FORBIDDEN_KEYS = new Set(['__proto__', 'prototype', 'constructor']);

export function setJsonPath(content: string, keyPath: string, value: string): { content: string; action: WriteAction } {
  const parts = parseKeyPath(keyPath);
  if (!parts.length || parts.some((p) => FORBIDDEN_KEYS.has(p))) throw new UserError('invalid key path', 'invalid_key');
  let doc: unknown = {};
  if (content.trim()) {
    try {
      doc = JSON.parse(content);
    } catch {
      throw new UserError('target is not valid JSON', 'invalid_target');
    }
  }
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) throw new UserError('target JSON root must be an object', 'invalid_target');
  let cur = doc as Record<string, unknown>;
  for (const p of parts.slice(0, -1)) {
    const next = cur[p];
    if (next === undefined) cur[p] = {};
    else if (!next || typeof next !== 'object' || Array.isArray(next)) throw new UserError('key path crosses a non-object', 'invalid_key');
    cur = cur[p] as Record<string, unknown>;
  }
  const last = parts[parts.length - 1]!;
  const action: WriteAction = Object.prototype.hasOwnProperty.call(cur, last) ? 'updated' : 'created';
  cur[last] = value;
  const indent = /\n( +|\t)"/.exec(content)?.[1] ?? '  ';
  return { content: JSON.stringify(doc, null, indent) + '\n', action };
}

export function getJsonPath(content: string, keyPath: string): unknown {
  let cur: unknown = JSON.parse(content);
  for (const p of parseKeyPath(keyPath)) {
    if (!cur || typeof cur !== 'object') return undefined;
    cur = (cur as Record<string, unknown>)[p];
  }
  return cur;
}

// ---------------------------------------------------------------- YAML (block mappings only)

/**
 * Sets `a.b.c: "<value>"` in a block-style YAML mapping. Supports nested block
 * mappings, comments and blank lines. Does not support flow style ({a: 1}),
 * anchors/aliases or keys inside sequences: those raise `unsupported_yaml`.
 * The value is written as a double-quoted JSON string (valid YAML).
 */
export function setYamlPath(content: string, keyPath: string, value: string): { content: string; action: WriteAction } {
  const parts = parseKeyPath(keyPath);
  if (!parts.length || parts.some((p) => !/^[A-Za-z0-9_.-]+$/.test(p) || FORBIDDEN_KEYS.has(p))) throw new UserError('invalid key path', 'invalid_key');
  const firstContent = content.split('\n').find((l) => !/^\s*(#|$)/.test(l)) ?? '';
  if (/^\s*[{[]/.test(firstContent) || /^---\s*[{[]/.test(firstContent)) {
    throw new UserError('flow-style YAML is not supported', 'unsupported_yaml');
  }
  const lines = content.length ? content.replace(/\n$/, '').split('\n') : [];
  const scalar = JSON.stringify(value);
  let parentIndent = -1;
  let searchStart = 0;
  let searchEnd = lines.length;
  for (let depth = 0; depth < parts.length; depth++) {
    const key = parts[depth]!;
    const found = findYamlKey(lines, key, searchStart, searchEnd, parentIndent);
    const isLast = depth === parts.length - 1;
    if (!found) {
      // create the remaining path at the end of the current block
      const childIndent = parentIndent < 0 ? 0 : guessChildIndent(lines, searchStart, searchEnd, parentIndent);
      const add: string[] = [];
      for (let d = depth; d < parts.length; d++) {
        const ind = ' '.repeat(childIndent + (d - depth) * 2);
        add.push(d === parts.length - 1 ? `${ind}${parts[d]}: ${scalar}` : `${ind}${parts[d]}:`);
      }
      lines.splice(searchEnd, 0, ...add);
      return { content: lines.join('\n') + '\n', action: 'created' };
    }
    const blockEnd = yamlBlockEnd(lines, found.line, found.indent);
    if (isLast) {
      const line = lines[found.line]!;
      const comment = / #.*$/.exec(found.rest.startsWith('"') || found.rest.startsWith("'") ? '' : found.rest)?.[0] ?? '';
      lines.splice(found.line, blockEnd - found.line, `${line.slice(0, found.indent)}${key}: ${scalar}${comment}`);
      return { content: lines.join('\n') + '\n', action: 'updated' };
    }
    if (found.rest.trim() && !found.rest.trim().startsWith('#')) throw new UserError('key path crosses a scalar', 'invalid_key');
    parentIndent = found.indent;
    searchStart = found.line + 1;
    searchEnd = blockEnd;
  }
  throw new UserError('unreachable', 'internal');
}

function findYamlKey(lines: string[], key: string, start: number, end: number, parentIndent: number) {
  let childIndent = -1;
  for (let i = start; i < end; i++) {
    const l = lines[i]!;
    if (/^\s*(#|$)/.test(l)) continue;
    const indent = /^ */.exec(l)![0].length;
    if (indent <= parentIndent) break;
    if (/^\s*-/.test(l) && (childIndent < 0 || indent === childIndent)) throw new UserError('YAML sequences on the key path are not supported', 'unsupported_yaml');
    if (childIndent < 0) childIndent = indent;
    if (indent !== childIndent) continue;
    const m = /^( *)(["']?)([^"':#]+)\2:(?:\s|$)(.*)$/.exec(l);
    if (m && m[3] === key) {
      if (/^[&*!]/.test(m[4]!.trim())) throw new UserError('YAML anchors/tags are not supported', 'unsupported_yaml');
      return { line: i, indent, rest: m[4]! };
    }
  }
  return undefined;
}

function yamlBlockEnd(lines: string[], line: number, indent: number): number {
  let i = line + 1;
  let lastContent = line;
  for (; i < lines.length; i++) {
    const l = lines[i]!;
    if (/^\s*$/.test(l)) continue;
    const ind = /^ */.exec(l)![0].length;
    if (ind <= indent && !/^\s*#/.test(l)) break;
    if (/^\s*#/.test(l) && ind <= indent) break;
    lastContent = i;
  }
  return lastContent + 1;
}

function guessChildIndent(lines: string[], start: number, end: number, parentIndent: number): number {
  for (let i = start; i < end; i++) {
    const l = lines[i]!;
    if (/^\s*(#|$)/.test(l)) continue;
    return /^ */.exec(l)![0].length;
  }
  return parentIndent + 2;
}
