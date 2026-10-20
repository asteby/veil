import type { DestinationConfig } from '../config.js';
import { checkUrl, httpRequest, type HttpResponse } from '../net.js';
import { UserError } from '../util.js';
import type { LocalResolver, PutResult, SecretStore } from './types.js';

type HttpApiConfig = Extract<DestinationConfig, { type: 'http-api' }>;

/**
 * Remote secret store reached over HTTPS. Values travel server→server (this MCP
 * process ↔ remote API) and are never part of a tool response. Remote response
 * bodies are never returned either: errors are reduced to status codes.
 *
 * The bootstrap credential (`auth.tokenRef`) is itself a secret resolved from a
 * LOCAL store (OS keychain by default), never from this config file.
 */
export interface RemoteCall {
  (method: string, path: string, body?: unknown, extraHeaders?: Record<string, string>): Promise<{ status: number; json: unknown }>;
}

export interface RemoteAdapter {
  read(call: RemoteCall, key: string): Promise<string | undefined>;
  write(call: RemoteCall, key: string, value: string): Promise<PutResult>;
  remove(call: RemoteCall, key: string): Promise<boolean>;
}

function fail(op: string, status: number): never {
  throw new UserError(`remote store ${op} failed with HTTP ${status}`, `http_${status}`);
}

function opt<T>(o: Record<string, unknown>, k: string, d?: T): T {
  const v = o[k];
  if (v === undefined) {
    if (d === undefined) throw new UserError(`http-api option "${k}" is required`, 'invalid_config');
    return d;
  }
  return v as T;
}

const enc = encodeURIComponent;

/** Reads a value by RFC 6901 JSON Pointer. */
export function jsonPointer(doc: unknown, pointer: string): unknown {
  if (!pointer || pointer === '/') return doc;
  let cur = doc;
  for (const raw of pointer.replace(/^\//, '').split('/')) {
    const k = raw.replace(/~1/g, '/').replace(/~0/g, '~');
    if (cur === null || typeof cur !== 'object') return undefined;
    cur = (cur as Record<string, unknown>)[k];
  }
  return cur;
}

function fillTemplate(t: unknown, vars: Record<string, string>): unknown {
  if (typeof t === 'string') {
    if (/^\{(\w+)\}$/.test(t)) return vars[t.slice(1, -1)] ?? t;
    return t.replace(/\{(\w+)\}/g, (m, k: string) => vars[k] ?? m);
  }
  if (Array.isArray(t)) return t.map((x) => fillTemplate(x, vars));
  if (t && typeof t === 'object') return Object.fromEntries(Object.entries(t).map(([k, v]) => [k, fillTemplate(v, vars)]));
  return t;
}

export function makeAdapter(adapter: HttpApiConfig['adapter'], o: Record<string, unknown>): RemoteAdapter {
  switch (adapter) {
    case 'generic': {
      type Op = { method: string; path: string; body?: unknown; pointer?: string };
      const read = opt<Op>(o, 'read');
      const write = opt<Op>(o, 'write');
      const del = o.delete as Op | undefined;
      return {
        async read(call, key) {
          const r = await call(read.method ?? 'GET', read.path.replace('{name}', enc(key)));
          if (r.status === 404) return undefined;
          if (r.status >= 300) fail('read', r.status);
          const v = jsonPointer(r.json, read.pointer ?? '/value');
          return v === undefined || v === null ? undefined : String(v);
        },
        async write(call, key, value) {
          const r = await call(write.method ?? 'PUT', write.path.replace('{name}', enc(key)), fillTemplate(write.body ?? { value: '{value}' }, { name: key, value }));
          if (r.status >= 300) fail('write', r.status);
          return { action: r.status === 201 ? 'created' : 'updated' };
        },
        async remove(call, key) {
          if (!del) throw new UserError('delete is not configured for this http-api destination', 'unsupported');
          const r = await call(del.method ?? 'DELETE', del.path.replace('{name}', enc(key)));
          if (r.status === 404) return false;
          if (r.status >= 300) fail('delete', r.status);
          return true;
        },
      };
    }
    case 'vault-kv2': {
      const mount = opt<string>(o, 'mount', 'secret');
      const field = opt<string>(o, 'field', 'value');
      const prefix = opt<string>(o, 'pathPrefix', '');
      const p = (kind: 'data' | 'metadata', key: string) => `/v1/${mount}/${kind}/${prefix}${enc(key)}`;
      return {
        async read(call, key) {
          const r = await call('GET', p('data', key));
          if (r.status === 404) return undefined;
          if (r.status >= 300) fail('read', r.status);
          const v = jsonPointer(r.json, `/data/data/${field}`);
          return v === undefined ? undefined : String(v);
        },
        async write(call, key, value) {
          const existing = await call('GET', p('metadata', key));
          const r = await call('POST', p('data', key), { data: { [field]: value } });
          if (r.status >= 300) fail('write', r.status);
          return { action: existing.status === 200 ? 'updated' : 'created' };
        },
        async remove(call, key) {
          const r = await call('DELETE', p('metadata', key));
          if (r.status === 404) return false;
          if (r.status >= 300) fail('delete', r.status);
          return true;
        },
      };
    }
    case 'infisical': {
      const workspaceId = opt<string>(o, 'workspaceId');
      const environment = opt<string>(o, 'environment');
      const secretPath = opt<string>(o, 'secretPath', '/');
      const qs = `workspaceId=${enc(workspaceId)}&environment=${enc(environment)}&secretPath=${enc(secretPath)}`;
      return {
        async read(call, key) {
          const r = await call('GET', `/api/v3/secrets/raw/${enc(key)}?${qs}`);
          if (r.status === 404) return undefined;
          if (r.status >= 300) fail('read', r.status);
          const v = jsonPointer(r.json, '/secret/secretValue');
          return v === undefined ? undefined : String(v);
        },
        async write(call, key, value) {
          const body = { workspaceId, environment, secretPath, secretValue: value, type: 'shared' };
          const existing = await call('GET', `/api/v3/secrets/raw/${enc(key)}?${qs}`);
          const r = await call(existing.status === 200 ? 'PATCH' : 'POST', `/api/v3/secrets/raw/${enc(key)}`, body);
          if (r.status >= 300) fail('write', r.status);
          return { action: existing.status === 200 ? 'updated' : 'created' };
        },
        async remove(call, key) {
          const r = await call('DELETE', `/api/v3/secrets/raw/${enc(key)}`, { workspaceId, environment, secretPath, type: 'shared' });
          if (r.status === 404) return false;
          if (r.status >= 300) fail('delete', r.status);
          return true;
        },
      };
    }
    case '1password-connect': {
      const vault = opt<string>(o, 'vaultId');
      const fieldLabel = opt<string>(o, 'field', 'credential');
      type Item = { id: string; fields?: { id?: string; label?: string; value?: string; type?: string; purpose?: string }[] };
      const find = async (call: RemoteCall, key: string): Promise<Item | undefined> => {
        const r = await call('GET', `/v1/vaults/${enc(vault)}/items?filter=${enc(`title eq "${key.replace(/"/g, '')}"`)}`);
        if (r.status >= 300) fail('lookup', r.status);
        const list = (Array.isArray(r.json) ? r.json : []) as Item[];
        if (!list[0]) return undefined;
        const full = await call('GET', `/v1/vaults/${enc(vault)}/items/${enc(list[0].id)}`);
        if (full.status >= 300) fail('read', full.status);
        return full.json as Item;
      };
      const pick = (it: Item) => it.fields?.find((f) => f.label === fieldLabel || f.id === fieldLabel);
      return {
        async read(call, key) {
          const it = await find(call, key);
          return it ? pick(it)?.value : undefined;
        },
        async write(call, key, value) {
          const it = await find(call, key);
          if (!it) {
            const r = await call('POST', `/v1/vaults/${enc(vault)}/items`, {
              vault: { id: vault },
              title: key,
              category: 'API_CREDENTIAL',
              fields: [{ id: fieldLabel, label: fieldLabel, type: 'CONCEALED', value }],
            });
            if (r.status >= 300) fail('write', r.status);
            return { action: 'created' };
          }
          const f = pick(it);
          if (f) f.value = value;
          else (it.fields ??= []).push({ id: fieldLabel, label: fieldLabel, type: 'CONCEALED', value });
          const r = await call('PUT', `/v1/vaults/${enc(vault)}/items/${enc(it.id)}`, it);
          if (r.status >= 300) fail('write', r.status);
          return { action: 'updated' };
        },
        async remove(call, key) {
          const it = await find(call, key);
          if (!it) return false;
          const r = await call('DELETE', `/v1/vaults/${enc(vault)}/items/${enc(it.id)}`);
          if (r.status >= 300) fail('delete', r.status);
          return true;
        },
      };
    }
    case 'ops-addon-settings': {
      // OPS (asteby-hq/ops): GET/PUT /api/addons/:key/settings, scoped to the
      // organization of the bearer token. Each secret name maps to a settings key.
      const addon = opt<string>(o, 'addon');
      const orgHeader = o.organizationHeader as { name: string; value: string } | undefined;
      const extra = orgHeader ? { [orgHeader.name]: orgHeader.value } : undefined;
      const path = `/api/addons/${enc(addon)}/settings`;
      return {
        async read(call, key) {
          const r = await call('GET', path, undefined, extra);
          if (r.status >= 300) fail('read', r.status);
          const v = jsonPointer(r.json, `/data/${key}`);
          return v === undefined || v === null || v === '' ? undefined : String(v);
        },
        async write(call, key, value) {
          const cur = await call('GET', path, undefined, extra);
          const existed = cur.status < 300 && jsonPointer(cur.json, `/data/${key}`) != null;
          const r = await call('PUT', path, { [key]: value }, extra);
          if (r.status >= 300) fail('write', r.status);
          return { action: existed ? 'updated' : 'created' };
        },
        async remove(call, key) {
          const r = await call('PUT', path, { [key]: null }, extra);
          if (r.status >= 300) fail('delete', r.status);
          return true;
        },
      };
    }
  }
}

export class HttpApiStore implements SecretStore {
  readonly type = 'http-api';
  readonly readable = true;
  private readonly adapter: RemoteAdapter;
  private readonly base: URL;

  constructor(
    readonly id: string,
    private readonly cfg: HttpApiConfig,
    private readonly resolveLocal: LocalResolver,
  ) {
    const allowed = cfg.allowedHosts.length ? cfg.allowedHosts : [new URL(cfg.baseUrl).hostname];
    this.base = checkUrl(cfg.baseUrl, { allowedHosts: allowed, allowInsecureLoopback: cfg.allowInsecureLoopback });
    this.adapter = makeAdapter(cfg.adapter, cfg.options);
  }

  private keyFor(name: string): string {
    const map = (this.cfg.options.keyMap ?? {}) as Record<string, string>;
    const prefix = (this.cfg.options.keyPrefix as string | undefined) ?? '';
    return map[name] ?? prefix + name;
  }

  private call: RemoteCall = async (method, path, body, extraHeaders) => {
    // Adapter paths are appended to baseUrl's path; the origin can never change.
    if (!path.startsWith('/') || path.includes('/../') || path.startsWith('//')) throw new UserError('invalid remote path', 'invalid_url');
    const full = new URL(this.base.pathname.replace(/\/$/, '') + path, this.base.origin);
    if (full.origin !== this.base.origin) throw new UserError('remote path escapes base URL', 'invalid_url');
    const headers: Record<string, string> = { accept: 'application/json', ...(extraHeaders ?? {}) };
    if (this.cfg.auth.scheme !== 'none') {
      if (!this.cfg.auth.tokenRef) throw new UserError(`destination ${this.id}: auth.tokenRef is required`, 'invalid_config');
      const token = await this.resolveLocal(this.cfg.auth.tokenRef);
      headers[this.cfg.auth.header.toLowerCase()] = this.cfg.auth.scheme === 'bearer' ? `Bearer ${token}` : token;
    }
    let payload: string | undefined;
    if (body !== undefined) {
      payload = JSON.stringify(body);
      headers['content-type'] = 'application/json';
    }
    let res: HttpResponse;
    try {
      res = await httpRequest({ method, url: full.href, headers, body: payload, timeoutMs: this.cfg.timeoutMs, maxResponseBytes: 1024 * 1024, caFile: this.cfg.caFile });
    } catch (e) {
      throw e instanceof UserError ? e : new UserError('remote store unreachable', 'network');
    }
    let json: unknown = undefined;
    try {
      json = res.body.length ? JSON.parse(res.body.toString('utf8')) : undefined;
    } catch {
      json = undefined;
    }
    return { status: res.status, json };
  };

  put(name: string, value: string): Promise<PutResult> {
    return this.adapter.write(this.call, this.keyFor(name), value);
  }

  get(name: string): Promise<string | undefined> {
    return this.adapter.read(this.call, this.keyFor(name));
  }

  delete(name: string): Promise<boolean> {
    return this.adapter.remove(this.call, this.keyFor(name));
  }

  describe(): string {
    return `remote ${this.cfg.adapter} API at ${this.base.origin}`;
  }
}
