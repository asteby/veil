import http from 'node:http';
import https from 'node:https';
import { readFileSync } from 'node:fs';
import { expandHome, globMatch, UserError } from './util.js';

export interface HttpRequest {
  method: string;
  url: string;
  headers?: Record<string, string>;
  body?: string | Buffer;
  timeoutMs?: number;
  maxResponseBytes?: number;
  caFile?: string;
}

export interface HttpResponse {
  status: number;
  headers: Record<string, string>;
  body: Buffer;
  truncated: boolean;
}

export interface UrlPolicy {
  allowedHosts: string[];
  allowInsecureLoopback?: boolean;
}

const LOOPBACK = new Set(['127.0.0.1', 'localhost', '[::1]', '::1']);

/** Enforces https (or loopback http when explicitly allowed) and the host allowlist. */
export function checkUrl(raw: string, policy: UrlPolicy): URL {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new UserError('invalid URL', 'invalid_url');
  }
  if (u.username || u.password) throw new UserError('credentials in URLs are not allowed; use headers with ${secret:...}', 'invalid_url');
  const loopback = LOOPBACK.has(u.hostname);
  if (u.protocol !== 'https:' && !(u.protocol === 'http:' && loopback && policy.allowInsecureLoopback)) {
    throw new UserError(`TLS is required (https://) for ${u.host}`, 'tls_required');
  }
  const hostOk = policy.allowedHosts.some((p) => globMatch(p, u.hostname) || globMatch(p, u.host));
  if (!hostOk) throw new UserError(`host ${u.host} is not in the allowlist`, 'host_not_allowed');
  return u;
}

/** Minimal HTTP client: no redirects are followed, bounded size and time. */
export function httpRequest(req: HttpRequest): Promise<HttpResponse> {
  return new Promise((resolve, reject) => {
    const u = new URL(req.url);
    const mod = u.protocol === 'https:' ? https : http;
    const max = req.maxResponseBytes ?? 256 * 1024;
    const body = req.body === undefined ? undefined : typeof req.body === 'string' ? Buffer.from(req.body) : req.body;
    const options: https.RequestOptions = {
      method: req.method.toUpperCase(),
      // explicit length: Node does not chunk-encode bodies of DELETE/GET by default
      headers: { 'user-agent': 'veilform', ...(req.headers ?? {}), ...(body ? { 'content-length': String(body.length) } : {}) },
      timeout: req.timeoutMs ?? 30_000,
    };
    if (req.caFile) options.ca = readFileSync(expandHome(req.caFile));
    const r = mod.request(u, options, (res) => {
      const chunks: Buffer[] = [];
      let len = 0;
      let truncated = false;
      res.on('data', (d: Buffer) => {
        if (len < max) {
          const take = d.subarray(0, max - len);
          chunks.push(take);
          len += take.length;
          if (take.length < d.length) truncated = true;
        } else {
          truncated = true;
        }
      });
      res.on('end', () => {
        const headers: Record<string, string> = {};
        for (const [k, v] of Object.entries(res.headers)) if (v !== undefined) headers[k] = Array.isArray(v) ? v.join(', ') : v;
        resolve({ status: res.statusCode ?? 0, headers, body: Buffer.concat(chunks), truncated });
      });
      res.on('error', reject);
    });
    r.on('timeout', () => r.destroy(new UserError('HTTP request timed out', 'timeout')));
    r.on('error', (e) => reject(e instanceof UserError ? e : new UserError(`HTTP request failed (${(e as NodeJS.ErrnoException).code ?? 'network'})`, 'network')));
    if (body) r.end(body);
    else r.end();
  });
}
