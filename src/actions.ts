import { readFileSync, existsSync } from 'node:fs';
import { z } from 'zod';
import type { Config } from './config.js';
import { parseEnv } from './fileformats.js';
import { checkUrl, httpRequest } from './net.js';
import type { Runner } from './proc.js';
import { Redactor } from './redact.js';
import { SECRET_REF, secretRefs } from './templates.js';
import { isOwnEnvVar } from './naming.js';
import { expandHome, ENV_KEY_RE, UserError } from './util.js';

export const ExecAction = z.object({
  action: z.literal('exec'),
  command: z.array(z.string()).min(1).optional().describe('argv, executed WITHOUT a shell. ${secret:..} is NOT allowed here; use env or stdin'),
  shell: z.string().optional().describe('POSIX sh script (needs explicit approval). ${secret:x} becomes an env var reference inside the child'),
  env: z.record(z.string(), z.string()).optional().describe('extra env vars; values may contain ${secret:name}'),
  stdin: z.string().optional().describe('data for the child stdin; may contain ${secret:name}'),
  cwd: z.string().optional(),
  timeout_ms: z.number().int().positive().optional(),
  redact_env_files: z.array(z.string()).optional().describe('also redact every value found in these .env files from the output'),
});

export const HttpAction = z.object({
  action: z.literal('http'),
  method: z.string().default('GET'),
  url: z.string().describe('may contain ${secret:name} (e.g. in a query parameter)'),
  headers: z.record(z.string(), z.string()).optional(),
  body: z.string().optional(),
  timeout_ms: z.number().int().positive().optional(),
});

export const UseAction = z.discriminatedUnion('action', [ExecAction, HttpAction]);
export type UseActionT = z.infer<typeof UseAction>;

export function actionSecretRefs(a: UseActionT): string[] {
  if (a.action === 'exec') {
    for (const tok of a.command ?? []) if (secretRefs(tok).length) throw new UserError('${secret:...} is not allowed in argv (it would be visible in the process list); pass it through env or stdin, or use shell', 'secret_in_argv');
    return secretRefs(a.shell, a.stdin, ...Object.values(a.env ?? {}));
  }
  return secretRefs(a.url, a.body, ...Object.values(a.headers ?? {}));
}

/** The value-free plan that is fingerprinted and shown literally for approval. */
export function actionPlan(a: UseActionT): Record<string, unknown> {
  if (a.action === 'exec') {
    return { action: 'exec', command: a.command, shell: a.shell, env: a.env, stdin: a.stdin, cwd: a.cwd, secrets: actionSecretRefs(a) };
  }
  return { action: 'http', method: a.method.toUpperCase(), url: a.url, headers: a.headers, body: a.body, secrets: actionSecretRefs(a) };
}

export function actionLiteral(a: UseActionT): string {
  if (a.action === 'exec') {
    const lines: string[] = [];
    if (a.cwd) lines.push(`cd ${a.cwd}`);
    for (const [k, v] of Object.entries(a.env ?? {})) lines.push(`env ${k}=${v}`);
    if (a.command) lines.push(`exec (no shell): ${JSON.stringify(a.command)}`);
    if (a.shell) lines.push(`sh -c <<'SCRIPT'\n${a.shell}\nSCRIPT`);
    if (a.stdin !== undefined) lines.push(`stdin: ${a.stdin}`);
    return lines.join('\n');
  }
  const lines = [`${a.method.toUpperCase()} ${a.url}`];
  for (const [k, v] of Object.entries(a.headers ?? {})) lines.push(`${k}: ${v}`);
  if (a.body !== undefined) lines.push('', a.body);
  return lines.join('\n');
}

export function actionWarnings(a: UseActionT, lang: 'en' | 'es'): string[] {
  const w: string[] = [];
  const es = lang === 'es';
  if (a.action === 'exec' && a.shell) {
    w.push(es ? 'Usa un shell: el script puede pasar el secreto a otros programas o enviarlo a la red. Revísalo línea por línea.' : 'Runs a shell: the script can pass the secret to other programs or send it over the network. Review it line by line.');
    if (/\b(curl|wget|nc|ncat|socat|ssh|scp|base64|xxd|openssl)\b/.test(a.shell)) w.push(es ? 'El script usa herramientas de red o codificación.' : 'The script uses network or encoding tools.');
  }
  if (a.action === 'exec' && a.command && /^(sh|bash|zsh|dash|python3?|node|perl|ruby)$/.test(a.command[0]!.split('/').pop()!)) {
    w.push(es ? 'El comando es un intérprete: los argumentos pueden ejecutar código arbitrario.' : 'The command is an interpreter: its arguments can run arbitrary code.');
  }
  if (a.action === 'http') w.push(es ? `El valor se enviará a ${safeHost(a.url)}.` : `The value will be sent to ${safeHost(a.url)}.`);
  return w;
}

function safeHost(u: string): string {
  try {
    return new URL(u.replace(SECRET_REF, 'x')).host;
  } catch {
    return '?';
  }
}

function subst(tpl: string, secrets: Map<string, string>): string {
  return tpl.replace(SECRET_REF, (_m, ref: string) => {
    const v = secrets.get(ref);
    if (v === undefined) throw new UserError(`secret ${ref} not resolved`, 'internal');
    return v;
  });
}

function envFileValues(files: string[]): { label: string; value: string }[] {
  const out: { label: string; value: string }[] = [];
  for (const f of files) {
    const p = expandHome(f);
    if (!existsSync(p)) continue;
    for (const e of parseEnv(readFileSync(p, 'utf8'))) if (e.value.length >= 4) out.push({ label: e.key, value: e.value });
  }
  return out;
}

export interface ExecResultSafe {
  exit_code: number | null;
  signal: string | null;
  timed_out: boolean;
  stdout: string;
  stderr: string;
  stdout_truncated: boolean;
  stderr_truncated: boolean;
}

export async function runExec(a: z.infer<typeof ExecAction>, secrets: Map<string, string>, cfg: Config, runner: Runner): Promise<ExecResultSafe> {
  if (!a.command && !a.shell) throw new UserError('exec needs command (argv) or shell', 'invalid_args');
  if (a.command && a.shell) throw new UserError('use either command or shell, not both', 'invalid_args');
  if (a.shell && !cfg.exec.allowShell) throw new UserError('shell execution is disabled in config', 'shell_disabled');
  const env: NodeJS.ProcessEnv = { ...process.env };
  // Never leak this server's own bootstrap material to children.
  for (const k of Object.keys(env)) if (isOwnEnvVar(k)) delete env[k];
  for (const d of Object.values(cfg.destinations)) if (d.type === 'encrypted-file' && d.key.source === 'env') delete env[d.key.env];
  for (const [k, v] of Object.entries(a.env ?? {})) {
    if (!ENV_KEY_RE.test(k)) throw new UserError(`invalid env name ${k}`, 'invalid_args');
    env[k] = subst(v, secrets);
  }
  let argv: string[];
  if (a.shell) {
    // ${secret:x} → "${SI_SECRET_n}" expanded by the child shell; the value is never in our argv.
    const refs = secretRefs(a.shell);
    let script = a.shell;
    refs.forEach((ref, i) => {
      env[`SI_SECRET_${i}`] = secrets.get(ref);
      script = script.split(`\${secret:${ref}}`).join(`\${SI_SECRET_${i}}`);
    });
    argv = ['/bin/sh', '-c', script];
  } else argv = a.command!;
  const timeout = Math.min(a.timeout_ms ?? cfg.exec.defaultTimeoutMs, cfg.exec.maxTimeoutMs);
  const res = await runner(argv, { env, cwd: a.cwd ? expandHome(a.cwd) : undefined, stdin: a.stdin !== undefined ? subst(a.stdin, secrets) : undefined, timeoutMs: timeout, maxOutputBytes: cfg.exec.maxOutputBytes });
  const red = new Redactor([...[...secrets].map(([label, value]) => ({ label, value })), ...envFileValues([...cfg.exec.redactEnvFiles, ...(a.redact_env_files ?? [])])]);
  return {
    exit_code: res.code,
    signal: res.signal,
    timed_out: res.timedOut,
    stdout: red.redact(res.stdout.toString('utf8'), { truncated: res.stdoutTruncated }),
    stderr: red.redact(res.stderr.toString('utf8'), { truncated: res.stderrTruncated }),
    stdout_truncated: res.stdoutTruncated,
    stderr_truncated: res.stderrTruncated,
  };
}

export async function runHttp(a: z.infer<typeof HttpAction>, secrets: Map<string, string>, cfg: Config): Promise<Record<string, unknown>> {
  const url = subst(a.url, secrets);
  checkUrl(url, { allowedHosts: cfg.http.allowedHosts, allowInsecureLoopback: cfg.http.allowInsecureLoopback });
  const headers: Record<string, string> = {};
  for (const [k, v] of Object.entries(a.headers ?? {})) headers[k] = subst(v, secrets);
  const res = await httpRequest({ method: a.method, url, headers, body: a.body !== undefined ? subst(a.body, secrets) : undefined, timeoutMs: Math.min(a.timeout_ms ?? cfg.http.timeoutMs, cfg.http.timeoutMs * 4), maxResponseBytes: cfg.http.maxResponseBytes });
  const red = new Redactor([...secrets].map(([label, value]) => ({ label, value })));
  const keepHeaders = ['content-type', 'content-length', 'location', 'retry-after', 'x-request-id'];
  return {
    http_status: res.status,
    headers: Object.fromEntries(Object.entries(res.headers).filter(([k]) => keepHeaders.includes(k)).map(([k, v]) => [k, red.redact(v)])),
    body: red.redact(res.body.toString('utf8'), { truncated: res.truncated }),
    body_truncated: res.truncated,
  };
}
