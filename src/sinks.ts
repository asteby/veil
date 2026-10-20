import { z } from 'zod';
import type { Config, DatabaseConfig } from './config.js';
import { checkUrl, httpRequest } from './net.js';
import type { Runner } from './proc.js';
import type { FieldDef, NormalizedSchema, Values, FieldError } from './schema.js';
import { allFields } from './schema.js';
import type { Ssh } from './ssh.js';
import { checkTargetAllowed, describeTarget, TargetSchema, type TargetWriter } from './targets.js';
import { fieldRefsDeep, renderJson, renderString, secretRefsDeep, showTemplate, stringify, typedValue, valuesToJson } from './templates.js';
import { jsonPointer } from './stores/http-api.js';
import { sha256Hex, UserError } from './util.js';
import type { Vault, MetaInput } from './vault.js';

/** Where blind_input values go. The model describes the sink; values never return. */
export const SinkSchema = z.discriminatedUnion('type', [
  z.object({
    type: z.literal('store'),
    destination: z.union([z.string(), z.array(z.string()).min(1)]).optional().describe('destination id(s) from config; default = defaultDestination'),
    names: z.record(z.string(), z.string()).optional().describe('field → secret name (default: field name)'),
  }),
  z.object({
    type: z.literal('http'),
    method: z.enum(['POST', 'PUT', 'PATCH']).default('POST'),
    url: z.string(),
    headers: z.record(z.string(), z.string()).optional(),
    body: z.unknown().optional().describe('JSON template; "${field}" keeps the JSON type; ${secret:name} allowed'),
    each: z.string().optional().describe('repeater field: one request per row'),
    id_pointer: z.string().optional().describe('JSON pointer of the created id in the response, e.g. /data/id'),
    expect_status: z.array(z.number().int()).optional(),
  }),
  z.object({
    type: z.literal('sql'),
    database: z.string().describe('databases.<id> from config'),
    table: z.string(),
    mode: z.enum(['insert', 'upsert']).default('insert'),
    columns: z.record(z.string(), z.string()).describe('column → template, e.g. {"sku": "${sku}", "currency": "USD"}'),
    rows: z.string().optional().describe('repeater field: one row per entry (otherwise a single row)'),
    dry_run: z.boolean().optional().describe('validate inside a transaction and ROLLBACK; reports row count'),
  }),
  z.object({
    type: z.literal('file'),
    target: TargetSchema.describe('env-file / json / yaml / systemd target (allowlisted)'),
    mapping: z.record(z.string(), z.string()).describe('field → key in the file'),
  }),
  z.object({
    type: z.literal('ops-dataload'),
    model: z.string(),
    rows: z.string().optional(),
    columns: z.record(z.string(), z.string()).optional(),
  }),
  z.object({
    type: z.literal('callback'),
    url: z.string(),
    headers: z.record(z.string(), z.string()).optional(),
  }),
]);
export type Sink = z.infer<typeof SinkSchema>;

export interface SinkResult {
  rows_written?: number;
  ids?: string[];
  stored?: string[];
  keys?: { key: string; action: string }[];
  field_errors?: FieldError[];
  http_statuses?: number[];
  dry_run?: boolean;
  rows_validated?: number;
}

export interface SinkDeps {
  cfg: Config;
  vault: Vault;
  runner: Runner;
  ssh: Ssh;
  writer: TargetWriter;
}

export interface SinkPlan {
  type: Sink['type'];
  /** Value-free plan (fingerprinted). */
  plan: Record<string, unknown>;
  /** Lines shown to the person on the form page. */
  lines: { label: string; value: string }[];
  /** true when the person must explicitly confirm (unless remembered). */
  requiresApproval: boolean;
  execute(values: Values, requestId: string, meta: MetaInput): Promise<SinkResult>;
}

const IDENT = /^[A-Za-z_][A-Za-z0-9_]{0,62}$/;

function qIdent(s: string): string {
  if (!IDENT.test(s)) throw new UserError(`invalid SQL identifier ${s}`, 'invalid_identifier');
  return `"${s}"`;
}

function qTable(t: string): string {
  return t.split('.').map(qIdent).join('.');
}

/** Ids that equal a submitted value are replaced by a short hash so values never echo back. */
function safeIds(ids: unknown[], values: Values): string[] {
  const submitted = new Set<string>();
  const add = (v: unknown) => {
    if (v === null || v === undefined) return;
    if (typeof v === 'object' && !Array.isArray(v)) {
      for (const x of Object.values(v as object)) add(x);
    } else if (Array.isArray(v)) v.forEach(add);
    else submitted.add(String(v));
  };
  Object.values(values).forEach(add);
  return ids.map((id) => {
    const s = String(id);
    return submitted.has(s) || s.length > 200 ? `h:${sha256Hex(s).slice(0, 12)}` : s;
  });
}

function checkRefs(schema: NormalizedSchema, template: unknown, rowsField?: string): void {
  const top = new Map(allFields(schema).map((f) => [f.name, f] as const));
  const rowCols = rowsField ? new Set((top.get(rowsField)?.fields ?? []).map((c) => c.name)) : new Set<string>();
  if (rowsField) {
    const r = top.get(rowsField);
    if (!r || r.kind !== 'repeater') throw new UserError(`"${rowsField}" is not a repeater field`, 'invalid_sink');
  }
  for (const ref of fieldRefsDeep(template)) {
    if (!top.has(ref) && !rowCols.has(ref)) throw new UserError(`sink template references unknown field "${ref}"`, 'invalid_sink');
  }
}

function rowsOf(values: Values, rowsField?: string): { scopes: Values[] }[] {
  if (!rowsField) return [{ scopes: [values] }];
  const rows = (values[rowsField] as Record<string, unknown>[] | null) ?? [];
  return rows.map((r) => ({ scopes: [r as Values, values] }));
}

export function planSink(sink: Sink, schema: NormalizedSchema, d: SinkDeps): SinkPlan {
  const fields = allFields(schema);
  switch (sink.type) {
    case 'store': {
      const dests = sink.destination === undefined ? [d.cfg.defaultDestination] : Array.isArray(sink.destination) ? sink.destination : [sink.destination];
      const stores = dests.map((id) => d.vault.store(id));
      const scalar = fields.filter((f) => f.kind !== 'repeater' && f.kind !== 'file');
      const nameOf = (f: FieldDef) => sink.names?.[f.name] ?? f.name;
      return {
        type: 'store',
        plan: { type: 'store', destinations: dests, names: scalar.map(nameOf) },
        lines: [
          ...stores.map((s) => ({ label: s.id, value: s.describe() })),
          { label: 'names', value: scalar.map(nameOf).join(', ') },
        ],
        requiresApproval: false,
        async execute(values, _req, meta) {
          const stored: string[] = [];
          for (const f of scalar) {
            const v = values[f.name];
            if (v === null || v === undefined || v === '') continue;
            const value = typeof v === 'object' && v && 'amount' in v ? String((v as { amount: string }).amount) : stringify(v);
            for (const dest of dests) await d.vault.put(dest, nameOf(f), value, { ...meta, field: { label: f.label, kind: f.kind, help: f.help, pattern: f.pattern } });
            stored.push(nameOf(f));
          }
          return { stored };
        },
      };
    }
    case 'http':
    case 'callback':
    case 'ops-dataload': {
      let method: string, url: string, headers: Record<string, string>, body: unknown, each: string | undefined, idPointer: string | undefined, expect: number[] | undefined;
      let insecure = d.cfg.http.allowInsecureLoopback;
      let allowedHosts = d.cfg.http.allowedHosts;
      let authRef: string | undefined;
      if (sink.type === 'http') {
        ({ method, url } = sink);
        headers = sink.headers ?? {};
        body = sink.body;
        each = sink.each;
        idPointer = sink.id_pointer;
        expect = sink.expect_status;
      } else if (sink.type === 'callback') {
        method = 'POST';
        url = sink.url;
        headers = sink.headers ?? {};
        body = undefined;
        each = undefined;
        idPointer = undefined;
        expect = undefined;
      } else {
        if (!d.cfg.ops.baseUrl) throw new UserError('ops.baseUrl is not configured', 'invalid_config');
        method = 'POST';
        url = d.cfg.ops.baseUrl.replace(/\/$/, '') + '/api/dataload';
        headers = {};
        allowedHosts = [new URL(d.cfg.ops.baseUrl).host, new URL(d.cfg.ops.baseUrl).hostname];
        insecure = d.cfg.ops.allowInsecureLoopback;
        authRef = d.cfg.ops.tokenRef;
        body = { model: sink.model, rows: sink.rows ? `one entry per row of ${sink.rows}` : 'single row', columns: sink.columns ?? 'all form fields' };
        each = undefined;
        idPointer = '/data/ids';
        expect = undefined;
      }
      checkUrl(url.replace(/\$\{[^}]+\}/g, 'x'), { allowedHosts, allowInsecureLoopback: insecure });
      if (sink.type === 'http') checkRefs(schema, { url, headers, body }, each);
      if (sink.type === 'ops-dataload' && sink.columns) checkRefs(schema, sink.columns, sink.rows);
      const secretNames = secretRefsDeep({ url, headers, body });
      const plan = { type: sink.type, method, url, headers, body, each, rows: sink.type === 'ops-dataload' ? sink.rows : undefined, secrets: secretNames };
      return {
        type: sink.type,
        plan,
        lines: [
          { label: 'request', value: `${method} ${url}` },
          ...Object.entries(headers).map(([k, v]) => ({ label: `header ${k}`, value: v })),
          ...(sink.type === 'callback' ? [{ label: 'body', value: 'JSON with all form values' }] : body !== undefined ? [{ label: 'body', value: showTemplate(body) }] : []),
          ...(each ? [{ label: 'each', value: `one request per row of ${each}` }] : []),
        ],
        requiresApproval: true,
        async execute(values, requestId) {
          const secrets = new Map<string, string>();
          for (const ref of secretNames) secrets.set(ref, (await d.vault.resolve(ref)).value);
          const auth = authRef ? (await d.vault.resolve(authRef)).value : undefined;
          const statuses: number[] = [];
          const ids: unknown[] = [];
          const field_errors: FieldError[] = [];
          let written = 0;
          const units = each ? rowsOf(values, each) : [{ scopes: [values] }];
          for (let i = 0; i < units.length; i++) {
            const ctx = { scopes: units[i]!.scopes, secrets };
            let payload: unknown;
            if (sink.type === 'callback') payload = { request_id: requestId, values: valuesToJson(values) };
            else if (sink.type === 'ops-dataload') {
              const rowsList = sink.rows ? rowsOf(values, sink.rows) : [{ scopes: [values] }];
              payload = {
                model: sink.model,
                rows: rowsList.map((r) => (sink.columns ? (renderJson(sink.columns, { scopes: r.scopes }) as object) : valuesToJson(r.scopes[0]!))),
              };
            } else payload = body === undefined ? undefined : renderJson(body, ctx);
            const h: Record<string, string> = {};
            for (const [k, v] of Object.entries(headers)) h[k] = renderString(v, ctx);
            if (auth) h.authorization = `Bearer ${auth}`;
            if (payload !== undefined) h['content-type'] = 'application/json';
            const res = await httpRequest({ method, url: renderString(url, ctx), headers: h, body: payload === undefined ? undefined : JSON.stringify(payload), timeoutMs: d.cfg.http.timeoutMs, maxResponseBytes: d.cfg.http.maxResponseBytes });
            statuses.push(res.status);
            const ok = expect ? expect.includes(res.status) : res.status >= 200 && res.status < 300;
            if (!ok) {
              field_errors.push({ field: each ? `${each}[${i}]` : '_request', code: `http_${res.status}` });
              continue;
            }
            written += sink.type === 'ops-dataload' ? ((payload as { rows: unknown[] }).rows.length) : 1;
            if (idPointer) {
              try {
                const v = jsonPointer(JSON.parse(res.body.toString('utf8')), idPointer);
                if (Array.isArray(v)) ids.push(...v);
                else if (v !== undefined && v !== null) ids.push(v);
              } catch {
                /* non-JSON response: no ids */
              }
            }
          }
          return { rows_written: written, ids: ids.length ? safeIds(ids, values) : undefined, http_statuses: statuses, field_errors: field_errors.length ? field_errors : undefined };
        },
      };
    }
    case 'sql': {
      const db = d.cfg.databases[sink.database];
      if (!db) throw new UserError(`database "${sink.database}" is not configured (allowlist)`, 'database_not_allowed');
      const table = db.tables[sink.table];
      if (!table) throw new UserError(`table "${sink.table}" is not allowed for ${sink.database}`, 'table_not_allowed');
      const cols = Object.keys(sink.columns);
      for (const c of cols) if (!table.columns.includes(c)) throw new UserError(`column "${c}" is not allowed in ${sink.table}`, 'column_not_allowed');
      if (sink.mode === 'upsert' && !table.conflict?.length) throw new UserError(`upsert needs "conflict" columns configured for ${sink.table}`, 'invalid_sink');
      checkRefs(schema, sink.columns, sink.rows);
      if (secretRefsDeep(sink.columns).length) throw new UserError('${secret:...} is not allowed in SQL column templates', 'invalid_sink');
      const script = buildSqlScript(sink.table, cols, sink.mode, table.conflict, table.returning, Boolean(sink.dry_run));
      const plan = { type: 'sql', database: sink.database, table: sink.table, mode: sink.mode, columns: sink.columns, rows: sink.rows };
      return {
        type: 'sql',
        plan,
        lines: [
          { label: 'database', value: `${sink.database}${db.ssh ? ` (via ssh ${db.ssh})` : ''}` },
          { label: 'statement', value: script.sqlPreview },
          { label: 'columns', value: Object.entries(sink.columns).map(([c, t]) => `${c} ← ${t}`).join('\n') },
          ...(sink.dry_run ? [{ label: 'dry run', value: 'validate and ROLLBACK (nothing is written)' }] : []),
        ],
        requiresApproval: true,
        async execute(values) {
          const units = rowsOf(values, sink.rows);
          if (units.length > db.maxRows) return { field_errors: [{ field: sink.rows ?? '_rows', code: 'too_many_rows' }] };
          const csv = units.map((u) => cols.map((c) => csvCell(renderCell(sink.columns[c]!, { scopes: u.scopes }))).join(',')).join('\n');
          const out = await runPsql(db, d, script.script(csv), Boolean(table.returning));
          if (out.error) return { rows_written: 0, field_errors: [{ field: '_sql', code: out.error }], dry_run: sink.dry_run || undefined };
          if (sink.dry_run) return { rows_written: 0, rows_validated: out.count, dry_run: true };
          return { rows_written: out.count, ids: out.ids.length ? safeIds(out.ids, values) : undefined };
        },
      };
    }
    case 'file': {
      const t = sink.target;
      if (!['env-file', 'json', 'yaml', 'systemd'].includes(t.kind)) throw new UserError('file sink supports env-file, json, yaml and systemd targets', 'invalid_sink');
      for (const f of Object.keys(sink.mapping)) if (!fields.some((x) => x.name === f && x.kind !== 'repeater' && x.kind !== 'file')) throw new UserError(`mapping references unknown or unsupported field "${f}"`, 'invalid_sink');
      const keys = Object.values(sink.mapping);
      checkTargetAllowed(d.cfg, t, keys);
      return {
        type: 'file',
        plan: { type: 'file', target: t, mapping: sink.mapping },
        lines: [
          ...Object.entries(describeTarget(t)).map(([k, v]) => ({ label: k, value: String(v) })),
          { label: 'keys', value: Object.entries(sink.mapping).map(([f, k]) => `${k} ← ${f}`).join('\n') },
        ],
        requiresApproval: true,
        async execute(values) {
          const entries = Object.entries(sink.mapping)
            .filter(([f]) => values[f] !== null && values[f] !== undefined)
            .map(([f, key]) => ({ key, value: stringify(typedValue({ scopes: [values] }, f)) }));
          const keysOut = await d.writer.write(t, entries);
          return { keys: keysOut, rows_written: keysOut.length };
        },
      };
    }
  }
}

function renderCell(tpl: string, ctx: { scopes: Values[] }): unknown {
  const exact = /^\$\{([A-Za-z_][A-Za-z0-9_]*)(?:\.([A-Za-z_][A-Za-z0-9_]*))?\}$/.exec(tpl);
  if (exact) return typedValue(ctx, exact[1]!, exact[2]);
  return renderString(tpl, ctx);
}

/** CSV cell for COPY ... (FORMAT csv): NULL = unquoted empty; everything else quoted. */
export function csvCell(v: unknown): string {
  if (v === null || v === undefined) return '';
  let s: string;
  if (typeof v === 'boolean') s = v ? 't' : 'f';
  else if (Array.isArray(v)) s = `{${v.map((x) => `"${String(x).replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`).join(',')}}`;
  else s = String(v);
  return `"${s.replace(/"/g, '""')}"`;
}

/**
 * Values never become SQL text: they are streamed as CSV data to
 * `COPY si_in FROM STDIN` (a temp table typed LIKE the target columns), then
 * INSERT ... SELECT from it inside one transaction. Errors are reported only as
 * SQLSTATE codes (VERBOSITY sqlstate), so constraint messages cannot echo values.
 */
export function buildSqlScript(table: string, cols: string[], mode: 'insert' | 'upsert', conflict: string[] | undefined, returning: string | undefined, dryRun: boolean) {
  const qt = qTable(table);
  const qc = cols.map(qIdent).join(', ');
  const upsert =
    mode === 'upsert'
      ? ` ON CONFLICT (${conflict!.map(qIdent).join(', ')}) DO UPDATE SET ${cols.filter((c) => !conflict!.includes(c)).map((c) => `${qIdent(c)} = EXCLUDED.${qIdent(c)}`).join(', ') || `${qIdent(conflict![0]!)} = EXCLUDED.${qIdent(conflict![0]!)}`}`
      : '';
  const ret = returning ? qIdent(returning) : '1';
  const insert = `WITH si_ins AS (INSERT INTO ${qt} (${qc}) SELECT ${qc} FROM si_in${upsert} RETURNING ${ret} AS si_id) SELECT 'SI_ID', si_id::text FROM si_ins;`;
  const sqlPreview = `INSERT INTO ${qt} (${qc}) VALUES (<parameters from the form>)${upsert}${returning ? ` RETURNING ${qIdent(returning)}` : ''}`;
  return {
    sqlPreview,
    script: (csv: string) =>
      [
        '\\set ON_ERROR_STOP on',
        '\\set VERBOSITY sqlstate',
        '\\set QUIET on',
        '\\pset format unaligned',
        '\\pset tuples_only on',
        'BEGIN;',
        `CREATE TEMP TABLE si_in ON COMMIT DROP AS SELECT ${qc} FROM ${qt} WITH NO DATA;`,
        `COPY si_in (${qc}) FROM STDIN WITH (FORMAT csv);`,
        ...(csv ? [csv] : []),
        '\\.',
        insert,
        dryRun ? 'ROLLBACK;' : 'COMMIT;',
        '',
      ].join('\n'),
  };
}

function parseDsn(dsn: string): NodeJS.ProcessEnv {
  const u = new URL(dsn);
  if (!/^postgres(ql)?:$/.test(u.protocol)) throw new UserError('dsnSecret must be a postgres:// URL', 'invalid_config');
  const env: NodeJS.ProcessEnv = {};
  if (u.hostname) env.PGHOST = decodeURIComponent(u.hostname);
  if (u.port) env.PGPORT = u.port;
  if (u.username) env.PGUSER = decodeURIComponent(u.username);
  if (u.password) env.PGPASSWORD = decodeURIComponent(u.password);
  const db = u.pathname.replace(/^\//, '');
  if (db) env.PGDATABASE = decodeURIComponent(db);
  const ssl = u.searchParams.get('sslmode');
  if (ssl) env.PGSSLMODE = ssl;
  return env;
}

async function runPsql(db: DatabaseConfig, d: SinkDeps, script: string, hasReturning: boolean): Promise<{ count: number; ids: string[]; error?: string }> {
  const psqlArgs = [...db.psql, '-X', '-q', '-v', 'ON_ERROR_STOP=1', '-f', '-'];
  let res;
  if (db.ssh) {
    res = await d.ssh.script(db.ssh, '"$@"', psqlArgs, { stdin: script, timeoutMs: 300_000, maxOutputBytes: 4 * 1024 * 1024 });
  } else {
    const env: NodeJS.ProcessEnv = { ...process.env, PGAPPNAME: 'secret-intake-mcp' };
    if (db.dsnSecret) Object.assign(env, parseDsn((await d.vault.resolve(db.dsnSecret)).value));
    if (db.passwordSecret) env.PGPASSWORD = (await d.vault.resolve(db.passwordSecret)).value;
    res = await d.runner(psqlArgs, { stdin: script, env, timeoutMs: 300_000, maxOutputBytes: 4 * 1024 * 1024 });
  }
  if (res.code !== 0) {
    const m = /ERROR:\s+([0-9A-Z]{5})/.exec(res.stderr.toString('utf8'));
    return { count: 0, ids: [], error: m ? `sql_${m[1]}` : res.timedOut ? 'sql_timeout' : `psql_exit_${res.code}` };
  }
  const ids: string[] = [];
  let count = 0;
  for (const line of res.stdout.toString('utf8').split('\n')) {
    const m = /^SI_ID\|(.*)$/.exec(line);
    if (m) {
      count++;
      ids.push(m[1]!);
    }
  }
  return { count, ids: hasReturning ? ids : [] };
}
