import type { FieldValue, MoneyValue, Values, FileValue } from './schema.js';
import { UserError } from './util.js';

/** `${secret:name}` or `${secret:destination:name}` */
export const SECRET_REF = /\$\{secret:([A-Za-z0-9_.-]+(?::[A-Za-z0-9_.-]+)?)\}/g;
/** `${field}` or `${field.sub}` (sub = currency | name | type | size for money/file) */
export const FIELD_REF = /\$\{(?!secret:)([A-Za-z_][A-Za-z0-9_]*)(?:\.([A-Za-z_][A-Za-z0-9_]*))?\}/g;

export function secretRefs(...templates: (string | undefined)[]): string[] {
  const out = new Set<string>();
  for (const t of templates) if (t) for (const m of t.matchAll(SECRET_REF)) out.add(m[1]!);
  return [...out].sort();
}

export function secretRefsDeep(v: unknown): string[] {
  const out = new Set<string>();
  walkStrings(v, (s) => secretRefs(s).forEach((r) => out.add(r)));
  return [...out].sort();
}

export function walkStrings(v: unknown, fn: (s: string) => void): void {
  if (typeof v === 'string') fn(v);
  else if (Array.isArray(v)) v.forEach((x) => walkStrings(x, fn));
  else if (v && typeof v === 'object') Object.values(v).forEach((x) => walkStrings(x, fn));
}

export function fieldRefsDeep(v: unknown): string[] {
  const out = new Set<string>();
  walkStrings(v, (s) => {
    for (const m of s.matchAll(FIELD_REF)) out.add(m[1]!);
  });
  return [...out];
}

export interface RenderCtx {
  /** row scope first, then top-level values */
  scopes: Values[];
  secrets?: Map<string, string>;
}

function lookup(ctx: RenderCtx, name: string): FieldValue | undefined {
  for (const s of ctx.scopes) if (Object.prototype.hasOwnProperty.call(s, name)) return s[name];
  return undefined;
}

function isMoney(v: unknown): v is MoneyValue {
  return Boolean(v && typeof v === 'object' && 'amount' in (v as object) && 'currency' in (v as object));
}
function isFile(v: unknown): v is FileValue {
  return Boolean(v && typeof v === 'object' && 'data' in (v as object) && Buffer.isBuffer((v as FileValue).data));
}

/** Typed value for `${x}` / `${x.sub}`. */
export function typedValue(ctx: RenderCtx, name: string, sub?: string): unknown {
  const v = lookup(ctx, name);
  if (v === undefined) throw new UserError(`template references unknown field "${name}"`, 'unknown_field');
  if (isMoney(v)) return sub === 'currency' ? v.currency : v.amount;
  if (isFile(v)) {
    if (sub === 'name') return v.name;
    if (sub === 'type') return v.type;
    if (sub === 'size') return v.size;
    return v.data.toString('base64');
  }
  if (sub) throw new UserError(`field "${name}" has no ".${sub}"`, 'unknown_field');
  return v;
}

export function stringify(v: unknown): string {
  if (v === null || v === undefined) return '';
  if (Array.isArray(v)) return v.map(stringify).join(',');
  return String(v);
}

export function renderString(tpl: string, ctx: RenderCtx): string {
  return tpl
    .replace(SECRET_REF, (_m, ref: string) => {
      const v = ctx.secrets?.get(ref);
      if (v === undefined) throw new UserError(`secret "${ref}" was not resolved`, 'internal');
      return v;
    })
    .replace(FIELD_REF, (_m, name: string, sub?: string) => stringify(typedValue(ctx, name, sub)));
}

/** JSON template: a string that is exactly `${x}` keeps x's JSON type. */
export function renderJson(tpl: unknown, ctx: RenderCtx): unknown {
  if (typeof tpl === 'string') {
    const exact = /^\$\{(?!secret:)([A-Za-z_][A-Za-z0-9_]*)(?:\.([A-Za-z_][A-Za-z0-9_]*))?\}$/.exec(tpl);
    if (exact) {
      const v = typedValue(ctx, exact[1]!, exact[2]);
      return isMoney(v) ? v.amount : v;
    }
    return renderString(tpl, ctx);
  }
  if (Array.isArray(tpl)) return tpl.map((x) => renderJson(x, ctx));
  if (tpl && typeof tpl === 'object') return Object.fromEntries(Object.entries(tpl).map(([k, v]) => [k, renderJson(v, ctx)]));
  return tpl;
}

/** Shows a template with placeholders exactly as written (for approval pages). */
export function showTemplate(v: unknown): string {
  return typeof v === 'string' ? v : JSON.stringify(v, null, 2);
}

/** Converts form values to a plain JSON object (files as base64), for callbacks. */
export function valuesToJson(values: Values): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(values)) {
    if (isFile(v)) out[k] = { name: v.name, type: v.type, size: v.size, base64: v.data.toString('base64') };
    else out[k] = v;
  }
  return out;
}
