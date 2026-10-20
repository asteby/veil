import { z } from 'zod';
import { UserError } from './util.js';

/**
 * Form schema for blind input. The model sends ONLY this metadata; the person
 * fills the values in a local page. Values never come back to the model.
 */
export const FIELD_KINDS = ['text', 'number', 'money', 'date', 'select', 'multiselect', 'boolean', 'textarea', 'secret', 'file', 'repeater'] as const;
export type FieldKind = (typeof FIELD_KINDS)[number];

const FieldName = z.string().regex(/^[A-Za-z_][A-Za-z0-9_]{0,63}$/, 'field names: letters, digits, underscore');

const Option = z.union([z.string(), z.object({ value: z.string(), label: z.string() })]);

const Condition = z.object({
  field: FieldName,
  equals: z.union([z.string(), z.boolean(), z.number()]).optional(),
  in: z.array(z.string()).optional(),
  notEmpty: z.boolean().optional(),
});

const BaseField = z.object({
  name: FieldName,
  label: z.string().min(1).max(200),
  kind: z.enum(FIELD_KINDS).default('text'),
  required: z.boolean().optional(),
  help: z.string().max(1000).optional(),
  placeholder: z.string().max(200).optional(),
  pattern: z.string().max(500).optional(),
  min: z.number().optional(),
  max: z.number().optional(),
  minLength: z.number().int().min(0).optional(),
  maxLength: z.number().int().positive().max(100_000).optional(),
  step: z.number().positive().optional(),
  options: z.array(Option).max(500).optional(),
  currency: z.string().regex(/^[A-Z]{3}$/).optional(),
  currencies: z.array(z.string().regex(/^[A-Z]{3}$/)).max(20).optional(),
  showIf: Condition.optional(),
  accept: z.array(z.string().max(100)).max(20).optional(),
  maxBytes: z.number().int().positive().max(10 * 1024 * 1024).optional(),
  default: z.union([z.string(), z.number(), z.boolean()]).optional().describe('initial value (non-secret fields only)'),
});

export const LeafFieldSchema = BaseField;
export const FieldSchema = BaseField.extend({
  fields: z.array(BaseField).max(50).optional().describe('columns for kind=repeater'),
  minRows: z.number().int().min(0).optional(),
  maxRows: z.number().int().positive().max(10_000).optional(),
  csv: z.boolean().optional().describe('repeater: allow CSV import / paste from spreadsheet (default true)'),
});
export type FieldDef = z.infer<typeof FieldSchema>;

export const SectionSchema = z.object({
  title: z.string().max(200).optional(),
  description: z.string().max(2000).optional(),
  fields: z.array(FieldSchema).min(1).max(200),
});

export const FormSchema = z.object({
  sections: z.array(SectionSchema).max(30).optional(),
  fields: z.array(FieldSchema).max(200).optional(),
});
export type FormSchemaT = z.infer<typeof FormSchema>;

export interface NormalizedSchema {
  sections: { title?: string; description?: string; fields: FieldDef[] }[];
}

export interface FieldError {
  field: string;
  code: string;
}

export function optionValues(f: FieldDef): string[] {
  return (f.options ?? []).map((o) => (typeof o === 'string' ? o : o.value));
}

/** Normalizes and checks a schema; throws UserError listing problems by path. */
export function normalizeSchema(input: FormSchemaT): NormalizedSchema {
  const sections = [...(input.sections ?? [])];
  if (input.fields?.length) sections.unshift({ fields: input.fields });
  if (!sections.length) throw new UserError('schema has no fields', 'invalid_schema');
  const problems: string[] = [];
  const names = new Set<string>();
  let count = 0;
  for (const s of sections) {
    for (const f of s.fields) {
      count++;
      if (names.has(f.name)) problems.push(`${f.name}: duplicate name`);
      names.add(f.name);
      checkField(f, problems, f.name);
      if (f.kind === 'repeater') {
        if (!f.fields?.length) problems.push(`${f.name}: repeater needs fields`);
        const sub = new Set<string>();
        for (const c of f.fields ?? []) {
          if (sub.has(c.name)) problems.push(`${f.name}.${c.name}: duplicate name`);
          sub.add(c.name);
          if (c.kind === 'repeater' || c.kind === 'file') problems.push(`${f.name}.${c.name}: ${c.kind} not allowed inside a repeater`);
          checkField(c as FieldDef, problems, `${f.name}.${c.name}`);
          if (c.showIf && !f.fields!.some((x) => x.name === c.showIf!.field)) problems.push(`${f.name}.${c.name}: showIf refers to unknown column`);
        }
      } else if (f.fields) problems.push(`${f.name}: only repeaters have fields`);
    }
  }
  for (const s of sections)
    for (const f of s.fields) if (f.showIf && !names.has(f.showIf.field)) problems.push(`${f.name}: showIf refers to unknown field ${f.showIf.field}`);
  if (count > 200) problems.push('too many fields (max 200)');
  if (problems.length) throw new UserError(`invalid schema: ${problems.join('; ')}`, 'invalid_schema');
  return { sections };
}

function checkField(f: FieldDef, problems: string[], p: string): void {
  if ((f.kind === 'select' || f.kind === 'multiselect') && !f.options?.length) problems.push(`${p}: ${f.kind} needs options`);
  if (f.pattern) {
    try {
      new RegExp(f.pattern, 'u');
    } catch {
      problems.push(`${p}: invalid pattern`);
    }
  }
  if (f.kind === 'secret' && f.default !== undefined) problems.push(`${p}: secret fields cannot have a default`);
  if (f.min !== undefined && f.max !== undefined && f.min > f.max) problems.push(`${p}: min > max`);
}

export function allFields(s: NormalizedSchema): FieldDef[] {
  return s.sections.flatMap((x) => x.fields);
}

export function secretFieldNames(s: NormalizedSchema): string[] {
  const out: string[] = [];
  for (const f of allFields(s)) {
    if (f.kind === 'secret') out.push(f.name);
    if (f.kind === 'repeater') for (const c of f.fields ?? []) if (c.kind === 'secret') out.push(`${f.name}.${c.name}`);
  }
  return out;
}

// ------------------------------------------------------------------ values

export interface FileValue {
  name: string;
  type: string;
  size: number;
  data: Buffer;
}
export interface MoneyValue {
  amount: string;
  currency: string;
}
export type FieldValue = string | number | boolean | string[] | FileValue | MoneyValue | Record<string, unknown>[] | null;
export type Values = Record<string, FieldValue>;

function isEmpty(v: unknown): boolean {
  return v === undefined || v === null || v === '' || (Array.isArray(v) && v.length === 0);
}

export function conditionHolds(cond: FieldDef['showIf'], scope: Record<string, unknown>): boolean {
  if (!cond) return true;
  const v = scope[cond.field];
  const sv = v && typeof v === 'object' && 'amount' in (v as object) ? (v as MoneyValue).amount : v;
  if (cond.notEmpty !== undefined) return cond.notEmpty ? !isEmpty(sv) : isEmpty(sv);
  if (cond.in) return Array.isArray(sv) ? sv.some((x) => cond.in!.includes(String(x))) : cond.in.includes(String(sv ?? ''));
  if (cond.equals !== undefined) {
    if (typeof cond.equals === 'boolean') return (sv === true || sv === 'true' || sv === 'on') === cond.equals;
    return String(sv ?? '') === String(cond.equals);
  }
  return !isEmpty(sv);
}

export function parseNumber(raw: string): number | undefined {
  let s = raw.trim().replace(/[\s_]/g, '');
  if (/^-?\d{1,3}(,\d{3})+(\.\d+)?$/.test(s)) s = s.replace(/,/g, '');
  else if (/^-?\d+,\d+$/.test(s)) s = s.replace(',', '.');
  if (!/^-?\d+(\.\d+)?$/.test(s)) return undefined;
  const n = Number(s);
  return Number.isFinite(n) ? n : undefined;
}

function normalizeDecimal(raw: string): string | undefined {
  const n = parseNumber(raw);
  if (n === undefined) return undefined;
  let s = raw.trim().replace(/[\s_]/g, '');
  if (/^-?\d{1,3}(,\d{3})+(\.\d+)?$/.test(s)) s = s.replace(/,/g, '');
  else if (/^-?\d+,\d+$/.test(s)) s = s.replace(',', '.');
  return s;
}

/** Validates one field value. Returns the typed value or pushes error codes. */
function validateField(f: FieldDef, raw: unknown, path: string, errors: FieldError[]): FieldValue | undefined {
  const err = (code: string) => {
    errors.push({ field: path, code });
    return undefined;
  };
  if (f.kind === 'boolean') {
    const b = raw === true || raw === 'true' || raw === 'on' || raw === '1';
    if (f.required && !b) return err('required');
    return b;
  }
  if (f.kind === 'repeater') return err('type');
  if (isEmpty(raw) || (f.kind === 'money' && isEmpty((raw as MoneyValue | undefined)?.amount))) {
    if (f.required) return err('required');
    return null;
  }
  switch (f.kind) {
    case 'number': {
      const n = typeof raw === 'number' ? raw : typeof raw === 'string' ? parseNumber(raw) : undefined;
      if (n === undefined) return err('type');
      if (f.min !== undefined && n < f.min) return err('min');
      if (f.max !== undefined && n > f.max) return err('max');
      return n;
    }
    case 'money': {
      const m = (typeof raw === 'object' && raw ? raw : { amount: raw }) as { amount?: unknown; currency?: unknown };
      const amount = normalizeDecimal(String(m.amount ?? ''));
      if (amount === undefined) return err('type');
      if (!/^-?\d+(\.\d{1,6})?$/.test(amount)) return err('type');
      const n = Number(amount);
      if (f.min !== undefined && n < f.min) return err('min');
      if (f.max !== undefined && n > f.max) return err('max');
      const allowed = f.currencies ?? [f.currency ?? 'USD'];
      const currency = typeof m.currency === 'string' && m.currency ? m.currency : allowed[0]!;
      if (!allowed.includes(currency)) return err('enum');
      return { amount, currency };
    }
    case 'date': {
      if (typeof raw !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(raw) || Number.isNaN(Date.parse(raw + 'T00:00:00Z'))) return err('type');
      if (f.min !== undefined || f.max !== undefined) {
        /* min/max on dates are not supported: use pattern */
      }
      return raw;
    }
    case 'select': {
      if (typeof raw !== 'string') return err('type');
      if (!optionValues(f).includes(raw)) return err('enum');
      return raw;
    }
    case 'multiselect': {
      const arr = Array.isArray(raw) ? raw.map(String) : [String(raw)];
      const allowed = optionValues(f);
      if (arr.some((x) => !allowed.includes(x))) return err('enum');
      if (f.min !== undefined && arr.length < f.min) return err('min');
      if (f.max !== undefined && arr.length > f.max) return err('max');
      return arr;
    }
    case 'file': {
      const fv = raw as { name?: unknown; type?: unknown; b64?: unknown };
      if (!fv || typeof fv.b64 !== 'string') return err('type');
      const data = Buffer.from(fv.b64, 'base64');
      const maxBytes = f.maxBytes ?? 1024 * 1024;
      if (data.length > maxBytes) return err('file_too_large');
      const name = String(fv.name ?? 'file').slice(0, 255);
      const type = String(fv.type ?? 'application/octet-stream').slice(0, 100);
      if (f.accept?.length && !f.accept.some((a) => (a.startsWith('.') ? name.toLowerCase().endsWith(a.toLowerCase()) : a.endsWith('/*') ? type.startsWith(a.slice(0, -1)) : type === a))) return err('file_type');
      return { name, type, size: data.length, data };
    }
    default: {
      // text, textarea, secret
      if (typeof raw !== 'string') return err('type');
      const max = f.maxLength ?? (f.kind === 'textarea' ? 100_000 : 10_000);
      if (raw.length > max) return err('max_length');
      if (f.minLength !== undefined && raw.length < f.minLength) return err('min_length');
      if (f.pattern && !new RegExp(`^(?:${f.pattern})$`, 'u').test(raw)) return err('pattern');
      return raw;
    }
  }
}

/**
 * Server-side validation (the browser validates too, but is not trusted).
 * Hidden fields (showIf false) are dropped. Errors carry field paths and codes only.
 */
export function validateValues(schema: NormalizedSchema, raw: Record<string, unknown>): { values: Values; errors: FieldError[] } {
  const errors: FieldError[] = [];
  const values: Values = {};
  const fields = allFields(schema);
  // Evaluate conditions against raw values (conditions reference scalar fields).
  for (const f of fields) {
    if (!conditionHolds(f.showIf, raw)) continue;
    if (f.kind === 'repeater') {
      const rows = Array.isArray(raw[f.name]) ? (raw[f.name] as Record<string, unknown>[]) : [];
      const nonEmpty = rows.filter((r) => r && typeof r === 'object' && Object.values(r).some((v) => !isEmpty(v) && v !== false));
      const minRows = f.minRows ?? (f.required ? 1 : 0);
      if (nonEmpty.length < minRows) errors.push({ field: f.name, code: 'too_few_rows' });
      if (nonEmpty.length > (f.maxRows ?? 5000)) {
        errors.push({ field: f.name, code: 'too_many_rows' });
        continue;
      }
      const out: Record<string, unknown>[] = [];
      nonEmpty.forEach((row, i) => {
        const r: Record<string, unknown> = {};
        for (const c of f.fields ?? []) {
          if (!conditionHolds(c.showIf, row)) continue;
          const v = validateField(c as FieldDef, row[c.name], `${f.name}[${i}].${c.name}`, errors);
          if (v !== undefined) r[c.name] = v;
        }
        out.push(r);
      });
      values[f.name] = out;
      continue;
    }
    const v = validateField(f, raw[f.name], f.name, errors);
    if (v !== undefined) values[f.name] = v;
  }
  return { values, errors };
}

/** Collects every string value (for registering as sensitive). */
export function flattenStrings(values: Values, secretOnly: Set<string> | undefined, minLength: number): { label: string; value: string }[] {
  const out: { label: string; value: string }[] = [];
  const push = (label: string, v: unknown) => {
    if (typeof v === 'string' && v.length >= minLength) out.push({ label, value: v });
    else if (typeof v === 'number' && String(v).length >= minLength) out.push({ label, value: String(v) });
    else if (v && typeof v === 'object' && 'amount' in (v as object)) push(label, (v as MoneyValue).amount);
    else if (Array.isArray(v)) v.forEach((x) => push(label, x));
  };
  for (const [k, v] of Object.entries(values)) {
    if (Array.isArray(v) && v.length && typeof v[0] === 'object') {
      for (const row of v as Record<string, unknown>[]) for (const [ck, cv] of Object.entries(row)) if (!secretOnly || secretOnly.has(`${k}.${ck}`)) push(`${k}.${ck}`, cv);
    } else if (!secretOnly || secretOnly.has(k)) push(k, v);
  }
  return out;
}
