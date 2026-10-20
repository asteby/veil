/**
 * Encrypted vault bundle (backup / sync). Layout = a set of opaque blobs:
 *
 *   manifest.json   public header + encrypted index (see Manifest)
 *   o/<oid>         one object per secret: {v, oid, wdek, ct}
 *
 * Envelope encryption:
 *   KEK  = HKDF( argon2id|scrypt(passphrase) || second factor (key file / keychain), "bundle:<bundle_id>" )
 *   DEK  = random 32 bytes per secret and per export
 *   ct   = AES-256-GCM(DEK, value, AAD = bundle_id|oid|destination|name|version)
 *   wdek = AES-256-GCM(KEK, DEK,  AAD = bundle_id|oid|version)
 *   index = AES-256-GCM(KEK, {entries:[{oid,name,destination,version,clock,meta}]}, AAD = canonical(manifest without index))
 *
 * The index AAD covers the format version, bundle id, the monotonic `seq` (anti-rollback),
 * the key header and the sha256 of every object: objects swapped, truncated, replaced by
 * older ones, or a header edited, all fail authentication. Names, destinations and metadata
 * live only inside the encrypted index; object ids are random. A storage target sees
 * opaque blobs, their sizes and count, and when they change.
 */
import { createHash, randomBytes } from 'node:crypto';
import { canonicalJson, UserError } from '../util.js';
import { b64, checkKdfParams, combineKek, deriveFromPassphrase, open, randomKey, seal, type KdfParams } from '../crypto/primitives.js';

export const MANIFEST = 'manifest.json';
export const objectPath = (oid: string) => `o/${oid}`;
const CHECK = 'veilform-bundle-check/v1';

export type SecondFactor = 'none' | 'key-file' | 'keychain' | 'systemd-credential';

export interface KeyHeader {
  kdf: KdfParams | null;
  second: SecondFactor;
  check: string;
}

export interface Manifest {
  format: 'veilform-bundle';
  v: 1;
  bundle_id: string;
  seq: number;
  key: KeyHeader;
  objects: { id: string; sha256: string }[];
  index: string;
}

export type Clock = Record<string, number>;

export interface EntryMeta {
  createdAt?: string;
  updatedAt?: string;
  expiresAt?: string;
  rotateAfterDays?: number;
  tags?: string[];
  project?: string;
  field?: { label: string; kind: string; help?: string; pattern?: string };
  source?: string;
}

export interface BundleEntry {
  oid: string;
  name: string;
  destination: string;
  version: number;
  clock: Clock;
  meta: EntryMeta;
  /** in memory only */
  value: string;
}

interface IndexShape {
  entries: Omit<BundleEntry, 'value'>[];
  device: string;
  exported_at: string;
}

export interface KeyMaterial {
  passphrase?: string;
  second?: Buffer;
}

export const newBundleId = () => b64(randomBytes(16));
export const newOid = () => b64(randomBytes(16));
const sha = (b: Buffer) => createHash('sha256').update(b).digest('hex');

const dekAad = (bid: string, oid: string, v: number) => `veilform-bundle/v1/dek\0${bid}\0${oid}\0${v}`;
const valAad = (bid: string, e: { oid: string; destination: string; name: string; version: number }) => `veilform-bundle/v1/value\0${bid}\0${e.oid}\0${e.destination}\0${e.name}\0${e.version}`;
const checkAad = (bid: string) => `veilform-bundle/v1/check\0${bid}`;

function headerAad(m: Omit<Manifest, 'index'>): string {
  return canonicalJson({ format: m.format, v: m.v, bundle_id: m.bundle_id, seq: m.seq, key: { kdf: m.key.kdf, second: m.key.second }, objects: m.objects });
}

/** KEK for a bundle from the key header and the material (passphrase and/or second factor). */
export async function deriveKek(bundleId: string, kdf: KdfParams | null, second: SecondFactor, m: KeyMaterial): Promise<Buffer> {
  if (kdf && m.passphrase === undefined) throw new UserError('this bundle needs its passphrase', 'passphrase_required');
  if (second !== 'none' && !m.second) throw new UserError(`this bundle also needs its ${second}`, 'missing_key');
  const pk = kdf ? await deriveFromPassphrase(m.passphrase!, kdf) : undefined;
  const kek = await combineKek(pk, second !== 'none' ? m.second : undefined, `bundle:${bundleId}`);
  pk?.fill(0);
  return kek;
}

export function keyHeader(bundleId: string, kek: Buffer, kdf: KdfParams | null, second: SecondFactor): KeyHeader {
  return { kdf, second, check: seal(kek, CHECK, checkAad(bundleId)) };
}

export function verifyKek(m: Pick<Manifest, 'bundle_id' | 'key'>, kek: Buffer): void {
  try {
    if (open(kek, m.key.check, checkAad(m.bundle_id), 'wrong_key').toString() !== CHECK) throw new Error('x');
  } catch {
    throw new UserError('wrong passphrase or key for this bundle', 'wrong_key');
  }
}

export function buildBundle(a: { bundleId: string; seq: number; kek: Buffer; key: KeyHeader; device: string; entries: BundleEntry[]; now: Date }): { files: Map<string, Buffer>; manifest: Manifest } {
  const files = new Map<string, Buffer>();
  const objects: { id: string; sha256: string }[] = [];
  for (const e of a.entries) {
    const dek = randomKey();
    const obj = { v: 1, oid: e.oid, wdek: seal(a.kek, dek, dekAad(a.bundleId, e.oid, e.version)), ct: seal(dek, e.value, valAad(a.bundleId, e)) };
    dek.fill(0);
    const buf = Buffer.from(JSON.stringify(obj));
    files.set(objectPath(e.oid), buf);
    objects.push({ id: e.oid, sha256: sha(buf) });
  }
  objects.sort((x, y) => x.id.localeCompare(y.id));
  const head: Omit<Manifest, 'index'> = { format: 'veilform-bundle', v: 1, bundle_id: a.bundleId, seq: a.seq, key: a.key, objects };
  const index: IndexShape = { entries: a.entries.map(({ value: _v, ...rest }) => rest), device: a.device, exported_at: a.now.toISOString() };
  const manifest: Manifest = { ...head, index: seal(a.kek, JSON.stringify(index), headerAad(head)) };
  files.set(MANIFEST, Buffer.from(JSON.stringify(manifest, null, 1) + '\n'));
  return { files, manifest };
}

export function parseManifest(buf: Buffer | null): Manifest {
  if (!buf) throw new UserError('no bundle found at this location', 'not_found');
  let m: Manifest;
  try {
    m = JSON.parse(buf.toString('utf8')) as Manifest;
  } catch {
    throw new UserError('manifest is not valid JSON', 'malformed');
  }
  if (m?.format !== 'veilform-bundle') throw new UserError('not a veilform bundle', 'malformed');
  if (m.v !== 1) throw new UserError(`unsupported bundle version ${String(m.v)}`, 'unsupported_version');
  if (typeof m.bundle_id !== 'string' || !Number.isSafeInteger(m.seq) || m.seq < 0 || !Array.isArray(m.objects) || typeof m.index !== 'string' || !m.key || typeof m.key.check !== 'string') throw new UserError('malformed manifest', 'malformed');
  if (m.key.kdf) checkKdfParams(m.key.kdf);
  if (!['none', 'key-file', 'keychain', 'systemd-credential'].includes(m.key.second)) throw new UserError('malformed manifest', 'malformed');
  return m;
}

export type Getter = (path: string) => Promise<Buffer | null>;

/**
 * Opens a bundle: verifies the KEK, the index (authenticates the whole header), each object
 * hash and each object's AEAD. `minSeq` rejects bundles older than one already seen (rollback).
 */
export async function openBundle(get: Getter, kek: Buffer | ((m: Manifest) => Promise<Buffer>), opts: { minSeq?: number } = {}): Promise<{ manifest: Manifest; entries: BundleEntry[]; device: string; exportedAt: string }> {
  const m = parseManifest(await get(MANIFEST));
  if (opts.minSeq !== undefined && m.seq < opts.minSeq) throw new UserError(`bundle seq ${m.seq} is older than one already seen (${opts.minSeq}): possible rollback`, 'rollback');
  const key = typeof kek === 'function' ? await kek(m) : kek;
  verifyKek(m, key);
  const { index: sealedIndex, ...head } = m;
  const index = JSON.parse(open(key, sealedIndex, headerAad(head)).toString('utf8')) as IndexShape;
  const hashes = new Map(m.objects.map((o) => [o.id, o.sha256]));
  if (hashes.size !== index.entries.length || index.entries.some((e) => !hashes.has(e.oid))) throw new UserError('bundle index and object list disagree', 'tampered');
  const entries: BundleEntry[] = [];
  for (const e of index.entries) {
    const buf = await get(objectPath(e.oid));
    if (!buf) throw new UserError('a bundle object is missing (truncated upload?)', 'truncated');
    if (sha(buf) !== hashes.get(e.oid)) throw new UserError('a bundle object does not match the manifest', 'tampered');
    let obj: { v: number; oid: string; wdek: string; ct: string };
    try {
      obj = JSON.parse(buf.toString('utf8'));
    } catch {
      throw new UserError('malformed object', 'tampered');
    }
    if (obj.oid !== e.oid) throw new UserError('object id mismatch', 'tampered');
    const dek = open(key, obj.wdek, dekAad(m.bundle_id, e.oid, e.version));
    const value = open(dek, obj.ct, valAad(m.bundle_id, e)).toString('utf8');
    dek.fill(0);
    entries.push({ ...e, value });
  }
  return { manifest: m, entries, device: index.device, exportedAt: index.exported_at };
}

/**
 * KEK rotation without touching values: unwraps each DEK with the old KEK, wraps it with the
 * new one, keeps every `ct` as is and writes a new manifest with seq+1.
 */
export async function rekeyBundle(get: Getter, oldKek: Buffer, newKek: Buffer, newKey: Omit<KeyHeader, 'check'>, seq?: number): Promise<{ files: Map<string, Buffer>; manifest: Manifest }> {
  const m = parseManifest(await get(MANIFEST));
  verifyKek(m, oldKek);
  const { index: sealedIndex, ...head } = m;
  const indexJson = open(oldKek, sealedIndex, headerAad(head)).toString('utf8');
  const index = JSON.parse(indexJson) as IndexShape;
  const files = new Map<string, Buffer>();
  const objects: { id: string; sha256: string }[] = [];
  const hashes = new Map(m.objects.map((o) => [o.id, o.sha256]));
  for (const e of index.entries) {
    const buf = await get(objectPath(e.oid));
    if (!buf || sha(buf) !== hashes.get(e.oid)) throw new UserError('bundle object missing or modified', 'tampered');
    const obj = JSON.parse(buf.toString('utf8')) as { v: number; oid: string; wdek: string; ct: string };
    const dek = open(oldKek, obj.wdek, dekAad(m.bundle_id, e.oid, e.version));
    const nb = Buffer.from(JSON.stringify({ ...obj, wdek: seal(newKek, dek, dekAad(m.bundle_id, e.oid, e.version)) }));
    dek.fill(0);
    files.set(objectPath(e.oid), nb);
    objects.push({ id: e.oid, sha256: sha(nb) });
  }
  objects.sort((x, y) => x.id.localeCompare(y.id));
  const nh: Omit<Manifest, 'index'> = { ...head, seq: seq ?? m.seq + 1, key: keyHeader(m.bundle_id, newKek, newKey.kdf, newKey.second), objects };
  const manifest: Manifest = { ...nh, index: seal(newKek, indexJson, headerAad(nh)) };
  files.set(MANIFEST, Buffer.from(JSON.stringify(manifest, null, 1) + '\n'));
  return { files, manifest };
}

// ------------------------------------------------------------------ single-file packing

export function packSingle(files: Map<string, Buffer>): Buffer {
  const out: Record<string, string> = {};
  for (const [p, b] of [...files].sort(([a], [c]) => a.localeCompare(c))) out[p] = b.toString('base64');
  return Buffer.from(JSON.stringify({ format: 'veilform-bundle-file', v: 1, files: out }) + '\n');
}

export function unpackSingle(buf: Buffer): Map<string, Buffer> {
  let j: { format?: string; v?: number; files?: Record<string, string> };
  try {
    j = JSON.parse(buf.toString('utf8'));
  } catch {
    throw new UserError('bundle file is not valid JSON', 'malformed');
  }
  if (j.format !== 'veilform-bundle-file' || j.v !== 1 || !j.files) throw new UserError('not a veilform bundle file', 'malformed');
  return new Map(Object.entries(j.files).map(([p, s]) => [p, Buffer.from(s, 'base64')]));
}

// ------------------------------------------------------------------ logical clocks

export function compareClocks(a: Clock, b: Clock): 'equal' | 'a_newer' | 'b_newer' | 'concurrent' {
  let aGt = false;
  let bGt = false;
  for (const k of new Set([...Object.keys(a), ...Object.keys(b)])) {
    const x = a[k] ?? 0;
    const y = b[k] ?? 0;
    if (x > y) aGt = true;
    if (y > x) bGt = true;
  }
  return aGt && bGt ? 'concurrent' : aGt ? 'a_newer' : bGt ? 'b_newer' : 'equal';
}

export function mergeClocks(a: Clock, b: Clock): Clock {
  const out: Clock = { ...a };
  for (const [k, v] of Object.entries(b)) out[k] = Math.max(out[k] ?? 0, v);
  return out;
}

export const clockVersion = (c: Clock) => Object.values(c).reduce((s, n) => s + n, 0);
