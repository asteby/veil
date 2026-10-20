/**
 * `veil init`: assisted first use. Runs the doctor, shows a plan and applies ONLY user-level
 * changes (the Veil directory, its permissions and config.json). It never runs sudo and
 * never asks for a secret: the master password of Veil's encrypted store is defined on the
 * local page, on first use (or right away with `--master`).
 */
import { chmodSync, copyFileSync, existsSync, mkdirSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import path from 'node:path';
import { parseConfig, type Paths } from './config.js';
import { DEFAULT_KEYCHAIN_SERVICE } from './naming.js';
import type { Bi, DoctorReport } from './doctor.js';
import { LocalFileIO } from './fileio.js';

export interface InitStep {
  id: string;
  title: Bi;
  /** user-level change (never privileged) */
  apply(): Promise<void>;
}

export interface InitPlan {
  steps: InitStep[];
  /** commands that need privileges: printed for the person to copy, never run */
  manual: { title: Bi; command: string }[];
  /** config.json after the plan (value-free) */
  config?: Record<string, unknown>;
  notes: Bi[];
}

function tilde(p: string): string {
  const h = homedir();
  return p.startsWith(h + path.sep) ? `~/${p.slice(h.length + 1)}` : p;
}

export function planInit(paths: Paths, report: DoctorReport, opts: { configText?: string | null } = {}): InitPlan {
  const steps: InitStep[] = [];
  const notes: Bi[] = [];
  const io = new LocalFileIO();
  const home = paths.home;
  if (!existsSync(home)) {
    steps.push({ id: 'mkdir', title: { en: `Create ${tilde(home)} (0700)`, es: `Crear ${tilde(home)} (0700)` }, apply: async () => void mkdirSync(home, { recursive: true, mode: 0o700 }) });
  } else if (process.platform !== 'win32') {
    const st = statSync(home);
    if ((st.mode & 0o077) !== 0) steps.push({ id: 'chmod-home', title: { en: `chmod 700 ${tilde(home)}`, es: `chmod 700 ${tilde(home)}` }, apply: async () => chmodSync(home, 0o700) });
    for (const f of readdirSync(home)) {
      const full = path.join(home, f);
      const s = statSync(full);
      if (s.isFile() && (s.mode & 0o077) !== 0) steps.push({ id: `chmod-${f}`, title: { en: `chmod 600 ${tilde(full)}`, es: `chmod 600 ${tilde(full)}` }, apply: async () => chmodSync(full, 0o600) });
    }
  }

  const text = opts.configText !== undefined ? opts.configText : existsSync(paths.configFile) ? readFileSync(paths.configFile, 'utf8') : null;
  const usable = report.keychain.usable;
  const vaultPath = tilde(path.join(home, 'local-vault.json'));
  let config: Record<string, unknown> | undefined;
  if (text === null) {
    config = usable
      ? { defaultDestination: 'local', destinations: { local: { type: 'keychain', service: DEFAULT_KEYCHAIN_SERVICE, fallback: 'auto' } }, localVault: { unlockMinutes: 15 } }
      : { defaultDestination: 'local', destinations: { local: { type: 'encrypted-file', path: vaultPath, key: { source: 'master' } } }, localVault: { path: vaultPath, unlockMinutes: 15 } };
    steps.push({
      id: 'config',
      title: usable
        ? { en: `Write ${tilde(paths.configFile)}: default "local" = OS keychain, falling back automatically to Veil's encrypted store`, es: `Escribir ${tilde(paths.configFile)}: "local" por defecto = llavero del sistema, con caída automática al almacén cifrado de Veil` }
        : { en: `Write ${tilde(paths.configFile)}: default "local" = Veil's encrypted store (${vaultPath}); works without installing anything`, es: `Escribir ${tilde(paths.configFile)}: "local" por defecto = almacén cifrado de Veil (${vaultPath}); funciona sin instalar nada` },
      apply: () => writeConfig(io, paths, config!),
    });
  } else {
    let raw: Record<string, unknown> | undefined;
    try {
      raw = JSON.parse(text) as Record<string, unknown>;
      parseConfig(raw);
    } catch {
      raw = undefined;
      notes.push({ en: `${tilde(paths.configFile)} is invalid: init does not touch it. Fix it (see doctor) or move it away and run init again.`, es: `${tilde(paths.configFile)} no es válido: init no lo toca. Corrígelo (ver doctor) o muévelo y ejecuta init de nuevo.` });
    }
    if (raw) {
      const cfg = parseConfig(raw);
      const dests = { ...((raw.destinations as Record<string, Record<string, unknown>> | undefined) ?? {}) };
      const defId = cfg.defaultDestination;
      const def = cfg.destinations[defId];
      let changed = false;
      if (!def) {
        dests[defId] = usable ? { type: 'keychain', service: DEFAULT_KEYCHAIN_SERVICE, fallback: 'auto' } : { type: 'encrypted-file', path: vaultPath, key: { source: 'master' } };
        changed = true;
        notes.push({ en: `Adds the missing default destination "${defId}".`, es: `Agrega el destino por defecto "${defId}" que faltaba.` });
      } else if (def.type === 'keychain' && def.fallback !== 'auto' && !usable) {
        dests[defId] = { ...(dests[defId] ?? { type: 'keychain' }), fallback: 'auto' };
        changed = true;
        notes.push({ en: `"${defId}" stays the OS keychain but falls back automatically to Veil's encrypted store while the keychain is unavailable.`, es: `"${defId}" sigue siendo el llavero del sistema pero cae automáticamente al almacén cifrado de Veil mientras el llavero no esté disponible.` });
      }
      if (changed) {
        config = { ...raw, destinations: dests };
        steps.push({ id: 'config', title: { en: `Update ${tilde(paths.configFile)} (backup at config.json.bak)`, es: `Actualizar ${tilde(paths.configFile)} (respaldo en config.json.bak)` }, apply: async () => {
          copyFileSync(paths.configFile, paths.configFile + '.bak');
          chmodSync(paths.configFile + '.bak', 0o600);
          await writeConfig(io, paths, config!);
        } });
      } else notes.push({ en: 'The existing configuration already works; it is left as is.', es: 'La configuración existente ya funciona; se deja como está.' });
    }
  }

  const manual: InitPlan['manual'] = [];
  for (const c of report.checks) {
    if ((c.status !== 'warn' && c.status !== 'error') || !c.fix?.command) continue;
    if (/^sudo |^winget |^brew /.test(c.fix.command) && !manual.some((m) => m.command === c.fix!.command)) manual.push({ title: c.title, command: c.fix.command });
  }
  notes.push({
    en: `The master password of the encrypted store is NOT asked here: the local page asks for it the first time a value goes there (or now with "veil init --master"). If you forget it, the data cannot be recovered: keep a copy and back up ${vaultPath}.`,
    es: `La contraseña maestra del almacén cifrado NO se pide aquí: la página local la pide la primera vez que un valor va ahí (o ahora con "veil init --master"). Si la olvidas, los datos no se pueden recuperar: guarda una copia y respalda ${vaultPath}.`,
  });
  return { steps, manual, config, notes };
}

async function writeConfig(io: LocalFileIO, paths: Paths, config: Record<string, unknown>): Promise<void> {
  parseConfig(config);
  mkdirSync(path.dirname(paths.configFile), { recursive: true, mode: 0o700 });
  await io.writeAtomic(paths.configFile, JSON.stringify(config, null, 2) + '\n', { mode: '0600' });
}

export function formatPlan(plan: InitPlan, lang: 'en' | 'es'): string {
  const out: string[] = [];
  out.push(lang === 'es' ? 'Plan (solo cambios de tu usuario; nada con sudo):' : 'Plan (user-level changes only; nothing with sudo):');
  if (!plan.steps.length) out.push(lang === 'es' ? '  (nada que cambiar)' : '  (nothing to change)');
  for (const s of plan.steps) out.push(`  - ${s.title[lang]}`);
  if (plan.config) out.push('', lang === 'es' ? 'config.json resultante:' : 'Resulting config.json:', JSON.stringify(plan.config, null, 2).replace(/^/gm, '    '));
  for (const n of plan.notes) out.push('', `* ${n[lang]}`);
  if (plan.manual.length) {
    out.push('', lang === 'es' ? 'Opcional, arreglos que necesitan privilegios (cópialos tú; Veil no los ejecuta):' : 'Optional fixes that need privileges (copy them yourself; Veil does not run them):');
    for (const m of plan.manual) out.push(`  # ${m.title[lang]}`, `  $ ${m.command}`);
  }
  return out.join('\n');
}

/** Command that registers this build as an MCP server in Claude Code. */
export function registerCommand(cliPath: string): string {
  return `claude mcp add -s user veil -- node ${cliPath}`;
}
