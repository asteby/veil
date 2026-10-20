/**
 * Setup commands run by the PERSON: `doctor`, `init` and `unlock`. Nothing here runs sudo or
 * reads a secret from argv; the master password is typed on the TTY (no echo) or on the local
 * page.
 */
import { existsSync } from 'node:fs';
import { createInterface } from 'node:readline/promises';
import { fileURLToPath } from 'node:url';
import type { App } from './app.js';
import { askPage, askTty, parseArgs } from './cli-vault.js';
import { resolvePaths } from './config.js';
import { cliLang, formatReport, runDoctor } from './doctor.js';
import { errorHelp } from './errors.js';
import { formatPlan, planInit, registerCommand } from './init.js';
import { MIN_MASTER_LENGTH, type LocalVault } from './localvault.js';
import { run as defaultRunner } from './proc.js';
import { UserError } from './util.js';
import { VERSION } from './version.js';

const out = (s: string) => process.stdout.write(s + '\n');
const err = (s: string) => process.stderr.write(s + '\n');

export const SETUP_HELP = `  doctor [--json] [--lang es|en]               diagnose what Veil needs (read-only, nothing privileged)
  init [--yes] [--dry-run] [--master] [--lang es|en]   working setup without installing anything
  unlock [--minutes N] [--ui] [--save-keychain] [--forget-keychain] [--change-password] [--status]
                                               create/unlock Veil's encrypted store (master password)`;

async function confirm(question: string): Promise<boolean> {
  if (!process.stdin.isTTY) return false;
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  try {
    return /^(y|yes|s|si|sí)$/i.test((await rl.question(question)).trim());
  } finally {
    rl.close();
  }
}

/** Returns an exit code, or undefined when argv is not a setup command. */
export async function runSetupCli(argv: string[], makeApp: () => App): Promise<number | undefined> {
  const [cmd] = argv;
  if (cmd !== 'doctor' && cmd !== 'init' && cmd !== 'unlock') return undefined;
  const a = parseArgs(argv.slice(1));
  const flag = (k: string) => a.flags.get(k)?.at(-1);
  const has = (k: string) => a.flags.has(k);
  const lang = cliLang(process.env, flag('lang'));
  const paths = resolvePaths();

  if (cmd === 'doctor' || cmd === 'init') {
    let localVault;
    let app: App | undefined;
    if (existsSync(paths.home) && existsSync(paths.configFile)) {
      try {
        app = makeApp();
        localVault = await app.vault.localVault.status();
      } catch {
        /* invalid config: the doctor reports it */
      }
    }
    try {
      const report = await runDoctor({ paths, version: VERSION, runner: defaultRunner, localVault });
      if (cmd === 'doctor') {
        out(has('json') ? JSON.stringify(report, null, 2) : formatReport(report, lang));
        return report.ready ? 0 : 1;
      }
      // ------------------------------------------------------------ init
      out(formatReport(report, lang));
      out('');
      const plan = planInit(paths, report);
      out(formatPlan(plan, lang));
      out('');
      if (has('dry-run')) return 0;
      if (plan.steps.length) {
        const yes = has('yes') || (await confirm(lang === 'es' ? '¿Aplicar estos cambios? [s/N] ' : 'Apply these changes? [y/N] '));
        if (!yes) {
          err(lang === 'es' ? 'Sin cambios (usa --yes para aplicar sin preguntar).' : 'Nothing changed (use --yes to apply without asking).');
          return 1;
        }
        for (const s of plan.steps) {
          await s.apply();
          out(`  ✓ ${s.title[lang]}`);
        }
      }
      const cli = fileURLToPath(new URL('./cli.js', import.meta.url));
      out('');
      out(lang === 'es' ? 'Registra Veil en Claude Code:' : 'Register Veil in Claude Code:');
      out(`  $ ${registerCommand(cli)}`);
      out(lang === 'es' ? '  (publicado: claude mcp add -s user veil -- npx -y @asteby/veil)' : '  (published: claude mcp add -s user veil -- npx -y @asteby/veil)');
      if (has('master')) {
        await app?.shutdown();
        app = makeApp();
        return await unlockCmd(app, app.vault.localVault, { ui: true, minutes: Number(flag('minutes') ?? app.cfg.localVault.unlockMinutes), lang });
      }
      return 0;
    } finally {
      await app?.shutdown();
    }
  }

  // ---------------------------------------------------------------- unlock
  const app = makeApp();
  try {
    const v = app.vault.localVault;
    if (has('status')) {
      out(JSON.stringify(await v.status(), null, 2));
      return 0;
    }
    if (has('forget-keychain')) {
      out(JSON.stringify({ forgotten: await v.forgetKeychainKey() }));
      return 0;
    }
    if (has('change-password')) {
      const cur = await ask(app, has('ui'), lang === 'es' ? 'Contraseña maestra actual' : 'Current master password');
      const next = await askNew(app, has('ui'), lang);
      if (!cur || !next) throw new UserError('no password given', 'passphrase_required');
      out(JSON.stringify(await v.changePassword(cur, next)));
      return 0;
    }
    const code = await unlockCmd(app, v, { ui: has('ui'), minutes: Number(flag('minutes') ?? app.cfg.localVault.unlockMinutes), lang });
    if (code === 0 && has('save-keychain')) {
      out(JSON.stringify(await v.saveKeyToKeychain()));
      err(lang === 'es' ? 'La llave derivada quedó en el llavero del sistema: el almacén se abrirá sin contraseña mientras tu sesión esté desbloqueada.' : 'The derived key is now in the OS keychain: the store opens without the password while your session is unlocked.');
    }
    return code;
  } catch (e) {
    if (e instanceof UserError) {
      err(`${e.code}: ${e.message}`);
      const h = errorHelp(e.code);
      if (h?.fix) err(`  ${h.fix[lang]}${h.fix.command ? `\n  $ ${h.fix.command}` : ''}`);
    } else err('failed (details withheld to protect values)');
    return 1;
  } finally {
    await app.shutdown();
  }
}

async function ask(app: App, ui: boolean, label: string): Promise<string | undefined> {
  if (!ui && process.stdin.isTTY) return askTty(`${label}: `);
  const v = await askPage(app, label, [{ name: 'p', label, kind: 'secret', required: true }]);
  return v?.p;
}

async function askNew(app: App, ui: boolean, lang: 'en' | 'es'): Promise<string | undefined> {
  const warn =
    lang === 'es'
      ? `Al menos ${MIN_MASTER_LENGTH} caracteres. Si la olvidas, los datos NO se pueden recuperar: guarda una copia en tu gestor de contraseñas o en papel.`
      : `At least ${MIN_MASTER_LENGTH} characters. If you forget it the data CANNOT be recovered: keep a copy in your password manager or on paper.`;
  const l1 = lang === 'es' ? 'Nueva contraseña maestra' : 'New master password';
  const l2 = lang === 'es' ? 'Repítela' : 'Repeat it';
  if (!ui && process.stdin.isTTY) {
    process.stderr.write(warn + '\n');
    const p1 = await askTty(`${l1}: `);
    const p2 = await askTty(`${l2}: `);
    if (p1 !== p2) throw new UserError('passwords do not match', 'mismatch');
    return p1;
  }
  const v = await askPage(app, l1, [
    { name: 'p1', label: l1, kind: 'secret', required: true, help: warn },
    { name: 'p2', label: l2, kind: 'secret', required: true },
    { name: 'ack', label: lang === 'es' ? 'Entiendo, y guardo una copia en un lugar seguro' : 'I understand, and I keep a copy somewhere safe', kind: 'boolean', required: true },
  ]);
  if (v && v.p1 !== v.p2) throw new UserError('passwords do not match', 'mismatch');
  return v?.p1;
}

async function unlockCmd(app: App, v: LocalVault, o: { ui: boolean; minutes: number; lang: 'en' | 'es' }): Promise<number> {
  const st = await v.status();
  if (st.unlocked) {
    out(JSON.stringify({ status: 'unlocked', via: st.via, path: st.path }));
    return 0;
  }
  if (!st.exists) {
    const p = await askNew(app, o.ui, o.lang);
    if (!p) throw new UserError('no password given', 'passphrase_required');
    const r = await v.create(p, o.minutes);
    app.audit.write('local_vault_created', { via: 'cli', kdf: r.kdf, cached: r.cached });
    out(JSON.stringify({ status: 'created', path: v.file, kdf: r.kdf, cached: r.cached }));
    return 0;
  }
  const p = await ask(app, o.ui, o.lang === 'es' ? 'Contraseña maestra de Veil' : 'Veil master password');
  if (!p) throw new UserError('no password given', 'passphrase_required');
  const r = await v.unlock(p, o.minutes);
  app.audit.write('local_vault_unlocked', { via: 'cli', cached: r.cached, minutes: o.minutes });
  out(JSON.stringify({ status: 'unlocked', cached: r.cached, minutes: o.minutes }));
  if (r.cached !== 'agent')
    err(
      o.lang === 'es'
        ? 'Aviso: no hay agente de sesión, así que este desbloqueo solo vale para este comando. Inicia "veil agent" para compartirlo con el servidor MCP, o usa la herramienta MCP local_unlock.'
        : 'Note: no session agent is running, so this unlock only lasts for this command. Start "veil agent" to share it with the MCP server, or use the MCP tool local_unlock.',
    );
  return 0;
}
