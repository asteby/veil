/**
 * `veilform doctor`: diagnoses everything Veil needs WITHOUT running anything privileged and
 * without asking for (or reading) any secret. It only:
 *  - reads files (/etc/os-release, /proc/<pid>/comm, permissions of the veilform directory),
 *  - scans PATH,
 *  - runs read-only, unprivileged probes with a short timeout (`busctl --user get-property ...
 *    Locked` / `gdbus`, `security show-keychain-info`).
 * Every problem carries its impact and the EXACT command to fix it for the detected
 * distribution (apt/dnf/pacman/zypper/apk/brew/winget). Veil never runs those commands.
 */
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { localVaultPath, parseConfig, type Config, type Paths } from './config.js';
import { agentRequest, agentSocketPath } from './crypto/keysource.js';
import { hasArgon2 } from './crypto/primitives.js';
import type { LocalVaultStatus } from './localvault.js';
import { detectPlatform, installCommand, which as defaultWhich, type PlatformInfo, type Tool } from './platform.js';
import type { Runner } from './proc.js';

export type CheckStatus = 'ok' | 'warn' | 'error' | 'info';

export interface Bi {
  en: string;
  es: string;
}

export interface Check {
  id: string;
  area: 'node' | 'crypto' | 'keychain' | 'storage' | 'tools' | 'config' | 'permissions';
  status: CheckStatus;
  title: Bi;
  /** non-secret facts (paths, versions, tool names) */
  detail?: string;
  impact?: Bi;
  fix?: Bi & { command?: string };
}

export interface DoctorReport {
  version: string;
  platform: PlatformInfo & { node: string };
  /** true when secret_request to the default destination can complete (possibly via the encrypted store) */
  ready: boolean;
  keychain: { backend: string; usable: boolean; reason?: string };
  default_destination: { id: string; type: string; fallback?: string; effective: 'keychain' | 'local-vault' | 'other' | 'unavailable' };
  checks: Check[];
  summary: Record<CheckStatus, number>;
}

export interface DoctorDeps {
  paths: Paths;
  version: string;
  platform?: NodeJS.Platform;
  osRelease?: string;
  env?: NodeJS.ProcessEnv;
  /** only for read-only, unprivileged probes */
  runner?: Runner;
  which?: (cmd: string) => string | undefined;
  /** names of running processes (default: /proc/<pid>/comm on Linux) */
  procNames?: () => string[];
  nodeVersion?: string;
  argon2?: boolean;
  /** raw config text (default: read paths.configFile) */
  configText?: string | null;
  localVault?: LocalVaultStatus;
  agentRunning?: boolean;
  moduleAvailable?: (name: string) => boolean;
  uid?: number;
  probeTimeoutMs?: number;
}

const KEYRING_PROCS = ['gnome-keyring-d', 'gnome-keyring-daemon', 'kwalletd5', 'kwalletd6', 'ksecretd', 'keepassxc', 'kwalletd'];

function procNamesLinux(): string[] {
  const out: string[] = [];
  try {
    for (const d of readdirSync('/proc')) {
      if (!/^\d+$/.test(d)) continue;
      try {
        out.push(readFileSync(`/proc/${d}/comm`, 'utf8').trim());
      } catch {
        /* gone */
      }
    }
  } catch {
    /* no /proc */
  }
  return out;
}

function moduleAvailableDefault(name: string): boolean {
  try {
    createRequire(import.meta.url).resolve(name);
    return true;
  } catch {
    return false;
  }
}

function versionAtLeast(v: string, min: [number, number]): boolean {
  const [a, b] = v.replace(/^v/, '').split('.').map(Number) as [number, number];
  return a > min[0] || (a === min[0] && b >= min[1]);
}

function fixInstall(tool: Tool, p: PlatformInfo, what: Bi): Bi & { command?: string } {
  const command = installCommand(tool, p);
  return command
    ? { en: `Install ${what.en} (copy the command; it asks for your sudo password, Veil never runs sudo).`, es: `Instala ${what.es} (copia el comando; pide tu contraseña de sudo, Veil nunca ejecuta sudo).`, command }
    : { en: `Install ${what.en} with your system's package manager.`, es: `Instala ${what.es} con el gestor de paquetes de tu sistema.` };
}

const LOCAL_VAULT_FIX: Bi & { command: string } = {
  en: "Or use Veil's own encrypted store, which needs nothing installed.",
  es: 'O usa el almacén cifrado propio de Veil, que no necesita instalar nada.',
  command: 'veilform init',
};

export async function runDoctor(d: DoctorDeps): Promise<DoctorReport> {
  const env = d.env ?? process.env;
  const os = d.platform ?? process.platform;
  const p = detectPlatform({ platform: os, osRelease: d.osRelease });
  const which = d.which ?? ((c: string) => defaultWhich(c, env, os));
  const nodeVersion = d.nodeVersion ?? process.version;
  const checks: Check[] = [];
  const add = (c: Check) => checks.push(c);
  const timeout = d.probeTimeoutMs ?? 3000;

  // ---------------------------------------------------------------- node / crypto
  const nodeOk = versionAtLeast(nodeVersion, [20, 11]);
  add({
    id: 'node.version',
    area: 'node',
    status: nodeOk ? 'ok' : 'error',
    title: { en: `Node.js ${nodeVersion}`, es: `Node.js ${nodeVersion}` },
    ...(nodeOk ? {} : { impact: { en: 'Veil needs Node.js >= 20.11.', es: 'Veil necesita Node.js >= 20.11.' }, fix: { en: 'Install a current Node.js LTS (nvm works without sudo).', es: 'Instala un Node.js LTS actual (nvm funciona sin sudo).', command: 'nvm install --lts' } }),
  });
  let aesOk = true;
  try {
    const k = randomBytes(32);
    const iv = randomBytes(12);
    const c = createCipheriv('aes-256-gcm', k, iv);
    const ct = Buffer.concat([c.update('probe'), c.final()]);
    const dd = createDecipheriv('aes-256-gcm', k, iv);
    dd.setAuthTag(c.getAuthTag());
    aesOk = Buffer.concat([dd.update(ct), dd.final()]).toString() === 'probe';
  } catch {
    aesOk = false;
  }
  add({ id: 'crypto.aes-gcm', area: 'crypto', status: aesOk ? 'ok' : 'error', title: { en: 'AES-256-GCM (node:crypto / OpenSSL)', es: 'AES-256-GCM (node:crypto / OpenSSL)' }, ...(aesOk ? {} : { impact: { en: 'No encryption is possible.', es: 'No es posible cifrar nada.' }, fix: { en: 'Reinstall Node.js from nodejs.org or your package manager.', es: 'Reinstala Node.js desde nodejs.org o tu gestor de paquetes.', command: installCommand('node', p) } }) });
  const argon = d.argon2 ?? hasArgon2();
  add({
    id: 'crypto.kdf',
    area: 'crypto',
    status: argon ? 'ok' : 'warn',
    title: argon ? { en: 'Password KDF: argon2id', es: 'KDF de contraseñas: argon2id' } : { en: 'Password KDF: scrypt (argon2id needs Node >= 24.7)', es: 'KDF de contraseñas: scrypt (argon2id requiere Node >= 24.7)' },
    ...(argon ? {} : { impact: { en: 'Still safe (scrypt N=2^17); argon2id resists GPU attacks better.', es: 'Sigue siendo seguro (scrypt N=2^17); argon2id resiste mejor ataques con GPU.' }, fix: { en: 'Optional: upgrade Node.js to >= 24.7.', es: 'Opcional: actualiza Node.js a >= 24.7.', command: 'nvm install 24' } }),
  });

  // ---------------------------------------------------------------- config
  let cfg: Config | undefined;
  let configText = d.configText;
  if (configText === undefined) configText = existsSync(d.paths.configFile) ? readFileSync(d.paths.configFile, 'utf8') : null;
  try {
    cfg = parseConfig(configText === null ? {} : JSON.parse(configText));
    add({ id: 'config', area: 'config', status: 'ok', title: configText === null ? { en: 'No config file: built-in defaults', es: 'Sin archivo de configuración: valores por defecto' } : { en: 'Config is valid', es: 'La configuración es válida' }, detail: d.paths.configFile });
  } catch (e) {
    add({ id: 'config', area: 'config', status: 'error', title: { en: 'Config is invalid', es: 'La configuración no es válida' }, detail: `${d.paths.configFile}: ${(e as Error).message.slice(0, 300)}`, impact: { en: 'The MCP server will not start.', es: 'El servidor MCP no arrancará.' }, fix: { en: 'Fix the file, or move it away and let init write a working one.', es: 'Corrige el archivo, o muévelo y deja que init escriba uno que funcione.', command: `mv ${d.paths.configFile} ${d.paths.configFile}.bad && veilform init` } });
  }

  // ---------------------------------------------------------------- keychain
  let backend = 'none';
  let usable = false;
  let reason: string | undefined;
  if (os === 'linux' || os === 'freebsd') {
    backend = 'secret-tool (Secret Service)';
    const st = which('secret-tool');
    const busAddr = env.DBUS_SESSION_BUS_ADDRESS;
    const busPath = busAddr?.startsWith('unix:path=') ? busAddr.slice('unix:path='.length).split(',')[0] : env.XDG_RUNTIME_DIR ? path.join(env.XDG_RUNTIME_DIR, 'bus') : undefined;
    const dbusOk = Boolean((busAddr && !busAddr.startsWith('unix:path=')) || (busPath && existsSync(busPath)));
    const procs = (d.procNames ?? (os === 'linux' ? procNamesLinux : () => []))();
    const daemon = KEYRING_PROCS.find((n) => procs.includes(n));
    add({
      id: 'keychain.secret-tool',
      area: 'keychain',
      status: st ? 'ok' : 'warn',
      title: st ? { en: 'secret-tool installed', es: 'secret-tool instalado' } : { en: 'secret-tool (libsecret-tools) is NOT installed', es: 'secret-tool (libsecret-tools) NO está instalado' },
      detail: st,
      ...(st
        ? {}
        : {
            impact: { en: 'The OS keychain cannot be used: Veil stores values in its own encrypted file instead (master password on the local page).', es: 'No se puede usar el llavero del sistema: Veil guarda los valores en su propio archivo cifrado (contraseña maestra en la página local).' },
            fix: fixInstall('secret-tool', p, { en: 'secret-tool', es: 'secret-tool' }),
          }),
    });
    add({
      id: 'keychain.dbus',
      area: 'keychain',
      status: dbusOk ? 'ok' : 'warn',
      title: dbusOk ? { en: 'D-Bus session bus available', es: 'Bus de sesión D-Bus disponible' } : { en: 'No D-Bus session bus (SSH / headless session?)', es: 'No hay bus de sesión D-Bus (¿sesión SSH / sin escritorio?)' },
      detail: busPath ?? busAddr,
      ...(dbusOk ? {} : { impact: { en: 'The Secret Service cannot be reached from this session.', es: 'No se puede contactar al Secret Service desde esta sesión.' }, fix: { en: 'Run from your desktop session or start a D-Bus session for this shell.', es: 'Ejecuta desde tu sesión de escritorio o inicia una sesión D-Bus para esta terminal.', command: 'dbus-run-session -- $SHELL' } }),
    });
    const gk = which('gnome-keyring-daemon');
    add({
      id: 'keychain.daemon',
      area: 'keychain',
      status: daemon ? 'ok' : 'warn',
      title: daemon ? { en: `Secret Service provider running (${daemon})`, es: `Proveedor de Secret Service activo (${daemon})` } : gk ? { en: 'gnome-keyring-daemon is installed but not running', es: 'gnome-keyring-daemon está instalado pero no está activo' } : { en: 'No Secret Service provider (GNOME Keyring / KWallet / KeePassXC) found', es: 'No se encontró proveedor de Secret Service (GNOME Keyring / KWallet / KeePassXC)' },
      ...(daemon
        ? {}
        : {
            impact: { en: 'secret-tool has nobody to talk to (it may be started on demand by D-Bus activation).', es: 'secret-tool no tiene con quién hablar (D-Bus podría iniciarlo bajo demanda).' },
            fix: gk ? { en: 'Start its secrets component for your session (no sudo).', es: 'Inicia su componente de secretos en tu sesión (sin sudo).', command: 'gnome-keyring-daemon --start --components=secrets' } : fixInstall('gnome-keyring', p, { en: 'GNOME Keyring', es: 'GNOME Keyring' }),
          }),
    });
    let locked: boolean | undefined;
    let probe = 'skipped';
    if (dbusOk && d.runner !== undefined) {
      const r = await probeSecretServiceLocked(d.runner, which, timeout, env);
      locked = r.locked;
      probe = r.probe;
      if (r.locked === undefined && r.noService) probe = 'no-service';
    }
    if (dbusOk && probe !== 'skipped') {
      add({
        id: 'keychain.unlocked',
        area: 'keychain',
        status: locked === false ? 'ok' : 'warn',
        title:
          locked === false
            ? { en: 'Default keyring is unlocked', es: 'El llavero por defecto está desbloqueado' }
            : locked === true
              ? { en: 'Default keyring is LOCKED', es: 'El llavero por defecto está BLOQUEADO' }
              : probe === 'no-service'
                ? { en: 'No Secret Service answers on D-Bus', es: 'Ningún Secret Service responde en D-Bus' }
                : probe === 'no-collection'
                  ? { en: 'No default keyring yet (created on first store; may prompt)', es: 'Aún no hay llavero por defecto (se crea al guardar por primera vez; puede pedir contraseña)' }
                  : { en: 'Could not read the keyring lock state', es: 'No se pudo leer el estado de bloqueo del llavero' },
        detail: `probe: ${probe}`,
        ...(locked === true
          ? { impact: { en: 'Writes to the keychain fail or wait for an unlock prompt.', es: 'Las escrituras al llavero fallan o esperan un diálogo de desbloqueo.' }, fix: { en: 'Unlock "Login" in Passwords and Keys (seahorse), or log out and in.', es: 'Desbloquea "Inicio de sesión" en Contraseñas y claves (seahorse), o cierra sesión y vuelve a entrar.', command: 'seahorse' } }
          : probe === 'no-service'
            ? { impact: { en: 'The OS keychain cannot be used.', es: 'No se puede usar el llavero del sistema.' }, fix: gk ? { en: 'Start GNOME Keyring for your session.', es: 'Inicia GNOME Keyring en tu sesión.', command: 'gnome-keyring-daemon --start --components=secrets' } : fixInstall('gnome-keyring', p, { en: 'GNOME Keyring', es: 'GNOME Keyring' }) }
            : {}),
      });
    }
    usable = Boolean(st) && dbusOk && probe !== 'no-service' && locked !== true;
    reason = !st ? 'missing_tool' : !dbusOk ? 'no_dbus' : probe === 'no-service' ? 'no_service' : locked === true ? 'locked' : undefined;
  } else if (os === 'darwin') {
    backend = 'macOS Keychain (security)';
    const sec = which('security') ?? (existsSync('/usr/bin/security') ? '/usr/bin/security' : undefined);
    let locked: boolean | undefined;
    if (sec && d.runner) {
      try {
        const r = await d.runner([sec, 'show-keychain-info'], { timeoutMs: timeout });
        const err = r.stderr.toString('utf8');
        locked = r.code === 0 ? false : r.code === 36 || /interaction is not allowed|locked/i.test(err) ? true : undefined;
      } catch {
        locked = undefined;
      }
    }
    add({ id: 'keychain.security', area: 'keychain', status: sec ? 'ok' : 'error', title: sec ? { en: 'security (Keychain CLI) available', es: 'security (CLI del llavero) disponible' } : { en: 'security not found', es: 'No se encontró security' }, detail: sec, ...(sec ? {} : { fix: { en: 'security ships with macOS; check PATH.', es: 'security viene con macOS; revisa el PATH.', command: 'ls -l /usr/bin/security' } }) });
    if (locked !== undefined)
      add({
        id: 'keychain.unlocked',
        area: 'keychain',
        status: locked ? 'warn' : 'ok',
        title: locked ? { en: 'Login keychain is LOCKED', es: 'El llavero de inicio de sesión está BLOQUEADO' } : { en: 'Login keychain is unlocked', es: 'El llavero de inicio de sesión está desbloqueado' },
        ...(locked ? { fix: { en: 'Unlock it (asks for your macOS password in the terminal).', es: 'Desbloquéalo (pide tu contraseña de macOS en la terminal).', command: 'security unlock-keychain ~/Library/Keychains/login.keychain-db' } } : {}),
      });
    usable = Boolean(sec) && locked !== true;
    reason = !sec ? 'missing_tool' : locked ? 'locked' : undefined;
  } else {
    backend = os === 'win32' ? 'Windows Credential Manager (planned)' : `none for ${os}`;
    add({
      id: 'keychain.unsupported',
      area: 'keychain',
      status: 'warn',
      title: { en: `No OS keychain backend for ${os} yet${os === 'win32' ? ' (Credential Manager / DPAPI is planned)' : ''}`, es: `Aún no hay backend de llavero para ${os}${os === 'win32' ? ' (Credential Manager / DPAPI está previsto)' : ''}` },
      impact: { en: "Values go to Veil's own encrypted store (master password on the local page).", es: 'Los valores van al almacén cifrado propio de Veil (contraseña maestra en la página local).' },
      fix: LOCAL_VAULT_FIX,
    });
    usable = false;
    reason = 'unsupported_os';
  }

  // ---------------------------------------------------------------- default destination
  const defId = cfg?.defaultDestination ?? 'local';
  const dc = cfg?.destinations[defId];
  let effective: DoctorReport['default_destination']['effective'] = 'other';
  let fallback: string | undefined;
  if (!dc) {
    effective = 'unavailable';
    add({ id: 'destination.default', area: 'config', status: 'error', title: { en: `Default destination "${defId}" is not configured`, es: `El destino por defecto "${defId}" no está configurado` }, impact: { en: 'secret_request without a destination fails.', es: 'secret_request sin destino falla.' }, fix: { en: 'Write a working configuration.', es: 'Escribe una configuración que funcione.', command: 'veilform init' } });
  } else if (dc.type === 'keychain') {
    fallback = dc.fallback;
    effective = usable ? 'keychain' : dc.fallback === 'never' ? 'unavailable' : 'local-vault';
    add({
      id: 'destination.default',
      area: 'config',
      status: usable ? 'ok' : dc.fallback === 'never' ? 'error' : 'warn',
      title: usable
        ? { en: `Default destination "${defId}": OS keychain`, es: `Destino por defecto "${defId}": llavero del sistema` }
        : dc.fallback === 'never'
          ? { en: `Default destination "${defId}" (keychain, fallback: never) cannot store values`, es: `El destino por defecto "${defId}" (llavero, fallback: never) no puede guardar valores` }
          : { en: `Default destination "${defId}": keychain unavailable, Veil's encrypted store will be used (${dc.fallback === 'auto' ? 'automatically' : 'offered on the page'})`, es: `Destino por defecto "${defId}": llavero no disponible, se usará el almacén cifrado de Veil (${dc.fallback === 'auto' ? 'automáticamente' : 'ofrecido en la página'})` },
      ...(usable ? {} : { impact: { en: 'secret_request still completes: the local page asks for (or creates) the master password.', es: 'secret_request igual se completa: la página local pide (o crea) la contraseña maestra.' }, fix: { en: 'Make the encrypted store the explicit default (no prompt about the keychain each time).', es: 'Haz del almacén cifrado el destino explícito por defecto (sin aviso del llavero cada vez).', command: 'veilform init' } }),
    });
  } else if (dc.type === 'encrypted-file') {
    effective = dc.key.source === 'master' ? 'local-vault' : 'other';
    add({ id: 'destination.default', area: 'config', status: 'ok', title: { en: `Default destination "${defId}": encrypted file (${dc.key.source})`, es: `Destino por defecto "${defId}": archivo cifrado (${dc.key.source})` }, detail: dc.path });
  } else {
    add({ id: 'destination.default', area: 'config', status: 'ok', title: { en: `Default destination "${defId}": ${dc.type}`, es: `Destino por defecto "${defId}": ${dc.type}` } });
  }

  // ---------------------------------------------------------------- local vault / agent
  const lvPath = cfg ? localVaultPath(cfg, d.paths) : path.join(d.paths.home, 'local-vault.json');
  const lv = d.localVault ?? { path: lvPath, exists: existsSync(lvPath), unlocked: false };
  if (!lv.exists)
    add({ id: 'storage.local-vault', area: 'storage', status: 'info', title: { en: "Veil's encrypted store not created yet (created on first use, master password on the local page)", es: 'El almacén cifrado de Veil aún no existe (se crea en el primer uso, contraseña maestra en la página local)' }, detail: lv.path });
  else
    add({
      id: 'storage.local-vault',
      area: 'storage',
      status: lv.permissions_ok === false ? 'error' : 'ok',
      title: { en: `Veil's encrypted store: ${lv.unlocked ? `unlocked (${lv.via})` : 'locked'}${lv.kdf ? `, ${lv.kdf}` : ''}${lv.entries !== undefined ? `, ${lv.entries} entries` : ''}`, es: `Almacén cifrado de Veil: ${lv.unlocked ? `desbloqueado (${lv.via})` : 'bloqueado'}${lv.kdf ? `, ${lv.kdf}` : ''}${lv.entries !== undefined ? `, ${lv.entries} entradas` : ''}` },
      detail: lv.path,
      ...(lv.permissions_ok === false ? { impact: { en: 'Other local users could copy the ciphertext for offline guessing.', es: 'Otros usuarios locales podrían copiar el cifrado para adivinar sin conexión.' }, fix: { en: 'Restrict it to your user.', es: 'Restríngelo a tu usuario.', command: `chmod 600 ${lv.path}` } } : {}),
    });
  let agentRunning = d.agentRunning;
  if (agentRunning === undefined) {
    try {
      agentRunning = Boolean((await agentRequest(agentSocketPath(d.paths.home, env), { op: 'ping' }, 1000)).ok);
    } catch {
      agentRunning = false;
    }
  }
  add({
    id: 'storage.session-agent',
    area: 'storage',
    status: 'info',
    title: agentRunning ? { en: 'Session agent running (unlocks are shared and "veilform lock" forgets them)', es: 'Agente de sesión activo (los desbloqueos se comparten y "veilform lock" los olvida)' } : { en: 'Session agent not running (unlock lasts only inside each Veil process)', es: 'Agente de sesión no activo (el desbloqueo dura solo dentro de cada proceso de Veil)' },
    ...(agentRunning ? {} : { fix: { en: 'Optional: start it in your session.', es: 'Opcional: inícialo en tu sesión.', command: 'veilform agent &' } }),
  });

  // ---------------------------------------------------------------- permissions
  checkPermissions(d.paths.home, d.uid ?? (process.getuid ? process.getuid() : undefined), os, add);

  // ---------------------------------------------------------------- tools per feature
  const needs = featureNeeds(cfg);
  const tool = (id: string, bins: string[], t: Tool, label: string, needed: boolean, feature: Bi) => {
    const found = bins.map((b) => which(b)).find(Boolean);
    add({
      id: `tools.${id}`,
      area: 'tools',
      status: found ? 'ok' : needed ? 'error' : 'info',
      title: found ? { en: `${label} found`, es: `${label} encontrado` } : { en: `${label} not found${needed ? '' : ' (only needed for: ' + feature.en + ')'}`, es: `${label} no encontrado${needed ? '' : ' (solo hace falta para: ' + feature.es + ')'}` },
      detail: found,
      ...(found ? {} : { impact: { en: `Needed for ${feature.en}.`, es: `Necesario para ${feature.es}.` }, fix: fixInstall(t, p, { en: label, es: label }) }),
    });
  };
  tool('ssh', ['ssh'], 'ssh', 'ssh', needs.ssh, { en: 'ssh_exec, ssh_key_provision, ssh-file destinations and ssh sync targets', es: 'ssh_exec, ssh_key_provision, destinos ssh-file y destinos de sync por ssh' });
  tool('ssh-keygen', ['ssh-keygen'], 'ssh', 'ssh-keygen', needs.ssh, { en: 'ssh_key_provision', es: 'ssh_key_provision' });
  tool('git', ['git'], 'git', 'git', needs.git, { en: 'git sync targets, env diff against git and the pre-commit hook', es: 'destinos de sync git, env diff contra git y el hook de pre-commit' });
  tool('gh', ['gh'], 'gh', 'gh (GitHub CLI)', needs.gh, { en: 'secret_write to GitHub Actions secrets', es: 'secret_write a secretos de GitHub Actions' });
  tool('psql', ['psql'], 'psql', 'psql', needs.psql, { en: 'blind_input sql sinks', es: 'sinks sql de blind_input' });
  if (os === 'linux' || os === 'freebsd') tool('xdg-open', ['xdg-open'], 'xdg-open', 'xdg-open', false, { en: 'opening the local page automatically (otherwise copy the URL)', es: 'abrir la página local automáticamente (si no, copia la URL)' });
  // browser for web_capture / web_login
  const exe = cfg?.web.executablePath;
  const browser = exe ? (existsSync(exe) ? exe : undefined) : ['chromium', 'chromium-browser', 'google-chrome', 'google-chrome-stable', 'microsoft-edge'].map((b) => which(b)).find(Boolean);
  const pw = (d.moduleAvailable ?? moduleAvailableDefault)('playwright-core');
  const webOk = Boolean(browser) && pw;
  add({
    id: 'tools.browser',
    area: 'tools',
    status: webOk ? 'ok' : needs.web ? 'error' : 'info',
    title: webOk ? { en: 'Browser for web_capture/web_login available', es: 'Navegador para web_capture/web_login disponible' } : { en: `Browser automation not ready (${!pw ? 'playwright-core missing' : 'no Chromium found'})${needs.web ? '' : ' — only for web_capture/web_login'}`, es: `Automatización de navegador no lista (${!pw ? 'falta playwright-core' : 'no se encontró Chromium'})${needs.web ? '' : ' — solo para web_capture/web_login'}` },
    detail: browser,
    ...(webOk ? {} : { impact: { en: 'Needed for web_capture and web_login.', es: 'Necesario para web_capture y web_login.' }, fix: !pw ? { en: 'Install playwright-core next to Veil (no sudo).', es: 'Instala playwright-core junto a Veil (sin sudo).', command: 'npm install -g playwright-core' } : { en: 'Download a private Chromium for your user (no sudo).', es: 'Descarga un Chromium privado para tu usuario (sin sudo).', command: 'npx playwright install chromium' } }),
  });

  const summary: Record<CheckStatus, number> = { ok: 0, warn: 0, error: 0, info: 0 };
  for (const c of checks) summary[c.status]++;
  const core = checks.filter((c) => c.area === 'node' || c.area === 'crypto' || c.area === 'config' || c.area === 'permissions');
  const ready = !core.some((c) => c.status === 'error') && effective !== 'unavailable';
  return {
    version: d.version,
    platform: { ...p, node: nodeVersion },
    ready,
    keychain: { backend, usable, ...(reason ? { reason } : {}) },
    default_destination: { id: defId, type: dc?.type ?? 'missing', ...(fallback ? { fallback } : {}), effective },
    checks,
    summary,
  };
}

async function probeSecretServiceLocked(runner: Runner, which: (c: string) => string | undefined, timeoutMs: number, env: NodeJS.ProcessEnv): Promise<{ locked?: boolean; probe: string; noService?: boolean }> {
  const path0 = '/org/freedesktop/secrets/aliases/default';
  const attempts: string[][] = [];
  if (which('busctl')) attempts.push(['busctl', '--user', 'get-property', 'org.freedesktop.secrets', path0, 'org.freedesktop.Secret.Collection', 'Locked']);
  if (which('gdbus')) attempts.push(['gdbus', 'call', '--session', '--dest', 'org.freedesktop.secrets', '--object-path', path0, '--method', 'org.freedesktop.DBus.Properties.Get', 'org.freedesktop.Secret.Collection', 'Locked']);
  for (const argv of attempts) {
    try {
      const r = await runner(argv, { timeoutMs, env });
      const out = r.stdout.toString('utf8');
      const err = r.stderr.toString('utf8');
      if (r.code === 0) {
        if (/\btrue\b/.test(out)) return { locked: true, probe: argv[0]! };
        if (/\bfalse\b/.test(out)) return { locked: false, probe: argv[0]! };
      }
      if (/not provided by any|ServiceUnknown|was not provided|activatable/i.test(err)) return { probe: 'no-service', noService: true };
      if (/does not exist|UnknownObject|No such object/i.test(err)) return { probe: 'no-collection' };
    } catch {
      /* try the next tool */
    }
  }
  return { probe: attempts.length ? 'unknown' : 'no-dbus-cli' };
}

function checkPermissions(home: string, uid: number | undefined, os: NodeJS.Platform, add: (c: Check) => void): void {
  if (!existsSync(home)) {
    add({ id: 'permissions.home', area: 'permissions', status: 'info', title: { en: 'Veil directory not created yet (created 0700 on first run)', es: 'El directorio de Veil aún no existe (se crea 0700 en la primera ejecución)' }, detail: home });
    return;
  }
  if (os === 'win32') {
    add({ id: 'permissions.home', area: 'permissions', status: 'info', title: { en: 'Veil directory (Windows ACLs are not checked)', es: 'Directorio de Veil (no se revisan ACLs de Windows)' }, detail: home });
    return;
  }
  const st = statSync(home);
  if (uid !== undefined && st.uid !== uid) {
    add({ id: 'permissions.home', area: 'permissions', status: 'error', title: { en: 'Veil directory belongs to another user', es: 'El directorio de Veil pertenece a otro usuario' }, detail: home, impact: { en: 'Veil cannot trust or write its files.', es: 'Veil no puede confiar en sus archivos ni escribirlos.' }, fix: { en: 'Recreate it as your user (move the old one away first).', es: 'Créalo de nuevo como tu usuario (mueve antes el anterior).', command: `mv ${home} ${home}.old && mkdir -m 700 ${home}` } });
    return;
  }
  const loose: string[] = [];
  try {
    for (const f of readdirSync(home)) {
      const full = path.join(home, f);
      const s = statSync(full);
      if (s.isFile() && (s.mode & 0o077) !== 0) loose.push(full);
    }
  } catch {
    /* unreadable */
  }
  const dirOk = (st.mode & 0o077) === 0;
  add({
    id: 'permissions.home',
    area: 'permissions',
    status: dirOk && !loose.length ? 'ok' : 'warn',
    title: dirOk && !loose.length ? { en: 'Veil directory is private (0700, files 0600)', es: 'El directorio de Veil es privado (0700, archivos 0600)' } : { en: 'Veil directory or files are readable by other users', es: 'El directorio o archivos de Veil son legibles por otros usuarios' },
    detail: dirOk ? (loose.length ? loose.join(', ') : home) : `${home} (${(st.mode & 0o777).toString(8)})`,
    ...(dirOk && !loose.length ? {} : { impact: { en: 'Other local users could read metadata, audit logs or ciphertext.', es: 'Otros usuarios locales podrían leer metadatos, auditoría o cifrados.' }, fix: { en: 'Restrict them to your user (veilform init does it too).', es: 'Restríngelos a tu usuario (veilform init también lo hace).', command: `chmod 700 ${home}${loose.length ? ' && chmod 600 ' + loose.join(' ') : ''}` } }),
  });
}

function featureNeeds(cfg: Config | undefined): { ssh: boolean; git: boolean; gh: boolean; psql: boolean; web: boolean } {
  if (!cfg) return { ssh: false, git: false, gh: false, psql: false, web: false };
  const syncTypes = Object.values(cfg.sync.targets).map((t) => t.type);
  return {
    ssh: Object.keys(cfg.ssh.hosts).length > 0 || syncTypes.includes('ssh'),
    git: syncTypes.includes('git'),
    gh: cfg.writeTargets.some((w) => w.kind === 'github'),
    psql: Object.values(cfg.databases).some((db) => !db.ssh && (db.psql[0] ?? 'psql') === 'psql'),
    web: Object.keys(cfg.web.sites).length > 0,
  };
}

// ------------------------------------------------------------------ human output

const MARK: Record<CheckStatus, string> = { ok: '[ok]', warn: '[!!]', error: '[XX]', info: '[i] ' };

export function formatReport(r: DoctorReport, lang: 'en' | 'es'): string {
  const L = (b: Bi) => b[lang];
  const lines: string[] = [];
  const plat = r.platform.distroName ?? r.platform.distro;
  lines.push(lang === 'es' ? `Veil doctor ${r.version} — ${plat} (${r.platform.os}), gestor de paquetes: ${r.platform.packageManager}, Node ${r.platform.node}` : `Veil doctor ${r.version} — ${plat} (${r.platform.os}), package manager: ${r.platform.packageManager}, Node ${r.platform.node}`);
  lines.push('');
  for (const c of r.checks) {
    lines.push(`${MARK[c.status]} ${L(c.title)}${c.detail ? `  (${c.detail})` : ''}`);
    if (c.status !== 'ok' && c.impact) lines.push(`     ${lang === 'es' ? 'Impacto' : 'Impact'}: ${L(c.impact)}`);
    if (c.status !== 'ok' && c.fix) {
      lines.push(`     ${lang === 'es' ? 'Arreglo' : 'Fix'}: ${L(c.fix)}`);
      if (c.fix.command) lines.push(`       $ ${c.fix.command}`);
    }
  }
  lines.push('');
  const eff = r.default_destination.effective;
  if (lang === 'es') {
    lines.push(`Llavero del sistema: ${r.keychain.backend} — ${r.keychain.usable ? 'utilizable' : `no utilizable${r.keychain.reason ? ` (${r.keychain.reason})` : ''}`}`);
    lines.push(`Destino por defecto "${r.default_destination.id}": ${eff === 'keychain' ? 'llavero del sistema' : eff === 'local-vault' ? 'almacén cifrado de Veil' : eff === 'unavailable' ? 'NO disponible' : r.default_destination.type}`);
    lines.push(r.ready ? 'Resultado: Veil puede pedir y guardar credenciales en esta máquina.' : 'Resultado: hay problemas que impiden usar Veil; aplica los arreglos marcados [XX].');
    lines.push(`Resumen: ${r.summary.ok} ok, ${r.summary.warn} avisos, ${r.summary.error} errores, ${r.summary.info} info. Veil no ejecutó nada con privilegios.`);
  } else {
    lines.push(`OS keychain: ${r.keychain.backend} — ${r.keychain.usable ? 'usable' : `not usable${r.keychain.reason ? ` (${r.keychain.reason})` : ''}`}`);
    lines.push(`Default destination "${r.default_destination.id}": ${eff === 'keychain' ? 'OS keychain' : eff === 'local-vault' ? "Veil's encrypted store" : eff === 'unavailable' ? 'NOT available' : r.default_destination.type}`);
    lines.push(r.ready ? 'Result: Veil can ask for and store credentials on this machine.' : 'Result: some problems prevent using Veil; apply the fixes marked [XX].');
    lines.push(`Summary: ${r.summary.ok} ok, ${r.summary.warn} warnings, ${r.summary.error} errors, ${r.summary.info} info. Veil ran nothing privileged.`);
  }
  return lines.join('\n');
}

export function cliLang(env: NodeJS.ProcessEnv = process.env, flag?: string): 'en' | 'es' {
  if (flag === 'es' || flag === 'en') return flag;
  const l = env.VEILFORM_LANG ?? env.LC_ALL ?? env.LC_MESSAGES ?? env.LANG ?? '';
  return /^es/i.test(l) ? 'es' : 'en';
}
