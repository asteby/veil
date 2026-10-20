/**
 * Actionable error catalog. Every structured error code that a person can fix gets a short
 * explanation and a `fix` (text + the EXACT command to copy) in English and Spanish, adapted
 * to the detected OS / package manager. Built only from codes and platform facts: never from
 * values, passphrases or tool output.
 */
import { currentPlatform, installCommand, type PlatformInfo } from './platform.js';
import { UserError } from './util.js';

export type KeychainReason = 'missing_tool' | 'no_dbus' | 'no_service' | 'unsupported_os' | 'other';

/** Keychain failure with a non-secret sub-cause (used to pick the right fix). */
export class KeychainError extends UserError {
  constructor(
    message: string,
    code: 'keychain_unavailable' | 'keychain_locked' | 'keychain_unsupported' | 'keychain_failed',
    readonly reason: KeychainReason = 'other',
  ) {
    super(message, code);
  }
}

export const KEYCHAIN_CODES = new Set(['keychain_unavailable', 'keychain_locked', 'keychain_unsupported', 'keychain_failed']);

export function isKeychainFailure(e: unknown): boolean {
  return e instanceof UserError && KEYCHAIN_CODES.has(e.code);
}

export interface Fix {
  en: string;
  es: string;
  /** exact command to copy (never run by Veil when it needs privileges) */
  command?: string;
}

export interface ErrorHelp {
  code: string;
  en: string;
  es: string;
  fix?: Fix;
  /** a second way out that never needs installing anything */
  alternative?: Fix;
}

const USE_LOCAL_VAULT: Fix = {
  en: "Or keep going without installing anything: use Veil's own encrypted store (one file, AES-256-GCM, master password typed on the local page).",
  es: 'O sigue sin instalar nada: usa el almacén cifrado propio de Veil (un archivo, AES-256-GCM, contraseña maestra escrita en la página local).',
  command: 'veilform init',
};

export function errorHelp(code: string, ctx: { reason?: KeychainReason; platform?: PlatformInfo } = {}): ErrorHelp | undefined {
  const p = ctx.platform ?? currentPlatform();
  switch (code) {
    case 'keychain_unavailable': {
      if (ctx.reason === 'no_dbus')
        return {
          code,
          en: 'The OS keychain cannot be reached: there is no D-Bus session (typical of SSH or headless sessions).',
          es: 'No se puede contactar al llavero del sistema: no hay sesión D-Bus (típico de sesiones SSH o sin escritorio).',
          fix: { en: 'Run Veil from your desktop session, or start one D-Bus session for this shell.', es: 'Ejecuta Veil desde tu sesión de escritorio, o inicia una sesión D-Bus para esta terminal.', command: 'dbus-run-session -- $SHELL' },
          alternative: USE_LOCAL_VAULT,
        };
      if (ctx.reason === 'no_service')
        return {
          code,
          en: 'secret-tool is installed but no Secret Service (GNOME Keyring / KWallet) answers on D-Bus.',
          es: 'secret-tool está instalado pero ningún Secret Service (GNOME Keyring / KWallet) responde en D-Bus.',
          fix: { en: 'Start the GNOME Keyring secrets component for your session (no sudo).', es: 'Inicia el componente de secretos de GNOME Keyring en tu sesión (sin sudo).', command: 'gnome-keyring-daemon --start --components=secrets' },
          alternative: USE_LOCAL_VAULT,
        };
      if (p.os === 'darwin')
        return { code, en: 'The macOS keychain tool (security) is not available.', es: 'La herramienta del llavero de macOS (security) no está disponible.', fix: { en: 'security ships with macOS; check your PATH.', es: 'security viene con macOS; revisa tu PATH.', command: 'ls -l /usr/bin/security' }, alternative: USE_LOCAL_VAULT };
      return {
        code,
        en: 'The OS keychain is not available: secret-tool (libsecret) is not installed.',
        es: 'El llavero del sistema no está disponible: secret-tool (libsecret) no está instalado.',
        fix: { en: 'Install it (needs your sudo password; Veil never runs sudo).', es: 'Instálalo (pide tu contraseña de sudo; Veil nunca ejecuta sudo).', command: installCommand('secret-tool', p) },
        alternative: USE_LOCAL_VAULT,
      };
    }
    case 'keychain_locked':
      return {
        code,
        en: 'The OS keychain is locked.',
        es: 'El llavero del sistema está bloqueado.',
        fix:
          p.os === 'darwin'
            ? { en: 'Unlock the login keychain (it asks for your macOS password in the terminal).', es: 'Desbloquea el llavero de inicio de sesión (pide tu contraseña de macOS en la terminal).', command: 'security unlock-keychain ~/Library/Keychains/login.keychain-db' }
            : { en: 'Unlock the "Login" keyring: open Passwords and Keys (seahorse) and unlock it, or log out and back in.', es: 'Desbloquea el llavero "Inicio de sesión": abre Contraseñas y claves (seahorse) y desbloquéalo, o cierra sesión y vuelve a entrar.', command: 'seahorse' },
        alternative: USE_LOCAL_VAULT,
      };
    case 'keychain_unsupported':
      return {
        code,
        en: 'There is no OS keychain backend for this platform yet (Windows Credential Manager is planned).',
        es: 'Aún no hay backend de llavero del sistema para esta plataforma (Windows Credential Manager está previsto).',
        fix: USE_LOCAL_VAULT,
      };
    case 'keychain_failed':
      return { code, en: 'The OS keychain refused the operation.', es: 'El llavero del sistema rechazó la operación.', fix: { en: 'Run the diagnosis to see why.', es: 'Ejecuta el diagnóstico para ver por qué.', command: 'veilform doctor' }, alternative: USE_LOCAL_VAULT };
    case 'passphrase_required':
      return {
        code,
        en: "Veil's encrypted store is locked.",
        es: 'El almacén cifrado de Veil está bloqueado.',
        fix: { en: 'Unlock it with the master password on the local page (MCP tool local_unlock) or in your terminal. It stays unlocked in memory for the configured minutes.', es: 'Desbloquéalo con la contraseña maestra en la página local (herramienta MCP local_unlock) o en tu terminal. Queda desbloqueado en memoria los minutos configurados.', command: 'veilform unlock' },
      };
    case 'master_password_not_set':
      return {
        code,
        en: "Veil's encrypted store has no master password yet.",
        es: 'El almacén cifrado de Veil aún no tiene contraseña maestra.',
        fix: { en: 'Define it on the local page (never in the chat). If you forget it the data cannot be recovered: keep a backup.', es: 'Defínela en la página local (nunca en el chat). Si la olvidas los datos no se pueden recuperar: guarda un respaldo.', command: 'veilform unlock' },
      };
    case 'destination_not_configured':
      return {
        code,
        en: 'The destination is not configured.',
        es: 'El destino no está configurado.',
        fix: { en: 'Create a working configuration (keychain when it works, encrypted store otherwise) or add the destination to config.json.', es: 'Crea una configuración que funcione (llavero si funciona, almacén cifrado si no) o agrega el destino a config.json.', command: 'veilform init' },
      };
    case 'wrong_key':
      return { code, en: 'Wrong master password or key (attempts are limited).', es: 'Contraseña maestra o llave incorrecta (los intentos son limitados).', fix: { en: 'Try again on the local page.', es: 'Inténtalo de nuevo en la página local.', command: 'veilform unlock' } };
    case 'too_many_attempts':
      return { code, en: 'Too many failed attempts; locked for a while.', es: 'Demasiados intentos fallidos; bloqueado por un tiempo.', fix: { en: 'Wait and try again.', es: 'Espera e inténtalo de nuevo.' } };
    case 'weak_passphrase':
      return { code, en: 'The master password is too short.', es: 'La contraseña maestra es demasiado corta.', fix: { en: 'Use at least 10 characters (a few random words work well).', es: 'Usa al menos 10 caracteres (unas cuantas palabras al azar funcionan bien).' } };
    default:
      return undefined;
  }
}

/** Structured, value-free fix for a thrown error (for MCP responses). */
export function fixOf(e: unknown): { help?: { en: string; es: string }; fix?: Fix & { alternative?: Fix }; reason?: KeychainReason } {
  if (!(e instanceof UserError)) return {};
  const reason = e instanceof KeychainError ? e.reason : undefined;
  const h = errorHelp(e.code, { reason });
  if (!h) return reason ? { reason } : {};
  return {
    help: { en: h.en, es: h.es },
    ...(h.fix ? { fix: { ...h.fix, ...(h.alternative ? { alternative: h.alternative } : {}) } } : {}),
    ...(reason ? { reason } : {}),
  };
}
