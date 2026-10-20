/**
 * Product name and compatibility with the former name "veilform".
 *
 * Current: package `@asteby/veil`, command `veil`, environment `VEIL_*`, config directory
 * `~/.config/veil`, MCP server name `veil`, visible name "Veil".
 *
 * Kept for compatibility (see CHANGELOG "Renamed to Veil"):
 *  - command `veilform` (bin alias) and `VEILFORM_*` variables (deprecated aliases, warned once);
 *  - `~/.config/veilform` is used when `~/.config/veil` does not exist yet;
 *  - persisted format constants: the `encrypted-file` check `veilform:v1`, the default keychain
 *    service `veilform` (the service `veil` is read as an alias), crypto domain strings
 *    (`veilform-env/v1/…`, `veilform-bundle…`, `veilform-share…`, `veilform/kek/v1`), the systemd
 *    credential `veilform-key` (read after `veil-key`), remote defaults already deployed
 *    (`/etc/veilform/<unit>.env`, `50-veilform.conf`, sync prefixes `veilform/`);
 *  - encrypted `.env`: `#/veilform-env v1` + `enc:v1:` are read; new files use `#/veil-env v1`
 *    + `veil:1:` (docs/FORMAT-VEIL-SPEC.md §10.2).
 */
export const APP = 'veil';
export const APP_DISPLAY = 'Veil';
export const LEGACY_APP = 'veilform';

/** Default keychain service. Unchanged on purpose: existing secrets live under it. */
export const DEFAULT_KEYCHAIN_SERVICE = 'veilform';

/** Keychain services read as aliases of each other (new name and former name). */
export function keychainServiceAliases(service: string): string[] {
  if (service === LEGACY_APP) return [APP];
  if (service === APP) return [LEGACY_APP];
  return [];
}

const warned = new Set<string>();

/**
 * Reads `VEIL_<name>`, falling back to the deprecated `VEILFORM_<name>` (one warning per name
 * and process on stderr). Never pass values to the warning: only the variable name.
 */
export function envVar(name: string, env: NodeJS.ProcessEnv = process.env): string | undefined {
  const v = env[`VEIL_${name}`];
  if (v !== undefined) return v;
  const legacy = env[`VEILFORM_${name}`];
  if (legacy !== undefined && !warned.has(name)) {
    warned.add(name);
    const quiet = (env.VEIL_QUIET ?? env.VEILFORM_QUIET) === '1';
    if (!quiet) process.stderr.write(`[veil] WARN VEILFORM_${name} is deprecated; use VEIL_${name}\n`);
  }
  return legacy;
}

/** Reads an environment variable by its full name; `VEIL_*` names also accept the `VEILFORM_*` alias. */
export function envByName(full: string, env: NodeJS.ProcessEnv = process.env): string | undefined {
  return full.startsWith('VEIL_') ? envVar(full.slice(5), env) : env[full];
}

/** Variables of this program (current and former prefix), removed from child environments. */
export function isOwnEnvVar(k: string): boolean {
  return /^VEIL(FORM)?_/.test(k);
}

/** For tests: forget which deprecation warnings were already printed. */
export function resetEnvWarnings(): void {
  warned.clear();
}
