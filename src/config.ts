import { existsSync, mkdirSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import path from 'node:path';
import { z } from 'zod';
import { SyncTargetSchema } from './sync/targets.js';
import { expandHome, UserError } from './util.js';

/**
 * Configuration = the allowlist. The model can only reference destinations, SSH
 * hosts, databases, write targets, HTTP hosts and web sites that the person put
 * here. The model never supplies hosts, paths or credentials for stores directly.
 */

const SecretRef = z.string().describe('"name" or "destination:name" of a stored secret');

const KeychainDest = z.object({
  type: z.literal('keychain'),
  service: z.string().default('veilform'),
  /**
   * When the OS keychain is missing/locked/unsupported:
   *  - ask: the local page OFFERS Veil's encrypted store (master password typed there)
   *  - auto: use the encrypted store automatically (still asks the master password on first use)
   *  - never: fail with an actionable error
   */
  fallback: z.enum(['ask', 'auto', 'never']).default('ask'),
});

const EncryptedFileDest = z.object({
  type: z.literal('encrypted-file'),
  path: z.string(),
  key: z
    .discriminatedUnion('source', [
      z.object({ source: z.literal('keychain'), service: z.string().default('veilform'), account: z.string().default('encrypted-file-key') }),
      z.object({ source: z.literal('env'), env: z.string().default('VEILFORM_PASSPHRASE') }),
      /** Veil's own store: master password defined/typed on the local page, unlocked in memory (see localVault). */
      z.object({ source: z.literal('master') }),
    ])
    .default({ source: 'keychain', service: 'veilform', account: 'encrypted-file-key' }),
});

const EnvFileDest = z.object({
  type: z.literal('env-file'),
  path: z.string(),
  host: z.string().optional().describe('ssh host key from ssh.hosts; omit for local'),
  mode: z.string().default('0600'),
  owner: z.string().optional(),
  group: z.string().optional(),
  backup: z.boolean().default(false),
});

const SshFileDest = z.object({
  type: z.literal('ssh-file'),
  host: z.string(),
  path: z.string().describe('remote path; {name} is replaced by the secret name'),
  mode: z.string().default('0600'),
  owner: z.string().optional(),
  group: z.string().optional(),
});

const HttpApiDest = z.object({
  type: z.literal('http-api'),
  adapter: z.enum(['generic', 'vault-kv2', 'infisical', '1password-connect', 'ops-addon-settings']),
  baseUrl: z.string(),
  allowedHosts: z.array(z.string()).default([]),
  /** Bootstrap credential for the remote store; resolved from a LOCAL store (keychain by default). */
  auth: z
    .object({
      tokenRef: SecretRef.optional(),
      scheme: z.enum(['bearer', 'header', 'none']).default('bearer'),
      header: z.string().default('Authorization'),
    })
    .default({ scheme: 'none', header: 'Authorization' }),
  /** Only for tests/dev: allow plain http on 127.0.0.1/localhost. */
  allowInsecureLoopback: z.boolean().default(false),
  caFile: z.string().optional(),
  timeoutMs: z.number().int().positive().default(15_000),
  options: z.record(z.string(), z.unknown()).default({}),
});

export const DestinationSchema = z.discriminatedUnion('type', [KeychainDest, EncryptedFileDest, EnvFileDest, SshFileDest, HttpApiDest]);
export type DestinationConfig = z.infer<typeof DestinationSchema>;

const SshHost = z.object({
  host: z.string().optional().describe('hostname or ~/.ssh/config alias; defaults to the key'),
  user: z.string().optional(),
  port: z.number().int().optional(),
  identityFile: z.string().optional(),
  /** Use a key provisioned by ssh_key_provision under this alias. */
  keyAlias: z.string().optional(),
  sudo: z.boolean().default(false),
  /** Where ssh_key_provision installs public keys (default ~/.ssh/authorized_keys of the remote user). */
  authorizedKeysFile: z.string().optional(),
});
export type SshHostConfig = z.infer<typeof SshHost>;

const WriteTarget = z.object({
  kind: z.enum(['env-file', 'json', 'yaml', 'systemd', 'github', 'clipboard']),
  host: z.string().optional(),
  path: z.string().optional().describe('glob; * = one path segment, ** = any'),
  keys: z.array(z.string()).optional().describe('globs of allowed keys'),
  unit: z.string().optional(),
  repo: z.string().optional(),
});
export type WriteTargetRule = z.infer<typeof WriteTarget>;

const Database = z.object({
  /** argv prefix that starts psql reading a script from stdin, e.g. ["psql","-d","appdb"] or ["docker","exec","-i","db","psql","-U","app","-d","app"]. */
  psql: z.array(z.string()).default(['psql']),
  ssh: z.string().optional(),
  /** postgres:// DSN stored as a secret; parsed into PG* env vars (never argv). Local only. */
  dsnSecret: SecretRef.optional(),
  passwordSecret: SecretRef.optional(),
  tables: z.record(
    z.string(),
    z.object({
      columns: z.array(z.string()),
      conflict: z.array(z.string()).optional(),
      returning: z.string().optional(),
    }),
  ),
  maxRows: z.number().int().positive().default(5000),
});
export type DatabaseConfig = z.infer<typeof Database>;

const WebSite = z.object({
  origins: z.array(z.string()).min(1),
  startUrl: z.string().optional(),
});

export const ConfigSchema = z.object({
  ui: z
    .object({
      lang: z.enum(['auto', 'en', 'es']).default('auto'),
      openBrowser: z.boolean().default(true),
      ttlSeconds: z.number().int().positive().max(3600).default(600),
      /** Block the tool call up to N seconds waiting for the person when URL elicitation is unavailable. */
      blockSeconds: z.number().int().min(0).max(600).default(0),
    })
    .default({ lang: 'auto', openBrowser: true, ttlSeconds: 600, blockSeconds: 0 }),
  cacheTtlSeconds: z.number().int().min(0).max(3600).default(60),
  defaultDestination: z.string().default('local'),
  destinations: z.record(z.string(), DestinationSchema).default({ local: { type: 'keychain', service: 'veilform', fallback: 'ask' } }),
  /** Veil's own single-file encrypted store (fallback when the OS keychain is not available). */
  localVault: z
    .object({
      /** default: <veilform home>/local-vault.json */
      path: z.string().optional(),
      /** minutes the derived key stays unlocked (session agent or this process) */
      unlockMinutes: z.number().int().min(0).max(480).default(15),
      kdf: z.enum(['argon2id', 'scrypt']).optional(),
      /** where the derived key is saved when the person opts in (veilform unlock --save-keychain) */
      keychain: z.object({ service: z.string().default('veilform'), account: z.string().default('local-vault-key') }).default({ service: 'veilform', account: 'local-vault-key' }),
      maxAttempts: z.number().int().min(1).max(100).default(5),
    })
    .default({ unlockMinutes: 15, keychain: { service: 'veilform', account: 'local-vault-key' }, maxAttempts: 5 }),
  ssh: z
    .object({
      binary: z.string().default('ssh'),
      hosts: z.record(z.string(), SshHost).default({}),
      connectTimeoutSeconds: z.number().int().positive().default(15),
    })
    .default({ binary: 'ssh', hosts: {}, connectTimeoutSeconds: 15 }),
  http: z
    .object({
      allowedHosts: z.array(z.string()).default([]),
      timeoutMs: z.number().int().positive().default(30_000),
      maxResponseBytes: z.number().int().positive().default(256 * 1024),
      allowInsecureLoopback: z.boolean().default(false),
    })
    .default({ allowedHosts: [], timeoutMs: 30_000, maxResponseBytes: 262144, allowInsecureLoopback: false }),
  exec: z
    .object({
      defaultTimeoutMs: z.number().int().positive().default(60_000),
      maxTimeoutMs: z.number().int().positive().default(600_000),
      maxOutputBytes: z.number().int().positive().default(64 * 1024),
      allowShell: z.boolean().default(true),
      redactEnvFiles: z.array(z.string()).default([]),
    })
    .default({ defaultTimeoutMs: 60000, maxTimeoutMs: 600000, maxOutputBytes: 65536, allowShell: true, redactEnvFiles: [] }),
  writeTargets: z.array(WriteTarget).default([]),
  databases: z.record(z.string(), Database).default({}),
  web: z
    .object({
      sites: z.record(z.string(), WebSite).default({}),
      headless: z.boolean().default(false),
      executablePath: z.string().optional(),
      sessionTtlHours: z.number().positive().default(12),
      stepTimeoutMs: z.number().int().positive().default(300_000),
    })
    .default({ sites: {}, headless: false, sessionTtlHours: 12, stepTimeoutMs: 300000 }),
  ops: z
    .object({ baseUrl: z.string().optional(), tokenRef: SecretRef.optional(), allowInsecureLoopback: z.boolean().default(false) })
    .default({ allowInsecureLoopback: false }),
  /** Destination used for internal material (ssh private keys, web sessions key). */
  internalDestination: z.string().optional(),
  /** Encrypted backup/sync of the vault and token shares (see README "Sync y compartir"). */
  sync: z
    .object({
      targets: z.record(z.string(), SyncTargetSchema).default({}),
      /** KDF for the passphrase; default argon2id when node:crypto has it, else scrypt. */
      kdf: z.enum(['argon2id', 'scrypt']).optional(),
      /** false = KEK from the second factor only (no passphrase). */
      passphrase: z.boolean().default(true),
      secondFactor: z
        .discriminatedUnion('type', [
          z.object({ type: z.literal('none') }),
          z.object({ type: z.literal('key-file'), path: z.string() }),
          z.object({ type: z.literal('keychain'), service: z.string().default('veilform'), account: z.string().default('sync-key') }),
        ])
        .default({ type: 'none' }),
      /** destinations included in exports (default: every readable local destination) */
      include: z.array(z.string()).optional(),
      /** keep the derived KEK in this process' memory for N minutes (0 = ask every time) */
      unlockMinutes: z.number().int().min(0).max(480).default(10),
      /** default target for share bundles */
      shareTarget: z.string().optional(),
      /** maximum share lifetime */
      maxShareSeconds: z.number().int().positive().default(30 * 86400),
    })
    .default({ targets: {}, passphrase: true, secondFactor: { type: 'none' }, unlockMinutes: 10, maxShareSeconds: 2592000 }),
  /** Encrypted .env files (veilform env ...). */
  env: z
    .object({
      /** globs of encrypted/plain .env files the MCP tools may operate on */
      files: z.array(z.string()).default(['**/.env', '**/.env.*']),
      /** key files tried automatically (besides VEILFORM_KEY_FILE and systemd credentials) */
      keyFiles: z.array(z.string()).default([]),
      /** OS keychain entry holding a key that is added as recipient by default */
      keychain: z.object({ service: z.string().default('veilform'), account: z.string().default('env-key') }).optional(),
      kdf: z.enum(['argon2id', 'scrypt']).optional(),
      /** failed passphrase attempts per file before a 15 min lockout */
      maxAttempts: z.number().int().min(1).max(100).default(5),
    })
    .default({ files: ['**/.env', '**/.env.*'], keyFiles: [], maxAttempts: 5 }),
});

export type Config = z.infer<typeof ConfigSchema>;

export interface Paths {
  home: string;
  configFile: string;
  auditFile: string;
  indexFile: string;
  approvalsFile: string;
  dataDir: string;
}

export function localVaultPath(cfg: Config, paths: Paths): string {
  return expandHome(cfg.localVault.path ?? path.join(paths.home, 'local-vault.json'));
}

export function resolvePaths(env: NodeJS.ProcessEnv = process.env): Paths {
  const home = expandHome(env.VEILFORM_HOME ?? path.join(env.XDG_CONFIG_HOME ?? path.join(homedir(), '.config'), 'veilform'));
  return {
    home,
    configFile: expandHome(env.VEILFORM_CONFIG ?? path.join(home, 'config.json')),
    auditFile: path.join(home, 'audit.jsonl'),
    indexFile: path.join(home, 'index.json'),
    approvalsFile: path.join(home, 'approvals.json'),
    dataDir: path.join(home, 'data'),
  };
}

export function loadConfig(paths: Paths): Config {
  mkdirSync(paths.home, { recursive: true, mode: 0o700 });
  let raw: unknown = {};
  if (existsSync(paths.configFile)) {
    try {
      raw = JSON.parse(readFileSync(paths.configFile, 'utf8'));
    } catch (e) {
      throw new UserError(`config ${paths.configFile} is not valid JSON: ${(e as Error).message}`);
    }
  }
  return parseConfig(raw);
}

export function parseConfig(raw: unknown): Config {
  const parsed = ConfigSchema.safeParse(raw);
  if (!parsed.success) {
    throw new UserError(`invalid config: ${parsed.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; ')}`);
  }
  const cfg = parsed.data;
  for (const [id, t] of Object.entries(cfg.sync.targets)) {
    if (t.type === 'ssh' && !cfg.ssh.hosts[t.host]) throw new UserError(`sync target ${id}: host is not in ssh.hosts allowlist`);
  }
  if (cfg.sync.shareTarget && !cfg.sync.targets[cfg.sync.shareTarget]) throw new UserError('sync.shareTarget is not a configured sync target');
  for (const [id, d] of Object.entries(cfg.destinations)) {
    if ((d.type === 'ssh-file' || (d.type === 'env-file' && d.host)) && !cfg.ssh.hosts[(d as { host: string }).host]) {
      throw new UserError(`destination ${id}: host is not in ssh.hosts allowlist`);
    }
  }
  return cfg;
}
