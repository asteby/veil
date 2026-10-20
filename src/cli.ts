#!/usr/bin/env node
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { App } from './app.js';
import { verifyAuditLog } from './audit.js';
import { resolvePaths, loadConfig } from './config.js';
import { createServer, VERSION } from './server.js';
import { runVaultCli, VAULT_HELP } from './cli-vault.js';
import { runSetupCli, SETUP_HELP } from './cli-setup.js';

async function main(): Promise<void> {
  const arg = process.argv[2];
  if (arg === '--version' || arg === '-v') {
    process.stdout.write(`${VERSION}\n`);
    return;
  }
  if (arg === 'check-config') {
    const paths = resolvePaths();
    const cfg = loadConfig(paths);
    process.stdout.write(
      JSON.stringify(
        { config: paths.configFile, home: paths.home, destinations: Object.keys(cfg.destinations), ssh_hosts: Object.keys(cfg.ssh.hosts), databases: Object.keys(cfg.databases), web_sites: Object.keys(cfg.web.sites), write_targets: cfg.writeTargets.length },
        null,
        2,
      ) + '\n',
    );
    return;
  }
  if (arg === 'verify-audit') {
    const bad = verifyAuditLog(resolvePaths().auditFile);
    process.stdout.write(bad ? `audit log broken at line ${bad}\n` : 'audit log OK\n');
    process.exitCode = bad ? 1 : 0;
    return;
  }
  if (arg === 'help' || arg === '--help' || arg === '-h') {
    process.stdout.write(`${VAULT_HELP}\n\nSetup:\n${SETUP_HELP}\n`);
    return;
  }
  const setup = await runSetupCli(process.argv.slice(2), () => new App());
  if (setup !== undefined) {
    process.exitCode = setup;
    return;
  }
  const code = await runVaultCli(process.argv.slice(2), () => new App());
  if (code !== undefined) {
    process.exitCode = code;
    return;
  }
  if (arg && arg !== 'serve') {
    process.stderr.write(`unknown command ${arg}; try "veilform help"\n`);
    process.exitCode = 2;
    return;
  }
  const app = new App();
  const server = createServer(app);
  const transport = new StdioServerTransport();
  let closing = false;
  const close = async () => {
    if (closing) return;
    closing = true;
    await app.shutdown().catch(() => undefined);
    await server.close().catch(() => undefined);
    process.exit(0);
  };
  process.on('SIGINT', close);
  process.on('SIGTERM', close);
  process.stdin.on('close', close);
  process.on('exit', () => {
    app.vault.clearCache();
    app.keys.stop();
  });
  await server.connect(transport);
}

main().catch((e) => {
  console.error(`[veilform] fatal: ${e instanceof Error && e.name === 'UserError' ? e.message : 'startup failed'}`);
  process.exit(1);
});
