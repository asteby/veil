#!/usr/bin/env node
// Optional, harmless post-install step. It never changes anything, never runs sudo and never
// fails the install: it prints how to finish the setup. With VEILFORM_POSTINSTALL=init it shows
// the doctor report and the init plan (`init --dry-run`); applying it is always `veilform init`.
import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

try {
  const cli = fileURLToPath(new URL('../dist/cli.js', import.meta.url));
  const quiet = process.env.CI || process.env.VEILFORM_POSTINSTALL === 'off' || !existsSync(cli);
  if (!quiet) {
    if (process.env.VEILFORM_POSTINSTALL === 'init') spawnSync(process.execPath, [cli, 'init', '--dry-run'], { stdio: 'inherit' });
    else process.stderr.write('[veilform] next step: "npx veilform init" (diagnoses this machine and sets up a destination that works without installing anything)\n');
  }
} catch {
  /* never break an install */
}
