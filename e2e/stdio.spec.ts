import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { expect, test } from '@playwright/test';

const CLI = path.resolve('dist/cli.js');
const SHOTS = process.env.SHOTS_DIR ?? path.join('test-results', 'shots');

test.skip(!existsSync(CLI), 'run `pnpm build` first');

test('full stack over stdio: the built server, a real MCP client and a real browser', async ({ page }) => {
  const home = mkdtempSync(path.join(tmpdir(), 'si-stdio-'));
  writeFileSync(
    path.join(home, 'config.json'),
    JSON.stringify({
      defaultDestination: 'vault',
      ui: { openBrowser: false, lang: 'en' },
      destinations: { vault: { type: 'encrypted-file', path: path.join(home, 'secrets.enc'), key: { source: 'env', env: 'VEIL_PASSPHRASE' } } },
      writeTargets: [{ kind: 'env-file', path: path.join(home, '**') }],
    }),
  );
  const stderr: string[] = [];
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [CLI],
    env: { ...(process.env as Record<string, string>), VEIL_HOME: home, VEIL_PASSPHRASE: 'e2e passphrase 1234', VEIL_AGENT: 'playwright-e2e' },
    stderr: 'pipe',
  });
  transport.stderr?.on('data', (d) => stderr.push(String(d)));
  const client = new Client({ name: 'e2e', version: '1' });
  await client.connect(transport);
  const wire: string[] = [];
  const call = async (name: string, args: Record<string, unknown>) => {
    const r = await client.callTool({ name, arguments: args });
    const text = (r.content as { text: string }[])[0]!.text;
    wire.push(text);
    return JSON.parse(text) as Record<string, unknown>;
  };
  const VALUE = 'sk_live_E2E_9f8e7d6c5b4a3210zz';

  const req = await call('secret_request', { title: 'Stripe (stdio e2e)', fields: [{ name: 'STRIPE_KEY', label: 'Secret key' }] });
  await page.goto(String(req.url));
  await page.getByLabel('Secret key').fill(VALUE);
  await page.getByRole('button', { name: 'Save securely' }).click();
  await expect(page.getByRole('status')).toContainText('Saved', { timeout: 30_000 });
  expect(await call('secret_wait', { id: req.request_id })).toMatchObject({ status: 'completed', stored: ['STRIPE_KEY'] });

  const use = await call('secret_use', { action: 'exec', command: [process.execPath, '-e', 'process.stdout.write("key=" + process.env.K)'], env: { K: '${secret:STRIPE_KEY}' } });
  await page.goto(String(use.url));
  await page.screenshot({ path: path.join(SHOTS, '12-stdio-approval.png'), fullPage: true });
  await page.getByRole('button', { name: 'Approve' }).click();
  const done = await call('secret_wait', { id: use.request_id });
  expect(done).toMatchObject({ status: 'completed', exit_code: 0, stdout: 'key=[REDACTED:STRIPE_KEY]' });

  const envFile = path.join(home, 'app', '.env');
  const wr = await call('secret_write', { name: 'STRIPE_KEY', target: { kind: 'env-file', path: envFile } });
  await page.goto(String(wr.url));
  await page.getByRole('button', { name: 'Approve' }).click();
  expect(await call('secret_wait', { id: wr.request_id })).toMatchObject({ written: true, keys: [{ key: 'STRIPE_KEY', action: 'created' }] });
  expect(readFileSync(envFile, 'utf8')).toBe(`STRIPE_KEY=${VALUE}\n`);

  await client.close();
  const everything = [...wire, stderr.join(''), readFileSync(path.join(home, 'audit.jsonl'), 'utf8'), readFileSync(path.join(home, 'secrets.enc'), 'utf8')].join('\n');
  expect(everything).not.toContain(VALUE);
  expect(everything).not.toContain(Buffer.from(VALUE).toString('base64'));
});
