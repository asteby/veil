import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { ElicitRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { variantsOf } from '../src/redact.js';
import { createServer } from '../src/server.js';
import { makeApp, prng, randomSecret, submit, approve, type TestApp } from './helpers.js';

async function connect(t: TestApp, capabilities: Record<string, unknown> = {}) {
  const server = createServer(t.app);
  const [ct, st] = InMemoryTransport.createLinkedPair();
  const wire: string[] = [];
  // record every raw JSON-RPC message the server sends to the client
  const origSend = st.send.bind(st);
  st.send = async (m, o) => {
    wire.push(JSON.stringify(m));
    return origSend(m, o);
  };
  await server.connect(st);
  const client = new Client({ name: 'test-client', version: '1.0' }, { capabilities });
  await client.connect(ct);
  return { client, server, wire };
}

const text = (r: unknown) => JSON.parse(((r as { content: { text: string }[] }).content[0]!).text) as Record<string, unknown>;

describe('MCP protocol surface', () => {
  let t: TestApp;
  afterEach(async () => t?.cleanup());

  it('exposes 27 tools with object input schemas', async () => {
    t = makeApp();
    const { client } = await connect(t);
    const { tools } = await client.listTools();
    expect(tools.map((x) => x.name).sort()).toEqual(
      [
        'blind_input', 'blind_input_preview', 'secret_delete', 'secret_list', 'secret_request', 'secret_rotate', 'secret_use', 'secret_wait', 'secret_write', 'ssh_exec', 'ssh_key_provision', 'web_capture', 'web_login',
        'vault_export', 'vault_sync', 'vault_import', 'vault_rekey', 'share_create', 'share_list', 'share_revoke', 'share_import', 'env_status', 'env_unlock', 'env_encrypt', 'env_edit', 'env_diff', 'env_rotate',
      ].sort(),
    );
    for (const tool of tools) expect(tool.inputSchema.type).toBe('object');
  });

  it('without URL elicitation the tool returns the local URL; with it, the call completes in one step', async () => {
    t = makeApp();
    const plain = await connect(t);
    const r1 = text(await plain.client.callTool({ name: 'secret_request', arguments: { title: 'A', fields: [{ name: 'A', label: 'A' }] } }));
    expect(r1.status).toBe('awaiting_user');

    // A client that supports URL-mode elicitation: it "opens" the URL (here: the person fills it).
    const el = await connect(t, { elicitation: { url: {} } });
    const seen: { mode?: string; url?: string; elicitationId?: string }[] = [];
    el.client.setRequestHandler(ElicitRequestSchema, async (req) => {
      seen.push(req.params as never);
      const url = (req.params as { url: string }).url;
      setTimeout(() => void submit(url, { B: 'elicited-secret-value-1' }), 50);
      return { action: 'accept' };
    });
    const r2 = text(await el.client.callTool({ name: 'secret_request', arguments: { title: 'B', fields: [{ name: 'B', label: 'B' }] } }));
    expect(seen[0]).toMatchObject({ mode: 'url' });
    expect(seen[0]!.url).toMatch(/^http:\/\/127\.0\.0\.1:\d+\/p\//);
    expect(r2).toEqual({ request_id: seen[0]!.elicitationId, status: 'completed', stored: ['B'] });
    expect(el.wire.join('\n')).not.toContain('elicited-secret-value-1');
    expect(el.wire.some((m) => m.includes('notifications/elicitation/complete'))).toBe(true);
  });

  it('declining the elicitation cancels the request', async () => {
    t = makeApp();
    const el = await connect(t, { elicitation: { url: {} } });
    el.client.setRequestHandler(ElicitRequestSchema, async () => ({ action: 'decline' }));
    const r = text(await el.client.callTool({ name: 'secret_request', arguments: { title: 'C', fields: [{ name: 'C', label: 'C' }] } }));
    expect(r.status).toBe('cancelled');
  });

  it('errors never echo argument values', async () => {
    t = makeApp();
    const { client } = await connect(t);
    const r = await client.callTool({ name: 'secret_request', arguments: { title: 'x', fields: [{ name: 'bad name with sk_live_ECHO', label: 'x' }] } });
    expect(r.isError).toBe(true);
    expect(JSON.stringify(r)).not.toContain('sk_live_ECHO');
  });

  it('property: over the wire, no JSON-RPC message ever carries a submitted or used value', async () => {
    const rnd = prng(99);
    for (let i = 0; i < 8; i++) {
      t = makeApp({ writeTargets: [{ kind: 'env-file', path: '**/.env' }] });
      const { client, wire } = await connect(t);
      const VALUE = randomSecret(rnd);
      const req = text(await client.callTool({ name: 'secret_request', arguments: { title: 'p', fields: [{ name: 'S', label: 'S' }, { name: 'NOTE', label: 'Note', kind: 'text' }] } }));
      await submit(String(req.url), { S: VALUE, NOTE: `note-${VALUE}` });
      text(await client.callTool({ name: 'secret_wait', arguments: { id: req.request_id } }));
      const use = text(await client.callTool({ name: 'secret_use', arguments: { action: 'exec', command: [process.execPath, '-e', 'process.stdout.write(process.env.S + " " + Buffer.from(process.env.S).toString("base64"))'], env: { S: '${secret:S}' } } }));
      await approve(String(use.url));
      const done = text(await client.callTool({ name: 'secret_wait', arguments: { id: use.request_id } }));
      expect(done.status).toBe('completed');
      const env = path.join(t.home, 'x', '.env');
      const wr = text(await client.callTool({ name: 'secret_write', arguments: { name: 'S', target: { kind: 'env-file', path: env } } }));
      await approve(String(wr.url));
      text(await client.callTool({ name: 'secret_wait', arguments: { id: wr.request_id } }));
      text(await client.callTool({ name: 'secret_list', arguments: {} }));
      const all = wire.join('\n') + readFileSync(path.join(t.home, 'audit.jsonl'), 'utf8');
      for (const v of variantsOf(VALUE)) expect(all.includes(v), `iteration ${i} variant ${JSON.stringify(v)}`).toBe(false);
      await t.cleanup();
    }
  }, 120_000);
});
