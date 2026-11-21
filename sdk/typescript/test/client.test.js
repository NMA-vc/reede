import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { readFile, mkdtemp, writeFile, rm } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
// Explicit installed-package checks can select a trusted local module. The Cargo
// source conformance runner clears this override to test this checkout exactly.
const { ReedeClient, AgentHostClient, ReedeError, verifyFile } = await import(process.env.REEDE_SDK_NODE_MODULE ?? '../src/index.js');

const ID = '00000000-0000-0000-0000-000000000001';

async function fixture(t) {
  const requests = [], responses = [];
  const server = createServer(async (req, res) => {
    let body = '';
    for await (const part of req) body += part;
    const json = body ? JSON.parse(body) : undefined;
    requests.push({ method: req.method, path: req.url, token: req.headers.authorization, body: json });
    let [code, value] = responses.shift() ?? [200, []];
    if (value === 'rpc') value = { jsonrpc: '2.0', id: json.id, result: { task_id: ID } };
    res.writeHead(code, { 'retry-after': '0', location: '/credential-sink' });
    res.end(typeof value === 'string' ? value : JSON.stringify(value));
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => new Promise(resolve => { server.closeAllConnections(); server.close(resolve); }));
  const url = `http://127.0.0.1:${server.address().port}`;
  return { requests, responses, url, client: new ReedeClient(url, 'secret-token', { allowLocalHttp: true }) };
}

test('lifecycle routes use bearer authority and reject redirects', async t => {
  const { client, requests, responses } = await fixture(t);
  responses.push([200, []], [200, { id: ID }], [200, []], [202, { id: ID }]);
  await client.listTasks({ limit: 3 }); await client.getTask(ID); await client.listLeases(ID); await client.cancelTask(ID);
  assert.deepEqual(requests.map(r => r.path), ['/api/v1/reede/tasks?limit=3', `/api/v1/reede/tasks/${ID}`, `/api/v1/reede/tasks/${ID}/leases`, `/api/v1/reede/tasks/${ID}/cancel`]);
  assert.ok(requests.every(r => r.token === 'Bearer secret-token'));
  responses.push([302, {}]);
  await assert.rejects(client.getTask(ID), ReedeError);
  assert.equal(requests.length, 5);
  assert.ok(!JSON.stringify(client).includes('secret-token'));
});

test('transient reads retry; mutations do not and errors omit response content', async t => {
  const { client, requests, responses } = await fixture(t);
  responses.push([503, { private: 'secret-token' }], [200, []]);
  await client.listTasks(); assert.equal(requests.length, 2);
  responses.push([503, { private: 'secret-token' }]);
  await assert.rejects(client.cancelTask(ID), error => error.code === 'server_error' && !error.message.includes('secret-token'));
  assert.equal(requests.length, 3);
});

test('host RPC matches implemented operations and preserves invocation identity', async t => {
  const { url, requests, responses } = await fixture(t);
  const host = new AgentHostClient(url, 'token', { allowLocalHttp: true });
  responses.push(...Array.from({ length: 8 }, () => [200, 'rpc']));
  await host.submit('agent', { topic: 'spring' }, { invocationId: 'stable' });
  await host.start(ID); await host.status(ID); await host.decide('key', 'approve', { editedOutput: 'reviewed' }); await host.cancel(ID);
  await host.pendingTools({ taskId: ID, limit: 20 }); await host.decideTool('tool-key', 'approve');
  await host.recover(ID);
  assert.deepEqual(requests.map(r => r.body.method), ['task.submit', 'task.start', 'task.status', 'task.decide', 'task.cancel', 'task.tool_pending', 'task.tool_decide', 'task.recover']);
  assert.equal(requests[0].body.params.invocation_id, 'stable');
  assert.equal(requests[3].body.params.edited_output, 'reviewed');
  assert.deepEqual(requests[5].body.params, { task_id: ID, limit: 20 });
  assert.deepEqual(requests[6].body.params, { approval_key: 'tool-key', decision: 'approve' });
  assert.deepEqual(requests[7].body.params, { task_id: ID });
});

test('large integer responses preserve source decimals', async t => {
  const { client, responses } = await fixture(t);
  responses.push([200, '[{"credits":9223372036854775807}]']);
  const data = await client.listTasks();
  assert.equal(data[0].credits, '9223372036854775807');
});

test('unsafe URLs and path injection fail before network access', async () => {
  for (const url of ['http://example.com', 'https://token@example.com', 'https://example.com?tenant=x', 'https://example.com#x']) assert.throws(() => new ReedeClient(url, 'token'));
  const client = new ReedeClient('https://example.com', 'token');
  await assert.rejects(client.getTask('../../secrets'), TypeError);
  const host = new AgentHostClient('https://example.com', 'token');
  for (const limit of [0, 101, true, 1.5]) assert.throws(() => host.pendingTools({ limit }), TypeError);
  assert.throws(() => host.pendingTools({ taskId: '../../secrets' }), TypeError);
  assert.throws(() => host.decideTool('key', 'maybe'), TypeError);
});

test('shared Rust offline verifier accepts vector and rejects tamper', { skip: !process.env.REEDE_VERIFY_BIN }, async t => {
  const load = async name => JSON.parse(await readFile(new URL(`../../../tests/fixtures/${name}`, import.meta.url), 'utf8'));
  const dir = await mkdtemp(join(tmpdir(), 'reede-sdk-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const file = join(dir, 'chain.json');
  const verifier = process.env.REEDE_VERIFY_BIN;
  const write = receipt => writeFile(file, JSON.stringify([receipt]));

  // reede-v2 (what Reede emits): the vector is the chain's seq-2 link, so it is a
  // trusted-head segment, not a whole history.
  const v2 = await load('reede-v2-vector.json');
  const r2 = v2.receipt;
  assert.equal(r2.format, 'reede-v2');
  await write(r2);
  const trusted = { verifier, expectedHead: r2.content_hash, expectedCount: 1 };
  const report = await verifyFile(file, v2.pubkey_hex, trusted);
  assert.equal(report.completeness, 'supplied_segment_only');
  await assert.rejects(verifyFile(file, v2.pubkey_hex, { ...trusted, requireGenesis: true }), ReedeError);
  // Every signed v2 field is tamper-evident, including the outer sequence_no and timestamp.
  for (const [field, value] of [['credits_spent', r2.credits_spent + 1], ['sequence_no', 3], ['timestamp', '2023-11-14T22:13:21.123456Z']]) {
    await write({ ...r2, [field]: value });
    await assert.rejects(verifyFile(file, v2.pubkey_hex, { verifier }), ReedeError, field);
    // The SDK error is opaque by design; ask the verifier itself for the reason.
    const out = spawnSync(verifier, ['--chain', file, '--pubkey', v2.pubkey_hex, '--json'], { encoding: 'utf8' });
    assert.equal(out.status, 1, field);
    assert.match(JSON.parse(out.stdout).error, /content_hash mismatch/, field);
  }

  // reede-v1 (legacy): still recomputed and accepted; its genesis vector verifies whole.
  const v1 = await load('reede-v1-vector.json');
  const r1 = v1.receipt;
  assert.equal(r1.format, 'reede-v1');
  await write(r1);
  const whole = await verifyFile(file, v1.pubkey_hex, { verifier, expectedHead: r1.content_hash, expectedCount: 1, requireGenesis: true });
  assert.equal(whole.completeness, 'verified_against_trusted_boundary');
  await write({ ...r1, credits_spent: r1.credits_spent + 1 });
  await assert.rejects(verifyFile(file, v1.pubkey_hex, { verifier }), ReedeError);
});

