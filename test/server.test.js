import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { Ledger } from '../src/ledger.js';
import { generateAccountKeyPair, openInfo } from '../src/crypto.js';
import { createHttpServer } from '../src/server.js';

const token = 'c'.repeat(64);
const adminToken = 'd'.repeat(64);

async function setup(t) {
  const ledger = new Ledger({ path: ':memory:', fingerprintKey: Buffer.alloc(32, 1) });
  const server = createHttpServer({ ledger, apiToken: token, adminToken });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => {
    await new Promise(resolve => server.close(resolve));
    ledger.close();
  });
  const base = `http://127.0.0.1:${server.address().port}`;
  async function request(path, { method = 'GET', json, authorization = `Bearer ${token}`, contentType = 'application/json', raw } = {}) {
    const response = await fetch(`${base}${path}`, {
      method,
      headers: { Authorization: authorization, ...(json || raw ? { 'Content-Type': contentType } : {}) },
      body: json ? JSON.stringify(json) : raw,
    });
    return { status: response.status, headers: response.headers, body: await response.json() };
  }
  return { request };
}

test('only health is unauthenticated; encrypted PayerInfo and PayeeInfo work over HTTP', async t => {
  const { request } = await setup(t);
  const alice = generateAccountKeyPair();
  const bob = generateAccountKeyPair();
  assert.equal((await request('/health', { authorization: '' })).status, 200);
  assert.equal((await request('/v1/accounts/alice', { authorization: '' })).status, 401);
  assert.equal((await request('/v1/accounts/alice', { authorization: 'Bearer wrong' })).status, 401);
  assert.equal((await request('/v1/accounts', { method: 'POST', json: { id: 'alice', publicKey: alice.publicKey } })).status, 401);
  assert.equal((await request('/v1/accounts', { method: 'POST', json: { id: 'alice', publicKey: alice.publicKey }, authorization: `Bearer ${adminToken}` })).status, 201);
  assert.equal((await request('/v1/accounts', { method: 'POST', json: { id: 'bob', publicKey: bob.publicKey }, authorization: `Bearer ${adminToken}` })).status, 201);
  assert.equal((await request('/v1/issuances', { method: 'POST', json: { to: 'alice', amount: 50, requestId: randomUUID() } })).status, 401);
  const issued = await request('/v1/issuances', { method: 'POST', json: { to: 'alice', amount: 50, requestId: randomUUID() }, authorization: `Bearer ${adminToken}` });
  assert.equal(issued.status, 201);
  const payload = { from: 'alice', to: 'bob', amount: 20, requestId: randomUUID() };
  const sent = await request('/v1/transfers', { method: 'POST', json: payload });
  assert.equal(sent.status, 201);
  assert.equal(sent.body.transaction.PayerInfo.algorithm, 'X25519-HKDF-SHA256-AES-256-GCM');
  assert.equal(sent.body.transaction.PayeeInfo.algorithm, 'X25519-HKDF-SHA256-AES-256-GCM');
  assert.deepEqual(openInfo(sent.body.transaction.PayerInfo, alice.privateKeyPem, sent.body.transaction.id, 'PayerInfo'),
    { transactionId: sent.body.transaction.id, amount: 20, payer: 'alice' });
  assert.deepEqual(openInfo(sent.body.transaction.PayeeInfo, bob.privateKeyPem, sent.body.transaction.id, 'PayeeInfo'),
    { transactionId: sent.body.transaction.id, amount: 20, payee: 'bob' });
  const replay = await request('/v1/transfers', { method: 'POST', json: payload });
  assert.equal(replay.status, 200);
  assert.equal(replay.body.created, false);
  assert.equal((await request('/v1/accounts/alice')).body.account.balance, 30);
  assert.equal((await request('/v1/accounts/bob')).body.account.balance, 20);
  assert.deepEqual((await request(`/v1/transactions/${sent.body.transaction.id}`)).body.transaction, sent.body.transaction);
  assert.equal(sent.headers.get('cache-control'), 'no-store');
});

test('bad inputs and unsupported routes return safe errors', async t => {
  const { request } = await setup(t);
  assert.equal((await request('/v1/accounts', { method: 'POST', raw: '{bad', authorization: `Bearer ${adminToken}` })).status, 400);
  assert.equal((await request('/v1/accounts', { method: 'POST', raw: '{}', contentType: 'text/plain', authorization: `Bearer ${adminToken}` })).status, 415);
  assert.equal((await request('/v1/accounts', { method: 'POST', raw: JSON.stringify({ id: 'a' }) + ' '.repeat(9000), authorization: `Bearer ${adminToken}` })).status, 413);
  assert.equal((await request('/v1/accounts/x?oops=1')).status, 400);
  assert.equal((await request('/v1/other')).status, 404);
});
