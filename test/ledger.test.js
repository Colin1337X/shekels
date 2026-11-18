import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { Ledger } from '../src/ledger.js';
import { generateAccountKeyPair, openInfo } from '../src/crypto.js';

function makeLedger(t) {
  const ledger = new Ledger({ path: ':memory:', fingerprintKey: Buffer.alloc(32, 7) });
  t.after(() => ledger.close());
  const keyPairs = {};
  function account(id) {
    keyPairs[id] = generateAccountKeyPair();
    ledger.createAccount({ id, publicKey: keyPairs[id].publicKey });
  }
  return { ledger, account, keyPairs };
}
const requestId = () => randomUUID();

test('issuance and transfer store PayerInfo and PayeeInfo for separate recipients', t => {
  const { ledger, account, keyPairs } = makeLedger(t);
  account('alice');
  account('bob');
  const issued = ledger.issue({ to: 'alice', amount: 100, requestId: requestId() });
  assert.equal(issued.transaction.kind, 'issuance');
  assert.equal(issued.transaction.PayerInfo, null);
  assert.deepEqual(openInfo(issued.transaction.PayeeInfo, keyPairs.alice.privateKeyPem, issued.transaction.id, 'PayeeInfo'),
    { transactionId: issued.transaction.id, amount: 100, payee: 'alice' });
  const sent = ledger.transfer({ from: 'alice', to: 'bob', amount: 30, requestId: requestId() });
  assert.equal(sent.created, true);
  const tx = sent.transaction;
  assert.deepEqual(openInfo(tx.PayerInfo, keyPairs.alice.privateKeyPem, tx.id, 'PayerInfo'),
    { transactionId: tx.id, amount: 30, payer: 'alice' });
  assert.deepEqual(openInfo(tx.PayeeInfo, keyPairs.bob.privateKeyPem, tx.id, 'PayeeInfo'),
    { transactionId: tx.id, amount: 30, payee: 'bob' });
  assert.throws(() => openInfo(tx.PayerInfo, keyPairs.bob.privateKeyPem, tx.id, 'PayerInfo'));
  assert.throws(() => openInfo(tx.PayeeInfo, keyPairs.alice.privateKeyPem, tx.id, 'PayeeInfo'));
  assert.equal(ledger.getAccount('alice').balance, 70);
  assert.equal(ledger.getAccount('bob').balance, 30);
  assert.deepEqual(ledger.getTransaction(tx.id), tx);
  const raw = ledger.db.prepare('SELECT PayerInfo, PayeeInfo FROM transactions WHERE id = ?').get(tx.id);
  assert.ok(raw.PayerInfo instanceof Uint8Array);
  assert.ok(raw.PayeeInfo instanceof Uint8Array);
  assert.equal(Buffer.from(raw.PayerInfo).includes(Buffer.from('"payer":"alice"')), false);
  assert.equal(Buffer.from(raw.PayeeInfo).includes(Buffer.from('"payee":"bob"')), false);
  assert.equal(Buffer.from(raw.PayerInfo).includes(Buffer.from('"amount":30')), false);
});

test('idempotent retries do not duplicate money or regenerate ciphertext', t => {
  const { ledger, account } = makeLedger(t);
  account('alice');
  account('bob');
  const issuance = { to: 'alice', amount: 40, requestId: requestId() };
  assert.equal(ledger.issue(issuance).created, true);
  assert.equal(ledger.issue(issuance).created, false);
  assert.equal(ledger.getAccount('alice').balance, 40);
  assert.throws(() => ledger.issue({ ...issuance, amount: 50 }), /already used/);
  const transfer = { from: 'alice', to: 'bob', amount: 10, requestId: requestId() };
  const first = ledger.transfer(transfer);
  const second = ledger.transfer(transfer);
  assert.equal(second.created, false);
  assert.deepEqual(first.transaction, second.transaction);
  assert.equal(ledger.getAccount('alice').balance, 30);
  assert.equal(ledger.getAccount('bob').balance, 10);
  assert.throws(() => ledger.transfer({ ...transfer, amount: 12 }), /already used/);
});

test('failures leave balances and journal intact', t => {
  const { ledger, account } = makeLedger(t);
  account('alice');
  account('bob');
  ledger.issue({ to: 'alice', amount: 15, requestId: requestId() });
  assert.throws(() => ledger.transfer({ from: 'alice', to: 'bob', amount: 16, requestId: requestId() }), /Insufficient funds/);
  assert.throws(() => ledger.transfer({ from: 'alice', to: 'charlie', amount: 10, requestId: requestId() }), /Destination account not found/);
  assert.equal(ledger.getAccount('alice').balance, 15);
  assert.equal(ledger.getAccount('bob').balance, 0);
  assert.equal(ledger.db.prepare('SELECT COUNT(*) AS n FROM transactions').get().n, 1);
});

test('validation prevents invalid account keys, amounts and self-transfers', t => {
  const { ledger, account, keyPairs } = makeLedger(t);
  account('alice');
  assert.throws(() => ledger.createAccount({ id: 'alice', publicKey: keyPairs.alice.publicKey }), /already exists/);
  assert.throws(() => ledger.createAccount({ id: 'other', publicKey: 'bogus' }), /publicKey/);
  assert.throws(() => ledger.createAccount({ id: '../admin', publicKey: keyPairs.alice.publicKey }), /Account ID/);
  assert.throws(() => ledger.issue({ to: 'alice', amount: 1.5, requestId: requestId() }), /safe JSON integer/);
  assert.throws(() => ledger.issue({ to: 'alice', amount: -1, requestId: requestId() }), /safe JSON integer/);
  assert.throws(() => ledger.issue({ to: 'alice', amount: 1, requestId: requestId(), extra: 'hi' }), /Unexpected field/);
  assert.throws(() => ledger.transfer({ from: 'alice', to: 'alice', amount: 1, requestId: requestId() }), /same account/);
  assert.equal(ledger.getAccount('alice').balance, 0);
});

test('overflow protection is atomic', t => {
  const { ledger, account } = makeLedger(t);
  account('alice');
  account('bob');
  ledger.issue({ to: 'bob', amount: Number.MAX_SAFE_INTEGER, requestId: requestId() });
  ledger.issue({ to: 'alice', amount: 1, requestId: requestId() });
  assert.throws(() => ledger.transfer({ from: 'alice', to: 'bob', amount: 1, requestId: requestId() }), /overflow/);
  assert.equal(ledger.getAccount('alice').balance, 1);
  assert.equal(ledger.getAccount('bob').balance, Number.MAX_SAFE_INTEGER);
});
