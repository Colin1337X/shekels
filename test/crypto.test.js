import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { generateAccountKeyPair, parseFingerprintKey, parsePublicKey, sealInfo, openInfo, requestFingerprint } from '../src/crypto.js';

const key = Buffer.alloc(32, 5);

test('validates fingerprint and X25519 public keys', () => {
  assert.throws(() => parseFingerprintKey('password'), /32 bytes/);
  assert.equal(parseFingerprintKey('a'.repeat(64)).length, 32);
  const payer = generateAccountKeyPair();
  assert.equal(parsePublicKey(payer.publicKey).asymmetricKeyType, 'x25519');
  assert.throws(() => parsePublicKey('not a public key'), /publicKey/);
  assert.throws(() => parsePublicKey(Buffer.alloc(256).toString('base64')), /publicKey/);
});

test('each envelope is independent, randomized, authenticated and recipient-only', () => {
  const id = randomUUID();
  const payer = generateAccountKeyPair();
  const payee = generateAccountKeyPair();
  const aliceData = { transactionId: id, amount: 12, payer: 'alice' };
  const bobData = { transactionId: id, amount: 12, payee: 'bob' };
  const a = sealInfo(aliceData, payer.publicKey, id, 'PayerInfo');
  const b = sealInfo(bobData, payee.publicKey, id, 'PayeeInfo');
  const a2 = sealInfo(aliceData, payer.publicKey, id, 'PayerInfo');
  assert.notDeepEqual(a, a2);
  assert.deepEqual(openInfo(a, payer.privateKeyPem, id, 'PayerInfo'), aliceData);
  assert.deepEqual(openInfo(b, payee.privateKeyPem, id, 'PayeeInfo'), bobData);
  assert.throws(() => openInfo(a, payee.privateKeyPem, id, 'PayerInfo'));
  assert.throws(() => openInfo(b, payer.privateKeyPem, id, 'PayeeInfo'));
  assert.throws(() => openInfo(a, payer.privateKeyPem, id, 'PayeeInfo'));
  assert.throws(() => openInfo(a, payer.privateKeyPem, randomUUID(), 'PayerInfo'));
  assert.throws(() => openInfo({ ...a, ciphertext: 'AAAA' }, payer.privateKeyPem, id, 'PayerInfo'));
});

test('fingerprints depend on all meaningful fields and secret key', () => {
  const request = { kind: 'transfer', from: 'alice', to: 'bob', amount: 10, requestId: randomUUID() };
  assert.equal(requestFingerprint(request, key), requestFingerprint(request, key));
  assert.notEqual(requestFingerprint(request, key), requestFingerprint({ ...request, amount: 11 }, key));
  assert.notEqual(requestFingerprint(request, key), requestFingerprint(request, Buffer.alloc(32, 7)));
});
