import { readFileSync } from 'node:fs';
import { openInfo } from '../src/crypto.js';

const [, , privateKeyPath, role, transactionJsonPath] = process.argv;
if (!privateKeyPath || !transactionJsonPath || !['PayerInfo', 'PayeeInfo'].includes(role) || process.argv.length !== 5) {
  console.error('Usage: node tools/decrypt.js <private-key.pem> <PayerInfo|PayeeInfo> <transaction.json>');
  process.exitCode = 2;
} else {
  const input = JSON.parse(readFileSync(transactionJsonPath, 'utf8'));
  // Accept an API response from either create-transfer or fetch-transaction.
  const transaction = input.transaction ?? input;
  const envelope = transaction[role];
  if (envelope === null || envelope === undefined) {
    throw new Error(`Transaction has no ${role} envelope`);
  }
  const privateKeyPem = readFileSync(privateKeyPath, 'utf8');
  console.log(JSON.stringify(openInfo(envelope, privateKeyPem, transaction.id, role), null, 2));
}
