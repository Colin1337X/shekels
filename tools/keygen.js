import { writeFileSync } from 'node:fs';
import { generateAccountKeyPair } from '../src/crypto.js';

const output = process.argv[2];
if (!output || process.argv.length !== 3) {
  console.error('Usage: node tools/keygen.js <private-key-output.pem>');
  process.exitCode = 2;
} else {
  const { publicKey, privateKeyPem } = generateAccountKeyPair();
  // Never overwrite an existing private key. Restrict permissions on creation.
  writeFileSync(output, privateKeyPem, { flag: 'wx', mode: 0o600 });
  console.log(JSON.stringify({ publicKey, privateKeyFile: output }, null, 2));
}
