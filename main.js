import { Ledger } from './src/ledger.js';
import { parseFingerprintKey } from './src/crypto.js';
import { createHttpServer } from './src/server.js';

const port = Number(process.env.PORT ?? 1000);
if (!Number.isInteger(port) || port < 1 || port > 65535) {
  throw new Error('PORT must be an integer between 1 and 65535');
}
const host = process.env.HOST ?? '127.0.0.1';
const fingerprintKey = parseFingerprintKey(process.env.SHEKELS_FINGERPRINT_KEY);
const apiToken = process.env.SHEKELS_API_TOKEN;
const adminToken = process.env.SHEKELS_ADMIN_TOKEN;
const ledger = new Ledger({
  path: process.env.SHEKELS_DB_PATH ?? './shekels.sqlite',
  fingerprintKey,
});
const server = createHttpServer({ ledger, apiToken, adminToken });
server.listen(port, host, () => console.log(`Shekels listening on http://${host}:${port}`));

function shutdown() {
  server.close(() => {
    ledger.close();
    process.exitCode = 0;
  });
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
