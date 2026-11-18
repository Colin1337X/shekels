import { createHash, timingSafeEqual } from 'node:crypto';
import { createServer } from 'node:http';
import { LedgerError } from './ledger.js';

const MAX_BODY_BYTES = 8192;

function send(res, status, body) {
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
  });
  res.end(JSON.stringify(body));
}

function forbidden() {
  throw new LedgerError(401, 'unauthorized', 'Valid bearer token required');
}

function authenticate(req, expectedHash) {
  const header = req.headers.authorization;
  if (typeof header !== 'string' || !header.startsWith('Bearer ')) forbidden();
  const token = header.slice(7);
  const hash = createHash('sha256').update(token).digest();
  if (!timingSafeEqual(hash, expectedHash)) forbidden();
}

async function parseBody(req) {
  if (!/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(req.headers['content-type'] ?? '')) {
    throw new LedgerError(415, 'unsupported_media_type', 'Use Content-Type: application/json');
  }
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) {
      throw new LedgerError(413, 'payload_too_large', 'JSON body exceeds 8192 bytes');
    }
    chunks.push(chunk);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    throw new LedgerError(400, 'invalid_json', 'Request body must be valid JSON');
  }
}

function hashConfiguredToken(value, name) {
  if (typeof value !== 'string' || !/^[0-9a-fA-F]{64,}$/.test(value) || value.length % 2 !== 0) {
    throw new Error(`${name} must be at least 32 random bytes encoded in hex`);
  }
  return createHash('sha256').update(value).digest();
}

export function createHttpServer({ ledger, apiToken, adminToken }) {
  const expectedHash = hashConfiguredToken(apiToken, 'SHEKELS_API_TOKEN');
  const adminHash = hashConfiguredToken(adminToken, 'SHEKELS_ADMIN_TOKEN');
  if (timingSafeEqual(expectedHash, adminHash)) {
    throw new Error('Admin and API tokens must be different');
  }

  const server = createServer(async (req, res) => {
    try {
      const url = new URL(req.url, 'http://localhost');
      if (req.method === 'GET' && url.pathname === '/health') {
        return send(res, 200, { status: 'ok' });
      }
      if (url.search !== '') {
        throw new LedgerError(400, 'invalid_request', 'Query parameters are not supported');
      }
      const isAdminAction = req.method === 'POST' &&
        (url.pathname === '/v1/accounts' || url.pathname === '/v1/issuances');
      authenticate(req, isAdminAction ? adminHash : expectedHash);

      if (req.method === 'POST' && url.pathname === '/v1/accounts') {
        const account = ledger.createAccount(await parseBody(req));
        return send(res, 201, { account });
      }
      if (req.method === 'POST' && url.pathname === '/v1/issuances') {
        const result = ledger.issue(await parseBody(req));
        return send(res, result.created ? 201 : 200, result);
      }
      if (req.method === 'POST' && url.pathname === '/v1/transfers') {
        const result = ledger.transfer(await parseBody(req));
        return send(res, result.created ? 201 : 200, result);
      }
      if (req.method === 'GET' && url.pathname.startsWith('/v1/accounts/')) {
        const id = url.pathname.slice('/v1/accounts/'.length);
        return send(res, 200, { account: ledger.getAccount(id) });
      }
      if (req.method === 'GET' && url.pathname.startsWith('/v1/transactions/')) {
        const id = url.pathname.slice('/v1/transactions/'.length);
        return send(res, 200, { transaction: ledger.getTransaction(id) });
      }
      return send(res, 404, { error: { code: 'not_found', message: 'Route not found' } });
    } catch (error) {
      if (error instanceof LedgerError) {
        return send(res, error.status, { error: { code: error.code, message: error.message } });
      }
      // Don't disclose DB paths, SQL, keys or decryption errors to API clients.
      console.error('Request failed:', error);
      return send(res, 500, { error: { code: 'internal_error', message: 'Internal server error' } });
    }
  });
  server.requestTimeout = 10_000;
  server.headersTimeout = 10_000;
  server.maxHeadersCount = 40;
  return server;
}
