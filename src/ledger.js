import { randomUUID, timingSafeEqual } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { parsePublicKey, sealInfo, requestFingerprint } from './crypto.js';

export const MAX_BALANCE = Number.MAX_SAFE_INTEGER;

export class LedgerError extends Error {
  constructor(status, code, message) {
    super(message);
    this.name = 'LedgerError';
    this.status = status;
    this.code = code;
  }
}

function badRequest(message) { throw new LedgerError(400, 'invalid_request', message); }
function conflict(message) { throw new LedgerError(409, 'conflict', message); }
function notFound(message) { throw new LedgerError(404, 'not_found', message); }

function requireObject(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) badRequest('Expected a JSON object');
}

function requireFields(value, names) {
  requireObject(value);
  for (const key of Object.keys(value)) {
    if (!names.includes(key)) badRequest(`Unexpected field: ${key}`);
  }
}

export function validateAccountId(value) {
  if (typeof value !== 'string' || !/^[a-zA-Z0-9_-]{1,64}$/.test(value)) {
    badRequest('Account ID must be 1-64 ASCII letters, digits, underscores, or hyphens');
  }
  return value;
}

function validateRequestId(value) {
  if (typeof value !== 'string' || !/^[a-zA-Z0-9_-]{16,100}$/.test(value)) {
    badRequest('requestId must be 16-100 ASCII letters, digits, underscores, or hyphens');
  }
  return value;
}

function validateAmount(value) {
  if (!Number.isSafeInteger(value) || value <= 0) {
    badRequest('amount must be a positive, safe JSON integer in the smallest currency unit');
  }
  return value;
}

function validateAccountPublicKey(value) {
  try {
    parsePublicKey(value);
  } catch {
    badRequest('publicKey must be a valid base64-encoded X25519 SPKI DER public key');
  }
  return value;
}

function parseStoredInfo(value) {
  return value === null ? null : JSON.parse(Buffer.from(value).toString('utf8'));
}

export class Ledger {
  constructor({ path, fingerprintKey }) {
    if (!Buffer.isBuffer(fingerprintKey) || fingerprintKey.length !== 32) {
      throw new Error('Ledger needs a 32-byte fingerprint key');
    }
    this.fingerprintKey = fingerprintKey;
    this.db = new DatabaseSync(path);
    this.db.exec('PRAGMA foreign_keys = ON');
    this.db.exec('PRAGMA busy_timeout = 5000');
    // Refuse to silently reuse an older DB with a different transaction schema.
    const oldTransactions = this.db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'transactions'").get();
    if (oldTransactions) {
      const columns = this.db.prepare('PRAGMA table_info(transactions)').all().map(row => row.name);
      if (!columns.includes('PayerInfo') || !columns.includes('PayeeInfo')) {
        this.db.close();
        throw new Error('Incompatible transactions schema: back up and migrate the database before starting Shekels v0.3');
      }
    }
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS accounts (
        id TEXT PRIMARY KEY,
        public_key TEXT NOT NULL,
        balance INTEGER NOT NULL DEFAULT 0 CHECK(balance >= 0 AND balance <= ${MAX_BALANCE})
      );
      CREATE TABLE IF NOT EXISTS transactions (
        id TEXT PRIMARY KEY,
        request_id TEXT NOT NULL UNIQUE,
        request_fingerprint TEXT NOT NULL,
        kind TEXT NOT NULL CHECK(kind IN ('issuance', 'transfer')),
        from_account TEXT REFERENCES accounts(id),
        to_account TEXT NOT NULL REFERENCES accounts(id),
        amount INTEGER NOT NULL CHECK(amount > 0 AND amount <= ${MAX_BALANCE}),
        created_at TEXT NOT NULL,
        PayerInfo BLOB,
        PayeeInfo BLOB NOT NULL,
        CHECK ((kind = 'issuance' AND from_account IS NULL AND PayerInfo IS NULL) OR
               (kind = 'transfer' AND from_account IS NOT NULL AND PayerInfo IS NOT NULL))
      );
      CREATE INDEX IF NOT EXISTS transactions_from_idx ON transactions(from_account);
      CREATE INDEX IF NOT EXISTS transactions_to_idx ON transactions(to_account);
    `);
    const accountColumns = this.db.prepare('PRAGMA table_info(accounts)').all().map(row => row.name);
    if (!accountColumns.includes('public_key')) {
      this.db.close();
      throw new Error('Incompatible accounts schema: a public key is required for every account');
    }

    this.selectAccount = this.db.prepare('SELECT id, public_key, balance FROM accounts WHERE id = ?');
    this.selectByRequest = this.db.prepare('SELECT * FROM transactions WHERE request_id = ?');
    this.selectTransaction = this.db.prepare('SELECT * FROM transactions WHERE id = ?');
    this.debit = this.db.prepare('UPDATE accounts SET balance = balance - ? WHERE id = ? AND balance >= ?');
    this.credit = this.db.prepare('UPDATE accounts SET balance = balance + ? WHERE id = ? AND balance <= ?');
    this.insertTransaction = this.db.prepare(`
      INSERT INTO transactions
      (id, request_id, request_fingerprint, kind, from_account, to_account, amount,
       created_at, PayerInfo, PayeeInfo)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
  }

  close() { this.db.close(); }

  createAccount(input) {
    requireFields(input, ['id', 'publicKey']);
    const id = validateAccountId(input.id);
    const publicKey = validateAccountPublicKey(input.publicKey);
    if (this.selectAccount.get(id)) conflict('Account already exists');
    this.db.prepare('INSERT INTO accounts (id, public_key) VALUES (?, ?)').run(id, publicKey);
    return { id, publicKey, balance: 0 };
  }

  getAccount(id) {
    validateAccountId(id);
    const account = this.selectAccount.get(id);
    if (!account) notFound('Account not found');
    return { id: account.id, publicKey: account.public_key, balance: account.balance };
  }

  getTransaction(id) {
    if (typeof id !== 'string' || !/^[0-9a-f-]{36}$/i.test(id)) badRequest('Invalid transaction ID');
    const row = this.selectTransaction.get(id);
    if (!row) notFound('Transaction not found');
    return this.formatTransaction(row);
  }

  formatTransaction(row) {
    return {
      id: row.id,
      kind: row.kind,
      from: row.from_account,
      to: row.to_account,
      amount: row.amount,
      createdAt: row.created_at,
      PayerInfo: parseStoredInfo(row.PayerInfo),
      PayeeInfo: parseStoredInfo(row.PayeeInfo),
    };
  }

  issue(input) {
    requireFields(input, ['to', 'amount', 'requestId']);
    const to = validateAccountId(input.to);
    const amount = validateAmount(input.amount);
    const requestId = validateRequestId(input.requestId);
    return this.record({ kind: 'issuance', from: null, to, amount, requestId });
  }

  transfer(input) {
    requireFields(input, ['from', 'to', 'amount', 'requestId']);
    const from = validateAccountId(input.from);
    const to = validateAccountId(input.to);
    if (from === to) badRequest('Cannot transfer to the same account');
    const amount = validateAmount(input.amount);
    const requestId = validateRequestId(input.requestId);
    return this.record({ kind: 'transfer', from, to, amount, requestId });
  }

  record(request) {
    const fingerprint = requestFingerprint(request, this.fingerprintKey);
    const previous = this.selectByRequest.get(request.requestId);
    if (previous) return this.replayed(previous, fingerprint);

    // Balances, envelope creation, and journal insertion happen in one SQLite write transaction.
    this.db.exec('BEGIN IMMEDIATE');
    let committed = false;
    try {
      const existing = this.selectByRequest.get(request.requestId);
      if (existing) {
        this.db.exec('COMMIT');
        committed = true;
        return this.replayed(existing, fingerprint);
      }
      const recipient = this.selectAccount.get(request.to);
      if (!recipient) notFound('Destination account not found');
      let payer = null;
      if (request.from) {
        payer = this.selectAccount.get(request.from);
        if (!payer) notFound('Source account not found');
        if (this.debit.run(request.amount, request.from, request.amount).changes !== 1) {
          conflict('Insufficient funds');
        }
      }
      if (this.credit.run(request.amount, request.to, MAX_BALANCE - request.amount).changes !== 1) {
        conflict('Destination balance would overflow');
      }
      const id = randomUUID();
      const payerInfo = payer === null ? null : sealInfo(
        { transactionId: id, amount: request.amount, payer: payer.id },
        payer.public_key, id, 'PayerInfo',
      );
      const payeeInfo = sealInfo(
        { transactionId: id, amount: request.amount, payee: recipient.id },
        recipient.public_key, id, 'PayeeInfo',
      );
      this.insertTransaction.run(
        id, request.requestId, fingerprint, request.kind, request.from, request.to,
        request.amount, new Date().toISOString(),
        payerInfo === null ? null : Buffer.from(JSON.stringify(payerInfo)),
        Buffer.from(JSON.stringify(payeeInfo)),
      );
      this.db.exec('COMMIT');
      committed = true;
      return { created: true, transaction: this.getTransaction(id) };
    } catch (error) {
      if (!committed) this.db.exec('ROLLBACK');
      throw error;
    }
  }

  replayed(row, fingerprint) {
    if (!timingSafeEqual(Buffer.from(row.request_fingerprint, 'hex'), Buffer.from(fingerprint, 'hex'))) {
      conflict('requestId was already used with different transaction details');
    }
    return { created: false, transaction: this.formatTransaction(row) };
  }
}
