# Shekels

**Shekels v0.3** is a compact, server-authoritative school-currency ledger with **two independently public-key-encrypted transaction fields**. The payer can decrypt `PayerInfo` using their private key; the payee can decrypt `PayeeInfo` using theirs. The server stores **only recipient public keys** and never needs an account's private key.

> **Important privacy distinction:** The server **creates** the encrypted views from transfer data it has already validated. The server still sees and stores account IDs, amounts and balances in plaintext so it can enforce conservation of currency. This is **recipient-only encryption at rest**, not a server-blind or fully end-to-end encrypted payment protocol. A system that conceals balances and amounts from the validating server while preventing counterfeiting requires an additional cryptographic protocol (such as verifiable commitments and conservation proofs).

## Design

### Database

```sql
CREATE TABLE accounts (
  id TEXT PRIMARY KEY,
  public_key TEXT NOT NULL,  -- X25519 SPKI DER, base64
  balance INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE transactions (
  id TEXT PRIMARY KEY,
  request_id TEXT NOT NULL UNIQUE,
  request_fingerprint TEXT NOT NULL,
  kind TEXT NOT NULL,         -- issuance or transfer
  from_account TEXT,         -- server-authoritative audit metadata
  to_account TEXT NOT NULL,
  amount INTEGER NOT NULL,   -- server-authoritative accounting amount
  created_at TEXT NOT NULL,
  PayerInfo BLOB,            -- null for issuance
  PayeeInfo BLOB NOT NULL
);
```

The actual tables additionally enforce constraints, foreign keys and indexes; the SQL above is an abbreviated layout.

For a transfer of 25 units from Alice to Bob, the server encrypts the following **separately**:

`PayerInfo` (Alice's public key):

```json
{"transactionId":"<id>","amount":25,"payer":"alice"}
```

`PayeeInfo` (Bob's public key):

```json
{"transactionId":"<id>","amount":25,"payee":"bob"}
```

These plaintext samples describe the **data before encryption**, not what is stored. Each BLOB holds a JSON-serialized authenticated-encryption envelope with version, algorithm, ephemeral public key, salt, nonce, ciphertext, and tag. HTTP responses return each envelope as a JSON object. `PayerInfo` is `null` for admin issuances, since no account paid; `PayeeInfo` is encrypted to the receiving account as usual.

**Cryptography:** Ephemeral X25519 ECDH + HKDF-SHA256 + AES-256-GCM; fresh ephemeral key, 32-byte salt and 12-byte nonce for **each recipient and each transfer**. The AEAD associated data binds each ciphertext to its transaction ID and `PayerInfo`/`PayeeInfo` role. Using the wrong private key, swapping roles, moving ciphertext to another transaction, or modifying the envelope fails authentication. Cryptographic envelopes are never reused on a retry: the same `requestId` returns the original transaction without changing balances.

**Accounting:** Transfers debit and credit inside a single SQLite write transaction. A debit fails on insufficient funds, credits fail on overflow, and failed transfers roll back. Issuance requires an **admin token**, so normal transfer requests cannot create currency. There is no arbitrary balance-setting API and no raw-SQL endpoint.

## Requirements

- **Node.js 22.13+** (`node:sqlite`; Node 24 LTS recommended; Node 22 may warn that SQLite is experimental)
- A trusted service that authenticates the actual payer **before** it calls Shekels. The shared API token is intended for trusted service-to-service calls, not students or browsers.
- A trusted HTTPS reverse proxy for remote use. The HTTP listener defaults to `127.0.0.1:1000`.
- No third-party npm dependencies.

## Quick start

Generate and retain three **different** random 32-byte secrets. Configure them through your process environment (Node does not automatically read `.env` files):

```sh
export SHEKELS_API_TOKEN="$(openssl rand -hex 32)"
export SHEKELS_ADMIN_TOKEN="$(openssl rand -hex 32)"
export SHEKELS_FINGERPRINT_KEY="$(openssl rand -hex 32)"
npm start
```

`SHEKELS_FINGERPRINT_KEY` protects the keyed idempotency fingerprints. It is **not** a decryption key: the server cannot decrypt an account's saved encrypted views with it. Persist all three server secrets securely and don't check them into Git. See `.env.example` for `HOST`, `PORT` and `SHEKELS_DB_PATH`.

### 1. Generate public/private key pairs locally

Each account must create its keys on its **own trusted device**. Examples:

```sh
npm run keygen -- alice-private.pem
npm run keygen -- bob-private.pem
```

Each command writes a non-overwriting PKCS#8 X25519 private key file with restrictive file permissions and prints the matching **public** key, base64-encoded SPKI DER. Send only each printed `publicKey` to the trusted account-registration service. **Never send `*-private.pem` to Shekels.** Protect the files, back them up securely, and restrict OS access (including on Windows, where `0600` is not a complete ACL solution). There is no automatic private-key recovery or rotation in this MVP.

### 2. Create accounts (admin-only)

Replace the example public keys with the generated values. Reuse the same admin token only in your trusted backend:

```sh
curl -s http://127.0.0.1:1000/v1/accounts \
  -H "Authorization: Bearer $SHEKELS_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"id":"alice","publicKey":"<ALICE_PUBLIC_KEY_BASE64>"}'

curl -s http://127.0.0.1:1000/v1/accounts \
  -H "Authorization: Bearer $SHEKELS_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"id":"bob","publicKey":"<BOB_PUBLIC_KEY_BASE64>"}'
```

### 3. Issue currency and transfer

```sh
curl -s http://127.0.0.1:1000/v1/issuances \
  -H "Authorization: Bearer $SHEKELS_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"to":"alice","amount":100,"requestId":"issue_alice_000001"}'

curl -s http://127.0.0.1:1000/v1/transfers \
  -H "Authorization: Bearer $SHEKELS_API_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"from":"alice","to":"bob","amount":25,"requestId":"alice_bob_000001"}' > transfer.json
```

The response contains `transaction.id`, metadata and the **two encrypted** envelopes. To decrypt locally:

```sh
npm run decrypt -- alice-private.pem PayerInfo transfer.json
npm run decrypt -- bob-private.pem PayeeInfo transfer.json
```

These commands print the corresponding JSON data, or fail if given the wrong key/role or altered data. The private key is loaded from disk locally and never transmitted to the server.

## HTTP API

All POST payloads are JSON (`Content-Type: application/json`), authenticated using `Authorization: Bearer <token>`. Only `/health` is public.

| Method | Path | Token | Purpose |
| --- | --- | --- | --- |
| `GET` | `/health` | None | Liveness |
| `POST` | `/v1/accounts` | Admin | Create account with a public key and zero balance |
| `POST` | `/v1/issuances` | Admin | Mint a recorded amount into an existing account |
| `POST` | `/v1/transfers` | API | Transfer between two existing accounts |
| `GET` | `/v1/accounts/:id` | API | Read account public key and server-maintained balance |
| `GET` | `/v1/transactions/:id` | API | Read metadata and encrypted payer/payee envelopes |

Amounts must be positive safe JSON integers in the smallest currency unit. Account IDs allow 1–64 ASCII letters, digits, hyphens or underscores. Each issuance or transfer requires a 16–100 character `requestId` (same character set); identical retries return 200 with `created: false`, a new transaction returns 201, and conflicting retries return HTTP 409. Error responses use `{ "error": { "code": "...", "message": "..." } }`.

## Security boundaries and limitations

- **Not user authentication:** A shared `SHEKELS_API_TOKEN` allows transfers **from any account**. A separate, trusted identity service must verify that the payer has authorized each transaction. Do **not** give this token to clients.
- **Not true E2EE against the server:** The server sees account IDs and amounts when processing and stores those in the journal for accounting. The encrypted views protect their content from a later database-reader who lacks the individual account's private key, but journal metadata leaks the same transfer details. To make metadata truly confidential, the ledger protocol must be redesigned, not merely the columns.
- **No privacy from a malicious encryption server:** Because the server constructs envelopes, an untrusted server could replace their plaintext before encryption. End-user authenticity requires cryptographic signatures or other independent verification on the client side.
- **Key management:** The account public key is immutable in this MVP; there is no private-key recovery, rotation or rewrapping of historical envelopes. Public key substitution during registration must be prevented by a trusted provisioning process.
- **Persistence:** SQLite defaults to `./shekels.sqlite`. The schema is **not compatible** with the old `transactions.db` or the earlier memo-based Shekels draft; there is **no automatic migration**. Back up old data separately before first deployment.
- **Operational controls missing:** Authentication tied to individual payers, rate limiting, abuse monitoring, administration approval workflows, signed receipts, consistent SQLite backups and restore drills are required before real deployment. This implementation has not received an independent security audit.

## Development

```sh
npm run check
npm test
```

CI tests Node 22 and Node 24. Tests include independent encryption/decryption, wrong keys, tampering, transaction/role binding, schema behavior, atomic transfers, replay resistance, validation, overflow, and real HTTP requests.
