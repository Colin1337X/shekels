import {
  createCipheriv, createDecipheriv, createHmac, createPrivateKey, createPublicKey,
  diffieHellman, generateKeyPairSync, hkdfSync, randomBytes,
} from 'node:crypto';

const INFO_VERSION = 1;
const INFO_ALGORITHM = 'X25519-HKDF-SHA256-AES-256-GCM';
const NONCE_BYTES = 12;
const SALT_BYTES = 32;
const SPKI_BYTES_MAX = 128;

export function parseFingerprintKey(value) {
  if (typeof value !== 'string' || !/^[0-9a-fA-F]{64}$/.test(value)) {
    throw new Error('SHEKELS_FINGERPRINT_KEY must be exactly 32 bytes encoded as 64 hex characters');
  }
  return Buffer.from(value, 'hex');
}

export function parsePublicKey(publicKey) {
  if (typeof publicKey !== 'string' || publicKey.length > 200 || !/^[A-Za-z0-9+/]+={0,2}$/.test(publicKey)) {
    throw new TypeError('publicKey must be a base64-encoded X25519 SPKI DER public key');
  }
  const der = Buffer.from(publicKey, 'base64');
  if (der.length === 0 || der.length > SPKI_BYTES_MAX || der.toString('base64') !== publicKey) {
    throw new TypeError('publicKey must be a canonical base64-encoded X25519 SPKI DER public key');
  }
  let key;
  try {
    key = createPublicKey({ key: der, format: 'der', type: 'spki' });
  } catch {
    throw new TypeError('Invalid X25519 public key');
  }
  if (key.asymmetricKeyType !== 'x25519') throw new TypeError('Expected an X25519 public key');
  return key;
}

// The key pair is created on the recipient's trusted device. Only the public half
// should be given to the ledger service. The private half never touches this server.
export function generateAccountKeyPair() {
  const { publicKey, privateKey } = generateKeyPairSync('x25519');
  return {
    publicKey: publicKey.export({ format: 'der', type: 'spki' }).toString('base64'),
    privateKeyPem: privateKey.export({ format: 'pem', type: 'pkcs8' }),
  };
}

function aad(transactionId, role) {
  if (!['PayerInfo', 'PayeeInfo'].includes(role)) throw new TypeError('Invalid envelope role');
  if (typeof transactionId !== 'string' || !/^[0-9a-f-]{36}$/i.test(transactionId)) {
    throw new TypeError('Invalid transaction ID');
  }
  return Buffer.from(`shekels:encrypted-info:v1:${role}:${transactionId}`, 'utf8');
}

function deriveKey(secret, salt, context) {
  return Buffer.from(hkdfSync('sha256', secret, salt, context, 32));
}

// Hybrid encryption: ephemeral X25519 + HKDF-SHA256 + AES-256-GCM. Fresh ephemeral
// key, HKDF salt and GCM nonce per recipient and per transaction.
export function sealInfo(plaintext, recipientPublicKey, transactionId, role) {
  const publicKey = typeof recipientPublicKey === 'string'
    ? parsePublicKey(recipientPublicKey) : recipientPublicKey;
  if (publicKey?.asymmetricKeyType !== 'x25519') throw new TypeError('Expected X25519 public key');
  const { publicKey: ephemeralPublicKey, privateKey: ephemeralPrivateKey } = generateKeyPairSync('x25519');
  const salt = randomBytes(SALT_BYTES);
  const nonce = randomBytes(NONCE_BYTES);
  const associatedData = aad(transactionId, role);
  const secret = diffieHellman({ privateKey: ephemeralPrivateKey, publicKey });
  const key = deriveKey(secret, salt, associatedData);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  cipher.setAAD(associatedData);
  const ciphertext = Buffer.concat([cipher.update(JSON.stringify(plaintext), 'utf8'), cipher.final()]);
  return {
    version: INFO_VERSION,
    algorithm: INFO_ALGORITHM,
    ephemeralPublicKey: ephemeralPublicKey.export({ format: 'der', type: 'spki' }).toString('base64'),
    salt: salt.toString('base64'),
    nonce: nonce.toString('base64'),
    ciphertext: ciphertext.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
  };
}

function canonicalBytes(value, expectedLength, name) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) {
    throw new TypeError(`Invalid ${name}`);
  }
  const bytes = Buffer.from(value, 'base64');
  if ((expectedLength !== null && bytes.length !== expectedLength) ||
      bytes.toString('base64') !== value || bytes.length > 4096) {
    throw new TypeError(`Invalid ${name}`);
  }
  return bytes;
}

// Client-only operation: pass the recipient's private PEM, never the server's token.
export function openInfo(envelope, privateKeyPem, transactionId, role) {
  if (!envelope || envelope.version !== INFO_VERSION || envelope.algorithm !== INFO_ALGORITHM) {
    throw new TypeError('Unsupported encrypted-info envelope');
  }
  const privateKey = createPrivateKey(privateKeyPem);
  if (privateKey.asymmetricKeyType !== 'x25519') throw new TypeError('Expected X25519 private key');
  const ephemeralPublicKey = parsePublicKey(envelope.ephemeralPublicKey);
  const salt = canonicalBytes(envelope.salt, SALT_BYTES, 'salt');
  const nonce = canonicalBytes(envelope.nonce, NONCE_BYTES, 'nonce');
  const tag = canonicalBytes(envelope.tag, 16, 'tag');
  const ciphertext = canonicalBytes(envelope.ciphertext, null, 'ciphertext');
  const associatedData = aad(transactionId, role);
  const secret = diffieHellman({ privateKey, publicKey: ephemeralPublicKey });
  const key = deriveKey(secret, salt, associatedData);
  const decipher = createDecipheriv('aes-256-gcm', key, nonce);
  decipher.setAAD(associatedData);
  decipher.setAuthTag(tag);
  return JSON.parse(Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8'));
}

export function requestFingerprint(request, key) {
  return createHmac('sha256', key)
    .update('shekels:idempotency:v2\0')
    .update(JSON.stringify(request))
    .digest('hex');
}
