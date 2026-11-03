import {gcmsiv} from '@noble/ciphers'
import {argon2id} from '@noble/hashes/argon2'
import { Database } from 'node:sqlite'


const express = require('express')
const app = express()
const port = 1000
const nonceLength = 12
const nonce = crypto.getRandomValues(new Uint8Array(nonceLength))
const db = new Database('transactions.db')
initDatabase()

app.listen(port, () => {
  console.log(`transaction handler running on port ${port}`)
  console.log(`protecting your shekels since 2026 with aes-256-gcm-siv and argon2id`)
})

async function initDatabase() {
  await db.exec (`CREATE TABLE IF NOT EXISTS transactions (transactionid INTEGER PRIMARY KEY AUTOINCREMENT, ciphertext BLOB)`)
}

async function deriveKey(password, salt) {
  const key = await argon2id(password, salt, {mem: 65536, time: 3, parallelism: 1, hashLength: 32})
  return key
}

async function encrypt(plaintext, key) {
  const cipher = await gcmsiv(key, nonce)
  const ciphertext = await cipher.encrypt(plaintext)
  return {ciphertext}
}

async function decrypt(ciphertext, key) {
  const cipher = await gcmsiv(key, nonce)
  const plaintext = await cipher.decrypt(ciphertext)
  return plaintext
}

async function storeTransaction(transactionid, ciphertext) {
  const stmt = await db.prepare('INSERT INTO transactions (id, ciphertext) VALUES (?, ?)')
  await stmt.run(transactionid, ciphertext)
  await stmt.finalize()
}

async function retrieveTransaction(transactionid) {
  const stmt = await db.prepare('SELECT ciphertext FROM transactions WHERE id = ?')
  const row = await stmt.get(transactionid)
  await stmt.finalize()
  return row ? row.ciphertext : null
}

async function rawsql(cmd, masterkey) {
    if (masterkey === process.env.MASTERKEY) {
        const stmt = await db.prepare(cmd)
        await stmt.finalize()
    }
    else {
        throw new Error('Invalid master key')
        throw new Error('Attempted to execute raw SQL command without valid master key')
    }
}