/**
 * vault.js — Core Vault Operations
 *
 * Exposes createVault and unlockVault.
 */

import { createHmac, timingSafeEqual } from 'node:crypto';
import { generateSalt, generateIV } from '../crypto/random.js';
import { deriveKey, DEFAULT_PARAMS } from '../crypto/kdf.js';
import { encrypt, decrypt } from '../crypto/aead.js';
import { encodeVault, decodeVault, getHmacPayload } from './format.js';
import { VaultAuthError, VaultError, VaultCorruptedError } from './errors.js';

/**
 * Creates a new encrypted vault containing the given secrets.
 *
 * @param {Buffer} password — The master password
 * @param {object} secrets  — The JSON-serializable secrets payload
 * @returns {Buffer}        — The serialized `.zvault` binary data
 */
export function createVault(password, secrets) {
  if (!Buffer.isBuffer(password) || password.length === 0) {
    throw new VaultError('Password must be a non-empty Buffer');
  }
  if (typeof secrets !== 'object' || secrets === null) {
    throw new VaultError('Secrets must be a non-null object');
  }

  const salt = generateSalt();
  const iv = generateIV();

  // 1. Derive Keys
  const { encKey, macKey } = deriveKey(password, salt);

  // 2. Serialize Payload
  const plaintext = Buffer.from(JSON.stringify(secrets), 'utf8');

  // 3. We need the AAD to encrypt, which means we must construct the header first.
  // We can use a dummy HMAC and TAG for the initial encode to get the header bytes.
  // But simpler: just encode it directly or extract it.
  const dummyHmac = Buffer.alloc(32, 0);
  const dummyTag = Buffer.alloc(16, 0);
  const dummyCiphertext = Buffer.alloc(0);
  const initialBuf = encodeVault(DEFAULT_PARAMS, salt, iv, dummyHmac, dummyTag, dummyCiphertext);
  const headerForAAD = decodeVault(initialBuf).headerForAAD;

  // 4. Encrypt
  let ciphertext, tag;
  try {
    const res = encrypt(encKey, iv, plaintext, headerForAAD);
    ciphertext = res.ciphertext;
    tag = res.tag;
  } finally {
    // Zero encryption key and plaintext immediately after use
    encKey.fill(0);
    plaintext.fill(0);
  }

  // 5. Outer HMAC
  const hmacPayload = getHmacPayload(headerForAAD, tag, ciphertext);
  let hmac;
  try {
    const h = createHmac('sha256', macKey);
    h.update(hmacPayload);
    hmac = h.digest();
  } finally {
    // Zero MAC key immediately after use
    macKey.fill(0);
  }

  // 6. Final Assemble
  return encodeVault(DEFAULT_PARAMS, salt, iv, hmac, tag, ciphertext);
}

/**
 * Unlocks a vault and returns the parsed secrets.
 *
 * @param {Buffer} password  — The master password
 * @param {Buffer} vaultData — The serialized `.zvault` binary data
 * @returns {object}         — The decrypted secrets
 * @throws {VaultAuthError}  — On wrong password or tampered data
 * @throws {VaultFormatError}— On malformed binary format
 */
export function unlockVault(password, vaultData) {
  if (!Buffer.isBuffer(password) || password.length === 0) {
    throw new VaultError('Password must be a non-empty Buffer');
  }

  // 1. Decode Format (throws VaultFormatError if malformed)
  const { kdfParams, salt, iv, hmac, tag, ciphertext, headerForAAD } = decodeVault(vaultData);

  // 2. Derive Keys
  const { encKey, macKey } = deriveKey(password, salt, kdfParams);

  try {
    // 3. Verify Outer HMAC (Constant-time check)
    // This catches wrong passwords and tampered data before AES-GCM runs.
    const hmacPayload = getHmacPayload(headerForAAD, tag, ciphertext);
    const h = createHmac('sha256', macKey);
    h.update(hmacPayload);
    const expectedHmac = h.digest();

    if (!timingSafeEqual(hmac, expectedHmac)) {
      throw new VaultAuthError('Authentication failed or vault is corrupted');
    }

    // 4. Decrypt
    // Even though the HMAC passed, we still verify the GCM tag for defense-in-depth.
    let plaintext;
    try {
      plaintext = decrypt(encKey, iv, ciphertext, tag, headerForAAD);
    } catch (err) {
      throw new VaultAuthError('Authentication failed or vault is corrupted');
    }

    // 5. Parse JSON
    try {
      return JSON.parse(plaintext.toString('utf8'));
    } catch (err) {
      // This should never happen if encryption/auth succeeded unless the creator stored invalid JSON.
      throw new VaultCorruptedError('Failed to parse decrypted payload as JSON');
    } finally {
      if (plaintext) plaintext.fill(0);
    }
  } finally {
    encKey.fill(0);
    macKey.fill(0);
  }
}
