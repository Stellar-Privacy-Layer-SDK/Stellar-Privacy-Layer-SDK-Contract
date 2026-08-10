/**
 * Cryptography primitives for the Stellar Privacy Layer SDK.
 *
 * Implemented on top of @noble/hashes and @noble/ciphers (audited, MIT-licensed,
 * dependency-free pure-JS cryptography) so the SDK runs identically in browsers
 * and Node.js without any polyfills or Node built-ins.
 *
 * All functions are synchronous and operate on Uint8Array.
 */
import { gcm } from '@noble/ciphers/aes.js';
import { expand, extract } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  bytesToHex as nobleBytesToHex,
  hexToBytes as nobleHexToBytes,
  randomBytes as nobleRandomBytes,
} from '@noble/hashes/utils.js';

/** GCM nonce length in bytes (standard 96-bit nonce). */
export const AES_GCM_IV_LENGTH = 12;
/** GCM authentication tag length in bytes. */
export const AES_GCM_TAG_LENGTH = 16;

/**
 * Copy bytes into a fresh `ArrayBuffer`-backed view. Guarantees the narrower
 * `Uint8Array<ArrayBuffer>` type that @stellar/stellar-sdk's XDR layer accepts.
 */
function toArrayBufferBacked(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  const buffer = bytes.buffer.slice(
    bytes.byteOffset,
    bytes.byteOffset + bytes.byteLength,
  ) as ArrayBuffer;
  return new Uint8Array(buffer);
}

/** Hex-encode bytes (lowercase). */
export function bytesToHex(bytes: Uint8Array): string {
  return nobleBytesToHex(bytes);
}

/** Decode a hex string into bytes (throws on malformed input). */
export function hexToBytes(hex: string): Uint8Array<ArrayBuffer> {
  return toArrayBufferBacked(nobleHexToBytes(hex));
}

/** Cryptographically secure random bytes. */
export function randomBytes(length: number): Uint8Array<ArrayBuffer> {
  return toArrayBufferBacked(nobleRandomBytes(length));
}

/**
 * SHA-256 hash of the given input.
 */
export function sha256Digest(data: Uint8Array): Uint8Array {
  return sha256(data);
}

/**
 * SHA-256 hash of the given input, hex-encoded.
 */
export function sha256Hex(data: Uint8Array): string {
  return bytesToHex(sha256(data));
}

/**
 * HKDF-SHA256 key derivation (RFC 5869).
 */
export function hkdfSha256(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  length = 32,
): Uint8Array {
  const prk = extract(sha256, ikm, salt);
  return expand(sha256, prk, info, length);
}

/**
 * AES-256-GCM authenticated encryption.
 *
 * Output layout: `[12-byte nonce || ciphertext || 16-byte auth tag]`.
 */
export function aesGcmEncrypt(key: Uint8Array, plaintext: Uint8Array): Uint8Array {
  if (key.length !== 32) {
    throw new Error('AES-256-GCM requires a 32-byte key');
  }
  const nonce = randomBytes(AES_GCM_IV_LENGTH);
  const cipher = gcm(key, nonce);
  const encrypted = cipher.encrypt(plaintext);
  const blob = new Uint8Array(AES_GCM_IV_LENGTH + encrypted.length);
  blob.set(nonce, 0);
  blob.set(encrypted, AES_GCM_IV_LENGTH);
  return blob;
}

/**
 * AES-256-GCM authenticated decryption.
 *
 * Input layout must match {@link aesGcmEncrypt}. Throws if the auth tag
 * verification fails (tampered or wrong key).
 */
export function aesGcmDecrypt(key: Uint8Array, blob: Uint8Array): Uint8Array {
  if (key.length !== 32) {
    throw new Error('AES-256-GCM requires a 32-byte key');
  }
  if (blob.length < AES_GCM_IV_LENGTH + AES_GCM_TAG_LENGTH) {
    throw new Error('Encrypted payload is truncated');
  }
  const nonce = blob.slice(0, AES_GCM_IV_LENGTH);
  const data = blob.slice(AES_GCM_IV_LENGTH);
  const cipher = gcm(key, nonce);
  return cipher.decrypt(data);
}

/**
 * Cryptographically secure random bytes.
 *
 * Wraps {@link randomBytes} from @noble/hashes (which uses the platform CSPRNG:
 * `crypto.getRandomValues` in browsers, `crypto.randomBytes` in Node).
 */
export function randomBytes32(): Uint8Array {
  return randomBytes(32);
}

/**
 * RFC 4122 v4 UUID using only Web Platform APIs (fallback included for
 * environments without `crypto.randomUUID`).
 */
export function randomUUID(): string {
  const c = globalThis.crypto;
  if (typeof c?.randomUUID === 'function') {
    return c.randomUUID();
  }
  const bytes = randomBytes(16);
  bytes[6] = ((bytes[6] ?? 0) & 0x0f) | 0x40;
  bytes[8] = ((bytes[8] ?? 0) & 0x3f) | 0x80;
  const hex = bytesToHex(bytes);
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/**
 * Constant-time byte comparison. Returns true when both inputs are equal.
 */
export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) {
    diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  }
  return diff === 0;
}
