import { describe, expect, it } from 'vitest';
import {
  AES_GCM_IV_LENGTH,
  AES_GCM_TAG_LENGTH,
  aesGcmDecrypt,
  aesGcmEncrypt,
  bytesToHex,
  equalBytes,
  hexToBytes,
  hkdfSha256,
  randomBytes,
  randomBytes32,
  randomUUID,
  sha256Digest,
  sha256Hex,
} from '../crypto.js';

describe('sha256', () => {
  it('hashes the empty input to the known SHA-256 vector', () => {
    expect(sha256Hex(new Uint8Array())).toBe(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    );
  });

  it('hashes ASCII input to the known SHA-256 vector', () => {
    expect(sha256Hex(new TextEncoder().encode('abc'))).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    );
  });

  it('sha256Digest returns 32 bytes', () => {
    expect(sha256Digest(new TextEncoder().encode('x'))).toHaveLength(32);
  });
});

describe('hex encoding', () => {
  it('round-trips bytes through hex', () => {
    const bytes = new Uint8Array([0, 255, 16, 17]);
    expect(bytesToHex(bytes)).toBe('00ff1011');
    expect(hexToBytes('00ff1011')).toEqual(bytes);
  });

  it('throws on malformed hex input', () => {
    expect(() => hexToBytes('zz')).toThrow();
    expect(() => hexToBytes('abc')).toThrow();
  });

  it('returns ArrayBuffer-backed bytes (compatible with stellar-sdk)', () => {
    const bytes = hexToBytes('aa');
    expect(bytes.buffer).toBeInstanceOf(ArrayBuffer);
  });
});

describe('randomBytes', () => {
  it('returns the requested length', () => {
    expect(randomBytes(16)).toHaveLength(16);
    expect(randomBytes32()).toHaveLength(32);
  });

  it('produces distinct values across calls', () => {
    const a = bytesToHex(randomBytes(32));
    const b = bytesToHex(randomBytes(32));
    expect(a).not.toBe(b);
  });
});

describe('hkdfSha256', () => {
  it('derives the requested key length deterministically', () => {
    const ikm = randomBytes(32);
    const salt = new TextEncoder().encode('salt');
    const info = new TextEncoder().encode('info');
    const k1 = hkdfSha256(ikm, salt, info, 32);
    const k2 = hkdfSha256(ikm, salt, info, 32);
    expect(k1).toEqual(k2);
    expect(k1).toHaveLength(32);
    expect(hkdfSha256(ikm, salt, info, 48)).toHaveLength(48);
  });

  it('derives different keys from different salts', () => {
    const ikm = randomBytes(32);
    const a = hkdfSha256(ikm, new TextEncoder().encode('s1'), new TextEncoder().encode('i'));
    const b = hkdfSha256(ikm, new TextEncoder().encode('s2'), new TextEncoder().encode('i'));
    expect(bytesToHex(a)).not.toBe(bytesToHex(b));
  });
});

describe('AES-256-GCM', () => {
  const key = randomBytes(32);
  const plaintext = new TextEncoder().encode('sensitive payload');

  it('encrypts and decrypts round-trip', () => {
    const blob = aesGcmEncrypt(key, plaintext);
    expect(blob.length).toBe(AES_GCM_IV_LENGTH + plaintext.length + AES_GCM_TAG_LENGTH);
    expect(aesGcmDecrypt(key, blob)).toEqual(plaintext);
  });

  it('uses a fresh nonce per encryption', () => {
    const a = aesGcmEncrypt(key, plaintext);
    const b = aesGcmEncrypt(key, plaintext);
    expect(a.slice(0, AES_GCM_IV_LENGTH)).not.toEqual(b.slice(0, AES_GCM_IV_LENGTH));
  });

  it('rejects a wrong key', () => {
    const blob = aesGcmEncrypt(key, plaintext);
    expect(() => aesGcmDecrypt(randomBytes(32), blob)).toThrow();
  });

  it('rejects truncated payloads', () => {
    expect(() => aesGcmDecrypt(key, new Uint8Array(8))).toThrow(/truncated/);
  });

  it('rejects non-32-byte keys', () => {
    expect(() => aesGcmEncrypt(new Uint8Array(16), plaintext)).toThrow(/32-byte key/);
    expect(() => aesGcmDecrypt(new Uint8Array(16), new Uint8Array(32))).toThrow(/32-byte key/);
  });
});

describe('randomUUID', () => {
  it('produces RFC 4122 v4-shaped UUIDs', () => {
    const uuid = randomUUID();
    expect(uuid).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    expect(randomUUID()).not.toBe(uuid);
  });
});

describe('equalBytes', () => {
  it('compares equal, unequal, and length-mismatched inputs', () => {
    const a = new Uint8Array([1, 2, 3]);
    expect(equalBytes(a, new Uint8Array([1, 2, 3]))).toBe(true);
    expect(equalBytes(a, new Uint8Array([1, 2, 4]))).toBe(false);
    expect(equalBytes(a, new Uint8Array([1, 2]))).toBe(false);
  });
});
