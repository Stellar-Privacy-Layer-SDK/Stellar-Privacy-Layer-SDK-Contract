import { describe, expect, it } from 'vitest';
import { ErrorCode } from '../errors.js';
import { KeyManager } from '../keys.js';

describe('KeyManager', () => {
  it('generates a well-formed key pair', () => {
    const kp = KeyManager.generateKeyPair();
    expect(kp.secretKey).toHaveLength(32);
    expect(kp.publicKey).toMatch(/^[0-9a-f]{64}$/);
    expect(kp.viewingKey).toHaveLength(32);
  });

  it('generates distinct key pairs', () => {
    const a = KeyManager.generateKeyPair();
    const b = KeyManager.generateKeyPair();
    expect(a.publicKey).not.toBe(b.publicKey);
  });

  it('generates 32-byte secrets and viewing keys', () => {
    expect(KeyManager.generateSecret()).toHaveLength(32);
    expect(KeyManager.generateViewingKey()).toHaveLength(32);
  });

  it('derives public keys deterministically', () => {
    const material = new Uint8Array(32).fill(7);
    expect(KeyManager.derivePublicKey(material)).toBe(KeyManager.derivePublicKey(material));
    expect(KeyManager.derivePublicKey(material)).toMatch(/^[0-9a-f]{64}$/);
  });

  it('hashes viewing keys deterministically', () => {
    const key = new Uint8Array([1, 2, 3]);
    const h1 = KeyManager.computeViewingKeyHash(key);
    const h2 = KeyManager.computeViewingKeyHash(key);
    expect(h1).toBe(h2);
    expect(h1).toMatch(/^[0-9a-f]{64}$/);
  });

  it('encrypts and decrypts for a viewer', () => {
    const viewingKey = KeyManager.generateViewingKey();
    const data = new TextEncoder().encode('confidential');
    const encrypted = KeyManager.encryptForViewer(data, viewingKey);
    const decrypted = KeyManager.decryptWithViewingKey(encrypted, viewingKey);
    expect(new TextDecoder().decode(decrypted)).toBe('confidential');
  });

  it('fails to decrypt with the wrong viewing key', () => {
    const data = new TextEncoder().encode('confidential');
    const encrypted = KeyManager.encryptForViewer(data, KeyManager.generateViewingKey());
    expect(() =>
      KeyManager.decryptWithViewingKey(encrypted, KeyManager.generateViewingKey()),
    ).toThrowError(ErrorCode.COMPLIANCE_ERROR);
  });

  it('hashes commitments deterministically and across inputs', () => {
    const secret = new Uint8Array([9, 9, 9]);
    const h1 = KeyManager.hashCommitment(secret, 'GA...', 1000n);
    const h2 = KeyManager.hashCommitment(secret, 'GA...', 1000n);
    expect(h1).toBe(h2);
    expect(h1).toMatch(/^[0-9a-f]{64}$/);
    expect(KeyManager.hashCommitment(secret, 'GA...', 1001n)).not.toBe(h1);
    expect(KeyManager.hashCommitment(secret, 'GB...', 1000n)).not.toBe(h1);
  });

  it('hashes nullifiers deterministically', () => {
    const secret = new Uint8Array([1, 2, 3]);
    const commitment = 'ab'.repeat(32);
    expect(KeyManager.hashNullifier(secret, commitment)).toBe(
      KeyManager.hashNullifier(secret, commitment),
    );
  });

  it('hex encodes and decodes', () => {
    const bytes = new Uint8Array([0, 1, 254, 255]);
    expect(KeyManager.toHex(bytes)).toBe('0001feff');
    expect(KeyManager.fromHex('0001feff')).toEqual(bytes);
  });
});
