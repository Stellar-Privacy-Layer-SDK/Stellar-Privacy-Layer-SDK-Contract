import crypto from 'crypto';
import { describe, it, expect } from 'vitest';
import { KeyManager } from '../keys';
import { PrivacyAccount } from '../account';
import { ProverClient } from '../prover';


describe('KeyManager', () => {
  it('generates key pair', () => {
    const kp = KeyManager.generateKeyPair();
    expect(kp.secretKey).toHaveLength(32);
    expect(typeof kp.publicKey).toBe('string');
    expect(kp.publicKey).toHaveLength(64);
    expect(kp.viewingKey).toHaveLength(32);
  });

  it('generates deterministic viewing key hash', () => {
    const key = new Uint8Array([1, 2, 3, 4]);
    const hash1 = KeyManager.computeViewingKeyHash(key);
    const hash2 = KeyManager.computeViewingKeyHash(key);
    expect(hash1).toBe(hash2);
  });

  it('encrypts and decrypts with viewing key', () => {
    const viewingKey = KeyManager.generateViewingKey();
    const data = new TextEncoder().encode('sensitive transaction data');

    const encrypted = KeyManager.encryptForViewer(data, viewingKey);
    const decrypted = KeyManager.decryptWithViewingKey(encrypted, viewingKey);

    expect(new TextDecoder().decode(decrypted)).toBe('sensitive transaction data');
  });

  it('hashes commitment deterministically', () => {
    const secret = new Uint8Array([1, 2, 3]);
    const h1 = KeyManager.hashCommitment(secret, 'GA...', 1000n);
    const h2 = KeyManager.hashCommitment(secret, 'GA...', 1000n);
    expect(h1).toBe(h2);
  });
});

describe('ProverClient', () => {
  it('generates deposit proof', async () => {
    const prover = new ProverClient(32);
    const secret = KeyManager.generateSecret();
    const result = await prover.generateDepositProof(
      secret,
      'GB...',
      1000n,
    );
    expect(result.commitment).toBeTruthy();
    expect(result.nullifier).toBeTruthy();
  });

  it('verifies proof format', async () => {
    const prover = new ProverClient(32);
    const secret = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
    const commitment = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
    const nullifier = crypto
      .createHash('sha256')
      .update(
        crypto.createHash('sha256').update(Buffer.from(secret, 'hex')).digest(),
      )
      .update(Buffer.from(commitment, 'hex'))
      .digest('hex');
    const valid = await prover.verifyProof({
      proofA: [secret, commitment],
      proofB: [['c'.repeat(64), 'd'.repeat(64)], ['e'.repeat(64), 'f'.repeat(64)]],
      proofC: ['g'.repeat(64), 'h'.repeat(64)],
      root: '0'.repeat(64),
      nullifier,
      recipient: 'GA...',
      amount: '1000',
    });
    expect(valid).toBe(true);
  });
});

describe('ComplianceModule', () => {
  it('encrypts and decrypts transaction data', () => {
    const viewingKey = KeyManager.generateViewingKey();
    const data = {
      sender: 'GA...',
      recipient: 'GB...',
      amount: '1000',
      timestamp: Date.now(),
    };

    const jsonData = JSON.stringify(data);
    const dataBytes = new TextEncoder().encode(jsonData);

    const encrypted = KeyManager.encryptForViewer(dataBytes, viewingKey);
    const decrypted = KeyManager.decryptWithViewingKey(encrypted, viewingKey);
    const decryptedStr = new TextDecoder().decode(decrypted);

    expect(JSON.parse(decryptedStr)).toEqual(data);
  });
});
