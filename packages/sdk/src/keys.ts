/**
 * Key management for the Stellar Privacy Layer SDK.
 *
 * - Deterministic HKDF-SHA256 key derivation with domain separation.
 * - AES-256-GCM encryption for regulatory viewing keys (authenticated).
 * - Commitment / nullifier hashing (SHA-256) matching the off-chain prover.
 *
 * All primitives come from {@link crypto.ts} and run in browsers and Node.js.
 */
import {
  aesGcmDecrypt,
  aesGcmEncrypt,
  bytesToHex,
  hexToBytes,
  hkdfSha256,
  randomBytes,
  sha256Digest,
} from './crypto.js';
import { ErrorCode, PrivacySDKError } from './errors.js';
import type { KeyPair } from './types.js';

const HKDF_INFO = new TextEncoder().encode('Stellar-Privacy-Layer-v1');
const HKDF_SALT = new TextEncoder().encode('Stellar-Privacy-SDK-v1');

function deriveKey(material: Uint8Array): Uint8Array {
  return hkdfSha256(material, HKDF_SALT, HKDF_INFO, 32);
}

export class KeyManager {
  /** Generate a fresh privacy key pair (secret key, public key, viewing key). */
  static generateKeyPair(): KeyPair {
    try {
      const secretKey = randomBytes(32);
      const key = deriveKey(secretKey);
      const publicKey = bytesToHex(key);
      const viewingKey = randomBytes(32);
      return { secretKey, publicKey, viewingKey };
    } catch (error) {
      throw new PrivacySDKError(
        ErrorCode.KEY_GENERATION_FAILED,
        'Failed to generate key pair',
        error,
      );
    }
  }

  /** Generate a fresh 32-byte deposit secret. */
  static generateSecret(): Uint8Array {
    return randomBytes(32);
  }

  /** Generate a fresh 32-byte regulatory viewing key. */
  static generateViewingKey(): Uint8Array {
    return randomBytes(32);
  }

  /** SHA-256 hash of a viewing key, hex-encoded. */
  static computeViewingKeyHash(viewingKey: Uint8Array): string {
    return bytesToHex(sha256Digest(viewingKey));
  }

  /** Derive the public key (hex) from a secret key material. */
  static derivePublicKey(secretKey: Uint8Array): string {
    return bytesToHex(deriveKey(secretKey));
  }

  /**
   * Encrypt data for a viewer using their public key material with
   * AES-256-GCM. Output layout: [iv || ciphertext || tag].
   */
  static encryptForViewer(data: Uint8Array, viewerPublicKey: Uint8Array): Uint8Array {
    const key = deriveKey(viewerPublicKey);
    return aesGcmEncrypt(key, data);
  }

  /**
   * Decrypt data encrypted with {@link encryptForViewer} using the matching
   * viewing key. Throws {@link PrivacySDKError} on tampered data or a wrong key.
   */
  static decryptWithViewingKey(encryptedData: Uint8Array, viewingKey: Uint8Array): Uint8Array {
    try {
      const key = deriveKey(viewingKey);
      return aesGcmDecrypt(key, encryptedData);
    } catch (error) {
      throw new PrivacySDKError(
        ErrorCode.COMPLIANCE_ERROR,
        'Failed to decrypt with viewing key',
        error,
      );
    }
  }

  /**
   * Compute the shielded deposit commitment: SHA-256(secret || recipient || amount).
   * Note: this is the convenience hash used by the reference SDK. The on-chain
   * contract and Rust prover use Poseidon-based commitments for production use.
   */
  static hashCommitment(secret: Uint8Array, recipient: string, amount: bigint): string {
    const recipientBytes = new TextEncoder().encode(recipient);
    const amountBytes = new TextEncoder().encode(amount.toString());
    const buf = new Uint8Array(secret.length + recipientBytes.length + amountBytes.length);
    buf.set(secret, 0);
    buf.set(recipientBytes, secret.length);
    buf.set(amountBytes, secret.length + recipientBytes.length);
    return bytesToHex(sha256Digest(buf));
  }

  /**
   * Compute the on-chain nullifier: SHA-256(secret || commitment).
   *
   * This matches the nullifier concept used by the Rust prover and the
   * contract (Poseidon(secret, commitment) in production). Note that the
   * reference JS proof in {@link ProverClient} binds a *derived* nullifier
   * `H(H(secret) || commitment)` so it can be verified without exposing the
   * secret — see `generateWithdrawalProof`.
   */
  static hashNullifier(secret: Uint8Array, commitment: string): string {
    const commitmentBytes = hexToBytes(commitment);
    const buf = new Uint8Array(secret.length + commitmentBytes.length);
    buf.set(secret, 0);
    buf.set(commitmentBytes, secret.length);
    return bytesToHex(sha256Digest(buf));
  }

  static toHex(bytes: Uint8Array): string {
    return bytesToHex(bytes);
  }

  static fromHex(hex: string): Uint8Array {
    return hexToBytes(hex);
  }
}
