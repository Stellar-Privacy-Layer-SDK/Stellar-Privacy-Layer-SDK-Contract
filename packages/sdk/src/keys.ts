import crypto from 'crypto';
import type { KeyPair } from './types';
import { ErrorCode, PrivacySDKError } from './errors';

const AES_TAG_LENGTH = 16;
const IV_LENGTH = 12;
const HKDF_INFO = Buffer.from('Stellar-Privacy-Layer-v1', 'utf-8');
const HKDF_SALT = Buffer.from('Stellar-Privacy-SDK-v1', 'utf-8');

function deriveKey(material: Uint8Array): Buffer {
  const ikm = Buffer.from(material);
  const key = crypto.hkdfSync('sha256', ikm, HKDF_SALT, HKDF_INFO, 32);
  return Buffer.from(key);
}

export class KeyManager {
  static generateKeyPair(): KeyPair {
    try {
      const secretKey = crypto.randomBytes(32);
      const key = deriveKey(secretKey);
      const publicKey = key.toString('hex');

      const viewingKey = crypto.randomBytes(32);

      return { secretKey, publicKey, viewingKey };
    } catch (error) {
      throw new PrivacySDKError(
        ErrorCode.KEY_GENERATION_FAILED,
        'Failed to generate key pair',
        error,
      );
    }
  }

  static generateSecret(): Uint8Array {
    return crypto.randomBytes(32);
  }

  static generateViewingKey(): Uint8Array {
    return crypto.randomBytes(32);
  }

  static computeViewingKeyHash(viewingKey: Uint8Array): string {
    const hash = crypto.createHash('sha256').update(viewingKey).digest();
    return hash.toString('hex');
  }

  static derivePublicKey(secretKey: Uint8Array): string {
    const key = deriveKey(secretKey);
    return key.toString('hex');
  }

  static encryptForViewer(
    data: Uint8Array,
    viewerPublicKey: Uint8Array,
  ): Uint8Array {
    const iv = crypto.randomBytes(IV_LENGTH);
    const key = deriveKey(viewerPublicKey);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([
      cipher.update(Buffer.from(data)),
      cipher.final(),
    ]);
    const tag = cipher.getAuthTag();
    return Buffer.concat([iv, encrypted, tag]);
  }

  static decryptWithViewingKey(
    encryptedData: Uint8Array,
    viewingKey: Uint8Array,
  ): Uint8Array {
    try {
      const iv = encryptedData.slice(0, IV_LENGTH);
      const tag = encryptedData.slice(encryptedData.length - AES_TAG_LENGTH);
      const data = encryptedData.slice(IV_LENGTH, encryptedData.length - AES_TAG_LENGTH);
      const key = deriveKey(viewingKey);
      const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
      decipher.setAuthTag(Buffer.from(tag));
      const decrypted = Buffer.concat([
        decipher.update(Buffer.from(data)),
        decipher.final(),
      ]);
      return decrypted;
    } catch (error) {
      throw new PrivacySDKError(
        ErrorCode.COMPLIANCE_ERROR,
        'Failed to decrypt with viewing key',
        error,
      );
    }
  }

  static hashCommitment(secret: Uint8Array, recipient: string, amount: bigint): string {
    const hash = crypto.createHash('sha256');
    hash.update(Buffer.from(secret));
    hash.update(Buffer.from(recipient));
    hash.update(amount.toString());
    return hash.digest().toString('hex');
  }

  static hashNullifier(secret: Uint8Array, commitment: string): string {
    const hash = crypto.createHash('sha256');
    hash.update(Buffer.from(secret));
    hash.update(Buffer.from(commitment, 'hex'));
    return hash.digest().toString('hex');
  }

  static toHex(bytes: Uint8Array): string {
    return Buffer.from(bytes).toString('hex');
  }

  static fromHex(hex: string): Uint8Array {
    return Buffer.from(hex, 'hex');
  }
}
