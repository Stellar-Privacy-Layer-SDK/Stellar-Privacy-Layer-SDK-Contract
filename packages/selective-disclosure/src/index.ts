/**
 * Regulatory viewing keys and selective disclosure proofs for the Stellar
 * Privacy Layer.
 *
 * Built on the audited, browser-safe primitives from @stellar-privacy/sdk
 * (AES-256-GCM + HKDF-SHA256 via @noble) so this package runs identically in
 * browsers and Node.js without native `crypto` dependencies.
 *
 * Flow:
 * 1. A regulator requests disclosure of a scoped subset of transaction data.
 * 2. The account holder fulfils the request, encrypting the filtered data for
 *    the regulator and binding it to their viewing key.
 * 3. The regulator verifies the viewing-key proof and decrypts the payload.
 */
import {
  aesGcmDecrypt,
  aesGcmEncrypt,
  ErrorCode,
  hkdfSha256,
  PrivacySDKError,
  randomUUID,
  sha256Hex,
} from '@stellar-privacy/sdk';

const AES_TAG_LENGTH = 16;
const IV_LENGTH = 12;
const HKDF_SALT = new TextEncoder().encode('Stellar-Privacy-Disclosure-v1');
const HKDF_INFO = new TextEncoder().encode('selective-disclosure');

export interface RegulatoryComplianceConfig {
  regulatorPublicKey: string;
  jurisdiction: string;
  complianceLevel: 'full' | 'limited' | 'minimum';
}

export interface DisclosureRequest {
  requestId: string;
  regulator: string;
  scope: string[];
  timestamp: number;
  expiresAt: number;
}

export interface DisclosureResponse {
  requestId: string;
  encryptedData: string;
  viewingKeyProof: string;
  timestamp: number;
}

export interface AuditRecord {
  id: string;
  user: string;
  amount: bigint;
  token: string;
  timestamp: number;
  disclosedTo: string[];
}

/** Derive the AES-256 key for a regulator from their public key material. */
function deriveEncryptionKey(material: string | Uint8Array): Uint8Array {
  const ikm = typeof material === 'string' ? new TextEncoder().encode(material) : material;
  if (ikm.length === 0) {
    throw new PrivacySDKError(ErrorCode.INVALID_CONFIG, 'regulatorPublicKey must not be empty');
  }
  return hkdfSha256(ikm, HKDF_SALT, HKDF_INFO, 32);
}

const COMPLIANCE_LEVELS = ['full', 'limited', 'minimum'] as const;

export class SelectiveDisclosureModule {
  private config: RegulatoryComplianceConfig;

  constructor(config: RegulatoryComplianceConfig) {
    if (!config || typeof config !== 'object') {
      throw new PrivacySDKError(ErrorCode.INVALID_CONFIG, 'config is required');
    }
    if (!config.regulatorPublicKey || config.regulatorPublicKey.length === 0) {
      throw new PrivacySDKError(ErrorCode.INVALID_CONFIG, 'regulatorPublicKey must not be empty');
    }
    if (!config.jurisdiction || config.jurisdiction.length === 0) {
      throw new PrivacySDKError(ErrorCode.INVALID_CONFIG, 'jurisdiction must not be empty');
    }
    if (!COMPLIANCE_LEVELS.includes(config.complianceLevel)) {
      throw new PrivacySDKError(
        ErrorCode.INVALID_CONFIG,
        `complianceLevel must be one of: ${COMPLIANCE_LEVELS.join(', ')}`,
      );
    }
    this.config = config;
  }

  createDisclosureRequest(
    regulator: string,
    scope: string[],
    ttlMs: number = 3600000,
  ): DisclosureRequest {
    if (!regulator || regulator.length === 0) {
      throw new PrivacySDKError(ErrorCode.INVALID_CONFIG, 'regulator must not be empty');
    }
    if (!Array.isArray(scope) || scope.length === 0) {
      throw new PrivacySDKError(ErrorCode.INVALID_CONFIG, 'scope must be a non-empty array');
    }
    if (!Number.isFinite(ttlMs) || ttlMs <= 0) {
      throw new PrivacySDKError(ErrorCode.INVALID_CONFIG, 'ttlMs must be a positive number');
    }
    const now = Date.now();
    return {
      requestId: randomUUID(),
      regulator,
      scope: [...scope],
      timestamp: now,
      expiresAt: now + ttlMs,
    };
  }

  async fulfillDisclosureRequest(
    request: DisclosureRequest,
    transactionData: Record<string, unknown>,
    viewingKey: Uint8Array,
  ): Promise<DisclosureResponse> {
    if (!request || typeof request !== 'object') {
      throw new PrivacySDKError(ErrorCode.INVALID_CONFIG, 'request is required');
    }
    if (!Array.isArray(request.scope) || request.scope.length === 0) {
      throw new PrivacySDKError(ErrorCode.INVALID_CONFIG, 'request.scope must be non-empty');
    }
    if (Date.now() > request.expiresAt) {
      throw new PrivacySDKError(ErrorCode.COMPLIANCE_ERROR, 'Disclosure request has expired');
    }

    const filteredData = this.filterDataByScope(request.scope, transactionData);
    const encrypted = this.encryptWithRegulatorKey(JSON.stringify(filteredData));

    const viewingKeyProof = this.computeViewingKeyProof(viewingKey, request.requestId);

    return {
      requestId: request.requestId,
      encryptedData: toBase64(encrypted),
      viewingKeyProof,
      timestamp: Date.now(),
    };
  }

  verifyDisclosureResponse(response: DisclosureResponse, viewingKey: Uint8Array): boolean {
    if (!response || typeof response !== 'object' || !response.requestId) {
      return false;
    }
    const expectedProof = this.computeViewingKeyProof(viewingKey, response.requestId);
    return response.viewingKeyProof === expectedProof;
  }

  decryptDisclosureData(
    response: DisclosureResponse,
    regulatorPrivateKey: Uint8Array,
  ): Record<string, unknown> {
    if (!response || typeof response !== 'object' || !response.encryptedData) {
      throw new PrivacySDKError(ErrorCode.INVALID_CONFIG, 'response is required');
    }
    try {
      const encrypted = fromBase64(response.encryptedData);
      const decrypted = this.decryptWithRegulatorKey(encrypted, regulatorPrivateKey);
      const parsed = JSON.parse(decrypted) as unknown;
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        throw new Error('decrypted payload is not an object');
      }
      return parsed as Record<string, unknown>;
    } catch (error) {
      throw new PrivacySDKError(
        ErrorCode.COMPLIANCE_ERROR,
        'Failed to decrypt disclosure data',
        error,
      );
    }
  }

  /** Regulator's public key material used for encryption. */
  getRegulatorPublicKey(): string {
    return this.config.regulatorPublicKey;
  }

  private filterDataByScope(
    scope: string[],
    data: Record<string, unknown>,
  ): Record<string, unknown> {
    const filtered: Record<string, unknown> = {};
    for (const key of scope) {
      if (key in data) {
        filtered[key] = data[key];
      }
    }
    return filtered;
  }

  private encryptWithRegulatorKey(data: string): Uint8Array {
    const key = deriveEncryptionKey(this.config.regulatorPublicKey);
    // aesGcmEncrypt returns [iv || ciphertext || tag] — same layout as the
    // historical Node crypto implementation.
    return aesGcmEncrypt(key, new TextEncoder().encode(data));
  }

  private decryptWithRegulatorKey(encrypted: Uint8Array, privateKey: Uint8Array): string {
    if (encrypted.length < IV_LENGTH + AES_TAG_LENGTH) {
      throw new Error('Encrypted payload is truncated');
    }
    const key = deriveEncryptionKey(privateKey);
    const decrypted = aesGcmDecrypt(key, encrypted);
    return new TextDecoder().decode(decrypted);
  }

  /** SHA-256(viewingKey || requestId) — binds the disclosure to the holder. */
  private computeViewingKeyProof(viewingKey: Uint8Array, requestId: string): string {
    const requestIdBytes = new TextEncoder().encode(requestId);
    const buf = new Uint8Array(viewingKey.length + requestIdBytes.length);
    buf.set(viewingKey, 0);
    buf.set(requestIdBytes, viewingKey.length);
    return sha256Hex(buf);
  }
}

export function generateAuditRecord(
  user: string,
  amount: bigint,
  token: string,
  disclosedTo: string[] = [],
): AuditRecord {
  if (!user || user.length === 0) {
    throw new PrivacySDKError(ErrorCode.INVALID_CONFIG, 'user must not be empty');
  }
  if (amount <= 0n) {
    throw new PrivacySDKError(ErrorCode.INVALID_AMOUNT, 'amount must be positive');
  }
  if (!token || token.length === 0) {
    throw new PrivacySDKError(ErrorCode.INVALID_CONFIG, 'token must not be empty');
  }
  return {
    id: randomUUID(),
    user,
    amount,
    token,
    timestamp: Date.now(),
    disclosedTo: [...disclosedTo],
  };
}

/** Encode bytes as base64 without Node Buffer (browser-safe). */
function toBase64(bytes: Uint8Array): string {
  const bin = Array.from(bytes, (byte) => String.fromCharCode(byte)).join('');
  // btoa exists in browsers and Node >= 16.
  return btoa(bin);
}

/** Decode base64 into bytes without Node Buffer (browser-safe). */
function fromBase64(value: string): Uint8Array {
  const bin = atob(value);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) {
    bytes[i] = bin.charCodeAt(i);
  }
  return bytes;
}
