import crypto from 'crypto';

const AES_TAG_LENGTH = 16;
const IV_LENGTH = 12;

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

function deriveEncryptionKey(material: string | Uint8Array): Buffer {
  const ikm = typeof material === 'string' ? Buffer.from(material, 'utf-8') : Buffer.from(material);
  const salt = Buffer.from('Stellar-Privacy-Disclosure-v1', 'utf-8');
  const info = Buffer.from('selective-disclosure', 'utf-8');
  return crypto.hkdfSync('sha256', ikm, salt, info, 32);
}

export class SelectiveDisclosureModule {
  private config: RegulatoryComplianceConfig;

  constructor(config: RegulatoryComplianceConfig) {
    this.config = config;
  }

  createDisclosureRequest(
    regulator: string,
    scope: string[],
    ttlMs: number = 3600000,
  ): DisclosureRequest {
    return {
      requestId: crypto.randomUUID(),
      regulator,
      scope,
      timestamp: Date.now(),
      expiresAt: Date.now() + ttlMs,
    };
  }

  async fulfillDisclosureRequest(
    request: DisclosureRequest,
    transactionData: Record<string, unknown>,
    viewingKey: Uint8Array,
  ): Promise<DisclosureResponse> {
    if (Date.now() > request.expiresAt) {
      throw new Error('Disclosure request has expired');
    }

    const filteredData = this.filterDataByScope(
      request.scope,
      transactionData,
    );

    const json = JSON.stringify(filteredData);
    const encrypted = this.encryptWithRegulatorKey(json);

    const viewingKeyProof = crypto
      .createHash('sha256')
      .update(Buffer.from(viewingKey))
      .update(request.requestId)
      .digest()
      .toString('hex');

    return {
      requestId: request.requestId,
      encryptedData: encrypted.toString('base64'),
      viewingKeyProof,
      timestamp: Date.now(),
    };
  }

  verifyDisclosureResponse(
    response: DisclosureResponse,
    viewingKey: Uint8Array,
  ): boolean {
    const expectedProof = crypto
      .createHash('sha256')
      .update(Buffer.from(viewingKey))
      .update(response.requestId)
      .digest()
      .toString('hex');

    return response.viewingKeyProof === expectedProof;
  }

  decryptDisclosureData(
    response: DisclosureResponse,
    regulatorPrivateKey: Uint8Array,
  ): Record<string, unknown> {
    const encrypted = Buffer.from(response.encryptedData, 'base64');
    const decrypted = this.decryptWithRegulatorKey(
      encrypted,
      regulatorPrivateKey,
    );
    return JSON.parse(decrypted) as Record<string, unknown>;
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

  private encryptWithRegulatorKey(data: string): Buffer {
    const iv = crypto.randomBytes(IV_LENGTH);
    const key = deriveEncryptionKey(this.config.regulatorPublicKey);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const encrypted = Buffer.concat([
      cipher.update(Buffer.from(data)),
      cipher.final(),
    ]);
    const tag = cipher.getAuthTag();
    return Buffer.concat([iv, encrypted, tag]);
  }

  private decryptWithRegulatorKey(
    encrypted: Buffer,
    privateKey: Uint8Array,
  ): string {
    const iv = encrypted.subarray(0, IV_LENGTH);
    const tag = encrypted.subarray(encrypted.length - AES_TAG_LENGTH);
    const data = encrypted.subarray(IV_LENGTH, encrypted.length - AES_TAG_LENGTH);
    const key = deriveEncryptionKey(privateKey);
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    const decrypted = Buffer.concat([
      decipher.update(Buffer.from(data)),
      decipher.final(),
    ]);
    return decrypted.toString();
  }
}

export function generateAuditRecord(
  user: string,
  amount: bigint,
  token: string,
  disclosedTo: string[] = [],
): AuditRecord {
  return {
    id: crypto.randomUUID(),
    user,
    amount,
    token,
    timestamp: Date.now(),
    disclosedTo,
  };
}
