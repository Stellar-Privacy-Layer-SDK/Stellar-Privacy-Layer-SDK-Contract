/**
 * Compliance module: regulatory viewing keys and selective disclosure.
 *
 * The module encrypts transaction details for an authorized regulator using
 * AES-256-GCM with the regulator's public key material. Only the regulator (or
 * an account holding the viewing key) can decrypt — proving authorization.
 */
import { ShieldedPoolClient } from './client.js';
import { ErrorCode, PrivacySDKError } from './errors.js';
import { KeyManager } from './keys.js';
import { createLogger } from './logger.js';
import type { ComplianceView, PoolConfig } from './types.js';

const log = createLogger('ComplianceModule');

export class ComplianceModule {
  private client: ShieldedPoolClient;
  private viewingKey: Uint8Array;

  constructor(config: PoolConfig, viewingKey?: Uint8Array) {
    this.client = new ShieldedPoolClient(config);
    this.viewingKey = viewingKey ?? KeyManager.generateViewingKey();
  }

  /** Hex-encoded hash of the module's viewing key. */
  getViewingKeyHash(): string {
    return KeyManager.computeViewingKeyHash(this.viewingKey);
  }

  /** Register the viewing key hash on-chain for an owner. */
  async registerViewingKey(owner: string): Promise<void> {
    const hash = this.getViewingKeyHash();
    await this.client.registerViewingKey(owner, hash);
  }

  /** Authorize a regulator as a viewer for an owner. */
  async authorizeViewer(owner: string, viewer: string): Promise<void> {
    await this.client.authorizeViewer(owner, viewer);
  }

  /** Encrypt transaction data for a regulator. */
  encryptTransactionData(
    transactionData: Record<string, unknown>,
    viewerPublicKey: Uint8Array,
  ): Uint8Array {
    try {
      const json = safeStringify(transactionData);
      const data = new TextEncoder().encode(json);
      return KeyManager.encryptForViewer(data, viewerPublicKey);
    } catch (error) {
      throw new PrivacySDKError(
        ErrorCode.COMPLIANCE_ERROR,
        'Failed to encrypt transaction data',
        error,
      );
    }
  }

  /** Decrypt transaction data with the module's viewing key. */
  decryptTransactionData(encryptedData: Uint8Array): Record<string, unknown> {
    try {
      const decrypted = KeyManager.decryptWithViewingKey(encryptedData, this.viewingKey);
      const json = new TextDecoder().decode(decrypted);
      return JSON.parse(json) as Record<string, unknown>;
    } catch (error) {
      throw new PrivacySDKError(
        ErrorCode.COMPLIANCE_ERROR,
        'Failed to decrypt transaction data',
        error,
      );
    }
  }

  /**
   * Generate a selective disclosure proof: transaction details encrypted for
   * the regulator plus the viewing key hash that identifies this account.
   */
  async generateSelectiveDisclosureProof(
    transactionDetails: {
      sender: string;
      recipient: string;
      amount: bigint;
      timestamp: number;
    },
    regulatorPublicKey: Uint8Array,
  ): Promise<{ encryptedData: Uint8Array; viewingKeyHash: string }> {
    const encryptedData = this.encryptTransactionData(
      transactionDetails as unknown as Record<string, unknown>,
      regulatorPublicKey,
    );
    log.info('selective disclosure proof generated');
    return {
      encryptedData,
      viewingKeyHash: this.getViewingKeyHash(),
    };
  }

  /** Decrypt + parse a selective disclosure payload. */
  async verifySelectiveDisclosure(encryptedData: Uint8Array): Promise<Record<string, unknown>> {
    return this.decryptTransactionData(encryptedData);
  }

  /** Fetch the on-chain compliance view for an owner (null when unset). */
  static async getComplianceView(
    config: PoolConfig,
    owner: string,
  ): Promise<ComplianceView | null> {
    try {
      const client = new ShieldedPoolClient(config);
      const result = await client.getCompliance(owner);
      if (!result) return null;
      return normalizeComplianceView(result);
    } catch (error) {
      log.warn('getComplianceView failed', { error: messageOf(error) });
      return null;
    }
  }
}

/** Convert the on-chain (snake_case) compliance record to the SDK shape. */
function normalizeComplianceView(value: unknown): ComplianceView {
  const record = value as {
    owner?: unknown;
    viewing_key_hash?: unknown;
    authorized_viewers?: unknown;
  };
  return {
    owner: String(record.owner ?? ''),
    viewingKeyHash: String(record.viewing_key_hash ?? ''),
    authorizedViewers: Array.isArray(record.authorized_viewers)
      ? record.authorized_viewers.map((v) => String(v))
      : [],
  };
}

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/**
 * JSON.stringify that serializes `bigint` values as decimal strings, since
 * transaction amounts are bigints and JSON has no native BigInt support.
 */
function safeStringify(value: unknown): string {
  return JSON.stringify(value, (_key, item: unknown) =>
    typeof item === 'bigint' ? item.toString() : item,
  );
}
