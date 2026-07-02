import { KeyManager } from './keys';
import { ShieldedPoolClient } from './client';
import type { ComplianceView, PoolConfig } from './types';
import { ErrorCode, PrivacySDKError } from './errors';

export class ComplianceModule {
  private client: ShieldedPoolClient;
  private viewingKey: Uint8Array;

  constructor(config: PoolConfig, viewingKey?: Uint8Array) {
    this.client = new ShieldedPoolClient(config);
    this.viewingKey = viewingKey ?? KeyManager.generateViewingKey();
  }

  getViewingKeyHash(): string {
    return KeyManager.computeViewingKeyHash(this.viewingKey);
  }

  async registerViewingKey(owner: string): Promise<void> {
    const hash = this.getViewingKeyHash();
    await this.client.registerViewingKey(owner, hash);
  }

  async authorizeViewer(owner: string, viewer: string): Promise<void> {
    await this.client.authorizeViewer(owner, viewer);
  }

  encryptTransactionData(
    transactionData: Record<string, unknown>,
    viewerPublicKey: Uint8Array,
  ): Uint8Array {
    try {
      const json = JSON.stringify(transactionData);
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

  decryptTransactionData(encryptedData: Uint8Array): Record<string, unknown> {
    try {
      const decrypted = KeyManager.decryptWithViewingKey(
        encryptedData,
        this.viewingKey,
      );
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

    return {
      encryptedData,
      viewingKeyHash: this.getViewingKeyHash(),
    };
  }

  async verifySelectiveDisclosure(
    encryptedData: Uint8Array,
  ): Promise<Record<string, unknown>> {
    return this.decryptTransactionData(encryptedData);
  }

  static async getComplianceView(
    config: PoolConfig,
    owner: string,
  ): Promise<ComplianceView | null> {
    try {
      const client = new ShieldedPoolClient(config);
      const result = await client.simulateRead('get_compliance', []);

      if (!result) return null;

      return result as unknown as ComplianceView;
    } catch {
      return null;
    }
  }
}
