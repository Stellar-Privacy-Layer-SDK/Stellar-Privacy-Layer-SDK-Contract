import { KeyManager } from './keys';
import { ShieldedPoolClient } from './client';
import type { KeyPair, ShieldedTransferParams, ShieldedTransferProof } from './types';
import type { PoolConfig } from './types';

export class PrivacyAccount {
  public keyPair: KeyPair;
  private client: ShieldedPoolClient;

  constructor(config: PoolConfig, keyPair?: KeyPair) {
    this.keyPair = keyPair ?? KeyManager.generateKeyPair();
    this.client = new ShieldedPoolClient(config);
  }

  get address(): string {
    return this.keyPair.publicKey;
  }

  async getBalance(): Promise<bigint> {
    return 0n;
  }

  async deposit(params: ShieldedTransferParams): Promise<string> {
    const secret = params.secret ?? KeyManager.generateSecret();
    const commitment = KeyManager.hashCommitment(
      secret,
      params.recipient,
      params.amount,
    );

    return this.client.deposit(this.address, params.token, params.amount, commitment);
  }

  async withdraw(
    params: ShieldedTransferParams,
    leafIndex: number,
  ): Promise<string> {
    const secret = params.secret ?? KeyManager.generateSecret();
    const commitment = KeyManager.hashCommitment(
      secret,
      params.recipient,
      params.amount,
    );
    const nullifier = KeyManager.hashNullifier(secret, commitment);

    const zeroHex = KeyManager.toHex(new Uint8Array(32));

    const proof: ShieldedTransferProof = {
      proofA: [zeroHex, zeroHex] as [string, string],
      proofB: [[zeroHex, zeroHex], [zeroHex, zeroHex]] as [[string, string], [string, string]],
      proofC: [zeroHex, zeroHex] as [string, string],
      root: zeroHex,
      nullifier,
      recipient: params.recipient,
      amount: params.amount.toString(),
    };

    return this.client.withdraw(proof, params.amount, params.token);
  }

  async registerViewingKey(): Promise<void> {
    const viewingKeyHash = KeyManager.computeViewingKeyHash(
      this.keyPair.viewingKey,
    );
    await this.client.registerViewingKey(this.address, viewingKeyHash);
  }

  async authorizeViewer(viewerAddress: string): Promise<void> {
    await this.client.authorizeViewer(this.address, viewerAddress);
  }

  async getPoolStats(): Promise<{
    size: number;
    root: string | null;
    isPaused: boolean;
    version: number;
  }> {
    return this.client.getPoolStats();
  }
}
