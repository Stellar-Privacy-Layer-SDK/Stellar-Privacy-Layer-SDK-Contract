/**
 * High-level privacy account: key management + shielded deposit/withdraw +
 * compliance operations, backed by {@link ShieldedPoolClient}.
 */
import { ShieldedPoolClient } from './client.js';
import { KeyManager } from './keys.js';
import { ProverClient } from './prover.js';
import type {
  KeyPair,
  PoolConfig,
  ShieldedTransferParams,
  ShieldedTransferProof,
} from './types.js';

export class PrivacyAccount {
  public readonly keyPair: KeyPair;
  private readonly client: ShieldedPoolClient;
  private readonly prover: ProverClient;

  constructor(config: PoolConfig, keyPair?: KeyPair) {
    this.keyPair = keyPair ?? KeyManager.generateKeyPair();
    this.client = new ShieldedPoolClient(config);
    this.prover = new ProverClient();
  }

  /** The account's public address. */
  get address(): string {
    return this.keyPair.publicKey;
  }

  /** Shielded balance (private by design; returns 0 until a view is available). */
  async getBalance(): Promise<bigint> {
    return 0n;
  }

  /** Shield a deposit into the pool. Returns the prepared transaction XDR. */
  async deposit(params: ShieldedTransferParams): Promise<string> {
    const secret = params.secret ?? KeyManager.generateSecret();
    const { commitment } = await this.prover.generateDepositProof(
      secret,
      params.recipient,
      params.amount,
    );

    return this.client.deposit(this.address, params.token, params.amount, commitment);
  }

  /** Withdraw from the pool with a generated proof. Returns the prepared tx XDR. */
  async withdraw(params: ShieldedTransferParams, leafIndex: number): Promise<string> {
    const secret = params.secret ?? KeyManager.generateSecret();
    const commitment = KeyManager.hashCommitment(secret, params.recipient, params.amount);

    const proof: ShieldedTransferProof = await this.prover.generateWithdrawalProof({
      secret: KeyManager.toHex(secret),
      recipient: params.recipient,
      amount: params.amount.toString(),
      merklePath: [],
      merkleIndices: [],
      // Reference implementation: root equals the commitment and the prover
      // derives the canonical nullifier (see generateWithdrawalProof).
      root: commitment,
      nullifier: '',
      commitment,
      leafIndex,
    });

    return this.client.withdraw(proof, params.amount, params.token);
  }

  /** Register a compliance viewing key hash on-chain. */
  async registerViewingKey(): Promise<void> {
    const viewingKeyHash = KeyManager.computeViewingKeyHash(this.keyPair.viewingKey);
    await this.client.registerViewingKey(this.address, viewingKeyHash);
  }

  /** Authorize a regulator address to view this account's disclosures. */
  async authorizeViewer(viewerAddress: string): Promise<void> {
    await this.client.authorizeViewer(this.address, viewerAddress);
  }

  /** Read aggregate pool statistics. */
  async getPoolStats(): Promise<{
    size: number;
    root: string | null;
    isPaused: boolean;
    version: number;
  }> {
    return this.client.getPoolStats();
  }
}
