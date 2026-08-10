export interface PoolConfig {
  /** The deployed `ShieldedPool` contract address (C...). */
  contractId: string;
  /** Stellar network passphrase, e.g. `Test SDF Network ; quorum-test`. */
  networkPassphrase: string;
  /** Soroban RPC endpoint URL. */
  rpcUrl: string;
  /** Horizon endpoint URL (used for account/balance queries). */
  horizonUrl?: string;
  /**
   * Optional public key of the transaction source account. Required for
   * signing/submitting write transactions; optional for read-only calls.
   */
  sourceAccount?: string;
  /** Base fee for transactions, in stroops (default: '10000'). */
  fee?: string;
  /** Allow plain-HTTP RPC endpoints (dev only; defaults to false). */
  allowHttp?: boolean;
}

export interface ShieldedTransferProof {
  proofA: [string, string];
  proofB: [[string, string], [string, string]];
  proofC: [string, string];
  root: string;
  nullifier: string;
  recipient: string;
  amount: string;
}

export interface DepositEvent {
  depositor: string;
  commitment: string;
  amount: string;
  token: string;
  timestamp: number;
}

export interface WithdrawalEvent {
  recipient: string;
  nullifier: string;
  amount: string;
  token: string;
  timestamp: number;
}

export interface ProofInputs {
  /** Hex-encoded 32-byte secret. */
  secret: string;
  /** Recipient address (G...). */
  recipient: string;
  /** Amount as a decimal string. */
  amount: string;
  merklePath: string[];
  merkleIndices: boolean[];
  root: string;
  /**
   * Informational in the reference implementation: `generateWithdrawalProof`
   * derives the canonical proof binding (`H(H(secret) || commitment)`) and
   * ignores this field. See {@link KeyManager.hashNullifier} for the on-chain
   * nullifier concept.
   */
  nullifier: string;
  commitment: string;
  leafIndex: number;
}

export interface ComplianceView {
  owner: string;
  viewingKeyHash: string;
  authorizedViewers: string[];
}

export interface PoolStats {
  size: number;
  root: string | null;
  isPaused: boolean;
  version: number;
}

export interface ShieldedTransferParams {
  amount: bigint;
  recipient: string;
  token: string;
  secret?: Uint8Array;
}

export interface KeyPair {
  secretKey: Uint8Array;
  publicKey: string;
  viewingKey: Uint8Array;
}
