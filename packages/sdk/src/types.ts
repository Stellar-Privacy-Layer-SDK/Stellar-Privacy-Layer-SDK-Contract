export interface PoolConfig {
  contractId: string;
  networkPassphrase: string;
  rpcUrl: string;
  horizonUrl: string;
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
  secret: string;
  recipient: string;
  amount: string;
  merklePath: string[];
  merkleIndices: boolean[];
  root: string;
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
