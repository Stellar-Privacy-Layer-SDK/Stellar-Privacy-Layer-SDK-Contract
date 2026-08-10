export { PrivacyAccount } from './account.js';
export { ShieldedPoolClient } from './client.js';
export { ComplianceModule } from './compliance.js';
export {
  aesGcmDecrypt,
  aesGcmEncrypt,
  bytesToHex,
  equalBytes,
  hexToBytes,
  hkdfSha256,
  randomBytes,
  randomUUID,
  sha256Digest,
  sha256Hex,
} from './crypto.js';
export { ErrorCode, PrivacySDKError } from './errors.js';
export { KeyManager } from './keys.js';
export type { LogEntry, LogLevel, LogSink } from './logger.js';
export { configureLogger, createLogger } from './logger.js';
export { ProverClient } from './prover.js';
export type {
  ComplianceView,
  DepositEvent,
  KeyPair,
  PoolConfig,
  PoolStats,
  ProofInputs,
  ShieldedTransferParams,
  ShieldedTransferProof,
  WithdrawalEvent,
} from './types.js';
export {
  isHex,
  isPositiveAmount,
  isStellarAddress,
  validatePoolConfig,
} from './validation.js';
