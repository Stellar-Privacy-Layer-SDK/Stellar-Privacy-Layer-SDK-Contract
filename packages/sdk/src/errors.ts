export enum ErrorCode {
  /** Network / RPC connection failure. */
  CONNECTION_FAILED = 'CONNECTION_FAILED',
  /** Off-chain proof generation failed. */
  PROOF_GENERATION_FAILED = 'PROOF_GENERATION_FAILED',
  /** On-chain or local proof verification failed. */
  PROOF_VERIFICATION_FAILED = 'PROOF_VERIFICATION_FAILED',
  /** Commitment value is missing or malformed. */
  INVALID_COMMITMENT = 'INVALID_COMMITMENT',
  /** Nullifier has already been spent on-chain. */
  NULLIFIER_SPENT = 'NULLIFIER_SPENT',
  /** Caller is not authorized to perform the operation. */
  UNAUTHORIZED = 'UNAUTHORIZED',
  /** The shielded pool is paused by its admin. */
  CONTRACT_PAUSED = 'CONTRACT_PAUSED',
  /** The shielded pool has reached its maximum capacity. */
  POOL_FULL = 'POOL_FULL',
  /** Amount is missing, negative, or zero. */
  INVALID_AMOUNT = 'INVALID_AMOUNT',
  /** Compliance / disclosure operation failed. */
  COMPLIANCE_ERROR = 'COMPLIANCE_ERROR',
  /** Cryptographic key generation failed. */
  KEY_GENERATION_FAILED = 'KEY_GENERATION_FAILED',
  /** SDK configuration is invalid (bad contract id, URL, etc.). */
  INVALID_CONFIG = 'INVALID_CONFIG',
  /** The transaction was simulated but not yet signed/submitted. */
  TX_NEEDS_SIGNING = 'TX_NEEDS_SIGNING',
}

/**
 * Typed error thrown by the Stellar Privacy SDK.
 *
 * Carries a machine-readable {@link ErrorCode}, a human-readable message, and
 * optional structured details (e.g. the underlying cause).
 */
export class PrivacySDKError extends Error {
  readonly code: ErrorCode;
  readonly details?: unknown;

  constructor(code: ErrorCode, message: string, details?: unknown) {
    const suffix = details instanceof Error ? `: ${details.message}` : '';
    super(`[${code}] ${message}${suffix}`);
    this.name = 'PrivacySDKError';
    this.code = code;
    this.details = details;
    if (details instanceof Error) {
      // Preserve the original stack for diagnostics (best-effort).
      this.stack = `${this.stack}\nCaused by: ${details.stack}`;
    }
  }

  /** True when the error carries the given code. */
  is(code: ErrorCode): boolean {
    return this.code === code;
  }
}
