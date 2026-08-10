/**
 * Off-chain prover client.
 *
 * Generates and verifies shielded-transfer proofs. The current implementation
 * is a reference proof (SHA-256 hash-chain commitment/nullifier binding); the
 * Rust `stellar-privacy-prover` crate provides the production Groth16 circuit
 * prover over BN254. See the README for the integration path.
 */
import { bytesToHex, sha256Digest } from './crypto.js';
import { ErrorCode, PrivacySDKError } from './errors.js';
import { KeyManager } from './keys.js';
import { createLogger } from './logger.js';
import type { ProofInputs, ShieldedTransferProof } from './types.js';
import { assertScalarHex, isPositiveAmount } from './validation.js';

const log = createLogger('ProverClient');

const ZERO32_HEX = '00'.repeat(32);

export class ProverClient {
  private depth: number;

  constructor(depth = 32) {
    if (!Number.isInteger(depth) || depth < 0) {
      throw new PrivacySDKError(ErrorCode.INVALID_CONFIG, 'depth must be a non-negative integer');
    }
    this.depth = depth;
  }

  /**
   * Generate the commitment/nullifier pair for a shielded deposit.
   */
  async generateDepositProof(
    secret: Uint8Array,
    recipient: string,
    amount: bigint,
  ): Promise<{ commitment: string; nullifier: string }> {
    try {
      this.validateAmount(amount);
      const commitment = KeyManager.hashCommitment(secret, recipient, amount);
      const nullifier = KeyManager.hashNullifier(secret, commitment);
      log.debug('deposit proof generated');
      return { commitment, nullifier };
    } catch (error) {
      if (error instanceof PrivacySDKError) throw error;
      throw new PrivacySDKError(
        ErrorCode.PROOF_GENERATION_FAILED,
        'Failed to generate deposit proof',
        error,
      );
    }
  }

  /**
   * Generate a withdrawal proof for a previously deposited commitment.
   *
   * Reference binding scheme (the Rust prover uses Groth16/Poseidon):
   *   commitment = H(secret || recipient || amount)
   *   secretHash = H(secret)                       — kept in the proof, never the secret itself
   *   nullifier  = H(secretHash || commitment)     — verifiable without revealing the secret
   *
   * `inputs.nullifier` is informational in this reference implementation and is
   * always derived from the canonical binding above.
   */
  async generateWithdrawalProof(inputs: ProofInputs): Promise<ShieldedTransferProof> {
    try {
      this.validateProofInputs(inputs);

      const secretBytes = KeyManager.fromHex(inputs.secret);
      const commitment = KeyManager.hashCommitment(
        secretBytes,
        inputs.recipient,
        BigInt(inputs.amount),
      );

      const hash = (data: Uint8Array): string => bytesToHex(sha256Digest(data));
      const secretHash = hash(secretBytes);

      // H(secretHash || commitment) — matches verifyProof()'s re-computation.
      const secretHashBytes = KeyManager.fromHex(secretHash);
      const commitmentBytes = KeyManager.fromHex(commitment);
      const binding = new Uint8Array(secretHashBytes.length + commitmentBytes.length);
      binding.set(secretHashBytes, 0);
      binding.set(commitmentBytes, secretHashBytes.length);
      const nullifier = hash(binding);

      const proof: ShieldedTransferProof = {
        proofA: [secretHash, commitment],
        proofB: [
          [hash(KeyManager.fromHex(inputs.root)), nullifier],
          [
            hash(new TextEncoder().encode(inputs.recipient)),
            hash(new TextEncoder().encode(inputs.amount)),
          ],
        ],
        proofC: [hash(new TextEncoder().encode(String(inputs.leafIndex))), ZERO32_HEX],
        root: inputs.root,
        nullifier,
        recipient: inputs.recipient,
        amount: inputs.amount,
      };

      log.debug('withdrawal proof generated', { leafIndex: inputs.leafIndex });
      return proof;
    } catch (error) {
      if (error instanceof PrivacySDKError) throw error;
      throw new PrivacySDKError(
        ErrorCode.PROOF_GENERATION_FAILED,
        'Failed to generate withdrawal proof',
        error,
      );
    }
  }

  /**
   * Verify the internal consistency of a proof (commitment/nullifier binding).
   *
   * Re-computes `H(proofA[0] || proofA[1])` and compares it with the claimed
   * nullifier, mirroring {@link generateWithdrawalProof}. On-chain verification
   * is performed by the contract's verifier.
   */
  async verifyProof(proof: ShieldedTransferProof): Promise<boolean> {
    try {
      if (!assertScalarHexOrFalse(proof.root)) return false;
      if (!assertScalarHexOrFalse(proof.nullifier)) return false;
      if (!isPositiveAmount(proof.amount)) return false;

      // proofA[0] is the secret hash (never the raw secret) and proofA[1] is the
      // commitment; the nullifier is bound to both.
      const secretHash = KeyManager.fromHex(proof.proofA[0]);
      const commitmentBytes = KeyManager.fromHex(proof.proofA[1]);
      const buf = new Uint8Array(secretHash.length + commitmentBytes.length);
      buf.set(secretHash, 0);
      buf.set(commitmentBytes, secretHash.length);
      const computedNullifier = sha256Digest(buf);

      return bytesToHex(computedNullifier) === proof.nullifier;
    } catch (error) {
      throw new PrivacySDKError(
        ErrorCode.PROOF_VERIFICATION_FAILED,
        'Failed to verify proof',
        error,
      );
    }
  }

  private validateAmount(amount: bigint): void {
    if (!isPositiveAmount(amount)) {
      throw new PrivacySDKError(ErrorCode.INVALID_AMOUNT, 'Amount must be positive');
    }
  }

  private validateProofInputs(inputs: ProofInputs): void {
    if (!inputs.secret || inputs.secret.length === 0) {
      throw new PrivacySDKError(
        ErrorCode.INVALID_COMMITMENT,
        'Secret is required for proof generation',
      );
    }
    assertScalarHex(inputs.secret, 'secret');
    if (!inputs.recipient) {
      throw new PrivacySDKError(
        ErrorCode.INVALID_COMMITMENT,
        'Recipient is required for proof generation',
      );
    }
    this.validateAmount(BigInt(inputs.amount));
    if (this.depth > 0 && inputs.merklePath.length !== this.depth) {
      throw new PrivacySDKError(
        ErrorCode.INVALID_COMMITMENT,
        `Merkle path must have ${this.depth} elements`,
      );
    }
  }
}

function assertScalarHexOrFalse(value: string): boolean {
  if (typeof value !== 'string' || !/^[0-9a-fA-F]{64}$/.test(value)) {
    return false;
  }
  return true;
}
