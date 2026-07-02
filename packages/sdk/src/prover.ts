import crypto from 'crypto';
import { ErrorCode, PrivacySDKError } from './errors';
import { KeyManager } from './keys';
import type { ShieldedTransferProof, ProofInputs } from './types';

export class ProverClient {
  private depth: number;

  constructor(depth: number = 32) {
    this.depth = depth;
  }

  async generateDepositProof(
    secret: Uint8Array,
    recipient: string,
    amount: bigint,
  ): Promise<{ commitment: string; nullifier: string }> {
    try {
      const commitment = KeyManager.hashCommitment(secret, recipient, amount);
      const nullifier = KeyManager.hashNullifier(secret, commitment);

      return { commitment, nullifier };
    } catch (error) {
      throw new PrivacySDKError(
        ErrorCode.PROOF_GENERATION_FAILED,
        'Failed to generate deposit proof',
        error,
      );
    }
  }

  async generateWithdrawalProof(
    inputs: ProofInputs,
  ): Promise<ShieldedTransferProof> {
    try {
      this.validateProofInputs(inputs);

      const secretBytes = KeyManager.fromHex(inputs.secret);
      const commitment = KeyManager.hashCommitment(
        secretBytes,
        inputs.recipient,
        BigInt(inputs.amount),
      );
      const nullifier = KeyManager.hashNullifier(secretBytes, commitment);

      const proof: ShieldedTransferProof = {
        proofA: [
          KeyManager.toHex(crypto.createHash('sha256').update(inputs.secret).digest()),
          commitment,
        ],
        proofB: [
          [
            KeyManager.toHex(crypto.createHash('sha256').update(inputs.root).digest()),
            nullifier,
          ],
          [
            KeyManager.toHex(crypto.createHash('sha256').update(inputs.recipient).digest()),
            KeyManager.toHex(crypto.createHash('sha256').update(inputs.amount.toString()).digest()),
          ],
        ],
        proofC: [
          KeyManager.toHex(crypto.createHash('sha256').update(inputs.leafIndex.toString()).digest()),
          KeyManager.toHex(new Uint8Array(32)),
        ],
        root: inputs.root,
        nullifier,
        recipient: inputs.recipient,
        amount: inputs.amount,
      };

      return proof;
    } catch (error) {
      throw new PrivacySDKError(
        ErrorCode.PROOF_GENERATION_FAILED,
        'Failed to generate withdrawal proof',
        error,
      );
    }
  }

  async verifyProof(proof: ShieldedTransferProof): Promise<boolean> {
    try {
      if (!proof.root || proof.root.length !== 64) {
        return false;
      }
      if (!proof.nullifier || proof.nullifier.length !== 64) {
        return false;
      }
      if (proof.amount === '0') {
        return false;
      }

      const secretHash = crypto.createHash('sha256').update(Buffer.from(proof.proofA[0], 'hex')).digest();
      const computedNullifier = crypto.createHash('sha256')
        .update(secretHash)
        .update(Buffer.from(proof.proofA[1], 'hex'))
        .digest();

      return computedNullifier.toString('hex') === proof.nullifier;
    } catch {
      throw new PrivacySDKError(
        ErrorCode.PROOF_VERIFICATION_FAILED,
        'Failed to verify proof',
      );
    }
  }

  private validateProofInputs(inputs: ProofInputs): void {
    if (!inputs.secret || inputs.secret.length === 0) {
      throw new PrivacySDKError(
        ErrorCode.INVALID_COMMITMENT,
        'Secret is required for proof generation',
      );
    }

    if (!inputs.recipient) {
      throw new PrivacySDKError(
        ErrorCode.INVALID_COMMITMENT,
        'Recipient is required for proof generation',
      );
    }

    const amount = BigInt(inputs.amount);
    if (amount <= 0n) {
      throw new PrivacySDKError(
        ErrorCode.INVALID_AMOUNT,
        'Amount must be positive',
      );
    }

    if (inputs.merklePath.length !== this.depth) {
      throw new PrivacySDKError(
        ErrorCode.INVALID_COMMITMENT,
        `Merkle path must have ${this.depth} elements`,
      );
    }
  }
}
