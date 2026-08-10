import { describe, expect, it } from 'vitest';
import { ErrorCode } from '../errors.js';
import { KeyManager } from '../keys.js';
import { ProverClient } from '../prover.js';
import type { ProofInputs } from '../types.js';

const SECRET = 'bb'.repeat(32);
const COMMITMENT = 'aa'.repeat(32);

function validInputs(overrides: Partial<ProofInputs> = {}): ProofInputs {
  return {
    secret: SECRET,
    recipient: 'GB...',
    amount: '1000',
    merklePath: [],
    merkleIndices: [],
    root: COMMITMENT,
    nullifier: '',
    commitment: COMMITMENT,
    leafIndex: 0,
    ...overrides,
  };
}

describe('ProverClient', () => {
  it('defaults to depth 32 and rejects invalid depths', () => {
    expect(new ProverClient()).toBeDefined();
    expect(() => new ProverClient(-1)).toThrowError(ErrorCode.INVALID_CONFIG);
    expect(() => new ProverClient(1.5)).toThrowError(ErrorCode.INVALID_CONFIG);
  });

  it('generates a deposit proof (commitment + nullifier)', async () => {
    const prover = new ProverClient();
    const result = await prover.generateDepositProof(KeyManager.generateSecret(), 'GB...', 1000n);
    expect(result.commitment).toMatch(/^[0-9a-f]{64}$/);
    expect(result.nullifier).toMatch(/^[0-9a-f]{64}$/);
    expect(result.commitment).not.toBe(result.nullifier);
  });

  it('rejects non-positive deposit amounts', async () => {
    const prover = new ProverClient();
    await expect(
      prover.generateDepositProof(KeyManager.generateSecret(), 'GB...', 0n),
    ).rejects.toMatchObject({ code: ErrorCode.INVALID_AMOUNT });
  });

  it('generates a withdrawal proof with a verifiable binding', async () => {
    const prover = new ProverClient(0);
    const proof = await prover.generateWithdrawalProof(validInputs());
    const expectedCommitment = KeyManager.hashCommitment(
      KeyManager.fromHex(SECRET),
      'GB...',
      1000n,
    );
    expect(proof.proofA[0]).toMatch(/^[0-9a-f]{64}$/);
    expect(proof.proofA[1]).toBe(expectedCommitment);
    expect(proof.nullifier).toMatch(/^[0-9a-f]{64}$/);
    expect(await prover.verifyProof(proof)).toBe(true);
  });

  it('never places the raw secret in the proof', async () => {
    const prover = new ProverClient(0);
    const proof = await prover.generateWithdrawalProof(validInputs());
    const serialized = JSON.stringify(proof);
    expect(serialized).not.toContain(SECRET);
  });

  it('rejects an empty or malformed secret', async () => {
    const prover = new ProverClient(0);
    await expect(prover.generateWithdrawalProof(validInputs({ secret: '' }))).rejects.toMatchObject(
      { code: ErrorCode.INVALID_COMMITMENT },
    );
    await expect(
      prover.generateWithdrawalProof(validInputs({ secret: 'not-hex' })),
    ).rejects.toMatchObject({ code: ErrorCode.INVALID_COMMITMENT });
  });

  it('rejects a missing recipient', async () => {
    const prover = new ProverClient(0);
    await expect(
      prover.generateWithdrawalProof(validInputs({ recipient: '' })),
    ).rejects.toMatchObject({ code: ErrorCode.INVALID_COMMITMENT });
  });

  it('rejects a non-positive amount', async () => {
    const prover = new ProverClient(0);
    await expect(
      prover.generateWithdrawalProof(validInputs({ amount: '0' })),
    ).rejects.toMatchObject({ code: ErrorCode.INVALID_AMOUNT });
  });

  it('rejects a mismatched merkle path length at non-zero depth', async () => {
    const prover = new ProverClient(2);
    await expect(prover.generateWithdrawalProof(validInputs())).rejects.toMatchObject({
      code: ErrorCode.INVALID_COMMITMENT,
    });
  });

  it('accepts a full merkle path at depth 32', async () => {
    const prover = new ProverClient(32);
    const inputs = validInputs({
      merklePath: Array.from({ length: 32 }, () => '00'.repeat(32)),
    });
    const proof = await prover.generateWithdrawalProof(inputs);
    expect(await prover.verifyProof(proof)).toBe(true);
  });

  describe('verifyProof', () => {
    it('rejects proofs with malformed or non-positive fields', async () => {
      const proof = await new ProverClient(0).generateWithdrawalProof(validInputs());
      const verifier = new ProverClient();
      expect(await verifier.verifyProof({ ...proof, root: 'zz' })).toBe(false);
      expect(await verifier.verifyProof({ ...proof, nullifier: 'not-hex' })).toBe(false);
      expect(await verifier.verifyProof({ ...proof, amount: '0' })).toBe(false);
    });

    it('rejects a tampered nullifier', async () => {
      const proof = await new ProverClient(0).generateWithdrawalProof(validInputs());
      const verifier = new ProverClient();
      expect(await verifier.verifyProof({ ...proof, nullifier: 'ff'.repeat(32) })).toBe(false);
    });

    it('rejects malformed proof scalars with a typed error', async () => {
      const proof = await new ProverClient(0).generateWithdrawalProof(validInputs());
      const verifier = new ProverClient();
      await expect(verifier.verifyProof({ ...proof, proofA: ['zz', 'zz'] })).rejects.toMatchObject({
        code: ErrorCode.PROOF_VERIFICATION_FAILED,
      });
    });
  });
});
