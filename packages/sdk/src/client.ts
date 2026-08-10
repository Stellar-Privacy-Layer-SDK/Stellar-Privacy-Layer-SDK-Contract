/**
 * On-chain client for the `ShieldedPool` Soroban contract.
 *
 * Built on the @stellar/stellar-sdk v16 `AssembledTransaction` API:
 * - Read calls are simulated and return the decoded result.
 * - Write calls are simulated and returned as a base64 XDR envelope ready to be
 *   signed and submitted by the caller's wallet (`signAndSend` is left to the
 *   integrator to keep this SDK signer-agnostic).
 */
import { Address, nativeToScVal, rpc, scValToNative, xdr } from '@stellar/stellar-sdk';
import { AssembledTransaction } from '@stellar/stellar-sdk/contract';
import { hexToBytes } from './crypto.js';
import { ErrorCode, PrivacySDKError } from './errors.js';
import { createLogger } from './logger.js';
import type { PoolConfig, PoolStats, ShieldedTransferProof } from './types.js';
import { assertScalarHex, validatePoolConfig } from './validation.js';

const DEFAULT_FEE = '10000';
const DEFAULT_TIMEOUT = 30;

const log = createLogger('ShieldedPoolClient');

/** Convert a hex string to an `xdr.ScVal` `bytes` value. */
function bytesScVal(hex: string): xdr.ScVal {
  // stellar-sdk types `scvBytes(value: Buffer)`; at runtime any Uint8Array is a
  // Buffer (Buffer extends Uint8Array). The cast keeps this SDK browser-safe
  // without depending on Node's Buffer polyfill.
  return xdr.ScVal.scvBytes(hexToBytes(hex) as unknown as Buffer);
}

export class ShieldedPoolClient {
  private config: PoolConfig;
  private server: rpc.Server;

  constructor(config: PoolConfig) {
    validatePoolConfig(config);
    this.config = config;
    this.server = new rpc.Server(config.rpcUrl, { allowHttp: config.allowHttp ?? false });
  }

  /**
   * Simulate a read-only contract call and return the native (decoded) result.
   */
  async simulateRead(method: string, args: xdr.ScVal[]): Promise<unknown> {
    const tx = await this.build(method, args, (retval) => scValToNative(retval));
    return tx.result;
  }

  /** Deposit tokens into the shielded pool. Returns the prepared tx XDR. */
  async deposit(
    depositor: string,
    token: string,
    amount: bigint,
    commitment: string,
  ): Promise<string> {
    assertScalarHex(commitment, 'commitment');
    try {
      const args = [
        new Address(depositor).toScVal(),
        new Address(token).toScVal(),
        nativeToScVal(amount, { type: 'i128' }),
        bytesScVal(commitment),
      ];
      const tx = await this.build('deposit', args, (retval) => String(scValToNative(retval)));
      log.info('deposit transaction assembled', { contractId: this.config.contractId });
      return tx.toXDR();
    } catch (error) {
      if (error instanceof PrivacySDKError) throw error;
      throw new PrivacySDKError(ErrorCode.CONNECTION_FAILED, 'Deposit transaction failed', error);
    }
  }

  /** Withdraw tokens from the shielded pool. Returns the prepared tx XDR. */
  async withdraw(proof: ShieldedTransferProof, amount: bigint, token: string): Promise<string> {
    try {
      const args = [
        this.proofToScVal(proof),
        nativeToScVal(amount, { type: 'i128' }),
        new Address(token).toScVal(),
      ];
      const tx = await this.build('withdraw', args, (retval) => String(scValToNative(retval)));
      log.info('withdraw transaction assembled', { contractId: this.config.contractId });
      return tx.toXDR();
    } catch (error) {
      if (error instanceof PrivacySDKError) throw error;
      throw new PrivacySDKError(
        ErrorCode.PROOF_VERIFICATION_FAILED,
        'Withdraw transaction failed',
        error,
      );
    }
  }

  /** Register a compliance viewing key hash on-chain. Returns the prepared tx XDR. */
  async registerViewingKey(owner: string, viewingKeyHash: string): Promise<string> {
    assertScalarHex(viewingKeyHash, 'viewingKeyHash');
    try {
      const args = [new Address(owner).toScVal(), bytesScVal(viewingKeyHash)];
      const tx = await this.build('register_viewing_key', args, () => undefined);
      return tx.toXDR();
    } catch (error) {
      if (error instanceof PrivacySDKError) throw error;
      throw new PrivacySDKError(
        ErrorCode.COMPLIANCE_ERROR,
        'Failed to register viewing key',
        error,
      );
    }
  }

  /** Authorize a regulator as a viewer on-chain. Returns the prepared tx XDR. */
  async authorizeViewer(owner: string, viewer: string): Promise<string> {
    try {
      const args = [new Address(owner).toScVal(), new Address(viewer).toScVal()];
      const tx = await this.build('authorize_viewer', args, () => undefined);
      return tx.toXDR();
    } catch (error) {
      if (error instanceof PrivacySDKError) throw error;
      throw new PrivacySDKError(ErrorCode.COMPLIANCE_ERROR, 'Failed to authorize viewer', error);
    }
  }

  /** Read the current Merkle root, if the pool is initialized. */
  async getRoot(): Promise<string | null> {
    try {
      const result = await this.simulateRead('get_root', []);
      return result ? String(result) : null;
    } catch (error) {
      log.warn('get_root failed', { error: messageOf(error) });
      return null;
    }
  }

  /** Check whether a nullifier has already been spent. */
  async isNullifierSpent(nullifier: string): Promise<boolean> {
    assertScalarHex(nullifier, 'nullifier');
    try {
      const result = await this.simulateRead('is_nullifier_spent', [bytesScVal(nullifier)]);
      return result === true;
    } catch (error) {
      log.warn('is_nullifier_spent failed', { error: messageOf(error) });
      return false;
    }
  }

  /** Read the number of deposits in the pool. */
  async getPoolSize(): Promise<number> {
    try {
      const result = await this.simulateRead('get_pool_size', []);
      return Number(result);
    } catch (error) {
      log.warn('get_pool_size failed', { error: messageOf(error) });
      return 0;
    }
  }

  /** Read the compliance record for an owner, if one exists. */
  async getCompliance(owner: string): Promise<unknown> {
    return this.simulateRead('get_compliance', [new Address(owner).toScVal()]);
  }

  /** Read whether the shielded pool is paused by its admin. */
  async getPaused(): Promise<boolean> {
    try {
      const result = await this.simulateRead('is_paused', []);
      return result === true;
    } catch (error) {
      log.warn('is_paused failed', { error: messageOf(error) });
      return false;
    }
  }

  /** Read the contract version. */
  async getVersion(): Promise<number> {
    try {
      const result = await this.simulateRead('version', []);
      return Number(result);
    } catch (error) {
      log.warn('version read failed', { error: messageOf(error) });
      return 1;
    }
  }

  /**
   * Convenience aggregate of read-only pool statistics. Each read degrades
   * gracefully (root → null, size → 0, paused → false, version → 1) so callers
   * always get a well-formed {@link PoolStats} even when a read fails.
   */
  async getPoolStats(): Promise<PoolStats> {
    const [root, size, isPaused, version] = await Promise.all([
      this.getRoot(),
      this.getPoolSize(),
      this.getPaused(),
      this.getVersion(),
    ]);
    return { root, size, isPaused, version };
  }

  /**
   * Build + simulate a contract call. Read calls require no signer; write calls
   * return a prepared transaction envelope via `tx.toXDR()`.
   */
  private async build<T>(
    method: string,
    args: xdr.ScVal[],
    parseResultXdr: (retval: xdr.ScVal) => T,
  ): Promise<AssembledTransaction<T>> {
    return AssembledTransaction.build<T>({
      method,
      args,
      contractId: this.config.contractId,
      networkPassphrase: this.config.networkPassphrase,
      rpcUrl: this.config.rpcUrl,
      server: this.server,
      publicKey: this.config.sourceAccount,
      fee: this.config.fee ?? DEFAULT_FEE,
      timeoutInSeconds: DEFAULT_TIMEOUT,
      parseResultXdr,
    });
  }

  /** Serialize a `ShieldedTransferProof` into the contract's `Proof` struct XDR. */
  private proofToScVal(proof: ShieldedTransferProof): xdr.ScVal {
    assertScalarHex(proof.root, 'proof.root');
    assertScalarHex(proof.nullifier, 'proof.nullifier');
    const vec = (items: string[]): xdr.ScVal =>
      xdr.ScVal.scvVec(items.map((item) => bytesScVal(item)));
    return xdr.ScVal.scvVec([
      vec(proof.proofA),
      vec(proof.proofB.flat()),
      vec(proof.proofC),
      bytesScVal(proof.root),
      bytesScVal(proof.nullifier),
      new Address(proof.recipient).toScVal(),
    ]);
  }
}

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
