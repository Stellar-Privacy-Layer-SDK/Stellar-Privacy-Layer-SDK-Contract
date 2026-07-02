import {
  Contract,
  SorobanRpc,
  Address,
  nativeToScVal,
  scValToNative,
  TransactionBuilder,
  xdr,
} from '@stellar/stellar-sdk';
import type { PoolConfig, ShieldedTransferProof, PoolStats } from './types';
import { ErrorCode, PrivacySDKError } from './errors';

export class ShieldedPoolClient {
  private config: PoolConfig;
  private contract: Contract;
  private server: SorobanRpc.Server;

  constructor(config: PoolConfig) {
    this.config = config;
    this.contract = new Contract(config.contractId);
    this.server = new SorobanRpc.Server(config.rpcUrl);
  }

  async deposit(
    depositor: string,
    token: string,
    amount: bigint,
    commitment: string,
  ): Promise<string> {
    try {
      const params = [
        new Address(depositor).toScVal(),
        new Address(token).toScVal(),
        nativeToScVal(amount, { type: 'i128' }),
        nativeToScVal(commitment, { type: 'bytes' }),
      ];

      const result = await this.simulateAndSend('deposit', params);
      return String(result);
    } catch (error) {
      throw new PrivacySDKError(
        ErrorCode.CONNECTION_FAILED,
        'Deposit transaction failed',
        error,
      );
    }
  }

  async withdraw(
    proof: ShieldedTransferProof,
    amount: bigint,
    token: string,
  ): Promise<string> {
    try {
      const proofScVal = this.proofToScVal(proof);
      const params = [
        proofScVal,
        nativeToScVal(amount, { type: 'i128' }),
        new Address(token).toScVal(),
      ];

      const result = await this.simulateAndSend('withdraw', params);
      return String(result);
    } catch (error) {
      throw new PrivacySDKError(
        ErrorCode.PROOF_VERIFICATION_FAILED,
        'Withdraw transaction failed',
        error,
      );
    }
  }

  async registerViewingKey(owner: string, viewingKeyHash: string): Promise<void> {
    try {
      const params = [
        new Address(owner).toScVal(),
        nativeToScVal(viewingKeyHash, { type: 'bytes' }),
      ];

      await this.simulateAndSend('register_viewing_key', params);
    } catch (error) {
      throw new PrivacySDKError(
        ErrorCode.COMPLIANCE_ERROR,
        'Failed to register viewing key',
        error,
      );
    }
  }

  async authorizeViewer(owner: string, viewer: string): Promise<void> {
    try {
      const params = [
        new Address(owner).toScVal(),
        new Address(viewer).toScVal(),
      ];

      await this.simulateAndSend('authorize_viewer', params);
    } catch (error) {
      throw new PrivacySDKError(
        ErrorCode.COMPLIANCE_ERROR,
        'Failed to authorize viewer',
        error,
      );
    }
  }

  async getRoot(): Promise<string | null> {
    try {
      const result = await this.simulateRead('get_root', []);
      return result ? String(result) : null;
    } catch {
      return null;
    }
  }

  async isNullifierSpent(nullifier: string): Promise<boolean> {
    try {
      const params = [nativeToScVal(nullifier, { type: 'bytes' })];
      const result = await this.simulateRead('is_nullifier_spent', params);
      return result === true;
    } catch {
      return false;
    }
  }

  async getPoolSize(): Promise<number> {
    try {
      const result = await this.simulateRead('get_pool_size', []);
      return Number(result);
    } catch {
      return 0;
    }
  }

  async getPoolStats(): Promise<PoolStats> {
    const [root, size] = await Promise.all([
      this.getRoot(),
      this.getPoolSize(),
    ]);

    return { root, size, isPaused: false, version: 1 };
  }

  async simulateRead(
    method: string,
    params: xdr.ScVal[],
  ): Promise<unknown> {
    const source = await this.server.getAccount(
      this.config.contractId,
    );

    const operation = this.contract.call(method, ...params);
    const transaction = new TransactionBuilder(source, {
      fee: '10000',
      networkPassphrase: this.config.networkPassphrase,
    })
      .addOperation(operation)
      .setTimeout(30)
      .build();

    const response = await this.server.simulateTransaction(transaction);
    if (SorobanRpc.Api.isSimulationError(response)) {
      return null;
    }

    if (!response.result) {
      return null;
    }

    return scValToNative(response.result.retval);
  }

  private async simulateAndSend(
    method: string,
    params: xdr.ScVal[],
  ): Promise<unknown> {
    const source = await this.server.getAccount(
      this.config.contractId,
    );

    const operation = this.contract.call(method, ...params);
    const transaction = new TransactionBuilder(source, {
      fee: '10000',
      networkPassphrase: this.config.networkPassphrase,
    })
      .addOperation(operation)
      .setTimeout(30)
      .build();

    const simulateResponse = await this.server.simulateTransaction(transaction);
    if (SorobanRpc.Api.isSimulationError(simulateResponse)) {
      throw new Error(`Simulation error: ${simulateResponse.error}`);
    }

    const assembleResponse =
      SorobanRpc.Api.isSimulationRestore(simulateResponse)
        ? await this.server.prepareTransaction(transaction)
        : SorobanRpc.assembleTransaction(transaction, simulateResponse);

    return assembleResponse;
  }

  private proofToScVal(proof: ShieldedTransferProof): xdr.ScVal {
    const obj: Record<string, unknown> = {
      proof_a: proof.proofA,
      proof_b: proof.proofB,
      proof_c: proof.proofC,
      root: proof.root,
      nullifier: proof.nullifier,
      recipient: proof.recipient,
    };
    return nativeToScVal(obj, { type: 'map' }) as xdr.ScVal;
  }
}
