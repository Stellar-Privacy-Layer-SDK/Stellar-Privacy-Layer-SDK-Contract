import { beforeEach, describe, expect, it, vi } from 'vitest';

let mockClientInstance: {
  deposit: ReturnType<typeof vi.fn>;
  withdraw: ReturnType<typeof vi.fn>;
  registerViewingKey: ReturnType<typeof vi.fn>;
  authorizeViewer: ReturnType<typeof vi.fn>;
  getPoolStats: ReturnType<typeof vi.fn>;
} | null = null;

const mockClientDeposit = vi.fn(async () => 'xdr:deposit');

const mockGenerateDepositProof = vi.fn(async () => ({
  commitment: 'aa'.repeat(32),
  nullifier: 'bb'.repeat(32),
}));
const mockGenerateWithdrawalProof = vi.fn(async () => ({
  proofA: ['aa'.repeat(32), 'bb'.repeat(32)],
  proofB: [
    ['cc'.repeat(32), 'dd'.repeat(32)],
    ['ee'.repeat(32), 'ff'.repeat(32)],
  ],
  proofC: ['11'.repeat(32), '22'.repeat(32)],
  root: 'ab'.repeat(32),
  nullifier: 'cd'.repeat(32),
  recipient: 'G'.padEnd(56, 'F'),
  amount: '1000',
}));

vi.mock('../client.js', () => ({
  ShieldedPoolClient: class MockPoolClient {
    constructor() {
      mockClientInstance = this;
    }
    deposit = mockClientDeposit;
    withdraw = vi.fn(async () => 'xdr:withdraw');
    registerViewingKey = vi.fn(async () => undefined);
    authorizeViewer = vi.fn(async () => undefined);
    getPoolStats = vi.fn(async () => ({
      root: 'ab'.repeat(32),
      size: 3,
      isPaused: false,
      version: 1,
    }));
  },
}));

vi.mock('../prover.js', () => ({
  ProverClient: class MockProver {
    generateDepositProof = mockGenerateDepositProof;
    generateWithdrawalProof = mockGenerateWithdrawalProof;
  },
}));

import { PrivacyAccount } from '../account.js';
import { ErrorCode } from '../errors.js';
import { KeyManager } from '../keys.js';
import type { KeyPair } from '../types.js';

const CONFIG = {
  contractId: 'C'.padEnd(56, 'A'),
  networkPassphrase: 'Test SDF Network ; quorum-test',
  rpcUrl: 'https://rpc.testnet.stellar.org',
  sourceAccount: 'G'.padEnd(56, 'B'),
};

describe('PrivacyAccount', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockClientInstance = null;
  });

  it('generates a key pair when none is provided', () => {
    const account = new PrivacyAccount(CONFIG);
    expect(account.address).toMatch(/^[0-9a-f]{64}$/);
    expect(account.keyPair).toBeDefined();
  });

  it('uses a provided key pair', () => {
    const kp: KeyPair = {
      secretKey: new Uint8Array(32),
      publicKey: 'AB'.repeat(32),
      viewingKey: new Uint8Array(32),
    };
    const account = new PrivacyAccount(CONFIG, kp);
    expect(account.address).toBe('AB'.repeat(32));
  });

  it('exposes the public address', () => {
    const kp = KeyManager.generateKeyPair();
    const account = new PrivacyAccount(CONFIG, kp);
    expect(account.address).toBe(kp.publicKey);
  });

  it('reports a private balance of zero', async () => {
    const account = new PrivacyAccount(CONFIG);
    expect(await account.getBalance()).toBe(0n);
  });

  it('deposits with a generated secret', async () => {
    const account = new PrivacyAccount(CONFIG);
    const xdr = await account.deposit({
      amount: 1000n,
      recipient: account.address,
      token: 'C'.padEnd(56, 'T'),
    });
    expect(xdr).toBe('xdr:deposit');
    expect(mockGenerateDepositProof).toHaveBeenCalledTimes(1);
    expect(mockClientInstance?.deposit).toHaveBeenCalledTimes(1);
  });

  it('deposits with an explicit secret', async () => {
    const account = new PrivacyAccount(CONFIG);
    const secret = KeyManager.generateSecret();
    await account.deposit({
      amount: 1000n,
      recipient: account.address,
      token: 'C'.padEnd(56, 'T'),
      secret,
    });
    expect(mockGenerateDepositProof).toHaveBeenCalledWith(secret, account.address, 1000n);
  });

  it('withdraws using a generated proof', async () => {
    const account = new PrivacyAccount(CONFIG);
    const xdr = await account.withdraw(
      { amount: 500n, recipient: account.address, token: 'C'.padEnd(56, 'T') },
      7,
    );
    expect(xdr).toBe('xdr:withdraw');
    expect(mockGenerateWithdrawalProof).toHaveBeenCalledTimes(1);
    expect(mockClientInstance?.withdraw).toHaveBeenCalledTimes(1);
  });

  it('registers a viewing key hash on-chain', async () => {
    const account = new PrivacyAccount(CONFIG);
    await account.registerViewingKey();
    expect(mockClientInstance?.registerViewingKey).toHaveBeenCalledWith(
      account.address,
      KeyManager.computeViewingKeyHash(account.keyPair.viewingKey),
    );
  });

  it('authorizes a viewer on-chain', async () => {
    const account = new PrivacyAccount(CONFIG);
    const viewer = 'G'.padEnd(56, 'V');
    await account.authorizeViewer(viewer);
    expect(mockClientInstance?.authorizeViewer).toHaveBeenCalledWith(account.address, viewer);
  });

  it('reads pool statistics', async () => {
    const account = new PrivacyAccount(CONFIG);
    const stats = await account.getPoolStats();
    expect(stats).toEqual({ root: 'ab'.repeat(32), size: 3, isPaused: false, version: 1 });
  });

  it('surfaces typed deposit failures', async () => {
    mockClientDeposit.mockRejectedValueOnce(
      Object.assign(new Error('x'), { code: ErrorCode.CONNECTION_FAILED }),
    );
    const account = new PrivacyAccount(CONFIG);
    await expect(
      account.deposit({ amount: 1000n, recipient: account.address, token: 'C'.padEnd(56, 'T') }),
    ).rejects.toThrow();
  });
});
