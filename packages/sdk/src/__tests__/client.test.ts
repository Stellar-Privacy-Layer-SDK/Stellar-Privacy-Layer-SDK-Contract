import { beforeEach, describe, expect, it, vi } from 'vitest';

const RETVALS: Record<string, unknown> = {
  get_root: 'ab'.repeat(32),
  is_nullifier_spent: true,
  get_pool_size: 42,
  get_compliance: {
    owner: 'GA',
    viewing_key_hash: 'ab'.repeat(32),
    authorized_viewers: ['G1', 'G2'],
  },
};

// Shared mock of AssembledTransaction.build; tests can override per-call with
// mockRejectedValueOnce to exercise the client's error handling.
const mockBuild = vi.fn(
  async (options: { method: string; parseResultXdr?: (retval: unknown) => unknown }) => {
    const retval = RETVALS[options.method];
    return {
      result: options.parseResultXdr ? options.parseResultXdr(retval) : undefined,
      toXDR: () => `xdr:${options.method}`,
    };
  },
);
const mockServerCtor = vi.fn();

vi.mock('@stellar/stellar-sdk', () => {
  class MockAddress {
    constructor(private readonly value: string) {}
    toScVal(): { type: string; value: string } {
      return { type: 'address', value: this.value };
    }
  }
  return {
    Address: MockAddress,
    nativeToScVal: (value: unknown) => ({ type: 'native', value: String(value) }),
    scValToNative: (value: unknown) => value,
    xdr: {
      ScVal: {
        scvBytes: (bytes: Uint8Array) => ({
          type: 'bytes',
          hex: Array.from(bytes)
            .map((b) => b.toString(16).padStart(2, '0'))
            .join(''),
        }),
        scvVec: (items: unknown[]) => ({ type: 'vec', items }),
      },
    },
    rpc: {
      Server: class MockServer {
        constructor(url: string, opts: unknown) {
          mockServerCtor(url, opts);
        }
      },
    },
  };
});

vi.mock('@stellar/stellar-sdk/contract', () => ({
  AssembledTransaction: {
    build: (options: unknown) => mockBuild(options),
  },
}));

import { ShieldedPoolClient } from '../client.js';
import { ErrorCode } from '../errors.js';
import type { ShieldedTransferProof } from '../types.js';

const CONTRACT_ID = 'C'.padEnd(56, 'A');
const SOURCE = 'G'.padEnd(56, 'B');

const VALID_CONFIG = {
  contractId: CONTRACT_ID,
  networkPassphrase: 'Test SDF Network ; quorum-test',
  rpcUrl: 'https://rpc.testnet.stellar.org',
  sourceAccount: SOURCE,
};

function validProof(): ShieldedTransferProof {
  return {
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
  };
}

describe('ShieldedPoolClient', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('validates the config on construction', () => {
    expect(() => new ShieldedPoolClient(VALID_CONFIG)).not.toThrow();
    expect(() => new ShieldedPoolClient({ ...VALID_CONFIG, rpcUrl: 'not-a-url' })).toThrowError(
      ErrorCode.INVALID_CONFIG,
    );
    expect(() => new ShieldedPoolClient({ ...VALID_CONFIG, contractId: 'nope' })).toThrowError(
      ErrorCode.INVALID_CONFIG,
    );
  });

  it('creates the RPC server with allowHttp defaulting to false', () => {
    new ShieldedPoolClient(VALID_CONFIG);
    expect(mockServerCtor).toHaveBeenCalledWith(VALID_CONFIG.rpcUrl, { allowHttp: false });
  });

  it('allows opting into plain-HTTP dev endpoints', () => {
    new ShieldedPoolClient({ ...VALID_CONFIG, allowHttp: true });
    expect(mockServerCtor).toHaveBeenCalledWith(VALID_CONFIG.rpcUrl, { allowHttp: true });
  });

  it('assembles a deposit transaction', async () => {
    const client = new ShieldedPoolClient(VALID_CONFIG);
    const xdr = await client.deposit(SOURCE, CONTRACT_ID, 1000n, 'aa'.repeat(32));
    expect(xdr).toBe('xdr:deposit');
    expect(mockBuild).toHaveBeenCalledWith(expect.objectContaining({ method: 'deposit' }));
  });

  it('rejects a malformed commitment on deposit', async () => {
    const client = new ShieldedPoolClient(VALID_CONFIG);
    await expect(client.deposit(SOURCE, CONTRACT_ID, 1000n, 'zz')).rejects.toMatchObject({
      code: ErrorCode.INVALID_COMMITMENT,
    });
  });

  it('wraps deposit network failures in a typed error', async () => {
    mockBuild.mockRejectedValueOnce(new Error('rpc down'));
    const client = new ShieldedPoolClient(VALID_CONFIG);
    await expect(client.deposit(SOURCE, CONTRACT_ID, 1000n, 'aa'.repeat(32))).rejects.toMatchObject(
      { code: ErrorCode.CONNECTION_FAILED },
    );
  });

  it('assembles a withdrawal transaction', async () => {
    const client = new ShieldedPoolClient(VALID_CONFIG);
    const xdr = await client.withdraw(validProof(), 1000n, CONTRACT_ID);
    expect(xdr).toBe('xdr:withdraw');
    expect(mockBuild).toHaveBeenCalledWith(expect.objectContaining({ method: 'withdraw' }));
  });

  it('rejects malformed proof scalars on withdraw', async () => {
    const client = new ShieldedPoolClient(VALID_CONFIG);
    const proof = validProof();
    proof.root = 'zz';
    await expect(client.withdraw(proof, 1000n, CONTRACT_ID)).rejects.toMatchObject({
      code: ErrorCode.INVALID_COMMITMENT,
    });
  });

  it('assembles a viewing-key registration', async () => {
    const client = new ShieldedPoolClient(VALID_CONFIG);
    const xdr = await client.registerViewingKey(SOURCE, 'ab'.repeat(32));
    expect(xdr).toBe('xdr:register_viewing_key');
  });

  it('rejects a malformed viewing key hash', async () => {
    const client = new ShieldedPoolClient(VALID_CONFIG);
    await expect(client.registerViewingKey(SOURCE, 'zz')).rejects.toMatchObject({
      code: ErrorCode.INVALID_COMMITMENT,
    });
  });

  it('assembles a viewer authorization', async () => {
    const client = new ShieldedPoolClient(VALID_CONFIG);
    const xdr = await client.authorizeViewer(SOURCE, 'G'.padEnd(56, 'E'));
    expect(xdr).toBe('xdr:authorize_viewer');
  });

  it('reads the merkle root', async () => {
    const client = new ShieldedPoolClient(VALID_CONFIG);
    expect(await client.getRoot()).toBe('ab'.repeat(32));
  });

  it('returns null when the root read fails', async () => {
    mockBuild.mockRejectedValueOnce(new Error('boom'));
    const client = new ShieldedPoolClient(VALID_CONFIG);
    expect(await client.getRoot()).toBeNull();
  });

  it('checks whether a nullifier is spent', async () => {
    const client = new ShieldedPoolClient(VALID_CONFIG);
    expect(await client.isNullifierSpent('cd'.repeat(32))).toBe(true);
  });

  it('returns false when the nullifier check fails', async () => {
    mockBuild.mockRejectedValueOnce(new Error('boom'));
    const client = new ShieldedPoolClient(VALID_CONFIG);
    expect(await client.isNullifierSpent('cd'.repeat(32))).toBe(false);
  });

  it('reads the pool size', async () => {
    const client = new ShieldedPoolClient(VALID_CONFIG);
    expect(await client.getPoolSize()).toBe(42);
  });

  it('returns 0 when the pool size read fails', async () => {
    mockBuild.mockRejectedValueOnce(new Error('boom'));
    const client = new ShieldedPoolClient(VALID_CONFIG);
    expect(await client.getPoolSize()).toBe(0);
  });

  it('reads a compliance view', async () => {
    const client = new ShieldedPoolClient(VALID_CONFIG);
    const view = await client.getCompliance(SOURCE);
    expect(view).toEqual(RETVALS.get_compliance);
  });

  it('aggregates pool stats', async () => {
    const client = new ShieldedPoolClient(VALID_CONFIG);
    const stats = await client.getPoolStats();
    expect(stats).toEqual({ root: 'ab'.repeat(32), size: 42, isPaused: false, version: 1 });
  });
});
