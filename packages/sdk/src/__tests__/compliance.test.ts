import { beforeEach, describe, expect, it, vi } from 'vitest';

const mockRegisterViewingKey = vi.fn(async () => undefined);
const mockAuthorizeViewer = vi.fn(async () => undefined);
const mockGetCompliance = vi.fn(async () => ({
  owner: 'GA',
  viewing_key_hash: 'ab'.repeat(32),
  authorized_viewers: ['G1', 'G2'],
}));

vi.mock('../client.js', () => ({
  ShieldedPoolClient: class MockPoolClient {
    registerViewingKey = mockRegisterViewingKey;
    authorizeViewer = mockAuthorizeViewer;
    getCompliance = mockGetCompliance;
  },
}));

import { ComplianceModule } from '../compliance.js';
import { ErrorCode } from '../errors.js';
import { KeyManager } from '../keys.js';

const CONFIG = {
  contractId: 'C'.padEnd(56, 'A'),
  networkPassphrase: 'Test SDF Network ; quorum-test',
  rpcUrl: 'https://rpc.testnet.stellar.org',
  sourceAccount: 'G'.padEnd(56, 'B'),
};

describe('ComplianceModule', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('generates a viewing key when none is provided', () => {
    const module = new ComplianceModule(CONFIG);
    expect(module.getViewingKeyHash()).toMatch(/^[0-9a-f]{64}$/);
  });

  it('uses a provided viewing key', () => {
    const viewingKey = KeyManager.generateViewingKey();
    const module = new ComplianceModule(CONFIG, viewingKey);
    expect(module.getViewingKeyHash()).toBe(KeyManager.computeViewingKeyHash(viewingKey));
  });

  it('registers the viewing key hash on-chain', async () => {
    const module = new ComplianceModule(CONFIG);
    const owner = 'G'.padEnd(56, 'O');
    await module.registerViewingKey(owner);
    expect(mockRegisterViewingKey).toHaveBeenCalledWith(owner, module.getViewingKeyHash());
  });

  it('authorizes a viewer on-chain', async () => {
    const module = new ComplianceModule(CONFIG);
    const viewer = 'G'.padEnd(56, 'V');
    await module.authorizeViewer('G'.padEnd(56, 'O'), viewer);
    expect(mockAuthorizeViewer).toHaveBeenCalledWith('G'.padEnd(56, 'O'), viewer);
  });

  it('encrypts and decrypts transaction data for the holding key', () => {
    const viewingKey = KeyManager.generateViewingKey();
    const module = new ComplianceModule(CONFIG, viewingKey);
    const data = { sender: 'GA', amount: '1000', ts: 1 };
    // The module decrypts with its own viewing key, so encryption must target
    // the same key material for a round-trip.
    const encrypted = module.encryptTransactionData(data, viewingKey);
    expect(module.decryptTransactionData(encrypted)).toEqual(data);
  });

  it('fails to decrypt data encrypted for another key', () => {
    const module = new ComplianceModule(CONFIG);
    const other = new ComplianceModule(CONFIG);
    const encrypted = module.encryptTransactionData({ a: 1 }, KeyManager.generateViewingKey());
    expect(() => other.decryptTransactionData(encrypted)).toThrowError(ErrorCode.COMPLIANCE_ERROR);
  });

  it('generates a selective disclosure proof', async () => {
    const viewingKey = KeyManager.generateViewingKey();
    const module = new ComplianceModule(CONFIG, viewingKey);
    const disclosure = await module.generateSelectiveDisclosureProof(
      { sender: 'GA', recipient: 'GB', amount: 100n, timestamp: 123 },
      viewingKey,
    );
    expect(disclosure.viewingKeyHash).toBe(module.getViewingKeyHash());
    expect(disclosure.encryptedData.length).toBeGreaterThan(0);
  });

  it('verifies a selective disclosure payload by decrypting it', async () => {
    const viewingKey = KeyManager.generateViewingKey();
    const module = new ComplianceModule(CONFIG, viewingKey);
    const data = { sender: 'GA', recipient: 'GB', amount: 100n, timestamp: 123 };
    const disclosure = await module.generateSelectiveDisclosureProof(data, viewingKey);
    const verified = await module.verifySelectiveDisclosure(disclosure.encryptedData);
    // bigint amounts are serialized as decimal strings (JSON has no BigInt).
    expect(verified).toEqual({ ...data, amount: '100' });
  });

  describe('getComplianceView (static)', () => {
    it('normalizes the on-chain compliance record', async () => {
      const view = await ComplianceModule.getComplianceView(CONFIG, 'G'.padEnd(56, 'O'));
      expect(view).toEqual({
        owner: 'GA',
        viewingKeyHash: 'ab'.repeat(32),
        authorizedViewers: ['G1', 'G2'],
      });
    });

    it('returns null when no record exists', async () => {
      mockGetCompliance.mockResolvedValueOnce(undefined);
      const view = await ComplianceModule.getComplianceView(CONFIG, 'G'.padEnd(56, 'O'));
      expect(view).toBeNull();
    });

    it('returns null when the read fails', async () => {
      mockGetCompliance.mockRejectedValueOnce(new Error('rpc down'));
      const view = await ComplianceModule.getComplianceView(CONFIG, 'G'.padEnd(56, 'O'));
      expect(view).toBeNull();
    });
  });
});
