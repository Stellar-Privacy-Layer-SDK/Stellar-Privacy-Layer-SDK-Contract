import { describe, it, expect } from 'vitest';
import { SelectiveDisclosureModule, generateAuditRecord } from '../index';

describe('SelectiveDisclosureModule', () => {
  const config = {
    regulatorPublicKey: 'regulator-public-key-123',
    jurisdiction: 'US',
    complianceLevel: 'full' as const,
  };

  it('creates disclosure request', () => {
    const module = new SelectiveDisclosureModule(config);
    const request = module.createDisclosureRequest(
      'regulator-address',
      ['amount', 'sender', 'recipient'],
    );

    expect(request.requestId).toBeTruthy();
    expect(request.regulator).toBe('regulator-address');
    expect(request.scope).toEqual(['amount', 'sender', 'recipient']);
    expect(request.expiresAt).toBeGreaterThan(request.timestamp);
  });

  it('fulfills and verifies disclosure request', async () => {
    const module = new SelectiveDisclosureModule(config);
    const viewingKey = new Uint8Array([1, 2, 3, 4, 5]);

    const request = module.createDisclosureRequest(
      'regulator-address',
      ['amount', 'sender'],
    );

    const response = await module.fulfillDisclosureRequest(
      request,
      {
        sender: 'GA...',
        recipient: 'GB...',
        amount: '1000',
        timestamp: Date.now(),
      },
      viewingKey,
    );

    expect(response.requestId).toBe(request.requestId);
    expect(response.encryptedData).toBeTruthy();
    expect(response.viewingKeyProof).toBeTruthy();

    const isVerified = module.verifyDisclosureResponse(response, viewingKey);
    expect(isVerified).toBe(true);

    const wrongKey = new Uint8Array([9, 9, 9]);
    const isNotVerified = module.verifyDisclosureResponse(response, wrongKey);
    expect(isNotVerified).toBe(false);
  });

  it('rejects expired requests', async () => {
    const module = new SelectiveDisclosureModule(config);

    const request = module.createDisclosureRequest(
      'regulator-address',
      ['amount'],
      -1,
    );

    await expect(
      module.fulfillDisclosureRequest(
        request,
        { amount: '1000' },
        new Uint8Array(32),
      ),
    ).rejects.toThrow('expired');
  });
});

describe('generateAuditRecord', () => {
  it('generates valid audit record', () => {
    const record = generateAuditRecord('GA...', 1000n, 'USDC');
    expect(record.id).toBeTruthy();
    expect(record.user).toBe('GA...');
    expect(record.amount).toBe(1000n);
    expect(record.token).toBe('USDC');
    expect(record.disclosedTo).toEqual([]);
  });

  it('includes disclosed regulators', () => {
    const record = generateAuditRecord('GA...', 500n, 'USDC', [
      'regulator-1',
    ]);
    expect(record.disclosedTo).toContain('regulator-1');
  });
});
