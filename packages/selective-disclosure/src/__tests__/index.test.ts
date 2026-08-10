import { ErrorCode } from '@stellar-privacy/sdk';
import { describe, expect, it } from 'vitest';
import {
  type DisclosureRequest,
  generateAuditRecord,
  SelectiveDisclosureModule,
} from '../index.js';

function makeConfig(
  overrides: Partial<
    Record<'regulatorPublicKey' | 'jurisdiction' | 'complianceLevel', unknown>
  > = {},
) {
  return {
    regulatorPublicKey: 'regulator-public-key-123',
    jurisdiction: 'US',
    complianceLevel: 'full' as const,
    ...overrides,
  };
}

describe('SelectiveDisclosureModule', () => {
  it('rejects an invalid config', () => {
    expect(
      () => new SelectiveDisclosureModule(makeConfig({ regulatorPublicKey: '' })),
    ).toThrowError(ErrorCode.INVALID_CONFIG);
    expect(() => new SelectiveDisclosureModule(makeConfig({ jurisdiction: '' }))).toThrowError(
      ErrorCode.INVALID_CONFIG,
    );
    expect(
      () => new SelectiveDisclosureModule(makeConfig({ complianceLevel: 'nope' })),
    ).toThrowError(ErrorCode.INVALID_CONFIG);
    expect(() => new SelectiveDisclosureModule(undefined as never)).toThrowError(
      ErrorCode.INVALID_CONFIG,
    );
  });

  it('exposes the regulator public key', () => {
    const module = new SelectiveDisclosureModule(makeConfig());
    expect(module.getRegulatorPublicKey()).toBe('regulator-public-key-123');
  });

  it('creates disclosure requests with sane defaults', () => {
    const module = new SelectiveDisclosureModule(makeConfig());
    const request = module.createDisclosureRequest('regulator-address', ['amount', 'sender']);
    expect(request.requestId).toBeTruthy();
    expect(request.regulator).toBe('regulator-address');
    expect(request.scope).toEqual(['amount', 'sender']);
    expect(request.expiresAt).toBeGreaterThan(request.timestamp);
    expect(request.expiresAt - request.timestamp).toBe(3600000);
  });

  it('copies the scope array', () => {
    const module = new SelectiveDisclosureModule(makeConfig());
    const scope = ['amount'];
    const request = module.createDisclosureRequest('r', scope);
    scope.push('sender');
    expect(request.scope).toEqual(['amount']);
  });

  it('rejects invalid request inputs', () => {
    const module = new SelectiveDisclosureModule(makeConfig());
    expect(() => module.createDisclosureRequest('', ['amount'])).toThrowError(
      ErrorCode.INVALID_CONFIG,
    );
    expect(() => module.createDisclosureRequest('r', [])).toThrowError(ErrorCode.INVALID_CONFIG);
    expect(() => module.createDisclosureRequest('r', 'amount' as never)).toThrowError(
      ErrorCode.INVALID_CONFIG,
    );
    expect(() => module.createDisclosureRequest('r', ['amount'], 0)).toThrowError(
      ErrorCode.INVALID_CONFIG,
    );
    expect(() => module.createDisclosureRequest('r', ['amount'], -1)).toThrowError(
      ErrorCode.INVALID_CONFIG,
    );
  });

  it('fulfills and verifies disclosure requests', async () => {
    const module = new SelectiveDisclosureModule(makeConfig());
    const viewingKey = new Uint8Array([1, 2, 3, 4, 5]);

    const request = module.createDisclosureRequest('regulator-address', ['amount', 'sender']);
    const response = await module.fulfillDisclosureRequest(
      request,
      { sender: 'GA...', recipient: 'GB...', amount: '1000', timestamp: Date.now() },
      viewingKey,
    );

    expect(response.requestId).toBe(request.requestId);
    expect(response.encryptedData).toBeTruthy();
    expect(response.viewingKeyProof).toBeTruthy();

    expect(module.verifyDisclosureResponse(response, viewingKey)).toBe(true);
    expect(module.verifyDisclosureResponse(response, new Uint8Array([9, 9, 9]))).toBe(false);
    expect(module.verifyDisclosureResponse(null as never, viewingKey)).toBe(false);
  });

  it('only includes fields in scope', async () => {
    const module = new SelectiveDisclosureModule(makeConfig());
    const viewingKey = new Uint8Array(32);
    // Decryption key must match the encryption key derived from the
    // regulator public key configured on the module.
    const regulatorKey = new TextEncoder().encode('regulator-public-key-123');
    const request = module.createDisclosureRequest('r', ['amount']);
    const response = await module.fulfillDisclosureRequest(
      request,
      { sender: 'GA', recipient: 'GB', amount: '1000' },
      viewingKey,
    );
    const decrypted = module.decryptDisclosureData(response, regulatorKey);
    expect(decrypted).toEqual({ amount: '1000' });
  });

  it('rejects expired requests', async () => {
    const module = new SelectiveDisclosureModule(makeConfig());
    // Hand-built request that has already expired (createDisclosureRequest
    // correctly refuses non-positive TTLs).
    const expired: DisclosureRequest = {
      requestId: 'expired-1',
      regulator: 'regulator-address',
      scope: ['amount'],
      timestamp: Date.now() - 10_000,
      expiresAt: Date.now() - 1,
    };
    await expect(
      module.fulfillDisclosureRequest(expired, { amount: '1000' }, new Uint8Array(32)),
    ).rejects.toThrowError(ErrorCode.COMPLIANCE_ERROR);
  });

  it('rejects malformed requests in fulfillment', async () => {
    const module = new SelectiveDisclosureModule(makeConfig());
    await expect(
      module.fulfillDisclosureRequest(null as never, { amount: '1000' }, new Uint8Array(32)),
    ).rejects.toThrowError(ErrorCode.INVALID_CONFIG);
    await expect(
      module.fulfillDisclosureRequest(
        { requestId: 'x', scope: [], expiresAt: Date.now() + 1000 } as never,
        { amount: '1000' },
        new Uint8Array(32),
      ),
    ).rejects.toThrowError(ErrorCode.INVALID_CONFIG);
  });

  it('decrypts with the matching regulator key', async () => {
    const module = new SelectiveDisclosureModule(makeConfig());
    const viewingKey = new Uint8Array(32);
    const regulatorKey = new TextEncoder().encode('regulator-public-key-123');
    const request = module.createDisclosureRequest('r', ['sender']);
    const response = await module.fulfillDisclosureRequest(
      request,
      { sender: 'GA', amount: '100' },
      viewingKey,
    );
    expect(module.decryptDisclosureData(response, regulatorKey)).toEqual({ sender: 'GA' });
  });

  it('fails to decrypt with the wrong regulator key', async () => {
    const module = new SelectiveDisclosureModule(makeConfig());
    const request = module.createDisclosureRequest('r', ['sender']);
    const response = await module.fulfillDisclosureRequest(
      request,
      { sender: 'GA' },
      new Uint8Array(32),
    );
    expect(() => module.decryptDisclosureData(response, new Uint8Array(32).fill(1))).toThrowError(
      ErrorCode.COMPLIANCE_ERROR,
    );
  });

  it('rejects malformed disclosure responses', async () => {
    const module = new SelectiveDisclosureModule(makeConfig());
    expect(() => module.decryptDisclosureData(null as never, new Uint8Array(32))).toThrowError(
      ErrorCode.INVALID_CONFIG,
    );
    expect(() =>
      module.decryptDisclosureData(
        { requestId: 'x', encryptedData: '%%%not-base64%%%', viewingKeyProof: 'p', timestamp: 1 },
        new Uint8Array(32),
      ),
    ).toThrowError(ErrorCode.COMPLIANCE_ERROR);
    expect(() =>
      module.decryptDisclosureData(
        { requestId: 'x', encryptedData: 'YWJj', viewingKeyProof: 'p', timestamp: 1 },
        new Uint8Array(32),
      ),
    ).toThrowError(ErrorCode.COMPLIANCE_ERROR);
  });
});

describe('generateAuditRecord', () => {
  it('generates valid audit records', () => {
    const record = generateAuditRecord('GA...', 1000n, 'USDC');
    expect(record.id).toBeTruthy();
    expect(record.user).toBe('GA...');
    expect(record.amount).toBe(1000n);
    expect(record.token).toBe('USDC');
    expect(record.disclosedTo).toEqual([]);
  });

  it('includes disclosed regulators and copies the array', () => {
    const disclosed = ['regulator-1'];
    const record = generateAuditRecord('GA...', 500n, 'USDC', disclosed);
    disclosed.push('regulator-2');
    expect(record.disclosedTo).toEqual(['regulator-1']);
  });

  it('validates inputs', () => {
    expect(() => generateAuditRecord('', 1n, 'USDC')).toThrowError(ErrorCode.INVALID_CONFIG);
    expect(() => generateAuditRecord('GA', 0n, 'USDC')).toThrowError(ErrorCode.INVALID_AMOUNT);
    expect(() => generateAuditRecord('GA', -1n, 'USDC')).toThrowError(ErrorCode.INVALID_AMOUNT);
    expect(() => generateAuditRecord('GA', 1n, '')).toThrowError(ErrorCode.INVALID_CONFIG);
  });
});
