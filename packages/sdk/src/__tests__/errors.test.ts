import { describe, expect, it } from 'vitest';
import { ErrorCode, PrivacySDKError } from '../errors.js';

describe('ErrorCode', () => {
  it('exposes stable string codes', () => {
    expect(ErrorCode.CONNECTION_FAILED).toBe('CONNECTION_FAILED');
    expect(ErrorCode.PROOF_GENERATION_FAILED).toBe('PROOF_GENERATION_FAILED');
    expect(ErrorCode.PROOF_VERIFICATION_FAILED).toBe('PROOF_VERIFICATION_FAILED');
    expect(ErrorCode.INVALID_COMMITMENT).toBe('INVALID_COMMITMENT');
    expect(ErrorCode.NULLIFIER_SPENT).toBe('NULLIFIER_SPENT');
    expect(ErrorCode.UNAUTHORIZED).toBe('UNAUTHORIZED');
    expect(ErrorCode.CONTRACT_PAUSED).toBe('CONTRACT_PAUSED');
    expect(ErrorCode.POOL_FULL).toBe('POOL_FULL');
    expect(ErrorCode.INVALID_AMOUNT).toBe('INVALID_AMOUNT');
    expect(ErrorCode.COMPLIANCE_ERROR).toBe('COMPLIANCE_ERROR');
    expect(ErrorCode.KEY_GENERATION_FAILED).toBe('KEY_GENERATION_FAILED');
    expect(ErrorCode.INVALID_CONFIG).toBe('INVALID_CONFIG');
    expect(ErrorCode.TX_NEEDS_SIGNING).toBe('TX_NEEDS_SIGNING');
  });
});

describe('PrivacySDKError', () => {
  it('formats a message with the code and cause', () => {
    const cause = new Error('root cause');
    const err = new PrivacySDKError(ErrorCode.INVALID_CONFIG, 'Bad config', cause);
    expect(err).toBeInstanceOf(Error);
    expect(err.name).toBe('PrivacySDKError');
    expect(err.code).toBe(ErrorCode.INVALID_CONFIG);
    expect(err.details).toBe(cause);
    expect(err.message).toContain('[INVALID_CONFIG] Bad config');
    expect(err.message).toContain('root cause');
    expect(err.stack).toContain('Caused by:');
  });

  it('omits the cause when no details are provided', () => {
    const err = new PrivacySDKError(ErrorCode.INVALID_AMOUNT, 'Amount must be positive');
    expect(err.message).toBe('[INVALID_AMOUNT] Amount must be positive');
    expect(err.details).toBeUndefined();
  });

  it('stringifies non-Error details', () => {
    const err = new PrivacySDKError(ErrorCode.COMPLIANCE_ERROR, 'Failed', { reason: 42 });
    expect(err.message).toBe('[COMPLIANCE_ERROR] Failed');
    expect(err.details).toEqual({ reason: 42 });
  });

  it('supports code checks via is()', () => {
    const err = new PrivacySDKError(ErrorCode.NULLIFIER_SPENT, 'spent');
    expect(err.is(ErrorCode.NULLIFIER_SPENT)).toBe(true);
    expect(err.is(ErrorCode.UNAUTHORIZED)).toBe(false);
  });
});
