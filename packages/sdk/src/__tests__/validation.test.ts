import { describe, expect, it } from 'vitest';
import { ErrorCode } from '../errors.js';
import {
  assertScalarHex,
  isHex,
  isPositiveAmount,
  isStellarAddress,
  validatePoolConfig,
} from '../validation.js';

const CONTRACT_ID = 'C'.padEnd(56, 'A');
const SOURCE = 'G'.padEnd(56, 'B');

describe('isHex', () => {
  it('accepts lowercase/uppercase hex strings', () => {
    expect(isHex('deadbeef')).toBe(true);
    expect(isHex('DEADBEEF')).toBe(true);
    expect(isHex('0123456789abcdefABCDEF')).toBe(true);
  });

  it('rejects non-hex, empty, and non-string values', () => {
    expect(isHex('')).toBe(false);
    expect(isHex('zz')).toBe(false);
    expect(isHex(123)).toBe(false);
    expect(isHex(null)).toBe(false);
    expect(isHex(undefined)).toBe(false);
  });

  it('enforces an optional byte length', () => {
    expect(isHex('aabb', 2)).toBe(true);
    expect(isHex('aabb', 3)).toBe(false);
  });
});

describe('isStellarAddress', () => {
  it('accepts G and C addresses of the correct length', () => {
    expect(isStellarAddress('G'.padEnd(56, 'A'))).toBe(true);
    expect(isStellarAddress('C'.padEnd(56, 'A'))).toBe(true);
  });

  it('rejects malformed addresses', () => {
    expect(isStellarAddress('G'.padEnd(55, 'A'))).toBe(false);
    expect(isStellarAddress('G'.padEnd(57, 'A'))).toBe(false);
    expect(isStellarAddress('X'.padEnd(56, 'A'))).toBe(false);
    expect(isStellarAddress('g'.padEnd(56, 'a'))).toBe(false);
    expect(isStellarAddress('not-an-address')).toBe(false);
    expect(isStellarAddress(42)).toBe(false);
  });
});

describe('isPositiveAmount', () => {
  it('accepts positive bigints, numbers, and numeric strings', () => {
    expect(isPositiveAmount(5n)).toBe(true);
    expect(isPositiveAmount(5)).toBe(true);
    expect(isPositiveAmount('1000')).toBe(true);
  });

  it('rejects zero, negatives, and garbage', () => {
    expect(isPositiveAmount(0n)).toBe(false);
    expect(isPositiveAmount(-1n)).toBe(false);
    expect(isPositiveAmount(0)).toBe(false);
    expect(isPositiveAmount(-5)).toBe(false);
    expect(isPositiveAmount('0')).toBe(false);
    expect(isPositiveAmount('-5')).toBe(false);
    expect(isPositiveAmount('abc')).toBe(false);
    expect(isPositiveAmount(NaN)).toBe(false);
    expect(isPositiveAmount(Infinity)).toBe(false);
    expect(isPositiveAmount({})).toBe(false);
    expect(isPositiveAmount(null)).toBe(false);
  });
});

describe('validatePoolConfig', () => {
  const valid = {
    contractId: CONTRACT_ID,
    networkPassphrase: 'Test SDF Network ; quorum-test',
    rpcUrl: 'https://rpc.testnet.stellar.org',
  };

  it('accepts a valid config', () => {
    expect(() => validatePoolConfig(valid)).not.toThrow();
  });

  it('rejects a missing or non-object config', () => {
    expect(() => validatePoolConfig(undefined as never)).toThrowError(ErrorCode.INVALID_CONFIG);
    expect(() => validatePoolConfig(null as never)).toThrowError(ErrorCode.INVALID_CONFIG);
    expect(() => validatePoolConfig('x' as never)).toThrowError(ErrorCode.INVALID_CONFIG);
  });

  it('rejects a non-contract contractId', () => {
    expect(() => validatePoolConfig({ ...valid, contractId: 'G'.padEnd(56, 'A') })).toThrowError(
      ErrorCode.INVALID_CONFIG,
    );
    expect(() => validatePoolConfig({ ...valid, contractId: 'short' })).toThrowError(
      ErrorCode.INVALID_CONFIG,
    );
  });

  it('rejects an empty network passphrase', () => {
    expect(() => validatePoolConfig({ ...valid, networkPassphrase: '' })).toThrowError(
      ErrorCode.INVALID_CONFIG,
    );
  });

  it('rejects invalid RPC and horizon URLs', () => {
    expect(() => validatePoolConfig({ ...valid, rpcUrl: 'not-a-url' })).toThrowError(
      ErrorCode.INVALID_CONFIG,
    );
    expect(() => validatePoolConfig({ ...valid, rpcUrl: 'ftp://example.com' })).toThrowError(
      ErrorCode.INVALID_CONFIG,
    );
    expect(() => validatePoolConfig({ ...valid, horizonUrl: 'nope' })).toThrowError(
      ErrorCode.INVALID_CONFIG,
    );
  });

  it('validates the optional sourceAccount', () => {
    expect(() => validatePoolConfig({ ...valid, sourceAccount: SOURCE })).not.toThrow();
    expect(() => validatePoolConfig({ ...valid, sourceAccount: 'bogus' })).toThrowError(
      ErrorCode.INVALID_CONFIG,
    );
  });

  it('validates the optional fee', () => {
    expect(() => validatePoolConfig({ ...valid, fee: '10000' })).not.toThrow();
    expect(() => validatePoolConfig({ ...valid, fee: 'abc' })).toThrowError(
      ErrorCode.INVALID_CONFIG,
    );
    expect(() => validatePoolConfig({ ...valid, fee: '-1' })).toThrowError(
      ErrorCode.INVALID_CONFIG,
    );
  });
});

describe('assertScalarHex', () => {
  it('accepts a 32-byte hex scalar', () => {
    expect(() => assertScalarHex('ab'.repeat(32), 'scalar')).not.toThrow();
  });

  it('rejects scalars of the wrong size or format', () => {
    expect(() => assertScalarHex('ab'.repeat(16), 'scalar')).toThrowError(
      ErrorCode.INVALID_COMMITMENT,
    );
    expect(() => assertScalarHex('zz', 'scalar')).toThrowError(ErrorCode.INVALID_COMMITMENT);
    expect(() => assertScalarHex(undefined, 'scalar')).toThrowError(ErrorCode.INVALID_COMMITMENT);
  });
});
