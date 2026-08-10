/**
 * Input validation helpers. All functions throw {@link PrivacySDKError} with a
 * stable {@link ErrorCode} so callers can react programmatically.
 */
import { ErrorCode, PrivacySDKError } from './errors.js';
import type { PoolConfig } from './types.js';

const HEX_RE = /^[0-9a-fA-F]*$/;
const STELLAR_ADDRESS_RE = /^[GCA][0-9A-Z]{55}$/;

/** True when `value` is a non-empty lowercase/uppercase hex string. */
export function isHex(value: unknown, length?: number): value is string {
  if (typeof value !== 'string' || value.length === 0 || !HEX_RE.test(value)) {
    return false;
  }
  return length === undefined || value.length === length * 2;
}

/** True when `value` looks like a Stellar account (G...) or contract (C...) address. */
export function isStellarAddress(value: unknown): value is string {
  return typeof value === 'string' && STELLAR_ADDRESS_RE.test(value);
}

/** True when `value` is a positive amount (bigint or numeric string). */
export function isPositiveAmount(value: unknown): value is bigint {
  if (typeof value === 'bigint') return value > 0n;
  if (typeof value === 'number') return Number.isFinite(value) && value > 0;
  if (typeof value === 'string') {
    try {
      return BigInt(value) > 0n;
    } catch {
      return false;
    }
  }
  return false;
}

function requireUrl(name: string, value: string): void {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new PrivacySDKError(ErrorCode.INVALID_CONFIG, `${name} must be a valid URL`);
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    throw new PrivacySDKError(ErrorCode.INVALID_CONFIG, `${name} must use http(s)`);
  }
}

/**
 * Validate a {@link PoolConfig}. Throws {@link PrivacySDKError} with
 * `ErrorCode.INVALID_CONFIG` on the first problem found.
 */
export function validatePoolConfig(config: PoolConfig): void {
  if (!config || typeof config !== 'object') {
    throw new PrivacySDKError(ErrorCode.INVALID_CONFIG, 'PoolConfig is required');
  }
  if (!isStellarAddress(config.contractId) || !config.contractId.startsWith('C')) {
    throw new PrivacySDKError(
      ErrorCode.INVALID_CONFIG,
      'contractId must be a Stellar contract address (C...)',
    );
  }
  if (typeof config.networkPassphrase !== 'string' || config.networkPassphrase.length === 0) {
    throw new PrivacySDKError(ErrorCode.INVALID_CONFIG, 'networkPassphrase is required');
  }
  requireUrl('rpcUrl', config.rpcUrl);
  if (config.horizonUrl) {
    requireUrl('horizonUrl', config.horizonUrl);
  }
  if (config.sourceAccount !== undefined && !isStellarAddress(config.sourceAccount)) {
    throw new PrivacySDKError(
      ErrorCode.INVALID_CONFIG,
      'sourceAccount must be a Stellar account address (G...)',
    );
  }
  if (config.fee !== undefined && (!/^\d+$/.test(config.fee) || BigInt(config.fee) < 0n)) {
    throw new PrivacySDKError(
      ErrorCode.INVALID_CONFIG,
      'fee must be a non-negative integer string',
    );
  }
}

/** Validate a hex-encoded scalar (32 bytes = 64 hex chars). */
export function assertScalarHex(value: unknown, name: string): asserts value is string {
  if (!isHex(value, 32)) {
    throw new PrivacySDKError(ErrorCode.INVALID_COMMITMENT, `${name} must be a 32-byte hex string`);
  }
}
