import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const mockDeposit = vi.fn(async () => 'TXHASH-DEPOSIT-123');
const mockWithdraw = vi.fn(async () => 'TXHASH-WITHDRAW-123');
const mockRegisterViewingKey = vi.fn(async () => undefined);
const mockAuthorizeViewer = vi.fn(async () => undefined);
const mockGenerateDisclosure = vi.fn(async () => ({
  encryptedData: new Uint8Array([1, 2, 3, 4]),
  viewingKeyHash: 'ef'.repeat(32),
}));

const mockAddress = 'AB'.repeat(32);

vi.mock('@stellar-privacy/sdk', () => {
  class MockPrivacyAccount {
    address = mockAddress;
    keyPair = { viewingKey: new Uint8Array(32) };
    deposit = mockDeposit;
    withdraw = mockWithdraw;
    registerViewingKey = mockRegisterViewingKey;
    authorizeViewer = mockAuthorizeViewer;
    getBalance = vi.fn(async () => 0n);
    getPoolStats = vi.fn(async () => ({ root: null, size: 0, isPaused: false, version: 1 }));
  }

  class MockComplianceModule {
    generateSelectiveDisclosureProof = mockGenerateDisclosure;
  }

  class MockPrivacySDKError extends Error {
    code: string;
    constructor(code: string, message: string) {
      super(message);
      this.name = 'PrivacySDKError';
      this.code = code;
    }
  }

  return {
    PrivacyAccount: MockPrivacyAccount,
    ComplianceModule: MockComplianceModule,
    KeyManager: {
      generateKeyPair: vi.fn(() => ({
        secretKey: new Uint8Array(32),
        publicKey: mockAddress,
        viewingKey: new Uint8Array(32),
      })),
      toHex: () => 'ab'.repeat(32),
    },
    PrivacySDKError: MockPrivacySDKError,
    ErrorCode: {
      CONNECTION_FAILED: 'CONNECTION_FAILED',
      PROOF_VERIFICATION_FAILED: 'PROOF_VERIFICATION_FAILED',
      COMPLIANCE_ERROR: 'COMPLIANCE_ERROR',
    },
    isStellarAddress: (value: unknown) =>
      typeof value === 'string' && /^[GCA][0-9A-Z]{55}$/.test(value),
  };
});

import { ErrorCode, PrivacySDKError } from '@stellar-privacy/sdk';
import App from '../App';

describe('App', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders the header and all five navigation views', () => {
    render(<App />);
    expect(screen.getByRole('heading', { name: /stellar privacy layer/i })).toBeInTheDocument();
    for (const label of ['Wallet', 'Deposit', 'Withdraw', 'Compliance', 'Audit']) {
      expect(screen.getByRole('button', { name: label })).toBeInTheDocument();
    }
  });

  it('shows the wallet view by default', () => {
    render(<App />);
    expect(screen.getByRole('heading', { name: 'Wallet' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /create privacy account/i })).toBeInTheDocument();
  });

  it('creates a privacy account', async () => {
    const user = userEvent.setup();
    render(<App />);
    await user.click(screen.getByRole('button', { name: /create privacy account/i }));
    expect(await screen.findByText(mockAddress)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /new account/i })).toBeInTheDocument();
  });

  it('disables deposit and withdraw until an account exists', async () => {
    const user = userEvent.setup();
    render(<App />);
    await user.click(screen.getByRole('button', { name: 'Deposit' }));
    expect(screen.getByRole('button', { name: /deposit 100 usdc/i })).toBeDisabled();
    await user.click(screen.getByRole('button', { name: 'Withdraw' }));
    expect(screen.getByRole('button', { name: /withdraw 50 usdc/i })).toBeDisabled();
  });

  it('deposits after creating an account', async () => {
    const user = userEvent.setup();
    render(<App />);
    await user.click(screen.getByRole('button', { name: /create privacy account/i }));
    await user.click(screen.getByRole('button', { name: 'Deposit' }));
    await user.click(screen.getByRole('button', { name: /deposit 100 usdc/i }));

    expect(mockDeposit).toHaveBeenCalledTimes(1);
    expect(await screen.findByRole('status')).toHaveTextContent(/deposit prepared/i);
  });

  it('shows an error banner when a deposit fails', async () => {
    mockDeposit.mockRejectedValueOnce(new PrivacySDKError(ErrorCode.CONNECTION_FAILED, 'rpc down'));
    const user = userEvent.setup();
    render(<App />);
    await user.click(screen.getByRole('button', { name: /create privacy account/i }));
    await user.click(screen.getByRole('button', { name: 'Deposit' }));
    await user.click(screen.getByRole('button', { name: /deposit 100 usdc/i }));

    expect(await screen.findByRole('status')).toHaveTextContent(/rpc down/i);
    expect(screen.getByRole('status')).toHaveTextContent(/CONNECTION_FAILED/i);
  });

  it('withdraws with a generated proof', async () => {
    const user = userEvent.setup();
    render(<App />);
    await user.click(screen.getByRole('button', { name: /create privacy account/i }));
    await user.click(screen.getByRole('button', { name: 'Withdraw' }));
    await user.click(screen.getByRole('button', { name: /withdraw 50 usdc/i }));

    expect(mockWithdraw).toHaveBeenCalledTimes(1);
    expect(await screen.findByRole('status')).toHaveTextContent(/withdrawal prepared/i);
  });

  it('registers a viewing key from the compliance view', async () => {
    const user = userEvent.setup();
    render(<App />);
    await user.click(screen.getByRole('button', { name: /create privacy account/i }));
    await user.click(screen.getByRole('button', { name: 'Compliance' }));
    await user.click(screen.getByRole('button', { name: /register viewing key/i }));

    expect(mockRegisterViewingKey).toHaveBeenCalledTimes(1);
    expect(await screen.findByRole('status')).toHaveTextContent(/viewing key registered/i);
  });

  it('authorizes a regulator with a valid address', async () => {
    const user = userEvent.setup();
    render(<App />);
    await user.click(screen.getByRole('button', { name: /create privacy account/i }));
    await user.click(screen.getByRole('button', { name: 'Compliance' }));

    const regulator = 'G'.padEnd(56, 'Z');
    await user.clear(screen.getByLabelText(/regulator address/i));
    await user.type(screen.getByLabelText(/regulator address/i), regulator);
    await user.click(screen.getByRole('button', { name: /authorize regulator/i }));

    expect(mockAuthorizeViewer).toHaveBeenCalledWith(regulator);
    expect(await screen.findByRole('status')).toHaveTextContent(/authorized/i);
  });

  it('rejects an invalid regulator address without calling the SDK', async () => {
    const user = userEvent.setup();
    render(<App />);
    await user.click(screen.getByRole('button', { name: /create privacy account/i }));
    await user.click(screen.getByRole('button', { name: 'Compliance' }));

    await user.clear(screen.getByLabelText(/regulator address/i));
    await user.type(screen.getByLabelText(/regulator address/i), 'not-an-address');
    await user.click(screen.getByRole('button', { name: /authorize regulator/i }));

    expect(mockAuthorizeViewer).not.toHaveBeenCalled();
    expect(await screen.findByRole('status')).toHaveTextContent(/valid stellar account/i);
  });

  it('generates a selective disclosure proof', async () => {
    const user = userEvent.setup();
    render(<App />);
    await user.click(screen.getByRole('button', { name: 'Compliance' }));
    await user.click(screen.getByRole('button', { name: /generate disclosure proof/i }));

    expect(mockGenerateDisclosure).toHaveBeenCalledTimes(1);
    expect(await screen.findByRole('status')).toHaveTextContent(/disclosure proof generated/i);
  });

  it('records activity in the audit log', async () => {
    const user = userEvent.setup();
    render(<App />);
    await user.click(screen.getByRole('button', { name: /create privacy account/i }));
    await user.click(screen.getByRole('button', { name: 'Audit' }));

    expect(await screen.findByRole('log')).toHaveTextContent(/created privacy account/i);
  });
});
