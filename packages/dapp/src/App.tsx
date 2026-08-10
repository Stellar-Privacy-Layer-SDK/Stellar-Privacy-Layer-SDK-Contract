import {
  ComplianceModule,
  isStellarAddress,
  KeyManager,
  PrivacyAccount,
  PrivacySDKError,
} from '@stellar-privacy/sdk';
import { useCallback, useMemo, useState } from 'react';
import { APP_CONFIG } from './config';

type View = 'wallet' | 'deposit' | 'withdraw' | 'compliance' | 'audit';

const VIEWS: Array<{ id: View; label: string }> = [
  { id: 'wallet', label: 'Wallet' },
  { id: 'deposit', label: 'Deposit' },
  { id: 'withdraw', label: 'Withdraw' },
  { id: 'compliance', label: 'Compliance' },
  { id: 'audit', label: 'Audit' },
];

interface Status {
  kind: 'success' | 'error';
  message: string;
}

function formatError(error: unknown): string {
  if (error instanceof PrivacySDKError) {
    return `[${error.code}] ${error.message}`;
  }
  return error instanceof Error ? error.message : String(error);
}

function App() {
  const [view, setView] = useState<View>('wallet');
  const [account, setAccount] = useState<PrivacyAccount | null>(null);
  const [compliance] = useState(() => new ComplianceModule(APP_CONFIG));
  const [status, setStatus] = useState<Status | null>(null);
  const [logs, setLogs] = useState<string[]>([]);
  const [pending, setPending] = useState<string | null>(null);
  const [regulator, setRegulator] = useState(APP_CONFIG.defaultRegulator);

  const addLog = useCallback((message: string) => {
    setLogs((prev) => [`[${new Date().toISOString()}] ${message}`, ...prev].slice(0, 50));
  }, []);

  /** Runs an async action with loading + status + audit logging. */
  const run = useCallback(
    async (label: string, action: () => Promise<string>) => {
      setPending(label);
      setStatus(null);
      try {
        const message = await action();
        setStatus({ kind: 'success', message });
        addLog(message);
      } catch (error) {
        const message = formatError(error);
        setStatus({ kind: 'error', message });
        addLog(`FAILED: ${message}`);
      } finally {
        setPending(null);
      }
    },
    [addLog],
  );

  const busy = useMemo(() => pending !== null, [pending]);

  const handleCreateAccount = useCallback(() => {
    if (busy) return;
    try {
      const keyPair = KeyManager.generateKeyPair();
      const next = new PrivacyAccount(APP_CONFIG, keyPair);
      setAccount(next);
      setStatus(null);
      addLog(`Created privacy account ${next.address.slice(0, 12)}…`);
    } catch (error) {
      setStatus({ kind: 'error', message: formatError(error) });
      addLog(`FAILED: ${formatError(error)}`);
    }
  }, [busy, addLog]);

  const handleDeposit = useCallback(() => {
    if (!account) return;
    return run('Deposit', async () => {
      const tx = await account.deposit({
        amount: APP_CONFIG.depositAmount,
        recipient: account.address,
        token: APP_CONFIG.usdcToken,
      });
      return `Deposit prepared — ${APP_CONFIG.depositAmount.toString()} USDC shielded (tx ${tx.slice(0, 16)}…)`;
    });
  }, [account, run]);

  const handleWithdraw = useCallback(() => {
    if (!account) return;
    return run('Withdraw', async () => {
      const tx = await account.withdraw(
        {
          amount: APP_CONFIG.withdrawAmount,
          recipient: account.address,
          token: APP_CONFIG.usdcToken,
        },
        0,
      );
      return `Withdrawal prepared — ${APP_CONFIG.withdrawAmount.toString()} USDC with ZK proof (tx ${tx.slice(0, 16)}…)`;
    });
  }, [account, run]);

  const handleRegisterViewingKey = useCallback(() => {
    if (!account) return;
    return run('Register viewing key', async () => {
      await account.registerViewingKey();
      return `Viewing key registered for ${account.address.slice(0, 12)}…`;
    });
  }, [account, run]);

  const handleAuthorizeViewer = useCallback(() => {
    if (!account) return;
    if (!isStellarAddress(regulator)) {
      const message = 'Regulator address must be a valid Stellar account (G…) address';
      setStatus({ kind: 'error', message });
      addLog(`FAILED: ${message}`);
      return;
    }
    return run('Authorize viewer', async () => {
      await account.authorizeViewer(regulator);
      return `Authorized ${regulator.slice(0, 8)}… as compliance viewer`;
    });
  }, [account, regulator, run, addLog]);

  const handleDiscloseToRegulator = useCallback(() => {
    return run('Generate disclosure', async () => {
      const disclosure = await compliance.generateSelectiveDisclosureProof(
        {
          sender: account?.address ?? 'unset',
          recipient: account?.address ?? 'unset',
          amount: APP_CONFIG.withdrawAmount,
          timestamp: Date.now(),
        },
        new Uint8Array(32),
      );
      return `Disclosure proof generated (viewing key ${disclosure.viewingKeyHash.slice(0, 12)}…)`;
    });
  }, [account, compliance, run]);

  const renderNav = () => (
    <nav className="nav" aria-label="Primary">
      {VIEWS.map(({ id, label }) => (
        <button
          key={id}
          type="button"
          className={view === id ? 'active' : undefined}
          onClick={() => setView(id)}
          aria-current={view === id ? 'page' : undefined}
        >
          {label}
        </button>
      ))}
    </nav>
  );

  const renderStatus = () =>
    status && (
      <div className={`banner ${status.kind}`} role="status" aria-live="polite">
        {status.message.startsWith('[') ? <code>{status.message}</code> : status.message}
      </div>
    );

  return (
    <div className="app">
      <header className="app-header">
        <h1>Stellar Privacy Layer</h1>
        <p>Shielded USDC transfers — privacy with selective compliance disclosure</p>
      </header>

      {renderNav()}

      <main className="card">
        {view === 'wallet' && (
          <section aria-label="Wallet">
            <h2>Wallet</h2>
            {!account ? (
              <>
                <p className="subtitle">
                  No privacy account yet. Create one to start shielding USDC — your balances stay
                  private by design.
                </p>
                <button type="button" className="btn" onClick={handleCreateAccount} disabled={busy}>
                  Create Privacy Account
                </button>
              </>
            ) : (
              <>
                <p className="detail">
                  <strong>Address:</strong> <code>{account.address}</code>
                </p>
                <p className="detail">
                  <strong>Viewing Key:</strong>{' '}
                  <code>{KeyManager.toHex(account.keyPair.viewingKey).slice(0, 32)}…</code>
                </p>
                <p className="detail">
                  <strong>Network:</strong> {APP_CONFIG.networkPassphrase}
                </p>
                <div className="btn-row">
                  <button
                    type="button"
                    className="btn"
                    onClick={handleCreateAccount}
                    disabled={busy}
                  >
                    New Account
                  </button>
                </div>
              </>
            )}
          </section>
        )}

        {view === 'deposit' && (
          <section aria-label="Shielded deposit">
            <h2>Shielded Deposit</h2>
            <p className="subtitle">
              Deposit USDC into the shielded pool. A commitment is stored on-chain — the amount
              stays hidden.
            </p>
            <button
              type="button"
              className="btn"
              onClick={() => void handleDeposit()}
              disabled={!account || busy}
            >
              {pending === 'Deposit' && <span className="spinner" aria-hidden="true" />}
              Deposit {APP_CONFIG.depositAmount.toString()} USDC
            </button>
            {!account && <p className="muted">Create a wallet first to deposit.</p>}
          </section>
        )}

        {view === 'withdraw' && (
          <section aria-label="Shielded withdrawal">
            <h2>Shielded Withdrawal</h2>
            <p className="subtitle">
              Withdraw USDC with a zero-knowledge proof. The nullifier prevents the same commitment
              from being spent twice.
            </p>
            <button
              type="button"
              className="btn"
              onClick={() => void handleWithdraw()}
              disabled={!account || busy}
            >
              {pending === 'Withdraw' && <span className="spinner" aria-hidden="true" />}
              Withdraw {APP_CONFIG.withdrawAmount.toString()} USDC
            </button>
            {!account && <p className="muted">Create a wallet first to withdraw.</p>}
          </section>
        )}

        {view === 'compliance' && (
          <section aria-label="Compliance and selective disclosure">
            <h2>Compliance &amp; Selective Disclosure</h2>
            <p className="subtitle">
              Prove regulatory compliance without surrendering privacy: register a viewing key,
              authorize a regulator, and disclose only what is required.
            </p>
            <div className="btn-row">
              <button
                type="button"
                className="btn"
                onClick={() => void handleRegisterViewingKey()}
                disabled={!account || busy}
              >
                {pending === 'Register viewing key' && (
                  <span className="spinner" aria-hidden="true" />
                )}
                Register Viewing Key
              </button>
              <button
                type="button"
                className="btn"
                onClick={() => void handleDiscloseToRegulator()}
                disabled={busy}
              >
                {pending === 'Generate disclosure' && (
                  <span className="spinner" aria-hidden="true" />
                )}
                Generate Disclosure Proof
              </button>
            </div>

            <label className="field-label" htmlFor="regulator-address">
              Regulator address
            </label>
            <input
              id="regulator-address"
              className="input"
              value={regulator}
              onChange={(event) => setRegulator(event.target.value.trim())}
              placeholder="G…"
              autoComplete="off"
              spellCheck={false}
            />
            <div className="btn-row" style={{ marginTop: 12 }}>
              <button
                type="button"
                className="btn secondary"
                onClick={() => void handleAuthorizeViewer()}
                disabled={!account || busy}
              >
                {pending === 'Authorize viewer' && <span className="spinner" aria-hidden="true" />}
                Authorize Regulator
              </button>
            </div>
            {!account && <p className="muted">Create a wallet first to register compliance.</p>}
          </section>
        )}

        {view === 'audit' && (
          <section aria-label="Audit log">
            <h2>Audit Log</h2>
            <p className="subtitle">Transaction history and compliance audit trail.</p>
            {logs.length === 0 ? (
              <p className="muted">No activity yet.</p>
            ) : (
              <div className="audit-log" role="log" aria-live="polite">
                {logs.map((line, index) => (
                  <div key={line + String(index)}>{line}</div>
                ))}
              </div>
            )}
          </section>
        )}

        {renderStatus()}
      </main>

      <footer className="app-footer">
        Powered by Stellar Protocol 25 — BN254 + Poseidon ZK primitives · testnet by default
      </footer>
    </div>
  );
}

export default App;
