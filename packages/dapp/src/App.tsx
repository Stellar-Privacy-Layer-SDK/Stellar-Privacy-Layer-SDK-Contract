import React, { useState, useCallback } from 'react';
import {
  PrivacyAccount,
  KeyManager,
  ComplianceModule,
  ShieldedPoolClient,
} from '@stellar-privacy/sdk';

const POOL_CONFIG = {
  contractId: process.env.REACT_APP_CONTRACT_ID || 'CCJZK7W4TVG5Q6Z7Y7Q3Z7Y7Q3Z7Y7Q3Z7Y7Q3Z7Y7Q3',
  networkPassphrase: 'Test SDF Network ; quorum-test',
  rpcUrl: process.env.REACT_APP_RPC_URL || 'https://rpc.testnet.stellar.org',
  horizonUrl: process.env.REACT_APP_HORIZON_URL || 'https://horizon-testnet.stellar.org',
};

type View = 'wallet' | 'deposit' | 'withdraw' | 'compliance' | 'audit';

function App() {
  const [view, setView] = useState<View>('wallet');
  const [account, setAccount] = useState<PrivacyAccount | null>(null);
  const [compliance] = useState(
    () => new ComplianceModule(POOL_CONFIG),
  );
  const [status, setStatus] = useState<string>('');
  const [logs, setLogs] = useState<string[]>([]);

  const addLog = useCallback((msg: string) => {
    setLogs(prev => [`[${new Date().toISOString()}] ${msg}`, ...prev].slice(0, 50));
  }, []);

  const handleCreateAccount = useCallback(() => {
    try {
      const kp = KeyManager.generateKeyPair();
      const acc = new PrivacyAccount(POOL_CONFIG, kp);
      setAccount(acc);
      setStatus(`Account created: ${acc.address.slice(0, 16)}...`);
      addLog(`Created privacy account with key pair`);
    } catch (err) {
      setStatus(`Error: ${err}`);
    }
  }, [addLog]);

  const handleDeposit = useCallback(async () => {
    if (!account) return;
    try {
      setStatus('Generating deposit proof...');
      addLog('Generating shielded deposit...');
      const txHash = await account.deposit({
        amount: 100n,
        recipient: account.address,
        token: 'CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2S2QW3EY5XFG2L3UQP',
      });
      setStatus(`Deposit submitted: ${txHash.slice(0, 16)}...`);
      addLog(`Deposit transaction: ${txHash}`);
    } catch (err) {
      setStatus(`Deposit failed: ${err}`);
    }
  }, [account, addLog]);

  const handleWithdraw = useCallback(async () => {
    if (!account) return;
    try {
      setStatus('Generating withdrawal proof...');
      addLog('Generating shielded withdrawal...');
      const txHash = await account.withdraw(
        { amount: 50n, recipient: account.address, token: 'CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2S2QW3EY5XFG2L3UQP' },
        0,
      );
      setStatus(`Withdrawal submitted: ${txHash.slice(0, 16)}...`);
      addLog(`Withdrawal transaction: ${txHash}`);
    } catch (err) {
      setStatus(`Withdrawal failed: ${err}`);
    }
  }, [account, addLog]);

  const handleRegisterCompliance = useCallback(async () => {
    if (!account) return;
    try {
      await account.registerViewingKey();
      setStatus('Viewing key registered for compliance');
      addLog('Registered viewing key for regulatory compliance');
    } catch (err) {
      setStatus(`Compliance registration failed: ${err}`);
    }
  }, [account, addLog]);

  const handleAuthorizeViewer = useCallback(async () => {
    if (!account) return;
    try {
      const regulatorAddr = 'GREGULATORADDRESS123...';
      await account.authorizeViewer(regulatorAddr);
      setStatus(`Authorized ${regulatorAddr.slice(0, 8)}... as viewer`);
      addLog(`Authorized regulator as viewer`);
    } catch (err) {
      setStatus(`Authorization failed: ${err}`);
    }
  }, [account, addLog]);

  const handleDiscloseToRegulator = useCallback(async () => {
    try {
      const disclosure = await compliance.generateSelectiveDisclosureProof(
        {
          sender: account?.address || 'unknown',
          recipient: 'GB...',
          amount: 100n,
          timestamp: Date.now(),
        },
        new Uint8Array(32),
      );
      setStatus('Selective disclosure proof generated');
      addLog(`Generated selective disclosure: ${disclosure.viewingKeyHash.slice(0, 16)}...`);
    } catch (err) {
      setStatus(`Disclosure failed: ${err}`);
    }
  }, [account, compliance, addLog]);

  const navButton = (label: string, v: View) => (
    <button
      onClick={() => setView(v)}
      style={{
        padding: '8px 16px',
        background: view === v ? '#007bff' : '#f0f0f0',
        color: view === v ? 'white' : '#333',
        border: '1px solid #ccc',
        borderRadius: 4,
        cursor: 'pointer',
      }}
    >
      {label}
    </button>
  );

  return (
    <div style={{ maxWidth: 800, margin: '0 auto', padding: 20 }}>
      <header style={{ marginBottom: 24 }}>
        <h1 style={{ margin: 0 }}>Stellar Privacy Layer</h1>
        <p style={{ color: '#666', margin: '4px 0' }}>
          Shielded USDC Transfers — Protocol 25 ZK Primitives
        </p>
      </header>

      <nav style={{ display: 'flex', gap: 8, marginBottom: 24 }}>
        {navButton('Wallet', 'wallet')}
        {navButton('Deposit', 'deposit')}
        {navButton('Withdraw', 'withdraw')}
        {navButton('Compliance', 'compliance')}
        {navButton('Audit', 'audit')}
      </nav>

      <div style={{
        background: '#f8f9fa',
        borderRadius: 8,
        padding: 20,
        minHeight: 300,
      }}>
        {view === 'wallet' && (
          <div>
            <h2>Wallet</h2>
            {!account ? (
              <div>
                <p>No account created yet.</p>
                <button onClick={handleCreateAccount} style={btnStyle}>
                  Create Privacy Account
                </button>
              </div>
            ) : (
              <div>
                <p><strong>Address:</strong> {account.address}</p>
                <p><strong>Viewing Key:</strong> {KeyManager.toHex(account.keyPair.viewingKey).slice(0, 32)}...</p>
                <button onClick={handleCreateAccount} style={btnStyle}>
                  New Account
                </button>
              </div>
            )}
          </div>
        )}

        {view === 'deposit' && (
          <div>
            <h2>Shielded Deposit</h2>
            <p>Deposit USDC into the shielded pool. Your balance is private.</p>
            <button
              onClick={handleDeposit}
              style={btnStyle}
              disabled={!account}
            >
              Deposit 100 USDC
            </button>
          </div>
        )}

        {view === 'withdraw' && (
          <div>
            <h2>Shielded Withdrawal</h2>
            <p>Withdraw USDC from the shielded pool with a ZK proof.</p>
            <button
              onClick={handleWithdraw}
              style={btnStyle}
              disabled={!account}
            >
              Withdraw 50 USDC
            </button>
          </div>
        )}

        {view === 'compliance' && (
          <div>
            <h2>Compliance & Selective Disclosure</h2>
            <p>Configure regulatory compliance for your shielded transactions.</p>
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
              <button onClick={handleRegisterCompliance} style={btnStyle} disabled={!account}>
                Register Viewing Key
              </button>
              <button onClick={handleAuthorizeViewer} style={btnStyle} disabled={!account}>
                Authorize Regulator
              </button>
              <button onClick={handleDiscloseToRegulator} style={btnStyle}>
                Generate Disclosure Proof
              </button>
            </div>
          </div>
        )}

        {view === 'audit' && (
          <div>
            <h2>Audit Log</h2>
            <p>Transaction history and compliance audit trail.</p>
            {logs.length === 0 ? (
              <p style={{ color: '#999' }}>No activity yet.</p>
            ) : (
              <div style={{
                background: '#1a1a2e',
                color: '#0f0',
                padding: 12,
                borderRadius: 4,
                fontFamily: 'monospace',
                fontSize: 12,
                maxHeight: 400,
                overflow: 'auto',
              }}>
                {logs.map((log, i) => (
                  <div key={i}>{log}</div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>

      {status && (
        <div style={{
          marginTop: 16,
          padding: '8px 16px',
          background: '#d4edda',
          borderRadius: 4,
          color: '#155724',
        }}>
          {status}
        </div>
      )}

      <footer style={{ marginTop: 32, color: '#999', fontSize: 12 }}>
        Powered by Stellar Protocol 25 — BN254 + Poseidon ZK Primitives
      </footer>
    </div>
  );
}

const btnStyle: React.CSSProperties = {
  padding: '10px 20px',
  background: '#007bff',
  color: 'white',
  border: 'none',
  borderRadius: 4,
  cursor: 'pointer',
  fontSize: 14,
  fontWeight: 500,
};

export default App;
