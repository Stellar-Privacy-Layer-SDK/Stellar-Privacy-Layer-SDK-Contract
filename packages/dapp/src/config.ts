/**
 * Application configuration, driven by `import.meta.env` (VITE_* variables).
 *
 * See `.env.example` for the full list of supported variables. Defaults point
 * at the Stellar testnet so the reference dApp runs out of the box.
 */
export interface AppConfig {
  contractId: string;
  networkPassphrase: string;
  rpcUrl: string;
  horizonUrl: string;
  usdcToken: string;
  defaultRegulator: string;
  depositAmount: bigint;
  withdrawAmount: bigint;
}

const env = import.meta.env;

/** Env value or default — `||` (not `??`) so empty strings also fall back. */
const pick = (value: string | undefined, fallback: string): string => value || fallback;

export const APP_CONFIG: AppConfig = {
  contractId: pick(
    env.VITE_CONTRACT_ID,
    'CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2S2QW3EY5XFG2L3UQP',
  ),
  networkPassphrase: pick(env.VITE_NETWORK_PASSPHRASE, 'Test SDF Network ; quorum-test'),
  rpcUrl: pick(env.VITE_RPC_URL, 'https://rpc.testnet.stellar.org'),
  horizonUrl: pick(env.VITE_HORIZON_URL, 'https://horizon-testnet.stellar.org'),
  usdcToken: pick(env.VITE_USDC_TOKEN, 'CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2S2QW3EY5XFG2L3UQP'),
  defaultRegulator: pick(env.VITE_REGULATOR_ADDRESS, 'G'.padEnd(56, '7')),
  depositAmount: 100n,
  withdrawAmount: 50n,
};
