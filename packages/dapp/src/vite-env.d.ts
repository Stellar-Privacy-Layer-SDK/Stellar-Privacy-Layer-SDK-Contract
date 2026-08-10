/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_CONTRACT_ID?: string;
  readonly VITE_NETWORK_PASSPHRASE?: string;
  readonly VITE_RPC_URL?: string;
  readonly VITE_HORIZON_URL?: string;
  readonly VITE_USDC_TOKEN?: string;
  readonly VITE_REGULATOR_ADDRESS?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
