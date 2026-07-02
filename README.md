# Stellar Privacy Layer — Confidential Transfers SDK

A production-ready SDK for shielded asset transfers on Stellar, leveraging **Protocol 25** native zero-knowledge primitives (BN254 + Poseidon). Enables developers to build privacy-preserving financial applications with **selective compliance disclosure**.

## Architecture

```
┌──────────────────────────────────────────────────┐
│                   Reference dApp                  │
│         (React — Shielded USDC Transfers)         │
├──────────────────────────────────────────────────┤
│               TypeScript SDK (Frontend)            │
│  @stellar-privacy/sdk                             │
│  ┌──────────┐ ┌──────────┐ ┌──────────────────┐  │
│  │  Client   │ │  Prover  │ │ ComplianceModule │  │
│  └──────────┘ └──────────┘ └──────────────────┘  │
├──────────────────────────────────────────────────┤
│           Off-Chain Prover (Rust)                 │
│  stellar-privacy-prover                           │
│  ┌──────────┐ ┌──────────┐ ┌──────────────────┐  │
│  │ Circuits  │ │ Merkle   │ │ Proof Generation │  │
│  └──────────┘ └──────────┘ └──────────────────┘  │
├──────────────────────────────────────────────────┤
│     Soroban Smart Contract (On-Chain)             │
│  stellar-privacy-contract                         │
│  ┌──────────┐ ┌──────────┐ ┌──────────────────┐  │
│  │ Pool Mgr │ │Verifier  │ │ Compliance/Events │  │
│  └──────────┘ └──────────┘ └──────────────────┘  │
├──────────────────────────────────────────────────┤
│        Stellar Protocol 25 (Native ZK)            │
│         BN254 Curve + Poseidon Hash               │
└──────────────────────────────────────────────────┘
```

## Packages

| Package | Description | Language |
|---------|-------------|----------|
| `packages/contract` | Soroban verifier + shielded pool contract | Rust |
| `packages/prover` | Off-chain ZK proof generation library | Rust |
| `packages/sdk` | TypeScript wrapper SDK for frontend | TypeScript |
| `packages/selective-disclosure` | Compliance & regulatory viewing keys | TypeScript |
| `packages/dapp` | Reference React dApp for private USDC | TypeScript |

## Quick Start

```bash
# Install dependencies
make build

# Run tests
make test

# Build contract only
make build-contract

# Deploy contract (requires Stellar CLI + secrets)
make deploy-contract
```

## Smart Contract API

```rust
// Initialize pool
ShieldedPool::initialize(env, admin, verifier);

// Shielded deposit
ShieldedPool::deposit(env, depositor, token, amount, commitment);

// Shielded withdrawal with ZK proof
ShieldedPool::withdraw(env, proof, amount, token);

// Compliance — register viewing key
ShieldedPool::register_viewing_key(env, owner, viewing_key_hash);

// Compliance — authorize regulator
ShieldedPool::authorize_viewer(env, owner, viewer);
```

## TypeScript SDK Usage

```typescript
import { PrivacyAccount, KeyManager, ComplianceModule } from '@stellar-privacy/sdk';

// Create a privacy account
const account = new PrivacyAccount({
  contractId: 'CC...',
  networkPassphrase: 'Test SDF Network ; quorum-test',
  rpcUrl: 'https://rpc.testnet.stellar.org',
  horizonUrl: 'https://horizon-testnet.stellar.org',
});

// Shielded deposit
await account.deposit({
  amount: 1000n,
  recipient: 'G...',
  token: 'CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2S2QW3EY5XFG2L3UQP',
});

// Compliance — authorize a regulator to view transactions
await account.registerViewingKey();
await account.authorizeViewer('GREGULATOR...');

// Generate selective disclosure proof for regulator
const compliance = new ComplianceModule(config);
const disclosure = await compliance.generateSelectiveDisclosureProof(
  { sender, recipient, amount, timestamp },
  regulatorPublicKey,
);
```

## Compliance Module

The selective disclosure system enables **regulatory viewing keys**:

1. User registers a viewing key hash on-chain
2. User authorizes specific regulator addresses
3. When requested, user encrypts transaction details with the regulator's key
4. Regulator decrypts using their private key — proving they are authorized

This is **Tornado Cash architecture but compliance-forward**: proofs are selectively disclosable.

## ZK Circuit Design

The shielded transfer uses a **Groth16** proof over **BN254**:

- **Commitment**: `Poseidon(secret, recipient, amount)` — stored in Merkle tree
- **Nullifier**: `Poseidon(secret, commitment)` — prevents double-spending
- **Merkle Tree**: Depth 32, Poseidon-based, supports up to 2^32 deposits
- **Verification**: On-chain BN254 pairing check + Merkle root membership

## Protocol 25 Integration

Uses Stellar's native host functions from Protocol 25:

- `env.zk().bn254()` — BN254 curve operations (G1/G2 arithmetic, pairing)
- `env.zk().poseidon()` — Poseidon hash function

No external ZK circuit compiler needed — proofs verified natively.

## Development

```bash
# Rust toolchain
rustup target add wasm32-unknown-unknown

# Soroban CLI
cargo install soroban-cli

# Run all tests
cargo test -p stellar-privacy-prover -- --nocapture
npm test

# Type check
npx tsc --noEmit -p packages/sdk/tsconfig.json
```

## License

MIT OR Apache-2.0
