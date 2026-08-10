# Stellar Privacy Layer — Confidential Transfers SDK

A production-ready SDK for shielded asset transfers on Stellar, leveraging the network's **native zero-knowledge primitives** (BLS12-381 pairing + Poseidon). It enables developers to build privacy-preserving financial applications with **selective compliance disclosure** — privacy where you want it, transparency where the law requires it ("hug and ripples" compliance-forward architecture).

## Table of contents

- [Features](#features)
- [Architecture](#architecture)
- [Packages](#packages)
- [Prerequisites](#prerequisites)
- [Quick start](#quick-start)
- [Environment variables](#environment-variables)
- [Scripts](#scripts)
- [Testing & coverage](#testing--coverage)
- [Deployment](#deployment)
- [Security notes](#security-notes)
- [Contributing](#contributing)
- [License](#license)

## Features

- **Shielded deposits** — commit funds to a Merkle tree; amounts are hidden on-chain.
- **ZK withdrawals** — withdraw with a zero-knowledge proof; nullifiers prevent double-spending.
- **Regulatory viewing keys** — register an encrypted viewing key on-chain.
- **Selective disclosure** — disclose only the fields a regulator asks for, encrypted to their key.
- **Audit trail** — every compliance action is emitted as a structured on-chain event.
- **TypeScript SDK** — browser-safe cryptography (`@noble`-based), zero Node built-ins.
- **Rust prover** — Poseidon-based commitment/nullifier circuits + Merkle proofs, and a real **arkworks Groth16 prover** (BLS12-381).
- **Soroban contract** — admin controls (pause, verifier rotation), compliance records, Merkle pool, and a **full on-chain Groth16 verifier** using Stellar's native BLS12-381 host functions.

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                Reference dApp (React)                 │
│         @stellar-privacy/dapp — shielded USDC UI      │
├──────────────────────────────────────────────────────┤
│               TypeScript SDK (frontend)               │
│  @stellar-privacy/sdk                                 │
│  ┌──────────┐ ┌──────────┐ ┌──────────────────────┐   │
│  │  Client   │ │  Prover  │ │   ComplianceModule   │   │
│  └──────────┘ └──────────┘ └──────────────────────┘   │
│  @stellar-privacy/selective-disclosure                 │
│        regulatory requests + scoped disclosure         │
├──────────────────────────────────────────────────────┤
│              Off-chain Prover (Rust)                  │
│  stellar-privacy-prover — circuits, merkle, poseidon  │
├──────────────────────────────────────────────────────┤
│          Soroban Smart Contract (on-chain)            │
│  stellar-privacy-contract — pool, verifier, events    │
├──────────────────────────────────────────────────────┤
│            Soroban host (native BLS12-381)            │
│      g1_msm + pairing checks + Poseidon hash          │
└──────────────────────────────────────────────────────┘
```

## Packages

| Package | Description | Language |
| --- | --- | --- |
| `packages/contract` | Soroban verifier + shielded pool contract | Rust |
| `packages/prover` | Off-chain ZK proof generation library | Rust |
| `packages/sdk` | TypeScript SDK for frontends (ESM) | TypeScript |
| `packages/selective-disclosure` | Compliance & regulatory viewing keys (ESM) | TypeScript |
| `packages/dapp` | Reference React dApp for private USDC | TypeScript |

## Prerequisites

- **Node.js ≥ 22** and **npm ≥ 10** (npm workspaces)
- **Rust stable** with the `wasm32-unknown-unknown` target
- Optional: [Stellar CLI](https://github.com/stellar/stellar-cli) for contract deployment
- Optional: Docker + Docker Compose for containerized deployment

```bash
# Install the Rust wasm target (if missing)
rustup target add wasm32-unknown-unknown
```

## Quick start

```bash
# 1. Install all dependencies (npm workspaces)
npm install

# 2. Run the full quality gate (lint + format + typecheck + tests + build)
npm run check

# 3. Run the reference dApp locally
npm run dev          # http://localhost:5173

# 4. (Optional) run everything via Docker — one command
docker compose up --build   # http://localhost:8080
```

> The dApp defaults to Stellar **testnet** so it runs out of the box. Configure
> real contract/token addresses via environment variables (below).

## Environment variables

### dApp (`packages/dapp/.env.local` or root `.env`)

| Variable | Default | Description |
| --- | --- | --- |
| `VITE_CONTRACT_ID` | testnet USDC address | Deployed `ShieldedPool` contract id (`C...`) |
| `VITE_NETWORK_PASSPHRASE` | `Test SDF Network ; quorum-test` | Stellar network passphrase |
| `VITE_RPC_URL` | `https://rpc.testnet.stellar.org` | Soroban RPC endpoint |
| `VITE_HORIZON_URL` | `https://horizon-testnet.stellar.org` | Horizon endpoint |
| `VITE_USDC_TOKEN` | testnet USDC address | Token contract used by the demo |
| `VITE_REGULATOR_ADDRESS` | placeholder (`G...`) | Default regulator for compliance |

### Contract deployment (root `.env`)

| Variable | Description |
| --- | --- |
| `DEPLOYER_SECRET` | Funded Stellar account secret key (never commit this) |
| `STELLAR_NETWORK` | `testnet`, `futurenet`, or `mainnet` (stellar CLI network name) |

See [`.env.example`](./.env.example) and [`packages/dapp/.env.example`](./packages/dapp/.env.example).

## Scripts

```bash
npm run dev                  # start the dApp (vite dev server)
npm run check                # full gate: lint, format, typecheck, coverage, build
npm run lint                 # biome check
npm run format               # biome format --write
npm run typecheck            # tsc --noEmit across all TS packages
npm test                     # vitest (all TS packages)
npm run test:coverage        # vitest with coverage + threshold gates (>=80%)
npm run build:all            # build sdk → selective-disclosure → dapp

make check                   # Rust + TS full gate
make test                    # cargo tests + npm tests
make build-contract          # contract wasm (release)
make build-prover            # prover release build
make docker-up               # docker compose up -d
```

## Groth16 mode (production ZK path)

The contract ships a production Groth16 withdrawal path alongside the reference
one. The circuit (`packages/prover/src/groth16.rs`) is a compact, documented
shielded-transfer demo:

- **public inputs**: `commitment`, `nullifier` (32-byte big-endian scalars)
- **private witnesses**: `secret`, `recipient`
- **constraints**: `secret² = s_sq`, `s_sq + recipient = commitment`, `secret · recipient = nullifier`

Production circuits should additionally bind the withdrawal `recipient` and
`amount` as public inputs (front-running protection) and use a Poseidon/Merkle
membership circuit.

**Flow** — the admin sets a Groth16 verifying key (`set_groth16_vk`), then users
submit `withdraw_groth16(proof, amount, token)` where `public_inputs =
[commitment, nullifier]`. The contract checks note membership (the commitment
must have been deposited), enforces the nullifier spend-guard, and pays out.

**Cost** — verification performs a handful of subgroup checks, one 3-point
`g1_msm`, and a 4-pair `pairing_check`; the test-suite runs it inside the
default host budget, and the per-call cost can be benchmarked with the prover
`criterion` bench before a production launch.

**Test fixtures** — contract tests verify a *real* arkworks-generated proof
end-to-end via the committed fixture in
`packages/contract/test_snapshots/groth16/fixture.json`. Regenerate it (only
needed when the circuit changes) with:

```bash
cargo run -p stellar-privacy-prover --example gen_groth16_fixture
```

The prover test `groth16::tests::test_committed_fixture_is_valid` re-verifies
the fixture with arkworks, so a stale or mismatched fixture fails CI.

## Testing & coverage

| Package | Tests | Coverage (statements) |
| --- | --- | --- |
| `@stellar-privacy/sdk` | 108 unit tests | **94.7%** |
| `@stellar-privacy/selective-disclosure` | 15 unit tests | **97.6%** |
| `@stellar-privacy/dapp` | 14 component tests | **89.5%** |
| `stellar-privacy-contract` | 28 contract tests | — |
| `stellar-privacy-prover` | 23 unit tests | — |

Coverage thresholds are enforced by CI (`>=80%` statements/lines/functions).
Generate a local report with `npm run test:coverage` (also writes `lcov`).

## CI/CD

GitHub Actions runs on every push/PR to `main` (see [`.github/workflows/ci.yml`](./.github/workflows/ci.yml)):

- **Rust job** — `cargo fmt --check`, `cargo clippy -D warnings`, wasm32 contract build, `cargo test --all-features`, cached cargo, wasm artifact upload.
- **TypeScript job** — `npm ci`, biome lint + format check, typecheck, production build of all packages, tests with coverage gates, dapp artifact upload.
- **Status job** — aggregates both into one pass/fail signal.

No step can silently pass: the previous workflow's `|| echo "no config found"` fallbacks have been removed.

## Deployment

### Option A — Docker Compose (recommended)

```bash
# Build and run with defaults (testnet)
docker compose up -d --build

# Point at your own contract/token
cp .env.example .env
# edit .env, then:
docker compose up -d --build

# Health check
curl -fsS http://localhost:8080
```

### Option B — manual

```bash
npm ci
npm run build:all
# Serve packages/dapp/dist with any static host (nginx config included in repo)
```

### Option C — deploy the Soroban contract

```bash
# Install the Stellar CLI (once)
cargo install stellar-cli --features cli

# Configure a network (e.g. testnet) in your stellar CLI, then:
./scripts/deploy.sh contract     # or: make deploy-contract
```

Copy the printed contract id into `VITE_CONTRACT_ID` and rebuild the dApp.

## Security notes

- **Secrets** — never commit `DEPLOYER_SECRET` or `.env`; the repo's `.gitignore` excludes them.
- **Cryptography** — the SDK uses audited, dependency-free `@noble` primitives (AES-256-GCM, HKDF-SHA256, SHA-256) that run identically in browsers and Node. The Rust prover implements Poseidon and real Groth16 proofs over BLS12-381 (arkworks).
- **On-chain Groth16 verification** — `withdraw_groth16` runs the full verification equation on-chain with Stellar's native BLS12-381 host functions: public-input MSM (`g1_msm`) plus a 4-pair pairing product (`pairing_check`). Every point is subgroup-checked and the verifying key is validated at set time. The reference `withdraw` path (structural checks + Merkle root) remains for compatibility and is documented as such.
- **Input validation** — all public SDK surfaces validate inputs and throw typed `PrivacySDKError`s with stable codes.
- **Auditability** — compliance actions emit structured on-chain events; the dApp keeps a local audit trail.
- **Headers** — the nginx config ships CSP, X-Frame-Options, nosniff, and referrer-policy headers.

## Contributing

1. Fork and clone the repository.
2. Run `npm install` and `make check` to verify a clean baseline.
3. Add tests for new behavior (coverage gates apply).
4. Open a pull request — CI runs the full gate automatically.

## License

MIT OR Apache-2.0
