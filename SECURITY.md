# Security Policy

The Stellar Privacy Layer handles financial privacy primitives and
cryptographic keys — security is the top priority of this project.

## Reporting a vulnerability

**Do not open a public issue for security problems.** Please report
privately via GitHub's Private Vulnerability Reporting:

1. Open the repository's **Security** tab → **Report a vulnerability**
   (GitHub Private Vulnerability Reporting). If private reporting is not
   enabled for this repo, email the maintainers (address in the repo
   description) with `[SECURITY]` in the subject line.
2. Include:
   - the affected crate/package and version,
   - a minimal reproduction or affected code path,
   - the impact you believe the issue has, and
   - any suggested fix, if you have one.

If you cannot use GitHub's reporting UI, email the maintainers (address
published in the repo description / issue tracker) with the same details and
prefix the subject with `[SECURITY]`.

## Scope

In-scope components:

- `packages/contract` — Soroban `ShieldedPool` (verification, auth, storage)
- `packages/prover` — arkworks circuits, Poseidon, Groth16 prover
- `packages/sdk` and `packages/selective-disclosure` — TypeScript SDKs
- `packages/dapp`, `Dockerfile`, `nginx.conf`, deployment scripts

Out of scope (but still welcome): general feature requests, dependency
version bumps, and issues that only affect a local development environment.

## Response expectations

- **Acknowledgment** within 3 business days.
- **Triage / impact assessment** within 7 business days.
- **Fix or mitigation plan** within 30 days for critical issues (or a
  documented reason why more time is needed).

We will coordinate disclosure with you before publishing a fix or advisory.

## Security posture

- **Zero secrets in the repository** — `DEPLOYER_SECRET` and `.env` files are
  git-ignored; production configuration flows through environment variables.
- **Dependency auditing in CI** — `npm audit` (npm), `cargo audit`
  (RustSec), and `cargo deny` (licenses/bans/advisories) run on every push
  and pull request.
- **Supply-chain hardening** — GitHub Actions are pinned to exact commits;
  CodeQL runs on every PR.
- **On-chain verification** — the Groth16 withdrawal path subgroup-checks
  every point and runs the full pairing product using Stellar's native
  BLS12-381 host functions; the verifying key is validated at set time.
- **Browser-safe cryptography** — audited `@noble` primitives
  (AES-256-GCM, HKDF-SHA256, SHA-256), no Node built-ins.

See [README.md](./README.md#security-notes) for the full security notes.
