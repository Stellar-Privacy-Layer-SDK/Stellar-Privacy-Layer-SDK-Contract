# Contributing

Thanks for helping make the Stellar Privacy Layer production-grade. This is a
monorepo of TypeScript packages (npm workspaces) plus two Rust crates.

## Prerequisites

- Node.js ≥ 22 (`.nvmrc` — run `nvm use`)
- npm ≥ 10
- Rust stable + `wasm32-unknown-unknown` target (`rustup target add wasm32-unknown-unknown`)
- Optional: Docker (containerized runs), Stellar CLI (contract deploys)

## Getting started

```bash
npm ci
rustup target add wasm32-unknown-unknown
```

## The quality gate

CI runs this exact gate on every push/PR — make it pass locally first:

```bash
make check          # Rust: fmt + clippy -D warnings; JS: lint + format + typecheck + coverage + build
npm run check       # the TypeScript half only (lint + format:check + typecheck + test:coverage + build:all)
make test           # cargo tests (prover + contract) + npm tests
```

Coverage thresholds (≥80% statements/lines/functions) are enforced by CI for
all TypeScript packages. New Rust code must be `cargo clippy -D warnings`
clean and formatted with `cargo fmt`.

## Before opening a pull request

1. **Branch** from `main` — `feat/`, `fix/`, `chore/`, `docs/` prefixes.
2. **Add tests** for new behavior (unit tests for SDK/Rust; the contract's
   Groth16 tests use committed real-proof fixtures).
3. **Run the gate**: `make check && make test`.
4. **Verify security checks**: `npm audit` and `cargo audit` (0
   vulnerabilities), `cargo deny check` (see `deny.toml` for documented
   exceptions).
5. **Keep the diff focused** — one logical change per PR. Explain *why* in the
   description (templates are provided).
6. **Never commit secrets** — `.env`, `.env.local`, and `DEPLOYER_SECRET`
   values must stay out of git.

## Rules of thumb

- Reuse existing helpers (`KeyManager`, `createLogger`, typed
  `PrivacySDKError`s) instead of reimplementing them.
- Public SDK surfaces validate inputs and throw typed errors with stable
  codes.
- Don't change the project's core idea (shielded transfers + selective
  compliance disclosure, "hug and ripples") — improvements must be to
  quality, structure, and production readiness.
- If a change is security-relevant, reference it in the PR and add a note to
  `SECURITY.md` if it changes the security posture.

## Issue templates

Please use the issue templates (bug report / feature request) so maintainers
can triage quickly. For security issues, follow [SECURITY.md](./SECURITY.md).
