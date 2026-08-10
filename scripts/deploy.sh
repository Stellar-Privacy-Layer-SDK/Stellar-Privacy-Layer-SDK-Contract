#!/usr/bin/env bash
#
# Stellar Privacy Layer — deployment script.
#
# Usage:
#   ./scripts/deploy.sh [dapp|contract|all]
#
#   dapp      Build + start the reference dApp via Docker Compose (default).
#   contract  Deploy the Soroban contract to the configured network.
#   all       Deploy the contract, then build + start the dApp.
#
# Requires: docker, docker compose, and (for contract) the stellar CLI and the
# DEPLOYER_SECRET / STELLAR_NETWORK environment variables.
set -euo pipefail

cd "$(dirname "$0")/.."

# Load .env if present (ignored by git — never commit secrets).
if [ -f .env ]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

deploy_dapp() {
  echo "==> Building the dApp container image"
  docker compose build dapp

  echo "==> Starting the dApp on http://localhost:8080"
  docker compose up -d dapp

  echo "==> Done. Logs: docker compose logs -f dapp"
}

deploy_contract() {
  : "${DEPLOYER_SECRET:?DEPLOYER_SECRET must be set (funded Stellar account secret key)}"
  : "${STELLAR_NETWORK:?STELLAR_NETWORK must be set (e.g. testnet)}"

  echo "==> Building the contract wasm"
  cargo build -p stellar-privacy-contract --target wasm32-unknown-unknown --release --locked

  echo "==> Deploying the contract to '${STELLAR_NETWORK}'"
  stellar contract deploy \
    --wasm target/wasm32-unknown-unknown/release/stellar_privacy_contract.wasm \
    --source "${DEPLOYER_SECRET}" \
    --network "${STELLAR_NETWORK}"

  echo "==> Copy the printed contract id (C...) into VITE_CONTRACT_ID and rebuild the dApp."
}

case "${1:-dapp}" in
  dapp) deploy_dapp ;;
  contract) deploy_contract ;;
  all)
    deploy_contract
    deploy_dapp
    ;;
  *)
    echo "Unknown target '${1}'. Use: dapp | contract | all" >&2
    exit 1
    ;;
esac
