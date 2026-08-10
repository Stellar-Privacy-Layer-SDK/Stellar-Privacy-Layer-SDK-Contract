# syntax=docker/dockerfile:1

# ---- Stage 1: build the TypeScript packages and the dapp ----
FROM node:22-alpine AS build
WORKDIR /app

# Install dependencies first for better layer caching. `--no-audit`/`--no-fund`
# are safe here: vulnerability audits run in CI (`npm audit`) and on Dependabot.
# BuildKit caches the npm store between builds.
COPY package.json package-lock.json ./
COPY packages ./packages
RUN --mount=type=cache,target=/root/.npm npm ci --no-audit --no-fund

# Runtime configuration is baked in at build time (VITE_* variables). Defaults
# keep a plain `docker build` runnable against testnet.
ARG VITE_CONTRACT_ID=CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2S2QW3EY5XFG2L3UQP
ARG VITE_NETWORK_PASSPHRASE=Test SDF Network ; quorum-test
ARG VITE_RPC_URL=https://rpc.testnet.stellar.org
ARG VITE_HORIZON_URL=https://horizon-testnet.stellar.org
ARG VITE_USDC_TOKEN=CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2S2QW3EY5XFG2L3UQP
ARG VITE_REGULATOR_ADDRESS=GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA7
# NOTE: the VITE_* values above are PUBLIC testnet configuration (contract /
# token addresses, RPC URLs) — not secrets. Real secrets (DEPLOYER_SECRET) are
# never passed to the image; they live only in the git-ignored .env.
ENV \
  VITE_CONTRACT_ID=${VITE_CONTRACT_ID} \
  VITE_NETWORK_PASSPHRASE=${VITE_NETWORK_PASSPHRASE} \
  VITE_RPC_URL=${VITE_RPC_URL} \
  VITE_HORIZON_URL=${VITE_HORIZON_URL} \
  VITE_USDC_TOKEN=${VITE_USDC_TOKEN} \
  VITE_REGULATOR_ADDRESS=${VITE_REGULATOR_ADDRESS}

RUN npm run build:all

# ---- Stage 2: serve the static build with an UNPRIVILEGED nginx ----
# nginx-unprivileged runs as uid 101 (non-root) and listens on 8080 — no
# root processes, no privileged ports, per-container compromise stays contained.
FROM nginxinc/nginx-unprivileged:1.28-alpine AS runtime
COPY --from=build /app/packages/dapp/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -q --spider http://127.0.0.1:8080/ || exit 1
