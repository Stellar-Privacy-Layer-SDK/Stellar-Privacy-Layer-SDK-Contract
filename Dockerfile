# syntax=docker/dockerfile:1

# ---- Stage 1: build the TypeScript packages and the dapp ----
FROM node:22-alpine AS build
WORKDIR /app

# Install dependencies first for better layer caching.
COPY package.json package-lock.json ./
COPY packages ./packages
RUN npm ci

# Runtime configuration is baked in at build time (VITE_* variables). Defaults
# keep a plain `docker build` runnable against testnet.
ARG VITE_CONTRACT_ID=CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2S2QW3EY5XFG2L3UQP
ARG VITE_NETWORK_PASSPHRASE=Test SDF Network ; quorum-test
ARG VITE_RPC_URL=https://rpc.testnet.stellar.org
ARG VITE_HORIZON_URL=https://horizon-testnet.stellar.org
ARG VITE_USDC_TOKEN=CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2S2QW3EY5XFG2L3UQP
ARG VITE_REGULATOR_ADDRESS=GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA7
ENV \
  VITE_CONTRACT_ID=${VITE_CONTRACT_ID} \
  VITE_NETWORK_PASSPHRASE=${VITE_NETWORK_PASSPHRASE} \
  VITE_RPC_URL=${VITE_RPC_URL} \
  VITE_HORIZON_URL=${VITE_HORIZON_URL} \
  VITE_USDC_TOKEN=${VITE_USDC_TOKEN} \
  VITE_REGULATOR_ADDRESS=${VITE_REGULATOR_ADDRESS}

RUN npm run build:all

# ---- Stage 2: serve the static build with nginx ----
FROM nginx:1.27-alpine AS runtime
COPY --from=build /app/packages/dapp/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -q --spider http://127.0.0.1/ || exit 1
