.PHONY: all build check test clean build-contract build-prover build-sdk build-dapp

all: build test

build: build-contract build-prover build-sdk

check:
	cargo check -p stellar-privacy-contract --target wasm32-unknown-unknown
	cargo check -p stellar-privacy-prover
	npm run build:sdk

test:
	cargo test -p stellar-privacy-prover
	npm test

build-contract:
	cargo build -p stellar-privacy-contract --target wasm32-unknown-unknown --release

build-prover:
	cargo build -p stellar-privacy-prover --release

build-sdk:
	npm run build:sdk

build-dapp:
	npm run build:dapp

clean:
	cargo clean
	rm -rf packages/sdk/dist packages/selective-disclosure/dist packages/dapp/build

lint:
	cargo clippy --all-targets -- -D warnings
	npm run lint

format:
	cargo fmt --all
	npm run format

.PHONY: deploy-contract
deploy-contract:
	stellar contract deploy \
		--wasm target/wasm32-unknown-unknown/release/stellar_privacy_contract.wasm \
		--source \$${DEPLOYER_SECRET} \
		--network \$${STELLAR_NETWORK}
