.PHONY: all build check test clean build-contract build-prover build-sdk build-dapp typecheck lint format test-coverage docker-build docker-up docker-down deploy deploy-contract fixture

all: build test

build: build-contract build-prover build-sdk

check:
	cargo fmt --all --check
	cargo clippy --all-targets --all-features -- -D warnings
	npm run check

test:
	cargo test -p stellar-privacy-prover
	cargo test -p stellar-privacy-contract
	npm test

test-coverage:
	npm run test:coverage

typecheck:
	npm run typecheck

lint:
	cargo clippy --all-targets --all-features -- -D warnings
	npm run lint

format:
	cargo fmt --all
	npm run format

build-contract:
	cargo build -p stellar-privacy-contract --target wasm32-unknown-unknown --release

build-prover:
	cargo build -p stellar-privacy-prover --release

build-sdk:
	npm run build:sdk

build-dapp:
	npm run build:dapp

docker-build:
	docker compose build

docker-up:
	docker compose up -d

docker-down:
	docker compose down

deploy:
	./scripts/deploy.sh dapp

deploy-contract:
	./scripts/deploy.sh contract

fixture:
	cargo run -p stellar-privacy-prover --example gen_groth16_fixture

clean:
	cargo clean
	rm -rf packages/sdk/dist packages/selective-disclosure/dist packages/dapp/dist
