#![no_std]
#![cfg_attr(test, deny(warnings))]

mod events;
mod merkle;
mod pool;
mod types;
mod verifier;

use soroban_sdk::{contract, contractimpl, Address, BytesN, Env};

use crate::types::*;

#[contract]
pub struct ShieldedPool;

#[contractimpl]
impl ShieldedPool {
    pub fn initialize(e: Env, admin: Address, verifier: Address) {
        pool::initialize(&e, &admin, &verifier);
    }

    pub fn deposit(
        e: Env,
        depositor: Address,
        token: Address,
        amount: i128,
        commitment: BytesN<32>,
    ) -> DepositEvent {
        pool::deposit(&e, &depositor, &token, amount, &commitment)
    }

    pub fn withdraw(e: Env, proof: Proof, amount: i128, token: Address) -> WithdrawalEvent {
        pool::withdraw(&e, &proof, amount, &token)
    }

    pub fn register_viewing_key(e: Env, owner: Address, viewing_key_hash: BytesN<32>) {
        pool::register_viewing_key(&e, &owner, viewing_key_hash);
    }

    pub fn authorize_viewer(e: Env, owner: Address, viewer: Address) {
        pool::authorize_viewer(&e, &owner, &viewer);
    }

    pub fn pause(e: Env) {
        pool::pause(&e);
    }

    pub fn unpause(e: Env) {
        pool::unpause(&e);
    }

    pub fn set_verifier(e: Env, new_verifier: Address) {
        pool::set_verifier(&e, &new_verifier);
    }

    pub fn get_root(e: Env) -> Option<BytesN<32>> {
        pool::get_root(&e)
    }

    pub fn is_nullifier_spent(e: Env, nullifier: BytesN<32>) -> bool {
        pool::is_nullifier_spent(&e, &nullifier)
    }

    pub fn get_pool_size(e: Env) -> u64 {
        pool::get_pool_size(&e)
    }

    pub fn version() -> u32 {
        1
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use soroban_sdk::testutils::Address as _;

    struct TestCtx {
        e: Env,
        contract_id: Address,
    }

    fn setup() -> TestCtx {
        let e = Env::default();
        e.mock_all_auths();
        let contract_id = e.register(ShieldedPool, ());
        TestCtx { e, contract_id }
    }

    fn with_contract<T>(ctx: &TestCtx, f: impl FnOnce() -> T) -> T {
        ctx.e.as_contract(&ctx.contract_id, f)
    }

    #[test]
    fn test_contract_initialization() {
        let ctx = setup();
        let admin = Address::generate(&ctx.e);
        let verifier = Address::generate(&ctx.e);

        with_contract(&ctx, || {
            ShieldedPool::initialize(ctx.e.clone(), admin.clone(), verifier.clone());
        });

        let version = ShieldedPool::version();
        assert_eq!(version, 1, "version must be 1");
    }

    #[test]
    #[should_panic(expected = "already initialized")]
    fn test_double_initialization() {
        let ctx = setup();
        let admin = Address::generate(&ctx.e);
        let verifier = Address::generate(&ctx.e);

        with_contract(&ctx, || {
            ShieldedPool::initialize(ctx.e.clone(), admin.clone(), verifier.clone());
            ShieldedPool::initialize(ctx.e.clone(), admin.clone(), verifier.clone());
        });
    }

    #[test]
    fn test_register_viewing_key() {
        let ctx = setup();
        let admin = Address::generate(&ctx.e);
        let verifier = Address::generate(&ctx.e);

        with_contract(&ctx, || {
            ShieldedPool::initialize(ctx.e.clone(), admin.clone(), verifier.clone());
        });

        let owner = Address::generate(&ctx.e);
        let key_hash = BytesN::from_array(&ctx.e, &[0xab; 32]);

        with_contract(&ctx, || {
            ShieldedPool::register_viewing_key(ctx.e.clone(), owner.clone(), key_hash.clone());
        });
    }
}
