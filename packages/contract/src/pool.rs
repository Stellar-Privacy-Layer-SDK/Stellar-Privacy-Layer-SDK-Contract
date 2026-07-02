use soroban_sdk::{token::Client as TokenClient, Address, BytesN, Env, Vec};

use crate::events::*;
use crate::merkle::*;
use crate::types::*;
use crate::verifier::*;

const MAX_DEPOSITS: usize = 65536;

pub fn initialize(e: &Env, admin: &Address, verifier: &Address) {
    if e.storage().instance().has(&StorageKey::Admin) {
        panic!("already initialized");
    }

    e.storage().instance().set(&StorageKey::Admin, admin);
    e.storage().instance().set(&StorageKey::Verifier, verifier);
    e.storage().instance().set(&StorageKey::Paused, &false);

    let depth: u32 = MERKLE_TREE_DEPTH.try_into().expect("depth too large");
    let merkle = MerkleTree::new(e, depth);
    e.storage()
        .instance()
        .set(&StorageKey::Root(merkle.root.clone()), &true);
    e.storage().instance().set(&StorageKey::NextLeaf, &0u64);
    e.storage().instance().set(&StorageKey::MerkleTree, &merkle);
}

pub fn deposit(
    e: &Env,
    depositor: &Address,
    token: &Address,
    amount: i128,
    commitment: &Commitment,
) -> DepositEvent {
    assert_not_paused(e);
    depositor.require_auth();

    if amount <= 0 {
        panic!("amount must be positive");
    }

    if e.storage()
        .instance()
        .has(&StorageKey::Commitment(commitment.clone()))
    {
        panic!("commitment already exists");
    }

    let next_leaf: u64 = e
        .storage()
        .instance()
        .get(&StorageKey::NextLeaf)
        .unwrap_or(0);
    if next_leaf as usize >= MAX_DEPOSITS {
        panic!("pool full");
    }

    let mut merkle: MerkleTree = e.storage().instance().get(&StorageKey::MerkleTree).unwrap();

    let leaf = commitment.clone();
    let new_root = MerkleTree::insert(e, &mut merkle, &leaf);

    e.storage().instance().set(&StorageKey::MerkleTree, &merkle);
    e.storage()
        .instance()
        .set(&StorageKey::NextLeaf, &(next_leaf + 1));
    e.storage()
        .instance()
        .set(&StorageKey::Commitment(commitment.clone()), &true);
    e.storage()
        .instance()
        .set(&StorageKey::Root(new_root.clone()), &true);

    let token_client = TokenClient::new(e, token);
    token_client.transfer(depositor, &e.current_contract_address(), &amount);

    let event = DepositEvent {
        depositor: depositor.clone(),
        commitment: commitment.clone(),
        amount,
        token: token.clone(),
        timestamp: e.ledger().timestamp(),
    };

    emit_deposit(e, &event);
    event
}

pub fn withdraw(e: &Env, proof: &Proof, amount: i128, token: &Address) -> WithdrawalEvent {
    assert_not_paused(e);

    if e.storage()
        .instance()
        .has(&StorageKey::Nullifier(proof.nullifier.clone()))
    {
        panic!("nullifier already spent");
    }

    if !e
        .storage()
        .instance()
        .has(&StorageKey::Root(proof.root.clone()))
    {
        panic!("unknown root");
    }

    if !verify_shielded_transfer(e, proof, amount) {
        panic!("invalid proof");
    }

    e.storage()
        .instance()
        .set(&StorageKey::Nullifier(proof.nullifier.clone()), &true);

    let token_client = TokenClient::new(e, token);
    token_client.transfer(&e.current_contract_address(), &proof.recipient, &amount);

    let event = WithdrawalEvent {
        recipient: proof.recipient.clone(),
        nullifier: proof.nullifier.clone(),
        amount,
        token: token.clone(),
        timestamp: e.ledger().timestamp(),
    };

    emit_withdrawal(e, &event);
    event
}

pub fn register_viewing_key(e: &Env, owner: &Address, viewing_key_hash: BytesN<32>) {
    owner.require_auth();

    let compliance = ComplianceView {
        owner: owner.clone(),
        viewing_key_hash: viewing_key_hash.clone(),
        authorized_viewers: Vec::new(e),
    };

    e.storage()
        .instance()
        .set(&StorageKey::Compliance(owner.clone()), &compliance);
}

pub fn authorize_viewer(e: &Env, owner: &Address, viewer: &Address) {
    owner.require_auth();

    let mut compliance: ComplianceView = e
        .storage()
        .instance()
        .get(&StorageKey::Compliance(owner.clone()))
        .unwrap_or(ComplianceView {
            owner: owner.clone(),
            viewing_key_hash: BytesN::from_array(e, &[0u8; 32]),
            authorized_viewers: Vec::new(e),
        });

    compliance.authorized_viewers.push_back(viewer.clone());
    e.storage()
        .instance()
        .set(&StorageKey::Compliance(owner.clone()), &compliance);

    emit_compliance_set(e, owner, viewer);
}

pub fn pause(e: &Env) {
    let admin: Address = e
        .storage()
        .instance()
        .get(&StorageKey::Admin)
        .expect("contract not initialized");
    admin.require_auth();
    e.storage().instance().set(&StorageKey::Paused, &true);
}

pub fn unpause(e: &Env) {
    let admin: Address = e
        .storage()
        .instance()
        .get(&StorageKey::Admin)
        .expect("contract not initialized");
    admin.require_auth();
    e.storage().instance().set(&StorageKey::Paused, &false);
}

pub fn set_verifier(e: &Env, new_verifier: &Address) {
    let admin: Address = e
        .storage()
        .instance()
        .get(&StorageKey::Admin)
        .expect("contract not initialized");
    admin.require_auth();
    e.storage()
        .instance()
        .set(&StorageKey::Verifier, new_verifier);
}

pub fn get_root(e: &Env) -> Option<Scalar> {
    let merkle: MerkleTree = e.storage().instance().get(&StorageKey::MerkleTree)?;
    Some(merkle.root)
}

pub fn is_nullifier_spent(e: &Env, nullifier: &Nullifier) -> bool {
    e.storage()
        .instance()
        .has(&StorageKey::Nullifier(nullifier.clone()))
}

pub fn get_pool_size(e: &Env) -> u64 {
    e.storage()
        .instance()
        .get(&StorageKey::NextLeaf)
        .unwrap_or(0)
}

fn assert_not_paused(e: &Env) {
    if e.storage()
        .instance()
        .get::<_, bool>(&StorageKey::Paused)
        .unwrap_or(false)
    {
        panic!("contract is paused");
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::ShieldedPool;
    use soroban_sdk::testutils::{Address as _, Ledger, LedgerInfo};

    struct TestContext {
        e: soroban_sdk::Env,
        contract_id: Address,
        admin: Address,
        verifier: Address,
        user: Address,
    }

    fn setup_env() -> TestContext {
        let e = soroban_sdk::Env::default();
        e.mock_all_auths();
        e.ledger().set(LedgerInfo {
            timestamp: 12345,
            protocol_version: 22,
            sequence_number: 1000,
            network_id: [0; 32],
            base_reserve: 10,
            min_temp_entry_ttl: 100,
            min_persistent_entry_ttl: 100,
            max_entry_ttl: 100,
        });

        let admin = Address::generate(&e);
        let verifier = Address::generate(&e);
        let user = Address::generate(&e);
        let contract_id = e.register(ShieldedPool, ());

        e.as_contract(&contract_id, || {
            ShieldedPool::initialize(e.clone(), admin.clone(), verifier.clone());
        });

        TestContext {
            e,
            contract_id,
            admin,
            verifier,
            user,
        }
    }

    fn with_contract<T>(ctx: &TestContext, f: impl FnOnce() -> T) -> T {
        ctx.e.as_contract(&ctx.contract_id, f)
    }

    fn make_proof_vec(e: &soroban_sdk::Env, vals: &[[u8; 32]]) -> Vec<Scalar> {
        let mut v = Vec::new(e);
        for val in vals {
            v.push_back(BytesN::from_array(e, val));
        }
        v
    }

    #[test]
    fn test_pool_initialization() {
        let ctx = setup_env();
        with_contract(&ctx, || {
            assert!(ShieldedPool::get_root(ctx.e.clone()).is_some());
            assert_eq!(ShieldedPool::get_pool_size(ctx.e.clone()), 0);
        });
    }

    #[test]
    fn test_prevent_double_nullifier() {
        let ctx = setup_env();

        let nullifier = BytesN::from_array(&ctx.e, &[42u8; 32]);
        with_contract(&ctx, || {
            assert!(!ShieldedPool::is_nullifier_spent(
                ctx.e.clone(),
                nullifier.clone()
            ));
            ctx.e
                .storage()
                .instance()
                .set(&StorageKey::Nullifier(nullifier.clone()), &true);
            assert!(ShieldedPool::is_nullifier_spent(ctx.e.clone(), nullifier));
        });
    }

    #[test]
    fn test_set_verifier() {
        let ctx = setup_env();

        let new_verifier = Address::generate(&ctx.e);
        with_contract(&ctx, || {
            ShieldedPool::set_verifier(ctx.e.clone(), new_verifier.clone());
        });

        let stored: Address = with_contract(&ctx, || {
            ctx.e
                .storage()
                .instance()
                .get(&StorageKey::Verifier)
                .unwrap()
        });
        assert_eq!(stored, new_verifier);
    }

    #[test]
    fn test_get_pool_size() {
        let ctx = setup_env();
        with_contract(&ctx, || {
            assert_eq!(ShieldedPool::get_pool_size(ctx.e.clone()), 0);
        });
    }

    #[test]
    #[should_panic(expected = "amount must be positive")]
    fn test_deposit_rejects_zero_amount() {
        let ctx = setup_env();
        let token = Address::generate(&ctx.e);
        let commitment = BytesN::from_array(&ctx.e, &[2u8; 32]);
        with_contract(&ctx, || {
            ShieldedPool::deposit(ctx.e.clone(), ctx.user.clone(), token, 0, commitment);
        });
    }

    #[test]
    #[should_panic(expected = "contract is paused")]
    fn test_deposit_rejects_when_paused() {
        let ctx = setup_env();
        with_contract(&ctx, || {
            ShieldedPool::pause(ctx.e.clone());
        });
        let token = Address::generate(&ctx.e);
        let commitment = BytesN::from_array(&ctx.e, &[4u8; 32]);
        with_contract(&ctx, || {
            ShieldedPool::deposit(ctx.e.clone(), ctx.user.clone(), token, 100, commitment);
        });
    }

    #[test]
    fn test_pause_and_unpause() {
        let ctx = setup_env();

        with_contract(&ctx, || {
            ShieldedPool::pause(ctx.e.clone());
        });
        with_contract(&ctx, || {
            assert!(ctx
                .e
                .storage()
                .instance()
                .get::<_, bool>(&StorageKey::Paused)
                .unwrap_or(false));
        });
        with_contract(&ctx, || {
            ShieldedPool::unpause(ctx.e.clone());
        });
        with_contract(&ctx, || {
            assert!(!ctx
                .e
                .storage()
                .instance()
                .get::<_, bool>(&StorageKey::Paused)
                .unwrap_or(true));
        });
    }

    #[test]
    #[should_panic(expected = "already initialized")]
    fn test_double_initialization_guard() {
        let ctx = setup_env();

        with_contract(&ctx, || {
            ShieldedPool::initialize(ctx.e.clone(), ctx.admin.clone(), ctx.verifier.clone());
        });
    }

    #[test]
    fn test_register_viewing_key_integration() {
        let ctx = setup_env();

        let key_hash = BytesN::from_array(&ctx.e, &[0xab; 32]);
        with_contract(&ctx, || {
            ShieldedPool::register_viewing_key(ctx.e.clone(), ctx.user.clone(), key_hash.clone());
        });

        let stored: ComplianceView = with_contract(&ctx, || {
            ctx.e
                .storage()
                .instance()
                .get(&StorageKey::Compliance(ctx.user.clone()))
                .unwrap()
        });
        assert_eq!(stored.owner, ctx.user);
        assert_eq!(stored.viewing_key_hash, key_hash);
    }

    #[test]
    fn test_authorize_viewer() {
        let ctx = setup_env();

        let viewer = Address::generate(&ctx.e);
        let key_hash = BytesN::from_array(&ctx.e, &[0xab; 32]);
        with_contract(&ctx, || {
            ShieldedPool::register_viewing_key(ctx.e.clone(), ctx.user.clone(), key_hash);
        });
        with_contract(&ctx, || {
            ShieldedPool::authorize_viewer(ctx.e.clone(), ctx.user.clone(), viewer);
        });
    }

    #[test]
    #[should_panic(expected = "unknown root")]
    fn test_withdraw_rejects_unknown_root() {
        let ctx = setup_env();
        let recipient = Address::generate(&ctx.e);
        let proof = Proof {
            proof_a: make_proof_vec(&ctx.e, &[[1u8; 32], [2u8; 32]]),
            proof_b: make_proof_vec(&ctx.e, &[[3u8; 32], [4u8; 32], [5u8; 32], [6u8; 32]]),
            proof_c: make_proof_vec(&ctx.e, &[[7u8; 32], [8u8; 32]]),
            root: BytesN::from_array(&ctx.e, &[0xff; 32]),
            nullifier: BytesN::from_array(&ctx.e, &[9u8; 32]),
            recipient,
        };
        with_contract(&ctx, || {
            ShieldedPool::withdraw(ctx.e.clone(), proof, 100, Address::generate(&ctx.e));
        });
    }

    #[test]
    #[should_panic(expected = "nullifier already spent")]
    fn test_withdraw_rejects_double_spend_nullifier() {
        let ctx = setup_env();
        let nullifier = BytesN::from_array(&ctx.e, &[10u8; 32]);
        with_contract(&ctx, || {
            ctx.e
                .storage()
                .instance()
                .set(&StorageKey::Nullifier(nullifier.clone()), &true);
        });
        let recipient = Address::generate(&ctx.e);
        let root = with_contract(&ctx, || ShieldedPool::get_root(ctx.e.clone()).unwrap());
        let proof = Proof {
            proof_a: make_proof_vec(&ctx.e, &[[1u8; 32], [2u8; 32]]),
            proof_b: make_proof_vec(&ctx.e, &[[3u8; 32], [4u8; 32], [5u8; 32], [6u8; 32]]),
            proof_c: make_proof_vec(&ctx.e, &[[7u8; 32], [8u8; 32]]),
            root,
            nullifier,
            recipient,
        };
        with_contract(&ctx, || {
            ShieldedPool::withdraw(ctx.e.clone(), proof, 100, Address::generate(&ctx.e));
        });
    }

    #[test]
    #[should_panic(expected = "contract is paused")]
    fn test_withdraw_rejects_when_paused() {
        let ctx = setup_env();
        with_contract(&ctx, || {
            ShieldedPool::pause(ctx.e.clone());
        });
        let recipient = Address::generate(&ctx.e);
        let proof = Proof {
            proof_a: make_proof_vec(&ctx.e, &[[1u8; 32], [2u8; 32]]),
            proof_b: make_proof_vec(&ctx.e, &[[3u8; 32], [4u8; 32], [5u8; 32], [6u8; 32]]),
            proof_c: make_proof_vec(&ctx.e, &[[7u8; 32], [8u8; 32]]),
            root: BytesN::from_array(&ctx.e, &[1u8; 32]),
            nullifier: BytesN::from_array(&ctx.e, &[2u8; 32]),
            recipient,
        };
        with_contract(&ctx, || {
            ShieldedPool::withdraw(ctx.e.clone(), proof, 100, Address::generate(&ctx.e));
        });
    }
}
