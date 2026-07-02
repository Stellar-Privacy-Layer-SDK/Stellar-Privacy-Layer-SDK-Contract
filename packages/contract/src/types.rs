use soroban_sdk::{Address, BytesN, Vec};

pub const MERKLE_TREE_DEPTH: usize = 32;

pub type Scalar = BytesN<32>;
pub type Commitment = BytesN<32>;
pub type Nullifier = BytesN<32>;
#[allow(dead_code)]
pub type Secret = BytesN<32>;

#[derive(Clone, Debug, Eq, PartialEq)]
#[soroban_sdk::contracttype]
pub struct ShieldedTransfer {
    pub amount: i128,
    pub token: Address,
    pub recipient: Address,
    pub commitment: Commitment,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[soroban_sdk::contracttype]
pub struct Proof {
    pub proof_a: Vec<Scalar>,
    pub proof_b: Vec<Scalar>,
    pub proof_c: Vec<Scalar>,
    pub root: Scalar,
    pub nullifier: Nullifier,
    pub recipient: Address,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[soroban_sdk::contracttype]
pub struct DepositEvent {
    pub depositor: Address,
    pub commitment: Commitment,
    pub amount: i128,
    pub token: Address,
    pub timestamp: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[soroban_sdk::contracttype]
pub struct WithdrawalEvent {
    pub recipient: Address,
    pub nullifier: Nullifier,
    pub amount: i128,
    pub token: Address,
    pub timestamp: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[soroban_sdk::contracttype]
pub struct ComplianceView {
    pub owner: Address,
    pub viewing_key_hash: BytesN<32>,
    pub authorized_viewers: Vec<Address>,
}

#[derive(Clone, Debug)]
#[soroban_sdk::contracttype]
pub enum StorageKey {
    Pool,
    Commitment(Commitment),
    Nullifier(Nullifier),
    Root(Scalar),
    NextLeaf,
    MerkleTree,
    Verifier,
    Admin,
    Compliance(Address),
    Token(Address),
    Balance,
    Paused,
}
