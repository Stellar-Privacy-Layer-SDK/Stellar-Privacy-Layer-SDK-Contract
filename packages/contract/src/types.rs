use soroban_sdk::{Address, BytesN, Vec};

pub const MERKLE_TREE_DEPTH: usize = 32;

pub type Scalar = BytesN<32>;
pub type Commitment = BytesN<32>;
pub type Nullifier = BytesN<32>;
#[allow(dead_code)]
pub type Secret = BytesN<32>;

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

/// Groth16 verifying key (BLS12-381), serialized in the Soroban host-function
/// encoding (uncompressed points): 96-byte G1, 192-byte G2, 32-byte scalars.
#[derive(Clone, Debug, Eq, PartialEq)]
#[soroban_sdk::contracttype]
pub struct Groth16Vk {
    pub alpha_g1: BytesN<96>,
    pub beta_g2: BytesN<192>,
    pub gamma_g2: BytesN<192>,
    pub delta_g2: BytesN<192>,
    /// `γ_abc[0] + Σᵢ pub[i]·γ_abc[i+1]`; length = public inputs + 1.
    pub gamma_abc_g1: Vec<BytesN<96>>,
}

/// Groth16 proof (BLS12-381) plus the withdrawal recipient.
///
/// Convention for the shielded-transfer demo circuit:
/// `public_inputs = [commitment, nullifier]` (32-byte `Fr` scalars).
#[derive(Clone, Debug, Eq, PartialEq)]
#[soroban_sdk::contracttype]
pub struct Groth16Proof {
    pub a: BytesN<96>,
    pub b: BytesN<192>,
    pub c: BytesN<96>,
    pub public_inputs: Vec<BytesN<32>>,
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
    Commitment(Commitment),
    Nullifier(Nullifier),
    Root(Scalar),
    NextLeaf,
    MerkleTree,
    Verifier,
    Admin,
    Compliance(Address),
    Paused,
    Groth16Vk,
}
