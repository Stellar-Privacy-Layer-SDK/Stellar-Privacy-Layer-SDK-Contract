use serde::{Deserialize, Serialize};

pub const MERKLE_TREE_DEPTH: usize = 32;
pub const FIELD_BYTES: usize = 32;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShieldedTransferProof {
    pub proof_a: [String; 2],
    pub proof_b: [[String; 2]; 2],
    pub proof_c: [String; 2],
    pub root: String,
    pub nullifier: String,
    pub recipient: String,
    pub amount: u64,
}

#[derive(Debug, Clone)]
pub struct ProofInputs {
    pub secret: ark_bn254::Fr,
    pub recipient: ark_bn254::Fr,
    pub amount: ark_bn254::Fr,
    pub merkle_path: Vec<ark_bn254::Fr>,
    pub merkle_indices: Vec<bool>,
    pub root: ark_bn254::Fr,
    pub nullifier: ark_bn254::Fr,
    pub commitment: ark_bn254::Fr,
    pub leaf_index: u64,
}

#[derive(Debug, Clone)]
pub struct Witness {
    pub secret: ark_bn254::Fr,
    pub recipient: ark_bn254::Fr,
    pub amount: ark_bn254::Fr,
    pub merkle_path: Vec<ark_bn254::Fr>,
    pub merkle_indices: Vec<bool>,
    pub leaf_index: u64,
}

#[derive(Debug, Clone)]
pub struct PublicInputs {
    pub root: ark_bn254::Fr,
    pub nullifier: ark_bn254::Fr,
    pub recipient: ark_bn254::Fr,
    pub amount: ark_bn254::Fr,
}
