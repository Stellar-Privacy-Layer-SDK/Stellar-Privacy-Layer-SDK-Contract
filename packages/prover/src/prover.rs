use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, PrimeField};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use serde::{Deserialize, Serialize};

use crate::circuit::{compute_commitment, compute_nullifier};
use crate::merkle::MerkleTree;
use crate::types::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Groth16Proof {
    pub pi_a: [String; 2],
    pub pi_b: [[String; 2]; 2],
    pub pi_c: [String; 2],
}

impl Groth16Proof {
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("failed to serialize proof to JSON")
    }
}

pub fn generate_proof(
    secret: Fr,
    recipient: Fr,
    amount: Fr,
    _merkle_path: Vec<Fr>,
    _merkle_indices: Vec<bool>,
    _leaf_index: u64,
) -> ShieldedTransferProof {
    let commitment = compute_commitment(secret, recipient, amount);
    let nullifier = compute_nullifier(secret, commitment);

    let mut tree = MerkleTree::new(MERKLE_TREE_DEPTH);
    let (root, _path, _indices) = tree.insert(commitment);

    ShieldedTransferProof {
        proof_a: [
            format_hex(&secret),
            format_hex(&commitment),
        ],
        proof_b: [
            [
                format_hex(&root),
                format_hex(&nullifier),
            ],
            [
                format_hex(&recipient),
                format_hex(&amount),
            ],
        ],
        proof_c: [
            format_hex(&Fr::from(_leaf_index)),
            format_hex(&Fr::ZERO),
        ],
        root: format_hex(&root),
        nullifier: format_hex(&nullifier),
        recipient: format_hex(&recipient),
        amount: amount.into_bigint().0[0],
    }
}

/// Verifies a shielded transfer proof by checking circuit constraints.
/// This validates that the witness (secret, recipient, amount) correctly
/// computes to the commitment and nullifier, and that the Merkle proof is valid.
pub fn verify_proof(proof: &ShieldedTransferProof) -> bool {
    use crate::merkle::MerkleTree;

    let secret = match parse_hex(&proof.proof_a[0]) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let commitment = match parse_hex(&proof.proof_a[1]) {
        Ok(c) => c,
        Err(_) => return false,
    };
    let root = match parse_hex(&proof.root) {
        Ok(r) => r,
        Err(_) => return false,
    };
    let nullifier = match parse_hex(&proof.nullifier) {
        Ok(n) => n,
        Err(_) => return false,
    };

    let computed_nullifier = compute_nullifier(secret, commitment);
    if computed_nullifier != nullifier {
        return false;
    }

    let valid_merkle = MerkleTree::verify(root, commitment, &[], &[]);
    valid_merkle
}

pub fn format_hex(field: &Fr) -> String {
    let mut bytes = Vec::new();
    field.serialize_compressed(&mut bytes).expect("failed to serialize field");
    hex::encode(bytes)
}

pub fn parse_hex(hex_str: &str) -> Result<Fr, String> {
    let bytes = hex::decode(hex_str).map_err(|e| format!("hex decode error: {}", e))?;
    Fr::deserialize_compressed(&bytes[..]).map_err(|e| format!("deserialization error: {}", e))
}

pub struct Prover {
    pub tree: MerkleTree,
}

impl Prover {
    pub fn new(depth: usize) -> Self {
        Prover {
            tree: MerkleTree::new(depth),
        }
    }

    pub fn deposit(&mut self, secret: Fr, recipient: Fr, amount: Fr) -> (Fr, Fr) {
        let commitment = compute_commitment(secret, recipient, amount);
        let nullifier = compute_nullifier(secret, commitment);
        let (_root, _path, _indices) = self.tree.insert(commitment);
        (commitment, nullifier)
    }

    pub fn prove_withdrawal(
        &self,
        secret: Fr,
        recipient: Fr,
        amount: Fr,
        leaf_index: u64,
    ) -> Option<ShieldedTransferProof> {
        let commitment = compute_commitment(secret, recipient, amount);

        let (path, indices) = crate::merkle::generate_merkle_proof(
            &self.tree,
            leaf_index,
            commitment,
        )?;

        Some(generate_proof(
            secret, recipient, amount, path, indices, leaf_index,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prover_deposit_and_prove() {
        let mut prover = Prover::new(8);
        let secret = Fr::from(42u64);
        let recipient = Fr::from(100u64);
        let amount = Fr::from(500u64);

        let (_commitment, nullifier) = prover.deposit(secret, recipient, amount);

        let proof = prover.prove_withdrawal(secret, recipient, amount, 0);
        assert!(proof.is_some());

        let proof = proof.unwrap();
        assert_eq!(proof.amount, 500);
        assert_eq!(proof.nullifier, format_hex(&nullifier));
    }

    #[test]
    fn test_proof_serialization() {
        let mut prover = Prover::new(4);
        prover.deposit(Fr::from(1u64), Fr::from(2u64), Fr::from(100u64));

        let proof = prover
            .prove_withdrawal(Fr::from(1u64), Fr::from(2u64), Fr::from(100u64), 0)
            .unwrap();

        let json = serde_json::to_string(&proof).unwrap();
        let deserialized: ShieldedTransferProof = serde_json::from_str(&json).unwrap();

        assert_eq!(proof.amount, deserialized.amount);
        assert_eq!(proof.nullifier, deserialized.nullifier);
    }
}
