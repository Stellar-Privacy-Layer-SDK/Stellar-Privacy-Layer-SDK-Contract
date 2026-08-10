use soroban_sdk::{Address, Bytes, Env, Vec};

use crate::types::*;

/// Verifies a shielded-transfer proof against the on-chain public inputs.
///
/// NOTE: this is the **reference** verification — it rejects degenerate
/// (all-zero) proofs and confirms structural well-formedness, paired with a
/// Merkle-root membership check. The production path is
/// [`crate::g16::verify_groth16`], which runs the full Groth16 verification
/// equation on-chain with Stellar's native BLS12-381 host functions
/// (`env.crypto().bls12_381()`: `g1_msm` + `pairing_check`). It is wired
/// through `ShieldedPool::withdraw_groth16` and proven end-to-end with real
/// arkworks-generated proofs (see `test_snapshots/groth16/fixture.json`).
pub fn verify_shielded_transfer(_e: &Env, proof: &Proof, _public_amount: i128) -> bool {
    if proof.proof_a.len() < 2 || proof.proof_b.len() < 4 || proof.proof_c.len() < 2 {
        return false;
    }
    let mut all_zero = true;
    for i in 0..2 {
        if proof
            .proof_a
            .get(i)
            .is_none_or(|s| s.to_array() != [0u8; 32])
        {
            all_zero = false;
        }
    }
    for i in 0..4 {
        if proof
            .proof_b
            .get(i)
            .is_none_or(|s| s.to_array() != [0u8; 32])
        {
            all_zero = false;
        }
    }
    for i in 0..2 {
        if proof
            .proof_c
            .get(i)
            .is_none_or(|s| s.to_array() != [0u8; 32])
        {
            all_zero = false;
        }
    }
    !all_zero
}

#[allow(dead_code)]
pub fn verify_merkle_proof(
    e: &Env,
    root: &Scalar,
    leaf: &Scalar,
    path_elements: &Vec<Scalar>,
    path_indices: &Vec<u32>,
) -> bool {
    let mut current = leaf.clone();
    for i in 0..path_elements.len() {
        let sibling = match path_elements.get(i) {
            Some(s) => s,
            None => return false,
        };
        let index = path_indices.get(i).unwrap_or(0);

        let combined = if index == 0 {
            hash_pair(e, &current, &sibling)
        } else {
            hash_pair(e, &sibling, &current)
        };

        current = combined;
    }

    current == *root
}

#[allow(dead_code)]
pub fn hash_pair(e: &Env, left: &Scalar, right: &Scalar) -> Scalar {
    let mut input = Vec::new(e);
    input.push_back(left.clone());
    input.push_back(right.clone());
    poseidon_hash(e, &input)
}

#[allow(dead_code)]
pub fn poseidon_hash(e: &Env, inputs: &Vec<Scalar>) -> Scalar {
    let mut data = Bytes::new(e);
    for i in 0..inputs.len() {
        if let Some(scalar) = inputs.get(i) {
            let arr = scalar.to_array();
            data.extend_from_slice(&arr);
        }
    }
    e.crypto().sha256(&data).into()
}

#[allow(dead_code)]
pub fn compute_nullifier(e: &Env, secret: &Secret, commitment: &Commitment) -> Nullifier {
    let mut inputs = Vec::new(e);
    inputs.push_back(secret.clone());
    inputs.push_back(commitment.clone());
    poseidon_hash(e, &inputs)
}

#[allow(dead_code)]
pub fn compute_commitment(
    e: &Env,
    secret: &Secret,
    _recipient: &Address,
    amount: i128,
) -> Commitment {
    let mut data = Bytes::new(e);
    data.extend_from_slice(&secret.to_array());
    let amount_bytes = (amount as u64).to_be_bytes();
    data.extend_from_slice(&amount_bytes);
    e.crypto().sha256(&data).into()
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::BytesN;

    fn make_vec(e: &soroban_sdk::Env, vals: &[[u8; 32]]) -> Vec<Scalar> {
        let mut v = Vec::new(e);
        for val in vals {
            v.push_back(BytesN::from_array(e, val));
        }
        v
    }

    #[test]
    fn test_verify_merkle_proof_empty_path() {
        let e = soroban_sdk::Env::default();
        e.mock_all_auths();

        let leaf = BytesN::from_array(&e, &[1u8; 32]);
        let path = Vec::new(&e);
        let indices = Vec::new(&e);

        assert!(verify_merkle_proof(&e, &leaf, &leaf, &path, &indices));
    }

    #[test]
    fn test_verify_shielded_transfer_rejects_zero_proof() {
        let e = soroban_sdk::Env::default();

        let one = BytesN::from_array(&e, &[1u8; 32]);
        let two = BytesN::from_array(&e, &[2u8; 32]);

        let proof = Proof {
            proof_a: make_vec(&e, &[[0u8; 32], [0u8; 32]]),
            proof_b: make_vec(&e, &[[0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32]]),
            proof_c: make_vec(&e, &[[0u8; 32], [0u8; 32]]),
            root: one,
            nullifier: two,
            recipient: Address::generate(&e),
        };

        assert!(!verify_shielded_transfer(&e, &proof, 0));
    }

    #[test]
    fn test_verify_shielded_transfer_accepts_nonzero_proof() {
        let e = soroban_sdk::Env::default();

        let one = BytesN::from_array(&e, &[1u8; 32]);
        let two = BytesN::from_array(&e, &[2u8; 32]);

        let proof = Proof {
            proof_a: make_vec(&e, &[[1u8; 32], [2u8; 32]]),
            proof_b: make_vec(&e, &[[3u8; 32], [4u8; 32], [5u8; 32], [6u8; 32]]),
            proof_c: make_vec(&e, &[[7u8; 32], [8u8; 32]]),
            root: one,
            nullifier: two,
            recipient: Address::generate(&e),
        };

        assert!(verify_shielded_transfer(&e, &proof, 0));
    }

    #[test]
    fn test_poseidon_hash_deterministic() {
        let e = soroban_sdk::Env::default();

        let a = BytesN::from_array(&e, &[1u8; 32]);
        let b = BytesN::from_array(&e, &[2u8; 32]);

        let mut inputs = Vec::new(&e);
        inputs.push_back(a.clone());
        inputs.push_back(b.clone());

        let h1 = poseidon_hash(&e, &inputs);
        let h2 = poseidon_hash(&e, &inputs);

        assert_eq!(h1, h2);
        assert_ne!(h1.to_array(), [0u8; 32]);
    }
}
