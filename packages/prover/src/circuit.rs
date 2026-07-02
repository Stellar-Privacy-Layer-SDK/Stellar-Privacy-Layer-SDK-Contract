use ark_bn254::Fr;

use crate::poseidon::Poseidon;
use crate::types::*;

pub fn compute_commitment(secret: Fr, recipient: Fr, amount: Fr) -> Fr {
    let poseidon = Poseidon::new();
    let intermediate = poseidon.hash(vec![secret, recipient]).unwrap();
    poseidon.hash(vec![intermediate, amount]).unwrap()
}

pub fn compute_nullifier(secret: Fr, commitment: Fr) -> Fr {
    let poseidon = Poseidon::new();
    let inputs = vec![secret, commitment];
    poseidon.hash(inputs).unwrap()
}

pub fn generate_witness(inputs: &ProofInputs) -> Option<Witness> {
    let computed_commitment = compute_commitment(
        inputs.secret,
        inputs.recipient,
        inputs.amount,
    );

    let computed_nullifier = compute_nullifier(inputs.secret, computed_commitment);

    if computed_nullifier != inputs.nullifier {
        return None;
    }

    Some(Witness {
        secret: inputs.secret,
        recipient: inputs.recipient,
        amount: inputs.amount,
        merkle_path: inputs.merkle_path.clone(),
        merkle_indices: inputs.merkle_indices.clone(),
        leaf_index: inputs.leaf_index,
    })
}

pub fn generate_public_inputs(root: Fr, nullifier: Fr, recipient: Fr, amount: Fr) -> PublicInputs {
    PublicInputs {
        root,
        nullifier,
        recipient,
        amount,
    }
}

pub fn verify_circuit_constraints(witness: &Witness, public: &PublicInputs) -> bool {
    let committed = compute_commitment(witness.secret, witness.recipient, witness.amount);
    let nullifier_computed = compute_nullifier(witness.secret, committed);

    if nullifier_computed != public.nullifier {
        return false;
    }

    let leaf = committed;
    crate::merkle::MerkleTree::verify(
        public.root,
        leaf,
        &witness.merkle_path,
        &witness.merkle_indices,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::MerkleTree;
    use ark_ff::AdditiveGroup;

    #[test]
    fn test_circuit_constraints_valid() {
        let mut tree = MerkleTree::new(4);
        let secret = Fr::from(12345u64);
        let recipient = Fr::from(67890u64);
        let amount = Fr::from(1000u64);

        let commitment = compute_commitment(secret, recipient, amount);
        let nullifier = compute_nullifier(secret, commitment);

        let (root, path, indices) = tree.insert(commitment);

        let witness = Witness {
            secret,
            recipient,
            amount,
            merkle_path: path,
            merkle_indices: indices,
            leaf_index: 0,
        };

        let public = PublicInputs {
            root,
            nullifier,
            recipient,
            amount,
        };

        assert!(verify_circuit_constraints(&witness, &public));
    }

    #[test]
    fn test_circuit_constraints_invalid_secret() {
        let mut tree = MerkleTree::new(4);
        let secret = Fr::from(12345u64);
        let recipient = Fr::from(67890u64);
        let amount = Fr::from(1000u64);

        let commitment = compute_commitment(secret, recipient, amount);
        let (root, path, indices) = tree.insert(commitment);

        let wrong_nullifier = Fr::from(99999u64);

        let witness = Witness {
            secret: Fr::from(99999u64),
            recipient,
            amount,
            merkle_path: path,
            merkle_indices: indices,
            leaf_index: 0,
        };

        let public = PublicInputs {
            root,
            nullifier: wrong_nullifier,
            recipient,
            amount,
        };

        assert!(!verify_circuit_constraints(&witness, &public));
    }

    #[test]
    fn test_commitment_determinism() {
        let c1 = compute_commitment(Fr::from(1u64), Fr::from(2u64), Fr::from(3u64));
        let c2 = compute_commitment(Fr::from(1u64), Fr::from(2u64), Fr::from(3u64));
        assert_eq!(c1, c2);
    }

    #[test]
    fn test_nullifier_non_identity() {
        let n = compute_nullifier(Fr::from(1u64), Fr::from(2u64));
        assert_ne!(n, Fr::ZERO, "nullifier should not be zero");
    }

    #[test]
    fn test_generate_witness_returns_none_on_mismatch() {
        let inputs = ProofInputs {
            secret: Fr::from(1u64),
            recipient: Fr::from(2u64),
            amount: Fr::from(3u64),
            merkle_path: vec![],
            merkle_indices: vec![],
            root: Fr::ZERO,
            nullifier: Fr::from(999u64),
            commitment: Fr::ZERO,
            leaf_index: 0,
        };

        assert!(generate_witness(&inputs).is_none());
    }

    #[test]
    fn test_verify_circuit_constraints_rejects_bad_merkle() {
        let secret = Fr::from(42u64);
        let recipient = Fr::from(100u64);
        let amount = Fr::from(500u64);

        let commitment = compute_commitment(secret, recipient, amount);
        let nullifier = compute_nullifier(secret, commitment);

        let witness = Witness {
            secret,
            recipient,
            amount,
            merkle_path: vec![Fr::from(99u64)],
            merkle_indices: vec![false],
            leaf_index: 0,
        };

        let public = PublicInputs {
            root: Fr::from(12345u64),
            nullifier,
            recipient,
            amount,
        };

        assert!(!verify_circuit_constraints(&witness, &public));
    }
}
