use soroban_sdk::{Bytes, BytesN, Env, Vec};

use crate::types::*;

fn sha256_pair(e: &Env, left: &Scalar, right: &Scalar) -> Scalar {
    let mut data = Bytes::new(e);
    data.extend_from_slice(&left.to_array());
    data.extend_from_slice(&right.to_array());
    e.crypto().sha256(&data).into()
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[soroban_sdk::contracttype]
pub struct MerkleTree {
    pub root: Scalar,
    pub depth: u32,
    pub next_index: u64,
    pub filled_subtrees: Vec<Scalar>,
}

impl MerkleTree {
    pub fn new(e: &Env, depth: u32) -> Self {
        let mut zero_hashes = Vec::new(e);
        let zero = BytesN::from_array(e, &[0u8; 32]);
        let mut current = zero;
        for _ in 0..depth {
            zero_hashes.push_back(current.clone());
            current = sha256_pair(e, &current, &current);
        }

        let root = if depth > 0 {
            zero_hashes
                .get(depth - 1)
                .unwrap_or_else(|| BytesN::from_array(e, &[0u8; 32]))
        } else {
            BytesN::from_array(e, &[0u8; 32])
        };

        MerkleTree {
            root,
            depth,
            next_index: 0,
            filled_subtrees: zero_hashes,
        }
    }

    pub fn insert(e: &Env, tree: &mut MerkleTree, leaf: &Scalar) -> Scalar {
        let mut idx = tree.next_index;
        tree.next_index += 1;

        let mut current = leaf.clone();

        let mut level = 0u32;
        while level < tree.depth {
            if idx.is_multiple_of(2) {
                let zero_hash = tree
                    .filled_subtrees
                    .get(level)
                    .unwrap_or_else(|| BytesN::from_array(e, &[0u8; 32]));
                tree.filled_subtrees.set(level, current.clone());
                current = sha256_pair(e, &current, &zero_hash);
            } else {
                let left = tree
                    .filled_subtrees
                    .get(level)
                    .unwrap_or_else(|| BytesN::from_array(e, &[0u8; 32]));
                current = sha256_pair(e, &left, &current);
            }
            idx /= 2;
            level += 1;
        }

        tree.root = current.clone();
        current
    }

    pub fn verify(
        e: &Env,
        root: &Scalar,
        leaf: &Scalar,
        path: &[Scalar],
        indices: &[bool],
    ) -> bool {
        let mut current = leaf.clone();
        for (i, sibling) in path.iter().enumerate() {
            current = if i < indices.len() && indices[i] {
                sha256_pair(e, &current, sibling)
            } else {
                sha256_pair(e, sibling, &current)
            };
        }
        current == *root
    }
}
