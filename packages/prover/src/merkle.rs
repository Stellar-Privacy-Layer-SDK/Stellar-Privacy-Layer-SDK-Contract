use ark_bn254::Fr;
use ark_ff::AdditiveGroup;

use crate::poseidon::Poseidon;

pub fn poseidon_hash(left: Fr, right: Fr) -> Fr {
    let poseidon = Poseidon::new();
    let inputs = vec![left, right];
    poseidon.hash(inputs).unwrap()
}

pub struct MerkleTree {
    pub levels: Vec<Vec<Fr>>,
    pub depth: usize,
    pub root: Fr,
}

impl MerkleTree {
    pub fn new(depth: usize) -> Self {
        let empty = Fr::ZERO;
        let mut levels = Vec::with_capacity(depth);

        levels.push(Vec::new());

        let mut current = empty;
        for _ in 1..depth {
            let level = vec![current];
            levels.push(level);
            current = poseidon_hash(current, current);
        }

        MerkleTree {
            levels,
            depth,
            root: current,
        }
    }

    pub fn insert(&mut self, leaf: Fr) -> (Fr, Vec<Fr>, Vec<bool>) {
        let mut idx = self.levels[0].len();
        self.levels[0].push(leaf);

        let mut path = Vec::with_capacity(self.depth);
        let mut indices = Vec::with_capacity(self.depth);

        let mut current = leaf;
        for level in 0..self.depth {
            let sibling = if idx.is_multiple_of(2) {
                if idx + 1 < self.levels[level].len() {
                    self.levels[level][idx + 1]
                } else {
                    Fr::ZERO
                }
            } else {
                if idx > 0 {
                    self.levels[level][idx - 1]
                } else {
                    Fr::ZERO
                }
            };

            path.push(sibling);
            indices.push(!idx.is_multiple_of(2));

            current = if idx.is_multiple_of(2) {
                poseidon_hash(current, sibling)
            } else {
                poseidon_hash(sibling, current)
            };

            idx /= 2;

            if level + 1 < self.depth {
                if self.levels[level + 1].len() <= idx {
                    self.levels[level + 1].push(Fr::ZERO);
                }
                self.levels[level + 1][idx] = current;
            }
        }

        self.root = current;
        (current, path, indices)
    }

    pub fn verify(root: Fr, leaf: Fr, path: &[Fr], indices: &[bool]) -> bool {
        let mut current = leaf;
        for (i, sibling) in path.iter().enumerate() {
            current = if i < indices.len() && indices[i] {
                poseidon_hash(*sibling, current)
            } else {
                poseidon_hash(current, *sibling)
            };
        }
        current == root
    }
}

pub fn generate_merkle_proof(
    tree: &MerkleTree,
    leaf_index: u64,
    _leaf: Fr,
) -> Option<(Vec<Fr>, Vec<bool>)> {
    let mut idx = leaf_index as usize;
    let mut path = Vec::with_capacity(tree.depth);
    let mut indices = Vec::with_capacity(tree.depth);

    for level in 0..tree.depth {
        if idx >= tree.levels[level].len() {
            return None;
        }

        let sibling = if idx.is_multiple_of(2) {
            if idx + 1 < tree.levels[level].len() {
                tree.levels[level][idx + 1]
            } else {
                Fr::ZERO
            }
        } else {
            if idx > 0 {
                tree.levels[level][idx - 1]
            } else {
                Fr::ZERO
            }
        };

        path.push(sibling);
        indices.push(!idx.is_multiple_of(2));
        idx /= 2;
    }

    Some((path, indices))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_insert_and_verify() {
        let mut tree = MerkleTree::new(8);
        let leaf = Fr::from(42u64);

        let (new_root, path, indices) = tree.insert(leaf);
        assert!(MerkleTree::verify(new_root, leaf, &path, &indices));
    }

    #[test]
    fn test_merkle_different_roots() {
        let mut tree1 = MerkleTree::new(8);
        let mut tree2 = MerkleTree::new(8);

        let root1 = tree1.insert(Fr::from(1u64)).0;
        let root2 = tree2.insert(Fr::from(2u64)).0;

        assert_ne!(root1, root2);
    }

    #[test]
    fn test_generate_merkle_proof() {
        let mut tree = MerkleTree::new(8);
        let leaf = Fr::from(100u64);
        tree.insert(leaf);

        let proof = generate_merkle_proof(&tree, 0, leaf);
        assert!(proof.is_some());

        let (path, indices) = proof.unwrap();
        assert_eq!(path.len(), 8);
        assert_eq!(indices.len(), 8);

        assert!(MerkleTree::verify(tree.root, leaf, &path, &indices));
    }

    #[test]
    fn test_insert_multiple_leaves() {
        let mut tree = MerkleTree::new(4);
        for i in 0..5 {
            let leaf = Fr::from(i as u64);
            tree.insert(leaf);
        }

        for i in 0..5 {
            let leaf = Fr::from(i as u64);
            let proof = generate_merkle_proof(&tree, i as u64, leaf);
            assert!(proof.is_some());
            let (path, indices) = proof.unwrap();
            assert!(MerkleTree::verify(tree.root, leaf, &path, &indices));
        }
    }

    #[test]
    fn test_verify_invalid_leaf() {
        let mut tree = MerkleTree::new(4);
        tree.insert(Fr::from(42u64));
        let (path, indices) = generate_merkle_proof(&tree, 0, Fr::from(42u64)).unwrap();
        assert!(!MerkleTree::verify(
            tree.root,
            Fr::from(99u64),
            &path,
            &indices
        ));
    }
}
