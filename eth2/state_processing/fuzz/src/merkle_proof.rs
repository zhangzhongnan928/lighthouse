// This code is not maintain and was copied from
// https://github.com/michaelsproul/lighthouse/blob/fd2131008667d77405d6080ad0afa2fc96bfa8ee/eth2/utils/merkle_proof/src/lib.rs#L46
// At some point it should be merge into lighthouse master and this file deleted.

use hashing::hash;
use types::*;

const MAX_TREE_DEPTH: usize = 32;
const EMPTY_SLICE: &[Hash256] = &[];

lazy_static! {
    /// Cached zero hashes where `ZERO_HASHES[i]` is the hash of a Merkle tree with 2^i zero leaves.
    static ref ZERO_HASHES: Vec<Hash256> = {
        let mut hashes = vec![Hash256::from([0; 32]); MAX_TREE_DEPTH + 1];

        for i in 0..MAX_TREE_DEPTH {
            hashes[i + 1] = hash_concat(hashes[i], hashes[i]);
        }

        hashes
    };

    /// Zero nodes to act as "synthetic" left and right subtrees of other zero nodes.
    static ref ZERO_NODES: Vec<MerkleTree> = {
        (0..MAX_TREE_DEPTH + 1).map(MerkleTree::Zero).collect()
    };
}

/// Right-sparse Merkle tree.
///
/// Efficiently represents a Merkle tree of fixed depth where only the first N
/// indices are populated by non-zero leaves (perfect for the deposit contract tree).
#[derive(Debug)]
pub enum MerkleTree {
    /// Leaf node with the hash of its content.
    Leaf(Hash256),
    /// Internal node with hash, left subtree and right subtree.
    Node(Hash256, Box<Self>, Box<Self>),
    /// Zero subtree of a given depth.
    ///
    /// It represents a Merkle tree of 2^depth zero leaves.
    Zero(usize),
}

impl MerkleTree {
    /// Create a new Merkle tree from a list of leaves and a fixed depth.
    pub fn create(leaves: &[Hash256], depth: usize) -> Self {
        use MerkleTree::*;

        if leaves.is_empty() {
            return Zero(depth);
        }

        match depth {
            0 => {
                debug_assert_eq!(leaves.len(), 1);
                Leaf(leaves[0])
            }
            _ => {
                // Split leaves into left and right subtrees
                let subtree_capacity = 2usize.pow(depth as u32 - 1);
                let (left_leaves, right_leaves) = if leaves.len() <= subtree_capacity {
                    (leaves, EMPTY_SLICE)
                } else {
                    leaves.split_at(subtree_capacity)
                };

                let left_subtree = MerkleTree::create(left_leaves, depth - 1);
                let right_subtree = MerkleTree::create(right_leaves, depth - 1);
                let hash = hash_concat(left_subtree.hash(), right_subtree.hash());

                Node(hash, Box::new(left_subtree), Box::new(right_subtree))
            }
        }
    }

    /// Retrieve the root hash of this Merkle tree.
    pub fn hash(&self) -> Hash256 {
        match *self {
            MerkleTree::Leaf(h) => h,
            MerkleTree::Node(h, _, _) => h,
            MerkleTree::Zero(depth) => ZERO_HASHES[depth],
        }
    }

    /// Get a reference to the left and right subtrees if they exist.
    pub fn left_and_right_branches(&self) -> Option<(&Self, &Self)> {
        match *self {
            MerkleTree::Leaf(_) | MerkleTree::Zero(0) => None,
            MerkleTree::Node(_, ref l, ref r) => Some((l, r)),
            MerkleTree::Zero(depth) => Some((&ZERO_NODES[depth - 1], &ZERO_NODES[depth - 1])),
        }
    }

    /// Is this Merkle tree a leaf?
    pub fn is_leaf(&self) -> bool {
        match self {
            MerkleTree::Leaf(_) => true,
            _ => false,
        }
    }

    /// Return the leaf at `index` and a Merkle proof of its inclusion.
    ///
    /// The Merkle proof is in "bottom-up" order, starting with a leaf node
    /// and moving up the tree. Its length will be exactly equal to `depth`.
    pub fn generate_proof(&self, index: usize, depth: usize) -> (Hash256, Vec<Hash256>) {
        let mut proof = vec![];
        let mut current_node = self;
        let mut current_depth = depth;
        while current_depth > 0 {
            let ith_bit = (index >> (current_depth - 1)) & 0x01;
            // Note: unwrap is safe because leaves are only ever constructed at depth == 0.
            let (left, right) = current_node.left_and_right_branches().unwrap();

            // Go right, include the left branch in the proof.
            if ith_bit == 1 {
                proof.push(left.hash());
                current_node = right;
            } else {
                proof.push(right.hash());
                current_node = left;
            }
            current_depth -= 1;
        }

        debug_assert_eq!(proof.len(), depth);
        debug_assert!(current_node.is_leaf());

        // Put proof in bottom-up order.
        proof.reverse();

        (current_node.hash(), proof)
    }
}

/// Verify a proof that `leaf` exists at `index` in a Merkle tree rooted at `root`.
///
/// The `branch` argument is the main component of the proof: it should be a list of internal
/// node hashes such that the root can be reconstructed (in bottom-up order).
pub fn verify_merkle_proof(
    leaf: Hash256,
    branch: &[Hash256],
    depth: usize,
    index: usize,
    root: Hash256,
) -> bool {
    if branch.len() == depth {
        merkle_root_from_branch(leaf, branch, depth, index) == root
    } else {
        false
    }
}

/// Compute a root hash from a leaf and a Merkle proof.
fn merkle_root_from_branch(
    leaf: Hash256,
    branch: &[Hash256],
    depth: usize,
    index: usize,
) -> Hash256 {
    assert_eq!(branch.len(), depth, "proof length should equal depth");

    let mut merkle_root = leaf.as_bytes().to_vec();

    for (i, leaf) in branch.iter().enumerate().take(depth) {
        let ith_bit = (index >> i) & 0x01;
        if ith_bit == 1 {
            let input = concat(leaf.as_bytes().to_vec(), merkle_root);
            merkle_root = hash(&input);
        } else {
            let mut input = merkle_root;
            input.extend_from_slice(leaf.as_bytes());
            merkle_root = hash(&input);
        }
    }

    Hash256::from_slice(&merkle_root)
}

/// Concatenate two vectors.
fn concat(mut vec1: Vec<u8>, mut vec2: Vec<u8>) -> Vec<u8> {
    vec1.append(&mut vec2);
    vec1
}

/// Compute the hash of two other hashes concatenated.
fn hash_concat(h1: Hash256, h2: Hash256) -> Hash256 {
    Hash256::from_slice(&hash(&concat(
        h1.as_bytes().to_vec(),
        h2.as_bytes().to_vec(),
    )))
}
