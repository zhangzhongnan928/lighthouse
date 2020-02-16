use crate::typenum::Unsigned;
use crate::*;
use eth2_hashing::{hash32_concat, ZERO_HASHES};
use parking_lot::RwLock;
use std::marker::PhantomData;
use std::ops::Index;
use std::sync::Arc;
use tree_hash::TreeHash;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ValidatorLeaf {
    hash: RwLock<Option<Hash256>>,
    value: Validator,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ValidatorTreeNode {
    Leaf(ValidatorLeaf),
    Node {
        hash: RwLock<Option<Hash256>>,
        left: Arc<ValidatorTreeNode>,
        right: Arc<ValidatorTreeNode>,
    },
    Zero(u64),
}

/// Top-level validator tree.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ValidatorTree<N: Unsigned> {
    tree: Arc<ValidatorTreeNode>,
    length: usize,
    depth: u64,
    _phantom: PhantomData<N>,
}

impl<N: Unsigned> Default for ValidatorTree<N> {
    fn default() -> Self {
        Self::from(vec![])
    }
}

impl<N: Unsigned> From<Vec<Validator>> for ValidatorTree<N> {
    fn from(mut validators: Vec<Validator>) -> Self {
        validators.truncate(N::to_usize());

        let length = validators.len();
        let depth = int_log(N::to_usize());
        let tree = ValidatorTreeNode::create(
            validators
                .into_iter()
                .map(|validator| ValidatorTreeNode::leaf(validator))
                .collect(),
            depth,
        );
        Self {
            tree,
            length,
            depth,
            _phantom: PhantomData,
        }
    }
}

impl<N: Unsigned> ValidatorTree<N> {
    pub fn get(&self, index: u64) -> Option<&Validator> {
        if index < self.len() as u64 {
            self.tree.get(index, self.depth)
        } else {
            None
        }
    }

    pub fn replace_validator(&mut self, index: u64, validator: Validator) -> Result<(), Error> {
        self.tree = self.tree.with_updated_leaf(index, validator, self.depth)?;
        Ok(())
    }

    pub fn push(&mut self, validator: Validator) -> Result<(), Error> {
        let index = self.length as u64;
        self.tree = self.tree.with_updated_leaf(index, validator, self.depth)?;
        self.length += 1;
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.length
    }
}

impl<N: Unsigned> Index<u64> for ValidatorTree<N> {
    type Output = Validator;

    fn index(&self, index: u64) -> &Self::Output {
        self.get(index).expect("index out of bounds")
    }
}

impl<N: Unsigned> TreeHash for ValidatorTree<N> {
    fn tree_hash_type() -> tree_hash::TreeHashType {
        tree_hash::TreeHashType::List
    }

    fn tree_hash_packed_encoding(&self) -> Vec<u8> {
        unreachable!("List should never be packed.")
    }

    fn tree_hash_packing_factor() -> usize {
        unreachable!("List should never be packed.")
    }

    fn tree_hash_root(&self) -> Vec<u8> {
        let root = self.tree.tree_hash();
        tree_hash::mix_in_length(root.as_bytes(), self.len())
    }
}

#[derive(Debug)]
pub enum Error {
    Oops,
}

impl ValidatorLeaf {
    pub fn new(validator: Validator) -> Self {
        ValidatorLeaf {
            hash: RwLock::new(None),
            value: validator,
        }
    }
}

impl ValidatorTreeNode {
    pub fn node(left: Arc<Self>, right: Arc<Self>) -> Arc<Self> {
        Arc::new(Self::Node {
            hash: RwLock::new(None),
            left,
            right,
        })
    }

    pub fn zero(depth: u64) -> Arc<Self> {
        Arc::new(Self::Zero(depth))
    }

    pub fn leaf(validator: Validator) -> Arc<Self> {
        Arc::new(Self::Leaf(ValidatorLeaf::new(validator)))
    }

    pub fn create(leaves: Vec<Arc<Self>>, depth: u64) -> Arc<Self> {
        if leaves.is_empty() {
            return Self::zero(depth);
        }

        let mut current_layer = leaves;

        // Disgustingly imperative
        for depth in 0..depth {
            let mut new_layer = Vec::with_capacity(current_layer.len() / 2);
            let mut iter = current_layer.into_iter();

            while let Some(left) = iter.next() {
                if let Some(right) = iter.next() {
                    new_layer.push(Self::node(left, right));
                } else {
                    new_layer.push(Self::node(left, Self::zero(depth)));
                }
            }

            current_layer = new_layer;
        }

        assert_eq!(current_layer.len(), 1);
        current_layer.pop().expect("current layer not empty")
    }

    pub fn get(&self, index: u64, depth: u64) -> Option<&Validator> {
        match self {
            Self::Leaf(ValidatorLeaf { value, .. }) if depth == 0 => Some(value),
            Self::Node { left, right, .. } if depth > 0 => {
                let new_depth = depth - 1;
                // Left
                if (index >> new_depth) & 1 == 0 {
                    left.get(index, new_depth)
                }
                // Right
                else {
                    right.get(index, new_depth)
                }
            }
            _ => None,
        }
    }

    pub fn with_updated_leaf(
        &self,
        index: u64,
        new_value: Validator,
        depth: u64,
    ) -> Result<Arc<Self>, Error> {
        // FIXME: check index less than 2^depth
        match self {
            Self::Leaf(_) if depth == 0 => Ok(Self::leaf(new_value)),
            Self::Node { left, right, .. } if depth > 0 => {
                let new_depth = depth - 1;
                if (index >> new_depth) & 1 == 0 {
                    // Index lies on the left, recurse left
                    Ok(Self::node(
                        left.with_updated_leaf(index, new_value, new_depth)?,
                        right.clone(),
                    ))
                } else {
                    // Index lies on the right, recurse right
                    Ok(Self::node(
                        left.clone(),
                        right.with_updated_leaf(index, new_value, new_depth)?,
                    ))
                }
            }
            Self::Zero(zero_depth) if *zero_depth == depth => {
                if depth == 0 {
                    Ok(Self::leaf(new_value))
                } else {
                    // Split zero node into a node with left and right, and recurse into
                    // the appropriate subtree
                    let new_zero = Self::zero(depth - 1);
                    Self::node(new_zero.clone(), new_zero)
                        .with_updated_leaf(index, new_value, depth)
                }
            }
            _ => Err(Error::Oops),
        }
    }

    pub fn tree_hash(&self) -> Hash256 {
        match self {
            Self::Leaf(ValidatorLeaf { hash, value }) => {
                let read_lock = hash.read();
                let existing_hash = *read_lock;
                drop(read_lock);
                if let Some(hash) = existing_hash {
                    hash
                } else {
                    let tree_hash = Hash256::from_slice(&value.tree_hash_root());
                    *hash.write() = Some(tree_hash);
                    tree_hash
                }
            }
            Self::Zero(depth) => Hash256::from_slice(&ZERO_HASHES[*depth as usize]),
            Self::Node { hash, left, right } => {
                let read_lock = hash.read();
                let existing_hash = *read_lock;
                drop(read_lock);
                if let Some(hash) = existing_hash {
                    hash
                } else {
                    let left_hash = left.tree_hash();
                    let right_hash = right.tree_hash();
                    let tree_hash =
                        Hash256::from(hash32_concat(left_hash.as_bytes(), right_hash.as_bytes()));
                    *hash.write() = Some(tree_hash);
                    tree_hash
                }
            }
        }
    }
}

// FIXME(sproul): deduplicate
/// Compute ceil(log(n))
///
/// Smallest number of bits d so that n <= 2^d
pub fn int_log(n: usize) -> u64 {
    match n.checked_next_power_of_two() {
        Some(x) => x.trailing_zeros(),
        None => 8 * std::mem::size_of::<u64>(),
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_utils::{SeedableRng, TestRandom, XorShiftRng};
    use crate::{typenum::U4, VariableList};
    use tree_hash::mix_in_length;

    #[test]
    fn lmao() {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let validators = (0..3)
            .map(|_| Validator::random_for_test(&mut rng))
            .collect();
        let tree = ValidatorTreeNode::from_validators(validators, 2);
        let new_val = Validator::random_for_test(&mut rng);
        let zero_tree = tree.with_updated_leaf(3, new_val.clone(), 2).unwrap();
        assert!(false);
    }

    #[test]
    fn tree_hash_test() {
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let validators = (0..3)
            .map(|_| Validator::random_for_test(&mut rng))
            .collect::<Vec<_>>();
        let tree = ValidatorTreeNode::from_validators(validators.clone(), 2);
        let val_root = tree.tree_hash().unwrap();
        let obs_root = mix_in_length(val_root.as_bytes(), 3);

        let l = VariableList::<_, U4>::from(validators);
        let exp_root = l.tree_hash_root();

        assert_eq!(obs_root, exp_root);
    }
}
