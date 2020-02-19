use crate::typenum::Unsigned;
use crate::*;
use eth2_hashing::{hash32_concat, ZERO_HASHES};
use parking_lot::RwLock;
use serde_derive::{Deserialize, Serialize};
use std::marker::PhantomData;
use std::ops::Index;
use std::sync::Arc;
use tree_hash::TreeHash;

#[derive(Debug)]
pub struct ValidatorLeaf {
    hash: RwLock<Option<Hash256>>,
    value: Validator,
}

impl Clone for ValidatorLeaf {
    fn clone(&self) -> Self {
        Self {
            hash: RwLock::new(self.hash.read().as_ref().cloned()),
            value: self.value.clone(),
        }
    }
}

impl PartialEq for ValidatorLeaf {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

#[derive(Debug)]
pub enum ValidatorTreeNode {
    Leaf(ValidatorLeaf),
    Node {
        hash: RwLock<Option<Hash256>>,
        left: Arc<ValidatorTreeNode>,
        right: Arc<ValidatorTreeNode>,
    },
    Zero(usize),
}

impl Clone for ValidatorTreeNode {
    fn clone(&self) -> Self {
        match self {
            Self::Node { hash, left, right } => Self::Node {
                hash: RwLock::new(hash.read().as_ref().cloned()),
                left: left.clone(),
                right: right.clone(),
            },
            Self::Leaf(leaf) => Self::Leaf(leaf.clone()),
            Self::Zero(depth) => Self::Zero(*depth),
        }
    }
}

impl PartialEq for ValidatorTreeNode {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Leaf(l1), Self::Leaf(l2)) => l1 == l2,
            (
                Self::Node {
                    left: l1,
                    right: r1,
                    ..
                },
                Self::Node {
                    left: l2,
                    right: r2,
                    ..
                },
            ) => l1 == l2 && r1 == r2,
            (Self::Zero(d1), Self::Zero(d2)) => d1 == d2,
            _ => false,
        }
    }
}

/// Top-level validator tree.
#[derive(Debug, PartialEq, Clone, Deserialize, Serialize)]
#[serde(from = "Vec<Validator>")]
#[serde(into = "Vec<Validator>")]
pub struct ValidatorTree<N: Unsigned + Clone> {
    tree: Arc<ValidatorTreeNode>,
    length: usize,
    depth: usize,
    _phantom: PhantomData<N>,
}

impl<N: Unsigned + Clone> Default for ValidatorTree<N> {
    fn default() -> Self {
        Self::from(vec![])
    }
}

impl<N: Unsigned + Clone> From<Vec<Validator>> for ValidatorTree<N> {
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

impl<N: Unsigned + Clone> Into<Vec<Validator>> for ValidatorTree<N> {
    fn into(self) -> Vec<Validator> {
        self.iter().cloned().collect()
    }
}

impl<N: Unsigned + Clone> ValidatorTree<N> {
    pub fn get(&self, index: usize) -> Option<&Validator> {
        if index < self.len() {
            self.tree.get(index, self.depth)
        } else {
            None
        }
    }

    pub fn replace(
        &mut self,
        index: usize,
        validator: Validator,
    ) -> Result<(), ValidatorTreeError> {
        self.tree = self.tree.with_updated_leaf(index, validator, self.depth)?;
        Ok(())
    }

    pub fn push(&mut self, validator: Validator) -> Result<(), ValidatorTreeError> {
        let index = self.length;
        self.tree = self.tree.with_updated_leaf(index, validator, self.depth)?;
        self.length += 1;
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.length
    }

    pub fn iter<'a>(&'a self) -> impl Iterator<Item = &'a Validator> + 'a {
        Iter {
            stack: vec![&self.tree],
            index: 0,
            full_depth: self.depth,
        }
    }
}

pub struct Iter<'a> {
    stack: Vec<&'a ValidatorTreeNode>,
    index: u64,
    full_depth: usize,
}

impl<'a> Iterator for Iter<'a> {
    type Item = &'a Validator;

    fn next(&mut self) -> Option<Self::Item> {
        match self.stack.last() {
            None | Some(ValidatorTreeNode::Zero(_)) => None,
            Some(ValidatorTreeNode::Leaf(ValidatorLeaf { value, .. })) => {
                let result = Some(value);

                self.index += 1;

                // Backtrack to the parent node of the next subtree
                self.stack.pop();
                for _ in 0..self.index.trailing_zeros() + 1 {
                    self.stack.pop();
                }

                result
            }
            Some(ValidatorTreeNode::Node { left, right, .. }) => {
                let depth = self.full_depth - self.stack.len();

                // Go left
                if (self.index >> depth) & 1 == 0 {
                    self.stack.push(&left);
                    self.next()
                }
                // Go right
                else {
                    self.stack.push(&right);
                    self.next()
                }
            }
        }
    }
}

/* FIXME(sproul): consider this
impl<N: Unsigned + Clone> Index<u64> for ValidatorTree<N> {
    type Output = Validator;

    fn index(&self, index: usize) -> &Self::Output {
        self.get(index).expect("index out of bounds")
    }
}
*/

impl<N: Unsigned + Clone> Index<usize> for ValidatorTree<N> {
    type Output = Validator;

    fn index(&self, index: usize) -> &Self::Output {
        self.get(index).expect("index out of bounds")
    }
}

impl<N: Unsigned + Clone> TreeHash for ValidatorTree<N> {
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

impl<N: Unsigned + Clone> ssz::Encode for ValidatorTree<N> {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_bytes_len(&self) -> usize {
        assert!(<Validator as ssz::Encode>::is_ssz_fixed_len());
        <Validator as ssz::Encode>::ssz_fixed_len() * self.len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        // FIXME: implement encode for Vec<&T> to save the clone, or do something better
        let vec = self.iter().cloned().collect::<Vec<_>>();
        vec.ssz_append(buf)
    }
}

impl<N: Unsigned + Clone> ssz::Decode for ValidatorTree<N> {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        let vec = <Vec<Validator>>::from_ssz_bytes(bytes)?;
        Ok(Self::from(vec))
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum ValidatorTreeError {
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
        Arc::new(ValidatorTreeNode::Node {
            hash: RwLock::new(None),
            left,
            right,
        })
    }

    pub fn zero(depth: usize) -> Arc<Self> {
        Arc::new(Self::Zero(depth))
    }

    pub fn leaf(validator: Validator) -> Arc<Self> {
        Arc::new(Self::Leaf(ValidatorLeaf::new(validator)))
    }

    pub fn create(leaves: Vec<Arc<Self>>, depth: usize) -> Arc<Self> {
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

    pub fn get(&self, index: usize, depth: usize) -> Option<&Validator> {
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
        index: usize,
        new_value: Validator,
        depth: usize,
    ) -> Result<Arc<Self>, ValidatorTreeError> {
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
            _ => Err(ValidatorTreeError::Oops),
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
            Self::Zero(depth) => Hash256::from_slice(&ZERO_HASHES[*depth]),
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
pub fn int_log(n: usize) -> usize {
    match n.checked_next_power_of_two() {
        Some(x) => x.trailing_zeros() as usize,
        None => 8 * std::mem::size_of::<usize>(),
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test_utils::{SeedableRng, TestRandom, XorShiftRng};
    use crate::{typenum::U1099511627776, VariableList};
    use tree_hash::mix_in_length;

    /*
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
    */

    #[test]
    fn iter_bench() {
        use crate::typenum;
        use std::time::Instant;
        let mut rng = XorShiftRng::from_seed([42; 16]);
        let validators = (0..32_768)
            .map(|_| Validator::random_for_test(&mut rng))
            .collect::<Vec<_>>();

        let t = Instant::now();
        let tree = ValidatorTree::<typenum::U1099511627776>::from(validators.clone());
        println!("construction: {}us", t.elapsed().as_micros());

        let extracted: Vec<Validator> = tree.iter().cloned().collect();
        // println!("{:#?}", extracted);
        // println!("{:#?}", validators);
        assert_eq!(extracted.len(), validators.len());
        assert_eq!(extracted, validators);

        let t = Instant::now();
        let sum = tree.iter().map(|v| v.effective_balance).sum::<u64>();
        println!("{}", sum / tree.len() as u64);
        println!("iteration: {}us", t.elapsed().as_micros());

        // For comparison
        let t = Instant::now();
        let sum = validators.iter().map(|v| v.effective_balance).sum::<u64>();
        println!("{}", sum / tree.len() as u64);
        println!("vec iteration: {}us", t.elapsed().as_micros());
    }
}
