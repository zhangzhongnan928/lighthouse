//! Storage functionality for Lighthouse.
//!
//! Provides the following stores:
//!
//! - `HotColdDB`: an on-disk store backed by leveldb. Used in production.
//! - `MemoryStore`: an in-memory store backed by a hash-map. Used for testing.
//!
//! Provides a simple API for storing/retrieving all types that sometimes needs type-hints. See
//! tests for implementation examples.
#[macro_use]
extern crate lazy_static;

pub mod chunked_iter;
pub mod chunked_vector;
pub mod config;
pub mod errors;
mod forwards_iter;
pub mod hot_cold_store;
mod impls;
mod leveldb_store;
mod memory_store;
mod metrics;
mod partial_beacon_state;
mod state_batch;

pub mod iter;

use std::sync::Arc;

pub use self::config::StoreConfig;
pub use self::hot_cold_store::{HotColdDB, HotStateSummary};
pub use self::leveldb_store::LevelDB;
pub use self::memory_store::MemoryStore;
pub use self::partial_beacon_state::PartialBeaconState;
pub use errors::Error;
pub use impls::beacon_state::StorageContainer as BeaconStateStorageContainer;
pub use metrics::scrape_for_metrics;
pub use state_batch::StateBatch;
pub use types::*;

pub trait KeyValueStore<E: EthSpec>: Sync + Send + Sized + 'static {
    /// Retrieve some bytes in `column` with `key`.
    fn get_bytes(&self, column: &str, key: &[u8]) -> Result<Option<Vec<u8>>, Error>;

    /// Store some `value` in `column`, indexed with `key`.
    fn put_bytes(&self, column: &str, key: &[u8], value: &[u8]) -> Result<(), Error>;

    /// Return `true` if `key` exists in `column`.
    fn key_exists(&self, column: &str, key: &[u8]) -> Result<bool, Error>;

    /// Removes `key` from `column`.
    fn key_delete(&self, column: &str, key: &[u8]) -> Result<(), Error>;

    /// Execute either all of the operations in `batch` or none at all, returning an error.
    fn do_atomically(&self, batch: &[StoreOp]) -> Result<(), Error>;
}

pub trait ItemStore<E: EthSpec>: KeyValueStore<E> + Sync + Send + Sized + 'static {
    /// Store an item in `Self`.
    fn put<I: StoreItem>(&self, key: &Hash256, item: &I) -> Result<(), Error> {
        let column = I::db_column().into();
        let key = key.as_bytes();

        self.put_bytes(column, key, &item.as_store_bytes())
            .map_err(Into::into)
    }

    /// Retrieve an item from `Self`.
    fn get<I: StoreItem>(&self, key: &Hash256) -> Result<Option<I>, Error> {
        let column = I::db_column().into();
        let key = key.as_bytes();

        match self.get_bytes(column, key)? {
            Some(bytes) => Ok(Some(I::from_store_bytes(&bytes[..])?)),
            None => Ok(None),
        }
    }

    /// Returns `true` if the given key represents an item in `Self`.
    fn exists<I: StoreItem>(&self, key: &Hash256) -> Result<bool, Error> {
        let column = I::db_column().into();
        let key = key.as_bytes();

        self.key_exists(column, key)
    }

    /// Remove an item from `Self`.
    fn delete<I: StoreItem>(&self, key: &Hash256) -> Result<(), Error> {
        let column = I::db_column().into();
        let key = key.as_bytes();

        self.key_delete(column, key)
    }
}

/// An object capable of storing and retrieving objects implementing `StoreItem`.
///
/// A `Store` is fundamentally backed by a key-value database, however it provides support for
/// columns. A simple column implementation might involve prefixing a key with some bytes unique to
/// each column.
pub trait Store<E: EthSpec>: Sync + Send + Sized + 'static {
    type ForwardsBlockRootsIterator: Iterator<Item = Result<(Hash256, Slot), Error>>;

    /// Store a block in the store.
    fn put_block(&self, block_root: &Hash256, block: SignedBeaconBlock<E>) -> Result<(), Error>;

    /// Fetch a block from the store.
    fn get_block(&self, block_root: &Hash256) -> Result<Option<SignedBeaconBlock<E>>, Error>;

    /// Delete a block from the store.
    fn delete_block(&self, block_root: &Hash256) -> Result<(), Error>;

    /// Store a state in the store.
    fn put_state(&self, state_root: &Hash256, state: &BeaconState<E>) -> Result<(), Error>;

    /// Store a state summary in the store.
    fn put_state_summary(
        &self,
        state_root: &Hash256,
        summary: HotStateSummary,
    ) -> Result<(), Error>;

    /// Fetch a state from the store.
    fn get_state(
        &self,
        state_root: &Hash256,
        slot: Option<Slot>,
    ) -> Result<Option<BeaconState<E>>, Error>;

    /// Delete a state from the store.
    fn delete_state(&self, state_root: &Hash256, _slot: Slot) -> Result<(), Error>;

    /// Get a forwards (slot-ascending) iterator over the beacon block roots since `start_slot`.
    ///
    /// Will be efficient for frozen portions of the database if using `HotColdDB`.
    ///
    /// The `end_state` and `end_block_root` are required for backtracking in the post-finalization
    /// part of the chain, and should be usually be set to the current head. Importantly, the
    /// `end_state` must be a state that has had a block applied to it, and the hash of that
    /// block must be `end_block_root`.
    // NOTE: could maybe optimise by getting the `BeaconState` and end block root from a closure, as
    // it's not always required.
    fn forwards_block_roots_iterator(
        store: Arc<Self>,
        start_slot: Slot,
        end_state: BeaconState<E>,
        end_block_root: Hash256,
        spec: &ChainSpec,
    ) -> Result<Self::ForwardsBlockRootsIterator, Error>;

    fn load_epoch_boundary_state(
        &self,
        state_root: &Hash256,
    ) -> Result<Option<BeaconState<E>>, Error>;

    fn put_item<I: StoreItem>(&self, key: &Hash256, item: &I) -> Result<(), Error>;

    fn get_item<I: StoreItem>(&self, key: &Hash256) -> Result<Option<I>, Error>;

    fn item_exists<I: StoreItem>(&self, key: &Hash256) -> Result<bool, Error>;

    fn do_atomically(&self, batch: &[StoreOp]) -> Result<(), Error>;
}

/// Reified key-value storage operation.  Helps in modifying the storage atomically.
/// See also https://github.com/sigp/lighthouse/issues/692
pub enum StoreOp {
    DeleteBlock(SignedBeaconBlockHash),
    DeleteState(BeaconStateHash, Slot),
}

/// A unique column identifier.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DBColumn {
    /// For data related to the database itself.
    BeaconMeta,
    BeaconBlock,
    BeaconState,
    /// For persisting in-memory state to the database.
    BeaconChain,
    OpPool,
    Eth1Cache,
    ForkChoice,
    /// For the table mapping restore point numbers to state roots.
    BeaconRestorePoint,
    /// For the mapping from state roots to their slots or summaries.
    BeaconStateSummary,
    BeaconBlockRoots,
    BeaconStateRoots,
    BeaconHistoricalRoots,
    BeaconRandaoMixes,
    DhtEnrs,
}

impl Into<&'static str> for DBColumn {
    /// Returns a `&str` that can be used for keying a key-value data base.
    fn into(self) -> &'static str {
        match self {
            DBColumn::BeaconMeta => "bma",
            DBColumn::BeaconBlock => "blk",
            DBColumn::BeaconState => "ste",
            DBColumn::BeaconChain => "bch",
            DBColumn::OpPool => "opo",
            DBColumn::Eth1Cache => "etc",
            DBColumn::ForkChoice => "frk",
            DBColumn::BeaconRestorePoint => "brp",
            DBColumn::BeaconStateSummary => "bss",
            DBColumn::BeaconBlockRoots => "bbr",
            DBColumn::BeaconStateRoots => "bsr",
            DBColumn::BeaconHistoricalRoots => "bhr",
            DBColumn::BeaconRandaoMixes => "brm",
            DBColumn::DhtEnrs => "dht",
        }
    }
}

/// An item that may stored in a `Store` by serializing and deserializing from bytes.
pub trait StoreItem: Sized {
    /// Identifies which column this item should be placed in.
    fn db_column() -> DBColumn;

    /// Serialize `self` as bytes.
    fn as_store_bytes(&self) -> Vec<u8>;

    /// De-serialize `self` from bytes.
    ///
    /// Return an instance of the type and the number of bytes that were read.
    fn from_store_bytes(bytes: &[u8]) -> Result<Self, Error>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssz::{Decode, Encode};
    use ssz_derive::{Decode, Encode};
    use tempfile::tempdir;

    #[derive(PartialEq, Debug, Encode, Decode)]
    struct StorableThing {
        a: u64,
        b: u64,
    }

    impl StoreItem for StorableThing {
        fn db_column() -> DBColumn {
            DBColumn::BeaconBlock
        }

        fn as_store_bytes(&self) -> Vec<u8> {
            self.as_ssz_bytes()
        }

        fn from_store_bytes(bytes: &[u8]) -> Result<Self, Error> {
            Self::from_ssz_bytes(bytes).map_err(Into::into)
        }
    }

    fn test_impl(store: impl ItemStore<MinimalEthSpec>) {
        let key = Hash256::random();
        let item = StorableThing { a: 1, b: 42 };

        assert_eq!(store.exists::<StorableThing>(&key).unwrap(), false);

        store.put(&key, &item).unwrap();

        assert_eq!(store.exists::<StorableThing>(&key).unwrap(), true);

        let retrieved = store.get(&key).unwrap().unwrap();
        assert_eq!(item, retrieved);

        store.delete::<StorableThing>(&key).unwrap();

        assert_eq!(store.exists::<StorableThing>(&key).unwrap(), false);

        assert_eq!(store.get::<StorableThing>(&key).unwrap(), None);
    }

    #[test]
    fn simplediskdb() {
        let dir = tempdir().unwrap();
        let path = dir.path();
        let store = LevelDB::open(&path).unwrap();

        test_impl(store);
    }

    #[test]
    fn memorydb() {
        let store = MemoryStore::open();

        test_impl(store);
    }

    #[test]
    fn exists() {
        let store = MemoryStore::<MinimalEthSpec>::open();
        let key = Hash256::random();
        let item = StorableThing { a: 1, b: 42 };

        assert_eq!(store.exists::<StorableThing>(&key).unwrap(), false);

        store.put(&key, &item).unwrap();

        assert_eq!(store.exists::<StorableThing>(&key).unwrap(), true);

        store.delete::<StorableThing>(&key).unwrap();

        assert_eq!(store.exists::<StorableThing>(&key).unwrap(), false);
    }
}
