extern crate hashing;
extern crate hex;
extern crate ssz;
extern crate state_processing;
extern crate store;
extern crate tree_hash;
extern crate types;
#[macro_use]
extern crate lazy_static;

use ssz::{Decode, Encode};
use std::convert::TryInto;
use std::fs::{DirBuilder, File};
use std::io::prelude::*;
use std::io::{BufReader, LineWriter};
use std::path::PathBuf;
use store::StorageContainer;
use tree_hash::TreeHash;
use types::test_utils::TestingBeaconStateBuilder;
use types::*;

mod generate_corpus;
mod merkle_proof;
pub use generate_corpus::*;
pub use merkle_proof::*;

pub const MINIMAL_STATE_FILE: &str = "fuzzer_minimal_state.bin";
pub const KEYPAIRS_FILE: &str = "fuzzer_keypairs.txt";
pub const TMP_DIR: &str = "/tmp/lighthouse";
pub const NUM_VALIDATORS: usize = 8;
pub const STATE_EPOCH: u64 = 4;

pub fn insert_eth1_data(state: &mut BeaconState<MinimalEthSpec>, deposit: &mut Deposit) {
    let block_hash = Hash256::from_slice(&vec![1u8; 32]);

    let signed_root = Hash256::from_slice(&deposit.data.tree_hash_root());

    let merkle_root = MerkleTree::create(&[signed_root], 32);
    // Uncomment this line if generating_deposit()
    //deposit.proof = merkle_root.generate_proof(0, 32).1.into();

    let eth1_data = Eth1Data {
        deposit_root: merkle_root.hash(),
        deposit_count: 1,
        block_hash,
    };
    state.eth1_data = eth1_data;
}

pub fn increase_state_epoch(
    state: &mut BeaconState<MinimalEthSpec>,
    epoch: Epoch,
    spec: &ChainSpec,
) {
    state.slot = epoch.end_slot(MinimalEthSpec::slots_per_epoch());

    state.previous_justified_checkpoint.epoch = epoch - 3;
    state.current_justified_checkpoint.epoch = epoch - 2;
    state.justification_bits = BitVector::from_bytes(vec![0b0000_1111]).unwrap();

    state.finalized_checkpoint.epoch = epoch - 3;

    state.build_all_caches(spec).unwrap();
}

// Will either load minimal_state.bin OR will create the file for future runs.
pub fn from_minimal_state_file(spec: &ChainSpec) -> BeaconState<MinimalEthSpec> {
    DirBuilder::new()
        .recursive(true)
        .create(TMP_DIR).unwrap();
    let dir = PathBuf::from(TMP_DIR);
    let file = dir.join(MINIMAL_STATE_FILE);

    if file.exists() {
        read_state_from_file(&file)
    } else {
        create_minimal_state_file(&file, &spec)
    }
}

// If the fuzzer_minimal_state.bin file exists load from that.
pub fn read_state_from_file(path: &PathBuf) -> BeaconState<MinimalEthSpec> {
    let mut file = File::open(path).unwrap();
    let mut buffer = Vec::new();
    let _ = file.read_to_end(&mut buffer);

    let storage = StorageContainer::from_ssz_bytes(&buffer).unwrap();

    storage.try_into().unwrap()
}

// Create a fuzzer_minimal_state.bin file
pub fn create_minimal_state_file(path: &PathBuf, spec: &ChainSpec) -> BeaconState<MinimalEthSpec> {
    // Create the BeaconState
    let (state, _) = build_minimal_state(&spec);

    // Convert the state to bytes
    let storage = StorageContainer::new(&state);
    let storage_bytes = storage.as_ssz_bytes();

    // Write state to file
    let mut file = File::create(path).unwrap();
    let _ = file.write_all(&storage_bytes);

    state
}

// Will either load minimal_state.bin OR will create the file for future runs.
pub fn from_keypairs_file(spec: &ChainSpec) -> Vec<Keypair> {
    DirBuilder::new()
        .recursive(true)
        .create(TMP_DIR).unwrap();
    let dir = PathBuf::from(TMP_DIR);
    let file = dir.join(KEYPAIRS_FILE);

    if file.exists() {
        read_keypairs(&file)
    } else {
        create_keypairs_file(&file, &spec)
    }
}

// Read the deterministic keypairs from file
fn read_keypairs(path: &PathBuf) -> Vec<Keypair> {
    let file = File::open(path).unwrap();
    let file = BufReader::new(file);
    let mut keypairs: Vec<Keypair> = vec![];

    for line in file.lines() {
        let line = line.unwrap();
        let parts = line.split(",").collect::<Vec<&str>>();
        let pk = hex::decode(parts[0]).unwrap();
        let sk = hex::decode(parts[1]).unwrap();

        let pk = PublicKey::from_ssz_bytes(&pk).unwrap();
        let sk = SecretKey::from_ssz_bytes(&sk).unwrap();
        let pair = Keypair { sk, pk };
        keypairs.push(pair);
    }

    keypairs
}

// Create fuzzer_keypairs.txt file
pub fn create_keypairs_file(path: &PathBuf, spec: &ChainSpec) -> Vec<Keypair> {
    // Create the Keypair
    let (_, keypairs) = build_minimal_state_with_validators(NUM_VALIDATORS + 5, &spec);

    // Open fuzzer_keypairs.txt file.
    let file = File::create(path).unwrap();
    let mut file = LineWriter::new(file);

    // Convert the keypairs to str and write to file
    for pair in keypairs.iter() {
        let pk = hex::encode(pair.pk.as_ssz_bytes());
        let sk = hex::encode(pair.sk.as_ssz_bytes());

        let _ = file.write_all(pk.as_bytes());
        let _ = file.write_all(b",");
        let _ = file.write_all(sk.as_bytes());
        let _ = file.write_all(b"\n");
    }

    let _ = file.flush();
    keypairs
}

// Creates a BeaconState in the last slot of the 4th Epoch.
pub fn build_minimal_state(spec: &ChainSpec) -> (BeaconState<MinimalEthSpec>, Vec<Keypair>) {
    let mut state_builder =
        TestingBeaconStateBuilder::from_default_keypairs_file_if_exists(NUM_VALIDATORS, &spec);
    // Set the state and block to be in the last slot of the 4th epoch.
    let slot =
        (MinimalEthSpec::genesis_epoch() + STATE_EPOCH).end_slot(MinimalEthSpec::slots_per_epoch());
    state_builder.teleport_to_slot(slot);
    let _ = state_builder.build_caches(&spec);

    state_builder.build()
}

// Creates a BeaconState in the last slot of the 4th Epoch.
pub fn build_minimal_state_with_validators(
    num_validators: usize,
    spec: &ChainSpec,
) -> (BeaconState<MinimalEthSpec>, Vec<Keypair>) {
    let mut state_builder =
        TestingBeaconStateBuilder::from_default_keypairs_file_if_exists(num_validators, &spec);
    // Set the state and block to be in the last slot of the 4th epoch.
    let slot =
        (MinimalEthSpec::genesis_epoch() + STATE_EPOCH).end_slot(MinimalEthSpec::slots_per_epoch());
    state_builder.teleport_to_slot(slot);
    let _ = state_builder.build_caches(&spec);

    state_builder.build()
}
