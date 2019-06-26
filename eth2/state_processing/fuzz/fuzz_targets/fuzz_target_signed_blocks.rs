#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate dirs;
extern crate hex;
extern crate ssz;
extern crate state_processing;
extern crate store;
extern crate tree_hash;
extern crate types;

use ssz::{Decode, DecodeError, Encode};
use std::env;
use std::fs::File;
use std::io::prelude::*;
use std::io::{BufReader, LineWriter};
use std::path::PathBuf;
use std::convert::TryInto;
use store::StorageContainer;
use tree_hash::{SignedRoot, TreeHash};
use types::*;
use types::test_utils::TestingBeaconStateBuilder;
use state_processing::{per_block_processing, block_processing_builder::BlockProcessingBuilder};

pub const MINIMAL_STATE_FILE: &str = "fuzzer_minimal_state.bin";
pub const KEYPAIRS_FILE: &str = "fuzzer_keypairs.txt";
pub const NUM_VALIDATORS: usize = 8;

// Fuzz `per_block_processing()`
fuzz_target!(|data: &[u8]| {
    // Convert data to a BeaconBlock
    let block = BeaconBlock::from_ssz_bytes(&data);

    if !block.is_err() {
        println!("Processing block");
        // Generate a chain_spec
        let spec = MinimalEthSpec::default_spec();
        let mut state = from_minimal_state_file(&spec);
        let keypairs = from_keypairs_file(&spec);


        // Set a valid block Signature
        let mut block = block.unwrap();
        sign_block(&mut block, &state, keypairs, &spec);


        // Fuzz per_block_processing (if decoding was successful)
        println!("Valid block? {}", !per_block_processing(&mut state, &block, &spec).is_err());
    }
});

fn sign_block(block: &mut BeaconBlock, state: &BeaconState<MinimalEthSpec>, keypairs: Vec<Keypair>, spec: &ChainSpec) {
    // Get secret key of the proposer
    let proposer_index = state
        .get_beacon_proposer_index(state.slot, RelativeEpoch::Current, spec)
        .unwrap();
    let keypair = &keypairs[proposer_index];

    // Sign Block
    let message = block.signed_root();
    let epoch = block.slot.epoch(MinimalEthSpec::slots_per_epoch());
    let domain = spec.get_domain(epoch, Domain::BeaconProposer, &state.fork);
    block.signature = Signature::new(&message, domain, &keypair.sk);
}

// Will either load minimal_state.bin OR will create the file for future runs.
pub fn from_minimal_state_file(spec: &ChainSpec) -> BeaconState<MinimalEthSpec> {
    let dir = dirs::home_dir()
    .and_then(|home| Some(home.join(".lighthouse")))
    .unwrap_or_else(|| PathBuf::from(""));
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
    file.read_to_end(&mut buffer);

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
    file.write_all(&storage_bytes);

    state
}

// Will either load minimal_state.bin OR will create the file for future runs.
pub fn from_keypairs_file(spec: &ChainSpec) -> Vec<Keypair> {
    let dir = dirs::home_dir()
    .and_then(|home| Some(home.join(".lighthouse")))
    .unwrap_or_else(|| PathBuf::from(""));
    let file = dir.join(KEYPAIRS_FILE);

    if file.exists() {
        read_keypairs(&file)
    } else {
        create_keypairs_file(&file, &spec)
    }
}

// Read the deterministic keypairs from file
fn read_keypairs(path: &PathBuf) -> Vec<Keypair>{
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
        let pair = Keypair {
            sk,
            pk,
        };
        keypairs.push(pair);
    }

    keypairs
}

// Create fuzzer_keypairs.txt file
pub fn create_keypairs_file(path: &PathBuf, spec: &ChainSpec) -> Vec<Keypair> {
    // Create the Keypair
    let (_, keypairs) = build_minimal_state(&spec);

    // Open fuzzer_keypairs.txt file.
    let file = File::create(path).unwrap();
    let mut file = LineWriter::new(file);

    // Convert the keypairs to str and write to file
    for pair in keypairs.iter() {
        let pk = hex::encode(pair.pk.as_ssz_bytes());
        let sk = hex::encode(pair.sk.as_ssz_bytes());

        file.write_all(pk.as_bytes());
        file.write_all(b",");
        file.write_all(sk.as_bytes());
        file.write_all(b"\n");
    }

    file.flush();
    keypairs
}

// Creates a BeaconState in the last slot of the 4th Epoch.
pub fn build_minimal_state(spec: &ChainSpec) -> (BeaconState<MinimalEthSpec>, Vec<Keypair>) {
    let mut state_builder =
        TestingBeaconStateBuilder::from_default_keypairs_file_if_exists(NUM_VALIDATORS, &spec);
    // Set the state and block to be in the last slot of the 4th epoch.
    let slot =
        (MinimalEthSpec::genesis_epoch() + 4).end_slot(MinimalEthSpec::slots_per_epoch());
    state_builder.teleport_to_slot(slot);
    state_builder.build_caches(&spec);

    state_builder.build()
}
