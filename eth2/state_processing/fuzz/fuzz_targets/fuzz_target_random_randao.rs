#![no_main]
extern crate hex;
#[macro_use] extern crate libfuzzer_sys;
extern crate ssz;
extern crate state_processing;
extern crate state_processing_fuzz;
extern crate types;

use ssz::{Decode, Encode};
use state_processing_fuzz::{from_minimal_state_file, from_keypairs_file};
use types::*;
use types::test_utils::TestingBeaconBlockBuilder;
use state_processing::process_randao;


// Fuzz `per_block_processing()`
fuzz_target!(|data: &[u8]| {
    // Generate a corpus
    //generate_randao();

    // Convert data to a BeaconBlock
    let block = BeaconBlock::from_ssz_bytes(&data);

    if !block.is_err() {
        println!("Processing randao");
        // Generate a chain_spec
        let spec = MinimalEthSpec::default_spec();
        let mut state = from_minimal_state_file(&spec);

        // Fuzz per_block_processing (if decoding was successful)
        let block = &block.unwrap();
        println!("Valid Randao? {}", !process_randao(&mut state, &block, &spec).is_err());
    }
});

// Code for generating a BeaconBlock (use as a corpus)
pub fn generate_randao() {
    println!("Generating Block with valid Randao");
    let spec = MinimalEthSpec::default_spec();

    let keypairs = from_keypairs_file(&spec);

    let mut state = from_minimal_state_file(&spec);

    let mut builder = TestingBeaconBlockBuilder::new(&spec);

    // Setup block
    builder.set_slot(state.slot);

    // Add randao
    let proposer_index = state.get_beacon_proposer_index(state.slot, RelativeEpoch::Current, &spec).unwrap();
    let keypair = &keypairs[proposer_index];
    builder.set_randao_reveal::<MinimalEthSpec>(&keypair.sk, &state.fork, &spec);

    let block = builder.build::<MinimalEthSpec>(&keypair.sk, &state.fork, &spec);

    assert!(!process_randao(&mut state, &block, &spec).is_err());
    println!("Block {}", hex::encode(block.as_ssz_bytes()));
}
