#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate ssz;
extern crate state_processing;
extern crate types;

use ssz::{Decode, DecodeError};
use std::env;
use std::fs::File;
use std::io::prelude::*;
use types::*;
use state_processing::{per_block_processing, block_processing_builder::BlockProcessingBuilder};


// Fuzz per_block_processing
fuzz_target!(|data: &[u8]| {
    // Convert data to a BeaconBlock
    let block = BeaconBlock::from_ssz_bytes(&data) ;

    if !block.is_err() {
        println!("Processing block");
        // Generate a chain_spec
        let spec = MinimalEthSpec::default_spec();

        let mut state = read_state_from_file();

        // Fuzz per_block_processing (if decoding was successful)
        per_block_processing(&mut state, &block.unwrap(), &spec);
    }
});

fn get_builder(spec: &ChainSpec) -> (BlockProcessingBuilder<MinimalEthSpec>) {
    let num_validators = 2;
    let mut builder = BlockProcessingBuilder::new(num_validators, &spec);

    // Set the state and block to be in the last slot of the 4th epoch.
    let slot =
        (MinimalEthSpec::genesis_epoch() + 4).end_slot(MinimalEthSpec::slots_per_epoch());
    builder.set_slot(last_slot_of_epoch, &spec);
    builder.build_caches(&spec);

    (builder)
}

fn read_state_from_file() -> BeaconState<MinimalEthSpec> {
    let mut file = File::open("fuzz/state.bin").unwrap();
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer);

    BeaconState::from_ssz_bytes(&buffer).unwrap()
}
