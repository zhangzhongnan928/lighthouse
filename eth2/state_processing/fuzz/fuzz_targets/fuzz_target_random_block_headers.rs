#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate ssz;
extern crate state_processing;
extern crate state_processing_fuzz;
extern crate tree_hash;
extern crate types;

use ssz::Decode;
use state_processing_fuzz::from_minimal_state_file;
use types::*;
use state_processing::process_block_header;


// Fuzz `per_block_processing()`
fuzz_target!(|data: &[u8]| {
    // Convert data to a BeaconBlock
    let block = BeaconBlock::from_ssz_bytes(&data);

    if !block.is_err() {
        println!("Processing block header");
        // Generate a chain_spec
        let spec = MinimalEthSpec::default_spec();
        let mut state = from_minimal_state_file(&spec);

        // Fuzz per_block_processing (if decoding was successful)
        let block = &block.unwrap();
        println!("Valid block header? {}", !process_block_header(&mut state, &block, &spec, true).is_err());
    }
});
