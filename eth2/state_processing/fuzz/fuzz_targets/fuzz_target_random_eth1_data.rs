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
use state_processing::process_eth1_data;


// Fuzz `per_block_processing()`
fuzz_target!(|data: &[u8]| {
    // Convert data to a BeaconBlock
    let eth1_data = Eth1Data::from_ssz_bytes(&data);

    if !eth1_data.is_err() {
        println!("Processing randao");
        // Generate a chain_spec
        let spec = MinimalEthSpec::default_spec();
        let mut state = from_minimal_state_file(&spec);

        // Fuzz per_block_processing (if decoding was successful)
        let eth1_data = &eth1_data.unwrap();
        println!("Valid Eth1Data Vote? {}", !process_eth1_data(&mut state, &eth1_data, &spec).is_err());
    }
});
