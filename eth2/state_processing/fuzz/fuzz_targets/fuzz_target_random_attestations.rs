#![no_main]
extern crate hex;
#[macro_use] extern crate libfuzzer_sys;
extern crate ssz;
extern crate state_processing;
extern crate state_processing_fuzz;
extern crate store;
extern crate types;
extern crate tree_hash;

use ssz::Decode;
use state_processing_fuzz::from_minimal_state_file;
use types::*;
use state_processing::process_attestations;

// Fuzz per_block_processing - BeaconBlock.Eth1Data
fuzz_target!(|data: &[u8]| {
    // Convert data to Attestation
    let attestation = Attestation::from_ssz_bytes(data);

    // If valid attestation attempt to process it
    if !attestation.is_err() {
        println!("Processing block");

        // Generate a chain_spec
        let spec = MinimalEthSpec::default_spec();

        // Generate a BeaconState and BeaconBlock (with Fuzzed - Attestation)
        let mut state = from_minimal_state_file(&spec);

        // Fuzz per_block_processing (Attestation)
        println!("Valid block? {}", !process_attestations(&mut state, &[attestation.unwrap()], &spec).is_err());
    }
});
