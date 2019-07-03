#![no_main]
extern crate hex;
extern crate state_processing_fuzz;
#[macro_use]
extern crate libfuzzer_sys;
extern crate ssz;
extern crate state_processing;
extern crate store;
extern crate tree_hash;
extern crate types;

use ssz::Decode;
use state_processing::process_attester_slashings;
use state_processing_fuzz::from_minimal_state_file;
use types::*;

// Fuzz per_block_processing - process_attester_slashings
fuzz_target!(|data: &[u8]| {
    // Convert data to Attestation
    let attester_slashing = AttesterSlashing::from_ssz_bytes(data);

    // If valid attestation attempt to process it
    if attester_slashing.is_ok() {
        let spec = MinimalEthSpec::default_spec();
        let mut state = from_minimal_state_file(&spec);

        // Run process_attester_slashings
        let _ = process_attester_slashings(&mut state, &[attester_slashing.unwrap()], &spec);
    }
});
