#![no_main]
extern crate hex;
#[macro_use]
extern crate libfuzzer_sys;
extern crate ssz;
extern crate state_processing;
extern crate state_processing_fuzz;
extern crate store;
extern crate tree_hash;
extern crate types;

use ssz::Decode;
use state_processing::process_attestations;
use state_processing_fuzz::from_minimal_state_file;
use types::*;

// Fuzz per_block_processing - process_attestation
fuzz_target!(|data: &[u8]| {
    // Convert data to Attestation
    let attestation = Attestation::from_ssz_bytes(data);

    // If valid attestation attempt to process it
    if attestation.is_ok() {
        let spec = MinimalEthSpec::default_spec();
        let mut state = from_minimal_state_file(&spec);

        // Run `process_attestation`
        let _ = process_attestations(&mut state, &[attestation.unwrap()], &spec);
    }
});
