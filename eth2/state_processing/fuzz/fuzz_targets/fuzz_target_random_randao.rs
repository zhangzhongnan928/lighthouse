#![no_main]
extern crate hex;
#[macro_use]
extern crate libfuzzer_sys;
extern crate ssz;
extern crate state_processing;
extern crate state_processing_fuzz;
extern crate types;

use ssz::Decode;
use state_processing::process_randao;
use state_processing_fuzz::from_minimal_state_file;
use types::*;

// Fuzz per_block_processing - process_randao
fuzz_target!(|data: &[u8]| {
    // Convert data to a BeaconBlock with randao
    let block = BeaconBlock::from_ssz_bytes(&data);

    if block.is_ok() {
        let spec = MinimalEthSpec::default_spec();
        let mut state = from_minimal_state_file(&spec);

        // Run process_randao
        let block = &block.unwrap();
        let _ = process_randao(&mut state, &block, &spec);
    }
});
