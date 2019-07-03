#![no_main]
extern crate hex;
#[macro_use]
extern crate libfuzzer_sys;
extern crate ssz;
extern crate state_processing;
extern crate state_processing_fuzz;
extern crate types;

use ssz::Decode;
use state_processing::process_eth1_data;
use state_processing_fuzz::from_minimal_state_file;
use types::*;

// Fuzz per_block_processing - process_eth1_data
fuzz_target!(|data: &[u8]| {
    // Convert data to a Eth1Data
    let eth1_data = Eth1Data::from_ssz_bytes(&data);

    if eth1_data.is_ok() {
        let spec = MinimalEthSpec::default_spec();
        let mut state = from_minimal_state_file(&spec);

        // Run process_eth1_data
        let eth1_data = &eth1_data.unwrap();
        let _ = process_eth1_data(&mut state, &eth1_data, &spec);
    }
});
