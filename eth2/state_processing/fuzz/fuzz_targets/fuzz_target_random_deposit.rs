#![no_main]
extern crate hex;
#[macro_use]
extern crate libfuzzer_sys;
extern crate ssz;
extern crate state_processing;
extern crate state_processing_fuzz;
extern crate tree_hash;
extern crate types;

use ssz::Decode;
use state_processing::process_deposits;
use state_processing_fuzz::{from_minimal_state_file, insert_eth1_data};
use types::*;

// Fuzz per_block_processing - process_deposits
fuzz_target!(|data: &[u8]| {
    // Convert data to a Deposit
    let deposit = Deposit::from_ssz_bytes(&data);

    if deposit.is_ok() {
        let spec = MinimalEthSpec::default_spec();
        let mut state = from_minimal_state_file(&spec);

        let mut deposit = deposit.unwrap();

        // Add Eth1Data to state so deposit can process
        insert_eth1_data(&mut state, &mut deposit);

        // Run process_deposits
        let _ = process_deposits(&mut state, &[deposit], &spec);
    }
});
