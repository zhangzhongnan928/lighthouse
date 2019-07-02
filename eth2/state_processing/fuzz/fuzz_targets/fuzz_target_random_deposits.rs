#![no_main]
extern crate hex;
#[macro_use]
extern crate libfuzzer_sys;
extern crate ssz;
extern crate state_processing;
extern crate state_processing_fuzz;
extern crate tree_hash;
extern crate types;

use ssz::{Decode, Encode};
use state_processing::process_deposits;
use state_processing_fuzz::{
    from_keypairs_file, from_minimal_state_file, insert_eth1_data, MerkleTree, NUM_VALIDATORS,
};
use tree_hash::TreeHash;
use types::test_utils::TestingDepositBuilder;
use types::*;

// Fuzz per_block_processing - process_deposits
fuzz_target!(|data: &[u8]| {
    // Convert data to a Deposit
    let deposit = Deposit::from_ssz_bytes(&data);

    if deposit.is_ok() {
        println!("Processing deposit");
        let spec = MinimalEthSpec::default_spec();
        let mut state = from_minimal_state_file(&spec);

        let mut deposit = deposit.unwrap();

        // Add Eth1Data to state so deposit can process
        insert_eth1_data(&mut state, &mut deposit);

        // Run process_deposits
        println!(
            "Valid Deposit? {}",
            process_deposits(&mut state, &[deposit], &spec).is_ok()
        );
    }
});
