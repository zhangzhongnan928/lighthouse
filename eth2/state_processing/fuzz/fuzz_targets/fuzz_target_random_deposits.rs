#![no_main]
extern crate hex;
#[macro_use] extern crate libfuzzer_sys;
extern crate ssz;
extern crate state_processing;
extern crate state_processing_fuzz;
extern crate types;
extern crate tree_hash;

use ssz::{Decode, Encode};
use state_processing_fuzz::{from_minimal_state_file, from_keypairs_file, insert_eth1_data, NUM_VALIDATORS, MerkleTree};
use tree_hash::TreeHash;
use types::*;
use types::test_utils::TestingDepositBuilder;
use state_processing::process_deposits;


// Fuzz `per_block_processing()`
fuzz_target!(|data: &[u8]| {
    // Convert data to a BeaconBlock
    let deposit = Deposit::from_ssz_bytes(&data);

    if deposit.is_ok() {
        println!("Processing deposit");
        // Generate a chain_spec
        let spec = MinimalEthSpec::default_spec();
        let mut state = from_minimal_state_file(&spec);

        let mut deposit = deposit.unwrap();

        // Add Eth1Data to state so deposit can process
        insert_eth1_data(&mut state, &mut deposit);

        // Fuzz per_block_processing (if decoding was successful)
        println!("Valid Deposit? {}", process_deposits(&mut state, &[deposit], &spec).is_ok());
    }
});
