#![no_main]
extern crate state_processing_fuzz;
extern crate hex;
#[macro_use] extern crate libfuzzer_sys;
extern crate ssz;
extern crate state_processing;
extern crate store;
extern crate types;
extern crate tree_hash;

use ssz::{Decode, DecodeError, Encode};
use state_processing_fuzz::{from_keypairs_file, from_minimal_state_file, NUM_VALIDATORS};
use tree_hash::SignedRoot;
use types::*;
use types::test_utils::TestingAttesterSlashingBuilder;
use state_processing::process_attester_slashings;


// Fuzz per_block_processing - BeaconBlock.Eth1Data
fuzz_target!(|data: &[u8]| {
    // Convert data to Attestation
    let attester_slashing = AttesterSlashing::from_ssz_bytes(data);

    // If valid attestation attempt to process it
    if !attester_slashing.is_err() {
        println!("Processing block");

        // Generate a chain_spec
        let spec = MinimalEthSpec::default_spec();

        // Generate a BeaconState and BeaconBlock (with Fuzzed - Attestation)
        let mut state = from_minimal_state_file(&spec);

        // Fuzz per_block_processing (Attestation)
        println!("Valid AttesterSlashing? {}", !process_attester_slashings(&mut state, &[attester_slashing.unwrap()], &spec).is_err());
    }
});

// Code for printing an AtterSlashing to terminal (use for creating a corpus)
pub fn generate_attester_slashing() {
    println!("Generating Code");
    // Generate a chain_spec
    let spec = MinimalEthSpec::default_spec();

    // Generate a BeaconState and BeaconBlock (with Fuzzed - Attestation)
    let mut state = from_minimal_state_file(&spec);

    // Create Attester Slashing
    let keypairs = from_keypairs_file(&spec);

    let mut validator_indices: Vec<u64> = vec![];
    for i in 0..NUM_VALIDATORS {
        validator_indices.push(i as u64);
    }

    let signer = |validator_index: u64, message: &[u8], epoch: Epoch, domain: Domain| {
        let key_index = validator_indices
            .iter()
            .position(|&i| i == validator_index)
            .expect("Unable to find attester slashing key");
        let domain = spec.get_domain(epoch, domain, &state.fork);
        Signature::new(message, domain, &keypairs[key_index].sk)
    };

    let attester_slashing = TestingAttesterSlashingBuilder::double_vote(&validator_indices, signer);

    assert!(!process_attester_slashings(&mut state, &[attester_slashing.clone()], &spec).is_err());

    println!("AttesterSlashing {}", hex::encode(attester_slashing.as_ssz_bytes()));

}
