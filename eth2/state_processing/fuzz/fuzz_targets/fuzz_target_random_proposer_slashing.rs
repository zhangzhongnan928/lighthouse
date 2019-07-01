#![no_main]
extern crate hex;
#[macro_use] extern crate libfuzzer_sys;
extern crate ssz;
extern crate state_processing;
extern crate state_processing_fuzz;
extern crate types;

use ssz::{Decode, Encode};
use state_processing_fuzz::{from_keypairs_file, from_minimal_state_file};
use types::*;
use types::test_utils::TestingProposerSlashingBuilder;
use state_processing::process_proposer_slashings;


// Fuzz per_block_processing - BeaconBlock.Eth1Data
fuzz_target!(|data: &[u8]| {
    // Convert data to Attestation
    let proposer_slashing = ProposerSlashing::from_ssz_bytes(data);

    // If valid attestation attempt to process it
    if !proposer_slashing.is_err() {
        println!("Processing block");

        // Generate a chain_spec
        let spec = MinimalEthSpec::default_spec();

        // Generate a BeaconState and BeaconBlock (with Fuzzed - Attestation)
        let mut state = from_minimal_state_file(&spec);

        // Fuzz per_block_processing (Attestation)
        println!("Valid AttesterSlashing? {}", !process_proposer_slashings(&mut state, &[proposer_slashing.unwrap()], &spec).is_err());
    }
});

// Code for printing an AttesterSlashing to terminal (use for creating a corpus)
pub fn generate_proposer_slashing() {
    println!("Generating Code");
    // Generate a chain_spec
    let spec = MinimalEthSpec::default_spec();

    // Generate a BeaconState and BeaconBlock (with Fuzzed - Attestation)
    let mut state = from_minimal_state_file(&spec);

    // Create Attester Slashing
    let keypairs = from_keypairs_file(&spec);
    let validator_index = 0;

    let signer = |_validator_index: u64, message: &[u8], epoch: Epoch, domain: Domain| {
        let domain = spec.get_domain(epoch, domain, &state.fork);
        Signature::new(message, domain, &keypairs[validator_index].sk)
    };

    let proposer_slashing = TestingProposerSlashingBuilder::double_vote::<MinimalEthSpec, _>(validator_index as u64, signer);

    assert!(!process_proposer_slashings(&mut state, &[proposer_slashing.clone()], &spec).is_err());

    println!("ProposerSlashing {}", hex::encode(proposer_slashing.as_ssz_bytes()));

}
