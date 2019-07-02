#![no_main]
extern crate hex;
#[macro_use]
extern crate libfuzzer_sys;
extern crate ssz;
extern crate state_processing;
extern crate state_processing_fuzz;
extern crate types;

use ssz::{Decode, Encode};
use state_processing::process_proposer_slashings;
use state_processing_fuzz::{from_keypairs_file, from_minimal_state_file};
use types::test_utils::TestingProposerSlashingBuilder;
use types::*;

// Fuzz per_block_processing - process_proposer_slashings
fuzz_target!(|data: &[u8]| {
    // Convert data to ProposerSlashing
    let proposer_slashing = ProposerSlashing::from_ssz_bytes(data);

    // If valid attestation attempt to process it
    if !proposer_slashing.is_err() {
        println!("Processing ProposerSlashing");
        let spec = MinimalEthSpec::default_spec();
        let mut state = from_minimal_state_file(&spec);

        // Run process_proposer_slashings
        println!(
            "Valid AttesterSlashing? {}",
            !process_proposer_slashings(&mut state, &[proposer_slashing.unwrap()], &spec).is_err()
        );
    }
});
