#![no_main]
extern crate hex;
#[macro_use] extern crate libfuzzer_sys;
extern crate ssz;
extern crate state_processing;
extern crate state_processing_fuzz;
extern crate types;
extern crate tree_hash;

use ssz::Decode;
use state_processing_fuzz::{from_minimal_state_file, increase_state_epoch, STATE_EPOCH};
use types::*;
use state_processing::process_exits;


// Fuzz `per_block_processing()`
fuzz_target!(|data: &[u8]| {
    // Convert data to a BeaconBlock
    let exit = VoluntaryExit::from_ssz_bytes(&data);

    if exit.is_ok() {
        println!("Processing VoluntaryExit");

        let spec = MinimalEthSpec::default_spec();
        let mut state = from_minimal_state_file(&spec);

        // Increase state slot to allow validator to exit
        let new_epoch = Epoch::new(STATE_EPOCH + spec.persistent_committee_period);
        increase_state_epoch(&mut state, new_epoch, &spec);

        let exit = exit.unwrap();

        // Fuzz per_block_processing (if decoding was successful)
        println!("Valid VoluntaryExit? {}", process_exits(&mut state, &[exit], &spec).is_ok());
    }
});
