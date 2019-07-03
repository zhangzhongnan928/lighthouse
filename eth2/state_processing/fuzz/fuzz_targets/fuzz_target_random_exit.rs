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
use state_processing::process_exits;
use state_processing_fuzz::{from_minimal_state_file, increase_state_epoch, STATE_EPOCH};
use types::*;

// Fuzz per_block_processing - process_exits
fuzz_target!(|data: &[u8]| {
    // Convert data to a VoluntaryExit
    let exit = VoluntaryExit::from_ssz_bytes(&data);

    if exit.is_ok() {
        let spec = MinimalEthSpec::default_spec();
        let mut state = from_minimal_state_file(&spec);

        // Increase state slot to allow validator to exit
        let new_epoch = Epoch::new(STATE_EPOCH + spec.persistent_committee_period);
        increase_state_epoch(&mut state, new_epoch, &spec);

        let exit = exit.unwrap();

        // Run process_exits
        let _ = process_exits(&mut state, &[exit], &spec);
    }
});
