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
use state_processing::process_transfers;
use state_processing_fuzz::from_minimal_state_file;
use types::*;

// Fuzz per_block_processing - process_transfers
fuzz_target!(|data: &[u8]| {
    // Convert data to a Transfer
    let transfer = Transfer::from_ssz_bytes(&data);

    if transfer.is_ok() {
        println!("Processing Transfer");
        let spec = MinimalEthSpec::default_spec();
        let mut state = from_minimal_state_file(&spec);

        // Increase proposer's balance so transaction is valid
        let sender = state
            .get_beacon_proposer_index(state.slot, RelativeEpoch::Current, &spec)
            .unwrap();
        state.balances[sender as usize] += 1_010_000_000_000;

        let transfer = transfer.unwrap();

        // Run process_transfers
        println!(
            "Valid Transfer? {}",
            process_transfers(&mut state, &[transfer], &spec).is_ok()
        );
    }
});
