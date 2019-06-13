#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate state_processing;

// Fuzz per_block_processing
fuzz_target!(|data: &[u8]| {
    // Generate a chain_spec
    
    // Generate a BeaconState after genesis

    // Convert data to a BeaconBlock

});
