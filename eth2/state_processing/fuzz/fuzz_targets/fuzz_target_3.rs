#![no_main]
use libfuzzer_sys::fuzz_target;
use state_processing::per_epoch_processing::process_slashings;
use types::*;

type TestEthSpec = MinimalEthSpec;

fuzz_target!(|wrapper: (BeaconState<TestEthSpec>, u64)| {
    // Get default spec
    let spec = TestEthSpec::default_spec();

    // Upnack arbitrary values
    let (mut state, total_balance) = wrapper;

    // Fuzz Target
    process_slashings(&mut state, total_balance, &spec);
});
