#![no_main]
use libfuzzer_sys::fuzz_target;
use state_processing::per_epoch_processing::process_registry_updates;
use types::*;

type TestEthSpec = MinimalEthSpec;

fuzz_target!(|wrapper: (BeaconState<TestEthSpec>)| {
    // Get default spec
    let spec = TestEthSpec::default_spec();

    // Upnack arbitrary values
    let mut state = wrapper;

    // Fuzz Target
    process_registry_updates(&mut state, &spec);
});
