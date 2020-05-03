#![no_main]
use libfuzzer_sys::fuzz_target;
use state_processing::per_epoch_processing::process_rewards_and_penalties;
use state_processing::per_epoch_processing::validator_statuses::ValidatorStatuses;
use types::*;

type TestEthSpec = MinimalEthSpec;

fuzz_target!(|wrapper: (BeaconState<TestEthSpec>, ValidatorStatuses)| {
    // Get default spec
    let spec = TestEthSpec::default_spec();

    // Upnack arbitrary values
    let (mut state, mut validator_statuses) = wrapper;

    // Fuzz Target
    process_rewards_and_penalties(&mut state, &mut validator_statuses, &spec);
});
