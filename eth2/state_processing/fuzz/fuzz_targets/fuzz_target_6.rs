#![no_main]
use libfuzzer_sys::fuzz_target;
use state_processing::per_epoch_processing::process_justification_and_finalization;
use state_processing::per_epoch_processing::validator_statuses::TotalBalances;

use types::*;

type TestEthSpec = MinimalEthSpec;

fuzz_target!(|wrapper: (BeaconState<TestEthSpec>, TotalBalances)| {
    // Get default spec
    // let spec = TestEthSpec::default_spec();

    // Upnack arbitrary values
    let (mut state, total_balances) = wrapper;

    // Fuzz Target
    process_justification_and_finalization(&mut state, &total_balances);
});
