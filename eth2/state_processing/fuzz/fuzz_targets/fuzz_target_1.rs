#![no_main]
use libfuzzer_sys::fuzz_target;
use state_processing::per_block_processing::verify_attestation_for_block_inclusion;
use state_processing::VerifySignatures;
use types::*;

type TestEthSpec = MinimalEthSpec;

fuzz_target!(|wrapper: (BeaconState<TestEthSpec>, Attestation<TestEthSpec>, VerifySignatures)| {
    // Get default spec
    let spec = TestEthSpec::default_spec();

    // Upnack arbitrary values
    let (state, attestation, verify_signatures) = wrapper;

    // Fuzz Target
    verify_attestation_for_block_inclusion(&state, &attestation, verify_signatures, &spec);
});
