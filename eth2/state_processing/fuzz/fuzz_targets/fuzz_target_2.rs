#![no_main]
extern crate hex;
#[macro_use] extern crate libfuzzer_sys;
extern crate ssz;
extern crate state_processing;
extern crate types;
extern crate tree_hash;

use ssz::{Decode, DecodeError, Encode};
use tree_hash::SignedRoot;
use types::*;
use types::test_utils::{TestingBeaconBlockBuilder, TestingBeaconStateBuilder};
use state_processing::{per_block_processing, block_processing_builder::BlockProcessingBuilder};

pub const NUM_VALIDATORS: usize = 2;

// Fuzz per_block_processing - BeaconBlock.Eth1Data
fuzz_target!(|data: &[u8]| {
    // Convert data to
    println!("Processing block");
    // Generate a chain_spec
    let spec = FoundationEthSpec::spec();

    // Generate a BeaconState and BeaconBlock
    let (block, mut state) = build_beacon_state_and_block(&spec, NUM_VALIDATORS);
    //println!("State {}", hex::encode(state.as_ssz_bytes()));

    // Fuzz per_block_processing (if decoding was successful)
    println!("{}", per_block_processing(&mut state, &block, &spec).is_err());
});

fn build_beacon_state_and_block(spec: &ChainSpec, num_validators: usize) -> (BeaconBlock, BeaconState<FoundationEthSpec>) {
    let mut state_builder =
        TestingBeaconStateBuilder::from_default_keypairs_file_if_exists(num_validators, &spec);
    let slot = (spec.genesis_epoch + 4).end_slot(spec.slots_per_epoch);
    state_builder.teleport_to_slot(slot, &spec);
    state_builder.build_caches(&spec);

    let (state, keypairs) = state_builder.build();

    let mut block_builder = TestingBeaconBlockBuilder::new(spec);

    block_builder.set_slot(slot);

    match state.get_block_root(slot) {
        Ok(root) => block_builder.set_previous_block_root(*root),
        Err(_) => block_builder.set_previous_block_root(Hash256::from_slice(
            &state.latest_block_header.signed_root(),
        )),
    }

    let proposer_index = state
        .get_beacon_proposer_index(state.slot, RelativeEpoch::Current, spec)
        .unwrap();
    let keypair = &keypairs[proposer_index];

    block_builder.set_randao_reveal(&keypair.sk, &state.fork, spec);

    // TODO: Add fuzz data here into block

    let block = block_builder.build(&keypair.sk, &state.fork, spec);

    (block, state)
}
