#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate ssz;
extern crate state_processing;
extern crate state_processing_fuzz;
extern crate tree_hash;
extern crate types;

use ssz::Decode;
use state_processing_fuzz::{from_keypairs_file, from_minimal_state_file};
use tree_hash::SignedRoot;
use types::*;
use state_processing::per_block_processing;

// Fuzz `per_block_processing()`
fuzz_target!(|data: &[u8]| {
    // Convert data to a BeaconBlock
    let block = BeaconBlock::from_ssz_bytes(&data);

    if !block.is_err() {
        println!("Processing block");
        // Generate a chain_spec
        let spec = MinimalEthSpec::default_spec();
        let mut state = from_minimal_state_file(&spec);
        let keypairs = from_keypairs_file(&spec);


        // Set a valid block Signature
        let mut block = block.unwrap();
        sign_block(&mut block, &state, keypairs, &spec);


        // Fuzz per_block_processing (if decoding was successful)
        println!("Valid block? {}", !per_block_processing(&mut state, &block, &spec).is_err());
    }
});

fn sign_block(block: &mut BeaconBlock, state: &BeaconState<MinimalEthSpec>, keypairs: Vec<Keypair>, spec: &ChainSpec) {
    // Get secret key of the proposer
    let proposer_index = state
        .get_beacon_proposer_index(state.slot, RelativeEpoch::Current, spec)
        .unwrap();
    let keypair = &keypairs[proposer_index];

    // Sign Block
    let message = block.signed_root();
    let epoch = block.slot.epoch(MinimalEthSpec::slots_per_epoch());
    let domain = spec.get_domain(epoch, Domain::BeaconProposer, &state.fork);
    block.signature = Signature::new(&message, domain, &keypair.sk);
}
