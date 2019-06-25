#![no_main]
extern crate hex;
#[macro_use] extern crate libfuzzer_sys;
extern crate ssz;
extern crate state_processing;
extern crate types;
extern crate tree_hash;

use ssz::{Decode, DecodeError, Encode};
use std::env;
use std::fs::File;
use std::io::BufReader;
use std::io::prelude::*;
use tree_hash::SignedRoot;
use types::*;
use types::test_utils::{TestingBeaconBlockBuilder, TestingBeaconStateBuilder};
use state_processing::{per_block_processing, block_processing_builder::BlockProcessingBuilder};

pub const NUM_VALIDATORS: usize = 8;

// Fuzz per_block_processing - BeaconBlock.Eth1Data
fuzz_target!(|data: &[u8]| {
    // Convert data to Attestation
    let attestation = Attestation::from_ssz_bytes(data);

    // If valid attestation attempt to process it
    if !attestation.is_err() {
        println!("Processing block");

        // Generate a chain_spec
        let spec = MinimalEthSpec::default_spec();

        // Generate a BeaconState and BeaconBlock
        let (block, mut state) = build_beacon_state_and_block(&spec, attestation.unwrap());

        // Fuzz per_block_processing (if decoding was successful) and print output
        println!("Valid block? {}", !per_block_processing(&mut state, &block, &spec).is_err());
    }
});

// Generate a default BeaconState and default BeaconBlock with give `Attestation`
fn build_beacon_state_and_block(spec: &ChainSpec, attestation: Attestation) -> (BeaconBlock, BeaconState<MinimalEthSpec>) {
    // Build state with slot at end of 4th epoch
    let slot =
        (MinimalEthSpec::genesis_epoch() + 4).end_slot(MinimalEthSpec::slots_per_epoch());
    let state = read_state_from_file();
    let keypairs = read_keypairs();

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

    block_builder.set_randao_reveal::<MinimalEthSpec>(&keypair.sk, &state.fork, spec);

    // Use secret keys to generate valid attestation
    let secret_keys = keypairs.iter().map(|x| &x.sk).collect::<Vec<_>>();
    block_builder.insert_attestations(&state, secret_keys.as_slice(), 1, &spec);

    // Add Fuzz generated Attestation to BeaconBlock
    //block_builder.block.body.attestations.push(attestation);

    let block = block_builder.build::<MinimalEthSpec>(&keypair.sk, &state.fork, spec);

    (block, state)
}

// Read the deterministic keypairs from file
fn read_keypairs() -> Vec<Keypair>{
    let file = File::open("fuzz/binaries/keypairs.txt").unwrap();
    let file = BufReader::new(file);
    let mut keypairs: Vec<Keypair> = vec![];

    for line in file.lines() {
        let line = line.unwrap();
        let parts = line.split(",").collect::<Vec<&str>>();
        let pk = hex::decode(parts[0]).unwrap();
        let sk = hex::decode(parts[1]).unwrap();

        let pk = PublicKey::from_ssz_bytes(&pk).unwrap();
        let sk = SecretKey::from_ssz_bytes(&sk).unwrap();
        let pair = Keypair {
            sk,
            pk,
        };
        keypairs.push(pair);
    }

    keypairs
}

// Read a BeaconState from file (far faster than building)
fn read_state_from_file() -> BeaconState<MinimalEthSpec> {
    let mut file = File::open("fuzz/binaries/state.bin").unwrap();
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer);

    BeaconState::from_ssz_bytes(&buffer).unwrap()
}
