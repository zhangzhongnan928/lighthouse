#![no_main]
extern crate hex;
#[macro_use] extern crate libfuzzer_sys;
extern crate ssz;
extern crate state_processing;
extern crate state_processing_fuzz;
extern crate types;
extern crate tree_hash;

use ssz::{Decode, Encode};
use state_processing_fuzz::{from_minimal_state_file, from_keypairs_file, NUM_VALIDATORS, MerkleTree};
use tree_hash::TreeHash;
use types::*;
use types::test_utils::TestingDepositBuilder;
use state_processing::process_deposits;


// Fuzz `per_block_processing()`
fuzz_target!(|data: &[u8]| {
    // Generate Deposit
    //generate_deposit();

    // Convert data to a BeaconBlock
    let deposit = Deposit::from_ssz_bytes(&data);

    if deposit.is_ok() {
        println!("Processing deposit");
        // Generate a chain_spec
        let spec = MinimalEthSpec::default_spec();
        let mut state = from_minimal_state_file(&spec);

        let mut deposit = deposit.unwrap();

        // Add Eth1Data to state so deposit can process
        insert_eth1_data(&mut state, &mut deposit);

        // Fuzz per_block_processing (if decoding was successful)
        println!("Valid Deposit? {}", process_deposits(&mut state, &[deposit], &spec).is_ok());
    }
});


pub fn generate_deposit() {
    println!("Generating deposit");
    let spec = MinimalEthSpec::default_spec();
    let mut state = from_minimal_state_file(&spec);
    let keypairs = from_keypairs_file(&spec);
    let keypair = keypairs[NUM_VALIDATORS + 1].clone();

    let amount = 32_000_000_000;

    let mut builder = TestingDepositBuilder::new(keypair.pk.clone(), amount);
    builder.set_index(state.deposit_index);
    builder.sign(
        &keypair,
        state.slot.epoch(MinimalEthSpec::slots_per_epoch()),
        &state.fork,
        &spec,
    );

    let mut deposit = builder.build();

    insert_eth1_data(&mut state, &mut deposit);
    assert!(process_deposits(&mut state, &[deposit.clone()], &spec).is_ok());

    println!("Deposit {}", hex::encode(deposit.as_ssz_bytes()));
}

pub fn insert_eth1_data(state: &mut BeaconState<MinimalEthSpec>, deposit: &mut Deposit) {
    let block_hash = Hash256::from_slice(&vec![1u8; 32]);

    let signed_root = Hash256::from_slice(&deposit.data.tree_hash_root());

    let merkle_root = MerkleTree::create(&[signed_root], 32);
    // Uncomment this line if generating_deposit()
    //deposit.proof = merkle_root.generate_proof(0, 32).1.into();

    let eth1_data = Eth1Data {
        deposit_root: merkle_root.hash(),
        deposit_count: 1,
        block_hash,
    };
    state.latest_eth1_data = eth1_data;
}
