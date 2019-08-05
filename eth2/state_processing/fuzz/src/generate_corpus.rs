extern crate hashing;
extern crate hex;
extern crate ssz;
extern crate state_processing;
extern crate store;
extern crate tree_hash;
extern crate types;

use crate::{
    from_keypairs_file, from_minimal_state_file, increase_state_epoch, insert_eth1_data,
    NUM_VALIDATORS, STATE_EPOCH,
};
use ssz::Encode;
use state_processing::*;
use tree_hash::SignedRoot;
use types::test_utils::{
    TestingAttestationBuilder, TestingAttesterSlashingBuilder, TestingBeaconBlockBuilder,
    TestingDepositBuilder, TestingProposerSlashingBuilder, TestingVoluntaryExitBuilder,
};
use types::*;

// Generate an Attestation and print to terminal
pub fn generate_attestation() {
    println!("Generating an Attestation");
    let spec = MinimalEthSpec::default_spec();
    let mut state = from_minimal_state_file(&spec);
    let keypairs = from_keypairs_file(&spec);

    // Build valid Attestation
    let shard = 0;
    let cc = state
        .get_crosslink_committee_for_shard(shard, RelativeEpoch::Current)
        .unwrap();
    let mut builder = TestingAttestationBuilder::new(&state, cc.committee, cc.slot, shard, &spec);

    // Get keys for all validators in the committee
    let signing_secret_keys: Vec<&SecretKey> = cc.committee.iter()
        .map(|validator_index| &keypairs[*validator_index].sk)
        .collect();
    // Sign the attestation by all members of the committee
    builder.sign(
        cc.committee,
        &signing_secret_keys,
        &state.fork,
        &spec,
        false,
    );

    // Build
    let attestation = builder.build();

    // Verify Attestation is valid and print to terminal
    assert!(!process_attestations(&mut state, &[attestation.clone()], &spec).is_err());
    println!(
        "Attestation {}",
        hex::encode(attestation.as_ssz_bytes())
    );
}

// Generate an AtterSlashing and print to terminal
pub fn generate_attester_slashing() {
    println!("Generating an AttesterSlashing");
    let spec = MinimalEthSpec::default_spec();
    let mut state = from_minimal_state_file(&spec);
    let keypairs = from_keypairs_file(&spec);

    // Use validator SecretKeys to make an attester double vote
    let mut validator_indices: Vec<u64> = vec![];
    for i in 0..NUM_VALIDATORS {
        validator_indices.push(i as u64);
    }

    let signer = |validator_index: u64, message: &[u8], epoch: Epoch, domain: Domain| {
        let key_index = validator_indices
            .iter()
            .position(|&i| i == validator_index)
            .expect("Unable to find attester slashing key");
        let domain = spec.get_domain(epoch, domain, &state.fork);
        Signature::new(message, domain, &keypairs[key_index].sk)
    };

    // Build Valid AttesterSlashing
    let attester_slashing = TestingAttesterSlashingBuilder::double_vote(&validator_indices, signer);

    // Verify AttesterSlashing is valid and print to terminal
    assert!(!process_attester_slashings(&mut state, &[attester_slashing.clone()], &spec).is_err());
    println!(
        "AttesterSlashing {}",
        hex::encode(attester_slashing.as_ssz_bytes())
    );
}

// Generate a BeaconBlock and print to terminal
pub fn generate_block_header() {
    println!("Generating a BeaconBlock");
    let spec = MinimalEthSpec::default_spec();
    let mut state = from_minimal_state_file(&spec);
    let keypairs = from_keypairs_file(&spec);

    let proposer_index = state
        .get_beacon_proposer_index(state.slot, RelativeEpoch::Current, &spec)
        .unwrap();
    let keypair = &keypairs[proposer_index];

    let mut builder = TestingBeaconBlockBuilder::new(&spec);
    builder.set_slot(state.slot);
    builder.set_parent_root(Hash256::from_slice(
        &state.latest_block_header.signed_root(),
    ));
    let block = builder.build(&keypair.sk, &state.fork, &spec);

    assert!(!process_block_header(&mut state, &block, &spec, true).is_err());
    println!("Block {}", hex::encode(block.as_ssz_bytes()));
}

// Generate a Deposit and print to terminal
pub fn generate_deposit() {
    println!("Generating a Deposit");
    let spec = MinimalEthSpec::default_spec();
    let mut state = from_minimal_state_file(&spec);
    let keypairs = from_keypairs_file(&spec);

    let keypair = keypairs[NUM_VALIDATORS + 1].clone();
    let amount = 32_000_000_000;

    let mut builder = TestingDepositBuilder::new(keypair.pk.clone(), amount);
    // builder.set_index(state.eth1_deposit_index);
    builder.sign(
        &keypair,
        state.slot.epoch(MinimalEthSpec::slots_per_epoch()),
        &state.fork,
        &spec,
    );

    // Build Deposit
    let mut deposit = builder.build();

    // Add the Deposit to BeaconState as Eth1Data
    insert_eth1_data(&mut state, &mut deposit);

    // Verify Deposit is valid and print to terminal
    assert!(process_deposits(&mut state, &[deposit.clone()], &spec).is_ok());
    println!("Deposit {}", hex::encode(deposit.as_ssz_bytes()));
}

// Code for printing an AttesterSlashing to terminal (use for creating a corpus)
pub fn generate_proposer_slashing() {
    println!("Generating Code");
    // Generate a chain_spec
    let spec = MinimalEthSpec::default_spec();

    // Generate a BeaconState and BeaconBlock (with Fuzzed - Attestation)
    let mut state = from_minimal_state_file(&spec);

    // Create Attester Slashing
    let keypairs = from_keypairs_file(&spec);
    let validator_index = 0;

    let signer = |_validator_index: u64, message: &[u8], epoch: Epoch, domain: Domain| {
        let domain = spec.get_domain(epoch, domain, &state.fork);
        Signature::new(message, domain, &keypairs[validator_index].sk)
    };

    let proposer_slashing = TestingProposerSlashingBuilder::double_vote::<MinimalEthSpec, _>(
        validator_index as u64,
        signer,
    );

    assert!(!process_proposer_slashings(&mut state, &[proposer_slashing.clone()], &spec).is_err());

    println!(
        "ProposerSlashing {}",
        hex::encode(proposer_slashing.as_ssz_bytes())
    );
}

// Generate a BeaconBlock with Randao and print to terminal
pub fn generate_randao() {
    println!("Generating Block with valid Randao");
    let spec = MinimalEthSpec::default_spec();
    let keypairs = from_keypairs_file(&spec);
    let mut state = from_minimal_state_file(&spec);

    let mut builder = TestingBeaconBlockBuilder::new(&spec);

    let proposer_index = state
        .get_beacon_proposer_index(state.slot, RelativeEpoch::Current, &spec)
        .unwrap();

    // Setup block
    builder.set_slot(state.slot);
    builder.set_parent_root(Hash256::from_slice(
        &state.latest_block_header.signed_root(),
    ));

    // Add randao
    let keypair = &keypairs[proposer_index];
    builder.set_randao_reveal(&keypair.sk, &state.fork, &spec);

    // Build block
    let block = builder.build(&keypair.sk, &state.fork, &spec);

    // Verify randao is valid and print it to terminal
    assert!(!process_randao(&mut state, &block, &spec).is_err());
    println!("Block {}", hex::encode(block.as_ssz_bytes()));
}

// Generate a valid Transfer and print to terminal
pub fn generate_transfer() {
    println!("Generating Transfer");
    let spec = MinimalEthSpec::default_spec();
    let keypairs = from_keypairs_file(&spec);
    let mut state = from_minimal_state_file(&spec);

    // Select proposer as payee
    let proposer_index = state
        .get_beacon_proposer_index(state.slot, RelativeEpoch::Current, &spec)
        .unwrap();
    let keypair = keypairs[proposer_index].clone();

    // Create Transfer
    let amount = 1_000_000_000_000;
    let fee = 10_000_000_000;
    let sender = proposer_index as u64;
    let recipient = ((proposer_index + 1) % 2) as u64;

    let mut transfer = Transfer {
        sender,
        recipient,
        amount,
        fee,
        slot: state.slot,
        pubkey: keypair.pk,
        signature: Signature::empty_signature(),
    };

    // Generate valid Signature
    let message = transfer.signed_root();
    let epoch = transfer.slot.epoch(MinimalEthSpec::slots_per_epoch());
    let domain = spec.get_domain(epoch, Domain::Transfer, &state.fork);
    transfer.signature = Signature::new(&message, domain, &keypair.sk);

    // Increase sender's balance so transaction is valid
    state.balances[sender as usize] += fee + amount;

    // Verify transaction is valid
    assert!(!process_transfers(&mut state, &[transfer.clone()], &spec).is_err());
    println!("Block with Transfer {}", hex::encode(transfer.as_ssz_bytes()));
}

// Code for generating VoluntaryExit and print to terminal
pub fn generate_voluntary_exit() {
    let spec = MinimalEthSpec::default_spec();
    let mut state = from_minimal_state_file(&spec);
    let keypairs = from_keypairs_file(&spec);

    // Increase state slot to allow validator to exit
    let new_epoch = Epoch::new(STATE_EPOCH + spec.persistent_committee_period);
    increase_state_epoch(&mut state, new_epoch, &spec);

    // Let proposer be the validator to exit
    let proposer_index = state
        .get_beacon_proposer_index(state.slot, RelativeEpoch::Current, &spec)
        .unwrap();
    let keypair = keypairs[proposer_index].clone();

    // Build a Voluntary Exit
    let mut builder = TestingVoluntaryExitBuilder::new(new_epoch, proposer_index as u64);
    builder.sign(&keypair.sk, &state.fork, &spec);
    let exit = builder.build();

    assert!(process_exits(&mut state, &[exit.clone()], &spec).is_ok());
    println!("VoluntaryExit {}", hex::encode(&exit.as_ssz_bytes()));
}
