extern crate hex;
extern crate hashing;
extern crate ssz;
extern crate state_processing;
extern crate state_processing_fuzz;
extern crate store;
extern crate types;
extern crate tree_hash;

use ssz::{Decode, Encode};
use state_processing::process_transfers;
use state_processing_fuzz::*;
use std::fs::File;
use std::io::{BufReader, LineWriter};
use std::io::prelude::*;
use std::path::PathBuf;
use std::convert::TryInto;
use store::StorageContainer;
use tree_hash::TreeHash;
use types::*;

pub fn main() {
    let bytes = hex::decode("040000000000000001000000000000000010a5d4e800000000bfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbf2700000000000000abb2a7f3635928dc438d15a38f2c7d6a166b8c04c76ed59c9da46d4014b63f5fcf00bfbfbf2700000000000000abb2a7f3635928dc438d15a38f2c7d6a166b8c04c76ed59c9da46d4014b63f5fcf0097dcba1393a7b618e49524fcfce0362f6df452da5adff8bd7162a9919f1fa8cb9ba95f2c8e9b033d5a4deba6b30de8").unwrap();
    let transfer = Transfer::from_ssz_bytes(&bytes).unwrap();

    let spec = MinimalEthSpec::default_spec();
    let mut state = from_minimal_state_file(&spec);

    // Increase proposer's balance so transaction is valid
    let sender = state.get_beacon_proposer_index(state.slot, RelativeEpoch::Current, &spec).unwrap();
    state.balances[sender as usize] += 1_010_000_000_000;

    // Fuzz per_block_processing (if decoding was successful)
    println!("Valid Transfer? {}", process_transfers(&mut state, &[transfer], &spec).is_ok());
}
