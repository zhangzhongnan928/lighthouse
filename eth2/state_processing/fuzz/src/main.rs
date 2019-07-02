extern crate hex;
extern crate ssz;
extern crate state_processing;
extern crate state_processing_fuzz;
extern crate types;

use ssz::Decode;
use state_processing::process_transfers;
use state_processing_fuzz::*;
use types::*;

pub fn main() {
    // Subtract overflow in `Here 4`
    //let bytes = hex::decode("040000000000000001000000000000000010a5d4e800000000bfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbfbf2700000000000000abb2a7f3635928dc438d15a38f2c7d6a166b8c04c76ed59c9da46d4014b63f5fcf00bfbfbf2700000000000000abb2a7f3635928dc438d15a38f2c7d6a166b8c04c76ed59c9da46d4014b63f5fcf0097dcba1393a7b618e49524fcfce0362f6df452da5adff8bd7162a9919f1fa8cb9ba95f2c8e9b033d5a4deba6b30de8").unwrap();

    // Mehdi's
    //let bytes = hex::decode("000000ffffffffffffff030000000000ffffff000000f6ffffffffffffff0000000000000000000000000000000a00ff0a000000000a003a3a3a3a3a30ff25300000000000000000000a00ff0a3000ff15151515000000000a00ff000000ff00ff0000f6ffffffffffffff000000000000000000000000ffffffff00000a29000000ffffffff00000a2900000000ffff00000a00ff0a2900000000ffff0000ffff0000000a00ffffff0002ff000000fcff00000000000000").unwrap();

    // Subtract overflow in `Here 4`
    let bytes = hex::decode("000000000000000000000000000000000000b8000000000000000000fff6000000007900000000000000000000000000000000000000000000000000ffff0000ffff0000000a00ffffff0002ff000000fcff0000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000d7000000000000000000000000fff600000000790000000000000000000000000000000000000000000000000000000000000000").unwrap();

    let transfer = Transfer::from_ssz_bytes(&bytes).unwrap();

    let spec = MinimalEthSpec::default_spec();
    let mut state = from_minimal_state_file(&spec);

    // Increase proposer's balance so transaction is valid
    let sender = state
        .get_beacon_proposer_index(state.slot, RelativeEpoch::Current, &spec)
        .unwrap();
    state.balances[sender as usize] += 1_010_000_000_000;

    // Fuzz per_block_processing (if decoding was successful)
    println!(
        "Valid Transfer? {}",
        process_transfers(&mut state, &[transfer], &spec).is_ok()
    );
}
