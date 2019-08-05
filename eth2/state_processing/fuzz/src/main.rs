extern crate hex;
extern crate ssz;
extern crate state_processing;
extern crate state_processing_fuzz;
extern crate types;

use ssz::Decode;
use state_processing::process_attestations;
use state_processing_fuzz::*;
use types::*;

pub fn main() {
    // Code for generating corpus'
    //generate_attestation();

    // Code for checking fuzz crashes
    let bytes = hex::decode("30010000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000002f000000000000040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c78009fdf07fc56a11f122370658a353aaa542ed63e44c4bc15ff4cd105ab33c0000000080000000000000000000000000000000000000000000000000000000000000000032010000a65187cf470e4cd016673c83cc512d5f513a738cb1a77be6846306739992d4ea85df8393ab6ba1beafb7941d8fdab38c0e1b145a88a689d98c5200152c5eafc04ba3f276848164406b773509d23066ee70aa50295da06f0233a738cd3e6a82040302").unwrap();

    let attestation = Attestation::from_ssz_bytes(&bytes);

    // If valid attestation attempt to process it
    if attestation.is_ok() {
        println!("Ok");

        let spec = MinimalEthSpec::default_spec();
        let mut state = from_minimal_state_file(&spec);

        // Run `process_attestation`
        let _ = process_attestations(&mut state, &[attestation.unwrap()], &spec);
    } else {
        println!("Not Ok");
    }

}
