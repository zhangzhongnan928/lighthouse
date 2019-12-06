#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate eth2_libp2p;
extern crate libp2p;
extern crate tokio;

use eth2_libp2p::{BaseOutboundCodec, ProtocolId, RPC_STATUS, RPC_GOODBYE, RPC_BLOCKS_BY_RANGE, RPC_BLOCKS_BY_ROOT, SSZOutboundCodec};
use libp2p::bytes::BytesMut;
use tokio::codec::Decoder;

const MAX_RPC_SIZE: usize = 4_194_304; // 4M

fuzz_target!(|data: &[u8]| {
    let mut message = RPC_STATUS;
    let mut bytes_mut = BytesMut::new();

    if data.len() >=1 {
        message = match data[0] {
            1 => RPC_GOODBYE,
            2 => RPC_BLOCKS_BY_RANGE,
            3 => RPC_BLOCKS_BY_ROOT,
            _ => RPC_STATUS,
        };
        bytes_mut.extend_from_slice(&data[1..]);
    } else {
        bytes_mut.extend_from_slice(data);
    }
    let protocol_id = ProtocolId::new(message, "1", "ssz");
    let mut ssz_codec = BaseOutboundCodec::new(SSZOutboundCodec::new(protocol_id, MAX_RPC_SIZE));

    // Attempt to Decode random bytes
    ssz_codec.decode(&mut bytes_mut);
});
