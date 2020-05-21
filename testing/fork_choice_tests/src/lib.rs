use beacon_chain::builder::BeaconChainBuilder;
use beacon_chain::migrate::NullMigrator;
use genesis::interop_genesis_state;
use itertools::Itertools;
use sloggers::{null::NullLoggerBuilder, Build};
use std::sync::Arc;
use std::time::Duration;
use store::MemoryStore;
use tempfile::tempdir;
use types::{
    test_utils::generate_deterministic_keypairs, Attestation, EthSpec, Hash256, MainnetEthSpec,
    SignedBeaconBlock, Slot,
};

type E = MainnetEthSpec;

pub struct ForkChoiceTest {
    pub name: String,
    pub validator_count: usize,
    pub blocks: Vec<(Slot, SignedBeaconBlock<E>)>,
    pub attestations: Vec<(Slot, Attestation<E>)>,
    pub heads: Vec<(Slot, Hash256)>,
}

enum Event {
    ProcessBlock(SignedBeaconBlock<E>),
    ProcessAttestation(Attestation<E>),
    FindHead(Hash256),
}

impl ForkChoiceTest {
    pub fn run(self) {
        let data_dir = tempdir().expect("should create temporary data_dir");
        let spec = E::default_spec();

        let keypairs = generate_deterministic_keypairs(self.validator_count);
        let log = NullLoggerBuilder.build().unwrap();

        let chain = BeaconChainBuilder::new(MainnetEthSpec)
            .logger(log.clone())
            .custom_spec(spec.clone())
            .store(Arc::new(MemoryStore::open()))
            .store_migrator(NullMigrator)
            .data_dir(data_dir.path().to_path_buf())
            .genesis_state(
                interop_genesis_state::<E>(&keypairs, spec.min_genesis_time, &spec)
                    .expect("should generate interop state"),
            )
            .expect("should build state using recent genesis")
            .dummy_eth1_backend()
            .expect("should build dummy backend")
            .null_event_handler()
            .testing_slot_clock(Duration::from_millis(spec.milliseconds_per_slot))
            .expect("should configure testing slot clock")
            .reduced_tree_fork_choice()
            .expect("should add fork choice to builder")
            .build()
            .expect("should build");

        for (slot, event) in Self::linearize_events(self.blocks, self.attestations, self.heads) {
            chain.slot_clock.set_slot(slot.as_u64());

            match event {
                Event::ProcessBlock(block) => {
                    chain
                        .process_block(block)
                        .expect("block should process successfully");
                }
                Event::ProcessAttestation(attestation) => {
                    chain
                        .apply_attestation_to_fork_choice(&attestation)
                        .unwrap();
                }
                Event::FindHead(head) => {
                    assert_eq!(chain.fork_choice.find_head(&chain), Ok(head));
                }
            }
        }
    }

    fn linearize_events(
        blocks: Vec<(Slot, SignedBeaconBlock<E>)>,
        attestations: Vec<(Slot, Attestation<E>)>,
        heads: Vec<(Slot, Hash256)>,
    ) -> Vec<(Slot, Event)> {
        blocks
            .into_iter()
            .map(|(slot, block)| (slot, Event::ProcessBlock(block)))
            .merge_by(
                attestations
                    .into_iter()
                    .map(|(slot, att)| (slot, Event::ProcessAttestation(att))),
                |(s1, _), (s2, _)| s1 <= s2,
            )
            .merge_by(
                heads
                    .into_iter()
                    .map(|(slot, head)| (slot, Event::FindHead(head))),
                |(s1, _), (s2, _)| s1 <= s2,
            )
            .collect()
    }
}
