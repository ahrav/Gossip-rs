//! Source connectors: filesystem, git, and in-memory implementations.
//!
//! This crate provides concrete source-family implementations that bridge
//! specific data sources (local filesystem, git repository snapshots, or
//! deterministic in-memory fixtures) into the shared connector contracts
//! defined in `gossip-contracts`.
//!
//! Shared connector value types (`ScanItem`, `ItemRef`, etc.) live in the
//! `gossip_contracts::connector` module. This crate supplies concrete adapters
//! for the currently supported source families.
//!
//! **Dependency direction:** This crate depends on `gossip-contracts` for value
//! types and traits. It must not depend on persistence backends or
//! coordination backend implementations.

mod common;
#[cfg(unix)]
pub mod filesystem;
pub mod git;
pub mod in_memory;
mod split_estimator;

pub use common::path_buf_from_bytes;
#[cfg(unix)]
pub use filesystem::FilesystemConnector;
pub use git::GitConnector;
pub use gossip_contracts::connector::{
    FILESYSTEM_CONNECTOR_TAG, GIT_CONNECTOR_TAG, IN_MEMORY_CONNECTOR_TAG,
};
pub use in_memory::{InMemoryDeterministicConnector, MemItem};

#[doc(hidden)]
/// Benchmark hook: drives the streaming split estimator's `observe` loop on a
/// deterministic fixed-size workload for Criterion benches and allocation guards.
pub fn benchmark_streaming_split_estimator_observe_fixed_size(
    sample_cap: usize,
    count: usize,
    file_size: u64,
) -> Option<u64> {
    use split_estimator::StreamingSplitEstimator;

    let mut estimator = StreamingSplitEstimator::new(sample_cap);
    for idx in 0..count {
        let key = u64::try_from(idx).expect("bench key index must fit in u64");
        estimator.observe(&key.to_be_bytes(), file_size);
    }
    estimator
        .estimate_split_key()
        .map(|key| u64::from_be_bytes(key.try_into().expect("split keys use u64 bytes")))
}

#[cfg(test)]
mod tests {
    use super::{FILESYSTEM_CONNECTOR_TAG, GIT_CONNECTOR_TAG, IN_MEMORY_CONNECTOR_TAG};

    #[test]
    fn canonical_connector_tags_are_distinct() {
        assert_ne!(FILESYSTEM_CONNECTOR_TAG, GIT_CONNECTOR_TAG);
        assert_ne!(FILESYSTEM_CONNECTOR_TAG, IN_MEMORY_CONNECTOR_TAG);
        assert_ne!(GIT_CONNECTOR_TAG, IN_MEMORY_CONNECTOR_TAG);
    }

    #[test]
    fn in_memory_connector_tag_bytes_match_fixture() {
        assert_eq!(IN_MEMORY_CONNECTOR_TAG.as_bytes(), b"inmem\0\0\0");
    }
}
