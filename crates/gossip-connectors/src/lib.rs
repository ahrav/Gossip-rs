//! Source connectors: filesystem, git, and in-memory implementations.
//!
//! This crate provides concrete connector implementations that bridge
//! specific data sources (local filesystem, git repository, or deterministic
//! in-memory fixtures) into the unified shard-based enumeration and read model
//! defined in `gossip-contracts`. Connector traits and shared value types
//! (`ScanItem`, `ItemRef`, `EnumerationPage`, etc.) live in the
//! `gossip_contracts::connector` module; this crate supplies the currently
//! implemented per-source-type adapters.
//!
//! **Dependency direction:** This crate depends on `gossip-contracts` for
//! trait definitions and value types. It must not depend on
//! `gossip-persistence` or the coordination backend implementation.

mod common;
#[cfg(unix)]
pub mod filesystem;
pub mod git;
pub mod in_memory;
mod scan_driver;
#[cfg(unix)]
mod split_estimator;

pub use common::path_buf_from_bytes;
#[cfg(unix)]
pub use filesystem::{FILESYSTEM_CONNECTOR_TAG, FilesystemConnector};
pub use git::{GIT_CONNECTOR_TAG, GitConnector};
pub use in_memory::{InMemoryDeterministicConnector, MemItem};
pub use scan_driver::{
    FilesystemScanSourceFactory, GitScanSourceFactory, InMemoryScanSourceFactory,
};

#[cfg(unix)]
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
