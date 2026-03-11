//! Source connectors: filesystem, git, and in-memory implementations.
//!
//! This crate provides concrete connector implementations that bridge
//! specific data sources (local filesystem, git repository, or deterministic
//! in-memory fixtures) into the unified shard-based read model
//! defined in `gossip-contracts`. Shared value types
//! (`ScanItem`, `ItemRef`, etc.) live in the
//! `gossip_contracts::connector` module; this crate supplies the currently
//! implemented per-source-type adapters.
//!
//! **Dependency direction:** This crate depends on `gossip-contracts` for
//! value types. It must not depend on
//! `gossip-persistence` or the coordination backend implementation.

use gossip_contracts::identity::ConnectorTag;
use gossip_scan_driver::ConnectorKind;

mod common;
#[cfg(unix)]
pub mod filesystem;
pub mod git;
pub mod in_memory;
mod scan_driver;
mod split_estimator;

pub use common::{
    FILESYSTEM_CONNECTOR_TAG, GIT_CONNECTOR_TAG, IN_MEMORY_CONNECTOR_TAG, path_buf_from_bytes,
};
#[cfg(unix)]
pub use filesystem::FilesystemConnector;
pub use git::GitConnector;
pub use in_memory::{InMemoryDeterministicConnector, MemItem};
pub use scan_driver::{
    FilesystemScanSourceFactory, GitDebugLevel, GitExecutionConfig, InMemoryScanSourceFactory,
    execute_git_assignment,
};

/// Return the canonical tag assigned to a connector kind.
///
/// This is a convenience dispatcher that maps a runtime [`ConnectorKind`]
/// to the canonical tag constant. The tag constants themselves
/// (`FILESYSTEM_CONNECTOR_TAG`, `GIT_CONNECTOR_TAG`,
/// `IN_MEMORY_CONNECTOR_TAG`) are the authoritative source of truth —
/// this function simply provides a `match`-based lookup for callers that
/// need to resolve a dynamic kind at runtime.
#[must_use]
pub const fn connector_tag_for_kind(kind: ConnectorKind) -> ConnectorTag {
    match kind {
        ConnectorKind::Filesystem => FILESYSTEM_CONNECTOR_TAG,
        ConnectorKind::Git => GIT_CONNECTOR_TAG,
        ConnectorKind::InMemory => IN_MEMORY_CONNECTOR_TAG,
    }
}

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
    use gossip_scan_driver::ConnectorKind;

    use super::{
        FILESYSTEM_CONNECTOR_TAG, GIT_CONNECTOR_TAG, IN_MEMORY_CONNECTOR_TAG,
        connector_tag_for_kind,
    };

    #[test]
    fn canonical_tag_mapping_matches_constants() {
        assert_eq!(
            connector_tag_for_kind(ConnectorKind::Filesystem),
            FILESYSTEM_CONNECTOR_TAG
        );
        assert_eq!(
            connector_tag_for_kind(ConnectorKind::Git),
            GIT_CONNECTOR_TAG
        );
        assert_eq!(
            connector_tag_for_kind(ConnectorKind::InMemory),
            IN_MEMORY_CONNECTOR_TAG
        );
        assert_eq!(IN_MEMORY_CONNECTOR_TAG.as_bytes(), b"inmem\0\0\0");
    }

    #[test]
    fn canonical_connector_tags_are_distinct() {
        assert_ne!(FILESYSTEM_CONNECTOR_TAG, GIT_CONNECTOR_TAG);
        assert_ne!(FILESYSTEM_CONNECTOR_TAG, IN_MEMORY_CONNECTOR_TAG);
        assert_ne!(GIT_CONNECTOR_TAG, IN_MEMORY_CONNECTOR_TAG);
    }
}
