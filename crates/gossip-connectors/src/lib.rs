//! Source connectors: filesystem and in-memory implementations.
//!
//! This crate provides concrete source-family implementations that bridge
//! specific data sources (local filesystem or deterministic in-memory fixtures)
//! into the shared connector contracts defined in `gossip-contracts`.
//!
//! Shared connector value types (`ScanItem`, `ItemRef`, etc.) live in the
//! `gossip_contracts::connector` module. This crate supplies concrete adapters
//! for the currently supported source families, while the crate root stays
//! intentionally small and mostly curates the public exports that downstream
//! code uses to select a connector implementation.
//!
//! # Invariants
//!
//! - **Stateless Connectors:** Connector instances maintain no internal state
//!   regarding the coordination layer; they purely map source data to standard
//!   types.
//!
//! # Design Trade-offs
//!
//! - **Dependency Isolation:** By keeping standard types in `gossip-contracts`
//!   and concrete implementations here, we prevent coordination engines from
//!   importing heavyweight dependencies (like `git2` or filesystem libraries)
//!   unless specifically required.
//!
//! **Dependency direction:** This crate depends on `gossip-contracts` for value
//! types and traits. It must not depend on persistence backends or
//! coordination backend implementations.
//!
//! # Platform Boundaries
//!
//! - Filesystem connectors are exported only on Unix (`#[cfg(unix)]`).
//! - In-memory connectors are always available for deterministic tests and
//!   benchmarks across platforms.

mod common;
#[cfg(unix)]
pub mod filesystem;
pub mod in_memory;
mod split_estimator;

/// I/O classification helpers shared by connector implementations.
///
/// These functions normalize platform and OS-level errors into stable checks
/// used by retry and traversal logic in higher layers.
pub use common::{is_permanent_io_error, is_symlink_loop, path_buf_from_bytes};
/// Local filesystem-backed connector implementation.
///
/// Available only on Unix platforms where path and metadata semantics match the
/// implementation assumptions.
#[cfg(unix)]
pub use filesystem::FilesystemConnector;
/// Canonical connector-family tags used in metadata and fixtures.
///
/// These constants are defined in `gossip-contracts` and re-exported here so
/// callers can select source families without depending on the contracts crate
/// directly.
pub use gossip_contracts::connector::{
    FILESYSTEM_CONNECTOR_TAG, GIT_CONNECTOR_TAG, IN_MEMORY_CONNECTOR_TAG,
};
/// Deterministic in-memory connector and item fixture type used by tests and
/// benchmarks.
pub use in_memory::{InMemoryDeterministicConnector, MemItem};

#[doc(hidden)]
/// Drives the streaming split estimator with a deterministic fixed-size
/// workload for benchmarks.
///
/// The helper feeds `count` monotonically increasing `u64` keys, encoded as
/// big-endian bytes, into the estimator. Using a fixed key sequence and a
/// uniform `file_size` lets Criterion benches and allocation guards measure
/// estimator behavior without depending on filesystem scans or repository
/// traversal.
///
/// Returns the estimated split key decoded back into a `u64`, or `None` when
/// the estimator cannot derive a split point for the observed sample set, such
/// as when no items were observed.
///
/// `sample_cap` is forwarded directly to
/// `split_estimator::StreamingSplitEstimator::new`, so benchmark callers can
/// exercise the estimator under different sampling budgets.
///
/// # Complexity
///
/// Runs in `O(count)` time and `O(sample_cap)` additional memory, matching the
/// estimator's streaming sample budget.
///
/// # Panics
///
/// Panics if:
/// - A generated benchmark key index does not fit into `u64`.
/// - The estimator returns a split key that is not exactly 8 bytes long.
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
