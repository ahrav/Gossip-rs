//! Source connectors: filesystem, git, and SaaS integrations.
//!
//! This crate provides concrete connector implementations that bridge
//! specific data sources (local filesystem, git repository, cloud SaaS
//! API, etc.) into the unified shard-based enumeration and read model
//! defined in `gossip-contracts`. Connector traits and shared value types
//! (`ScanItem`, `ItemRef`, `EnumerationPage`, etc.) live in the
//! `gossip_contracts::connector` module; this crate supplies the
//! per-source-type implementations.
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
/// Benchmark-only wrapper around the private streaming split estimator.
///
/// The estimator itself stays crate-private because production callers consume
/// split hints through connector APIs, not by instantiating the sketch
/// directly. Criterion benches and cross-crate regression tests still need a
/// stable way to drive the real `observe` path, so this doc-hidden shim
/// exposes a deterministic fixed-size workload entry point while leaving the
/// estimator type and its internal sampling helpers unexported.
pub fn benchmark_streaming_split_estimator_observe_fixed_size(
    sample_cap: usize,
    count: usize,
    file_size: u64,
) -> Option<u64> {
    split_estimator::benchmark_observe_fixed_size(sample_cap, count, file_size)
}
