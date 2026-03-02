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

pub use common::path_buf_from_bytes;
#[cfg(unix)]
pub use filesystem::{FILESYSTEM_CONNECTOR_TAG, FilesystemConnector};
pub use git::{GIT_CONNECTOR_TAG, GitConnector};
pub use in_memory::{InMemoryDeterministicConnector, MemItem};
pub use scan_driver::{
    FilesystemScanSourceFactory, GitScanSourceFactory, InMemoryScanSourceFactory,
};
