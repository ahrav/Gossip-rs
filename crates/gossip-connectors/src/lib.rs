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

pub mod in_memory;
