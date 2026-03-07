//! etcd-backed coordination backend for shard and run lifecycle management.
//!
//! This crate provides [`EtcdCoordinator`], which implements the full
//! coordination trait surface ([`CoordinationBackend`], [`RunManagement`],
//! [`ShardClaiming`]) backed by a real etcd cluster connection. It is the
//! production-path alternative to the in-memory coordinator used in tests.
//!
//! # Architecture
//!
//! The crate is structured in five internal modules:
//!
//! - **`config`** — Validated connection parameters (endpoints, namespace
//!   prefix). Construction normalizes whitespace and enforces keyspace
//!   prefix invariants.
//! - **`backend`** — [`EtcdCoordinator`] itself: owns the etcd client,
//!   exposes health-check (`status()`), and forwards trait methods.
//! - **`keyspace`** — Deterministic ASCII etcd path construction for
//!   runs, shards, ownership leases, and active indexes.
//! - **`codec`** — Explicit versioned binary encoding for coordination
//!   records persisted to etcd.
//! - **`error`** — Unified error types covering configuration validation,
//!   Tokio runtime creation, and etcd client failures.
//!
//! # Current delegation model
//!
//! All shard and run protocol semantics (acquire, renew, checkpoint,
//! complete, split, park, claim) are delegated to [`InMemoryCoordinator`]
//! from `gossip-coordination`. The etcd connection is established and
//! health-checked at construction, but shard/run state lives in memory.
//!
//! # Build requirements
//!
//! The upstream `etcd-client` crate generates gRPC stubs at build time.
//! Build hosts must have `protoc` installed (or the `PROTOC` environment
//! variable pointing to its binary).
//!
//! [`CoordinationBackend`]: gossip_coordination::CoordinationBackend
//! [`RunManagement`]: gossip_coordination::RunManagement
//! [`ShardClaiming`]: gossip_coordination::ShardClaiming
//! [`InMemoryCoordinator`]: gossip_coordination::InMemoryCoordinator

#![forbid(unsafe_code)]

mod backend;
mod codec;
mod config;
mod error;
mod keyspace;

pub use backend::EtcdCoordinator;
pub use codec::{
    BlobKind, EtcdCodecError, decode_run_record_v1, decode_shard_record_v1, encode_run_record_v1,
    encode_shard_record_v1,
};
pub use config::{EtcdCoordinatorConfig, EtcdCoordinatorConfigError};
pub use error::{EtcdCoordinatorError, EtcdOperation};
pub use keyspace::{EtcdKeyspace, EtcdKeyspaceError};

#[cfg(test)]
mod tests;
