//! etcd-backed coordination backend for shard and run lifecycle management.
//!
//! This crate provides [`EtcdCoordinator`], which implements the coordination
//! trait surface against persisted etcd state. It uses etcd transactions for
//! fenced hot-path mutations and real etcd leases for ephemeral shard-owner
//! bindings.
//!
//! # Architecture
//!
//! The crate is structured in five internal modules:
//!
//! - **`config`** — Validated connection parameters (endpoints, namespace
//!   prefix). Construction normalizes whitespace and enforces keyspace
//!   prefix invariants.
//! - **`backend`** — [`EtcdCoordinator`] itself: owns the etcd client, exposes
//!   health-check (`status()`), and executes persisted coordination
//!   transactions.
//! - **`keyspace`** — Deterministic ASCII etcd path construction for
//!   runs, shards, ownership leases, and active indexes.
//! - **`codec`** — Explicit binary encoding (v1 wire format) for coordination
//!   records and shard-owner bindings persisted to etcd.
//! - **`error`** — Unified error types covering configuration validation,
//!   Tokio runtime creation, and etcd client failures.
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
    BlobKind, EtcdCodecError, OwnerLeaseValue, decode_owner_value, decode_run_record,
    decode_shard_record, encode_owner_value, encode_run_record, encode_shard_record,
};
pub use config::{EtcdCoordinatorConfig, EtcdCoordinatorConfigError};
pub use error::{EtcdCoordinatorError, EtcdOperation};
pub use keyspace::{EtcdKeyspace, EtcdKeyspaceError};

#[cfg(test)]
mod tests;
