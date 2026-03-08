//! etcd-backed coordination backend for shard and run lifecycle management.
//!
//! This crate provides [`EtcdCoordinator`], which implements the coordination
//! trait surface ([`CoordinationBackend`], [`RunManagement`],
//! [`ShardClaiming`]) against persisted etcd state. It uses etcd transactions
//! for fenced hot-path mutations, publishes worker-visible active-run/shard
//! indexes, garbage-collects stale partially created runs, and uses real etcd
//! leases for ephemeral shard-owner bindings.
//!
//! # Architecture
//!
//! The crate is structured in five internal modules:
//!
//! - **`config`** — Validated connection parameters (endpoints, namespace
//!   prefix, shard limits, tuning). Construction normalizes whitespace and
//!   enforces keyspace prefix invariants.
//! - **`backend`** — [`EtcdCoordinator`] itself: owns the etcd client and a
//!   single-threaded Tokio runtime, exposes health-check (`status()`), and
//!   executes persisted coordination transactions for run lifecycle, shard
//!   lifecycle, and cold-path maintenance. Feature-gated test seeding and
//!   fault-injection helpers live in `backend/test_support.rs`.
//! - **`keyspace`** — Deterministic ASCII etcd path construction for runs,
//!   shards, ownership leases, and active indexes. See the module docs for
//!   the full key layout.
//! - **`codec`** — Explicit binary encoding for coordination records and
//!   shard-owner bindings persisted to etcd.
//! - **`error`** — Unified error types covering configuration validation,
//!   Tokio runtime creation, codec failures, and etcd RPC errors.
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

#![forbid(unsafe_code)]

mod backend;
mod codec;
mod config;
mod error;
mod keyspace;

pub use backend::EtcdCoordinator;
#[cfg(any(test, feature = "test-support"))]
pub use backend::{EtcdTestFault, EtcdTestShardSnapshot};
pub use codec::{
    BlobKind, EtcdCodecError, OwnerLeaseValue, decode_owner_value, decode_run_record,
    decode_shard_record, encode_owner_value, encode_run_record, encode_shard_record,
};
pub use config::{EtcdCoordinatorConfig, EtcdCoordinatorConfigError};
pub use error::{EtcdCoordinatorError, EtcdOperation};
pub use keyspace::{EtcdKeyspace, EtcdKeyspaceError};

#[cfg(test)]
mod test_etcd;

#[cfg(test)]
mod tests;
