//! etcd-backed coordination backend for shard and run lifecycle management.
//!
//! This crate provides two entrypoints:
//!
//! - [`EtcdCoordinator`] — sync wrapper that owns a single-threaded Tokio
//!   runtime. Implements [`CoordinationBackend`], [`RunManagement`], and
//!   [`ShardClaiming`] by wrapping etcd RPCs in `block_on`.
//!   Use this when no async runtime is available.
//! - [`AsyncEtcdCoordinator`] — async core that implements
//!   [`AsyncCoordinationBackend`] and [`AsyncRunManagement`]. Use this
//!   when an async runtime is already available (e.g., inside a Tokio task).
//!
//! Both share the same coordination logic and static helpers, with the
//! only difference being their execution model.
//!
//! Both use etcd transactions for fenced hot-path mutations, publish
//! worker-visible active-run/shard indexes, garbage-collect stale
//! partially created runs, and use real etcd leases for ephemeral
//! shard-owner bindings.
//!
//! # Architecture
//!
//! The crate is structured in five internal modules:
//!
//! - **`config`** — Validated connection parameters (endpoints, namespace
//!   prefix, shard limits, tuning). Construction normalizes whitespace and
//!   enforces keyspace prefix invariants.
//! - **`backend`** — [`EtcdCoordinator`] and [`AsyncEtcdCoordinator`]:
//!   the sync wrapper and async core respectively. Both implement most
//!   coordination operations (sync and async variants); see the backend
//!   module docs for per-operation coverage and any fail-closed stubs
//!   (e.g., `complete` and `park_shard`). Each wraps
//!   etcd RPC calls, health-check (`status()`), and persisted
//!   coordination transactions for run lifecycle, shard lifecycle, and
//!   cold-path maintenance. Feature-gated test seeding and fault-injection
//!   helpers live in `backend/test_support.rs`.
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
//! [`AsyncCoordinationBackend`]: gossip_coordination::AsyncCoordinationBackend
//! [`RunManagement`]: gossip_coordination::RunManagement
//! [`AsyncRunManagement`]: gossip_coordination::AsyncRunManagement
//! [`ShardClaiming`]: gossip_coordination::ShardClaiming

#![forbid(unsafe_code)]

mod backend;
mod codec;
mod config;
mod error;
mod keyspace;

pub use backend::{AsyncEtcdCoordinator, EtcdCoordinator};
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
