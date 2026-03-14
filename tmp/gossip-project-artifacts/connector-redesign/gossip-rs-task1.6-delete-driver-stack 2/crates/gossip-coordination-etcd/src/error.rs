//! Unified error types for the etcd coordination backend.
//!
//! All fallible operations in this crate ultimately surface one of two
//! error types:
//!
//! - [`EtcdCoordinatorError`] — top-level error covering config validation,
//!   keyspace construction, Tokio runtime creation, codec decode/encode
//!   failures, and etcd RPC errors.
//! - [`EtcdOperation`] — a discriminant that tags which RPC or codec step
//!   failed, providing structured context for diagnostics without embedding
//!   the full error chain in the variant name.
//!
//! Domain-level errors (e.g., [`AcquireError`], [`CheckpointError`]) are
//! defined in `gossip-coordination` and returned directly from the
//! [`CoordinationBackend`] trait methods; this module covers only
//! infrastructure failures.
//!
//! [`AcquireError`]: gossip_coordination::AcquireError
//! [`CheckpointError`]: gossip_coordination::CheckpointError
//! [`CoordinationBackend`]: gossip_coordination::CoordinationBackend

use std::fmt;

use crate::codec::EtcdCodecError;
use crate::config::EtcdCoordinatorConfigError;
use crate::keyspace::EtcdKeyspaceError;

/// Labels the etcd RPC or codec stage that failed.
///
/// Paired with an error source in [`EtcdCoordinatorError::Etcd`] or
/// [`EtcdCoordinatorError::Codec`] to provide structured failure context
/// without losing the underlying cause.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum EtcdOperation {
    /// Initial TCP/TLS connection to the etcd cluster.
    Connect,
    /// Maintenance `status` health-check RPC.
    Status,
    /// Key-value `get` (point lookup or prefix scan).
    Get,
    /// Key-value `put`.
    Put,
    /// Key-value `delete` (point or prefix).
    Delete,
    /// Compare-and-swap transaction (`txn`).
    Txn,
    /// Lease `grant` (create a new TTL-based lease).
    LeaseGrant,
    /// Lease `keep_alive` (extend an existing lease's TTL).
    LeaseKeepAlive,
    /// Lease `revoke` (immediately expire a lease and delete its keys).
    LeaseRevoke,
}

impl fmt::Display for EtcdOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connect => f.write_str("connect"),
            Self::Status => f.write_str("status"),
            Self::Get => f.write_str("get"),
            Self::Put => f.write_str("put"),
            Self::Delete => f.write_str("delete"),
            Self::Txn => f.write_str("txn"),
            Self::LeaseGrant => f.write_str("lease_grant"),
            Self::LeaseKeepAlive => f.write_str("lease_keep_alive"),
            Self::LeaseRevoke => f.write_str("lease_revoke"),
        }
    }
}

/// Top-level errors surfaced by the etcd coordination backend.
///
/// Covers all infrastructure failure modes: configuration validation,
/// keyspace construction, Tokio runtime creation, wire-format codec
/// failures, and raw etcd RPC errors. Domain-level coordination errors
/// (wrong status, stale fence, etc.) are returned via their own types
/// from the [`CoordinationBackend`] trait.
///
/// [`CoordinationBackend`]: gossip_coordination::CoordinationBackend
#[derive(Debug)]
#[non_exhaustive]
pub enum EtcdCoordinatorError {
    /// Invalid [`EtcdCoordinatorConfig`](crate::EtcdCoordinatorConfig) parameters.
    Config(EtcdCoordinatorConfigError),
    /// Invalid [`EtcdKeyspace`](crate::EtcdKeyspace) prefix.
    Keyspace(EtcdKeyspaceError),
    /// Failed to build the internal single-threaded Tokio runtime.
    RuntimeBuild(std::io::Error),
    /// A v1 blob failed to encode or decode during the given operation.
    Codec {
        operation: EtcdOperation,
        source: EtcdCodecError,
    },
    /// An etcd gRPC call failed during the given operation.
    Etcd {
        operation: EtcdOperation,
        source: etcd_client::Error,
    },
}

impl fmt::Display for EtcdCoordinatorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(err) => write!(f, "invalid etcd coordinator config: {err}"),
            Self::Keyspace(err) => write!(f, "invalid etcd keyspace: {err}"),
            Self::RuntimeBuild(err) => write!(f, "failed to build tokio runtime: {err}"),
            Self::Codec { operation, source } => {
                write!(f, "etcd {operation} codec operation failed: {source}")
            }
            Self::Etcd { operation, source } => {
                write!(f, "etcd {operation} operation failed: {source}")
            }
        }
    }
}

impl std::error::Error for EtcdCoordinatorError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Config(err) => Some(err),
            Self::Keyspace(err) => Some(err),
            Self::RuntimeBuild(err) => Some(err),
            Self::Codec { source, .. } => Some(source),
            Self::Etcd { source, .. } => Some(source),
        }
    }
}

impl From<EtcdCoordinatorConfigError> for EtcdCoordinatorError {
    fn from(value: EtcdCoordinatorConfigError) -> Self {
        Self::Config(value)
    }
}

impl From<EtcdKeyspaceError> for EtcdCoordinatorError {
    fn from(value: EtcdKeyspaceError) -> Self {
        Self::Keyspace(value)
    }
}
