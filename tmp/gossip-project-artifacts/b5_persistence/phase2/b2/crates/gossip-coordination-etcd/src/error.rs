use std::fmt;

use crate::codec::EtcdCodecError;
use crate::config::EtcdCoordinatorConfigError;
use crate::keyspace::EtcdKeyspaceError;

/// etcd operations performed by the backend.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum EtcdOperation {
    Connect,
    Status,
    Get,
    Put,
    Delete,
    Txn,
    LeaseGrant,
    LeaseKeepAlive,
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

/// Errors surfaced by the etcd coordinator backend.
#[derive(Debug)]
#[non_exhaustive]
pub enum EtcdCoordinatorError {
    Config(EtcdCoordinatorConfigError),
    Keyspace(EtcdKeyspaceError),
    RuntimeBuild(std::io::Error),
    Codec {
        operation: EtcdOperation,
        source: EtcdCodecError,
    },
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
