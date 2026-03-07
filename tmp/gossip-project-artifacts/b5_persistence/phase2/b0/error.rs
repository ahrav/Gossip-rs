use std::fmt;

use crate::config::EtcdCoordinatorConfigError;

/// etcd operations performed by the B0 backend scaffold.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum EtcdOperation {
    Connect,
    Status,
}

impl fmt::Display for EtcdOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connect => f.write_str("connect"),
            Self::Status => f.write_str("status"),
        }
    }
}

/// Errors surfaced by the B0 etcd coordinator scaffold.
#[derive(Debug)]
#[non_exhaustive]
pub enum EtcdCoordinatorError {
    Config(EtcdCoordinatorConfigError),
    RuntimeBuild(std::io::Error),
    Etcd {
        operation: EtcdOperation,
        source: etcd_client::Error,
    },
}

impl fmt::Display for EtcdCoordinatorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(err) => write!(f, "invalid etcd coordinator config: {err}"),
            Self::RuntimeBuild(err) => write!(f, "failed to build tokio runtime: {err}"),
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
            Self::RuntimeBuild(err) => Some(err),
            Self::Etcd { source, .. } => Some(source),
        }
    }
}

impl From<EtcdCoordinatorConfigError> for EtcdCoordinatorError {
    fn from(value: EtcdCoordinatorConfigError) -> Self {
        Self::Config(value)
    }
}
