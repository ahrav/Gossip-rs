use std::fmt;

use crate::config::EtcdCoordinatorConfigError;
use crate::keyspace::EtcdKeyspaceError;

/// Labels the specific etcd RPC that failed, providing diagnostic context
/// inside [`EtcdCoordinatorError::Etcd`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EtcdOperation {
    /// Initial gRPC connection to the etcd cluster.
    Connect,
    /// Maintenance `status` RPC used to verify cluster health after connect.
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

/// Errors surfaced by the etcd coordination backend.
///
/// The variants form a progression that mirrors the `connect()` sequence:
///
/// 1. **Configuration validation** ([`Config`](Self::Config)) — checked
///    before any I/O. Catches invalid endpoints or namespace prefixes.
/// 2. **Tokio runtime construction** ([`RuntimeBuild`](Self::RuntimeBuild)) —
///    a system-resource failure (e.g. `ulimit` exhaustion) that prevents the
///    sync/async bridge from starting.
/// 3. **etcd client errors** ([`Etcd`](Self::Etcd)) — network, TLS, or
///    cluster-level failures encountered during gRPC calls.
#[derive(Debug)]
pub enum EtcdCoordinatorError {
    /// The [`EtcdCoordinatorConfig`](crate::EtcdCoordinatorConfig) failed validation before any I/O.
    ///
    /// See [`EtcdCoordinatorConfigError`] for the specific constraint that
    /// was violated (missing endpoints, bad namespace prefix, etc.).
    Config(EtcdCoordinatorConfigError),

    /// The Tokio current-thread runtime required by the sync/async bridge
    /// could not be created — typically a system-resource exhaustion
    /// (fd limits, thread limits).
    RuntimeBuild(std::io::Error),

    /// An etcd gRPC call failed. `operation` identifies which RPC, and
    /// `source` carries the upstream [`etcd_client::Error`] with transport
    /// and cluster-level details.
    Etcd {
        operation: EtcdOperation,
        source: etcd_client::Error,
    },

    /// The etcd namespace prefix could not be converted into a valid
    /// deterministic keyspace builder.
    Keyspace(EtcdKeyspaceError),
}

impl fmt::Display for EtcdCoordinatorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(error) => write!(f, "invalid etcd coordinator config: {error}"),
            Self::RuntimeBuild(error) => write!(f, "failed to build tokio runtime: {error}"),
            Self::Etcd { operation, source } => {
                write!(f, "etcd {operation} operation failed: {source}")
            }
            Self::Keyspace(error) => write!(f, "invalid etcd keyspace: {error}"),
        }
    }
}

impl std::error::Error for EtcdCoordinatorError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Config(error) => Some(error),
            Self::RuntimeBuild(error) => Some(error),
            Self::Etcd { source, .. } => Some(source),
            Self::Keyspace(error) => Some(error),
        }
    }
}

/// Allows `?` propagation from [`EtcdCoordinatorConfig::validate()`] inside
/// [`EtcdCoordinator::connect()`].
///
/// [`EtcdCoordinatorConfig::validate()`]: crate::config::EtcdCoordinatorConfig::validate
/// [`EtcdCoordinator::connect()`]: crate::backend::EtcdCoordinator::connect
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
