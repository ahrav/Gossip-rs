use std::fmt;

use crate::config::EtcdCoordinatorConfigError;

/// Labels the specific etcd RPC that failed, providing diagnostic context
/// inside [`EtcdCoordinatorError::Etcd`].
///
/// Marked `#[non_exhaustive]` because new variants will be added as the
/// backend evolves from delegation to real etcd persistence (e.g. `Put`,
/// `Txn`, `LeaseGrant`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
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
///
/// Marked `#[non_exhaustive]` because new variants will appear as the
/// backend adds real persistence operations (e.g. lease management, key
/// encoding errors).
#[derive(Debug)]
#[non_exhaustive]
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
}

impl fmt::Display for EtcdCoordinatorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(error) => write!(f, "invalid etcd coordinator config: {error}"),
            Self::RuntimeBuild(error) => write!(f, "failed to build tokio runtime: {error}"),
            Self::Etcd { operation, source } => {
                write!(f, "etcd {operation} operation failed: {source}")
            }
        }
    }
}

impl std::error::Error for EtcdCoordinatorError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Config(error) => Some(error),
            Self::RuntimeBuild(error) => Some(error),
            Self::Etcd { source, .. } => Some(source),
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
