//! Error types and supporting newtypes for the in-memory persistence backends.
//!
//! This module contains:
//!
//! - [`InMemoryPersistenceError`] — the unified error enum for both done-ledger
//!   and findings backends.
//! - [`InMemoryStoreKind`] — discriminator used in error variants to identify
//!   which backend produced the error.
//! - [`CompletionOrder`] — queue drain direction for manually releasing delayed
//!   commits.
//! - [`PendingWriteId`] — opaque handle referencing a specific pending write
//!   operation.

use std::{error::Error, fmt};

use gossip_contracts::{
    identity::{FindingId, ObservationId, OccurrenceId, TenantId},
    persistence::PersistenceInputError,
};

/// Ordering used when manually releasing delayed in-memory commits.
///
/// The ordering applies to the internal FIFO queue of pending operations.
/// [`OldestFirst`](Self::OldestFirst) is the natural "drain" order;
/// [`NewestFirst`](Self::NewestFirst) lets tests simulate out-of-order
/// durability where a later write becomes durable before an earlier one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompletionOrder {
    /// Release the oldest pending operation first (FIFO drain).
    OldestFirst,
    /// Release the newest pending operation first (LIFO / reverse drain).
    NewestFirst,
}

/// Store kind used in fault injection and error reporting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InMemoryStoreKind {
    /// Done-ledger reference store.
    DoneLedger,
    /// Findings/occurrences/observations reference store.
    Findings,
}

impl fmt::Display for InMemoryStoreKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DoneLedger => f.write_str("done-ledger"),
            Self::Findings => f.write_str("findings"),
        }
    }
}

/// Identifier for a pending in-memory write operation.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PendingWriteId(u64);

impl PendingWriteId {
    /// Zero sentinel value.
    pub const ZERO: Self = Self(0);

    /// Construct from a raw integer.
    #[inline]
    #[must_use]
    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    /// Return the raw integer value.
    #[inline]
    #[must_use]
    pub const fn as_raw(self) -> u64 {
        self.0
    }
}

impl fmt::Debug for PendingWriteId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PendingWriteId({})", self.0)
    }
}

impl fmt::Display for PendingWriteId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

/// Errors returned by the in-memory persistence reference backends.
///
/// Variants fall into three categories:
///
/// - **Fault injection** ([`InjectedSubmissionFailure`](Self::InjectedSubmissionFailure),
///   [`InjectedCommitFailure`](Self::InjectedCommitFailure)) — deterministic
///   test-controlled failures that exercise error-handling paths.
/// - **Infrastructure** ([`Poisoned`](Self::Poisoned),
///   [`UnknownOperation`](Self::UnknownOperation)) — internal consistency
///   violations that indicate misuse or a poisoned mutex.
/// - **Data integrity** ([`MissingFinding`](Self::MissingFinding),
///   [`MissingOccurrence`](Self::MissingOccurrence),
///   [`FindingConflict`](Self::FindingConflict),
///   [`OccurrenceConflict`](Self::OccurrenceConflict),
///   [`ObservationConflict`](Self::ObservationConflict),
///   [`BatchValidation`](Self::BatchValidation)) — referential integrity or
///   immutability violations caught during apply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InMemoryPersistenceError {
    /// The request was rejected before a handle was created.
    InjectedSubmissionFailure {
        /// Store that rejected the submission.
        store: InMemoryStoreKind,
    },
    /// The request was accepted, but the durable commit failed.
    InjectedCommitFailure {
        /// Store whose commit failed.
        store: InMemoryStoreKind,
    },
    /// The backend's mutex or condvar became poisoned.
    Poisoned {
        /// Store whose internal state was poisoned.
        store: InMemoryStoreKind,
    },
    /// A commit handle waited on an operation that no longer exists.
    UnknownOperation {
        /// Store that issued the handle.
        store: InMemoryStoreKind,
        /// Operation id carried by the handle.
        op_id: PendingWriteId,
    },
    /// An occurrence referenced a finding that was neither durable nor present
    /// in the same batch.
    MissingFinding {
        tenant_id: TenantId,
        finding_id: FindingId,
        occurrence_id: OccurrenceId,
    },
    /// An observation referenced an occurrence that was neither durable nor
    /// present in the same batch.
    MissingOccurrence {
        tenant_id: TenantId,
        occurrence_id: OccurrenceId,
        observation_id: ObservationId,
    },
    /// Two finding rows shared the same `(tenant_id, finding_id)` but had
    /// different immutable content.
    FindingConflict {
        tenant_id: TenantId,
        finding_id: FindingId,
    },
    /// Two occurrence rows shared the same `(tenant_id, occurrence_id)` but had
    /// different immutable content.
    OccurrenceConflict {
        tenant_id: TenantId,
        occurrence_id: OccurrenceId,
    },
    /// Two observation rows shared the same `(tenant_id, observation_id)` but
    /// disagreed on immutable identity fields.
    ObservationConflict {
        tenant_id: TenantId,
        observation_id: ObservationId,
    },
    /// Local validation failed before submission.
    BatchValidation(PersistenceInputError),
}

impl fmt::Display for InMemoryPersistenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InjectedSubmissionFailure { store } => {
                write!(f, "in-memory {store} submission failed via fault injection")
            }
            Self::InjectedCommitFailure { store } => {
                write!(f, "in-memory {store} commit failed via fault injection")
            }
            Self::Poisoned { store } => write!(f, "in-memory {store} state lock poisoned"),
            Self::UnknownOperation { store, op_id } => {
                write!(f, "unknown in-memory {store} operation {op_id}")
            }
            Self::MissingFinding {
                tenant_id,
                finding_id,
                occurrence_id,
            } => write!(
                f,
                "occurrence {occurrence_id:?} for tenant {tenant_id:?} references missing finding {finding_id:?}"
            ),
            Self::MissingOccurrence {
                tenant_id,
                occurrence_id,
                observation_id,
            } => write!(
                f,
                "observation {observation_id:?} for tenant {tenant_id:?} references missing occurrence {occurrence_id:?}"
            ),
            Self::FindingConflict {
                tenant_id,
                finding_id,
            } => write!(
                f,
                "finding conflict for tenant {tenant_id:?}, finding {finding_id:?}"
            ),
            Self::OccurrenceConflict {
                tenant_id,
                occurrence_id,
            } => write!(
                f,
                "occurrence conflict for tenant {tenant_id:?}, occurrence {occurrence_id:?}"
            ),
            Self::ObservationConflict {
                tenant_id,
                observation_id,
            } => write!(
                f,
                "observation conflict for tenant {tenant_id:?}, observation {observation_id:?}"
            ),
            Self::BatchValidation(err) => err.fmt(f),
        }
    }
}

impl Error for InMemoryPersistenceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::BatchValidation(err) => Some(err),
            _ => None,
        }
    }
}

impl From<PersistenceInputError> for InMemoryPersistenceError {
    #[inline]
    fn from(value: PersistenceInputError) -> Self {
        Self::BatchValidation(value)
    }
}
