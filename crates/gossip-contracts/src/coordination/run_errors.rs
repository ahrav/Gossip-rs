//! Operation-specific error types for run-level operations.
//!
//! Follows the same pattern as shard-level errors in `error.rs`:
//! - `#[non_exhaustive]` on all enums
//! - Custom `Debug` impls that redact hash values (SEC-6)
//! - No `actual` field in `TenantMismatch` (SEC-1)
//! - `From<RunOpIdConflict>` for types with `OpIdConflict` variant
//! - Explicit rejection in all `From` impls (no wildcards)

use std::fmt;

use crate::coordination::record::ShardStatus;
use crate::coordination::run::{ManifestValidationError, RunConfigError, RunOpIdConflict};
use crate::identity::{OpId, RunId, TenantId};

// ============================================================================
// CreateRunError
// ============================================================================

/// Error from `create_run`.
///
/// `create_run` is NOT idempotent — no `OpIdConflict` variant.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CreateRunError {
    /// The run config failed validation.
    InvalidConfig(RunConfigError),
    /// A run with this `RunId` already exists for this tenant.
    RunAlreadyExists { run: RunId },
    /// Registration step failed during `create_run_with_shards`.
    RegistrationFailed { reason: String },
}

impl fmt::Display for CreateRunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(e) => write!(f, "invalid run config: {e}"),
            Self::RunAlreadyExists { run } => write!(f, "run already exists: {run:?}"),
            Self::RegistrationFailed { reason } => {
                write!(f, "registration failed: {reason}")
            }
        }
    }
}

impl std::error::Error for CreateRunError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidConfig(e) => Some(e),
            _ => None,
        }
    }
}

impl From<RunConfigError> for CreateRunError {
    fn from(e: RunConfigError) -> Self {
        Self::InvalidConfig(e)
    }
}

// ============================================================================
// RegisterShardsError
// ============================================================================

/// Error from `register_shards`.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RegisterShardsError {
    RunNotFound,
    /// Tenant isolation violation. Only `expected` is exposed (SEC-1).
    TenantMismatch {
        expected: TenantId,
    },
    /// Run is not in `Initializing` status.
    WrongStatus,
    /// Manifest validation failed.
    ManifestInvalid(ManifestValidationError),
    /// OpId reuse with different payload hash.
    OpIdConflict {
        op_id: OpId,
        expected_hash: u64,
        actual_hash: u64,
    },
}

impl fmt::Debug for RegisterShardsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RunNotFound => write!(f, "RunNotFound"),
            Self::TenantMismatch { expected } => f
                .debug_struct("TenantMismatch")
                .field("expected", expected)
                .finish(),
            Self::WrongStatus => write!(f, "WrongStatus"),
            Self::ManifestInvalid(e) => f.debug_tuple("ManifestInvalid").field(e).finish(),
            Self::OpIdConflict { op_id, .. } => f
                .debug_struct("OpIdConflict")
                .field("op_id", op_id)
                .field("expected_hash", &"<redacted>")
                .field("actual_hash", &"<redacted>")
                .finish(),
        }
    }
}

impl fmt::Display for RegisterShardsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RunNotFound => f.write_str("run not found"),
            Self::TenantMismatch { expected } => {
                write!(f, "tenant mismatch (expected {expected:?})")
            }
            Self::WrongStatus => f.write_str("run is not in Initializing status"),
            Self::ManifestInvalid(e) => write!(f, "manifest invalid: {e}"),
            Self::OpIdConflict { op_id, .. } => {
                write!(f, "op-id conflict: {op_id:?} reused with different payload")
            }
        }
    }
}

impl std::error::Error for RegisterShardsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ManifestInvalid(e) => Some(e),
            _ => None,
        }
    }
}

impl From<RunOpIdConflict> for RegisterShardsError {
    fn from(c: RunOpIdConflict) -> Self {
        Self::OpIdConflict {
            op_id: c.op_id,
            expected_hash: c.expected_hash,
            actual_hash: c.actual_hash,
        }
    }
}

// ============================================================================
// GetRunError
// ============================================================================

/// Error from `get_run`, `get_run_progress`, and `list_shards`.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum GetRunError {
    RunNotFound,
    /// Tenant isolation violation. Only `expected` is exposed (SEC-1).
    TenantMismatch {
        expected: TenantId,
    },
}

impl fmt::Display for GetRunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RunNotFound => f.write_str("run not found"),
            Self::TenantMismatch { expected } => {
                write!(f, "tenant mismatch (expected {expected:?})")
            }
        }
    }
}

impl std::error::Error for GetRunError {}

// ============================================================================
// CompleteRunError
// ============================================================================

/// Error from `complete_run`.
///
/// `complete_run` requires Active status.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CompleteRunError {
    RunNotFound,
    /// Tenant isolation violation. Only `expected` is exposed (SEC-1).
    TenantMismatch {
        expected: TenantId,
    },
    /// Run is already in a terminal state.
    RunTerminal,
    /// Run is not in `Active` status (e.g., still Initializing).
    WrongStatus,
    /// OpId reuse with different payload hash.
    OpIdConflict {
        op_id: OpId,
        expected_hash: u64,
        actual_hash: u64,
    },
}

impl fmt::Debug for CompleteRunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RunNotFound => write!(f, "RunNotFound"),
            Self::TenantMismatch { expected } => f
                .debug_struct("TenantMismatch")
                .field("expected", expected)
                .finish(),
            Self::RunTerminal => write!(f, "RunTerminal"),
            Self::WrongStatus => write!(f, "WrongStatus"),
            Self::OpIdConflict { op_id, .. } => f
                .debug_struct("OpIdConflict")
                .field("op_id", op_id)
                .field("expected_hash", &"<redacted>")
                .field("actual_hash", &"<redacted>")
                .finish(),
        }
    }
}

impl fmt::Display for CompleteRunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RunNotFound => f.write_str("run not found"),
            Self::TenantMismatch { expected } => {
                write!(f, "tenant mismatch (expected {expected:?})")
            }
            Self::RunTerminal => f.write_str("run is already terminal"),
            Self::WrongStatus => f.write_str("run is not Active"),
            Self::OpIdConflict { op_id, .. } => {
                write!(f, "op-id conflict: {op_id:?} reused with different payload")
            }
        }
    }
}

impl std::error::Error for CompleteRunError {}

impl From<RunOpIdConflict> for CompleteRunError {
    fn from(c: RunOpIdConflict) -> Self {
        Self::OpIdConflict {
            op_id: c.op_id,
            expected_hash: c.expected_hash,
            actual_hash: c.actual_hash,
        }
    }
}

// ============================================================================
// FailRunError
// ============================================================================

/// Error from `fail_run`.
///
/// Separate from `CompleteRunError` (PD-6) because `fail_run` requires
/// Active only (rejects Initializing), unlike `complete_run`.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FailRunError {
    RunNotFound,
    /// Tenant isolation violation. Only `expected` is exposed (SEC-1).
    TenantMismatch {
        expected: TenantId,
    },
    /// Run is already in a terminal state.
    RunTerminal,
    /// Run is not in `Active` status. For Initializing runs, use `cancel_run`.
    WrongStatus,
    /// OpId reuse with different payload hash.
    OpIdConflict {
        op_id: OpId,
        expected_hash: u64,
        actual_hash: u64,
    },
}

impl fmt::Debug for FailRunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RunNotFound => write!(f, "RunNotFound"),
            Self::TenantMismatch { expected } => f
                .debug_struct("TenantMismatch")
                .field("expected", expected)
                .finish(),
            Self::RunTerminal => write!(f, "RunTerminal"),
            Self::WrongStatus => write!(f, "WrongStatus"),
            Self::OpIdConflict { op_id, .. } => f
                .debug_struct("OpIdConflict")
                .field("op_id", op_id)
                .field("expected_hash", &"<redacted>")
                .field("actual_hash", &"<redacted>")
                .finish(),
        }
    }
}

impl fmt::Display for FailRunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RunNotFound => f.write_str("run not found"),
            Self::TenantMismatch { expected } => {
                write!(f, "tenant mismatch (expected {expected:?})")
            }
            Self::RunTerminal => f.write_str("run is already terminal"),
            Self::WrongStatus => f.write_str("run is not Active (use cancel_run for Initializing)"),
            Self::OpIdConflict { op_id, .. } => {
                write!(f, "op-id conflict: {op_id:?} reused with different payload")
            }
        }
    }
}

impl std::error::Error for FailRunError {}

impl From<RunOpIdConflict> for FailRunError {
    fn from(c: RunOpIdConflict) -> Self {
        Self::OpIdConflict {
            op_id: c.op_id,
            expected_hash: c.expected_hash,
            actual_hash: c.actual_hash,
        }
    }
}

// ============================================================================
// CancelRunError
// ============================================================================

/// Error from `cancel_run`.
///
/// `cancel_run` accepts both Initializing and Active (no `WrongStatus`
/// under normal operation — only terminal runs are rejected).
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CancelRunError {
    RunNotFound,
    /// Tenant isolation violation. Only `expected` is exposed (SEC-1).
    TenantMismatch {
        expected: TenantId,
    },
    /// Run is already in a terminal state.
    RunTerminal,
    /// OpId reuse with different payload hash.
    OpIdConflict {
        op_id: OpId,
        expected_hash: u64,
        actual_hash: u64,
    },
}

impl fmt::Debug for CancelRunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RunNotFound => write!(f, "RunNotFound"),
            Self::TenantMismatch { expected } => f
                .debug_struct("TenantMismatch")
                .field("expected", expected)
                .finish(),
            Self::RunTerminal => write!(f, "RunTerminal"),
            Self::OpIdConflict { op_id, .. } => f
                .debug_struct("OpIdConflict")
                .field("op_id", op_id)
                .field("expected_hash", &"<redacted>")
                .field("actual_hash", &"<redacted>")
                .finish(),
        }
    }
}

impl fmt::Display for CancelRunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RunNotFound => f.write_str("run not found"),
            Self::TenantMismatch { expected } => {
                write!(f, "tenant mismatch (expected {expected:?})")
            }
            Self::RunTerminal => f.write_str("run is already terminal"),
            Self::OpIdConflict { op_id, .. } => {
                write!(f, "op-id conflict: {op_id:?} reused with different payload")
            }
        }
    }
}

impl std::error::Error for CancelRunError {}

impl From<RunOpIdConflict> for CancelRunError {
    fn from(c: RunOpIdConflict) -> Self {
        Self::OpIdConflict {
            op_id: c.op_id,
            expected_hash: c.expected_hash,
            actual_hash: c.actual_hash,
        }
    }
}

// ============================================================================
// UnparkError
// ============================================================================

/// Error from `unpark_shard`.
///
/// Unpark is shard-level (not run-level) but managed through `RunManagement`
/// because it's an admin operation. Idempotency is stored in the shard op-log.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum UnparkError {
    /// The shard does not exist.
    ShardNotFound,
    /// Tenant isolation violation. Only `expected` is exposed (SEC-1).
    TenantMismatch { expected: TenantId },
    /// The shard is not in `Parked` status.
    NotParked { status: ShardStatus },
    /// OpId reuse with different payload hash.
    OpIdConflict {
        op_id: OpId,
        expected_hash: u64,
        actual_hash: u64,
    },
}

impl fmt::Debug for UnparkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ShardNotFound => write!(f, "ShardNotFound"),
            Self::TenantMismatch { expected } => f
                .debug_struct("TenantMismatch")
                .field("expected", expected)
                .finish(),
            Self::NotParked { status } => {
                f.debug_struct("NotParked").field("status", status).finish()
            }
            Self::OpIdConflict { op_id, .. } => f
                .debug_struct("OpIdConflict")
                .field("op_id", op_id)
                .field("expected_hash", &"<redacted>")
                .field("actual_hash", &"<redacted>")
                .finish(),
        }
    }
}

impl fmt::Display for UnparkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ShardNotFound => f.write_str("shard not found"),
            Self::TenantMismatch { expected } => {
                write!(f, "tenant mismatch (expected {expected:?})")
            }
            Self::NotParked { status } => {
                write!(f, "shard is not parked (status: {status})")
            }
            Self::OpIdConflict { op_id, .. } => {
                write!(f, "op-id conflict: {op_id:?} reused with different payload")
            }
        }
    }
}

impl std::error::Error for UnparkError {}

impl From<RunOpIdConflict> for UnparkError {
    fn from(c: RunOpIdConflict) -> Self {
        Self::OpIdConflict {
            op_id: c.op_id,
            expected_hash: c.expected_hash,
            actual_hash: c.actual_hash,
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{OpId, RunId, TenantId};

    fn test_tenant() -> TenantId {
        TenantId::from_bytes([0x01; 32])
    }

    // -- SEC-1: No actual tenant in any TenantMismatch --

    #[test]
    fn register_shards_error_no_actual_tenant() {
        let err = RegisterShardsError::TenantMismatch {
            expected: test_tenant(),
        };
        let display = err.to_string();
        assert!(display.contains("expected"));
        assert!(
            !display.contains("actual"),
            "must not contain 'actual': {display}"
        );
    }

    #[test]
    fn get_run_error_no_actual_tenant() {
        let err = GetRunError::TenantMismatch {
            expected: test_tenant(),
        };
        let display = err.to_string();
        assert!(
            !display.contains("actual"),
            "must not contain 'actual': {display}"
        );
    }

    #[test]
    fn complete_run_error_no_actual_tenant() {
        let err = CompleteRunError::TenantMismatch {
            expected: test_tenant(),
        };
        let display = err.to_string();
        assert!(
            !display.contains("actual"),
            "must not contain 'actual': {display}"
        );
    }

    #[test]
    fn fail_run_error_no_actual_tenant() {
        let err = FailRunError::TenantMismatch {
            expected: test_tenant(),
        };
        let display = err.to_string();
        assert!(
            !display.contains("actual"),
            "must not contain 'actual': {display}"
        );
    }

    #[test]
    fn cancel_run_error_no_actual_tenant() {
        let err = CancelRunError::TenantMismatch {
            expected: test_tenant(),
        };
        let display = err.to_string();
        assert!(
            !display.contains("actual"),
            "must not contain 'actual': {display}"
        );
    }

    #[test]
    fn unpark_error_no_actual_tenant() {
        let err = UnparkError::TenantMismatch {
            expected: test_tenant(),
        };
        let display = err.to_string();
        assert!(
            !display.contains("actual"),
            "must not contain 'actual': {display}"
        );
    }

    // -- SEC-6: OpIdConflict Debug redacts hashes --

    fn assert_op_id_conflict_redacted(debug: &str, type_name: &str) {
        assert!(
            debug.contains("<redacted>"),
            "{type_name} Debug must contain <redacted>: {debug}"
        );
        assert!(
            !debug.contains("DEAD") && !debug.contains("CAFE"),
            "{type_name} Debug leaks hex hash: {debug}"
        );
        assert!(
            !debug.contains("3735928559") && !debug.contains("3405691582"),
            "{type_name} Debug leaks decimal hash: {debug}"
        );
    }

    #[test]
    fn op_id_conflict_debug_redacted_all_types() {
        let op = OpId::from_raw(1);
        let ha = 0xDEAD_BEEF_u64;
        let hb = 0xCAFE_BABE_u64;

        let e = RegisterShardsError::OpIdConflict {
            op_id: op,
            expected_hash: ha,
            actual_hash: hb,
        };
        assert_op_id_conflict_redacted(&format!("{e:?}"), "RegisterShardsError");

        let e = CompleteRunError::OpIdConflict {
            op_id: op,
            expected_hash: ha,
            actual_hash: hb,
        };
        assert_op_id_conflict_redacted(&format!("{e:?}"), "CompleteRunError");

        let e = FailRunError::OpIdConflict {
            op_id: op,
            expected_hash: ha,
            actual_hash: hb,
        };
        assert_op_id_conflict_redacted(&format!("{e:?}"), "FailRunError");

        let e = CancelRunError::OpIdConflict {
            op_id: op,
            expected_hash: ha,
            actual_hash: hb,
        };
        assert_op_id_conflict_redacted(&format!("{e:?}"), "CancelRunError");

        let e = UnparkError::OpIdConflict {
            op_id: op,
            expected_hash: ha,
            actual_hash: hb,
        };
        assert_op_id_conflict_redacted(&format!("{e:?}"), "UnparkError");
    }

    // -- From<RunOpIdConflict> --

    #[test]
    fn from_run_op_id_conflict_routes_correctly() {
        use crate::coordination::run::RunOpIdConflict;

        let conflict = RunOpIdConflict {
            op_id: OpId::from_raw(42),
            expected_hash: 1,
            actual_hash: 2,
        };

        let _: RegisterShardsError = conflict.clone().into();
        let _: CompleteRunError = conflict.clone().into();
        let _: FailRunError = conflict.clone().into();
        let _: CancelRunError = conflict.clone().into();
        let _: UnparkError = conflict.into();
    }

    // -- Display determinism --

    #[test]
    fn error_display_deterministic() {
        let errors: Vec<Box<dyn std::error::Error>> = vec![
            Box::new(CreateRunError::RunAlreadyExists {
                run: RunId::from_raw(1),
            }),
            Box::new(RegisterShardsError::RunNotFound),
            Box::new(GetRunError::RunNotFound),
            Box::new(CompleteRunError::RunTerminal),
            Box::new(FailRunError::WrongStatus),
            Box::new(CancelRunError::RunTerminal),
            Box::new(UnparkError::ShardNotFound),
        ];
        for err in &errors {
            let s1 = err.to_string();
            let s2 = err.to_string();
            assert_eq!(s1, s2, "Display must be deterministic");
        }
    }
}
