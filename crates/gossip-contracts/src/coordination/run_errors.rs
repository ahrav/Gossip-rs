//! Operation-specific error types for run-level operations.
//!
//! Shares these conventions with shard-level `error.rs`:
//! - `#[non_exhaustive]` on all enums
//! - Custom `Debug` impls that redact hash values
//! - No `actual` field in `TenantMismatch` (tenant isolation)
//!
//! Differs from `error.rs` in error composition: shard-level errors use a
//! shared `CoordError` base with `From<CoordError>` narrowing per operation.
//! Run-level errors are per-operation where the variants differ meaningfully
//! (`CreateRunError`, `RegisterShardsError`, `GetRunError`, `UnparkError`).
//! Terminal transitions (`complete_run`, `fail_run`, `cancel_run`) share
//! [`RunTransitionError`] because their variant sets are structurally identical.
//! The only shared `From` conversion across all types is `From<RunOpIdConflict>`
//! (for types with an `OpIdConflict` variant); individual types may have
//! additional operation-specific `From` impls.
//!
//! ## Hash Redaction via Opaque Wrapper
//!
//! All `OpIdConflict` variants wrap [`RunOpIdConflict`] as a tuple variant
//! (`OpIdConflict(RunOpIdConflict)`) rather than exposing `expected_hash`
//! and `actual_hash` as public fields. This prevents external callers from
//! extracting raw hash values via pattern matching, ensuring that Debug
//! and Display redaction cannot be bypassed.

use std::fmt;

use gossip_stdx::SlabFull;

use crate::coordination::record::ShardStatus;
use crate::coordination::run::{
    ManifestValidationError, RunConfigError, RunOpIdConflict, RunStatus,
};
use crate::coordination::shard_spec::ShardLimitScope;
use crate::identity::{RunId, TenantId};

/// Generates the `From<RunOpIdConflict>` impl for error types with an
/// `OpIdConflict(RunOpIdConflict)` tuple variant.
macro_rules! impl_from_run_op_id_conflict {
    ($ty:ident) => {
        impl From<RunOpIdConflict> for $ty {
            fn from(c: RunOpIdConflict) -> Self {
                Self::OpIdConflict(c)
            }
        }
    };
}

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
    /// Shard registration failed during `create_run_with_shards`.
    RegisterShardsFailed(RegisterShardsError),
    /// Run lookup failed during `create_run_with_shards`.
    GetRunFailed(GetRunError),
    /// A run with this `RunId` already exists with a different `RunConfig`.
    ConfigMismatch { run: RunId },
}

impl fmt::Display for CreateRunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(e) => write!(f, "invalid run config: {e}"),
            Self::RunAlreadyExists { run } => write!(f, "run already exists: {run:?}"),
            Self::RegisterShardsFailed(e) => write!(f, "shard registration failed: {e}"),
            Self::GetRunFailed(e) => write!(f, "run lookup failed: {e}"),
            Self::ConfigMismatch { run } => {
                write!(f, "run {run:?} exists with different config")
            }
        }
    }
}

impl std::error::Error for CreateRunError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidConfig(e) => Some(e),
            Self::RegisterShardsFailed(e) => Some(e),
            Self::GetRunFailed(e) => Some(e),
            _ => None,
        }
    }
}

impl From<RunConfigError> for CreateRunError {
    fn from(e: RunConfigError) -> Self {
        Self::InvalidConfig(e)
    }
}

impl From<RegisterShardsError> for CreateRunError {
    fn from(e: RegisterShardsError) -> Self {
        Self::RegisterShardsFailed(e)
    }
}

impl From<GetRunError> for CreateRunError {
    fn from(e: GetRunError) -> Self {
        Self::GetRunFailed(e)
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
    /// Tenant isolation violation. Only `expected` is exposed (tenant isolation).
    TenantMismatch {
        expected: TenantId,
    },
    /// Run is not in `Initializing` status.
    WrongStatus {
        status: RunStatus,
    },
    /// Manifest validation failed.
    ManifestInvalid(ManifestValidationError),
    /// OpId reuse with different payload hash. Wraps [`RunOpIdConflict`]
    /// to prevent external access to raw hash values (hash redaction).
    OpIdConflict(RunOpIdConflict),
    /// Shard count limit exceeded (per-tenant or global).
    ShardLimitExceeded {
        current: usize,
        additional: usize,
        max: usize,
        scope: ShardLimitScope,
    },
    /// The byte slab could not satisfy an allocation request.
    /// Recoverable: the caller may retry after freeing slab space.
    ResourceExhausted(SlabFull),
    /// Coordinator index/map capacity could not be expanded for this request.
    /// Recoverable: retry with a larger runtime capacity budget.
    CapacityExceeded {
        resource: &'static str,
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
            Self::WrongStatus { status } => f
                .debug_struct("WrongStatus")
                .field("status", status)
                .finish(),
            Self::ManifestInvalid(e) => f.debug_tuple("ManifestInvalid").field(e).finish(),
            Self::OpIdConflict(c) => c.fmt(f),
            Self::ShardLimitExceeded {
                current,
                additional,
                max,
                scope,
            } => f
                .debug_struct("ShardLimitExceeded")
                .field("current", current)
                .field("additional", additional)
                .field("max", max)
                .field("scope", scope)
                .finish(),
            Self::ResourceExhausted(e) => f.debug_tuple("ResourceExhausted").field(e).finish(),
            Self::CapacityExceeded { resource } => f
                .debug_struct("CapacityExceeded")
                .field("resource", resource)
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
            Self::WrongStatus { status } => {
                write!(f, "run is not in Initializing status (status: {status})")
            }
            Self::ManifestInvalid(e) => write!(f, "manifest invalid: {e}"),
            Self::OpIdConflict(c) => fmt::Display::fmt(c, f),
            Self::ShardLimitExceeded {
                current,
                additional,
                max,
                scope,
            } => {
                write!(
                    f,
                    "shard limit exceeded ({scope:?}): {current} + {additional} > {max}"
                )
            }
            Self::ResourceExhausted(e) => write!(f, "slab full: {e}"),
            Self::CapacityExceeded { resource } => {
                write!(f, "coordinator capacity exceeded for {resource}")
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

impl_from_run_op_id_conflict!(RegisterShardsError);

impl From<SlabFull> for RegisterShardsError {
    fn from(e: SlabFull) -> Self {
        Self::ResourceExhausted(e)
    }
}

// ============================================================================
// GetRunError
// ============================================================================

/// Error from `get_run`, `get_run_progress`, and `list_shards_into`.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum GetRunError {
    RunNotFound,
    /// Tenant isolation violation. Only `expected` is exposed (tenant isolation).
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
// RunTransitionError
// ============================================================================

/// Error from terminal run transitions (`complete_run`, `fail_run`,
/// `cancel_run`).
///
/// All three operations share the same variant set. The only behavioral
/// difference is that `cancel_run` never produces `WrongStatus` (it
/// accepts both Initializing and Active). The `target` field in
/// `WrongStatus` preserves operation-specific Display messages.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RunTransitionError {
    RunNotFound,
    /// Tenant isolation violation. Only `expected` is exposed (tenant isolation).
    TenantMismatch {
        expected: TenantId,
    },
    /// Run is already in a terminal state.
    RunTerminal {
        status: RunStatus,
    },
    /// Run is not in the required status for this transition.
    ///
    /// `target` is the terminal status the caller attempted to transition to,
    /// enabling context-specific Display messages (e.g., "use cancel_run for
    /// Initializing" when target is `Failed`).
    ///
    /// `complete_run` produces `target: Done`; `fail_run` produces `target: Failed`.
    /// `cancel_run` never produces this variant.
    WrongStatus {
        status: RunStatus,
        target: RunStatus,
    },
    /// OpId reuse with different payload hash. Wraps [`RunOpIdConflict`]
    /// to prevent external access to raw hash values (hash redaction).
    OpIdConflict(RunOpIdConflict),
}

impl fmt::Debug for RunTransitionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RunNotFound => write!(f, "RunNotFound"),
            Self::TenantMismatch { expected } => f
                .debug_struct("TenantMismatch")
                .field("expected", expected)
                .finish(),
            Self::RunTerminal { status } => f
                .debug_struct("RunTerminal")
                .field("status", status)
                .finish(),
            Self::WrongStatus { status, target } => f
                .debug_struct("WrongStatus")
                .field("status", status)
                .field("target", target)
                .finish(),
            Self::OpIdConflict(c) => c.fmt(f),
        }
    }
}

impl fmt::Display for RunTransitionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RunNotFound => f.write_str("run not found"),
            Self::TenantMismatch { expected } => {
                write!(f, "tenant mismatch (expected {expected:?})")
            }
            Self::RunTerminal { status } => {
                write!(f, "run is already terminal (status: {status})")
            }
            Self::WrongStatus { status, target } => match target {
                RunStatus::Failed => write!(
                    f,
                    "run is not Active, use cancel_run for Initializing (status: {status})"
                ),
                RunStatus::Done => write!(f, "run is not Active (status: {status})"),
                other => write!(
                    f,
                    "run cannot transition to {other} from current status (status: {status})"
                ),
            },
            Self::OpIdConflict(c) => fmt::Display::fmt(c, f),
        }
    }
}

impl std::error::Error for RunTransitionError {}

impl_from_run_op_id_conflict!(RunTransitionError);

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
    /// Tenant isolation violation. Only `expected` is exposed (tenant isolation).
    TenantMismatch { expected: TenantId },
    /// The run is already in a terminal state — unparking is pointless.
    RunTerminal { status: RunStatus },
    /// The shard is not in `Parked` status.
    NotParked { status: ShardStatus },
    /// OpId reuse with different payload hash. Wraps [`RunOpIdConflict`]
    /// to prevent external access to raw hash values (hash redaction).
    OpIdConflict(RunOpIdConflict),
}

impl fmt::Debug for UnparkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ShardNotFound => write!(f, "ShardNotFound"),
            Self::TenantMismatch { expected } => f
                .debug_struct("TenantMismatch")
                .field("expected", expected)
                .finish(),
            Self::RunTerminal { status } => f
                .debug_struct("RunTerminal")
                .field("status", status)
                .finish(),
            Self::NotParked { status } => {
                f.debug_struct("NotParked").field("status", status).finish()
            }
            Self::OpIdConflict(c) => c.fmt(f),
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
            Self::RunTerminal { status } => {
                write!(f, "run is already terminal (status: {status})")
            }
            Self::NotParked { status } => {
                write!(f, "shard is not parked (status: {status})")
            }
            Self::OpIdConflict(c) => fmt::Display::fmt(c, f),
        }
    }
}

impl std::error::Error for UnparkError {}

impl_from_run_op_id_conflict!(UnparkError);

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coordination::run::{ManifestValidationError, RunConfigError, RunOpIdConflict};
    use crate::coordination::shard_spec::ShardLimitScope;
    use crate::identity::{OpId, RunId, ShardId, TenantId};
    use rstest::rstest;

    fn test_tenant() -> TenantId {
        TenantId::from_bytes([0x01; 32])
    }

    /// Helper to create a `RunOpIdConflict` for test construction.
    fn test_conflict() -> RunOpIdConflict {
        RunOpIdConflict {
            op_id: OpId::from_raw(1),
            expected_hash: 0xDEAD_BEEF,
            actual_hash: 0xCAFE_BABE,
        }
    }

    // -- SEC-1: No actual tenant in any TenantMismatch --

    #[rstest]
    #[case::register_shards(RegisterShardsError::TenantMismatch { expected: TenantId::from_bytes([0x01; 32]) }.to_string())]
    #[case::get_run(GetRunError::TenantMismatch { expected: TenantId::from_bytes([0x01; 32]) }.to_string())]
    #[case::run_transition(RunTransitionError::TenantMismatch { expected: TenantId::from_bytes([0x01; 32]) }.to_string())]
    #[case::unpark(UnparkError::TenantMismatch { expected: TenantId::from_bytes([0x01; 32]) }.to_string())]
    fn tenant_mismatch_no_actual_tenant(#[case] display: String) {
        assert!(
            display.contains("expected"),
            "must contain 'expected': {display}"
        );
        assert!(
            !display.contains("actual"),
            "must not contain 'actual': {display}"
        );
    }

    // -- SEC-6: OpIdConflict Debug redacts hashes --

    #[rstest]
    #[case::register_shards(format!("{:?}", RegisterShardsError::OpIdConflict(test_conflict())))]
    #[case::run_transition(format!("{:?}", RunTransitionError::OpIdConflict(test_conflict())))]
    #[case::unpark(format!("{:?}", UnparkError::OpIdConflict(test_conflict())))]
    fn op_id_conflict_debug_redacted(#[case] debug: String) {
        assert!(
            debug.contains("<redacted>"),
            "must contain <redacted>: {debug}"
        );
        assert!(
            !debug.contains("DEAD") && !debug.contains("CAFE"),
            "leaks hex hash: {debug}"
        );
        assert!(
            !debug.contains("3735928559") && !debug.contains("3405691582"),
            "leaks decimal hash: {debug}"
        );
    }

    // -- SEC-6: OpIdConflict Display does not leak hashes --

    #[rstest]
    #[case::register_shards(RegisterShardsError::OpIdConflict(test_conflict()).to_string())]
    #[case::run_transition(RunTransitionError::OpIdConflict(test_conflict()).to_string())]
    #[case::unpark(UnparkError::OpIdConflict(test_conflict()).to_string())]
    fn op_id_conflict_display_no_hash_leak(#[case] display: String) {
        assert!(
            !display.contains("DEAD") && !display.contains("CAFE"),
            "Display leaks hex hash: {display}"
        );
        assert!(
            !display.contains("3735928559") && !display.contains("3405691582"),
            "Display leaks decimal hash: {display}"
        );
    }

    // -- From<RunOpIdConflict> --

    #[test]
    fn from_run_op_id_conflict_routes_correctly() {
        let conflict = RunOpIdConflict {
            op_id: OpId::from_raw(42),
            expected_hash: 1,
            actual_hash: 2,
        };

        let _: RegisterShardsError = conflict.clone().into();
        let _: RunTransitionError = conflict.clone().into();
        let _: UnparkError = conflict.into();
    }

    // -- Display determinism --

    #[rstest]
    #[case::create_run_already_exists(Box::new(CreateRunError::RunAlreadyExists { run: RunId::from_raw(1) }) as Box<dyn std::error::Error>)]
    #[case::create_config_mismatch(Box::new(CreateRunError::ConfigMismatch { run: RunId::from_raw(1) }) as Box<dyn std::error::Error>)]
    #[case::create_register_shards_failed(Box::new(CreateRunError::RegisterShardsFailed(RegisterShardsError::RunNotFound)) as Box<dyn std::error::Error>)]
    #[case::create_get_run_failed(Box::new(CreateRunError::GetRunFailed(GetRunError::RunNotFound)) as Box<dyn std::error::Error>)]
    #[case::register_shards_not_found(Box::new(RegisterShardsError::RunNotFound) as Box<dyn std::error::Error>)]
    #[case::register_shard_limit(Box::new(RegisterShardsError::ShardLimitExceeded { current: 5, additional: 3, max: 6, scope: ShardLimitScope::PerTenant }) as Box<dyn std::error::Error>)]
    #[case::get_run_not_found(Box::new(GetRunError::RunNotFound) as Box<dyn std::error::Error>)]
    #[case::transition_terminal(Box::new(RunTransitionError::RunTerminal { status: RunStatus::Done }) as Box<dyn std::error::Error>)]
    #[case::transition_wrong_status_done(Box::new(RunTransitionError::WrongStatus { status: RunStatus::Initializing, target: RunStatus::Done }) as Box<dyn std::error::Error>)]
    #[case::transition_wrong_status_failed(Box::new(RunTransitionError::WrongStatus { status: RunStatus::Initializing, target: RunStatus::Failed }) as Box<dyn std::error::Error>)]
    #[case::unpark_shard_not_found(Box::new(UnparkError::ShardNotFound) as Box<dyn std::error::Error>)]
    #[case::unpark_run_terminal(Box::new(UnparkError::RunTerminal { status: RunStatus::Cancelled }) as Box<dyn std::error::Error>)]
    fn error_display_deterministic(#[case] err: Box<dyn std::error::Error>) {
        let s1 = err.to_string();
        let s2 = err.to_string();
        assert_eq!(s1, s2, "Display must be deterministic");
    }

    // -- Error::source() chaining --

    #[rstest]
    #[case::create_invalid_config(Box::new(CreateRunError::InvalidConfig(RunConfigError::ZeroLeaseDuration)) as Box<dyn std::error::Error>, true)]
    #[case::create_already_exists(Box::new(CreateRunError::RunAlreadyExists { run: RunId::from_raw(1) }) as Box<dyn std::error::Error>, false)]
    #[case::create_register_shards_failed(Box::new(CreateRunError::RegisterShardsFailed(RegisterShardsError::RunNotFound)) as Box<dyn std::error::Error>, true)]
    #[case::create_get_run_failed(Box::new(CreateRunError::GetRunFailed(GetRunError::RunNotFound)) as Box<dyn std::error::Error>, true)]
    #[case::create_config_mismatch(Box::new(CreateRunError::ConfigMismatch { run: RunId::from_raw(1) }) as Box<dyn std::error::Error>, false)]
    #[case::register_manifest_invalid(Box::new(RegisterShardsError::ManifestInvalid(ManifestValidationError::Empty)) as Box<dyn std::error::Error>, true)]
    #[case::register_manifest_unbounded(Box::new(RegisterShardsError::ManifestInvalid(ManifestValidationError::UnboundedRange { shard_id: ShardId::from_raw(0) })) as Box<dyn std::error::Error>, true)]
    #[case::register_not_found(Box::new(RegisterShardsError::RunNotFound) as Box<dyn std::error::Error>, false)]
    #[case::register_shard_limit(Box::new(RegisterShardsError::ShardLimitExceeded { current: 5, additional: 3, max: 6, scope: ShardLimitScope::PerTenant }) as Box<dyn std::error::Error>, false)]
    #[case::get_run_not_found(Box::new(GetRunError::RunNotFound) as Box<dyn std::error::Error>, false)]
    #[case::transition_terminal(Box::new(RunTransitionError::RunTerminal { status: RunStatus::Done }) as Box<dyn std::error::Error>, false)]
    #[case::transition_wrong_status(Box::new(RunTransitionError::WrongStatus { status: RunStatus::Initializing, target: RunStatus::Done }) as Box<dyn std::error::Error>, false)]
    #[case::unpark_shard_not_found(Box::new(UnparkError::ShardNotFound) as Box<dyn std::error::Error>, false)]
    #[case::unpark_run_terminal(Box::new(UnparkError::RunTerminal { status: RunStatus::Cancelled }) as Box<dyn std::error::Error>, false)]
    fn error_source_chaining(#[case] err: Box<dyn std::error::Error>, #[case] has_source: bool) {
        assert_eq!(err.source().is_some(), has_source);
    }

    // -- Display non-empty for all variants --

    #[rstest]
    // CreateRunError
    #[case::create_invalid_config(CreateRunError::InvalidConfig(RunConfigError::ZeroLeaseDuration).to_string())]
    #[case::create_already_exists(CreateRunError::RunAlreadyExists { run: RunId::from_raw(1) }.to_string())]
    #[case::create_register_shards_failed(CreateRunError::RegisterShardsFailed(RegisterShardsError::RunNotFound).to_string())]
    #[case::create_get_run_failed(CreateRunError::GetRunFailed(GetRunError::RunNotFound).to_string())]
    #[case::create_config_mismatch(CreateRunError::ConfigMismatch { run: RunId::from_raw(1) }.to_string())]
    // RegisterShardsError
    #[case::register_not_found(RegisterShardsError::RunNotFound.to_string())]
    #[case::register_tenant_mismatch(RegisterShardsError::TenantMismatch { expected: test_tenant() }.to_string())]
    #[case::register_wrong_status(RegisterShardsError::WrongStatus { status: RunStatus::Active }.to_string())]
    #[case::register_manifest_invalid(RegisterShardsError::ManifestInvalid(ManifestValidationError::Empty).to_string())]
    #[case::register_manifest_unbounded(RegisterShardsError::ManifestInvalid(ManifestValidationError::UnboundedRange { shard_id: ShardId::from_raw(0) }).to_string())]
    #[case::register_op_id_conflict(RegisterShardsError::OpIdConflict(test_conflict()).to_string())]
    #[case::register_shard_limit_exceeded(RegisterShardsError::ShardLimitExceeded { current: 5, additional: 3, max: 6, scope: ShardLimitScope::PerTenant }.to_string())]
    // GetRunError
    #[case::get_not_found(GetRunError::RunNotFound.to_string())]
    #[case::get_tenant_mismatch(GetRunError::TenantMismatch { expected: test_tenant() }.to_string())]
    // RunTransitionError
    #[case::transition_not_found(RunTransitionError::RunNotFound.to_string())]
    #[case::transition_tenant_mismatch(RunTransitionError::TenantMismatch { expected: test_tenant() }.to_string())]
    #[case::transition_terminal(RunTransitionError::RunTerminal { status: RunStatus::Done }.to_string())]
    #[case::transition_wrong_status_done(RunTransitionError::WrongStatus { status: RunStatus::Initializing, target: RunStatus::Done }.to_string())]
    #[case::transition_wrong_status_failed(RunTransitionError::WrongStatus { status: RunStatus::Initializing, target: RunStatus::Failed }.to_string())]
    #[case::transition_op_id_conflict(RunTransitionError::OpIdConflict(test_conflict()).to_string())]
    // UnparkError
    #[case::unpark_not_found(UnparkError::ShardNotFound.to_string())]
    #[case::unpark_tenant_mismatch(UnparkError::TenantMismatch { expected: test_tenant() }.to_string())]
    #[case::unpark_run_terminal(UnparkError::RunTerminal { status: RunStatus::Cancelled }.to_string())]
    #[case::unpark_not_parked(UnparkError::NotParked { status: ShardStatus::Active }.to_string())]
    #[case::unpark_op_id_conflict(UnparkError::OpIdConflict(test_conflict()).to_string())]
    fn all_variants_display_non_empty(#[case] display: String) {
        assert!(!display.is_empty(), "variant has empty Display: {display}");
    }

    // -- Variant-specific Display content --

    #[test]
    fn wrong_status_display_differs_by_target() {
        let done_err = RunTransitionError::WrongStatus {
            status: RunStatus::Initializing,
            target: RunStatus::Done,
        };
        let fail_err = RunTransitionError::WrongStatus {
            status: RunStatus::Initializing,
            target: RunStatus::Failed,
        };
        let done_msg = done_err.to_string();
        let fail_msg = fail_err.to_string();
        assert!(
            done_msg.contains("not Active"),
            "Done target must mention Active: {done_msg}"
        );
        assert!(
            fail_msg.contains("cancel_run"),
            "Failed target must suggest cancel_run: {fail_msg}"
        );
        assert_ne!(done_msg, fail_msg, "Display messages must differ by target");
    }

    #[test]
    fn wrong_status_catchall_target_produces_generic_message() {
        let err = RunTransitionError::WrongStatus {
            status: RunStatus::Initializing,
            target: RunStatus::Cancelled,
        };
        let msg = err.to_string();
        assert!(
            msg.contains("cannot transition to"),
            "catch-all must produce generic message: {msg}"
        );
    }

    #[test]
    fn unpark_not_parked_display_includes_status() {
        let e = UnparkError::NotParked {
            status: ShardStatus::Active,
        };
        let s = e.to_string();
        assert!(
            s.contains("Active"),
            "NotParked display must include status: {s}"
        );
    }

    #[test]
    fn create_run_register_shards_failed_display_includes_inner() {
        let e = CreateRunError::RegisterShardsFailed(RegisterShardsError::RunNotFound);
        let s = e.to_string();
        assert!(
            s.contains("shard registration failed"),
            "RegisterShardsFailed display must include prefix: {s}"
        );
        assert!(
            s.contains("run not found"),
            "RegisterShardsFailed display must include inner error: {s}"
        );
    }

    #[test]
    fn create_run_get_run_failed_display_includes_inner() {
        let e = CreateRunError::GetRunFailed(GetRunError::RunNotFound);
        let s = e.to_string();
        assert!(
            s.contains("run lookup failed"),
            "GetRunFailed display must include prefix: {s}"
        );
        assert!(
            s.contains("run not found"),
            "GetRunFailed display must include inner error: {s}"
        );
    }
}
