//! Backend-agnostic persistence conformance harness.
//!
//! This module provides a reusable test harness that every [`DoneLedger`] and
//! [`FindingsSink`] backend must pass. The harness is intentionally strict about
//! the invariants it can actually observe through the current persistence API:
//!
//! - done-ledger upserts are idempotent
//! - scanned states dominate failed states under out-of-order writes
//!   (the [`DoneLedgerStatus`] join-semilattice)
//! - findings-layer writes are replay-safe under retry
//! - occurrence / observation referential integrity failures do not leave
//!   partial durable rows behind (atomicity of failure)
//! - `Debug` for sensitive persistence types does not leak raw secret bytes
//!
//! ## Test structure
//!
//! The suite is split into three independently runnable sub-suites:
//!
//! 1. **Done-ledger** ([`run_done_ledger_conformance`]) — five checks:
//!    idempotent upsert, fail-then-scan dominance, scan-then-fail dominance,
//!    batch-get positional semantics, terminal-key enumeration.
//! 2. **Findings** ([`run_findings_conformance`]) — four checks: idempotent
//!    upsert with durable count verification, orphan occurrence rejection,
//!    orphan observation rejection, observation upsert merge idempotency.
//! 3. **Redaction** ([`run_redaction_conformance`]) — three checks: `NormHash`,
//!    `SecretHash`, and `FindingRecord` `Debug` output must not contain raw hex
//!    bytes of the underlying secret material.
//!
//! [`run_conformance`] executes all three sequentially and aggregates the
//! results into a [`PersistenceConformanceReport`].
//!
//! ## Fixture isolation
//!
//! Each test case constructs its own `SampleFixture`
//! from a distinct seed byte, producing unique `(tenant, policy, ovid)` keys.
//! This means test cases are independent of each other and of any pre-existing
//! state in the backend — they can run against a shared backend instance
//! without cross-contamination.
//!
//! ## Why a probe trait exists
//!
//! The write-side `FindingsSink` API is intentionally narrow. That is correct
//! for production, but it means pure write-only testing cannot observe whether
//! replay created duplicate durable rows. A backend could accept the same batch
//! twice and silently duplicate storage while still returning `Ok(())` both
//! times.
//!
//! To make idempotency testable, the harness uses a small test-only read-side
//! probe: [`FindingsConformanceProbe`]. Production code does not depend on this
//! trait; backend test suites implement it in their test harnesses.

use std::{collections::HashSet, error::Error, fmt, sync::Arc};

use super::{
    CommitHandle, DoneLedger, DoneLedgerCommitReceipt, DoneLedgerErrorCode, DoneLedgerKey,
    DoneLedgerProvenance, DoneLedgerRecord, DoneLedgerStatus, FindingRecord, FindingsCommitReceipt,
    FindingsSink, FindingsUpsertBatch, ObservationRecord, OccurrenceRecord, OvidHash,
    OvidHashInputs, derive_ovid_hash,
};
use crate::{
    connector::{Location, VersionId},
    identity::{
        FenceEpoch, LogicalTime, NormHash, ObjectVersionId, PolicyHash, RuleFingerprint, RunId,
        ShardId, StableItemId, TenantId, TenantSecretKey, key_secret_hash,
    },
};

/// Type alias for a boxed, thread-safe error used in internal harness diagnostics.
type BoxError = Box<dyn Error + Send + Sync + 'static>;

/// Durable row counts observed through the findings-layer test probe.
///
/// Mirrors the three-layer findings data model (finding → occurrence →
/// observation). The conformance harness snapshots counts before and after
/// writes, then uses [`saturating_sub`](Self::saturating_sub) to compute
/// deltas and verify that replays produce zero additional rows.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DurableFindingsCounts {
    /// Number of durable finding rows.
    pub findings: u64,
    /// Number of durable occurrence rows.
    pub occurrences: u64,
    /// Number of durable observation rows.
    pub observations: u64,
}

impl DurableFindingsCounts {
    /// Construct count totals for all three findings layers.
    #[inline]
    #[must_use]
    pub const fn new(findings: u64, occurrences: u64, observations: u64) -> Self {
        Self {
            findings,
            occurrences,
            observations,
        }
    }

    /// Return the per-layer saturating delta from `base`.
    ///
    /// Used by the conformance harness to compare before/after snapshots.
    /// Saturating arithmetic avoids panic if a backend resets counts between
    /// snapshots (the delta clamps to zero rather than wrapping).
    #[inline]
    #[must_use]
    pub const fn saturating_sub(self, base: Self) -> Self {
        Self {
            findings: self.findings.saturating_sub(base.findings),
            occurrences: self.occurrences.saturating_sub(base.occurrences),
            observations: self.observations.saturating_sub(base.observations),
        }
    }
}

/// Test-only read-side probe for observing durable findings state.
///
/// The production [`FindingsSink`] API is write-only by design. That makes it
/// impossible to verify idempotency from the outside: a backend that silently
/// duplicates rows on replay still returns `Ok(())`. This trait adds a narrow
/// read surface — just enough for the conformance harness to snapshot row
/// counts before and after writes.
///
/// Backend crates typically implement this on their in-memory test double or
/// directly on the integration-test wrapper around the real store. Production
/// code paths never reference this trait.
pub trait FindingsConformanceProbe: Send + Sync {
    /// Backend-specific probe error.
    type Error: Error + Send + Sync + 'static;

    /// Return durable row counts currently visible through the backend.
    ///
    /// "Currently visible" means the counts should reflect all writes whose
    /// [`CommitHandle::wait`] has already returned successfully. Backends that
    /// buffer writes asynchronously must ensure the probe sees flushed state.
    fn durable_counts(&self) -> Result<DurableFindingsCounts, Self::Error>;
}

/// Aggregate report returned by [`run_conformance`].
///
/// Each field counts the number of checks that passed in that sub-suite. The
/// harness returns `Err` on the first failure, so a successful report means
/// *all* checks passed.
///
/// Current check counts (for reference):
/// - Done-ledger: 5 (idempotent upsert, fail→scan dominance, scan→fail dominance,
///   batch-get positional semantics, terminal-key enumeration)
/// - Findings: 4 (idempotent upsert, orphan occurrence, orphan observation,
///   observation upsert merge)
/// - Redaction: 3 (`NormHash` debug, `SecretHash` debug, `FindingRecord` debug)
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PersistenceConformanceReport {
    /// Number of done-ledger checks that completed successfully.
    pub done_ledger_checks: u32,
    /// Number of findings checks that completed successfully.
    pub findings_checks: u32,
    /// Number of redaction checks that completed successfully.
    pub redaction_checks: u32,
}

impl PersistenceConformanceReport {
    /// Construct a report from the completed check counts.
    #[inline]
    #[must_use]
    pub const fn new(done_ledger_checks: u32, findings_checks: u32, redaction_checks: u32) -> Self {
        Self {
            done_ledger_checks,
            findings_checks,
            redaction_checks,
        }
    }

    /// Sum of all check counts across sub-suites.
    #[inline]
    #[must_use]
    pub const fn total_checks(self) -> u32 {
        self.done_ledger_checks + self.findings_checks + self.redaction_checks
    }
}

impl fmt::Display for PersistenceConformanceReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "persistence conformance: {} done-ledger, {} findings, {} redaction ({} total)",
            self.done_ledger_checks,
            self.findings_checks,
            self.redaction_checks,
            self.total_checks(),
        )
    }
}

/// Failure reported by the persistence conformance harness.
///
/// Every variant carries a `case` label formatted as `"sub-suite/test:phase"`
/// (e.g. `"done-ledger/idempotent:fetch"`) so failures can be traced back to
/// the exact check and phase that produced them.
///
/// Variants split into two categories:
/// - **Operational failures** (`*Submit`, `*Wait`, `*Get`, `Probe`,
///   `FixtureConstruction`) — the backend returned an error where the harness
///   expected success. These carry a boxed source error for diagnostics.
/// - **Invariant violations** (`*Invariant`, `RedactionLeak`) — the backend
///   succeeded but the observable result violated a persistence contract.
///   These carry a human-readable message describing the violation.
#[derive(Debug, thiserror::Error)]
pub enum PersistenceConformanceError {
    /// Internal sample-data construction failed.
    FixtureConstruction {
        case: &'static str,
        source: BoxError,
    },
    /// Done-ledger write submission failed unexpectedly.
    DoneLedgerSubmit {
        case: &'static str,
        source: BoxError,
    },
    /// Done-ledger durable acknowledgement failed unexpectedly.
    DoneLedgerWait {
        case: &'static str,
        source: BoxError,
    },
    /// Done-ledger lookup failed unexpectedly.
    DoneLedgerGet {
        case: &'static str,
        source: BoxError,
    },
    /// Done-ledger invariant violation.
    DoneLedgerInvariant { case: &'static str, message: String },
    /// Findings write submission failed unexpectedly.
    FindingsSubmit {
        case: &'static str,
        source: BoxError,
    },
    /// Findings durable acknowledgement failed unexpectedly.
    FindingsWait {
        case: &'static str,
        source: BoxError,
    },
    /// Findings invariant violation.
    FindingsInvariant { case: &'static str, message: String },
    /// Findings probe failed.
    Probe {
        case: &'static str,
        source: BoxError,
    },
    /// Sensitive debug output leaked raw bytes.
    RedactionLeak {
        case: &'static str,
        debug_output: String,
        leaked_fragment: String,
    },
}

impl fmt::Display for PersistenceConformanceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FixtureConstruction { case, source } => {
                write!(f, "fixture construction failed for {case}: {source}")
            }
            Self::DoneLedgerSubmit { case, source } => {
                write!(f, "done-ledger submission failed in {case}: {source}")
            }
            Self::DoneLedgerWait { case, source } => {
                write!(f, "done-ledger wait failed in {case}: {source}")
            }
            Self::DoneLedgerGet { case, source } => {
                write!(f, "done-ledger lookup failed in {case}: {source}")
            }
            Self::DoneLedgerInvariant { case, message } => {
                write!(f, "done-ledger invariant failed in {case}: {message}")
            }
            Self::FindingsSubmit { case, source } => {
                write!(f, "findings submission failed in {case}: {source}")
            }
            Self::FindingsWait { case, source } => {
                write!(f, "findings wait failed in {case}: {source}")
            }
            Self::FindingsInvariant { case, message } => {
                write!(f, "findings invariant failed in {case}: {message}")
            }
            Self::Probe { case, source } => write!(f, "findings probe failed in {case}: {source}"),
            Self::RedactionLeak {
                case,
                leaked_fragment,
                ..
            } => {
                let truncated = if leaked_fragment.len() > 8 {
                    format!("{}...", &leaked_fragment[..8])
                } else {
                    leaked_fragment.clone()
                };
                write!(
                    f,
                    "sensitive Debug output leaked raw bytes in {case}: \
                     leaked fragment `{truncated}` (full output redacted)"
                )
            }
        }
    }
}

/// Run the full persistence conformance suite against one done-ledger backend
/// and one findings backend.
///
/// Executes [`run_done_ledger_conformance`], [`run_findings_conformance`], and
/// [`run_redaction_conformance`] sequentially. Stops at the first failure.
///
/// The findings backend must also implement [`FindingsConformanceProbe`] so the
/// harness can snapshot durable row counts and prove replay does not duplicate
/// rows.
///
/// # Errors
///
/// Returns [`PersistenceConformanceError`] on the first check that fails,
/// whether due to a backend operational error or a contract invariant violation.
pub fn run_conformance<L, F>(
    done_ledger: &L,
    findings: &F,
) -> Result<PersistenceConformanceReport, PersistenceConformanceError>
where
    L: DoneLedger,
    F: FindingsSink + FindingsConformanceProbe,
{
    let done_ledger_checks = run_done_ledger_conformance(done_ledger)?;
    let findings_checks = run_findings_conformance(findings)?;
    let redaction_checks = run_redaction_conformance()?;
    Ok(PersistenceConformanceReport {
        done_ledger_checks,
        findings_checks,
        redaction_checks,
    })
}

/// Run only the done-ledger portion of the conformance suite.
///
/// Verifies five properties of the [`DoneLedger`] implementation:
///
/// 1. **Idempotent upsert** — writing the same `ScannedWithFindings` record
///    twice must not alter durable state. The harness writes, replays, reads
///    back, and asserts byte-for-byte equality.
///
/// 2. **Fail-then-scan dominance** — writing a `FailedRetryable` record
///    followed by a `ScannedWithFindings` record for the same key must leave
///    the durable state in the scanned status, because [`DoneLedgerStatus`]
///    forms a join-semilattice where scanned ranks above failed.
///
/// 3. **Scan-then-fail dominance** — the reverse ordering must produce the
///    same result: a subsequent failure write must not downgrade a scanned
///    entry. This tests the lattice property regardless of arrival order.
///
/// 4. **Batch-get positional semantics** — `batch_get` with a multi-element
///    `ovid_hashes` slice must return a result vector of the same length,
///    where `result[i]` corresponds to `ovid_hashes[i]`. Existing keys
///    yield `Some`, absent keys yield `None`, and the positional alignment
///    must hold regardless of which keys are present.
///
/// 5. **Terminal-key enumeration** — `list_done_hashes` must return exactly
///    the keys in the requested `(tenant, policy)` scope whose durable status
///    is terminal. `FailedRetryable` keys must be excluded. Cross-tenant and
///    cross-policy isolation must hold: terminal keys outside the queried scope
///    must not appear in results.
///
/// Returns the number of checks that passed (currently 5).
///
/// # Errors
///
/// Returns on the first invariant violation or backend error.
pub fn run_done_ledger_conformance<L>(done_ledger: &L) -> Result<u32, PersistenceConformanceError>
where
    L: DoneLedger,
{
    check_done_ledger_idempotent(done_ledger)?;
    check_done_ledger_fail_then_scan(done_ledger)?;
    check_done_ledger_scan_then_fail(done_ledger)?;
    check_done_ledger_batch_get_positional(done_ledger)?;
    check_done_ledger_list_done_hashes(done_ledger)?;
    Ok(5)
}

/// Check 1: writing the same `ScannedWithFindings` record twice must not
/// alter durable state. The harness writes, replays, reads back, and asserts
/// byte-for-byte equality.
fn check_done_ledger_idempotent<L>(done_ledger: &L) -> Result<(), PersistenceConformanceError>
where
    L: DoneLedger,
{
    let fixture = sample_fixture(0x11)?;
    let receipt = submit_done_ledger(
        done_ledger,
        "done-ledger/idempotent:first",
        std::slice::from_ref(&fixture.scanned_record),
    )?;
    if receipt.record_count() != 1 || receipt.scanned_count() != 1 || receipt.findings_count() != 1
    {
        return Err(PersistenceConformanceError::DoneLedgerInvariant {
            case: "done-ledger/idempotent:first",
            message: format!(
                "unexpected receipt counts: record_count={}, scanned_count={}, findings_count={}",
                receipt.record_count(),
                receipt.scanned_count(),
                receipt.findings_count(),
            ),
        });
    }
    let _ = submit_done_ledger(
        done_ledger,
        "done-ledger/idempotent:second",
        std::slice::from_ref(&fixture.scanned_record),
    )?;
    let fetched = get_single_done_ledger(done_ledger, "done-ledger/idempotent:fetch", &fixture)?;
    if fetched != fixture.scanned_record {
        return Err(PersistenceConformanceError::DoneLedgerInvariant {
            case: "done-ledger/idempotent:fetch",
            message: format!(
                "replaying the same record changed durable state: expected {:?}, got {:?}",
                fixture.scanned_record, fetched
            ),
        });
    }
    Ok(())
}

/// Check 2: writing a `FailedRetryable` record followed by a
/// `ScannedWithFindings` record for the same key must leave the durable state
/// in the scanned status (the lattice join of failed v scanned).
fn check_done_ledger_fail_then_scan<L>(done_ledger: &L) -> Result<(), PersistenceConformanceError>
where
    L: DoneLedger,
{
    let fixture = sample_fixture(0x22)?;
    let _ = submit_done_ledger(
        done_ledger,
        "done-ledger/fail-then-scan:failed",
        std::slice::from_ref(&fixture.failed_record),
    )?;
    let _ = submit_done_ledger(
        done_ledger,
        "done-ledger/fail-then-scan:scanned",
        std::slice::from_ref(&fixture.scanned_record),
    )?;
    let fetched =
        get_single_done_ledger(done_ledger, "done-ledger/fail-then-scan:fetch", &fixture)?;
    assert_scanned_dominates(
        "done-ledger/fail-then-scan:fetch",
        &fixture.failed_record,
        &fixture.scanned_record,
        &fetched,
    )
}

/// Check 3: the reverse arrival order (scanned first, failure second) must
/// produce the same result. A subsequent failure write must not downgrade a
/// scanned entry. This tests the lattice property regardless of arrival order.
fn check_done_ledger_scan_then_fail<L>(done_ledger: &L) -> Result<(), PersistenceConformanceError>
where
    L: DoneLedger,
{
    let fixture = sample_fixture(0x33)?;
    let _ = submit_done_ledger(
        done_ledger,
        "done-ledger/scan-then-fail:scanned",
        std::slice::from_ref(&fixture.scanned_record),
    )?;
    let _ = submit_done_ledger(
        done_ledger,
        "done-ledger/scan-then-fail:failed",
        std::slice::from_ref(&fixture.failed_record),
    )?;
    let fetched =
        get_single_done_ledger(done_ledger, "done-ledger/scan-then-fail:fetch", &fixture)?;
    assert_scanned_dominates(
        "done-ledger/scan-then-fail:fetch",
        &fixture.failed_record,
        &fixture.scanned_record,
        &fetched,
    )
}

/// Check 4: `batch_get` with a two-element `ovid_hashes` slice must return
/// a result vector of the same length, where `result[0]` is `Some` for a
/// written key and `result[1]` is `None` for an absent key.
fn check_done_ledger_batch_get_positional<L>(
    done_ledger: &L,
) -> Result<(), PersistenceConformanceError>
where
    L: DoneLedger,
{
    let fixture = sample_fixture(0xAA)?;
    let _ = submit_done_ledger(
        done_ledger,
        "done-ledger/batch-get-positional:write",
        std::slice::from_ref(&fixture.scanned_record),
    )?;
    // Derive a second ovid_hash that shares tenant/policy but was never written.
    let absent_ovid_hash = derive_ovid_hash(&OvidHashInputs {
        stable_item_id: StableItemId::from_bytes(fill32(0xAA_u8.wrapping_add(20))),
        version: VersionId::Strong(ObjectVersionId::from_version_bytes(
            b"conformance-absent-version",
        )),
    });
    let rows = done_ledger
        .batch_get(
            fixture.tenant_id,
            fixture.policy_hash,
            &[fixture.ovid_hash, absent_ovid_hash],
        )
        .map_err(|err| PersistenceConformanceError::DoneLedgerGet {
            case: "done-ledger/batch-get-positional:fetch",
            source: Box::new(err),
        })?;
    if rows.len() != 2 {
        return Err(PersistenceConformanceError::DoneLedgerInvariant {
            case: "done-ledger/batch-get-positional:fetch",
            message: format!(
                "expected result length 2 for two-element query, got {}",
                rows.len()
            ),
        });
    }
    if rows[0].is_none() {
        return Err(PersistenceConformanceError::DoneLedgerInvariant {
            case: "done-ledger/batch-get-positional:fetch",
            message: "result[0] should be Some for a written key, got None".to_owned(),
        });
    }
    if rows[1].is_some() {
        return Err(PersistenceConformanceError::DoneLedgerInvariant {
            case: "done-ledger/batch-get-positional:fetch",
            message: "result[1] should be None for an absent key, got Some".to_owned(),
        });
    }
    Ok(())
}

/// Check 5: `list_done_hashes` must return only terminal keys for one scope,
/// with cross-tenant and cross-policy isolation.
fn check_done_ledger_list_done_hashes<L>(done_ledger: &L) -> Result<(), PersistenceConformanceError>
where
    L: DoneLedger,
{
    let fixture = sample_fixture(0xBB)?;
    let retryable_hash = derive_ovid_hash(&OvidHashInputs {
        stable_item_id: StableItemId::from_bytes(fill32(0xBB_u8.wrapping_add(20))),
        version: VersionId::Strong(ObjectVersionId::from_version_bytes(
            b"conformance-retryable-version",
        )),
    });
    let retryable_error_code =
        DoneLedgerErrorCode::try_new("TEMP_RETRYABLE").map_err(|source| {
            PersistenceConformanceError::FixtureConstruction {
                case: "done-ledger/list-done-hashes:retryable-error-code",
                source: Box::new(source),
            }
        })?;
    let retryable_record = DoneLedgerRecord::try_new(
        DoneLedgerKey::new(fixture.tenant_id, fixture.policy_hash, retryable_hash),
        DoneLedgerStatus::FailedRetryable,
        512,
        0,
        DoneLedgerProvenance::new(
            RunId::from_raw(33),
            ShardId::from_raw(34),
            FenceEpoch::from_raw(35),
            LogicalTime::from_raw(36),
            LogicalTime::from_raw(37),
        ),
        Some(retryable_error_code),
    )
    .map_err(|source| PersistenceConformanceError::FixtureConstruction {
        case: "done-ledger/list-done-hashes:retryable-record",
        source: Box::new(source),
    })?;

    let failed_permanent_hash = derive_ovid_hash(&OvidHashInputs {
        stable_item_id: StableItemId::from_bytes(fill32(0xBB_u8.wrapping_add(21))),
        version: VersionId::Strong(ObjectVersionId::from_version_bytes(
            b"conformance-failed-permanent-version",
        )),
    });
    let failed_permanent_code = DoneLedgerErrorCode::try_new("PERM_FAILURE").map_err(|source| {
        PersistenceConformanceError::FixtureConstruction {
            case: "done-ledger/list-done-hashes:failed-permanent-error-code",
            source: Box::new(source),
        }
    })?;
    let failed_permanent_record = DoneLedgerRecord::try_new(
        DoneLedgerKey::new(
            fixture.tenant_id,
            fixture.policy_hash,
            failed_permanent_hash,
        ),
        DoneLedgerStatus::FailedPermanent,
        1024,
        0,
        DoneLedgerProvenance::new(
            RunId::from_raw(40),
            ShardId::from_raw(41),
            FenceEpoch::from_raw(42),
            LogicalTime::from_raw(43),
            LogicalTime::from_raw(44),
        ),
        Some(failed_permanent_code),
    )
    .map_err(|source| PersistenceConformanceError::FixtureConstruction {
        case: "done-ledger/list-done-hashes:failed-permanent-record",
        source: Box::new(source),
    })?;

    let skipped_hash = derive_ovid_hash(&OvidHashInputs {
        stable_item_id: StableItemId::from_bytes(fill32(0xBB_u8.wrapping_add(22))),
        version: VersionId::Strong(ObjectVersionId::from_version_bytes(
            b"conformance-skipped-version",
        )),
    });
    let skipped_code = DoneLedgerErrorCode::try_new("UNSUPPORTED_FORMAT").map_err(|source| {
        PersistenceConformanceError::FixtureConstruction {
            case: "done-ledger/list-done-hashes:skipped-error-code",
            source: Box::new(source),
        }
    })?;
    let skipped_record = DoneLedgerRecord::try_new(
        DoneLedgerKey::new(fixture.tenant_id, fixture.policy_hash, skipped_hash),
        DoneLedgerStatus::Skipped,
        512,
        0,
        DoneLedgerProvenance::new(
            RunId::from_raw(50),
            ShardId::from_raw(51),
            FenceEpoch::from_raw(52),
            LogicalTime::from_raw(53),
            LogicalTime::from_raw(54),
        ),
        Some(skipped_code),
    )
    .map_err(|source| PersistenceConformanceError::FixtureConstruction {
        case: "done-ledger/list-done-hashes:skipped-record",
        source: Box::new(source),
    })?;

    let scanned_clean_hash = derive_ovid_hash(&OvidHashInputs {
        stable_item_id: StableItemId::from_bytes(fill32(0xBB_u8.wrapping_add(23))),
        version: VersionId::Strong(ObjectVersionId::from_version_bytes(
            b"conformance-scanned-clean-version",
        )),
    });
    let scanned_clean_record = DoneLedgerRecord::try_new(
        DoneLedgerKey::new(fixture.tenant_id, fixture.policy_hash, scanned_clean_hash),
        DoneLedgerStatus::ScannedClean,
        2048,
        0,
        DoneLedgerProvenance::new(
            RunId::from_raw(60),
            ShardId::from_raw(61),
            FenceEpoch::from_raw(62),
            LogicalTime::from_raw(63),
            LogicalTime::from_raw(64),
        ),
        None,
    )
    .map_err(|source| PersistenceConformanceError::FixtureConstruction {
        case: "done-ledger/list-done-hashes:scanned-clean-record",
        source: Box::new(source),
    })?;

    let _ = submit_done_ledger(
        done_ledger,
        "done-ledger/list-done-hashes:upsert",
        &[
            fixture.scanned_record.clone(),
            retryable_record,
            failed_permanent_record,
            skipped_record,
            scanned_clean_record,
        ],
    )?;

    let hashes = done_ledger
        .list_done_hashes(fixture.tenant_id, fixture.policy_hash)
        .map_err(|err| PersistenceConformanceError::DoneLedgerGet {
            case: "done-ledger/list-done-hashes:list",
            source: Box::new(err),
        })?;
    // Assert raw Vec length before converting to HashSet so duplicate rows
    // from a buggy backend cannot be masked by set deduplication.
    let expected_terminal_count = 4;
    if hashes.len() != expected_terminal_count {
        return Err(PersistenceConformanceError::DoneLedgerInvariant {
            case: "done-ledger/list-done-hashes:terminal-count",
            message: format!(
                "expected {} terminal hashes, got {}",
                expected_terminal_count,
                hashes.len()
            ),
        });
    }
    let actual: HashSet<_> = hashes.into_iter().collect();
    let expected = HashSet::from([
        fixture.ovid_hash,
        failed_permanent_hash,
        skipped_hash,
        scanned_clean_hash,
    ]);
    if actual != expected {
        return Err(PersistenceConformanceError::DoneLedgerInvariant {
            case: "done-ledger/list-done-hashes:terminal-set",
            message: format!(
                "expected terminal hash set {:?}, got {:?}",
                expected, actual
            ),
        });
    }

    // Cross-tenant isolation: a terminal key under a different tenant must not
    // leak into the original scope's results.
    let other_tenant = TenantId::from_bytes(fill32(0xBB_u8.wrapping_add(30)));
    let cross_tenant_hash = derive_ovid_hash(&OvidHashInputs {
        stable_item_id: StableItemId::from_bytes(fill32(0xBB_u8.wrapping_add(31))),
        version: VersionId::Strong(ObjectVersionId::from_version_bytes(
            b"conformance-cross-tenant-version",
        )),
    });
    let cross_tenant_record = DoneLedgerRecord::try_new(
        DoneLedgerKey::new(other_tenant, fixture.policy_hash, cross_tenant_hash),
        DoneLedgerStatus::ScannedClean,
        256,
        0,
        DoneLedgerProvenance::new(
            RunId::from_raw(70),
            ShardId::from_raw(71),
            FenceEpoch::from_raw(72),
            LogicalTime::from_raw(73),
            LogicalTime::from_raw(74),
        ),
        None,
    )
    .map_err(|source| PersistenceConformanceError::FixtureConstruction {
        case: "done-ledger/list-done-hashes:cross-tenant-record",
        source: Box::new(source),
    })?;
    let _ = submit_done_ledger(
        done_ledger,
        "done-ledger/list-done-hashes:cross-tenant-upsert",
        &[cross_tenant_record],
    )?;

    let hashes_after = done_ledger
        .list_done_hashes(fixture.tenant_id, fixture.policy_hash)
        .map_err(|err| PersistenceConformanceError::DoneLedgerGet {
            case: "done-ledger/list-done-hashes:cross-tenant-requery",
            source: Box::new(err),
        })?;
    if hashes_after.len() != expected_terminal_count {
        return Err(PersistenceConformanceError::DoneLedgerInvariant {
            case: "done-ledger/list-done-hashes:cross-tenant-count",
            message: format!(
                "cross-tenant requery: expected {} hashes, got {}",
                expected_terminal_count,
                hashes_after.len()
            ),
        });
    }
    let actual_after: HashSet<_> = hashes_after.into_iter().collect();
    if actual_after != expected {
        return Err(PersistenceConformanceError::DoneLedgerInvariant {
            case: "done-ledger/list-done-hashes:cross-tenant-isolation",
            message: format!(
                "cross-tenant key leaked into scope: expected {:?}, got {:?}",
                expected, actual_after
            ),
        });
    }

    // Cross-policy isolation: a terminal key under the same tenant but a
    // different policy must not leak into the original scope's results.
    let other_policy = PolicyHash::from_bytes(fill32(0xBB_u8.wrapping_add(32)));
    let cross_policy_hash = derive_ovid_hash(&OvidHashInputs {
        stable_item_id: StableItemId::from_bytes(fill32(0xBB_u8.wrapping_add(33))),
        version: VersionId::Strong(ObjectVersionId::from_version_bytes(
            b"conformance-cross-policy-version",
        )),
    });
    let cross_policy_record = DoneLedgerRecord::try_new(
        DoneLedgerKey::new(fixture.tenant_id, other_policy, cross_policy_hash),
        DoneLedgerStatus::ScannedClean,
        256,
        0,
        DoneLedgerProvenance::new(
            RunId::from_raw(80),
            ShardId::from_raw(81),
            FenceEpoch::from_raw(82),
            LogicalTime::from_raw(83),
            LogicalTime::from_raw(84),
        ),
        None,
    )
    .map_err(|source| PersistenceConformanceError::FixtureConstruction {
        case: "done-ledger/list-done-hashes:cross-policy-record",
        source: Box::new(source),
    })?;
    let _ = submit_done_ledger(
        done_ledger,
        "done-ledger/list-done-hashes:cross-policy-upsert",
        &[cross_policy_record],
    )?;

    let hashes_cross_policy = done_ledger
        .list_done_hashes(fixture.tenant_id, fixture.policy_hash)
        .map_err(|err| PersistenceConformanceError::DoneLedgerGet {
            case: "done-ledger/list-done-hashes:cross-policy-requery",
            source: Box::new(err),
        })?;
    if hashes_cross_policy.len() != expected_terminal_count {
        return Err(PersistenceConformanceError::DoneLedgerInvariant {
            case: "done-ledger/list-done-hashes:cross-policy-count",
            message: format!(
                "cross-policy requery: expected {} hashes, got {}",
                expected_terminal_count,
                hashes_cross_policy.len()
            ),
        });
    }
    let actual_cross_policy: HashSet<_> = hashes_cross_policy.into_iter().collect();
    if actual_cross_policy != expected {
        return Err(PersistenceConformanceError::DoneLedgerInvariant {
            case: "done-ledger/list-done-hashes:cross-policy-isolation",
            message: format!(
                "cross-policy key leaked into scope: expected {:?}, got {:?}",
                expected, actual_cross_policy
            ),
        });
    }

    Ok(())
}

/// Run only the findings-layer portion of the conformance suite.
///
/// Verifies four properties of a [`FindingsSink`] + [`FindingsConformanceProbe`]
/// implementation:
///
/// 1. **Idempotent upsert** — writing a complete (finding, occurrence,
///    observation) batch twice must add exactly one row per layer on the first
///    write and zero additional rows on the replay. The harness uses the probe
///    to snapshot durable counts before, between, and after the two writes.
///
/// 2. **Orphan occurrence rejection** — submitting an occurrence without its
///    parent finding must fail (at submission or at durable commit). The
///    harness verifies that no partial rows leaked by checking durable counts
///    are unchanged after the expected failure.
///
/// 3. **Orphan observation rejection** — submitting an observation without
///    its parent occurrence must fail and leave no partial rows.
///
/// 4. **Observation upsert merge** — replaying the same observation (same
///    `observation_id`) with a different `seen_at` timestamp must not create
///    a duplicate observation row. The harness writes a full batch, then
///    replays the observation with a later timestamp and verifies durable
///    counts are unchanged.
///
/// Returns the number of checks that passed (currently 4).
///
/// # Errors
///
/// Returns on the first invariant violation or backend error.
pub fn run_findings_conformance<F>(findings: &F) -> Result<u32, PersistenceConformanceError>
where
    F: FindingsSink + FindingsConformanceProbe,
{
    check_findings_idempotent(findings)?;
    check_findings_orphan_occurrence(findings)?;
    check_findings_orphan_observation(findings)?;
    check_findings_observation_merge(findings)?;
    Ok(4)
}

/// Check 1: writing a complete (finding, occurrence, observation) batch twice
/// must add exactly one row per layer on the first write and zero additional
/// rows on the replay. Uses the probe to snapshot durable counts before,
/// between, and after the two writes.
fn check_findings_idempotent<F>(findings: &F) -> Result<(), PersistenceConformanceError>
where
    F: FindingsSink + FindingsConformanceProbe,
{
    let fixture = sample_fixture(0x44)?;
    let before = probe_counts(findings, "findings/idempotent:before")?;
    let batch = fixture.findings_batch();
    let receipt = submit_findings(findings, "findings/idempotent:first", batch)?;
    if receipt.finding_count() != 1
        || receipt.occurrence_count() != 1
        || receipt.observation_count() != 1
    {
        return Err(PersistenceConformanceError::FindingsInvariant {
            case: "findings/idempotent:first",
            message: format!(
                "unexpected receipt counts: findings={}, occurrences={}, observations={}",
                receipt.finding_count(),
                receipt.occurrence_count(),
                receipt.observation_count(),
            ),
        });
    }
    let after_first = probe_counts(findings, "findings/idempotent:after-first")?;
    let delta = after_first.saturating_sub(before);
    if delta
        != (DurableFindingsCounts {
            findings: 1,
            occurrences: 1,
            observations: 1,
        })
    {
        return Err(PersistenceConformanceError::FindingsInvariant {
            case: "findings/idempotent:after-first",
            message: format!("expected durable count delta of (1,1,1), got {:?}", delta),
        });
    }

    let _ = submit_findings(
        findings,
        "findings/idempotent:replay",
        fixture.findings_batch(),
    )?;
    let after_replay = probe_counts(findings, "findings/idempotent:after-replay")?;
    if after_replay != after_first {
        return Err(PersistenceConformanceError::FindingsInvariant {
            case: "findings/idempotent:after-replay",
            message: format!(
                "replaying the same batch changed durable counts: before replay {:?}, after replay {:?}",
                after_first, after_replay
            ),
        });
    }
    Ok(())
}

/// Check 2: submitting an occurrence without its parent finding must fail (at
/// submission or at durable commit). The failure must not leave partial rows
/// behind.
fn check_findings_orphan_occurrence<F>(findings: &F) -> Result<(), PersistenceConformanceError>
where
    F: FindingsSink + FindingsConformanceProbe,
{
    let fixture = sample_fixture(0x55)?;
    let occurrences = [fixture.occurrence.clone()];
    assert_orphan_rejected(
        findings,
        "findings/missing-finding",
        FindingsUpsertBatch::new(&[], &occurrences, &[]),
    )?;
    Ok(())
}

/// Check 3: submitting an observation without its parent occurrence must fail
/// and leave no partial rows. Same principle as orphan occurrence rejection,
/// one level deeper in the hierarchy.
fn check_findings_orphan_observation<F>(findings: &F) -> Result<(), PersistenceConformanceError>
where
    F: FindingsSink + FindingsConformanceProbe,
{
    let fixture = sample_fixture(0x66)?;
    let observations = [fixture.observation.clone()];
    assert_orphan_rejected(
        findings,
        "findings/missing-occurrence",
        FindingsUpsertBatch::new(&[], &[], &observations),
    )?;
    Ok(())
}

/// Check 4: replaying the same observation (same `observation_id`) with a
/// different `seen_at` timestamp must not create a duplicate observation row.
/// The backend must merge (upsert) instead of inserting a duplicate.
fn check_findings_observation_merge<F>(findings: &F) -> Result<(), PersistenceConformanceError>
where
    F: FindingsSink + FindingsConformanceProbe,
{
    let fixture = sample_fixture(0x88)?;
    let batch = fixture.findings_batch();
    let _ = submit_findings(findings, "findings/observation-merge:first", batch)?;
    let after_first = probe_counts(findings, "findings/observation-merge:after-first")?;

    // Construct a second observation with the same identity inputs but a
    // later seen_at timestamp.
    let replayed_observation = ObservationRecord::new(
        fixture.observation.tenant_id(),
        fixture.observation.occurrence_id(),
        fixture.observation.policy_hash(),
        fixture.observation.ovid_hash(),
        fixture.observation.run_id(),
        fixture.observation.shard_id(),
        fixture.observation.fence_epoch(),
        LogicalTime::from_raw(fixture.observation.seen_at().as_raw() + 1000),
    );
    let findings_slice = [fixture.finding.clone()];
    let occurrences_slice = [fixture.occurrence.clone()];
    let observations_slice = [replayed_observation];
    let replay_batch =
        FindingsUpsertBatch::new(&findings_slice, &occurrences_slice, &observations_slice);
    let _ = submit_findings(findings, "findings/observation-merge:replay", replay_batch)?;
    let after_replay = probe_counts(findings, "findings/observation-merge:after-replay")?;

    if after_replay.observations != after_first.observations {
        return Err(PersistenceConformanceError::FindingsInvariant {
            case: "findings/observation-merge:after-replay",
            message: format!(
                "replaying an observation with the same observation_id but different seen_at \
                 created a duplicate row: observations before replay {}, after replay {}",
                after_first.observations, after_replay.observations
            ),
        });
    }
    Ok(())
}

/// Run only the redaction-related portion of the conformance suite.
///
/// Verifies that `Debug` implementations on sensitive persistence types
/// do not leak raw secret bytes as lowercase hex. This is a defense-in-depth
/// check: secret-derived types should use redacted or truncated debug output
/// so that structured logging and error messages do not accidentally expose
/// key material.
///
/// Checks three types:
/// 1. `NormHash` — the normalized secret hash.
/// 2. `SecretHash` — the keyed, tenant-scoped secret hash.
/// 3. `FindingRecord` — the aggregate record containing a `SecretHash` field.
///
/// Does not require a backend instance (pure in-memory checks).
///
/// Returns the number of checks that passed (currently 3).
pub fn run_redaction_conformance() -> Result<u32, PersistenceConformanceError> {
    let mut checks = 0u32;
    let fixture = sample_fixture(0x77)?;
    let norm = NormHash::from_digest([0xE7; 32]);
    let norm_debug = format!("{norm:?}");
    assert_no_raw_encoding("redaction/norm-hash-debug", &norm_debug, norm.as_bytes())?;
    checks += 1;

    let secret_hash = fixture.finding.secret_hash();
    let secret_debug = format!("{secret_hash:?}");
    assert_no_raw_encoding(
        "redaction/secret-hash-debug",
        &secret_debug,
        secret_hash.as_bytes(),
    )?;
    checks += 1;

    let finding_debug = format!("{:?}", fixture.finding);
    assert_no_raw_encoding(
        "redaction/finding-record-debug",
        &finding_debug,
        secret_hash.as_bytes(),
    )?;
    checks += 1;

    Ok(checks)
}

/// Submit a done-ledger batch and wait for durable acknowledgement.
///
/// Wraps the two-phase `batch_upsert` → `handle.wait()` flow, mapping both
/// submission and durability errors into [`PersistenceConformanceError`] with
/// the provided `case` label for diagnostics.
fn submit_done_ledger<L>(
    done_ledger: &L,
    case: &'static str,
    records: &[DoneLedgerRecord],
) -> Result<DoneLedgerCommitReceipt, PersistenceConformanceError>
where
    L: DoneLedger,
{
    let handle = done_ledger.batch_upsert(records).map_err(|err| {
        PersistenceConformanceError::DoneLedgerSubmit {
            case,
            source: Box::new(err),
        }
    })?;
    handle
        .wait()
        .map_err(|err| PersistenceConformanceError::DoneLedgerWait {
            case,
            source: Box::new(err),
        })
}

/// Fetch a single done-ledger record by the fixture's natural key.
///
/// Uses `batch_get` with a single-element hash slice and expects exactly one
/// `Some` result. Returns an invariant error if the record is missing or the
/// result vector has an unexpected length.
fn get_single_done_ledger<L>(
    done_ledger: &L,
    case: &'static str,
    fixture: &SampleFixture,
) -> Result<DoneLedgerRecord, PersistenceConformanceError>
where
    L: DoneLedger,
{
    let rows = done_ledger
        .batch_get(fixture.tenant_id, fixture.policy_hash, &[fixture.ovid_hash])
        .map_err(|err| PersistenceConformanceError::DoneLedgerGet {
            case,
            source: Box::new(err),
        })?;

    match rows.as_slice() {
        [Some(record)] => Ok(record.clone()),
        [None] => Err(PersistenceConformanceError::DoneLedgerInvariant {
            case,
            message: "expected durable record, got None".to_owned(),
        }),
        _ => Err(PersistenceConformanceError::DoneLedgerInvariant {
            case,
            message: format!("expected one result row, got {}", rows.len()),
        }),
    }
}

/// Assert that the durable record reflects scanned-state dominance.
///
/// After writing both a failed and a scanned record for the same key (in
/// either order), the durable state must satisfy all of:
///
/// 1. The key is unchanged.
/// 2. The status is a scanned variant (the lattice join of failed ∨ scanned).
/// 3. `bytes_scanned` has not regressed below the max of both inputs.
/// 4. `findings_count` respects the SwF-aware merge rule: only
///    `ScannedWithFindings` contributors supply findings; `ScannedClean`
///    forces the count to 0.
/// 5. The status rank is at least as high as the scanned record's rank.
///
/// These checks collectively verify the join-semilattice merge contract
/// that backends must implement during upsert.
fn assert_scanned_dominates(
    case: &'static str,
    failed: &DoneLedgerRecord,
    scanned: &DoneLedgerRecord,
    actual: &DoneLedgerRecord,
) -> Result<(), PersistenceConformanceError> {
    if actual.key() != scanned.key() {
        return Err(PersistenceConformanceError::DoneLedgerInvariant {
            case,
            message: format!(
                "durable key changed unexpectedly: expected {:?}, got {:?}",
                scanned.key(),
                actual.key()
            ),
        });
    }
    if !actual.status().is_scanned() {
        return Err(PersistenceConformanceError::DoneLedgerInvariant {
            case,
            message: format!(
                "expected a scanned status to dominate failure, got {:?}",
                actual.status()
            ),
        });
    }
    if actual.bytes_scanned() < failed.bytes_scanned().max(scanned.bytes_scanned()) {
        return Err(PersistenceConformanceError::DoneLedgerInvariant {
            case,
            message: format!(
                "bytes_scanned regressed: got {}, expected at least {}",
                actual.bytes_scanned(),
                failed.bytes_scanned().max(scanned.bytes_scanned())
            ),
        });
    }
    let expected_min_findings = match actual.status() {
        DoneLedgerStatus::ScannedClean => 0,
        DoneLedgerStatus::ScannedWithFindings => {
            let failed_swf = if failed.status() == DoneLedgerStatus::ScannedWithFindings {
                failed.findings_count()
            } else {
                0
            };
            let scanned_swf = if scanned.status() == DoneLedgerStatus::ScannedWithFindings {
                scanned.findings_count()
            } else {
                0
            };
            failed_swf.max(scanned_swf).max(1)
        }
        _ => failed.findings_count().max(scanned.findings_count()),
    };
    if actual.findings_count() < expected_min_findings {
        return Err(PersistenceConformanceError::DoneLedgerInvariant {
            case,
            message: format!(
                "findings_count regressed: got {}, expected at least {}",
                actual.findings_count(),
                expected_min_findings
            ),
        });
    }
    if actual.status().rank() < scanned.status().rank() {
        return Err(PersistenceConformanceError::DoneLedgerInvariant {
            case,
            message: format!(
                "dominant scanned status rank regressed: got {}, expected at least {}",
                actual.status().rank(),
                scanned.status().rank()
            ),
        });
    }
    Ok(())
}

/// Submit a findings batch and wait for durable acknowledgement.
///
/// Mirrors [`submit_done_ledger`] for the findings layer: wraps
/// `upsert_batch` → `handle.wait()` with error mapping.
fn submit_findings<F>(
    findings: &F,
    case: &'static str,
    batch: FindingsUpsertBatch<'_>,
) -> Result<FindingsCommitReceipt, PersistenceConformanceError>
where
    F: FindingsSink,
{
    let handle = findings.upsert_batch(batch).map_err(|err| {
        PersistenceConformanceError::FindingsSubmit {
            case,
            source: Box::new(err),
        }
    })?;
    handle
        .wait()
        .map_err(|err| PersistenceConformanceError::FindingsWait {
            case,
            source: Box::new(err),
        })
}

/// Submit a findings batch and assert that it fails.
///
/// The failure may occur at either phase: submission (`upsert_batch` returns
/// `Err`) or durability (`handle.wait()` returns `Err`). Both are acceptable.
/// The harness only reports an invariant violation if the write durably
/// succeeds — that means the backend accepted an invalid batch.
fn expect_findings_failure<F>(
    findings: &F,
    case: &'static str,
    batch: FindingsUpsertBatch<'_>,
) -> Result<(), PersistenceConformanceError>
where
    F: FindingsSink,
{
    match findings.upsert_batch(batch) {
        Err(_submit_err) => Ok(()),
        Ok(handle) => match handle.wait() {
            Err(_wait_err) => Ok(()),
            Ok(receipt) => Err(PersistenceConformanceError::FindingsInvariant {
                case,
                message: format!(
                    "expected write failure, but it durably succeeded with receipt {:?}",
                    receipt
                ),
            }),
        },
    }
}

/// Submit an orphan batch and assert it is rejected without side effects.
///
/// Snapshots durable counts before and after the expected failure and asserts
/// they are identical — proving the rejected write left no partial rows.
fn assert_orphan_rejected<F>(
    findings: &F,
    case: &'static str,
    batch: FindingsUpsertBatch<'_>,
) -> Result<(), PersistenceConformanceError>
where
    F: FindingsSink + FindingsConformanceProbe,
{
    let before = probe_counts(findings, case)?;
    expect_findings_failure(findings, case, batch)?;
    let after = probe_counts(findings, case)?;
    if after != before {
        return Err(PersistenceConformanceError::FindingsInvariant {
            case,
            message: format!(
                "failed write changed durable counts: before {:?}, after {:?}",
                before, after
            ),
        });
    }
    Ok(())
}

/// Snapshot the current durable findings counts via the test probe.
fn probe_counts<F>(
    findings: &F,
    case: &'static str,
) -> Result<DurableFindingsCounts, PersistenceConformanceError>
where
    F: FindingsConformanceProbe,
{
    findings
        .durable_counts()
        .map_err(|err| PersistenceConformanceError::Probe {
            case,
            source: Box::new(err),
        })
}

/// Assert that `debug_output` does not contain common encodings of
/// `raw_bytes` (hex or base64).
///
/// Three checks are performed:
///
/// 1. **Full-length hex** — the complete lowercase hex encoding of the byte
///    sequence (case-insensitive comparison).
/// 2. **Prefix hex** — the first 8 bytes (16 hex chars). This catches the
///    `define_id_32!` 4-byte Debug format (`TypeName(e7e7e7e7..)`) with
///    margin, guarding against accidental use of an unrestricted macro on a
///    sensitive type.
/// 3. **Base64** — standard base64 encoding of the full byte sequence.
///
/// Partial-leak detection is left to manual review.
fn assert_no_raw_encoding(
    case: &'static str,
    debug_output: &str,
    raw_bytes: &[u8],
) -> Result<(), PersistenceConformanceError> {
    let lowered = debug_output.to_ascii_lowercase();

    // Full-length check.
    let full_hex = hex_lower(raw_bytes);
    if lowered.contains(&full_hex) {
        return Err(PersistenceConformanceError::RedactionLeak {
            case,
            debug_output: debug_output.to_owned(),
            leaked_fragment: full_hex,
        });
    }

    // Prefix check: catches define_id_32! 4-byte Debug format.
    const PREFIX_BYTES: usize = 8;
    if raw_bytes.len() >= PREFIX_BYTES {
        let prefix_hex = hex_lower(&raw_bytes[..PREFIX_BYTES]);
        if lowered.contains(&prefix_hex) {
            return Err(PersistenceConformanceError::RedactionLeak {
                case,
                debug_output: debug_output.to_owned(),
                leaked_fragment: prefix_hex,
            });
        }
    }

    // Also check standard base64 encoding.
    let base64_fragment = base64_encode(raw_bytes);
    if base64_fragment.len() >= 4 && debug_output.contains(&base64_fragment) {
        return Err(PersistenceConformanceError::RedactionLeak {
            case,
            debug_output: debug_output.to_owned(),
            leaked_fragment: base64_fragment,
        });
    }

    Ok(())
}

/// Encode `bytes` as a lowercase hex string without allocating a dependency on
/// the `hex` crate.
fn hex_lower(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(LUT[(byte >> 4) as usize] as char);
        out.push(LUT[(byte & 0x0F) as usize] as char);
    }
    out
}

/// Encode bytes as standard base64 (RFC 4648) without padding.
/// Hand-rolled to avoid adding a crate dependency for a test-only helper.
fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((triple >> 18) & 0x3F) as usize] as char);
        out.push(ALPHABET[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[((triple >> 6) & 0x3F) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(triple & 0x3F) as usize] as char);
        }
    }
    out
}

/// Self-contained test fixture holding all record types needed by the harness.
///
/// Each fixture is deterministically derived from a single `seed` byte via
/// [`sample_fixture`]. Different seeds produce disjoint identity keys, so
/// multiple fixtures can coexist in the same backend without collision.
///
/// The fixture includes both a `scanned_record` and a `failed_record` sharing
/// the same [`DoneLedgerKey`], which is what lets the dominance checks test
/// the status lattice merge.
#[derive(Clone, Debug)]
struct SampleFixture {
    /// Tenant scoping identity for the test fixture.
    tenant_id: TenantId,
    /// Policy scope identity for the test fixture.
    policy_hash: PolicyHash,
    /// Object version identity for the test fixture.
    ovid_hash: OvidHash,
    /// Layer 1 — stable finding identity.
    finding: FindingRecord,
    /// Layer 2 — version-specific occurrence.
    occurrence: OccurrenceRecord,
    /// Layer 3 — policy- and run-scoped observation.
    observation: ObservationRecord,
    /// Done-ledger record with `ScannedWithFindings` status.
    scanned_record: DoneLedgerRecord,
    /// Done-ledger record with `FailedRetryable` status (same key as `scanned_record`).
    failed_record: DoneLedgerRecord,
}

impl SampleFixture {
    /// Build a single-element [`FindingsUpsertBatch`] containing the fixture's
    /// finding, occurrence, and observation — a complete referential closure.
    fn findings_batch(&self) -> FindingsUpsertBatch<'_> {
        FindingsUpsertBatch::new(
            std::slice::from_ref(&self.finding),
            std::slice::from_ref(&self.occurrence),
            std::slice::from_ref(&self.observation),
        )
    }
}

/// Build a deterministic test fixture from a single seed byte.
///
/// Each identity field is derived from `fill32(seed + offset)` with a unique
/// offset, so different seeds produce non-overlapping key material. The seed
/// also flows into provenance fields (run, shard, epoch, logical time) to
/// keep fixtures fully distinguishable under inspection.
///
/// The `failed_record` intentionally uses a **larger** `bytes_scanned` (4096)
/// than the `scanned_record` (2048). This is realistic — a failure during a
/// large-file scan followed by a successful scan of a smaller file — and
/// ensures the conformance harness's per-field max check in
/// [`assert_scanned_dominates`] is non-vacuous: a backend that simply returns
/// the dominant record wholesale (instead of computing per-field max) will
/// fail the check.
fn sample_fixture(seed: u8) -> Result<SampleFixture, PersistenceConformanceError> {
    debug_assert!(
        seed <= 0xF9,
        "seed too high; wrapping_add offsets would collide"
    );

    let tenant_id = TenantId::from_bytes(fill32(seed));
    let policy_hash = PolicyHash::from_bytes(fill32(seed.wrapping_add(1)));
    let stable_item_id = StableItemId::from_bytes(fill32(seed.wrapping_add(2)));
    let rule_fingerprint = RuleFingerprint::from_bytes(fill32(seed.wrapping_add(3)));
    let tenant_key = TenantSecretKey::from_bytes(fill32(seed.wrapping_add(4)));
    let norm_hash = NormHash::from_digest(fill32(seed.wrapping_add(5)));
    let secret_hash = key_secret_hash(&tenant_key, &norm_hash);

    let finding = FindingRecord::new(tenant_id, stable_item_id, rule_fingerprint, secret_hash);

    let object_version_id =
        ObjectVersionId::from_version_bytes(format!("conformance-version-{seed}").as_bytes());
    let occurrence = OccurrenceRecord::try_new(
        tenant_id,
        finding.finding_id(),
        object_version_id,
        100 + u64::from(seed),
        32,
    )
    .map_err(|err| PersistenceConformanceError::FixtureConstruction {
        case: "sample-fixture/occurrence",
        source: Box::new(err),
    })?;

    let ovid_hash = derive_ovid_hash(&OvidHashInputs {
        stable_item_id,
        version: VersionId::Strong(object_version_id),
    });

    let location = Location::try_new(
        format!("safe/path/conformance-{seed}.txt"),
        Some(format!("https://example.invalid/conformance/{seed}")),
    )
    .map_err(|err| PersistenceConformanceError::FixtureConstruction {
        case: "sample-fixture/location",
        source: Box::new(err),
    })?;

    let observation = ObservationRecord::new(
        tenant_id,
        occurrence.occurrence_id(),
        policy_hash,
        ovid_hash,
        RunId::from_raw(10_000 + u64::from(seed)),
        ShardId::from_raw(20_000 + u64::from(seed)),
        FenceEpoch::from_raw(30_000 + u64::from(seed)),
        LogicalTime::from_raw(40_000 + u64::from(seed)),
    )
    .with_location(Arc::new(location));

    let key = DoneLedgerKey::new(tenant_id, policy_hash, ovid_hash);
    let failed_record = DoneLedgerRecord::try_new(
        key,
        DoneLedgerStatus::FailedRetryable,
        4_096,
        1,
        DoneLedgerProvenance::new(
            RunId::from_raw(50_000 + u64::from(seed)),
            ShardId::from_raw(60_000 + u64::from(seed)),
            FenceEpoch::from_raw(70_000 + u64::from(seed)),
            LogicalTime::from_raw(80_000 + u64::from(seed)),
            LogicalTime::from_raw(80_010 + u64::from(seed)),
        ),
        Some(DoneLedgerErrorCode::try_new("TIMEOUT").map_err(|err| {
            PersistenceConformanceError::FixtureConstruction {
                case: "sample-fixture/error-code",
                source: Box::new(err),
            }
        })?),
    )
    .map_err(|err| PersistenceConformanceError::FixtureConstruction {
        case: "sample-fixture/failed-record",
        source: Box::new(err),
    })?;
    let scanned_record = DoneLedgerRecord::try_new(
        key,
        DoneLedgerStatus::ScannedWithFindings,
        2_048,
        1,
        DoneLedgerProvenance::new(
            RunId::from_raw(50_100 + u64::from(seed)),
            ShardId::from_raw(60_100 + u64::from(seed)),
            FenceEpoch::from_raw(70_100 + u64::from(seed)),
            LogicalTime::from_raw(80_100 + u64::from(seed)),
            LogicalTime::from_raw(80_110 + u64::from(seed)),
        ),
        None,
    )
    .map_err(|err| PersistenceConformanceError::FixtureConstruction {
        case: "sample-fixture/scanned-record",
        source: Box::new(err),
    })?;

    Ok(SampleFixture {
        tenant_id,
        policy_hash,
        ovid_hash,
        finding,
        occurrence,
        observation,
        scanned_record,
        failed_record,
    })
}

/// Produce a 32-byte array filled with `byte`. Used to construct identity
/// newtypes from deterministic, distinguishable key material.
#[inline]
fn fill32(byte: u8) -> [u8; 32] {
    [byte; 32]
}
