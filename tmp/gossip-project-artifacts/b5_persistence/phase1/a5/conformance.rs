//! Backend-agnostic persistence conformance harness.
//!
//! This module provides a reusable test harness that every `DoneLedger` and
//! `FindingsSink` backend must pass. The harness is intentionally strict about
//! the invariants it can actually observe through the current persistence API:
//!
//! - done-ledger upserts are idempotent
//! - scanned states dominate failed states under out-of-order writes
//! - findings-layer writes are replay-safe under retry
//! - occurrence / observation referential integrity failures do not leave
//!   partial durable rows behind
//! - `Debug` for sensitive persistence types does not leak raw secret bytes
//!
//! ## Why a probe trait exists
//!
//! The write-side `FindingsSink` API is intentionally narrow. That is correct
//! for production, but it means pure write-only testing cannot *observe* whether
//! replay created duplicate durable rows. A backend could accept the same batch
//! twice and silently duplicate storage while still returning `Ok(())` both
//! times.
//!
//! To make idempotency testable, the harness uses a small test-only read-side
//! probe: [`FindingsConformanceProbe`]. Production code does not depend on this
//! trait; backend test suites implement it in their test harnesses.

use std::{
    error::Error,
    fmt,
};

use super::{
    derive_ovid_hash, CommitHandle, DoneLedger, DoneLedgerErrorCode, DoneLedgerProvenance,
    DoneLedgerRecord, DoneLedgerStatus, FindingRecord, FindingsSink, FindingsUpsertBatch,
    ObservationRecord, OccurrenceRecord, OvidHash, OvidHashInputs,
};
use crate::{
    connector::{Location, VersionId},
    identity::{
        derive_finding_id, derive_occurrence_id, key_secret_hash, FindingIdInputs, FenceEpoch,
        LogicalTime, NormHash, ObjectVersionId, OccurrenceIdInputs, PolicyHash,
        RuleFingerprint, RunId, ShardId, StableItemId, TenantId, TenantSecretKey,
    },
};

type BoxError = Box<dyn Error + Send + Sync + 'static>;

/// Durable row counts observed through the findings-layer test probe.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DurableFindingsCounts {
    findings: u64,
    occurrences: u64,
    observations: u64,
}

impl DurableFindingsCounts {
    /// Construct count totals.
    #[inline]
    #[must_use]
    pub const fn new(findings: u64, occurrences: u64, observations: u64) -> Self {
        Self {
            findings,
            occurrences,
            observations,
        }
    }

    #[inline]
    #[must_use]
    pub const fn findings(self) -> u64 {
        self.findings
    }

    #[inline]
    #[must_use]
    pub const fn occurrences(self) -> u64 {
        self.occurrences
    }

    #[inline]
    #[must_use]
    pub const fn observations(self) -> u64 {
        self.observations
    }

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

/// Test-only probe used by the conformance harness to observe durable findings
/// counts after replay and failed writes.
///
/// This stays out of the production write path. Backend crates typically
/// implement it in integration tests or on in-memory test doubles.
pub trait FindingsConformanceProbe: Send + Sync {
    /// Backend-specific probe error.
    type Error: Error + Send + Sync + 'static;

    /// Return durable row counts currently visible through the backend.
    fn durable_counts(&self) -> Result<DurableFindingsCounts, Self::Error>;
}

/// Aggregate report returned by [`run_conformance`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PersistenceConformanceReport {
    done_ledger_checks: u32,
    findings_checks: u32,
    redaction_checks: u32,
}

impl PersistenceConformanceReport {
    #[inline]
    #[must_use]
    pub const fn new(done_ledger_checks: u32, findings_checks: u32, redaction_checks: u32) -> Self {
        Self {
            done_ledger_checks,
            findings_checks,
            redaction_checks,
        }
    }

    #[inline]
    #[must_use]
    pub const fn done_ledger_checks(self) -> u32 {
        self.done_ledger_checks
    }

    #[inline]
    #[must_use]
    pub const fn findings_checks(self) -> u32 {
        self.findings_checks
    }

    #[inline]
    #[must_use]
    pub const fn redaction_checks(self) -> u32 {
        self.redaction_checks
    }
}

/// Failure reported by the persistence conformance harness.
#[derive(Debug)]
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
    DoneLedgerInvariant {
        case: &'static str,
        message: String,
    },
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
    FindingsInvariant {
        case: &'static str,
        message: String,
    },
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
                debug_output,
                leaked_fragment,
            } => write!(
                f,
                "sensitive Debug output leaked raw bytes in {case}: leaked fragment `{leaked_fragment}` in `{debug_output}`"
            ),
        }
    }
}

impl Error for PersistenceConformanceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::FixtureConstruction { source, .. }
            | Self::DoneLedgerSubmit { source, .. }
            | Self::DoneLedgerWait { source, .. }
            | Self::DoneLedgerGet { source, .. }
            | Self::FindingsSubmit { source, .. }
            | Self::FindingsWait { source, .. }
            | Self::Probe { source, .. } => Some(source.as_ref()),
            Self::DoneLedgerInvariant { .. }
            | Self::FindingsInvariant { .. }
            | Self::RedactionLeak { .. } => None,
        }
    }
}

/// Run the full persistence conformance suite against one done-ledger backend
/// and one findings backend.
///
/// The findings backend must also provide [`FindingsConformanceProbe`] so the
/// harness can observe durable row counts and prove replay does not duplicate
/// rows.
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
    Ok(PersistenceConformanceReport::new(
        done_ledger_checks,
        findings_checks,
        redaction_checks,
    ))
}

/// Run only the done-ledger portion of the conformance suite.
pub fn run_done_ledger_conformance<L>(
    done_ledger: &L,
) -> Result<u32, PersistenceConformanceError>
where
    L: DoneLedger,
{
    let mut checks = 0u32;

    // Case 1: idempotent upsert of the same key/record.
    let fixture = sample_fixture(0x11)?;
    let receipt = submit_done_ledger(done_ledger, "done-ledger/idempotent:first", &[fixture.scanned_record.clone()])?;
    if receipt.record_count() != 1 || receipt.scanned_count() != 1 {
        return Err(PersistenceConformanceError::DoneLedgerInvariant {
            case: "done-ledger/idempotent:first",
            message: format!(
                "unexpected receipt counts: record_count={}, scanned_count={}",
                receipt.record_count(),
                receipt.scanned_count()
            ),
        });
    }
    let _ = submit_done_ledger(done_ledger, "done-ledger/idempotent:second", &[fixture.scanned_record.clone()])?;
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
    checks += 1;

    // Case 2: failed then scanned converges to scanned.
    let fixture = sample_fixture(0x22)?;
    let _ = submit_done_ledger(done_ledger, "done-ledger/fail-then-scan:failed", &[fixture.failed_record.clone()])?;
    let _ = submit_done_ledger(done_ledger, "done-ledger/fail-then-scan:scanned", &[fixture.scanned_record.clone()])?;
    let fetched = get_single_done_ledger(done_ledger, "done-ledger/fail-then-scan:fetch", &fixture)?;
    assert_scanned_dominates(
        "done-ledger/fail-then-scan:fetch",
        &fixture.failed_record,
        &fixture.scanned_record,
        &fetched,
    )?;
    checks += 1;

    // Case 3: scanned then failed still converges to scanned.
    let fixture = sample_fixture(0x33)?;
    let _ = submit_done_ledger(done_ledger, "done-ledger/scan-then-fail:scanned", &[fixture.scanned_record.clone()])?;
    let _ = submit_done_ledger(done_ledger, "done-ledger/scan-then-fail:failed", &[fixture.failed_record.clone()])?;
    let fetched = get_single_done_ledger(done_ledger, "done-ledger/scan-then-fail:fetch", &fixture)?;
    assert_scanned_dominates(
        "done-ledger/scan-then-fail:fetch",
        &fixture.failed_record,
        &fixture.scanned_record,
        &fetched,
    )?;
    checks += 1;

    Ok(checks)
}

/// Run only the findings-layer portion of the conformance suite.
pub fn run_findings_conformance<F>(
    findings: &F,
) -> Result<u32, PersistenceConformanceError>
where
    F: FindingsSink + FindingsConformanceProbe,
{
    let mut checks = 0u32;

    // Case 1: valid insert followed by exact replay does not duplicate durable rows.
    let fixture = sample_fixture(0x44)?;
    let before = probe_counts(findings, "findings/idempotent:before")?;
    let batch = fixture.findings_batch();
    let receipt = submit_findings(findings, "findings/idempotent:first", batch)?;
    if receipt.finding_count() != 1 || receipt.occurrence_count() != 1 || receipt.observation_count() != 1 {
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
    if delta != DurableFindingsCounts::new(1, 1, 1) {
        return Err(PersistenceConformanceError::FindingsInvariant {
            case: "findings/idempotent:after-first",
            message: format!(
                "expected durable count delta of (1,1,1), got {:?}",
                delta
            ),
        });
    }

    let _ = submit_findings(findings, "findings/idempotent:replay", fixture.findings_batch())?;
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
    checks += 1;

    // Case 2: occurrence referencing a missing finding must fail without side effects.
    let fixture = sample_fixture(0x55)?;
    let before = probe_counts(findings, "findings/missing-finding:before")?;
    let occurrences = [fixture.occurrence.clone()];
    expect_findings_failure(
        findings,
        "findings/missing-finding",
        FindingsUpsertBatch::new(&[], &occurrences, &[]),
    )?;
    let after = probe_counts(findings, "findings/missing-finding:after")?;
    if after != before {
        return Err(PersistenceConformanceError::FindingsInvariant {
            case: "findings/missing-finding:after",
            message: format!(
                "failed write changed durable counts: before {:?}, after {:?}",
                before, after
            ),
        });
    }
    checks += 1;

    // Case 3: observation referencing a missing occurrence must fail without side effects.
    let fixture = sample_fixture(0x66)?;
    let before = probe_counts(findings, "findings/missing-occurrence:before")?;
    let observations = [fixture.observation.clone()];
    expect_findings_failure(
        findings,
        "findings/missing-occurrence",
        FindingsUpsertBatch::new(&[], &[], &observations),
    )?;
    let after = probe_counts(findings, "findings/missing-occurrence:after")?;
    if after != before {
        return Err(PersistenceConformanceError::FindingsInvariant {
            case: "findings/missing-occurrence:after",
            message: format!(
                "failed write changed durable counts: before {:?}, after {:?}",
                before, after
            ),
        });
    }
    checks += 1;

    Ok(checks)
}

/// Run only the redaction-related portion of the conformance suite.
pub fn run_redaction_conformance() -> Result<u32, PersistenceConformanceError> {
    let fixture = sample_fixture(0x77)?;
    let norm = NormHash::from_digest([0xE7; 32]);
    let norm_debug = format!("{:?}", norm);
    assert_no_raw_hex(
        "redaction/norm-hash-debug",
        &norm_debug,
        norm.as_bytes(),
    )?;

    let secret_hash = fixture.finding.secret_hash();
    let secret_debug = format!("{:?}", secret_hash);
    assert_no_raw_hex(
        "redaction/secret-hash-debug",
        &secret_debug,
        secret_hash.as_bytes(),
    )?;

    let finding_debug = format!("{:?}", fixture.finding);
    assert_no_raw_hex(
        "redaction/finding-record-debug",
        &finding_debug,
        secret_hash.as_bytes(),
    )?;

    Ok(3)
}

fn submit_done_ledger<L>(
    done_ledger: &L,
    case: &'static str,
    records: &[DoneLedgerRecord],
) -> Result<super::DoneLedgerCommitReceipt, PersistenceConformanceError>
where
    L: DoneLedger,
{
    let handle = done_ledger
        .batch_upsert(records)
        .map_err(|err| PersistenceConformanceError::DoneLedgerSubmit {
            case,
            source: Box::new(err),
        })?;
    handle
        .wait()
        .map_err(|err| PersistenceConformanceError::DoneLedgerWait {
            case,
            source: Box::new(err),
        })
}

fn get_single_done_ledger<L>(
    done_ledger: &L,
    case: &'static str,
    fixture: &SampleFixture,
) -> Result<DoneLedgerRecord, PersistenceConformanceError>
where
    L: DoneLedger,
{
    let rows = done_ledger
        .batch_get(
            fixture.tenant_id,
            fixture.policy_hash,
            &[fixture.ovid_hash],
        )
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
    if actual.findings_count() < failed.findings_count().max(scanned.findings_count()) {
        return Err(PersistenceConformanceError::DoneLedgerInvariant {
            case,
            message: format!(
                "findings_count regressed: got {}, expected at least {}",
                actual.findings_count(),
                failed.findings_count().max(scanned.findings_count())
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

fn submit_findings<F>(
    findings: &F,
    case: &'static str,
    batch: FindingsUpsertBatch<'_>,
) -> Result<super::FindingsCommitReceipt, PersistenceConformanceError>
where
    F: FindingsSink,
{
    let handle = findings
        .upsert_batch(batch)
        .map_err(|err| PersistenceConformanceError::FindingsSubmit {
            case,
            source: Box::new(err),
        })?;
    handle
        .wait()
        .map_err(|err| PersistenceConformanceError::FindingsWait {
            case,
            source: Box::new(err),
        })
}

fn expect_findings_failure<F>(
    findings: &F,
    case: &'static str,
    batch: FindingsUpsertBatch<'_>,
) -> Result<(), PersistenceConformanceError>
where
    F: FindingsSink,
{
    match findings.upsert_batch(batch) {
        Err(_) => Ok(()),
        Ok(handle) => match handle.wait() {
            Err(_) => Ok(()),
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

fn assert_no_raw_hex(
    case: &'static str,
    debug_output: &str,
    raw_bytes: &[u8],
) -> Result<(), PersistenceConformanceError> {
    let leaked_fragment = hex_lower(raw_bytes);
    if debug_output.to_ascii_lowercase().contains(&leaked_fragment) {
        return Err(PersistenceConformanceError::RedactionLeak {
            case,
            debug_output: debug_output.to_owned(),
            leaked_fragment,
        });
    }
    Ok(())
}

fn hex_lower(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(LUT[(byte >> 4) as usize] as char);
        out.push(LUT[(byte & 0x0F) as usize] as char);
    }
    out
}

#[derive(Clone, Debug)]
struct SampleFixture {
    tenant_id: TenantId,
    policy_hash: PolicyHash,
    ovid_hash: OvidHash,
    finding: FindingRecord,
    occurrence: OccurrenceRecord,
    observation: ObservationRecord,
    scanned_record: DoneLedgerRecord,
    failed_record: DoneLedgerRecord,
}

impl SampleFixture {
    fn findings_batch(&self) -> FindingsUpsertBatch<'_> {
        FindingsUpsertBatch::new(
            std::slice::from_ref(&self.finding),
            std::slice::from_ref(&self.occurrence),
            std::slice::from_ref(&self.observation),
        )
    }
}

fn sample_fixture(seed: u8) -> Result<SampleFixture, PersistenceConformanceError> {
    let tenant_id = TenantId::from_bytes(fill32(seed));
    let policy_hash = PolicyHash::from_bytes(fill32(seed.wrapping_add(1)));
    let stable_item_id = StableItemId::from_bytes(fill32(seed.wrapping_add(2)));
    let rule_fingerprint = RuleFingerprint::from_bytes(fill32(seed.wrapping_add(3)));
    let tenant_key = TenantSecretKey::from_bytes(fill32(seed.wrapping_add(4)));
    let norm_hash = NormHash::from_digest(fill32(seed.wrapping_add(5)));
    let secret_hash = key_secret_hash(&tenant_key, &norm_hash);

    let finding_id = derive_finding_id(&FindingIdInputs {
        tenant: tenant_id,
        item: stable_item_id,
        rule: rule_fingerprint,
        secret: secret_hash,
    });

    let object_version_id = ObjectVersionId::from_version_bytes(format!("conformance-version-{seed}").as_bytes());
    let occurrence_id = derive_occurrence_id(&OccurrenceIdInputs {
        finding: finding_id,
        version: object_version_id,
        byte_offset: 100 + seed as u64,
        byte_length: 32,
    });

    let ovid_hash = derive_ovid_hash(&OvidHashInputs::new(
        stable_item_id,
        VersionId::Strong(object_version_id),
    ));

    let finding = FindingRecord::new(
        tenant_id,
        finding_id,
        stable_item_id,
        rule_fingerprint,
        secret_hash,
    );

    let occurrence = OccurrenceRecord::try_new(
        tenant_id,
        occurrence_id,
        finding_id,
        object_version_id,
        100 + seed as u64,
        32,
    )
    .map_err(|err| PersistenceConformanceError::FixtureConstruction {
        case: "sample-fixture/occurrence",
        source: Box::new(err),
    })?;

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
        occurrence_id,
        policy_hash,
        ovid_hash,
        RunId::from_raw(10_000 + seed as u64),
        ShardId::from_raw(20_000 + seed as u64),
        FenceEpoch::from_raw(30_000 + seed as u64),
        LogicalTime::from_raw(40_000 + seed as u64),
    )
    .with_location(location);

    let key = super::DoneLedgerKey::new(tenant_id, policy_hash, ovid_hash);
    let failed_record = DoneLedgerRecord::new(
        key,
        DoneLedgerStatus::FailedRetryable,
        2_048,
        1,
        DoneLedgerProvenance::new(
            RunId::from_raw(50_000 + seed as u64),
            ShardId::from_raw(60_000 + seed as u64),
            FenceEpoch::from_raw(70_000 + seed as u64),
            LogicalTime::from_raw(80_000 + seed as u64),
            LogicalTime::from_raw(80_010 + seed as u64),
        ),
        Some(
            DoneLedgerErrorCode::try_new("TIMEOUT").map_err(|err| {
                PersistenceConformanceError::FixtureConstruction {
                    case: "sample-fixture/error-code",
                    source: Box::new(err),
                }
            })?,
        ),
    );
    let scanned_record = DoneLedgerRecord::new(
        key,
        DoneLedgerStatus::ScannedWithFindings,
        4_096,
        1,
        DoneLedgerProvenance::new(
            RunId::from_raw(50_100 + seed as u64),
            ShardId::from_raw(60_100 + seed as u64),
            FenceEpoch::from_raw(70_100 + seed as u64),
            LogicalTime::from_raw(80_100 + seed as u64),
            LogicalTime::from_raw(80_110 + seed as u64),
        ),
        None,
    );

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

#[inline]
fn fill32(byte: u8) -> [u8; 32] {
    [byte; 32]
}
