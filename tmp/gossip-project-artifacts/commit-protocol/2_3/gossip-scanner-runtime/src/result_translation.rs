//! Deterministic translation from runtime scan results into persistence rows.
//!
//! Epic 2.3 freezes the logic that turns one completed item scan into the
//! durable records that later runtime stages will commit:
//!
//! - [`FindingRecord`](gossip_contracts::persistence::FindingRecord)
//! - [`OccurrenceRecord`](gossip_contracts::persistence::OccurrenceRecord)
//! - [`ObservationRecord`](gossip_contracts::persistence::ObservationRecord)
//! - [`DoneLedgerRecord`](gossip_contracts::persistence::DoneLedgerRecord)
//!
//! The translation is intentionally runtime-local and deterministic. Given the
//! same [`ScanItem`], the same policy/write scope, the same tenant secret key,
//! and the same finding spans + normalized hashes, it will always derive the
//! same persistence identities in the same order.
//!
//! ## Ordering and dedupe semantics
//!
//! - Input finding order is preserved.
//! - Stable findings are de-duplicated by `FindingId`.
//! - Occurrences are de-duplicated by `OccurrenceId`.
//! - Observations are de-duplicated by `ObservationId`.
//! - The done-ledger `findings_count` is the number of distinct stable
//!   findings for the item version, not the number of raw engine emissions.
//!
//! ## Span semantics
//!
//! [`FsFindingRecord::span_start`] / [`FsFindingRecord::span_end`] are the
//! version-specific occurrence span. Root-hint fields are dedupe aids for the
//! scanner pipeline and do not enter persistence identity derivation.

use std::{collections::HashSet, error::Error, fmt};

use gossip_contracts::{
    connector::ScanItem,
    identity::{
        LogicalTime, NormHash, RuleFingerprint, TenantSecretKey, key_secret_hash,
    },
    persistence::{
        DoneLedgerErrorCode, DoneLedgerKey, DoneLedgerProvenance, DoneLedgerRecord,
        DoneLedgerStatus, FindingRecord, FindingsUpsertBatch, ObservationRecord,
        OccurrenceRecord, OvidHash, OvidHashInputs, PersistenceInputError, WriteContext,
        derive_ovid_hash,
    },
};
use scanner_scheduler::FsFindingRecord;

/// Logical timing for one completed item scan.
///
/// `started_at` and `finished_at` are carried into the done-ledger provenance,
/// while `finished_at` is also used as the observation `seen_at` timestamp.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScanTiming {
    started_at: LogicalTime,
    finished_at: LogicalTime,
}

impl ScanTiming {
    /// Construct item timing metadata.
    #[inline]
    #[must_use]
    pub fn new(started_at: LogicalTime, finished_at: LogicalTime) -> Self {
        debug_assert!(
            started_at.as_raw() <= finished_at.as_raw(),
            "scan timing must be monotonic: started_at ({started_at:?}) > finished_at ({finished_at:?})"
        );
        Self {
            started_at,
            finished_at,
        }
    }

    /// Logical timestamp when item processing began.
    #[inline]
    #[must_use]
    pub const fn started_at(self) -> LogicalTime {
        self.started_at
    }

    /// Logical timestamp when item processing finished.
    #[inline]
    #[must_use]
    pub const fn finished_at(self) -> LogicalTime {
        self.finished_at
    }
}

/// Runtime-visible terminal outcome for one scanned item.
///
/// The translated done-ledger status comes entirely from this enum. Findings,
/// occurrences, and observations are produced only for the `Scanned` branch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ItemResult<'a> {
    /// The item was scanned successfully; findings may be empty.
    Scanned {
        /// Post-dedupe findings for this item, in deterministic scan order.
        findings: &'a [FsFindingRecord],
    },
    /// The scan failed in a retryable way.
    FailedRetryable {
        /// Structured bounded error code for the done-ledger row.
        error_code: DoneLedgerErrorCode,
    },
    /// The scan failed permanently.
    FailedPermanent {
        /// Structured bounded error code for the done-ledger row.
        error_code: DoneLedgerErrorCode,
    },
    /// The item was intentionally skipped.
    Skipped {
        /// Structured bounded error code for the done-ledger row.
        error_code: DoneLedgerErrorCode,
    },
}

impl<'a> ItemResult<'a> {
    /// Returns the corresponding done-ledger status.
    #[inline]
    #[must_use]
    pub const fn done_ledger_status(&self, findings_count: usize) -> DoneLedgerStatus {
        match self {
            Self::Scanned { .. } if findings_count == 0 => DoneLedgerStatus::ScannedClean,
            Self::Scanned { .. } => DoneLedgerStatus::ScannedWithFindings,
            Self::FailedRetryable { .. } => DoneLedgerStatus::FailedRetryable,
            Self::FailedPermanent { .. } => DoneLedgerStatus::FailedPermanent,
            Self::Skipped { .. } => DoneLedgerStatus::Skipped,
        }
    }

    /// Optional done-ledger error code for non-success terminal outcomes.
    #[inline]
    #[must_use]
    pub fn error_code(&self) -> Option<&DoneLedgerErrorCode> {
        match self {
            Self::Scanned { .. } => None,
            Self::FailedRetryable { error_code }
            | Self::FailedPermanent { error_code }
            | Self::Skipped { error_code } => Some(error_code),
        }
    }
}

/// Fully translated persistence rows for one completed item.
///
/// Owns the three findings layers plus the done-ledger row so later commit
/// stages can borrow a [`FindingsUpsertBatch`] and the corresponding
/// [`DoneLedgerRecord`] without re-deriving identities.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PersistenceTranslation {
    ovid_hash: OvidHash,
    findings: Vec<FindingRecord>,
    occurrences: Vec<OccurrenceRecord>,
    observations: Vec<ObservationRecord>,
    done_ledger: DoneLedgerRecord,
}

impl PersistenceTranslation {
    /// Construct a translated record bundle.
    #[must_use]
    pub fn new(
        ovid_hash: OvidHash,
        findings: Vec<FindingRecord>,
        occurrences: Vec<OccurrenceRecord>,
        observations: Vec<ObservationRecord>,
        done_ledger: DoneLedgerRecord,
    ) -> Self {
        Self {
            ovid_hash,
            findings,
            occurrences,
            observations,
            done_ledger,
        }
    }

    /// Object-version identity shared by the findings observations and the
    /// done-ledger key.
    #[inline]
    #[must_use]
    pub const fn ovid_hash(&self) -> OvidHash {
        self.ovid_hash
    }

    /// Stable findings layer for this item.
    #[inline]
    #[must_use]
    pub fn findings(&self) -> &[FindingRecord] {
        &self.findings
    }

    /// Version-specific occurrences layer for this item.
    #[inline]
    #[must_use]
    pub fn occurrences(&self) -> &[OccurrenceRecord] {
        &self.occurrences
    }

    /// Policy-scoped observations layer for this item.
    #[inline]
    #[must_use]
    pub fn observations(&self) -> &[ObservationRecord] {
        &self.observations
    }

    /// Borrowed view over the findings-layer rows.
    #[inline]
    #[must_use]
    pub fn findings_batch(&self) -> FindingsUpsertBatch<'_> {
        FindingsUpsertBatch::new(&self.findings, &self.occurrences, &self.observations)
    }

    /// Done-ledger row corresponding to this completed item.
    #[inline]
    #[must_use]
    pub fn done_ledger(&self) -> &DoneLedgerRecord {
        &self.done_ledger
    }

    /// Number of distinct stable findings in this translation.
    #[inline]
    #[must_use]
    pub fn finding_count(&self) -> usize {
        self.findings.len()
    }

    /// Number of distinct occurrences in this translation.
    #[inline]
    #[must_use]
    pub fn occurrence_count(&self) -> usize {
        self.occurrences.len()
    }

    /// Number of distinct observations in this translation.
    #[inline]
    #[must_use]
    pub fn observation_count(&self) -> usize {
        self.observations.len()
    }
}

/// Errors produced while translating runtime scan results into persistence rows.
#[derive(Debug)]
pub enum ResultTranslationError {
    /// A finding span was empty or inverted.
    InvalidFindingSpan {
        /// Index of the offending finding in the input slice.
        index: usize,
        /// Inclusive start offset.
        start: u64,
        /// Exclusive end offset.
        end: u64,
    },
    /// Distinct stable findings exceeded the `u32` count range accepted by the
    /// current done-ledger row shape.
    TooManyDistinctFindings {
        /// Number of distinct findings discovered during translation.
        count: usize,
    },
    /// One of the persistence-layer constructors or validators rejected the
    /// translated rows.
    Persistence(PersistenceInputError),
}

impl fmt::Display for ResultTranslationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFindingSpan { index, start, end } => write!(
                f,
                "finding at index {index} has invalid span [{start}, {end})"
            ),
            Self::TooManyDistinctFindings { count } => write!(
                f,
                "distinct finding count {count} exceeds done-ledger u32 capacity"
            ),
            Self::Persistence(err) => write!(f, "persistence translation error: {err}"),
        }
    }
}

impl Error for ResultTranslationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Persistence(err) => Some(err),
            Self::InvalidFindingSpan { .. } | Self::TooManyDistinctFindings { .. } => None,
        }
    }
}

impl From<PersistenceInputError> for ResultTranslationError {
    #[inline]
    fn from(value: PersistenceInputError) -> Self {
        Self::Persistence(value)
    }
}

/// Translate one completed item result into deterministic persistence rows.
///
/// The translation is pure with respect to its inputs: no wall-clock reads,
/// random values, or backend state enter identity derivation. The same item,
/// findings, write context, and tenant secret key always yield the same
/// persistence IDs and done-ledger key.
///
/// # Errors
///
/// Returns [`ResultTranslationError`] when input finding spans are invalid or
/// when any persistence-layer constructor/validator rejects the translated rows.
pub fn translate_item_result(
    write_context: WriteContext,
    tenant_secret_key: &TenantSecretKey,
    item: &ScanItem,
    bytes_scanned: u64,
    timing: ScanTiming,
    result: ItemResult<'_>,
) -> Result<PersistenceTranslation, ResultTranslationError> {
    let ovid_hash = derive_ovid_hash(&OvidHashInputs {
        stable_item_id: item.stable_item_id(),
        version: item.version(),
    });
    let key = DoneLedgerKey::new(
        write_context.tenant_id(),
        write_context.policy_hash(),
        ovid_hash,
    );
    let provenance =
        DoneLedgerProvenance::from_write_context(write_context, timing.started_at(), timing.finished_at());

    let (findings, occurrences, observations) = match &result {
        ItemResult::Scanned { findings } => translate_findings(
            write_context,
            tenant_secret_key,
            item,
            ovid_hash,
            timing.finished_at(),
            findings,
        )?,
        ItemResult::FailedRetryable { .. }
        | ItemResult::FailedPermanent { .. }
        | ItemResult::Skipped { .. } => (Vec::new(), Vec::new(), Vec::new()),
    };

    let findings_count = u32::try_from(findings.len()).map_err(|_| {
        ResultTranslationError::TooManyDistinctFindings {
            count: findings.len(),
        }
    })?;
    let status = result.done_ledger_status(findings.len());
    let done_ledger = DoneLedgerRecord::try_new(
        key,
        status,
        bytes_scanned,
        findings_count,
        provenance,
        result.error_code().cloned(),
    )?;
    done_ledger.validate()?;

    let translation = PersistenceTranslation::new(
        ovid_hash,
        findings,
        occurrences,
        observations,
        done_ledger,
    );

    let batch = translation.findings_batch();
    batch.validate_observation_identity()?;
    batch.validate_referential_integrity()?;

    Ok(translation)
}

fn translate_findings(
    write_context: WriteContext,
    tenant_secret_key: &TenantSecretKey,
    item: &ScanItem,
    ovid_hash: OvidHash,
    seen_at: LogicalTime,
    input: &[FsFindingRecord],
) -> Result<
    (
        Vec<FindingRecord>,
        Vec<OccurrenceRecord>,
        Vec<ObservationRecord>,
    ),
    ResultTranslationError,
> {
    let mut findings = Vec::with_capacity(input.len());
    let mut occurrences = Vec::with_capacity(input.len());
    let mut observations = Vec::with_capacity(input.len());

    let mut seen_findings = HashSet::with_capacity(input.len());
    let mut seen_occurrences = HashSet::with_capacity(input.len());
    let mut seen_observations = HashSet::with_capacity(input.len());
    let location = item.location().cloned();

    for (index, finding) in input.iter().enumerate() {
        if finding.span_end <= finding.span_start {
            return Err(ResultTranslationError::InvalidFindingSpan {
                index,
                start: finding.span_start,
                end: finding.span_end,
            });
        }

        let norm_hash = NormHash::from_digest(finding.norm_hash);
        let secret_hash = key_secret_hash(tenant_secret_key, &norm_hash);
        let finding_record = FindingRecord::new(
            write_context.tenant_id(),
            item.stable_item_id(),
            rule_fingerprint_from_rule_id(finding.rule_id),
            secret_hash,
        );
        let occurrence_record = OccurrenceRecord::try_new(
            write_context.tenant_id(),
            finding_record.finding_id(),
            item.version().object_version_id(),
            finding.span_start,
            finding.span_end - finding.span_start,
        )?;
        let mut observation_record = ObservationRecord::from_write_context(
            write_context,
            occurrence_record.occurrence_id(),
            ovid_hash,
            seen_at,
        );
        if let Some(location) = location.clone() {
            observation_record = observation_record.with_location(location);
        }

        if seen_findings.insert(finding_record.finding_id()) {
            findings.push(finding_record);
        }
        if seen_occurrences.insert(occurrence_record.occurrence_id()) {
            occurrences.push(occurrence_record);
        }
        if seen_observations.insert(observation_record.observation_id()) {
            observations.push(observation_record);
        }
    }

    Ok((findings, occurrences, observations))
}

/// Expand the legacy numeric runtime rule id into the 32-byte fingerprint
/// shape used by the persistence identity layer.
///
/// This is a compatibility shim for the current runtime. Once rule
/// fingerprints are carried end-to-end, this helper should disappear.
#[inline]
#[must_use]
pub(crate) fn rule_fingerprint_from_rule_id(rule_id: u32) -> RuleFingerprint {
    let mut bytes = [0u8; 32];
    bytes[..4].copy_from_slice(&rule_id.to_le_bytes());
    RuleFingerprint::from_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use gossip_contracts::{
        connector::{ItemKey, ItemRef, Location, ScanItem, VersionId},
        identity::{
            FenceEpoch, ObjectVersionId, PolicyHash, RunId, ShardId, StableItemId, TenantId,
        },
        persistence::{DoneLedgerErrorCode, DoneLedgerStatus, WriteContext},
    };

    use super::*;

    fn write_context() -> WriteContext {
        WriteContext::new(
            TenantId::from_bytes([0x11; 32]),
            PolicyHash::from_bytes([0x22; 32]),
            RunId::from_raw(33),
            ShardId::from_raw(44),
            FenceEpoch::from_raw(55),
        )
    }

    fn tenant_secret_key() -> TenantSecretKey {
        TenantSecretKey::from_bytes([0x99; 32])
    }

    fn scan_item() -> ScanItem {
        ScanItem::new(
            ItemKey::try_from_slice(b"tenant/repo/path.txt").expect("item key"),
            ItemRef::try_from_vec(b"opaque-ref".to_vec()).expect("item ref"),
            StableItemId::from_bytes([0x33; 32]),
            VersionId::Strong(ObjectVersionId::from_bytes([0x44; 32])),
        )
        .with_location(Location::try_new(
            "tenant/repo/path.txt".to_owned(),
            Some("https://example.invalid/tenant/repo/path.txt".to_owned()),
        )
        .expect("location"))
    }

    fn timing() -> ScanTiming {
        ScanTiming::new(LogicalTime::from_raw(1_000), LogicalTime::from_raw(2_000))
    }

    fn finding(rule_id: u32, span_start: u64, span_end: u64, hash_seed: u8) -> FsFindingRecord {
        FsFindingRecord {
            rule_id,
            root_hint_start: span_start,
            root_hint_end: span_end,
            span_start,
            span_end,
            norm_hash: [hash_seed; 32],
            confidence_score: 7,
        }
    }

    #[test]
    fn scanned_item_translation_derives_all_persistence_layers() {
        let item = scan_item();
        let findings = [finding(7, 10, 20, 0xAA), finding(7, 40, 50, 0xAA)];

        let translated = translate_item_result(
            write_context(),
            &tenant_secret_key(),
            &item,
            4_096,
            timing(),
            ItemResult::Scanned { findings: &findings },
        )
        .expect("translation should succeed");

        assert_eq!(translated.finding_count(), 1);
        assert_eq!(translated.occurrence_count(), 2);
        assert_eq!(translated.observation_count(), 2);
        assert_eq!(translated.done_ledger().status(), DoneLedgerStatus::ScannedWithFindings);
        assert_eq!(translated.done_ledger().findings_count(), 1);
        assert_eq!(translated.done_ledger().bytes_scanned(), 4_096);
        assert_eq!(translated.done_ledger().write_context(), write_context());

        let observations = translated.observations();
        assert_eq!(observations.len(), 2);
        assert_eq!(observations[0].write_context(), write_context());
        assert_eq!(observations[0].ovid_hash(), translated.ovid_hash());
        assert_eq!(observations[0].seen_at(), timing().finished_at());
        assert_eq!(
            observations[0].location().expect("location").display(),
            "tenant/repo/path.txt"
        );

        translated
            .findings_batch()
            .validate_referential_integrity()
            .expect("translator should produce closed referential graph");
    }

    #[test]
    fn translation_is_deterministic_for_same_inputs() {
        let item = scan_item();
        let findings = [finding(9, 1, 5, 0xBC), finding(9, 12, 18, 0xBC)];

        let a = translate_item_result(
            write_context(),
            &tenant_secret_key(),
            &item,
            128,
            timing(),
            ItemResult::Scanned { findings: &findings },
        )
        .expect("translation a");
        let b = translate_item_result(
            write_context(),
            &tenant_secret_key(),
            &item,
            128,
            timing(),
            ItemResult::Scanned { findings: &findings },
        )
        .expect("translation b");

        assert_eq!(a, b);
        assert_eq!(a.ovid_hash(), b.ovid_hash());
        assert_eq!(a.done_ledger(), b.done_ledger());
    }

    #[test]
    fn translation_rejects_empty_or_inverted_spans() {
        let item = scan_item();
        let bad = [finding(1, 22, 22, 0xDD)];

        let err = translate_item_result(
            write_context(),
            &tenant_secret_key(),
            &item,
            64,
            timing(),
            ItemResult::Scanned { findings: &bad },
        )
        .expect_err("zero-length span must fail");

        match err {
            ResultTranslationError::InvalidFindingSpan { index, start, end } => {
                assert_eq!(index, 0);
                assert_eq!(start, 22);
                assert_eq!(end, 22);
            }
            other => panic!("expected InvalidFindingSpan, got {other:?}"),
        }
    }

    #[test]
    fn failed_translation_emits_done_ledger_only() {
        let item = scan_item();
        let error_code = DoneLedgerErrorCode::try_new("TIMEOUT").expect("error code");

        let translated = translate_item_result(
            write_context(),
            &tenant_secret_key(),
            &item,
            512,
            timing(),
            ItemResult::FailedRetryable { error_code },
        )
        .expect("translation should succeed");

        assert!(translated.findings().is_empty());
        assert!(translated.occurrences().is_empty());
        assert!(translated.observations().is_empty());
        assert_eq!(translated.done_ledger().status(), DoneLedgerStatus::FailedRetryable);
        assert_eq!(
            translated.done_ledger().error_code().expect("error code").as_str(),
            "TIMEOUT"
        );
        assert_eq!(translated.done_ledger().findings_count(), 0);
    }

    #[test]
    fn duplicate_occurrence_collapses_to_one_observation() {
        let item = scan_item();
        let findings = [
            finding(5, 100, 110, 0xA1),
            finding(5, 100, 110, 0xA1),
            finding(5, 100, 110, 0xA1),
        ];

        let translated = translate_item_result(
            write_context(),
            &tenant_secret_key(),
            &item,
            999,
            timing(),
            ItemResult::Scanned { findings: &findings },
        )
        .expect("translation should succeed");

        assert_eq!(translated.finding_count(), 1);
        assert_eq!(translated.occurrence_count(), 1);
        assert_eq!(translated.observation_count(), 1);
        assert_eq!(translated.done_ledger().findings_count(), 1);
    }

    #[test]
    fn strong_and_weak_versions_translate_to_different_ovid_hashes() {
        let strong_item = scan_item();
        let weak_item = ScanItem::new(
            ItemKey::try_from_slice(b"tenant/repo/path.txt").expect("item key"),
            ItemRef::try_from_vec(b"opaque-ref".to_vec()).expect("item ref"),
            StableItemId::from_bytes([0x33; 32]),
            VersionId::Weak(ObjectVersionId::from_bytes([0x44; 32])),
        );
        let findings = [finding(11, 3, 9, 0xE1)];

        let strong = translate_item_result(
            write_context(),
            &tenant_secret_key(),
            &strong_item,
            77,
            timing(),
            ItemResult::Scanned { findings: &findings },
        )
        .expect("strong translation");
        let weak = translate_item_result(
            write_context(),
            &tenant_secret_key(),
            &weak_item,
            77,
            timing(),
            ItemResult::Scanned { findings: &findings },
        )
        .expect("weak translation");

        assert_ne!(strong.ovid_hash(), weak.ovid_hash());
        assert_ne!(strong.done_ledger().key(), weak.done_ledger().key());
    }
}
