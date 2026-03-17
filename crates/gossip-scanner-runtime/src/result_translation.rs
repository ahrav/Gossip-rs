//! Deterministic translation from completed item results into persistence rows.
//!
//! The translator bridges runtime scan output into the durable record types used
//! by persistence backends:
//!
//! - [`FindingRecord`]
//! - [`OccurrenceRecord`]
//! - [`ObservationRecord`]
//! - [`DoneLedgerRecord`]
//!
//! Ordering and identity behavior are part of the contract:
//!
//! - input finding order is preserved;
//! - findings are deduplicated by `FindingId`;
//! - occurrences are deduplicated by `OccurrenceId`;
//! - observations are deduplicated by `ObservationId`;
//! - `done_ledger.findings_count` is the number of distinct stable findings.
//!
//! Occurrence span boundaries come only from [`FsFindingRecord::span_start`] and
//! [`FsFindingRecord::span_end`]. Root-hint fields remain scanner-local
//! metadata and never participate in persistence identity derivation.

use std::{collections::HashSet, error::Error, fmt, sync::Arc};

use gossip_contracts::{
    connector::ScanItem,
    identity::{LogicalTime, NormHash, RuleFingerprint, TenantSecretKey, key_secret_hash},
    persistence::{
        DoneLedgerErrorCode, DoneLedgerKey, DoneLedgerProvenance, DoneLedgerRecord,
        DoneLedgerStatus, FindingRecord, FindingsUpsertBatch, ObservationRecord, OccurrenceRecord,
        OvidHash, OvidHashInputs, PersistenceInputError, WriteContext, derive_ovid_hash,
    },
};
use scanner_scheduler::store::FsFindingRecord;

type FindingsLayers = (
    Vec<FindingRecord>,
    Vec<OccurrenceRecord>,
    Vec<ObservationRecord>,
);

/// Logical timing metadata for one completed item scan.
///
/// `started_at` and `finished_at` feed done-ledger provenance, while
/// `finished_at` also becomes the observation `seen_at` timestamp.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScanTiming {
    started_at: LogicalTime,
    finished_at: LogicalTime,
}

impl ScanTiming {
    /// Construct item-local scan timing metadata, returning an error when
    /// `started_at` exceeds `finished_at`.
    #[inline]
    pub fn try_new(
        started_at: LogicalTime,
        finished_at: LogicalTime,
    ) -> Result<Self, ResultTranslationError> {
        if started_at.as_raw() > finished_at.as_raw() {
            return Err(ResultTranslationError::InvalidScanTiming {
                started_at: started_at.as_raw(),
                finished_at: finished_at.as_raw(),
            });
        }
        Ok(Self {
            started_at,
            finished_at,
        })
    }

    /// Construct item-local scan timing metadata.
    ///
    /// # Panics
    ///
    /// Panics if `started_at > finished_at`. Callers must validate timing
    /// monotonicity before construction when timestamps originate from
    /// external sources (connectors, deserialized data). Prefer
    /// [`Self::try_new`] when the caller can handle the error.
    #[inline]
    #[must_use]
    pub fn new(started_at: LogicalTime, finished_at: LogicalTime) -> Self {
        Self::try_new(started_at, finished_at).expect("scan timing must be monotonic")
    }

    /// Logical time when scanning began for this item.
    #[inline]
    #[must_use]
    pub const fn started_at(self) -> LogicalTime {
        self.started_at
    }

    /// Logical time when scanning finished for this item.
    #[inline]
    #[must_use]
    pub const fn finished_at(self) -> LogicalTime {
        self.finished_at
    }
}

/// Terminal outcome for one item translation request.
///
/// Only scanned items contribute finding-layer rows. Failures and skips still
/// produce a done-ledger row so the runtime can durably record the terminal
/// state for the item-version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ItemResult<'a> {
    /// Successful scan output, in deterministic engine order.
    Scanned { findings: &'a [FsFindingRecord] },
    /// Retryable failure with a bounded structured error code.
    FailedRetryable { error_code: DoneLedgerErrorCode },
    /// Permanent failure with a bounded structured error code.
    FailedPermanent { error_code: DoneLedgerErrorCode },
    /// Intentional skip with a bounded structured error code.
    Skipped { error_code: DoneLedgerErrorCode },
}

impl<'a> ItemResult<'a> {
    /// Map the terminal outcome into the corresponding done-ledger status.
    #[inline]
    #[must_use]
    pub fn done_ledger_status(&self) -> DoneLedgerStatus {
        match self {
            Self::Scanned { findings: [] } => DoneLedgerStatus::ScannedClean,
            Self::Scanned { .. } => DoneLedgerStatus::ScannedWithFindings,
            Self::FailedRetryable { .. } => DoneLedgerStatus::FailedRetryable,
            Self::FailedPermanent { .. } => DoneLedgerStatus::FailedPermanent,
            Self::Skipped { .. } => DoneLedgerStatus::Skipped,
        }
    }

    /// Return the done-ledger error code for failure and skip states.
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

/// Owned persistence rows derived from one completed item.
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
    ///
    /// Restricted to the crate because the only validated construction path is
    /// [`translate_item_result`], which runs done-ledger, observation-identity,
    /// and referential-integrity checks after building the bundle.
    #[must_use]
    pub(crate) fn new(
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

    /// Object-version identity shared by observations and the done ledger.
    #[inline]
    #[must_use]
    pub const fn ovid_hash(&self) -> OvidHash {
        self.ovid_hash
    }

    /// Stable finding rows in this translation.
    #[inline]
    #[must_use]
    pub fn findings(&self) -> &[FindingRecord] {
        &self.findings
    }

    /// Version-scoped occurrence rows in this translation.
    #[inline]
    #[must_use]
    pub fn occurrences(&self) -> &[OccurrenceRecord] {
        &self.occurrences
    }

    /// Policy-scoped observation rows in this translation.
    #[inline]
    #[must_use]
    pub fn observations(&self) -> &[ObservationRecord] {
        &self.observations
    }

    /// View of the three-layer findings payload as a batch reference.
    #[inline]
    #[must_use]
    pub fn findings_batch(&self) -> FindingsUpsertBatch<'_> {
        FindingsUpsertBatch::new(&self.findings, &self.occurrences, &self.observations)
    }

    /// Done-ledger row for the translated item.
    #[inline]
    #[must_use]
    pub fn done_ledger(&self) -> &DoneLedgerRecord {
        &self.done_ledger
    }

    /// Number of distinct stable findings.
    #[inline]
    #[must_use]
    pub fn finding_count(&self) -> usize {
        self.findings.len()
    }

    /// Number of distinct occurrences.
    #[inline]
    #[must_use]
    pub fn occurrence_count(&self) -> usize {
        self.occurrences.len()
    }

    /// Number of distinct observations.
    #[inline]
    #[must_use]
    pub fn observation_count(&self) -> usize {
        self.observations.len()
    }
}

/// Errors returned while translating runtime scan output into persistence rows.
#[derive(Debug)]
pub enum ResultTranslationError {
    /// A finding span was empty or inverted before persistence-layer validation.
    InvalidFindingSpan { index: usize, start: u64, end: u64 },
    /// Distinct findings exceeded the `u32` capacity used by done-ledger rows.
    TooManyDistinctFindings { count: usize },
    /// Scan timing was inverted: `started_at` exceeded `finished_at`.
    InvalidScanTiming { started_at: u64, finished_at: u64 },
    /// A persistence constructor or validator rejected the translated rows.
    Persistence(PersistenceInputError),
    /// A persistence constructor rejected a finding at a known index.
    PersistenceAtIndex {
        index: usize,
        source: PersistenceInputError,
    },
}

impl fmt::Display for ResultTranslationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFindingSpan { index, start, end } => {
                write!(
                    f,
                    "finding at index {index} has invalid span [{start}, {end})"
                )
            }
            Self::TooManyDistinctFindings { count } => write!(
                f,
                "distinct finding count {count} exceeds done-ledger u32 capacity",
            ),
            Self::InvalidScanTiming {
                started_at,
                finished_at,
            } => write!(
                f,
                "scan timing inverted: started_at ({started_at}) > finished_at ({finished_at})",
            ),
            Self::Persistence(err) => write!(f, "persistence translation error: {err}"),
            Self::PersistenceAtIndex { index, source } => {
                write!(f, "persistence error at finding index {index}: {source}")
            }
        }
    }
}

impl Error for ResultTranslationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Persistence(err) | Self::PersistenceAtIndex { source: err, .. } => Some(err),
            Self::InvalidFindingSpan { .. }
            | Self::TooManyDistinctFindings { .. }
            | Self::InvalidScanTiming { .. } => None,
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
/// No I/O, clocks, randomness, or backend state participate in translation.
/// The same inputs always derive the same persistence IDs and done-ledger key.
///
/// # Errors
///
/// Returns [`ResultTranslationError`] when scan spans are invalid or when a
/// persistence-layer constructor or validator rejects the translated rows.
pub fn translate_item_result(
    write_context: WriteContext,
    tenant_secret_key: &TenantSecretKey,
    item: &ScanItem,
    bytes_scanned: u64,
    timing: ScanTiming,
    result: ItemResult<'_>,
    rule_fingerprint: &dyn Fn(u32) -> RuleFingerprint,
) -> Result<PersistenceTranslation, ResultTranslationError> {
    let ovid_hash = derive_ovid_hash(&OvidHashInputs {
        stable_item_id: item.stable_item_id(),
        version: item.version(),
    });
    let done_ledger_key = DoneLedgerKey::new(
        write_context.tenant_id(),
        write_context.policy_hash(),
        ovid_hash,
    );
    let provenance = DoneLedgerProvenance::from_write_context(
        write_context,
        timing.started_at(),
        timing.finished_at(),
    );

    let (findings, occurrences, observations) = match &result {
        ItemResult::Scanned { findings } => translate_findings(
            write_context,
            tenant_secret_key,
            item,
            ovid_hash,
            timing.finished_at(),
            findings,
            rule_fingerprint,
        )?,
        ItemResult::FailedRetryable { .. }
        | ItemResult::FailedPermanent { .. }
        | ItemResult::Skipped { .. } => (Vec::new(), Vec::new(), Vec::new()),
    };

    let distinct_findings = findings.len();
    let findings_count = u32::try_from(distinct_findings).map_err(|_| {
        ResultTranslationError::TooManyDistinctFindings {
            count: distinct_findings,
        }
    })?;

    let done_ledger = DoneLedgerRecord::try_new(
        done_ledger_key,
        result.done_ledger_status(),
        bytes_scanned,
        findings_count,
        provenance,
        result.error_code().cloned(),
    )?;
    // `try_new` checks findings_count vs status; `validate` additionally
    // enforces error_code consistency (failure/skip require a code, clean
    // scans forbid one). Both passes are intentional.
    done_ledger.validate()?;

    let translation =
        PersistenceTranslation::new(ovid_hash, findings, occurrences, observations, done_ledger);

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
    findings_input: &[FsFindingRecord],
    rule_fingerprint: &dyn Fn(u32) -> RuleFingerprint,
) -> Result<FindingsLayers, ResultTranslationError> {
    if findings_input.is_empty() {
        return Ok((Vec::new(), Vec::new(), Vec::new()));
    }

    let mut findings = Vec::with_capacity(findings_input.len());
    let mut occurrences = Vec::with_capacity(findings_input.len());
    let mut observations = Vec::with_capacity(findings_input.len());
    let mut seen_findings = HashSet::with_capacity(findings_input.len());
    let mut seen_occurrences = HashSet::with_capacity(findings_input.len());
    let mut seen_observations = HashSet::with_capacity(findings_input.len());
    // Wrap in Arc once so repeated observations share the same allocation
    // instead of cloning the underlying String fields per iteration.
    let location: Option<Arc<_>> = item.location().map(|l| Arc::new(l.clone()));

    for (index, finding) in findings_input.iter().enumerate() {
        // confidence_score is intentionally omitted: the persistence schema does not
        // carry confidence.

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
            rule_fingerprint(finding.rule_id),
            secret_hash,
        );
        let occurrence_record = OccurrenceRecord::try_new(
            write_context.tenant_id(),
            finding_record.finding_id(),
            item.version().object_version_id(),
            finding.span_start,
            finding.span_end - finding.span_start,
        )
        .map_err(|e| ResultTranslationError::PersistenceAtIndex { index, source: e })?;
        let mut observation_record = ObservationRecord::from_write_context(
            write_context,
            occurrence_record.occurrence_id(),
            ovid_hash,
            seen_at,
        );

        if seen_findings.insert(finding_record.finding_id()) {
            findings.push(finding_record);
        }
        if seen_occurrences.insert(occurrence_record.occurrence_id()) {
            occurrences.push(occurrence_record);
        }
        if seen_observations.insert(observation_record.observation_id()) {
            if let Some(location) = location.clone() {
                observation_record = observation_record.with_location(location);
            }
            observations.push(observation_record);
        }
    }

    Ok((findings, occurrences, observations))
}

#[cfg(test)]
mod tests {
    use gossip_contracts::{
        connector::{ItemKey, ItemRef, Location, ScanItem, VersionId},
        identity::{
            FenceEpoch, LogicalTime, ObjectVersionId, PolicyHash, RuleFingerprint, RunId, ShardId,
            StableItemId, TenantId, TenantSecretKey, derive_rule_fingerprint,
        },
        persistence::{DoneLedgerErrorCode, DoneLedgerStatus, WriteContext},
    };
    use scanner_scheduler::store::FsFindingRecord;

    use super::{
        ItemResult, PersistenceTranslation, ResultTranslationError, ScanTiming,
        translate_item_result,
    };

    /// Test-only rule fingerprint lookup that derives from a synthetic name.
    ///
    /// Uses `"test-rule-{rule_id}"` so that different rule IDs produce
    /// different stable fingerprints within tests.
    fn test_rule_fingerprint(rule_id: u32) -> RuleFingerprint {
        let name = format!("test-rule-{rule_id}");
        derive_rule_fingerprint(&name)
    }

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

    fn scan_item_with_version(version: VersionId) -> ScanItem {
        ScanItem::new(
            ItemKey::try_from_slice(b"tenant/repo/path.txt").expect("item key"),
            ItemRef::try_from_vec(b"opaque-ref".to_vec()).expect("item ref"),
            StableItemId::from_bytes([0x33; 32]),
            version,
        )
        .with_location(
            Location::try_new(
                "tenant/repo/path.txt".to_owned(),
                Some("https://example.invalid/tenant/repo/path.txt".to_owned()),
            )
            .expect("location"),
        )
    }

    fn scan_item() -> ScanItem {
        scan_item_with_version(VersionId::Strong(ObjectVersionId::from_bytes([0x44; 32])))
    }

    fn scan_item_without_location() -> ScanItem {
        ScanItem::new(
            ItemKey::try_from_slice(b"tenant/repo/path.txt").expect("item key"),
            ItemRef::try_from_vec(b"opaque-ref".to_vec()).expect("item ref"),
            StableItemId::from_bytes([0x33; 32]),
            VersionId::Strong(ObjectVersionId::from_bytes([0x44; 32])),
        )
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

    fn translate_scanned(findings: &[FsFindingRecord]) -> PersistenceTranslation {
        translate_item_result(
            write_context(),
            &tenant_secret_key(),
            &scan_item(),
            4_096,
            timing(),
            ItemResult::Scanned { findings },
            &test_rule_fingerprint,
        )
        .expect("translation should succeed")
    }

    #[test]
    fn item_result_maps_status_and_error_code() {
        let findings = [finding(1, 10, 20, 0xAA)];
        let error_code = DoneLedgerErrorCode::try_new("TIMEOUT").expect("error code");

        let clean = ItemResult::Scanned { findings: &[] };
        assert_eq!(clean.done_ledger_status(), DoneLedgerStatus::ScannedClean);
        assert!(clean.error_code().is_none());

        let scanned = ItemResult::Scanned {
            findings: &findings,
        };
        assert_eq!(
            scanned.done_ledger_status(),
            DoneLedgerStatus::ScannedWithFindings
        );
        assert!(scanned.error_code().is_none());

        let retryable = ItemResult::FailedRetryable {
            error_code: error_code.clone(),
        };
        assert_eq!(
            retryable.done_ledger_status(),
            DoneLedgerStatus::FailedRetryable
        );
        assert_eq!(
            retryable
                .error_code()
                .expect("retryable error code")
                .as_str(),
            "TIMEOUT",
        );

        let permanent = ItemResult::FailedPermanent {
            error_code: error_code.clone(),
        };
        assert_eq!(
            permanent.done_ledger_status(),
            DoneLedgerStatus::FailedPermanent
        );
        assert_eq!(
            permanent
                .error_code()
                .expect("permanent error code")
                .as_str(),
            "TIMEOUT",
        );

        let skipped = ItemResult::Skipped { error_code };
        assert_eq!(skipped.done_ledger_status(), DoneLedgerStatus::Skipped);
        assert_eq!(
            skipped.error_code().expect("skipped error code").as_str(),
            "TIMEOUT",
        );
    }

    #[test]
    fn scanned_item_translation_derives_all_persistence_layers() {
        let findings = [finding(7, 10, 20, 0xAA), finding(7, 40, 50, 0xAA)];
        let translated = translate_scanned(&findings);

        assert_eq!(translated.finding_count(), 1);
        assert_eq!(translated.occurrence_count(), 2);
        assert_eq!(translated.observation_count(), 2);
        assert_eq!(
            translated.done_ledger().status(),
            DoneLedgerStatus::ScannedWithFindings,
        );
        assert_eq!(translated.done_ledger().findings_count(), 1);
        assert_eq!(translated.done_ledger().bytes_scanned(), 4_096);
        assert_eq!(translated.done_ledger().write_context(), write_context());

        let observations = translated.observations();
        assert_eq!(observations.len(), 2);
        for obs in observations {
            assert_eq!(obs.write_context(), write_context());
            assert_eq!(obs.ovid_hash(), translated.ovid_hash());
            assert_eq!(obs.seen_at(), timing().finished_at());
            assert_eq!(
                obs.location().expect("location").display(),
                "tenant/repo/path.txt",
            );
        }
        // Two observations must reference distinct occurrences (different spans).
        assert_ne!(
            observations[0].occurrence_id(),
            observations[1].occurrence_id(),
            "observations with different spans must reference distinct occurrences",
        );

        translated
            .findings_batch()
            .validate_referential_integrity()
            .expect("translator should produce a closed referential graph");
    }

    #[test]
    fn scanned_clean_translation_produces_done_ledger_only() {
        let translated = translate_scanned(&[]);

        assert!(translated.findings().is_empty());
        assert!(translated.occurrences().is_empty());
        assert!(translated.observations().is_empty());
        assert_eq!(
            translated.done_ledger().status(),
            DoneLedgerStatus::ScannedClean
        );
        assert_eq!(translated.done_ledger().findings_count(), 0);
        assert!(translated.done_ledger().error_code().is_none());
    }

    #[test]
    fn translation_is_deterministic_for_same_inputs() {
        let findings = [finding(9, 1, 5, 0xBC), finding(9, 12, 18, 0xBC)];

        let a = translate_scanned(&findings);
        let b = translate_scanned(&findings);

        assert_eq!(a, b, "identical inputs must produce identical translations");
    }

    #[test]
    fn translation_rejects_empty_or_inverted_spans() {
        let item = scan_item();
        let invalid = [finding(1, 22, 22, 0xDD), finding(2, 30, 29, 0xEE)];

        for (index, bad) in invalid.into_iter().enumerate() {
            let err = translate_item_result(
                write_context(),
                &tenant_secret_key(),
                &item,
                64,
                timing(),
                ItemResult::Scanned {
                    findings: std::slice::from_ref(&bad),
                },
                &test_rule_fingerprint,
            )
            .expect_err("invalid span must fail");

            match err {
                ResultTranslationError::InvalidFindingSpan {
                    index: got_index,
                    start,
                    end,
                } => {
                    assert_eq!(got_index, 0);
                    assert_eq!(start, bad.span_start);
                    assert_eq!(end, bad.span_end);
                }
                other => panic!("case {index} expected InvalidFindingSpan, got {other:?}"),
            }
        }

        // Boundary twin: a 1-byte span (end == start + 1) must be accepted.
        let boundary = finding(3, 22, 23, 0xFF);
        let ok = translate_item_result(
            write_context(),
            &tenant_secret_key(),
            &item,
            64,
            timing(),
            ItemResult::Scanned {
                findings: std::slice::from_ref(&boundary),
            },
            &test_rule_fingerprint,
        )
        .expect("1-byte span (end == start + 1) must be accepted");
        assert_eq!(ok.occurrence_count(), 1);
    }

    #[test]
    fn failed_translation_emits_done_ledger_only() {
        let error_code = DoneLedgerErrorCode::try_new("TIMEOUT").expect("error code");

        let translated = translate_item_result(
            write_context(),
            &tenant_secret_key(),
            &scan_item(),
            512,
            timing(),
            ItemResult::FailedRetryable { error_code },
            &test_rule_fingerprint,
        )
        .expect("translation should succeed");

        assert!(translated.findings().is_empty());
        assert!(translated.occurrences().is_empty());
        assert!(translated.observations().is_empty());
        assert_eq!(
            translated.done_ledger().status(),
            DoneLedgerStatus::FailedRetryable
        );
        assert_eq!(
            translated
                .done_ledger()
                .error_code()
                .expect("error code")
                .as_str(),
            "TIMEOUT",
        );
        assert_eq!(translated.done_ledger().findings_count(), 0);
    }

    #[test]
    fn duplicate_input_findings_collapse_by_identity() {
        let findings = [
            finding(5, 100, 110, 0xA1),
            finding(5, 100, 110, 0xA1),
            finding(5, 100, 110, 0xA1),
        ];
        let translated = translate_scanned(&findings);

        assert_eq!(translated.finding_count(), 1);
        assert_eq!(translated.occurrence_count(), 1);
        assert_eq!(translated.observation_count(), 1);
        assert_eq!(translated.done_ledger().findings_count(), 1);
    }

    /// Non-collapse twin: findings that differ in an identity-contributing field
    /// must remain distinct. Varying `rule_id` changes `RuleFingerprint` and
    /// varying `hash_seed` changes `SecretHash` — both contribute to `FindingId`.
    #[test]
    fn distinct_findings_do_not_collapse() {
        let findings = [
            finding(1, 100, 110, 0xA1), // unique (rule_id=1, hash=0xA1)
            finding(2, 100, 110, 0xA1), // differs by rule_id → distinct FindingId
            finding(1, 100, 110, 0xB2), // differs by norm_hash → distinct FindingId
        ];
        let translated = translate_scanned(&findings);

        assert_eq!(
            translated.finding_count(),
            3,
            "findings with distinct identity-contributing fields must not collapse",
        );
        assert_eq!(translated.occurrence_count(), 3);
        assert_eq!(translated.observation_count(), 3);
        assert_eq!(translated.done_ledger().findings_count(), 3);
    }

    #[test]
    fn strong_and_weak_versions_translate_to_different_ovid_hashes() {
        let findings = [finding(11, 3, 9, 0xE1)];
        let strong_item =
            scan_item_with_version(VersionId::Strong(ObjectVersionId::from_bytes([0x44; 32])));
        let weak_item =
            scan_item_with_version(VersionId::Weak(ObjectVersionId::from_bytes([0x44; 32])));

        let strong = translate_item_result(
            write_context(),
            &tenant_secret_key(),
            &strong_item,
            77,
            timing(),
            ItemResult::Scanned {
                findings: &findings,
            },
            &test_rule_fingerprint,
        )
        .expect("strong translation");
        let weak = translate_item_result(
            write_context(),
            &tenant_secret_key(),
            &weak_item,
            77,
            timing(),
            ItemResult::Scanned {
                findings: &findings,
            },
            &test_rule_fingerprint,
        )
        .expect("weak translation");

        assert_ne!(strong.ovid_hash(), weak.ovid_hash());
        assert_ne!(strong.done_ledger().key(), weak.done_ledger().key());
    }

    #[test]
    fn failed_permanent_translation_emits_done_ledger_only() {
        let error_code = DoneLedgerErrorCode::try_new("PERM_ERR").expect("error code");

        let translated = translate_item_result(
            write_context(),
            &tenant_secret_key(),
            &scan_item(),
            512,
            timing(),
            ItemResult::FailedPermanent { error_code },
            &test_rule_fingerprint,
        )
        .expect("translation should succeed");

        assert!(translated.findings().is_empty());
        assert!(translated.occurrences().is_empty());
        assert!(translated.observations().is_empty());
        assert_eq!(
            translated.done_ledger().status(),
            DoneLedgerStatus::FailedPermanent
        );
        assert_eq!(
            translated
                .done_ledger()
                .error_code()
                .expect("error code")
                .as_str(),
            "PERM_ERR",
        );
        assert_eq!(translated.done_ledger().findings_count(), 0);
    }

    #[test]
    fn skipped_translation_emits_done_ledger_only() {
        let error_code = DoneLedgerErrorCode::try_new("SKIP_REASON").expect("error code");

        let translated = translate_item_result(
            write_context(),
            &tenant_secret_key(),
            &scan_item(),
            256,
            timing(),
            ItemResult::Skipped { error_code },
            &test_rule_fingerprint,
        )
        .expect("translation should succeed");

        assert!(translated.findings().is_empty());
        assert!(translated.occurrences().is_empty());
        assert!(translated.observations().is_empty());
        assert_eq!(translated.done_ledger().status(), DoneLedgerStatus::Skipped);
        assert_eq!(
            translated
                .done_ledger()
                .error_code()
                .expect("error code")
                .as_str(),
            "SKIP_REASON",
        );
        assert_eq!(translated.done_ledger().findings_count(), 0);
    }

    #[test]
    fn translation_without_location_produces_observations_with_no_location() {
        let findings = [finding(7, 10, 20, 0xAA)];
        let translated = translate_item_result(
            write_context(),
            &tenant_secret_key(),
            &scan_item_without_location(),
            1_024,
            timing(),
            ItemResult::Scanned {
                findings: &findings,
            },
            &test_rule_fingerprint,
        )
        .expect("translation should succeed");

        assert_eq!(translated.observation_count(), 1);
        assert!(
            translated.observations()[0].location().is_none(),
            "observation should have no location when ScanItem lacks location metadata"
        );
    }

    /// Module-level invariant: input finding order is preserved through
    /// translation into all three persistence layers.
    #[test]
    fn output_order_matches_input_order() {
        // Three findings with distinct identities, deliberately not in sorted
        // order by any field — the translator must preserve input order.
        let findings = [
            finding(30, 200, 210, 0xC1),
            finding(10, 100, 110, 0xA1),
            finding(20, 300, 310, 0xB1),
        ];
        let translated = translate_scanned(&findings);

        // Findings layer: rule fingerprints appear in input order (30, 10, 20).
        let finding_rules: Vec<_> = translated
            .findings()
            .iter()
            .map(|f| f.rule_fingerprint())
            .collect();
        assert_eq!(
            finding_rules,
            vec![
                test_rule_fingerprint(30),
                test_rule_fingerprint(10),
                test_rule_fingerprint(20),
            ],
            "finding output order must match input order",
        );

        // Occurrences layer: byte offsets appear in input order (200, 100, 300).
        let occ_offsets: Vec<_> = translated
            .occurrences()
            .iter()
            .map(|o| o.byte_offset())
            .collect();
        assert_eq!(
            occ_offsets,
            vec![200, 100, 300],
            "occurrence output order must match input order",
        );

        // Observations layer: occurrence references follow the same order.
        let obs_occ_ids: Vec<_> = translated
            .observations()
            .iter()
            .map(|o| o.occurrence_id())
            .collect();
        let occ_ids: Vec<_> = translated
            .occurrences()
            .iter()
            .map(|o| o.occurrence_id())
            .collect();
        assert_eq!(
            obs_occ_ids, occ_ids,
            "observation order must mirror occurrence order",
        );
    }

    /// Module-level invariant: root_hint_start and root_hint_end are
    /// scanner-local metadata and never participate in persistence identity
    /// derivation.
    #[test]
    fn root_hint_fields_do_not_affect_persistence_identity() {
        let mut a = finding(7, 100, 110, 0xAA);
        let mut b = finding(7, 100, 110, 0xAA);

        // Diverge only the root-hint fields; span and all other fields stay
        // identical.
        a.root_hint_start = 50;
        a.root_hint_end = 200;
        b.root_hint_start = 0;
        b.root_hint_end = 500;

        let translated_a = translate_scanned(&[a]);
        let translated_b = translate_scanned(&[b]);

        assert_eq!(
            translated_a.findings()[0].finding_id(),
            translated_b.findings()[0].finding_id(),
            "root_hint fields must not participate in FindingId derivation",
        );
        assert_eq!(
            translated_a.occurrences()[0].occurrence_id(),
            translated_b.occurrences()[0].occurrence_id(),
            "root_hint fields must not participate in OccurrenceId derivation",
        );
        assert_eq!(
            translated_a.observations()[0].observation_id(),
            translated_b.observations()[0].observation_id(),
            "root_hint fields must not participate in ObservationId derivation",
        );
    }

    #[test]
    fn inverted_scan_timing_is_rejected() {
        let later = LogicalTime::from_raw(100);
        let earlier = LogicalTime::from_raw(50);
        assert!(ScanTiming::try_new(later, earlier).is_err());
        // Equal times are accepted (zero-duration scan).
        assert!(ScanTiming::try_new(later, later).is_ok());
    }
}
