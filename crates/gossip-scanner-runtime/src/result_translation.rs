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
//! Occurrence span boundaries come from [`gossip_contracts::persistence::PersistenceFinding`]
//! implementors. Root-hint fields remain scanner-local metadata and never
//! participate in persistence identity derivation.

use std::{
    collections::{HashMap, HashSet},
    hash::{BuildHasher, Hasher},
    sync::Arc,
};

use gossip_contracts::{
    connector::{GIT_CONNECTOR_TAG, Location, ScanItem, VersionId, git::RepoKey},
    identity::{
        CanonicalBytes, ConnectorInstanceIdHash, IdentityInputError, ItemIdentityKey, LogicalTime,
        NormHash, ObjectVersionId, RuleFingerprint, StableItemId, TenantSecretKey, domain,
        domain_hasher, finalize_32, key_secret_hash,
    },
    persistence::{
        DoneLedgerErrorCode, DoneLedgerKey, DoneLedgerProvenance, DoneLedgerRecord,
        DoneLedgerStatus, FindingRecord, FindingsUpsertBatch, ObservationRecord, OccurrenceRecord,
        OvidHash, OvidHashInputs, PersistenceFinding, PersistenceInputError, WriteContext,
        derive_ovid_hash,
    },
};
use scanner_git::OidBytes;
use scanner_scheduler::store::FsFindingRecord;

use crate::coordination_sink::GitFindingForPersistence;
use crate::event_sink::sanitize_path;
use crate::git_persistence::git_repo_ovid_inputs;

// ---------------------------------------------------------------------------
// Passthrough hasher for BLAKE3-derived 32-byte identity types.
//
// FindingId, OccurrenceId, and ObservationId are BLAKE3 digests — already
// uniformly distributed. Re-hashing through SipHash wastes ~20ns per
// insert/lookup. This hasher reads the first 8 bytes of the derived
// `Hash` output as a u64 and returns that directly.
// ---------------------------------------------------------------------------

/// Hasher that returns the first 8 bytes of the last `write` call as a u64.
///
/// Correct only for types whose derived `Hash` impl writes at least 8 bytes
/// of uniformly distributed data (`define_id_32!` types derive `Hash` on a
/// `[u8; 32]` field — the derived impl writes a length prefix then the
/// 32-byte payload; this hasher captures the last write >= 8 bytes).
struct PreHashedHasher(u64);

impl Hasher for PreHashedHasher {
    #[inline]
    fn finish(&self) -> u64 {
        self.0
    }

    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        // The derived Hash for [u8; 32] writes a length prefix (usize) then
        // the 32 bytes. We want the first 8 bytes of the *payload*, so we
        // only capture the final write that carries the actual digest bytes.
        // For a [u8; 32] the derived Hash writes: write_usize(32) then
        // write(&self.0). We always overwrite, so the last write wins — and
        // for these types the last write is the 32-byte payload.
        if bytes.len() >= 8 {
            // Checked: bytes.len() >= 8 above.
            self.0 = u64::from_ne_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ]);
        }
    }
}

/// `BuildHasher` producing [`PreHashedHasher`] instances.
struct PreHashedBuildHasher;

impl BuildHasher for PreHashedBuildHasher {
    type Hasher = PreHashedHasher;

    #[inline]
    fn build_hasher(&self) -> PreHashedHasher {
        PreHashedHasher(0)
    }
}

type FindingsLayers = (
    Vec<FindingRecord>,
    Vec<OccurrenceRecord>,
    Vec<ObservationRecord>,
);

#[derive(Clone, Copy, Debug)]
struct TranslationItem<'a> {
    stable_item_id: StableItemId,
    version: VersionId,
    _marker: std::marker::PhantomData<&'a ()>,
}

impl<'a> TranslationItem<'a> {
    #[inline]
    fn from_scan_item(item: &'a ScanItem) -> Self {
        Self {
            stable_item_id: item.stable_item_id(),
            version: item.version(),
            _marker: std::marker::PhantomData,
        }
    }

    #[inline]
    const fn object_version_id(self) -> ObjectVersionId {
        self.version.object_version_id()
    }

    #[inline]
    fn ovid_hash(self) -> OvidHash {
        derive_ovid_hash(&OvidHashInputs {
            stable_item_id: self.stable_item_id,
            version: self.version,
        })
    }
}

#[derive(Clone, Copy, Debug)]
struct FsFindingRef<'a>(&'a FsFindingRecord);

impl PersistenceFinding for FsFindingRef<'_> {
    #[inline]
    fn rule_id(&self) -> u32 {
        self.0.rule_id
    }

    #[inline]
    fn norm_hash(&self) -> NormHash {
        NormHash::from_digest(self.0.norm_hash)
    }

    #[inline]
    fn span_start(&self) -> u64 {
        self.0.span_start
    }

    #[inline]
    fn span_end(&self) -> u64 {
        self.0.span_end
    }
}

/// Uninhabited finding type for non-Scanned translation paths where no
/// findings exist. Satisfies the generic bound on `translate_result`
/// without coupling to any concrete finding type.
enum NeverFinding {}

impl PersistenceFinding for NeverFinding {
    fn rule_id(&self) -> u32 {
        match *self {}
    }

    fn norm_hash(&self) -> NormHash {
        match *self {}
    }

    fn span_start(&self) -> u64 {
        match *self {}
    }

    fn span_end(&self) -> u64 {
        match *self {}
    }
}

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
pub enum ItemResult<'a, F = FsFindingRecord> {
    /// Successful scan output, in deterministic engine order.
    Scanned { findings: &'a [F] },
    /// Retryable failure with a bounded structured error code.
    FailedRetryable { error_code: DoneLedgerErrorCode },
    /// Permanent failure with a bounded structured error code.
    FailedPermanent { error_code: DoneLedgerErrorCode },
    /// Intentional skip with a bounded structured error code.
    Skipped { error_code: DoneLedgerErrorCode },
}

impl<'a, F> ItemResult<'a, F> {
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
    done_ledger_ovid_hash: OvidHash,
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
        done_ledger_ovid_hash: OvidHash,
        findings: Vec<FindingRecord>,
        occurrences: Vec<OccurrenceRecord>,
        observations: Vec<ObservationRecord>,
        done_ledger: DoneLedgerRecord,
    ) -> Self {
        Self {
            done_ledger_ovid_hash,
            findings,
            occurrences,
            observations,
            done_ledger,
        }
    }

    /// Done-ledger object-version identity for the translated item.
    #[inline]
    #[must_use]
    pub const fn ovid_hash(&self) -> OvidHash {
        self.done_ledger_ovid_hash
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
#[derive(Debug, thiserror::Error)]
pub enum ResultTranslationError {
    /// A finding span was empty or inverted before persistence-layer validation.
    #[error("finding at index {index} has invalid span [{start}, {end})")]
    InvalidFindingSpan { index: usize, start: u64, end: u64 },
    /// Distinct findings exceeded the `u32` capacity used by done-ledger rows.
    #[error("distinct finding count {count} exceeds done-ledger u32 capacity")]
    TooManyDistinctFindings { count: usize },
    /// Scan timing was inverted: `started_at` exceeded `finished_at`.
    #[error("scan timing inverted: started_at ({started_at}) > finished_at ({finished_at})")]
    InvalidScanTiming { started_at: u64, finished_at: u64 },
    /// Git finding payload omitted the commit ordinal required for object identity.
    #[error("git finding at index {index} is missing commit identity")]
    MissingGitCommitId { index: usize },
    /// Git finding referenced a commit ordinal absent from the sparse OID map.
    #[error("git finding at index {index} references unknown commit_id {commit_id}")]
    MissingGitCommitOid { index: usize, commit_id: u32 },
    /// Git finding could not derive a stable per-object item identity.
    #[error("git finding at index {index} has invalid object identity: {source}")]
    GitItemIdentity {
        index: usize,
        source: IdentityInputError,
    },
    /// A persistence constructor or validator rejected the translated rows.
    #[error("persistence translation error: {0}")]
    Persistence(#[source] PersistenceInputError),
    /// A persistence constructor rejected a finding at a known index.
    #[error("persistence error at finding index {index}: {source}")]
    PersistenceAtIndex {
        index: usize,
        source: PersistenceInputError,
    },
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
    let location = item.location().cloned().map(Arc::new);
    let item = TranslationItem::from_scan_item(item);
    match result {
        ItemResult::Scanned { findings } => {
            // Per-item allocation; bounded by finding count (typically < 100).
            let findings: Vec<_> = findings.iter().map(FsFindingRef).collect();
            translate_result(
                write_context,
                tenant_secret_key,
                item,
                location,
                bytes_scanned,
                timing,
                ItemResult::Scanned {
                    findings: &findings,
                },
                rule_fingerprint,
            )
        }
        // Type witness only — no findings exist for non-Scanned variants. Any
        // PersistenceFinding implementor works; NeverFinding is uninhabited and
        // exists solely to satisfy the generic bound without implying a concrete
        // finding source.
        ItemResult::FailedRetryable { error_code } => translate_result::<NeverFinding, _>(
            write_context,
            tenant_secret_key,
            item,
            location,
            bytes_scanned,
            timing,
            ItemResult::FailedRetryable { error_code },
            rule_fingerprint,
        ),
        ItemResult::FailedPermanent { error_code } => translate_result::<NeverFinding, _>(
            write_context,
            tenant_secret_key,
            item,
            location,
            bytes_scanned,
            timing,
            ItemResult::FailedPermanent { error_code },
            rule_fingerprint,
        ),
        ItemResult::Skipped { error_code } => translate_result::<NeverFinding, _>(
            write_context,
            tenant_secret_key,
            item,
            location,
            bytes_scanned,
            timing,
            ItemResult::Skipped { error_code },
            rule_fingerprint,
        ),
    }
}

/// Translate one completed Git repo scan into deterministic persistence rows.
///
/// Always produces a `Scanned` result because the Git path rejects errors
/// before reaching translation — failed or skipped repos never call this
/// function. The FS path handles all four `ItemResult` variants via
/// `translate_item_result`.
///
/// Git repo-frontier scans keep the done-ledger row repo-scoped via `repo_id`,
/// while each observation derives its stable item identity from the connector
/// instance plus the repository-relative object path and its strong version
/// identity from the scanned commit OID for that path.
#[allow(clippy::too_many_arguments)]
pub(crate) fn translate_git_item_result(
    write_context: WriteContext,
    tenant_secret_key: &TenantSecretKey,
    repo_key: &RepoKey,
    repo_id: u64,
    bytes_scanned: u64,
    timing: ScanTiming,
    findings: &[GitFindingForPersistence],
    commit_oid_map: &HashMap<u32, OidBytes>,
    rule_fingerprint: &dyn Fn(u32) -> RuleFingerprint,
) -> Result<PersistenceTranslation, ResultTranslationError> {
    let done_ledger_item = git_repo_ovid_inputs(repo_id);
    let result = ItemResult::Scanned { findings };
    let findings_layers = translate_git_findings(
        write_context,
        tenant_secret_key,
        repo_key,
        commit_oid_map,
        timing.finished_at(),
        findings,
        rule_fingerprint,
    )?;
    build_translation(
        write_context,
        bytes_scanned,
        timing,
        &result,
        derive_ovid_hash(&done_ledger_item),
        findings_layers,
    )
}

#[allow(clippy::too_many_arguments)]
fn translate_result<F, R>(
    write_context: WriteContext,
    tenant_secret_key: &TenantSecretKey,
    item: TranslationItem<'_>,
    location: Option<Arc<Location>>,
    bytes_scanned: u64,
    timing: ScanTiming,
    result: ItemResult<'_, F>,
    rule_fingerprint: &R,
) -> Result<PersistenceTranslation, ResultTranslationError>
where
    F: PersistenceFinding,
    R: Fn(u32) -> RuleFingerprint + ?Sized,
{
    let done_ledger_ovid_hash = item.ovid_hash();
    let findings_layers = match &result {
        ItemResult::Scanned { findings } => translate_findings(
            write_context,
            tenant_secret_key,
            item,
            done_ledger_ovid_hash,
            location,
            timing.finished_at(),
            findings,
            rule_fingerprint,
        )?,
        ItemResult::FailedRetryable { .. }
        | ItemResult::FailedPermanent { .. }
        | ItemResult::Skipped { .. } => (Vec::new(), Vec::new(), Vec::new()),
    };
    build_translation(
        write_context,
        bytes_scanned,
        timing,
        &result,
        done_ledger_ovid_hash,
        findings_layers,
    )
}

#[allow(clippy::too_many_arguments)]
fn translate_findings<F, R>(
    write_context: WriteContext,
    tenant_secret_key: &TenantSecretKey,
    item: TranslationItem<'_>,
    observation_ovid_hash: OvidHash,
    location: Option<Arc<Location>>,
    seen_at: LogicalTime,
    findings_input: &[F],
    rule_fingerprint: &R,
) -> Result<FindingsLayers, ResultTranslationError>
where
    F: PersistenceFinding,
    R: Fn(u32) -> RuleFingerprint + ?Sized,
{
    if findings_input.is_empty() {
        return Ok((Vec::new(), Vec::new(), Vec::new()));
    }

    let mut findings = Vec::with_capacity(findings_input.len());
    let mut occurrences = Vec::with_capacity(findings_input.len());
    let mut observations = Vec::with_capacity(findings_input.len());
    // BLAKE3-derived IDs are already uniformly distributed, so a passthrough
    // hasher that reads the first 8 bytes avoids redundant SipHash work.
    let mut seen_findings =
        HashSet::with_capacity_and_hasher(findings_input.len(), PreHashedBuildHasher);
    let mut seen_occurrences =
        HashSet::with_capacity_and_hasher(findings_input.len(), PreHashedBuildHasher);
    let mut seen_observations =
        HashSet::with_capacity_and_hasher(findings_input.len(), PreHashedBuildHasher);

    for (index, finding) in findings_input.iter().enumerate() {
        push_finding_layers(
            write_context,
            tenant_secret_key,
            item,
            observation_ovid_hash,
            location.clone(),
            seen_at,
            finding,
            rule_fingerprint,
            index,
            &mut findings,
            &mut occurrences,
            &mut observations,
            &mut seen_findings,
            &mut seen_occurrences,
            &mut seen_observations,
        )?;
    }

    Ok((findings, occurrences, observations))
}

fn translate_git_findings<R>(
    write_context: WriteContext,
    tenant_secret_key: &TenantSecretKey,
    repo_key: &RepoKey,
    commit_oid_map: &HashMap<u32, OidBytes>,
    seen_at: LogicalTime,
    findings_input: &[GitFindingForPersistence],
    rule_fingerprint: &R,
) -> Result<FindingsLayers, ResultTranslationError>
where
    R: Fn(u32) -> RuleFingerprint + ?Sized,
{
    if findings_input.is_empty() {
        return Ok((Vec::new(), Vec::new(), Vec::new()));
    }

    let mut findings = Vec::with_capacity(findings_input.len());
    let mut occurrences = Vec::with_capacity(findings_input.len());
    let mut observations = Vec::with_capacity(findings_input.len());
    let mut seen_findings =
        HashSet::with_capacity_and_hasher(findings_input.len(), PreHashedBuildHasher);
    let mut seen_occurrences =
        HashSet::with_capacity_and_hasher(findings_input.len(), PreHashedBuildHasher);
    let mut seen_observations =
        HashSet::with_capacity_and_hasher(findings_input.len(), PreHashedBuildHasher);
    let connector_instance = ConnectorInstanceIdHash::from_instance_id_bytes(repo_key.as_bytes());

    for (index, finding) in findings_input.iter().enumerate() {
        let commit_id = finding
            .commit_id
            .ok_or(ResultTranslationError::MissingGitCommitId { index })?;
        let commit_oid = commit_oid_map
            .get(&commit_id)
            .ok_or(ResultTranslationError::MissingGitCommitOid { index, commit_id })?;
        let identity = ItemIdentityKey::try_new(
            GIT_CONNECTOR_TAG,
            connector_instance,
            finding.object_path.as_ref(),
        )
        .map_err(|source| ResultTranslationError::GitItemIdentity { index, source })?;
        let item = TranslationItem {
            stable_item_id: identity.stable_id(),
            version: VersionId::Strong(git_object_version_id(
                commit_oid,
                finding.object_path.as_ref(),
            )),
            _marker: std::marker::PhantomData,
        };
        let observation_ovid_hash = item.ovid_hash();
        let location = git_observation_location(finding.object_path.as_ref());
        push_finding_layers(
            write_context,
            tenant_secret_key,
            item,
            observation_ovid_hash,
            location,
            seen_at,
            finding,
            rule_fingerprint,
            index,
            &mut findings,
            &mut occurrences,
            &mut observations,
            &mut seen_findings,
            &mut seen_occurrences,
            &mut seen_observations,
        )?;
    }

    Ok((findings, occurrences, observations))
}

#[allow(clippy::too_many_arguments)]
fn push_finding_layers<F, R>(
    write_context: WriteContext,
    tenant_secret_key: &TenantSecretKey,
    item: TranslationItem<'_>,
    observation_ovid_hash: OvidHash,
    location: Option<Arc<Location>>,
    seen_at: LogicalTime,
    finding: &F,
    rule_fingerprint: &R,
    index: usize,
    findings: &mut Vec<FindingRecord>,
    occurrences: &mut Vec<OccurrenceRecord>,
    observations: &mut Vec<ObservationRecord>,
    seen_findings: &mut HashSet<gossip_contracts::identity::FindingId, PreHashedBuildHasher>,
    seen_occurrences: &mut HashSet<gossip_contracts::identity::OccurrenceId, PreHashedBuildHasher>,
    seen_observations: &mut HashSet<
        gossip_contracts::identity::ObservationId,
        PreHashedBuildHasher,
    >,
) -> Result<(), ResultTranslationError>
where
    F: PersistenceFinding,
    R: Fn(u32) -> RuleFingerprint + ?Sized,
{
    if finding.span_end() <= finding.span_start() {
        return Err(ResultTranslationError::InvalidFindingSpan {
            index,
            start: finding.span_start(),
            end: finding.span_end(),
        });
    }

    let norm_hash = finding.norm_hash();
    let secret_hash = key_secret_hash(tenant_secret_key, &norm_hash);
    let finding_record = FindingRecord::new(
        write_context.tenant_id(),
        item.stable_item_id,
        rule_fingerprint(finding.rule_id()),
        secret_hash,
    );
    let finding_id = finding_record.finding_id();

    if seen_findings.insert(finding_id) {
        findings.push(finding_record);
    }

    let occurrence_record = OccurrenceRecord::try_new(
        write_context.tenant_id(),
        finding_id,
        item.object_version_id(),
        finding.span_start(),
        finding.span_len(),
    )
    .map_err(|source| ResultTranslationError::PersistenceAtIndex { index, source })?;
    let occurrence_id = occurrence_record.occurrence_id();

    if seen_occurrences.insert(occurrence_id) {
        occurrences.push(occurrence_record);
    }

    let mut observation_record = ObservationRecord::from_write_context(
        write_context,
        occurrence_id,
        observation_ovid_hash,
        seen_at,
    );

    if seen_observations.insert(observation_record.observation_id()) {
        if let Some(location) = location {
            observation_record = observation_record.with_location(location);
        }
        observations.push(observation_record);
    }

    Ok(())
}

fn build_translation<F>(
    write_context: WriteContext,
    bytes_scanned: u64,
    timing: ScanTiming,
    result: &ItemResult<'_, F>,
    done_ledger_ovid_hash: OvidHash,
    findings_layers: FindingsLayers,
) -> Result<PersistenceTranslation, ResultTranslationError> {
    let (findings, occurrences, observations) = findings_layers;
    let distinct_findings = findings.len();
    let findings_count = u32::try_from(distinct_findings).map_err(|_| {
        ResultTranslationError::TooManyDistinctFindings {
            count: distinct_findings,
        }
    })?;
    let done_ledger_key = DoneLedgerKey::new(
        write_context.tenant_id(),
        write_context.policy_hash(),
        done_ledger_ovid_hash,
    );
    let provenance = DoneLedgerProvenance::from_write_context(
        write_context,
        timing.started_at(),
        timing.finished_at(),
    );
    let done_ledger = DoneLedgerRecord::try_new(
        done_ledger_key,
        result.done_ledger_status(),
        bytes_scanned,
        findings_count,
        provenance,
        result.error_code().cloned(),
    )?;
    done_ledger.validate()?;

    let translation = PersistenceTranslation::new(
        done_ledger_ovid_hash,
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

fn git_object_version_id(commit_oid: &OidBytes, object_path: &[u8]) -> ObjectVersionId {
    let mut hasher = domain_hasher(domain::OBJECT_VERSION_V1);
    commit_oid.as_slice().write_canonical(&mut hasher);
    object_path.write_canonical(&mut hasher);
    ObjectVersionId::from_bytes(finalize_32(&hasher))
}

fn git_observation_location(object_path: &[u8]) -> Option<Arc<Location>> {
    Location::try_new(sanitize_path(object_path), None)
        .ok()
        .map(Arc::new)
}

#[cfg(test)]
mod tests {
    use gossip_contracts::{
        connector::{
            GIT_CONNECTOR_TAG, ItemKey, ItemRef, Location, ScanItem, VersionId, git::RepoKey,
        },
        identity::{
            CanonicalBytes, ConnectorInstanceIdHash, ItemIdentityKey, LogicalTime, NormHash,
            ObjectVersionId, StableItemId, domain, domain_hasher, finalize_32,
        },
        persistence::{DoneLedgerErrorCode, DoneLedgerStatus, PersistenceFinding},
    };
    use scanner_git::OidBytes;
    use scanner_scheduler::store::FsFindingRecord;

    use proptest::prelude::*;

    use super::{
        FsFindingRef, ItemResult, PersistenceTranslation, ResultTranslationError, ScanTiming,
        translate_git_item_result, translate_item_result,
    };
    use std::collections::HashMap;

    use crate::coordination_sink::GitFindingForPersistence;
    use crate::event_sink::sanitize_path;
    use crate::test_fixtures::{
        finding, tenant_secret_key, test_rule_fingerprint, timing, write_context,
    };

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

    fn git_repo_key() -> RepoKey {
        RepoKey::for_local_path(b"/tmp/runtime-git-identity").expect("repo key")
    }

    fn git_commit_oid() -> OidBytes {
        OidBytes::sha1([0x11; 20])
    }

    fn git_commit_oid_map() -> HashMap<u32, OidBytes> {
        HashMap::from([(7, git_commit_oid())])
    }

    fn boxed_path(path: &[u8]) -> Box<[u8]> {
        path.to_vec().into_boxed_slice()
    }

    fn git_object_scan_item(
        repo_key: &RepoKey,
        object_path: &[u8],
        commit_oid: OidBytes,
    ) -> ScanItem {
        let connector_instance =
            ConnectorInstanceIdHash::from_instance_id_bytes(repo_key.as_bytes());
        let identity = ItemIdentityKey::try_new(GIT_CONNECTOR_TAG, connector_instance, object_path)
            .expect("git item identity");
        let mut hasher = domain_hasher(domain::OBJECT_VERSION_V1);
        commit_oid.as_slice().write_canonical(&mut hasher);
        object_path.write_canonical(&mut hasher);
        let version = VersionId::Strong(ObjectVersionId::from_bytes(finalize_32(&hasher)));
        ScanItem::new(
            ItemKey::try_from_slice(b"tenant/repo/git/object").expect("item key"),
            ItemRef::try_from_vec(b"git-item-ref".to_vec()).expect("item ref"),
            identity.stable_id(),
            version,
        )
        .with_location(Location::try_new(sanitize_path(object_path), None).expect("location"))
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

    fn git_finding(
        rule_id: u32,
        span_start: u64,
        span_end: u64,
        hash_seed: u8,
    ) -> GitFindingForPersistence {
        GitFindingForPersistence {
            object_path: boxed_path(b"src/lib.rs"),
            commit_id: Some(7),
            span_start,
            span_end,
            norm_hash: NormHash::from_digest([hash_seed; 32]),
            rule_id,
        }
    }

    fn translate_git_scanned(findings: &[GitFindingForPersistence]) -> PersistenceTranslation {
        let repo_key = git_repo_key();
        let commit_oid_map = git_commit_oid_map();
        translate_git_item_result(
            write_context(),
            &tenant_secret_key(),
            &repo_key,
            42,
            4_096,
            timing(),
            findings,
            &commit_oid_map,
            &test_rule_fingerprint,
        )
        .expect("git translation should succeed")
    }

    #[test]
    fn item_result_maps_status_and_error_code() {
        let findings = [finding(1, 10, 20, 0xAA)];
        let error_code = DoneLedgerErrorCode::try_new("TIMEOUT").expect("error code");

        let clean: ItemResult<'_> = ItemResult::Scanned { findings: &[] };
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

        let retryable: ItemResult<'_> = ItemResult::FailedRetryable {
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

        let permanent: ItemResult<'_> = ItemResult::FailedPermanent {
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

        let skipped: ItemResult<'_> = ItemResult::Skipped { error_code };
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
    fn persistence_finding_trait_git_impl_round_trip() {
        let finding = git_finding(7, 0, 100, 0xCD);
        assert_eq!(finding.rule_id(), 7);
        assert_eq!(finding.norm_hash(), NormHash::from_digest([0xCD; 32]));
        assert_eq!(finding.span_start(), 0);
        assert_eq!(finding.span_end(), 100);
        assert_eq!(finding.span_len(), 100);
    }

    #[test]
    fn persistence_finding_trait_fs_impl_round_trip() {
        let rec = finding(42, 10, 50, 0xAB);
        let wrapper = FsFindingRef(&rec);
        assert_eq!(wrapper.rule_id(), 42);
        assert_eq!(wrapper.norm_hash(), NormHash::from_digest([0xAB; 32]));
        assert_eq!(wrapper.span_start(), 10);
        assert_eq!(wrapper.span_end(), 50);
        assert_eq!(wrapper.span_len(), 40);
    }

    #[test]
    fn translate_git_item_result_produces_valid_three_layer_batch() {
        let translated = translate_git_scanned(&[git_finding(3, 10, 24, 0xAB)]);
        assert_eq!(translated.finding_count(), 1);
        assert_eq!(translated.occurrence_count(), 1);
        assert_eq!(translated.observation_count(), 1);
        assert_eq!(
            translated.done_ledger().status(),
            DoneLedgerStatus::ScannedWithFindings,
        );
        translated
            .findings_batch()
            .validate_observation_identity()
            .expect("git translation must produce valid observation identities");
        translated
            .findings_batch()
            .validate_referential_integrity()
            .expect("git translation must produce a closed referential graph");
        assert_ne!(
            translated.observations()[0].ovid_hash(),
            translated.done_ledger().key().ovid_hash(),
            "git repo completion must stay repo-scoped while observations are per-object",
        );
    }

    #[test]
    fn identical_identity_fields_produce_identical_persistence_ids_across_source_types() {
        let fs = finding(7, 10, 50, 0xAB);
        let git = git_finding(7, 10, 50, 0xAB);
        let repo_key = git_repo_key();
        let fs_translation = translate_item_result(
            write_context(),
            &tenant_secret_key(),
            &git_object_scan_item(&repo_key, git.object_path.as_ref(), git_commit_oid()),
            4_096,
            timing(),
            ItemResult::Scanned { findings: &[fs] },
            &test_rule_fingerprint,
        )
        .expect("filesystem translation should succeed");
        let git_translation = translate_git_scanned(&[git]);

        assert_eq!(
            fs_translation.findings()[0].finding_id(),
            git_translation.findings()[0].finding_id(),
            "matching rule/hash identity must derive the same FindingId",
        );
        assert_eq!(
            fs_translation.occurrences()[0].occurrence_id(),
            git_translation.occurrences()[0].occurrence_id(),
            "matching span identity must derive the same OccurrenceId",
        );
        assert_eq!(
            fs_translation.observations()[0].observation_id(),
            git_translation.observations()[0].observation_id(),
            "matching persistence identity must derive the same ObservationId",
        );
    }

    #[test]
    fn norm_hash_from_digest_round_trip_acceptance() {
        let bytes = [0xA5; 32];
        let hash = NormHash::from_digest(bytes);
        assert_eq!(*hash.as_bytes(), bytes);
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
    fn translate_git_item_result_rejects_inverted_spans() {
        let finding = GitFindingForPersistence {
            object_path: boxed_path(b"src/lib.rs"),
            commit_id: Some(7),
            rule_id: 1,
            norm_hash: NormHash::from_digest([0xAA; 32]),
            span_start: 50,
            span_end: 10,
        };
        let repo_key = git_repo_key();
        let commit_oid_map = git_commit_oid_map();
        let err = translate_git_item_result(
            write_context(),
            &tenant_secret_key(),
            &repo_key,
            42,
            4096,
            timing(),
            &[finding],
            &commit_oid_map,
            &test_rule_fingerprint,
        )
        .expect_err("inverted spans must be rejected");
        assert!(
            matches!(
                err,
                ResultTranslationError::InvalidFindingSpan {
                    start: 50,
                    end: 10,
                    ..
                }
            ),
            "expected InvalidFindingSpan, got: {err:?}",
        );
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

    #[test]
    fn duplicate_git_findings_collapse_by_identity() {
        let f1 = git_finding(7, 10, 50, 0xAB);
        let f2 = git_finding(7, 10, 50, 0xAB);
        let translated = translate_git_scanned(&[f1, f2]);
        assert_eq!(
            translated.finding_count(),
            1,
            "duplicate git findings must collapse"
        );
        assert_eq!(translated.occurrence_count(), 1);
        assert_eq!(translated.observation_count(), 1);
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
    fn mixed_valid_and_invalid_batch_rejects_at_correct_index() {
        let item = scan_item();
        let findings = [finding(1, 10, 20, 0xAA), finding(2, 30, 30, 0xBB)];

        let err = translate_item_result(
            write_context(),
            &tenant_secret_key(),
            &item,
            64,
            timing(),
            ItemResult::Scanned {
                findings: &findings,
            },
            &test_rule_fingerprint,
        )
        .expect_err("batch with invalid finding at index 1 must fail");

        match err {
            ResultTranslationError::InvalidFindingSpan { index, start, end } => {
                assert_eq!(index, 1, "error must identify the invalid finding index");
                assert_eq!(start, 30);
                assert_eq!(end, 30);
            }
            other => panic!("expected InvalidFindingSpan, got {other:?}"),
        }
    }

    #[test]
    fn inverted_scan_timing_is_rejected() {
        let later = LogicalTime::from_raw(100);
        let earlier = LogicalTime::from_raw(50);
        assert!(ScanTiming::try_new(later, earlier).is_err());
        // Equal times are accepted (zero-duration scan).
        assert!(ScanTiming::try_new(later, later).is_ok());
    }

    /// Verifies that `ResultTranslationError` variants never expose norm_hash
    /// bytes in their Display or Debug representations.
    #[test]
    fn no_finding_data_in_error_context_strings() {
        let hash_bytes = [0xDE; 32];
        let bad_finding = GitFindingForPersistence {
            object_path: boxed_path(b"src/lib.rs"),
            commit_id: Some(7),
            rule_id: 7,
            norm_hash: NormHash::from_digest(hash_bytes),
            span_start: 50,
            span_end: 10, // inverted span triggers InvalidFindingSpan
        };
        let repo_key = git_repo_key();
        let commit_oid_map = git_commit_oid_map();
        let err = translate_git_item_result(
            write_context(),
            &tenant_secret_key(),
            &repo_key,
            42,
            4096,
            timing(),
            &[bad_finding],
            &commit_oid_map,
            &test_rule_fingerprint,
        )
        .expect_err("inverted span must fail");

        let display = format!("{err}");
        let debug = format!("{err:?}");
        // 0xDE = 222 decimal; must not appear in error output.
        assert!(
            !display.contains("222"),
            "Display must not leak hash bytes: {display}",
        );
        assert!(
            !debug.contains("222"),
            "Debug must not leak hash bytes: {debug}",
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 256,
            .. ProptestConfig::default()
        })]

        /// For any valid identity quadruple (rule_id, norm_hash, span_start,
        /// span_end), the FS and Git translation paths must produce identical
        /// FindingId, OccurrenceId, and ObservationId values.
        #[test]
        fn proptest_translate_findings_identity_equivalence(
            rule_id in 1..100u32,
            hash_seed in proptest::array::uniform32(0u8..),
            start in 0..u32::MAX as u64,
            len in 1..1000u64,
        ) {
            let end = start.saturating_add(len).max(start + 1);
            let fs_rec = FsFindingRecord {
                rule_id, norm_hash: hash_seed,
                span_start: start, span_end: end,
                root_hint_start: 0, root_hint_end: 0, confidence_score: 5,
            };
            let git_rec = GitFindingForPersistence {
                object_path: boxed_path(b"src/lib.rs"),
                commit_id: Some(7),
                rule_id,
                norm_hash: NormHash::from_digest(hash_seed),
                span_start: start, span_end: end,
            };

            let repo_key = git_repo_key();
            let item = git_object_scan_item(&repo_key, git_rec.object_path.as_ref(), git_commit_oid());
            let commit_oid_map = git_commit_oid_map();

            let fs_t = translate_item_result(
                write_context(), &tenant_secret_key(), &item, 4096, timing(),
                ItemResult::Scanned { findings: &[fs_rec] }, &test_rule_fingerprint,
            ).expect("fs translation");
            let git_t = translate_git_item_result(
                write_context(), &tenant_secret_key(), &repo_key, 42, 4096, timing(),
                &[git_rec], &commit_oid_map, &test_rule_fingerprint,
            ).expect("git translation");

            prop_assert_eq!(
                fs_t.findings()[0].finding_id(),
                git_t.findings()[0].finding_id(),
            );
            prop_assert_eq!(
                fs_t.occurrences()[0].occurrence_id(),
                git_t.occurrences()[0].occurrence_id(),
            );
            prop_assert_eq!(
                fs_t.observations()[0].observation_id(),
                git_t.observations()[0].observation_id(),
            );
        }
    }

    #[test]
    fn translate_git_item_result_empty_findings_produces_scanned_clean() {
        let translated = translate_git_scanned(&[]);

        assert!(translated.findings().is_empty());
        assert!(translated.occurrences().is_empty());
        assert!(translated.observations().is_empty());
        assert_eq!(
            translated.done_ledger().status(),
            DoneLedgerStatus::ScannedClean,
        );
        assert_eq!(translated.done_ledger().findings_count(), 0);
    }

    #[test]
    fn translate_git_item_result_rejects_inverted_span() {
        let bad = git_finding(1, 50, 10, 0xDD);
        let repo_key = git_repo_key();
        let commit_oid_map = git_commit_oid_map();
        let err = translate_git_item_result(
            write_context(),
            &tenant_secret_key(),
            &repo_key,
            42,
            4_096,
            timing(),
            &[bad],
            &commit_oid_map,
            &test_rule_fingerprint,
        )
        .expect_err("inverted git span must fail");
        assert!(matches!(
            err,
            ResultTranslationError::InvalidFindingSpan { .. }
        ));
    }

    #[test]
    fn translate_git_item_result_rejects_missing_commit_id() {
        let repo_key = git_repo_key();
        let err = translate_git_item_result(
            write_context(),
            &tenant_secret_key(),
            &repo_key,
            42,
            4_096,
            timing(),
            &[GitFindingForPersistence {
                object_path: boxed_path(b"src/lib.rs"),
                commit_id: None,
                span_start: 10,
                span_end: 20,
                norm_hash: NormHash::from_digest([0xAA; 32]),
                rule_id: 7,
            }],
            &git_commit_oid_map(),
            &test_rule_fingerprint,
        )
        .expect_err("missing commit identity must be rejected");
        assert!(matches!(
            err,
            ResultTranslationError::MissingGitCommitId { index: 0 }
        ));
    }

    #[test]
    fn translate_git_item_result_rejects_unknown_commit_oid() {
        let repo_key = git_repo_key();
        let err = translate_git_item_result(
            write_context(),
            &tenant_secret_key(),
            &repo_key,
            42,
            4_096,
            timing(),
            &[GitFindingForPersistence {
                object_path: boxed_path(b"src/lib.rs"),
                commit_id: Some(99),
                span_start: 10,
                span_end: 20,
                norm_hash: NormHash::from_digest([0xAA; 32]),
                rule_id: 7,
            }],
            &git_commit_oid_map(),
            &test_rule_fingerprint,
        )
        .expect_err("unknown commit OID must be rejected");
        assert!(matches!(
            err,
            ResultTranslationError::MissingGitCommitOid {
                index: 0,
                commit_id: 99
            }
        ));
    }

    #[test]
    fn translate_git_item_result_uses_distinct_observation_ovids_for_distinct_objects() {
        let translated = translate_git_scanned(&[
            GitFindingForPersistence {
                object_path: boxed_path(b"src/lib.rs"),
                commit_id: Some(7),
                span_start: 10,
                span_end: 20,
                norm_hash: NormHash::from_digest([0xAA; 32]),
                rule_id: 7,
            },
            GitFindingForPersistence {
                object_path: boxed_path(b"src/main.rs"),
                commit_id: Some(7),
                span_start: 10,
                span_end: 20,
                norm_hash: NormHash::from_digest([0xBB; 32]),
                rule_id: 7,
            },
        ]);
        assert_eq!(translated.observation_count(), 2);
        assert_ne!(
            translated.observations()[0].ovid_hash(),
            translated.observations()[1].ovid_hash(),
            "distinct git objects must not share observation OVIDs",
        );
        assert_eq!(
            translated.done_ledger().key().ovid_hash(),
            translated.ovid_hash(),
            "translation accessor should expose the repo-level done-ledger OVID",
        );
    }

    #[test]
    fn translate_git_item_result_rejects_zero_length_span() {
        let bad = git_finding(1, 30, 30, 0xAA);
        let repo_key = git_repo_key();
        let commit_oid_map = git_commit_oid_map();
        let err = translate_git_item_result(
            write_context(),
            &tenant_secret_key(),
            &repo_key,
            42,
            64,
            timing(),
            &[bad],
            &commit_oid_map,
            &test_rule_fingerprint,
        )
        .expect_err("zero-length git span must fail");
        assert!(matches!(
            err,
            ResultTranslationError::InvalidFindingSpan { .. }
        ));
    }

    #[test]
    fn translate_git_multiple_findings_with_distinct_identities() {
        let translated =
            translate_git_scanned(&[git_finding(1, 10, 20, 0xAA), git_finding(2, 30, 40, 0xBB)]);
        assert_eq!(translated.finding_count(), 2);
        assert_eq!(translated.occurrence_count(), 2);
        assert_eq!(translated.observation_count(), 2);
    }

    /// Verifies that [`PreHashedHasher`] extracts the first 8 bytes of the
    /// 32-byte payload written by `derive(Hash)` on `[u8; 32]` newtypes.
    ///
    /// If rustc changes how `derive(Hash)` calls the `Hasher` trait (e.g.,
    /// drops the length prefix write or reorders calls), this test will catch
    /// the regression before it silently degrades `HashSet` distribution in
    /// the translation pipeline.
    #[test]
    fn prehashed_hasher_extracts_first_payload_bytes() {
        use std::hash::BuildHasher;

        use gossip_contracts::identity::FindingId;

        use super::PreHashedBuildHasher;

        let bytes_a = [0xA1; 32];
        let bytes_b = [0xB2; 32];
        let id_a = FindingId::from_bytes(bytes_a);
        let id_b = FindingId::from_bytes(bytes_b);

        let ha = PreHashedBuildHasher.hash_one(id_a);
        let hb = PreHashedBuildHasher.hash_one(id_b);

        // Distinct IDs must produce distinct hashes.
        assert_ne!(ha, hb, "distinct FindingIds collapsed to the same hash");

        // The hash must equal the first 8 bytes of the inner [u8; 32],
        // interpreted as a native-endian u64.
        assert_eq!(
            ha,
            u64::from_ne_bytes([0xA1; 8]),
            "hash does not match first 8 bytes of payload"
        );
        assert_eq!(
            hb,
            u64::from_ne_bytes([0xB2; 8]),
            "hash does not match first 8 bytes of payload"
        );
    }
}
