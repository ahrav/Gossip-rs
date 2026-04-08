//! Durable stage checkpoints for Git scan resumption.
//!
//! The Git scan runner can persist stage-complete state at four boundaries:
//!
//! 1. post-commit-plan
//! 2. post-spill/dedup
//! 3. pack-plan-complete
//! 4. pre-finalize
//!
//! The public trait surface intentionally keeps the persistence backend opaque.
//! Callers load and store raw checkpoint blobs, while this module owns the
//! encoding and decoding of runner state.
//!
//! Checkpoint blobs are framed as `[magic: 4][crc32_le: 4][postcard payload]`
//! so resume loads can reject accidental corruption before deserializing state.

use gix_commitgraph::Position;
use serde::{Deserialize, Serialize};

use crate::byte_arena::{ByteArena, ByteRef};
use crate::commit_walk::PlannedCommit;
use crate::engine_adapter::{
    FindingKey, FindingSpan, GitScanCommonMetrics, ScannedBlob, ScannedBlobs, ScoredFinding,
};
use crate::mapping_bridge::MappingStats;
use crate::object_id::OidBytes;
use crate::pack_candidates::{LooseCandidate, PackCandidate};
use crate::repo_open::RepoArtifactFingerprint;
use crate::runner::{CandidateSkipReason, GitScanMode, SkippedCandidate};
use crate::spiller::SpillStats;
use crate::tree_candidate::{CandidateContext, ChangeKind};
use crate::tree_diff::TreeDiffStats;
use crate::NormHash;

/// Magic bytes that identify scanner-git checkpoint blobs.
///
/// Envelope layout: `[magic: 4 bytes][crc32_le: 4 bytes][postcard payload: N bytes]`.
const CHECKPOINT_MAGIC: [u8; 4] = *b"gkpt";

/// Size of the fixed checkpoint envelope prefix (see [`CHECKPOINT_MAGIC`]).
const CHECKPOINT_ENVELOPE_HEADER_LEN: usize = CHECKPOINT_MAGIC.len() + std::mem::size_of::<u32>();

/// Maximum checkpoint payload size accepted during deserialization (256 MiB).
///
/// Prevents a crafted blob from triggering unbounded allocation.
/// The limit applies to the postcard payload within the integrity envelope,
/// not to the total framed blob. The encode path logs an error when this limit
/// is exceeded but still returns the blob: the decode side discards oversize
/// blobs gracefully via `Ok(None)`, and persisting the blob is safer than
/// returning `None` (which the checkpoint sink interprets as "delete the
/// prefix key", erasing the last durable resume anchor).
const MAX_CHECKPOINT_BYTES: usize = 256 * 1024 * 1024;

/// Serialize a checkpoint value, logging an error if the payload exceeds the decode
/// limit.
///
/// Always returns the serialized bytes wrapped in the checkpoint integrity
/// envelope. The decode path in [`checkpoint_deserialize`] rejects oversize
/// payloads by returning an error (which `from_loaded` converts to `Ok(None)`,
/// restarting the scan fresh). Returning `None` here is deliberately avoided:
/// the checkpoint sink treats `None` as "delete the prefix key", which would
/// erase the last durable pack-plan frontier on large repos.
fn checkpoint_serialize<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, ScanCheckpointError> {
    let payload =
        postcard::to_allocvec(value).map_err(|err| ScanCheckpointError::Encode(err.to_string()))?;
    if payload.len() > MAX_CHECKPOINT_BYTES {
        tracing::error!(
            size = payload.len(),
            limit = MAX_CHECKPOINT_BYTES,
            dead_on_resume = true,
            "checkpoint payload exceeds size limit; blob will be persisted \
             but rejected on the next resume attempt, causing a full restart"
        );
    }

    let crc32 = crc32fast::hash(&payload);
    let mut encoded = Vec::with_capacity(CHECKPOINT_ENVELOPE_HEADER_LEN + payload.len());
    encoded.extend_from_slice(&CHECKPOINT_MAGIC);
    encoded.extend_from_slice(&crc32.to_le_bytes());
    encoded.extend_from_slice(&payload);
    Ok(encoded)
}

/// Deserialize a checkpoint blob with envelope integrity verification.
///
/// Verification order is: magic bytes, payload size guard, CRC32, then
/// postcard deserialization. The CRC32 guard detects accidental corruption
/// such as bit-rot, truncation, and format drift; it does not provide tamper
/// resistance. Uses strict-consume semantics (`from_bytes`) so that trailing
/// garbage causes a decode failure rather than being silently ignored. Per the
/// no-versioning rule, format changes update all readers/writers in one pass;
/// there is no forward-compatibility contract that would require tolerating
/// trailing bytes.
fn checkpoint_deserialize<'de, T: serde::Deserialize<'de>>(
    bytes: &'de [u8],
) -> Result<T, ScanCheckpointError> {
    if bytes.len() < CHECKPOINT_ENVELOPE_HEADER_LEN {
        return Err(ScanCheckpointError::Decode(format!(
            "checkpoint blob shorter than integrity envelope header ({CHECKPOINT_ENVELOPE_HEADER_LEN} bytes)"
        )));
    }
    if bytes[..CHECKPOINT_MAGIC.len()] != CHECKPOINT_MAGIC {
        return Err(ScanCheckpointError::Decode(
            "checkpoint blob magic mismatch".to_owned(),
        ));
    }

    let payload = &bytes[CHECKPOINT_ENVELOPE_HEADER_LEN..];
    if payload.len() > MAX_CHECKPOINT_BYTES {
        return Err(ScanCheckpointError::Decode(format!(
            "checkpoint payload exceeds size limit ({MAX_CHECKPOINT_BYTES} bytes)"
        )));
    }

    let stored_crc32 = u32::from_le_bytes(
        bytes[CHECKPOINT_MAGIC.len()..CHECKPOINT_ENVELOPE_HEADER_LEN]
            .try_into()
            .expect("checksum slice must match the fixed envelope width"),
    );
    let computed_crc32 = crc32fast::hash(payload);
    if stored_crc32 != computed_crc32 {
        return Err(ScanCheckpointError::Decode(format!(
            "checkpoint CRC mismatch (stored {stored_crc32:#010x}, computed {computed_crc32:#010x})"
        )));
    }

    postcard::from_bytes(payload).map_err(|err| ScanCheckpointError::Decode(err.to_string()))
}

/// Storage payloads returned by [`ScanCheckpointSink::load_resume_state`].
///
/// The three variants make orphaned prefixes (prefix present without a base)
/// structurally unrepresentable.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum LoadedScanCheckpoint {
    /// No durable checkpoint exists.
    #[default]
    Empty,
    /// Only the base-state blob exists (no prefix).
    BaseOnly {
        /// Durable base-state blob.
        base_state: Vec<u8>,
    },
    /// Both base-state and prefix-state blobs exist.
    BaseAndPrefix {
        /// Durable base-state blob.
        base_state: Vec<u8>,
        /// Durable prefix-state blob.
        prefix_state: Vec<u8>,
    },
}

/// Checkpoint sink control signal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckpointAck {
    /// Continue the scan.
    Continue,
    /// Stop after this checkpoint becomes durable.
    Abort,
}

/// Durable stage discriminant for Git scan checkpoints.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanCheckpointStage {
    /// Commit plan is durable.
    PostCommitPlan = 1,
    /// Candidate discovery and spill/dedup are durable.
    PostSpillDedup = 2,
    /// A clean contiguous prefix of pack plans is durable.
    PackPlanComplete = 3,
    /// Full scan output is durable and finalize can resume directly.
    PreFinalize = 4,
}

/// Stage discriminant restricted to stages that produce a durable prefix blob.
///
/// Only [`PackPlanComplete`](Self::PackPlanComplete) and
/// [`PreFinalize`](Self::PreFinalize) emit prefix state. This type makes the
/// constraint visible at compile time, eliminating dead match arms in
/// consumers.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PrefixStage {
    /// A clean contiguous prefix of pack plans is durable.
    PackPlanComplete = 3,
    /// Full scan output is durable and finalize can resume directly.
    PreFinalize = 4,
}

impl From<PrefixStage> for ScanCheckpointStage {
    fn from(value: PrefixStage) -> Self {
        match value {
            PrefixStage::PackPlanComplete => Self::PackPlanComplete,
            PrefixStage::PreFinalize => Self::PreFinalize,
        }
    }
}

impl ScanCheckpointStage {
    /// Stable numeric encoding for cursor tokens.
    #[inline]
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Checkpoint load/store errors surfaced by the runner.
#[derive(Debug, thiserror::Error)]
pub enum ScanCheckpointError {
    /// Checkpoint encoding failed.
    #[error("checkpoint encoding failed: {0}")]
    Encode(String),
    /// Checkpoint decoding failed.
    #[error("checkpoint decoding failed: {0}")]
    Decode(String),
    /// Backend persistence failed.
    #[error("checkpoint backend failed: {0}")]
    Backend(String),
    /// Loaded state was internally inconsistent.
    #[error("checkpoint state invalid: {0}")]
    InvalidState(String),
}

impl ScanCheckpointError {
    /// Construct a backend error from a displayable message.
    #[must_use]
    pub fn backend(detail: impl Into<String>) -> Self {
        Self::Backend(detail.into())
    }
}

/// Mandatory checkpoint sink contract for stage-gated Git scan durability.
///
/// Non-distributed callers use [`NoopCheckpointSink`], which disables loading
/// and discards all notifications.
pub trait ScanCheckpointSink {
    /// Whether the runner should emit intermediate durable checkpoints.
    ///
    /// Distributed sinks return `true`, which enables per-stage resume state.
    /// [`NoopCheckpointSink`] returns `false` so local callers can keep the
    /// existing batch execution path without checkpoint overhead.
    fn checkpoints_enabled(&self) -> bool {
        true
    }

    /// Load the most recent durable checkpoint payloads for this scan scope.
    fn load_resume_state(&self) -> Result<LoadedScanCheckpoint, ScanCheckpointError>;

    /// Persist one stage-complete checkpoint.
    ///
    /// The implementation must ensure atomicity between the base-state and
    /// prefix-state blobs produced by
    /// [`StageCheckpoint::encode_base_state`] and
    /// [`StageCheckpoint::encode_prefix_state`]:
    ///
    /// - When `encode_base_state` returns `Some` and `encode_prefix_state`
    ///   returns `None`, the base blob must be stored and any prior prefix
    ///   blob must be deleted in the same atomic batch.
    /// - When `encode_base_state` returns `None` and `encode_prefix_state`
    ///   returns `Some`, the prefix blob must be stored alongside the
    ///   existing base blob; a partial write that persists the prefix
    ///   without the base creates an unrecoverable orphan.
    /// - If the backend does not support atomic multi-key writes, the
    ///   implementation should apply prefix ops before base ops. For
    ///   base-only stages the prefix op is a delete: a crash after the
    ///   delete but before the base write leaves "no prefix + old base",
    ///   which is a valid earlier checkpoint. For prefix-only stages the
    ///   prefix is written first while the base is unchanged, so no crash
    ///   window exists. This ordering ensures the worst case is always a
    ///   valid, less-advanced state rather than an orphaned prefix.
    fn notify_stage_complete(
        &self,
        checkpoint: &StageCheckpoint<'_>,
    ) -> Result<CheckpointAck, ScanCheckpointError>;
}

/// No-op checkpoint sink used when stage checkpointing is disabled.
#[derive(Default)]
pub struct NoopCheckpointSink;

impl ScanCheckpointSink for NoopCheckpointSink {
    fn checkpoints_enabled(&self) -> bool {
        false
    }

    fn load_resume_state(&self) -> Result<LoadedScanCheckpoint, ScanCheckpointError> {
        Ok(LoadedScanCheckpoint::default())
    }

    fn notify_stage_complete(
        &self,
        _checkpoint: &StageCheckpoint<'_>,
    ) -> Result<CheckpointAck, ScanCheckpointError> {
        Ok(CheckpointAck::Continue)
    }
}

/// Borrowed stage-complete state emitted by the runner.
pub enum StageCheckpoint<'a> {
    /// Commit plan is durable.
    PostCommitPlan {
        scan_mode: GitScanMode,
        artifact_fingerprint: &'a RepoArtifactFingerprint,
        plan: &'a [PlannedCommit],
    },
    /// Candidate discovery output is durable.
    PostSpillDedup {
        scan_mode: GitScanMode,
        artifact_fingerprint: &'a RepoArtifactFingerprint,
        plan: &'a [PlannedCommit],
        packed: &'a [PackCandidate],
        loose: &'a [LooseCandidate],
        path_arena: &'a ByteArena,
        tree_diff_stats: TreeDiffStats,
        spill_stats: SpillStats,
        mapping_stats: MappingStats,
    },
    /// A clean contiguous pack-plan prefix is durable.
    PackPlanComplete {
        scan_mode: GitScanMode,
        artifact_fingerprint: &'a RepoArtifactFingerprint,
        plan: &'a [PlannedCommit],
        packed: &'a [PackCandidate],
        loose: &'a [LooseCandidate],
        path_arena: &'a ByteArena,
        tree_diff_stats: TreeDiffStats,
        spill_stats: SpillStats,
        mapping_stats: MappingStats,
        completed_plan_count: usize,
        scanned: &'a ScannedBlobs,
        skipped_candidates: &'a [SkippedCandidate],
        common_metrics: GitScanCommonMetrics,
    },
    /// Full scan output is durable and finalize can resume directly.
    PreFinalize {
        scan_mode: GitScanMode,
        artifact_fingerprint: &'a RepoArtifactFingerprint,
        plan: &'a [PlannedCommit],
        packed: &'a [PackCandidate],
        loose: &'a [LooseCandidate],
        path_arena: &'a ByteArena,
        tree_diff_stats: TreeDiffStats,
        spill_stats: SpillStats,
        mapping_stats: MappingStats,
        completed_plan_count: usize,
        scanned: &'a ScannedBlobs,
        skipped_candidates: &'a [SkippedCandidate],
        common_metrics: GitScanCommonMetrics,
    },
}

impl StageCheckpoint<'_> {
    /// Stage discriminant for this checkpoint.
    #[must_use]
    pub const fn stage(&self) -> ScanCheckpointStage {
        match self {
            Self::PostCommitPlan { .. } => ScanCheckpointStage::PostCommitPlan,
            Self::PostSpillDedup { .. } => ScanCheckpointStage::PostSpillDedup,
            Self::PackPlanComplete { .. } => ScanCheckpointStage::PackPlanComplete,
            Self::PreFinalize { .. } => ScanCheckpointStage::PreFinalize,
        }
    }

    /// Encode the checkpoint's base-state payload, if it changes at this stage.
    pub fn encode_base_state(&self) -> Result<Option<Vec<u8>>, ScanCheckpointError> {
        match self {
            Self::PostCommitPlan {
                scan_mode,
                artifact_fingerprint,
                plan,
            } => {
                let encoded =
                    checkpoint_serialize(&StoredBaseState::CommitPlan(StoredCommitPlanState {
                        scan_mode: StoredGitScanMode::from(*scan_mode),
                        artifact_fingerprint: StoredRepoArtifactFingerprint::from(
                            *artifact_fingerprint,
                        ),
                        plan: plan
                            .iter()
                            .copied()
                            .map(StoredPlannedCommit::from)
                            .collect(),
                    }))?;
                Ok(Some(encoded))
            }
            Self::PostSpillDedup {
                scan_mode,
                artifact_fingerprint,
                plan,
                packed,
                loose,
                path_arena,
                tree_diff_stats,
                spill_stats,
                mapping_stats,
            } => {
                let encoded =
                    checkpoint_serialize(&StoredBaseState::SpillDedup(StoredSpillDedupState {
                        scan_mode: StoredGitScanMode::from(*scan_mode),
                        artifact_fingerprint: StoredRepoArtifactFingerprint::from(
                            *artifact_fingerprint,
                        ),
                        plan: plan
                            .iter()
                            .copied()
                            .map(StoredPlannedCommit::from)
                            .collect(),
                        packed: packed
                            .iter()
                            .copied()
                            .map(StoredPackCandidate::from)
                            .collect(),
                        loose: loose
                            .iter()
                            .copied()
                            .map(StoredLooseCandidate::from)
                            .collect(),
                        path_arena: path_arena.backing_bytes().to_vec(),
                        tree_diff_stats: StoredTreeDiffStats::from(tree_diff_stats.clone()),
                        spill_stats: StoredSpillStats::from(spill_stats.clone()),
                        mapping_stats: StoredMappingStats::from(*mapping_stats),
                    }))?;
                Ok(Some(encoded))
            }
            Self::PackPlanComplete { .. } | Self::PreFinalize { .. } => Ok(None),
        }
    }

    /// Encode the checkpoint's prefix-state payload, if any.
    pub fn encode_prefix_state(&self) -> Result<Option<Vec<u8>>, ScanCheckpointError> {
        match self {
            Self::PostCommitPlan { .. } | Self::PostSpillDedup { .. } => Ok(None),
            Self::PackPlanComplete {
                completed_plan_count,
                scanned,
                skipped_candidates,
                common_metrics,
                ..
            }
            | Self::PreFinalize {
                completed_plan_count,
                scanned,
                skipped_candidates,
                common_metrics,
                ..
            } => {
                let completed_plan_count = u32::try_from(*completed_plan_count).map_err(|_| {
                    ScanCheckpointError::Encode("completed_plan_count exceeds u32::MAX".to_owned())
                })?;
                let encoded = checkpoint_serialize(&StoredPrefixState {
                    stage: self.stage(),
                    completed_plan_count,
                    scanned: StoredScannedBlobs::from(*scanned),
                    skipped_candidates: skipped_candidates
                        .iter()
                        .copied()
                        .map(StoredSkippedCandidate::from)
                        .collect(),
                    common_metrics: StoredGitScanCommonMetrics::from(*common_metrics),
                })?;
                Ok(Some(encoded))
            }
        }
    }

    /// Encode a compact cursor token for repo-frontier resume tracking.
    pub fn resume_token(&self) -> Result<Vec<u8>, ScanCheckpointError> {
        let completed_plan_count = match self {
            Self::PackPlanComplete {
                completed_plan_count,
                ..
            }
            | Self::PreFinalize {
                completed_plan_count,
                ..
            } => u32::try_from(*completed_plan_count).map_err(|_| {
                ScanCheckpointError::Encode("completed_plan_count exceeds u32::MAX".to_owned())
            })?,
            Self::PostCommitPlan { .. } | Self::PostSpillDedup { .. } => 0,
        };

        let mut token = Vec::with_capacity(9);
        token.extend_from_slice(b"gcp\0");
        token.push(self.stage().as_u8());
        token.extend_from_slice(&completed_plan_count.to_le_bytes());
        Ok(token)
    }
}

/// Validate OID lengths and path-arena bounds for deserialized base-state
/// candidates before infallible `From` conversion.
fn validate_stored_base_candidates(
    packed: &[StoredPackCandidate],
    loose: &[StoredLooseCandidate],
    arena_len: u32,
) -> Result<(), ScanCheckpointError> {
    for (i, cand) in packed.iter().enumerate() {
        validate_stored_oid(&cand.oid, "packed candidate", i)?;
        validate_stored_byte_ref(&cand.ctx.path_ref, arena_len, "packed candidate", i)?;
    }
    for (i, cand) in loose.iter().enumerate() {
        validate_stored_oid(&cand.oid, "loose candidate", i)?;
        validate_stored_byte_ref(&cand.ctx.path_ref, arena_len, "loose candidate", i)?;
    }
    Ok(())
}

/// Validate OID lengths, finding-arena bounds, path-arena bounds, and
/// skipped-candidate OIDs for a deserialized prefix state.
///
/// `path_arena_len` is the length of the base state's path arena, which
/// prefix `ScannedBlob` entries reference via `ctx.path_ref`.
fn validate_stored_prefix(
    prefix: &StoredPrefixState,
    path_arena_len: u32,
) -> Result<(), ScanCheckpointError> {
    let finding_arena_len = prefix.scanned.finding_arena.len();
    for (i, blob) in prefix.scanned.blobs.iter().enumerate() {
        validate_stored_oid(&blob.oid, "scanned blob", i)?;
        validate_stored_byte_ref(&blob.ctx.path_ref, path_arena_len, "scanned blob", i)?;
        let end = blob
            .findings
            .start
            .checked_add(blob.findings.len)
            .ok_or_else(|| {
                ScanCheckpointError::InvalidState(format!(
                    "scanned blob {i}: FindingSpan start + len overflows u32"
                ))
            })?;
        if end as usize > finding_arena_len {
            return Err(ScanCheckpointError::InvalidState(format!(
                "scanned blob {i}: FindingSpan [{}, {end}) exceeds finding_arena length {finding_arena_len}",
                blob.findings.start,
            )));
        }
    }
    for (i, skip) in prefix.skipped_candidates.iter().enumerate() {
        validate_stored_oid(&skip.oid, "skipped candidate", i)?;
    }
    Ok(())
}

fn validate_stored_oid(
    oid: &StoredOidBytes,
    ctx: &str,
    index: usize,
) -> Result<(), ScanCheckpointError> {
    if oid.len != 20 && oid.len != 32 {
        return Err(ScanCheckpointError::InvalidState(format!(
            "{ctx} {index}: invalid OID length {}",
            oid.len,
        )));
    }
    Ok(())
}

fn validate_stored_byte_ref(
    r: &StoredByteRef,
    arena_len: u32,
    ctx: &str,
    index: usize,
) -> Result<(), ScanCheckpointError> {
    let end = r.off.checked_add(u32::from(r.len)).ok_or_else(|| {
        ScanCheckpointError::InvalidState(format!("{ctx} {index}: ByteRef off + len overflows u32"))
    })?;
    if end > arena_len {
        return Err(ScanCheckpointError::InvalidState(format!(
            "{ctx} {index}: ByteRef [{}, {end}) exceeds arena length {arena_len}",
            r.off,
        )));
    }
    Ok(())
}

/// Deserialized resume state produced by [`from_loaded`](Self::from_loaded).
///
/// Each variant corresponds to one of the four checkpoint stages and carries
/// the validated, owned data needed to resume a scan from that point.
#[derive(Clone, Debug)]
pub enum ScanResumeState {
    PostCommitPlan(CommitPlanResumeState),
    PostSpillDedup(ScanResumeBaseState),
    PackPlanComplete {
        base: ScanResumeBaseState,
        prefix: ScanResumePrefixState,
    },
    PreFinalize {
        base: ScanResumeBaseState,
        prefix: ScanResumePrefixState,
    },
}

impl ScanResumeState {
    /// Decode and validate a durable checkpoint into resume state.
    ///
    /// Returns `Ok(None)` when the checkpoint should be discarded: empty
    /// input, envelope verification failure, decode failure, stale scan mode,
    /// or artifact fingerprint mismatch. Returns `Err` for structural
    /// validation failures (bad OID lengths, out-of-bounds arena refs, invalid
    /// stage discriminator, impossible `completed_plan_count`).
    pub fn from_loaded(
        loaded: LoadedScanCheckpoint,
        scan_mode: GitScanMode,
        artifact_fingerprint: &RepoArtifactFingerprint,
    ) -> Result<Option<Self>, ScanCheckpointError> {
        let (base_state, prefix_state) = match loaded {
            LoadedScanCheckpoint::Empty => return Ok(None),
            LoadedScanCheckpoint::BaseOnly { base_state } => (base_state, None),
            LoadedScanCheckpoint::BaseAndPrefix {
                base_state,
                prefix_state,
            } => (base_state, Some(prefix_state)),
        };

        let base: StoredBaseState = match checkpoint_deserialize(&base_state) {
            Ok(e) => e,
            Err(err) => {
                tracing::warn!("checkpoint base decode failed, restarting fresh: {err}");
                return Ok(None);
            }
        };
        match base {
            StoredBaseState::CommitPlan(base) => {
                if GitScanMode::from(base.scan_mode) != scan_mode
                    || RepoArtifactFingerprint::from(base.artifact_fingerprint.clone())
                        != *artifact_fingerprint
                {
                    return Ok(None);
                }
                if prefix_state.is_some() {
                    return Err(ScanCheckpointError::InvalidState(
                        "commit-plan checkpoint cannot carry a prefix payload".to_owned(),
                    ));
                }
                Ok(Some(Self::PostCommitPlan(CommitPlanResumeState {
                    plan: base.plan.into_iter().map(PlannedCommit::from).collect(),
                })))
            }
            StoredBaseState::SpillDedup(base) => {
                if GitScanMode::from(base.scan_mode) != scan_mode
                    || RepoArtifactFingerprint::from(base.artifact_fingerprint.clone())
                        != *artifact_fingerprint
                {
                    if prefix_state.is_some() {
                        tracing::debug!(
                            "discarding stale prefix checkpoint alongside mismatched base state"
                        );
                    }
                    return Ok(None);
                }

                // Validate deserialized fields before conversion so that
                // downstream From impls (which use debug_assert-only checks)
                // never encounter out-of-range values in release builds.
                let arena_len = u32::try_from(base.path_arena.len()).map_err(|_| {
                    ScanCheckpointError::InvalidState(
                        "path arena exceeds u32 address space".to_owned(),
                    )
                })?;
                validate_stored_base_candidates(&base.packed, &base.loose, arena_len)?;

                let base = ScanResumeBaseState {
                    plan: base.plan.into_iter().map(PlannedCommit::from).collect(),
                    packed: base.packed.into_iter().map(PackCandidate::from).collect(),
                    loose: base.loose.into_iter().map(LooseCandidate::from).collect(),
                    path_arena: ByteArena::from_backing_bytes(base.path_arena),
                    tree_diff_stats: base.tree_diff_stats.into(),
                    spill_stats: base.spill_stats.into(),
                    mapping_stats: base.mapping_stats.into(),
                };

                let Some(prefix_state) = prefix_state else {
                    return Ok(Some(Self::PostSpillDedup(base)));
                };
                let prefix: StoredPrefixState = match checkpoint_deserialize(&prefix_state) {
                    Ok(e) => e,
                    Err(err) => {
                        tracing::warn!(
                            "checkpoint prefix decode failed, resuming from base only: {err}"
                        );
                        return Ok(Some(Self::PostSpillDedup(base)));
                    }
                };

                validate_stored_prefix(&prefix, arena_len)?;

                let prefix_stage = match prefix.stage {
                    ScanCheckpointStage::PackPlanComplete => PrefixStage::PackPlanComplete,
                    ScanCheckpointStage::PreFinalize => PrefixStage::PreFinalize,
                    _ => {
                        return Err(ScanCheckpointError::InvalidState(
                            "prefix checkpoint has an invalid stage discriminator".to_owned(),
                        ));
                    }
                };

                let packed_candidate_count = base.packed.len();
                // Pack plans are rebuilt by grouping packed candidates by
                // `pack_id`, so a durable prefix can never cover more pack
                // plans than there are packed candidates even when multiple
                // candidates collapse into the same rebuilt plan.
                if (prefix.completed_plan_count as usize) > packed_candidate_count {
                    return Err(ScanCheckpointError::InvalidState(format!(
                        "completed_plan_count ({}) exceeds packed candidate count ({packed_candidate_count})",
                        prefix.completed_plan_count,
                    )));
                }

                let prefix = ScanResumePrefixState {
                    stage: prefix_stage,
                    completed_plan_count: prefix.completed_plan_count as usize,
                    scanned: prefix.scanned.into(),
                    skipped_candidates: prefix
                        .skipped_candidates
                        .into_iter()
                        .map(SkippedCandidate::from)
                        .collect(),
                    common_metrics: prefix.common_metrics.into(),
                };

                match prefix.stage {
                    PrefixStage::PackPlanComplete => {
                        Ok(Some(Self::PackPlanComplete { base, prefix }))
                    }
                    PrefixStage::PreFinalize => Ok(Some(Self::PreFinalize { base, prefix })),
                }
            }
        }
    }

    #[must_use]
    pub(crate) fn plan(&self) -> &[PlannedCommit] {
        match self {
            Self::PostCommitPlan(state) => &state.plan,
            Self::PostSpillDedup(state) => &state.plan,
            Self::PackPlanComplete { base, .. } | Self::PreFinalize { base, .. } => &base.plan,
        }
    }

    /// Split resume state into its constituent parts, consuming the value.
    ///
    /// Returns `(stage, base_state, prefix_state)` where base and prefix are
    /// moved out without cloning, which matters when the inner fields are
    /// multi-MiB candidate vectors.
    pub(crate) fn into_parts(
        self,
    ) -> (
        ScanCheckpointStage,
        Option<ScanResumeBaseState>,
        Option<ScanResumePrefixState>,
    ) {
        match self {
            Self::PostCommitPlan(_state) => {
                // The commit plan is already threaded into the mode pipelines
                // by `run_git_scan_with_context`; returning `None` for the base
                // forces the runners to run full candidate generation (tree diff,
                // spill/dedup) rather than skipping it with empty vectors.
                (ScanCheckpointStage::PostCommitPlan, None, None)
            }
            Self::PostSpillDedup(base) => (ScanCheckpointStage::PostSpillDedup, Some(base), None),
            Self::PackPlanComplete { base, prefix } => (
                ScanCheckpointStage::PackPlanComplete,
                Some(base),
                Some(prefix),
            ),
            Self::PreFinalize { base, prefix } => {
                (ScanCheckpointStage::PreFinalize, Some(base), Some(prefix))
            }
        }
    }
}

/// Early-stage resume state carrying only the commit plan.
#[derive(Clone, Debug)]
pub struct CommitPlanResumeState {
    pub plan: Vec<PlannedCommit>,
}

/// Base resume state from the `PostSpillDedup` stage, carrying the full
/// candidate set and associated statistics.
#[derive(Clone, Debug)]
pub struct ScanResumeBaseState {
    pub plan: Vec<PlannedCommit>,
    pub packed: Vec<PackCandidate>,
    pub loose: Vec<LooseCandidate>,
    pub path_arena: ByteArena,
    pub tree_diff_stats: TreeDiffStats,
    pub spill_stats: SpillStats,
    pub mapping_stats: MappingStats,
}

/// Incremental pack-plan execution progress from a prefix-carrying stage.
#[derive(Clone, Debug)]
pub struct ScanResumePrefixState {
    pub stage: PrefixStage,
    pub completed_plan_count: usize,
    pub scanned: ScannedBlobs,
    pub skipped_candidates: Vec<SkippedCandidate>,
    pub common_metrics: GitScanCommonMetrics,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
enum StoredBaseState {
    CommitPlan(StoredCommitPlanState),
    SpillDedup(StoredSpillDedupState),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredCommitPlanState {
    scan_mode: StoredGitScanMode,
    artifact_fingerprint: StoredRepoArtifactFingerprint,
    plan: Vec<StoredPlannedCommit>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredSpillDedupState {
    scan_mode: StoredGitScanMode,
    artifact_fingerprint: StoredRepoArtifactFingerprint,
    plan: Vec<StoredPlannedCommit>,
    packed: Vec<StoredPackCandidate>,
    loose: Vec<StoredLooseCandidate>,
    path_arena: Vec<u8>,
    tree_diff_stats: StoredTreeDiffStats,
    spill_stats: StoredSpillStats,
    mapping_stats: StoredMappingStats,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredPrefixState {
    stage: ScanCheckpointStage,
    completed_plan_count: u32,
    scanned: StoredScannedBlobs,
    skipped_candidates: Vec<StoredSkippedCandidate>,
    common_metrics: StoredGitScanCommonMetrics,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
enum StoredGitScanMode {
    DiffHistory,
    OdbBlobFast,
}

impl From<GitScanMode> for StoredGitScanMode {
    fn from(value: GitScanMode) -> Self {
        match value {
            GitScanMode::DiffHistory => Self::DiffHistory,
            GitScanMode::OdbBlobFast => Self::OdbBlobFast,
        }
    }
}

impl From<StoredGitScanMode> for GitScanMode {
    fn from(value: StoredGitScanMode) -> Self {
        match value {
            StoredGitScanMode::DiffHistory => Self::DiffHistory,
            StoredGitScanMode::OdbBlobFast => Self::OdbBlobFast,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredRepoArtifactFingerprint {
    packs_hash: [u8; 32],
    idx_hash: [u8; 32],
}

impl From<&RepoArtifactFingerprint> for StoredRepoArtifactFingerprint {
    fn from(value: &RepoArtifactFingerprint) -> Self {
        Self {
            packs_hash: value.packs_hash,
            idx_hash: value.idx_hash,
        }
    }
}

impl From<StoredRepoArtifactFingerprint> for RepoArtifactFingerprint {
    fn from(value: StoredRepoArtifactFingerprint) -> Self {
        Self {
            packs_hash: value.packs_hash,
            idx_hash: value.idx_hash,
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct StoredPlannedCommit {
    pos: u32,
    snapshot_root: bool,
}

impl From<PlannedCommit> for StoredPlannedCommit {
    fn from(value: PlannedCommit) -> Self {
        Self {
            pos: value.pos.0,
            snapshot_root: value.snapshot_root,
        }
    }
}

impl From<StoredPlannedCommit> for PlannedCommit {
    fn from(value: StoredPlannedCommit) -> Self {
        Self {
            pos: Position(value.pos),
            snapshot_root: value.snapshot_root,
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
enum StoredChangeKind {
    Add,
    Modify,
}

impl From<ChangeKind> for StoredChangeKind {
    fn from(value: ChangeKind) -> Self {
        match value {
            ChangeKind::Add => Self::Add,
            ChangeKind::Modify => Self::Modify,
        }
    }
}

impl From<StoredChangeKind> for ChangeKind {
    fn from(value: StoredChangeKind) -> Self {
        match value {
            StoredChangeKind::Add => Self::Add,
            StoredChangeKind::Modify => Self::Modify,
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct StoredByteRef {
    off: u32,
    len: u16,
}

impl From<ByteRef> for StoredByteRef {
    fn from(value: ByteRef) -> Self {
        Self {
            off: value.off,
            len: value.len,
        }
    }
}

impl From<StoredByteRef> for ByteRef {
    fn from(value: StoredByteRef) -> Self {
        Self::new(value.off, value.len)
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct StoredCandidateContext {
    commit_id: u32,
    parent_idx: u8,
    change_kind: StoredChangeKind,
    ctx_flags: u16,
    cand_flags: u16,
    path_ref: StoredByteRef,
}

impl From<CandidateContext> for StoredCandidateContext {
    fn from(value: CandidateContext) -> Self {
        Self {
            commit_id: value.commit_id,
            parent_idx: value.parent_idx,
            change_kind: value.change_kind.into(),
            ctx_flags: value.ctx_flags,
            cand_flags: value.cand_flags,
            path_ref: value.path_ref.into(),
        }
    }
}

impl From<StoredCandidateContext> for CandidateContext {
    fn from(value: StoredCandidateContext) -> Self {
        Self {
            commit_id: value.commit_id,
            parent_idx: value.parent_idx,
            change_kind: value.change_kind.into(),
            ctx_flags: value.ctx_flags,
            cand_flags: value.cand_flags,
            path_ref: value.path_ref.into(),
        }
    }
}

/// Fixed-size OID storage that avoids per-OID heap allocation.
///
/// `OidBytes` is `(u8 len, [u8; 32])` — always 33 bytes. Storing the raw
/// layout avoids one `Vec<u8>` allocation per candidate during checkpoint
/// encoding. For SHA-1 OIDs the trailing 12 bytes are zeroed by
/// construction.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct StoredOidBytes {
    len: u8,
    bytes: [u8; 32],
}

impl From<OidBytes> for StoredOidBytes {
    #[inline]
    fn from(value: OidBytes) -> Self {
        Self {
            len: value.len(),
            bytes: value.raw_bytes(),
        }
    }
}

impl From<StoredOidBytes> for OidBytes {
    #[inline]
    fn from(value: StoredOidBytes) -> Self {
        OidBytes::from_raw(value.len, value.bytes)
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct StoredPackCandidate {
    oid: StoredOidBytes,
    ctx: StoredCandidateContext,
    pack_id: u16,
    offset: u64,
}

impl From<PackCandidate> for StoredPackCandidate {
    fn from(value: PackCandidate) -> Self {
        Self {
            oid: value.oid.into(),
            ctx: value.ctx.into(),
            pack_id: value.pack_id,
            offset: value.offset,
        }
    }
}

impl From<StoredPackCandidate> for PackCandidate {
    fn from(value: StoredPackCandidate) -> Self {
        Self {
            oid: value.oid.into(),
            ctx: value.ctx.into(),
            pack_id: value.pack_id,
            offset: value.offset,
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct StoredLooseCandidate {
    oid: StoredOidBytes,
    ctx: StoredCandidateContext,
}

impl From<LooseCandidate> for StoredLooseCandidate {
    fn from(value: LooseCandidate) -> Self {
        Self {
            oid: value.oid.into(),
            ctx: value.ctx.into(),
        }
    }
}

impl From<StoredLooseCandidate> for LooseCandidate {
    fn from(value: StoredLooseCandidate) -> Self {
        Self {
            oid: value.oid.into(),
            ctx: value.ctx.into(),
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct StoredTreeDiffStats {
    trees_loaded: u64,
    tree_bytes_loaded: u64,
    tree_bytes_in_flight_peak: u64,
    candidates_emitted: u64,
    subtrees_skipped: u64,
    max_depth_reached: u16,
}

impl From<TreeDiffStats> for StoredTreeDiffStats {
    fn from(value: TreeDiffStats) -> Self {
        Self {
            trees_loaded: value.trees_loaded,
            tree_bytes_loaded: value.tree_bytes_loaded,
            tree_bytes_in_flight_peak: value.tree_bytes_in_flight_peak,
            candidates_emitted: value.candidates_emitted,
            subtrees_skipped: value.subtrees_skipped,
            max_depth_reached: value.max_depth_reached,
        }
    }
}

impl From<StoredTreeDiffStats> for TreeDiffStats {
    fn from(value: StoredTreeDiffStats) -> Self {
        Self {
            trees_loaded: value.trees_loaded,
            tree_bytes_loaded: value.tree_bytes_loaded,
            tree_bytes_in_flight_peak: value.tree_bytes_in_flight_peak,
            candidates_emitted: value.candidates_emitted,
            subtrees_skipped: value.subtrees_skipped,
            max_depth_reached: value.max_depth_reached,
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct StoredSpillStats {
    candidates_received: u64,
    unique_blobs: u64,
    spill_runs: u64,
    spill_bytes: u64,
    seen_blobs: u64,
    emitted_blobs: u64,
}

impl From<SpillStats> for StoredSpillStats {
    fn from(value: SpillStats) -> Self {
        Self {
            candidates_received: value.candidates_received,
            unique_blobs: value.unique_blobs,
            spill_runs: value.spill_runs as u64,
            spill_bytes: value.spill_bytes,
            seen_blobs: value.seen_blobs,
            emitted_blobs: value.emitted_blobs,
        }
    }
}

impl From<StoredSpillStats> for SpillStats {
    fn from(value: StoredSpillStats) -> Self {
        Self {
            candidates_received: value.candidates_received,
            unique_blobs: value.unique_blobs,
            spill_runs: value.spill_runs.try_into().unwrap_or(usize::MAX),
            spill_bytes: value.spill_bytes,
            seen_blobs: value.seen_blobs,
            emitted_blobs: value.emitted_blobs,
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct StoredMappingStats {
    unique_blobs_in: u64,
    packed_matched: u64,
    loose_unmatched: u64,
}

impl From<MappingStats> for StoredMappingStats {
    fn from(value: MappingStats) -> Self {
        Self {
            unique_blobs_in: value.unique_blobs_in,
            packed_matched: value.packed_matched,
            loose_unmatched: value.loose_unmatched,
        }
    }
}

impl From<StoredMappingStats> for MappingStats {
    fn from(value: StoredMappingStats) -> Self {
        Self {
            unique_blobs_in: value.unique_blobs_in,
            packed_matched: value.packed_matched,
            loose_unmatched: value.loose_unmatched,
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct StoredFindingKey {
    start: u32,
    end: u32,
    rule_id: u32,
    norm_hash: NormHash,
}

impl From<FindingKey> for StoredFindingKey {
    fn from(value: FindingKey) -> Self {
        Self {
            start: value.start,
            end: value.end,
            rule_id: value.rule_id,
            norm_hash: value.norm_hash,
        }
    }
}

impl From<StoredFindingKey> for FindingKey {
    fn from(value: StoredFindingKey) -> Self {
        Self {
            start: value.start,
            end: value.end,
            rule_id: value.rule_id,
            norm_hash: value.norm_hash,
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct StoredScoredFinding {
    key: StoredFindingKey,
    confidence_score: i8,
}

impl From<ScoredFinding> for StoredScoredFinding {
    fn from(value: ScoredFinding) -> Self {
        Self {
            key: value.key.into(),
            confidence_score: value.confidence_score,
        }
    }
}

impl From<StoredScoredFinding> for ScoredFinding {
    fn from(value: StoredScoredFinding) -> Self {
        Self {
            key: value.key.into(),
            confidence_score: value.confidence_score,
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct StoredFindingSpan {
    start: u32,
    len: u32,
}

impl From<FindingSpan> for StoredFindingSpan {
    fn from(value: FindingSpan) -> Self {
        Self {
            start: value.start,
            len: value.len,
        }
    }
}

impl From<StoredFindingSpan> for FindingSpan {
    fn from(value: StoredFindingSpan) -> Self {
        Self {
            start: value.start,
            len: value.len,
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct StoredScannedBlob {
    oid: StoredOidBytes,
    ctx: StoredCandidateContext,
    findings: StoredFindingSpan,
}

impl From<ScannedBlob> for StoredScannedBlob {
    fn from(value: ScannedBlob) -> Self {
        Self {
            oid: value.oid.into(),
            ctx: value.ctx.into(),
            findings: value.findings.into(),
        }
    }
}

impl From<StoredScannedBlob> for ScannedBlob {
    fn from(value: StoredScannedBlob) -> Self {
        Self {
            oid: value.oid.into(),
            ctx: value.ctx.into(),
            findings: value.findings.into(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredScannedBlobs {
    blobs: Vec<StoredScannedBlob>,
    finding_arena: Vec<StoredScoredFinding>,
}

impl From<&ScannedBlobs> for StoredScannedBlobs {
    fn from(value: &ScannedBlobs) -> Self {
        Self {
            blobs: value
                .blobs
                .iter()
                .cloned()
                .map(StoredScannedBlob::from)
                .collect(),
            finding_arena: value
                .finding_arena
                .iter()
                .copied()
                .map(StoredScoredFinding::from)
                .collect(),
        }
    }
}

impl From<StoredScannedBlobs> for ScannedBlobs {
    fn from(value: StoredScannedBlobs) -> Self {
        Self {
            blobs: value.blobs.into_iter().map(ScannedBlob::from).collect(),
            finding_arena: value
                .finding_arena
                .into_iter()
                .map(ScoredFinding::from)
                .collect(),
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
enum StoredCandidateSkipReason {
    LooseMissing,
    LooseDecode,
    LooseNotBlob,
    PackNotBlob,
    PackDecode,
    PackDelta,
    PackBaseMissing,
    PackExternalBaseMissing,
    PackExternalBaseError,
    PackParse,
}

impl From<CandidateSkipReason> for StoredCandidateSkipReason {
    fn from(value: CandidateSkipReason) -> Self {
        match value {
            CandidateSkipReason::LooseMissing => Self::LooseMissing,
            CandidateSkipReason::LooseDecode => Self::LooseDecode,
            CandidateSkipReason::LooseNotBlob => Self::LooseNotBlob,
            CandidateSkipReason::PackNotBlob => Self::PackNotBlob,
            CandidateSkipReason::PackDecode => Self::PackDecode,
            CandidateSkipReason::PackDelta => Self::PackDelta,
            CandidateSkipReason::PackBaseMissing => Self::PackBaseMissing,
            CandidateSkipReason::PackExternalBaseMissing => Self::PackExternalBaseMissing,
            CandidateSkipReason::PackExternalBaseError => Self::PackExternalBaseError,
            CandidateSkipReason::PackParse => Self::PackParse,
        }
    }
}

impl From<StoredCandidateSkipReason> for CandidateSkipReason {
    fn from(value: StoredCandidateSkipReason) -> Self {
        match value {
            StoredCandidateSkipReason::LooseMissing => Self::LooseMissing,
            StoredCandidateSkipReason::LooseDecode => Self::LooseDecode,
            StoredCandidateSkipReason::LooseNotBlob => Self::LooseNotBlob,
            StoredCandidateSkipReason::PackNotBlob => Self::PackNotBlob,
            StoredCandidateSkipReason::PackDecode => Self::PackDecode,
            StoredCandidateSkipReason::PackDelta => Self::PackDelta,
            StoredCandidateSkipReason::PackBaseMissing => Self::PackBaseMissing,
            StoredCandidateSkipReason::PackExternalBaseMissing => Self::PackExternalBaseMissing,
            StoredCandidateSkipReason::PackExternalBaseError => Self::PackExternalBaseError,
            StoredCandidateSkipReason::PackParse => Self::PackParse,
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct StoredSkippedCandidate {
    oid: StoredOidBytes,
    reason: StoredCandidateSkipReason,
}

impl From<SkippedCandidate> for StoredSkippedCandidate {
    fn from(value: SkippedCandidate) -> Self {
        Self {
            oid: value.oid.into(),
            reason: value.reason.into(),
        }
    }
}

impl From<StoredSkippedCandidate> for SkippedCandidate {
    fn from(value: StoredSkippedCandidate) -> Self {
        Self {
            oid: value.oid.into(),
            reason: value.reason.into(),
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct StoredGitScanCommonMetrics {
    objects_scanned: u64,
    chunks_scanned: u64,
    bytes_scanned: u64,
    findings_emitted: u64,
    binary_skipped: u64,
    ext_skipped: u64,
    lock_skipped: u64,
    binary_extracted: u64,
    errors: u64,
}

impl From<GitScanCommonMetrics> for StoredGitScanCommonMetrics {
    fn from(value: GitScanCommonMetrics) -> Self {
        Self {
            objects_scanned: value.objects_scanned,
            chunks_scanned: value.chunks_scanned,
            bytes_scanned: value.bytes_scanned,
            findings_emitted: value.findings_emitted,
            binary_skipped: value.binary_skipped,
            ext_skipped: value.ext_skipped,
            lock_skipped: value.lock_skipped,
            binary_extracted: value.binary_extracted,
            errors: value.errors,
        }
    }
}

impl From<StoredGitScanCommonMetrics> for GitScanCommonMetrics {
    fn from(value: StoredGitScanCommonMetrics) -> Self {
        Self {
            objects_scanned: value.objects_scanned,
            chunks_scanned: value.chunks_scanned,
            bytes_scanned: value.bytes_scanned,
            findings_emitted: value.findings_emitted,
            binary_skipped: value.binary_skipped,
            ext_skipped: value.ext_skipped,
            lock_skipped: value.lock_skipped,
            binary_extracted: value.binary_extracted,
            errors: value.errors,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn artifact(byte: u8) -> RepoArtifactFingerprint {
        RepoArtifactFingerprint {
            packs_hash: [byte; 32],
            idx_hash: [byte.wrapping_add(1); 32],
        }
    }

    fn plan() -> Vec<PlannedCommit> {
        vec![
            PlannedCommit {
                pos: Position(7),
                snapshot_root: false,
            },
            PlannedCommit {
                pos: Position(9),
                snapshot_root: true,
            },
        ]
    }

    /// Frame raw bytes as a checkpoint envelope without serde serialization.
    ///
    /// Used for tests that need to inject pre-encoded payloads or corrupt
    /// specific envelope fields. Must be updated in lockstep with
    /// [`checkpoint_serialize`] if the envelope format changes.
    fn frame_checkpoint_payload(payload: &[u8]) -> Vec<u8> {
        let crc32 = crc32fast::hash(payload);
        let mut encoded = Vec::with_capacity(CHECKPOINT_ENVELOPE_HEADER_LEN + payload.len());
        encoded.extend_from_slice(&CHECKPOINT_MAGIC);
        encoded.extend_from_slice(&crc32.to_le_bytes());
        encoded.extend_from_slice(payload);
        encoded
    }

    fn serialize_checkpoint_for_test<T: serde::Serialize>(value: &T) -> Vec<u8> {
        checkpoint_serialize(value).expect("framed checkpoint encoding should succeed")
    }

    #[test]
    fn resume_state_ignores_stale_artifact_fingerprint() {
        let checkpoint = StageCheckpoint::PostCommitPlan {
            scan_mode: GitScanMode::OdbBlobFast,
            artifact_fingerprint: &artifact(1),
            plan: &plan(),
        };
        let loaded = LoadedScanCheckpoint::BaseOnly {
            base_state: checkpoint
                .encode_base_state()
                .expect("encode")
                .expect("PostCommitPlan produces base"),
        };

        let state = ScanResumeState::from_loaded(loaded, GitScanMode::OdbBlobFast, &artifact(9))
            .expect("load should succeed");
        assert!(state.is_none(), "stale artifacts must restart from scratch");
    }

    #[test]
    fn stage_checkpoint_token_carries_stage_and_prefix_count() {
        let checkpoint = StageCheckpoint::PackPlanComplete {
            scan_mode: GitScanMode::OdbBlobFast,
            artifact_fingerprint: &artifact(2),
            plan: &[],
            packed: &[],
            loose: &[],
            path_arena: &ByteArena::with_capacity(0),
            tree_diff_stats: TreeDiffStats {
                trees_loaded: 0,
                tree_bytes_loaded: 0,
                tree_bytes_in_flight_peak: 0,
                candidates_emitted: 0,
                subtrees_skipped: 0,
                max_depth_reached: 0,
            },
            spill_stats: SpillStats {
                candidates_received: 0,
                unique_blobs: 0,
                spill_runs: 0,
                spill_bytes: 0,
                seen_blobs: 0,
                emitted_blobs: 0,
            },
            mapping_stats: MappingStats {
                unique_blobs_in: 0,
                packed_matched: 0,
                loose_unmatched: 0,
            },
            completed_plan_count: 3,
            scanned: &ScannedBlobs {
                blobs: Vec::new(),
                finding_arena: Vec::new(),
            },
            skipped_candidates: &[],
            common_metrics: GitScanCommonMetrics::default(),
        };
        let token = checkpoint.resume_token().expect("token");
        assert_eq!(&token[..4], b"gcp\0");
        assert_eq!(token[4], ScanCheckpointStage::PackPlanComplete.as_u8());
        assert_eq!(u32::from_le_bytes(token[5..9].try_into().unwrap()), 3);
    }

    #[test]
    fn pack_prefix_stages_do_not_rewrite_base_state() {
        let checkpoint = StageCheckpoint::PackPlanComplete {
            scan_mode: GitScanMode::OdbBlobFast,
            artifact_fingerprint: &artifact(3),
            plan: &[],
            packed: &[],
            loose: &[],
            path_arena: &ByteArena::with_capacity(0),
            tree_diff_stats: TreeDiffStats::default(),
            spill_stats: SpillStats::default(),
            mapping_stats: MappingStats::default(),
            completed_plan_count: 0,
            scanned: &ScannedBlobs {
                blobs: Vec::new(),
                finding_arena: Vec::new(),
            },
            skipped_candidates: &[],
            common_metrics: GitScanCommonMetrics::default(),
        };

        assert!(
            checkpoint
                .encode_base_state()
                .expect("base encoding")
                .is_none(),
            "clean-prefix checkpoints must not rewrite the base blob"
        );
        assert!(
            checkpoint
                .encode_prefix_state()
                .expect("prefix encoding")
                .is_some(),
            "clean-prefix checkpoints must still emit a prefix blob"
        );
    }

    #[test]
    fn round_trip_pack_plan_complete_through_from_loaded() {
        let fp = artifact(5);
        let commits = plan();
        let mut path_arena = ByteArena::with_capacity(1024);
        let path_ref = path_arena.intern(b"src/main.rs").unwrap();

        let oid = OidBytes::sha1([0xAA; 20]);
        let ctx = CandidateContext {
            commit_id: 7,
            parent_idx: 0,
            change_kind: ChangeKind::Add,
            ctx_flags: 0o100644,
            cand_flags: 1,
            path_ref,
        };
        let packed = vec![PackCandidate {
            oid,
            ctx,
            pack_id: 2,
            offset: 4096,
        }];
        let loose = vec![LooseCandidate { oid, ctx }];

        let tree_diff_stats = TreeDiffStats {
            trees_loaded: 10,
            tree_bytes_loaded: 2048,
            tree_bytes_in_flight_peak: 512,
            candidates_emitted: 5,
            subtrees_skipped: 1,
            max_depth_reached: 3,
        };
        let spill_stats = SpillStats {
            candidates_received: 100,
            unique_blobs: 42,
            spill_runs: 2,
            spill_bytes: 8192,
            seen_blobs: 10,
            emitted_blobs: 32,
        };
        let mapping_stats = MappingStats {
            unique_blobs_in: 42,
            packed_matched: 30,
            loose_unmatched: 12,
        };

        // Encode base state from PostSpillDedup (the stage that emits base).
        let base_checkpoint = StageCheckpoint::PostSpillDedup {
            scan_mode: GitScanMode::DiffHistory,
            artifact_fingerprint: &fp,
            plan: &commits,
            packed: &packed,
            loose: &loose,
            path_arena: &path_arena,
            tree_diff_stats: tree_diff_stats.clone(),
            spill_stats: spill_stats.clone(),
            mapping_stats,
        };
        let base_state = base_checkpoint
            .encode_base_state()
            .expect("base encode")
            .expect("PostSpillDedup must produce base state");

        // Encode prefix state from PackPlanComplete.
        let finding = ScoredFinding {
            key: FindingKey {
                start: 10,
                end: 20,
                rule_id: 99,
                norm_hash: [0xBB; 32],
            },
            confidence_score: 7,
        };
        let scanned = ScannedBlobs {
            blobs: vec![ScannedBlob {
                oid,
                ctx,
                findings: FindingSpan { start: 0, len: 1 },
            }],
            finding_arena: vec![finding],
        };
        let skipped = vec![SkippedCandidate {
            oid,
            reason: CandidateSkipReason::PackDelta,
        }];
        let common_metrics = GitScanCommonMetrics {
            objects_scanned: 50,
            chunks_scanned: 200,
            bytes_scanned: 1_000_000,
            findings_emitted: 3,
            binary_skipped: 1,
            ext_skipped: 0,
            lock_skipped: 0,
            binary_extracted: 0,
            errors: 0,
        };

        let prefix_checkpoint = StageCheckpoint::PackPlanComplete {
            scan_mode: GitScanMode::DiffHistory,
            artifact_fingerprint: &fp,
            plan: &commits,
            packed: &packed,
            loose: &loose,
            path_arena: &path_arena,
            tree_diff_stats,
            spill_stats: spill_stats.clone(),
            mapping_stats,
            completed_plan_count: 1,
            scanned: &scanned,
            skipped_candidates: &skipped,
            common_metrics,
        };
        let prefix_state = prefix_checkpoint
            .encode_prefix_state()
            .expect("prefix encode")
            .expect("PackPlanComplete must produce prefix state");

        // Round-trip through from_loaded.
        let loaded = LoadedScanCheckpoint::BaseAndPrefix {
            base_state,
            prefix_state,
        };
        let resume = ScanResumeState::from_loaded(loaded, GitScanMode::DiffHistory, &fp)
            .expect("from_loaded should succeed")
            .expect("matching fingerprint should produce Some");

        let (stage, base, prefix) = resume.into_parts();
        assert_eq!(stage, ScanCheckpointStage::PackPlanComplete);

        let base = base.expect("base must be present");
        assert_eq!(base.plan, commits);
        assert_eq!(base.packed, packed);
        assert_eq!(base.loose, loose);
        assert_eq!(base.path_arena.backing_bytes(), path_arena.backing_bytes());
        assert_eq!(base.spill_stats.spill_runs, 2);
        assert_eq!(base.spill_stats.candidates_received, 100);
        assert_eq!(base.mapping_stats.packed_matched, 30);
        assert_eq!(base.tree_diff_stats.trees_loaded, 10);

        let prefix = prefix.expect("prefix must be present");
        assert_eq!(prefix.stage, PrefixStage::PackPlanComplete);
        assert_eq!(prefix.completed_plan_count, 1);
        assert_eq!(prefix.scanned.blobs.len(), 1);
        assert_eq!(prefix.scanned.finding_arena.len(), 1);
        assert_eq!(prefix.scanned.finding_arena[0].confidence_score, 7);
        assert_eq!(prefix.skipped_candidates.len(), 1);
        assert_eq!(
            prefix.skipped_candidates[0].reason,
            CandidateSkipReason::PackDelta
        );
        assert_eq!(prefix.common_metrics.objects_scanned, 50);
        assert_eq!(prefix.common_metrics.bytes_scanned, 1_000_000);
    }

    /// Helper: builds a non-trivial `PostSpillDedup` checkpoint and returns the
    /// encoded base state alongside the inputs for later verification.
    fn encode_spill_dedup_base(
        fp: &RepoArtifactFingerprint,
    ) -> (
        Vec<u8>,
        Vec<PlannedCommit>,
        Vec<PackCandidate>,
        Vec<LooseCandidate>,
        ByteArena,
        TreeDiffStats,
        SpillStats,
        MappingStats,
    ) {
        let commits = vec![
            PlannedCommit {
                pos: Position(3),
                snapshot_root: false,
            },
            PlannedCommit {
                pos: Position(17),
                snapshot_root: true,
            },
        ];
        let mut path_arena = ByteArena::with_capacity(4096);
        let path_ref = path_arena.intern(b"lib/scanner.rs").unwrap();

        let oid_a = OidBytes::sha1([0xAA; 20]);
        let oid_b = OidBytes::sha1([0xBB; 20]);
        let ctx = CandidateContext {
            commit_id: 5,
            parent_idx: 1,
            change_kind: ChangeKind::Modify,
            ctx_flags: 0o100755,
            cand_flags: 2,
            path_ref,
        };
        let packed = vec![
            PackCandidate {
                oid: oid_a,
                ctx,
                pack_id: 4,
                offset: 8192,
            },
            PackCandidate {
                oid: oid_b,
                ctx,
                pack_id: 1,
                offset: 256,
            },
        ];
        let loose = vec![LooseCandidate { oid: oid_b, ctx }];

        let tree_diff_stats = TreeDiffStats {
            trees_loaded: 20,
            tree_bytes_loaded: 4096,
            tree_bytes_in_flight_peak: 1024,
            candidates_emitted: 12,
            subtrees_skipped: 3,
            max_depth_reached: 5,
        };
        let spill_stats = SpillStats {
            candidates_received: 200,
            unique_blobs: 80,
            spill_runs: 4,
            spill_bytes: 16384,
            seen_blobs: 20,
            emitted_blobs: 60,
        };
        let mapping_stats = MappingStats {
            unique_blobs_in: 80,
            packed_matched: 55,
            loose_unmatched: 25,
        };

        let checkpoint = StageCheckpoint::PostSpillDedup {
            scan_mode: GitScanMode::DiffHistory,
            artifact_fingerprint: fp,
            plan: &commits,
            packed: &packed,
            loose: &loose,
            path_arena: &path_arena,
            tree_diff_stats: tree_diff_stats.clone(),
            spill_stats: spill_stats.clone(),
            mapping_stats,
        };
        let base_bytes = checkpoint
            .encode_base_state()
            .expect("encode must succeed")
            .expect("PostSpillDedup produces base state");

        (
            base_bytes,
            commits,
            packed,
            loose,
            path_arena,
            tree_diff_stats,
            spill_stats,
            mapping_stats,
        )
    }

    #[test]
    fn resume_state_round_trips_spill_dedup_base() {
        let fp = artifact(10);
        let (
            base_bytes,
            commits,
            packed,
            loose,
            path_arena,
            tree_diff_stats,
            spill_stats,
            mapping_stats,
        ) = encode_spill_dedup_base(&fp);

        let loaded = LoadedScanCheckpoint::BaseOnly {
            base_state: base_bytes,
        };
        let resume = ScanResumeState::from_loaded(loaded, GitScanMode::DiffHistory, &fp)
            .expect("from_loaded should succeed")
            .expect("matching fingerprint should produce Some");

        match resume {
            ScanResumeState::PostSpillDedup(base) => {
                assert_eq!(base.plan.len(), commits.len());
                assert_eq!(base.plan[0].pos, Position(3));
                assert!(!base.plan[0].snapshot_root);
                assert_eq!(base.plan[1].pos, Position(17));
                assert!(base.plan[1].snapshot_root);

                assert_eq!(base.packed.len(), packed.len());
                assert_eq!(base.packed[0].oid, packed[0].oid);
                assert_eq!(base.packed[0].pack_id, 4);
                assert_eq!(base.packed[0].offset, 8192);
                assert_eq!(base.packed[1].oid, packed[1].oid);
                assert_eq!(base.packed[1].pack_id, 1);

                assert_eq!(base.loose.len(), loose.len());
                assert_eq!(base.loose[0].oid, loose[0].oid);

                assert_eq!(
                    base.path_arena.backing_bytes().len(),
                    path_arena.backing_bytes().len()
                );

                assert_eq!(
                    base.tree_diff_stats.trees_loaded,
                    tree_diff_stats.trees_loaded
                );
                assert_eq!(
                    base.tree_diff_stats.tree_bytes_loaded,
                    tree_diff_stats.tree_bytes_loaded
                );
                assert_eq!(
                    base.tree_diff_stats.candidates_emitted,
                    tree_diff_stats.candidates_emitted
                );
                assert_eq!(
                    base.tree_diff_stats.subtrees_skipped,
                    tree_diff_stats.subtrees_skipped
                );
                assert_eq!(
                    base.tree_diff_stats.max_depth_reached,
                    tree_diff_stats.max_depth_reached
                );

                assert_eq!(
                    base.spill_stats.candidates_received,
                    spill_stats.candidates_received
                );
                assert_eq!(base.spill_stats.unique_blobs, spill_stats.unique_blobs);
                assert_eq!(base.spill_stats.spill_runs, spill_stats.spill_runs);
                assert_eq!(base.spill_stats.spill_bytes, spill_stats.spill_bytes);
                assert_eq!(base.spill_stats.seen_blobs, spill_stats.seen_blobs);
                assert_eq!(base.spill_stats.emitted_blobs, spill_stats.emitted_blobs);

                assert_eq!(
                    base.mapping_stats.unique_blobs_in,
                    mapping_stats.unique_blobs_in
                );
                assert_eq!(
                    base.mapping_stats.packed_matched,
                    mapping_stats.packed_matched
                );
                assert_eq!(
                    base.mapping_stats.loose_unmatched,
                    mapping_stats.loose_unmatched
                );
            }
            other => panic!(
                "expected PostSpillDedup, got stage {:?}",
                other.plan().len()
            ),
        }
    }

    #[test]
    fn resume_state_round_trips_pack_plan_prefix() {
        let fp = artifact(11);
        let (base_bytes, _, _, _, _, _, _, _) = encode_spill_dedup_base(&fp);

        let oid = OidBytes::sha1([0xCC; 20]);
        let ctx = CandidateContext {
            commit_id: 3,
            parent_idx: 0,
            change_kind: ChangeKind::Add,
            ctx_flags: 0o100644,
            cand_flags: 0,
            path_ref: ByteRef::new(0, 0),
        };
        let finding = ScoredFinding {
            key: FindingKey {
                start: 5,
                end: 15,
                rule_id: 42,
                norm_hash: [0xDD; 32],
            },
            confidence_score: -3,
        };
        let scanned = ScannedBlobs {
            blobs: vec![ScannedBlob {
                oid,
                ctx,
                findings: FindingSpan { start: 0, len: 1 },
            }],
            finding_arena: vec![finding],
        };
        let skipped = vec![SkippedCandidate {
            oid,
            reason: CandidateSkipReason::LooseMissing,
        }];
        let common_metrics = GitScanCommonMetrics {
            objects_scanned: 100,
            chunks_scanned: 400,
            bytes_scanned: 2_000_000,
            findings_emitted: 5,
            binary_skipped: 2,
            ext_skipped: 1,
            lock_skipped: 0,
            binary_extracted: 1,
            errors: 0,
        };

        let prefix_checkpoint = StageCheckpoint::PackPlanComplete {
            scan_mode: GitScanMode::DiffHistory,
            artifact_fingerprint: &fp,
            plan: &[],
            packed: &[],
            loose: &[],
            path_arena: &ByteArena::with_capacity(0),
            tree_diff_stats: TreeDiffStats::default(),
            spill_stats: SpillStats::default(),
            mapping_stats: MappingStats::default(),
            completed_plan_count: 2,
            scanned: &scanned,
            skipped_candidates: &skipped,
            common_metrics,
        };
        let prefix_bytes = prefix_checkpoint
            .encode_prefix_state()
            .expect("prefix encode")
            .expect("PackPlanComplete must produce prefix state");

        let loaded = LoadedScanCheckpoint::BaseAndPrefix {
            base_state: base_bytes,
            prefix_state: prefix_bytes,
        };
        let resume = ScanResumeState::from_loaded(loaded, GitScanMode::DiffHistory, &fp)
            .expect("from_loaded should succeed")
            .expect("matching fingerprint should produce Some");

        let (stage, _base, prefix) = resume.into_parts();
        assert_eq!(stage, ScanCheckpointStage::PackPlanComplete);

        let prefix = prefix.expect("prefix must be present");
        assert_eq!(prefix.completed_plan_count, 2);
        assert_eq!(prefix.scanned.blobs.len(), 1);
        assert_eq!(prefix.scanned.finding_arena.len(), 1);
        assert_eq!(prefix.scanned.finding_arena[0].confidence_score, -3);
        assert_eq!(prefix.skipped_candidates.len(), 1);
        assert_eq!(
            prefix.skipped_candidates[0].reason,
            CandidateSkipReason::LooseMissing
        );
        assert_eq!(prefix.common_metrics.objects_scanned, 100);
        assert_eq!(prefix.common_metrics.chunks_scanned, 400);
        assert_eq!(prefix.common_metrics.bytes_scanned, 2_000_000);
        assert_eq!(prefix.common_metrics.findings_emitted, 5);
        assert_eq!(prefix.common_metrics.binary_skipped, 2);
        assert_eq!(prefix.common_metrics.ext_skipped, 1);
        assert_eq!(prefix.common_metrics.binary_extracted, 1);
    }

    /// Orphaned prefix (prefix present without base) is now structurally
    /// unrepresentable via [`LoadedScanCheckpoint`]. The persistence layer
    /// rejects the invalid state at construction time rather than deferring
    /// validation to `from_loaded`.
    #[test]
    fn loaded_checkpoint_default_is_empty() {
        let loaded = LoadedScanCheckpoint::default();
        assert_eq!(loaded, LoadedScanCheckpoint::Empty);
    }

    #[test]
    fn from_loaded_rejects_commit_plan_with_prefix() {
        let fp = artifact(21);
        let checkpoint = StageCheckpoint::PostCommitPlan {
            scan_mode: GitScanMode::DiffHistory,
            artifact_fingerprint: &fp,
            plan: &plan(),
        };
        let base_bytes = checkpoint
            .encode_base_state()
            .expect("encode")
            .expect("PostCommitPlan produces base state");

        let loaded = LoadedScanCheckpoint::BaseAndPrefix {
            base_state: base_bytes,
            prefix_state: vec![0xFF],
        };
        let err = ScanResumeState::from_loaded(loaded, GitScanMode::DiffHistory, &fp)
            .expect_err("should reject commit-plan with prefix");
        let msg = err.to_string();
        assert!(
            msg.contains("commit-plan checkpoint cannot carry"),
            "unexpected error message: {msg}"
        );
    }

    #[test]
    fn from_loaded_rejects_invalid_prefix_stage() {
        let fp = artifact(22);
        let (base_bytes, _, _, _, _, _, _, _) = encode_spill_dedup_base(&fp);

        // Build a prefix payload with an invalid stage (PostCommitPlan is not
        // valid as a prefix discriminator).
        let invalid_prefix = StoredPrefixState {
            stage: ScanCheckpointStage::PostCommitPlan,
            completed_plan_count: 0,
            scanned: StoredScannedBlobs {
                blobs: Vec::new(),
                finding_arena: Vec::new(),
            },
            skipped_candidates: Vec::new(),
            common_metrics: StoredGitScanCommonMetrics::from(GitScanCommonMetrics::default()),
        };
        let prefix_bytes = serialize_checkpoint_for_test(&invalid_prefix);

        let loaded = LoadedScanCheckpoint::BaseAndPrefix {
            base_state: base_bytes,
            prefix_state: prefix_bytes,
        };
        let err = ScanResumeState::from_loaded(loaded, GitScanMode::DiffHistory, &fp)
            .expect_err("should reject invalid prefix stage");
        let msg = err.to_string();
        assert!(
            msg.contains("invalid stage discriminator"),
            "unexpected error message: {msg}"
        );
    }

    #[test]
    fn resume_state_ignores_stale_scan_mode() {
        let fp = artifact(23);
        let checkpoint = StageCheckpoint::PostCommitPlan {
            scan_mode: GitScanMode::DiffHistory,
            artifact_fingerprint: &fp,
            plan: &plan(),
        };
        let base_bytes = checkpoint
            .encode_base_state()
            .expect("encode")
            .expect("PostCommitPlan produces base state");

        let loaded = LoadedScanCheckpoint::BaseOnly {
            base_state: base_bytes,
        };
        // Load with a different scan mode than what was encoded.
        let result =
            ScanResumeState::from_loaded(loaded, GitScanMode::OdbBlobFast, &fp).expect("load ok");
        assert!(
            result.is_none(),
            "scan_mode mismatch must discard the checkpoint"
        );
    }

    #[test]
    fn deserialize_truncated_blob_restarts_fresh() {
        let loaded = LoadedScanCheckpoint::BaseOnly {
            base_state: vec![b'g', b'k', b'p', b't', 0x00, 0x00],
        };
        let result = ScanResumeState::from_loaded(loaded, GitScanMode::DiffHistory, &artifact(1))
            .expect("graceful decode failure returns Ok");
        assert!(result.is_none(), "truncated envelope must restart fresh");
    }

    #[test]
    fn deserialize_oversized_blob_restarts_fresh() {
        // Build a blob exceeding `MAX_CHECKPOINT_BYTES` so that the size
        // guard in `checkpoint_deserialize` rejects the framed payload before
        // postcard attempts to parse anything.
        let blob = frame_checkpoint_payload(&vec![0u8; MAX_CHECKPOINT_BYTES + 1]);

        let loaded = LoadedScanCheckpoint::BaseOnly { base_state: blob };
        let result =
            ScanResumeState::from_loaded(loaded, GitScanMode::DiffHistory, &artifact(0xAA))
                .expect("graceful decode failure returns Ok");
        assert!(result.is_none(), "oversized blob must restart fresh");
    }

    #[test]
    fn resume_state_rejects_invalid_oid_length() {
        let fp = artifact(0x10);

        // StoredBaseState with a corrupted OID length (99 instead of 20/32).
        // from_loaded rejects this as InvalidState.
        let bad_oid = StoredOidBytes {
            len: 99,
            bytes: [0; 32],
        };
        let bad_packed = StoredPackCandidate {
            oid: bad_oid,
            ctx: StoredCandidateContext {
                commit_id: 0,
                parent_idx: 0,
                change_kind: StoredChangeKind::Add,
                ctx_flags: 0,
                cand_flags: 0,
                path_ref: StoredByteRef { off: 0, len: 0 },
            },
            pack_id: 0,
            offset: 0,
        };
        let stored = StoredBaseState::SpillDedup(StoredSpillDedupState {
            scan_mode: StoredGitScanMode::DiffHistory,
            artifact_fingerprint: StoredRepoArtifactFingerprint::from(&fp),
            plan: Vec::new(),
            packed: vec![bad_packed],
            loose: Vec::new(),
            path_arena: Vec::new(),
            tree_diff_stats: StoredTreeDiffStats::from(TreeDiffStats::default()),
            spill_stats: StoredSpillStats::from(SpillStats::default()),
            mapping_stats: StoredMappingStats::from(MappingStats::default()),
        });
        let blob = serialize_checkpoint_for_test(&stored);

        let loaded = LoadedScanCheckpoint::BaseOnly { base_state: blob };
        let err = ScanResumeState::from_loaded(loaded, GitScanMode::DiffHistory, &fp)
            .expect_err("invalid OID length must fail");
        assert!(
            matches!(err, ScanCheckpointError::InvalidState(_)),
            "expected InvalidState for bad OID, got: {err:?}"
        );
        assert!(
            err.to_string().contains("invalid OID length"),
            "error message should mention OID: {err}"
        );
    }

    #[test]
    fn resume_state_rejects_out_of_bounds_byte_ref() {
        let fp = artifact(0x11);
        let valid_oid = StoredOidBytes {
            len: 20,
            bytes: [0xAA; 32],
        };
        // path_arena is 4 bytes, but ByteRef references offset 10.
        let bad_ref = StoredByteRef { off: 10, len: 5 };
        let bad_packed = StoredPackCandidate {
            oid: valid_oid,
            ctx: StoredCandidateContext {
                commit_id: 0,
                parent_idx: 0,
                change_kind: StoredChangeKind::Add,
                ctx_flags: 0,
                cand_flags: 0,
                path_ref: bad_ref,
            },
            pack_id: 0,
            offset: 0,
        };
        let stored = StoredBaseState::SpillDedup(StoredSpillDedupState {
            scan_mode: StoredGitScanMode::DiffHistory,
            artifact_fingerprint: StoredRepoArtifactFingerprint::from(&fp),
            plan: Vec::new(),
            packed: vec![bad_packed],
            loose: Vec::new(),
            path_arena: vec![0u8; 4],
            tree_diff_stats: StoredTreeDiffStats::from(TreeDiffStats::default()),
            spill_stats: StoredSpillStats::from(SpillStats::default()),
            mapping_stats: StoredMappingStats::from(MappingStats::default()),
        });
        let blob = serialize_checkpoint_for_test(&stored);

        let loaded = LoadedScanCheckpoint::BaseOnly { base_state: blob };
        let err = ScanResumeState::from_loaded(loaded, GitScanMode::DiffHistory, &fp)
            .expect_err("OOB ByteRef must fail");
        assert!(
            matches!(err, ScanCheckpointError::InvalidState(_)),
            "expected InvalidState for OOB ByteRef, got: {err:?}"
        );
        assert!(
            err.to_string().contains("ByteRef"),
            "error message should mention ByteRef: {err}"
        );
    }

    #[test]
    fn resume_state_rejects_out_of_bounds_finding_span() {
        let fp = artifact(0x12);
        let (base_blob, ..) = encode_spill_dedup_base(&fp);

        // Build a prefix with a FindingSpan that exceeds the finding_arena.
        let bad_scanned = StoredScannedBlobs {
            blobs: vec![StoredScannedBlob {
                oid: StoredOidBytes {
                    len: 20,
                    bytes: [0xCC; 32],
                },
                ctx: StoredCandidateContext {
                    commit_id: 0,
                    parent_idx: 0,
                    change_kind: StoredChangeKind::Add,
                    ctx_flags: 0,
                    cand_flags: 0,
                    path_ref: StoredByteRef { off: 0, len: 0 },
                },
                findings: StoredFindingSpan {
                    start: 0,
                    len: 1000,
                },
            }],
            finding_arena: Vec::new(),
        };
        let prefix = StoredPrefixState {
            stage: ScanCheckpointStage::PackPlanComplete,
            completed_plan_count: 0,
            scanned: bad_scanned,
            skipped_candidates: Vec::new(),
            common_metrics: StoredGitScanCommonMetrics::from(GitScanCommonMetrics::default()),
        };
        let prefix_blob = serialize_checkpoint_for_test(&prefix);

        let loaded = LoadedScanCheckpoint::BaseAndPrefix {
            base_state: base_blob,
            prefix_state: prefix_blob,
        };
        let err = ScanResumeState::from_loaded(loaded, GitScanMode::DiffHistory, &fp)
            .expect_err("OOB FindingSpan must fail");
        assert!(
            matches!(err, ScanCheckpointError::InvalidState(_)),
            "expected InvalidState for OOB FindingSpan, got: {err:?}"
        );
        assert!(
            err.to_string().contains("FindingSpan"),
            "error message should mention FindingSpan: {err}"
        );
    }

    /// PostCommitPlan round-trip: encode, decode via from_loaded, plan survives.
    #[test]
    fn round_trip_post_commit_plan_through_from_loaded() {
        let fp = artifact(30);
        let commits = plan();
        let checkpoint = StageCheckpoint::PostCommitPlan {
            scan_mode: GitScanMode::DiffHistory,
            artifact_fingerprint: &fp,
            plan: &commits,
        };
        let base_state = checkpoint
            .encode_base_state()
            .expect("encode")
            .expect("PostCommitPlan produces base state");

        let loaded = LoadedScanCheckpoint::BaseOnly { base_state };
        let resume = ScanResumeState::from_loaded(loaded, GitScanMode::DiffHistory, &fp)
            .expect("from_loaded should succeed")
            .expect("matching fingerprint should produce Some");

        let (stage, base, prefix) = resume.into_parts();
        assert_eq!(stage, ScanCheckpointStage::PostCommitPlan);
        assert!(prefix.is_none(), "PostCommitPlan must not carry a prefix");
        assert!(
            base.is_none(),
            "PostCommitPlan must not carry a base — runners must regenerate candidates"
        );
    }

    /// PreFinalize round-trip: encode, decode via from_loaded, stage and prefix survive.
    #[test]
    fn round_trip_pre_finalize_through_from_loaded() {
        let fp = artifact(31);
        let (base_bytes, _, _, _, _, _, _, _) = encode_spill_dedup_base(&fp);

        let dummy_ctx = CandidateContext {
            commit_id: 0,
            parent_idx: 0,
            change_kind: ChangeKind::Add,
            ctx_flags: 0o100644,
            cand_flags: 0,
            path_ref: ByteRef { off: 0, len: 0 },
        };
        let scanned = ScannedBlobs {
            blobs: vec![ScannedBlob {
                oid: OidBytes::sha1([0xDD; 20]),
                ctx: dummy_ctx,
                findings: FindingSpan { start: 0, len: 0 },
            }],
            finding_arena: Vec::new(),
        };
        let path_arena = ByteArena::with_capacity(0);
        let prefix_checkpoint = StageCheckpoint::PreFinalize {
            scan_mode: GitScanMode::DiffHistory,
            artifact_fingerprint: &fp,
            plan: &plan(),
            packed: &[],
            loose: &[],
            path_arena: &path_arena,
            tree_diff_stats: TreeDiffStats::default(),
            spill_stats: SpillStats::default(),
            mapping_stats: MappingStats::default(),
            completed_plan_count: 2,
            scanned: &scanned,
            skipped_candidates: &[],
            common_metrics: GitScanCommonMetrics::default(),
        };
        let prefix_state = prefix_checkpoint
            .encode_prefix_state()
            .expect("prefix encode")
            .expect("PreFinalize must produce prefix state");

        let loaded = LoadedScanCheckpoint::BaseAndPrefix {
            base_state: base_bytes,
            prefix_state,
        };
        let resume = ScanResumeState::from_loaded(loaded, GitScanMode::DiffHistory, &fp)
            .expect("from_loaded should succeed")
            .expect("matching fingerprint should produce Some");

        let (stage, _base, prefix) = resume.into_parts();
        assert_eq!(stage, ScanCheckpointStage::PreFinalize);

        let prefix = prefix.expect("PreFinalize must carry a prefix");
        assert_eq!(prefix.stage, PrefixStage::PreFinalize);
        assert_eq!(prefix.completed_plan_count, 2);
        assert_eq!(prefix.scanned.blobs.len(), 1);
    }

    #[test]
    fn checkpoint_deserialize_rejects_valid_envelope_with_invalid_postcard() {
        // Exercises the postcard::from_bytes error-wrapping path (line 127):
        // valid magic, valid CRC, within size limit, but garbage postcard bytes.
        let garbage = &[0xFF, 0xFE, 0xFD];
        let blob = frame_checkpoint_payload(garbage);

        let err = checkpoint_deserialize::<StoredBaseState>(&blob)
            .expect_err("garbage postcard payload must fail");
        assert!(
            matches!(err, ScanCheckpointError::Decode(_)),
            "expected Decode variant, got: {err:?}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("checkpoint decoding failed"),
            "error message should use the Decode variant prefix: {msg}"
        );
    }

    #[test]
    fn checkpoint_deserialize_rejects_magic_mismatch() {
        let payload = postcard::to_allocvec(&123u32).expect("payload");
        let mut blob = frame_checkpoint_payload(&payload);
        blob[..CHECKPOINT_MAGIC.len()].copy_from_slice(b"nope");

        let err = checkpoint_deserialize::<u32>(&blob).expect_err("bad magic must fail");
        assert_eq!(
            err.to_string(),
            "checkpoint decoding failed: checkpoint blob magic mismatch"
        );
    }

    #[test]
    fn checkpoint_deserialize_rejects_crc_mismatch_with_safe_diagnostics() {
        let mut blob = checkpoint_serialize(&123u32).expect("serialize");
        let stored_crc32 = u32::from_le_bytes(
            blob[CHECKPOINT_MAGIC.len()..CHECKPOINT_ENVELOPE_HEADER_LEN]
                .try_into()
                .expect("checksum slice"),
        );
        blob[CHECKPOINT_ENVELOPE_HEADER_LEN] ^= 0xFF;
        let computed_crc32 = crc32fast::hash(&blob[CHECKPOINT_ENVELOPE_HEADER_LEN..]);

        let err = checkpoint_deserialize::<u32>(&blob).expect_err("corrupted CRC must fail");
        assert_eq!(
            err.to_string(),
            format!(
                "checkpoint decoding failed: checkpoint CRC mismatch (stored {stored_crc32:#010x}, computed {computed_crc32:#010x})"
            )
        );
    }

    #[test]
    fn deserialize_empty_payload_with_valid_crc_returns_decode_error() {
        // Header-only blob: valid magic + CRC of empty payload. Passes the
        // envelope checks but postcard cannot decode an empty byte slice into
        // a structured type, so this exercises the postcard error mapping.
        let blob = frame_checkpoint_payload(&[]);
        let err = checkpoint_deserialize::<StoredBaseState>(&blob)
            .expect_err("empty payload cannot decode to StoredBaseState");
        assert!(matches!(err, ScanCheckpointError::Decode(_)));
    }

    #[test]
    fn deserialize_truncated_payload_triggers_crc_mismatch() {
        // Valid header length but payload truncated after framing: the stored
        // CRC covers the original full payload, so truncation is detected as
        // a CRC mismatch rather than a postcard decode error.
        let full_blob = serialize_checkpoint_for_test(&vec![0xAAu8; 32]);
        assert!(
            full_blob.len() > CHECKPOINT_ENVELOPE_HEADER_LEN + 1,
            "test value must produce a multi-byte payload"
        );
        let truncated = full_blob[..CHECKPOINT_ENVELOPE_HEADER_LEN + 1].to_vec();
        let err =
            checkpoint_deserialize::<Vec<u8>>(&truncated).expect_err("truncated payload must fail");
        assert!(
            err.to_string().contains("CRC mismatch"),
            "expected CRC mismatch, got: {err}"
        );
    }

    #[test]
    fn corrupted_prefix_crc_falls_back_to_base_only() {
        let fp = artifact(33);
        let (base_state, _, _, _, _, _, _, _) = encode_spill_dedup_base(&fp);
        let path_arena = ByteArena::with_capacity(0);
        let scanned = ScannedBlobs {
            blobs: Vec::new(),
            finding_arena: Vec::new(),
        };
        let prefix_checkpoint = StageCheckpoint::PackPlanComplete {
            scan_mode: GitScanMode::DiffHistory,
            artifact_fingerprint: &fp,
            plan: &plan(),
            packed: &[],
            loose: &[],
            path_arena: &path_arena,
            tree_diff_stats: TreeDiffStats::default(),
            spill_stats: SpillStats::default(),
            mapping_stats: MappingStats::default(),
            completed_plan_count: 1,
            scanned: &scanned,
            skipped_candidates: &[],
            common_metrics: GitScanCommonMetrics::default(),
        };
        let mut prefix_state = prefix_checkpoint
            .encode_prefix_state()
            .expect("prefix encode")
            .expect("PackPlanComplete must produce prefix state");
        prefix_state[CHECKPOINT_ENVELOPE_HEADER_LEN] ^= 0x01;

        let loaded = LoadedScanCheckpoint::BaseAndPrefix {
            base_state,
            prefix_state,
        };
        let resume = ScanResumeState::from_loaded(loaded, GitScanMode::DiffHistory, &fp)
            .expect("load should succeed")
            .expect("base state should remain usable");

        assert!(
            matches!(resume, ScanResumeState::PostSpillDedup(_)),
            "corrupted prefix CRC must fall back to base-only resume"
        );
    }

    /// Verify that `completed_plan_count` survives serialization round-trip,
    /// ensuring the runner-level guard (`completed_plan_prefix_len > plans.len()`)
    /// receives the correct value.
    #[test]
    fn completed_plan_count_fidelity_through_round_trip() {
        let fp = artifact(32);
        let (base_bytes, _, _, _, _, _, _, _) = encode_spill_dedup_base(&fp);

        let path_arena = ByteArena::with_capacity(0);
        let scanned = ScannedBlobs {
            blobs: Vec::new(),
            finding_arena: Vec::new(),
        };
        let prefix_checkpoint = StageCheckpoint::PackPlanComplete {
            scan_mode: GitScanMode::DiffHistory,
            artifact_fingerprint: &fp,
            plan: &plan(),
            packed: &[],
            loose: &[],
            path_arena: &path_arena,
            tree_diff_stats: TreeDiffStats::default(),
            spill_stats: SpillStats::default(),
            mapping_stats: MappingStats::default(),
            completed_plan_count: 2,
            scanned: &scanned,
            skipped_candidates: &[],
            common_metrics: GitScanCommonMetrics::default(),
        };
        let prefix_state = prefix_checkpoint
            .encode_prefix_state()
            .expect("prefix encode")
            .expect("PackPlanComplete must produce prefix state");

        let loaded = LoadedScanCheckpoint::BaseAndPrefix {
            base_state: base_bytes,
            prefix_state,
        };
        let resume = ScanResumeState::from_loaded(loaded, GitScanMode::DiffHistory, &fp)
            .expect("from_loaded should succeed")
            .expect("matching fingerprint should produce Some");

        let (_stage, _base, prefix) = resume.into_parts();
        let prefix = prefix.expect("PackPlanComplete must carry a prefix");
        assert_eq!(
            prefix.completed_plan_count, 2,
            "completed_plan_count must survive serialization round-trip"
        );
    }

    #[rstest]
    #[case(0, true)]
    #[case(1, true)]
    #[case(2, true)]
    #[case(3, false)]
    fn completed_plan_count_validation_boundary(
        #[case] completed_plan_count: usize,
        #[case] should_succeed: bool,
    ) {
        // `encode_spill_dedup_base` produces a base with 2 packed candidates.
        // The validation in `from_loaded` checks `completed_plan_count` against
        // `base.packed.len()` (= 2), so count <= 2 succeeds and count > 2 fails.
        // The `packed: &[]` in the prefix checkpoint below only controls what is
        // serialized into the prefix blob; it is not used for validation.
        let fp = artifact(34);
        let (base_state, ..) = encode_spill_dedup_base(&fp);
        let path_arena = ByteArena::with_capacity(0);
        let scanned = ScannedBlobs {
            blobs: Vec::new(),
            finding_arena: Vec::new(),
        };
        let prefix_checkpoint = StageCheckpoint::PackPlanComplete {
            scan_mode: GitScanMode::DiffHistory,
            artifact_fingerprint: &fp,
            plan: &plan(),
            packed: &[],
            loose: &[],
            path_arena: &path_arena,
            tree_diff_stats: TreeDiffStats::default(),
            spill_stats: SpillStats::default(),
            mapping_stats: MappingStats::default(),
            completed_plan_count,
            scanned: &scanned,
            skipped_candidates: &[],
            common_metrics: GitScanCommonMetrics::default(),
        };
        let prefix_state = prefix_checkpoint
            .encode_prefix_state()
            .expect("prefix encode")
            .expect("PackPlanComplete must produce prefix state");
        let loaded = LoadedScanCheckpoint::BaseAndPrefix {
            base_state,
            prefix_state,
        };

        if should_succeed {
            let resume = ScanResumeState::from_loaded(loaded, GitScanMode::DiffHistory, &fp)
                .expect("within-bound prefix should load")
                .expect("within-bound prefix should resume");
            let (_, _, prefix) = resume.into_parts();
            assert_eq!(
                prefix
                    .expect("PackPlanComplete must carry a prefix")
                    .completed_plan_count,
                completed_plan_count
            );
        } else {
            let err = ScanResumeState::from_loaded(loaded, GitScanMode::DiffHistory, &fp)
                .expect_err("out-of-bound prefix must fail");
            assert_eq!(
                err.to_string(),
                "checkpoint state invalid: completed_plan_count (3) exceeds packed candidate count (2)"
            );
        }
    }
}
