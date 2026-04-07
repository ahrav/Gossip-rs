//! Durable stage checkpoints for Git scan resumption.
//!
//! The Git scan runner can persist stage-complete state at four boundaries:
////!
//! 1. post-commit-plan
//! 2. post-spill/dedup
//! 3. post-clean-pack-prefix
//! 4. pre-finalize
//!
//! The public trait surface intentionally keeps the persistence backend opaque.
//! Callers load and store raw checkpoint blobs, while this module owns the
//! encoding and decoding of runner state.

use bincode::Options as _;
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

fn checkpoint_codec() -> impl bincode::Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .allow_trailing_bytes()
}

/// Storage payloads returned by [`ScanCheckpointSink::load_resume_state`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LoadedScanCheckpoint {
    /// Durable base-state blob, if any.
    pub base_state: Option<Vec<u8>>,
    /// Durable prefix-state blob, if any.
    pub prefix_state: Option<Vec<u8>>,
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
                let encoded = checkpoint_codec()
                    .serialize(&StoredBaseState::CommitPlan(StoredCommitPlanState {
                        scan_mode: StoredGitScanMode::from(*scan_mode),
                        artifact_fingerprint: StoredRepoArtifactFingerprint::from(
                            *artifact_fingerprint,
                        ),
                        plan: plan
                            .iter()
                            .copied()
                            .map(StoredPlannedCommit::from)
                            .collect(),
                    }))
                    .map_err(|error| ScanCheckpointError::Encode(error.to_string()))?;
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
                let encoded = checkpoint_codec()
                    .serialize(&StoredBaseState::SpillDedup(StoredSpillDedupState {
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
                    }))
                    .map_err(|error| ScanCheckpointError::Encode(error.to_string()))?;
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
                let encoded = checkpoint_codec()
                    .serialize(&StoredPrefixState {
                        stage: self.stage(),
                        completed_plan_count,
                        scanned: StoredScannedBlobs::from(*scanned),
                        skipped_candidates: skipped_candidates
                            .iter()
                            .copied()
                            .map(StoredSkippedCandidate::from)
                            .collect(),
                        common_metrics: StoredGitScanCommonMetrics::from(*common_metrics),
                    })
                    .map_err(|error| ScanCheckpointError::Encode(error.to_string()))?;
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
        token.extend_from_slice(b"gcp1");
        token.push(self.stage().as_u8());
        token.extend_from_slice(&completed_plan_count.to_le_bytes());
        Ok(token)
    }
}

#[derive(Clone, Debug)]
pub(crate) enum ScanResumeState {
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
    pub(crate) fn from_loaded(
        loaded: LoadedScanCheckpoint,
        scan_mode: GitScanMode,
        artifact_fingerprint: &RepoArtifactFingerprint,
    ) -> Result<Option<Self>, ScanCheckpointError> {
        let Some(base_state) = loaded.base_state else {
            if loaded.prefix_state.is_some() {
                return Err(ScanCheckpointError::InvalidState(
                    "prefix checkpoint exists without a base checkpoint".to_owned(),
                ));
            }
            return Ok(None);
        };

        let base: StoredBaseState = checkpoint_codec()
            .deserialize(&base_state)
            .map_err(|error| ScanCheckpointError::Decode(error.to_string()))?;
        match base {
            StoredBaseState::CommitPlan(base) => {
                if GitScanMode::from(base.scan_mode) != scan_mode
                    || RepoArtifactFingerprint::from(base.artifact_fingerprint.clone())
                        != *artifact_fingerprint
                {
                    return Ok(None);
                }
                if loaded.prefix_state.is_some() {
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
                    return Ok(None);
                }
                let base = ScanResumeBaseState {
                    plan: base.plan.into_iter().map(PlannedCommit::from).collect(),
                    packed: base.packed.into_iter().map(PackCandidate::from).collect(),
                    loose: base.loose.into_iter().map(LooseCandidate::from).collect(),
                    path_arena: ByteArena::from_backing_bytes(base.path_arena),
                    tree_diff_stats: base.tree_diff_stats.into(),
                    spill_stats: base.spill_stats.into(),
                    mapping_stats: base.mapping_stats.into(),
                };

                let Some(prefix_state) = loaded.prefix_state else {
                    return Ok(Some(Self::PostSpillDedup(base)));
                };
                let prefix: StoredPrefixState = checkpoint_codec()
                    .deserialize(&prefix_state)
                    .map_err(|error| ScanCheckpointError::Decode(error.to_string()))?;
                let prefix = ScanResumePrefixState {
                    stage: prefix.stage,
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
                    ScanCheckpointStage::PostCommitPlan | ScanCheckpointStage::PostSpillDedup => {
                        Err(ScanCheckpointError::InvalidState(
                            "prefix checkpoint has an invalid stage discriminator".to_owned(),
                        ))
                    }
                    ScanCheckpointStage::PackPlanComplete => {
                        Ok(Some(Self::PackPlanComplete { base, prefix }))
                    }
                    ScanCheckpointStage::PreFinalize => {
                        Ok(Some(Self::PreFinalize { base, prefix }))
                    }
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

    #[must_use]
    pub(crate) const fn stage(&self) -> ScanCheckpointStage {
        match self {
            Self::PostCommitPlan(_) => ScanCheckpointStage::PostCommitPlan,
            Self::PostSpillDedup(_) => ScanCheckpointStage::PostSpillDedup,
            Self::PackPlanComplete { .. } => ScanCheckpointStage::PackPlanComplete,
            Self::PreFinalize { .. } => ScanCheckpointStage::PreFinalize,
        }
    }

    #[must_use]
    pub(crate) fn base_state(&self) -> Option<&ScanResumeBaseState> {
        match self {
            Self::PostCommitPlan(_) => None,
            Self::PostSpillDedup(state) => Some(state),
            Self::PackPlanComplete { base, .. } | Self::PreFinalize { base, .. } => Some(base),
        }
    }

    #[must_use]
    pub(crate) fn prefix_state(&self) -> Option<&ScanResumePrefixState> {
        match self {
            Self::PackPlanComplete { prefix, .. } | Self::PreFinalize { prefix, .. } => {
                Some(prefix)
            }
            Self::PostCommitPlan(_) | Self::PostSpillDedup(_) => None,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct CommitPlanResumeState {
    pub(crate) plan: Vec<PlannedCommit>,
}

#[derive(Clone, Debug)]
pub(crate) struct ScanResumeBaseState {
    pub(crate) plan: Vec<PlannedCommit>,
    pub(crate) packed: Vec<PackCandidate>,
    pub(crate) loose: Vec<LooseCandidate>,
    pub(crate) path_arena: ByteArena,
    pub(crate) tree_diff_stats: TreeDiffStats,
    pub(crate) spill_stats: SpillStats,
    pub(crate) mapping_stats: MappingStats,
}

#[derive(Clone, Debug)]
pub(crate) struct ScanResumePrefixState {
    pub(crate) stage: ScanCheckpointStage,
    pub(crate) completed_plan_count: usize,
    pub(crate) scanned: ScannedBlobs,
    pub(crate) skipped_candidates: Vec<SkippedCandidate>,
    pub(crate) common_metrics: GitScanCommonMetrics,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredPackCandidate {
    oid: Vec<u8>,
    ctx: StoredCandidateContext,
    pack_id: u16,
    offset: u64,
}

impl From<PackCandidate> for StoredPackCandidate {
    fn from(value: PackCandidate) -> Self {
        Self {
            oid: value.oid.as_slice().to_vec(),
            ctx: value.ctx.into(),
            pack_id: value.pack_id,
            offset: value.offset,
        }
    }
}

impl From<StoredPackCandidate> for PackCandidate {
    fn from(value: StoredPackCandidate) -> Self {
        Self {
            oid: OidBytes::from_slice(&value.oid),
            ctx: value.ctx.into(),
            pack_id: value.pack_id,
            offset: value.offset,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredLooseCandidate {
    oid: Vec<u8>,
    ctx: StoredCandidateContext,
}

impl From<LooseCandidate> for StoredLooseCandidate {
    fn from(value: LooseCandidate) -> Self {
        Self {
            oid: value.oid.as_slice().to_vec(),
            ctx: value.ctx.into(),
        }
    }
}

impl From<StoredLooseCandidate> for LooseCandidate {
    fn from(value: StoredLooseCandidate) -> Self {
        Self {
            oid: OidBytes::from_slice(&value.oid),
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
            spill_runs: value.spill_runs as usize,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredScannedBlob {
    oid: Vec<u8>,
    ctx: StoredCandidateContext,
    findings: StoredFindingSpan,
}

impl From<ScannedBlob> for StoredScannedBlob {
    fn from(value: ScannedBlob) -> Self {
        Self {
            oid: value.oid.as_slice().to_vec(),
            ctx: value.ctx.into(),
            findings: value.findings.into(),
        }
    }
}

impl From<StoredScannedBlob> for ScannedBlob {
    fn from(value: StoredScannedBlob) -> Self {
        Self {
            oid: OidBytes::from_slice(&value.oid),
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

#[derive(Clone, Debug, Serialize, Deserialize)]
struct StoredSkippedCandidate {
    oid: Vec<u8>,
    reason: StoredCandidateSkipReason,
}

impl From<SkippedCandidate> for StoredSkippedCandidate {
    fn from(value: SkippedCandidate) -> Self {
        Self {
            oid: value.oid.as_slice().to_vec(),
            reason: value.reason.into(),
        }
    }
}

impl From<StoredSkippedCandidate> for SkippedCandidate {
    fn from(value: StoredSkippedCandidate) -> Self {
        Self {
            oid: OidBytes::from_slice(&value.oid),
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

    #[test]
    fn resume_state_ignores_stale_artifact_fingerprint() {
        let checkpoint = StageCheckpoint::PostCommitPlan {
            scan_mode: GitScanMode::OdbBlobFast,
            artifact_fingerprint: &artifact(1),
            plan: &plan(),
        };
        let loaded = LoadedScanCheckpoint {
            base_state: checkpoint.encode_base_state().unwrap(),
            prefix_state: None,
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
        assert_eq!(&token[..4], b"gcp1");
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
}
