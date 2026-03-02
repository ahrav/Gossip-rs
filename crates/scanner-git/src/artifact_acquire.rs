//! Artifact construction for Git scanning.
//!
//! This module builds in-memory MIDX and commit-graph artifacts from pack
//! index files and commit data. It does not attempt to reuse on-disk
//! artifacts.
//!
//! # Construction Flow
//!
//! 1. `acquire_midx()`: Builds MIDX from `.idx` files via k-way merge
//! 2. `acquire_commit_graph()`: Loads commits and builds `CommitGraphMem`
//!
//! # Memory Limits
//!
//! The `ArtifactBuildLimits` struct provides hard caps on artifact
//! construction to prevent runaway memory usage on large repositories.
//!
//! # Consistency
//! When artifacts are built, `RepoJobState` is mutated to store the new bytes
//! and to set fingerprints to the `PackSet` variant. Callers should re-check
//! `artifacts_unchanged` before starting any pack scans.

use std::fmt;
use std::io;
use std::path::PathBuf;

use super::bytes::BytesView;
use super::commit_graph_mem::CommitGraphMem;
use super::commit_loader::{
    load_commits_from_tips, load_commits_with_identities, load_shallow_boundary_roots,
    resolve_pack_paths_from_midx, CommitLoadError, CommitLoadLimits,
};
use super::errors::{CommitPlanError, RepoOpenError};
use super::identity_intern::IdentityInterner;
use super::midx::MidxView;
use super::midx_build::{build_midx_bytes, MidxBuildError, MidxBuildLimits};
use super::midx_error::MidxError;
use super::object_id::OidBytes;
use super::repo_open::{repo_has_reachable_refs, RepoArtifactFingerprint, RepoJobState};
use super::repo_paths::{collect_loose_dirs, collect_pack_dirs};

/// Limits for in-memory artifact construction.
///
/// These limits are enforced only when building artifacts in memory; they do
/// not apply to disk-backed artifact access in `repo_open`.
#[derive(Clone, Copy, Debug, Default)]
pub struct ArtifactBuildLimits {
    /// MIDX build limits.
    pub midx: MidxBuildLimits,
    /// Commit loading limits.
    pub commit_load: CommitLoadLimits,
}

/// Errors from artifact acquisition.
#[derive(Debug)]
#[non_exhaustive]
pub enum ArtifactAcquireError {
    /// I/O error during artifact access.
    Io(io::Error),
    /// MIDX build failed.
    MidxBuild(MidxBuildError),
    /// MIDX parsing failed.
    MidxParse(MidxError),
    /// Commit loading failed during in-memory graph build.
    CommitLoad(CommitLoadError),
    /// In-memory commit graph construction failed.
    CommitGraphBuild(CommitPlanError),
    /// Repo open error (e.g., fingerprint computation).
    RepoOpen(RepoOpenError),
    /// Start set resolved to zero tips while repository refs are present.
    ///
    /// This is treated as an explicit error so scans cannot silently become
    /// no-ops on repositories that still advertise reachable refs.
    EmptyStartSetWithRefs,
    /// Concurrent maintenance detected.
    ConcurrentMaintenance,
}

impl fmt::Display for ArtifactAcquireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "artifact I/O error: {err}"),
            Self::MidxBuild(err) => write!(f, "MIDX build failed: {err}"),
            Self::MidxParse(err) => write!(f, "MIDX parse failed: {err}"),
            Self::CommitLoad(err) => write!(f, "commit loading failed: {err}"),
            Self::CommitGraphBuild(err) => write!(f, "commit graph build failed: {err}"),
            Self::RepoOpen(err) => write!(f, "repo open error: {err}"),
            Self::EmptyStartSetWithRefs => {
                write!(
                    f,
                    "empty start set while repository refs exist (refusing silent no-op scan)"
                )
            }
            Self::ConcurrentMaintenance => write!(f, "concurrent maintenance detected"),
        }
    }
}

impl std::error::Error for ArtifactAcquireError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::MidxBuild(err) => Some(err),
            Self::MidxParse(err) => Some(err),
            Self::CommitLoad(err) => Some(err),
            Self::CommitGraphBuild(err) => Some(err),
            Self::RepoOpen(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for ArtifactAcquireError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<MidxBuildError> for ArtifactAcquireError {
    fn from(err: MidxBuildError) -> Self {
        Self::MidxBuild(err)
    }
}

impl From<MidxError> for ArtifactAcquireError {
    fn from(err: MidxError) -> Self {
        Self::MidxParse(err)
    }
}

impl From<CommitLoadError> for ArtifactAcquireError {
    fn from(err: CommitLoadError) -> Self {
        Self::CommitLoad(err)
    }
}

impl From<RepoOpenError> for ArtifactAcquireError {
    fn from(err: RepoOpenError) -> Self {
        Self::RepoOpen(err)
    }
}

/// Output of MIDX acquisition, carrying the MIDX bytes and resolved
/// pack file paths needed for subsequent pack planning and execution.
pub struct MidxAcquireResult {
    /// The acquired MIDX bytes (built in-memory).
    pub bytes: BytesView,
    /// Whether the MIDX was built in-memory (vs. loaded from disk).
    pub built_in_memory: bool,
    /// Pack file paths in MIDX order.
    ///
    /// These paths align with `pack_id` values in the MIDX.
    pub pack_paths: Vec<PathBuf>,
}

/// Acquires MIDX data by building it in memory.
///
/// # Arguments
/// * `repo` - Repository state from `repo_open`
/// * `limits` - Build limits for artifact construction
///
/// # Returns
/// A `MidxAcquireResult` containing the MIDX bytes and metadata.
///
/// # Behavior
/// Builds the MIDX from `.idx` files via k-way merge; existing on-disk MIDX
/// files are not consulted.
///
/// # Side Effects
/// This function updates `repo.mmaps.midx` with the built bytes and sets
/// the fingerprint to `PackSet` variant.
///
/// # Errors
/// Returns:
/// - `ArtifactAcquireError::MidxBuild` when in-memory MIDX construction fails.
/// - `ArtifactAcquireError::MidxParse` when the freshly built bytes do not
///   parse for `repo.object_format`.
/// - `ArtifactAcquireError::CommitLoad` when MIDX pack names cannot be resolved
///   to `.pack` paths.
/// - `ArtifactAcquireError::RepoOpen` if fingerprint refresh fails.
pub fn acquire_midx(
    repo: &mut RepoJobState,
    limits: &ArtifactBuildLimits,
) -> Result<MidxAcquireResult, ArtifactAcquireError> {
    let midx_bytes = build_midx_bytes(&repo.paths, repo.object_format, &limits.midx)?;
    MidxView::parse(midx_bytes.as_slice(), repo.object_format)?;
    let pack_paths = resolve_pack_paths(repo, &midx_bytes)?;

    let packset_fingerprint = RepoArtifactFingerprint::from_pack_dirs(&repo.paths)?;
    repo.artifact_fingerprint = Some(packset_fingerprint);

    repo.mmaps.midx = Some(midx_bytes.clone());

    Ok(MidxAcquireResult {
        bytes: midx_bytes,
        built_in_memory: true,
        pack_paths,
    })
}

/// Builds the commit-graph from commit data.
///
/// # Arguments
/// * `repo` - Repository state from `repo_open`
/// * `midx` - Parsed MIDX view (needed for commit loading)
/// * `pack_paths` - Pack file paths in MIDX order
/// * `limits` - Build limits for artifact construction
///
/// # Returns
/// A `CommitGraphMem` that can be used for commit traversal.
///
/// # Behavior
/// Loads commits via BFS from the start set tips and builds `CommitGraphMem`.
/// Commit lookup prefers MIDX-backed packs and falls back to loose object
/// directories when a tip/parent OID is absent from MIDX.
/// The graph contains only commits reachable from `repo.start_set` tips.
/// Parents outside that set are treated as external roots.
///
/// If `repo.start_set` is empty but repository refs still exist, this returns
/// `ArtifactAcquireError::EmptyStartSetWithRefs` instead of silently producing
/// an empty graph.
///
/// Bounded by `limits.commit_load`.
///
/// # Errors
/// Returns `ArtifactAcquireError` when shallow-boundary loading or commit
/// loading fails, or when `CommitGraphMem` rejects the loaded commit set.
pub fn acquire_commit_graph(
    repo: &RepoJobState,
    midx: &MidxView<'_>,
    pack_paths: &[PathBuf],
    limits: &ArtifactBuildLimits,
) -> Result<CommitGraphMem, ArtifactAcquireError> {
    let tips: Vec<OidBytes> = repo.start_set.iter().map(|r| r.tip).collect();

    if tips.is_empty() {
        if repo_has_reachable_refs(&repo.paths)? {
            return Err(ArtifactAcquireError::EmptyStartSetWithRefs);
        }

        // Repository has no reachable refs; empty graph is expected.
        return CommitGraphMem::build(vec![], repo.object_format)
            .map_err(ArtifactAcquireError::CommitGraphBuild);
    }

    let loose_dirs = collect_loose_dirs(&repo.paths);
    let shallow_boundary_roots =
        load_shallow_boundary_roots(&repo.paths, repo.object_format, &limits.commit_load)?;
    let commits = load_commits_from_tips(
        &tips,
        midx,
        pack_paths,
        &loose_dirs,
        &shallow_boundary_roots,
        repo.object_format,
        &limits.commit_load,
        None, // No progress callback for now
    )?;

    CommitGraphMem::build(commits, repo.object_format)
        .map_err(ArtifactAcquireError::CommitGraphBuild)
}

/// Builds the commit-graph with identity enrichment.
///
/// Same tip resolution and BFS traversal as [`acquire_commit_graph`], but also
/// extracts and interns author/committer identity strings from each commit's
/// raw bytes. Returns both the identity-enriched `CommitGraphMem` and the
/// `IdentityInterner` that holds the deduped string data.
///
/// The interner is allocated with a 4 MiB arena and an initial estimate of
/// 16,384 unique identity strings.
///
/// If `repo.start_set` is empty and the repository has no reachable refs, this
/// returns an empty graph and an empty interner.
///
/// # Errors
/// Same error surface as [`acquire_commit_graph`], plus interning failures
/// surfaced by `load_commits_with_identities`.
pub fn acquire_commit_graph_with_identities(
    repo: &RepoJobState,
    midx: &MidxView<'_>,
    pack_paths: &[PathBuf],
    limits: &ArtifactBuildLimits,
) -> Result<(CommitGraphMem, IdentityInterner), ArtifactAcquireError> {
    let tips: Vec<OidBytes> = repo.start_set.iter().map(|r| r.tip).collect();

    if tips.is_empty() {
        if repo_has_reachable_refs(&repo.paths)? {
            return Err(ArtifactAcquireError::EmptyStartSetWithRefs);
        }

        let graph = CommitGraphMem::build(vec![], repo.object_format)
            .map_err(ArtifactAcquireError::CommitGraphBuild)?;
        let interner = IdentityInterner::with_capacity(0, 0);
        return Ok((graph, interner));
    }

    let loose_dirs = collect_loose_dirs(&repo.paths);
    let shallow_boundary_roots =
        load_shallow_boundary_roots(&repo.paths, repo.object_format, &limits.commit_load)?;
    let mut interner = IdentityInterner::with_capacity(4 * 1024 * 1024, 16_384);

    let (commits, identity_ids) = load_commits_with_identities(
        &tips,
        midx,
        pack_paths,
        &loose_dirs,
        &shallow_boundary_roots,
        repo.object_format,
        &limits.commit_load,
        &mut interner,
        None, // No progress callback for now
    )?;

    let graph = CommitGraphMem::build_with_identities(commits, identity_ids, repo.object_format)
        .map_err(ArtifactAcquireError::CommitGraphBuild)?;

    Ok((graph, interner))
}

/// Resolves `.pack` paths from freshly built MIDX bytes.
///
/// Re-parses the MIDX bytes for the repository object format, then resolves
/// pack names using directory precedence from [`collect_pack_dirs`].
fn resolve_pack_paths(
    repo: &RepoJobState,
    midx_bytes: &BytesView,
) -> Result<Vec<PathBuf>, ArtifactAcquireError> {
    let midx = MidxView::parse(midx_bytes.as_slice(), repo.object_format)?;
    let pack_dirs = collect_pack_dirs(&repo.paths);
    resolve_pack_paths_from_midx(&midx, &pack_dirs).map_err(ArtifactAcquireError::CommitLoad)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn artifact_build_limits_default() {
        let limits = ArtifactBuildLimits::default();
        assert!(limits.midx.max_packs > 0);
        assert!(limits.commit_load.max_commits > 0);
        assert!(limits.commit_load.max_shallow_file_bytes > 0);
        assert!(limits.commit_load.max_shallow_roots > 0);
    }
}
