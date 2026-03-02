//! Maintenance preflight for Git repository scanning.
//!
//! Performs a deterministic readiness check without reading blobs:
//! - Resolve repository paths
//! - Verify commit-graph and MIDX presence
//! - Enforce pack count limits
//! - Detect maintenance lock files
//!
//! # Invariants
//! - No blob reads (metadata only).
//! - File reads are bounded by explicit limits.
//! - Outputs are deterministic for identical repo state.
//!
//! # Notes
//! - Alternate object directories are included when counting packs.
//! - Missing pack directories are ignored; other I/O errors are surfaced.

use std::ffi::OsStr;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use super::preflight_error::PreflightError;
use super::preflight_limits::PreflightLimits;
use super::repo::GitRepoPaths;

/// Paths to required artifact files.
///
/// These are derived from the resolved repository layout and do not imply
/// existence; `ArtifactStatus` reports whether they are present.
#[derive(Clone, Debug)]
pub struct ArtifactPaths {
    /// Path to the commit-graph file.
    pub commit_graph: PathBuf,
    /// Path to the multi-pack-index file.
    pub midx: PathBuf,
    /// Path to the pack directory.
    pub pack_dir: PathBuf,
}

/// Status of required artifacts (commit-graph, MIDX, lock files).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArtifactStatus {
    /// All required artifacts are present.
    Ready,
    /// One or more required artifacts are missing or locked.
    NeedsMaintenance {
        /// `true` if `info/commit-graph` is missing.
        missing_commit_graph: bool,
        /// `true` if `multi-pack-index` is missing.
        missing_midx: bool,
        /// `true` if a Git maintenance lock file is present.
        lock_present: bool,
    },
}

impl ArtifactStatus {
    /// Returns true if all artifacts are ready.
    #[inline]
    #[must_use]
    pub const fn is_ready(&self) -> bool {
        matches!(self, Self::Ready)
    }
}

/// Result of the preflight check.
///
/// The report is fully derived from repository metadata; no blob objects are
/// read during preflight and artifact contents are not parsed. Readiness is
/// reported separately from maintenance recommendations (pack count).
#[derive(Debug)]
pub struct PreflightReport {
    /// Resolved repository paths.
    pub repo: GitRepoPaths,
    /// Artifact paths derived from repository layout.
    pub artifact_paths: ArtifactPaths,
    /// Artifact readiness status.
    pub status: ArtifactStatus,
    /// Maintenance recommendation details.
    pub maintenance: PreflightMaintenance,
}

/// Maintenance recommendation details.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PreflightMaintenance {
    /// Total number of `*.pack` files observed (including alternates).
    ///
    /// This count is capped at `max_pack_count + 1` to allow early exit
    /// when the limit is exceeded.
    pub pack_count: u32,
    /// Pack count recommendation threshold.
    pub max_pack_count: u16,
    /// `true` if pack count exceeds the recommendation threshold.
    pub pack_count_exceeded: bool,
}

impl PreflightMaintenance {
    /// Returns true if maintenance is recommended.
    #[inline]
    #[must_use]
    pub const fn recommended(&self) -> bool {
        self.pack_count_exceeded
    }
}

/// Executes the maintenance preflight.
///
/// # Arguments
/// * `repo_root` - Path to repository (worktree or bare root)
/// * `limits` - Hard caps for preflight
///
/// # Returns
/// A `PreflightReport` containing artifact paths and readiness status.
///
/// # Errors
/// Returns `PreflightError` for repository discovery failures, malformed
/// metadata files, size limit violations, or I/O failures.
pub fn preflight(
    repo_root: &Path,
    limits: PreflightLimits,
) -> Result<PreflightReport, PreflightError> {
    limits.validate();

    let repo = GitRepoPaths::resolve(repo_root, &limits)?;

    let artifact_paths = ArtifactPaths {
        commit_graph: repo.objects_dir.join("info").join("commit-graph"),
        midx: repo.pack_dir.join("multi-pack-index"),
        pack_dir: repo.pack_dir.clone(),
    };

    let missing_commit_graph = !is_file(&artifact_paths.commit_graph);
    let missing_midx = !is_file(&artifact_paths.midx);
    let pack_count = count_pack_files(&repo, limits.max_pack_count)?;
    let pack_limit_exceeded = pack_count > limits.max_pack_count as u32;
    let lock_present = has_lock_files(&repo, &artifact_paths)?;

    let status = if missing_commit_graph || missing_midx || lock_present {
        ArtifactStatus::NeedsMaintenance {
            missing_commit_graph,
            missing_midx,
            lock_present,
        }
    } else {
        ArtifactStatus::Ready
    };

    Ok(PreflightReport {
        repo,
        artifact_paths,
        status,
        maintenance: PreflightMaintenance {
            pack_count,
            max_pack_count: limits.max_pack_count,
            pack_count_exceeded: pack_limit_exceeded,
        },
    })
}

/// Counts pack files across the repository and alternates.
///
/// The returned count is capped at `max_pack_count + 1` to allow callers to
/// detect limit violations without scanning every directory.
fn count_pack_files(repo: &GitRepoPaths, max_pack_count: u16) -> Result<u32, PreflightError> {
    let cap = max_pack_count as u32 + 1;
    let mut total = 0_u32;

    let mut pack_dirs = Vec::with_capacity(1 + repo.alternate_object_dirs.len());
    pack_dirs.push(repo.pack_dir.clone());
    for alternate in &repo.alternate_object_dirs {
        if alternate == &repo.objects_dir {
            continue;
        }
        pack_dirs.push(alternate.join("pack"));
    }

    for pack_dir in pack_dirs {
        if total >= cap {
            break;
        }
        let remaining = cap - total;
        total += count_pack_files_in_dir(&pack_dir, remaining)?;
    }

    Ok(total)
}

/// Counts pack files in a single `objects/pack` directory.
///
/// Only `*.pack` files are counted; `.idx` and other entries are ignored.
/// The count stops once `limit` is reached.
/// Missing directories return zero.
fn count_pack_files_in_dir(pack_dir: &Path, limit: u32) -> Result<u32, PreflightError> {
    if limit == 0 {
        return Ok(0);
    }

    let mut count = 0_u32;
    let entries = match fs::read_dir(pack_dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(err) => return Err(PreflightError::io(err)),
    };

    for entry in entries {
        let entry = entry.map_err(PreflightError::io)?;
        let file_type = entry.file_type().map_err(PreflightError::io)?;
        if !file_type.is_file() {
            continue;
        }

        let file_name = entry.file_name();
        if is_pack_file(&file_name) {
            count += 1;
            if count >= limit {
                break;
            }
        }
    }

    Ok(count)
}

/// Returns true if any maintenance lock files are present.
///
/// Only lock files alongside commit-graph, MIDX, and within pack directories
/// are checked. Other repository lock files are ignored by preflight.
fn has_lock_files(
    repo: &GitRepoPaths,
    artifact_paths: &ArtifactPaths,
) -> Result<bool, PreflightError> {
    if is_file(&lock_path(&artifact_paths.commit_graph))
        || is_file(&lock_path(&artifact_paths.midx))
    {
        return Ok(true);
    }

    let mut pack_dirs = Vec::with_capacity(1 + repo.alternate_object_dirs.len());
    pack_dirs.push(repo.pack_dir.clone());
    for alternate in &repo.alternate_object_dirs {
        if alternate == &repo.objects_dir {
            continue;
        }
        pack_dirs.push(alternate.join("pack"));
    }

    for pack_dir in pack_dirs {
        if has_lock_files_in_dir(&pack_dir)? {
            return Ok(true);
        }
    }

    Ok(false)
}

fn has_lock_files_in_dir(pack_dir: &Path) -> Result<bool, PreflightError> {
    let entries = match fs::read_dir(pack_dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(PreflightError::io(err)),
    };

    for entry in entries {
        let entry = entry.map_err(PreflightError::io)?;
        let file_type = entry.file_type().map_err(PreflightError::io)?;
        if !file_type.is_file() {
            continue;
        }

        let file_name = entry.file_name();
        if Path::new(&file_name)
            .extension()
            .is_some_and(|ext| ext == "lock")
        {
            return Ok(true);
        }
    }

    Ok(false)
}

#[inline]
fn lock_path(path: &Path) -> PathBuf {
    path.with_extension("lock")
}

/// Returns true if the filename ends with `.pack`.
fn is_pack_file(name: &OsStr) -> bool {
    Path::new(name).extension().is_some_and(|ext| ext == "pack")
}

/// Checks if a path is a file (follows symlinks).
#[inline]
fn is_file(path: &Path) -> bool {
    fs::metadata(path).map(|m| m.is_file()).unwrap_or(false)
}
