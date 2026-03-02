//! Repository discovery and open for Git scanning.
//!
//! This stage prepares a repository for scanning by:
//! - Resolving repository paths (worktree, bare, linked worktree)
//! - Detecting maintenance lock files and recording artifact fingerprints
//! - Resolving start set tips (refs to scan)
//! - Loading persisted watermarks for incremental scanning
//!
//! Artifacts (MIDX, commit-graph) are always built in memory from pack/idx
//! files in later phases (`artifact_acquire`). This module only performs
//! a lightweight existence check (`is_file()`) on the commit-graph path to
//! record its fingerprint; it does not mmap or parse disk-based artifacts.
//!
//! Packs are not mmapped here. They are opened on demand in later phases
//! per pack plan to avoid unnecessary FD and VMA pressure.
//!
//! # Invariants
//! - Start set refs are sorted deterministically by name.
//! - Fingerprints are `PackSet` only, derived from pack/idx metadata.
//!
//! # Concurrency
//! Repo maintenance must not mutate artifacts during a scan. We detect
//! maintenance by comparing fingerprints and checking for lock files;
//! the check is best-effort and does not guard against all races.

use std::fs::{self, File};
use std::io::{BufRead, Read};
use std::path::{Path, PathBuf};

use super::byte_arena::{ByteArena, ByteRef};
use super::bytes::BytesView;
use super::errors::RepoOpenError;
use super::limits::RepoOpenLimits;
use super::object_id::{ObjectFormat, OidBytes};
use super::repo::GitRepoPaths;
use super::start_set::StartSetId;

/// Paths to artifact files used for lock-file detection.
#[derive(Clone, Debug)]
pub struct RepoArtifactPaths {
    /// Path to the commit-graph file (used for lock detection only).
    pub commit_graph: PathBuf,
    /// Path to the multi-pack-index file (used for lock detection only).
    pub midx: PathBuf,
}

/// Artifact bytes populated by `artifact_acquire`.
///
/// The MIDX is stored here after `acquire_midx` builds it in memory.
/// The commit-graph is handled separately via `CommitGraphMem`.
#[derive(Debug, Default)]
pub struct RepoArtifactMmaps {
    /// Multi-pack-index bytes (built in-memory by `acquire_midx`).
    pub midx: Option<BytesView>,
}

/// Fingerprint for artifact change detection.
///
/// Uses hashes of pack/idx metadata (basename, size, mtime) to detect
/// changes without re-reading artifact files. It is a coarse detector
/// and does not verify pack contents.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepoArtifactFingerprint {
    /// Hash of `(pack_basename, size, mtime)` for all pack files.
    pub packs_hash: [u8; 32],
    /// Hash of `(idx_basename, size, mtime)` for all idx files.
    pub idx_hash: [u8; 32],
}

/// A ref in the start set with its resolved tip and optional watermark.
#[derive(Clone, Debug)]
pub struct StartSetRef {
    /// Interned ref name (e.g., `refs/heads/main`).
    pub name: ByteRef,
    /// Resolved commit OID at tip.
    pub tip: OidBytes,
    /// Last scanned tip OID for this ref (if previously scanned).
    pub watermark: Option<OidBytes>,
}

/// Complete state for a repository job after repo open.
///
/// This struct contains everything needed for later Git phases without
/// additional file opens (except pack files in pack processing phases). It
/// also records artifact fingerprints used to detect concurrent maintenance.
///
/// Artifacts (MIDX, commit-graph) are built in memory by `artifact_acquire`
/// after repo open. The `mmaps.midx` field is populated by `acquire_midx`.
///
/// # Invariants
/// - `start_set` is sorted lexicographically by ref name.
/// - `mmaps.midx` is `None` until `acquire_midx` populates it.
#[derive(Debug)]
pub struct RepoJobState {
    /// Resolved repository paths.
    pub paths: GitRepoPaths,

    /// Object ID format (SHA-1 or SHA-256).
    pub object_format: ObjectFormat,

    /// Paths to artifact files (used for lock-file detection).
    pub artifact_paths: RepoArtifactPaths,

    /// Artifact bytes populated by `artifact_acquire`.
    pub mmaps: RepoArtifactMmaps,

    /// Artifact fingerprints (set by `acquire_midx` from pack/idx metadata).
    pub artifact_fingerprint: Option<RepoArtifactFingerprint>,

    /// Arena for ref name storage.
    pub ref_names: ByteArena,

    /// Start set refs, sorted deterministically by name.
    ///
    /// Invariant: sorted by `ref_names.get(r.name)` lexicographically.
    pub start_set: Vec<StartSetRef>,
}

impl RepoJobState {
    /// Returns true if pack/idx files remain unchanged and no lock files are present.
    ///
    /// Returns `false` if no baseline fingerprint was captured.
    ///
    /// # Errors
    /// Returns `RepoOpenError` if filesystem operations fail (e.g., reading
    /// pack directory metadata or checking for lock files).
    pub fn artifacts_unchanged(&self) -> Result<bool, RepoOpenError> {
        let Some(ref expected) = self.artifact_fingerprint else {
            return Ok(false);
        };

        if has_lock_files(&self.paths, &self.artifact_paths)? {
            return Ok(false);
        }

        let current = RepoArtifactFingerprint::from_pack_dirs(&self.paths)?;
        Ok(&current == expected)
    }
}

impl RepoArtifactFingerprint {
    /// Creates a fingerprint from pack directories.
    ///
    /// Hashes the metadata (basename, size, mtime) of all pack and idx files.
    pub fn from_pack_dirs(paths: &GitRepoPaths) -> Result<Self, RepoOpenError> {
        use sha2::{Digest, Sha256};

        let mut pack_dirs = Vec::with_capacity(1 + paths.alternate_object_dirs.len());
        pack_dirs.push(paths.pack_dir.clone());
        for alternate in &paths.alternate_object_dirs {
            if alternate != &paths.objects_dir {
                pack_dirs.push(alternate.join("pack"));
            }
        }

        // Collect and sort pack/idx file metadata for deterministic hashing
        let mut pack_entries: Vec<(Vec<u8>, u64, i64)> = Vec::new();
        let mut idx_entries: Vec<(Vec<u8>, u64, i64)> = Vec::new();

        for pack_dir in &pack_dirs {
            let entries = match fs::read_dir(pack_dir) {
                Ok(e) => e,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
                Err(err) => return Err(RepoOpenError::io(err)),
            };

            for entry in entries {
                let entry = entry.map_err(RepoOpenError::io)?;
                let file_type = entry.file_type().map_err(RepoOpenError::io)?;
                if !file_type.is_file() {
                    continue;
                }

                let file_name = entry.file_name();
                let path = entry.path();
                let ext = path.extension().and_then(|e| e.to_str());

                let metadata = entry.metadata().map_err(RepoOpenError::io)?;
                let mtime = mtime_epoch_seconds(metadata.modified().map_err(RepoOpenError::io)?);

                let basename = file_name.as_encoded_bytes().to_vec();
                let size = metadata.len();

                match ext {
                    Some("pack") => pack_entries.push((basename, size, mtime)),
                    Some("idx") => idx_entries.push((basename, size, mtime)),
                    _ => {}
                }
            }
        }

        pack_entries.sort();
        idx_entries.sort();

        let mut pack_hasher = Sha256::new();
        for (basename, size, mtime) in &pack_entries {
            pack_hasher.update(basename);
            pack_hasher.update(b"\0");
            pack_hasher.update(size.to_le_bytes());
            pack_hasher.update(mtime.to_le_bytes());
        }
        let packs_hash: [u8; 32] = pack_hasher.finalize().into();

        let mut idx_hasher = Sha256::new();
        for (basename, size, mtime) in &idx_entries {
            idx_hasher.update(basename);
            idx_hasher.update(b"\0");
            idx_hasher.update(size.to_le_bytes());
            idx_hasher.update(mtime.to_le_bytes());
        }
        let idx_hash: [u8; 32] = idx_hasher.finalize().into();

        Ok(Self {
            packs_hash,
            idx_hash,
        })
    }
}

#[inline]
fn mtime_epoch_seconds(mtime: std::time::SystemTime) -> i64 {
    match mtime.duration_since(std::time::UNIX_EPOCH) {
        Ok(delta) => delta.as_secs().min(i64::MAX as u64) as i64,
        Err(err) => -(err.duration().as_secs().min(i64::MAX as u64) as i64),
    }
}

/// Trait for resolving start set refs.
///
/// Implement this with gix plumbing to enumerate refs per your start set
/// configuration (default branch only, all remotes, branches + tags, etc).
pub trait StartSetResolver {
    /// Resolves refs in the start set.
    ///
    /// # Requirements
    ///
    /// - Ref names must be fully qualified (e.g., `refs/heads/main`)
    /// - Tips must be commit OIDs (peel tags to commits)
    /// - Order does not matter (repo open sorts deterministically)
    ///
    /// # Errors
    ///
    /// Return an error if ref resolution fails.
    fn resolve(&self, paths: &GitRepoPaths) -> Result<Vec<(Vec<u8>, OidBytes)>, RepoOpenError>;
}

/// Trait for loading persisted ref watermarks.
///
/// Implement this with your database layer. The watermark store is keyed by
/// `(repo_id, policy_hash, start_set_id, ref_name)`.
pub trait RefWatermarkStore {
    /// Loads watermarks for the given refs.
    ///
    /// # Arguments
    ///
    /// * `repo_id` - Repository identifier
    /// * `policy_hash` - Policy identity (rules + merge semantics)
    /// * `start_set_id` - Start set configuration identity
    /// * `ref_names` - Ref names to load watermarks for (in order)
    ///
    /// # Returns
    ///
    /// A vector of `Option<OidBytes>` aligned with `ref_names`.
    /// Length must equal `ref_names.len()`.
    fn load_watermarks(
        &self,
        repo_id: u64,
        policy_hash: [u8; 32],
        start_set_id: StartSetId,
        ref_names: &[&[u8]],
    ) -> Result<Vec<Option<OidBytes>>, RepoOpenError>;
}

/// Executes repo discovery and open.
///
/// # Arguments
///
/// * `repo_root` - Path to repository (worktree or bare root)
/// * `repo_id` - Repository identifier (for watermark keys)
/// * `policy_hash` - Policy identity hash
/// * `start_set_id` - Start set configuration identity
/// * `resolver` - Start set resolver implementation
/// * `watermark_store` - Watermark store implementation
/// * `limits` - Hard caps for repo open
///
/// # Returns
///
/// A `RepoJobState` ready for later Git phases. Callers must call
/// `acquire_midx` and `acquire_commit_graph` before scanning.
///
/// # Errors
///
/// Returns an error if:
/// - Repository paths cannot be resolved
/// - Start set exceeds limits
/// - Watermark store returns wrong count
pub fn repo_open(
    repo_root: &Path,
    repo_id: u64,
    policy_hash: [u8; 32],
    start_set_id: StartSetId,
    resolver: &dyn StartSetResolver,
    watermark_store: &dyn RefWatermarkStore,
    limits: RepoOpenLimits,
) -> Result<RepoJobState, RepoOpenError> {
    limits.validate();

    let paths = GitRepoPaths::resolve(repo_root, &limits)?;
    let object_format = detect_object_format(&paths, &limits)?;

    let artifact_paths = RepoArtifactPaths {
        commit_graph: commit_graph_path(&paths.objects_dir),
        midx: paths.pack_dir.join("multi-pack-index"),
    };

    let (ref_names, start_set) = resolve_start_set_with_watermarks(
        repo_id,
        policy_hash,
        start_set_id,
        &paths,
        resolver,
        watermark_store,
        &limits,
    )?;

    Ok(RepoJobState {
        paths,
        object_format,
        artifact_paths,
        mmaps: RepoArtifactMmaps::default(),
        artifact_fingerprint: None,
        ref_names,
        start_set,
    })
}

fn commit_graph_path(objects_dir: &Path) -> PathBuf {
    let info_dir = objects_dir.join("info");
    let split_chain = info_dir.join("commit-graphs").join("commit-graph-chain");
    if is_file(&split_chain) {
        split_chain
    } else {
        info_dir.join("commit-graph")
    }
}

/// Resolves the start set, interns ref names, and loads watermarks.
///
/// The resolver output is sorted lexicographically by ref name to ensure a
/// deterministic order. Watermarks are fetched in that same order and then
/// paired back with their refs.
///
/// # Errors
/// Returns an error if limits are exceeded, ref names cannot be interned,
/// or the watermark store returns a mismatched count.
fn resolve_start_set_with_watermarks(
    repo_id: u64,
    policy_hash: [u8; 32],
    start_set_id: StartSetId,
    paths: &GitRepoPaths,
    resolver: &dyn StartSetResolver,
    watermark_store: &dyn RefWatermarkStore,
    limits: &RepoOpenLimits,
) -> Result<(ByteArena, Vec<StartSetRef>), RepoOpenError> {
    let mut refs = resolver.resolve(paths)?;

    if refs.len() > limits.max_refs_in_start_set as usize {
        return Err(RepoOpenError::StartSetTooLarge {
            count: refs.len(),
            max: limits.max_refs_in_start_set as usize,
        });
    }

    refs.sort_by(|(a, _), (b, _)| a.as_slice().cmp(b.as_slice()));

    let mut ref_names = ByteArena::with_capacity(limits.max_refname_arena_bytes);
    let mut interned_refs = Vec::with_capacity(refs.len());

    for (name_bytes, tip) in &refs {
        if name_bytes.len() > limits.max_refname_bytes as usize {
            return Err(RepoOpenError::RefNameTooLong {
                len: name_bytes.len(),
                max: limits.max_refname_bytes as usize,
            });
        }

        let name_ref = ref_names
            .intern(name_bytes)
            .ok_or(RepoOpenError::ArenaOverflow)?;

        interned_refs.push((name_ref, *tip));
    }

    let name_slices: Vec<&[u8]> = interned_refs
        .iter()
        .map(|(name_ref, _)| ref_names.get(*name_ref))
        .collect();

    let watermarks =
        watermark_store.load_watermarks(repo_id, policy_hash, start_set_id, &name_slices)?;

    if watermarks.len() != interned_refs.len() {
        return Err(RepoOpenError::WatermarkCountMismatch {
            got: watermarks.len(),
            expected: interned_refs.len(),
        });
    }

    let start_set: Vec<StartSetRef> = interned_refs
        .into_iter()
        .zip(watermarks)
        .map(|((name, tip), watermark)| StartSetRef {
            name,
            tip,
            watermark,
        })
        .collect();

    Ok((ref_names, start_set))
}

/// Returns true if the repository currently advertises any reachable refs.
///
/// This check is used as a guardrail for empty start-set handling in the
/// in-memory artifact path:
/// - Loose refs are detected by walking `common_dir/refs` recursively.
/// - Packed refs are detected by scanning `common_dir/packed-refs` entries.
///
/// Pseudo-refs (like `HEAD`) are intentionally excluded; this function is about
/// named refs that define start-set coverage.
pub(crate) fn repo_has_reachable_refs(paths: &GitRepoPaths) -> Result<bool, RepoOpenError> {
    if has_loose_refs(&paths.common_dir.join("refs"))? {
        return Ok(true);
    }
    has_packed_refs(&paths.common_dir.join("packed-refs"))
}

fn has_loose_refs(refs_dir: &Path) -> Result<bool, RepoOpenError> {
    let mut stack = vec![refs_dir.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => return Err(RepoOpenError::io(err)),
        };

        for entry in entries {
            let entry = entry.map_err(RepoOpenError::io)?;
            let file_type = entry.file_type().map_err(RepoOpenError::io)?;
            if file_type.is_dir() {
                stack.push(entry.path());
                continue;
            }
            if file_type.is_file() || file_type.is_symlink() {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn has_packed_refs(packed_refs_path: &Path) -> Result<bool, RepoOpenError> {
    let file = match File::open(packed_refs_path) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(RepoOpenError::io(err)),
    };

    let mut reader = std::io::BufReader::new(file);
    let mut line = String::new();
    loop {
        line.clear();
        let read = reader.read_line(&mut line).map_err(RepoOpenError::io)?;
        if read == 0 {
            break;
        }

        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('^') {
            continue;
        }

        if line.split_once(' ').is_some() || line.split_once('\t').is_some() {
            return Ok(true);
        }
    }

    Ok(false)
}

fn has_lock_files(
    paths: &GitRepoPaths,
    artifact_paths: &RepoArtifactPaths,
) -> Result<bool, RepoOpenError> {
    // Only artifact and pack directory locks are considered here.
    if is_file(&lock_path(&artifact_paths.commit_graph))
        || is_file(&lock_path(&artifact_paths.midx))
    {
        return Ok(true);
    }

    let mut pack_dirs = Vec::with_capacity(1 + paths.alternate_object_dirs.len());
    pack_dirs.push(paths.pack_dir.clone());
    for alternate in &paths.alternate_object_dirs {
        if alternate == &paths.objects_dir {
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

fn has_lock_files_in_dir(pack_dir: &Path) -> Result<bool, RepoOpenError> {
    let entries = match fs::read_dir(pack_dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(RepoOpenError::io(err)),
    };

    for entry in entries {
        let entry = entry.map_err(RepoOpenError::io)?;
        let file_type = entry.file_type().map_err(RepoOpenError::io)?;
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

/// Detects the repository object format via config.
///
/// Returns `ObjectFormat::Sha256` if any config file contains a line matching
/// `objectformat` and `sha256` (case-insensitive). **Defaults to SHA-1** if
/// no config file is found or no matching line exists.
///
/// This is a lightweight heuristic scan, not a full Git config parser. It:
/// - Reads the first existing config path
/// - Ignores comments and blank lines
/// - Does not parse sections or handle multi-line values
fn detect_object_format(
    paths: &GitRepoPaths,
    limits: &RepoOpenLimits,
) -> Result<ObjectFormat, RepoOpenError> {
    for config_path in paths.config_paths() {
        if !config_path.is_file() {
            continue;
        }

        let bytes = read_bounded_file(&config_path, limits.max_config_file_bytes)?;
        let text = std::str::from_utf8(&bytes).map_err(|_| RepoOpenError::InvalidUtf8Config)?;

        for line in text.lines() {
            let line = line.trim();
            if line.starts_with('#') || line.starts_with(';') || line.is_empty() {
                continue;
            }

            let lower = line.to_ascii_lowercase();
            if lower.contains("objectformat") && lower.contains("sha256") {
                return Ok(ObjectFormat::Sha256);
            }
        }

        return Ok(ObjectFormat::Sha1);
    }

    Ok(ObjectFormat::Sha1)
}

/// Reads a file with a maximum byte limit.
///
/// The size check is done via metadata first; the read itself is bounded via
/// `take()` to guard against concurrent file growth.
fn read_bounded_file(path: &Path, max_bytes: u32) -> Result<Vec<u8>, RepoOpenError> {
    let file = File::open(path).map_err(RepoOpenError::io)?;
    let metadata = file.metadata().map_err(RepoOpenError::io)?;

    if metadata.len() > max_bytes as u64 {
        return Err(RepoOpenError::FileTooLarge {
            size: metadata.len(),
            limit: max_bytes,
        });
    }

    let size = metadata.len() as usize;
    let mut buffer = Vec::with_capacity(size);
    let mut take = file.take(max_bytes as u64);
    take.read_to_end(&mut buffer).map_err(RepoOpenError::io)?;

    Ok(buffer)
}

#[inline]
fn is_file(path: &Path) -> bool {
    fs::metadata(path).map(|m| m.is_file()).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::mtime_epoch_seconds;
    use std::time::{Duration, UNIX_EPOCH};

    #[test]
    fn mtime_epoch_seconds_preserves_post_epoch_values() {
        let t = UNIX_EPOCH + Duration::from_secs(42);
        assert_eq!(mtime_epoch_seconds(t), 42);
    }

    #[test]
    fn mtime_epoch_seconds_preserves_pre_epoch_values() {
        let t = UNIX_EPOCH - Duration::from_secs(7);
        assert_eq!(mtime_epoch_seconds(t), -7);
    }
}
