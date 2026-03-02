//! Repository path resolution and layout detection for Git scanning.
//!
//! This module handles:
//! - Normal worktrees (`.git` directory)
//! - Linked worktrees (`.git` file pointing to `worktrees/<n>`)
//! - Bare repositories (no worktree, `HEAD` + `objects` in root)
//! - Alternates (shared object stores)
//!
//! # Invariants
//! - All file reads are bounded by limits (no unbounded reads).
//! - All returned paths are canonicalized and validated to exist,
//!   except `pack_dir` which may not exist in empty repositories.
//! - Path comparisons are reliable after canonicalization.
//!
//! # Failure Modes
//! - Malformed `.git` or `commondir` files return dedicated errors.
//! - Missing directories (objects, common dir, alternates) are reported.
//! - File size limits are enforced before reading file contents.
//!
//! # Trust Model
//! This module trusts repository contents (`.git` files, `commondir`,
//! `alternates`). Paths are followed wherever they point, including
//! symlinks. This matches Git's behavior.
//!
//! # Concurrency Note
//! Path validation is point-in-time. The repository structure may change
//! between resolution and subsequent operations (TOCTOU).

use std::ffi::OsStr;
use std::fs::{self, File};
use std::io;
use std::io::Read;
use std::path::{Path, PathBuf};

use super::errors::RepoOpenError;
use super::limits::RepoOpenLimits;

/// Limits required for repository path resolution.
pub trait RepoLimits {
    /// Maximum bytes to read from `.git` file (gitdir pointer).
    fn max_dot_git_file_bytes(&self) -> u32;
    /// Maximum bytes to read from `commondir` file.
    fn max_commondir_file_bytes(&self) -> u32;
    /// Maximum bytes to read from `info/alternates` file.
    fn max_alternates_file_bytes(&self) -> u32;
    /// Maximum number of alternates to accept.
    fn max_alternates_count(&self) -> u8;
}

impl RepoLimits for RepoOpenLimits {
    fn max_dot_git_file_bytes(&self) -> u32 {
        self.max_dot_git_file_bytes
    }

    fn max_commondir_file_bytes(&self) -> u32 {
        self.max_commondir_file_bytes
    }

    fn max_alternates_file_bytes(&self) -> u32 {
        self.max_alternates_file_bytes
    }

    fn max_alternates_count(&self) -> u8 {
        self.max_alternates_count
    }
}

/// Error contract required for repository path resolution.
pub trait RepoError: Sized {
    /// I/O error during file operations.
    fn io(err: io::Error) -> Self;
    /// Path canonicalization failed.
    fn canonicalization(err: io::Error) -> Self;
    /// Not a Git repository (no .git dir/file, not bare).
    fn not_a_repository() -> Self;
    /// The .git file is malformed (bad gitdir pointer).
    fn malformed_gitdir_file() -> Self;
    /// The gitdir target doesn't exist or isn't a directory.
    fn gitdir_target_not_dir() -> Self;
    /// The commondir file is malformed.
    fn malformed_commondir_file() -> Self;
    /// The common directory doesn't exist or isn't a directory.
    fn common_dir_not_dir() -> Self;
    /// The objects directory doesn't exist or isn't a directory.
    fn objects_dir_not_dir() -> Self;
    /// An alternate object directory doesn't exist or isn't a directory.
    fn alternate_not_dir() -> Self;
    /// File exceeds size limit.
    fn file_too_large(size: u64, limit: u32) -> Self;
}

impl RepoError for RepoOpenError {
    fn io(err: io::Error) -> Self {
        Self::io(err)
    }

    fn canonicalization(err: io::Error) -> Self {
        Self::canonicalization(err)
    }

    fn not_a_repository() -> Self {
        Self::NotARepository
    }

    fn malformed_gitdir_file() -> Self {
        Self::MalformedGitdirFile
    }

    fn gitdir_target_not_dir() -> Self {
        Self::GitdirTargetNotDir
    }

    fn malformed_commondir_file() -> Self {
        Self::MalformedCommondirFile
    }

    fn common_dir_not_dir() -> Self {
        Self::CommonDirNotDir
    }

    fn objects_dir_not_dir() -> Self {
        Self::ObjectsDirNotDir
    }

    fn alternate_not_dir() -> Self {
        Self::AlternateNotDir
    }

    fn file_too_large(size: u64, limit: u32) -> Self {
        Self::FileTooLarge { size, limit }
    }
}

/// Type of Git repository detected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RepoKind {
    /// Normal repository with worktree.
    Worktree,
    /// Bare repository (no worktree).
    Bare,
}

/// Resolved paths for a Git repository.
///
/// All paths are canonicalized and validated to exist at resolution time,
/// except `pack_dir` which may be missing in an empty repository.
#[derive(Clone, Debug)]
pub struct GitRepoPaths {
    /// Repository kind (worktree or bare).
    pub kind: RepoKind,

    /// Worktree root (where working files live).
    /// `None` for bare repositories.
    /// Canonicalized.
    pub worktree_root: Option<PathBuf>,

    /// The `.git` directory (or bare repo root).
    /// For linked worktrees, this is the worktree-specific gitdir.
    /// Canonicalized.
    pub git_dir: PathBuf,

    /// The common directory for shared data.
    /// For normal repos: same as `git_dir`.
    /// For linked worktrees: the main repo's `.git` directory.
    /// Canonicalized.
    pub common_dir: PathBuf,

    /// The `objects` directory.
    /// Always under `common_dir`.
    /// Canonicalized.
    pub objects_dir: PathBuf,

    /// The `objects/pack` directory.
    /// May not exist in empty repositories.
    pub pack_dir: PathBuf,

    /// Alternate object directories (from `info/alternates`).
    ///
    /// May be empty; bounded by limits. Only immediate alternates are
    /// resolved; recursive alternates are not expanded. Canonicalized.
    pub alternate_object_dirs: Vec<PathBuf>,
}

impl GitRepoPaths {
    /// Resolves repository paths from a root path.
    ///
    /// The root can be:
    /// - A worktree root (containing `.git` dir or file)
    /// - A bare repository root (containing `HEAD` + `objects`)
    ///
    /// # Algorithm
    /// - Prefer `.git` directory or file if present.
    /// - Otherwise, fall back to a bare-repo heuristic (`HEAD`, `objects`,
    ///   and either `refs` or `config` exist).
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The path is not a Git repository
    /// - Required directories are missing
    /// - File reads exceed limits
    /// - Path canonicalization fails
    pub fn resolve<E, L>(repo_root: &Path, limits: &L) -> Result<Self, E>
    where
        E: RepoError,
        L: RepoLimits,
    {
        assert!(
            !repo_root.as_os_str().is_empty(),
            "repo_root cannot be empty"
        );

        let dot_git = repo_root.join(".git");

        match fs::symlink_metadata(&dot_git) {
            Ok(meta) if meta.is_dir() => {
                // Case 1: .git is a directory (normal worktree)
                let git_dir = canonicalize_path(&dot_git)?;
                let worktree_root = Some(canonicalize_path(repo_root)?);
                return Self::from_git_dir(RepoKind::Worktree, worktree_root, git_dir, limits);
            }
            Ok(meta) if meta.is_file() => {
                // Case 2: .git is a file (linked worktree)
                let git_dir = parse_gitdir_file(&dot_git, repo_root, limits)?;
                let worktree_root = Some(canonicalize_path(repo_root)?);
                return Self::from_git_dir(RepoKind::Worktree, worktree_root, git_dir, limits);
            }
            _ => {}
        }

        // Case 3: Bare repository heuristic
        let head = repo_root.join("HEAD");
        let objects = repo_root.join("objects");
        let refs = repo_root.join("refs");
        let config = repo_root.join("config");

        let is_bare = is_file(&head) && is_dir(&objects) && (is_dir(&refs) || is_file(&config));

        if is_bare {
            let git_dir = canonicalize_path(repo_root)?;
            return Self::from_git_dir(RepoKind::Bare, None, git_dir, limits);
        }

        Err(E::not_a_repository())
    }

    /// Returns true if this is a linked worktree (git_dir != common_dir).
    #[inline]
    #[must_use]
    pub fn is_linked_worktree(&self) -> bool {
        self.git_dir != self.common_dir
    }

    /// Resolves paths given a known git directory.
    ///
    /// `git_dir` must already be canonicalized. This routine also validates
    /// the `objects` directory and parses `info/alternates`.
    fn from_git_dir<E, L>(
        kind: RepoKind,
        worktree_root: Option<PathBuf>,
        git_dir: PathBuf,
        limits: &L,
    ) -> Result<Self, E>
    where
        E: RepoError,
        L: RepoLimits,
    {
        assert!(!git_dir.as_os_str().is_empty(), "git_dir cannot be empty");
        assert!(
            limits.max_alternates_count() > 0,
            "must allow at least 1 alternate"
        );

        let common_dir = resolve_common_dir::<E, L>(&git_dir, limits)?;

        let objects_dir = common_dir.join("objects");
        if !is_dir(&objects_dir) {
            return Err(E::objects_dir_not_dir());
        }
        let objects_dir = canonicalize_path::<E>(&objects_dir)?;

        let pack_dir = objects_dir.join("pack");

        let alternate_object_dirs = parse_alternates::<E, L>(&objects_dir, limits)?;

        debug_assert!(
            objects_dir.starts_with(&common_dir),
            "objects_dir must be under common_dir"
        );

        Ok(Self {
            kind,
            worktree_root,
            git_dir,
            common_dir,
            objects_dir,
            pack_dir,
            alternate_object_dirs,
        })
    }

    /// Returns path candidates for the Git config file.
    ///
    /// For normal repos: returns `common_dir/config`.
    /// For linked worktrees: returns `common_dir/config` only.
    ///
    /// Note: Worktree-specific config (`git_dir/config.worktree`) is not
    /// currently supported. The standard config in `common_dir` is used.
    pub fn config_paths(&self) -> impl Iterator<Item = PathBuf> + '_ {
        std::iter::once(self.common_dir.join("config"))
    }
}

/// Parses a `.git` file to extract the gitdir path.
///
/// Expected format: `gitdir: <path>\n`. The path may contain non-UTF-8 bytes.
///
/// Relative paths are resolved against the worktree root (`base_dir`),
/// matching Git's behavior for linked worktrees.
fn parse_gitdir_file<E, L>(dot_git_file: &Path, base_dir: &Path, limits: &L) -> Result<PathBuf, E>
where
    E: RepoError,
    L: RepoLimits,
{
    let bytes = read_bounded_file::<E>(dot_git_file, limits.max_dot_git_file_bytes())?;

    let path = parse_gitdir_bytes(&bytes).ok_or(E::malformed_gitdir_file())?;

    let resolved = resolve_path(base_dir, &path);
    let canonical = canonicalize_path::<E>(&resolved)?;

    if !is_dir(&canonical) {
        return Err(E::gitdir_target_not_dir());
    }

    Ok(canonical)
}

/// Parses gitdir file content as bytes, handling non-UTF-8 paths.
///
/// Leading whitespace after `gitdir:` is skipped; trailing newlines are
/// trimmed. Empty paths are rejected.
fn parse_gitdir_bytes(bytes: &[u8]) -> Option<PathBuf> {
    const PREFIX: &[u8] = b"gitdir:";

    if !bytes.starts_with(PREFIX) {
        return None;
    }

    let mut path_bytes = &bytes[PREFIX.len()..];

    while path_bytes
        .first()
        .is_some_and(|b| *b == b' ' || *b == b'\t')
    {
        path_bytes = &path_bytes[1..];
    }

    while path_bytes
        .last()
        .is_some_and(|b| *b == b'\n' || *b == b'\r')
    {
        path_bytes = &path_bytes[..path_bytes.len() - 1];
    }

    if path_bytes.is_empty() {
        return None;
    }

    Some(bytes_to_path(path_bytes))
}

/// Resolves the common directory for a git directory.
///
/// If a `commondir` file exists, it is interpreted relative to `git_dir`.
fn resolve_common_dir<E, L>(git_dir: &Path, limits: &L) -> Result<PathBuf, E>
where
    E: RepoError,
    L: RepoLimits,
{
    let commondir_file = git_dir.join("commondir");

    if !is_file(&commondir_file) {
        return Ok(git_dir.to_path_buf());
    }

    let bytes = read_bounded_file::<E>(&commondir_file, limits.max_commondir_file_bytes())?;

    let path = parse_commondir_bytes(&bytes).ok_or(E::malformed_commondir_file())?;

    let resolved = resolve_path(git_dir, &path);
    let canonical = canonicalize_path::<E>(&resolved)?;

    if !is_dir(&canonical) {
        return Err(E::common_dir_not_dir());
    }

    Ok(canonical)
}

/// Parses commondir file content as bytes.
///
/// Trailing newlines are trimmed; empty content is rejected.
fn parse_commondir_bytes(bytes: &[u8]) -> Option<PathBuf> {
    let mut path_bytes = bytes;

    while path_bytes
        .last()
        .is_some_and(|b| *b == b'\n' || *b == b'\r')
    {
        path_bytes = &path_bytes[..path_bytes.len() - 1];
    }

    if path_bytes.is_empty() {
        return None;
    }

    Some(bytes_to_path(path_bytes))
}

/// Parses the `info/alternates` file to get alternate object directories.
///
/// The file format is one path per line. Blank lines and `#` comments are
/// ignored. Parsing stops after a bounded number of lines and paths to keep
/// runtime and memory bounded. Relative paths are resolved against the
/// repository's `objects` directory, matching Git's behavior.
fn parse_alternates<E, L>(objects_dir: &Path, limits: &L) -> Result<Vec<PathBuf>, E>
where
    E: RepoError,
    L: RepoLimits,
{
    let alternates_file = objects_dir.join("info").join("alternates");

    if !is_file(&alternates_file) {
        return Ok(Vec::new());
    }

    let bytes = read_bounded_file::<E>(&alternates_file, limits.max_alternates_file_bytes())?;

    let max_count = limits.max_alternates_count() as usize;
    let mut alternates = Vec::with_capacity(max_count.min(8));

    let max_lines = max_count * 2; // Account for comments and blank lines
    let mut line_count = 0;

    for line in bytes.split(|&b| b == b'\n') {
        line_count += 1;
        if line_count > max_lines {
            break;
        }

        let trimmed = line.trim_ascii();
        if trimmed.is_empty() || trimmed.starts_with(b"#") {
            continue;
        }

        if alternates.len() >= max_count {
            break;
        }

        let path = bytes_to_path(trimmed);
        let resolved = resolve_path(objects_dir, &path);

        let canonical = match canonicalize_path::<E>(&resolved) {
            Ok(p) => p,
            Err(_) => return Err(E::alternate_not_dir()),
        };

        if !is_dir(&canonical) {
            return Err(E::alternate_not_dir());
        }

        alternates.push(canonical);
    }

    assert!(alternates.len() <= max_count);

    Ok(alternates)
}

/// Resolves a path that may be relative or absolute.
///
/// Relative paths are interpreted against the provided base directory.
fn resolve_path(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

/// Canonicalizes a path, resolving symlinks and `..` components.
///
/// Errors are mapped via `RepoError::canonicalization`.
fn canonicalize_path<E: RepoError>(path: &Path) -> Result<PathBuf, E> {
    fs::canonicalize(path).map_err(E::canonicalization)
}

/// Reads a file with a maximum byte limit.
///
/// The file size is checked via metadata before reading. The read itself is
/// capped with `take()` to guard against concurrent file growth.
fn read_bounded_file<E: RepoError>(path: &Path, max_bytes: u32) -> Result<Vec<u8>, E> {
    let file = File::open(path).map_err(E::io)?;
    let metadata = file.metadata().map_err(E::io)?;

    if metadata.len() > max_bytes as u64 {
        return Err(E::file_too_large(metadata.len(), max_bytes));
    }

    let size = metadata.len() as usize;
    let mut buffer = Vec::with_capacity(size);
    let mut take = file.take(max_bytes as u64);
    take.read_to_end(&mut buffer).map_err(E::io)?;

    Ok(buffer)
}

/// Converts byte slice to PathBuf, handling platform differences.
///
/// On Unix, raw bytes are preserved. On non-Unix platforms, invalid UTF-8 is
/// lossy-converted.
#[cfg(unix)]
fn bytes_to_path(bytes: &[u8]) -> PathBuf {
    use std::os::unix::ffi::OsStrExt;
    PathBuf::from(OsStr::from_bytes(bytes))
}

#[cfg(not(unix))]
fn bytes_to_path(bytes: &[u8]) -> PathBuf {
    let s = String::from_utf8_lossy(bytes);
    PathBuf::from(s.as_ref())
}

/// Checks if a path is a file (follows symlinks).
#[inline]
fn is_file(path: &Path) -> bool {
    fs::metadata(path).map(|m| m.is_file()).unwrap_or(false)
}

/// Checks if a path is a directory (follows symlinks).
#[inline]
fn is_dir(path: &Path) -> bool {
    fs::metadata(path).map(|m| m.is_dir()).unwrap_or(false)
}
