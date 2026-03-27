//! Error types for Git scanning preflight.
//!
//! These errors cover repository discovery and maintenance preflight checks.
//! Variants distinguish user/environment issues (not a repo, malformed files)
//! from I/O failures (permission, transient filesystem errors).

use std::io;

/// Errors from the maintenance preflight.
///
/// This enum is intentionally non-exhaustive so new diagnostics can be
/// introduced without breaking downstream matches.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PreflightError {
    /// I/O error during file operations.
    #[error("I/O error: {0}")]
    Io(#[source] io::Error),
    /// Path canonicalization failed.
    #[error("path canonicalization failed: {0}")]
    Canonicalization(#[source] io::Error),
    /// Not a Git repository (no .git dir/file, not bare).
    #[error("not a Git repository")]
    NotARepository,
    /// The .git file is malformed (bad gitdir pointer).
    #[error("malformed .git file (expected 'gitdir: <path>')")]
    MalformedGitdirFile,
    /// The gitdir target doesn't exist or isn't a directory.
    #[error("gitdir target is not a directory")]
    GitdirTargetNotDir,
    /// The commondir file is malformed.
    #[error("malformed commondir file")]
    MalformedCommondirFile,
    /// The common directory doesn't exist or isn't a directory.
    #[error("common directory is not a directory")]
    CommonDirNotDir,
    /// The objects directory doesn't exist or isn't a directory.
    #[error("objects directory is not a directory")]
    ObjectsDirNotDir,
    /// An alternate object directory doesn't exist or isn't a directory.
    #[error("alternate object directory is not a directory")]
    AlternateNotDir,
    /// File exceeds size limit.
    ///
    /// The limit comes from `PreflightLimits`; the size is the on-disk length.
    #[error("file too large: {size} bytes (limit: {limit})")]
    FileTooLarge { size: u64, limit: u32 },
}

impl PreflightError {
    /// Creates an I/O error variant.
    #[inline]
    pub fn io(err: io::Error) -> Self {
        Self::Io(err)
    }

    /// Creates a canonicalization error variant.
    #[inline]
    pub fn canonicalization(err: io::Error) -> Self {
        Self::Canonicalization(err)
    }
}

impl super::repo::RepoError for PreflightError {
    fn io(err: io::Error) -> Self {
        Self::Io(err)
    }

    fn canonicalization(err: io::Error) -> Self {
        Self::Canonicalization(err)
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
