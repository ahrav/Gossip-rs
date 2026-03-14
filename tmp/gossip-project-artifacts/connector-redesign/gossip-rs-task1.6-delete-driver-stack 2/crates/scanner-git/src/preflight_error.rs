//! Error types for Git scanning preflight.
//!
//! These errors cover repository discovery and maintenance preflight checks.
//! Variants distinguish user/environment issues (not a repo, malformed files)
//! from I/O failures (permission, transient filesystem errors).

use std::fmt;
use std::io;

/// Errors from the maintenance preflight.
///
/// This enum is intentionally non-exhaustive so new diagnostics can be
/// introduced without breaking downstream matches.
#[derive(Debug)]
#[non_exhaustive]
pub enum PreflightError {
    /// I/O error during file operations.
    Io(io::Error),
    /// Path canonicalization failed.
    Canonicalization(io::Error),
    /// Not a Git repository (no .git dir/file, not bare).
    NotARepository,
    /// The .git file is malformed (bad gitdir pointer).
    MalformedGitdirFile,
    /// The gitdir target doesn't exist or isn't a directory.
    GitdirTargetNotDir,
    /// The commondir file is malformed.
    MalformedCommondirFile,
    /// The common directory doesn't exist or isn't a directory.
    CommonDirNotDir,
    /// The objects directory doesn't exist or isn't a directory.
    ObjectsDirNotDir,
    /// An alternate object directory doesn't exist or isn't a directory.
    AlternateNotDir,
    /// File exceeds size limit.
    ///
    /// The limit comes from `PreflightLimits`; the size is the on-disk length.
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

impl fmt::Display for PreflightError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "I/O error: {err}"),
            Self::Canonicalization(err) => write!(f, "path canonicalization failed: {err}"),
            Self::NotARepository => write!(f, "not a Git repository"),
            Self::MalformedGitdirFile => {
                write!(f, "malformed .git file (expected 'gitdir: <path>')")
            }
            Self::GitdirTargetNotDir => write!(f, "gitdir target is not a directory"),
            Self::MalformedCommondirFile => write!(f, "malformed commondir file"),
            Self::CommonDirNotDir => write!(f, "common directory is not a directory"),
            Self::ObjectsDirNotDir => write!(f, "objects directory is not a directory"),
            Self::AlternateNotDir => write!(f, "alternate object directory is not a directory"),
            Self::FileTooLarge { size, limit } => {
                write!(f, "file too large: {size} bytes (limit: {limit})")
            }
        }
    }
}

impl std::error::Error for PreflightError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) | Self::Canonicalization(err) => Some(err),
            _ => None,
        }
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
