//! Error types for Git scanning stages.
//!
//! Errors are stage-specific to keep diagnostics precise and avoid a
//! single monolithic error enum that grows unbounded. Error enums are
//! `#[non_exhaustive]` to allow adding variants without breaking callers;
//! consumers should include a fallback match arm. (Helper enums like
//! `MappingCandidateKind` are exhaustive by design.)
//!
//! # Design Notes
//! - Variants with `detail` carry human-readable context and are not stable
//!   for machine parsing.
//! - I/O errors preserve their source to keep diagnostics actionable.
//! - Stage boundaries are intentional: an error from one stage should not be
//!   reused to describe another stage's failure mode.

use std::fmt;
use std::io;

use super::midx_error::MidxError;

/// Errors from repo discovery and open.
///
/// These errors occur before any object scanning begins and typically
/// indicate repository layout, configuration, or limit violations.
#[derive(Debug)]
#[non_exhaustive]
pub enum RepoOpenError {
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
    FileTooLarge { size: u64, limit: u32 },
    /// Start set has too many refs.
    StartSetTooLarge { count: usize, max: usize },
    /// Ref name exceeds length limit.
    RefNameTooLong { len: usize, max: usize },
    /// Arena capacity exceeded.
    ArenaOverflow,
    /// Watermark store returned wrong number of results.
    WatermarkCountMismatch { got: usize, expected: usize },
    /// Config file contains invalid UTF-8.
    InvalidUtf8Config,
}

impl RepoOpenError {
    /// Creates an I/O error variant.
    #[inline]
    pub fn io(err: io::Error) -> Self {
        Self::Io(err)
    }

    /// Creates a canonicalization error variant.
    ///
    /// This preserves the original `io::Error` as the source.
    #[inline]
    pub fn canonicalization(err: io::Error) -> Self {
        Self::Canonicalization(err)
    }
}

impl fmt::Display for RepoOpenError {
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
            Self::StartSetTooLarge { count, max } => {
                write!(f, "start set too large: {count} refs (max: {max})")
            }
            Self::RefNameTooLong { len, max } => {
                write!(f, "ref name too long: {len} bytes (max: {max})")
            }
            Self::ArenaOverflow => write!(f, "arena overflow"),
            Self::WatermarkCountMismatch { got, expected } => {
                write!(
                    f,
                    "watermark count mismatch: got {got}, expected {expected}"
                )
            }
            Self::InvalidUtf8Config => write!(f, "config file contains invalid UTF-8"),
        }
    }
}

impl std::error::Error for RepoOpenError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) | Self::Canonicalization(err) => Some(err),
            _ => None,
        }
    }
}

/// Errors from commit selection (commit-graph traversal and ordering).
///
/// These errors occur before tree diffing starts and typically indicate
/// commit-graph corruption, missing tips, or violated traversal limits.
#[derive(Debug)]
#[non_exhaustive]
pub enum CommitPlanError {
    /// Commit-graph could not be opened or parsed.
    CommitGraphOpen { reason: String },
    /// OID has invalid length.
    InvalidOidLength { len: usize, expected: usize },
    /// Commit-graph exceeds the configured limit.
    CommitGraphTooLarge { commits: u32, max: u32 },
    /// Tip commit not found in the commit-graph.
    TipNotFound,
    /// Heap frontier exceeded the configured limit.
    HeapLimitExceeded { entries: u32, max: u32 },
    /// Commit-graph parent list entry is corrupt.
    ParentDecodeFailed,
    /// Commit has more parents than allowed.
    TooManyParents { count: usize, max: usize },
    /// Topological ordering could not process all commits (cycle or corruption).
    TopoSortCycle { remaining: u32 },
    /// Identity-ID vector length does not match commit count.
    IdentityLengthMismatch { commits: usize, identity_ids: usize },
}

impl fmt::Display for CommitPlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CommitGraphOpen { reason } => {
                write!(f, "commit-graph open failed: {reason}")
            }
            Self::InvalidOidLength { len, expected } => {
                write!(f, "invalid OID length: {len} (expected {expected})")
            }
            Self::CommitGraphTooLarge { commits, max } => {
                write!(f, "commit-graph too large: {commits} commits (max: {max})")
            }
            Self::TipNotFound => write!(f, "tip commit not found in commit-graph"),
            Self::HeapLimitExceeded { entries, max } => {
                write!(f, "heap limit exceeded: {entries} entries (max: {max})")
            }
            Self::ParentDecodeFailed => write!(f, "commit-graph parent decode failed"),
            Self::TooManyParents { count, max } => {
                write!(f, "too many parents: {count} (max: {max})")
            }
            Self::TopoSortCycle { remaining } => {
                write!(
                    f,
                    "topological ordering failed: {remaining} commits unresolved"
                )
            }
            Self::IdentityLengthMismatch {
                commits,
                identity_ids,
            } => {
                write!(
                    f,
                    "identity_ids length ({identity_ids}) does not match commits ({commits})"
                )
            }
        }
    }
}

impl std::error::Error for CommitPlanError {}

/// Errors from tree diff and candidate collection.
///
/// These errors occur after the commit plan is built, while loading trees
/// and extracting candidate paths. Many are recoverable by maintenance or
/// increasing limits (tree depth, bytes, or buffer capacity).
#[derive(Debug)]
#[non_exhaustive]
pub enum TreeDiffError {
    /// Tree object not found.
    TreeNotFound,
    /// Object exists but is not a tree.
    NotATree,
    /// Tree object is corrupt or malformed.
    CorruptTree { detail: &'static str },
    /// OID has invalid length.
    InvalidOidLength { len: usize, expected: usize },
    /// Maximum tree recursion depth exceeded.
    MaxTreeDepthExceeded { max_depth: u16 },
    /// In-flight tree bytes budget exceeded.
    TreeBytesBudgetExceeded { loaded: u64, budget: u64 },
    /// Path exceeds length limit.
    PathTooLong { len: usize, max: usize },
    /// Candidate buffer is full.
    CandidateBufferFull,
    /// Path arena capacity exceeded.
    PathArenaFull,
    /// Candidate cap exceeded.
    CandidateLimitExceeded {
        kind: MappingCandidateKind,
        max: u32,
        observed: u32,
    },
    /// Candidate sink failed.
    CandidateSinkError { detail: String },
    /// Object store failure (MIDX, pack, or loose object decode).
    ObjectStoreError { detail: String },
    /// Cooperative abort signalled by another worker.
    Aborted,
}

impl fmt::Display for TreeDiffError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TreeNotFound => write!(f, "tree not found"),
            Self::NotATree => write!(f, "object is not a tree"),
            Self::CorruptTree { detail } => write!(f, "corrupt tree: {detail}"),
            Self::InvalidOidLength { len, expected } => {
                write!(f, "invalid OID length: {len} (expected {expected})")
            }
            Self::MaxTreeDepthExceeded { max_depth } => {
                write!(f, "max tree depth exceeded: {max_depth}")
            }
            Self::TreeBytesBudgetExceeded { loaded, budget } => {
                write!(
                    f,
                    "tree bytes in-flight budget exceeded: loaded {loaded}, budget {budget}"
                )
            }
            Self::PathTooLong { len, max } => {
                write!(f, "path too long: {len} bytes (max: {max})")
            }
            Self::CandidateBufferFull => write!(f, "candidate buffer full"),
            Self::PathArenaFull => write!(f, "path arena full"),
            Self::CandidateLimitExceeded {
                kind,
                max,
                observed,
            } => write!(
                f,
                "candidate limit exceeded: kind={kind} observed={observed} max={max}"
            ),
            Self::CandidateSinkError { detail } => write!(f, "candidate sink error: {detail}"),
            Self::ObjectStoreError { detail } => write!(f, "object store error: {detail}"),
            Self::Aborted => write!(f, "aborted by cooperative cancellation"),
        }
    }
}

impl std::error::Error for TreeDiffError {}

/// Mapping candidate kind for cap enforcement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MappingCandidateKind {
    /// Candidate mapped to a pack offset.
    Packed,
    /// Candidate that must be loaded from loose objects.
    Loose,
}

impl fmt::Display for MappingCandidateKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Packed => write!(f, "packed"),
            Self::Loose => write!(f, "loose"),
        }
    }
}

/// Errors from spill and dedupe.
///
/// These errors occur after candidate extraction, when spilling and
/// de-duplicating large result sets on disk.
#[derive(Debug)]
#[non_exhaustive]
pub enum SpillError {
    /// I/O error during spill file operations.
    Io(io::Error),
    /// Maximum number of spill run files exceeded.
    SpillRunLimitExceeded { runs: usize, max: usize },
    /// Total spill bytes exceeded budget.
    SpillBytesExceeded { bytes: u64, max: u64 },
    /// Spill run file has invalid header.
    InvalidRunHeader,
    /// Spill run file is corrupt.
    CorruptRunFile { detail: &'static str },
    /// OID length in run file doesn't match expected.
    OidLengthMismatch { got: u8, expected: u8 },
    /// MIDX mapping or lookup error.
    MidxError(MidxError),
    /// Path in run file exceeds safety limit.
    RunPathTooLong { len: usize, max: usize },
    /// Seen-blob store returned wrong number of results.
    SeenResponseMismatch { got: usize, expected: usize },
    /// Arena capacity exceeded.
    ArenaOverflow,
    /// Path exceeds length limit.
    PathTooLong { len: usize, max: usize },
    /// Mapping candidate cap exceeded.
    MappingCandidateLimitExceeded {
        /// Candidate kind that exceeded the cap.
        kind: MappingCandidateKind,
        /// Configured maximum.
        max: u32,
        /// Observed count when the cap was exceeded.
        observed: u32,
    },
}

impl fmt::Display for SpillError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "I/O error: {err}"),
            Self::SpillRunLimitExceeded { runs, max } => {
                write!(f, "spill run limit exceeded: {runs} runs (max: {max})")
            }
            Self::SpillBytesExceeded { bytes, max } => {
                write!(f, "spill bytes exceeded: {bytes} bytes (max: {max})")
            }
            Self::InvalidRunHeader => write!(f, "invalid run file header"),
            Self::CorruptRunFile { detail } => write!(f, "corrupt run file: {detail}"),
            Self::OidLengthMismatch { got, expected } => {
                write!(
                    f,
                    "OID length mismatch in run: got {got}, expected {expected}"
                )
            }
            Self::MidxError(err) => write!(f, "{err}"),
            Self::RunPathTooLong { len, max } => {
                write!(f, "path in run file too long: {len} bytes (max: {max})")
            }
            Self::SeenResponseMismatch { got, expected } => {
                write!(
                    f,
                    "seen-blob response length mismatch: got {got}, expected {expected}"
                )
            }
            Self::ArenaOverflow => write!(f, "arena overflow"),
            Self::PathTooLong { len, max } => {
                write!(f, "path too long: {len} bytes (max: {max})")
            }
            Self::MappingCandidateLimitExceeded {
                kind,
                max,
                observed,
            } => {
                write!(
                    f,
                    "mapping candidate cap exceeded for {kind}: saw {observed} (max: {max})"
                )
            }
        }
    }
}

impl std::error::Error for SpillError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::MidxError(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for SpillError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<MidxError> for SpillError {
    fn from(err: MidxError) -> Self {
        Self::MidxError(err)
    }
}

/// Errors from persistence operations.
///
/// These errors represent failures after scanning has completed; in-memory
/// results may still be available even if persistence fails.
#[derive(Debug)]
#[non_exhaustive]
pub enum PersistError {
    /// I/O error during persistence operations.
    Io(io::Error),
    /// Backend-specific error string.
    Backend { detail: String },
}

impl PersistError {
    /// Creates an I/O error variant.
    #[inline]
    pub fn io(err: io::Error) -> Self {
        Self::Io(err)
    }

    /// Creates a backend error variant.
    #[inline]
    pub fn backend(detail: impl Into<String>) -> Self {
        Self::Backend {
            detail: detail.into(),
        }
    }
}

impl fmt::Display for PersistError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "persistence I/O error: {err}"),
            Self::Backend { detail } => write!(f, "persistence backend error: {detail}"),
        }
    }
}

impl std::error::Error for PersistError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for PersistError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repo_open_error_display() {
        let err = RepoOpenError::StartSetTooLarge {
            count: 100,
            max: 50,
        };
        let msg = format!("{err}");
        assert!(msg.contains("100"));
        assert!(msg.contains("50"));
    }

    #[test]
    fn tree_diff_error_display() {
        let err = TreeDiffError::MaxTreeDepthExceeded { max_depth: 256 };
        let msg = format!("{err}");
        assert!(msg.contains("256"));
    }

    #[test]
    fn commit_plan_error_display() {
        let err = CommitPlanError::HeapLimitExceeded {
            entries: 10,
            max: 5,
        };
        let msg = format!("{err}");
        assert!(msg.contains("10"));
        assert!(msg.contains("5"));
    }

    #[test]
    fn spill_error_display() {
        let err = SpillError::SpillRunLimitExceeded { runs: 10, max: 8 };
        let msg = format!("{err}");
        assert!(msg.contains("10"));
        assert!(msg.contains("8"));
    }

    #[test]
    fn spill_from_io_error() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "test");
        let spill_err: SpillError = io_err.into();
        assert!(matches!(spill_err, SpillError::Io(_)));
    }
}
