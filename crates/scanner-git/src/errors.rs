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
#[derive(thiserror::Error)]
#[non_exhaustive]
pub enum RepoOpenError {
    /// I/O error during file operations.
    #[error("I/O error ({})", .0.kind())]
    Io(#[source] io::Error),
    /// Path canonicalization failed.
    #[error("path canonicalization failed ({})", .0.kind())]
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
    #[error("file too large: {size} bytes (limit: {limit})")]
    FileTooLarge { size: u64, limit: u32 },
    /// Start set has too many refs.
    #[error("start set too large: {count} refs (max: {max})")]
    StartSetTooLarge { count: usize, max: usize },
    /// Ref name exceeds length limit.
    #[error("ref name too long: {len} bytes (max: {max})")]
    RefNameTooLong { len: usize, max: usize },
    /// Arena capacity exceeded.
    #[error("arena overflow")]
    ArenaOverflow,
    /// Watermark store returned wrong number of results.
    #[error("watermark count mismatch: got {got}, expected {expected}")]
    WatermarkCountMismatch { got: usize, expected: usize },
    /// Config file contains invalid UTF-8.
    #[error("config file contains invalid UTF-8")]
    InvalidUtf8Config,
}

/// Redacts `io::Error` messages in Debug output to prevent filesystem path
/// leakage through error chains. `Io` and `Canonicalization` show only the
/// `ErrorKind`; all other variants format identically to the derived Debug.
impl fmt::Debug for RepoOpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => f
                .debug_struct("Io")
                .field("kind", &err.kind())
                .field("message", &"(redacted)")
                .finish(),
            Self::Canonicalization(err) => f
                .debug_struct("Canonicalization")
                .field("kind", &err.kind())
                .field("message", &"(redacted)")
                .finish(),
            Self::NotARepository => write!(f, "NotARepository"),
            Self::MalformedGitdirFile => write!(f, "MalformedGitdirFile"),
            Self::GitdirTargetNotDir => write!(f, "GitdirTargetNotDir"),
            Self::MalformedCommondirFile => write!(f, "MalformedCommondirFile"),
            Self::CommonDirNotDir => write!(f, "CommonDirNotDir"),
            Self::ObjectsDirNotDir => write!(f, "ObjectsDirNotDir"),
            Self::AlternateNotDir => write!(f, "AlternateNotDir"),
            Self::FileTooLarge { size, limit } => f
                .debug_struct("FileTooLarge")
                .field("size", size)
                .field("limit", limit)
                .finish(),
            Self::StartSetTooLarge { count, max } => f
                .debug_struct("StartSetTooLarge")
                .field("count", count)
                .field("max", max)
                .finish(),
            Self::RefNameTooLong { len, max } => f
                .debug_struct("RefNameTooLong")
                .field("len", len)
                .field("max", max)
                .finish(),
            Self::ArenaOverflow => write!(f, "ArenaOverflow"),
            Self::WatermarkCountMismatch { got, expected } => f
                .debug_struct("WatermarkCountMismatch")
                .field("got", got)
                .field("expected", expected)
                .finish(),
            Self::InvalidUtf8Config => write!(f, "InvalidUtf8Config"),
        }
    }
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

/// Errors from commit selection (commit-graph traversal and ordering).
///
/// These errors occur before tree diffing starts and typically indicate
/// commit-graph corruption, missing tips, or violated traversal limits.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CommitPlanError {
    /// Commit-graph could not be opened or parsed.
    #[error("commit-graph open failed: {reason}")]
    CommitGraphOpen { reason: String },
    /// OID has invalid length.
    #[error("invalid OID length: {len} (expected {expected})")]
    InvalidOidLength { len: usize, expected: usize },
    /// Commit-graph exceeds the configured limit.
    #[error("commit-graph too large: {commits} commits (max: {max})")]
    CommitGraphTooLarge { commits: u32, max: u32 },
    /// Tip commit not found in the commit-graph.
    #[error("tip commit not found in commit-graph")]
    TipNotFound,
    /// Heap frontier exceeded the configured limit.
    #[error("heap limit exceeded: {entries} entries (max: {max})")]
    HeapLimitExceeded { entries: u32, max: u32 },
    /// Commit-graph parent list entry is corrupt.
    #[error("commit-graph parent decode failed")]
    ParentDecodeFailed,
    /// Commit has more parents than allowed.
    #[error("too many parents: {count} (max: {max})")]
    TooManyParents { count: usize, max: usize },
    /// Topological ordering could not process all commits (cycle or corruption).
    #[error("topological ordering failed: {remaining} commits unresolved")]
    TopoSortCycle { remaining: u32 },
    /// Identity-ID vector length does not match commit count.
    #[error("identity_ids length ({identity_ids}) does not match commits ({commits})")]
    IdentityLengthMismatch { commits: usize, identity_ids: usize },
}

/// Errors from tree diff and candidate collection.
///
/// These errors occur after the commit plan is built, while loading trees
/// and extracting candidate paths. Many are recoverable by maintenance or
/// increasing limits (tree depth, bytes, or buffer capacity).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TreeDiffError {
    /// Tree object not found.
    #[error("tree not found")]
    TreeNotFound,
    /// Object exists but is not a tree.
    #[error("object is not a tree")]
    NotATree,
    /// Tree object is corrupt or malformed.
    #[error("corrupt tree: {detail}")]
    CorruptTree { detail: &'static str },
    /// OID has invalid length.
    #[error("invalid OID length: {len} (expected {expected})")]
    InvalidOidLength { len: usize, expected: usize },
    /// Maximum tree recursion depth exceeded.
    #[error("max tree depth exceeded: {max_depth}")]
    MaxTreeDepthExceeded { max_depth: u16 },
    /// In-flight tree bytes budget exceeded.
    #[error("tree bytes in-flight budget exceeded: loaded {loaded}, budget {budget}")]
    TreeBytesBudgetExceeded { loaded: u64, budget: u64 },
    /// Path exceeds length limit.
    #[error("path too long: {len} bytes (max: {max})")]
    PathTooLong { len: usize, max: usize },
    /// Candidate buffer is full.
    #[error("candidate buffer full")]
    CandidateBufferFull,
    /// Path arena capacity exceeded.
    #[error("path arena full")]
    PathArenaFull,
    /// Candidate cap exceeded.
    #[error("candidate limit exceeded: kind={kind} observed={observed} max={max}")]
    CandidateLimitExceeded {
        kind: MappingCandidateKind,
        max: u32,
        observed: u32,
    },
    /// Candidate sink failed.
    #[error("candidate sink error: {detail}")]
    CandidateSinkError { detail: String },
    /// Object store failure (MIDX, pack, or loose object decode).
    #[error("object store error: {detail}")]
    ObjectStoreError { detail: String },
    /// Cooperative abort signalled by another worker.
    #[error("aborted by cooperative cancellation")]
    Aborted,
}

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
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SpillError {
    /// I/O error during spill file operations.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    /// Maximum number of spill run files exceeded.
    #[error("spill run limit exceeded: {runs} runs (max: {max})")]
    SpillRunLimitExceeded { runs: usize, max: usize },
    /// Total spill bytes exceeded budget.
    #[error("spill bytes exceeded: {bytes} bytes (max: {max})")]
    SpillBytesExceeded { bytes: u64, max: u64 },
    /// Spill run file has invalid header.
    #[error("invalid run file header")]
    InvalidRunHeader,
    /// Spill run file is corrupt.
    #[error("corrupt run file: {detail}")]
    CorruptRunFile { detail: &'static str },
    /// OID length in run file doesn't match expected.
    #[error("OID length mismatch in run: got {got}, expected {expected}")]
    OidLengthMismatch { got: u8, expected: u8 },
    /// MIDX mapping or lookup error.
    #[error("{0}")]
    MidxError(#[from] MidxError),
    /// Path in run file exceeds safety limit.
    #[error("path in run file too long: {len} bytes (max: {max})")]
    RunPathTooLong { len: usize, max: usize },
    /// Seen-blob store returned wrong number of results.
    #[error("seen-blob response length mismatch: got {got}, expected {expected}")]
    SeenResponseMismatch { got: usize, expected: usize },
    /// Arena capacity exceeded.
    #[error("arena overflow")]
    ArenaOverflow,
    /// Path exceeds length limit.
    #[error("path too long: {len} bytes (max: {max})")]
    PathTooLong { len: usize, max: usize },
    /// Mapping candidate cap exceeded.
    #[error("mapping candidate cap exceeded for {kind}: saw {observed} (max: {max})")]
    MappingCandidateLimitExceeded {
        /// Candidate kind that exceeded the cap.
        kind: MappingCandidateKind,
        /// Configured maximum.
        max: u32,
        /// Observed count when the cap was exceeded.
        observed: u32,
    },
}

/// Errors from persistence operations.
///
/// These errors represent failures after scanning has completed; in-memory
/// results may still be available even if persistence fails.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PersistError {
    /// I/O error during persistence operations.
    #[error("persistence I/O error: {0}")]
    Io(#[from] io::Error),
    /// Backend-specific error string.
    #[error("persistence backend error: {detail}")]
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

    #[test]
    fn repo_open_error_debug_redacts_io_paths() {
        let err = RepoOpenError::Io(io::Error::new(
            io::ErrorKind::NotFound,
            "/secret/path/to/repo",
        ));
        let debug = format!("{err:?}");
        assert!(
            !debug.contains("/secret/path"),
            "io path leaked into Debug output: {debug}"
        );
        assert!(debug.contains("(redacted)"));

        let err = RepoOpenError::Canonicalization(io::Error::new(
            io::ErrorKind::NotFound,
            "/secret/canonical/path",
        ));
        let debug = format!("{err:?}");
        assert!(
            !debug.contains("/secret/canonical"),
            "canonical path leaked into Debug output: {debug}"
        );
        assert!(debug.contains("(redacted)"));
    }
}
