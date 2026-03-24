//! Canonical filesystem submission request types and normalization helpers.
//!
//! The normalization seam keeps two invariants stable for downstream
//! control-plane stages:
//!
//! - Source mode stays explicit instead of being re-inferred from path shape.
//! - Equivalent requests normalize to the same canonical root.
//!
//! Normalized requests flow to [`crate::planner`] for initial shard geometry
//! planning, then into the scanner runtime's `OrderedContentRuntimeInput`
//! for page validation.

use std::ffi::OsStr;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use gossip_coordination::RunConfig;

/// Explicit source mode for filesystem submissions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FilesystemSourceMode {
    /// Scan a single regular file.
    SingleFile,
    /// Scan a directory root and treat child objects as root-relative keys.
    DirectoryRoot,
}

impl FilesystemSourceMode {
    /// Returns the filesystem path kind that canonicalization must produce for
    /// this source mode. Used during normalization to reject mode/path mismatches
    /// (e.g., a `SingleFile` request targeting a directory).
    #[must_use]
    pub fn expected_path_kind(self) -> FilesystemPathKind {
        match self {
            Self::SingleFile => FilesystemPathKind::File,
            Self::DirectoryRoot => FilesystemPathKind::Directory,
        }
    }
}

impl fmt::Display for FilesystemSourceMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SingleFile => f.write_str("single_file"),
            Self::DirectoryRoot => f.write_str("directory_root"),
        }
    }
}

/// Concrete filesystem path class used during normalization validation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FilesystemPathKind {
    /// Regular file target.
    File,
    /// Directory target.
    Directory,
}

impl FilesystemPathKind {
    /// Classify a [`std::fs::FileType`] as file or directory.
    ///
    /// Returns `None` for symlinks, FIFOs, sockets, and other non-regular types.
    #[must_use]
    pub fn from_file_type(file_type: &std::fs::FileType) -> Option<Self> {
        if file_type.is_file() {
            Some(Self::File)
        } else if file_type.is_dir() {
            Some(Self::Directory)
        } else {
            None
        }
    }
}

impl fmt::Display for FilesystemPathKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::File => f.write_str("regular file"),
            Self::Directory => f.write_str("directory"),
        }
    }
}

/// Filesystem submission request before canonicalization.
///
/// Stores the raw path and explicit source mode. The [`RunConfig`] carries
/// coordination-level settings for downstream stages.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FilesystemRequest {
    mode: FilesystemSourceMode,
    path: PathBuf,
    run_config: RunConfig,
}

impl FilesystemRequest {
    /// Construct a filesystem request from explicit source mode and path.
    #[must_use]
    pub fn new(
        mode: FilesystemSourceMode,
        path: impl Into<PathBuf>,
        run_config: RunConfig,
    ) -> Self {
        Self {
            mode,
            path: path.into(),
            run_config,
        }
    }

    /// Construct a single-file request for `path`.
    #[must_use]
    pub fn single_file(path: impl Into<PathBuf>, run_config: RunConfig) -> Self {
        Self::new(FilesystemSourceMode::SingleFile, path, run_config)
    }

    /// Construct a directory-root request for `path`.
    #[must_use]
    pub fn directory_root(path: impl Into<PathBuf>, run_config: RunConfig) -> Self {
        Self::new(FilesystemSourceMode::DirectoryRoot, path, run_config)
    }

    /// Requested source mode before normalization.
    #[must_use]
    pub fn mode(&self) -> FilesystemSourceMode {
        self.mode
    }

    /// Raw path before canonicalization.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Coordination-level run settings for this request.
    #[must_use]
    pub fn run_config(&self) -> RunConfig {
        self.run_config
    }

    /// Canonicalize the request path, validate it against the requested mode,
    /// and enforce that the canonical root resides within `allowed_root`.
    ///
    /// This is the recommended entry point for requests originating from
    /// untrusted input. It delegates to [`Self::normalize`] for
    /// canonicalization and mode validation, then verifies path containment.
    ///
    /// # Errors
    ///
    /// Returns [`FilesystemRequestError::AllowedRootCanonicalize`] if `allowed_root`
    /// cannot be canonicalized, any error that [`Self::normalize`] can
    /// produce, or [`FilesystemRequestError::PathConfinementViolation`] if
    /// the canonical path escapes the allowed root.
    ///
    /// # Limitations
    ///
    /// A TOCTOU window exists between canonicalizing `allowed_root` and
    /// canonicalizing the request path inside [`Self::normalize`]. The
    /// containment check is advisory; the downstream connector's
    /// `O_NOFOLLOW` / `openat` enforcement provides the authoritative
    /// safety guard against filesystem races.
    pub fn normalize_within(
        &self,
        allowed_root: &Path,
    ) -> Result<NormalizedFilesystemRequest, FilesystemRequestError> {
        let allowed_canonical = fs::canonicalize(allowed_root).map_err(|source| {
            FilesystemRequestError::AllowedRootCanonicalize {
                path: allowed_root.to_path_buf(),
                source,
            }
        })?;

        let normalized = self.normalize()?;

        if !normalized.canonical_root().starts_with(&allowed_canonical) {
            return Err(FilesystemRequestError::PathConfinementViolation {
                mode: normalized.mode(),
                path: normalized.canonical_root.clone(),
                allowed_root: allowed_canonical,
            });
        }

        Ok(normalized)
    }

    /// Canonicalize the request path and validate it against the requested mode.
    ///
    /// The returned request preserves explicit source mode, stores the
    /// canonical root, and carries coordination-level run config for later
    /// control-plane stages.
    ///
    /// # Path confinement
    ///
    /// This method does not enforce path containment. Callers exposed to
    /// untrusted input must verify the canonical root falls within an
    /// allowed directory before forwarding the normalized request.
    ///
    /// # Limitations
    ///
    /// A TOCTOU window exists between `fs::canonicalize` and the subsequent
    /// `fs::metadata` kind check. The downstream `FilesystemConnector`'s
    /// `O_NOFOLLOW` / `openat` enforcement at the read boundary provides
    /// the authoritative safety guard.
    ///
    /// # Errors
    ///
    /// Returns an error when the path is empty, cannot be canonicalized,
    /// canonicalizes to a path kind that does not match the requested mode,
    /// or resolves to something other than a regular file or directory.
    pub fn normalize(&self) -> Result<NormalizedFilesystemRequest, FilesystemRequestError> {
        let requested_path = self.path.as_path();
        if requested_path.as_os_str().is_empty() {
            return Err(FilesystemRequestError::EmptyPath { mode: self.mode });
        }

        let canonical_root = fs::canonicalize(requested_path).map_err(|source| {
            FilesystemRequestError::Canonicalize {
                path: requested_path.to_path_buf(),
                source,
            }
        })?;
        let actual_kind = detect_path_kind(&canonical_root)?;
        let expected_kind = self.mode.expected_path_kind();
        if actual_kind != expected_kind {
            return Err(FilesystemRequestError::PathKindMismatch {
                mode: self.mode,
                path: canonical_root,
                actual: actual_kind,
            });
        }

        // Defensive: single-file targets must resolve to a path with a file
        // name component. Canonicalization + the mode/kind check above should
        // already guarantee this (only root `/` lacks a file name, and root is
        // a directory), but we verify explicitly because downstream consumers
        // rely on `relative_namespace_name()` returning `Some` for single-file
        // requests.
        if self.mode == FilesystemSourceMode::SingleFile && canonical_root.file_name().is_none() {
            return Err(FilesystemRequestError::SingleFileMissingName {
                path: canonical_root,
            });
        }

        Ok(NormalizedFilesystemRequest {
            mode: self.mode,
            canonical_root,
            run_config: self.run_config,
        })
    }
}

/// Normalized filesystem submission with a canonicalized path and validated mode.
///
/// Produced by [`FilesystemRequest::normalize`]. Downstream control-plane stages
/// consume the canonical root and explicit mode for shard planning, payload
/// encoding, and run setup.
///
/// # Safety contract
///
/// The canonical path stored here was produced by [`std::fs::canonicalize`]
/// and may or may not have been validated against an allowed root —
/// only [`FilesystemRequest::normalize_within`] performs containment
/// checks. Callers must not open this path directly with
/// `std::fs::File::open` or equivalent. All reads must go through a
/// connector that enforces `O_NOFOLLOW`/`openat` at every path component
/// to close the TOCTOU gap between canonicalization and open.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NormalizedFilesystemRequest {
    mode: FilesystemSourceMode,
    canonical_root: PathBuf,
    run_config: RunConfig,
}

impl NormalizedFilesystemRequest {
    /// Explicit source mode preserved across normalization.
    #[must_use]
    pub fn mode(&self) -> FilesystemSourceMode {
        self.mode
    }

    /// Canonical file or directory root for this source.
    #[must_use]
    pub fn canonical_root(&self) -> &Path {
        &self.canonical_root
    }

    /// Coordination-level run settings for this normalized request.
    #[must_use]
    pub fn run_config(&self) -> RunConfig {
        self.run_config
    }

    /// Basename-rooted relative namespace for single-file scans.
    ///
    /// Directory-root scans return `None` because downstream paths stay
    /// relative to the directory root rather than anchoring to a basename.
    #[must_use]
    pub fn relative_namespace_name(&self) -> Option<&OsStr> {
        match self.mode {
            FilesystemSourceMode::SingleFile => self.canonical_root.file_name(),
            FilesystemSourceMode::DirectoryRoot => None,
        }
    }
}

/// Normalization failures for [`FilesystemRequest`].
///
/// # Security note
///
/// Error messages include filesystem paths for operator diagnostics.
/// Callers that surface errors to untrusted consumers must redact
/// path details before returning.
#[derive(thiserror::Error)]
pub enum FilesystemRequestError {
    /// The request path was empty.
    #[error("filesystem request mode '{mode}' requires a non-empty path")]
    EmptyPath {
        /// Requested source mode.
        mode: FilesystemSourceMode,
    },
    /// The request path could not be canonicalized.
    #[error("failed to canonicalize filesystem request path '{}': {source}", path.display())]
    Canonicalize {
        /// Raw request path.
        path: PathBuf,
        /// I/O error from canonicalization.
        source: io::Error,
    },
    /// Metadata lookup failed after canonicalization.
    #[error("failed to inspect canonical filesystem request path '{}': {source}", path.display())]
    Metadata {
        /// Canonical path.
        path: PathBuf,
        /// I/O error from metadata lookup.
        source: io::Error,
    },
    /// The canonical path kind does not match the requested source mode.
    #[error(
        "filesystem request mode '{mode}' requires a {}, but '{}' canonicalized to a {actual}",
        mode.expected_path_kind(),
        path.display()
    )]
    PathKindMismatch {
        /// Requested source mode.
        mode: FilesystemSourceMode,
        /// Canonical path.
        path: PathBuf,
        /// Actual canonical path kind.
        actual: FilesystemPathKind,
    },
    /// The canonical path is neither a regular file nor a directory.
    #[error("filesystem request path '{}' must be a regular file or directory", path.display())]
    UnsupportedPathKind {
        /// Canonical path.
        path: PathBuf,
    },
    /// A canonical single-file target did not expose a file name component.
    #[error("single-file request path '{}' does not have a file name", path.display())]
    SingleFileMissingName {
        /// Canonical path.
        path: PathBuf,
    },
    /// The canonical path falls outside the allowed root directory.
    #[error(
        "filesystem request mode '{mode}' path '{}' is not contained within allowed root '{}'",
        path.display(),
        allowed_root.display()
    )]
    PathConfinementViolation {
        /// Requested source mode.
        mode: FilesystemSourceMode,
        /// Canonical path that escaped confinement.
        path: PathBuf,
        /// The root directory the path must reside within.
        allowed_root: PathBuf,
    },
    /// The allowed root directory path could not be canonicalized.
    #[error("failed to canonicalize allowed root directory '{}': {source}", path.display())]
    AllowedRootCanonicalize {
        /// Server-configured allowed root path.
        path: PathBuf,
        /// I/O error from canonicalization.
        source: io::Error,
    },
}

// Custom Debug: redacts all `PathBuf` fields to prevent filesystem path
// leakage through error chains (`anyhow`, `tracing`, `{:?}` formatting).
// Display already includes paths for operator diagnostics behind explicit
// `.display()` calls; Debug must not duplicate that exposure.
impl fmt::Debug for FilesystemRequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPath { mode } => f.debug_struct("EmptyPath").field("mode", mode).finish(),
            Self::Canonicalize { source, .. } => f
                .debug_struct("Canonicalize")
                .field("path", &"<redacted>")
                .field("source", source)
                .finish(),
            Self::Metadata { source, .. } => f
                .debug_struct("Metadata")
                .field("path", &"<redacted>")
                .field("source", source)
                .finish(),
            Self::PathKindMismatch { mode, actual, .. } => f
                .debug_struct("PathKindMismatch")
                .field("mode", mode)
                .field("path", &"<redacted>")
                .field("actual", actual)
                .finish(),
            Self::UnsupportedPathKind { .. } => f
                .debug_struct("UnsupportedPathKind")
                .field("path", &"<redacted>")
                .finish(),
            Self::SingleFileMissingName { .. } => f
                .debug_struct("SingleFileMissingName")
                .field("path", &"<redacted>")
                .finish(),
            Self::PathConfinementViolation { mode, .. } => f
                .debug_struct("PathConfinementViolation")
                .field("mode", mode)
                .field("path", &"<redacted>")
                .field("allowed_root", &"<redacted>")
                .finish(),
            Self::AllowedRootCanonicalize { source, .. } => f
                .debug_struct("AllowedRootCanonicalize")
                .field("path", &"<redacted>")
                .field("source", source)
                .finish(),
        }
    }
}

fn detect_path_kind(path: &Path) -> Result<FilesystemPathKind, FilesystemRequestError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|source| FilesystemRequestError::Metadata {
            path: path.to_path_buf(),
            source,
        })?;
    // Defense-in-depth: after `fs::canonicalize`, canonical paths should never
    // be symlinks. Reject them explicitly so this code path stays symmetric
    // with the hydration path in `distributed.rs`.
    if metadata.file_type().is_symlink() {
        return Err(FilesystemRequestError::UnsupportedPathKind {
            path: path.to_path_buf(),
        });
    }
    FilesystemPathKind::from_file_type(&metadata.file_type()).ok_or_else(|| {
        FilesystemRequestError::UnsupportedPathKind {
            path: path.to_path_buf(),
        }
    })
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::fs;

    use tempfile::tempdir;

    use super::*;
    use crate::test_support::run_config;

    #[test]
    fn single_file_normalizes_path_and_preserves_mode() {
        let dir = tempdir().expect("tempdir");
        let file_path = dir.path().join("scan-target.txt");
        fs::write(&file_path, "fixture").expect("write fixture");

        let request_path = file_path
            .parent()
            .expect("file has parent")
            .join(".")
            .join("scan-target.txt");
        let request =
            FilesystemRequest::new(FilesystemSourceMode::SingleFile, request_path, run_config());

        let normalized = request.normalize().expect("file request should normalize");
        let canonical_path = file_path.canonicalize().expect("canonicalize file");

        assert_eq!(normalized.mode(), FilesystemSourceMode::SingleFile);
        assert_eq!(normalized.canonical_root(), canonical_path.as_path());
        assert_eq!(normalized.run_config(), run_config());
        assert_eq!(
            normalized.relative_namespace_name(),
            Some(OsStr::new("scan-target.txt"))
        );
    }

    #[test]
    fn directory_root_normalizes_path_and_preserves_mode() {
        let dir = tempdir().expect("tempdir");
        let root_path = dir.path().join("scan-root");
        fs::create_dir(&root_path).expect("create root dir");

        let request = FilesystemRequest::new(
            FilesystemSourceMode::DirectoryRoot,
            root_path.join("."),
            run_config(),
        );

        let normalized = request
            .normalize()
            .expect("directory request should normalize");
        let canonical_root = root_path.canonicalize().expect("canonicalize dir");

        assert_eq!(normalized.mode(), FilesystemSourceMode::DirectoryRoot);
        assert_eq!(normalized.canonical_root(), canonical_root.as_path());
        assert_eq!(normalized.run_config(), run_config());
        assert_eq!(normalized.relative_namespace_name(), None);
    }

    #[test]
    fn single_file_convenience_constructor() {
        let dir = tempdir().expect("tempdir");
        let file_path = dir.path().join("target.txt");
        fs::write(&file_path, "fixture").expect("write fixture");

        let request = FilesystemRequest::single_file(&file_path, run_config());
        assert_eq!(request.mode(), FilesystemSourceMode::SingleFile);
        assert_eq!(request.path(), file_path.as_path());

        let normalized = request.normalize().expect("should normalize");
        assert_eq!(normalized.mode(), FilesystemSourceMode::SingleFile);
    }

    #[test]
    fn directory_root_convenience_constructor() {
        let dir = tempdir().expect("tempdir");

        let request = FilesystemRequest::directory_root(dir.path(), run_config());
        assert_eq!(request.mode(), FilesystemSourceMode::DirectoryRoot);

        let normalized = request.normalize().expect("should normalize");
        assert_eq!(normalized.mode(), FilesystemSourceMode::DirectoryRoot);
    }

    #[test]
    fn single_file_rejects_directory_target() {
        let dir = tempdir().expect("tempdir");
        let request = FilesystemRequest::single_file(dir.path(), run_config());

        let err = request
            .normalize()
            .expect_err("directory target should be rejected");

        assert!(matches!(
            err,
            FilesystemRequestError::PathKindMismatch {
                mode: FilesystemSourceMode::SingleFile,
                actual: FilesystemPathKind::Directory,
                ..
            }
        ));
    }

    #[test]
    fn directory_root_rejects_regular_file_target() {
        let dir = tempdir().expect("tempdir");
        let file_path = dir.path().join("scan-target.txt");
        fs::write(&file_path, "fixture").expect("write fixture");
        let request = FilesystemRequest::directory_root(&file_path, run_config());

        let err = request
            .normalize()
            .expect_err("file target should be rejected");

        assert!(matches!(
            err,
            FilesystemRequestError::PathKindMismatch {
                mode: FilesystemSourceMode::DirectoryRoot,
                actual: FilesystemPathKind::File,
                ..
            }
        ));
    }

    #[test]
    fn equivalent_requests_normalize_to_identical_output() {
        let dir = tempdir().expect("tempdir");
        let file_path = dir.path().join("scan-target.txt");
        fs::write(&file_path, "fixture").expect("write fixture");

        let canonical_request =
            FilesystemRequest::new(FilesystemSourceMode::SingleFile, &file_path, run_config());
        let dotted_request = FilesystemRequest::new(
            FilesystemSourceMode::SingleFile,
            file_path
                .parent()
                .expect("file has parent")
                .join(".")
                .join("scan-target.txt"),
            run_config(),
        );

        assert_eq!(
            canonical_request
                .normalize()
                .expect("canonical request should normalize"),
            dotted_request
                .normalize()
                .expect("dotted request should normalize")
        );
    }

    #[test]
    fn run_config_preserved_through_normalization() {
        let dir = tempdir().expect("tempdir");
        let file_path = dir.path().join("target.txt");
        fs::write(&file_path, "fixture").expect("write fixture");

        let cfg = run_config();
        let request = FilesystemRequest::single_file(&file_path, cfg);
        let normalized = request.normalize().expect("should normalize");

        assert_eq!(normalized.run_config(), cfg);
    }

    #[test]
    fn relative_namespace_name_single_file_returns_basename() {
        let dir = tempdir().expect("tempdir");
        let file_path = dir.path().join("data.bin");
        fs::write(&file_path, "fixture").expect("write fixture");

        let normalized = FilesystemRequest::single_file(&file_path, run_config())
            .normalize()
            .expect("should normalize");

        assert_eq!(
            normalized.relative_namespace_name(),
            Some(OsStr::new("data.bin"))
        );
    }

    #[test]
    fn relative_namespace_name_directory_returns_none() {
        let dir = tempdir().expect("tempdir");

        let normalized = FilesystemRequest::directory_root(dir.path(), run_config())
            .normalize()
            .expect("should normalize");

        assert_eq!(normalized.relative_namespace_name(), None);
    }

    #[test]
    fn empty_path_rejected_for_single_file_mode() {
        let request = FilesystemRequest::new(
            FilesystemSourceMode::SingleFile,
            PathBuf::new(),
            run_config(),
        );
        let err = request
            .normalize()
            .expect_err("empty path must be rejected");
        assert!(matches!(
            err,
            FilesystemRequestError::EmptyPath {
                mode: FilesystemSourceMode::SingleFile,
            }
        ));
    }

    #[test]
    fn empty_path_rejected_for_directory_root_mode() {
        let request = FilesystemRequest::new(
            FilesystemSourceMode::DirectoryRoot,
            PathBuf::new(),
            run_config(),
        );
        let err = request
            .normalize()
            .expect_err("empty path must be rejected");
        assert!(matches!(
            err,
            FilesystemRequestError::EmptyPath {
                mode: FilesystemSourceMode::DirectoryRoot,
            }
        ));
    }

    #[test]
    fn nonexistent_path_rejected() {
        let dir = tempdir().expect("tempdir");
        let missing = dir.path().join("does-not-exist.txt");
        let request = FilesystemRequest::single_file(missing, run_config());
        let err = request
            .normalize()
            .expect_err("nonexistent path must be rejected");
        assert!(matches!(err, FilesystemRequestError::Canonicalize { .. }));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_normalizes_to_target() {
        let dir = tempdir().expect("tempdir");
        let real_file = dir.path().join("real.txt");
        fs::write(&real_file, "content").expect("write fixture");
        let link = dir.path().join("link.txt");
        std::os::unix::fs::symlink(&real_file, &link).expect("create symlink");

        let request = FilesystemRequest::single_file(&link, run_config());
        let normalized = request.normalize().expect("symlink should normalize");
        let canonical_real = real_file.canonicalize().expect("canonicalize real");
        assert_eq!(normalized.canonical_root(), canonical_real.as_path());
    }

    #[cfg(unix)]
    #[test]
    fn unsupported_path_kind_rejects_fifo() {
        use std::process::Command;

        let dir = tempdir().expect("tempdir");
        let fifo_path = dir.path().join("test.fifo");
        let status = Command::new("mkfifo")
            .arg(&fifo_path)
            .status()
            .expect("mkfifo command");
        assert!(status.success(), "mkfifo failed");

        let request = FilesystemRequest::single_file(&fifo_path, run_config());
        let err = request.normalize().expect_err("FIFO must be rejected");
        assert!(matches!(
            err,
            FilesystemRequestError::UnsupportedPathKind { .. }
        ));
    }

    #[test]
    fn normalize_within_accepts_path_inside_allowed_root() {
        let dir = tempdir().expect("tempdir");
        let file_path = dir.path().join("inner.txt");
        fs::write(&file_path, "fixture").expect("write fixture");

        let request = FilesystemRequest::single_file(&file_path, run_config());
        let normalized = request
            .normalize_within(dir.path())
            .expect("path inside allowed root must succeed");

        assert_eq!(normalized.mode(), FilesystemSourceMode::SingleFile);
        let canonical_file = file_path.canonicalize().expect("canonicalize file");
        assert_eq!(normalized.canonical_root(), canonical_file.as_path());
    }

    #[test]
    fn normalize_within_rejects_path_outside_allowed_root() {
        let allowed_dir = tempdir().expect("allowed tempdir");
        let outside_dir = tempdir().expect("outside tempdir");
        let file_path = outside_dir.path().join("escape.txt");
        fs::write(&file_path, "fixture").expect("write fixture");

        let request = FilesystemRequest::single_file(&file_path, run_config());
        let err = request
            .normalize_within(allowed_dir.path())
            .expect_err("path outside allowed root must be rejected");

        assert!(matches!(
            err,
            FilesystemRequestError::PathConfinementViolation {
                mode: FilesystemSourceMode::SingleFile,
                ..
            }
        ));
    }

    #[cfg(unix)]
    #[test]
    fn normalize_within_rejects_symlink_escaping_allowed_root() {
        use std::os::unix::fs as unix_fs;

        let allowed = tempdir().expect("allowed tempdir");
        let outside = tempdir().expect("outside tempdir");
        let target = outside.path().join("secret.txt");
        fs::write(&target, "sensitive").expect("write target");

        let link = allowed.path().join("escape_link.txt");
        unix_fs::symlink(&target, &link).expect("create symlink");

        let request = FilesystemRequest::single_file(&link, run_config());
        let err = request
            .normalize_within(allowed.path())
            .expect_err("symlink escaping allowed root must be rejected");

        assert!(matches!(
            err,
            FilesystemRequestError::PathConfinementViolation { .. }
        ));
    }

    #[test]
    fn normalize_within_accepts_path_at_allowed_root() {
        let dir = tempdir().expect("tempdir");

        let request = FilesystemRequest::directory_root(dir.path(), run_config());
        let normalized = request
            .normalize_within(dir.path())
            .expect("path equal to allowed root must succeed");

        assert_eq!(normalized.mode(), FilesystemSourceMode::DirectoryRoot);
        let canonical_dir = dir.path().canonicalize().expect("canonicalize dir");
        assert_eq!(normalized.canonical_root(), canonical_dir.as_path());
    }

    #[test]
    fn normalize_within_reports_allowed_root_canonicalization_failure() {
        let dir = tempdir().expect("tempdir");
        let file_path = dir.path().join("target.txt");
        fs::write(&file_path, "fixture").expect("write fixture");

        let nonexistent_root = dir.path().join("does-not-exist");
        let request = FilesystemRequest::single_file(&file_path, run_config());
        let err = request
            .normalize_within(&nonexistent_root)
            .expect_err("nonexistent allowed root must fail");

        assert!(matches!(
            err,
            FilesystemRequestError::AllowedRootCanonicalize { .. }
        ));

        let err_msg = err.to_string();
        assert!(
            err_msg.contains("allowed root"),
            "error message should mention 'allowed root', got: {err_msg}"
        );
        assert!(
            !err_msg.contains("request path"),
            "error message should not say 'request path', got: {err_msg}"
        );
    }

    #[test]
    fn normalize_within_rejects_dotdot_traversal_escaping_allowed_root() {
        let outer = tempdir().expect("outer tempdir");
        let allowed = outer.path().join("allowed");
        let sibling = outer.path().join("sibling");
        fs::create_dir_all(&allowed).expect("create allowed");
        fs::create_dir_all(&sibling).expect("create sibling");
        let target = sibling.join("escaped.txt");
        fs::write(&target, "fixture").expect("write fixture");

        let escaped_path = allowed.join("../sibling/escaped.txt");
        let request = FilesystemRequest::single_file(escaped_path, run_config());
        let err = request
            .normalize_within(&allowed)
            .expect_err("dotdot traversal must be rejected");
        assert!(matches!(
            err,
            FilesystemRequestError::PathConfinementViolation { .. }
        ));
    }

    #[test]
    fn normalize_within_rejects_directory_root_outside_allowed_root() {
        let allowed_dir = tempdir().expect("allowed tempdir");
        let outside_dir = tempdir().expect("outside tempdir");

        let request = FilesystemRequest::directory_root(outside_dir.path(), run_config());
        let err = request
            .normalize_within(allowed_dir.path())
            .expect_err("directory outside allowed root must be rejected");

        assert!(matches!(
            err,
            FilesystemRequestError::PathConfinementViolation {
                mode: FilesystemSourceMode::DirectoryRoot,
                ..
            }
        ));
    }

    /// Guards the custom `Debug` impl on `FilesystemRequestError` against
    /// accidental replacement by `#[derive(Debug)]`. All `PathBuf` fields
    /// must render as `"<redacted>"` in `{:?}` output.
    #[test]
    fn debug_format_redacts_filesystem_paths() {
        let err = FilesystemRequestError::PathConfinementViolation {
            mode: FilesystemSourceMode::SingleFile,
            path: PathBuf::from("/secret/location/file.txt"),
            allowed_root: PathBuf::from("/allowed/root"),
        };
        let debug = format!("{:?}", err);
        assert!(
            debug.contains("<redacted>"),
            "Debug must redact paths: {debug}"
        );
        assert!(
            !debug.contains("/secret"),
            "Debug must not contain actual path: {debug}"
        );
        assert!(
            !debug.contains("/allowed"),
            "Debug must not contain allowed root: {debug}"
        );
    }
}
