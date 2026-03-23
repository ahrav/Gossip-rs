//! Canonical filesystem submission request types and normalization helpers.
//!
//! The normalization seam keeps two invariants stable for downstream
//! control-plane stages:
//!
//! - Source mode stays explicit instead of being re-inferred from path shape.
//! - Equivalent requests normalize to the same canonical root.

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
#[derive(Debug)]
pub enum FilesystemRequestError {
    /// The request path was empty.
    EmptyPath {
        /// Requested source mode.
        mode: FilesystemSourceMode,
    },
    /// The request path could not be canonicalized.
    Canonicalize {
        /// Raw request path.
        path: PathBuf,
        /// I/O error from canonicalization.
        source: io::Error,
    },
    /// Metadata lookup failed after canonicalization.
    Metadata {
        /// Canonical path.
        path: PathBuf,
        /// I/O error from metadata lookup.
        source: io::Error,
    },
    /// The canonical path kind does not match the requested source mode.
    PathKindMismatch {
        /// Requested source mode.
        mode: FilesystemSourceMode,
        /// Canonical path.
        path: PathBuf,
        /// Actual canonical path kind.
        actual: FilesystemPathKind,
    },
    /// The canonical path is neither a regular file nor a directory.
    UnsupportedPathKind {
        /// Canonical path.
        path: PathBuf,
    },
}

impl fmt::Display for FilesystemRequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPath { mode } => {
                write!(
                    f,
                    "filesystem request mode '{mode}' requires a non-empty path"
                )
            }
            Self::Canonicalize { path, source } => write!(
                f,
                "failed to canonicalize filesystem request path '{}': {source}",
                path.display()
            ),
            Self::Metadata { path, source } => write!(
                f,
                "failed to inspect canonical filesystem request path '{}': {source}",
                path.display()
            ),
            Self::PathKindMismatch { mode, path, actual } => write!(
                f,
                "filesystem request mode '{mode}' requires a {}, but '{}' canonicalized to a {}",
                mode.expected_path_kind(),
                path.display(),
                actual
            ),
            Self::UnsupportedPathKind { path } => write!(
                f,
                "filesystem request path '{}' must be a regular file or directory",
                path.display()
            ),
        }
    }
}

impl std::error::Error for FilesystemRequestError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Canonicalize { source, .. } | Self::Metadata { source, .. } => Some(source),
            Self::EmptyPath { .. }
            | Self::PathKindMismatch { .. }
            | Self::UnsupportedPathKind { .. } => None,
        }
    }
}

fn detect_path_kind(path: &Path) -> Result<FilesystemPathKind, FilesystemRequestError> {
    let metadata = fs::metadata(path).map_err(|source| FilesystemRequestError::Metadata {
        path: path.to_path_buf(),
        source,
    })?;
    let file_type = metadata.file_type();
    if file_type.is_file() {
        return Ok(FilesystemPathKind::File);
    }
    if file_type.is_dir() {
        return Ok(FilesystemPathKind::Directory);
    }
    Err(FilesystemRequestError::UnsupportedPathKind {
        path: path.to_path_buf(),
    })
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::fs;

    use gossip_coordination::CursorSemantics;
    use tempfile::tempdir;

    use super::*;

    fn run_config() -> RunConfig {
        RunConfig::try_new(CursorSemantics::Completed, 30_000, Some(5))
            .expect("run config should be valid")
    }

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
}
