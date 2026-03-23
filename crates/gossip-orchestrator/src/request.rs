//! Canonical filesystem submission request types and normalization helpers.
//!
//! The normalization seam keeps two invariants stable for downstream
//! control-plane stages:
//!
//! - Source mode stays explicit instead of being re-inferred from path shape.
//! - Equivalent requests normalize to the same canonical root and runtime
//!   scan settings.

use std::ffi::OsStr;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use gossip_coordination::RunConfig;
use gossip_scanner_runtime::FsScanConfig;

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
/// The request reuses [`FsScanConfig`] as the runtime-facing scan settings
/// carrier and adds explicit source mode plus coordination-level run config.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FilesystemRequest {
    mode: FilesystemSourceMode,
    scan_config: FsScanConfig,
    run_config: RunConfig,
}

impl FilesystemRequest {
    /// Construct one filesystem request from explicit source mode and scan config.
    #[must_use]
    pub fn new(
        mode: FilesystemSourceMode,
        scan_config: FsScanConfig,
        run_config: RunConfig,
    ) -> Self {
        Self {
            mode,
            scan_config,
            run_config,
        }
    }

    /// Construct a single-file request with default scan settings for `path`.
    #[must_use]
    pub fn single_file(path: impl Into<PathBuf>, run_config: RunConfig) -> Self {
        Self::new(
            FilesystemSourceMode::SingleFile,
            FsScanConfig::new(path),
            run_config,
        )
    }

    /// Construct a directory-root request with default scan settings for `path`.
    #[must_use]
    pub fn directory_root(path: impl Into<PathBuf>, run_config: RunConfig) -> Self {
        Self::new(
            FilesystemSourceMode::DirectoryRoot,
            FsScanConfig::new(path),
            run_config,
        )
    }

    /// Requested source mode before normalization.
    #[must_use]
    pub fn mode(&self) -> FilesystemSourceMode {
        self.mode
    }

    /// Scan settings before path canonicalization.
    #[must_use]
    pub fn scan_config(&self) -> &FsScanConfig {
        &self.scan_config
    }

    /// Coordination-level run settings for this request.
    #[must_use]
    pub fn run_config(&self) -> RunConfig {
        self.run_config
    }

    /// Canonicalize the request path and validate it against the requested mode.
    ///
    /// The returned request preserves explicit source mode, stores the
    /// canonical root, and exposes a geometry-only planning input for later
    /// control-plane stages.
    ///
    /// # Errors
    ///
    /// Returns an error when the path is empty, cannot be canonicalized,
    /// canonicalizes to a path kind that does not match the requested mode,
    /// or resolves to something other than a regular file or directory.
    pub fn normalize(&self) -> Result<NormalizedFilesystemRequest, FilesystemRequestError> {
        let requested_path = self.scan_config.path.as_path();
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
        if matches!(self.mode, FilesystemSourceMode::SingleFile)
            && canonical_root.file_name().is_none()
        {
            return Err(FilesystemRequestError::SingleFileMissingName {
                path: canonical_root,
            });
        }

        let mut scan_config = self.scan_config.clone();
        scan_config.path = canonical_root.clone();

        let source = NormalizedFilesystemSource {
            mode: self.mode,
            canonical_root: canonical_root.clone(),
            scan_config,
        };
        let initial_plan = FilesystemInitialPlanInput {
            mode: self.mode,
            canonical_root,
        };

        Ok(NormalizedFilesystemRequest {
            run_config: self.run_config,
            source,
            initial_plan,
        })
    }
}

/// Normalized filesystem submission state shared across later control-plane stages.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NormalizedFilesystemRequest {
    run_config: RunConfig,
    source: NormalizedFilesystemSource,
    initial_plan: FilesystemInitialPlanInput,
}

impl NormalizedFilesystemRequest {
    /// Coordination-level run settings for this normalized request.
    #[must_use]
    pub fn run_config(&self) -> RunConfig {
        self.run_config
    }

    /// Canonical filesystem source information.
    #[must_use]
    pub fn source(&self) -> &NormalizedFilesystemSource {
        &self.source
    }

    /// Geometry-only planning input for initial shard planning.
    #[must_use]
    pub fn initial_plan(&self) -> &FilesystemInitialPlanInput {
        &self.initial_plan
    }
}

/// Canonical filesystem source information derived from a normalized request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NormalizedFilesystemSource {
    mode: FilesystemSourceMode,
    canonical_root: PathBuf,
    scan_config: FsScanConfig,
}

impl NormalizedFilesystemSource {
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

    /// Runtime scan settings with the canonicalized path installed.
    #[must_use]
    pub fn scan_config(&self) -> &FsScanConfig {
        &self.scan_config
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

/// Geometry-only input derived from a normalized filesystem request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FilesystemInitialPlanInput {
    mode: FilesystemSourceMode,
    canonical_root: PathBuf,
}

impl FilesystemInitialPlanInput {
    /// Explicit source mode for planning decisions.
    #[must_use]
    pub fn mode(&self) -> FilesystemSourceMode {
        self.mode
    }

    /// Canonical file or directory root for the planner input.
    #[must_use]
    pub fn canonical_root(&self) -> &Path {
        &self.canonical_root
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
    /// A canonical single-file target did not expose a file name component.
    SingleFileMissingName {
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
            Self::SingleFileMissingName { path } => write!(
                f,
                "single-file request path '{}' does not have a file name",
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
            | Self::UnsupportedPathKind { .. }
            | Self::SingleFileMissingName { .. } => None,
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
    use gossip_scanner_runtime::{AnchorMode, ExecutionMode, ScanBudgets, TransformFilter};
    use tempfile::tempdir;

    use super::*;

    fn run_config() -> RunConfig {
        RunConfig::try_new(CursorSemantics::Completed, 30_000, Some(5))
            .expect("run config should be valid")
    }

    #[test]
    fn single_file_request_normalizes_to_canonical_file_source() {
        let dir = tempdir().expect("tempdir");
        let file_path = dir.path().join("scan-target.txt");
        let rules_file = dir.path().join("rules.yaml");
        fs::write(&file_path, "fixture").expect("write fixture");
        fs::write(&rules_file, "rules").expect("write rules");

        let request_path = file_path
            .parent()
            .expect("file has parent")
            .join(".")
            .join("scan-target.txt");
        let request = FilesystemRequest::new(
            FilesystemSourceMode::SingleFile,
            FsScanConfig::new(request_path)
                .with_workers(3)
                .with_decode_depth(Some(2))
                .with_skip_archives(true)
                .with_scan_binary(true)
                .with_persist_findings(true)
                .with_anchor_mode(AnchorMode::Derived)
                .with_rules_file(Some(rules_file.clone()))
                .with_transform_filter(TransformFilter::None)
                .with_execution_mode(ExecutionMode::Connector)
                .with_budgets(ScanBudgets {
                    max_items: 99,
                    max_bytes: 1_234,
                }),
            run_config(),
        );

        let normalized = request.normalize().expect("file request should normalize");
        let canonical_path = file_path.canonicalize().expect("canonicalize file");

        assert_eq!(normalized.run_config(), run_config());
        assert_eq!(normalized.source().mode(), FilesystemSourceMode::SingleFile);
        assert_eq!(
            normalized.source().canonical_root(),
            canonical_path.as_path()
        );
        assert_eq!(
            normalized.source().scan_config().path.as_path(),
            canonical_path.as_path()
        );
        assert_eq!(normalized.source().scan_config().workers, 3);
        assert_eq!(normalized.source().scan_config().decode_depth, Some(2));
        assert!(normalized.source().scan_config().skip_archives);
        assert!(normalized.source().scan_config().scan_binary);
        assert!(normalized.source().scan_config().persist_findings);
        assert_eq!(
            normalized.source().scan_config().anchor_mode,
            AnchorMode::Derived
        );
        assert_eq!(
            normalized.source().scan_config().rules_file,
            Some(rules_file)
        );
        assert_eq!(
            normalized.source().scan_config().transform_filter,
            TransformFilter::None
        );
        assert_eq!(
            normalized.source().scan_config().execution_mode,
            ExecutionMode::Connector
        );
        assert_eq!(
            normalized.source().scan_config().budgets,
            ScanBudgets {
                max_items: 99,
                max_bytes: 1_234,
            }
        );
        assert_eq!(
            normalized.source().relative_namespace_name(),
            Some(OsStr::new("scan-target.txt"))
        );
        assert_eq!(
            normalized.initial_plan().mode(),
            FilesystemSourceMode::SingleFile
        );
        assert_eq!(
            normalized.initial_plan().canonical_root(),
            canonical_path.as_path()
        );
    }

    #[test]
    fn directory_root_request_normalizes_to_canonical_directory_source() {
        let dir = tempdir().expect("tempdir");
        let root_path = dir.path().join("scan-root");
        fs::create_dir(&root_path).expect("create root dir");

        let request = FilesystemRequest::new(
            FilesystemSourceMode::DirectoryRoot,
            FsScanConfig::new(root_path.join(".")),
            run_config(),
        );

        let normalized = request
            .normalize()
            .expect("directory request should normalize");
        let canonical_root = root_path.canonicalize().expect("canonicalize dir");

        assert_eq!(
            normalized.source().mode(),
            FilesystemSourceMode::DirectoryRoot
        );
        assert_eq!(
            normalized.source().canonical_root(),
            canonical_root.as_path()
        );
        assert_eq!(
            normalized.source().scan_config().path.as_path(),
            canonical_root.as_path()
        );
        assert_eq!(normalized.source().relative_namespace_name(), None);
        assert_eq!(
            normalized.initial_plan().mode(),
            FilesystemSourceMode::DirectoryRoot
        );
    }

    #[test]
    fn single_file_request_rejects_directory_target() {
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
    fn directory_root_request_rejects_regular_file_target() {
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

        let canonical_request = FilesystemRequest::new(
            FilesystemSourceMode::SingleFile,
            FsScanConfig::new(&file_path)
                .with_workers(2)
                .with_execution_mode(ExecutionMode::Connector),
            run_config(),
        );
        let dotted_request = FilesystemRequest::new(
            FilesystemSourceMode::SingleFile,
            FsScanConfig::new(
                file_path
                    .parent()
                    .expect("file has parent")
                    .join(".")
                    .join("scan-target.txt"),
            )
            .with_workers(2)
            .with_execution_mode(ExecutionMode::Connector),
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
}
