//! Typed filesystem shard payload carried through shard metadata.
//!
//! The coordination layer transports shard metadata as an opaque byte slice
//! (`connector_extra` in `ShardMetadata` from `gossip-frontier`).  This
//! module gives that byte slice a typed interpretation specific to
//! filesystem scans: the **source mode** (single file vs. directory root)
//! and the **canonical path** that identifies what to scan.
//!
//! # Wire format
//!
//! ```text
//! ┌──────────┬────────────────────────────┐
//! │ tag (1B) │  canonical UTF-8 path (nB) │
//! └──────────┴────────────────────────────┘
//!   0x00 = single file
//!   0x01 = directory root
//! ```
//!
//! The format is intentionally minimal and fixed-width-tag: a single leading
//! byte discriminates the source mode, followed by the canonical path as raw
//! UTF-8.  No length prefix is needed because the `connector_extra` envelope
//! already carries the total byte count.
//!
//! # Scope boundary
//!
//! Key-range bounds live in the shard spec itself and are deliberately
//! **not** duplicated here.  The payload captures _what_ to scan; the shard
//! spec captures _which slice_ of that scan space the shard owns.

use std::fmt;
use std::path::{Path, PathBuf};

use crate::request::{FilesystemSourceMode, NormalizedFilesystemRequest};

// Wire-format discriminant bytes.  Adding a new mode means adding a new
// constant here and extending `mode_tag` / `decode_mode`.
const SINGLE_FILE_TAG: u8 = 0;
const DIRECTORY_ROOT_TAG: u8 = 1;

/// Filesystem-specific shard payload encoded into `connector_extra`.
///
/// Bundles the two pieces of connector-private identity that the generic
/// coordination envelope cannot represent on its own:
///
/// - [`FilesystemSourceMode`] — whether the scan target is a single file or
///   a directory tree.
/// - `canonical_root` — the absolute, canonicalized filesystem path.
///
/// The payload round-trips deterministically through [`encode`](Self::encode)
/// / [`decode`](Self::decode).  Coordination and frontier code treat the
/// encoded bytes as opaque; only the filesystem connector interprets them.
#[derive(Clone, PartialEq, Eq)]
pub struct FilesystemShardPayload {
    mode: FilesystemSourceMode,
    canonical_root: PathBuf,
}

// Custom Debug: redacts `canonical_root` to prevent filesystem path leakage
// through error chains (`anyhow`, `tracing`, `{:?}` formatting).
impl fmt::Debug for FilesystemShardPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FilesystemShardPayload")
            .field("mode", &self.mode)
            .field("canonical_root", &"<redacted>")
            .finish()
    }
}

impl FilesystemShardPayload {
    /// Construct a payload from an explicit source mode and canonical root.
    ///
    /// Does not validate the path. Validation is deferred to
    /// [`Self::encode`], which rejects empty, relative, and non-UTF-8
    /// paths. Prefer [`Self::from_normalized_request`] for production
    /// use — it guarantees a canonical, non-empty, absolute path.
    #[must_use]
    pub fn new(mode: FilesystemSourceMode, canonical_root: impl Into<PathBuf>) -> Self {
        Self {
            mode,
            canonical_root: canonical_root.into(),
        }
    }

    /// Construct the payload from a [`NormalizedFilesystemRequest`].
    ///
    /// Extracts the already-canonicalized root and validated source mode,
    /// so the resulting payload is guaranteed to encode successfully on
    /// platforms where canonical paths are UTF-8.
    #[must_use]
    pub fn from_normalized_request(request: &NormalizedFilesystemRequest) -> Self {
        Self::new(request.mode(), request.canonical_root())
    }

    /// Explicit filesystem source mode preserved in the payload.
    #[must_use]
    pub fn mode(&self) -> FilesystemSourceMode {
        self.mode
    }

    /// Canonical file or directory root carried by the payload.
    #[must_use]
    pub fn canonical_root(&self) -> &Path {
        &self.canonical_root
    }

    /// Encode the payload into deterministic `connector_extra` bytes.
    ///
    /// Wire layout:
    ///
    /// | offset | content                                          |
    /// |--------|--------------------------------------------------|
    /// | `0`    | source-mode tag (`0` = single file, `1` = dir)   |
    /// | `1..`  | canonical path as UTF-8 bytes (no NUL terminator)|
    ///
    /// The output is deterministic: the same `(mode, path)` pair always
    /// produces the same byte sequence, which is important for shard identity
    /// comparisons downstream.
    ///
    /// # Errors
    ///
    /// - [`EmptyPath`](FilesystemShardPayloadEncodeError::EmptyPath) — the
    ///   canonical root is the empty string.
    /// - [`NonUtf8Path`](FilesystemShardPayloadEncodeError::NonUtf8Path) —
    ///   the canonical root contains bytes that are not valid UTF-8 (possible
    ///   on Unix with non-UTF-8 filenames).
    /// - [`RelativePath`](FilesystemShardPayloadEncodeError::RelativePath) —
    ///   the canonical root is not an absolute path.
    pub fn encode(&self) -> Result<Vec<u8>, FilesystemShardPayloadEncodeError> {
        if self.canonical_root.as_os_str().is_empty() {
            return Err(FilesystemShardPayloadEncodeError::EmptyPath { mode: self.mode });
        }

        if !self.canonical_root.is_absolute() {
            return Err(FilesystemShardPayloadEncodeError::RelativePath { mode: self.mode });
        }

        let canonical_root = self.canonical_root.to_str().ok_or_else(|| {
            FilesystemShardPayloadEncodeError::NonUtf8Path {
                path: self.canonical_root.clone(),
            }
        })?;

        let mut encoded = Vec::with_capacity(1 + canonical_root.len());
        encoded.push(mode_tag(self.mode));
        encoded.extend_from_slice(canonical_root.as_bytes());
        Ok(encoded)
    }

    /// Decode filesystem payload bytes previously stored in `connector_extra`.
    ///
    /// Validates the mode tag, path presence, and UTF-8 well-formedness
    /// in that order.  On success the returned payload is structurally
    /// identical to the one that produced `bytes` via [`encode`](Self::encode).
    ///
    /// # Errors
    ///
    /// - [`EmptyPayload`](FilesystemShardPayloadDecodeError::EmptyPayload) —
    ///   zero-length input (no mode tag).
    /// - [`UnknownModeTag`](FilesystemShardPayloadDecodeError::UnknownModeTag)
    ///   — the leading byte is not a recognized source-mode discriminant.
    /// - [`MissingPath`](FilesystemShardPayloadDecodeError::MissingPath) —
    ///   the tag byte is present but no path bytes follow.
    /// - [`InvalidUtf8Path`](FilesystemShardPayloadDecodeError::InvalidUtf8Path)
    ///   — path bytes are present but not valid UTF-8.
    /// - [`RelativePath`](FilesystemShardPayloadDecodeError::RelativePath)
    ///   — path is valid UTF-8 but not absolute (canonical paths must be
    ///   absolute).
    pub fn decode(bytes: &[u8]) -> Result<Self, FilesystemShardPayloadDecodeError> {
        let Some((&tag, canonical_root)) = bytes.split_first() else {
            return Err(FilesystemShardPayloadDecodeError::EmptyPayload);
        };
        let mode = decode_mode(tag)?;

        if canonical_root.is_empty() {
            return Err(FilesystemShardPayloadDecodeError::MissingPath { mode });
        }

        let canonical_root = std::str::from_utf8(canonical_root).map_err(|source| {
            FilesystemShardPayloadDecodeError::InvalidUtf8Path { mode, source }
        })?;

        let path = Path::new(canonical_root);
        if !path.is_absolute() {
            return Err(FilesystemShardPayloadDecodeError::RelativePath { mode });
        }

        Ok(Self::new(mode, canonical_root))
    }
}

/// Errors from [`FilesystemShardPayload::encode`].
///
/// Variants indicate a payload that was constructed with a path the
/// wire format cannot represent.  Normal operation through
/// [`from_normalized_request`](FilesystemShardPayload::from_normalized_request)
/// avoids these because request normalization canonicalizes the path first.
///
/// # Security note
///
/// Error messages include filesystem paths for operator diagnostics.
/// Callers that surface errors to untrusted consumers must redact
/// path details before returning.
pub enum FilesystemShardPayloadEncodeError {
    /// The payload path was empty.
    EmptyPath {
        /// Source mode being encoded.
        mode: FilesystemSourceMode,
    },
    /// The canonical path could not be represented as UTF-8.
    NonUtf8Path {
        /// The offending path.
        path: PathBuf,
    },
    /// The canonical path is relative; the wire format requires absolute paths.
    RelativePath {
        /// Source mode being encoded.
        mode: FilesystemSourceMode,
    },
}

// Custom Debug: redacts `PathBuf` fields to prevent filesystem path leakage
// through error chains (`anyhow`, `tracing`, `{:?}` formatting).
// Display already includes paths for operator diagnostics behind explicit
// `.display()` calls; Debug must not duplicate that exposure.
impl fmt::Debug for FilesystemShardPayloadEncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPath { mode } => f.debug_struct("EmptyPath").field("mode", mode).finish(),
            Self::NonUtf8Path { .. } => f
                .debug_struct("NonUtf8Path")
                .field("path", &"<redacted>")
                .finish(),
            Self::RelativePath { mode } => {
                f.debug_struct("RelativePath").field("mode", mode).finish()
            }
        }
    }
}

impl fmt::Display for FilesystemShardPayloadEncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPath { mode } => write!(
                f,
                "filesystem shard payload mode '{mode}' requires a non-empty canonical path"
            ),
            Self::NonUtf8Path { path } => write!(
                f,
                "filesystem shard payload path '{}' is not valid UTF-8",
                path.display()
            ),
            Self::RelativePath { mode } => write!(
                f,
                "filesystem shard payload mode '{mode}' path must be absolute"
            ),
        }
    }
}

impl std::error::Error for FilesystemShardPayloadEncodeError {}

/// Errors from [`FilesystemShardPayload::decode`].
///
/// Variants are ordered by the validation sequence: empty input is checked
/// first, then the mode tag, then path presence, then path UTF-8 validity,
/// then absolute-path verification.
#[derive(Debug)]
pub enum FilesystemShardPayloadDecodeError {
    /// No payload bytes were present.
    EmptyPayload,
    /// The leading mode tag is not recognized.
    UnknownModeTag(u8),
    /// The payload omitted the canonical path bytes.
    MissingPath {
        /// Decoded source mode tag.
        mode: FilesystemSourceMode,
    },
    /// The payload path bytes were not valid UTF-8.
    InvalidUtf8Path {
        /// Decoded source mode tag.
        mode: FilesystemSourceMode,
        /// Underlying UTF-8 decode failure.
        source: std::str::Utf8Error,
    },
    /// The payload path is relative; canonical paths must be absolute.
    RelativePath {
        /// Decoded source mode tag.
        mode: FilesystemSourceMode,
    },
}

impl fmt::Display for FilesystemShardPayloadDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPayload => f.write_str("filesystem shard payload is empty"),
            Self::UnknownModeTag(tag) => {
                write!(f, "filesystem shard payload mode tag '{tag}' is unknown")
            }
            Self::MissingPath { mode } => write!(
                f,
                "filesystem shard payload mode '{mode}' requires canonical path bytes"
            ),
            Self::InvalidUtf8Path { mode, source } => write!(
                f,
                "filesystem shard payload mode '{mode}' path is not valid UTF-8: {source}"
            ),
            Self::RelativePath { mode } => write!(
                f,
                "filesystem shard payload mode '{mode}' path must be absolute"
            ),
        }
    }
}

impl std::error::Error for FilesystemShardPayloadDecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidUtf8Path { source, .. } => Some(source),
            Self::EmptyPayload
            | Self::UnknownModeTag(_)
            | Self::MissingPath { .. }
            | Self::RelativePath { .. } => None,
        }
    }
}

/// Map a source mode to its wire-format tag byte.
fn mode_tag(mode: FilesystemSourceMode) -> u8 {
    match mode {
        FilesystemSourceMode::SingleFile => SINGLE_FILE_TAG,
        FilesystemSourceMode::DirectoryRoot => DIRECTORY_ROOT_TAG,
    }
}

/// Reverse-map a wire-format tag byte to a source mode.
fn decode_mode(tag: u8) -> Result<FilesystemSourceMode, FilesystemShardPayloadDecodeError> {
    match tag {
        SINGLE_FILE_TAG => Ok(FilesystemSourceMode::SingleFile),
        DIRECTORY_ROOT_TAG => Ok(FilesystemSourceMode::DirectoryRoot),
        other => Err(FilesystemShardPayloadDecodeError::UnknownModeTag(other)),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::*;
    use crate::planner::plan_filesystem_initial_shards;
    use crate::test_support::run_config;

    #[test]
    fn single_file_payload_round_trips() {
        let dir = tempdir().expect("tempdir");
        let file_path = dir.path().join("scan-target.txt");
        fs::write(&file_path, "fixture").expect("write fixture");
        let normalized = crate::request::FilesystemRequest::single_file(&file_path, run_config())
            .normalize()
            .expect("normalize request");
        let plan = plan_filesystem_initial_shards(normalized.clone());
        let payload = plan.shard_payload();

        let decoded = FilesystemShardPayload::decode(&payload.encode().expect("encode payload"))
            .expect("decode payload");

        assert_eq!(decoded, payload);
        assert_eq!(decoded.mode(), FilesystemSourceMode::SingleFile);
        assert_eq!(decoded.canonical_root(), normalized.canonical_root());
    }

    #[test]
    fn directory_root_payload_round_trips() {
        let dir = tempdir().expect("tempdir");
        let root = dir.path().join("scan-root");
        fs::create_dir(&root).expect("create root");
        let normalized = crate::request::FilesystemRequest::directory_root(&root, run_config())
            .normalize()
            .expect("normalize request");
        let plan = plan_filesystem_initial_shards(normalized.clone());
        let payload = plan.shard_payload();

        let decoded = FilesystemShardPayload::decode(&payload.encode().expect("encode payload"))
            .expect("decode payload");

        assert_eq!(decoded, payload);
        assert_eq!(decoded.mode(), FilesystemSourceMode::DirectoryRoot);
        assert_eq!(decoded.canonical_root(), normalized.canonical_root());
    }

    #[test]
    fn decode_rejects_empty_payload() {
        let err = FilesystemShardPayload::decode(&[]).expect_err("empty payload must fail");
        assert!(matches!(
            err,
            FilesystemShardPayloadDecodeError::EmptyPayload
        ));
    }

    #[test]
    fn decode_rejects_unknown_mode_tag() {
        let err = FilesystemShardPayload::decode(&[9, b'/', b't', b'm', b'p'])
            .expect_err("unknown tag must fail");
        assert!(matches!(
            err,
            FilesystemShardPayloadDecodeError::UnknownModeTag(9)
        ));
    }

    #[test]
    fn decode_rejects_missing_path() {
        let err =
            FilesystemShardPayload::decode(&[SINGLE_FILE_TAG]).expect_err("missing path must fail");
        assert!(matches!(
            err,
            FilesystemShardPayloadDecodeError::MissingPath {
                mode: FilesystemSourceMode::SingleFile,
            }
        ));
    }

    #[test]
    fn decode_rejects_relative_path() {
        let bytes = [SINGLE_FILE_TAG, b'r', b'e', b'l', b'/', b'f', b'o', b'o'];
        let err =
            FilesystemShardPayload::decode(&bytes).expect_err("relative path must be rejected");
        assert!(matches!(
            err,
            FilesystemShardPayloadDecodeError::RelativePath {
                mode: FilesystemSourceMode::SingleFile,
            }
        ));
        assert!(
            err.to_string().contains("must be absolute"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn decode_rejects_invalid_utf8_path() {
        let err = FilesystemShardPayload::decode(&[SINGLE_FILE_TAG, 0xFF, 0xFE])
            .expect_err("invalid UTF-8 path must fail");
        assert!(matches!(
            err,
            FilesystemShardPayloadDecodeError::InvalidUtf8Path {
                mode: FilesystemSourceMode::SingleFile,
                ..
            }
        ));
    }

    #[test]
    fn encode_rejects_empty_path() {
        let err = FilesystemShardPayload::new(FilesystemSourceMode::SingleFile, PathBuf::new())
            .encode()
            .expect_err("empty path must fail");
        assert!(matches!(
            err,
            FilesystemShardPayloadEncodeError::EmptyPath {
                mode: FilesystemSourceMode::SingleFile,
            }
        ));
    }

    #[cfg(unix)]
    #[test]
    fn encode_rejects_non_utf8_path() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let path = PathBuf::from(OsString::from_vec(vec![0x66, 0x6f, 0x80]));
        let err = FilesystemShardPayload::new(FilesystemSourceMode::SingleFile, path)
            .encode()
            .expect_err("non-UTF-8 path must fail");

        assert!(matches!(
            err,
            FilesystemShardPayloadEncodeError::NonUtf8Path { .. }
        ));
    }
}
