//! Typed filesystem shard payload carried through shard metadata.
//!
//! The payload owns the filesystem-specific shard identity that the generic
//! frontier metadata envelope transports opaquely:
//!
//! - the canonical filesystem root or file path to scan
//! - the explicit source mode (`single_file` or `directory_root`)
//!
//! Range bounds remain in the shard spec itself. They are intentionally not
//! duplicated here.

use std::fmt;
use std::path::{Path, PathBuf};

use crate::request::{FilesystemSourceMode, NormalizedFilesystemRequest};

const SINGLE_FILE_TAG: u8 = 0;
const DIRECTORY_ROOT_TAG: u8 = 1;

/// Filesystem-specific shard payload encoded into `connector_extra`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FilesystemShardPayload {
    mode: FilesystemSourceMode,
    canonical_root: PathBuf,
}

impl FilesystemShardPayload {
    /// Construct a payload from an explicit source mode and canonical root.
    #[must_use]
    pub fn new(mode: FilesystemSourceMode, canonical_root: impl Into<PathBuf>) -> Self {
        Self {
            mode,
            canonical_root: canonical_root.into(),
        }
    }

    /// Construct the payload that corresponds to one normalized filesystem request.
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

    /// Encode the payload into deterministic connector metadata bytes.
    ///
    /// The wire format is:
    ///
    /// - byte `0`: source-mode tag (`0` = single file, `1` = directory root)
    /// - bytes `1..`: canonical UTF-8 path bytes
    ///
    /// # Errors
    ///
    /// Returns an error when the canonical path is empty or not valid UTF-8.
    pub fn encode(&self) -> Result<Vec<u8>, FilesystemShardPayloadEncodeError> {
        if self.canonical_root.as_os_str().is_empty() {
            return Err(FilesystemShardPayloadEncodeError::EmptyPath { mode: self.mode });
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

    /// Decode filesystem payload bytes from `connector_extra`.
    ///
    /// # Errors
    ///
    /// Returns an error when the payload is empty, carries an unknown mode tag,
    /// omits the canonical path bytes, or stores a path that is not valid UTF-8.
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

        Ok(Self::new(mode, canonical_root))
    }
}

/// Payload-encoding failures.
#[derive(Debug)]
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
        }
    }
}

impl std::error::Error for FilesystemShardPayloadEncodeError {}

/// Payload-decoding failures.
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
        }
    }
}

impl std::error::Error for FilesystemShardPayloadDecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidUtf8Path { source, .. } => Some(source),
            Self::EmptyPayload | Self::UnknownModeTag(_) | Self::MissingPath { .. } => None,
        }
    }
}

fn mode_tag(mode: FilesystemSourceMode) -> u8 {
    match mode {
        FilesystemSourceMode::SingleFile => SINGLE_FILE_TAG,
        FilesystemSourceMode::DirectoryRoot => DIRECTORY_ROOT_TAG,
    }
}

fn decode_mode(tag: u8) -> Result<FilesystemSourceMode, FilesystemShardPayloadDecodeError> {
    match tag {
        SINGLE_FILE_TAG => Ok(FilesystemSourceMode::SingleFile),
        DIRECTORY_ROOT_TAG => Ok(FilesystemSourceMode::DirectoryRoot),
        other => Err(FilesystemShardPayloadDecodeError::UnknownModeTag(other)),
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::fs;

    use tempfile::tempdir;

    use super::*;
    use crate::test_support::run_config;

    #[test]
    fn single_file_payload_round_trips() {
        let dir = tempdir().expect("tempdir");
        let file_path = dir.path().join("scan-target.txt");
        fs::write(&file_path, "fixture").expect("write fixture");
        let normalized = crate::request::FilesystemRequest::single_file(&file_path, run_config())
            .normalize()
            .expect("normalize request");
        let payload = normalized.shard_payload();

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
        let payload = normalized.shard_payload();

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

    #[cfg(unix)]
    #[test]
    fn encode_rejects_non_utf8_path() {
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
