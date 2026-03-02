//! Spill run file format and canonical ordering.
//!
//! The run format stores sorted, deduped candidates on disk for later
//! k-way merging. Records are serialized in a stable, platform-independent
//! encoding with strict version validation.
//!
//! # Record layout
//! Each record is encoded as:
//! - `oid` bytes (20 or 32)
//! - `commit_id` (u32, big-endian)
//! - `parent_idx` (u8)
//! - `change_kind` (u8: 1 = Add, 2 = Modify)
//! - `ctx_flags` (u16, big-endian)
//! - `cand_flags` (u16, big-endian)
//! - `path_len` (u16, big-endian)
//! - `path` bytes
//!
//! The caller must sort and dedupe by the canonical ordering below before
//! writing a run.

use std::cmp::Ordering;

use super::errors::SpillError;
use super::object_id::OidBytes;
use super::tree_candidate::ChangeKind;

/// Spill run magic bytes.
const RUN_MAGIC: [u8; 4] = *b"SRUN";
/// Spill run format version.
const RUN_VERSION: u16 = 1;

/// Fixed-size run file header (12 bytes).
///
/// All multi-byte integers are big-endian for stability across platforms.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RunHeader {
    /// Format version.
    pub version: u16,
    /// OID length (20 or 32 bytes).
    pub oid_len: u8,
    /// Number of records encoded in the run.
    pub record_count: u32,
}

impl RunHeader {
    /// Creates a new header for the given OID length and record count.
    ///
    /// The reader trusts `record_count` to bound iteration.
    pub fn new(oid_len: u8, record_count: u32) -> Result<Self, SpillError> {
        if oid_len != 20 && oid_len != 32 {
            return Err(SpillError::OidLengthMismatch {
                got: oid_len,
                expected: 20,
            });
        }
        Ok(Self {
            version: RUN_VERSION,
            oid_len,
            record_count,
        })
    }

    /// Encodes the header to bytes.
    ///
    /// Layout: magic (4) || version (2) || oid_len (1) || reserved (1) ||
    /// record_count (4).
    pub fn encode(&self) -> [u8; 12] {
        let mut out = [0u8; 12];
        out[0..4].copy_from_slice(&RUN_MAGIC);
        out[4..6].copy_from_slice(&self.version.to_be_bytes());
        out[6] = self.oid_len;
        out[7] = 0;
        out[8..12].copy_from_slice(&self.record_count.to_be_bytes());
        out
    }

    /// Decodes a header from bytes.
    ///
    /// Returns `InvalidRunHeader` if magic, version, or OID length are invalid.
    pub fn decode(bytes: &[u8]) -> Result<Self, SpillError> {
        if bytes.len() < 12 {
            return Err(SpillError::InvalidRunHeader);
        }
        if bytes[0..4] != RUN_MAGIC {
            return Err(SpillError::InvalidRunHeader);
        }
        let version = u16::from_be_bytes([bytes[4], bytes[5]]);
        if version != RUN_VERSION {
            return Err(SpillError::InvalidRunHeader);
        }
        let oid_len = bytes[6];
        if oid_len != 20 && oid_len != 32 {
            return Err(SpillError::InvalidRunHeader);
        }
        let record_count = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        Ok(Self {
            version,
            oid_len,
            record_count,
        })
    }
}

/// Context fields stored for each spill record.
///
/// These mirror the in-memory candidate context and are stable across spill
/// runs to allow dedupe and merge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RunContext {
    /// Commit-graph position associated with this serialized candidate context.
    pub commit_id: u32,
    /// Parent index in the commit's parent list.
    pub parent_idx: u8,
    /// Change kind (Add/Modify).
    pub change_kind: ChangeKind,
    /// Context flags (file mode bits, etc.).
    pub ctx_flags: u16,
    /// Candidate flags (path class bits, etc.).
    pub cand_flags: u16,
}

/// Record stored in a spill run.
///
/// Paths are stored as raw bytes (not UTF-8) to preserve Git path semantics.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunRecord {
    /// Blob object ID.
    pub oid: OidBytes,
    /// Canonical context.
    pub ctx: RunContext,
    /// Path bytes.
    pub path: Vec<u8>,
}

impl RunRecord {
    /// Canonical ordering used for spill dedupe and merge.
    ///
    /// Ordering is total and stable: OID, then path bytes, then full context.
    pub fn cmp_canonical(&self, other: &Self) -> Ordering {
        self.oid
            .cmp(&other.oid)
            .then_with(|| self.path.cmp(&other.path))
            .then_with(|| self.ctx.commit_id.cmp(&other.ctx.commit_id))
            .then_with(|| self.ctx.parent_idx.cmp(&other.ctx.parent_idx))
            .then_with(|| {
                self.ctx
                    .change_kind
                    .as_u8()
                    .cmp(&other.ctx.change_kind.as_u8())
            })
            .then_with(|| self.ctx.ctx_flags.cmp(&other.ctx.ctx_flags))
            .then_with(|| self.ctx.cand_flags.cmp(&other.ctx.cand_flags))
    }

    /// Creates a reusable scratch record with a preallocated path buffer.
    ///
    /// If `oid_len` is invalid, this falls back to a zero SHA-1 OID; callers
    /// should pass validated lengths from `RunHeader`.
    pub fn scratch(oid_len: u8, path_capacity: usize) -> Self {
        let oid = match oid_len {
            20 => OidBytes::sha1([0u8; 20]),
            32 => OidBytes::sha256([0u8; 32]),
            _ => OidBytes::sha1([0u8; 20]),
        };
        Self {
            oid,
            ctx: RunContext {
                commit_id: 0,
                parent_idx: 0,
                change_kind: ChangeKind::Add,
                ctx_flags: 0,
                cand_flags: 0,
            },
            path: Vec::with_capacity(path_capacity),
        }
    }
}

impl Ord for RunRecord {
    fn cmp(&self, other: &Self) -> Ordering {
        self.cmp_canonical(other)
    }
}

impl PartialOrd for RunRecord {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(std::cmp::Ord::cmp(self, other))
    }
}
