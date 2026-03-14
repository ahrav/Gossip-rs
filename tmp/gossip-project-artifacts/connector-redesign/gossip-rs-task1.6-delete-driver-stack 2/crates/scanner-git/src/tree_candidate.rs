//! Candidate buffer for tree diff output.
//!
//! Stores OID-only candidates with canonical context and interned paths.
//! The buffer enforces hard caps on candidate count and path arena usage.
//!
//! # Canonical context
//! Each candidate carries enough context to be stable across spill/merge:
//! commit id, parent index, change kind, file mode, and path classification
//! bits. Paths are interned into a shared arena to avoid per-candidate copies.

use super::byte_arena::{ByteArena, ByteRef};
use super::errors::TreeDiffError;
use super::object_id::OidBytes;
use super::tree_diff_limits::TreeDiffLimits;

/// Change kind for a tree diff candidate.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChangeKind {
    /// New blob introduced at this path.
    Add = 1,
    /// Existing blob modified at this path.
    Modify = 2,
}

impl ChangeKind {
    /// Returns the stable numeric encoding used in run records and spill files.
    #[inline]
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Returns a human-readable string label for event emission.
    #[inline]
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Add => "add",
            Self::Modify => "modify",
        }
    }
}

/// Canonical context for a blob candidate.
///
/// This structure is designed to be stable across spill/merge boundaries:
/// the same blob candidate in the same commit/parent context should yield
/// identical serialized context.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CandidateContext {
    /// Commit-graph position for this candidate context.
    ///
    /// In serial introduced-by walks this is the introducing commit position.
    /// In parallel ODB-blob introduction, this can be the race-winner
    /// observation context.
    pub commit_id: u32,
    /// Index of the parent in the commit's parent list.
    pub parent_idx: u8,
    /// Type of change: Add or Modify.
    pub change_kind: ChangeKind,
    /// Git tree entry file mode, cast to `u16`.
    ///
    /// Populated by the tree diff walker as `mode as u16`. All standard
    /// Git tree entry modes (e.g. `0o100644` = 33188) fit in `u16`
    /// without truncation. Used in sort keys and spill records for
    /// deduplication and ordering.
    pub ctx_flags: u16,
    /// Candidate flags — [`PathClass`](super::path_policy::PathClass) bitflags
    /// produced by [`classify_path`](super::path_policy::classify_path).
    ///
    /// Bits: source, test, vendor, generated, binary, unknown, lock_file.
    pub cand_flags: u16,
    /// Path reference into the shared `ByteArena`.
    pub path_ref: ByteRef,
}

/// Tree diff candidate (OID + context).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TreeCandidate {
    /// Blob object ID.
    pub oid: OidBytes,
    /// Canonical context for the candidate.
    pub ctx: CandidateContext,
}

/// Dereferenced form of [`TreeCandidate`] with path bytes resolved from
/// the owning arena.
///
/// Produced by both [`CandidateBuffer::iter_resolved`] and
/// `CandidateChunk::iter_resolved`; borrows from the respective buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolvedCandidate<'a> {
    /// Blob object ID.
    pub oid: OidBytes,
    /// Full path bytes (borrowed from the owning buffer or chunk arena).
    pub path: &'a [u8],
    /// Commit-graph position associated with this emitted candidate context.
    pub commit_id: u32,
    /// Parent index in the commit's parent list.
    pub parent_idx: u8,
    /// Change kind.
    pub change_kind: ChangeKind,
    /// Context flags.
    pub ctx_flags: u16,
    /// Candidate flags.
    pub cand_flags: u16,
}

/// Sink for tree diff candidates.
///
/// Implementations should treat `path` as ephemeral input and copy/intern it
/// if it needs to persist beyond the call.
pub trait CandidateSink {
    /// Receives a candidate blob.
    #[allow(clippy::too_many_arguments)]
    fn emit(
        &mut self,
        oid: OidBytes,
        path: &[u8],
        commit_id: u32,
        parent_idx: u8,
        change_kind: ChangeKind,
        ctx_flags: u16,
        cand_flags: u16,
    ) -> Result<(), TreeDiffError>;
}

/// In-memory candidate buffer for tree diff output.
///
/// # Invariants
/// - `oid_len` is 20 or 32
/// - `candidates.len() <= max_candidates`
/// - All `path_ref` values refer into `path_arena`
///
/// # Ordering
/// Candidates are stored in the order they are emitted by the tree diff
/// walker (Git tree order), with no additional sorting.
pub struct CandidateBuffer {
    candidates: Vec<TreeCandidate>,
    path_arena: ByteArena,
    max_candidates: u32,
    oid_len: u8,
}

impl CandidateBuffer {
    const INIT_CAP: u32 = 16_384;

    /// Creates a new candidate buffer.
    #[must_use]
    pub fn new(limits: &TreeDiffLimits, oid_len: u8) -> Self {
        assert!(oid_len == 20 || oid_len == 32, "oid_len must be 20 or 32");
        let init_cap = limits.max_candidates.min(Self::INIT_CAP) as usize;
        Self {
            candidates: Vec::with_capacity(init_cap),
            path_arena: ByteArena::with_capacity(limits.max_path_arena_bytes),
            max_candidates: limits.max_candidates,
            oid_len,
        }
    }

    /// Returns the number of candidates in the buffer.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.candidates.len()
    }

    /// Returns true if the buffer is empty.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.candidates.is_empty()
    }

    /// Clears the buffer contents (retains capacity).
    ///
    /// This resets the path arena, invalidating any previously returned
    /// `ByteRef` values and resolved path slices.
    pub fn clear(&mut self) {
        self.candidates.clear();
        self.path_arena.clear_keep_capacity();
    }

    /// Pushes a new candidate.
    ///
    /// # Errors
    ///
    /// Returns:
    /// - `CandidateBufferFull` if the candidate cap is exceeded
    /// - `PathArenaFull` if path arena capacity is exceeded
    /// - `InvalidOidLength` if OID length mismatches the configured length
    #[allow(clippy::too_many_arguments)]
    pub fn push(
        &mut self,
        oid: OidBytes,
        path: &[u8],
        commit_id: u32,
        parent_idx: u8,
        change_kind: ChangeKind,
        ctx_flags: u16,
        cand_flags: u16,
    ) -> Result<(), TreeDiffError> {
        if self.candidates.len() as u32 >= self.max_candidates {
            return Err(TreeDiffError::CandidateBufferFull);
        }
        if oid.len() != self.oid_len {
            return Err(TreeDiffError::InvalidOidLength {
                len: oid.len() as usize,
                expected: self.oid_len as usize,
            });
        }

        let path_ref = self
            .path_arena
            .intern(path)
            .ok_or(TreeDiffError::PathArenaFull)?;

        let ctx = CandidateContext {
            commit_id,
            parent_idx,
            change_kind,
            ctx_flags,
            cand_flags,
            path_ref,
        };

        self.candidates.push(TreeCandidate { oid, ctx });
        Ok(())
    }

    /// Iterates over resolved candidates (with path bytes).
    #[must_use]
    pub fn iter_resolved(&self) -> ResolvedIter<'_> {
        ResolvedIter { buf: self, idx: 0 }
    }
}

impl CandidateSink for CandidateBuffer {
    fn emit(
        &mut self,
        oid: OidBytes,
        path: &[u8],
        commit_id: u32,
        parent_idx: u8,
        change_kind: ChangeKind,
        ctx_flags: u16,
        cand_flags: u16,
    ) -> Result<(), TreeDiffError> {
        self.push(
            oid,
            path,
            commit_id,
            parent_idx,
            change_kind,
            ctx_flags,
            cand_flags,
        )
    }
}

/// Iterator over resolved candidates.
///
/// The returned paths borrow from the candidate buffer's arena and remain
/// valid only as long as the buffer is not cleared or dropped.
pub struct ResolvedIter<'a> {
    buf: &'a CandidateBuffer,
    idx: usize,
}

impl<'a> Iterator for ResolvedIter<'a> {
    type Item = ResolvedCandidate<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.idx >= self.buf.candidates.len() {
            return None;
        }
        let cand = self.buf.candidates[self.idx];
        self.idx += 1;

        let path = self.buf.path_arena.get(cand.ctx.path_ref);
        Some(ResolvedCandidate {
            oid: cand.oid,
            path,
            commit_id: cand.ctx.commit_id,
            parent_idx: cand.ctx.parent_idx,
            change_kind: cand.ctx.change_kind,
            ctx_flags: cand.ctx.ctx_flags,
            cand_flags: cand.ctx.cand_flags,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn change_kind_as_str_values() {
        assert_eq!(ChangeKind::Add.as_str(), "add");
        assert_eq!(ChangeKind::Modify.as_str(), "modify");
    }

    #[test]
    fn change_kind_as_u8_roundtrip() {
        assert_eq!(ChangeKind::Add.as_u8(), 1);
        assert_eq!(ChangeKind::Modify.as_u8(), 2);
    }

    #[test]
    fn ctx_flags_carries_file_mode() {
        // tree_diff.rs passes `mode as u16` (Git tree entry mode) as ctx_flags.
        // Regular file = 0o100644 = 33188 (fits in u16 without truncation).
        let mode_regular: u16 = 0o100644u32 as u16; // 33188
        assert_ne!(mode_regular, 0, "regular file mode must be non-zero");

        let limits = TreeDiffLimits::RESTRICTIVE;
        let mut buf = CandidateBuffer::new(&limits, 20);
        buf.push(
            OidBytes::from_slice(&[0xAA; 20]),
            b"src/main.rs",
            1,
            0,
            ChangeKind::Add,
            mode_regular,
            0,
        )
        .expect("push with non-zero ctx_flags");

        let resolved: Vec<_> = buf.iter_resolved().collect();
        assert_eq!(resolved.len(), 1);
        assert_eq!(
            resolved[0].ctx_flags, mode_regular,
            "ctx_flags must round-trip the file mode, not be reserved/zero"
        );
    }
}
