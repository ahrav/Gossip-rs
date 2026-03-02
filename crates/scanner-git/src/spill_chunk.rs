//! Spill chunk storage and in-chunk dedupe.
//!
//! A spill chunk holds a bounded set of candidates plus an arena for their
//! paths. The chunk can be sorted and deduped using a canonical ordering
//! that is stable across spill runs, so spill files can be merged without
//! additional normalization.
//!
//! Canonical ordering: OID, path bytes, commit id, parent index, change kind,
//! context flags, candidate flags.
//!
//! # Invariants
//! - `candidates.len() <= max_candidates`
//! - All `path_ref` values refer into `path_arena`
//! - `oid_len` is 20 or 32

use std::cmp::Ordering;

use super::byte_arena::ByteArena;
use super::errors::SpillError;
use super::object_id::OidBytes;
use super::spill_limits::SpillLimits;
use super::tree_candidate::{CandidateContext, ChangeKind, ResolvedCandidate, TreeCandidate};
use super::work_items::WorkItems;

/// Spill chunk with bounded candidate and path storage.
///
/// This is a single-threaded, in-memory structure. It does not perform any
/// spilling itself; the caller (spiller) decides when to flush to disk.
///
/// Candidates are appended in arbitrary order. Call `sort_and_dedupe` before
/// persisting or iterating for spill output.
///
/// # Invariants
/// - `path_ref` values in `candidates` point into `path_arena`.
/// - `oid_len` is validated on every push.
#[derive(Debug)]
pub struct CandidateChunk {
    candidates: Vec<TreeCandidate>,
    path_arena: ByteArena,
    max_candidates: u32,
    max_path_len: u16,
    oid_len: u8,
}

impl CandidateChunk {
    /// Creates a new spill chunk.
    #[must_use]
    pub fn new(limits: &SpillLimits, oid_len: u8) -> Self {
        assert!(oid_len == 20 || oid_len == 32, "oid_len must be 20 or 32");
        Self {
            candidates: Vec::with_capacity(limits.max_chunk_candidates as usize),
            path_arena: ByteArena::with_capacity(limits.max_chunk_path_bytes),
            max_candidates: limits.max_chunk_candidates,
            max_path_len: limits.max_path_len,
            oid_len,
        }
    }

    /// Returns the number of candidates in the chunk.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.candidates.len()
    }

    /// Returns true if the chunk is empty.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.candidates.is_empty()
    }

    /// Clears candidates and path arena, retaining capacity.
    ///
    /// Any previously returned `ByteRef` values become invalid.
    pub fn clear(&mut self) {
        self.candidates.clear();
        self.path_arena.clear_keep_capacity();
    }

    /// Pushes a candidate into the chunk.
    ///
    /// Ordering is not enforced; duplicates are allowed until `sort_and_dedupe`.
    ///
    /// # Errors
    /// - `SpillError::OidLengthMismatch` if the OID length does not match `oid_len`.
    /// - `SpillError::PathTooLong` if the path exceeds `max_path_len`.
    /// - `SpillError::ArenaOverflow` if the chunk or path arena is full.
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
    ) -> Result<(), SpillError> {
        if oid.len() != self.oid_len {
            return Err(SpillError::OidLengthMismatch {
                got: oid.len(),
                expected: self.oid_len,
            });
        }

        if self.candidates.len() as u32 >= self.max_candidates {
            return Err(SpillError::ArenaOverflow);
        }

        let max_len = self.max_path_len as usize;
        if path.len() > max_len {
            return Err(SpillError::PathTooLong {
                len: path.len(),
                max: max_len,
            });
        }

        let path_ref = self
            .path_arena
            .intern(path)
            .ok_or(SpillError::ArenaOverflow)?;
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

    /// Sorts candidates by canonical order and removes duplicates.
    ///
    /// This is required before spilling a chunk to disk to ensure run files
    /// are globally mergeable. The ordering compares path bytes (not arena
    /// offsets) to stay stable across runs.
    ///
    /// Two dedup passes run in sequence:
    /// 1. Exact-match dedup on the full canonical key (OID + path + context).
    /// 2. Per-OID reduction that keeps only the most canonical candidate for
    ///    each distinct OID (lowest commit id, then path, then context).
    pub fn sort_and_dedupe(&mut self) {
        let arena = &self.path_arena;
        self.candidates
            .sort_unstable_by(|a, b| compare_candidates(arena, a, b));
        self.candidates
            .dedup_by(|a, b| candidates_equal(arena, a, b));
        self.reduce_by_oid();
    }

    fn reduce_by_oid(&mut self) {
        if self.candidates.is_empty() {
            return;
        }

        let arena = &self.path_arena;
        let mut write = 0usize;
        let mut idx = 0usize;
        let len = self.candidates.len();
        while idx < len {
            let oid = self.candidates[idx].oid;
            let mut best = self.candidates[idx];
            let mut best_path = arena.get(best.ctx.path_ref);
            idx += 1;

            while idx < len && self.candidates[idx].oid == oid {
                let cand = self.candidates[idx];
                let path = arena.get(cand.ctx.path_ref);
                if is_more_canonical(cand.ctx, path, best.ctx, best_path) {
                    best = cand;
                    best_path = path;
                }
                idx += 1;
            }

            self.candidates[write] = best;
            write += 1;
        }

        self.candidates.truncate(write);
    }

    /// Iterates over resolved candidates with path bytes.
    ///
    /// The returned order matches the current candidate vector. Call
    /// `sort_and_dedupe` first to get canonical ordering.
    ///
    /// The returned paths borrow from the chunk's arena and become invalid
    /// once the chunk is cleared.
    #[must_use]
    pub fn iter_resolved(&self) -> ResolvedIter<'_> {
        ResolvedIter {
            chunk: self,
            idx: 0,
        }
    }

    /// Populates work item tables with the chunk's candidates.
    ///
    /// The work items reference this chunk's path arena via `ByteRef`, so the
    /// chunk must remain alive while the items are processed.
    ///
    /// Items are emitted in the current candidate order; call
    /// `sort_and_dedupe` first if you require canonical ordering.
    ///
    /// # Errors
    /// Returns `SpillError::ArenaOverflow` if the destination work items are full.
    pub fn fill_work_items(&self, items: &mut WorkItems) -> Result<(), SpillError> {
        items.clear();
        for cand in &self.candidates {
            items.push(
                cand.oid,
                cand.ctx,
                cand.ctx.path_ref,
                cand.ctx.cand_flags,
                0,
                0,
            )?;
        }
        Ok(())
    }
}

/// Iterator over resolved candidates.
///
/// Each yielded item borrows path bytes from the chunk's arena.
pub struct ResolvedIter<'a> {
    chunk: &'a CandidateChunk,
    idx: usize,
}

impl<'a> Iterator for ResolvedIter<'a> {
    type Item = ResolvedCandidate<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.idx >= self.chunk.candidates.len() {
            return None;
        }
        let cand = self.chunk.candidates[self.idx];
        self.idx += 1;

        let path = self.chunk.path_arena.get(cand.ctx.path_ref);
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

fn compare_candidates(arena: &ByteArena, a: &TreeCandidate, b: &TreeCandidate) -> Ordering {
    a.oid
        .cmp(&b.oid)
        // Compare by path bytes so ordering is independent of arena layout.
        .then_with(|| arena.get(a.ctx.path_ref).cmp(arena.get(b.ctx.path_ref)))
        .then_with(|| a.ctx.commit_id.cmp(&b.ctx.commit_id))
        .then_with(|| a.ctx.parent_idx.cmp(&b.ctx.parent_idx))
        .then_with(|| a.ctx.change_kind.as_u8().cmp(&b.ctx.change_kind.as_u8()))
        .then_with(|| a.ctx.ctx_flags.cmp(&b.ctx.ctx_flags))
        .then_with(|| a.ctx.cand_flags.cmp(&b.ctx.cand_flags))
}

/// Returns true if two candidates are identical for spill dedupe purposes.
fn candidates_equal(arena: &ByteArena, a: &TreeCandidate, b: &TreeCandidate) -> bool {
    a.oid == b.oid
        && a.ctx.commit_id == b.ctx.commit_id
        && a.ctx.parent_idx == b.ctx.parent_idx
        && a.ctx.change_kind == b.ctx.change_kind
        && a.ctx.ctx_flags == b.ctx.ctx_flags
        && a.ctx.cand_flags == b.ctx.cand_flags
        && arena.get(a.ctx.path_ref) == arena.get(b.ctx.path_ref)
}

fn is_more_canonical(
    a_ctx: CandidateContext,
    a_path: &[u8],
    b_ctx: CandidateContext,
    b_path: &[u8],
) -> bool {
    match a_ctx.commit_id.cmp(&b_ctx.commit_id) {
        Ordering::Less => return true,
        Ordering::Greater => return false,
        Ordering::Equal => {}
    }
    match a_path.cmp(b_path) {
        Ordering::Less => return true,
        Ordering::Greater => return false,
        Ordering::Equal => {}
    }
    match a_ctx.parent_idx.cmp(&b_ctx.parent_idx) {
        Ordering::Less => return true,
        Ordering::Greater => return false,
        Ordering::Equal => {}
    }
    match a_ctx.change_kind.as_u8().cmp(&b_ctx.change_kind.as_u8()) {
        Ordering::Less => return true,
        Ordering::Greater => return false,
        Ordering::Equal => {}
    }
    match a_ctx.ctx_flags.cmp(&b_ctx.ctx_flags) {
        Ordering::Less => return true,
        Ordering::Greater => return false,
        Ordering::Equal => {}
    }
    a_ctx.cand_flags < b_ctx.cand_flags
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> SpillLimits {
        SpillLimits {
            max_spill_bytes: 1024 * 1024,
            seen_batch_max_oids: 16,
            seen_batch_max_path_bytes: 256,
            max_chunk_candidates: 8,
            max_chunk_path_bytes: 128,
            max_spill_runs: 4,
            max_path_len: 16,
        }
    }

    #[test]
    fn sort_and_dedupe_orders_and_removes_dupes() {
        let limits = limits();
        let mut chunk = CandidateChunk::new(&limits, 20);

        let oid_a = OidBytes::sha1([0x01; 20]);
        let oid_b = OidBytes::sha1([0x02; 20]);

        chunk
            .push(oid_a, b"b.txt", 2, 0, ChangeKind::Add, 0, 0)
            .unwrap();
        chunk
            .push(oid_a, b"a.txt", 1, 0, ChangeKind::Add, 0, 0)
            .unwrap();
        chunk
            .push(oid_b, b"a.txt", 3, 0, ChangeKind::Modify, 1, 1)
            .unwrap();
        // Duplicate of the second entry.
        chunk
            .push(oid_a, b"a.txt", 1, 0, ChangeKind::Add, 0, 0)
            .unwrap();

        chunk.sort_and_dedupe();

        let resolved: Vec<_> = chunk.iter_resolved().collect();
        assert_eq!(resolved.len(), 2);
        assert_eq!(resolved[0].oid, oid_a);
        assert_eq!(resolved[0].path, b"a.txt");
        assert_eq!(resolved[1].oid, oid_b);
        assert_eq!(resolved[1].path, b"a.txt");
    }

    #[test]
    fn path_too_long_rejected() {
        let limits = limits();
        let mut chunk = CandidateChunk::new(&limits, 20);
        let oid = OidBytes::sha1([0x11; 20]);
        let path = vec![b'a'; limits.max_path_len as usize + 1];

        let err = chunk
            .push(oid, &path, 1, 0, ChangeKind::Add, 0, 0)
            .unwrap_err();

        assert!(matches!(err, SpillError::PathTooLong { .. }));
    }
}
