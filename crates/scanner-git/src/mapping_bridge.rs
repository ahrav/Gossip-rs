//! Mapping bridge from unique blobs to pack/loose candidates.
//!
//! The bridge re-interns path bytes into a long-lived `ByteArena`, enforces
//! sorted unique input, and maps each blob to a pack offset via the MIDX
//! or emits it as a loose candidate. All emitted candidates reference the
//! bridge-owned arena, so callers must keep it alive for downstream use.
//!
//! # Algorithm
//! 1. Validate strict OID ordering (rejects duplicates or regressions).
//! 2. Re-intern the candidate path into the bridge arena.
//! 3. Classify the interned path and build candidate context with updated flags.
//! 4. Look up the blob OID in the MIDX using a streaming cursor.
//! 5. Emit a packed or loose candidate into the downstream sink.
//! 6. Track per-blob stats and reconcile them at `finish()`.
//!
//! # Invariants
//! - Input OIDs must be strictly increasing and duplicate-free.
//! - Path references in emitted candidates are valid only while the bridge's
//!   arena is alive.
//! - Mapping stats must reconcile at `finish()`.
//!
//! This stage is typically driven by the spill/unique-blob output, which
//! guarantees sorted OIDs.

use std::cmp::Ordering;

use crate::perf_stats;

use super::byte_arena::{ByteArena, ByteRef};
use super::errors::SpillError;
use super::midx::{MidxCursor, MidxView};
use super::midx_error::MidxError;
use super::object_id::OidBytes;
use super::pack_candidates::{LooseCandidate, PackCandidate, PackCandidateSink};
use super::path_policy::classify_path;
use super::tree_candidate::CandidateContext;
use super::unique_blob::{UniqueBlob, UniqueBlobSink};
use scanner_engine::perf_counters as perf;

/// Configuration for the mapping bridge.
///
/// Note: `max_*_candidates` are not enforced by `MappingBridge` itself. They
/// are intended to size or cap downstream sinks (for example
/// `CappedPackCandidateSink`) and to keep pipeline budgets consistent.
#[derive(Clone, Copy, Debug)]
pub struct MappingBridgeConfig {
    /// Maximum path arena capacity in bytes.
    ///
    /// Default: 64 MiB.
    pub path_arena_capacity: u32,
    /// Maximum packed candidates retained by the mapping sink.
    ///
    /// Default: 1,048,576 (1M).
    pub max_packed_candidates: u32,
    /// Maximum loose candidates retained by the mapping sink.
    ///
    /// Default: 1,048,576 (1M).
    pub max_loose_candidates: u32,
}

impl Default for MappingBridgeConfig {
    fn default() -> Self {
        Self {
            path_arena_capacity: 64 * 1024 * 1024,
            max_packed_candidates: 1_048_576,
            max_loose_candidates: 1_048_576,
        }
    }
}

/// Mapping statistics.
///
/// `unique_blobs_in` should equal `packed_matched + loose_unmatched` after
/// a successful `finish`.
///
/// Populated only when `perf-stats` is enabled in debug builds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MappingStats {
    /// Total unique blobs processed.
    pub unique_blobs_in: u64,
    /// Blobs found in the MIDX.
    pub packed_matched: u64,
    /// Blobs missing from the MIDX (loose fallback).
    pub loose_unmatched: u64,
}

/// Adapter that maps unique blobs to pack/loose candidates.
///
/// Paths are re-interned into the bridge's arena so downstream stages can
/// hold stable `ByteRef` values. The input stream must be strictly sorted
/// by OID and contain no duplicates.
///
/// # Guarantees
/// - Each successful `emit` call produces exactly one candidate: packed when
///   the MIDX lookup succeeds, loose otherwise.
/// - `finish()` validates that `unique_blobs_in == packed_matched + loose_unmatched`.
///
/// # Errors
/// - `SpillError::PathTooLong` if a path exceeds `ByteRef::MAX_LEN`.
/// - `SpillError::ArenaOverflow` if the bridge path arena fills up.
/// - `SpillError::MidxError` for MIDX lookup or ordering violations.
pub struct MappingBridge<'midx, S: PackCandidateSink> {
    midx: &'midx MidxView<'midx>,
    sink: S,
    path_arena: ByteArena,
    stats: MappingStats,
    last_oid: Option<OidBytes>,
    midx_cursor: MidxCursor,
}

impl<'midx, S: PackCandidateSink> MappingBridge<'midx, S> {
    /// Creates a new mapping bridge.
    ///
    /// The internal path arena uses `config.path_arena_capacity`.
    #[must_use]
    pub fn new(midx: &'midx MidxView<'midx>, sink: S, config: MappingBridgeConfig) -> Self {
        Self {
            midx,
            sink,
            path_arena: ByteArena::with_capacity(config.path_arena_capacity),
            stats: MappingStats::default(),
            last_oid: None,
            midx_cursor: MidxCursor::default(),
        }
    }

    /// Returns current mapping statistics.
    #[must_use]
    pub const fn stats(&self) -> MappingStats {
        self.stats
    }

    /// Returns a reference to the bridge's path arena.
    ///
    /// The arena must stay alive for as long as emitted candidates are used.
    #[must_use]
    pub fn path_arena(&self) -> &ByteArena {
        &self.path_arena
    }

    /// Finishes the bridge and returns stats, sink, and path arena.
    ///
    /// This does not call `sink.finish()`. Callers should invoke the sink
    /// finish via the `UniqueBlobSink` trait before consuming the bridge.
    ///
    /// The returned arena must stay alive as long as emitted candidates are
    /// used, because their `ByteRef`s point into it.
    ///
    /// # Errors
    /// Returns `SpillError::MidxError` if internal stats are inconsistent.
    pub fn finish(self) -> Result<(MappingStats, S, ByteArena), SpillError> {
        let total = self.stats.packed_matched + self.stats.loose_unmatched;
        if total != self.stats.unique_blobs_in {
            return Err(SpillError::from(MidxError::corrupt(
                "mapping stats mismatch",
            )));
        }
        Ok((self.stats, self.sink, self.path_arena))
    }

    /// Ensures strictly increasing OID order and rejects duplicates.
    ///
    /// This defends against spill bugs and protects downstream merge logic
    /// that assumes sorted candidates.
    fn ensure_sorted(&mut self, oid: OidBytes) -> Result<(), SpillError> {
        if let Some(last) = self.last_oid {
            match oid.cmp(&last) {
                Ordering::Less => return Err(SpillError::from(MidxError::InputNotSorted)),
                Ordering::Equal => return Err(SpillError::from(MidxError::DuplicateInputOid)),
                Ordering::Greater => {}
            }
        }
        self.last_oid = Some(oid);
        Ok(())
    }

    /// Re-interns a path from a source arena into the bridge arena.
    ///
    /// Empty paths are preserved as the zero `ByteRef` sentinel.
    /// This maintains stable path references across downstream stages.
    fn intern_path(&mut self, paths: &ByteArena, path_ref: ByteRef) -> Result<ByteRef, SpillError> {
        let path = paths.get(path_ref);
        if path.is_empty() {
            return Ok(ByteRef::new(0, 0));
        }
        if path.len() > ByteRef::MAX_LEN as usize {
            return Err(SpillError::PathTooLong {
                len: path.len(),
                max: ByteRef::MAX_LEN as usize,
            });
        }
        self.path_arena
            .intern(path)
            .ok_or(SpillError::ArenaOverflow)
    }
}

impl<S: PackCandidateSink> UniqueBlobSink for MappingBridge<'_, S> {
    fn emit(&mut self, blob: &UniqueBlob, paths: &ByteArena) -> Result<(), SpillError> {
        let (res, nanos) = perf::time(|| {
            self.ensure_sorted(blob.oid)?;

            let path_ref = self.intern_path(paths, blob.ctx.path_ref)?;
            // Classify using the interned bytes so we only do this once per unique blob.
            let path_bytes = self.path_arena.get(path_ref);
            let cand_flags = classify_path(path_bytes).bits();
            let ctx = CandidateContext {
                cand_flags,
                path_ref,
                ..blob.ctx
            };

            perf_stats::sat_add_u64(&mut self.stats.unique_blobs_in, 1);

            match self
                .midx
                .find_oid_sorted(&mut self.midx_cursor, &blob.oid)?
            {
                Some(idx) => {
                    let (pack_id, offset) = self.midx.offset_at(idx)?;
                    let candidate = PackCandidate {
                        oid: blob.oid,
                        ctx,
                        pack_id,
                        offset,
                    };
                    self.sink.emit_packed(&candidate)?;
                    perf_stats::sat_add_u64(&mut self.stats.packed_matched, 1);
                }
                None => {
                    let candidate = LooseCandidate { oid: blob.oid, ctx };
                    self.sink.emit_loose(&candidate)?;
                    perf_stats::sat_add_u64(&mut self.stats.loose_unmatched, 1);
                }
            }

            Ok(())
        });

        perf::record_mapping(nanos);
        res
    }

    fn finish(&mut self) -> Result<(), SpillError> {
        self.sink.finish()
    }
}
