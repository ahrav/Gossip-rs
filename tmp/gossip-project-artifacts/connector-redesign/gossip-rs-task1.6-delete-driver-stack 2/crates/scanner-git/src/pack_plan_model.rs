//! Pack plan model types.
//!
//! Pack plans group candidates by pack and describe which offsets must be
//! decoded (candidates plus pack-local bases), along with delta dependency
//! metadata for later execution strategies.
//!
//! Execution order is optional: it is present when the DFS scheduler
//! produces a decode order different from ascending offset order.
//!
//! # Invariants
//! - `need_offsets` is sorted and unique.
//! - `candidate_offsets` is sorted by offset (ties by candidate index).
//! - `exec_order` indices refer to `need_offsets`.
//! - `delta_deps` is sorted by offset (subset of `need_offsets`).
//! - `delta_dep_index` maps `need_offsets` index -> `delta_deps` index or NONE_U32.

use super::object_id::OidBytes;
use super::pack_candidates::PackCandidate;

/// Sentinel for missing `u32` indices.
pub const NONE_U32: u32 = u32::MAX;

/// Delta encoding kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeltaKind {
    /// OFS_DELTA (base offset within same pack).
    Ofs,
    /// REF_DELTA (base object ID reference).
    Ref,
}

/// Delta base location.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BaseLoc {
    /// Base stored at the given pack offset.
    Offset(u64),
    /// Base stored outside this pack (or unresolved).
    External { oid: OidBytes },
}

/// Delta dependency for a pack entry.
///
/// For REF deltas whose base is not in the same pack, `base` is external.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeltaDep {
    /// Offset of the delta entry.
    pub offset: u64,
    /// Delta encoding kind.
    pub kind: DeltaKind,
    /// Base location (internal offset or external OID).
    pub base: BaseLoc,
    /// Byte offset where this delta entry's zlib payload starts.
    ///
    /// Populated by `pack_plan` from parsed entry headers. Synthetic plans
    /// may leave this as `0`, in which case executors should fall back to
    /// parsing the header at execution time. Using `0` as a sentinel is
    /// safe because the pack header occupies bytes `0..12`, so no valid
    /// data payload can start at offset 0.
    pub data_start: u64,
    /// Declared uncompressed delta payload size from the pack entry header.
    ///
    /// Populated by `pack_plan` from parsed entry headers. Synthetic plans
    /// may leave this as `0`.
    pub delta_size: u64,
}

impl DeltaDep {
    /// Returns true when plan-time header metadata is available.
    #[inline]
    #[must_use]
    pub const fn has_header_meta(self) -> bool {
        self.data_start != 0
    }
}

/// Candidate index paired with its pack offset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CandidateAtOffset {
    /// Offset within the pack.
    pub offset: u64,
    /// Index into `PackPlan.candidates`.
    pub cand_idx: u32,
}

/// Pack plan summary statistics.
///
/// `candidate_span` is the span of unique candidate offsets (0 if empty).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PackPlanStats {
    /// Number of candidate entries in the plan.
    pub(crate) candidate_count: u32,
    /// Number of unique offsets that must be decoded.
    pub(crate) need_count: u32,
    /// Number of REF deltas whose base is outside the pack.
    pub(crate) external_bases: u32,
    /// Number of dependencies where base offset > dependent offset.
    pub(crate) forward_deps: u32,
    /// Span between first and last candidate offsets.
    pub(crate) candidate_span: u64,
    /// Number of indegree-0 nodes with dependents (delta tree roots).
    /// Only populated when both `perf-stats` feature and `debug_assertions` are active.
    pub(crate) delta_tree_roots: u32,
    /// Maximum depth of the dependency DAG.
    /// Only populated when both `perf-stats` feature and `debug_assertions` are active.
    pub(crate) delta_tree_max_depth: u32,
}

impl PackPlanStats {
    /// Returns a zeroed stats struct for empty plans.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            candidate_count: 0,
            need_count: 0,
            external_bases: 0,
            forward_deps: 0,
            candidate_span: 0,
            delta_tree_roots: 0,
            delta_tree_max_depth: 0,
        }
    }

    /// Number of candidate entries in the plan.
    #[inline]
    #[must_use]
    pub const fn candidate_count(&self) -> u32 {
        self.candidate_count
    }

    /// Number of unique offsets that must be decoded.
    #[inline]
    #[must_use]
    pub const fn need_count(&self) -> u32 {
        self.need_count
    }

    /// Number of REF deltas whose base is outside the pack.
    #[inline]
    #[must_use]
    pub const fn external_bases(&self) -> u32 {
        self.external_bases
    }

    /// Number of dependencies where base offset > dependent offset.
    #[inline]
    #[must_use]
    pub const fn forward_deps(&self) -> u32 {
        self.forward_deps
    }

    /// Span between first and last candidate offsets.
    #[inline]
    #[must_use]
    pub const fn candidate_span(&self) -> u64 {
        self.candidate_span
    }

    /// Number of indegree-0 nodes with dependents (delta tree roots).
    /// Only populated when `perf-stats` is enabled.
    #[inline]
    #[must_use]
    pub const fn delta_tree_roots(&self) -> u32 {
        self.delta_tree_roots
    }

    /// Maximum depth of the dependency DAG.
    /// Only populated when `perf-stats` is enabled.
    #[inline]
    #[must_use]
    pub const fn delta_tree_max_depth(&self) -> u32 {
        self.delta_tree_max_depth
    }
}

/// Pack plan for a single pack file.
///
/// The plan contains both the candidate list and the expanded set of
/// offsets required to decode them (including pack-local delta bases).
/// `exec_order` is present only when the DFS scheduler produces an order
/// different from the natural `[0, 1, ..., n-1]` sequence; without it
/// the executor uses ascending offset order with a merge cursor.
///
/// # Lookup indirection
///
/// `delta_deps` is a compact, sorted-by-offset array of dependency
/// descriptors. To look up the dependency for a given `need_offsets[i]`
/// in O(1), use `delta_dep_index[i]`: it yields the index into
/// `delta_deps`, or [`NONE_U32`] if the offset is not a delta.
///
/// This two-table design avoids a `HashMap` on the hot decode path while
/// keeping `delta_deps` dense for iteration during planning.
#[derive(Clone, Debug)]
pub struct PackPlan {
    /// Pack id (PNAM order).
    pub(crate) pack_id: u16,
    /// OID length for this repository (20 or 32).
    pub(crate) oid_len: u8,
    /// Maximum delta chain depth expanded in planning.
    pub(crate) max_delta_depth: u8,
    /// Pack candidates for this pack.
    pub(crate) candidates: Vec<PackCandidate>,
    /// Candidate offsets sorted by offset (ties by candidate index).
    pub(crate) candidate_offsets: Vec<CandidateAtOffset>,
    /// Offsets to decode (candidates + pack-local bases), sorted unique.
    pub(crate) need_offsets: Vec<u64>,
    /// Delta dependencies for offsets in `need_offsets`, sorted by offset.
    pub(crate) delta_deps: Vec<DeltaDep>,
    /// Dense index: `delta_dep_index[i]` is the `delta_deps` index for
    /// `need_offsets[i]`, or [`NONE_U32`] if the offset has no dependency.
    pub(crate) delta_dep_index: Vec<u32>,
    /// Optional execution order (indices into `need_offsets`).
    ///
    /// Present only when the DFS scheduler produces an order different
    /// from the natural `[0, 1, ..., n-1]` sequence. `None` means
    /// ascending offset order is correct.
    pub(crate) exec_order: Option<Vec<u32>>,
    /// Summary statistics for strategy selection.
    pub(crate) stats: PackPlanStats,
}

impl PackPlan {
    /// Pack id (PNAM order).
    #[inline]
    #[must_use]
    pub const fn pack_id(&self) -> u16 {
        self.pack_id
    }

    /// OID length for this repository (20 or 32).
    #[inline]
    #[must_use]
    pub const fn oid_len(&self) -> u8 {
        self.oid_len
    }

    /// Maximum delta chain depth expanded in planning.
    #[inline]
    #[must_use]
    pub const fn max_delta_depth(&self) -> u8 {
        self.max_delta_depth
    }

    /// Pack candidates for this pack.
    #[inline]
    #[must_use]
    pub fn candidates(&self) -> &[PackCandidate] {
        &self.candidates
    }

    /// Candidate offsets sorted by offset (ties by candidate index).
    #[inline]
    #[must_use]
    pub fn candidate_offsets(&self) -> &[CandidateAtOffset] {
        &self.candidate_offsets
    }

    /// Offsets to decode (candidates + pack-local bases), sorted unique.
    #[inline]
    #[must_use]
    pub fn need_offsets(&self) -> &[u64] {
        &self.need_offsets
    }

    /// Delta dependencies for offsets in `need_offsets`, sorted by offset.
    #[inline]
    #[must_use]
    pub fn delta_deps(&self) -> &[DeltaDep] {
        &self.delta_deps
    }

    /// Dense index: `delta_dep_index[i]` is the `delta_deps` index for
    /// `need_offsets[i]`, or [`NONE_U32`] if the offset has no dependency.
    #[inline]
    #[must_use]
    pub fn delta_dep_index(&self) -> &[u32] {
        &self.delta_dep_index
    }

    /// Optional execution order (indices into `need_offsets`).
    ///
    /// Present only when the DFS scheduler produces an order different
    /// from the natural `[0, 1, ..., n-1]` sequence. `None` means
    /// ascending offset order is correct.
    #[inline]
    #[must_use]
    pub fn exec_order(&self) -> Option<&[u32]> {
        self.exec_order.as_deref()
    }

    /// Summary statistics for strategy selection.
    #[inline]
    #[must_use]
    pub const fn stats(&self) -> &PackPlanStats {
        &self.stats
    }
}
