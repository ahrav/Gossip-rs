//! Commit-graph indexing helpers for attribution-first ODB scans.
//!
//! This module provides a cache-friendly view over commit-graph data. It
//! precomputes commit OIDs, root tree OIDs, and committer timestamps into
//! flat arrays so hot-path lookups avoid per-commit graph access.
//!
//! # Invariants
//! - Arrays are sized to the commit-graph `num_commits()` and never grow.
//! - Positions are used as direct indices into the arrays.
//! - OID lengths always match the repo's object format.
//! - The index is immutable after construction; all reads are O(1).

use gix_commitgraph::Position;

use super::commit_graph_mem::CommitGraphMem;
use super::commit_walk::CommitGraph;
use super::errors::CommitPlanError;
use super::identity_intern::CommitIdentityIds;
use super::object_id::OidBytes;

/// Cache-friendly commit-graph index.
///
/// Owns copies of commit/tree OIDs so the backing commit-graph view can be
/// dropped after construction. Optionally carries per-commit identity IDs
/// when identity enrichment was enabled during graph construction.
#[derive(Debug)]
pub struct CommitGraphIndex {
    commit_oids: Vec<OidBytes>,
    root_trees: Vec<OidBytes>,
    committer_timestamps: Vec<u64>,
    identity_ids: Option<Vec<CommitIdentityIds>>,
}

impl CommitGraphIndex {
    /// Builds a commit-graph index from any `CommitGraph` implementation.
    ///
    /// Identity data is not populated — use [`build_from_mem`](Self::build_from_mem)
    /// when identity enrichment is enabled.
    ///
    /// # Costs
    /// - Time: O(N) over commit-graph entries
    /// - Memory: O(N × `size_of::<OidBytes>()`) for commit and tree OIDs, plus
    ///   O(N × 8) for timestamps
    ///
    /// # Errors
    /// Returns `CommitPlanError` if the underlying `CommitGraph` returns an
    /// error for any commit's OID or root tree OID lookup.
    pub fn build<CG: CommitGraph>(cg: &CG) -> Result<Self, CommitPlanError> {
        let count = cg.num_commits() as usize;
        let mut commit_oids = Vec::with_capacity(count);
        let mut root_trees = Vec::with_capacity(count);
        let mut committer_timestamps = Vec::with_capacity(count);

        for idx in 0..count {
            let pos = Position(idx as u32);
            commit_oids.push(cg.commit_oid(pos)?);
            root_trees.push(cg.root_tree_oid(pos)?);
            committer_timestamps.push(cg.committer_timestamp(pos));
        }

        Ok(Self {
            commit_oids,
            root_trees,
            committer_timestamps,
            identity_ids: None,
        })
    }

    /// Builds a commit-graph index from a [`CommitGraphMem`], carrying identity
    /// data when present.
    ///
    /// This is the identity-aware counterpart to [`build`](Self::build).
    /// When `cg` contains identity data (from
    /// [`CommitGraphMem::build_with_identities`]), the resulting index also
    /// carries per-commit identity IDs accessible via
    /// [`identity_ids`](Self::identity_ids).
    ///
    /// Unlike [`build`](Self::build), OID lookups here use `CommitGraphMem`'s
    /// inherent methods which index directly into the SoA arrays and cannot
    /// fail, so the `Result` is only retained for API symmetry.
    pub fn build_from_mem(cg: &CommitGraphMem) -> Result<Self, CommitPlanError> {
        let count = cg.num_commits() as usize;
        let mut commit_oids = Vec::with_capacity(count);
        let mut root_trees = Vec::with_capacity(count);
        let mut committer_timestamps = Vec::with_capacity(count);

        for idx in 0..count {
            let pos = Position(idx as u32);
            commit_oids.push(cg.commit_oid(pos));
            root_trees.push(cg.root_tree_oid(pos));
            committer_timestamps.push(cg.committer_timestamp(pos));
        }

        let identity_ids = if cg.has_identity_data() {
            let mut ids = Vec::with_capacity(count);
            for idx in 0..count {
                ids.push(cg.identity_ids(Position(idx as u32)).unwrap_or_default());
            }
            Some(ids)
        } else {
            None
        };

        Ok(Self {
            commit_oids,
            root_trees,
            committer_timestamps,
            identity_ids,
        })
    }

    /// Returns the number of commits indexed.
    #[inline]
    pub fn len(&self) -> usize {
        self.commit_oids.len()
    }

    /// Returns true if the index is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.commit_oids.is_empty()
    }

    /// Returns the commit OID for `pos`.
    ///
    /// # Panics
    /// Panics if `pos` is out of range (`>= len()`).
    #[inline]
    pub fn commit_oid(&self, pos: Position) -> OidBytes {
        self.commit_oids[pos.0 as usize]
    }

    /// Returns the root tree OID for `pos`.
    ///
    /// # Panics
    /// Panics if `pos` is out of range (`>= len()`).
    #[inline]
    pub fn root_tree_oid(&self, pos: Position) -> OidBytes {
        self.root_trees[pos.0 as usize]
    }

    /// Returns the committer timestamp for `pos` (seconds since epoch).
    ///
    /// # Panics
    /// Panics if `pos` is out of range (`>= len()`).
    #[inline]
    pub fn committer_timestamp(&self, pos: Position) -> u64 {
        self.committer_timestamps[pos.0 as usize]
    }

    /// Returns per-commit identity IDs for `pos`, if identity enrichment
    /// was enabled during graph construction.
    ///
    /// Returns `None` when the index was built without identity data.
    #[inline]
    pub fn identity_ids(&self, pos: Position) -> Option<CommitIdentityIds> {
        self.identity_ids.as_ref().map(|ids| ids[pos.0 as usize])
    }
}

#[cfg(test)]
impl CommitGraphIndex {
    /// Creates an empty index with no commits (test-only).
    #[must_use]
    pub fn empty() -> Self {
        Self {
            commit_oids: Vec::new(),
            root_trees: Vec::new(),
            committer_timestamps: Vec::new(),
            identity_ids: None,
        }
    }
}

// Tests live in `tests/integration/git_commit_walk.rs` to reuse git helpers.
