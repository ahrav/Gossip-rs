//! In-memory commit graph for use when file-based commit-graph is unavailable.
//!
//! This module provides `CommitGraphMem`, an in-memory commit graph built from
//! loaded commit objects. It implements the `CommitGraph` trait, enabling
//! transparent substitution when on-disk commit-graph files are missing.
//!
//! # Layout
//! Uses Struct-of-Arrays (SoA) for cache-friendly access:
//! - `commit_oids`: N * oid_len bytes (sorted by position)
//! - `root_trees`: N * oid_len bytes
//! - `timestamps`: N * u64
//! - `generations`: N * u32
//! - `parent_start`: N+1 * u32 (CSR-style prefix sums)
//! - `parents`: flattened parent positions
//! - `identity_ids`: optional N * `CommitIdentityIds` (16 bytes each)
//!
//! # Generation Numbers
//! Computed as `gen(commit) = 1 + max(gen(parent))` with roots having gen=1.
//! This matches Git's commit-graph generation semantics.
//! Parents outside the loaded set are treated as generation 0 and are
//! not stored in the parent list.
//! Generation assignment uses a single topological propagation pass
//! (`O(N+E)` over in-set commit edges).
//!
//! # Invalid Input
//! Cycles are not expected in valid Git history. If a cycle (or unresolved
//! parent chain) is detected during generation computation, remaining commits
//! are force-assigned generation 1 to keep the graph usable.
//!
//! # Deterministic Ordering
//! Commits are sorted by `(generation ASC, commit_oid ASC)` to assign
//! deterministic positions. This ensures stable traversal order.
//! Parent order is preserved from the loaded commit list when stored.

use std::collections::{HashMap, VecDeque};

use gix_commitgraph::Position;

use super::commit_loader::LoadedCommit;
use super::commit_walk::{CommitGraph, ParentScratch};
use super::errors::CommitPlanError;
use super::identity_intern::CommitIdentityIds;
use super::object_id::{ObjectFormat, OidBytes};

/// In-memory commit graph built from loaded commits.
///
/// Provides equivalent functionality to file-backed commit graphs for repos
/// without pre-built commit-graph files. All per-commit data uses Struct-of-Arrays
/// layout for cache-friendly sequential access during generation-ordered
/// traversal.
///
/// Parent edges use Compressed Sparse Row (CSR) encoding:
/// `parent_start[i]..parent_start[i+1]` indexes into the flat `parents`
/// array, avoiding one `Vec` allocation per commit.
///
/// When identity enrichment is enabled, per-commit identity IDs are stored
/// in a flat `Vec<CommitIdentityIds>` (16 bytes per commit) indexed by
/// position. The identity data survives the `(generation, oid)` sort
/// permutation applied during construction.
#[derive(Debug)]
pub struct CommitGraphMem {
    format: ObjectFormat,
    num_commits: u32,

    // Per-commit data (SoA layout, indexed by Position)
    commit_oids: Vec<u8>,  // N * oid_len bytes
    root_trees: Vec<u8>,   // N * oid_len bytes
    timestamps: Vec<u64>,  // N entries
    generations: Vec<u32>, // N entries

    // Parent storage (CSR: parent_start[i]..parent_start[i+1] into parents)
    parent_start: Vec<u32>, // N+1 entries (prefix sums)
    parents: Vec<u32>,      // flattened parent positions

    // Lookup table
    oid_to_pos: HashMap<OidBytes, u32>,

    // Optional per-commit identity IDs (when enrichment is enabled)
    identity_ids: Option<Vec<CommitIdentityIds>>,
}

impl CommitGraphMem {
    /// Builds an in-memory commit graph from loaded commits.
    ///
    /// Commits are sorted deterministically by `(generation, oid)` to assign
    /// stable positions. Generation numbers are computed from parent links.
    ///
    /// # Arguments
    /// * `commits` - Loaded commits from `load_commits_from_tips`
    /// * `format` - Object format (SHA-1 or SHA-256)
    ///
    /// # Errors
    /// Currently infallible; the error type is reserved for future validation.
    /// Parents that are missing from the loaded set are dropped and treated
    /// as external roots for generation computation.
    ///
    /// # Complexity
    /// `O(N+E)` to propagate generations over in-set parent edges, plus
    /// `O(N log N)` for deterministic `(generation, oid)` position sorting.
    pub fn build(
        commits: Vec<LoadedCommit>,
        format: ObjectFormat,
    ) -> Result<Self, CommitPlanError> {
        if commits.is_empty() {
            return Ok(Self::empty(format));
        }

        let oid_len = format.oid_len() as usize;
        let n = commits.len();

        // Build OID -> index mapping (for parent resolution)
        let mut oid_to_idx: HashMap<OidBytes, usize> = HashMap::with_capacity(n);
        for (idx, commit) in commits.iter().enumerate() {
            oid_to_idx.insert(commit.oid, idx);
        }

        // Build in-set edge topology: parent -> child adjacency and in-degree.
        // Parents outside our loaded set are treated as generation-0 external roots.
        let mut in_degree = vec![0u32; n];
        let mut child_counts = vec![0u32; n];
        let mut edge_count = 0usize;
        for (child_idx, commit) in commits.iter().enumerate() {
            for parent_oid in &commit.parents {
                if let Some(&parent_idx) = oid_to_idx.get(parent_oid) {
                    in_degree[child_idx] = in_degree[child_idx].saturating_add(1);
                    child_counts[parent_idx] = child_counts[parent_idx].saturating_add(1);
                    edge_count = edge_count.saturating_add(1);
                }
            }
        }

        // CSR-style child adjacency for cache-friendly O(N+E) propagation.
        let mut child_start = vec![0u32; n + 1];
        for idx in 0..n {
            child_start[idx + 1] = child_start[idx].saturating_add(child_counts[idx]);
        }
        let mut children = vec![0u32; edge_count];
        let mut child_cursor = child_start[..n].to_vec();
        for (child_idx, commit) in commits.iter().enumerate() {
            for parent_oid in &commit.parents {
                if let Some(&parent_idx) = oid_to_idx.get(parent_oid) {
                    let insert_at = child_cursor[parent_idx] as usize;
                    children[insert_at] = child_idx as u32;
                    child_cursor[parent_idx] = child_cursor[parent_idx].saturating_add(1);
                }
            }
        }

        // Kahn's algorithm for topological generation propagation:
        // Seed the ready queue with in-degree-zero nodes (roots or commits
        // whose parents are all outside the loaded set), then propagate
        // gen(node) = 1 + max(gen(parent)) through the child adjacency.
        let mut generations = vec![0u32; n];
        let mut max_parent_gen = vec![0u32; n];
        let mut ready = VecDeque::with_capacity(n);
        for (idx, &degree) in in_degree.iter().enumerate() {
            if degree == 0 {
                ready.push_back(idx);
            }
        }

        let mut resolved_count = 0usize;
        while let Some(idx) = ready.pop_front() {
            let gen = max_parent_gen[idx].saturating_add(1);
            generations[idx] = gen;
            resolved_count = resolved_count.saturating_add(1);

            let start = child_start[idx] as usize;
            let end = child_start[idx + 1] as usize;
            for &child in &children[start..end] {
                let child_idx = child as usize;
                max_parent_gen[child_idx] = max_parent_gen[child_idx].max(gen);
                debug_assert!(in_degree[child_idx] > 0);
                in_degree[child_idx] -= 1;
                if in_degree[child_idx] == 0 {
                    ready.push_back(child_idx);
                }
            }
        }

        // Force-resolve remaining commits (cycle or unresolved in-set parent
        // chain). Assigning gen=1 keeps the graph usable for traversal; the
        // (generation, oid) sort still produces a deterministic order, just
        // without meaningful generation semantics for these nodes.
        if resolved_count != n {
            for gen in &mut generations {
                if *gen == 0 {
                    *gen = 1;
                }
            }
        }

        // Sort commits by (generation, oid) for deterministic positions
        let mut sorted_indices: Vec<usize> = (0..n).collect();
        sorted_indices.sort_by(|&a, &b| match generations[a].cmp(&generations[b]) {
            std::cmp::Ordering::Equal => commits[a].oid.cmp(&commits[b].oid),
            ord => ord,
        });

        let mut idx_to_pos = vec![0u32; n];
        for (pos, &idx) in sorted_indices.iter().enumerate() {
            idx_to_pos[idx] = pos as u32;
        }

        let mut commit_oids = Vec::with_capacity(n * oid_len);
        let mut root_trees = Vec::with_capacity(n * oid_len);
        let mut timestamps = Vec::with_capacity(n);
        let mut final_generations = Vec::with_capacity(n);
        let mut parent_start = Vec::with_capacity(n + 1);
        let mut parents_flat = Vec::new();
        let mut oid_to_pos = HashMap::with_capacity(n);

        parent_start.push(0);

        for &idx in &sorted_indices {
            let commit = &commits[idx];
            let pos = idx_to_pos[idx];

            commit_oids.extend_from_slice(commit.oid.as_slice());
            root_trees.extend_from_slice(commit.tree_oid.as_slice());
            timestamps.push(commit.timestamp);
            final_generations.push(generations[idx]);
            oid_to_pos.insert(commit.oid, pos);

            for parent_oid in &commit.parents {
                if let Some(&parent_idx) = oid_to_idx.get(parent_oid) {
                    parents_flat.push(idx_to_pos[parent_idx]);
                }
                // Parents outside our set are dropped (they're unreachable)
            }
            parent_start.push(parents_flat.len() as u32);
        }

        Ok(Self {
            format,
            num_commits: n as u32,
            commit_oids,
            root_trees,
            timestamps,
            generations: final_generations,
            parent_start,
            parents: parents_flat,
            oid_to_pos,
            identity_ids: None,
        })
    }

    /// Builds an in-memory commit graph with per-commit identity data.
    ///
    /// This is the identity-aware counterpart to [`build`](Self::build).
    /// The `identity_ids` vector must be the same length as `commits` and
    /// aligned 1:1 — `identity_ids[i]` corresponds to `commits[i]`.
    ///
    /// The identity data is permuted to match the deterministic
    /// `(generation, oid)` sort order applied during graph construction.
    ///
    /// # Errors
    /// Returns [`CommitPlanError::IdentityLengthMismatch`] if
    /// `commits.len() != identity_ids.len()`.
    pub fn build_with_identities(
        commits: Vec<LoadedCommit>,
        identity_ids: Vec<CommitIdentityIds>,
        format: ObjectFormat,
    ) -> Result<Self, CommitPlanError> {
        if commits.len() != identity_ids.len() {
            return Err(CommitPlanError::IdentityLengthMismatch {
                commits: commits.len(),
                identity_ids: identity_ids.len(),
            });
        }

        // Capture original OIDs before build() consumes commits.
        let original_oids: Vec<OidBytes> = commits.iter().map(|c| c.oid).collect();
        let mut graph = Self::build(commits, format)?;

        // Empty graphs have no identity data to permute.
        if original_oids.is_empty() {
            return Ok(graph);
        }

        // Apply the same (generation, oid) permutation to identity data.
        let n = original_oids.len();
        let mut sorted_ids = vec![CommitIdentityIds::default(); n];
        for (orig_idx, oid) in original_oids.iter().enumerate() {
            if let Some(&pos) = graph.oid_to_pos.get(oid) {
                sorted_ids[pos as usize] = identity_ids[orig_idx];
            }
        }

        graph.identity_ids = Some(sorted_ids);
        Ok(graph)
    }

    /// Creates an empty commit graph (zero commits, valid CSR sentinel).
    fn empty(format: ObjectFormat) -> Self {
        Self {
            format,
            num_commits: 0,
            commit_oids: Vec::new(),
            root_trees: Vec::new(),
            timestamps: Vec::new(),
            generations: Vec::new(),
            parent_start: vec![0],
            parents: Vec::new(),
            oid_to_pos: HashMap::new(),
            identity_ids: None,
        }
    }

    /// Returns the root tree OID for the commit at `pos`.
    ///
    /// # Panics
    /// Panics if `pos` is out of range (`>= num_commits`).
    pub fn root_tree_oid(&self, pos: Position) -> OidBytes {
        let oid_len = self.format.oid_len() as usize;
        let start = pos.0 as usize * oid_len;
        OidBytes::from_slice(&self.root_trees[start..start + oid_len])
    }

    /// Returns the commit OID for the commit at `pos`.
    ///
    /// # Panics
    /// Panics if `pos` is out of range (`>= num_commits`).
    pub fn commit_oid(&self, pos: Position) -> OidBytes {
        let oid_len = self.format.oid_len() as usize;
        let start = pos.0 as usize * oid_len;
        OidBytes::from_slice(&self.commit_oids[start..start + oid_len])
    }

    /// Returns the committer timestamp for the commit at `pos`.
    ///
    /// # Panics
    /// Panics if `pos` is out of range (`>= num_commits`).
    #[inline]
    pub fn committer_timestamp(&self, pos: Position) -> u64 {
        self.timestamps[pos.0 as usize]
    }

    /// Returns `true` if this graph carries per-commit identity data.
    #[inline]
    pub fn has_identity_data(&self) -> bool {
        self.identity_ids.is_some()
    }

    /// Returns per-commit identity IDs for `pos`, if identity enrichment
    /// was enabled during graph construction.
    ///
    /// Returns `None` when the graph was built without identity data.
    #[inline]
    pub fn identity_ids(&self, pos: Position) -> Option<CommitIdentityIds> {
        self.identity_ids.as_ref().map(|ids| ids[pos.0 as usize])
    }
}

impl CommitGraph for CommitGraphMem {
    #[inline]
    fn num_commits(&self) -> u32 {
        self.num_commits
    }

    fn lookup(&self, oid: &OidBytes) -> Result<Option<Position>, CommitPlanError> {
        let expected = self.format.oid_len() as usize;
        let len = oid.len() as usize;
        if len != expected {
            return Err(CommitPlanError::InvalidOidLength { len, expected });
        }

        Ok(self.oid_to_pos.get(oid).map(|&pos| Position(pos)))
    }

    #[inline]
    fn generation(&self, pos: Position) -> u32 {
        self.generations[pos.0 as usize]
    }

    fn collect_parents(
        &self,
        pos: Position,
        max_parents: u32,
        scratch: &mut ParentScratch,
    ) -> Result<(), CommitPlanError> {
        scratch.clear();

        let idx = pos.0 as usize;
        let start = self.parent_start[idx] as usize;
        let end = self.parent_start[idx + 1] as usize;

        let parent_count = end - start;
        if parent_count > max_parents as usize {
            return Err(CommitPlanError::TooManyParents {
                count: parent_count,
                max: max_parents as usize,
            });
        }

        for &parent_pos in &self.parents[start..end] {
            scratch.push(Position(parent_pos), max_parents)?;
        }

        Ok(())
    }

    fn root_tree_oid(&self, pos: Position) -> Result<OidBytes, CommitPlanError> {
        Ok(CommitGraphMem::root_tree_oid(self, pos))
    }

    fn commit_oid(&self, pos: Position) -> Result<OidBytes, CommitPlanError> {
        Ok(CommitGraphMem::commit_oid(self, pos))
    }

    fn committer_timestamp(&self, pos: Position) -> u64 {
        CommitGraphMem::committer_timestamp(self, pos)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_commit(oid: [u8; 20], tree: [u8; 20], parents: &[[u8; 20]], ts: u64) -> LoadedCommit {
        LoadedCommit {
            oid: OidBytes::sha1(oid),
            tree_oid: OidBytes::sha1(tree),
            parents: parents.iter().map(|p| OidBytes::sha1(*p)).collect(),
            timestamp: ts,
        }
    }

    #[test]
    fn empty_graph() {
        let graph = CommitGraphMem::build(vec![], ObjectFormat::Sha1).unwrap();
        assert_eq!(graph.num_commits(), 0);
    }

    #[test]
    fn single_root_commit() {
        let commit = make_commit([1; 20], [2; 20], &[], 1000);
        let graph = CommitGraphMem::build(vec![commit], ObjectFormat::Sha1).unwrap();

        assert_eq!(graph.num_commits(), 1);

        let pos = graph.lookup(&OidBytes::sha1([1; 20])).unwrap().unwrap();
        assert_eq!(graph.generation(pos), 1);
        assert_eq!(graph.committer_timestamp(pos), 1000);
        assert_eq!(graph.commit_oid(pos), OidBytes::sha1([1; 20]));
        assert_eq!(graph.root_tree_oid(pos), OidBytes::sha1([2; 20]));
    }

    #[test]
    fn linear_chain() {
        // c3 -> c2 -> c1 (root)
        let c1 = make_commit([1; 20], [11; 20], &[], 1000);
        let c2 = make_commit([2; 20], [12; 20], &[[1; 20]], 2000);
        let c3 = make_commit([3; 20], [13; 20], &[[2; 20]], 3000);

        let graph = CommitGraphMem::build(vec![c3, c2, c1], ObjectFormat::Sha1).unwrap();

        assert_eq!(graph.num_commits(), 3);

        let pos1 = graph.lookup(&OidBytes::sha1([1; 20])).unwrap().unwrap();
        let pos2 = graph.lookup(&OidBytes::sha1([2; 20])).unwrap().unwrap();
        let pos3 = graph.lookup(&OidBytes::sha1([3; 20])).unwrap().unwrap();

        assert_eq!(graph.generation(pos1), 1);
        assert_eq!(graph.generation(pos2), 2);
        assert_eq!(graph.generation(pos3), 3);
    }

    #[test]
    fn merge_commit() {
        // c3 (merge) -> c1, c2 (both roots)
        let c1 = make_commit([1; 20], [11; 20], &[], 1000);
        let c2 = make_commit([2; 20], [12; 20], &[], 2000);
        let c3 = make_commit([3; 20], [13; 20], &[[1; 20], [2; 20]], 3000);

        let graph = CommitGraphMem::build(vec![c1, c2, c3], ObjectFormat::Sha1).unwrap();

        assert_eq!(graph.num_commits(), 3);

        let pos3 = graph.lookup(&OidBytes::sha1([3; 20])).unwrap().unwrap();
        // Generation should be 1 + max(gen(c1), gen(c2)) = 1 + max(1, 1) = 2
        assert_eq!(graph.generation(pos3), 2);

        // Check parents
        let mut scratch = ParentScratch::new();
        graph.collect_parents(pos3, 10, &mut scratch).unwrap();
        assert_eq!(scratch.as_slice().len(), 2);
    }

    #[test]
    fn lookup_missing_oid() {
        let c1 = make_commit([1; 20], [11; 20], &[], 1000);
        let graph = CommitGraphMem::build(vec![c1], ObjectFormat::Sha1).unwrap();

        let result = graph.lookup(&OidBytes::sha1([99; 20])).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn deterministic_positions() {
        // Build graph twice with same commits in different order
        let c1 = make_commit([1; 20], [11; 20], &[], 1000);
        let c2 = make_commit([2; 20], [12; 20], &[[1; 20]], 2000);
        let c3 = make_commit([3; 20], [13; 20], &[[2; 20]], 3000);

        let graph1 =
            CommitGraphMem::build(vec![c1.clone(), c2.clone(), c3.clone()], ObjectFormat::Sha1)
                .unwrap();
        let graph2 = CommitGraphMem::build(vec![c3, c1, c2], ObjectFormat::Sha1).unwrap();

        // Positions should be identical due to deterministic sorting
        let pos1_a = graph1.lookup(&OidBytes::sha1([1; 20])).unwrap().unwrap();
        let pos1_b = graph2.lookup(&OidBytes::sha1([1; 20])).unwrap().unwrap();
        assert_eq!(pos1_a, pos1_b);

        let pos2_a = graph1.lookup(&OidBytes::sha1([2; 20])).unwrap().unwrap();
        let pos2_b = graph2.lookup(&OidBytes::sha1([2; 20])).unwrap().unwrap();
        assert_eq!(pos2_a, pos2_b);
    }

    #[test]
    fn non_trivial_dag_generations_and_missing_parent_semantics() {
        // a(root)      b(root)      j(missing-parent only)
        //   |            |            |
        //   c            |            |
        //   | \          |            |
        //   d  \         |            |
        //    \  \        |            |
        //      \ e <-----+            |
        //       \ \                    |
        //        \ f                   |
        //         \|                   |
        //          g                   |
        //          | \                 |
        //          |  h (also has missing parent)
        //          | /
        //          i
        let missing_1 = [250; 20];
        let missing_2 = [251; 20];

        let a = make_commit([1; 20], [11; 20], &[], 1);
        let b = make_commit([2; 20], [12; 20], &[], 2);
        let c = make_commit([3; 20], [13; 20], &[[1; 20]], 3);
        let d = make_commit([4; 20], [14; 20], &[[1; 20]], 4);
        let e = make_commit([5; 20], [15; 20], &[[3; 20], [2; 20]], 5);
        let f = make_commit([6; 20], [16; 20], &[[4; 20], [5; 20]], 6);
        let g = make_commit([7; 20], [17; 20], &[[5; 20]], 7);
        let h = make_commit([8; 20], [18; 20], &[missing_1, [7; 20]], 8);
        let i = make_commit([9; 20], [19; 20], &[[6; 20], [8; 20]], 9);
        let j = make_commit([10; 20], [20; 20], &[missing_2], 10);

        let graph =
            CommitGraphMem::build(vec![h, d, i, b, g, f, j, c, e, a], ObjectFormat::Sha1).unwrap();

        let pos_a = graph.lookup(&OidBytes::sha1([1; 20])).unwrap().unwrap();
        let pos_b = graph.lookup(&OidBytes::sha1([2; 20])).unwrap().unwrap();
        let pos_c = graph.lookup(&OidBytes::sha1([3; 20])).unwrap().unwrap();
        let pos_d = graph.lookup(&OidBytes::sha1([4; 20])).unwrap().unwrap();
        let pos_e = graph.lookup(&OidBytes::sha1([5; 20])).unwrap().unwrap();
        let pos_f = graph.lookup(&OidBytes::sha1([6; 20])).unwrap().unwrap();
        let pos_g = graph.lookup(&OidBytes::sha1([7; 20])).unwrap().unwrap();
        let pos_h = graph.lookup(&OidBytes::sha1([8; 20])).unwrap().unwrap();
        let pos_i = graph.lookup(&OidBytes::sha1([9; 20])).unwrap().unwrap();
        let pos_j = graph.lookup(&OidBytes::sha1([10; 20])).unwrap().unwrap();

        assert_eq!(graph.generation(pos_a), 1);
        assert_eq!(graph.generation(pos_b), 1);
        assert_eq!(graph.generation(pos_j), 1);
        assert_eq!(graph.generation(pos_c), 2);
        assert_eq!(graph.generation(pos_d), 2);
        assert_eq!(graph.generation(pos_e), 3);
        assert_eq!(graph.generation(pos_f), 4);
        assert_eq!(graph.generation(pos_g), 4);
        assert_eq!(graph.generation(pos_h), 5);
        assert_eq!(graph.generation(pos_i), 6);

        // Missing parents are dropped from stored parent lists.
        let mut scratch = ParentScratch::new();
        graph.collect_parents(pos_h, 16, &mut scratch).unwrap();
        assert_eq!(scratch.as_slice(), &[pos_g]);

        graph.collect_parents(pos_j, 16, &mut scratch).unwrap();
        assert!(scratch.as_slice().is_empty());
    }

    #[test]
    fn deterministic_positions_on_non_trivial_dag() {
        let missing_1 = [250; 20];
        let missing_2 = [251; 20];

        let a = make_commit([1; 20], [11; 20], &[], 1);
        let b = make_commit([2; 20], [12; 20], &[], 2);
        let c = make_commit([3; 20], [13; 20], &[[1; 20]], 3);
        let d = make_commit([4; 20], [14; 20], &[[1; 20]], 4);
        let e = make_commit([5; 20], [15; 20], &[[3; 20], [2; 20]], 5);
        let f = make_commit([6; 20], [16; 20], &[[4; 20], [5; 20]], 6);
        let g = make_commit([7; 20], [17; 20], &[[5; 20]], 7);
        let h = make_commit([8; 20], [18; 20], &[missing_1, [7; 20]], 8);
        let i = make_commit([9; 20], [19; 20], &[[6; 20], [8; 20]], 9);
        let j = make_commit([10; 20], [20; 20], &[missing_2], 10);

        let graph1 = CommitGraphMem::build(
            vec![
                a.clone(),
                b.clone(),
                c.clone(),
                d.clone(),
                e.clone(),
                f.clone(),
                g.clone(),
                h.clone(),
                i.clone(),
                j.clone(),
            ],
            ObjectFormat::Sha1,
        )
        .unwrap();
        let graph2 =
            CommitGraphMem::build(vec![i, d, h, c, j, g, a, f, b, e], ObjectFormat::Sha1).unwrap();

        assert_eq!(graph1.num_commits(), graph2.num_commits());
        for pos_idx in 0..graph1.num_commits() {
            let pos = Position(pos_idx);
            assert_eq!(graph1.commit_oid(pos), graph2.commit_oid(pos));
            assert_eq!(graph1.generation(pos), graph2.generation(pos));
        }

        // Concrete ordering check: sorted by (generation, oid).
        let ordered_oids: Vec<OidBytes> = (0..graph1.num_commits())
            .map(|pos_idx| graph1.commit_oid(Position(pos_idx)))
            .collect();
        assert_eq!(
            ordered_oids,
            vec![
                OidBytes::sha1([1; 20]),
                OidBytes::sha1([2; 20]),
                OidBytes::sha1([10; 20]),
                OidBytes::sha1([3; 20]),
                OidBytes::sha1([4; 20]),
                OidBytes::sha1([5; 20]),
                OidBytes::sha1([6; 20]),
                OidBytes::sha1([7; 20]),
                OidBytes::sha1([8; 20]),
                OidBytes::sha1([9; 20]),
            ]
        );
    }

    #[test]
    fn cycle_falls_back_to_generation_one() {
        // Invalid cycle: a <-> b. Existing semantics force unresolved commits to gen=1.
        let a = make_commit([1; 20], [11; 20], &[[2; 20]], 1);
        let b = make_commit([2; 20], [12; 20], &[[1; 20]], 2);

        let graph = CommitGraphMem::build(vec![a, b], ObjectFormat::Sha1).unwrap();
        let pos_a = graph.lookup(&OidBytes::sha1([1; 20])).unwrap().unwrap();
        let pos_b = graph.lookup(&OidBytes::sha1([2; 20])).unwrap().unwrap();
        assert_eq!(graph.generation(pos_a), 1);
        assert_eq!(graph.generation(pos_b), 1);
    }

    #[test]
    fn memory_layout_efficient() {
        // Verify SoA layout is reasonably sized
        let size = std::mem::size_of::<CommitGraphMem>();
        // identity_ids adds Option<Vec<CommitIdentityIds>> (24+8 bytes)
        assert!(size < 350, "CommitGraphMem struct too large: {size}");
    }

    #[test]
    fn build_with_identities_empty_has_no_identity_data() {
        let graph =
            CommitGraphMem::build_with_identities(vec![], vec![], ObjectFormat::Sha1).unwrap();
        assert_eq!(graph.num_commits(), 0);
        assert!(
            !graph.has_identity_data(),
            "empty graph should not claim to have identity data"
        );
    }

    #[test]
    fn build_with_identities_mismatched_lengths_returns_error() {
        let c1 = make_commit([1; 20], [11; 20], &[], 1000);
        let result = CommitGraphMem::build_with_identities(
            vec![c1],
            vec![], // 1 commit but 0 identity IDs
            ObjectFormat::Sha1,
        );
        assert!(
            result.is_err(),
            "mismatched commits/identity_ids lengths should return Err"
        );
    }

    #[test]
    fn build_with_identities_preserves_permutation() {
        // c2 -> c1 (root). Build order: [c2, c1].
        // Deterministic sort: (gen=1, c1), (gen=2, c2) → positions [0, 1].
        let c1 = make_commit([1; 20], [11; 20], &[], 1000);
        let c2 = make_commit([2; 20], [12; 20], &[[1; 20]], 2000);

        let id_c1 = CommitIdentityIds {
            author_name: 10,
            author_email: 11,
            committer_name: 12,
            committer_email: 13,
        };
        let id_c2 = CommitIdentityIds {
            author_name: 20,
            author_email: 21,
            committer_name: 22,
            committer_email: 23,
        };

        // Input order: [c2, c1], identity order: [id_c2, id_c1].
        let graph = CommitGraphMem::build_with_identities(
            vec![c2, c1],
            vec![id_c2, id_c1],
            ObjectFormat::Sha1,
        )
        .unwrap();

        assert!(graph.has_identity_data());

        // After sort: pos 0 = c1 (gen=1), pos 1 = c2 (gen=2).
        let pos_c1 = graph.lookup(&OidBytes::sha1([1; 20])).unwrap().unwrap();
        let pos_c2 = graph.lookup(&OidBytes::sha1([2; 20])).unwrap().unwrap();

        assert_eq!(graph.identity_ids(pos_c1), Some(id_c1));
        assert_eq!(graph.identity_ids(pos_c2), Some(id_c2));
    }

    #[test]
    fn identity_ids_none_without_enrichment() {
        let c1 = make_commit([1; 20], [11; 20], &[], 1000);
        let graph = CommitGraphMem::build(vec![c1], ObjectFormat::Sha1).unwrap();
        assert!(!graph.has_identity_data());

        let pos = graph.lookup(&OidBytes::sha1([1; 20])).unwrap().unwrap();
        assert_eq!(graph.identity_ids(pos), None);
    }
}
