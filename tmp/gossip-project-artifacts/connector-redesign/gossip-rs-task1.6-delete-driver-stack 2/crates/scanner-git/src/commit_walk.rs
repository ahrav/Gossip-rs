//! Commit traversal and ordering for Git scanning.
//!
//! This module produces the set of commits that tree diffing must process.
//! It supports:
//! - **Introduced-by-commit mode**: `(watermark, tip]` traversal using the
//!   commit-graph for deterministic ordering.
//! - **Topological ordering**: post-process a scanned subgraph so ancestors
//!   are emitted before descendants (first-introduction semantics).
//!
//! # Range walk algorithm
//! The introduced-by walk mirrors `git rev-list <tip> ^<watermark>` using two
//! generation-ordered heaps: an interesting frontier (commits reachable from
//! `tip`) and an uninteresting frontier (commits reachable from `watermark`).
//! Before emitting the highest-generation interesting commit, the algorithm
//! advances the uninteresting heap down to that generation so any commit
//! reachable from the watermark is marked and excluded. This keeps the walk
//! deterministic while pruning with generation numbers.
//!
//! # Correctness contract
//! - Commit range semantics: `reachable(tip) - reachable(watermark)`.
//! - If watermark is missing or not an ancestor of tip, treat as full history.
//! - `visited_commit` bitset deduplicates **emission** across refs.
//! - Deterministic: identical repo state yields identical output.
//! - Parent iteration order must be deterministic across runs.
//!
//! # Memory model
//! - `VisitedCommitBitset`: 1 bit per commit.
//! - `RefScratch`: 1 byte per commit, cleared via touched list.
//! - Heap frontiers: bounded by `CommitWalkLimits::max_heap_entries`.
//! - Parent scratch: inline buffer for <=16 parents; heap spill for larger merges.

use std::cmp::Ordering;
use std::collections::BinaryHeap;

use gix_commitgraph::Position;

use super::commit_walk_limits::CommitWalkLimits;
use super::errors::CommitPlanError;
use super::object_id::OidBytes;
use super::repo_open::{RepoJobState, StartSetRef};

// =========================================================================
// Constants
// =========================================================================

/// Maximum parents stored inline per commit (fast path).
const MAX_PARENTS_INLINE: usize = 16;
/// Initial capacity hint for the DFS stack used in `is_ancestor`.
const ANCESTOR_DFS_STACK_CAPACITY: usize = 64;
/// Initial capacity hint for each BinaryHeap frontier.
const HEAP_INITIAL_CAPACITY: usize = 512;

// =========================================================================
// Output type
// =========================================================================

/// A planned commit to be processed by tree diffing.
///
/// - If `snapshot_root == true`, this commit should be diffed against the
///   empty tree (snapshot enumeration).
/// - Otherwise, diff against parent trees per merge diff mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlannedCommit {
    /// Position in the commit-graph.
    pub pos: Position,
    /// If true, diff against the empty tree (snapshot semantics).
    pub snapshot_root: bool,
}

// =========================================================================
// Commit-graph adapter
// =========================================================================

/// Commit-graph access required by traversal and ordering.
///
/// Implementations must provide deterministic parent iteration to keep
/// traversal output stable across runs.
pub trait CommitGraph {
    /// Total commits in the commit-graph.
    fn num_commits(&self) -> u32;
    /// Lookup a commit OID, returning its position if found.
    fn lookup(&self, oid: &OidBytes) -> Result<Option<Position>, CommitPlanError>;
    /// Returns the generation number for a commit.
    fn generation(&self, pos: Position) -> u32;
    /// Collects parent positions into `scratch`.
    ///
    /// Implementations must clear `scratch` before populating it. The
    /// resulting slice from `scratch.as_slice()` is valid until the next
    /// call that mutates the scratch.
    ///
    /// # Ordering
    /// Parent order must be deterministic. It is used for traversal order
    /// and therefore impacts output stability.
    fn collect_parents(
        &self,
        pos: Position,
        max_parents: u32,
        scratch: &mut ParentScratch,
    ) -> Result<(), CommitPlanError>;
    /// Returns the root tree OID for the commit at `pos`.
    fn root_tree_oid(&self, pos: Position) -> Result<OidBytes, CommitPlanError>;
    /// Returns the commit OID for the commit at `pos`.
    fn commit_oid(&self, pos: Position) -> Result<OidBytes, CommitPlanError>;
    /// Returns the committer timestamp (seconds since epoch) for the commit at `pos`.
    fn committer_timestamp(&self, pos: Position) -> u64;
}

// =========================================================================
// Parent collection scratch
// =========================================================================

/// Scratch buffer for collecting parent positions.
///
/// # Invariants
/// - When `spilled == false`, parents live in `inline[..inline_len]`.
/// - When `spilled == true`, parents live in `spill` and `inline_len` is ignored.
///
/// # Performance
/// - <=16 parents: no heap allocation.
/// - >16 parents: a single spill into `Vec` reused across calls.
#[derive(Debug)]
pub struct ParentScratch {
    inline: [Position; MAX_PARENTS_INLINE],
    inline_len: usize,
    spill: Vec<Position>,
    spilled: bool,
}

impl ParentScratch {
    /// Creates an empty scratch buffer.
    pub fn new() -> Self {
        Self {
            inline: [Position(0); MAX_PARENTS_INLINE],
            inline_len: 0,
            spill: Vec::new(),
            spilled: false,
        }
    }

    /// Clears the buffer for reuse.
    #[inline(always)]
    pub fn clear(&mut self) {
        self.inline_len = 0;
        self.spill.clear();
        self.spilled = false;
    }

    /// Appends a parent position, spilling to heap if needed.
    ///
    /// Returns `TooManyParents` if `max_parents` is exceeded.
    #[inline(always)]
    pub fn push(&mut self, pos: Position, max_parents: u32) -> Result<(), CommitPlanError> {
        if !self.spilled {
            if self.inline_len < MAX_PARENTS_INLINE {
                self.inline[self.inline_len] = pos;
                self.inline_len += 1;
            } else {
                self.spill.clear();
                self.spill
                    .extend_from_slice(&self.inline[..self.inline_len]);
                self.spill.push(pos);
                self.spilled = true;
            }
        } else {
            self.spill.push(pos);
        }

        if self.len() > max_parents as usize {
            return Err(CommitPlanError::TooManyParents {
                count: self.len(),
                max: max_parents as usize,
            });
        }

        Ok(())
    }

    /// Returns the collected parents as a slice.
    #[inline(always)]
    pub fn as_slice(&self) -> &[Position] {
        if self.spilled {
            self.spill.as_slice()
        } else {
            &self.inline[..self.inline_len]
        }
    }

    /// Returns the number of collected parents.
    #[inline(always)]
    pub fn len(&self) -> usize {
        if self.spilled {
            self.spill.len()
        } else {
            self.inline_len
        }
    }

    /// Returns true if no parents were collected.
    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for ParentScratch {
    fn default() -> Self {
        Self::new()
    }
}

// =========================================================================
// Visited-commit bitset (emission dedup across refs)
// =========================================================================

/// Bitset indexed by commit-graph `Position` for cross-ref emission dedup.
///
/// This is intentionally separate from per-ref traversal scratch: it records
/// what has already been *emitted* so we never schedule the same commit twice
/// when multiple refs overlap.
pub struct VisitedCommitBitset {
    words: Vec<u64>,
    capacity: u32,
}

impl VisitedCommitBitset {
    /// Creates a new bitset for `num_commits` positions, all initially unset.
    pub fn new(num_commits: u32) -> Self {
        let n = num_commits as usize;
        let word_count = n.div_ceil(64);
        Self {
            words: vec![0u64; word_count],
            capacity: num_commits,
        }
    }

    /// Tests whether the bit at `pos` is set.
    ///
    /// # Panics
    /// Panics (debug assertion) if `pos >= capacity`.
    #[inline(always)]
    pub fn test(&self, pos: Position) -> bool {
        debug_assert!(
            pos.0 < self.capacity,
            "bitset access out of range: {} >= {}",
            pos.0,
            self.capacity,
        );
        let i = pos.0 as usize;
        let word = i >> 6;
        let bit = i & 63;
        (self.words[word] >> bit) & 1 == 1
    }

    /// Tests and sets the bit at `pos`.
    ///
    /// Returns `true` if this call newly marked the bit (was previously unset).
    /// Returns `false` if the bit was already set.
    ///
    /// # Panics
    /// Panics (debug assertion) if `pos >= capacity`.
    #[inline(always)]
    pub fn test_and_set(&mut self, pos: Position) -> bool {
        debug_assert!(
            pos.0 < self.capacity,
            "bitset access out of range: {} >= {}",
            pos.0,
            self.capacity,
        );
        let i = pos.0 as usize;
        let word = i >> 6;
        let bit = i & 63;
        let mask = 1u64 << bit;
        let was_unset = (self.words[word] & mask) == 0;
        self.words[word] |= mask;
        was_unset
    }
}

// =========================================================================
// Per-ref traversal scratch (cleared via touched list)
// =========================================================================

/// Seen in the interesting (tip) walk.
const SEEN_I: u8 = 1 << 0;
/// Seen in the uninteresting (watermark) walk.
const SEEN_U: u8 = 1 << 1;
/// Known to be reachable from watermark and therefore excluded.
const MARK_U: u8 = 1 << 2;

/// Per-ref traversal scratch.
///
/// `state` stores a byte per commit with the flags above, and `touched` holds
/// the positions that transitioned from zero to non-zero. This lets us clear
/// only the touched entries between refs instead of zeroing `state` in O(N).
struct RefScratch {
    state: Vec<u8>,
    touched: Vec<u32>,
}

impl RefScratch {
    fn new(num_commits: u32) -> Self {
        Self {
            state: vec![0u8; num_commits as usize],
            touched: Vec::new(),
        }
    }

    /// Clears all touched positions to zero.
    #[inline(always)]
    fn clear(&mut self) {
        for &p in &self.touched {
            debug_assert!((p as usize) < self.state.len());
            self.state[p as usize] = 0;
        }
        self.touched.clear();
    }

    /// Sets a bit on the state byte for `pos`, recording `pos` in the touched list.
    #[inline(always)]
    fn set_bit(&mut self, pos: Position, bit: u8) {
        let idx = pos.0 as usize;
        debug_assert!(idx < self.state.len());
        let s = &mut self.state[idx];
        if *s == 0 {
            self.touched.push(pos.0);
        }
        *s |= bit;
    }

    /// Tests whether a specific bit is set for `pos`.
    #[inline(always)]
    fn has(&self, pos: Position, bit: u8) -> bool {
        debug_assert!((pos.0 as usize) < self.state.len());
        (self.state[pos.0 as usize] & bit) != 0
    }
}

// =========================================================================
// Ancestry check
// =========================================================================

/// Tests whether `ancestor` is reachable from `descendant` using a DFS
/// with generation-number pruning.
///
/// # Side effects
/// Clears and reuses `scratch` and `stack`. The caller must treat their
/// contents as undefined after return.
///
/// # Complexity
/// O(V + E) in the reachable subgraph, with early exits when generation
/// numbers prove the ancestor cannot be reached.
///
/// # Notes
/// This is a best-effort ancestry check using generation numbers for pruning;
/// incorrect generation data can cause missed ancestry detection.
fn is_ancestor<CG: CommitGraph>(
    cg: &CG,
    ancestor: Position,
    descendant: Position,
    scratch: &mut RefScratch,
    stack: &mut Vec<Position>,
    parents: &mut ParentScratch,
    max_parents: u32,
) -> Result<bool, CommitPlanError> {
    if ancestor == descendant {
        return Ok(true);
    }

    let anc_gen = cg.generation(ancestor);
    let desc_gen = cg.generation(descendant);
    if anc_gen > desc_gen {
        return Ok(false);
    }

    scratch.clear();
    stack.clear();
    stack.push(descendant);
    scratch.set_bit(descendant, SEEN_I);

    while let Some(cur) = stack.pop() {
        if cur == ancestor {
            return Ok(true);
        }

        let cur_gen = cg.generation(cur);
        if cur_gen < anc_gen {
            continue;
        }

        cg.collect_parents(cur, max_parents, parents)?;
        for &p in parents.as_slice() {
            if !scratch.has(p, SEEN_I) {
                scratch.set_bit(p, SEEN_I);
                stack.push(p);
            }
        }
    }

    Ok(false)
}

// =========================================================================
// Heap item for generation-ordered traversal
// =========================================================================

#[derive(Clone, Copy)]
struct HeapItem {
    gen: u32,
    pos: Position,
}

/// Max-heap by (generation, position). Higher generation = higher priority.
impl Ord for HeapItem {
    fn cmp(&self, other: &Self) -> Ordering {
        self.gen
            .cmp(&other.gen)
            .then_with(|| self.pos.0.cmp(&other.pos.0))
    }
}

impl PartialOrd for HeapItem {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for HeapItem {
    fn eq(&self, other: &Self) -> bool {
        self.gen == other.gen && self.pos == other.pos
    }
}

impl Eq for HeapItem {}

// =========================================================================
// Per-ref range walker state
// =========================================================================

/// Two-frontier range walk state: interesting (tip) and uninteresting (watermark).
struct RefRangeWalker {
    heap_interesting: BinaryHeap<HeapItem>,
    heap_uninteresting: BinaryHeap<HeapItem>,
}

impl RefRangeWalker {
    fn new() -> Self {
        Self {
            heap_interesting: BinaryHeap::with_capacity(HEAP_INITIAL_CAPACITY),
            heap_uninteresting: BinaryHeap::with_capacity(HEAP_INITIAL_CAPACITY),
        }
    }

    fn reset(&mut self) {
        self.heap_interesting.clear();
        self.heap_uninteresting.clear();
    }

    #[inline(always)]
    fn current_heap_size(&self) -> u32 {
        (self.heap_interesting.len() + self.heap_uninteresting.len()) as u32
    }
}

// =========================================================================
// Public API: Introduced-by-commit iterator
// =========================================================================

/// Iterator over commits in `(watermark, tip]` for all refs in the start set.
///
/// # Ordering
/// - Within a single ref: roughly reverse topological (highest generation first).
/// - Across refs: deterministic order of the start set.
///
/// # Deduplication
/// A commit is emitted at most once across all refs.
///
/// # Errors
/// The iterator yields `Err` on commit-graph corruption or limit violations.
/// Callers should stop consuming after the first error.
pub struct CommitPlanIter<'a, CG: CommitGraph> {
    cg: &'a CG,
    limits: CommitWalkLimits,

    refs: &'a [StartSetRef],
    ref_idx: usize,

    visited: VisitedCommitBitset,
    scratch: RefScratch,
    walker: RefRangeWalker,

    cur_tip: Option<Position>,
    cur_wm: Option<Position>,

    ancestor_stack: Vec<Position>,
    parent_scratch: ParentScratch,
}

impl<'a, CG: CommitGraph> CommitPlanIter<'a, CG> {
    /// Creates a new introduced-by-commit iterator.
    ///
    /// # Errors
    /// Returns `CommitGraphTooLarge` if the graph exceeds the configured limit.
    /// Additional errors (e.g., `TipNotFound`, `HeapLimitExceeded`) are yielded
    /// during iteration as `Err` items.
    pub fn new(
        repo: &'a RepoJobState,
        cg: &'a CG,
        limits: CommitWalkLimits,
    ) -> Result<Self, CommitPlanError> {
        Self::new_from_refs(&repo.start_set, cg, limits)
    }

    /// Creates a new iterator from an explicit ref slice.
    ///
    /// Refs are processed in the given order to keep output deterministic.
    pub fn new_from_refs(
        refs: &'a [StartSetRef],
        cg: &'a CG,
        limits: CommitWalkLimits,
    ) -> Result<Self, CommitPlanError> {
        limits.validate();

        let commits = cg.num_commits();
        if commits > limits.max_commits_in_graph {
            return Err(CommitPlanError::CommitGraphTooLarge {
                commits,
                max: limits.max_commits_in_graph,
            });
        }

        Ok(Self {
            cg,
            limits,
            refs,
            ref_idx: 0,
            visited: VisitedCommitBitset::new(commits),
            scratch: RefScratch::new(commits),
            walker: RefRangeWalker::new(),
            cur_tip: None,
            cur_wm: None,
            ancestor_stack: Vec::with_capacity(ANCESTOR_DFS_STACK_CAPACITY),
            parent_scratch: ParentScratch::new(),
        })
    }

    fn init_next_ref(&mut self) -> Result<bool, CommitPlanError> {
        if self.ref_idx >= self.refs.len() {
            return Ok(false);
        }

        self.walker.reset();
        self.scratch.clear();

        let r = &self.refs[self.ref_idx];
        self.ref_idx += 1;

        let tip_pos = self
            .cg
            .lookup(&r.tip)?
            .ok_or(CommitPlanError::TipNotFound)?;

        // Optional new-ref skip optimization.
        //
        // If this ref has no watermark and its tip is an ancestor of another
        // ref's watermark, then the entire history reachable from this tip
        // was already scanned in the prior run. Skip to avoid rescanning
        // old history. The check count is bounded to avoid O(refs^2).
        if r.watermark.is_none() {
            let mut checks = 0u32;
            for other in self.refs.iter() {
                if checks >= self.limits.max_new_ref_skip_checks {
                    break;
                }
                let Some(wm_oid) = other.watermark else {
                    continue;
                };
                let Some(wm_pos) = self.cg.lookup(&wm_oid)? else {
                    continue;
                };
                checks += 1;

                if is_ancestor(
                    self.cg,
                    tip_pos,
                    wm_pos,
                    &mut self.scratch,
                    &mut self.ancestor_stack,
                    &mut self.parent_scratch,
                    self.limits.max_parents_per_commit,
                )? {
                    self.cur_tip = None;
                    self.cur_wm = None;
                    return self.init_next_ref();
                }
            }
        }

        // Resolve and validate watermark. Non-ancestor watermarks are ignored,
        // which falls back to a full-history walk for that ref.
        let mut wm_pos_opt: Option<Position> = None;
        if let Some(wm_oid) = r.watermark {
            if let Some(wm_pos) = self.cg.lookup(&wm_oid)? {
                if is_ancestor(
                    self.cg,
                    wm_pos,
                    tip_pos,
                    &mut self.scratch,
                    &mut self.ancestor_stack,
                    &mut self.parent_scratch,
                    self.limits.max_parents_per_commit,
                )? {
                    wm_pos_opt = Some(wm_pos);
                }
            }
        }

        self.cur_tip = Some(tip_pos);
        self.cur_wm = wm_pos_opt;

        // Clear scratch before seeding the range walk.
        self.scratch.clear();

        let tip_gen = self.cg.generation(tip_pos);
        self.walker.heap_interesting.push(HeapItem {
            gen: tip_gen,
            pos: tip_pos,
        });
        self.scratch.set_bit(tip_pos, SEEN_I);

        if let Some(wm_pos) = wm_pos_opt {
            self.scratch.set_bit(wm_pos, MARK_U);
            let wm_gen = self.cg.generation(wm_pos);
            self.walker.heap_uninteresting.push(HeapItem {
                gen: wm_gen,
                pos: wm_pos,
            });
            self.scratch.set_bit(wm_pos, SEEN_U);
        }

        Ok(true)
    }

    /// Advances the uninteresting frontier down to `target_gen`.
    ///
    /// This marks every commit reachable from the watermark with generation
    /// `>= target_gen` as uninteresting, so the interesting frontier can
    /// safely emit any commit of that generation without missing exclusions.
    ///
    /// Heap growth is bounded by `limits.max_heap_entries`.
    fn advance_uninteresting(&mut self, target_gen: u32) -> Result<(), CommitPlanError> {
        while let Some(&top_u) = self.walker.heap_uninteresting.peek() {
            if top_u.gen < target_gen {
                break;
            }

            let u = self.walker.heap_uninteresting.pop().unwrap();
            let pos = u.pos;
            self.scratch.set_bit(pos, MARK_U);

            self.cg.collect_parents(
                pos,
                self.limits.max_parents_per_commit,
                &mut self.parent_scratch,
            )?;
            for &p in self.parent_scratch.as_slice() {
                if !self.scratch.has(p, SEEN_U) {
                    self.scratch.set_bit(p, SEEN_U);
                    let gen = self.cg.generation(p);
                    self.walker
                        .heap_uninteresting
                        .push(HeapItem { gen, pos: p });
                }
            }

            if self.walker.current_heap_size() > self.limits.max_heap_entries {
                return Err(CommitPlanError::HeapLimitExceeded {
                    entries: self.walker.current_heap_size(),
                    max: self.limits.max_heap_entries,
                });
            }
        }
        Ok(())
    }
}

impl<CG: CommitGraph> Iterator for CommitPlanIter<'_, CG> {
    type Item = Result<PlannedCommit, CommitPlanError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.cur_tip.is_none() {
                match self.init_next_ref() {
                    Ok(false) => return None,
                    Ok(true) => {}
                    Err(e) => return Some(Err(e)),
                }
            }

            while let Some(top_i) = self.walker.heap_interesting.peek().copied() {
                if let Err(e) = self.advance_uninteresting(top_i.gen) {
                    return Some(Err(e));
                }

                let it = self.walker.heap_interesting.pop().unwrap();
                let pos = it.pos;

                if self.scratch.has(pos, MARK_U) {
                    continue;
                }

                if let Err(e) = self.cg.collect_parents(
                    pos,
                    self.limits.max_parents_per_commit,
                    &mut self.parent_scratch,
                ) {
                    return Some(Err(e));
                }

                for &p in self.parent_scratch.as_slice() {
                    if !self.scratch.has(p, SEEN_I) {
                        self.scratch.set_bit(p, SEEN_I);
                        let gen = self.cg.generation(p);
                        self.walker.heap_interesting.push(HeapItem { gen, pos: p });
                    }
                }

                if self.walker.current_heap_size() > self.limits.max_heap_entries {
                    return Some(Err(CommitPlanError::HeapLimitExceeded {
                        entries: self.walker.current_heap_size(),
                        max: self.limits.max_heap_entries,
                    }));
                }

                // Only emit if this commit was not already emitted by a prior ref.
                if !self.visited.test_and_set(pos) {
                    continue;
                }

                return Some(Ok(PlannedCommit {
                    pos,
                    snapshot_root: false,
                }));
            }

            self.cur_tip = None;
            self.cur_wm = None;
        }
    }
}

// =========================================================================
// Public API: Introduced-by plan with topological ordering
// =========================================================================

/// Collects introduced-by commits and returns them in topological order.
///
/// This is the safe default for "first introduction" semantics: ancestors
/// are always emitted before descendants, even across merges.
///
/// # Errors
/// Returns `CommitPlanError` if:
/// - The commit-graph exceeds `limits.max_commits_in_graph`
/// - A commit-graph lookup fails (corruption)
/// - Heap size exceeds `limits.max_heap_entries`
/// - Topological sort detects a cycle
pub fn introduced_by_plan<CG: CommitGraph>(
    repo: &RepoJobState,
    cg: &CG,
    limits: CommitWalkLimits,
) -> Result<Vec<PlannedCommit>, CommitPlanError> {
    let iter = CommitPlanIter::new(repo, cg, limits)?;
    let mut positions = Vec::new();
    for item in iter {
        positions.push(item?.pos);
    }

    let ordered = topo_order_positions(cg, &positions, limits)?;
    Ok(ordered
        .into_iter()
        .map(|pos| PlannedCommit {
            pos,
            snapshot_root: false,
        })
        .collect())
}

// =========================================================================
// Public API: Topological ordering (first-introduction semantics)
// =========================================================================

/// Topologically orders the given commit positions within the scanned subgraph.
///
/// # Algorithm
/// Kahn's algorithm with dense arrays and a ring buffer queue. Ties are
/// broken by commit-graph position to keep output deterministic.
///
/// Only parent edges where both endpoints are in `positions` are considered.
/// The implementation uses arrays sized to the full commit-graph to avoid
/// hash maps and keep memory access predictable.
///
/// # Guarantees
/// - Parents appear before children (ancestor-first).
/// - Deterministic order for identical inputs.
///
/// # Errors
/// Returns `CommitPlanError` if:
/// - The commit-graph exceeds `limits.max_commits_in_graph`
/// - Parent collection fails for any commit
/// - A cycle is detected in the subgraph (`TopoSortCycle`)
pub fn topo_order_positions<CG: CommitGraph>(
    cg: &CG,
    positions: &[Position],
    limits: CommitWalkLimits,
) -> Result<Vec<Position>, CommitPlanError> {
    if positions.is_empty() {
        return Ok(Vec::new());
    }

    limits.validate();

    let num_commits = cg.num_commits();
    if num_commits > limits.max_commits_in_graph {
        return Err(CommitPlanError::CommitGraphTooLarge {
            commits: num_commits,
            max: limits.max_commits_in_graph,
        });
    }

    let mut positions_sorted = positions.to_vec();
    positions_sorted.sort_by_key(|p| p.0);
    positions_sorted.dedup_by_key(|p| p.0);

    let total = positions_sorted.len();

    let mut in_set = vec![false; num_commits as usize];
    for &pos in &positions_sorted {
        let idx = pos.0 as usize;
        debug_assert!(idx < in_set.len());
        in_set[idx] = true;
    }

    let mut in_degree = vec![0u32; num_commits as usize];
    let mut out_degree = vec![0u32; num_commits as usize];
    let mut parent_scratch = ParentScratch::new();
    let mut edge_count: u64 = 0;

    for &pos in &positions_sorted {
        cg.collect_parents(pos, limits.max_parents_per_commit, &mut parent_scratch)?;
        for &p in parent_scratch.as_slice() {
            let p_idx = p.0 as usize;
            if in_set[p_idx] {
                in_degree[pos.0 as usize] += 1;
                out_degree[p_idx] += 1;
                edge_count += 1;
            }
        }
    }

    let mut offsets = vec![0usize; num_commits as usize + 1];
    for i in 0..num_commits as usize {
        offsets[i + 1] = offsets[i] + out_degree[i] as usize;
    }

    let total_edges = offsets[num_commits as usize];
    debug_assert_eq!(total_edges as u64, edge_count);

    let mut children = vec![Position(0); total_edges];
    let mut cursor = offsets.clone();

    for &pos in &positions_sorted {
        cg.collect_parents(pos, limits.max_parents_per_commit, &mut parent_scratch)?;
        for &p in parent_scratch.as_slice() {
            let p_idx = p.0 as usize;
            if in_set[p_idx] {
                let slot = cursor[p_idx];
                children[slot] = pos;
                cursor[p_idx] += 1;
            }
        }
    }

    let mut queue = PosQueue::with_capacity(total);
    for &pos in &positions_sorted {
        if in_degree[pos.0 as usize] == 0 {
            queue.push(pos);
        }
    }

    let mut ordered = Vec::with_capacity(total);
    while let Some(pos) = queue.pop() {
        ordered.push(pos);
        let idx = pos.0 as usize;
        let start = offsets[idx];
        let end = offsets[idx + 1];
        for child in &children[start..end] {
            let c_idx = child.0 as usize;
            let deg = &mut in_degree[c_idx];
            debug_assert!(*deg > 0);
            *deg -= 1;
            if *deg == 0 {
                queue.push(*child);
            }
        }
    }

    if ordered.len() != total {
        let remaining = (total - ordered.len()) as u32;
        return Err(CommitPlanError::TopoSortCycle { remaining });
    }

    Ok(ordered)
}

// =========================================================================
// Ring buffer queue for Kahn ordering
// =========================================================================

/// Fixed-capacity ring buffer queue.
///
/// Capacity must be at least the number of positions that can be enqueued;
/// overflow is a logic error guarded by debug assertions.
struct PosQueue {
    buf: Vec<Position>,
    head: usize,
    len: usize,
}

impl PosQueue {
    fn with_capacity(capacity: usize) -> Self {
        debug_assert!(capacity > 0);
        Self {
            buf: vec![Position(0); capacity],
            head: 0,
            len: 0,
        }
    }

    #[inline(always)]
    fn push(&mut self, pos: Position) {
        debug_assert!(self.len < self.buf.len(), "PosQueue overflow");
        let tail = (self.head + self.len) % self.buf.len();
        self.buf[tail] = pos;
        self.len += 1;
    }

    #[inline(always)]
    fn pop(&mut self) -> Option<Position> {
        if self.len == 0 {
            return None;
        }
        let pos = self.buf[self.head];
        self.head = (self.head + 1) % self.buf.len();
        self.len -= 1;
        Some(pos)
    }
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bitset_initially_unset() {
        let bs = VisitedCommitBitset::new(128);
        for i in 0..128 {
            assert!(!bs.test(Position(i)));
        }
    }

    #[test]
    fn bitset_test_and_set_returns_newly_set() {
        let mut bs = VisitedCommitBitset::new(64);
        assert!(bs.test_and_set(Position(5)));
        assert!(bs.test(Position(5)));
        assert!(!bs.test_and_set(Position(5)));
        assert!(bs.test(Position(5)));
    }

    #[test]
    fn bitset_word_boundary() {
        let mut bs = VisitedCommitBitset::new(128);
        assert!(bs.test_and_set(Position(63)));
        assert!(bs.test_and_set(Position(64)));
        assert!(bs.test(Position(63)));
        assert!(bs.test(Position(64)));
        assert!(!bs.test(Position(62)));
        assert!(!bs.test(Position(65)));
    }

    #[test]
    fn scratch_clear_resets_touched() {
        let mut scratch = RefScratch::new(16);
        scratch.set_bit(Position(3), SEEN_I);
        scratch.set_bit(Position(7), MARK_U);
        scratch.set_bit(Position(3), SEEN_U);

        assert!(scratch.has(Position(3), SEEN_I));
        assert!(scratch.has(Position(3), SEEN_U));
        assert!(scratch.has(Position(7), MARK_U));

        scratch.clear();

        assert!(!scratch.has(Position(3), SEEN_I));
        assert!(!scratch.has(Position(3), SEEN_U));
        assert!(!scratch.has(Position(7), MARK_U));
        assert!(scratch.touched.is_empty());
    }

    #[test]
    fn scratch_set_bit_records_touched_once() {
        let mut scratch = RefScratch::new(8);
        scratch.set_bit(Position(2), SEEN_I);
        scratch.set_bit(Position(2), SEEN_U);
        scratch.set_bit(Position(5), SEEN_I);

        assert_eq!(scratch.touched.len(), 2);
        assert!(scratch.touched.contains(&2));
        assert!(scratch.touched.contains(&5));
    }

    #[test]
    fn heap_item_higher_gen_is_greater() {
        let a = HeapItem {
            gen: 10,
            pos: Position(1),
        };
        let b = HeapItem {
            gen: 20,
            pos: Position(1),
        };
        assert!(b > a);
    }

    #[test]
    fn heap_item_same_gen_higher_pos_is_greater() {
        let a = HeapItem {
            gen: 10,
            pos: Position(1),
        };
        let b = HeapItem {
            gen: 10,
            pos: Position(2),
        };
        assert!(b > a);
    }

    #[test]
    fn walker_current_heap_size_tracks_both_heaps() {
        let mut walker = RefRangeWalker::new();
        assert_eq!(walker.current_heap_size(), 0);

        walker.heap_interesting.push(HeapItem {
            gen: 1,
            pos: Position(0),
        });
        assert_eq!(walker.current_heap_size(), 1);

        walker.heap_uninteresting.push(HeapItem {
            gen: 2,
            pos: Position(1),
        });
        assert_eq!(walker.current_heap_size(), 2);

        walker.heap_interesting.pop();
        assert_eq!(walker.current_heap_size(), 1);

        walker.heap_uninteresting.pop();
        assert_eq!(walker.current_heap_size(), 0);
    }

    #[test]
    fn parent_scratch_inline_and_spill() {
        let mut scratch = ParentScratch::new();

        for i in 0..MAX_PARENTS_INLINE {
            scratch.push(Position(i as u32), 64).unwrap();
        }
        assert_eq!(scratch.len(), MAX_PARENTS_INLINE);
        assert!(!scratch.spilled);

        scratch.push(Position(99), 64).unwrap();
        assert!(scratch.spilled);
        assert_eq!(scratch.len(), MAX_PARENTS_INLINE + 1);
        assert_eq!(scratch.as_slice().len(), MAX_PARENTS_INLINE + 1);
    }

    #[test]
    fn parent_scratch_too_many() {
        let mut scratch = ParentScratch::new();
        for i in 0..4 {
            scratch.push(Position(i as u32), 4).unwrap();
        }
        let err = scratch.push(Position(4), 4).unwrap_err();
        assert!(matches!(err, CommitPlanError::TooManyParents { .. }));
    }
}
