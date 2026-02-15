//! Boundary â‘¢ â€” Shard Algebra & Keyspace Contract: Chunk 5 (DRAFT)
//!
//! Keyspace coverage verification: the connector-facing contract for
//! answering "did we scan everything?" after a run settles.
//!
//! This file is additive to Boundary â‘  (chunks 1â€“5), Boundary â‘¡
//! (chunks 1â€“5), and Boundary â‘¢ (chunks 1â€“4).
//!
//! ## Problem Statement
//!
//! The scanner instructions Â§5.3 require:
//!
//! > The system must verify that all units of work were scanned (no drops).
//! > Maintain an expected work manifest. Compare against completed work set.
//!
//! In our shard model, splits create a tree of shards from each root.
//! A root shard may be split into children, which may be split further.
//! The "leaf" shards â€” those NOT in Split status â€” are the ones that
//! actually hold scanning progress. Coverage is verified by checking
//! that the leaf shards' key ranges tile the root shards' key ranges
//! without gaps.
//!
//! ```text
//!  Root manifest (expected):   [aaaaâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€zzzz)
//!
//!  After splits:               root(Split)
//!                             â•±                â•²
//!                    child_0(Done)      child_1(Split)
//!                    [aaaaâ”€â”€mmm)       â•±              â•²
//!                              child_1a(Done)   child_1b(Parked)
//!                              [mmmâ”€â”€â”€ttt)      [tttâ”€â”€â”€zzzz)
//!
//!  Leaf shards:   [aaaaâ”€â”€mmm) âˆª [mmmâ”€â”€ttt) âˆª [tttâ”€â”€zzzz)
//!  Expected:      [aaaaâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€zzzz)
//!
//!  Coverage: COMPLETE (but has failures: child_1b is Parked)
//! ```
//!
//! ## Design Decisions (locked)
//!
//! D3.20: Coverage verification operates on `ShardSummary` lists, NOT
//!        on full `ShardRecord` data. This is deliberate:
//!        - ShardSummary is the public listing API (B2 chunk 4).
//!        - Full records include op-logs and lease state irrelevant
//!          to coverage analysis.
//!        - Summaries are cheaper to fetch and cache.
//!
//!        The verification functions accept `&[ShardSummary]` and never
//!        call the coordinator. The caller is responsible for fetching
//!        shard listings via `list_shards` and passing them in.
//!
//!        Reference: Separation of mechanism and policy â€” the verifier
//!        is a pure function of the shard listing, not coupled to I/O.
//!
//! D3.21: Leaf shard identification uses status, NOT the lineage tree.
//!        A shard is a leaf iff `status != Split`. This is correct
//!        because:
//!        - Done shards: completed their range, are leaves.
//!        - Parked shards: stopped but still "own" their range, are leaves.
//!        - Active shards: in progress, are leaves (work not yet delegated).
//!        - Split shards: replaced by children, NOT leaves.
//!
//!        The lineage tree (parent/spawned) is used for diagnostic
//!        reporting but not for determining coverage â€” the status
//!        field is the authoritative indicator.
//!
//!        Reference: CockroachDB range report â€” range coverage is
//!        determined by the current set of non-merged ranges, not by
//!        the split/merge history.
//!
//! D3.22: Gap detection uses sorted interval merging, NOT set
//!        reconciliation (Eppstein et al., SIGCOMM 2011). Set
//!        reconciliation is designed for comparing two sets of
//!        arbitrary elements; our problem is comparing two sets of
//!        contiguous, half-open byte intervals. Sorted interval
//!        merging is O(N log N) and exact for this problem.
//!
//!        We reserve set reconciliation / anti-entropy for a future
//!        layer that compares scanned items (individual secrets) across
//!        replicas â€” that IS a set membership problem. For shard-level
//!        coverage, interval algebra is simpler and more precise.
//!
//!        Reference: Standard interval scheduling / sweep-line
//!        algorithms â€” Cormen et al., Introduction to Algorithms,
//!        Chapter 16 (greedy interval scheduling).
//!
//! D3.23: The verification result is a diagnostic value, not a
//!        pass/fail boolean. It reports:
//!        - The list of covered intervals (from leaf shards).
//!        - The list of gap intervals (uncovered ranges).
//!        - The list of overlap intervals (ranges covered by >1 leaf).
//!        - Aggregate status counts (done, parked, active leaves).
//!
//!        This supports both automated completeness checks ("is it
//!        done?") and human-readable diagnostics ("what's missing?").
//!
//! D3.24: Overlap detection is included for defensive verification.
//!        Overlaps should NEVER occur if the split algebra (chunk 4)
//!        and coordinator validation (B2 chunk 1) are correct. But
//!        detecting them catches bugs in the split path â€” the most
//!        safety-critical code path in the system.
//!
//!        Reference: Tiger Style â€” "assert at every boundary."

// Assumes all types from Boundaries â‘ , â‘¡, â‘¢ chunks 1â€“4 are in scope.

use core::fmt;

// ============================================================================
// Â§ Chunk 5: Keyspace Coverage Verification
// ============================================================================

// ---------------------------------------------------------------------------
// Â§5.1 LeafShard â€” a shard that owns its key range directly
// ---------------------------------------------------------------------------

/// A shard that directly owns its key range (not Split).
///
/// Leaf shards are the "current" view of the shard tree â€” they are the
/// shards that either completed scanning, are in progress, or are parked.
/// Split shards are excluded because their coverage is delegated to
/// their children.
///
/// ## Derivation
///
/// A ShardSummary with `status != Split` is a leaf shard.
///
/// ## Invariants
///
/// **Safety (non-split)**: A LeafShard never has `status == Split`.
/// This is enforced by `extract_leaf_shards`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeafShard {
    pub shard: ShardId,
    pub status: ShardStatus,
    pub park_reason: Option<ParkReason>,
    pub key_range_start: Box<[u8]>,
    pub key_range_end: Box<[u8]>,
    pub parent: Option<ShardId>,
}

impl LeafShard {
    /// Extract from a ShardSummary. Returns None for Split shards.
    pub fn from_summary(summary: &ShardSummary) -> Option<Self> {
        if summary.status == ShardStatus::Split {
            return None;
        }

        Some(Self {
            shard: summary.shard,
            status: summary.status,
            park_reason: summary.park_reason,
            key_range_start: summary.key_range_start.clone(),
            key_range_end: summary.key_range_end.clone(),
            parent: summary.parent,
        })
    }

    /// Returns true if this leaf completed successfully.
    #[inline]
    pub fn is_done(&self) -> bool {
        self.status == ShardStatus::Done
    }

    /// Returns true if this leaf is parked (failed).
    #[inline]
    pub fn is_parked(&self) -> bool {
        self.status == ShardStatus::Parked
    }

    /// Returns true if this leaf is still active (in progress).
    #[inline]
    pub fn is_active(&self) -> bool {
        self.status == ShardStatus::Active
    }
}

/// Extract all leaf shards from a shard listing.
///
/// Filters out Split shards and returns the remainder as `LeafShard`
/// values sorted by `key_range_start` (lexicographic, ascending).
///
/// ## Complexity
///
/// O(N log N) where N is the number of summaries (sort-dominated).
pub fn extract_leaf_shards(summaries: &[ShardSummary]) -> Vec<LeafShard> {
    let mut leaves: Vec<LeafShard> = summaries
        .iter()
        .filter_map(LeafShard::from_summary)
        .collect();

    leaves.sort_by(|a, b| a.key_range_start.cmp(&b.key_range_start));
    leaves
}

// ---------------------------------------------------------------------------
// Â§5.2 KeyInterval â€” half-open byte interval for coverage algebra
// ---------------------------------------------------------------------------

/// A half-open byte interval `[start, end)`.
///
/// The fundamental unit of the coverage algebra. Represents a contiguous
/// range of the keyspace. Empty intervals (`start == end`) are not
/// produced by this module â€” they are filtered out.
///
/// ## Ordering
///
/// Intervals are ordered by `start`, then by `end`. This supports the
/// sweep-line algorithm in `compute_coverage`.
///
/// ## Invariants
///
/// **Safety (non-empty)**: `start < end` (byte lexicographic).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct KeyInterval {
    pub start: Box<[u8]>,
    pub end: Box<[u8]>,
}

impl KeyInterval {
    /// Create a new interval. Returns None if `start >= end`.
    pub fn new(start: impl Into<Box<[u8]>>, end: impl Into<Box<[u8]>>) -> Option<Self> {
        let start = start.into();
        let end = end.into();
        if start >= end {
            None
        } else {
            Some(Self { start, end })
        }
    }

    /// Create a new interval, panicking if invalid.
    ///
    /// For test convenience only.
    #[cfg(test)]
    pub fn must(start: &[u8], end: &[u8]) -> Self {
        Self::new(start.to_vec(), end.to_vec())
            .unwrap_or_else(|| panic!("invalid interval: {:?}..{:?}", start, end))
    }

    /// The byte length of this interval's representation.
    /// NOT the number of keys contained â€” that depends on the key schema.
    #[inline]
    pub fn start_len(&self) -> usize {
        self.start.len()
    }

    /// Returns true if `key` falls within `[start, end)`.
    pub fn contains_key(&self, key: &[u8]) -> bool {
        key >= self.start.as_ref() && key < self.end.as_ref()
    }

    /// Returns true if this interval overlaps with `other`.
    ///
    /// Two half-open intervals `[a, b)` and `[c, d)` overlap iff
    /// `a < d && c < b`.
    pub fn overlaps(&self, other: &KeyInterval) -> bool {
        self.start < other.end && other.start < self.end
    }

    /// Returns true if this interval is immediately adjacent to `other`.
    /// `[a, b)` is adjacent to `[b, c)` (this.end == other.start).
    pub fn adjacent_to(&self, other: &KeyInterval) -> bool {
        self.end == other.start
    }

    /// Merge this interval with an overlapping or adjacent one.
    /// Returns None if the intervals are disjoint and non-adjacent.
    pub fn merge(&self, other: &KeyInterval) -> Option<Self> {
        if self.overlaps(other) || self.adjacent_to(other) || other.adjacent_to(self) {
            let merged_start = if self.start < other.start {
                self.start.clone()
            } else {
                other.start.clone()
            };
            let merged_end = if self.end > other.end {
                self.end.clone()
            } else {
                other.end.clone()
            };
            Some(Self {
                start: merged_start,
                end: merged_end,
            })
        } else {
            None
        }
    }
}

impl fmt::Display for KeyInterval {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Show as hex for readability.
        write!(f, "[")?;
        for b in self.start.iter().take(8) {
            write!(f, "{:02x}", b)?;
        }
        if self.start.len() > 8 {
            write!(f, "â€¦")?;
        }
        write!(f, ", ")?;
        for b in self.end.iter().take(8) {
            write!(f, "{:02x}", b)?;
        }
        if self.end.len() > 8 {
            write!(f, "â€¦")?;
        }
        write!(f, ")")
    }
}

// ---------------------------------------------------------------------------
// Â§5.3 merge_intervals â€” sweep-line interval union
// ---------------------------------------------------------------------------

/// Merge a sorted list of intervals into a minimal set of non-overlapping,
/// non-adjacent intervals.
///
/// This is the standard sweep-line interval merge:
/// 1. Sort by start (caller must do this, or use `merge_intervals_unsorted`).
/// 2. Walk left-to-right, extending the current interval when the next
///    overlaps or is adjacent, otherwise starting a new interval.
///
/// ## Complexity
///
/// O(N) for already-sorted input. O(N log N) with `merge_intervals_unsorted`.
///
/// ## Invariants
///
/// **Safety (coverage preservation)**: The union of the output intervals
/// equals the union of the input intervals. No points are added or removed.
///
/// **Safety (minimal output)**: No two output intervals overlap or are
/// adjacent. The output is the unique minimal representation.
///
/// Reference: Standard sweep-line algorithm â€” Cormen et al., Introduction
/// to Algorithms, Â§16.1 (greedy algorithms on intervals).
pub fn merge_intervals(sorted: &[KeyInterval]) -> Vec<KeyInterval> {
    if sorted.is_empty() {
        return Vec::new();
    }

    let mut merged: Vec<KeyInterval> = Vec::with_capacity(sorted.len());
    merged.push(sorted[0].clone());

    for interval in &sorted[1..] {
        let last = merged.last().unwrap();
        if let Some(combined) = last.merge(interval) {
            let idx = merged.len() - 1;
            merged[idx] = combined;
        } else {
            merged.push(interval.clone());
        }
    }

    merged
}

/// Merge unsorted intervals.
pub fn merge_intervals_unsorted(intervals: &[KeyInterval]) -> Vec<KeyInterval> {
    let mut sorted = intervals.to_vec();
    sorted.sort();
    merge_intervals(&sorted)
}

// ---------------------------------------------------------------------------
// Â§5.4 find_gaps â€” identify uncovered ranges
// ---------------------------------------------------------------------------

/// Find gaps between a set of covering intervals and an expected range.
///
/// Given:
/// - `expected`: the intervals that SHOULD be covered (from root shards).
/// - `actual`: the intervals that ARE covered (from leaf shards).
///
/// Returns the set of intervals in `expected` that are NOT in `actual`.
///
/// Both inputs should be pre-merged (non-overlapping, sorted). If not,
/// results may contain spurious gaps.
///
/// ## Algorithm
///
/// Sweep-line subtraction: walk both lists left-to-right, subtracting
/// actual coverage from expected coverage.
///
/// ## Complexity
///
/// O(E + A) where E = expected intervals, A = actual intervals.
///
/// ## Invariants
///
/// **Safety (gap correctness)**: Every point in a gap interval is:
/// (a) within some expected interval, AND
/// (b) NOT within any actual interval.
///
/// **Safety (no false gaps)**: No gap interval contains a point that
/// IS covered by an actual interval.
///
/// Reference: Computational geometry interval subtraction â€” de Berg
/// et al., Computational Geometry: Algorithms and Applications, Ch 10.
pub fn find_gaps(
    expected: &[KeyInterval],
    actual: &[KeyInterval],
) -> Vec<KeyInterval> {
    let mut gaps = Vec::new();
    let mut a_idx = 0; // index into actual

    for exp in expected {
        let mut cursor = exp.start.clone();

        while cursor < exp.end {
            // Skip actual intervals that end before our cursor.
            while a_idx < actual.len() && actual[a_idx].end <= cursor {
                a_idx += 1;
            }

            if a_idx >= actual.len() || actual[a_idx].start >= exp.end {
                // No more actual intervals cover [cursor, exp.end).
                // The rest is a gap.
                if let Some(gap) = KeyInterval::new(cursor.clone(), exp.end.clone()) {
                    gaps.push(gap);
                }
                break;
            }

            let actual_interval = &actual[a_idx];

            if actual_interval.start > cursor {
                // Gap from cursor to actual_interval.start.
                let gap_end = if actual_interval.start < exp.end {
                    actual_interval.start.clone()
                } else {
                    exp.end.clone()
                };
                if let Some(gap) = KeyInterval::new(cursor.clone(), gap_end) {
                    gaps.push(gap);
                }
            }

            // Advance cursor past this actual interval.
            if actual_interval.end < exp.end {
                cursor = actual_interval.end.clone();
                a_idx += 1;
            } else {
                // Actual interval covers the rest of expected.
                break;
            }
        }
    }

    gaps
}

// ---------------------------------------------------------------------------
// Â§5.5 find_overlaps â€” detect overlapping leaf shards (defensive)
// ---------------------------------------------------------------------------

/// Detect overlapping intervals in a sorted list.
///
/// Overlapping leaf shards indicate a bug in the split algebra or
/// coordinator validation. This function is a defensive check â€” it
/// should always return an empty vec in a correct system.
///
/// Returns pairs of overlapping intervals.
///
/// ## Complexity
///
/// O(N) for sorted input.
///
/// ## Invariants
///
/// **Safety (bug detection)**: If any two leaf shards overlap, this
/// function reports them. No overlaps are silently ignored.
pub fn find_overlaps(sorted_intervals: &[KeyInterval]) -> Vec<(KeyInterval, KeyInterval)> {
    let mut overlaps = Vec::new();

    for window in sorted_intervals.windows(2) {
        if window[0].overlaps(&window[1]) {
            overlaps.push((window[0].clone(), window[1].clone()));
        }
    }

    overlaps
}

// ---------------------------------------------------------------------------
// Â§5.6 CoverageReport â€” the diagnostic output
// ---------------------------------------------------------------------------

/// Leaf shard status breakdown in a coverage report.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LeafCounts {
    /// Number of leaf shards that completed (Done).
    pub done: u64,
    /// Number of leaf shards that are parked (failed).
    pub parked: u64,
    /// Number of leaf shards still active (in progress).
    pub active: u64,
}

impl LeafCounts {
    /// Total leaf shards.
    #[inline]
    pub fn total(&self) -> u64 {
        self.done + self.parked + self.active
    }
}

/// The result of keyspace coverage verification for a run.
///
/// Produced by `verify_coverage`. Contains enough information for both
/// automated checks ("is coverage complete?") and human-readable
/// diagnostics ("what ranges are missing?").
///
/// ## Usage
///
/// ```text
/// let summaries = backend.list_shards(now, tenant, run, ShardFilter::all())?;
/// let report = verify_coverage(&summaries, &root_shard_specs);
///
/// if report.is_complete() {
///     // All root ranges are fully covered by Done leaf shards.
/// } else if report.is_covered() {
///     // All ranges are covered but some leaves are Parked/Active.
/// } else {
///     // There are gaps â€” ranges with no covering shard.
///     for gap in &report.gaps {
///         log::warn!("uncovered range: {}", gap);
///     }
/// }
/// ```
///
/// ## Invariants
///
/// **Safety (gap correctness)**: `gaps` contains exactly the intervals
/// in `expected_ranges` not covered by any leaf shard.
///
/// **Safety (overlap detection)**: `overlaps` contains all pairs of
/// leaf shards with overlapping key ranges.
///
/// **Safety (leaf count consistency)**: `leaf_counts.total()` equals
/// the number of non-Split shards in the input listing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoverageReport {
    /// The expected coverage: merged intervals from root shard specs.
    /// This is the "ground truth" of what the run should scan.
    pub expected_ranges: Vec<KeyInterval>,

    /// The actual coverage: merged intervals from leaf shard ranges.
    pub actual_ranges: Vec<KeyInterval>,

    /// Uncovered ranges: intervals in expected but not in actual.
    /// Empty means full coverage (no missing work).
    pub gaps: Vec<KeyInterval>,

    /// Overlapping leaf shard ranges (should always be empty in a
    /// correct system). Non-empty indicates a split algebra bug.
    pub overlaps: Vec<(KeyInterval, KeyInterval)>,

    /// Breakdown of leaf shards by status.
    pub leaf_counts: LeafCounts,

    /// Split shards found in the listing (for diagnostics).
    /// These are the "interior nodes" of the shard tree.
    pub split_count: u64,
}

impl CoverageReport {
    /// Returns true if all expected ranges are covered by Done leaf shards
    /// and there are no active or parked leaves.
    ///
    /// This is the strongest completeness condition: the run is fully
    /// done with no failures and no in-progress work.
    pub fn is_complete(&self) -> bool {
        self.gaps.is_empty()
            && self.leaf_counts.parked == 0
            && self.leaf_counts.active == 0
            && self.leaf_counts.done > 0
            && self.overlaps.is_empty()
    }

    /// Returns true if all expected ranges are covered by leaf shards
    /// (regardless of their status).
    ///
    /// This means there are no gaps â€” every byte in the expected
    /// keyspace is owned by some leaf shard. But some of those shards
    /// may be Parked or Active.
    pub fn is_covered(&self) -> bool {
        self.gaps.is_empty() && self.overlaps.is_empty()
    }

    /// Returns true if there are gaps in coverage â€” ranges that no
    /// leaf shard owns.
    ///
    /// Gaps indicate a bug: shards were dropped without being replaced.
    /// This should never happen if the coordinator correctly validates
    /// split coverage (B2 INV-S11).
    pub fn has_gaps(&self) -> bool {
        !self.gaps.is_empty()
    }

    /// Returns true if overlapping leaf shards were detected.
    ///
    /// Overlaps indicate a bug in the split algebra. Split children
    /// should exactly partition their parent's range (B2 INV-S11).
    pub fn has_overlaps(&self) -> bool {
        !self.overlaps.is_empty()
    }

    /// Returns true if any leaf shard is parked (failed).
    pub fn has_failures(&self) -> bool {
        self.leaf_counts.parked > 0
    }

    /// Returns true if any leaf shard is still active.
    pub fn has_in_progress(&self) -> bool {
        self.leaf_counts.active > 0
    }
}

impl fmt::Display for CoverageReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CoverageReport {{ leaves: {} done / {} parked / {} active, \
             split: {}, gaps: {}, overlaps: {} }}",
            self.leaf_counts.done,
            self.leaf_counts.parked,
            self.leaf_counts.active,
            self.split_count,
            self.gaps.len(),
            self.overlaps.len(),
        )
    }
}

// ---------------------------------------------------------------------------
// Â§5.7 verify_coverage â€” the main entry point
// ---------------------------------------------------------------------------

/// Verify keyspace coverage for a completed (or settling) run.
///
/// ## Arguments
///
/// * `all_summaries` â€” Full shard listing for the run (root + all
///   children). Obtained via `backend.list_shards(... ShardFilter::all())`.
///
/// * `root_specs` â€” The original root shard specs from run creation.
///   These define the "expected" coverage. Typically obtained from
///   the `RunRecord.root_shards` IDs and looking up each shard's spec.
///   For convenience, this function also accepts root shard ranges
///   directly as `KeyInterval` values via `verify_coverage_with_expected`.
///
/// ## Algorithm
///
/// 1. Extract leaf shards (non-Split) from the listing.
/// 2. Build sorted interval lists for expected (root) and actual (leaf).
/// 3. Merge each list into minimal non-overlapping intervals.
/// 4. Compute gaps: expected \ actual.
/// 5. Detect overlaps in the (pre-merge) leaf intervals.
/// 6. Count leaf shards by status.
///
/// ## Complexity
///
/// O(N log N) where N = total shards (dominated by sorting).
///
/// ## Invariants
///
/// Inherits from Â§5.4 (gap correctness) and Â§5.5 (overlap detection).
///
/// Reference: Â§5.3 of distributed-secret-scanner-instructions â€” "Maintain
/// an expected work manifest. Compare against completed work set."
/// Eppstein et al., "What's the Difference?" (SIGCOMM 2011) â€” set
/// reconciliation concept; we use interval algebra (Â§D3.22) instead
/// of general set reconciliation since our units are contiguous ranges.
pub fn verify_coverage(
    all_summaries: &[ShardSummary],
    root_specs: &[ShardSpec],
) -> CoverageReport {
    // Build expected intervals from root specs.
    let expected: Vec<KeyInterval> = root_specs
        .iter()
        .filter_map(|spec| {
            KeyInterval::new(
                spec.key_range_start.clone(),
                spec.key_range_end.clone(),
            )
        })
        .collect();

    verify_coverage_with_expected(all_summaries, &expected)
}

/// Verify keyspace coverage with pre-built expected intervals.
///
/// This is the core implementation. `verify_coverage` delegates here
/// after converting root specs to intervals.
pub fn verify_coverage_with_expected(
    all_summaries: &[ShardSummary],
    expected_intervals: &[KeyInterval],
) -> CoverageReport {
    // 1. Extract and sort leaf shards.
    let leaves = extract_leaf_shards(all_summaries);

    // 2. Count split shards.
    let split_count = all_summaries
        .iter()
        .filter(|s| s.status == ShardStatus::Split)
        .count() as u64;

    // 3. Build leaf intervals (sorted by extract_leaf_shards).
    let leaf_intervals: Vec<KeyInterval> = leaves
        .iter()
        .filter_map(|leaf| {
            KeyInterval::new(
                leaf.key_range_start.clone(),
                leaf.key_range_end.clone(),
            )
        })
        .collect();

    // 4. Detect overlaps BEFORE merging (merging hides them).
    let overlaps = find_overlaps(&leaf_intervals);

    // 5. Merge both lists.
    let merged_expected = merge_intervals_unsorted(expected_intervals);
    let merged_actual = merge_intervals(&leaf_intervals); // already sorted

    // 6. Compute gaps.
    let gaps = find_gaps(&merged_expected, &merged_actual);

    // 7. Count leaves by status.
    let mut leaf_counts = LeafCounts::default();
    for leaf in &leaves {
        match leaf.status {
            ShardStatus::Done => leaf_counts.done += 1,
            ShardStatus::Parked => leaf_counts.parked += 1,
            ShardStatus::Active => leaf_counts.active += 1,
            ShardStatus::Split => {
                // Should never happen â€” extract_leaf_shards filters these.
                debug_assert!(false, "Split shard in leaf list");
            }
        }
    }

    CoverageReport {
        expected_ranges: merged_expected,
        actual_ranges: merged_actual,
        gaps,
        overlaps,
        leaf_counts,
        split_count,
    }
}

// ---------------------------------------------------------------------------
// Â§5.8 Targeted diagnostics â€” finding specific problem areas
// ---------------------------------------------------------------------------

/// Identify parked leaf shards and their key ranges.
///
/// Returns the parked leaves sorted by key_range_start. Useful for
/// targeted retry/unpark operations â€” the operator can see exactly
/// which ranges failed and decide whether to unpark or abort.
pub fn parked_ranges(all_summaries: &[ShardSummary]) -> Vec<LeafShard> {
    let leaves = extract_leaf_shards(all_summaries);
    leaves.into_iter().filter(|l| l.is_parked()).collect()
}

/// Identify active (in-progress) leaf shards.
///
/// Returns the active leaves sorted by key_range_start. Useful for
/// progress monitoring â€” shows which ranges are still being scanned.
pub fn active_ranges(all_summaries: &[ShardSummary]) -> Vec<LeafShard> {
    let leaves = extract_leaf_shards(all_summaries);
    leaves.into_iter().filter(|l| l.is_active()).collect()
}

/// Compute the fraction of the expected keyspace that has been
/// successfully scanned (Done leaf shards only).
///
/// Returns a value in `[0.0, 1.0]` representing byte-range coverage.
/// This is an approximation â€” it measures the fraction of the keyspace
/// width, not the number of items scanned. A range `[a, z)` that is
/// Done counts the same whether it contained 1 item or 1 million.
///
/// ## Limitations
///
/// - Byte-width is a proxy for actual work. Dense ranges appear the
///   same as sparse ranges.
/// - Unbounded ranges (empty start or end) are excluded from the
///   calculation (their width is undefined).
///
/// Returns `None` if no expected ranges have computable width.
pub fn done_coverage_fraction(
    all_summaries: &[ShardSummary],
    root_specs: &[ShardSpec],
) -> Option<f64> {
    let expected: Vec<KeyInterval> = root_specs
        .iter()
        .filter_map(|spec| {
            KeyInterval::new(
                spec.key_range_start.clone(),
                spec.key_range_end.clone(),
            )
        })
        .collect();
    let merged_expected = merge_intervals_unsorted(&expected);

    let leaves = extract_leaf_shards(all_summaries);
    let done_intervals: Vec<KeyInterval> = leaves
        .iter()
        .filter(|l| l.is_done())
        .filter_map(|l| {
            KeyInterval::new(l.key_range_start.clone(), l.key_range_end.clone())
        })
        .collect();
    let merged_done = merge_intervals_unsorted(&done_intervals);

    let total_width = interval_total_width(&merged_expected);
    let done_width = interval_covered_width(&merged_expected, &merged_done);

    if total_width == 0.0 {
        return None;
    }

    Some((done_width / total_width).min(1.0))
}

/// Estimate the total "width" of a set of intervals.
///
/// Width is computed as the sum of byte-level differences between
/// start and end. This is an approximation for variable-length keys.
///
/// For fixed-length keys of length L, this is exact.
/// For variable-length keys, longer intervals may appear narrower
/// than shorter ones if their byte representation is shorter.
fn interval_total_width(intervals: &[KeyInterval]) -> f64 {
    intervals.iter().map(|i| interval_width(i)).sum()
}

/// Estimate the width of the intersection of a set of expected
/// intervals with a set of actual intervals.
///
/// Used to compute what fraction of expected is covered by actual.
fn interval_covered_width(
    expected: &[KeyInterval],
    actual: &[KeyInterval],
) -> f64 {
    // Gaps = expected - actual. Covered = expected - gaps.
    let gaps = find_gaps(expected, actual);
    let total = interval_total_width(expected);
    let gap_width = interval_total_width(&gaps);
    (total - gap_width).max(0.0)
}

/// Estimate the byte-width of a single interval.
///
/// Treats the key bytes as a big-endian unsigned integer and computes
/// the numeric difference. For keys of different lengths, pads the
/// shorter one with zeros.
///
/// This is a heuristic â€” it's used for progress estimation, not for
/// correctness decisions.
fn interval_width(interval: &KeyInterval) -> f64 {
    let start = &interval.start;
    let end = &interval.end;
    let max_len = start.len().max(end.len()).min(8); // Cap at 8 bytes for f64 precision.

    let mut start_val: u64 = 0;
    let mut end_val: u64 = 0;

    for i in 0..max_len {
        let s = if i < start.len() { start[i] as u64 } else { 0 };
        let e = if i < end.len() { end[i] as u64 } else { 0 };
        start_val = (start_val << 8) | s;
        end_val = (end_val << 8) | e;
    }

    end_val.saturating_sub(start_val) as f64
}

// ---------------------------------------------------------------------------
// Â§5.9 Chunk 5 Invariant Catalog
// ---------------------------------------------------------------------------

//! ## Chunk 5 Invariant Additions
//!
//! These extend the B3 invariant catalog from chunks 3â€“4.
//!
//! ### Safety Invariants
//!
//! ```text
//! â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
//! â”‚ ID          â”‚ Statement                                              â”‚ Enforced By          â”‚ Verification                   â”‚
//! â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
//! â”‚ INV-B3-S23  â”‚ Leaf shard extraction: extract_leaf_shards returns     â”‚ extract_leaf_shards()â”‚ Unit test: listing with mixed  â”‚
//! â”‚             â”‚ exactly the non-Split shards from the input, sorted by â”‚                      â”‚ statuses â†’ only non-Split in   â”‚
//! â”‚             â”‚ key_range_start.                                       â”‚                      â”‚ output, sorted.                â”‚
//! â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
//! â”‚ INV-B3-S24  â”‚ Interval merge coverage preservation: the union of     â”‚ merge_intervals()    â”‚ Property test: âˆ€ point in any  â”‚
//! â”‚             â”‚ output intervals == the union of input intervals. No   â”‚                      â”‚ input interval, point is in     â”‚
//! â”‚             â”‚ points added or removed.                               â”‚                      â”‚ some output interval, and vice  â”‚
//! â”‚             â”‚                                                        â”‚                      â”‚ versa.                         â”‚
//! â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
//! â”‚ INV-B3-S25  â”‚ Interval merge minimality: no two output intervals     â”‚ merge_intervals()    â”‚ Unit test: output intervals areâ”‚
//! â”‚             â”‚ overlap or are adjacent.                               â”‚                      â”‚ pairwise non-overlapping and   â”‚
//! â”‚             â”‚                                                        â”‚                      â”‚ non-adjacent.                  â”‚
//! â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
//! â”‚ INV-B3-S26  â”‚ Gap correctness: every point in a gap interval is      â”‚ find_gaps()          â”‚ Property test: âˆ€ point in gap, â”‚
//! â”‚             â”‚ within expected AND NOT within actual.                 â”‚                      â”‚ point âˆˆ expected âˆ§ point âˆ‰     â”‚
//! â”‚             â”‚                                                        â”‚                      â”‚ actual.                        â”‚
//! â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
//! â”‚ INV-B3-S27  â”‚ Gap completeness: no point outside gaps is both in     â”‚ find_gaps()          â”‚ Property test: âˆ€ point âˆˆ       â”‚
//! â”‚             â”‚ expected and not in actual.                            â”‚                      â”‚ expected \ actual â†’ point âˆˆ    â”‚
//! â”‚             â”‚                                                        â”‚                      â”‚ some gap.                      â”‚
//! â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
//! â”‚ INV-B3-S28  â”‚ Overlap detection soundness: if two leaf shard ranges  â”‚ find_overlaps()      â”‚ Unit test: overlapping and     â”‚
//! â”‚             â”‚ overlap, find_overlaps reports them. No overlaps are   â”‚                      â”‚ non-overlapping interval pairs. â”‚
//! â”‚             â”‚ silently ignored.                                      â”‚                      â”‚                                â”‚
//! â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
//! â”‚ INV-B3-S29  â”‚ Correct split algebra â†’ no overlaps: if B2 INV-S11    â”‚ B2 validate_split_   â”‚ Integration test: run with     â”‚
//! â”‚             â”‚ holds for all splits, find_overlaps returns empty.     â”‚ coverage + B3 split  â”‚ splits â†’ verify overlaps       â”‚
//! â”‚             â”‚ Non-empty overlaps indicate a split algebra bug.       â”‚ planner              â”‚ empty.                         â”‚
//! â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
//! â”‚ INV-B3-S30  â”‚ Correct split algebra â†’ no gaps: if all leaves are    â”‚ B2 validate_split_   â”‚ Integration test: run where    â”‚
//! â”‚             â”‚ Done and B2 INV-S11 holds, find_gaps returns empty.   â”‚ coverage + B3 split  â”‚ all leaves Done â†’ verify gaps  â”‚
//! â”‚             â”‚                                                        â”‚ planner              â”‚ empty.                         â”‚
//! â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
//! â”‚ INV-B3-S31  â”‚ CoverageReport.is_complete() â†” run is fully done:     â”‚ verify_coverage()    â”‚ Unit test: complete, partial,  â”‚
//! â”‚             â”‚ is_complete() returns true iff gaps empty, no parked,  â”‚                      â”‚ and failed scenarios.          â”‚
//! â”‚             â”‚ no active, at least one Done leaf, no overlaps.        â”‚                      â”‚                                â”‚
//! â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
//! ```
//!
//! ### Liveness Invariants
//!
//! ```text
//! â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
//! â”‚ ID          â”‚ Statement                                              â”‚ Enforced By          â”‚ Verification                   â”‚
//! â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
//! â”‚ INV-B3-L04  â”‚ verify_coverage terminates: the function is O(N log N) â”‚ verify_coverage()    â”‚ By construction (bounded loops â”‚
//! â”‚             â”‚ and performs no I/O, no blocking, no recursion.        â”‚                      â”‚ over finite collections).      â”‚
//! â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
//! â”‚ INV-B3-L05  â”‚ Convergence: as all Active leaves â†’ Done, the coverageâ”‚ Shard lifecycle      â”‚ Simulation test: run all       â”‚
//! â”‚             â”‚ fraction monotonically approaches 1.0.                â”‚ + done_coverage_     â”‚ shards to completion â†’ fractionâ”‚
//! â”‚             â”‚                                                        â”‚ fraction()           â”‚ == 1.0.                        â”‚
//! â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
//! ```
//!
//! ### Cross-Boundary Dependencies
//!
//! - INV-B3-S29 depends on B2's INV-S11 (split coverage).
//! - INV-B3-S30 depends on B2's INV-S11 + INV-S09 (terminal irreversibility).
//! - INV-B3-S23 depends on B2's ShardStatus enum stability (D2.6).
//! - INV-B3-S31 depends on B2's RunProgress semantics (chunk 4).

// ============================================================================
// Â§ Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // â”€â”€ Test helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// Create a ShardSummary for testing.
    fn summary(
        id: u64,
        status: ShardStatus,
        start: &[u8],
        end: &[u8],
        parent: Option<u64>,
    ) -> ShardSummary {
        ShardSummary {
            shard: ShardId(id),
            status,
            park_reason: if status == ShardStatus::Parked {
                Some(ParkReason::TooManyErrors)
            } else {
                None
            },
            is_leased: status == ShardStatus::Active,
            acquire_count: 0,
            last_key: None,
            key_range_start: start.to_vec().into_boxed_slice(),
            key_range_end: end.to_vec().into_boxed_slice(),
            parent: parent.map(ShardId),
            spawned_count: 0,
        }
    }

    fn done(id: u64, start: &[u8], end: &[u8]) -> ShardSummary {
        summary(id, ShardStatus::Done, start, end, None)
    }

    fn split(id: u64, start: &[u8], end: &[u8]) -> ShardSummary {
        summary(id, ShardStatus::Split, start, end, None)
    }

    fn parked(id: u64, start: &[u8], end: &[u8]) -> ShardSummary {
        summary(id, ShardStatus::Parked, start, end, None)
    }

    fn active(id: u64, start: &[u8], end: &[u8]) -> ShardSummary {
        summary(id, ShardStatus::Active, start, end, None)
    }

    fn child_done(id: u64, start: &[u8], end: &[u8], parent: u64) -> ShardSummary {
        summary(id, ShardStatus::Done, start, end, Some(parent))
    }

    fn child_parked(id: u64, start: &[u8], end: &[u8], parent: u64) -> ShardSummary {
        summary(id, ShardStatus::Parked, start, end, Some(parent))
    }

    fn spec(start: &[u8], end: &[u8]) -> ShardSpec {
        ShardSpec::with_range(start.to_vec(), end.to_vec())
    }

    // â”€â”€ KeyInterval â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn key_interval_creation() {
        assert!(KeyInterval::new(b"a".to_vec(), b"z".to_vec()).is_some());
        assert!(KeyInterval::new(b"z".to_vec(), b"a".to_vec()).is_none());
        assert!(KeyInterval::new(b"a".to_vec(), b"a".to_vec()).is_none());
    }

    #[test]
    fn key_interval_contains() {
        let i = KeyInterval::must(b"b", b"y");
        assert!(!i.contains_key(b"a"));
        assert!(i.contains_key(b"b"));
        assert!(i.contains_key(b"m"));
        assert!(!i.contains_key(b"y")); // half-open
        assert!(!i.contains_key(b"z"));
    }

    #[test]
    fn key_interval_overlaps() {
        let a = KeyInterval::must(b"a", b"m");
        let b = KeyInterval::must(b"f", b"z");
        let c = KeyInterval::must(b"m", b"z");

        assert!(a.overlaps(&b));
        assert!(b.overlaps(&a));
        assert!(!a.overlaps(&c)); // [a, m) and [m, z) are adjacent, not overlapping
        assert!(!c.overlaps(&a));
    }

    #[test]
    fn key_interval_adjacent() {
        let a = KeyInterval::must(b"a", b"m");
        let b = KeyInterval::must(b"m", b"z");
        assert!(a.adjacent_to(&b));
        assert!(!b.adjacent_to(&a)); // b is after a, not before
    }

    #[test]
    fn key_interval_merge() {
        let a = KeyInterval::must(b"a", b"m");
        let b = KeyInterval::must(b"f", b"z");
        let merged = a.merge(&b).unwrap();
        assert_eq!(merged.start.as_ref(), b"a");
        assert_eq!(merged.end.as_ref(), b"z");
    }

    #[test]
    fn key_interval_merge_adjacent() {
        let a = KeyInterval::must(b"a", b"m");
        let b = KeyInterval::must(b"m", b"z");
        let merged = a.merge(&b).unwrap();
        assert_eq!(merged.start.as_ref(), b"a");
        assert_eq!(merged.end.as_ref(), b"z");
    }

    #[test]
    fn key_interval_merge_disjoint() {
        let a = KeyInterval::must(b"a", b"f");
        let b = KeyInterval::must(b"m", b"z");
        assert!(a.merge(&b).is_none());
    }

    // â”€â”€ merge_intervals â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn merge_intervals_empty() {
        assert!(merge_intervals(&[]).is_empty());
    }

    #[test]
    fn merge_intervals_single() {
        let intervals = vec![KeyInterval::must(b"a", b"z")];
        let merged = merge_intervals(&intervals);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0], intervals[0]);
    }

    #[test]
    fn merge_intervals_adjacent() {
        let intervals = vec![
            KeyInterval::must(b"a", b"m"),
            KeyInterval::must(b"m", b"z"),
        ];
        let merged = merge_intervals(&intervals);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].start.as_ref(), b"a");
        assert_eq!(merged[0].end.as_ref(), b"z");
    }

    #[test]
    fn merge_intervals_overlapping() {
        let intervals = vec![
            KeyInterval::must(b"a", b"m"),
            KeyInterval::must(b"f", b"z"),
        ];
        let merged = merge_intervals(&intervals);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].start.as_ref(), b"a");
        assert_eq!(merged[0].end.as_ref(), b"z");
    }

    #[test]
    fn merge_intervals_disjoint() {
        let intervals = vec![
            KeyInterval::must(b"a", b"f"),
            KeyInterval::must(b"m", b"z"),
        ];
        let merged = merge_intervals(&intervals);
        assert_eq!(merged.len(), 2);
    }

    #[test]
    fn merge_intervals_many_adjacent() {
        let intervals = vec![
            KeyInterval::must(b"a", b"d"),
            KeyInterval::must(b"d", b"g"),
            KeyInterval::must(b"g", b"k"),
            KeyInterval::must(b"k", b"z"),
        ];
        let merged = merge_intervals(&intervals);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].start.as_ref(), b"a");
        assert_eq!(merged[0].end.as_ref(), b"z");
    }

    // â”€â”€ find_gaps â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn find_gaps_no_gaps() {
        let expected = vec![KeyInterval::must(b"a", b"z")];
        let actual = vec![KeyInterval::must(b"a", b"z")];
        assert!(find_gaps(&expected, &actual).is_empty());
    }

    #[test]
    fn find_gaps_total_gap() {
        let expected = vec![KeyInterval::must(b"a", b"z")];
        let actual = vec![];
        let gaps = find_gaps(&expected, &actual);
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0].start.as_ref(), b"a");
        assert_eq!(gaps[0].end.as_ref(), b"z");
    }

    #[test]
    fn find_gaps_left_gap() {
        let expected = vec![KeyInterval::must(b"a", b"z")];
        let actual = vec![KeyInterval::must(b"m", b"z")];
        let gaps = find_gaps(&expected, &actual);
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0].start.as_ref(), b"a");
        assert_eq!(gaps[0].end.as_ref(), b"m");
    }

    #[test]
    fn find_gaps_right_gap() {
        let expected = vec![KeyInterval::must(b"a", b"z")];
        let actual = vec![KeyInterval::must(b"a", b"m")];
        let gaps = find_gaps(&expected, &actual);
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0].start.as_ref(), b"m");
        assert_eq!(gaps[0].end.as_ref(), b"z");
    }

    #[test]
    fn find_gaps_middle_gap() {
        let expected = vec![KeyInterval::must(b"a", b"z")];
        let actual = vec![
            KeyInterval::must(b"a", b"f"),
            KeyInterval::must(b"m", b"z"),
        ];
        let gaps = find_gaps(&expected, &actual);
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0].start.as_ref(), b"f");
        assert_eq!(gaps[0].end.as_ref(), b"m");
    }

    #[test]
    fn find_gaps_multiple_gaps() {
        let expected = vec![KeyInterval::must(b"a", b"z")];
        let actual = vec![
            KeyInterval::must(b"c", b"f"),
            KeyInterval::must(b"k", b"p"),
        ];
        let gaps = find_gaps(&expected, &actual);
        assert_eq!(gaps.len(), 3);
        assert_eq!(gaps[0].start.as_ref(), b"a");
        assert_eq!(gaps[0].end.as_ref(), b"c");
        assert_eq!(gaps[1].start.as_ref(), b"f");
        assert_eq!(gaps[1].end.as_ref(), b"k");
        assert_eq!(gaps[2].start.as_ref(), b"p");
        assert_eq!(gaps[2].end.as_ref(), b"z");
    }

    #[test]
    fn find_gaps_actual_exceeds_expected() {
        let expected = vec![KeyInterval::must(b"d", b"p")];
        let actual = vec![KeyInterval::must(b"a", b"z")];
        assert!(find_gaps(&expected, &actual).is_empty());
    }

    #[test]
    fn find_gaps_multiple_expected() {
        let expected = vec![
            KeyInterval::must(b"a", b"f"),
            KeyInterval::must(b"m", b"z"),
        ];
        let actual = vec![KeyInterval::must(b"a", b"f")];
        let gaps = find_gaps(&expected, &actual);
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0].start.as_ref(), b"m");
        assert_eq!(gaps[0].end.as_ref(), b"z");
    }

    // â”€â”€ find_overlaps â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn find_overlaps_none() {
        let intervals = vec![
            KeyInterval::must(b"a", b"m"),
            KeyInterval::must(b"m", b"z"),
        ];
        assert!(find_overlaps(&intervals).is_empty());
    }

    #[test]
    fn find_overlaps_detected() {
        let intervals = vec![
            KeyInterval::must(b"a", b"n"),
            KeyInterval::must(b"m", b"z"),
        ];
        let overlaps = find_overlaps(&intervals);
        assert_eq!(overlaps.len(), 1);
    }

    // â”€â”€ extract_leaf_shards â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn extract_leaf_shards_filters_split() {
        let summaries = vec![
            done(0, b"a", b"m"),
            split(1, b"a", b"z"),
            parked(2, b"m", b"z"),
        ];
        let leaves = extract_leaf_shards(&summaries);
        assert_eq!(leaves.len(), 2);
        assert!(leaves.iter().all(|l| l.status != ShardStatus::Split));
    }

    #[test]
    fn extract_leaf_shards_sorted_by_start() {
        let summaries = vec![
            done(0, b"m", b"z"),
            done(1, b"a", b"m"),
        ];
        let leaves = extract_leaf_shards(&summaries);
        assert!(leaves[0].key_range_start.as_ref() < leaves[1].key_range_start.as_ref());
    }

    // â”€â”€ verify_coverage: complete run â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn verify_coverage_single_root_done() {
        let summaries = vec![done(0, b"a", b"z")];
        let roots = vec![spec(b"a", b"z")];
        let report = verify_coverage(&summaries, &roots);

        assert!(report.is_complete());
        assert!(report.is_covered());
        assert!(!report.has_gaps());
        assert!(!report.has_overlaps());
        assert_eq!(report.leaf_counts.done, 1);
        assert_eq!(report.split_count, 0);
    }

    #[test]
    fn verify_coverage_split_children_done() {
        // Root split into two children, both done.
        let summaries = vec![
            split(0, b"a", b"z"),
            child_done(100, b"a", b"m", 0),
            child_done(101, b"m", b"z", 0),
        ];
        let roots = vec![spec(b"a", b"z")];
        let report = verify_coverage(&summaries, &roots);

        assert!(report.is_complete());
        assert_eq!(report.leaf_counts.done, 2);
        assert_eq!(report.split_count, 1);
    }

    #[test]
    fn verify_coverage_deep_tree_all_done() {
        // Root â†’ 2 children, one child splits again.
        let summaries = vec![
            split(0, b"a", b"z"),
            child_done(100, b"a", b"m", 0),
            summary(101, ShardStatus::Split, b"m", b"z", Some(0)),
            summary(200, ShardStatus::Done, b"m", b"t", Some(101)),
            summary(201, ShardStatus::Done, b"t", b"z", Some(101)),
        ];
        let roots = vec![spec(b"a", b"z")];
        let report = verify_coverage(&summaries, &roots);

        assert!(report.is_complete());
        assert_eq!(report.leaf_counts.done, 3);
        assert_eq!(report.split_count, 2);
    }

    // â”€â”€ verify_coverage: partial completion â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn verify_coverage_one_child_parked() {
        let summaries = vec![
            split(0, b"a", b"z"),
            child_done(100, b"a", b"m", 0),
            child_parked(101, b"m", b"z", 0),
        ];
        let roots = vec![spec(b"a", b"z")];
        let report = verify_coverage(&summaries, &roots);

        assert!(!report.is_complete()); // Has failures.
        assert!(report.is_covered());   // No gaps though.
        assert!(!report.has_gaps());
        assert!(report.has_failures());
        assert_eq!(report.leaf_counts.done, 1);
        assert_eq!(report.leaf_counts.parked, 1);
    }

    #[test]
    fn verify_coverage_active_leaves() {
        let summaries = vec![
            active(0, b"a", b"m"),
            active(1, b"m", b"z"),
        ];
        let roots = vec![spec(b"a", b"z")];
        let report = verify_coverage(&summaries, &roots);

        assert!(!report.is_complete());
        assert!(report.is_covered());
        assert!(report.has_in_progress());
    }

    // â”€â”€ verify_coverage: gaps â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn verify_coverage_with_gap() {
        // Two roots, only first covered.
        let summaries = vec![done(0, b"a", b"m")];
        let roots = vec![spec(b"a", b"m"), spec(b"p", b"z")];
        let report = verify_coverage(&summaries, &roots);

        assert!(!report.is_covered());
        assert!(report.has_gaps());
        assert_eq!(report.gaps.len(), 1);
        assert_eq!(report.gaps[0].start.as_ref(), b"p");
        assert_eq!(report.gaps[0].end.as_ref(), b"z");
    }

    // â”€â”€ verify_coverage: overlaps (bug detection) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn verify_coverage_detects_overlap() {
        // Two done leaves that overlap â€” should never happen in practice.
        let summaries = vec![
            done(0, b"a", b"n"),
            done(1, b"m", b"z"),
        ];
        let roots = vec![spec(b"a", b"z")];
        let report = verify_coverage(&summaries, &roots);

        assert!(report.has_overlaps());
        assert_eq!(report.overlaps.len(), 1);
        assert!(!report.is_complete()); // Overlaps prevent is_complete.
    }

    // â”€â”€ verify_coverage: multiple roots â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn verify_coverage_multiple_roots_all_done() {
        let summaries = vec![
            done(0, b"a", b"m"),
            done(1, b"p", b"z"),
        ];
        let roots = vec![spec(b"a", b"m"), spec(b"p", b"z")];
        let report = verify_coverage(&summaries, &roots);

        assert!(report.is_complete());
        assert_eq!(report.leaf_counts.done, 2);
    }

    // â”€â”€ verify_coverage: empty run â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn verify_coverage_empty_run() {
        let summaries: Vec<ShardSummary> = vec![];
        let roots: Vec<ShardSpec> = vec![];
        let report = verify_coverage(&summaries, &roots);

        // No expected work, no actual work â†’ vacuously "covered" but
        // not "complete" (no Done leaves).
        assert!(report.gaps.is_empty());
        assert!(!report.is_complete()); // leaf_counts.done == 0
    }

    // â”€â”€ diagnostic helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn parked_ranges_basic() {
        let summaries = vec![
            done(0, b"a", b"m"),
            parked(1, b"m", b"t"),
            done(2, b"t", b"z"),
        ];
        let parked = parked_ranges(&summaries);
        assert_eq!(parked.len(), 1);
        assert_eq!(parked[0].shard, ShardId(1));
    }

    #[test]
    fn active_ranges_basic() {
        let summaries = vec![
            done(0, b"a", b"m"),
            active(1, b"m", b"z"),
        ];
        let active = active_ranges(&summaries);
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].shard, ShardId(1));
    }

    // â”€â”€ done_coverage_fraction â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn coverage_fraction_all_done() {
        let summaries = vec![done(0, b"\x00", b"\xff")];
        let roots = vec![spec(b"\x00", b"\xff")];
        let frac = done_coverage_fraction(&summaries, &roots).unwrap();
        assert!((frac - 1.0).abs() < 0.001);
    }

    #[test]
    fn coverage_fraction_half_done() {
        // Roughly half the range done.
        let summaries = vec![
            done(0, b"\x00", b"\x80"),
            active(1, b"\x80", b"\xff"),
        ];
        let roots = vec![spec(b"\x00", b"\xff")];
        let frac = done_coverage_fraction(&summaries, &roots).unwrap();
        // \x80 is 128 out of 255 â‰ˆ 0.502
        assert!(frac > 0.45 && frac < 0.55, "fraction: {}", frac);
    }

    #[test]
    fn coverage_fraction_none_done() {
        let summaries = vec![active(0, b"\x00", b"\xff")];
        let roots = vec![spec(b"\x00", b"\xff")];
        let frac = done_coverage_fraction(&summaries, &roots).unwrap();
        assert!(frac < 0.001);
    }

    // â”€â”€ CoverageReport Display â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn coverage_report_display() {
        let summaries = vec![
            done(0, b"a", b"m"),
            parked(1, b"m", b"z"),
        ];
        let roots = vec![spec(b"a", b"z")];
        let report = verify_coverage(&summaries, &roots);
        let display = format!("{}", report);
        assert!(display.contains("1 done"));
        assert!(display.contains("1 parked"));
    }

    // â”€â”€ Property-based test stubs â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    // TODO: proptest for merge_intervals coverage preservation:
    //   âˆ€ sorted intervals, âˆ€ byte in any input interval:
    //     byte is in some output interval, and vice versa.
    //
    // TODO: proptest for find_gaps correctness:
    //   âˆ€ expected, actual intervals, âˆ€ point:
    //     point âˆˆ expected âˆ§ point âˆ‰ actual â†” point âˆˆ some gap.
    //
    // TODO: proptest for verify_coverage consistency:
    //   âˆ€ shard listings where all leaves are Done and no overlaps:
    //     report.is_complete() == true â†” gaps.is_empty()
    //
    // TODO: proptest for interval_width monotonicity:
    //   âˆ€ interval [a, b) âŠ‚ [c, d):
    //     interval_width([a, b)) <= interval_width([c, d))
}
