//! Hard caps and tunables for commit selection (commit-graph traversal).
//!
//! These limits bound memory usage and protect against pathological commit
//! graphs during the `(watermark, tip]` traversal and topological ordering.
//! All limits are explicit and enforced; exceeding most limits yields an
//! error (`max_new_ref_skip_checks` silently caps a loop instead).

/// Hard caps for commit-graph traversal and ordering.
///
/// These limits are enforced during commit planning:
/// - Range walks for introduced-by commits.
/// - Topological ordering of the scanned subgraph.
/// - Snapshot plans (tip-only) still validate graph size.
///
/// # Layout
/// Fields are ordered for optimal packing (16 bytes total).
#[derive(Clone, Copy, Debug)]
pub struct CommitWalkLimits {
    /// Maximum number of commits in the commit-graph.
    ///
    /// This bounds the size of `visited_commit` and per-ref scratch arrays.
    /// Default: 10,000,000 (10M).
    pub max_commits_in_graph: u32,

    /// Maximum total heap entries across interesting + uninteresting frontiers.
    ///
    /// This is a live count of heap entries (not a monotonic total). The
    /// limit protects against pathological DAG shapes that could cause
    /// unbounded frontier growth.
    /// Default: 2,000,000.
    pub max_heap_entries: u32,

    /// Maximum parents per commit allowed during traversal.
    ///
    /// Git octopus merges can be large; this guard prevents corrupt graphs
    /// or adversarial inputs from exploding traversal costs.
    /// Default: 128.
    pub max_parents_per_commit: u32,

    /// Maximum ancestry checks when attempting the "new ref skip" optimization.
    ///
    /// This caps the number of watermark ancestry checks performed when a
    /// ref has no watermark. Excess refs are skipped without checks.
    /// Default: 1024.
    pub max_new_ref_skip_checks: u32,
}

impl CommitWalkLimits {
    /// Safe defaults suitable for large monorepos.
    pub const DEFAULT: Self = Self {
        max_commits_in_graph: 10_000_000,
        max_heap_entries: 2_000_000,
        max_parents_per_commit: 128,
        max_new_ref_skip_checks: 1024,
    };

    /// Restrictive limits for testing or memory-constrained environments.
    pub const RESTRICTIVE: Self = Self {
        max_commits_in_graph: 200_000,
        max_heap_entries: 50_000,
        max_parents_per_commit: 32,
        max_new_ref_skip_checks: 128,
    };

    /// Validates that limits are internally consistent.
    ///
    /// # Panics
    ///
    /// Panics if limits are invalid (indicates a configuration bug).
    #[track_caller]
    pub const fn validate(&self) {
        assert!(
            self.max_commits_in_graph > 0,
            "must allow at least 1 commit"
        );
        assert!(self.max_heap_entries > 0, "heap entry limit must be > 0");
        assert!(
            self.max_parents_per_commit > 0,
            "must allow at least 1 parent"
        );
        assert!(
            self.max_new_ref_skip_checks > 0,
            "must allow at least 1 skip check"
        );

        assert!(
            self.max_commits_in_graph <= 100_000_000,
            "unreasonably large commit-graph cap"
        );
        assert!(
            self.max_heap_entries <= self.max_commits_in_graph,
            "heap entry limit exceeds commit-graph cap"
        );
        assert!(
            self.max_parents_per_commit <= 4096,
            "max parents per commit is unreasonably large"
        );
        assert!(
            self.max_new_ref_skip_checks <= 1_000_000,
            "max new-ref skip checks is unreasonably large"
        );
    }

    /// Non-panicking validation for runtime configuration.
    ///
    /// Returns a short, static error string suitable for surfacing in
    /// configuration diagnostics.
    #[must_use = "check limits validity before use"]
    pub const fn try_validate(&self) -> Result<(), &'static str> {
        if self.max_commits_in_graph == 0 {
            return Err("must allow at least 1 commit");
        }
        if self.max_heap_entries == 0 {
            return Err("heap entry limit must be > 0");
        }
        if self.max_parents_per_commit == 0 {
            return Err("must allow at least 1 parent");
        }
        if self.max_new_ref_skip_checks == 0 {
            return Err("must allow at least 1 skip check");
        }
        if self.max_commits_in_graph > 100_000_000 {
            return Err("unreasonably large commit-graph cap");
        }
        if self.max_heap_entries > self.max_commits_in_graph {
            return Err("heap entry limit exceeds commit-graph cap");
        }
        if self.max_parents_per_commit > 4096 {
            return Err("max parents per commit is unreasonably large");
        }
        if self.max_new_ref_skip_checks > 1_000_000 {
            return Err("max new-ref skip checks is unreasonably large");
        }
        Ok(())
    }
}

impl Default for CommitWalkLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

const _: () = CommitWalkLimits::DEFAULT.validate();
const _: () = CommitWalkLimits::RESTRICTIVE.validate();
const _: () = assert!(std::mem::size_of::<CommitWalkLimits>() == 16);
