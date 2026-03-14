//! Deterministic Yield Policies
//!
//! # Purpose
//!
//! Provides deterministic yield points for long-running tasks to enable:
//!
//! - **Reproducible interleavings**: Same seed + same input = same yield pattern
//! - **Deterministic replay**: Debug issues with exact trace reproduction
//! - **Stable benchmarks**: No timing-dependent variance
//!
//! # Problem Solved
//!
//! Wall-clock-based yielding (e.g., `if elapsed > 10ms { yield }`) creates
//! timing-dependent behavior that breaks reproducibility. This module provides
//! work-unit-based yielding where yield decisions depend only on the number
//! of work units processed.
//!
//! # Usage
//!
//! ```ignore
//! let mut policy = EveryN::new(64); // Yield every 64 work units
//!
//! for item in items {
//!     process(item);
//!
//!     if policy.should_yield(1) {
//!         ctx.spawn_local(Task::Continue { cursor, policy });
//!         return;
//!     }
//! }
//! ```
//!
//! # Performance Characteristics
//!
//! - `should_yield()` is O(1): one add, one compare, one well-predicted branch
//! - No heap allocation after construction
//! - Inlines completely in release builds
//!
//! # Correctness Invariants
//!
//! - **Chunking invariance**: Yield behavior depends only on TOTAL work units,
//!   not on how they are batched. `should_yield(15)` and `should_yield(10) + should_yield(5)`
//!   produce equivalent state (modulo the yield that occurred).
//! - **Counter bounded**: After any operation, `counter < interval` always holds.
//! - **Deterministic**: Same sequence of `should_yield()` calls produces same results.
//! - **No timing dependencies**: Pure function of work units and internal state.
//!
//! # Serialization for Replay
//!
//! `EveryN` provides `from_state(interval, counter)` for replay. `AdaptiveYield`
//! state capture requires serializing `intervals`, `current_phase`, and `counter`.

// ============================================================================
// YieldPolicy Trait
// ============================================================================

/// Deterministic yield policy for long-running tasks.
///
/// # Implementor Requirements
///
/// - `should_yield()` MUST be a pure function of work units and internal state
/// - `should_yield()` MUST NOT use wall-clock time or random values
/// - `should_yield()` MUST preserve chunking invariance (see module docs)
/// - After `should_yield()`, `counter() < interval()` MUST hold
///
/// # Thread Safety
///
/// Policies are NOT thread-safe. Each task should have its own policy instance.
/// Policies can be `Send` to move between threads (task migration).
pub trait YieldPolicy: Send {
    /// Check if the task should yield after processing `work_units`.
    ///
    /// # Parameters
    ///
    /// - `work_units`: Number of work units just completed (e.g., commits, bytes, items)
    ///
    /// # Returns
    ///
    /// `true` if the task should yield control back to the scheduler.
    ///
    /// # Chunking Invariance
    ///
    /// The yield behavior depends only on total work processed, not batching.
    /// After yielding, excess work beyond the interval is preserved for the
    /// next cycle.
    ///
    /// # Performance
    ///
    /// This is called in tight loops. Implementation MUST be O(1).
    fn should_yield(&mut self, work_units: u64) -> bool;

    /// Reset the counter for a new work cycle.
    ///
    /// This resets only the work counter, not phase or interval settings.
    /// Use when starting a logically new unit of work within the same task.
    ///
    /// # Note
    ///
    /// For `AdaptiveYield`, this does NOT reset the current phase.
    /// Phase represents "what kind of work" while counter represents
    /// "how much work in this cycle".
    fn reset(&mut self);

    /// Get the current counter value (for debugging/serialization).
    fn counter(&self) -> u64;

    /// Get the interval/threshold (for debugging/serialization).
    fn interval(&self) -> u64;
}

// ============================================================================
// EveryN - Fixed Interval Policy
// ============================================================================

/// Yield every N work units.
///
/// The simplest deterministic policy. Suitable when work units have
/// roughly uniform cost.
///
/// # Example
///
/// ```ignore
/// let mut policy = EveryN::new(128);
///
/// for commit in commits {
///     process_commit(commit);
///
///     if policy.should_yield(1) {
///         // Yield after every 128 commits
///         return YieldWith(cursor);
///     }
/// }
/// ```
///
/// # Chunking Invariance
///
/// This policy preserves excess work units when yielding:
/// - `should_yield(150)` with interval 100 yields once, counter becomes 50
/// - Equivalent to `should_yield(100)` (yield) + `should_yield(50)` (no yield)
///
/// # Performance
///
/// - `should_yield`: ~3-5 cycles (add + compare + branch + optional subtract)
/// - Branch is well-predicted (yield is rare in typical usage)
/// - Fully inlines in release builds
#[derive(Clone, Debug)]
pub struct EveryN {
    /// Yield interval (work units between yields).
    interval: u64,
    /// Current counter (work units since last yield).
    counter: u64,
}

impl EveryN {
    /// Create a policy that yields every `interval` work units.
    ///
    /// # Panics
    ///
    /// Panics if `interval` is 0.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let policy = EveryN::new(64); // Yield every 64 work units
    /// ```
    pub fn new(interval: u64) -> Self {
        assert!(interval > 0, "yield interval must be > 0");
        Self {
            interval,
            counter: 0,
        }
    }

    /// Create a policy from serialized state (for replay).
    ///
    /// # Parameters
    ///
    /// - `interval`: Original interval value
    /// - `counter`: Counter value at serialization point
    ///
    /// # Panics
    ///
    /// Panics if `interval` is 0 or if `counter >= interval` (invalid state).
    pub fn from_state(interval: u64, counter: u64) -> Self {
        assert!(interval > 0, "yield interval must be > 0");
        assert!(
            counter < interval,
            "counter {} must be < interval {} (invariant violation)",
            counter,
            interval
        );
        Self { interval, counter }
    }
}

impl YieldPolicy for EveryN {
    #[inline]
    fn should_yield(&mut self, work_units: u64) -> bool {
        // Use saturating_add to handle overflow correctly.
        // At u64::MAX, we'll always trigger a yield (correct behavior).
        self.counter = self.counter.saturating_add(work_units);

        if self.counter >= self.interval {
            // Preserve remainder to maintain chunking invariance.
            // This ensures yield behavior depends only on TOTAL work,
            // not on how work_units calls are batched.
            self.counter -= self.interval;

            // Handle case where work_units >> interval (multiple intervals in one call).
            // This is rare but must be handled correctly for determinism.
            if self.counter >= self.interval {
                self.counter %= self.interval;
            }

            true
        } else {
            false
        }
    }

    #[inline]
    fn reset(&mut self) {
        self.counter = 0;
    }

    #[inline]
    fn counter(&self) -> u64 {
        self.counter
    }

    #[inline]
    fn interval(&self) -> u64 {
        self.interval
    }
}

impl Default for EveryN {
    /// Default interval of 64 work units.
    fn default() -> Self {
        Self::new(64)
    }
}

// ============================================================================
// NeverYield - Disable Yielding
// ============================================================================

/// Never yield (run to completion).
///
/// Use for short tasks or when cooperative scheduling is disabled.
///
/// # Warning
///
/// Using this policy for long-running tasks will starve other work.
/// Only appropriate when the task is known to be short or when
/// the executor has only one task type.
#[derive(Clone, Copy, Debug, Default)]
pub struct NeverYield;

impl YieldPolicy for NeverYield {
    #[inline]
    fn should_yield(&mut self, _work_units: u64) -> bool {
        false
    }

    #[inline]
    fn reset(&mut self) {}

    #[inline]
    fn counter(&self) -> u64 {
        0
    }

    #[inline]
    fn interval(&self) -> u64 {
        u64::MAX
    }
}

// ============================================================================
// AlwaysYield - Maximum Cooperativeness
// ============================================================================

/// Always yield after any work.
///
/// Use for testing scheduler fairness or when maximum cooperativeness
/// is required.
///
/// # Performance Impact
///
/// This creates significant scheduling overhead. Only use for testing
/// or specialized scenarios.
///
/// # Note
///
/// This policy yields even when `work_units == 0`. This is intentional
/// for testing maximum cooperativeness.
#[derive(Clone, Copy, Debug, Default)]
pub struct AlwaysYield;

impl YieldPolicy for AlwaysYield {
    #[inline]
    fn should_yield(&mut self, _work_units: u64) -> bool {
        true
    }

    #[inline]
    fn reset(&mut self) {}

    #[inline]
    fn counter(&self) -> u64 {
        0
    }

    #[inline]
    fn interval(&self) -> u64 {
        1
    }
}

// ============================================================================
// AdaptiveYield - Variable Interval Based on Phase
// ============================================================================

/// Adaptive yield policy with different intervals per work type.
///
/// Use when different parts of a task have different work unit costs.
/// For example, Git commit walking is cheap but blob inflation is expensive.
///
/// # Work-Unit Semantics
///
/// Different work types typically count DIFFERENT units:
/// - Commit-walk intervals might count commits (cheap operations)
/// - Inflate intervals might count KB inflated (expensive operations)
///
/// When switching phases via `set_phase()`, the counter resets because
/// you're now counting a different type of work. This is intentional.
///
/// # Example
///
/// ```ignore
/// let mut policy = AdaptiveYield::new(64)
///     .with_phase(0, 256)   // Yield every 256 commits
///     .with_phase(1, 64);   // Yield every 64 KB inflated
///
/// // During commit walk (interval slot 0)
/// policy.set_phase(0);
/// for commit in commits {
///     if policy.should_yield(1) { ... }
/// }
///
/// // During blob inflation (interval slot 1) - counter resets
/// policy.set_phase(1);
/// for chunk in chunks {
///     if policy.should_yield(chunk.len_kb()) { ... }
/// }
/// ```
#[derive(Clone, Debug)]
pub struct AdaptiveYield {
    /// Intervals for each phase (up to 8 phases).
    intervals: [u64; 8],
    /// Current phase index.
    current_phase: usize,
    /// Counter for current phase.
    counter: u64,
}

impl AdaptiveYield {
    /// Create an adaptive policy with default interval for all phases.
    ///
    /// # Parameters
    ///
    /// - `default_interval`: Default yield interval for all phases
    pub fn new(default_interval: u64) -> Self {
        assert!(default_interval > 0, "default interval must be > 0");
        Self {
            intervals: [default_interval; 8],
            current_phase: 0,
            counter: 0,
        }
    }

    /// Set the yield interval for a specific phase.
    ///
    /// # Parameters
    ///
    /// - `phase`: Phase index (0-7)
    /// - `interval`: Yield interval for this phase
    ///
    /// # Panics
    ///
    /// Panics if `phase >= 8` or `interval == 0`.
    pub fn with_phase(mut self, phase: usize, interval: u64) -> Self {
        assert!(phase < 8, "phase must be < 8");
        assert!(interval > 0, "interval must be > 0");
        self.intervals[phase] = interval;
        self
    }

    /// Set the current phase.
    ///
    /// # Counter Reset on Phase Change
    ///
    /// When changing phases, the counter resets to 0. This is intentional:
    /// different phases count different types of work units (e.g., commits
    /// vs KB). Work accumulated in one phase doesn't carry over because
    /// it's measuring something fundamentally different.
    ///
    /// # Parameters
    ///
    /// - `phase`: Phase index (0-7)
    ///
    /// # Panics
    ///
    /// Panics if `phase >= 8`.
    #[inline]
    pub fn set_phase(&mut self, phase: usize) {
        assert!(phase < 8, "phase must be < 8");
        if self.current_phase != phase {
            self.current_phase = phase;
            self.counter = 0;
        }
    }

    /// Get the current phase.
    #[inline]
    pub fn current_phase(&self) -> usize {
        self.current_phase
    }

    /// Get the interval for a specific phase.
    ///
    /// # Panics
    ///
    /// Panics if `phase >= 8`.
    #[inline]
    pub fn phase_interval(&self, phase: usize) -> u64 {
        assert!(phase < 8, "phase must be < 8");
        self.intervals[phase]
    }
}

impl YieldPolicy for AdaptiveYield {
    #[inline]
    fn should_yield(&mut self, work_units: u64) -> bool {
        let interval = self.intervals[self.current_phase];
        debug_assert!(interval > 0, "interval must be > 0");

        // Use saturating_add for overflow safety
        self.counter = self.counter.saturating_add(work_units);

        if self.counter >= interval {
            // Preserve remainder for chunking invariance
            self.counter -= interval;

            // Handle multiple intervals in one call
            if self.counter >= interval {
                self.counter %= interval;
            }

            true
        } else {
            false
        }
    }

    #[inline]
    fn reset(&mut self) {
        self.counter = 0;
        // Note: Does NOT reset current_phase. Phase represents "what kind of work"
        // while counter represents "how much work in this cycle".
    }

    #[inline]
    fn counter(&self) -> u64 {
        self.counter
    }

    #[inline]
    fn interval(&self) -> u64 {
        self.intervals[self.current_phase]
    }
}

impl Default for AdaptiveYield {
    fn default() -> Self {
        Self::new(64)
    }
}

// ============================================================================
// GitYieldPolicy - Specialized for Git Operations
// ============================================================================

/// Git-specific operation identifiers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub enum GitPhase {
    /// Walking commit graph
    CommitWalk = 0,
    /// Emitting blob/tree candidates
    CandidateEmit = 1,
    /// Inflating/decompressing pack data
    PackInflate = 2,
    /// Resolving delta chains
    DeltaResolve = 3,
    /// Scanning content
    ContentScan = 4,
}

impl GitPhase {
    /// Convert from raw phase index.
    ///
    /// # Panics
    ///
    /// Panics if `phase > 4`.
    fn from_index(phase: usize) -> Self {
        match phase {
            0 => GitPhase::CommitWalk,
            1 => GitPhase::CandidateEmit,
            2 => GitPhase::PackInflate,
            3 => GitPhase::DeltaResolve,
            4 => GitPhase::ContentScan,
            _ => unreachable!("GitPhase index {} out of range (0-4)", phase),
        }
    }
}

/// Pre-configured yield policy for Git repository scanning.
///
/// # Default Intervals
///
/// | Operation | Interval | Rationale |
/// |-------|----------|-----------|
/// | CommitWalk | 128 | Commits are cheap to enumerate |
/// | CandidateEmit | 64 | Moderate cost per candidate |
/// | PackInflate | 512 KB | Inflation is CPU-intensive |
/// | DeltaResolve | 128 | Deltas vary in cost |
/// | ContentScan | 256 KB | Scanning is CPU-intensive |
#[derive(Clone, Debug)]
pub struct GitYieldPolicy {
    inner: AdaptiveYield,
}

impl GitYieldPolicy {
    /// Create a Git yield policy with default intervals.
    pub fn new() -> Self {
        Self {
            inner: AdaptiveYield::new(64)
                .with_phase(GitPhase::CommitWalk as usize, 128)
                .with_phase(GitPhase::CandidateEmit as usize, 64)
                .with_phase(GitPhase::PackInflate as usize, 512) // KB
                .with_phase(GitPhase::DeltaResolve as usize, 128)
                .with_phase(GitPhase::ContentScan as usize, 256), // KB
        }
    }

    /// Create a Git yield policy with custom intervals.
    ///
    /// # Parameters
    ///
    /// - `commit_walk`: Commits between yields
    /// - `candidate_emit`: Candidates between yields
    /// - `pack_inflate_kb`: KB inflated between yields
    /// - `delta_resolve`: Deltas between yields
    /// - `content_scan_kb`: KB scanned between yields
    pub fn custom(
        commit_walk: u64,
        candidate_emit: u64,
        pack_inflate_kb: u64,
        delta_resolve: u64,
        content_scan_kb: u64,
    ) -> Self {
        Self {
            inner: AdaptiveYield::new(64)
                .with_phase(GitPhase::CommitWalk as usize, commit_walk)
                .with_phase(GitPhase::CandidateEmit as usize, candidate_emit)
                .with_phase(GitPhase::PackInflate as usize, pack_inflate_kb)
                .with_phase(GitPhase::DeltaResolve as usize, delta_resolve)
                .with_phase(GitPhase::ContentScan as usize, content_scan_kb),
        }
    }

    /// Set the current Git operation phase.
    #[inline]
    pub fn set_phase(&mut self, phase: GitPhase) {
        self.inner.set_phase(phase as usize);
    }

    /// Get the current phase.
    #[inline]
    pub fn current_phase(&self) -> GitPhase {
        let phase_index = self.inner.current_phase();
        // This is safe because:
        // 1. GitYieldPolicy only sets phases via GitPhase enum (0-4)
        // 2. AdaptiveYield doesn't allow setting phases >= 8
        // 3. We only use phases 0-4
        debug_assert!(
            phase_index <= 4,
            "GitYieldPolicy phase {} out of range",
            phase_index
        );
        GitPhase::from_index(phase_index)
    }
}

impl Default for GitYieldPolicy {
    fn default() -> Self {
        Self::new()
    }
}

impl YieldPolicy for GitYieldPolicy {
    #[inline]
    fn should_yield(&mut self, work_units: u64) -> bool {
        self.inner.should_yield(work_units)
    }

    #[inline]
    fn reset(&mut self) {
        self.inner.reset();
    }

    #[inline]
    fn counter(&self) -> u64 {
        self.inner.counter()
    }

    #[inline]
    fn interval(&self) -> u64 {
        self.inner.interval()
    }
}

// ============================================================================
// Boxed Policy (for dynamic dispatch)
// ============================================================================

/// Type-erased yield policy for runtime polymorphism.
///
/// Use when the policy type isn't known at compile time.
///
/// # Performance
///
/// Adds one indirect call (~3-5 cycles) per `should_yield()`. Prefer
/// concrete types in hot paths.
pub type BoxedYieldPolicy = Box<dyn YieldPolicy>;

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_n_basic() {
        let mut policy = EveryN::new(3);

        assert!(!policy.should_yield(1)); // counter: 1
        assert!(!policy.should_yield(1)); // counter: 2
        assert!(policy.should_yield(1)); // counter: 3 -> yield, counter: 0

        assert!(!policy.should_yield(1)); // counter: 1
        assert!(!policy.should_yield(1)); // counter: 2
        assert!(policy.should_yield(1)); // counter: 3 -> yield
    }

    #[test]
    fn every_n_bulk_increment() {
        let mut policy = EveryN::new(100);

        assert!(!policy.should_yield(50)); // counter: 50
        assert!(!policy.should_yield(40)); // counter: 90
        assert!(policy.should_yield(20)); // counter: 110 >= 100 -> yield, counter: 10

        // Counter should be 10 (preserved remainder)
        assert_eq!(policy.counter(), 10);

        assert!(!policy.should_yield(80)); // counter: 90
        assert!(policy.should_yield(10)); // counter: 100 -> yield, counter: 0
    }

    /// Critical test: verify chunking invariance.
    /// Yield behavior must depend only on TOTAL work, not batching.
    #[test]
    fn chunking_invariance() {
        let mut p1 = EveryN::new(10);
        let mut p2 = EveryN::new(10);

        // Scenario A: One large chunk of 15
        let yield_a = p1.should_yield(15);
        // p1 counter should now be 5 (15 - 10)

        // Scenario B: Chunks of 10 and 5
        let yield_b1 = p2.should_yield(10); // yields, counter = 0
        let yield_b2 = p2.should_yield(5); // no yield, counter = 5

        assert!(yield_a, "single chunk of 15 should yield");
        assert!(yield_b1, "chunk of 10 should yield");
        assert!(!yield_b2, "chunk of 5 after yield should not yield");

        // Key assertion: both policies should have same counter state
        assert_eq!(
            p1.counter(),
            p2.counter(),
            "counter state must be invariant to chunk size"
        );
        assert_eq!(p1.counter(), 5);
    }

    /// Test multiple intervals crossed in single call.
    #[test]
    fn multiple_intervals_in_one_call() {
        let mut policy = EveryN::new(10);

        // Process 35 units at once (crosses 3 intervals, remainder 5)
        assert!(policy.should_yield(35));
        assert_eq!(policy.counter(), 5);

        // Adding 5 more makes counter = 10, which triggers yield
        assert!(policy.should_yield(5));
        assert_eq!(policy.counter(), 0);
    }

    #[test]
    fn multiple_intervals_correct() {
        let mut policy = EveryN::new(10);

        // Process 35 units at once (crosses 3 intervals, remainder 5)
        assert!(policy.should_yield(35));
        assert_eq!(policy.counter(), 5);

        // Another 4 should not yield (counter = 9)
        assert!(!policy.should_yield(4));
        assert_eq!(policy.counter(), 9);

        // One more should yield (counter = 10)
        assert!(policy.should_yield(1));
        assert_eq!(policy.counter(), 0);
    }

    #[test]
    fn every_n_reset() {
        let mut policy = EveryN::new(10);

        policy.should_yield(5);
        assert_eq!(policy.counter(), 5);

        policy.reset();
        assert_eq!(policy.counter(), 0);
    }

    #[test]
    fn every_n_from_state() {
        let policy = EveryN::from_state(100, 75);
        assert_eq!(policy.interval(), 100);
        assert_eq!(policy.counter(), 75);
    }

    #[test]
    #[should_panic(expected = "counter 100 must be < interval 100")]
    fn every_n_from_state_rejects_invalid() {
        let _ = EveryN::from_state(100, 100);
    }

    #[test]
    fn never_yield() {
        let mut policy = NeverYield;

        for _ in 0..1000 {
            assert!(!policy.should_yield(1));
        }
        assert!(!policy.should_yield(u64::MAX));
    }

    #[test]
    fn always_yield() {
        let mut policy = AlwaysYield;

        for _ in 0..100 {
            assert!(policy.should_yield(0));
            assert!(policy.should_yield(1));
            assert!(policy.should_yield(1000));
        }
    }

    #[test]
    fn adaptive_phases() {
        let mut policy = AdaptiveYield::new(100).with_phase(0, 10).with_phase(1, 5);

        // Slot 0: interval 10
        policy.set_phase(0);
        for _ in 0..9 {
            assert!(!policy.should_yield(1));
        }
        assert!(policy.should_yield(1)); // 10th

        // Slot 1: interval 5
        policy.set_phase(1);
        assert_eq!(policy.counter(), 0); // Reset on phase change
        for _ in 0..4 {
            assert!(!policy.should_yield(1));
        }
        assert!(policy.should_yield(1)); // 5th
    }

    #[test]
    fn adaptive_same_phase_no_reset() {
        let mut policy = AdaptiveYield::new(100).with_phase(0, 10);

        policy.set_phase(0);
        policy.should_yield(5);
        assert_eq!(policy.counter(), 5);

        policy.set_phase(0); // Same phase
        assert_eq!(policy.counter(), 5); // No reset
    }

    #[test]
    fn adaptive_chunking_invariance() {
        let mut p1 = AdaptiveYield::new(10);
        let mut p2 = AdaptiveYield::new(10);

        // Same chunking invariance test
        let yield_a = p1.should_yield(15);
        let yield_b1 = p2.should_yield(10);
        let yield_b2 = p2.should_yield(5);

        assert!(yield_a);
        assert!(yield_b1);
        assert!(!yield_b2);
        assert_eq!(p1.counter(), p2.counter());
    }

    #[test]
    #[should_panic(expected = "phase must be < 8")]
    fn adaptive_phase_interval_rejects_invalid() {
        let policy = AdaptiveYield::new(64);
        let _ = policy.phase_interval(8);
    }

    #[test]
    fn git_policy_phases() {
        let mut policy = GitYieldPolicy::new();

        // CommitWalk: interval 128
        policy.set_phase(GitPhase::CommitWalk);
        assert_eq!(policy.interval(), 128);
        assert_eq!(policy.current_phase(), GitPhase::CommitWalk);

        // PackInflate: interval 512
        policy.set_phase(GitPhase::PackInflate);
        assert_eq!(policy.interval(), 512);
        assert_eq!(policy.current_phase(), GitPhase::PackInflate);

        // CandidateEmit: interval 64
        policy.set_phase(GitPhase::CandidateEmit);
        assert_eq!(policy.interval(), 64);
        assert_eq!(policy.current_phase(), GitPhase::CandidateEmit);
    }

    #[test]
    fn git_policy_custom() {
        let policy = GitYieldPolicy::custom(256, 128, 1024, 256, 512);

        let mut p = policy;
        p.set_phase(GitPhase::CommitWalk);
        assert_eq!(p.interval(), 256);

        p.set_phase(GitPhase::CandidateEmit);
        assert_eq!(p.interval(), 128);
    }

    #[test]
    fn deterministic_sequence() {
        // Same sequence should produce same yield points
        fn run_sequence(policy: &mut impl YieldPolicy) -> Vec<bool> {
            let work_units = [1, 5, 10, 2, 8, 15, 3, 7, 4, 6];
            work_units.iter().map(|&w| policy.should_yield(w)).collect()
        }

        let mut p1 = EveryN::new(20);
        let mut p2 = EveryN::new(20);

        let r1 = run_sequence(&mut p1);
        let r2 = run_sequence(&mut p2);

        assert_eq!(r1, r2, "same policy should produce same results");
    }

    #[test]
    fn boxed_policy_works() {
        let mut policy: BoxedYieldPolicy = Box::new(EveryN::new(5));

        for _ in 0..4 {
            assert!(!policy.should_yield(1));
        }
        assert!(policy.should_yield(1));
    }

    #[test]
    #[should_panic(expected = "yield interval must be > 0")]
    fn every_n_rejects_zero_interval() {
        let _ = EveryN::new(0);
    }

    #[test]
    #[should_panic(expected = "phase must be < 8")]
    fn adaptive_rejects_invalid_phase() {
        let mut policy = AdaptiveYield::new(64);
        policy.set_phase(8);
    }

    #[test]
    fn policy_sizes() {
        assert_eq!(std::mem::size_of::<EveryN>(), 16);
        assert_eq!(std::mem::size_of::<NeverYield>(), 0);
        assert_eq!(std::mem::size_of::<AlwaysYield>(), 0);
        // AdaptiveYield: 8 * 8 (intervals) + 8 (phase) + 8 (counter) = 80
        assert!(std::mem::size_of::<AdaptiveYield>() <= 80);

        println!("EveryN: {} bytes", std::mem::size_of::<EveryN>());
        println!(
            "AdaptiveYield: {} bytes",
            std::mem::size_of::<AdaptiveYield>()
        );
        println!(
            "GitYieldPolicy: {} bytes",
            std::mem::size_of::<GitYieldPolicy>()
        );
    }

    /// Test overflow handling with saturating_add.
    #[test]
    fn overflow_handling() {
        let mut policy = EveryN::new(100);

        // Near-max value should saturate and yield
        policy.should_yield(u64::MAX - 50);

        // Counter saturated to MAX, which >= 100, so it yielded
        // After yield, counter should be reasonable (MAX % 100)
        assert!(
            policy.counter() < 100,
            "counter should be bounded after overflow"
        );
    }

    /// Verify counter is always < interval after should_yield
    #[test]
    fn counter_bounded_invariant() {
        let mut policy = EveryN::new(100);

        // Various work unit sizes
        for work in [1, 50, 99, 100, 101, 200, 999, 1000] {
            policy.should_yield(work);
            assert!(
                policy.counter() < policy.interval(),
                "counter {} must be < interval {} after should_yield({})",
                policy.counter(),
                policy.interval(),
                work
            );
        }
    }
}
