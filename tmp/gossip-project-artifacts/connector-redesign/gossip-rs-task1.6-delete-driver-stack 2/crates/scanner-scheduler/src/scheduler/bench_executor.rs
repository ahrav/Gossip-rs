//! Executor Microbenchmark
//!
//! # Purpose
//!
//! Measures raw scheduler overhead by running minimal tasks:
//! - Tasks/sec throughput
//! - Steal rate and local hit rate
//! - Queue time distribution (via executor metrics)
//!
//! # Key Metrics
//!
//! | Metric | What it Shows |
//! |--------|---------------|
//! | tasks/sec | Raw scheduler throughput |
//! | local_hit_rate | Work-stealing efficiency |
//! | steal_rate | Cross-worker task migration |
//! | queue_time p50/p99 | Scheduling latency (from MetricsSnapshot) |
//!
//! # Workload Topologies
//!
//! The benchmark supports different task spawn patterns:
//!
//! - **Injector-only** (`initial_batch = 0`): All tasks spawned externally via injector.
//!   Tests injector throughput and global queue contention.
//!
//! - **Chain spawn** (default): Initial tasks spawn chains of children.
//!   Tests local queue behavior and internal spawning.
//!
//! - **Burst spawn** (`burst_size > 0`): Each initial task spawns a burst of children.
//!   Creates stealable backlog for work-stealing stress tests.
//!
//! # Measurement Accuracy
//!
//! - Timer starts AFTER executor construction (thread startup not measured)
//! - No global atomic counters in task hot path (uses executor's internal metrics)
//! - `spin_work()` uses calibrated loop, not `Instant` (avoids timer overhead)
//!
//! # Caveats
//!
//! - `spin_work()` accuracy depends on CPU frequency; use for relative comparisons
//! - Very small `work_ns` values (<50ns) may be dominated by function call overhead
//! - Warmup iterations recommended to stabilize thread scheduling

use super::bench::{BenchIterMetrics, Benchmarkable};
use super::executor::{Executor, ExecutorConfig, WorkerCtx};
use super::metrics::MetricsSnapshot;

use std::time::Instant;

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for executor microbenchmark.
#[derive(Clone, Debug)]
pub struct ExecutorMicrobenchConfig {
    /// Total tasks to execute per iteration.
    pub task_count: usize,

    /// Simulated work per task in nanoseconds (approximate).
    ///
    /// Uses calibrated spin loop, not wall-clock timing.
    /// Accuracy varies with CPU frequency; use for relative comparisons.
    ///
    /// - 0 = pure scheduling overhead (function call only)
    /// - 100 = ~100ns spin (typical minimum useful task)
    /// - 1000 = ~1Âµs tasks
    pub work_ns: u64,

    /// Number of worker threads.
    pub workers: usize,

    /// Random seed for executor.
    pub seed: u64,

    /// Tasks spawned externally as chain roots.
    ///
    /// Each root spawns a chain of `chain_depth` children (internal spawns).
    /// Remaining tasks after chains are spawned as additional roots with depth 0.
    ///
    /// - 0 = all tasks via injector (no internal spawning)
    /// - N = N chain roots, each spawning children
    pub initial_batch: usize,

    /// For burst mode: each initial task spawns this many children at once.
    ///
    /// Creates stealable backlog on the spawning worker's queue.
    /// If 0, uses chain mode (each task spawns at most one child).
    ///
    /// Note: With burst_size > 0, total tasks = initial_batch * (1 + burst_size)
    pub burst_size: usize,
}

impl Default for ExecutorMicrobenchConfig {
    fn default() -> Self {
        Self {
            task_count: 100_000,
            work_ns: 100,
            workers: 4,
            seed: 0x853c49e6748fea9b,
            initial_batch: 100,
            burst_size: 0,
        }
    }
}

impl ExecutorMicrobenchConfig {
    /// Configuration for measuring pure scheduling overhead.
    pub fn zero_work() -> Self {
        Self {
            work_ns: 0,
            ..Default::default()
        }
    }

    /// Configuration for typical task sizes (~1Âµs).
    pub fn typical() -> Self {
        Self {
            work_ns: 1000,
            ..Default::default()
        }
    }

    /// Configuration for injector throughput testing.
    ///
    /// All tasks spawned externally - no internal spawn path.
    pub fn injector_only() -> Self {
        Self {
            initial_batch: 0,
            ..Default::default()
        }
    }

    /// Configuration for chain spawning (tests local queue).
    ///
    /// Each initial task spawns a chain of children via internal spawn.
    pub fn chain_spawn() -> Self {
        Self {
            task_count: 100_000,
            work_ns: 100,
            workers: 4,
            initial_batch: 10, // Few roots, deep chains
            burst_size: 0,
            ..Default::default()
        }
    }

    /// Configuration for work-stealing stress test.
    ///
    /// Creates stealable backlog by having initial tasks burst-spawn children.
    /// This fills local queues, forcing other workers to steal.
    pub fn steal_stress() -> Self {
        Self {
            task_count: 100_000,
            work_ns: 50,
            workers: 8,
            initial_batch: 8,       // One per worker
            burst_size: 12_500 - 1, // Each spawns ~12.5K children = 100K total
            ..Default::default()
        }
    }

    /// Validate configuration.
    pub fn validate(&self) -> Result<(), &'static str> {
        // In burst mode, task_count is ignored (uses initial_batch * (1 + burst_size))
        // In non-burst mode, task_count must be > 0
        if self.burst_size == 0 && self.task_count == 0 {
            return Err("task_count must be > 0 (unless using burst mode)");
        }
        if self.workers == 0 {
            return Err("workers must be > 0");
        }
        if self.burst_size > 0 && self.initial_batch == 0 {
            return Err("burst_size requires initial_batch > 0");
        }
        Ok(())
    }

    /// Compute effective task count based on topology.
    pub fn effective_task_count(&self) -> usize {
        if self.burst_size > 0 {
            // Burst mode: initial_batch roots, each spawns burst_size children
            self.initial_batch * (1 + self.burst_size)
        } else {
            self.task_count
        }
    }
}

// ============================================================================
// Microbench Results
// ============================================================================

/// Results from one microbenchmark iteration.
#[derive(Clone, Debug, Default)]
pub struct MicrobenchStats {
    /// Executor metrics snapshot (includes tasks_executed, steal stats, etc.).
    pub metrics: MetricsSnapshot,

    /// Wall time for task execution (excludes executor construction).
    pub wall_time_ns: u64,
}

impl MicrobenchStats {
    /// Tasks per second.
    pub fn tasks_per_sec(&self) -> f64 {
        if self.wall_time_ns == 0 {
            return 0.0;
        }
        self.metrics.tasks_executed as f64 / (self.wall_time_ns as f64 / 1_000_000_000.0)
    }

    /// Nanoseconds per task (scheduling + work).
    pub fn ns_per_task(&self) -> f64 {
        if self.metrics.tasks_executed == 0 {
            return 0.0;
        }
        self.wall_time_ns as f64 / self.metrics.tasks_executed as f64
    }

    /// Tasks completed (from executor metrics).
    pub fn tasks_completed(&self) -> u64 {
        self.metrics.tasks_executed
    }
}

// ============================================================================
// Calibrated Spin Work
// ============================================================================

/// Calibration factor: iterations per nanosecond.
///
/// Calibrated once at first use. Varies by CPU frequency.
static SPIN_CALIBRATION: std::sync::OnceLock<u64> = std::sync::OnceLock::new();

/// Get or compute the spin calibration factor.
fn get_spin_calibration() -> u64 {
    *SPIN_CALIBRATION.get_or_init(calibrate_spin)
}

/// Calibrate spin loop by measuring actual time.
///
/// Runs 100,000 iterations and computes iterations per nanosecond.
fn calibrate_spin() -> u64 {
    const CALIBRATION_ITERS: u64 = 100_000;

    let start = Instant::now();
    for _ in 0..CALIBRATION_ITERS {
        std::hint::spin_loop();
    }
    let elapsed_ns = start.elapsed().as_nanos() as u64;

    if elapsed_ns == 0 {
        // Fallback: assume ~3 cycles per spin_loop, ~1ns per cycle
        3
    } else {
        (CALIBRATION_ITERS / elapsed_ns).max(1)
    }
}

/// Spin for approximately `ns` nanoseconds using calibrated loop.
///
/// # Accuracy
///
/// Uses a calibrated iteration count rather than wall-clock timing.
/// This avoids `Instant::now()` overhead but accuracy varies with:
/// - CPU frequency scaling (turbo boost, power saving)
/// - Compiler optimizations
///
/// For scheduler benchmarks, relative consistency matters more than
/// absolute accuracy. Use warmup iterations to stabilize.
#[inline(never)]
fn spin_work(ns: u64) {
    if ns == 0 {
        return;
    }

    let iters_per_ns = get_spin_calibration();
    let iterations = ns.saturating_mul(iters_per_ns);

    for _ in 0..iterations {
        std::hint::spin_loop();
    }
}

// ============================================================================
// Microbench Task
// ============================================================================

/// A minimal task for microbenchmarking.
#[derive(Clone, Copy, Debug)]
struct MicrobenchTask {
    /// Chain depth remaining (decremented on each spawn).
    /// When 0, this task spawns no children.
    remaining: u64,

    /// Work to do in nanoseconds (copied to children).
    work_ns: u64,

    /// Burst spawn count (only used by initial tasks).
    /// If > 0, spawns this many children immediately, then sets to 0.
    burst: u64,
}

/// Per-worker scratch for microbenchmark.
struct MicrobenchScratch {
    /// Work per task (nanoseconds).
    work_ns: u64,
}

/// Process a microbench task.
///
/// # Task Execution Flow
///
/// 1. Spin for `work_ns` nanoseconds (simulated work).
/// 2. If burst mode (`task.burst > 0`): spawn `burst` leaf children, return.
/// 3. If chain mode (`task.remaining > 0`): spawn one child with `remaining - 1`.
///
/// # Spawning Behavior
///
/// - **Burst tasks** create stealable backlog—all children are leaf tasks
///   that go directly to the local queue.
/// - **Chain tasks** create deep dependency chains—each task spawns at most
///   one child, keeping work on the same worker (tests local queue affinity).
fn process_task(task: MicrobenchTask, ctx: &mut WorkerCtx<MicrobenchTask, MicrobenchScratch>) {
    // Do simulated work
    spin_work(ctx.scratch.work_ns);

    // Burst mode: spawn many children at once (creates stealable backlog)
    if task.burst > 0 {
        for _ in 0..task.burst {
            ctx.spawn_local(MicrobenchTask {
                remaining: 0, // Burst children are leaf tasks
                work_ns: task.work_ns,
                burst: 0,
            });
        }
        return; // Burst tasks don't also chain-spawn
    }

    // Chain mode: spawn one child with decremented remaining
    if task.remaining > 0 {
        ctx.spawn_local(MicrobenchTask {
            remaining: task.remaining - 1,
            work_ns: task.work_ns,
            burst: 0,
        });
    }
}

// ============================================================================
// Executor Microbench
// ============================================================================

/// Executor microbenchmark implementing `Benchmarkable`.
pub struct ExecutorMicrobench {
    config: ExecutorMicrobenchConfig,
}

impl ExecutorMicrobench {
    pub fn new(config: ExecutorMicrobenchConfig) -> Self {
        config.validate().expect("invalid config");
        Self { config }
    }

    /// Returns the configuration.
    pub fn config(&self) -> &ExecutorMicrobenchConfig {
        &self.config
    }

    /// Returns a description of the benchmark.
    pub fn description(&self) -> String {
        let mode = if self.config.burst_size > 0 {
            format!("burst({})", self.config.burst_size)
        } else if self.config.initial_batch == 0 {
            "injector-only".to_string()
        } else {
            "chain".to_string()
        };

        format!(
            "ExecutorMicrobench: {} tasks, {}ns work, {} workers, mode={}",
            self.config.effective_task_count(),
            self.config.work_ns,
            self.config.workers,
            mode,
        )
    }
}

impl Benchmarkable for ExecutorMicrobench {
    type Stats = MicrobenchStats;

    fn reset(&mut self) {
        // Ensure calibration happens before measured iterations
        let _ = get_spin_calibration();
    }

    fn run(&mut self) -> MicrobenchStats {
        // Preconditions (Tiger Style)
        // In burst mode, task_count is ignored (uses initial_batch * (1 + burst_size))
        debug_assert!(
            self.config.burst_size > 0 || self.config.task_count > 0,
            "task_count must be > 0 (unless using burst mode)"
        );
        debug_assert!(self.config.workers > 0, "workers must be > 0");

        let work_ns = self.config.work_ns;

        let executor_config = ExecutorConfig {
            workers: self.config.workers,
            seed: self.config.seed,
            ..Default::default()
        };

        // Create executor (thread startup happens here)
        let mut ex: Executor<MicrobenchTask> = Executor::new(
            executor_config,
            move |_wid| MicrobenchScratch { work_ns },
            process_task,
        );

        // Spawn tasks based on mode
        if self.config.burst_size > 0 {
            // Burst mode
            self.spawn_burst_tasks(&mut ex);
        } else if self.config.initial_batch == 0 {
            // Injector-only mode
            self.spawn_injector_only(&mut ex);
        } else {
            // Chain mode
            self.spawn_chain_tasks(&mut ex);
        }

        // Start timing AFTER tasks are queued (more accurate)
        let start = Instant::now();

        // Wait for completion
        let metrics = ex.join();

        let wall_time_ns = start.elapsed().as_nanos() as u64;

        let stats = MicrobenchStats {
            metrics,
            wall_time_ns,
        };

        // Postcondition: verify all tasks executed
        if cfg!(all(feature = "perf-stats", debug_assertions)) {
            debug_assert!(
                stats.tasks_completed() as usize >= self.config.effective_task_count(),
                "task count mismatch: {} < {}",
                stats.tasks_completed(),
                self.config.effective_task_count(),
            );
        }

        stats
    }

    fn extract_metrics(&self, stats: &MicrobenchStats) -> BenchIterMetrics {
        BenchIterMetrics {
            files: stats.tasks_completed(),
            bytes: 0,
            findings: 0,
            errors: 0,
        }
    }
}

impl ExecutorMicrobench {
    /// Spawn all tasks via injector (no internal spawning).
    fn spawn_injector_only(&self, ex: &mut Executor<MicrobenchTask>) {
        for _ in 0..self.config.task_count {
            let task = MicrobenchTask {
                remaining: 0,
                work_ns: self.config.work_ns,
                burst: 0,
            };
            ex.spawn_external(task).expect("spawn failed");
        }
    }

    /// Spawn chain roots that each spawn a chain of children.
    ///
    /// # Chain Depth Calculation
    ///
    /// To reach exactly `task_count` total tasks with `initial_batch` roots:
    ///
    /// ```text
    /// total = initial + initial * chain_depth
    /// chain_depth = (task_count - initial) / initial
    /// ```
    ///
    /// Remainder tasks (when division is uneven) are distributed by giving
    /// the first `remainder` chains one extra depth.
    fn spawn_chain_tasks(&self, ex: &mut Executor<MicrobenchTask>) {
        let initial = self.config.initial_batch.min(self.config.task_count).max(1);

        // Calculate chain depth to reach task_count
        // total_tasks = initial + initial * chain_depth
        // chain_depth = (task_count - initial) / initial
        let base_chain_depth = (self.config.task_count.saturating_sub(initial)) / initial;
        let remainder = self.config.task_count - initial - (initial * base_chain_depth);

        for i in 0..initial {
            // Distribute remainder across first few chains
            let extra = if i < remainder { 1 } else { 0 };
            let chain_depth = base_chain_depth + extra;

            let task = MicrobenchTask {
                remaining: chain_depth as u64,
                work_ns: self.config.work_ns,
                burst: 0,
            };
            ex.spawn_external(task).expect("spawn failed");
        }
    }

    /// Spawn burst roots that each spawn many children at once.
    fn spawn_burst_tasks(&self, ex: &mut Executor<MicrobenchTask>) {
        for _ in 0..self.config.initial_batch {
            let task = MicrobenchTask {
                remaining: 0,
                work_ns: self.config.work_ns,
                burst: self.config.burst_size as u64,
            };
            ex.spawn_external(task).expect("spawn failed");
        }
    }
}

// ============================================================================
// Standalone Run Function
// ============================================================================

/// Run executor microbenchmark without full bench harness.
///
/// Useful for quick profiling or integration into other tools.
pub fn run_executor_microbench(config: ExecutorMicrobenchConfig) -> MicrobenchStats {
    let mut bench = ExecutorMicrobench::new(config);
    bench.reset();
    bench.run()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_perf_tasks(actual: u64, expected: u64) {
        if cfg!(all(feature = "perf-stats", debug_assertions)) {
            assert_eq!(actual, expected);
        } else {
            assert_eq!(actual, 0);
        }
    }

    #[test]
    fn calibration_produces_nonzero() {
        let cal = calibrate_spin();
        assert!(cal > 0, "calibration must be > 0");
    }

    #[test]
    fn spin_work_completes() {
        // Just verify it doesn't hang
        spin_work(0);
        spin_work(100);
        spin_work(1000);
    }

    #[test]
    fn microbench_injector_only_completes() {
        let config = ExecutorMicrobenchConfig {
            task_count: 500,
            work_ns: 0,
            workers: 2,
            initial_batch: 0, // All external
            burst_size: 0,
            seed: 12345,
        };

        let stats = run_executor_microbench(config);

        assert_perf_tasks(stats.tasks_completed(), 500);
    }

    #[test]
    fn microbench_chain_completes() {
        let config = ExecutorMicrobenchConfig {
            task_count: 1000,
            work_ns: 0,
            workers: 2,
            initial_batch: 10,
            burst_size: 0,
            seed: 12345,
        };

        let stats = run_executor_microbench(config);

        assert_perf_tasks(stats.tasks_completed(), 1000);
    }

    #[test]
    fn microbench_burst_completes() {
        let config = ExecutorMicrobenchConfig {
            task_count: 0, // Ignored in burst mode
            work_ns: 0,
            workers: 2,
            initial_batch: 10,
            burst_size: 99, // 10 * (1 + 99) = 1000 total
            seed: 12345,
        };

        let stats = run_executor_microbench(config);

        assert_perf_tasks(stats.tasks_completed(), 1000);
    }

    #[test]
    fn chain_depth_distribution() {
        // Test that chain math distributes tasks correctly
        let config = ExecutorMicrobenchConfig {
            task_count: 1000,
            work_ns: 0,
            workers: 2,
            initial_batch: 7, // Doesn't divide evenly
            burst_size: 0,
            seed: 12345,
        };

        let stats = run_executor_microbench(config);

        // Should complete all 1000 tasks despite uneven division
        assert_perf_tasks(stats.tasks_completed(), 1000);
    }

    #[test]
    fn config_presets_valid() {
        assert!(ExecutorMicrobenchConfig::zero_work().validate().is_ok());
        assert!(ExecutorMicrobenchConfig::typical().validate().is_ok());
        assert!(ExecutorMicrobenchConfig::injector_only().validate().is_ok());
        assert!(ExecutorMicrobenchConfig::chain_spawn().validate().is_ok());
        assert!(ExecutorMicrobenchConfig::steal_stress().validate().is_ok());
    }

    #[test]
    fn stats_calculations() {
        let mut stats = MicrobenchStats::default();
        stats.metrics.tasks_executed = 1_000_000;
        stats.wall_time_ns = 1_000_000_000; // 1 second

        assert!((stats.tasks_per_sec() - 1_000_000.0).abs() < 1.0);
        assert!((stats.ns_per_task() - 1000.0).abs() < 0.01);
    }

    #[test]
    fn effective_task_count() {
        let chain = ExecutorMicrobenchConfig {
            task_count: 1000,
            initial_batch: 10,
            burst_size: 0,
            ..Default::default()
        };
        assert_eq!(chain.effective_task_count(), 1000);

        let burst = ExecutorMicrobenchConfig {
            task_count: 0, // Ignored
            initial_batch: 10,
            burst_size: 99,
            ..Default::default()
        };
        assert_eq!(burst.effective_task_count(), 1000); // 10 * (1 + 99)
    }

    #[test]
    fn config_validation() {
        let bad_task_count = ExecutorMicrobenchConfig {
            task_count: 0,
            ..Default::default()
        };
        assert!(bad_task_count.validate().is_err());

        let bad_workers = ExecutorMicrobenchConfig {
            workers: 0,
            ..Default::default()
        };
        assert!(bad_workers.validate().is_err());

        let bad_burst = ExecutorMicrobenchConfig {
            initial_batch: 0,
            burst_size: 10, // Can't burst without roots
            ..Default::default()
        };
        assert!(bad_burst.validate().is_err());
    }
}
