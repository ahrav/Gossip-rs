//! Benchmark Harness for Local Scanning
//!
//! # Purpose
//!
//! Provides reproducible, CI-friendly benchmarks that measure:
//! - Wall time (p50, p95, p99)
//! - CPU time (user + system via rusage)
//! - Memory usage (peak RSS)
//! - Throughput (MiB/s, files/s)
//!
//! # Key Principles
//!
//! 1. **Quiet by default**: No path/content output (uses NullEventSink)
//! 2. **Reproducible**: Fixed seeds, CPU pinning, warmup iterations
//! 3. **CI-friendly**: Stable summary format for regression detection
//! 4. **Payload-safe**: No sensitive data in output
//!
//! # Usage
//!
//! ```rust,ignore
//! let mut bench = MyBenchImpl::new(config);
//! let report = run_benchmark(&mut bench, BenchConfig::default());
//! println!("{}", report.summary());
//! ```
//!
//! # Benchmark Types
//!
//! - **Macrobench**: Full filesystem scan with I/O
//! - **Microbench**: In-memory scan (isolates CPU work from I/O)
//!
//! # What This Catches
//!
//! - Memory regressions: RSS increase visible in report
//! - Throughput regressions: bytes/s decrease visible in p95
//! - Unexpected allocations: can integrate with alloc stats

use super::rusage::{rusage_self, ProcUsage, ProcUsageDelta};
use std::time::{Duration, Instant};

// ============================================================================
// Benchmark Configuration
// ============================================================================

/// Configuration for benchmark runs.
#[derive(Clone, Debug)]
pub struct BenchConfig {
    /// Number of warmup iterations (not measured).
    ///
    /// Warmup ensures:
    /// - JIT/branch predictor trained
    /// - Page cache populated
    /// - Buffer pool initialized
    pub warmup_iters: usize,

    /// Number of measured iterations.
    pub iters: usize,

    /// CPU core to pin to (measurement hygiene).
    ///
    /// None = no pinning (may have variance from core migration).
    pub pin_core: Option<usize>,

    /// Whether to reset allocation stats before each iteration.
    ///
    /// Only meaningful if using CountingAllocator.
    pub reset_alloc_stats: bool,

    /// Seed for deterministic scheduler behavior.
    pub seed: u64,
}

impl Default for BenchConfig {
    fn default() -> Self {
        Self {
            warmup_iters: 2,
            iters: 5,
            pin_core: None,
            reset_alloc_stats: false,
            seed: 0x853c49e6748fea9b,
        }
    }
}

impl BenchConfig {
    /// Creates a config for quick CI regression tests.
    pub fn ci_quick() -> Self {
        Self {
            warmup_iters: 1,
            iters: 3,
            pin_core: None,
            reset_alloc_stats: false,
            seed: 12345,
        }
    }

    /// Creates a config for detailed profiling.
    pub fn detailed() -> Self {
        Self {
            warmup_iters: 3,
            iters: 10,
            pin_core: Some(0),
            reset_alloc_stats: true,
            seed: 12345,
        }
    }
}

// ============================================================================
// Per-Iteration Results
// ============================================================================

/// Results from a single benchmark iteration.
#[derive(Clone, Debug)]
pub struct BenchIter {
    /// Wall-clock time for this iteration.
    pub wall_time: Duration,

    /// CPU usage delta for this iteration.
    pub cpu_usage: ProcUsageDelta,

    /// Files processed in this iteration.
    pub files: u64,

    /// Bytes scanned in this iteration.
    pub bytes: u64,

    /// Findings count (if available).
    pub findings: u64,

    /// Errors/failures (if available).
    pub errors: u64,
}

impl BenchIter {
    /// Throughput in MiB/s.
    pub fn throughput_mibs(&self) -> f64 {
        let secs = self.wall_time.as_secs_f64().max(1e-9);
        (self.bytes as f64) / (1024.0 * 1024.0) / secs
    }

    /// Files per second.
    pub fn files_per_sec(&self) -> f64 {
        let secs = self.wall_time.as_secs_f64().max(1e-9);
        self.files as f64 / secs
    }
}

// ============================================================================
// Benchmark Report
// ============================================================================

/// Complete benchmark report with aggregated statistics.
#[derive(Clone, Debug)]
pub struct BenchReport {
    /// Individual iteration results.
    pub iterations: Vec<BenchIter>,

    /// Benchmark configuration used.
    pub config: BenchConfig,

    /// Total wall time (sum of all iterations).
    pub total_wall_time: Duration,

    /// Percentile wall times.
    pub p50_wall: Duration,
    pub p95_wall: Duration,
    pub p99_wall: Duration,

    /// Peak RSS across all iterations.
    pub peak_rss_bytes: u64,

    /// Total CPU time (user + system) across iterations.
    pub total_cpu_time: Duration,
}

impl BenchReport {
    /// Computes aggregate statistics from iterations.
    ///
    /// # Complexity
    ///
    /// O(n log n) where n = `iterations.len()` due to percentile sorting.
    ///
    /// # Panics
    ///
    /// Does not panic on empty `iterations`, but percentiles will be `Duration::ZERO`.
    pub fn from_iterations(iterations: Vec<BenchIter>, config: BenchConfig) -> Self {
        let total_wall_time: Duration = iterations.iter().map(|i| i.wall_time).sum();

        let mut walls: Vec<Duration> = iterations.iter().map(|i| i.wall_time).collect();
        walls.sort();

        let p50_wall = percentile(&walls, 0.50);
        let p95_wall = percentile(&walls, 0.95);
        let p99_wall = percentile(&walls, 0.99);

        let peak_rss_bytes = iterations
            .iter()
            .map(|i| i.cpu_usage.ending_max_rss_bytes)
            .max()
            .unwrap_or(0);

        let total_cpu_time: Duration = iterations
            .iter()
            .map(|i| i.cpu_usage.total_cpu_time())
            .sum();

        Self {
            iterations,
            config,
            total_wall_time,
            p50_wall,
            p95_wall,
            p99_wall,
            peak_rss_bytes,
            total_cpu_time,
        }
    }

    /// Aggregate throughput in MiB/s (median iteration).
    pub fn median_throughput_mibs(&self) -> f64 {
        if self.iterations.is_empty() {
            return 0.0;
        }
        let mut throughputs: Vec<f64> = self
            .iterations
            .iter()
            .map(|i| i.throughput_mibs())
            .collect();
        throughputs.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let mid = throughputs.len() / 2;
        throughputs[mid]
    }

    /// Total files processed across all iterations.
    pub fn total_files(&self) -> u64 {
        self.iterations.iter().map(|i| i.files).sum()
    }

    /// Total bytes processed across all iterations.
    pub fn total_bytes(&self) -> u64 {
        self.iterations.iter().map(|i| i.bytes).sum()
    }

    /// Total findings across all iterations.
    pub fn total_findings(&self) -> u64 {
        self.iterations.iter().map(|i| i.findings).sum()
    }

    /// Total errors across all iterations.
    pub fn total_errors(&self) -> u64 {
        self.iterations.iter().map(|i| i.errors).sum()
    }

    /// Returns a CI-friendly summary string.
    ///
    /// Format is stable for parsing by CI scripts.
    /// No paths or sensitive data included.
    pub fn summary(&self) -> String {
        format!(
            "bench_summary: iters={} p50_ms={:.1} p95_ms={:.1} p99_ms={:.1} \
             throughput_mibs={:.1} peak_rss_mb={:.1} total_files={} \
             total_bytes={} total_findings={} total_errors={}",
            self.iterations.len(),
            self.p50_wall.as_secs_f64() * 1000.0,
            self.p95_wall.as_secs_f64() * 1000.0,
            self.p99_wall.as_secs_f64() * 1000.0,
            self.median_throughput_mibs(),
            self.peak_rss_bytes as f64 / (1024.0 * 1024.0),
            self.total_files(),
            self.total_bytes(),
            self.total_findings(),
            self.total_errors(),
        )
    }

    /// Returns detailed per-iteration output.
    pub fn detailed(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "Benchmark: {} warmup + {} measured iterations\n",
            self.config.warmup_iters,
            self.iterations.len()
        ));
        out.push_str(&format!("Pin: {:?}\n\n", self.config.pin_core));

        out.push_str("Per-iteration:\n");
        for (i, iter) in self.iterations.iter().enumerate() {
            out.push_str(&format!(
                "  {:2}: wall={:6.1}ms  MiB/s={:6.1}  files/s={:6.0}  files={}  bytes={}\n",
                i,
                iter.wall_time.as_secs_f64() * 1000.0,
                iter.throughput_mibs(),
                iter.files_per_sec(),
                iter.files,
                iter.bytes,
            ));
        }

        out.push_str("\nSummary:\n");
        out.push_str(&format!(
            "  p50={:.1}ms  p95={:.1}ms  p99={:.1}ms\n",
            self.p50_wall.as_secs_f64() * 1000.0,
            self.p95_wall.as_secs_f64() * 1000.0,
            self.p99_wall.as_secs_f64() * 1000.0,
        ));
        out.push_str(&format!(
            "  median_throughput={:.1} MiB/s\n",
            self.median_throughput_mibs()
        ));
        out.push_str(&format!(
            "  peak_rss={:.1} MiB\n",
            self.peak_rss_bytes as f64 / (1024.0 * 1024.0)
        ));
        out.push_str(&format!(
            "  cpu_time={:.3}s (user+sys)\n",
            self.total_cpu_time.as_secs_f64()
        ));

        out
    }
}

impl std::fmt::Display for BenchReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.summary())
    }
}

// ============================================================================
// Percentile Calculation
// ============================================================================

/// Computes a percentile from a sorted slice using nearest-rank method.
///
/// # Algorithm
///
/// Uses rounding to nearest index: `idx = round((len - 1) * p)`.
/// This gives the nearest-rank percentile, not linear interpolation.
///
/// # Preconditions
///
/// - `sorted` must be sorted in ascending order (not verified).
/// - `p` is clamped to [0.0, 1.0].
///
/// # Returns
///
/// - `Duration::ZERO` if `sorted` is empty.
/// - The value at the computed percentile index otherwise.
fn percentile(sorted: &[Duration], p: f64) -> Duration {
    if sorted.is_empty() {
        return Duration::ZERO;
    }
    let p = p.clamp(0.0, 1.0);
    let idx = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

// ============================================================================
// Benchmark Runner
// ============================================================================

/// Trait for things that can be benchmarked.
///
/// Implementations must provide:
/// - A way to reset/prepare for the next iteration
/// - A way to run one iteration
/// - A way to extract stats from the run
///
/// # Lifecycle
///
/// The benchmark harness calls methods in this order:
///
/// ```text
/// for _ in 0..warmup_iters:
///     reset() → run()  // results discarded
///
/// for _ in 0..measured_iters:
///     reset() → run() → extract_metrics()
/// ```
///
/// # Implementor Guidelines
///
/// - `reset()`: Prepare state for the next iteration. Called before EVERY run,
///   including warmups. Keep this cheap—it's not measured but adds overhead.
/// - `run()`: Execute the workload. Timer starts BEFORE this call.
/// - `extract_metrics()`: Convert your stats to `BenchIterMetrics`. Called once
///   per measured iteration after `run()` completes.
///
/// # Example
///
/// ```rust,ignore
/// impl Benchmarkable for MyBench {
///     type Stats = MyStats;
///
///     fn reset(&mut self) {
///         self.counter = 0;
///         self.data.clear();
///     }
///
///     fn run(&mut self) -> MyStats {
///         // Do the work
///         MyStats { items: self.process_all() }
///     }
///
///     fn extract_metrics(&self, stats: &MyStats) -> BenchIterMetrics {
///         BenchIterMetrics {
///             files: stats.items as u64,
///             ..Default::default()
///         }
///     }
/// }
/// ```
pub trait Benchmarkable {
    /// Stats returned by a single run.
    type Stats;

    /// Reset state for next iteration (e.g., recreate file source).
    fn reset(&mut self);

    /// Run one iteration, returning stats.
    fn run(&mut self) -> Self::Stats;

    /// Extract iteration metrics from stats.
    fn extract_metrics(&self, stats: &Self::Stats) -> BenchIterMetrics;
}

/// Metrics extracted from one benchmark iteration.
#[derive(Clone, Debug, Default)]
pub struct BenchIterMetrics {
    pub files: u64,
    pub bytes: u64,
    pub findings: u64,
    pub errors: u64,
}

/// Generic benchmark runner.
///
/// Handles warmup, CPU pinning, rusage capture, and report generation.
pub fn run_benchmark<B: Benchmarkable>(target: &mut B, config: BenchConfig) -> BenchReport {
    // Pin CPU if requested
    if let Some(core) = config.pin_core {
        let _ = super::affinity::pin_current_thread_to_core(core);
    }

    // Warmup iterations
    for _ in 0..config.warmup_iters {
        target.reset();
        let _ = target.run();
    }

    // Measured iterations
    let mut iterations = Vec::with_capacity(config.iters);

    for _ in 0..config.iters {
        target.reset();

        // NOTE: reset_alloc_stats() was removed - use snapshot deltas via since() instead
        // Allocation tracking is now done via AllocGuard for specific sections
        let _ = config.reset_alloc_stats; // Silently ignore this flag

        let usage_before = rusage_self();
        let t0 = Instant::now();

        let stats = target.run();

        let wall_time = t0.elapsed();
        let usage_after = rusage_self();

        let metrics = target.extract_metrics(&stats);
        let cpu_usage = usage_after.since(&usage_before);

        iterations.push(BenchIter {
            wall_time,
            cpu_usage,
            files: metrics.files,
            bytes: metrics.bytes,
            findings: metrics.findings,
            errors: metrics.errors,
        });
    }

    BenchReport::from_iterations(iterations, config)
}

// ============================================================================
// Stopwatch Utility
// ============================================================================

/// Simple stopwatch for manual timing sections.
#[derive(Debug)]
pub struct Stopwatch {
    start: Instant,
    usage_start: ProcUsage,
}

impl Stopwatch {
    /// Starts the stopwatch.
    pub fn start() -> Self {
        Self {
            start: Instant::now(),
            usage_start: rusage_self(),
        }
    }

    /// Returns elapsed time and CPU usage since start.
    pub fn elapsed(&self) -> (Duration, ProcUsageDelta) {
        let wall = self.start.elapsed();
        let usage = rusage_self().since(&self.usage_start);
        (wall, usage)
    }

    /// Lap: returns elapsed and resets.
    pub fn lap(&mut self) -> (Duration, ProcUsageDelta) {
        let wall = self.start.elapsed();
        let usage = rusage_self().since(&self.usage_start);
        self.start = Instant::now();
        self.usage_start = rusage_self();
        (wall, usage)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bench_config_defaults() {
        let cfg = BenchConfig::default();
        assert!(cfg.warmup_iters >= 1);
        assert!(cfg.iters >= 1);
    }

    #[test]
    fn percentile_calculation() {
        // Data: [1, 2, ..., 100] ms (100 elements)
        // percentile uses: idx = round((len-1) * p)
        // p=0.5: round(99 * 0.5) = round(49.5) = 50 → data[50] = 51ms
        // p=0.95: round(99 * 0.95) = round(94.05) = 94 → data[94] = 95ms
        // p=0.99: round(99 * 0.99) = round(98.01) = 98 → data[98] = 99ms
        let data: Vec<Duration> = (1..=100).map(Duration::from_millis).collect();

        assert_eq!(percentile(&data, 0.5), Duration::from_millis(51));
        assert_eq!(percentile(&data, 0.95), Duration::from_millis(95));
        assert_eq!(percentile(&data, 0.99), Duration::from_millis(99));
    }

    #[test]
    fn percentile_empty() {
        let data: Vec<Duration> = vec![];
        assert_eq!(percentile(&data, 0.5), Duration::ZERO);
    }

    #[test]
    fn percentile_single() {
        let data = vec![Duration::from_millis(42)];
        assert_eq!(percentile(&data, 0.0), Duration::from_millis(42));
        assert_eq!(percentile(&data, 0.5), Duration::from_millis(42));
        assert_eq!(percentile(&data, 1.0), Duration::from_millis(42));
    }

    #[test]
    fn bench_iter_throughput() {
        let iter = BenchIter {
            wall_time: Duration::from_secs(1),
            cpu_usage: ProcUsageDelta::default(),
            files: 100,
            bytes: 100 * 1024 * 1024, // 100 MiB
            findings: 5,
            errors: 0,
        };

        let throughput = iter.throughput_mibs();
        assert!(
            (throughput - 100.0).abs() < 0.1,
            "Expected ~100 MiB/s, got {}",
            throughput
        );

        let files_per_sec = iter.files_per_sec();
        assert!(
            (files_per_sec - 100.0).abs() < 0.1,
            "Expected ~100 files/s, got {}",
            files_per_sec
        );
    }

    #[test]
    fn bench_report_summary_format() {
        let iterations = vec![
            BenchIter {
                wall_time: Duration::from_millis(100),
                cpu_usage: ProcUsageDelta {
                    user_time: Duration::from_millis(80),
                    sys_time: Duration::from_millis(10),
                    ending_max_rss_bytes: 50 * 1024 * 1024,
                },
                files: 10,
                bytes: 10 * 1024 * 1024,
                findings: 5,
                errors: 1,
            },
            BenchIter {
                wall_time: Duration::from_millis(120),
                cpu_usage: ProcUsageDelta {
                    user_time: Duration::from_millis(90),
                    sys_time: Duration::from_millis(15),
                    ending_max_rss_bytes: 55 * 1024 * 1024,
                },
                files: 10,
                bytes: 10 * 1024 * 1024,
                findings: 4,
                errors: 0,
            },
        ];

        let report = BenchReport::from_iterations(iterations, BenchConfig::default());
        let summary = report.summary();

        // Verify summary contains expected fields (stable format)
        assert!(summary.starts_with("bench_summary:"));
        assert!(summary.contains("iters=2"));
        assert!(summary.contains("p50_ms="));
        assert!(summary.contains("p95_ms="));
        assert!(summary.contains("throughput_mibs="));
        assert!(summary.contains("peak_rss_mb="));
        assert!(summary.contains("total_files=20"));
        assert!(summary.contains("total_findings=9"));
        assert!(summary.contains("total_errors=1"));
    }

    #[test]
    fn stopwatch_basic() {
        let sw = Stopwatch::start();
        std::thread::sleep(Duration::from_millis(10));
        let (wall, _cpu) = sw.elapsed();

        // Wall time should be at least 10ms
        assert!(wall >= Duration::from_millis(9)); // Allow small variance
    }

    #[test]
    fn bench_iter_metrics_default() {
        let metrics = BenchIterMetrics::default();
        assert_eq!(metrics.files, 0);
        assert_eq!(metrics.bytes, 0);
    }

    #[test]
    fn bench_report_aggregates() {
        let iterations = vec![
            BenchIter {
                wall_time: Duration::from_millis(100),
                cpu_usage: ProcUsageDelta::default(),
                files: 10,
                bytes: 1000,
                findings: 5,
                errors: 1,
            },
            BenchIter {
                wall_time: Duration::from_millis(200),
                cpu_usage: ProcUsageDelta::default(),
                files: 20,
                bytes: 2000,
                findings: 10,
                errors: 2,
            },
        ];

        let report = BenchReport::from_iterations(iterations, BenchConfig::default());

        assert_eq!(report.total_files(), 30);
        assert_eq!(report.total_bytes(), 3000);
        assert_eq!(report.total_findings(), 15);
        assert_eq!(report.total_errors(), 3);
        assert_eq!(report.total_wall_time, Duration::from_millis(300));
    }
}
