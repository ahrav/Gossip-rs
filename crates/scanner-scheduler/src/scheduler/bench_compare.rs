//! Benchmark Comparison and Regression Detection
//!
//! # Purpose
//!
//! Compare benchmark results to detect performance regressions:
//! - Throughput regression (MiB/s)
//! - Latency regression (p50, p95, p99 wall time)
//! - Memory regression (peak RSS)
//!
//! # CI Integration
//!
//! ```rust,ignore
//! let baseline = BenchBaseline::from_report("my_bench", &report);
//! // ... save baseline ...
//!
//! // Later:
//! let comparison = BenchComparison::compare_baseline(&baseline, &current_report);
//! if comparison.has_regression(5.0) {  // 5% threshold
//!     eprintln!("REGRESSION DETECTED:\n{}", comparison.summary(5.0));
//!     std::process::exit(1);
//! }
//! ```
//!
//! # Threshold Semantics
//!
//! - **Throughput**: Decrease beyond threshold is regression (negative change)
//! - **Latency**: Increase beyond threshold is regression (positive change)
//! - **Memory**: Increase beyond threshold is regression (positive change)
//!
//! Default tolerance multipliers:
//! - Latency: 2x base threshold (more variable due to OS scheduling)
//! - Memory: 3x base threshold (RSS measurement is noisier)

use crate::scheduler::bench::BenchReport;
use std::sync::OnceLock;

// ============================================================================
// Tolerance Multipliers (documented rationale)
// ============================================================================

/// Latency measurements are more variable than throughput due to:
/// - OS scheduling jitter
/// - Cache effects
/// - Background processes
///
/// Using 2x threshold for latency comparisons.
const LATENCY_TOLERANCE_MULTIPLIER: f64 = 2.0;

/// RSS measurements are noisier due to:
/// - Allocator fragmentation
/// - Lazy page allocation
/// - Kernel memory accounting variations
///
/// Using 3x threshold for memory comparisons.
const MEMORY_TOLERANCE_MULTIPLIER: f64 = 3.0;

// ============================================================================
// Comparison Result
// ============================================================================

/// Comparison between baseline and current benchmark results.
///
/// All `*_change_pct` fields follow this convention:
/// - Positive = metric increased (good for throughput, bad for latency/memory)
/// - Negative = metric decreased (bad for throughput, good for latency/memory)
#[derive(Clone, Debug)]
pub struct BenchComparison {
    /// Throughput change (positive = faster, negative = slower).
    pub throughput_change_pct: f64,

    /// P50 latency change (positive = slower, negative = faster).
    pub p50_change_pct: f64,

    /// P95 latency change.
    pub p95_change_pct: f64,

    /// P99 latency change.
    pub p99_change_pct: f64,

    /// Peak RSS change (positive = more memory, negative = less).
    pub rss_change_pct: f64,

    /// Baseline throughput (MiB/s).
    pub baseline_throughput: f64,

    /// Current throughput (MiB/s).
    pub current_throughput: f64,

    /// Baseline p50 latency (ns).
    pub baseline_p50_ns: u64,

    /// Current p50 latency (ns).
    pub current_p50_ns: u64,

    /// Baseline peak RSS (bytes).
    pub baseline_rss: u64,

    /// Current peak RSS (bytes).
    pub current_rss: u64,

    /// Whether any metrics had invalid baselines (zero or non-finite).
    pub has_invalid_baseline: bool,
}

impl BenchComparison {
    /// Compare two benchmark reports directly.
    pub fn new(baseline: &BenchReport, current: &BenchReport) -> Self {
        // Preconditions (Tiger Style)
        debug_assert!(
            !baseline.iterations.is_empty(),
            "baseline must have at least one iteration"
        );
        debug_assert!(
            !current.iterations.is_empty(),
            "current must have at least one iteration"
        );

        let baseline_throughput = baseline.median_throughput_mibs();
        let current_throughput = current.median_throughput_mibs();

        let baseline_p50_ns = baseline.p50_wall.as_nanos() as u64;
        let baseline_p95_ns = baseline.p95_wall.as_nanos() as u64;
        let baseline_p99_ns = baseline.p99_wall.as_nanos() as u64;
        let current_p50_ns = current.p50_wall.as_nanos() as u64;
        let current_p95_ns = current.p95_wall.as_nanos() as u64;
        let current_p99_ns = current.p99_wall.as_nanos() as u64;

        let baseline_rss = baseline.peak_rss_bytes;
        let current_rss = current.peak_rss_bytes;

        let mut has_invalid_baseline = false;

        let throughput_change_pct = safe_pct_change(
            baseline_throughput,
            current_throughput,
            &mut has_invalid_baseline,
        );
        let p50_change_pct = safe_pct_change(
            baseline_p50_ns as f64,
            current_p50_ns as f64,
            &mut has_invalid_baseline,
        );
        let p95_change_pct = safe_pct_change(
            baseline_p95_ns as f64,
            current_p95_ns as f64,
            &mut has_invalid_baseline,
        );
        let p99_change_pct = safe_pct_change(
            baseline_p99_ns as f64,
            current_p99_ns as f64,
            &mut has_invalid_baseline,
        );
        let rss_change_pct = safe_pct_change(
            baseline_rss as f64,
            current_rss as f64,
            &mut has_invalid_baseline,
        );

        Self {
            throughput_change_pct,
            p50_change_pct,
            p95_change_pct,
            p99_change_pct,
            rss_change_pct,
            baseline_throughput,
            current_throughput,
            baseline_p50_ns,
            current_p50_ns,
            baseline_rss,
            current_rss,
            has_invalid_baseline,
        }
    }

    /// Compare a stored baseline against a current report.
    ///
    /// This is the preferred method for CI regression detection as it
    /// compares metrics directly without creating synthetic reports.
    pub fn compare_baseline(baseline: &BenchBaseline, current: &BenchReport) -> Self {
        debug_assert!(
            !current.iterations.is_empty(),
            "current must have at least one iteration"
        );

        let current_throughput = current.median_throughput_mibs();
        let current_p50_ns = current.p50_wall.as_nanos() as u64;
        let current_p95_ns = current.p95_wall.as_nanos() as u64;
        let current_p99_ns = current.p99_wall.as_nanos() as u64;
        let current_rss = current.peak_rss_bytes;

        let mut has_invalid_baseline = false;

        let throughput_change_pct = safe_pct_change(
            baseline.throughput_mibs,
            current_throughput,
            &mut has_invalid_baseline,
        );
        let p50_change_pct = safe_pct_change(
            baseline.p50_ns as f64,
            current_p50_ns as f64,
            &mut has_invalid_baseline,
        );
        let p95_change_pct = safe_pct_change(
            baseline.p95_ns as f64,
            current_p95_ns as f64,
            &mut has_invalid_baseline,
        );
        let p99_change_pct = safe_pct_change(
            baseline.p99_ns as f64,
            current_p99_ns as f64,
            &mut has_invalid_baseline,
        );
        let rss_change_pct = safe_pct_change(
            baseline.peak_rss_bytes as f64,
            current_rss as f64,
            &mut has_invalid_baseline,
        );

        Self {
            throughput_change_pct,
            p50_change_pct,
            p95_change_pct,
            p99_change_pct,
            rss_change_pct,
            baseline_throughput: baseline.throughput_mibs,
            current_throughput,
            baseline_p50_ns: baseline.p50_ns,
            current_p50_ns,
            baseline_rss: baseline.peak_rss_bytes,
            current_rss,
            has_invalid_baseline,
        }
    }

    /// Returns true if throughput regressed beyond threshold.
    ///
    /// Throughput decrease (negative change) is a regression.
    pub fn is_throughput_regression(&self, threshold_pct: f64) -> bool {
        debug_assert!(threshold_pct >= 0.0, "threshold must be non-negative");
        self.throughput_change_pct < -threshold_pct
    }

    /// Returns true if p50 latency regressed beyond threshold.
    pub fn is_p50_regression(&self, threshold_pct: f64) -> bool {
        debug_assert!(threshold_pct >= 0.0, "threshold must be non-negative");
        self.p50_change_pct > threshold_pct
    }

    /// Returns true if p99 latency regressed beyond threshold.
    pub fn is_p99_regression(&self, threshold_pct: f64) -> bool {
        debug_assert!(threshold_pct >= 0.0, "threshold must be non-negative");
        self.p99_change_pct > threshold_pct
    }

    /// Returns true if memory usage regressed beyond threshold.
    pub fn is_memory_regression(&self, threshold_pct: f64) -> bool {
        debug_assert!(threshold_pct >= 0.0, "threshold must be non-negative");
        self.rss_change_pct > threshold_pct
    }

    /// Returns true if ANY metric regressed beyond threshold.
    ///
    /// Uses tolerance multipliers for latency and memory (they're noisier).
    /// Also returns true if baseline had invalid (zero/non-finite) metrics.
    ///
    /// This is the recommended method for CI regression gates.
    pub fn has_regression(&self, threshold_pct: f64) -> bool {
        debug_assert!(threshold_pct >= 0.0, "threshold must be non-negative");

        // Invalid baseline is always a regression (can't compare reliably)
        if self.has_invalid_baseline {
            return true;
        }

        self.is_throughput_regression(threshold_pct)
            || self.is_p99_regression(threshold_pct * LATENCY_TOLERANCE_MULTIPLIER)
            || self.is_memory_regression(threshold_pct * MEMORY_TOLERANCE_MULTIPLIER)
    }

    /// Returns a human-readable summary with regression markers.
    ///
    /// Markers use the provided threshold (with tolerance multipliers for latency/memory).
    pub fn summary(&self, threshold_pct: f64) -> String {
        let mut s = String::with_capacity(512);

        if self.has_invalid_baseline {
            s.push_str("WARNING: Baseline contained invalid (zero) metrics\n\n");
        }

        s.push_str("Benchmark Comparison:\n");
        s.push_str(&format!(
            "  Throughput: {:.1} â†’ {:.1} MiB/s ({:+.1}%){}\n",
            self.baseline_throughput,
            self.current_throughput,
            self.throughput_change_pct,
            throughput_marker(self.throughput_change_pct, threshold_pct),
        ));
        s.push_str(&format!(
            "  P50 Latency: {:.2} â†’ {:.2} ms ({:+.1}%){}\n",
            self.baseline_p50_ns as f64 / 1_000_000.0,
            self.current_p50_ns as f64 / 1_000_000.0,
            self.p50_change_pct,
            latency_marker(
                self.p50_change_pct,
                threshold_pct * LATENCY_TOLERANCE_MULTIPLIER
            ),
        ));
        s.push_str(&format!(
            "  P99 Latency: {:+.1}%{}\n",
            self.p99_change_pct,
            latency_marker(
                self.p99_change_pct,
                threshold_pct * LATENCY_TOLERANCE_MULTIPLIER
            ),
        ));
        s.push_str(&format!(
            "  Peak RSS: {:.1} â†’ {:.1} MiB ({:+.1}%){}\n",
            self.baseline_rss as f64 / (1024.0 * 1024.0),
            self.current_rss as f64 / (1024.0 * 1024.0),
            self.rss_change_pct,
            memory_marker(
                self.rss_change_pct,
                threshold_pct * MEMORY_TOLERANCE_MULTIPLIER
            ),
        ));

        s
    }

    /// Returns a CI-friendly one-line summary.
    pub fn ci_summary(&self) -> String {
        format!(
            "bench_compare: throughput_pct={:+.1} p50_pct={:+.1} p99_pct={:+.1} rss_pct={:+.1} invalid_baseline={}",
            self.throughput_change_pct,
            self.p50_change_pct,
            self.p99_change_pct,
            self.rss_change_pct,
            self.has_invalid_baseline,
        )
    }
}

/// Calculate percentage change, tracking invalid baselines.
///
/// # Formula
///
/// `((current - baseline) / baseline) * 100`
///
/// # Invalid Baseline Handling
///
/// If `baseline` is zero or non-finite:
/// - Sets `*has_invalid = true`
/// - Returns `0.0` if `current` is also zero (no change from nothing)
/// - Returns `f64::INFINITY` otherwise (infinite increase from zero)
///
/// The infinity case signals that comparison is meaningless—you can't
/// compute a percentage change from a zero baseline.
fn safe_pct_change(baseline: f64, current: f64, has_invalid: &mut bool) -> f64 {
    if !baseline.is_finite() || baseline == 0.0 {
        *has_invalid = true;
        if current == 0.0 {
            0.0
        } else {
            f64::INFINITY
        }
    } else {
        ((current - baseline) / baseline) * 100.0
    }
}

/// Marker for throughput (decrease is regression).
fn throughput_marker(change_pct: f64, threshold: f64) -> &'static str {
    if change_pct < -threshold {
        " [REGRESSION]"
    } else if change_pct > threshold {
        " [improved]"
    } else {
        ""
    }
}

/// Marker for latency (increase is regression).
fn latency_marker(change_pct: f64, threshold: f64) -> &'static str {
    if change_pct > threshold {
        " [REGRESSION]"
    } else if change_pct < -threshold {
        " [improved]"
    } else {
        ""
    }
}

/// Marker for memory (increase is regression).
fn memory_marker(change_pct: f64, threshold: f64) -> &'static str {
    if change_pct > threshold {
        " [REGRESSION]"
    } else if change_pct < -threshold {
        " [improved]"
    } else {
        ""
    }
}

// ============================================================================
// Baseline Management
// ============================================================================

/// Serializable benchmark baseline for storage.
#[derive(Clone, Debug)]
pub struct BenchBaseline {
    /// Benchmark name/identifier.
    pub name: String,

    /// Throughput in MiB/s.
    pub throughput_mibs: f64,

    /// P50 latency in nanoseconds.
    pub p50_ns: u64,

    /// P95 latency in nanoseconds.
    pub p95_ns: u64,

    /// P99 latency in nanoseconds.
    pub p99_ns: u64,

    /// Peak RSS in bytes.
    pub peak_rss_bytes: u64,

    /// CPU utilization ratio (e.g., 3.87 = 3.87 cores average).
    pub cpu_utilization: f64,

    /// Iteration count used.
    pub iters: usize,

    /// Unix timestamp when baseline was captured.
    pub timestamp: String,

    /// Git commit hash (if available).
    pub git_commit: Option<String>,

    /// Configuration fingerprint for comparison validation.
    pub config_fingerprint: Option<String>,
}

impl BenchBaseline {
    /// Create a baseline from a benchmark report.
    pub fn from_report(name: impl Into<String>, report: &BenchReport) -> Self {
        debug_assert!(
            !report.iterations.is_empty(),
            "report must have at least one iteration"
        );

        Self {
            name: name.into(),
            throughput_mibs: report.median_throughput_mibs(),
            p50_ns: report.p50_wall.as_nanos() as u64,
            p95_ns: report.p95_wall.as_nanos() as u64,
            p99_ns: report.p99_wall.as_nanos() as u64,
            peak_rss_bytes: report.peak_rss_bytes,
            // CPU utilization = total CPU time / total wall time
            cpu_utilization: if report.total_wall_time.as_secs_f64() > 0.0 {
                report.total_cpu_time.as_secs_f64() / report.total_wall_time.as_secs_f64()
            } else {
                0.0
            },
            iters: report.iterations.len(),
            timestamp: unix_timestamp_now(),
            git_commit: git_commit_hash_cached(),
            config_fingerprint: None,
        }
    }

    /// Create a baseline with a config fingerprint.
    pub fn from_report_with_config(
        name: impl Into<String>,
        report: &BenchReport,
        config_fingerprint: impl Into<String>,
    ) -> Self {
        let mut baseline = Self::from_report(name, report);
        baseline.config_fingerprint = Some(config_fingerprint.into());
        baseline
    }
}

/// Get current Unix timestamp as string.
fn unix_timestamp_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();

    format!("{}", duration.as_secs())
}

/// Get git commit hash (cached, only shells out once).
fn git_commit_hash_cached() -> Option<String> {
    static GIT_HASH: OnceLock<Option<String>> = OnceLock::new();

    GIT_HASH
        .get_or_init(|| {
            std::process::Command::new("git")
                .args(["rev-parse", "HEAD"])
                .output()
                .ok()
                .filter(|o| o.status.success())
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        })
        .clone()
}

// ============================================================================
// Multi-Benchmark Comparison
// ============================================================================

/// Compare multiple benchmarks at once.
///
/// Useful for CI pipelines that run several benchmark suites and need
/// a unified regression check.
///
/// # Example
///
/// ```rust,ignore
/// let mut multi = MultiComparison::new();
/// multi.add("local_scan", BenchComparison::new(&baseline1, &current1));
/// multi.add("executor", BenchComparison::new(&baseline2, &current2));
///
/// if multi.any_regression(5.0) {
///     eprintln!("Regressions in: {:?}", multi.regressed(5.0));
///     std::process::exit(1);
/// }
/// ```
#[derive(Clone, Debug, Default)]
pub struct MultiComparison {
    pub comparisons: Vec<(String, BenchComparison)>,
}

impl MultiComparison {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a comparison.
    pub fn add(&mut self, name: impl Into<String>, comparison: BenchComparison) {
        self.comparisons.push((name.into(), comparison));
    }

    /// Check if any benchmark has a regression (any metric).
    ///
    /// Uses `has_regression()` which checks throughput, latency, and memory.
    pub fn any_regression(&self, threshold_pct: f64) -> bool {
        self.comparisons
            .iter()
            .any(|(_, c)| c.has_regression(threshold_pct))
    }

    /// Get names of regressed benchmarks.
    pub fn regressed(&self, threshold_pct: f64) -> Vec<&str> {
        self.comparisons
            .iter()
            .filter(|(_, c)| c.has_regression(threshold_pct))
            .map(|(name, _)| name.as_str())
            .collect()
    }

    /// Summary of all comparisons.
    pub fn summary(&self, threshold_pct: f64) -> String {
        let mut s = String::new();
        for (name, comparison) in &self.comparisons {
            s.push_str(&format!("=== {} ===\n", name));
            s.push_str(&comparison.summary(threshold_pct));
            s.push('\n');
        }
        s
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheduler::bench::{BenchConfig, BenchIter, BenchReport};
    use std::time::Duration;

    fn make_report(throughput_mibs: f64, p50_ms: f64, rss_mb: f64) -> BenchReport {
        let wall_time = Duration::from_millis(p50_ms as u64);
        let bytes = (throughput_mibs * 1024.0 * 1024.0 * p50_ms / 1000.0) as u64;

        let iter = BenchIter {
            wall_time,
            cpu_usage: crate::scheduler::rusage::ProcUsageDelta {
                user_time: wall_time,
                sys_time: Duration::ZERO,
                ending_max_rss_bytes: (rss_mb * 1024.0 * 1024.0) as u64,
            },
            files: 100,
            bytes,
            findings: 0,
            errors: 0,
        };

        BenchReport::from_iterations(vec![iter], BenchConfig::default())
    }

    #[test]
    fn no_regression() {
        let baseline = make_report(100.0, 50.0, 100.0);
        let current = make_report(100.0, 50.0, 100.0);

        let comparison = BenchComparison::new(&baseline, &current);

        assert!(!comparison.has_regression(5.0));
        assert!(comparison.throughput_change_pct.abs() < 1.0);
        assert!(!comparison.has_invalid_baseline);
    }

    #[test]
    fn throughput_regression() {
        let baseline = make_report(100.0, 50.0, 100.0);
        let current = make_report(90.0, 50.0, 100.0); // 10% slower

        let comparison = BenchComparison::new(&baseline, &current);

        assert!(comparison.is_throughput_regression(5.0));
        assert!(comparison.has_regression(5.0));
    }

    #[test]
    fn latency_regression() {
        let baseline = make_report(100.0, 50.0, 100.0);
        let current = make_report(100.0, 75.0, 100.0); // 50% slower latency

        let comparison = BenchComparison::new(&baseline, &current);

        // With 5% threshold and 2x multiplier, latency threshold is 10%
        // 50% > 10%, so this is a regression
        assert!(comparison.is_p50_regression(10.0));
        assert!(comparison.has_regression(5.0)); // Uses 5% * 2 = 10% for latency
    }

    #[test]
    fn memory_regression() {
        let baseline = make_report(100.0, 50.0, 100.0);
        let current = make_report(100.0, 50.0, 150.0); // 50% more memory

        let comparison = BenchComparison::new(&baseline, &current);

        // With 5% threshold and 3x multiplier, memory threshold is 15%
        // 50% > 15%, so this is a regression
        assert!(comparison.is_memory_regression(15.0));
        assert!(comparison.has_regression(5.0)); // Uses 5% * 3 = 15% for memory
    }

    #[test]
    fn zero_baseline_flagged_as_invalid() {
        let baseline = make_report(0.0, 50.0, 100.0); // Zero throughput!
        let current = make_report(100.0, 50.0, 100.0);

        let comparison = BenchComparison::new(&baseline, &current);

        assert!(comparison.has_invalid_baseline);
        assert!(comparison.has_regression(5.0)); // Invalid baseline = regression
    }

    #[test]
    fn compare_baseline_directly() {
        let report = make_report(100.0, 50.0, 100.0);
        let baseline = BenchBaseline::from_report("test", &report);

        // Same data should show no change
        let comparison = BenchComparison::compare_baseline(&baseline, &report);

        assert!(!comparison.has_regression(5.0));
        assert!(comparison.throughput_change_pct.abs() < 0.1);
    }

    #[test]
    fn summary_markers_consistent_with_threshold() {
        let baseline = make_report(100.0, 50.0, 100.0);
        let current = make_report(90.0, 50.0, 100.0); // 10% throughput regression

        let comparison = BenchComparison::new(&baseline, &current);

        // At 5% threshold, should show regression marker
        let summary_5 = comparison.summary(5.0);
        assert!(summary_5.contains("[REGRESSION]"));

        // At 15% threshold, should NOT show regression marker
        let summary_15 = comparison.summary(15.0);
        assert!(!summary_15.contains("[REGRESSION]"));
    }

    #[test]
    fn multi_comparison_checks_all_metrics() {
        let baseline = make_report(100.0, 50.0, 100.0);

        // Throughput ok, but memory regressed
        let memory_regression = make_report(100.0, 50.0, 200.0); // 100% more memory

        let mut multi = MultiComparison::new();
        multi.add(
            "bench_a",
            BenchComparison::new(&baseline, &memory_regression),
        );

        // Should detect memory regression even though throughput is fine
        assert!(multi.any_regression(5.0));
        assert_eq!(multi.regressed(5.0), vec!["bench_a"]);
    }

    #[test]
    fn ci_summary_parseable() {
        let baseline = make_report(100.0, 50.0, 100.0);
        let current = make_report(95.0, 52.0, 105.0);

        let comparison = BenchComparison::new(&baseline, &current);
        let ci = comparison.ci_summary();

        assert!(ci.starts_with("bench_compare:"));
        assert!(ci.contains("throughput_pct="));
        assert!(ci.contains("invalid_baseline=false"));
    }

    #[test]
    fn baseline_with_config() {
        let report = make_report(100.0, 50.0, 100.0);
        let baseline =
            BenchBaseline::from_report_with_config("test", &report, "local:workers=4,files=100");

        assert_eq!(
            baseline.config_fingerprint.as_deref(),
            Some("local:workers=4,files=100")
        );
    }

    #[test]
    fn git_hash_cached() {
        // Call twice to verify caching
        let hash1 = git_commit_hash_cached();
        let hash2 = git_commit_hash_cached();

        // Should be identical (and fast due to caching)
        assert_eq!(hash1, hash2);
    }
}
