//! Local Scan Benchmark Harness
//!
//! # Purpose
//!
//! Wraps `scan_local()` to implement `Benchmarkable`, enabling:
//! - Reproducible benchmarks with synthetic data
//! - Integration with `run_benchmark()` harness
//! - CI regression detection
//!
//! # What This Measures
//!
//! **CPU scan throughput** - NOT disk I/O performance.
//!
//! After the first iteration (or file generation), all files are in the OS page cache.
//! Subsequent iterations measure memory bandwidth and scan engine efficiency, not
//! filesystem performance. This is intentional for measuring scanner throughput.
//!
//! For I/O-bound benchmarks, you would need:
//! - Data larger than RAM
//! - Cache-drop between iterations (requires root)
//! - Different file sets per iteration
//!
//! # Benchmark Configurations
//!
//! ## Throughput Benchmark (recommended)
//!
//! Measures scan engine speed with minimal output overhead:
//! ```rust,ignore
//! let synthetic = SyntheticConfig {
//!     secret_density: 0.0,  // No secrets = no event sink contention
//!     ..SyntheticConfig::realistic()
//! };
//! ```
//!
//! ## Output-Heavy Benchmark
//!
//! Measures findings output path (will be slower due to sink contention):
//! ```rust,ignore
//! let synthetic = SyntheticConfig {
//!     secret_density: 0.01,  // High density stresses output path
//!     ..Default::default()
//! };
//! ```
//!
//! # Known Limitations
//!
//! - `reset()` clones the file path list (~24KB for 1000 files). This happens
//!   between iterations, not in the scan hot path.
//! - Finding counts come from the `LocalReport` metrics, which track
//!   `findings_emitted` via the structured `EventSink`.
//!
//! # Usage
//!
//! ```rust,ignore
//! let engine = Arc::new(MockEngine::new(rules, overlap));
//! let synthetic = SyntheticConfig::realistic();
//! let local_cfg = LocalConfig::default();
//!
//! let mut bench = LocalScanBenchmark::new(engine, synthetic, local_cfg)?;
//! let report = run_benchmark(&mut bench, BenchConfig::default());
//!
//! println!("{}", report.detailed());
//! ```

use super::local_fs_owner::{scan_local, FileSource, LocalConfig, LocalReport, VecFileSource};
use crate::scheduler::bench::{BenchIterMetrics, Benchmarkable};
use crate::scheduler::bench_synthetic::{SyntheticConfig, SyntheticFileSource};
use crate::scheduler::engine_stub::MockEngine;

use std::io;
use std::sync::Arc;

// ============================================================================
// Local Scan Benchmark
// ============================================================================

/// Benchmark wrapper for local filesystem scanning.
///
/// Implements `Benchmarkable` for use with `run_benchmark()`.
///
/// # Lifecycle
///
/// 1. `new()` - Generates synthetic files (one-time cost, not measured)
/// 2. `reset()` - Prepares for next iteration (recreates file source iterator)
/// 3. `run()` - Executes `scan_local()` and returns metrics
///
/// The benchmark harness calls `reset()` before each iteration automatically.
pub struct LocalScanBenchmark {
    /// Detection engine (shared across iterations).
    engine: Arc<MockEngine>,

    /// Local scan configuration.
    local_config: LocalConfig,

    /// Generated synthetic files.
    synthetic: SyntheticFileSource,

    /// Current file source (recreated on each reset).
    ///
    /// Invariant: `Some` after `reset()`, `None` after `run()`.
    current_source: Option<VecFileSource>,
}

impl LocalScanBenchmark {
    /// Creates a new benchmark with synthetic file generation.
    ///
    /// Files are generated immediately. Generation time is not included
    /// in benchmark measurements.
    ///
    /// # Errors
    ///
    /// Returns error if synthetic file generation fails (disk full, permissions).
    ///
    /// # Panics
    ///
    /// Panics if `local_config` is invalid (programmer error).
    /// `synthetic_config` validation failures are returned as `io::Error`.
    pub fn new(
        engine: Arc<MockEngine>,
        synthetic_config: SyntheticConfig,
        local_config: LocalConfig,
    ) -> io::Result<Self> {
        // Validate configs (panics on invalid - programmer error)
        synthetic_config
            .validate()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        local_config.validate(engine.as_ref());

        // Generate synthetic files
        let synthetic = SyntheticFileSource::generate(synthetic_config)?;

        Ok(Self {
            engine,
            local_config,
            synthetic,
            current_source: None,
        })
    }

    /// Creates a benchmark from pre-generated synthetic files.
    ///
    /// Useful when you want to reuse the same files across multiple
    /// benchmark configurations.
    pub fn from_synthetic(
        engine: Arc<MockEngine>,
        synthetic: SyntheticFileSource,
        local_config: LocalConfig,
    ) -> Self {
        local_config.validate(engine.as_ref());

        Self {
            engine,
            local_config,
            synthetic,
            current_source: None,
        }
    }

    /// Returns synthetic file generation statistics.
    pub fn synthetic_stats(&self) -> &crate::scheduler::bench_synthetic::GenerationStats {
        self.synthetic.stats()
    }

    /// Returns the engine.
    pub fn engine(&self) -> &Arc<MockEngine> {
        &self.engine
    }

    /// Returns a description of the benchmark configuration.
    pub fn description(&self) -> String {
        format!(
            "LocalScanBenchmark: {} files, {} bytes, {} workers, {} chunk",
            self.synthetic.stats().files_generated,
            self.synthetic.stats().bytes_written,
            self.local_config.workers,
            self.local_config.chunk_size,
        )
    }
}

impl Benchmarkable for LocalScanBenchmark {
    type Stats = LocalReport;

    fn reset(&mut self) {
        // Recreate file source iterator (files remain on disk).
        // Note: This clones the file path list. For 1000 files, ~24KB allocation.
        // Happens between iterations, not in scan hot path.
        self.current_source = Some(self.synthetic.file_source());
    }

    fn run(&mut self) -> LocalReport {
        let source = self
            .current_source
            .take()
            .expect("reset() must be called before run() - this is a bug in the benchmark harness");

        // Note: Files are in OS page cache after first iteration.
        // We're measuring CPU scan throughput, not disk I/O.
        scan_local(Arc::clone(&self.engine), source, self.local_config.clone())
    }

    fn extract_metrics(&self, stats: &LocalReport) -> BenchIterMetrics {
        BenchIterMetrics {
            files: stats.stats.files_enqueued,
            bytes: stats.metrics.bytes_scanned,
            findings: stats.metrics.findings_emitted,
            errors: 0,
        }
    }
}

// ============================================================================
// Custom Source Benchmark
// ============================================================================

/// Benchmark wrapper that accepts a custom file source factory.
///
/// Use this when you want to benchmark against real files or a custom
/// file discovery mechanism.
///
/// # Type Bounds
///
/// The factory must be `Send` because the benchmark may be run from
/// different threads. The returned `FileSource` is already `Send + 'static`
/// by trait definition.
pub struct CustomSourceBenchmark<F>
where
    F: Fn() -> Box<dyn FileSource> + Send,
{
    engine: Arc<MockEngine>,
    local_config: LocalConfig,
    source_factory: F,
    current_source: Option<Box<dyn FileSource>>,
}

impl<F> CustomSourceBenchmark<F>
where
    F: Fn() -> Box<dyn FileSource> + Send,
{
    pub fn new(engine: Arc<MockEngine>, local_config: LocalConfig, source_factory: F) -> Self {
        local_config.validate(engine.as_ref());

        Self {
            engine,
            local_config,
            source_factory,
            current_source: None,
        }
    }
}

impl<F> Benchmarkable for CustomSourceBenchmark<F>
where
    F: Fn() -> Box<dyn FileSource> + Send,
{
    type Stats = LocalReport;

    fn reset(&mut self) {
        self.current_source = Some((self.source_factory)());
    }

    fn run(&mut self) -> LocalReport {
        let source = self
            .current_source
            .take()
            .expect("reset() must be called before run()");

        // Adapter for Box<dyn FileSource> -> impl FileSource
        let adapter = BoxedFileSourceAdapter { inner: source };

        scan_local(Arc::clone(&self.engine), adapter, self.local_config.clone())
    }

    fn extract_metrics(&self, stats: &LocalReport) -> BenchIterMetrics {
        BenchIterMetrics {
            files: stats.stats.files_enqueued,
            bytes: stats.metrics.bytes_scanned,
            findings: stats.metrics.findings_emitted,
            errors: 0,
        }
    }
}

/// Adapter to use `Box<dyn FileSource>` with `scan_local`.
///
/// # Why This Exists
///
/// `scan_local()` takes `impl FileSource`, not `Box<dyn FileSource>`.
/// This adapter bridges that gap for `CustomSourceBenchmark` which
/// stores a boxed trait object from the user's factory function.
///
/// # Performance
///
/// Adds one vtable dispatch per `next_file()` call. Since this happens
/// once per file (not per byte), the overhead is negligible compared
/// to actual I/O and scanning work.
struct BoxedFileSourceAdapter {
    inner: Box<dyn FileSource>,
}

impl FileSource for BoxedFileSourceAdapter {
    fn next_file(&mut self) -> Option<super::local_fs_owner::LocalFile> {
        self.inner.next_file()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::ArchiveConfig;
    use crate::scheduler::bench::{run_benchmark, BenchConfig};
    use crate::scheduler::engine_stub::MockRule;

    fn test_engine() -> MockEngine {
        MockEngine::new(
            vec![MockRule {
                name: "secret".into(),
                pattern: b"SECRET".to_vec(),
            }],
            16,
        )
    }

    fn small_local_config() -> LocalConfig {
        LocalConfig {
            workers: 2,
            chunk_size: 1024,
            pool_buffers: 8,
            local_queue_cap: 2,
            max_in_flight_objects: 8,
            max_file_size: u64::MAX,
            seed: 12345,
            pin_threads: false,
            dedupe_within_chunk: true,
            archive: ArchiveConfig::default(),
            skip_binary: true,
            event_sink: Arc::new(crate::unified::events::NullEventSink),
            store_producer: None,
        }
    }

    #[test]
    fn local_scan_benchmark_creation() {
        let engine = Arc::new(test_engine());
        let synthetic = SyntheticConfig {
            file_count: 3,
            file_size: crate::scheduler::bench_synthetic::FileSizeDistribution::Fixed(512),
            secret_density: 0.1,
            seed: 12345,
            ..Default::default()
        };

        let bench = LocalScanBenchmark::new(engine, synthetic, small_local_config()).unwrap();

        if cfg!(all(feature = "perf-stats", debug_assertions)) {
            assert_eq!(bench.synthetic_stats().files_generated, 3);
        } else {
            assert_eq!(bench.synthetic_stats().files_generated, 0);
        }
    }

    #[test]
    fn local_scan_benchmark_runs() {
        let engine = Arc::new(test_engine());
        let synthetic = SyntheticConfig {
            file_count: 5,
            file_size: crate::scheduler::bench_synthetic::FileSizeDistribution::Fixed(1024),
            secret_density: 0.1,
            seed: 12345,
            ..Default::default()
        };

        let mut bench = LocalScanBenchmark::new(engine, synthetic, small_local_config()).unwrap();

        // Run with minimal config
        let config = BenchConfig {
            warmup_iters: 1,
            iters: 2,
            pin_core: None,
            reset_alloc_stats: false,
            seed: 12345,
        };

        let report = run_benchmark(&mut bench, config);

        assert_eq!(report.iterations.len(), 2);

        // Each iteration should scan all 5 files
        for iter in &report.iterations {
            assert!(
                iter.files >= 5,
                "iteration scanned {} files, expected >= 5",
                iter.files
            );
        }

        assert!(report.total_bytes() > 0);
    }

    #[test]
    fn benchmark_description() {
        let engine = Arc::new(test_engine());
        let synthetic = SyntheticConfig {
            file_count: 10,
            file_size: crate::scheduler::bench_synthetic::FileSizeDistribution::Fixed(2048),
            seed: 12345,
            ..Default::default()
        };

        let bench = LocalScanBenchmark::new(engine, synthetic, small_local_config()).unwrap();

        let desc = bench.description();
        if cfg!(all(feature = "perf-stats", debug_assertions)) {
            assert!(desc.contains("10 files"));
        } else {
            assert!(desc.contains("0 files"));
        }
        assert!(desc.contains("2 workers"));
    }

    #[test]
    #[should_panic(expected = "reset() must be called before run()")]
    fn run_without_reset_panics() {
        let engine = Arc::new(test_engine());
        let synthetic = SyntheticConfig {
            file_count: 1,
            file_size: crate::scheduler::bench_synthetic::FileSizeDistribution::Fixed(64),
            seed: 12345,
            ..Default::default()
        };

        let mut bench = LocalScanBenchmark::new(engine, synthetic, small_local_config()).unwrap();

        // Calling run() without reset() should panic
        let _ = bench.run();
    }
}
