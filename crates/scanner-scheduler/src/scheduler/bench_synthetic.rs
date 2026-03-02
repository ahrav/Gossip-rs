//! Synthetic File Generation for Benchmarks
//!
//! # Purpose
//!
//! Generate synthetic files with controllable characteristics for benchmarking:
//! - File count and size distribution
//! - Secret injection density
//! - Deterministic generation via seed
//!
//! # What This Measures
//!
//! **CPU scan throughput** - NOT disk I/O performance.
//!
//! Files are written to a temp directory and remain in the OS page cache,
//! so scanning measures memoryâ†’CPU throughput. This is intentional for
//! benchmarking the scanner's processing speed.
//!
//! # Secret Density
//!
//! `secret_density` controls secrets per kilobyte of file content.
//! - `0.001` = ~1 secret per megabyte (default, low density)
//! - `0.01` = ~1 secret per 100KB (medium density)
//! - `0.1` = ~1 secret per 10KB (high density for stress testing)
//!
//! Note: At high densities, secrets may overlap and overwrite each other.
//! The `secrets_injected` count reflects injection attempts, not necessarily
//! surviving distinct patterns. For accurate recall testing, use low density.
//!
//! # Determinism
//!
//! With the same seed, file sizes and content are deterministic on the same
//! platform. Cross-platform determinism is NOT guaranteed due to floating-point
//! differences in size distribution sampling.

use super::local_fs_owner::{LocalFile, VecFileSource};
use super::rng::XorShift64;
use crate::perf_stats;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for synthetic file generation.
#[derive(Clone, Debug)]
pub struct SyntheticConfig {
    /// Number of files to generate.
    pub file_count: usize,

    /// Distribution of file sizes.
    pub file_size: FileSizeDistribution,

    /// Secret injection density (secrets per KB).
    /// Default: 0.001 (~1 secret per MB)
    pub secret_density: f64,

    /// Secret patterns to inject.
    /// Default: ["SECRET", "PASSWORD", "API_KEY"]
    pub secret_patterns: Vec<Vec<u8>>,

    /// Random seed for deterministic generation.
    pub seed: u64,

    /// Whether to fsync each file (default: false).
    /// Only enable if testing durability, not scan throughput.
    pub fsync: bool,
}

impl Default for SyntheticConfig {
    fn default() -> Self {
        Self {
            file_count: 100,
            file_size: FileSizeDistribution::Fixed(64 * 1024), // 64 KiB
            secret_density: 0.001,                             // ~1 secret per MB
            secret_patterns: vec![],
            seed: 0xDEADBEEF,
            fsync: false, // Don't fsync by default (benchmark mode)
        }
    }
}

impl SyntheticConfig {
    /// Quick configuration for CI (small, fast).
    pub fn quick() -> Self {
        Self {
            file_count: 50,
            file_size: FileSizeDistribution::Fixed(4 * 1024), // 4 KiB
            secret_density: 0.001,
            ..Default::default()
        }
    }

    /// Realistic configuration for profiling.
    pub fn realistic() -> Self {
        Self {
            file_count: 1000,
            file_size: FileSizeDistribution::Uniform {
                min: 1024,       // 1 KiB
                max: 256 * 1024, // 256 KiB
            },
            secret_density: 0.005,
            ..Default::default()
        }
    }

    /// Stress configuration for high-load testing.
    pub fn stress() -> Self {
        Self {
            file_count: 10_000,
            file_size: FileSizeDistribution::Exponential {
                base: 1024,       // 1 KiB minimum
                scale: 64 * 1024, // Average ~64 KiB
            },
            secret_density: 0.01,
            ..Default::default()
        }
    }

    /// Validate configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.file_count == 0 {
            return Err("file_count must be > 0".into());
        }
        if self.secret_density < 0.0 {
            return Err("secret_density must be >= 0".into());
        }
        if self.secret_density > 1.0 {
            return Err("secret_density > 1.0 is likely a mistake (1 = 1 secret per byte)".into());
        }
        self.file_size.validate()?;
        Ok(())
    }

    /// Estimate total bytes (for progress reporting).
    pub fn estimated_total_bytes(&self) -> u64 {
        let avg_size = self.file_size.average_size();
        (self.file_count as u64).saturating_mul(avg_size as u64)
    }
}

/// File size distribution.
#[derive(Clone, Debug)]
pub enum FileSizeDistribution {
    /// All files have the same size.
    Fixed(usize),

    /// Uniform distribution between min and max.
    Uniform { min: usize, max: usize },

    /// Exponential distribution with base minimum and scale.
    /// Size = base + Exp(1/scale), capped at base + 10*scale.
    Exponential { base: usize, scale: usize },
}

impl FileSizeDistribution {
    /// Sample a size from the distribution.
    pub fn sample(&self, rng: &mut XorShift64) -> usize {
        match self {
            Self::Fixed(size) => *size,
            Self::Uniform { min, max } => {
                if min >= max {
                    return *min;
                }
                let range = max - min;
                // Modulo reduction (slightly biased for non-power-of-two ranges)
                let r = rng.next_u64();
                min + (r as usize % (range + 1))
            }
            Self::Exponential { base, scale } => {
                if *scale == 0 {
                    return *base;
                }
                // Generate uniform in (0, 1], avoiding ln(0)
                let r = loop {
                    let raw = rng.next_u64();
                    if raw > 0 {
                        break (raw as f64) / (u64::MAX as f64);
                    }
                    // Raw was 0, retry (extremely rare)
                };
                let exp_val = (-r.ln() * (*scale as f64)) as usize;
                // Cap at 10x scale to avoid extreme outliers
                base + exp_val.min(scale.saturating_mul(10))
            }
        }
    }

    /// Average size for estimation.
    pub fn average_size(&self) -> usize {
        match self {
            Self::Fixed(size) => *size,
            Self::Uniform { min, max } => (min + max) / 2,
            Self::Exponential { base, scale } => base + scale,
        }
    }

    /// Validate distribution parameters.
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::Fixed(size) => {
                if *size == 0 {
                    return Err("Fixed size must be > 0".into());
                }
            }
            Self::Uniform { min, max } => {
                if *min == 0 {
                    return Err("Uniform min must be > 0".into());
                }
                if *min > *max {
                    return Err("Uniform min must be <= max".into());
                }
            }
            Self::Exponential { base, scale } => {
                if *base == 0 {
                    return Err("Exponential base must be > 0".into());
                }
                if *scale == 0 {
                    return Err("Exponential scale must be > 0".into());
                }
            }
        }
        Ok(())
    }
}

// ============================================================================
// Generation Statistics
// ============================================================================

/// Statistics from synthetic file generation.
///
/// Populated only when `perf-stats` is enabled in debug builds.
#[derive(Clone, Debug, Default)]
pub struct GenerationStats {
    /// Number of files generated.
    pub files_generated: usize,

    /// Total bytes written.
    pub bytes_written: u64,

    /// Number of secrets injected (attempts, may overlap).
    pub secrets_injected: usize,

    /// Generation time in milliseconds.
    pub generation_ms: u64,
}

// ============================================================================
// Unique Temp Directory
// ============================================================================

/// Global counter for unique temp directories within a process.
static TEMP_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Generate a unique temp directory path.
fn unique_temp_dir(seed: u64) -> PathBuf {
    let counter = TEMP_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "bench_synthetic_{}_{}_{}",
        std::process::id(),
        counter,
        seed
    ))
}

// ============================================================================
// Synthetic File Source
// ============================================================================

/// Synthetic file source that generates files on disk.
pub struct SyntheticFileSource {
    /// Directory containing generated files.
    temp_dir: PathBuf,

    /// List of generated files (shared via `Arc`).
    files: Arc<[LocalFile]>,

    /// Configuration used.
    config: SyntheticConfig,

    /// Generation statistics.
    stats: GenerationStats,
}

impl SyntheticFileSource {
    /// Generate synthetic files according to configuration.
    pub fn generate(config: SyntheticConfig) -> io::Result<Self> {
        config
            .validate()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        let start = std::time::Instant::now();

        // Create unique temp directory
        let temp_dir = unique_temp_dir(config.seed);
        fs::create_dir_all(&temp_dir)?;

        let mut rng = XorShift64::new(config.seed);
        let mut files = Vec::with_capacity(config.file_count);
        let mut stats = GenerationStats::default();

        // Default patterns if none specified
        let patterns: Vec<&[u8]> = if config.secret_patterns.is_empty() {
            vec![b"SECRET", b"PASSWORD", b"API_KEY"]
        } else {
            config
                .secret_patterns
                .iter()
                .map(|p| p.as_slice())
                .collect()
        };

        for i in 0..config.file_count {
            let size = config.file_size.sample(&mut rng);
            let filename = format!("file_{:06}.txt", i);
            let path = temp_dir.join(&filename);

            let secrets = generate_file_on_disk(
                &path,
                size,
                config.secret_density,
                &patterns,
                &mut rng,
                config.fsync,
            )?;

            files.push(LocalFile {
                path,
                size: size as u64,
            });

            perf_stats::sat_add_usize(&mut stats.files_generated, 1);
            perf_stats::sat_add_u64(&mut stats.bytes_written, size as u64);
            perf_stats::sat_add_usize(&mut stats.secrets_injected, secrets);
        }

        perf_stats::set_u64(&mut stats.generation_ms, start.elapsed().as_millis() as u64);

        Ok(Self {
            temp_dir,
            files: files.into(),
            config,
            stats,
        })
    }

    /// Get the temp directory path.
    pub fn temp_dir(&self) -> &Path {
        &self.temp_dir
    }

    /// Get generation statistics.
    pub fn stats(&self) -> &GenerationStats {
        &self.stats
    }

    /// Get configuration used.
    pub fn config(&self) -> &SyntheticConfig {
        &self.config
    }

    /// Create a file source for scanning.
    ///
    /// Clones the file list via `Arc::to_vec()` (deep copy of paths, not
    /// file contents). For 1000 files this is ~24 KB — negligible between
    /// benchmark iterations.
    pub fn file_source(&self) -> VecFileSource {
        VecFileSource::from_arc(Arc::clone(&self.files))
    }

    /// Get file count.
    pub fn file_count(&self) -> usize {
        self.files.len()
    }

    /// Get total bytes.
    pub fn total_bytes(&self) -> u64 {
        self.stats.bytes_written
    }
}

impl Drop for SyntheticFileSource {
    fn drop(&mut self) {
        // Clean up temp directory
        if self.temp_dir.exists() {
            let _ = fs::remove_dir_all(&self.temp_dir);
        }
    }
}

// ============================================================================
// Content Generation (shared between disk and in-memory)
// ============================================================================

/// Fill buffer with random printable ASCII content.
///
/// # Content Generation
///
/// - Each byte is uniformly sampled from printable ASCII (0x20 to 0x7E).
/// - Newlines (`\n`) are inserted every 80 characters for realism,
///   simulating typical source code or log file line lengths.
///
/// # Performance
///
/// Generates content byte-by-byte. For very large files, this could be
/// optimized with SIMD or larger random word extraction, but generation
/// time is typically negligible compared to benchmark measurement time.
fn fill_random_ascii(content: &mut [u8], rng: &mut XorShift64) {
    for byte in content.iter_mut() {
        // Printable ASCII: 0x20 (space) to 0x7E (~)
        *byte = (rng.next_u64() % 95) as u8 + 0x20;
    }

    // Add newlines for realism (every ~80 chars)
    for i in (80..content.len()).step_by(80) {
        content[i] = b'\n';
    }
}

/// Inject secrets into content buffer.
///
/// # Algorithm
///
/// Uses Poisson-like sampling to determine secret count:
///
/// ```text
/// lambda = (size_in_bytes / 1024) * density
/// count = floor(lambda) + Bernoulli(frac(lambda))
/// ```
///
/// This gives an expected count of `lambda` secrets per file, with some
/// variance. The Bernoulli term handles the fractional part probabilistically.
///
/// # Returns
///
/// Number of secrets injected (attempts). At high densities, secrets may
/// overlap and overwrite each other, so actual distinct patterns may be fewer.
///
/// # Preconditions
///
/// - `patterns` must not be empty (returns 0 if empty).
/// - `density` must be positive (returns 0 if <= 0).
fn inject_secrets(
    content: &mut [u8],
    density: f64,
    patterns: &[&[u8]],
    rng: &mut XorShift64,
) -> usize {
    if patterns.is_empty() || density <= 0.0 || content.is_empty() {
        return 0;
    }

    let size = content.len();

    // Calculate expected secret count using Poisson-like sampling:
    // lambda = size_kb * density
    // count = floor(lambda) + Bernoulli(frac(lambda))
    let lambda = (size as f64 / 1024.0) * density;
    let floor_lambda = lambda.floor() as usize;
    let frac_lambda = lambda - floor_lambda as f64;

    let count = if frac_lambda > 0.0 {
        let r = (rng.next_u64() as f64) / (u64::MAX as f64);
        if r < frac_lambda {
            floor_lambda + 1
        } else {
            floor_lambda
        }
    } else {
        floor_lambda
    };

    let mut secrets_injected = 0;

    for _ in 0..count {
        let pattern = patterns[rng.next_u64() as usize % patterns.len()];

        if size < pattern.len() {
            continue;
        }

        let pos = rng.next_u64() as usize % (size - pattern.len());

        // Inject (may overlap with previous secrets at high density)
        debug_assert!(pos + pattern.len() <= content.len());
        content[pos..pos + pattern.len()].copy_from_slice(pattern);
        secrets_injected += 1;
    }

    secrets_injected
}

/// Generate a file on disk.
fn generate_file_on_disk(
    path: &Path,
    size: usize,
    density: f64,
    patterns: &[&[u8]],
    rng: &mut XorShift64,
    fsync: bool,
) -> io::Result<usize> {
    let mut content = vec![0u8; size];

    fill_random_ascii(&mut content, rng);
    let secrets = inject_secrets(&mut content, density, patterns, rng);

    let mut file = File::create(path)?;
    file.write_all(&content)?;

    if fsync {
        file.sync_all()?;
    }

    Ok(secrets)
}

// ============================================================================
// In-Memory Generation
// ============================================================================

/// In-memory file for testing without disk I/O.
#[derive(Clone, Debug)]
pub struct InMemoryFile {
    pub name: String,
    pub content: Vec<u8>,
}

/// Generate files in memory (for unit tests).
pub fn generate_in_memory_files(config: &SyntheticConfig) -> Vec<InMemoryFile> {
    let mut rng = XorShift64::new(config.seed);

    let patterns: Vec<&[u8]> = if config.secret_patterns.is_empty() {
        vec![b"SECRET", b"PASSWORD", b"API_KEY"]
    } else {
        config
            .secret_patterns
            .iter()
            .map(|p| p.as_slice())
            .collect()
    };

    (0..config.file_count)
        .map(|i| {
            let size = config.file_size.sample(&mut rng);
            let mut content = vec![0u8; size];

            fill_random_ascii(&mut content, &mut rng);
            inject_secrets(&mut content, config.secret_density, &patterns, &mut rng);

            InMemoryFile {
                name: format!("file_{:06}.txt", i),
                content,
            }
        })
        .collect()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_validation() {
        let mut config = SyntheticConfig::default();
        assert!(config.validate().is_ok());

        config.file_count = 0;
        assert!(config.validate().is_err());

        config.file_count = 10;
        config.secret_density = -1.0;
        assert!(config.validate().is_err());

        config.secret_density = 2.0; // > 1.0 is suspicious
        assert!(config.validate().is_err());
    }

    #[test]
    fn unique_temp_dirs() {
        // Two sources should get different directories
        let config = SyntheticConfig::quick();

        let source1 = SyntheticFileSource::generate(config.clone()).unwrap();
        let source2 = SyntheticFileSource::generate(config.clone()).unwrap();

        assert_ne!(source1.temp_dir(), source2.temp_dir());
        assert!(source1.temp_dir().exists());
        assert!(source2.temp_dir().exists());

        // Both should have their files
        assert_eq!(source1.file_count(), config.file_count);
        assert_eq!(source2.file_count(), config.file_count);
    }

    #[test]
    fn source1_drop_preserves_source2() {
        let config = SyntheticConfig::quick();

        let source1 = SyntheticFileSource::generate(config.clone()).unwrap();
        let source2 = SyntheticFileSource::generate(config.clone()).unwrap();

        let dir2 = source2.temp_dir().to_path_buf();

        // Drop source1
        drop(source1);

        // source2's directory should still exist
        assert!(dir2.exists());
        assert_eq!(source2.file_count(), config.file_count);
    }

    #[test]
    fn deterministic_generation() {
        let config = SyntheticConfig {
            file_count: 10,
            file_size: FileSizeDistribution::Fixed(1024),
            seed: 12345,
            ..Default::default()
        };

        let files1 = generate_in_memory_files(&config);
        let files2 = generate_in_memory_files(&config);

        assert_eq!(files1.len(), files2.len());
        for (f1, f2) in files1.iter().zip(files2.iter()) {
            assert_eq!(f1.name, f2.name);
            assert_eq!(f1.content, f2.content);
        }
    }

    #[test]
    fn secret_injection_poisson() {
        // Test that secret count scales with density
        let mut rng = XorShift64::new(42);
        let patterns: Vec<&[u8]> = vec![b"SECRET"];

        // Low density: ~0.1 secrets per KB â†’ 0-1 for 1KB file
        let mut content = vec![0u8; 1024];
        fill_random_ascii(&mut content, &mut rng);
        let low_count = inject_secrets(&mut content, 0.1, &patterns, &mut rng);
        // Should be 0 or 1 with some probability

        // High density: ~10 secrets per KB
        let mut content = vec![0u8; 1024];
        fill_random_ascii(&mut content, &mut rng);
        let high_count = inject_secrets(&mut content, 10.0, &patterns, &mut rng);

        // High density should inject more
        assert!(
            high_count > low_count,
            "high_count={} low_count={}",
            high_count,
            low_count
        );
    }

    #[test]
    fn secret_injection_lambda_greater_than_one() {
        // Regression test: lambda > 1 should inject multiple secrets
        let mut rng = XorShift64::new(42);
        let patterns: Vec<&[u8]> = vec![b"SECRET"];

        // 10KB file with 1 secret/KB density â†’ expect ~10 secrets
        let mut content = vec![0u8; 10 * 1024];
        fill_random_ascii(&mut content, &mut rng);
        let count = inject_secrets(&mut content, 1.0, &patterns, &mut rng);

        // Should be approximately 10 (allow variance)
        assert!((5..=15).contains(&count), "count={} expected ~10", count);
    }

    #[test]
    fn file_source_is_cheap() {
        let config = SyntheticConfig::quick();
        let source = SyntheticFileSource::generate(config).unwrap();

        // file_source() should be a cheap Arc clone - both return independent iterators
        // over the same underlying file list
        let _fs1 = source.file_source();
        let _fs2 = source.file_source();

        // Both should work independently - verify file_count is consistent
        assert!(source.file_count() > 0);
    }

    #[test]
    fn exponential_handles_zero_rng() {
        // The ln(0) edge case should be handled
        let dist = FileSizeDistribution::Exponential {
            base: 1024,
            scale: 1024,
        };

        let mut rng = XorShift64::new(0);
        // Should not panic even with edge-case RNG values
        for _ in 0..1000 {
            let size = dist.sample(&mut rng);
            assert!(size >= 1024);
        }
    }

    #[test]
    fn no_fsync_by_default() {
        let config = SyntheticConfig::default();
        assert!(
            !config.fsync,
            "fsync should be disabled by default for benchmark mode"
        );
    }

    #[test]
    fn presets_valid() {
        assert!(SyntheticConfig::quick().validate().is_ok());
        assert!(SyntheticConfig::realistic().validate().is_ok());
        assert!(SyntheticConfig::stress().validate().is_ok());
    }
}
