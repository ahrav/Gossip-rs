//! Findings Collection System
//!
//! # Design
//!
//! Two-tier architecture optimized for concurrent collection with deterministic output:
//!
//! ```text
//! Worker buffers (lock-free local append)
//!     â”‚
//!     â–¼ batch flush (retains capacity)
//! GlobalCollector (mutex-protected append)
//!     â”‚
//!     â–¼ finalize()
//! Sort â†’ Linear Dedup â†’ Sorted Output
//! ```
//!
//! # Why Per-Worker Buffers?
//!
//! - Zero contention on hot path (local `Vec::push`)
//! - Batched flush amortizes lock acquisition cost
//! - Typical config: 64-128 capacity per worker, flush at chunk boundaries
//!
//! # Determinism Guarantees
//!
//! Work-stealing reorders task execution, but output is deterministic:
//! 1. Sort by total key: `(object_id, start_offset, end_offset, detector_id, secret_hash)`
//! 2. Dedup with deterministic tie-breaking: higher confidence wins, then non-partial
//! 3. Final order is reproducible from any execution order
//!
//! # Deduplication Strategy
//!
//! Uses sort-then-linear-dedup instead of HashMap:
//! - O(n log n) time (same as HashMap + sort)
//! - O(1) auxiliary space (vs O(n) for HashMap)
//! - Naturally produces sorted output
//! - Deterministic tie-breaking built-in

use std::cmp::Ordering;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::Mutex;

// ============================================================================
// Finding Types
// ============================================================================

/// Unique identifier for an object in the findings system.
///
/// **Note**: This is distinct from `contract::ObjectId` which is a structured
/// identifier with `(source, idx)` fields. This is a simple u64 wrapper
/// used for finding deduplication and output ordering.
///
/// The caller is responsible for mapping their object identifiers to `u64`.
/// Typical mappings:
/// - For `contract::ObjectId`: `(source.0 as u64) << 32 | idx as u64`
/// - For file IDs: use the file ID directly
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FindingObjectId(pub u64);

/// Unique identifier for a detector type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DetectorId(pub u32);

/// Hash of the normalized secret value.
///
/// # Purpose
///
/// Used for **deduplication** and **memory efficiency** only.
///
/// # NOT FOR SECURITY
///
/// **WARNING**: This is FNV-1a, a fast non-cryptographic hash.
/// It provides NO protection against offline brute-force attacks.
/// If these hashes leak, secrets with low entropy (e.g., `AKIA...` prefixes)
/// can be recovered by an attacker.
///
/// If you need to export findings externally, either:
/// - Omit the hash entirely
/// - Use a keyed hash (SipHash with per-run key, or keyed BLAKE3)
///
/// # Why FNV-1a?
///
/// - Fast: ~4 cycles/byte
/// - Sufficient collision resistance for dedup (not crypto)
/// - 8 bytes vs variable-length secret storage
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SecretHash(pub u64);

impl SecretHash {
    /// Compute FNV-1a hash of secret bytes.
    ///
    /// Normalizes by trimming whitespace before hashing.
    pub fn from_bytes(secret: &[u8]) -> Self {
        // Trim leading/trailing whitespace for normalization
        let trimmed = trim_bytes(secret);

        // FNV-1a 64-bit
        const FNV_OFFSET: u64 = 0xcbf29ce484222325;
        const FNV_PRIME: u64 = 0x100000001b3;

        let mut hash = FNV_OFFSET;
        for &byte in trimmed {
            hash ^= byte as u64;
            hash = hash.wrapping_mul(FNV_PRIME);
        }

        SecretHash(hash)
    }
}

/// Trim leading and trailing ASCII whitespace from bytes.
fn trim_bytes(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|&b| !b.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|&b| !b.is_ascii_whitespace())
        .map(|i| i + 1)
        .unwrap_or(start);
    &bytes[start..end]
}

/// Key for deduplication.
///
/// Two findings with the same key are considered duplicates.
/// When deduplicating, we keep the one with higher confidence.
///
/// # Key Components
///
/// - `object_id`: Which object (file/blob)
/// - `start_offset`, `end_offset`: Exact byte range of the finding
/// - `detector_id`: Which detector found it
/// - `secret_hash`: Hash of normalized secret value
///
/// # Why Include secret_hash?
///
/// Different detectors may normalize secrets differently, or the same
/// byte range could match multiple patterns. The hash ensures we only
/// dedupe truly identical secrets.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FindingKey {
    pub object_id: FindingObjectId,
    pub start_offset: u64,
    pub end_offset: u64,
    pub detector_id: DetectorId,
    pub secret_hash: SecretHash,
}

/// A detected secret finding.
#[derive(Clone, Debug)]
pub struct Finding {
    // === Dedup Key Fields ===
    /// Object where finding was detected.
    pub object_id: FindingObjectId,

    /// Byte offset where secret starts.
    pub start_offset: u64,

    /// Byte offset where secret ends (exclusive).
    pub end_offset: u64,

    /// Detector that found this secret.
    pub detector_id: DetectorId,

    /// Hash of normalized secret value.
    pub secret_hash: SecretHash,

    // === Metadata Fields (not part of dedup key) ===
    /// Human-readable object identifier (path, URL, etc).
    /// TODO: Consider Arc<[u8]> or interning for repeated paths.
    pub object_display: Vec<u8>,

    /// Surrounding context (for reporting).
    pub context: Option<Vec<u8>>,

    /// Confidence score (0.0 - 1.0).
    pub confidence: f32,

    /// Whether this finding is from a partial scan (object failed mid-way).
    pub partial: bool,
}

impl Finding {
    /// Extract the deduplication key.
    #[inline]
    pub fn key(&self) -> FindingKey {
        FindingKey {
            object_id: self.object_id,
            start_offset: self.start_offset,
            end_offset: self.end_offset,
            detector_id: self.detector_id,
            secret_hash: self.secret_hash,
        }
    }

    /// Compare findings for deterministic sorting.
    ///
    /// Total ordering: sort by key, then prefer higher confidence, then non-partial.
    fn deterministic_cmp(&self, other: &Self) -> Ordering {
        self.key()
            .cmp(&other.key())
            // Higher confidence first (reverse order)
            .then_with(|| other.confidence.total_cmp(&self.confidence))
            // Non-partial (false) before partial (true)
            .then_with(|| self.partial.cmp(&other.partial))
    }
}

// ============================================================================
// Worker Buffer
// ============================================================================

/// Per-worker findings buffer for lock-free local collection.
///
/// Workers push findings to their local buffer, then flush in batches
/// to the global collector. This eliminates contention on the hot path.
#[derive(Debug)]
pub struct WorkerFindingsBuffer {
    worker_id: u32,
    findings: Vec<Finding>,
    capacity: usize,
    flushed_count: u64,
}

impl WorkerFindingsBuffer {
    /// Create a new buffer with specified capacity.
    ///
    /// Capacity should be tuned to balance:
    /// - Memory per worker (larger = more memory)
    /// - Flush frequency (larger = fewer lock acquisitions)
    ///
    /// Typical values: 64-256
    pub fn new(worker_id: u32, capacity: usize) -> Self {
        Self {
            worker_id,
            findings: Vec::with_capacity(capacity),
            capacity,
            flushed_count: 0,
        }
    }

    /// Add a finding to the buffer.
    ///
    /// Does NOT auto-flush. Caller should check `should_flush()` and
    /// call `flush_to()` explicitly for control over flush timing.
    #[inline]
    pub fn push(&mut self, finding: Finding) {
        self.findings.push(finding);
    }

    /// Check if buffer should be flushed.
    #[inline]
    pub fn should_flush(&self) -> bool {
        self.findings.len() >= self.capacity
    }

    /// Get current buffer length.
    #[inline]
    pub fn len(&self) -> usize {
        self.findings.len()
    }

    /// Check if buffer is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.findings.is_empty()
    }

    /// Flush buffer contents to the global collector.
    ///
    /// Returns number of findings flushed.
    ///
    /// # Capacity Retention
    ///
    /// Uses `append()` internally to move elements while retaining
    /// the buffer's allocated capacity. This prevents reallocation
    /// churn on repeated flush cycles.
    pub fn flush_to(&mut self, collector: &GlobalFindingsCollector) -> usize {
        let count = self.findings.len();
        if count == 0 {
            return 0;
        }

        // Use append() to retain capacity
        collector.receive_batch_inplace(self.worker_id, &mut self.findings);
        self.flushed_count += count as u64;
        count
    }

    /// Get total findings flushed over lifetime of this buffer.
    #[inline]
    pub fn flushed_count(&self) -> u64 {
        self.flushed_count
    }

    /// Get worker ID.
    #[inline]
    pub fn worker_id(&self) -> u32 {
        self.worker_id
    }
}

// ============================================================================
// Global Collector
// ============================================================================

/// Configuration for the global findings collector.
///
/// # When to Disable Options
///
/// - `dedupe = false`: Useful for debugging duplicate detection logic, or when
///   you need raw findings before post-processing elsewhere.
/// - `sort_output = false`: Minor speedup if downstream consumers don't need
///   deterministic order (e.g., feeding into a hash-based aggregator).
#[derive(Clone, Debug)]
pub struct CollectorConfig {
    /// Enable deduplication (recommended for production).
    pub dedupe: bool,

    /// Sort output for deterministic results (recommended for reproducibility).
    pub sort_output: bool,

    /// Expected total findings (for pre-allocation).
    ///
    /// Underestimating causes reallocation; overestimating wastes memory.
    /// When in doubt, use the default (1024).
    pub expected_findings: usize,
}

impl Default for CollectorConfig {
    fn default() -> Self {
        Self {
            dedupe: true,
            sort_output: true,
            expected_findings: 1024,
        }
    }
}

/// Global findings collector with deduplication and deterministic output.
///
/// # Thread Safety
///
/// Multiple workers can flush concurrently. The internal mutex serializes
/// batch appends but contention is minimized by batching at the worker level.
///
/// # Mutex Poisoning
///
/// If a thread panics while holding the lock, subsequent operations recover
/// the inner data via `unwrap_or_else(|p| p.into_inner())`. This prioritizes
/// data preservation over propagating panics from unrelated threads.
#[derive(Debug)]
pub struct GlobalFindingsCollector {
    config: CollectorConfig,
    findings: Mutex<Vec<Finding>>,

    // Stats (atomic for lock-free reads)
    batches_received: AtomicU64,
    total_received: AtomicU64,
}

impl GlobalFindingsCollector {
    #[inline(always)]
    fn recording_enabled() -> bool {
        cfg!(all(feature = "perf-stats", debug_assertions))
    }

    /// Create a new collector with the given configuration.
    pub fn new(config: CollectorConfig) -> Self {
        Self {
            findings: Mutex::new(Vec::with_capacity(config.expected_findings)),
            batches_received: AtomicU64::new(0),
            total_received: AtomicU64::new(0),
            config,
        }
    }

    /// Receive a batch of findings from a worker (takes ownership).
    ///
    /// This variant takes a `Vec<Finding>` by value.
    pub fn receive_batch(&self, _worker_id: u32, batch: Vec<Finding>) {
        if batch.is_empty() {
            return;
        }

        let count = batch.len() as u64;

        {
            let mut findings = self.findings.lock().unwrap_or_else(|p| p.into_inner());
            findings.extend(batch);
        }

        if Self::recording_enabled() {
            self.batches_received.fetch_add(1, AtomicOrdering::Relaxed);
            self.total_received
                .fetch_add(count, AtomicOrdering::Relaxed);
        }
    }

    /// Receive a batch of findings from a worker (in-place, retains caller's capacity).
    ///
    /// This variant uses `append()` to move elements out of the caller's Vec
    /// while leaving the Vec empty but with its capacity intact.
    pub fn receive_batch_inplace(&self, _worker_id: u32, batch: &mut Vec<Finding>) {
        if batch.is_empty() {
            return;
        }

        let count = batch.len() as u64;

        {
            let mut findings = self.findings.lock().unwrap_or_else(|p| p.into_inner());
            findings.append(batch); // Moves elements, retains batch's capacity
        }

        if Self::recording_enabled() {
            self.batches_received.fetch_add(1, AtomicOrdering::Relaxed);
            self.total_received
                .fetch_add(count, AtomicOrdering::Relaxed);
        }
    }

    /// Get current stats without finalizing.
    pub fn stats(&self) -> CollectorStats {
        if !Self::recording_enabled() {
            return CollectorStats::default();
        }
        CollectorStats {
            total_received: self.total_received.load(AtomicOrdering::Relaxed),
            batches_received: self.batches_received.load(AtomicOrdering::Relaxed),
            duplicates_removed: 0, // Unknown until finalize
            final_count: 0,
        }
    }

    /// Finalize collection: deduplicate and sort.
    ///
    /// Consumes the collector and returns the final findings list.
    ///
    /// # Algorithm: Sort-then-Linear-Dedup
    ///
    /// 1. Sort by total key + tie-breakers (higher confidence first, non-partial first)
    /// 2. Linear scan to remove duplicates (keeping first = best)
    ///
    /// This approach:
    /// - Uses O(1) auxiliary space (vs O(n) for HashMap)
    /// - Produces deterministic output regardless of arrival order
    /// - Has deterministic tie-breaking built-in
    pub fn finalize(self) -> (Vec<Finding>, CollectorStats) {
        let mut findings = self
            .findings
            .into_inner()
            .unwrap_or_else(|p| p.into_inner());
        let total_received = findings.len();

        let mut duplicates_removed = 0;

        if self.config.sort_output || self.config.dedupe {
            // Sort by total deterministic key
            // This puts duplicates adjacent and preferred versions first
            findings.sort_by(Finding::deterministic_cmp);
        }

        if self.config.dedupe && !findings.is_empty() {
            // Linear dedup: keep first occurrence of each key (which is best due to sort)
            let mut write_idx = 0;
            for read_idx in 1..findings.len() {
                if findings[read_idx].key() != findings[write_idx].key() {
                    write_idx += 1;
                    if write_idx != read_idx {
                        // Move finding to its final position
                        findings.swap(write_idx, read_idx);
                    }
                } else {
                    duplicates_removed += 1;
                }
            }
            findings.truncate(write_idx + 1);
        }

        let stats = CollectorStats {
            total_received: total_received as u64,
            batches_received: if Self::recording_enabled() {
                self.batches_received.load(AtomicOrdering::Relaxed)
            } else {
                0
            },
            duplicates_removed,
            final_count: findings.len() as u64,
        };

        (findings, stats)
    }
}

/// Statistics from the collector.
#[derive(Clone, Debug, Default)]
pub struct CollectorStats {
    /// Total findings received (before dedup).
    pub total_received: u64,
    /// Number of batch flushes.
    pub batches_received: u64,
    /// Findings removed by deduplication.
    pub duplicates_removed: u64,
    /// Final output count.
    pub final_count: u64,
}

// ============================================================================
// Convenience Wrapper
// ============================================================================

use std::sync::Arc;

/// Convenience wrapper that auto-flushes based on threshold.
///
/// Provides a simpler API for common use cases where you want
/// automatic batching without manual flush management.
///
/// # Ownership
///
/// Holds an `Arc<GlobalFindingsCollector>` so the sink can be moved between
/// tasks while the collector remains accessible for finalization. The `Drop`
/// impl flushes any buffered findings, ensuring no data loss even if the
/// sink is dropped without explicit flush.
///
/// # Example
///
/// ```rust,ignore
/// let collector = Arc::new(GlobalFindingsCollector::new(CollectorConfig::default()));
/// let mut sink = FindingsSink::new(worker_id, Arc::clone(&collector));
///
/// for finding in findings {
///     sink.push(finding); // Auto-flushes when threshold reached
/// }
/// // Remaining findings flushed on drop
/// drop(sink);
///
/// let (results, stats) = Arc::try_unwrap(collector).unwrap().finalize();
/// ```
pub struct FindingsSink {
    buffer: WorkerFindingsBuffer,
    collector: Arc<GlobalFindingsCollector>,
    flush_threshold: usize,
}

impl FindingsSink {
    /// Create a new sink with default flush threshold (128).
    pub fn new(worker_id: u32, collector: Arc<GlobalFindingsCollector>) -> Self {
        Self::with_threshold(worker_id, collector, 128)
    }

    /// Create a new sink with custom flush threshold.
    pub fn with_threshold(
        worker_id: u32,
        collector: Arc<GlobalFindingsCollector>,
        flush_threshold: usize,
    ) -> Self {
        Self {
            buffer: WorkerFindingsBuffer::new(worker_id, flush_threshold),
            collector,
            flush_threshold,
        }
    }

    /// Add a finding, auto-flushing if threshold reached.
    pub fn push(&mut self, finding: Finding) {
        self.buffer.push(finding);
        if self.buffer.len() >= self.flush_threshold {
            self.flush();
        }
    }

    /// Manually flush the buffer.
    pub fn flush(&mut self) -> usize {
        self.buffer.flush_to(&self.collector)
    }

    /// Get number of findings currently buffered.
    #[inline]
    pub fn buffered(&self) -> usize {
        self.buffer.len()
    }
}

impl Drop for FindingsSink {
    fn drop(&mut self) {
        // Flush any remaining findings
        self.flush();
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_finding(
        object_id: u64,
        start: u64,
        end: u64,
        detector: u32,
        secret: &[u8],
        confidence: f32,
    ) -> Finding {
        Finding {
            object_id: FindingObjectId(object_id),
            start_offset: start,
            end_offset: end,
            detector_id: DetectorId(detector),
            secret_hash: SecretHash::from_bytes(secret),
            object_display: b"test.txt".to_vec(),
            context: None,
            confidence,
            partial: false,
        }
    }

    #[test]
    fn secret_hash_consistent() {
        let h1 = SecretHash::from_bytes(b"secret123");
        let h2 = SecretHash::from_bytes(b"secret123");
        assert_eq!(h1, h2);

        // Whitespace normalization
        let h3 = SecretHash::from_bytes(b"  secret123  ");
        assert_eq!(h1, h3);
    }

    #[test]
    fn secret_hash_empty() {
        let h = SecretHash::from_bytes(b"");
        assert_eq!(h, SecretHash::from_bytes(b"   ")); // All whitespace = empty
    }

    #[test]
    fn worker_buffer_basic() {
        let mut buffer = WorkerFindingsBuffer::new(0, 64);
        assert!(buffer.is_empty());

        buffer.push(make_finding(1, 0, 10, 1, b"secret", 0.9));
        assert_eq!(buffer.len(), 1);
        assert!(!buffer.is_empty());
    }

    #[test]
    fn worker_buffer_flush_retains_capacity() {
        let collector = GlobalFindingsCollector::new(CollectorConfig::default());
        let mut buffer = WorkerFindingsBuffer::new(0, 64);

        // Push some findings
        for i in 0..10 {
            buffer.push(make_finding(1, i * 10, i * 10 + 10, 1, b"secret", 0.9));
        }

        // Record capacity before flush
        let cap_before = buffer.findings.capacity();
        assert!(cap_before >= 10);

        // Flush
        let flushed = buffer.flush_to(&collector);
        assert_eq!(flushed, 10);
        assert!(buffer.is_empty());

        // CRITICAL: Capacity should be retained after flush
        let cap_after = buffer.findings.capacity();
        assert_eq!(cap_after, cap_before, "flush should retain capacity");
    }

    #[test]
    fn collector_deduplication() {
        let collector = GlobalFindingsCollector::new(CollectorConfig::default());

        // Same key, different confidence - should keep higher
        collector.receive_batch(
            0,
            vec![
                make_finding(1, 0, 10, 1, b"secret", 0.7),
                make_finding(1, 0, 10, 1, b"secret", 0.9), // Higher confidence
                make_finding(1, 0, 10, 1, b"secret", 0.8),
            ],
        );

        let (findings, stats) = collector.finalize();

        assert_eq!(findings.len(), 1);
        assert_eq!(stats.duplicates_removed, 2);
        assert_eq!(findings[0].confidence, 0.9); // Kept highest
    }

    #[test]
    fn collector_sorting_deterministic() {
        let collector = GlobalFindingsCollector::new(CollectorConfig::default());

        // Insert out of order
        collector.receive_batch(
            0,
            vec![
                make_finding(2, 100, 110, 1, b"c", 0.9),
                make_finding(1, 0, 10, 1, b"a", 0.9),
                make_finding(1, 50, 60, 2, b"b", 0.9),
            ],
        );

        let (findings, _) = collector.finalize();

        // Should be sorted by (object_id, start_offset, ...)
        assert_eq!(findings[0].object_id.0, 1);
        assert_eq!(findings[0].start_offset, 0);
        assert_eq!(findings[1].object_id.0, 1);
        assert_eq!(findings[1].start_offset, 50);
        assert_eq!(findings[2].object_id.0, 2);
    }

    #[test]
    fn collector_sort_includes_end_offset() {
        // Two findings with same (object_id, start_offset, detector_id) but different end_offset
        let collector = GlobalFindingsCollector::new(CollectorConfig::default());

        collector.receive_batch(
            0,
            vec![
                make_finding(1, 0, 20, 1, b"longer", 0.9), // Longer match
                make_finding(1, 0, 10, 1, b"short", 0.9),  // Shorter match
            ],
        );

        let (findings, _) = collector.finalize();

        // Both should be kept (different keys due to different end_offset)
        assert_eq!(findings.len(), 2);
        // Sorted by end_offset (10 before 20)
        assert_eq!(findings[0].end_offset, 10);
        assert_eq!(findings[1].end_offset, 20);
    }

    #[test]
    fn dedup_same_secret_different_locations() {
        let collector = GlobalFindingsCollector::new(CollectorConfig::default());

        // Same secret at different locations - should keep BOTH
        collector.receive_batch(
            0,
            vec![
                make_finding(1, 0, 10, 1, b"secret", 0.9),
                make_finding(1, 100, 110, 1, b"secret", 0.9),
            ],
        );

        let (findings, stats) = collector.finalize();

        assert_eq!(findings.len(), 2);
        assert_eq!(stats.duplicates_removed, 0);
    }

    #[test]
    fn dedup_same_location_different_detectors() {
        let collector = GlobalFindingsCollector::new(CollectorConfig::default());

        // Same location, different detectors - should keep BOTH
        collector.receive_batch(
            0,
            vec![
                make_finding(1, 0, 10, 1, b"secret", 0.9), // Detector 1
                make_finding(1, 0, 10, 2, b"secret", 0.8), // Detector 2
            ],
        );

        let (findings, stats) = collector.finalize();

        assert_eq!(findings.len(), 2);
        assert_eq!(stats.duplicates_removed, 0);
    }

    #[test]
    fn findings_sink_auto_flush() {
        let collector = Arc::new(GlobalFindingsCollector::new(CollectorConfig::default()));
        let mut sink = FindingsSink::with_threshold(0, Arc::clone(&collector), 5);

        // Push 7 findings (should trigger flush at 5)
        for i in 0..7 {
            sink.push(make_finding(1, i * 10, i * 10 + 10, 1, b"secret", 0.9));
        }

        // Check stats - should have flushed once
        let stats = collector.stats();
        if cfg!(all(feature = "perf-stats", debug_assertions)) {
            assert_eq!(stats.batches_received, 1);
            assert_eq!(stats.total_received, 5);
        } else {
            assert_eq!(stats.batches_received, 0);
            assert_eq!(stats.total_received, 0);
        }

        // 2 still buffered
        assert_eq!(sink.buffered(), 2);
    }

    #[test]
    fn findings_sink_flush_on_drop() {
        let collector = Arc::new(GlobalFindingsCollector::new(CollectorConfig::default()));

        {
            let mut sink = FindingsSink::with_threshold(0, Arc::clone(&collector), 100);
            sink.push(make_finding(1, 0, 10, 1, b"secret", 0.9));
            // Drop without explicit flush
        }

        // Should have flushed on drop
        let stats = collector.stats();
        if cfg!(all(feature = "perf-stats", debug_assertions)) {
            assert_eq!(stats.total_received, 1);
        } else {
            assert_eq!(stats.total_received, 0);
        }
    }

    #[test]
    fn multi_worker_concurrent_flush() {
        use std::thread;

        let collector = Arc::new(GlobalFindingsCollector::new(CollectorConfig::default()));
        let mut handles = vec![];

        // 4 workers, 100 findings each
        for worker_id in 0..4u32 {
            let coll = Arc::clone(&collector);
            handles.push(thread::spawn(move || {
                let mut buffer = WorkerFindingsBuffer::new(worker_id, 32);
                for i in 0..100u64 {
                    buffer.push(make_finding(
                        worker_id as u64,
                        i * 10,
                        i * 10 + 10,
                        1,
                        format!("secret{}", i).as_bytes(),
                        0.9,
                    ));
                    if buffer.should_flush() {
                        buffer.flush_to(&coll);
                    }
                }
                buffer.flush_to(&coll);
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        let (findings, stats) = Arc::try_unwrap(collector).unwrap().finalize();

        assert_eq!(stats.total_received, 400);
        assert_eq!(findings.len(), 400); // All unique
    }

    #[test]
    fn finding_key_equality() {
        let f1 = make_finding(1, 0, 10, 1, b"secret", 0.9);
        let f2 = make_finding(1, 0, 10, 1, b"secret", 0.5); // Different confidence

        // Same key despite different confidence
        assert_eq!(f1.key(), f2.key());

        let f3 = make_finding(1, 0, 10, 1, b"different", 0.9); // Different secret

        // Different key due to different secret_hash
        assert_ne!(f1.key(), f3.key());
    }

    #[test]
    fn dedup_prefers_non_partial() {
        let collector = GlobalFindingsCollector::new(CollectorConfig::default());

        let mut partial = make_finding(1, 0, 10, 1, b"secret", 0.9);
        partial.partial = true;

        let complete = make_finding(1, 0, 10, 1, b"secret", 0.9);

        // Insert partial first
        collector.receive_batch(0, vec![partial, complete]);

        let (findings, _) = collector.finalize();

        assert_eq!(findings.len(), 1);
        assert!(!findings[0].partial); // Should keep non-partial
    }

    #[test]
    fn determinism_with_equal_confidence() {
        // Regression test: equal confidence should have deterministic tie-breaker
        let collector1 = GlobalFindingsCollector::new(CollectorConfig::default());
        let collector2 = GlobalFindingsCollector::new(CollectorConfig::default());

        // Same findings in different order
        collector1.receive_batch(
            0,
            vec![
                make_finding(1, 0, 10, 1, b"secret", 0.9),
                make_finding(1, 0, 10, 1, b"secret", 0.9),
            ],
        );

        collector2.receive_batch(
            0,
            vec![
                make_finding(1, 0, 10, 1, b"secret", 0.9),
                make_finding(1, 0, 10, 1, b"secret", 0.9),
            ],
        );

        let (findings1, _) = collector1.finalize();
        let (findings2, _) = collector2.finalize();

        // Both should produce identical results
        assert_eq!(findings1.len(), findings2.len());
        assert_eq!(findings1.len(), 1); // Deduped
    }

    #[test]
    fn total_cmp_handles_confidence_ordering() {
        // Verify total_cmp correctly orders by confidence
        let f_high = make_finding(1, 0, 10, 1, b"secret", 0.9);
        let f_low = make_finding(1, 0, 10, 1, b"secret", 0.5);

        // Higher confidence should come first (sort order)
        let cmp = f_high.deterministic_cmp(&f_low);
        assert_eq!(cmp, Ordering::Less); // f_high < f_low in sort order (comes first)
    }
}
