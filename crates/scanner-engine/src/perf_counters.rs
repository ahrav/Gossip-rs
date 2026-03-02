//! Optional performance counters for Git scanning instrumentation.
//!
//! When enabled, counters cover pack decode/scan, mapping, and tree-load
//! operations to isolate bottlenecks in commit-walk pipelines.
//!
//! Enable with the `perf-counters` feature. When disabled, counter functions
//! are either no-ops or compiled out entirely, and snapshots return zeroed values.
//!
//! Counters use relaxed atomics for low overhead; snapshots are best-effort
//! and intended for coarse diagnostics rather than exact accounting.

#[cfg(feature = "perf-counters")]
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(feature = "perf-counters")]
use std::time::Instant;

/// Snapshot of Git scan performance counters.
///
/// Shape is stable across feature flags. In non-`perf-counters` builds snapshots
/// are still returned with this full structure, but every field is zero.
#[derive(Clone, Copy, Debug, Default)]
pub struct GitPerfStats {
    /// Total bytes inflated from pack entries (uncompressed size).
    pub pack_inflate_bytes: u64,
    /// Wall-clock nanoseconds spent inflating pack entries.
    pub pack_inflate_nanos: u64,
    /// Total bytes produced by delta application (uncompressed size).
    pub delta_apply_bytes: u64,
    /// Wall-clock nanoseconds spent applying deltas.
    pub delta_apply_nanos: u64,
    /// Total bytes scanned by the engine adapter.
    pub scan_bytes: u64,
    /// Wall-clock nanoseconds spent scanning blob bytes.
    pub scan_nanos: u64,
    /// Number of mapping-bridge calls recorded.
    pub mapping_calls: u64,
    /// Wall-clock nanoseconds spent in mapping-bridge calls.
    pub mapping_nanos: u64,
    /// Cache hit count for pack offsets.
    pub cache_hits: u64,
    /// Cache miss count for pack offsets.
    pub cache_misses: u64,
    /// Tree load calls (ObjectStore::load_tree).
    pub tree_load_calls: u64,
    /// Tree load bytes (payload length).
    pub tree_load_bytes: u64,
    /// Wall-clock nanoseconds spent in tree loads.
    pub tree_load_nanos: u64,
    /// Hits against the in-memory tree-object cache (avoids pack decode).
    pub tree_cache_hits: u64,
    /// Delta instruction stream cache hits (reuses previously inflated delta).
    pub tree_delta_cache_hits: u64,
    /// Delta instruction stream cache misses (full inflate required).
    pub tree_delta_cache_misses: u64,
    /// Tree delta cache bytes reused.
    pub tree_delta_cache_bytes: u64,
    /// Wall-clock nanoseconds spent resolving delta bases from cache hits.
    pub tree_delta_cache_hit_nanos: u64,
    /// Wall-clock nanoseconds spent resolving delta bases after cache misses.
    pub tree_delta_cache_miss_nanos: u64,
    /// Tree delta chain length = 0.
    pub tree_delta_chain_0: u64,
    /// Tree delta chain length = 1.
    pub tree_delta_chain_1: u64,
    /// Tree delta chain length = 2..=3.
    pub tree_delta_chain_2_3: u64,
    /// Tree delta chain length = 4..=7.
    pub tree_delta_chain_4_7: u64,
    /// Tree delta chain length >= 8.
    pub tree_delta_chain_8_plus: u64,
    /// Hits against the spill index for previously decoded tree payloads.
    pub tree_spill_hits: u64,
    /// Tree object loads (cache/spill misses).
    pub tree_object_loads: u64,
    /// Tree object bytes decoded.
    pub tree_object_bytes: u64,
    /// Wall-clock nanoseconds spent decoding tree objects.
    pub tree_object_nanos: u64,
    /// Tree inflate bytes (tree payloads or delta instruction streams).
    pub tree_inflate_bytes: u64,
    /// Wall-clock nanoseconds spent inflating tree payloads or delta streams.
    pub tree_inflate_nanos: u64,
    /// Tree delta apply bytes (post-delta output size).
    pub tree_delta_apply_bytes: u64,
    /// Wall-clock nanoseconds spent applying tree deltas.
    pub tree_delta_apply_nanos: u64,
    /// Tree objects loaded from pack files.
    pub tree_object_pack: u64,
    /// Tree objects loaded from loose objects.
    pub tree_object_loose: u64,

    // -- Scan sub-stage breakdown (within sink_emit) --
    /// Wall-clock nanoseconds in Vectorscan prefilter (`vs.scan_raw`).
    pub scan_vs_prefilter_nanos: u64,
    /// Wall-clock nanoseconds in window sort/merge + regex validation loop.
    pub scan_validate_nanos: u64,
    /// Wall-clock nanoseconds in transform decode + rescan (DecodeSpan items).
    pub scan_transform_nanos: u64,
    /// Wall-clock nanoseconds in per-blob `sort_unstable()` + `dedup()`.
    pub scan_sort_dedup_nanos: u64,
    /// Wall-clock nanoseconds in scratch reset (`reset_for_scan` / `reset_for_scan_after_prefilter`).
    pub scan_reset_nanos: u64,
    /// Total blobs scanned via `scan_blob_chunked_with_chunker`.
    pub scan_blob_count: u64,
    /// Total chunks processed via `scan_chunk`.
    pub scan_chunk_count: u64,
    /// Chunks where the prefilter produced zero hits (early return).
    pub scan_zero_hit_chunks: u64,
    /// Total findings produced (calls to `push_finding_with_drop_hint`).
    pub scan_findings_count: u64,
    /// Blobs that took the chunker bypass fast path (single-chunk blobs).
    pub scan_chunker_bypass_count: u64,
    /// Blobs skipped because they appear to be binary (NUL byte detected).
    pub scan_binary_skip_count: u64,
    /// Blobs where text was extracted from a known binary format (.ipynb, .class, etc.).
    pub scan_binary_extract_count: u64,
    /// Chunks where the hoisted prefilter bypassed reset+work-queue setup.
    pub scan_prefilter_bypass_count: u64,
}

/// Assigns a value to a perf-related struct field.
///
/// When `perf-counters` is disabled the assignment is elided entirely.
macro_rules! perf_set {
    ($target:expr, $field:ident, $val:expr) => {
        #[cfg(feature = "perf-counters")]
        {
            $target.$field = $val;
        }
    };
}
pub(crate) use perf_set;

/// Declares a `let` binding that only exists when `perf-counters` is enabled.
///
/// Use for `Instant::now()` timers that feed into [`perf_set!`] calls.
macro_rules! perf_let {
    ($name:ident = $val:expr) => {
        #[cfg(feature = "perf-counters")]
        let $name = $val;
    };
    (mut $name:ident = $val:expr) => {
        #[cfg(feature = "perf-counters")]
        let mut $name = $val;
    };
}
pub(crate) use perf_let;

#[cfg(feature = "perf-counters")]
static PACK_INFLATE_BYTES: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "perf-counters")]
static PACK_INFLATE_NANOS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "perf-counters")]
static DELTA_APPLY_BYTES: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "perf-counters")]
static DELTA_APPLY_NANOS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "perf-counters")]
static SCAN_BYTES: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "perf-counters")]
static SCAN_NANOS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "perf-counters")]
static MAPPING_CALLS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "perf-counters")]
static MAPPING_NANOS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "perf-counters")]
static CACHE_HITS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "perf-counters")]
static CACHE_MISSES: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "perf-counters")]
static TREE_LOAD_CALLS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "perf-counters")]
static TREE_LOAD_BYTES: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "perf-counters")]
static TREE_LOAD_NANOS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "perf-counters")]
static TREE_CACHE_HITS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "perf-counters")]
static TREE_DELTA_CACHE_HITS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "perf-counters")]
static TREE_DELTA_CACHE_MISSES: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "perf-counters")]
static TREE_DELTA_CACHE_BYTES: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "perf-counters")]
static TREE_DELTA_CACHE_HIT_NANOS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "perf-counters")]
static TREE_DELTA_CACHE_MISS_NANOS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "perf-counters")]
static TREE_DELTA_CHAIN_0: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "perf-counters")]
static TREE_DELTA_CHAIN_1: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "perf-counters")]
static TREE_DELTA_CHAIN_2_3: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "perf-counters")]
static TREE_DELTA_CHAIN_4_7: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "perf-counters")]
static TREE_DELTA_CHAIN_8_PLUS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "perf-counters")]
static TREE_SPILL_HITS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "perf-counters")]
static TREE_OBJECT_LOADS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "perf-counters")]
static TREE_OBJECT_BYTES: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "perf-counters")]
static TREE_OBJECT_NANOS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "perf-counters")]
static TREE_INFLATE_BYTES: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "perf-counters")]
static TREE_INFLATE_NANOS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "perf-counters")]
static TREE_DELTA_APPLY_BYTES: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "perf-counters")]
static TREE_DELTA_APPLY_NANOS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "perf-counters")]
static TREE_OBJECT_PACK: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "perf-counters")]
static TREE_OBJECT_LOOSE: AtomicU64 = AtomicU64::new(0);

#[cfg(feature = "perf-counters")]
static SCAN_VS_PREFILTER_NANOS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "perf-counters")]
static SCAN_VALIDATE_NANOS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "perf-counters")]
static SCAN_TRANSFORM_NANOS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "perf-counters")]
static SCAN_SORT_DEDUP_NANOS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "perf-counters")]
static SCAN_RESET_NANOS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "perf-counters")]
static SCAN_BLOB_COUNT: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "perf-counters")]
static SCAN_CHUNK_COUNT: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "perf-counters")]
static SCAN_ZERO_HIT_CHUNKS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "perf-counters")]
static SCAN_FINDINGS_COUNT: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "perf-counters")]
static SCAN_CHUNKER_BYPASS_COUNT: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "perf-counters")]
static SCAN_BINARY_SKIP_COUNT: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "perf-counters")]
static SCAN_BINARY_EXTRACT_COUNT: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "perf-counters")]
static SCAN_PREFILTER_BYPASS_COUNT: AtomicU64 = AtomicU64::new(0);

/// Reset all counters to zero.
///
/// This is a no-op when `perf-counters` is disabled.
pub fn reset() {
    #[cfg(feature = "perf-counters")]
    {
        PACK_INFLATE_BYTES.store(0, Ordering::Relaxed);
        PACK_INFLATE_NANOS.store(0, Ordering::Relaxed);
        DELTA_APPLY_BYTES.store(0, Ordering::Relaxed);
        DELTA_APPLY_NANOS.store(0, Ordering::Relaxed);
        SCAN_BYTES.store(0, Ordering::Relaxed);
        SCAN_NANOS.store(0, Ordering::Relaxed);
        MAPPING_CALLS.store(0, Ordering::Relaxed);
        MAPPING_NANOS.store(0, Ordering::Relaxed);
        CACHE_HITS.store(0, Ordering::Relaxed);
        CACHE_MISSES.store(0, Ordering::Relaxed);
        TREE_LOAD_CALLS.store(0, Ordering::Relaxed);
        TREE_LOAD_BYTES.store(0, Ordering::Relaxed);
        TREE_LOAD_NANOS.store(0, Ordering::Relaxed);
        TREE_CACHE_HITS.store(0, Ordering::Relaxed);
        TREE_DELTA_CACHE_HITS.store(0, Ordering::Relaxed);
        TREE_DELTA_CACHE_MISSES.store(0, Ordering::Relaxed);
        TREE_DELTA_CACHE_BYTES.store(0, Ordering::Relaxed);
        TREE_DELTA_CACHE_HIT_NANOS.store(0, Ordering::Relaxed);
        TREE_DELTA_CACHE_MISS_NANOS.store(0, Ordering::Relaxed);
        TREE_DELTA_CHAIN_0.store(0, Ordering::Relaxed);
        TREE_DELTA_CHAIN_1.store(0, Ordering::Relaxed);
        TREE_DELTA_CHAIN_2_3.store(0, Ordering::Relaxed);
        TREE_DELTA_CHAIN_4_7.store(0, Ordering::Relaxed);
        TREE_DELTA_CHAIN_8_PLUS.store(0, Ordering::Relaxed);
        TREE_SPILL_HITS.store(0, Ordering::Relaxed);
        TREE_OBJECT_LOADS.store(0, Ordering::Relaxed);
        TREE_OBJECT_BYTES.store(0, Ordering::Relaxed);
        TREE_OBJECT_NANOS.store(0, Ordering::Relaxed);
        TREE_INFLATE_BYTES.store(0, Ordering::Relaxed);
        TREE_INFLATE_NANOS.store(0, Ordering::Relaxed);
        TREE_DELTA_APPLY_BYTES.store(0, Ordering::Relaxed);
        TREE_DELTA_APPLY_NANOS.store(0, Ordering::Relaxed);
        TREE_OBJECT_PACK.store(0, Ordering::Relaxed);
        TREE_OBJECT_LOOSE.store(0, Ordering::Relaxed);
        SCAN_VS_PREFILTER_NANOS.store(0, Ordering::Relaxed);
        SCAN_VALIDATE_NANOS.store(0, Ordering::Relaxed);
        SCAN_TRANSFORM_NANOS.store(0, Ordering::Relaxed);
        SCAN_SORT_DEDUP_NANOS.store(0, Ordering::Relaxed);
        SCAN_RESET_NANOS.store(0, Ordering::Relaxed);
        SCAN_BLOB_COUNT.store(0, Ordering::Relaxed);
        SCAN_CHUNK_COUNT.store(0, Ordering::Relaxed);
        SCAN_ZERO_HIT_CHUNKS.store(0, Ordering::Relaxed);
        SCAN_FINDINGS_COUNT.store(0, Ordering::Relaxed);
        SCAN_CHUNKER_BYPASS_COUNT.store(0, Ordering::Relaxed);
        SCAN_BINARY_SKIP_COUNT.store(0, Ordering::Relaxed);
        SCAN_BINARY_EXTRACT_COUNT.store(0, Ordering::Relaxed);
        SCAN_PREFILTER_BYPASS_COUNT.store(0, Ordering::Relaxed);
    }
}

/// Snapshot current counters.
///
/// Returns zeros when `perf-counters` is disabled.
#[must_use]
pub fn snapshot() -> GitPerfStats {
    #[cfg(feature = "perf-counters")]
    {
        GitPerfStats {
            pack_inflate_bytes: PACK_INFLATE_BYTES.load(Ordering::Relaxed),
            pack_inflate_nanos: PACK_INFLATE_NANOS.load(Ordering::Relaxed),
            delta_apply_bytes: DELTA_APPLY_BYTES.load(Ordering::Relaxed),
            delta_apply_nanos: DELTA_APPLY_NANOS.load(Ordering::Relaxed),
            scan_bytes: SCAN_BYTES.load(Ordering::Relaxed),
            scan_nanos: SCAN_NANOS.load(Ordering::Relaxed),
            mapping_calls: MAPPING_CALLS.load(Ordering::Relaxed),
            mapping_nanos: MAPPING_NANOS.load(Ordering::Relaxed),
            cache_hits: CACHE_HITS.load(Ordering::Relaxed),
            cache_misses: CACHE_MISSES.load(Ordering::Relaxed),
            tree_load_calls: TREE_LOAD_CALLS.load(Ordering::Relaxed),
            tree_load_bytes: TREE_LOAD_BYTES.load(Ordering::Relaxed),
            tree_load_nanos: TREE_LOAD_NANOS.load(Ordering::Relaxed),
            tree_cache_hits: TREE_CACHE_HITS.load(Ordering::Relaxed),
            tree_delta_cache_hits: TREE_DELTA_CACHE_HITS.load(Ordering::Relaxed),
            tree_delta_cache_misses: TREE_DELTA_CACHE_MISSES.load(Ordering::Relaxed),
            tree_delta_cache_bytes: TREE_DELTA_CACHE_BYTES.load(Ordering::Relaxed),
            tree_delta_cache_hit_nanos: TREE_DELTA_CACHE_HIT_NANOS.load(Ordering::Relaxed),
            tree_delta_cache_miss_nanos: TREE_DELTA_CACHE_MISS_NANOS.load(Ordering::Relaxed),
            tree_delta_chain_0: TREE_DELTA_CHAIN_0.load(Ordering::Relaxed),
            tree_delta_chain_1: TREE_DELTA_CHAIN_1.load(Ordering::Relaxed),
            tree_delta_chain_2_3: TREE_DELTA_CHAIN_2_3.load(Ordering::Relaxed),
            tree_delta_chain_4_7: TREE_DELTA_CHAIN_4_7.load(Ordering::Relaxed),
            tree_delta_chain_8_plus: TREE_DELTA_CHAIN_8_PLUS.load(Ordering::Relaxed),
            tree_spill_hits: TREE_SPILL_HITS.load(Ordering::Relaxed),
            tree_object_loads: TREE_OBJECT_LOADS.load(Ordering::Relaxed),
            tree_object_bytes: TREE_OBJECT_BYTES.load(Ordering::Relaxed),
            tree_object_nanos: TREE_OBJECT_NANOS.load(Ordering::Relaxed),
            tree_inflate_bytes: TREE_INFLATE_BYTES.load(Ordering::Relaxed),
            tree_inflate_nanos: TREE_INFLATE_NANOS.load(Ordering::Relaxed),
            tree_delta_apply_bytes: TREE_DELTA_APPLY_BYTES.load(Ordering::Relaxed),
            tree_delta_apply_nanos: TREE_DELTA_APPLY_NANOS.load(Ordering::Relaxed),
            tree_object_pack: TREE_OBJECT_PACK.load(Ordering::Relaxed),
            tree_object_loose: TREE_OBJECT_LOOSE.load(Ordering::Relaxed),
            scan_vs_prefilter_nanos: SCAN_VS_PREFILTER_NANOS.load(Ordering::Relaxed),
            scan_validate_nanos: SCAN_VALIDATE_NANOS.load(Ordering::Relaxed),
            scan_transform_nanos: SCAN_TRANSFORM_NANOS.load(Ordering::Relaxed),
            scan_sort_dedup_nanos: SCAN_SORT_DEDUP_NANOS.load(Ordering::Relaxed),
            scan_reset_nanos: SCAN_RESET_NANOS.load(Ordering::Relaxed),
            scan_blob_count: SCAN_BLOB_COUNT.load(Ordering::Relaxed),
            scan_chunk_count: SCAN_CHUNK_COUNT.load(Ordering::Relaxed),
            scan_zero_hit_chunks: SCAN_ZERO_HIT_CHUNKS.load(Ordering::Relaxed),
            scan_findings_count: SCAN_FINDINGS_COUNT.load(Ordering::Relaxed),
            scan_chunker_bypass_count: SCAN_CHUNKER_BYPASS_COUNT.load(Ordering::Relaxed),
            scan_binary_skip_count: SCAN_BINARY_SKIP_COUNT.load(Ordering::Relaxed),
            scan_binary_extract_count: SCAN_BINARY_EXTRACT_COUNT.load(Ordering::Relaxed),
            scan_prefilter_bypass_count: SCAN_PREFILTER_BYPASS_COUNT.load(Ordering::Relaxed),
        }
    }

    #[cfg(not(feature = "perf-counters"))]
    {
        GitPerfStats::default()
    }
}

/// Time a closure, returning `(result, nanos)`.
///
/// Returns `(result, 0)` when `perf-counters` is disabled.
pub fn time<F, R>(f: F) -> (R, u64)
where
    F: FnOnce() -> R,
{
    #[cfg(feature = "perf-counters")]
    {
        let start = Instant::now();
        let out = f();
        let nanos = start.elapsed().as_nanos() as u64;
        (out, nanos)
    }

    #[cfg(not(feature = "perf-counters"))]
    {
        (f(), 0)
    }
}

/// Record pack entry inflation metrics.
pub fn record_pack_inflate(bytes: usize, nanos: u64) {
    #[cfg(feature = "perf-counters")]
    {
        PACK_INFLATE_BYTES.fetch_add(bytes as u64, Ordering::Relaxed);
        PACK_INFLATE_NANOS.fetch_add(nanos, Ordering::Relaxed);
    }
    #[cfg(not(feature = "perf-counters"))]
    {
        let _ = (bytes, nanos);
    }
}

/// Record delta application metrics.
pub fn record_delta_apply(bytes: usize, nanos: u64) {
    #[cfg(feature = "perf-counters")]
    {
        DELTA_APPLY_BYTES.fetch_add(bytes as u64, Ordering::Relaxed);
        DELTA_APPLY_NANOS.fetch_add(nanos, Ordering::Relaxed);
    }
    #[cfg(not(feature = "perf-counters"))]
    {
        let _ = (bytes, nanos);
    }
}

/// Record blob scan metrics.
pub fn record_scan(bytes: usize, nanos: u64) {
    #[cfg(feature = "perf-counters")]
    {
        SCAN_BYTES.fetch_add(bytes as u64, Ordering::Relaxed);
        SCAN_NANOS.fetch_add(nanos, Ordering::Relaxed);
    }
    #[cfg(not(feature = "perf-counters"))]
    {
        let _ = (bytes, nanos);
    }
}

/// Record a mapping-bridge invocation.
pub fn record_mapping(nanos: u64) {
    #[cfg(feature = "perf-counters")]
    {
        MAPPING_CALLS.fetch_add(1, Ordering::Relaxed);
        MAPPING_NANOS.fetch_add(nanos, Ordering::Relaxed);
    }
    #[cfg(not(feature = "perf-counters"))]
    {
        let _ = nanos;
    }
}

/// Record a cache hit for a pack offset.
pub fn record_cache_hit() {
    #[cfg(feature = "perf-counters")]
    {
        CACHE_HITS.fetch_add(1, Ordering::Relaxed);
    }
}

/// Record a cache miss for a pack offset.
pub fn record_cache_miss() {
    #[cfg(feature = "perf-counters")]
    {
        CACHE_MISSES.fetch_add(1, Ordering::Relaxed);
    }
}

/// Record a tree load (ObjectStore::load_tree).
pub fn record_tree_load(bytes: usize, nanos: u64) {
    #[cfg(feature = "perf-counters")]
    {
        TREE_LOAD_CALLS.fetch_add(1, Ordering::Relaxed);
        TREE_LOAD_BYTES.fetch_add(bytes as u64, Ordering::Relaxed);
        TREE_LOAD_NANOS.fetch_add(nanos, Ordering::Relaxed);
    }
    #[cfg(not(feature = "perf-counters"))]
    {
        let _ = (bytes, nanos);
    }
}

/// Record a tree-cache hit.
pub fn record_tree_cache_hit() {
    #[cfg(feature = "perf-counters")]
    {
        TREE_CACHE_HITS.fetch_add(1, Ordering::Relaxed);
    }
}

/// Record a tree delta-cache hit.
pub fn record_tree_delta_cache_hit(bytes: usize) {
    #[cfg(feature = "perf-counters")]
    {
        TREE_DELTA_CACHE_HITS.fetch_add(1, Ordering::Relaxed);
        TREE_DELTA_CACHE_BYTES.fetch_add(bytes as u64, Ordering::Relaxed);
    }
    #[cfg(not(feature = "perf-counters"))]
    {
        let _ = bytes;
    }
}

/// Record time spent resolving delta bases from cache hits.
pub fn record_tree_delta_cache_hit_nanos(nanos: u64) {
    #[cfg(feature = "perf-counters")]
    {
        TREE_DELTA_CACHE_HIT_NANOS.fetch_add(nanos, Ordering::Relaxed);
    }
    #[cfg(not(feature = "perf-counters"))]
    {
        let _ = nanos;
    }
}

/// Record a tree delta-cache miss.
pub fn record_tree_delta_cache_miss() {
    #[cfg(feature = "perf-counters")]
    {
        TREE_DELTA_CACHE_MISSES.fetch_add(1, Ordering::Relaxed);
    }
}

/// Record time spent resolving delta bases after cache misses.
pub fn record_tree_delta_cache_miss_nanos(nanos: u64) {
    #[cfg(feature = "perf-counters")]
    {
        TREE_DELTA_CACHE_MISS_NANOS.fetch_add(nanos, Ordering::Relaxed);
    }
    #[cfg(not(feature = "perf-counters"))]
    {
        let _ = nanos;
    }
}

/// Record a tree delta chain length.
pub fn record_tree_delta_chain(chain_len: u8) {
    #[cfg(feature = "perf-counters")]
    {
        match chain_len {
            0 => TREE_DELTA_CHAIN_0.fetch_add(1, Ordering::Relaxed),
            1 => TREE_DELTA_CHAIN_1.fetch_add(1, Ordering::Relaxed),
            2 | 3 => TREE_DELTA_CHAIN_2_3.fetch_add(1, Ordering::Relaxed),
            4..=7 => TREE_DELTA_CHAIN_4_7.fetch_add(1, Ordering::Relaxed),
            _ => TREE_DELTA_CHAIN_8_PLUS.fetch_add(1, Ordering::Relaxed),
        };
    }
    #[cfg(not(feature = "perf-counters"))]
    {
        let _ = chain_len;
    }
}

/// Record a spill-index hit for a tree payload.
pub fn record_tree_spill_hit() {
    #[cfg(feature = "perf-counters")]
    {
        TREE_SPILL_HITS.fetch_add(1, Ordering::Relaxed);
    }
}

/// Record a decoded tree object payload.
pub fn record_tree_object(bytes: usize, nanos: u64, from_pack: bool) {
    #[cfg(feature = "perf-counters")]
    {
        TREE_OBJECT_LOADS.fetch_add(1, Ordering::Relaxed);
        TREE_OBJECT_BYTES.fetch_add(bytes as u64, Ordering::Relaxed);
        TREE_OBJECT_NANOS.fetch_add(nanos, Ordering::Relaxed);
        if from_pack {
            TREE_OBJECT_PACK.fetch_add(1, Ordering::Relaxed);
        } else {
            TREE_OBJECT_LOOSE.fetch_add(1, Ordering::Relaxed);
        }
    }
    #[cfg(not(feature = "perf-counters"))]
    {
        let _ = (bytes, nanos, from_pack);
    }
}

/// Record tree inflate metrics (payload or delta instruction streams).
pub fn record_tree_inflate(bytes: usize, nanos: u64) {
    #[cfg(feature = "perf-counters")]
    {
        TREE_INFLATE_BYTES.fetch_add(bytes as u64, Ordering::Relaxed);
        TREE_INFLATE_NANOS.fetch_add(nanos, Ordering::Relaxed);
    }
    #[cfg(not(feature = "perf-counters"))]
    {
        let _ = (bytes, nanos);
    }
}

/// Record tree delta apply metrics.
pub fn record_tree_delta_apply(bytes: usize, nanos: u64) {
    #[cfg(feature = "perf-counters")]
    {
        TREE_DELTA_APPLY_BYTES.fetch_add(bytes as u64, Ordering::Relaxed);
        TREE_DELTA_APPLY_NANOS.fetch_add(nanos, Ordering::Relaxed);
    }
    #[cfg(not(feature = "perf-counters"))]
    {
        let _ = (bytes, nanos);
    }
}

/// Record Vectorscan prefilter timing.
pub fn record_scan_vs_prefilter(nanos: u64) {
    #[cfg(feature = "perf-counters")]
    {
        SCAN_VS_PREFILTER_NANOS.fetch_add(nanos, Ordering::Relaxed);
    }
    #[cfg(not(feature = "perf-counters"))]
    {
        let _ = nanos;
    }
}

/// Record window validation timing (sort/merge + regex).
///
/// Only compiled when `perf-counters` is enabled — all call sites are already
/// gated behind `#[cfg(feature = "perf-counters")]`.
#[cfg(feature = "perf-counters")]
pub fn record_scan_validate(nanos: u64) {
    SCAN_VALIDATE_NANOS.fetch_add(nanos, Ordering::Relaxed);
}

/// Record transform decode + rescan timing.
///
/// Only compiled when `perf-counters` is enabled — all call sites are already
/// gated behind `#[cfg(feature = "perf-counters")]`.
#[cfg(feature = "perf-counters")]
pub fn record_scan_transform(nanos: u64) {
    SCAN_TRANSFORM_NANOS.fetch_add(nanos, Ordering::Relaxed);
}

/// Record per-blob sort + dedup timing.
pub fn record_scan_sort_dedup(nanos: u64) {
    #[cfg(feature = "perf-counters")]
    {
        SCAN_SORT_DEDUP_NANOS.fetch_add(nanos, Ordering::Relaxed);
    }
    #[cfg(not(feature = "perf-counters"))]
    {
        let _ = nanos;
    }
}

/// Record scratch reset timing.
pub fn record_scan_reset(nanos: u64) {
    #[cfg(feature = "perf-counters")]
    {
        SCAN_RESET_NANOS.fetch_add(nanos, Ordering::Relaxed);
    }
    #[cfg(not(feature = "perf-counters"))]
    {
        let _ = nanos;
    }
}

/// Record a blob entering the scanner.
pub fn record_scan_blob() {
    #[cfg(feature = "perf-counters")]
    {
        SCAN_BLOB_COUNT.fetch_add(1, Ordering::Relaxed);
    }
}

/// Record a chunk entering the scanner.
pub fn record_scan_chunk() {
    #[cfg(feature = "perf-counters")]
    {
        SCAN_CHUNK_COUNT.fetch_add(1, Ordering::Relaxed);
    }
}

/// Record a chunk where the prefilter produced zero hits.
pub fn record_scan_zero_hit_chunk() {
    #[cfg(feature = "perf-counters")]
    {
        SCAN_ZERO_HIT_CHUNKS.fetch_add(1, Ordering::Relaxed);
    }
}

/// Record a finding produced by the engine.
pub fn record_scan_finding() {
    #[cfg(feature = "perf-counters")]
    {
        SCAN_FINDINGS_COUNT.fetch_add(1, Ordering::Relaxed);
    }
}

/// Record a blob that took the chunker bypass fast path.
pub fn record_scan_chunker_bypass() {
    #[cfg(feature = "perf-counters")]
    {
        SCAN_CHUNKER_BYPASS_COUNT.fetch_add(1, Ordering::Relaxed);
    }
}

/// Record a blob skipped because it appears to be binary.
pub fn record_scan_binary_skip() {
    #[cfg(feature = "perf-counters")]
    {
        SCAN_BINARY_SKIP_COUNT.fetch_add(1, Ordering::Relaxed);
    }
}

/// Record a blob where text was extracted from a known binary format.
pub fn record_scan_binary_extract() {
    #[cfg(feature = "perf-counters")]
    {
        SCAN_BINARY_EXTRACT_COUNT.fetch_add(1, Ordering::Relaxed);
    }
}

/// Record a chunk where the hoisted prefilter bypassed reset + work-queue setup.
pub fn record_scan_prefilter_bypass() {
    #[cfg(feature = "perf-counters")]
    {
        SCAN_PREFILTER_BYPASS_COUNT.fetch_add(1, Ordering::Relaxed);
    }
}
