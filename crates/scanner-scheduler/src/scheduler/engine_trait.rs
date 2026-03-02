//! Engine Trait Abstraction Layer
//!
//! # Purpose
//!
//! This module defines traits that abstract the detection engine interface,
//! allowing the scheduler to work with both the mock engine (for testing) and
//! the real production engine (for scanning).
//!
//! # Architecture
//!
//! The abstraction consists of four traits:
//!
//! - [`FindingRecord`]: A single finding from a scan (rule ID + byte offsets)
//! - [`FindingWithHashRecord`]: Extension of `FindingRecord` carrying a normalized secret hash
//! - [`EngineScratch`]: Per-worker scratch space for accumulating findings
//! - [`ScanEngine`]: The scanning engine itself (overlap, scan_chunk_into, etc.)
//!
//! # Type Differences
//!
//! The mock and real engines have slightly different finding representations:
//!
//! | Field | MockEngine | Real Engine |
//! |-------|------------|-------------|
//! | rule_id | `RuleId(u16)` | `u32` |
//! | span_start/end | `u64` | `u32` |
//! | file_id | — | `FileId` |
//! | step_id | — | `StepId` |
//!
//! The traits abstract these differences by exposing a common interface.
//! `file_id` and `step_id` are intentionally **not** part of the trait surface:
//! `file_id` is passed as a parameter to `scan_chunk_into` (the scheduler
//! already knows which file is being scanned), and `step_id` is an internal
//! engine concept (transform chain position) excluded from the dedup key.
//!
//! # Implementations
//!
//! - **Mock engine**: [`engine_stub::MockEngine`](super::engine_stub::MockEngine) for testing
//! - **Real engine**: [`engine_impl`](super::engine_impl) bridges to [`crate::engine::Engine`]
//!
//! # Thread Safety Model
//!
//! ```text
//! ┌────────────────────────────────────────────────────────────────────┐
//! │                         ScanEngine (Sync)                          │
//! │                    (shared across all workers)                     │
//! └────────────────────────────────────────────────────────────────────┘
//!                    │                    │                    │
//!                    ▼                    ▼                    ▼
//!          ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
//!          │ EngineScratch   │  │ EngineScratch   │  │ EngineScratch   │
//!          │   (Worker 0)    │  │   (Worker 1)    │  │   (Worker N)    │
//!          │   thread-local  │  │   thread-local  │  │   thread-local  │
//!          └─────────────────┘  └─────────────────┘  └─────────────────┘
//! ```
//!
//! The engine is immutable and shared; scratch is per-worker and never shared.

use crate::api::FileId;
use crate::engine::NormHash;

// ============================================================================
// FindingRecord Trait
// ============================================================================

/// A single finding record from a scan operation.
///
/// This trait abstracts the finding representation, allowing different engines
/// to use their own finding types while providing a common interface for
/// deduplication and output.
///
/// # Required Methods
///
/// - `rule_id`: The rule that matched (as u32 for compatibility)
/// - `root_hint_start/end`: Byte offsets in the original buffer for dedup
///
/// # Deduplication Semantics
///
/// Findings are deduplicated across chunk boundaries using `root_hint_start/end`:
/// - If a finding's `root_hint_end < new_bytes_start`, it belongs to the previous chunk
/// - The scheduler calls `EngineScratch::drop_prefix_findings()` to remove duplicates
///
/// # Performance
///
/// Implementations should be `Copy` or cheaply `Clone` for efficient
/// accumulation in per-worker buffers.
///
/// # Implementors
///
/// - [`engine_stub::FindingRec`](super::engine_stub::FindingRec) (mock)
/// - [`crate::api::FindingRec`] (real engine)
/// - [`FindingWithHash`] wrapper carrier (delegates to inner record)
pub trait FindingRecord: Clone + Send + 'static {
    /// Rule index that produced this finding.
    fn rule_id(&self) -> u32;

    /// Root hint start offset (byte position in original buffer).
    ///
    /// Used for cross-chunk deduplication: findings with `root_hint_end`
    /// within the overlap prefix are dropped.
    fn root_hint_start(&self) -> u64;

    /// Root hint end offset (byte position in original buffer).
    fn root_hint_end(&self) -> u64;

    /// Full match span start offset (byte position in original buffer).
    ///
    /// Used for within-chunk deduplication: findings with the same root_hint
    /// but different spans are distinct (e.g., from transformed content).
    fn span_start(&self) -> u64;

    /// Full match span end offset (byte position in original buffer).
    fn span_end(&self) -> u64;

    /// Whether `span_start/span_end` participates in dedupe identity.
    ///
    /// For findings that use coarse root hints, callers may opt into span-aware
    /// dedupe to avoid collapsing distinct occurrences that share a root range.
    fn dedupe_with_span(&self) -> bool;

    /// Additive confidence score from gate signals (Phase 1 range: 0–10).
    ///
    /// Does **not** participate in dedup keys — two findings at the same span
    /// with different scores still deduplicate normally.
    fn confidence_score(&self) -> i8;
}

/// A finding record that carries normalized secret hash bytes.
pub trait FindingWithHashRecord: FindingRecord {
    /// Normalized hash aligned with this finding.
    fn norm_hash(&self) -> &NormHash;
}

/// Finding record bundled with its normalized-secret hash.
///
/// # Why bundle the hash with the finding?
///
/// The engine computes a normalized hash of the matched secret at scan time
/// (inside `scan_chunk_into`). This hash must travel with the finding through
/// overlap dedup, within-chunk dedup, and final emission. Storing them in
/// separate parallel vectors is fragile — any sort, filter, or drain would
/// require coordinating two collections. Bundling into a single value type
/// makes the 1:1 alignment structural and impossible to violate.
///
/// # Hash Semantics
///
/// `norm_hash` is a BLAKE3 digest of the raw secret bytes extracted after gate
/// validation. Two findings with the same `norm_hash` matched the same logical
/// secret, even if their byte spans differ due to surrounding context or
/// transform chains. Real engine adapters carry the engine-computed hash; mock
/// adapters may use a deterministic placeholder hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FindingWithHash<F: FindingRecord> {
    /// Underlying engine finding record.
    pub finding: F,
    /// BLAKE3 digest of the normalized secret.
    pub norm_hash: NormHash,
}

impl<F: FindingRecord> FindingWithHash<F> {
    #[inline]
    pub const fn new(finding: F, norm_hash: NormHash) -> Self {
        Self { finding, norm_hash }
    }
}

impl<F: FindingRecord> FindingRecord for FindingWithHash<F> {
    #[inline]
    fn rule_id(&self) -> u32 {
        self.finding.rule_id()
    }

    #[inline]
    fn root_hint_start(&self) -> u64 {
        self.finding.root_hint_start()
    }

    #[inline]
    fn root_hint_end(&self) -> u64 {
        self.finding.root_hint_end()
    }

    #[inline]
    fn span_start(&self) -> u64 {
        self.finding.span_start()
    }

    #[inline]
    fn span_end(&self) -> u64 {
        self.finding.span_end()
    }

    #[inline]
    fn dedupe_with_span(&self) -> bool {
        self.finding.dedupe_with_span()
    }

    #[inline]
    fn confidence_score(&self) -> i8 {
        self.finding.confidence_score()
    }
}

impl<F: FindingRecord> FindingWithHashRecord for FindingWithHash<F> {
    #[inline]
    fn norm_hash(&self) -> &NormHash {
        &self.norm_hash
    }
}

// ============================================================================
// EngineScratch Trait
// ============================================================================

/// Per-worker scratch space for accumulating scan findings.
///
/// This trait abstracts the scratch memory that each worker thread uses to
/// collect findings during scanning. The scratch is reused across chunks
/// to avoid allocation churn.
///
/// # Lifetime
///
/// Scratch is single-threaded (one per worker) and never shared across threads.
/// It must be cleared between scans to avoid stale findings.
///
/// # Typical Usage Pattern
///
/// ```text
/// for each file:
///     scratch.clear()
///     for each chunk:
///         engine.scan_chunk_into(data, file_id, base_offset, scratch)
///         scratch.drop_prefix_findings(new_bytes_start)  // dedup
///         scratch.drain_findings_into(&mut output)
/// ```
///
/// # Deduplication
///
/// The `drop_prefix_findings` method implements overlap-based deduplication:
/// findings whose `root_hint_end` is less than `new_bytes_start` are removed
/// because they will be (or were) found by the chunk that "owns" those bytes.
///
/// # Implementors
///
/// - [`engine_stub::ScanScratch`](super::engine_stub::ScanScratch) (mock)
/// - [`engine_impl::RealEngineScratch`](super::engine_impl::RealEngineScratch) (real)
pub trait EngineScratch: Send + 'static {
    /// The finding type produced by this scratch.
    type Finding: FindingWithHashRecord;

    /// Clear all accumulated findings, preparing for a new scan.
    fn clear(&mut self);

    /// Drop findings whose root_hint_end is fully within the overlap prefix.
    ///
    /// # Arguments
    ///
    /// - `new_bytes_start`: Absolute offset where "new" bytes begin (after overlap)
    fn drop_prefix_findings(&mut self, new_bytes_start: u64);

    /// Drain all findings into the provided vector.
    ///
    /// Findings are **appended** to `out`; the caller is responsible for
    /// clearing `out` beforehand if a fresh batch is desired. The scratch's
    /// internal finding buffer is empty after this call.
    ///
    /// Implementations should transfer ownership without extra allocation
    /// when possible (e.g., `Vec::append` or `drain(..)` into `out`).
    fn drain_findings_into(&mut self, out: &mut Vec<Self::Finding>);

    /// Current number of pending findings held by scratch.
    ///
    /// Used by the scheduler to account for overlap/prefix pruning before
    /// drain. Implementations without efficient access can use the default.
    fn pending_findings_len(&self) -> usize {
        0
    }

    /// Count of findings dropped by engine per-scan caps.
    ///
    /// Default implementation returns 0 for engines without drop accounting.
    fn dropped_findings(&self) -> u64 {
        0
    }
}

// ============================================================================
// ScanEngine Trait
// ============================================================================

/// A scanning engine that detects secrets in byte buffers.
///
/// This trait abstracts the core scanning functionality, allowing the scheduler
/// to work with both mock and real engines. The engine is immutable after
/// construction; all mutable scan state lives in the associated `Scratch` type.
///
/// # Thread Safety
///
/// The engine itself is `Send + Sync` and can be shared across workers.
/// Each worker gets its own `Scratch` instance.
///
/// # Overlap Semantics
///
/// The engine declares a `required_overlap()` in bytes. The scheduler guarantees
/// that consecutive chunks overlap by at least this many bytes to ensure no
/// findings are missed at chunk boundaries.
pub trait ScanEngine: Send + Sync + 'static {
    /// The scratch type used by this engine for per-worker state.
    type Scratch: EngineScratch;

    /// Required overlap in bytes for chunked scanning.
    ///
    /// The scheduler must ensure each chunk overlaps with the previous chunk
    /// by at least this many bytes to guarantee no findings are missed.
    fn required_overlap(&self) -> usize;

    /// Create per-worker scratch space.
    ///
    /// Called once per worker at startup. The scratch is reused across all
    /// chunks scanned by that worker.
    fn new_scratch(&self) -> Self::Scratch;

    /// Scan a chunk, appending findings to scratch.
    ///
    /// # Arguments
    ///
    /// - `data`: Buffer to scan
    /// - `file_id`: File being scanned (for attribution)
    /// - `base_offset`: Absolute byte offset of `data[0]` in the file
    /// - `scratch`: Per-worker scratch space
    ///
    /// # Overlap Handling
    ///
    /// Findings are reported with absolute offsets. The scheduler is responsible
    /// for calling `scratch.drop_prefix_findings()` to deduplicate across chunks.
    fn scan_chunk_into(
        &self,
        data: &[u8],
        file_id: FileId,
        base_offset: u64,
        scratch: &mut Self::Scratch,
    );

    /// Get rule name by rule ID.
    ///
    /// Used for output formatting. Returns `"<unknown-rule>"` for invalid IDs.
    fn rule_name(&self, rule_id: u32) -> &str;

    /// Hard cap on findings per chunk scan.
    ///
    /// Used by the scheduler to pre-size per-worker buffers so that no
    /// allocations occur after startup. The engine enforces this cap
    /// internally; the scheduler trusts the value for capacity planning.
    fn max_findings_per_chunk(&self) -> usize;
}

#[cfg(test)]
mod tests {
    use super::{FindingRecord, FindingWithHash};

    #[derive(Clone, Copy)]
    struct DummyFinding {
        rule: u32,
        root_start: u64,
        root_end: u64,
        span_start: u64,
        span_end: u64,
        dedupe_with_span: bool,
    }

    impl FindingRecord for DummyFinding {
        fn rule_id(&self) -> u32 {
            self.rule
        }

        fn root_hint_start(&self) -> u64 {
            self.root_start
        }

        fn root_hint_end(&self) -> u64 {
            self.root_end
        }

        fn span_start(&self) -> u64 {
            self.span_start
        }

        fn span_end(&self) -> u64 {
            self.span_end
        }

        fn dedupe_with_span(&self) -> bool {
            self.dedupe_with_span
        }

        fn confidence_score(&self) -> i8 {
            0
        }
    }

    #[test]
    fn finding_with_hash_delegates_finding_record_methods() {
        let inner = DummyFinding {
            rule: 7,
            root_start: 100,
            root_end: 111,
            span_start: 101,
            span_end: 110,
            dedupe_with_span: true,
        };
        let wrapped = FindingWithHash::new(inner, [0xAB; 32]);

        assert_eq!(wrapped.rule_id(), inner.rule_id());
        assert_eq!(wrapped.root_hint_start(), inner.root_hint_start());
        assert_eq!(wrapped.root_hint_end(), inner.root_hint_end());
        assert_eq!(wrapped.span_start(), inner.span_start());
        assert_eq!(wrapped.span_end(), inner.span_end());
        assert_eq!(wrapped.norm_hash, [0xAB; 32]);
    }
}
