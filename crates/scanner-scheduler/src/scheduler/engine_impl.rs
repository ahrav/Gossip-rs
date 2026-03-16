//! Real Engine Trait Implementations
//!
//! This module implements the scheduler's engine traits for the production
//! scanning engine ([`crate::engine::Engine`]).
//!
//! # Usage
//!
//! Import this module to make the real engine compatible with the scheduler:
//!
//! ```ignore
//! use scanner_rs::scheduler::engine_impl::*;
//! use scanner_rs::scheduler::local_fs_owner::scan_local;
//! use scanner_rs::engine::Engine;
//!
//! let engine = Arc::new(Engine::new(rules, transforms, tuning));
//! let report = scan_local(engine, source, config, sink);
//! ```
//!
//! # Type Mapping
//!
//! | Scheduler Trait | Real Engine Type |
//! |-----------------|------------------|
//! | [`FindingRecord`](super::engine_trait::FindingRecord) | [`crate::api::FindingRec`] |
//! | [`EngineScratch`](super::engine_trait::EngineScratch) | [`RealEngineScratch`] (wraps [`crate::engine::ScanScratch`]) |
//! | [`ScanEngine`](super::engine_trait::ScanEngine) | [`crate::engine::Engine`] |
//!
//! # Design: Lazy Reset Pattern
//!
//! The real engine's `ScanScratch::reset_for_scan()` requires an `&Engine` reference,
//! but the trait's `clear()` method cannot provide one (engine reference isn't available
//! at that point). We solve this with a **lazy reset** pattern:
//!
//! 1. `clear()` only clears the findings buffer (no-op for internal scratch state)
//! 2. `Engine::scan_chunk_into()` calls `reset_for_scan()` internally before scanning
//!
//! This preserves the trait's simplicity while satisfying the real engine's requirements.

use super::engine_trait::{EngineScratch, FindingRecord, FindingWithHash, ScanEngine};
use crate::api::{FileId, FindingRec as ApiFindingRec};
use crate::engine::{Engine, ScanScratch as RealScanScratch};

// ============================================================================
// FindingRecord for api::FindingRec
// ============================================================================

/// Trivial delegation: the real engine's `FindingRec` already carries the
/// exact fields the trait requires (`rule_id`, `root_hint_*`, `span_*`,
/// `confidence_score`). Only trivial widening conversions are needed
/// (`u32` → `u64` for `span_start`/`span_end`).
impl FindingRecord for ApiFindingRec {
    #[inline]
    fn rule_id(&self) -> u32 {
        self.rule_id
    }

    #[inline]
    fn root_hint_start(&self) -> u64 {
        self.root_hint_start
    }

    #[inline]
    fn root_hint_end(&self) -> u64 {
        self.root_hint_end
    }

    #[inline]
    fn span_start(&self) -> u64 {
        u64::from(self.span_start)
    }

    #[inline]
    fn span_end(&self) -> u64 {
        u64::from(self.span_end)
    }

    #[inline]
    fn dedupe_with_span(&self) -> bool {
        self.dedupe_with_span
    }

    #[inline]
    fn confidence_score(&self) -> i8 {
        self.confidence_score
    }
}

// ============================================================================
// EngineScratch for engine::ScanScratch
// ============================================================================

/// Wrapper around the real `ScanScratch` using a lazy reset pattern.
///
/// The real `ScanScratch::reset_for_scan` requires an `&Engine` reference,
/// but the trait's `clear()` method cannot provide one. Instead of storing
/// an engine reference, we use a **lazy reset** approach:
///
/// - `clear()` only clears the local drain buffers (`findings_buf`,
///   `norm_hash_buf`).
/// - `Engine::scan_chunk_into()` calls `reset_for_scan()` internally
///   before scanning, resetting the engine's internal state.
///
/// This preserves the trait's simplicity while satisfying the real engine's
/// requirements.
pub struct RealEngineScratch {
    scratch: RealScanScratch,
    /// Temporary buffer for draining findings.
    findings_buf: Vec<ApiFindingRec>,
    /// Temporary buffer for draining normalized hashes aligned with findings.
    norm_hash_buf: Vec<crate::engine::NormHash>,
}

// SAFETY: RealEngineScratch wraps ScanScratch which is not automatically Send because
// it contains `Option<VsScratch>` fields holding raw pointers to Vectorscan FFI handles
// (`*mut hs_scratch_t`, `*mut hs_database_t`). Raw pointers are !Send by default.
//
// The unsafe impl Send is justified because:
//
// 1. **Ownership model**: Each scratch instance is created per-worker and never shared.
//    - Created once in `Executor::new()` via the `scratch_init` closure
//    - Stored in `WorkerCtx` which is pinned to a single worker thread
//    - Only accessed by the owning worker thread during `process_file()`
//
// 2. **Transfer semantics**: The Send bound is required by the `EngineScratch` trait
//    to allow the executor to pass scratch to worker threads at startup. After this
//    one-time transfer, each scratch instance is thread-local for the lifetime of
//    the scan.
//
// 3. **Vectorscan safety**: The underlying `hs_scratch_t` handles are not thread-safe
//    for concurrent use (Vectorscan requirement), but they ARE safe to transfer between
//    threads as long as only one thread uses them at a time. Our ownership model
//    guarantees single-thread access after initialization.
//
// 4. **Other fields**: `ScratchVec<T>` uses `NonNull` internally but owns its data
//    and follows Rust's aliasing rules. `Vec<u8>`, `Vec<FindingRec>`, etc. are all
//    Send when their contents are Send.
//
// If the executor's invariants change (e.g., work-stealing that moves scratch between
// workers), this unsafe impl would become unsound and must be revisited.
unsafe impl Send for RealEngineScratch {}

impl RealEngineScratch {
    /// Create a new wrapper, pre-allocating drain buffers to `max_findings`.
    ///
    /// `max_findings` must match `Tuning::max_findings_per_chunk` so that
    /// `drain_findings_into` never allocates. The engine enforces this cap
    /// internally; exceeding it is a logic error (caught by debug assertions
    /// in `drain_findings_into`).
    pub fn new(scratch: RealScanScratch, max_findings: usize) -> Self {
        Self {
            scratch,
            findings_buf: Vec::with_capacity(max_findings),
            norm_hash_buf: Vec::with_capacity(max_findings),
        }
    }

    /// Get mutable access to the underlying scratch for scanning.
    ///
    /// Only meaningful inside [`ScanEngine::scan_chunk_into`], which calls
    /// `reset_for_scan()` on the inner scratch before scanning. Calling this
    /// outside that context may observe stale internal state.
    pub fn inner_mut(&mut self) -> &mut RealScanScratch {
        &mut self.scratch
    }
}

impl EngineScratch for RealEngineScratch {
    type Finding = FindingWithHash<ApiFindingRec>;

    fn clear(&mut self) {
        // Lazy reset pattern: the real scratch's `reset_for_scan()` is called inside
        // `Engine::scan_chunk_into()`, not here. This is because `reset_for_scan()`
        // requires an `&Engine` reference that we don't have in this trait method.
        //
        // We only clear our temporary drain buffer here.
        self.findings_buf.clear();
        self.norm_hash_buf.clear();
    }

    fn drop_prefix_findings(&mut self, new_bytes_start: u64) {
        self.scratch.drop_prefix_findings(new_bytes_start);
    }

    fn drain_findings_into(&mut self, out: &mut Vec<Self::Finding>) {
        // The real `ScanScratch::drain_findings_with_hashes` *clears* the
        // destination vecs before writing, which would destroy any findings
        // already in `out`. We stage through local buffers to preserve the
        // trait's append semantics.
        self.findings_buf.clear();
        self.norm_hash_buf.clear();
        let pending = self.scratch.pending_findings_len();

        // Buffers were pre-sized to max_findings_per_chunk at startup.
        // The engine enforces this cap, so pending must fit.  Allocating
        // here would violate the zero-alloc-after-init invariant.
        debug_assert!(
            self.findings_buf.capacity() >= pending,
            "findings_buf capacity ({}) < pending findings ({}); \
             engine exceeded max_findings_per_chunk",
            self.findings_buf.capacity(),
            pending,
        );
        debug_assert!(
            self.norm_hash_buf.capacity() >= pending,
            "norm_hash_buf capacity ({}) < pending findings ({}); \
             engine exceeded max_findings_per_chunk",
            self.norm_hash_buf.capacity(),
            pending,
        );

        self.scratch
            .drain_findings_with_hashes(&mut self.findings_buf, &mut self.norm_hash_buf);

        debug_assert_eq!(
            self.findings_buf.len(),
            self.norm_hash_buf.len(),
            "finding/hash drain length mismatch"
        );

        // `out` is the per-worker `pending` vec, pre-sized to
        // max_findings_per_chunk at worker init.  After `clear()` by the
        // caller, capacity is guaranteed sufficient.
        debug_assert!(
            out.capacity() - out.len() >= self.findings_buf.len(),
            "output vec remaining capacity ({}) < drained findings ({})",
            out.capacity() - out.len(),
            self.findings_buf.len(),
        );
        for (finding, norm_hash) in self
            .findings_buf
            .drain(..)
            .zip(self.norm_hash_buf.drain(..))
        {
            out.push(FindingWithHash::new(finding, norm_hash));
        }
    }

    fn pending_findings_len(&self) -> usize {
        self.scratch.pending_findings_len()
    }

    fn dropped_findings(&self) -> u64 {
        self.scratch.dropped_findings() as u64
    }
}

// ============================================================================
// ScanEngine for engine::Engine
// ============================================================================

/// Bridges the real `Engine` to the scheduler's `ScanEngine` trait.
///
/// Most methods delegate directly to inherent methods of the same name.
/// `scan_chunk_into` unwraps the `RealEngineScratch` wrapper to pass the
/// inner `ScanScratch` to the engine, which calls `reset_for_scan`
/// internally (the lazy reset pattern described on [`RealEngineScratch`]).
impl ScanEngine for Engine {
    type Scratch = RealEngineScratch;

    fn required_overlap(&self) -> usize {
        self.required_overlap()
    }

    fn new_scratch(&self) -> Self::Scratch {
        let scratch = self.new_scratch();
        let max_findings = Engine::max_findings_per_chunk(self);
        RealEngineScratch::new(scratch, max_findings)
    }

    fn scan_chunk_into(
        &self,
        data: &[u8],
        file_id: FileId,
        base_offset: u64,
        scratch: &mut Self::Scratch,
    ) {
        // The real engine's scan_chunk_into calls reset_for_scan internally.
        self.scan_chunk_into(data, file_id, base_offset, scratch.inner_mut());
    }

    fn rule_name(&self, rule_id: u32) -> &str {
        self.rule_name(rule_id)
    }

    fn rule_fingerprint_bytes(&self, rule_id: u32) -> [u8; 32] {
        Engine::rule_fingerprint_bytes(self, rule_id)
    }

    fn max_findings_per_chunk(&self) -> usize {
        Engine::max_findings_per_chunk(self)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{RuleSpec, TransformConfig, Tuning};
    use regex::bytes::Regex;

    fn test_tuning() -> Tuning {
        Tuning {
            merge_gap: 64,
            max_windows_per_rule_variant: 64,
            pressure_gap_start: 128,
            max_anchor_hits_per_rule_variant: 256,
            max_utf16_decoded_bytes_per_window: 4096,
            max_transform_depth: 2,
            max_total_decode_output_bytes: 1024 * 1024,
            max_work_items: 64,
            max_findings_per_chunk: 4096,
            scan_utf16_variants: true,
        }
    }

    fn simple_rule() -> RuleSpec {
        RuleSpec {
            name: "test-secret",
            anchors: &[b"SECRET"],
            radius: 32,
            validator: crate::api::ValidatorKind::None,
            two_phase: None,
            must_contain: None,
            keywords_any: None,
            value_suppressors_any: None,
            entropy: None,
            char_class: None,
            local_context: None,
            secret_group: None,
            min_confidence: None,
            offline_validation: None,
            uuid_format_secret: false,
            re: Regex::new(r"SECRET[A-Z0-9]{8}").unwrap(),
        }
    }

    #[test]
    fn real_engine_implements_scan_engine() {
        let rules = vec![simple_rule()];
        let transforms: Vec<TransformConfig> = vec![];
        let engine = Engine::new(rules, transforms, test_tuning());

        // Verify trait methods work - use explicit trait syntax to avoid inherent method
        assert!(<Engine as ScanEngine>::required_overlap(&engine) > 0);
        let mut scratch = <Engine as ScanEngine>::new_scratch(&engine);

        let data = b"test SECRET12345678 end";
        <Engine as ScanEngine>::scan_chunk_into(&engine, data, FileId(0), 0, &mut scratch);

        let max_findings = engine.max_findings_per_chunk();
        let mut findings = Vec::with_capacity(max_findings);
        scratch.drain_findings_into(&mut findings);

        assert_eq!(findings.len(), 1);
        assert_ne!(findings[0].norm_hash, [0; 32]);
        assert_eq!(
            <Engine as ScanEngine>::rule_name(&engine, findings[0].rule_id()),
            "test-secret"
        );
    }

    #[test]
    fn drop_prefix_findings_works() {
        let rules = vec![simple_rule()];
        let transforms: Vec<TransformConfig> = vec![];
        let engine = Engine::new(rules, transforms, test_tuning());

        // Use trait method to get RealEngineScratch
        let mut scratch = <Engine as ScanEngine>::new_scratch(&engine);

        // Create two matches: one at offset 0, one at offset 100
        let data1 = b"SECRET12345678 padding";
        <Engine as ScanEngine>::scan_chunk_into(&engine, data1, FileId(0), 0, &mut scratch);

        // The finding root_hint_end should be around 14 (length of match)
        // Drop findings whose root_hint_end < 50
        scratch.drop_prefix_findings(50);

        let max_findings = engine.max_findings_per_chunk();
        let mut findings = Vec::with_capacity(max_findings);
        scratch.drain_findings_into(&mut findings);

        // Should have dropped the finding since it ended before offset 50
        assert!(findings.is_empty());
    }
}
