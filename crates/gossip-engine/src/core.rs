//! Runtime-agnostic scanner core — deterministic page and stream evaluation.
//!
//! # Purpose
//!
//! `ScannerCore` is the execution engine that evaluates connector pages,
//! produces [`ScanFinding`]s, and maintains cross-page deduplication. It sits
//! between the connector transport layer (which delivers [`ScanItem`] pages)
//! and the downstream pipeline (which consumes findings and diagnostics).
//!
//! # Algorithm (per page)
//!
//! 1. **Validate** that `item_bytes` length (if present) matches `items` length.
//! 2. **Seed** a deterministic FNV-1a page signature from the page context
//!    (key range boundaries + cursor state). This signature is used for
//!    parity comparisons across runtimes.
//! 3. **Iterate** items: for each item, mix it into the page signature, compute
//!    a finding fingerprint, and consult the caller-owned dedupe set:
//!    - **New fingerprint** → emit a [`ScanFinding`] (subject to the per-page
//!      finding cap).
//!    - **Seen fingerprint** → increment `duplicate_suppressed`.
//!    - **Over the cap** → increment `limit_suppressed`, flag truncation.
//! 4. **Emit diagnostics** for metadata-only pages and finding truncation.
//!
//! # Determinism guarantee
//!
//! Given identical inputs (items, bytes, context, config), output is
//! byte-identical across platforms. The hashing functions are hand-rolled
//! FNV-1a rather than `DefaultHasher` specifically to avoid platform variance.
//!
//! # Design trade-offs
//!
//! - **Page signature vs. finding fingerprint**: the page signature covers
//!   *all* structural fields (keys, refs, cursors, payload) to detect any
//!   divergence in connector output. The finding fingerprint covers only
//!   identity+version+payload so that deduplication is insensitive to
//!   pagination order or cursor drift.
//! - **`scan_page_into` API**: callers on hot paths can reuse a
//!   [`PageScanOutput`] across pages to amortize allocation. The convenience
//!   wrappers (`scan_page`, `scan_page_with_dedupe`) allocate internally.
//! - **FNV-1a over SipHash**: we need cross-platform determinism, not DoS
//!   resistance. FNV is simpler and sufficient for fingerprinting here.

use std::convert::TryFrom;

use gossip_contracts::connector::{ScanItem, VersionId};

use crate::{
    PageScanContext, PageScanOutput, PageScanRequest, PageScanSummary, ScanDedupState,
    ScanDedupeCounters, ScanDiagnostic, ScanFinding, ScanStats, ScannerCoreBuildError,
    ScannerCoreError, StreamScanOutput,
};

/// FNV-1a 64-bit offset basis.
///
/// Chosen over `DefaultHasher` / SipHash for cross-platform determinism.
/// See <http://www.isthe.com/chongo/tech/comp/fnv/>.
const FNV_OFFSET: u64 = 0xcbf29ce484222325;
const FNV_PRIME: u64 = 0x100000001b3;

/// Configuration for [`ScannerCore`].
///
/// Controls two behavioral knobs:
/// - **Finding cap**: limits memory growth per page by capping emitted
///   findings. Items past the cap are still hashed and deduped, but not
///   materialized into [`ScanFinding`]s. A truncation diagnostic is emitted.
/// - **Metadata-only diagnostics**: when callers stage migration from
///   metadata-only to full-content evaluation, this flag surfaces pages
///   that lack payload bytes so operators can track migration progress.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScannerCoreConfig {
    max_findings_per_page: usize,
    emit_metadata_only_diagnostics: bool,
}

impl ScannerCoreConfig {
    /// Build a config with explicit values.
    ///
    /// Note: construction does **not** validate `max_findings_per_page > 0`.
    /// Validation happens at [`ScannerCore::new`] / [`ScannerCoreBuilder::build`].
    #[must_use]
    pub const fn new(max_findings_per_page: usize, emit_metadata_only_diagnostics: bool) -> Self {
        Self {
            max_findings_per_page,
            emit_metadata_only_diagnostics,
        }
    }

    /// Max findings emitted from one page before truncation diagnostics.
    #[must_use]
    pub const fn max_findings_per_page(&self) -> usize {
        self.max_findings_per_page
    }

    /// Whether to emit [`ScanDiagnostic::MetadataOnlyInputs`] when bytes are absent.
    #[must_use]
    pub const fn emit_metadata_only_diagnostics(&self) -> bool {
        self.emit_metadata_only_diagnostics
    }
}

impl Default for ScannerCoreConfig {
    /// 8 192 findings per page balances memory use against the likelihood of
    /// needing truncation on realistic connector pages. Metadata-only
    /// diagnostics are on by default so operators notice missing payloads.
    fn default() -> Self {
        Self {
            max_findings_per_page: 8_192,
            emit_metadata_only_diagnostics: true,
        }
    }
}

/// Builder for [`ScannerCore`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScannerCoreBuilder {
    config: ScannerCoreConfig,
}

impl ScannerCoreBuilder {
    /// Start from default scanner-core config.
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: ScannerCoreConfig::default(),
        }
    }

    /// Start from a caller-specified config baseline.
    #[must_use]
    pub fn with_config(config: ScannerCoreConfig) -> Self {
        Self { config }
    }

    /// Set `max_findings_per_page`.
    #[must_use]
    pub fn max_findings_per_page(mut self, value: usize) -> Self {
        self.config.max_findings_per_page = value;
        self
    }

    /// Toggle metadata-only input diagnostics.
    #[must_use]
    pub fn emit_metadata_only_diagnostics(mut self, value: bool) -> Self {
        self.config.emit_metadata_only_diagnostics = value;
        self
    }

    /// Validate and build a [`ScannerCore`].
    ///
    /// # Errors
    ///
    /// Returns [`ScannerCoreBuildError::ZeroMaxFindingsPerPage`] when
    /// `max_findings_per_page == 0`.
    pub fn build(self) -> Result<ScannerCore, ScannerCoreBuildError> {
        ScannerCore::new(self.config)
    }
}

impl Default for ScannerCoreBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Runtime-agnostic scanner core surface.
///
/// `ScannerCore` is a stateless, deterministic evaluation engine: given the
/// same `(config, request, dedupe-state)` triple, it always produces the same
/// output. All mutable state (dedupe set, output buffers) is caller-owned,
/// which means multiple pages or streams can share a single `ScannerCore`
/// value without synchronisation.
///
/// The Phase 1A implementation is intentionally side-effect-free so callers
/// can wire parity scaffolding before full detector migration.
///
/// # Entrypoint hierarchy
///
/// | Method | Allocates output? | Owns dedupe? | Use case |
/// |---|---|---|---|
/// | [`scan_page`](Self::scan_page) | yes | yes | One-shot single page |
/// | [`scan_page_with_dedupe`](Self::scan_page_with_dedupe) | yes | no | Multi-page manual loop |
/// | [`scan_page_into`](Self::scan_page_into) | no (caller scratch) | no | Hot path |
/// | [`scan_stream`](Self::scan_stream) | yes | yes | Full stream convenience |
/// | [`scan_stream_with_dedupe`](Self::scan_stream_with_dedupe) | yes | no | Resumable stream |
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ScannerCore {
    config: ScannerCoreConfig,
}

impl ScannerCore {
    /// Start building a scanner core using default config.
    #[must_use]
    pub fn builder() -> ScannerCoreBuilder {
        ScannerCoreBuilder::new()
    }

    /// Construct from explicit config.
    ///
    /// # Errors
    ///
    /// Returns [`ScannerCoreBuildError::ZeroMaxFindingsPerPage`] when
    /// `config.max_findings_per_page == 0`.
    pub fn new(config: ScannerCoreConfig) -> Result<Self, ScannerCoreBuildError> {
        if config.max_findings_per_page == 0 {
            return Err(ScannerCoreBuildError::ZeroMaxFindingsPerPage);
        }
        Ok(Self { config })
    }

    /// Scanner-core config in use for this instance.
    #[must_use]
    pub fn config(&self) -> ScannerCoreConfig {
        self.config
    }

    /// Scan one page request using a fresh dedupe state.
    ///
    /// For cross-page dedupe, use [`scan_page_with_dedupe`](Self::scan_page_with_dedupe)
    /// or [`scan_stream`](Self::scan_stream).
    ///
    /// # Errors
    ///
    /// Propagates [`ScannerCoreError`] when request invariants are violated.
    pub fn scan_page(
        &self,
        request: PageScanRequest<'_>,
    ) -> Result<PageScanOutput, ScannerCoreError> {
        let mut dedupe = ScanDedupState::default();
        self.scan_page_with_dedupe(request, &mut dedupe)
    }

    /// Scan one page request using caller-owned dedupe state.
    ///
    /// # Errors
    ///
    /// Propagates [`ScannerCoreError`] when request invariants are violated.
    pub fn scan_page_with_dedupe(
        &self,
        request: PageScanRequest<'_>,
        dedupe: &mut ScanDedupState,
    ) -> Result<PageScanOutput, ScannerCoreError> {
        let mut output = PageScanOutput::empty();
        self.scan_page_into(request, dedupe, &mut output)?;
        Ok(output)
    }

    /// Scan one page request into caller-owned output scratch.
    ///
    /// This is the lowest-level page entrypoint. It clears `output` and fills
    /// it in-place, so callers on hot paths can reuse a single
    /// [`PageScanOutput`] across successive pages without per-call allocation.
    ///
    /// # Errors
    ///
    /// - [`ScannerCoreError::ItemBytesLenMismatch`] — `item_bytes` was
    ///   provided but its length differs from `items`.
    /// - [`ScannerCoreError::PayloadLengthOverflow`] — a payload slice is
    ///   longer than `u64::MAX` (theoretical on 128-bit platforms).
    pub fn scan_page_into(
        &self,
        request: PageScanRequest<'_>,
        dedupe: &mut ScanDedupState,
        output: &mut PageScanOutput,
    ) -> Result<(), ScannerCoreError> {
        output.clear();

        let context = request.context();
        let items = request.items();
        let item_bytes = request.item_bytes();

        // --- Preflight: validate parallel-slice invariant early. ---
        if let Some(item_bytes) = item_bytes
            && item_bytes.len() != items.len()
        {
            return Err(ScannerCoreError::ItemBytesLenMismatch {
                page_num: context.page_num(),
                items: items.len(),
                item_bytes: item_bytes.len(),
            });
        }

        // Seed the page signature from context (range + cursor state).
        // Every item will be mixed in during the loop below.
        let mut signature = page_signature_seed(context);
        let mut bytes_scanned = 0_u64;
        let mut metadata_only_count = 0_usize;
        let mut findings_truncated = false;
        let mut counters = ScanDedupeCounters::default();

        for (item_index, item) in items.iter().enumerate() {
            // When item_bytes is None (metadata-only mode), payload is empty.
            let payload = item_bytes
                .and_then(|bytes| bytes.get(item_index).copied())
                .unwrap_or_default();
            let payload_len = u64::try_from(payload.len()).map_err(|_| {
                ScannerCoreError::PayloadLengthOverflow {
                    page_num: context.page_num(),
                    item_index,
                    payload_len: payload.len(),
                }
            })?;
            bytes_scanned = bytes_scanned.saturating_add(payload_len);
            if payload.is_empty() {
                metadata_only_count = metadata_only_count.saturating_add(1);
            }

            // Page signature covers *all* structural item fields for parity
            // comparison; this is intentionally broader than the fingerprint.
            mix_page_item_signature(&mut signature, item, payload);

            // --- Dedupe gate ---
            // The fingerprint is narrower than the signature: it covers only
            // (stable_item_id, version, payload) so that reordering items
            // across pages doesn't defeat dedup.
            counters = counters.with_candidate();
            let fingerprint = finding_fingerprint(item, payload);
            if dedupe.mark_seen(fingerprint) {
                // First occurrence: emit if we haven't hit the per-page cap.
                if output.findings().len() < self.config.max_findings_per_page {
                    output.push_finding(ScanFinding::new(
                        item.stable_item_id(),
                        item.version(),
                        context.page_num(),
                        item_index,
                        fingerprint,
                        payload_len,
                    ));
                    counters = counters.with_emitted();
                } else {
                    counters = counters.with_limit_suppressed();
                    findings_truncated = true;
                }
            } else {
                counters = counters.with_duplicate_suppressed();
            }
        }

        output.set_summary(PageScanSummary::new(
            context.page_num(),
            signature,
            items.len(),
            bytes_scanned,
        ));
        output.set_stats(ScanStats::new(1, items.len() as u64, bytes_scanned));
        output.set_dedupe(counters);

        // --- Post-loop diagnostics ---
        if self.config.emit_metadata_only_diagnostics && metadata_only_count > 0 {
            output.push_diagnostic(ScanDiagnostic::MetadataOnlyInputs {
                page_num: context.page_num(),
                item_count: metadata_only_count,
            });
        }
        if findings_truncated {
            output.push_diagnostic(ScanDiagnostic::FindingsTruncated {
                page_num: context.page_num(),
                max_findings_per_page: self.config.max_findings_per_page,
                suppressed: counters.limit_suppressed(),
            });
        }

        Ok(())
    }

    /// Scan a stream of pages with a fresh, internally-owned dedupe set.
    ///
    /// Page numbers must be **strictly increasing** across the iterator;
    /// equal or decreasing page numbers yield
    /// [`ScannerCoreError::NonMonotonicPageNum`].
    ///
    /// # Errors
    ///
    /// Propagates [`ScannerCoreError`] from page scanning and stream-order
    /// checks.
    pub fn scan_stream<'a, I>(&self, pages: I) -> Result<StreamScanOutput, ScannerCoreError>
    where
        I: IntoIterator<Item = PageScanRequest<'a>>,
    {
        let mut dedupe = ScanDedupState::default();
        self.scan_stream_with_dedupe(pages, &mut dedupe)
    }

    /// Scan a stream of pages with caller-owned dedupe state.
    ///
    /// Caller-owned dedupe allows resumable streams: scan pages 1–10, persist
    /// the dedupe set, then later scan pages 11–20 with the same set to
    /// maintain cross-batch deduplication.
    ///
    /// # Errors
    ///
    /// - [`ScannerCoreError::NonMonotonicPageNum`] if page numbers are not
    ///   strictly increasing.
    /// - Any error from [`scan_page_with_dedupe`](Self::scan_page_with_dedupe).
    pub fn scan_stream_with_dedupe<'a, I>(
        &self,
        pages: I,
        dedupe: &mut ScanDedupState,
    ) -> Result<StreamScanOutput, ScannerCoreError>
    where
        I: IntoIterator<Item = PageScanRequest<'a>>,
    {
        let mut output = StreamScanOutput::empty();
        let mut previous_page_num = None;

        for request in pages {
            let page_num = request.context().page_num();
            if let Some(previous_page_num) = previous_page_num
                && page_num <= previous_page_num
            {
                return Err(ScannerCoreError::NonMonotonicPageNum {
                    previous_page_num,
                    page_num,
                });
            }
            previous_page_num = Some(page_num);
            let page_output = self.scan_page_with_dedupe(request, dedupe)?;
            output.push_page(&page_output);
        }

        Ok(output)
    }
}

// ---------------------------------------------------------------------------
// FNV-1a mixing helpers
//
// These form a self-contained, deterministic hashing toolkit used by both
// page signatures and finding fingerprints. The contract is simple:
//   - All multi-byte values are mixed in little-endian order.
//   - Variable-length fields are length-prefixed before content so that
//     ("ab", "c") hashes differently from ("a", "bc").
//   - `Option<&[u8]>` is domain-separated with a tag byte (0 = None, 1 = Some).
// ---------------------------------------------------------------------------

/// Mix a single byte into the running FNV-1a state.
#[inline]
fn fnv_mix_byte(sig: &mut u64, byte: u8) {
    *sig ^= u64::from(byte);
    *sig = sig.wrapping_mul(FNV_PRIME);
}

/// Mix a `u64` as 8 little-endian bytes.
#[inline]
fn fnv_mix_u64(sig: &mut u64, value: u64) {
    for byte in value.to_le_bytes() {
        fnv_mix_byte(sig, byte);
    }
}

/// Mix a byte slice, length-prefixed to avoid collisions between
/// concatenations that share a common prefix.
///
/// Bulk processing in 8-byte words reduces per-byte overhead for large
/// payloads without changing the hash result.
#[inline]
fn fnv_mix_bytes(sig: &mut u64, bytes: &[u8]) {
    fnv_mix_u64(sig, bytes.len() as u64);
    let full_chunks = bytes.len() / 8;
    let (bulk, tail) = bytes.split_at(full_chunks * 8);
    for chunk in bulk.chunks_exact(8) {
        let word = u64::from_le_bytes(chunk.try_into().expect("8-byte chunk"));
        fnv_mix_u64(sig, word);
    }
    for byte in tail {
        fnv_mix_byte(sig, *byte);
    }
}

/// Mix an optional byte slice with a tag byte for domain separation.
#[inline]
fn fnv_mix_opt_bytes(sig: &mut u64, bytes: Option<&[u8]>) {
    match bytes {
        Some(bytes) => {
            fnv_mix_byte(sig, 1);
            fnv_mix_bytes(sig, bytes);
        }
        None => fnv_mix_byte(sig, 0),
    }
}

/// Derive the initial page signature from page-level context fields.
///
/// The seed captures the shard key range boundaries and both the current
/// and next cursors. This means any change in pagination state — even if
/// the same items appear — produces a different page signature, which is
/// the desired behavior for parity comparison between runtimes.
///
/// Individual items are mixed into this seed later by [`mix_page_item_signature`].
#[inline]
fn page_signature_seed(context: PageScanContext<'_>) -> u64 {
    let mut signature = FNV_OFFSET;
    fnv_mix_bytes(&mut signature, context.key_range_start());
    fnv_mix_bytes(&mut signature, context.key_range_end());
    fnv_mix_opt_bytes(
        &mut signature,
        context.cursor().last_key().map(|key| key.as_bytes()),
    );
    fnv_mix_opt_bytes(
        &mut signature,
        context.cursor().token().map(|token| token.as_bytes()),
    );
    fnv_mix_opt_bytes(
        &mut signature,
        context.next_cursor().last_key().map(|key| key.as_bytes()),
    );
    fnv_mix_opt_bytes(
        &mut signature,
        context.next_cursor().token().map(|token| token.as_bytes()),
    );
    signature
}

/// Fold one item's structural fields into the running page signature.
///
/// Covers `item_key`, `item_ref`, `stable_item_id`, `size_hint`, and
/// payload — intentionally broader than [`finding_fingerprint`] so that
/// any metadata drift is detectable even when it doesn't affect dedup.
///
/// `size_hint` is sentinel-encoded (`u64::MAX` for `None`) rather than
/// using `fnv_mix_opt_bytes` because it is always a scalar, not a slice.
#[inline]
fn mix_page_item_signature(signature: &mut u64, item: &ScanItem, payload: &[u8]) {
    fnv_mix_bytes(signature, item.item_key().as_bytes());
    fnv_mix_bytes(signature, item.item_ref().as_bytes());
    fnv_mix_bytes(signature, item.stable_item_id().as_bytes());
    fnv_mix_u64(signature, item.size_hint().unwrap_or(u64::MAX));
    fnv_mix_bytes(signature, payload);
}

/// Compute the dedup fingerprint for one item.
///
/// The fingerprint is the key into [`ScanDedupState`]. It covers only the
/// fields that define *logical identity*:
///
/// - `stable_item_id` — tenant-independent object identity.
/// - `version` (strong or weak) — domain-separated with tag bytes
///   `1` (strong) / `2` (weak) to prevent collisions between version
///   namespaces.
/// - `payload` — the content bytes, if present.
///
/// Crucially, `item_key` and `item_ref` are **excluded** so that the same
/// logical item appearing on different pages (due to cursor drift or
/// re-enumeration) is still deduplicated.
#[inline]
fn finding_fingerprint(item: &ScanItem, payload: &[u8]) -> u64 {
    let mut fingerprint = FNV_OFFSET;
    fnv_mix_bytes(&mut fingerprint, item.stable_item_id().as_bytes());
    match item.version() {
        VersionId::Strong(version) => {
            fnv_mix_byte(&mut fingerprint, 1);
            fnv_mix_bytes(&mut fingerprint, version.as_bytes());
        }
        VersionId::Weak(version) => {
            fnv_mix_byte(&mut fingerprint, 2);
            fnv_mix_bytes(&mut fingerprint, version.as_bytes());
        }
    }
    fnv_mix_bytes(&mut fingerprint, payload);
    fingerprint
}

#[cfg(test)]
#[path = "core_tests.rs"]
mod tests;
