//! Value types for the scanner-core scan pipeline.
//!
//! This module defines the typed contract surface between connector-produced
//! page data and the runtime-agnostic [`ScannerCore`](crate::ScannerCore).
//! Types are organized in a pipeline progression:
//!
//! ```text
//! PageScanContext  ──►  PageScanRequest  ──►  ScannerCore::scan_page
//!                                                    │
//!           ┌────────────────────────────────────────┘
//!           ▼
//!    PageScanOutput  ──►  StreamScanOutput   (accumulated across pages)
//!    ├── PageScanSummary    (deterministic page signature + counters)
//!    ├── ScanFinding[]      (per-item identity envelope)
//!    ├── ScanStats          (throughput counters)
//!    ├── ScanDedupeCounters (candidate / emitted / suppressed tallies)
//!    └── ScanDiagnostic[]   (structured warnings)
//! ```
//!
//! ## Design choices
//!
//! - **Borrowed inputs** (`PageScanContext`, `PageScanRequest`): all request
//!   types borrow from caller-owned data so the core never forces a per-page
//!   allocation on its callers.
//! - **Caller-owned dedupe** ([`ScanDedupState`]): fingerprint tracking is
//!   externalized so callers can scope dedup to a single page, a stream, or an
//!   entire scan session without the core dictating lifetime policy.
//! - **Reusable output scratch** (`PageScanOutput::clear`): callers on hot
//!   paths can reuse a single output buffer across pages via
//!   [`ScannerCore::scan_page_into`](crate::ScannerCore::scan_page_into).
//! - **Saturating arithmetic** everywhere counters are merged — overflow is
//!   treated as "max observed" rather than a panic or wrap-around.

use std::collections::HashSet;

use gossip_contracts::{
    connector::{Cursor, ScanItem, VersionId},
    identity::StableItemId,
};

/// `HashSet<u64>` using ahash (non-cryptographic, faster than SipHash for
/// small integer keys). Safe here because the keys are already FNV-1a
/// fingerprints — no DoS concern.
type AHashSet64 = HashSet<u64, ahash::RandomState>;

/// Borrowed page-level context that seeds deterministic scan identities.
///
/// A `PageScanContext` captures the minimal set of boundary fields —
/// shard key range, current/next cursor pair, and 1-based page number —
/// from which the scanner core derives both page-level signatures and
/// per-item fingerprints.  It mirrors the scan-pipeline's page hook
/// boundary while remaining runtime-agnostic (no I/O, no formatting).
///
/// All fields are borrowed from the caller to avoid per-page allocation
/// in the core.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PageScanContext<'a> {
    key_range_start: &'a [u8],
    key_range_end: &'a [u8],
    cursor: &'a Cursor,
    next_cursor: &'a Cursor,
    page_num: u64,
}

impl<'a> PageScanContext<'a> {
    /// Construct a page-scan context from its constituent boundary fields.
    ///
    /// `page_num` is 1-based by convention; the scanner core does not enforce
    /// this for individual pages, but [`ScannerCore::scan_stream`](crate::ScannerCore::scan_stream)
    /// requires strictly increasing page numbers across a stream.
    #[must_use]
    pub fn new(
        key_range_start: &'a [u8],
        key_range_end: &'a [u8],
        cursor: &'a Cursor,
        next_cursor: &'a Cursor,
        page_num: u64,
    ) -> Self {
        Self {
            key_range_start,
            key_range_end,
            cursor,
            next_cursor,
            page_num,
        }
    }

    /// Start of the shard key range associated with this page.
    #[must_use]
    pub fn key_range_start(&self) -> &'a [u8] {
        self.key_range_start
    }

    /// End of the shard key range associated with this page.
    #[must_use]
    pub fn key_range_end(&self) -> &'a [u8] {
        self.key_range_end
    }

    /// Cursor used to request this page.
    #[must_use]
    pub fn cursor(&self) -> &'a Cursor {
        self.cursor
    }

    /// Connector-provided continuation cursor for the next page.
    #[must_use]
    pub fn next_cursor(&self) -> &'a Cursor {
        self.next_cursor
    }

    /// 1-based page number within a scan stream.
    #[must_use]
    pub fn page_num(&self) -> u64 {
        self.page_num
    }
}

/// Borrowed input for scanning a single connector page.
///
/// Carries the page context, the connector-produced item metadata slice,
/// and an optional parallel slice of per-item payload bytes.
///
/// `item_bytes` is optional to support two migration stages:
/// - **Metadata-only** (Phase 1A): parity is checked from identity fields
///   alone; `item_bytes` is `None`.
/// - **Full content** (Phase 1B+): payload bytes are mixed into fingerprints
///   and signatures, enabling content-level change detection.
///
/// When `item_bytes` is `Some`, its length **must** equal `items.len()`;
/// the scanner core returns [`ScannerCoreError::ItemBytesLenMismatch`](crate::ScannerCoreError::ItemBytesLenMismatch)
/// otherwise.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PageScanRequest<'a> {
    context: PageScanContext<'a>,
    items: &'a [ScanItem],
    item_bytes: Option<&'a [&'a [u8]]>,
}

impl<'a> PageScanRequest<'a> {
    /// Build a metadata-only page request.
    #[must_use]
    pub fn metadata_only(context: PageScanContext<'a>, items: &'a [ScanItem]) -> Self {
        Self {
            context,
            items,
            item_bytes: None,
        }
    }

    /// Build a page request that includes per-item payload bytes.
    ///
    /// # Preconditions
    ///
    /// `item_bytes.len()` **must** equal `items.len()`.  This is not enforced
    /// at construction time (to keep the builder zero-cost) but is validated
    /// when the request is submitted to [`ScannerCore::scan_page`](crate::ScannerCore::scan_page).
    #[must_use]
    pub fn with_item_bytes(
        context: PageScanContext<'a>,
        items: &'a [ScanItem],
        item_bytes: &'a [&'a [u8]],
    ) -> Self {
        Self {
            context,
            items,
            item_bytes: Some(item_bytes),
        }
    }

    /// Page context metadata.
    #[must_use]
    pub fn context(&self) -> PageScanContext<'a> {
        self.context
    }

    /// Connector scan items for this page.
    #[must_use]
    pub fn items(&self) -> &'a [ScanItem] {
        self.items
    }

    /// Optional per-item payload bytes.
    #[must_use]
    pub fn item_bytes(&self) -> Option<&'a [&'a [u8]]> {
        self.item_bytes
    }
}

/// Deterministic summary produced after evaluating one page.
///
/// The `signature` field is an FNV-1a hash over the page's key range,
/// cursor pair, and every item's identity + payload bytes.  Two pages that
/// present identical boundary context and identical item content will
/// always produce the same signature, making it suitable for parity
/// comparison between the old and new scan pipelines.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PageScanSummary {
    page_num: u64,
    signature: u64,
    item_count: usize,
    bytes_scanned: u64,
}

impl PageScanSummary {
    #[must_use]
    pub(crate) const fn new(
        page_num: u64,
        signature: u64,
        item_count: usize,
        bytes_scanned: u64,
    ) -> Self {
        Self {
            page_num,
            signature,
            item_count,
            bytes_scanned,
        }
    }

    /// 1-based page number from the request context.
    #[must_use]
    pub fn page_num(&self) -> u64 {
        self.page_num
    }

    /// FNV-1a page signature over key range, cursor pair, and all item fields.
    ///
    /// Deterministic: identical inputs always yield the same value.  Used for
    /// cross-pipeline parity comparison.
    #[must_use]
    pub fn signature(&self) -> u64 {
        self.signature
    }

    /// Number of items on this page.
    #[must_use]
    pub fn item_count(&self) -> usize {
        self.item_count
    }

    /// Total payload bytes consumed on this page.
    #[must_use]
    pub fn bytes_scanned(&self) -> u64 {
        self.bytes_scanned
    }
}

/// Per-item finding emitted by the scanner core after dedupe and limit gates.
///
/// A `ScanFinding` is a deterministic identity envelope: it captures the
/// item's stable identity, version, position within the page, a content
/// fingerprint, and the payload byte count mixed into that fingerprint.
///
/// ## Fingerprint semantics
///
/// The `fingerprint` is an FNV-1a hash over `(stable_item_id, version, payload)`.
/// Two items with identical identity *and* identical content produce the same
/// fingerprint, which the dedupe layer uses to suppress duplicates across
/// pages.  A fingerprint collision (different content, same hash) is
/// theoretically possible but benign in Phase 1A: it causes a duplicate
/// suppression, not a false positive.
///
/// ## Phase 1A scope
///
/// Currently used for parity wiring and dedupe behavior validation against
/// the legacy pipeline.  In later phases, findings may carry richer
/// detection metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScanFinding {
    stable_item_id: StableItemId,
    version: VersionId,
    page_num: u64,
    item_index: usize,
    fingerprint: u64,
    payload_bytes: u64,
}

impl ScanFinding {
    #[must_use]
    pub(crate) const fn new(
        stable_item_id: StableItemId,
        version: VersionId,
        page_num: u64,
        item_index: usize,
        fingerprint: u64,
        payload_bytes: u64,
    ) -> Self {
        Self {
            stable_item_id,
            version,
            page_num,
            item_index,
            fingerprint,
            payload_bytes,
        }
    }

    /// Stable tenant-independent item identity.
    #[must_use]
    pub fn stable_item_id(&self) -> StableItemId {
        self.stable_item_id
    }

    /// Connector version semantics recorded for this finding.
    #[must_use]
    pub fn version(&self) -> VersionId {
        self.version
    }

    /// Page number where this finding was observed.
    #[must_use]
    pub fn page_num(&self) -> u64 {
        self.page_num
    }

    /// Zero-based item index within the page.
    #[must_use]
    pub fn item_index(&self) -> usize {
        self.item_index
    }

    /// FNV-1a fingerprint over `(stable_item_id, version, payload)`.
    ///
    /// Used by [`ScanDedupState`] to suppress duplicate findings across pages.
    #[must_use]
    pub fn fingerprint(&self) -> u64 {
        self.fingerprint
    }

    /// Number of payload bytes mixed into the finding fingerprint.
    #[must_use]
    pub fn payload_bytes(&self) -> u64 {
        self.payload_bytes
    }
}

/// Aggregate counters tracking the dedupe funnel for a scan operation.
///
/// Every item entering the scan loop is a `candidate`.  It exits as exactly
/// one of:
/// - `emitted` — unique fingerprint, within the per-page findings limit.
/// - `duplicate_suppressed` — fingerprint already seen in the dedupe state.
/// - `limit_suppressed` — unique, but `max_findings_per_page` was reached.
///
/// **Invariant:** `candidates == emitted + duplicate_suppressed + limit_suppressed`.
///
/// Counters are updated in-place via `increment_*` methods on the hot path.
/// Internally, `merge` combines page-level counters into stream-level
/// aggregates.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ScanDedupeCounters {
    candidates: u64,
    emitted: u64,
    duplicate_suppressed: u64,
    limit_suppressed: u64,
}

impl ScanDedupeCounters {
    /// Increment candidates in place (hot-path mutation, avoids struct copy).
    pub(crate) fn increment_candidate(&mut self) {
        self.candidates = self.candidates.saturating_add(1);
    }

    /// Increment emitted in place.
    pub(crate) fn increment_emitted(&mut self) {
        self.emitted = self.emitted.saturating_add(1);
    }

    /// Increment duplicate_suppressed in place.
    pub(crate) fn increment_duplicate_suppressed(&mut self) {
        self.duplicate_suppressed = self.duplicate_suppressed.saturating_add(1);
    }

    /// Increment limit_suppressed in place.
    pub(crate) fn increment_limit_suppressed(&mut self) {
        self.limit_suppressed = self.limit_suppressed.saturating_add(1);
    }

    /// Combine two counter snapshots (e.g., page-level into stream-level).
    ///
    /// All fields use saturating addition — overflow clamps to `u64::MAX`
    /// rather than panicking, since these are observability counters, not
    /// correctness-critical values.
    #[must_use]
    pub(crate) fn merge(self, other: Self) -> Self {
        Self {
            candidates: self.candidates.saturating_add(other.candidates),
            emitted: self.emitted.saturating_add(other.emitted),
            duplicate_suppressed: self
                .duplicate_suppressed
                .saturating_add(other.duplicate_suppressed),
            limit_suppressed: self.limit_suppressed.saturating_add(other.limit_suppressed),
        }
    }

    /// Total candidate findings considered before dedupe.
    #[must_use]
    pub fn candidates(&self) -> u64 {
        self.candidates
    }

    /// Findings that survived dedupe and limit gates.
    #[must_use]
    pub fn emitted(&self) -> u64 {
        self.emitted
    }

    /// Findings suppressed because an identical fingerprint already existed.
    #[must_use]
    pub fn duplicate_suppressed(&self) -> u64 {
        self.duplicate_suppressed
    }

    /// Findings suppressed due to `max_findings_per_page`.
    #[must_use]
    pub fn limit_suppressed(&self) -> u64 {
        self.limit_suppressed
    }
}

/// Throughput counters for pages, items, and bytes processed.
///
/// Like [`ScanDedupeCounters`], stats use saturating arithmetic and are
/// accumulated via an internal `merge` when building stream-level totals.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ScanStats {
    pages_scanned: u64,
    items_scanned: u64,
    bytes_scanned: u64,
}

impl ScanStats {
    #[must_use]
    pub(crate) const fn new(pages_scanned: u64, items_scanned: u64, bytes_scanned: u64) -> Self {
        Self {
            pages_scanned,
            items_scanned,
            bytes_scanned,
        }
    }

    #[must_use]
    pub(crate) fn merge(self, other: Self) -> Self {
        Self {
            pages_scanned: self.pages_scanned.saturating_add(other.pages_scanned),
            items_scanned: self.items_scanned.saturating_add(other.items_scanned),
            bytes_scanned: self.bytes_scanned.saturating_add(other.bytes_scanned),
        }
    }

    /// Number of page requests processed.
    #[must_use]
    pub fn pages_scanned(&self) -> u64 {
        self.pages_scanned
    }

    /// Number of connector items processed.
    #[must_use]
    pub fn items_scanned(&self) -> u64 {
        self.items_scanned
    }

    /// Number of payload bytes mixed into finding/signature identity.
    #[must_use]
    pub fn bytes_scanned(&self) -> u64 {
        self.bytes_scanned
    }
}

/// Structured diagnostic event emitted during page evaluation.
///
/// Diagnostics are advisory, not errors — they signal conditions the
/// caller may want to log or alert on but that do not prevent the scan
/// from completing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScanDiagnostic {
    /// Page was evaluated without per-item payload bytes.
    MetadataOnlyInputs { page_num: u64, item_count: usize },
    /// Findings exceeded configured `max_findings_per_page`.
    FindingsTruncated {
        page_num: u64,
        max_findings_per_page: usize,
        suppressed: u64,
    },
}

/// Collected output from scanning one page request.
///
/// Mutation is crate-internal via `pub(crate)` setters so that
/// [`ScannerCore`](crate::ScannerCore) can populate fields incrementally
/// during the scan loop.  External consumers see only immutable accessors.
///
/// ## Reuse pattern
///
/// For hot-path callers, `PageScanOutput` supports a clear-and-reuse
/// cycle: clear all fields (or use
/// [`ScannerCore::scan_page_into`](crate::ScannerCore::scan_page_into))
/// to reset all fields without deallocating the backing `Vec`s, keeping
/// capacity warm across pages.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PageScanOutput {
    summary: PageScanSummary,
    findings: Vec<ScanFinding>,
    stats: ScanStats,
    dedupe: ScanDedupeCounters,
    diagnostics: Vec<ScanDiagnostic>,
}

impl PageScanOutput {
    #[must_use]
    pub(crate) fn empty() -> Self {
        Self::default()
    }

    /// Reset all fields to default without releasing heap capacity.
    ///
    /// `Vec::clear` preserves allocated capacity, so repeated
    /// `clear → scan_page_into` cycles amortize allocation cost.
    pub(crate) fn clear(&mut self) {
        self.summary = PageScanSummary::default();
        self.findings.clear();
        self.stats = ScanStats::default();
        self.dedupe = ScanDedupeCounters::default();
        self.diagnostics.clear();
    }

    pub(crate) fn set_summary(&mut self, summary: PageScanSummary) {
        self.summary = summary;
    }

    pub(crate) fn set_stats(&mut self, stats: ScanStats) {
        self.stats = stats;
    }

    pub(crate) fn set_dedupe(&mut self, dedupe: ScanDedupeCounters) {
        self.dedupe = dedupe;
    }

    /// Ensure the findings buffer has room for at least `additional` more
    /// entries. Called at the top of `scan_page_into` so the hot loop avoids
    /// incremental reallocation.
    pub(crate) fn reserve_findings(&mut self, additional: usize) {
        self.findings.reserve(additional);
    }

    pub(crate) fn push_finding(&mut self, finding: ScanFinding) {
        self.findings.push(finding);
    }

    pub(crate) fn push_diagnostic(&mut self, diagnostic: ScanDiagnostic) {
        self.diagnostics.push(diagnostic);
    }

    /// Page-level deterministic summary.
    #[must_use]
    pub fn summary(&self) -> &PageScanSummary {
        &self.summary
    }

    /// Per-item findings emitted for this page.
    #[must_use]
    pub fn findings(&self) -> &[ScanFinding] {
        &self.findings
    }

    /// Throughput counters for this page.
    #[must_use]
    pub fn stats(&self) -> ScanStats {
        self.stats
    }

    /// Dedupe counters for this page.
    #[must_use]
    pub fn dedupe(&self) -> ScanDedupeCounters {
        self.dedupe
    }

    /// Diagnostics emitted while scanning this page.
    #[must_use]
    pub fn diagnostics(&self) -> &[ScanDiagnostic] {
        &self.diagnostics
    }
}

/// Accumulated output from scanning a stream of pages.
///
/// Built incrementally by the scanner core, which merges
/// each [`PageScanOutput`] into running totals for stats/dedupe and
/// appends findings and diagnostics in stream order.
///
/// Findings are **already deduplicated** across pages (via the shared
/// [`ScanDedupState`] passed through the stream), so the `findings` slice
/// contains only unique items for the entire stream.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StreamScanOutput {
    page_summaries: Vec<PageScanSummary>,
    findings: Vec<ScanFinding>,
    stats: ScanStats,
    dedupe: ScanDedupeCounters,
    diagnostics: Vec<ScanDiagnostic>,
}

impl StreamScanOutput {
    #[must_use]
    pub(crate) fn empty() -> Self {
        Self::default()
    }

    /// Fold a single page's output into the running stream totals.
    pub(crate) fn push_page(&mut self, page: &PageScanOutput) {
        self.page_summaries.push(*page.summary());
        self.findings.extend_from_slice(page.findings());
        self.stats = self.stats.merge(page.stats());
        self.dedupe = self.dedupe.merge(page.dedupe());
        self.diagnostics.extend_from_slice(page.diagnostics());
    }

    /// Per-page summaries in stream order.
    #[must_use]
    pub fn page_summaries(&self) -> &[PageScanSummary] {
        &self.page_summaries
    }

    /// Flattened findings across all pages.
    #[must_use]
    pub fn findings(&self) -> &[ScanFinding] {
        &self.findings
    }

    /// Aggregate throughput counters.
    #[must_use]
    pub fn stats(&self) -> ScanStats {
        self.stats
    }

    /// Aggregate dedupe counters.
    #[must_use]
    pub fn dedupe(&self) -> ScanDedupeCounters {
        self.dedupe
    }

    /// Diagnostics across all pages in stream order.
    #[must_use]
    pub fn diagnostics(&self) -> &[ScanDiagnostic] {
        &self.diagnostics
    }
}

/// Caller-owned fingerprint set for cross-page duplicate suppression.
///
/// The scanner core does not own this state — callers create it, pass it
/// in by `&mut` reference, and decide when to [`clear`](Self::clear) it.
/// This gives callers full control over dedup scope:
///
/// - **Per-page**: create a fresh state (or clear it) before each page.
/// - **Per-stream**: reuse across all pages in a
///   [`scan_stream`](crate::ScannerCore::scan_stream) call.
/// - **Per-session**: carry state across multiple streams to deduplicate
///   an entire scan session.
///
/// Internally a `HashSet<u64, ahash::RandomState>` keyed on finding
/// fingerprints.  Uses ahash instead of the default SipHash for faster
/// lookups — the keys are already FNV-1a hashes, so cryptographic hash
/// resistance is unnecessary.  Dedup granularity is
/// `(stable_item_id, version, payload)` — the same fields mixed into
/// [`ScanFinding::fingerprint`].
#[derive(Clone, Debug)]
pub struct ScanDedupState {
    seen: AHashSet64,
}

impl Default for ScanDedupState {
    fn default() -> Self {
        Self {
            seen: HashSet::with_hasher(ahash::RandomState::new()),
        }
    }
}

impl ScanDedupState {
    /// Create an empty dedupe state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a dedupe state pre-sized for `capacity` unique fingerprints.
    ///
    /// Use this when the approximate item count is known up-front (e.g.,
    /// from a manifest or page-count estimate) to avoid rehashing during
    /// the scan loop.
    ///
    /// Each entry is a `u64` fingerprint (8 bytes) plus hash-map overhead,
    /// so budget roughly 40–56 bytes per entry depending on load factor.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            seen: HashSet::with_capacity_and_hasher(capacity, ahash::RandomState::new()),
        }
    }

    /// Number of unique fingerprints tracked so far.
    #[must_use]
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// Returns true when the dedupe state contains no fingerprints.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    /// Clear tracked fingerprints.
    pub fn clear(&mut self) {
        self.seen.clear();
    }

    /// Record a fingerprint; returns `true` if it was **not** already present.
    ///
    /// Mirrors `HashSet::insert` semantics: `true` = newly inserted (unique),
    /// `false` = duplicate.
    pub(crate) fn mark_seen(&mut self, fingerprint: u64) -> bool {
        self.seen.insert(fingerprint)
    }
}

#[cfg(test)]
#[path = "types_tests.rs"]
mod tests;
