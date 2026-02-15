//! Boundary â‘£ â€” Connector Contract: Chunk 5 (DRAFT)
//!
//! Shard-level statistics, full-pipeline integration helpers,
//! consolidated invariant catalog, and cross-boundary dependency map.
//!
//! This file is additive to Boundaries â‘ â€“â‘¢ (all chunks) and Boundary â‘£
//! chunks 1â€“4 (value types, traits, runtime bridge, test connector).
//!
//! ## Problem Statement
//!
//! With the connector value types (chunk 1), traits (chunk 2), runtime
//! bridge (chunk 3), and deterministic test connector (chunk 4) in
//! place, two gaps remain:
//!
//! 1. **Shard-level statistics**: As the runtime processes items from
//!    enumeration pages, it needs to aggregate per-shard metrics for
//!    observability, completion decisions, and hand-off to Boundary â‘¤
//!    (persistence). These statistics answer: "How did this shard's
//!    scan go?" â€” including item counts by outcome, finding totals,
//!    bytes processed, pages enumerated, and error tallies.
//!
//! 2. **Integration test helpers**: The chunks so far test each piece
//!    in isolation. Chunk 5 provides helpers that exercise the full
//!    pipeline: enumerate â†’ validate â†’ extract cursor â†’ read â†’
//!    record outcome â†’ aggregate stats. These helpers serve as both
//!    tests and documentation of how the runtime should compose B4.
//!
//! 3. **Consolidated catalog**: All invariants, design decisions, and
//!    cross-boundary dependencies for Boundary â‘£ in one reference.
//!
//! ## Design Decisions (locked)
//!
//! D4.40: `ShardScanStats` is a plain accumulator, NOT a stateful
//!        controller. The runtime calls `record_*` methods as items
//!        are processed; the stats struct holds running totals.
//!
//!        **Why**: Same philosophy as B3 `CoverageReport` â€” pure data,
//!        computed by the caller. No side effects, no I/O. The runtime
//!        owns the processing loop; stats are just bookkeeping.
//!
//! D4.41: Stats are per-shard, per-scan-cycle. When a shard completes
//!        or is parked, its stats are finalized and passed to the
//!        persistence layer (B5). There is no global stats aggregation
//!        in the contracts crate â€” that's an observability concern
//!        owned by the runtime.
//!
//! D4.42: `ShardScanStats` tracks both item-level outcomes AND
//!        page-level metadata (total pages, total API calls). This
//!        dual granularity is needed because:
//!        - Item outcomes feed the done-ledger (B5).
//!        - Page counts feed rate-limit budgeting and lease renewal
//!          decisions.
//!
//! D4.43: Integration helpers are functions, NOT a test harness
//!        framework. Each helper does one thing (e.g.,
//!        `run_shard_enumeration` iterates pages to exhaustion).
//!        The caller composes them. This avoids framework lock-in
//!        and keeps each helper independently testable.
//!
//!        Reference: xUnit Patterns (Meszaros, 2007) â€” prefer helper
//!        functions over test-framework abstractions.

// Assumes all types from prior boundaries and B4 chunks 1â€“4 are in scope.

use core::fmt;

// ============================================================================
// Â§ Chunk 5: Stats, Integration Helpers, Consolidated Catalog
// ============================================================================

// ---------------------------------------------------------------------------
// Â§5.1 ShardScanStats â€” per-shard scan metrics
// ---------------------------------------------------------------------------

/// Accumulated statistics for a single shard's scan cycle.
///
/// Built up incrementally as the runtime processes enumeration pages
/// and reads item content. Finalized when the shard reaches a terminal
/// state (Done or Parked).
///
/// ## Usage
///
/// ```text
///   let mut stats = ShardScanStats::new();
///
///   // Enumeration loop
///   loop {
///       let page = connector.enumerate_page(&spec, &cursor, &budget)?;
///       stats.record_page(&page);
///
///       for item in &page.items {
///           let outcome = process_item(item, &reader, &done_ledger);
///           stats.record_outcome(&outcome);
///       }
///
///       match page.next_cursor {
///           Some(next) => cursor = next,
///           None => break,
///       }
///   }
///
///   // stats is now finalized â€” pass to persistence layer.
///   persistence.flush_shard_stats(&shard_key, &stats)?;
/// ```
///
/// ## Invariants
///
/// **Safety (monotonic counters)**: All counters are monotonically
/// non-decreasing. There is no `decrement` or `reset` operation.
///
/// **Safety (consistent totals)**: `items_scanned + items_skipped
/// == items_enumerated` at all times. Every enumerated item has
/// exactly one outcome recorded.
///
/// **Safety (deterministic)**: Given the same sequence of
/// `record_page` and `record_outcome` calls, the stats are
/// identical. No time-dependence or randomness.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ShardScanStats {
    // -- Page-level counters --

    /// Total enumeration pages retrieved (successful calls only).
    pub pages_enumerated: u32,

    /// Total API calls consumed across all pages (sum of
    /// `EnumerationPage.api_calls_used`).
    pub api_calls_used: u32,

    /// Number of enumeration errors encountered (retried or not).
    pub enumeration_errors: u32,

    // -- Item-level counters --

    /// Total items discovered via enumeration.
    /// = items_scanned + items_skipped_version + items_skipped_binary
    ///   + items_skipped_read_error + items_scanned_truncated
    pub items_enumerated: u32,

    /// Items fully scanned (content read and analyzed).
    pub items_scanned: u32,

    /// Items scanned but content was truncated (exceeded budget).
    pub items_scanned_truncated: u32,

    /// Items skipped because the done-ledger had a matching
    /// strong version (no rescan needed).
    pub items_skipped_version: u32,

    /// Items skipped because content hints indicated binary
    /// content not covered by scan rules.
    pub items_skipped_binary: u32,

    /// Items skipped due to read errors (item deleted, permission
    /// denied, etc.).
    pub items_skipped_read_error: u32,

    // -- Finding counters --

    /// Total findings (secrets) detected across all scanned items.
    pub findings_total: u32,

    // -- Byte counters --

    /// Total bytes read from item content (including truncated reads).
    pub bytes_read: u64,

    // -- Read error counters --

    /// Number of read errors encountered (retried or not).
    pub read_errors: u32,
}

impl ShardScanStats {
    /// Create a new, zeroed stats accumulator.
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a successful enumeration page.
    ///
    /// Updates page count, API call total, and items_enumerated.
    pub fn record_page(&mut self, page: &EnumerationPage) {
        self.pages_enumerated += 1;
        self.api_calls_used += page.api_calls_used;
        self.items_enumerated += page.items.len() as u32;
    }

    /// Record an enumeration error (whether or not it was retried).
    #[inline]
    pub fn record_enumeration_error(&mut self) {
        self.enumeration_errors += 1;
    }

    /// Record the outcome of processing a single item.
    pub fn record_outcome(&mut self, outcome: &ItemOutcome) {
        match outcome {
            ItemOutcome::Scanned { findings } => {
                self.items_scanned += 1;
                self.findings_total += findings;
            }
            ItemOutcome::ScannedTruncated {
                findings,
                bytes_read,
            } => {
                self.items_scanned_truncated += 1;
                self.findings_total += findings;
                self.bytes_read += bytes_read;
            }
            ItemOutcome::SkippedByVersion => {
                self.items_skipped_version += 1;
            }
            ItemOutcome::SkippedBinary => {
                self.items_skipped_binary += 1;
            }
            ItemOutcome::SkippedReadError { .. } => {
                self.items_skipped_read_error += 1;
            }
        }
    }

    /// Record bytes read from a fully-scanned item (not truncated).
    ///
    /// Called separately from `record_outcome` because the byte count
    /// is known only after the read completes, while the outcome
    /// (finding count) is known only after scanning.
    #[inline]
    pub fn record_bytes_read(&mut self, bytes: u64) {
        self.bytes_read += bytes;
    }

    /// Record a read error (whether or not it was retried).
    #[inline]
    pub fn record_read_error(&mut self) {
        self.read_errors += 1;
    }

    // -- Derived metrics --

    /// Total items processed (scanned or skipped).
    /// Should equal `items_enumerated` when the shard is complete.
    #[inline]
    pub fn items_processed(&self) -> u32 {
        self.items_scanned
            + self.items_scanned_truncated
            + self.items_skipped_version
            + self.items_skipped_binary
            + self.items_skipped_read_error
    }

    /// Total items actually scanned (fully or truncated).
    #[inline]
    pub fn items_scanned_total(&self) -> u32 {
        self.items_scanned + self.items_scanned_truncated
    }

    /// Total items skipped (all skip reasons).
    #[inline]
    pub fn items_skipped_total(&self) -> u32 {
        self.items_skipped_version + self.items_skipped_binary + self.items_skipped_read_error
    }

    /// Fraction of enumerated items that were scanned (0.0 to 1.0).
    /// Returns 0.0 if no items were enumerated.
    pub fn scan_fraction(&self) -> f64 {
        if self.items_enumerated == 0 {
            return 0.0;
        }
        f64::from(self.items_scanned_total()) / f64::from(self.items_enumerated)
    }

    /// Returns `true` if all enumerated items have been processed.
    ///
    /// This is a consistency check: when the shard is about to
    /// complete, `items_processed() == items_enumerated` must hold.
    #[inline]
    pub fn is_fully_processed(&self) -> bool {
        self.items_processed() == self.items_enumerated
    }

    /// Assert that all enumerated items have been processed.
    ///
    /// # Panics
    ///
    /// Panics with diagnostic info if the counts don't match.
    pub fn assert_fully_processed(&self) {
        assert!(
            self.is_fully_processed(),
            "ShardScanStats: items_processed ({}) != items_enumerated ({}). \
             Breakdown: scanned={}, truncated={}, skip_ver={}, skip_bin={}, skip_err={}",
            self.items_processed(),
            self.items_enumerated,
            self.items_scanned,
            self.items_scanned_truncated,
            self.items_skipped_version,
            self.items_skipped_binary,
            self.items_skipped_read_error,
        );
    }
}

impl fmt::Display for ShardScanStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "pages={} items={} scanned={} skipped={} findings={} bytes={} errors(enum={},read={})",
            self.pages_enumerated,
            self.items_enumerated,
            self.items_scanned_total(),
            self.items_skipped_total(),
            self.findings_total,
            self.bytes_read,
            self.enumeration_errors,
            self.read_errors,
        )
    }
}

// ---------------------------------------------------------------------------
// Â§5.2 Integration helpers â€” composing the full pipeline
// ---------------------------------------------------------------------------

/// Result of running a shard's enumeration to exhaustion.
///
/// Returned by `run_shard_enumeration`. Contains all pages' items
/// collected into a single list, the final cursor, and accumulated
/// stats. Used in tests to verify the full enumeration pipeline.
#[derive(Debug)]
pub struct EnumerationRun {
    /// All items collected across all pages, in enumeration order.
    pub items: Vec<ScanItem>,

    /// The final cursor (from the last page's next_cursor, or
    /// constructed from the last item if exhausted).
    pub final_cursor: Option<Cursor>,

    /// Accumulated stats.
    pub stats: ShardScanStats,

    /// Number of pages retrieved.
    pub page_count: u32,

    /// Whether enumeration completed (last page had no next_cursor)
    /// or was interrupted (e.g., max_pages reached).
    pub exhausted: bool,
}

/// Run a connector's enumeration to exhaustion (or up to `max_pages`).
///
/// Iterates `enumerate_page` in a loop, collecting all items and
/// validating each page. This is the integration test helper for the
/// enumeration pipeline.
///
/// ## Parameters
///
/// - `connector`: The connector to enumerate.
/// - `spec`: The shard spec (key range).
/// - `budget`: The per-page budget.
/// - `max_pages`: Safety limit to prevent infinite loops. Set to a
///   large value (e.g., 1000) for exhaustive tests.
///
/// ## Returns
///
/// An `EnumerationRun` with all collected items and stats.
///
/// ## Panics
///
/// Panics if any page fails validation (identity, ordering,
/// membership, budget, liveness). This is intentional â€” test
/// helpers should fail loudly on invariant violations.
pub fn run_shard_enumeration(
    connector: &dyn EnumerationConnector,
    spec: &ShardSpec,
    budget: &EnumerationBudget,
    max_pages: u32,
) -> EnumerationRun {
    let mut all_items = Vec::new();
    let mut cursor = Cursor::initial();
    let mut stats = ShardScanStats::new();
    let mut page_count: u32 = 0;
    let mut exhausted = false;

    for _ in 0..max_pages {
        let page = match connector.enumerate_page(spec, &cursor, budget) {
            Ok(page) => page,
            Err(e) => {
                stats.record_enumeration_error();
                panic!("enumeration error in test helper: {e}");
            }
        };

        // Validate the page against all invariants.
        let validation = validate_page(&page, spec, budget);
        assert!(
            validation.is_valid(),
            "page validation failed on page {}: {}",
            page_count,
            validation,
        );

        stats.record_page(&page);
        all_items.extend(page.items.iter().cloned());
        page_count += 1;

        match page.next_cursor {
            Some(next) => cursor = next,
            None => {
                exhausted = true;
                break;
            }
        }
    }

    let final_cursor = if exhausted {
        // Construct cursor from last item.
        all_items
            .last()
            .map(|item| Cursor::with_last_key(item.item_key.path.to_vec()))
    } else {
        Some(cursor)
    };

    EnumerationRun {
        items: all_items,
        final_cursor,
        stats,
        page_count,
        exhausted,
    }
}

/// Run the full enumerate â†’ read pipeline on a connector and return
/// stats with content verification.
///
/// For each enumerated item:
/// 1. Calls `open_item` to read content.
/// 2. Reads all bytes from the reader.
/// 3. Records the outcome as `Scanned { findings: 0 }` (test helper
///    doesn't have a scanner â€” just verifies readability).
///
/// ## Panics
///
/// Panics on enumeration validation failures or unexpected read errors.
pub fn run_enumerate_and_read(
    connector: &(dyn Connector),
    spec: &ShardSpec,
    enum_budget: &EnumerationBudget,
    read_budget: &ReadBudget,
    max_pages: u32,
) -> ShardScanStats {
    let mut cursor = Cursor::initial();
    let mut stats = ShardScanStats::new();

    for _ in 0..max_pages {
        let page = match connector.enumerate_page(spec, &cursor, enum_budget) {
            Ok(page) => page,
            Err(e) => {
                stats.record_enumeration_error();
                panic!("enumeration error in end-to-end helper: {e}");
            }
        };

        let validation = validate_page(&page, spec, enum_budget);
        assert!(validation.is_valid(), "page invalid: {}", validation);

        stats.record_page(&page);

        for item in &page.items {
            match connector.open_item(&item.item_ref, read_budget) {
                Ok(result) => {
                    // Read all content.
                    let mut buf = Vec::new();
                    let bytes = result
                        .reader
                        .take(read_budget.max_bytes)
                        .read_to_end(&mut buf)
                        .expect("read should succeed for test connector");
                    stats.record_bytes_read(bytes as u64);
                    stats.record_outcome(&ItemOutcome::Scanned { findings: 0 });
                }
                Err(e) => {
                    stats.record_read_error();
                    stats.record_outcome(&ItemOutcome::SkippedReadError {
                        message: format!("{e}").into(),
                    });
                }
            }
        }

        match page.next_cursor {
            Some(next) => cursor = next,
            None => break,
        }
    }

    stats
}

/// Assert that running enumeration to exhaustion yields exactly
/// the expected number of items, all within the shard range, all
/// identity-consistent, all in sorted order.
///
/// This is the top-level "golden path" assertion for connector
/// implementations.
pub fn assert_enumeration_correct(
    connector: &dyn EnumerationConnector,
    spec: &ShardSpec,
    expected_item_count: usize,
) {
    let budget = EnumerationBudget::default_for_testing();
    let run = run_shard_enumeration(connector, spec, &budget, 10_000);

    assert!(
        run.exhausted,
        "enumeration did not exhaust within 10,000 pages"
    );

    assert_eq!(
        run.items.len(),
        expected_item_count,
        "expected {} items, got {}",
        expected_item_count,
        run.items.len(),
    );

    // Verify global ordering across all pages.
    for window in run.items.windows(2) {
        let a = (&window[0].item_key.connector, &window[0].item_key.path);
        let b = (&window[1].item_key.connector, &window[1].item_key.path);
        assert!(
            a <= b,
            "cross-page ordering violation: {:?} > {:?}",
            window[0].item_key.path,
            window[1].item_key.path,
        );
    }

    // Verify all items in range.
    for item in &run.items {
        assert!(
            check_key_membership(item.item_key.path.as_ref(), spec),
            "item {:?} outside shard range",
            item.item_key.path,
        );
    }
}

// ============================================================================
// Â§ Consolidated Invariant Catalog â€” Boundary â‘£ (All Chunks)
// ============================================================================
//
// This is the single authoritative reference for all Boundary â‘£ invariants.
// Invariants are numbered INV-4.XX with S (Safety) or L (Liveness) prefix.
//
// â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
// â”‚ ID          â”‚ Statement                                                  â”‚ Enforced By          â”‚ Verification                   â”‚
// â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
// â”‚ INV-4.S01   â”‚ VersionId strength honesty: a Strong version guarantees    â”‚ Connector impl       â”‚ Integration test per connector;â”‚
// â”‚             â”‚ byte-identical content on repeat retrieval. Weak does not. â”‚                      â”‚ simulation with version drift. â”‚
// â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
// â”‚ INV-4.S02   â”‚ ItemRef credential isolation: ItemRef MUST NOT be logged,  â”‚ ItemRef Debug impl   â”‚ Debug output test (redaction); â”‚
// â”‚             â”‚ persisted beyond scan cycle, or transmitted cross-worker.  â”‚ (redacted); runtime  â”‚ code review.                   â”‚
// â”‚             â”‚                                                            â”‚ discipline           â”‚                                â”‚
// â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
// â”‚ INV-4.S03   â”‚ Identity consistency: for every ScanItem,                  â”‚ ScanItemBuilder      â”‚ assert_identity_consistency();  â”‚
// â”‚             â”‚ stable_item_id == item_key.stable_id().                    â”‚ ::build() assertion  â”‚ proptest.                      â”‚
// â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
// â”‚ INV-4.S04   â”‚ Enumeration page ordering: items within a page are in     â”‚ validate_page()      â”‚ Unit + proptest; cross-page     â”‚
// â”‚             â”‚ non-decreasing (connector, path) order.                   â”‚                      â”‚ ordering in integration test.   â”‚
// â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
// â”‚ INV-4.S05   â”‚ Budget compliance: page.items.len() <= budget.max_items.  â”‚ validate_page()      â”‚ Test with tight budgets.        â”‚
// â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
// â”‚ INV-4.S06   â”‚ Shard membership: all items have item_key.path within     â”‚ validate_page() via  â”‚ Test with items outside range;  â”‚
// â”‚             â”‚ [spec.start, spec.end).                                   â”‚ check_key_membership â”‚ proptest with random ranges.    â”‚
// â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
// â”‚ INV-4.S07   â”‚ Budget non-zero: EnumerationBudget and ReadBudget fields  â”‚ Budget::new() panic  â”‚ #[should_panic] tests.          â”‚
// â”‚             â”‚ are all > 0 at construction.                              â”‚                      â”‚                                â”‚
// â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
// â”‚ INV-4.S08   â”‚ ItemLocation credential-free: display string and URL      â”‚ Code review;         â”‚ Integration test: verify no     â”‚
// â”‚             â”‚ MUST NOT contain authentication tokens.                   â”‚ connector discipline  â”‚ auth-pattern substrings.        â”‚
// â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
// â”‚ INV-4.S09   â”‚ ContentHints advisory: scanner MUST handle incorrect      â”‚ Scanner impl         â”‚ Test: pass wrong hints, verify  â”‚
// â”‚             â”‚ hints gracefully (Postel's Law).                          â”‚                      â”‚ scanner still works.            â”‚
// â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
// â”‚ INV-4.S10   â”‚ ItemRef scoped to connector: runtime MUST NOT pass an     â”‚ Runtime tag check    â”‚ Type-level or runtime tag       â”‚
// â”‚             â”‚ ItemRef from connector A to connector B.                  â”‚                      â”‚ enforcement.                   â”‚
// â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
// â”‚ INV-4.S11   â”‚ ConnectorInfo tag consistency: info().tag == tag used     â”‚ Runtime registration â”‚ Integration test at startup.    â”‚
// â”‚             â”‚ in all ItemKey constructions.                             â”‚ assertion            â”‚                                â”‚
// â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
// â”‚ INV-4.S12   â”‚ ConnectorInfo tag uniqueness: no two active connectors    â”‚ validate_registrationâ”‚ Unit test; runtime startup      â”‚
// â”‚             â”‚ share a ConnectorTag.                                     â”‚                      â”‚ assertion.                     â”‚
// â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
// â”‚ INV-4.S13   â”‚ ReadResult reader lifetime: reader remains valid until    â”‚ Connector impl       â”‚ Integration test with slow      â”‚
// â”‚             â”‚ dropped. Connector MUST NOT close connections early.      â”‚                      â”‚ reads; stress test.            â”‚
// â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
// â”‚ INV-4.S14   â”‚ CursorInvalidated recovery: connector MUST handle cursor â”‚ Connector impl       â”‚ Test: enumerate with token=None â”‚
// â”‚             â”‚ with token=None for any valid last_key.                   â”‚                      â”‚ after invalidation.            â”‚
// â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
// â”‚ INV-4.S15   â”‚ enumerate_page re-entrancy: safe to call concurrently    â”‚ &self signature;     â”‚ Concurrent shard simulation.    â”‚
// â”‚             â”‚ for different shards via &self.                           â”‚ interior mutability  â”‚                                â”‚
// â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
// â”‚ INV-4.S16   â”‚ validate_page completeness: checks ALL of S03, S04, S05, â”‚ validate_page()      â”‚ Test with pages violating each  â”‚
// â”‚             â”‚ S06, L01 in a single pass.                               â”‚                      â”‚ invariant individually.         â”‚
// â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
// â”‚ INV-4.S17   â”‚ Cursor extraction monotonicity: for a validated page,    â”‚ extract_checkpoint_  â”‚ proptest with sorted items.     â”‚
// â”‚             â”‚ returned cursor's last_key >= input cursor's last_key.   â”‚ cursor()             â”‚                                â”‚
// â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
// â”‚ INV-4.S18   â”‚ Circuit breaker no-correctness-dependency: circuit state â”‚ By design            â”‚ Code review; simulation test    â”‚
// â”‚             â”‚ is a liveness optimization, never a correctness gate.    â”‚                      â”‚ with stuck circuit.            â”‚
// â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
// â”‚ INV-4.S19   â”‚ Error mapping determinism: map_enumeration_error and     â”‚ Pure functions       â”‚ proptest: same error â†’ same     â”‚
// â”‚             â”‚ map_read_error are pure functions.                       â”‚                      â”‚ action.                        â”‚
// â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
// â”‚ INV-4.S20   â”‚ Key membership half-open: check_key_membership uses     â”‚ check_key_membership â”‚ Boundary value tests; proptest  â”‚
// â”‚             â”‚ [start, end) â€” same semantics as B2 cursor bounds.      â”‚                      â”‚ agreement with B2 check.        â”‚
// â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
// â”‚ INV-4.S21   â”‚ Test connector determinism: given the same config and    â”‚ TestConnector impl   â”‚ Run twice, assert identical     â”‚
// â”‚             â”‚ call sequence, output is identical. No randomness.       â”‚                      â”‚ output.                        â”‚
// â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
// â”‚ INV-4.S22   â”‚ Test connector no duplicate paths: build() panics if    â”‚ TestConnectorBuilder â”‚ #[should_panic] test.           â”‚
// â”‚             â”‚ any two items share a path.                              â”‚ ::build()            â”‚                                â”‚
// â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
// â”‚ INV-4.S23   â”‚ Stats consistency: items_processed() ==                  â”‚ assert_fully_        â”‚ Integration test at shard       â”‚
// â”‚             â”‚ items_enumerated when shard completes.                   â”‚ processed()          â”‚ completion.                    â”‚
// â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
//
// â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
// â”‚ ID          â”‚ Statement                                                  â”‚ Enforced By          â”‚ Verification                   â”‚
// â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
// â”‚ INV-4.L01   â”‚ Progress: under non-zero budget, enumerate_page returns   â”‚ validate_page()      â”‚ Liveness violation check in     â”‚
// â”‚             â”‚ items OR exhausted OR error. Zero items + Some(cursor)    â”‚ liveness check       â”‚ validate_page.                 â”‚
// â”‚             â”‚ + Ok = violation.                                          â”‚                      â”‚                                â”‚
// â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
// â”‚ INV-4.L02   â”‚ Retry convergence: runtime retry loop MUST terminate     â”‚ Runtime config       â”‚ Runtime configuration check;    â”‚
// â”‚             â”‚ regardless of RetryHint. Max retry count is bounded.     â”‚ (max_retries)        â”‚ simulation.                    â”‚
// â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
// â”‚ INV-4.L03   â”‚ Circuit breaker eventual recovery: Open state MUST       â”‚ maybe_half_open()    â”‚ Deterministic simulation with   â”‚
// â”‚             â”‚ eventually transition to HalfOpen given time advancement. â”‚                      â”‚ time advancement.              â”‚
// â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
// â”‚ INV-4.L04   â”‚ Read progress: reads from ReadResult.reader make progressâ”‚ Connector impl       â”‚ Integration test; timeout       â”‚
// â”‚             â”‚ (data or EOF) within bounded time.                       â”‚                      â”‚ enforcement by runtime.        â”‚
// â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜

// ============================================================================
// Â§ Cross-Boundary Dependency Map
// ============================================================================
//
// B4 depends on:
// â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
// â”‚ Source   â”‚ Type / Concept                       â”‚ Used In B4 For                       â”‚
// â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
// â”‚ B1 ch 1  â”‚ CanonicalBytes, domain_hasher       â”‚ VersionId canonical encoding (ch 1)  â”‚
// â”‚ B1 ch 2  â”‚ TenantId, RunId, ShardId, WorkerId  â”‚ (not directly used in B4; used by B2 â”‚
// â”‚          â”‚                                     â”‚ coordination which orchestrates B4)  â”‚
// â”‚ B1 ch 3  â”‚ ConnectorTag, ItemKey, StableItemId, â”‚ All connector value types (ch 1);   â”‚
// â”‚          â”‚ ObjectVersionId                     â”‚ trait method signatures (ch 2)       â”‚
// â”‚ B2 ch 1  â”‚ Cursor, ShardSpec                   â”‚ Enumeration pagination (ch 2);      â”‚
// â”‚          â”‚                                     â”‚ cursor extraction (ch 3)             â”‚
// â”‚ B2 ch 2  â”‚ ParkReason                          â”‚ Error mapping (ch 3)                â”‚
// â”‚ B2 ch 3  â”‚ CoordinationBackend (conceptual)    â”‚ Runtime composes B4 + B2: enumerate  â”‚
// â”‚          â”‚                                     â”‚ â†’ checkpoint â†’ complete              â”‚
// â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
//
// B4 feeds into:
// â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
// â”‚ Target   â”‚ Type / Concept                       â”‚ How B4 Feeds It                      â”‚
// â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
// â”‚ B5       â”‚ Done-ledger skip check              â”‚ ScanItem.version (Strong/Weak) tells â”‚
// â”‚          â”‚                                     â”‚ B5 whether skip-scan is safe.        â”‚
// â”‚ B5       â”‚ Finding identity                    â”‚ ScanItem.item_key + content feed     â”‚
// â”‚          â”‚                                     â”‚ FindingId / evidence_hash.           â”‚
// â”‚ B5       â”‚ Idempotent sink input               â”‚ EnumerationPage items + outcomes     â”‚
// â”‚          â”‚                                     â”‚ become the input to B5's flush.      â”‚
// â”‚ B5       â”‚ Done-ledger update                  â”‚ ItemOutcome (scanned/skipped) drives â”‚
// â”‚          â”‚                                     â”‚ done-ledger entries.                 â”‚
// â”‚ Runtime  â”‚ Coordination loop                   â”‚ extract_checkpoint_cursor â†’ B2       â”‚
// â”‚          â”‚                                     â”‚ checkpoint; ShardScanStats â†’ B5.     â”‚
// â”‚ Runtime  â”‚ Circuit breaker                     â”‚ CircuitState gates connector calls.  â”‚
// â”‚ Runtime  â”‚ ConnectorRegistration               â”‚ Startup handshake, shard routing.    â”‚
// â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜

// ============================================================================
// Â§ Design Decision Index â€” Boundary â‘£ (All Chunks)
// ============================================================================
//
// D4.1:  VersionId enum (Strong/Weak), not newtype. Strength classification
//        for done-ledger skip-scan decisions.
// D4.2:  ItemRef opaque blob. Not structured. Connector flexibility.
// D4.3:  ItemLocation display-safe. No credentials.
// D4.4:  ContentHints advisory, not binding. Postel's Law.
// D4.5:  ScanItem is the complete, self-describing enumeration unit.
// D4.6:  Budgets are explicit bounded envelopes for backpressure.
// D4.7:  u32 for counts, u64 for bytes. Platform-independent widths.
// D4.10: Separate EnumerationConnector + ReadConnector traits (ISP).
// D4.11: Synchronous API (blocking I/O). Contract defines semantics,
//        not execution model. Matches B2's CoordinationBackend.
// D4.12: enumerate_page takes &self. Cursor-based, not stream-based.
// D4.13: open_item returns Box<dyn Read>. Streaming, not materializing.
// D4.14: Operation-specific error types. Matches B2 pattern (D2.16).
// D4.15: RetryHint advisory. Runtime owns retry loop.
// D4.16: ConnectorInfo for registration and observability only.
// D4.20: Page validation is a pure function. No I/O.
// D4.21: Cursor extraction is deterministic and infallible for valid pages.
// D4.22: Error-to-ParkReason mapping is a pure function.
// D4.23: CircuitState is a value type, not a controller.
// D4.24: ConnectorRegistration bundles info + capabilities.
// D4.30: TestConnector configured via sorted Vec<TestItem>.
// D4.31: FailureScript = ordered (call_index, failure) pairs. Deterministic.
// D4.32: RefCell for call counter (single-threaded test detector).
// D4.33: TestItem stores Vec<u8>, not Box<dyn Read>. Small test content.
// D4.40: ShardScanStats is a plain accumulator, not a controller.
// D4.41: Stats are per-shard, per-scan-cycle.
// D4.42: Stats track both page-level and item-level granularity.
// D4.43: Integration helpers are functions, not a framework.

// ============================================================================
// Â§ Runtime Composition Guide
// ============================================================================
//
// How B4 types compose in the runtime's shard processing loop:
//
// ```text
//   â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
//   â”‚                    Runtime Shard Loop                          â”‚
//   â”‚                                                                â”‚
//   â”‚  1. acquire_and_restore (B2)                                   â”‚
//   â”‚     â””â†’ Lease + ShardSnapshot                                   â”‚
//   â”‚                                                                â”‚
//   â”‚  2. For each page:                                             â”‚
//   â”‚     a. compute_budget (B4 ch1: EnumerationBudget)              â”‚
//   â”‚        â””â†’ considers: lease.remaining, pipeline_pressure,       â”‚
//   â”‚           registration.recommended_enum_budget                 â”‚
//   â”‚                                                                â”‚
//   â”‚     b. circuit_state.allows_request()? (B4 ch3)                â”‚
//   â”‚        â””â†’ if not: wait or park                                 â”‚
//   â”‚                                                                â”‚
//   â”‚     c. connector.enumerate_page (B4 ch2)                       â”‚
//   â”‚        â””â†’ EnumerationPage or EnumerationError                  â”‚
//   â”‚                                                                â”‚
//   â”‚     d. ON ERROR:                                               â”‚
//   â”‚        â””â†’ map_enumeration_error (B4 ch3)                       â”‚
//   â”‚           â””â†’ ConnectorAction: Retry / RestartFromKey / Park    â”‚
//   â”‚        â””â†’ circuit_state.record_failure (B4 ch3)                â”‚
//   â”‚        â””â†’ stats.record_enumeration_error (B4 ch5)              â”‚
//   â”‚                                                                â”‚
//   â”‚     e. ON SUCCESS:                                             â”‚
//   â”‚        â””â†’ validate_page (B4 ch3)                               â”‚
//   â”‚        â””â†’ circuit_state.record_success (B4 ch3)                â”‚
//   â”‚        â””â†’ stats.record_page (B4 ch5)                           â”‚
//   â”‚                                                                â”‚
//   â”‚     f. For each item in page:                                  â”‚
//   â”‚        i.   done_ledger.should_skip(item)? (B5)                â”‚
//   â”‚             â””â†’ uses item.version.is_strong()                   â”‚
//   â”‚        ii.  connector.open_item (B4 ch2)                       â”‚
//   â”‚        iii. scanner.scan(reader) (engine, outside B4)          â”‚
//   â”‚        iv.  outcome = ItemOutcome (B4 ch3)                     â”‚
//   â”‚        v.   stats.record_outcome (B4 ch5)                      â”‚
//   â”‚        vi.  persistence.flush_finding (B5)                     â”‚
//   â”‚                                                                â”‚
//   â”‚     g. extract_checkpoint_cursor (B4 ch3)                      â”‚
//   â”‚        â””â†’ Cursor for coordinator.checkpoint (B2)               â”‚
//   â”‚                                                                â”‚
//   â”‚     h. coordinator.checkpoint(cursor, op_id) (B2)              â”‚
//   â”‚     i. coordinator.renew(lease) if needed (B2)                 â”‚
//   â”‚                                                                â”‚
//   â”‚  3. Shard terminal:                                            â”‚
//   â”‚     a. stats.assert_fully_processed() (B4 ch5)                 â”‚
//   â”‚     b. coordinator.complete(...) OR park_shard(...) (B2)       â”‚
//   â”‚     c. persistence.update_done_ledger(stats) (B5)              â”‚
//   â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
// ```

// ============================================================================
// Â§ Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    // -- ShardScanStats --

    #[test]
    fn stats_new_is_zeroed() {
        let s = ShardScanStats::new();
        assert_eq!(s.pages_enumerated, 0);
        assert_eq!(s.items_enumerated, 0);
        assert_eq!(s.findings_total, 0);
        assert!(s.is_fully_processed()); // 0 == 0
    }

    #[test]
    fn stats_record_page() {
        let mut s = ShardScanStats::new();
        let page = EnumerationPage {
            items: vec![
                test_scan_item(b"a"),
                test_scan_item(b"b"),
            ],
            next_cursor: None,
            api_calls_used: 3,
        };
        s.record_page(&page);
        assert_eq!(s.pages_enumerated, 1);
        assert_eq!(s.items_enumerated, 2);
        assert_eq!(s.api_calls_used, 3);
    }

    #[test]
    fn stats_record_outcomes() {
        let mut s = ShardScanStats::new();
        s.items_enumerated = 5;

        s.record_outcome(&ItemOutcome::Scanned { findings: 2 });
        s.record_outcome(&ItemOutcome::Scanned { findings: 1 });
        s.record_outcome(&ItemOutcome::SkippedByVersion);
        s.record_outcome(&ItemOutcome::SkippedBinary);
        s.record_outcome(&ItemOutcome::SkippedReadError {
            message: "404".into(),
        });

        assert_eq!(s.items_scanned, 2);
        assert_eq!(s.items_skipped_version, 1);
        assert_eq!(s.items_skipped_binary, 1);
        assert_eq!(s.items_skipped_read_error, 1);
        assert_eq!(s.findings_total, 3);
        assert!(s.is_fully_processed());
    }

    #[test]
    fn stats_truncated_counts() {
        let mut s = ShardScanStats::new();
        s.items_enumerated = 1;
        s.record_outcome(&ItemOutcome::ScannedTruncated {
            findings: 1,
            bytes_read: 1024,
        });

        assert_eq!(s.items_scanned_truncated, 1);
        assert_eq!(s.items_scanned_total(), 1);
        assert_eq!(s.findings_total, 1);
        assert_eq!(s.bytes_read, 1024);
        assert!(s.is_fully_processed());
    }

    #[test]
    fn stats_scan_fraction() {
        let mut s = ShardScanStats::new();
        s.items_enumerated = 10;
        s.items_scanned = 3;
        s.items_scanned_truncated = 2;
        s.items_skipped_version = 5;

        assert!((s.scan_fraction() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn stats_scan_fraction_zero_items() {
        let s = ShardScanStats::new();
        assert!((s.scan_fraction() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    #[should_panic(expected = "items_processed")]
    fn stats_assert_fully_processed_panics() {
        let mut s = ShardScanStats::new();
        s.items_enumerated = 5;
        s.items_scanned = 3; // Missing 2 outcomes.
        s.assert_fully_processed();
    }

    #[test]
    fn stats_display() {
        let mut s = ShardScanStats::new();
        s.pages_enumerated = 3;
        s.items_enumerated = 10;
        s.items_scanned = 7;
        s.findings_total = 2;
        let display = format!("{}", s);
        assert!(display.contains("pages=3"), "got: {display}");
        assert!(display.contains("items=10"), "got: {display}");
        assert!(display.contains("findings=2"), "got: {display}");
    }

    // -- Integration helpers with TestConnector --

    fn test_scan_item(path: &[u8]) -> ScanItem {
        let key = ItemKey::new(ConnectorTag::from_ascii(b"test"), path.to_vec());
        let stable_id = key.stable_id();
        ScanItem {
            item_key: key,
            stable_item_id: stable_id,
            item_ref: ItemRef::new(path.to_vec()),
            version: VersionId::strong_from_bytes(b"v1"),
            size_hint: None,
            content_hints: ContentHints::unknown(),
            location: ItemLocation::new("test"),
        }
    }

    #[test]
    fn run_shard_enumeration_empty() {
        let connector = test_connector_empty("test");
        let spec = ShardSpec::unbounded();
        let budget = EnumerationBudget::default_for_testing();

        let run = run_shard_enumeration(&connector, &spec, &budget, 100);
        assert!(run.exhausted);
        assert_eq!(run.items.len(), 0);
        assert_eq!(run.page_count, 1); // One empty page.
    }

    #[test]
    fn run_shard_enumeration_paged() {
        let connector = test_connector_paged("test", 15, 4);
        let spec = ShardSpec::unbounded();
        let budget = EnumerationBudget::default_for_testing();

        let run = run_shard_enumeration(&connector, &spec, &budget, 100);
        assert!(run.exhausted);
        assert_eq!(run.items.len(), 15);
        assert_eq!(run.page_count, 4); // 4+4+4+3
        assert_eq!(run.stats.items_enumerated, 15);
    }

    #[test]
    fn run_shard_enumeration_bounded_range() {
        let connector = test_connector_with_n_items("test", 20);
        // items are "item-00000" through "item-00019"
        // Range [item-00005, item-00010) should yield 5 items.
        let spec = ShardSpec::with_range(
            b"item-00005".to_vec(),
            b"item-00010".to_vec(),
        );
        let budget = EnumerationBudget::default_for_testing();

        let run = run_shard_enumeration(&connector, &spec, &budget, 100);
        assert!(run.exhausted);
        assert_eq!(run.items.len(), 5);
    }

    #[test]
    fn assert_enumeration_correct_passes() {
        let connector = test_connector_with_n_items("test", 10);
        let spec = ShardSpec::unbounded();
        assert_enumeration_correct(&connector, &spec, 10);
    }

    #[test]
    fn run_enumerate_and_read_full_pipeline() {
        let connector = TestConnectorBuilder::new("e2e")
            .item(TestItem::new("a.txt", "alpha content"))
            .item(TestItem::new("b.txt", "bravo content"))
            .item(TestItem::new("c.txt", "charlie content"))
            .build();

        let spec = ShardSpec::unbounded();
        let enum_budget = EnumerationBudget::default_for_testing();
        let read_budget = ReadBudget::default_for_testing();

        let stats = run_enumerate_and_read(
            &connector,
            &spec,
            &enum_budget,
            &read_budget,
            100,
        );

        assert_eq!(stats.items_enumerated, 3);
        assert_eq!(stats.items_scanned, 3);
        assert_eq!(stats.items_skipped_total(), 0);
        assert!(stats.bytes_read > 0);
        assert!(stats.is_fully_processed());
    }

    #[test]
    fn run_enumerate_and_read_with_read_failure() {
        let connector = TestConnectorBuilder::new("e2e")
            .item(TestItem::new("good.txt", "good content"))
            .item(TestItem::new("bad.txt", "bad content"))
            .read_failure("bad.txt", ScriptedReadFailure::NotFound)
            .build();

        let spec = ShardSpec::unbounded();
        let enum_budget = EnumerationBudget::default_for_testing();
        let read_budget = ReadBudget::default_for_testing();

        let stats = run_enumerate_and_read(
            &connector,
            &spec,
            &enum_budget,
            &read_budget,
            100,
        );

        assert_eq!(stats.items_enumerated, 2);
        assert_eq!(stats.items_scanned, 1);
        assert_eq!(stats.items_skipped_read_error, 1);
        assert_eq!(stats.read_errors, 1);
        assert!(stats.is_fully_processed());
    }

    // -- Cross-page ordering verification --

    #[test]
    fn cross_page_ordering_maintained() {
        let connector = test_connector_paged("test", 20, 3);
        let spec = ShardSpec::unbounded();
        let budget = EnumerationBudget::default_for_testing();

        let run = run_shard_enumeration(&connector, &spec, &budget, 100);

        // Verify strict cross-page ordering.
        for window in run.items.windows(2) {
            let a = &window[0].item_key.path;
            let b = &window[1].item_key.path;
            assert!(
                a.as_ref() < b.as_ref(),
                "ordering violation: {:?} >= {:?}",
                String::from_utf8_lossy(a.as_ref()),
                String::from_utf8_lossy(b.as_ref()),
            );
        }
    }

    // -- Stats with real TestConnector --

    #[test]
    fn stats_accumulation_matches_enumeration() {
        let connector = test_connector_paged("test", 25, 7);
        let spec = ShardSpec::unbounded();
        let budget = EnumerationBudget::default_for_testing();

        let run = run_shard_enumeration(&connector, &spec, &budget, 100);

        assert_eq!(run.stats.items_enumerated, 25);
        assert_eq!(run.stats.pages_enumerated, run.page_count);
        assert!(run.stats.api_calls_used >= run.page_count); // At least 1 API call per page.
    }

    // -- Property test stubs --

    // TODO: proptest for stats consistency:
    //   âˆ€ sequence of record_outcome calls:
    //     items_processed() == count of calls iff items_enumerated set correctly
    //
    // TODO: proptest for run_shard_enumeration completeness:
    //   âˆ€ n, page_size, spec:
    //     run yields exactly the items within spec's range
    //
    // TODO: proptest for cross-page ordering:
    //   âˆ€ n, page_size:
    //     concatenated items are sorted
    //
    // TODO: proptest for enumerate_and_read round-trip:
    //   âˆ€ items:
    //     bytes_read == sum(item.content.len()) for non-failed items
}
