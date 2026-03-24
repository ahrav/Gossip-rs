//! Ordered-content runtime boundary.
//!
//! This module owns two related ordered-content execution paths and a
//! done-ledger prefilter stage that sits between page acquisition and
//! item-level scan work:
//!
//! 1. **Page acquisition** — [`OrderedContentRuntime::execute_source`]
//!    performs one connector-driven ordered page fill and validates the page
//!    against the shard/cursor contract before any downstream read or scan
//!    work uses it.
//! 2. **Done-ledger prefilter** — [`OrderedContentPage::prefilter_done_ledger`]
//!    classifies each validated item as `AlreadyDone` or `ScanMiss` by
//!    looking up its object-version identity (OvidHash) in the done ledger.
//!    Items that already have a durable done-ledger row are skipped before
//!    any content is opened, saving I/O and scan budget.
//! 3. **Local filesystem scan** — `scan_local_filesystem` runs the direct
//!    scheduler-based parallel filesystem scan and forwards events and
//!    persistence batches through bounded channels.
//!
//! The connector-facing entrypoint is intentionally narrower than the direct
//! scan path. It validates authoritative shard bounds, resume cursor progress,
//! and enumerate error classification without yet taking ownership of
//! item-open, byte-read, findings, or durability orchestration.
//!
//! # Done-ledger prefilter
//!
//! The prefilter derives an [`OvidHash`](gossip_contracts::persistence::OvidHash)
//! from each item's [`StableItemId`](gossip_contracts::identity::StableItemId)
//! and [`VersionId`](gossip_contracts::connector::VersionId), then issues
//! positional [`DoneLedger::batch_get`]
//! calls scoped by the claim's `WriteContext` (tenant + policy). Lookups are
//! chunked at [`RECOMMENDED_MAX_BATCH_SIZE`]
//! to respect backend batch ceilings while preserving positional alignment
//! with the original page order. Because the hash includes version strength
//! (strong vs. weak), the same stable item under a different version claim
//! is correctly treated as a miss.
//!
//! # Threading model
//!
//! `scan_local_filesystem` uses [`std::thread::scope`] to spawn two forwarder
//! threads:
//!
//! 1. **Event forwarder** — drains core events (findings, progress, summary,
//!    diagnostics) from the scan workers into the caller's [`EventOutput`] sink.
//! 2. **Commit forwarder** — drains persistence batches into the caller's
//!    [`CommitSink`](crate::commit_sink::CommitSink) (a no-op sink for CLI
//!    scans; distributed mode routes the same lifecycle into the
//!    receipt-driven commit pipeline).
//!
//! Both channels are bounded (`EVENT_CHANNEL_CAP` and `COMMIT_CHANNEL_CAP`)
//! and are explicitly dropped after the scan completes so the forwarder
//! threads observe a clean EOF.
//!
//! # Integration with distributed scanning
//!
//! [`OrderedContentRuntime::execute_source`] is called by the distributed
//! worker loop to validate pages before downstream item-scanning and commit
//! work. The restored shard state and budgets are supplied via
//! [`OrderedContentRuntimeInput`], constructed from a
//! [`ShardLease`](crate::distributed::ShardLease).

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::sync_channel;

use anyhow::anyhow;
use gossip_contracts::{
    connector::{
        Budgets, Cursor, EnumerateError, ErrorClass, PageBuf, PageState, ScanItem,
        ordered::OrderedContentSource, validate_page_sequence,
    },
    coordination::{CursorSemantics, RestoredShardState, ShardSpec},
    persistence::{
        DoneLedger, OvidHashInputs, RECOMMENDED_MAX_BATCH_SIZE, WriteContext, derive_ovid_hash,
    },
};
use scanner_scheduler::events::EventOutput;
use scanner_scheduler::scheduler::parallel_scan::{ParallelScanConfig, parallel_scan_dir};

use crate::{
    AssignmentOutcome, COMMIT_CHANNEL_CAP, CancellationToken, ChannelEventOutput,
    ChannelStoreProducer, EVENT_CHANNEL_CAP, FsScanConfig, ScanReport, ScanRuntimeError,
    build_runtime_engine, forward_commits, forward_core_events, join_scoped,
};

/// Inputs required to acquire and validate one ordered connector page.
///
/// The runtime keeps the restored coordination state (shard bounds, resume
/// cursor, cursor semantics) and page budgets together so the page-fill
/// boundary always executes from authoritative state.
///
/// This bundle is self-contained: it carries everything needed to validate a
/// page against the coordination contract. The runtime never mutates these
/// fields; downstream execution decides checkpoint advancement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrderedContentRuntimeInput {
    state: RestoredShardState,
    budgets: Budgets,
}

impl OrderedContentRuntimeInput {
    /// Construct one ordered-content execution input bundle.
    ///
    /// `state` must carry [`CursorSemantics::Completed`] — the runtime
    /// rejects other semantics at execution time.
    #[must_use]
    pub fn new(state: RestoredShardState, budgets: Budgets) -> Self {
        Self { state, budgets }
    }

    /// Authoritative shard bounds used for page validation.
    #[must_use]
    pub fn shard(&self) -> &ShardSpec {
        self.state.shard_spec()
    }

    /// Resume cursor restored from runtime state.
    #[must_use]
    pub fn cursor(&self) -> &Cursor {
        self.state.resume_cursor()
    }

    /// Coordination cursor semantics for the shard.
    #[must_use]
    pub fn cursor_semantics(&self) -> CursorSemantics {
        self.state.cursor_semantics()
    }

    /// Connector page budgets.
    #[must_use]
    pub fn budgets(&self) -> Budgets {
        self.budgets
    }
}

/// Structured stop reason for connector enumeration failure.
///
/// Preserves the connector's retry classification and advisory backoff hint
/// so callers can route transient vs. terminal failures without parsing
/// error text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrderedContentStop {
    class: ErrorClass,
    message: String,
    retry_after_ms: Option<u64>,
}

impl OrderedContentStop {
    fn from_enumerate_error(error: EnumerateError) -> Self {
        Self {
            class: error.class(),
            retry_after_ms: error.retry_after_ms(),
            message: error.into_message(),
        }
    }

    /// Retry classification supplied by the connector.
    #[must_use]
    pub fn class(&self) -> ErrorClass {
        self.class
    }

    /// Connector-originated diagnostic text.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Optional connector-provided retry hint.
    #[must_use]
    pub fn retry_after_ms(&self) -> Option<u64> {
        self.retry_after_ms
    }
}

impl std::fmt::Display for OrderedContentStop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.retry_after_ms {
            Some(retry_after_ms) => write!(
                f,
                "ordered-content source stopped with {} enumerate error: {} (retry_after_ms={retry_after_ms})",
                self.class, self.message
            ),
            None => write!(
                f,
                "ordered-content source stopped with {} enumerate error: {}",
                self.class, self.message
            ),
        }
    }
}

/// Validated ordered connector page plus runtime-local summary counters.
///
/// `resume_cursor` is derived from the page boundary: for `HasMore` pages it
/// is the connector-supplied cursor (which carries token and last-key); for
/// `Complete` pages it is synthesized from the page's final emitted key.
/// Downstream execution decides whether to treat it as committed progress;
/// this module never advances shard state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrderedContentPage {
    page: PageBuf<ScanItem>,
    report: ScanReport,
    resume_cursor: Cursor,
}

impl OrderedContentPage {
    fn from_validated_page(page: PageBuf<ScanItem>) -> Self {
        debug_assert!(
            !page.items().is_empty(),
            "from_validated_page requires a non-empty page"
        );
        let last_key = page
            .items()
            .last()
            .expect("validated page is non-empty")
            .item_key()
            .clone();
        let resume_cursor = match page.state() {
            PageState::HasMore { cursor } => cursor.clone(),
            PageState::Complete => Cursor::with_last_key(last_key),
        };
        let bytes_scanned = page
            .items()
            .iter()
            .filter_map(ScanItem::size_hint)
            .fold(0u64, u64::saturating_add);

        Self {
            report: ScanReport {
                items_scanned: page.len() as u64,
                bytes_scanned,
                ..ScanReport::default()
            },
            page,
            resume_cursor,
        }
    }

    /// Validated connector page contents.
    #[must_use]
    pub fn page(&self) -> &PageBuf<ScanItem> {
        &self.page
    }

    /// Runtime-local summary counters derived from the page.
    #[must_use]
    pub fn report(&self) -> ScanReport {
        self.report
    }

    /// Resume cursor corresponding to the validated page boundary.
    #[must_use]
    pub fn resume_cursor(&self) -> &Cursor {
        &self.resume_cursor
    }

    /// Consume the page and return its owned parts.
    #[must_use]
    pub fn into_parts(self) -> (PageBuf<ScanItem>, ScanReport, Cursor) {
        (self.page, self.report, self.resume_cursor)
    }

    /// Classify the validated page against the done ledger before any item
    /// content is opened or scanned.
    ///
    /// Each item's [`StableItemId`](gossip_contracts::identity::StableItemId)
    /// and [`VersionId`](gossip_contracts::connector::VersionId) are hashed
    /// into an `OvidHash`, then looked up via
    /// [`DoneLedger::batch_get`]
    /// under the supplied `write_context`'s tenant and policy scope.
    ///
    /// # Batching
    ///
    /// Lookups are chunked at
    /// [`RECOMMENDED_MAX_BATCH_SIZE`]
    /// to stay within backend batch limits. Chunks are issued sequentially and
    /// their results are concatenated, preserving positional alignment with
    /// the original page items.
    ///
    /// # Invariants preserved
    ///
    /// - Original page item order is maintained in the returned
    ///   [`OrderedContentPrefilteredPage`].
    /// - The `report`, `resume_cursor`, and `page_state` are carried through
    ///   unmodified so downstream checkpoint logic remains correct.
    ///
    /// # Errors
    ///
    /// Returns [`ScanRuntimeError::Driver`] if:
    /// - The done-ledger `batch_get` call fails (I/O, timeout, etc.).
    /// - The backend returns a result vector whose length does not match the
    ///   number of lookup keys (violated positional contract).
    pub fn prefilter_done_ledger<D>(
        self,
        write_context: WriteContext,
        done_ledger: &D,
    ) -> Result<OrderedContentPrefilteredPage, ScanRuntimeError>
    where
        D: DoneLedger,
        D::Error: std::error::Error + Send + Sync + 'static,
    {
        let (page, report, resume_cursor) = self.into_parts();
        let (items, page_state) = page.into_parts();
        let tenant_id = write_context.tenant_id();
        let policy_hash = write_context.policy_hash();
        let mut present = Vec::with_capacity(items.len());

        // Respect backend batch ceilings without losing positional alignment
        // across the original page.
        for item_chunk in items.chunks(RECOMMENDED_MAX_BATCH_SIZE) {
            let ovid_hashes: Vec<_> = item_chunk
                .iter()
                .map(|item| {
                    derive_ovid_hash(&OvidHashInputs {
                        stable_item_id: item.stable_item_id(),
                        version: item.version(),
                    })
                })
                .collect();
            let batch = done_ledger
                .batch_get(tenant_id, policy_hash, &ovid_hashes)
                .map_err(|error| {
                    ScanRuntimeError::Driver(anyhow!(
                        "ordered-content done-ledger prefilter failed: {error}"
                    ))
                })?;
            if batch.len() != item_chunk.len() {
                return Err(ScanRuntimeError::Driver(anyhow!(
                    "ordered-content done-ledger prefilter returned {} result(s) for {} lookup key(s)",
                    batch.len(),
                    item_chunk.len()
                )));
            }
            present.extend(batch.into_iter().map(|record| record.is_some()));
        }

        debug_assert_eq!(
            present.len(),
            items.len(),
            "done-ledger presence flags must align with the original page",
        );

        let items = items
            .into_iter()
            .zip(present)
            .map(|(item, already_done)| {
                OrderedContentClassifiedItem::new(
                    item,
                    if already_done {
                        OrderedContentPrefilterDisposition::AlreadyDone
                    } else {
                        OrderedContentPrefilterDisposition::ScanMiss
                    },
                )
            })
            .collect();

        Ok(OrderedContentPrefilteredPage {
            items,
            page_state,
            report,
            resume_cursor,
        })
    }
}

/// Done-ledger classification for a single ordered-content page item.
///
/// Assigned by [`OrderedContentPage::prefilter_done_ledger`] based on whether
/// the item's `OvidHash` (derived from its stable identity and version claim)
/// already exists in the done ledger for the current tenant and policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OrderedContentPrefilterDisposition {
    /// The item already has a durable done-ledger row for this exact
    /// stable-item + version pair. No scan work is needed; the runtime
    /// can skip content open entirely.
    AlreadyDone,
    /// The item has no done-ledger entry and still needs content scan.
    ScanMiss,
}

/// A validated ordered-content item paired with its done-ledger disposition.
///
/// The disposition is assigned once during prefiltering and is immutable
/// thereafter. Downstream stages use it to decide whether to open the item's
/// content (`ScanMiss`) or skip it (`AlreadyDone`) without re-querying the
/// done ledger.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrderedContentClassifiedItem {
    item: ScanItem,
    disposition: OrderedContentPrefilterDisposition,
}

impl OrderedContentClassifiedItem {
    fn new(item: ScanItem, disposition: OrderedContentPrefilterDisposition) -> Self {
        Self { item, disposition }
    }

    /// The underlying connector scan item.
    #[must_use]
    pub fn item(&self) -> &ScanItem {
        &self.item
    }

    /// Prefilter classification: `AlreadyDone` or `ScanMiss`.
    #[must_use]
    pub fn disposition(&self) -> OrderedContentPrefilterDisposition {
        self.disposition
    }
}

/// Validated ordered page after done-ledger classification.
///
/// Items remain in their original page order so downstream runtime stages
/// preserve checkpoint-relevant sequencing. The `report`, `resume_cursor`,
/// and `page_state` are the same values produced by the pre-classification
/// [`OrderedContentPage`]; prefiltering does not alter them.
///
/// Callers typically iterate `scan_miss()` to drive content-open and scan
/// work, and count `already_done_len()` for metrics reporting. The full
/// classified item list is available via [`items()`](Self::items) for stages
/// that need per-item disposition regardless of classification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrderedContentPrefilteredPage {
    items: Vec<OrderedContentClassifiedItem>,
    page_state: PageState,
    report: ScanReport,
    resume_cursor: Cursor,
}

impl OrderedContentPrefilteredPage {
    /// Classified items in their original page order.
    ///
    /// The slice length equals the number of items in the source page.
    #[must_use]
    pub fn items(&self) -> &[OrderedContentClassifiedItem] {
        &self.items
    }

    /// Page completion state from the connector (`HasMore` or `Complete`).
    ///
    /// Carried through unchanged from the source page; prefiltering does not
    /// alter pagination state.
    #[must_use]
    pub fn page_state(&self) -> &PageState {
        &self.page_state
    }

    /// Runtime-local summary counters from the validated page.
    ///
    /// These reflect the full page (both done and miss items); prefiltering
    /// does not adjust the counts.
    #[must_use]
    pub fn report(&self) -> ScanReport {
        self.report
    }

    /// Resume cursor for checkpoint advancement.
    ///
    /// Carried through unchanged from the source page. Whether this cursor is
    /// actually committed depends on downstream checkpoint logic, not on
    /// prefilter results.
    #[must_use]
    pub fn resume_cursor(&self) -> &Cursor {
        &self.resume_cursor
    }

    /// Number of page items classified as `AlreadyDone`.
    ///
    /// O(n) linear scan; prefer caching the result if called in a loop.
    #[must_use]
    pub fn already_done_len(&self) -> usize {
        self.items
            .iter()
            .filter(|item| item.disposition() == OrderedContentPrefilterDisposition::AlreadyDone)
            .count()
    }

    /// Number of page items classified as `ScanMiss`.
    ///
    /// O(n) linear scan; prefer caching the result if called in a loop.
    #[must_use]
    pub fn scan_miss_len(&self) -> usize {
        self.items
            .iter()
            .filter(|item| item.disposition() == OrderedContentPrefilterDisposition::ScanMiss)
            .count()
    }

    /// Iterator over items with `AlreadyDone` disposition, in page order.
    ///
    /// Yields only the underlying [`ScanItem`] references; the disposition is
    /// implicit. Items classified as `ScanMiss` are skipped.
    pub fn already_done(&self) -> impl Iterator<Item = &ScanItem> + '_ {
        self.items.iter().filter_map(|item| {
            (item.disposition() == OrderedContentPrefilterDisposition::AlreadyDone)
                .then_some(item.item())
        })
    }

    /// Iterator over items with `ScanMiss` disposition, in page order.
    ///
    /// Yields only the underlying [`ScanItem`] references; the disposition is
    /// implicit. Items classified as `AlreadyDone` are skipped. This is the
    /// primary iterator for driving downstream content-open and scan work.
    pub fn scan_miss(&self) -> impl Iterator<Item = &ScanItem> + '_ {
        self.items.iter().filter_map(|item| {
            (item.disposition() == OrderedContentPrefilterDisposition::ScanMiss)
                .then_some(item.item())
        })
    }

    /// Consume the classified page and return its owned parts.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        Vec<OrderedContentClassifiedItem>,
        PageState,
        ScanReport,
        Cursor,
    ) {
        (self.items, self.page_state, self.report, self.resume_cursor)
    }
}

/// Result of one ordered-content page acquisition attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OrderedContentExecutionOutcome {
    /// The source reported no in-scope items for the current cursor position.
    Finished,
    /// The source returned one validated page.
    Page(Box<OrderedContentPage>),
    /// The source stopped with a classified enumerate failure.
    Stopped(OrderedContentStop),
}

/// Marker type for the ordered-content (filesystem) source family.
///
/// Provides the trait-dispatched entry point for connector-provided content
/// sources and validates the page contract before downstream runtime stages
/// consume the items.
#[derive(Debug, Default)]
pub struct OrderedContentRuntime;

impl OrderedContentRuntime {
    /// Execute one ordered-content source page acquisition.
    ///
    /// This validates:
    ///
    /// - the runtime is operating under `Completed` cursor semantics;
    /// - page shape rules (non-empty, in bounds, strictly increasing keys);
    /// - progress monotonicity relative to the restored resume cursor;
    /// - `HasMore` cursor presence (must carry a `last_key`); and
    /// - `HasMore` cursor agreement with the page's final emitted key.
    ///
    /// Connector enumerate failures surface as [`OrderedContentExecutionOutcome::Stopped`]
    /// so callers can preserve retry classification without message parsing.
    pub fn execute_source<S: OrderedContentSource>(
        source: &mut S,
        input: &OrderedContentRuntimeInput,
    ) -> Result<OrderedContentExecutionOutcome, ScanRuntimeError> {
        if input.cursor_semantics() != CursorSemantics::Completed {
            return Err(ScanRuntimeError::Driver(anyhow!(
                "ordered-content runtime requires Completed cursor semantics (got {:?})",
                input.cursor_semantics()
            )));
        }

        let page = match source.fill_page(input.shard(), input.cursor(), input.budgets()) {
            Ok(Some(page)) => page,
            Ok(None) => return Ok(OrderedContentExecutionOutcome::Finished),
            Err(error) => {
                return Ok(OrderedContentExecutionOutcome::Stopped(
                    OrderedContentStop::from_enumerate_error(error),
                ));
            }
        };

        validate_page_contract(input, &page)?;
        Ok(OrderedContentExecutionOutcome::Page(Box::new(
            OrderedContentPage::from_validated_page(page),
        )))
    }
}

/// Validate four page-level invariants after a successful `fill_page`:
///
/// 1. **Shape** — page is non-empty, keys are in-bounds, and strictly increasing.
/// 2. **Monotonicity** — the first emitted key is strictly after the restored
///    resume cursor's `last_key`, preventing duplicate processing on resume.
/// 3. **HasMore presence** — a `HasMore` cursor must carry a `last_key`.
/// 4. **Cursor agreement** — a `HasMore` cursor's `last_key` matches the page's
///    final emitted key, so the next `fill_page` call starts from the right point.
fn validate_page_contract(
    input: &OrderedContentRuntimeInput,
    page: &PageBuf<ScanItem>,
) -> Result<(), ScanRuntimeError> {
    validate_page_sequence(
        page.items(),
        page.state(),
        input.cursor().last_key(),
        input.shard().key_range_start(),
        input.shard().key_range_end(),
    )
    .map_err(|e| {
        ScanRuntimeError::Driver(anyhow!(
            "ordered-content page for shard [{:?}, {:?}) violated the page contract: {e}",
            input.shard().key_range_start(),
            input.shard().key_range_end(),
        ))
    })
}

/// Run a parallel filesystem scan against a local directory or single file.
///
/// This is the primary scan path for filesystem sources. It builds a
/// detection engine, configures the parallel scanner, and bridges scan
/// events and persistence batches into the caller's sinks.
///
/// # Persistence
///
/// When `config.persist_findings` is true, a [`ChannelStoreProducer`] is
/// wired into the parallel scanner. Finding batches flow through the commit
/// channel to the `commit` sink, which is a no-op for CLI scans; distributed
/// mode routes the same lifecycle into the receipt-driven commit pipeline via
/// its commit-sink adapter. All forwarder threads are joined before this
/// function returns, so the caller receives fully flushed scan counters.
///
/// # Errors
///
/// Returns [`ScanRuntimeError::Driver`] if `parallel_scan_dir` fails, or
/// propagates engine-construction errors from [`build_runtime_engine`].
pub(crate) fn scan_local_filesystem(
    config: &FsScanConfig,
    canonical_path: PathBuf,
    out: &dyn EventOutput,
    commit: &dyn crate::commit_sink::CommitSink,
    cancel: &CancellationToken,
) -> Result<AssignmentOutcome, ScanRuntimeError> {
    if cancel.is_cancelled() {
        return Ok(AssignmentOutcome {
            report: ScanReport::default(),
            checkpoint_hint: None,
            debug_output: None,
        });
    }

    let engine = build_runtime_engine(
        config.rules_file.as_deref(),
        &config.transform_filter,
        config.decode_depth,
        config.anchor_mode,
    )?;

    scan_local_filesystem_with_engine(config, canonical_path, engine, out, commit, cancel)
}

/// Run a parallel filesystem scan against a local directory or single file
/// using a caller-provided detection engine.
///
/// Distributed execution uses this to share one engine instance between the
/// scan workers and the receipt commit sink's rule-fingerprint lookup.
///
/// Returns early with a default (zero-count) report if cancellation has
/// already been requested. Otherwise spawns two scoped forwarder threads
/// (event and commit), runs the parallel scanner, and joins both forwarders
/// before returning.
///
/// # Errors
///
/// Returns `ScanRuntimeError::Driver` if `persist_findings` is enabled with
/// `workers != 1`. Finding persistence requires single-threaded scanning so
/// commit batches arrive in contiguous discovery-sequence groups; multi-worker
/// scanning reorders batches and breaks checkpoint sequencing.
pub(crate) fn scan_local_filesystem_with_engine(
    config: &FsScanConfig,
    canonical_path: PathBuf,
    engine: Arc<scanner_engine::Engine>,
    out: &dyn EventOutput,
    commit: &dyn crate::commit_sink::CommitSink,
    cancel: &CancellationToken,
) -> Result<AssignmentOutcome, ScanRuntimeError> {
    if cancel.is_cancelled() {
        return Ok(AssignmentOutcome {
            report: ScanReport::default(),
            checkpoint_hint: None,
            debug_output: None,
        });
    }

    let report = std::thread::scope(|scope| -> Result<ScanReport, ScanRuntimeError> {
        let (event_tx, event_rx) = sync_channel(EVENT_CHANNEL_CAP);
        let event_forwarder = scope.spawn(move || forward_core_events(out, event_rx));

        let (commit_tx, commit_rx) = sync_channel(COMMIT_CHANNEL_CAP);
        let commit_forwarder = scope.spawn(move || forward_commits(commit, commit_rx));

        let mut scan_cfg = ParallelScanConfig {
            workers: config.workers.max(1),
            event_sink: Arc::new(ChannelEventOutput::new(event_tx.clone())),
            skip_binary: !config.scan_binary,
            ..ParallelScanConfig::default()
        };
        if config.skip_archives {
            scan_cfg.archive.enabled = false;
        }
        if config.persist_findings {
            if config.workers != 1 {
                return Err(ScanRuntimeError::Driver(anyhow!(
                    "finding persistence requires workers=1 (got {}); \
                     multi-worker scanning reorders batches and breaks \
                     checkpoint sequencing",
                    config.workers
                )));
            }
            scan_cfg.store_producer = Some(Arc::new(ChannelStoreProducer::from_canonical_root(
                commit_tx.clone(),
                canonical_path.clone(),
            )));
        }

        let scan_start = std::time::Instant::now();
        let report = parallel_scan_dir(&canonical_path, engine, scan_cfg).map_err(|error| {
            ScanRuntimeError::Driver(anyhow!(
                "filesystem scan failed for '{}': {error}",
                canonical_path.display()
            ))
        })?;
        let scan_elapsed = scan_start.elapsed();

        // Close senders before joining so forwarder threads see EOF.
        drop(event_tx);
        drop(commit_tx);

        join_scoped(event_forwarder, "filesystem event forwarder thread")
            .map_err(ScanRuntimeError::Driver)?;
        join_scoped(commit_forwarder, "filesystem commit forwarder thread")
            .map_err(ScanRuntimeError::Driver)?
            .map_err(ScanRuntimeError::Driver)?;

        Ok(ScanReport {
            items_scanned: report.stats.files_enqueued,
            bytes_scanned: report.metrics.bytes_scanned,
            chunks_scanned: report.metrics.chunks_scanned,
            findings_emitted: report.metrics.findings_emitted,
            errors: report.metrics.io_errors,
            binary_skipped: report.metrics.binary_skipped,
            ext_skipped: report.metrics.ext_skipped,
            lock_skipped: report.metrics.lock_skipped,
            binary_extracted: report.metrics.binary_extracted,
            dropped_findings: report.stats.dropped_findings,
            persist_emit_failures: report.stats.persistence_emit_failures,
            persist_incomplete: report.stats.persistence_incomplete,
            scan_ns: u64::try_from(scan_elapsed.as_nanos()).unwrap_or(u64::MAX),
            persist_ns: report.metrics.persist_ns,
        })
    })?;

    Ok(AssignmentOutcome {
        report,
        checkpoint_hint: None,
        debug_output: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashSet;
    use std::io;
    use std::sync::Mutex;

    use gossip_contracts::{
        connector::{ItemKey, ItemRef, TokenBytes, VersionId},
        identity::{LogicalTime, ObjectVersionId, StableItemId},
        persistence::{
            DoneLedgerCommitReceipt, DoneLedgerKey, DoneLedgerProvenance, DoneLedgerRecord,
            DoneLedgerStatus, OvidHash, ReadyCommitHandle,
        },
    };

    use crate::test_fixtures::write_context;

    struct ScriptedSource {
        next: Option<Result<Option<PageBuf<ScanItem>>, EnumerateError>>,
    }

    impl ScriptedSource {
        fn returning(result: Result<Option<PageBuf<ScanItem>>, EnumerateError>) -> Self {
            Self { next: Some(result) }
        }
    }

    impl OrderedContentSource for ScriptedSource {
        fn capabilities(&self) -> gossip_contracts::connector::ordered::OrderedContentCapabilities {
            gossip_contracts::connector::ordered::OrderedContentCapabilities::default()
        }

        fn fill_page(
            &mut self,
            _shard: &ShardSpec,
            _cursor: &Cursor,
            _budgets: Budgets,
        ) -> Result<Option<PageBuf<ScanItem>>, EnumerateError> {
            self.next.take().expect("scripted fill_page result")
        }

        fn open(
            &mut self,
            _item_ref: &ItemRef,
            _budgets: Budgets,
        ) -> Result<Box<dyn std::io::Read + Send>, gossip_contracts::connector::ReadError> {
            unreachable!("execute_source does not read item contents")
        }
    }

    fn item(path: &[u8], size_hint: u64) -> ScanItem {
        ScanItem::new(
            ItemKey::try_from_slice(path).expect("item key"),
            ItemRef::try_from_slice(path).expect("item ref"),
            StableItemId::from_bytes([path[0]; 32]),
            VersionId::Strong(ObjectVersionId::from_version_bytes(path)),
        )
        .with_size_hint(size_hint)
    }

    fn runtime_input(
        shard: ShardSpec,
        cursor: Cursor,
        cursor_semantics: CursorSemantics,
    ) -> OrderedContentRuntimeInput {
        let state = RestoredShardState::new(shard, cursor, cursor_semantics);
        OrderedContentRuntimeInput::new(state, Budgets::try_new(8, 1_024, None).expect("budgets"))
    }

    fn item_with_identity(
        key: &str,
        stable_item_id: StableItemId,
        version_id: ObjectVersionId,
    ) -> ScanItem {
        ScanItem::new(
            ItemKey::try_from_slice(key.as_bytes()).expect("item key"),
            ItemRef::try_from_slice(key.as_bytes()).expect("item ref"),
            stable_item_id,
            VersionId::Strong(version_id),
        )
        .with_size_hint(1)
    }

    fn indexed_item(index: usize) -> ScanItem {
        let key = format!("item-{index:05}");
        let mut stable_bytes = [0u8; 32];
        stable_bytes[..8].copy_from_slice(&(index as u64).to_be_bytes());
        let mut version_bytes = [0u8; 32];
        version_bytes[..8].copy_from_slice(&(index as u64).to_be_bytes());
        version_bytes[31] = 1;
        item_with_identity(
            &key,
            StableItemId::from_bytes(stable_bytes),
            ObjectVersionId::from_bytes(version_bytes),
        )
    }

    fn item_ovid(item: &ScanItem) -> OvidHash {
        derive_ovid_hash(&OvidHashInputs {
            stable_item_id: item.stable_item_id(),
            version: item.version(),
        })
    }

    fn done_record_for(
        tenant_id: gossip_contracts::identity::TenantId,
        policy_hash: gossip_contracts::identity::PolicyHash,
        ovid_hash: OvidHash,
    ) -> DoneLedgerRecord {
        DoneLedgerRecord::try_new(
            DoneLedgerKey::new(tenant_id, policy_hash, ovid_hash),
            DoneLedgerStatus::ScannedClean,
            0,
            0,
            DoneLedgerProvenance::from_write_context(
                write_context(),
                LogicalTime::from_raw(10),
                LogicalTime::from_raw(20),
            ),
            None,
        )
        .expect("done-ledger record")
    }

    #[derive(Default)]
    struct TrackingDoneLedger {
        done: HashSet<OvidHash>,
        request_lengths: Mutex<Vec<usize>>,
    }

    impl TrackingDoneLedger {
        fn with_done(done: impl IntoIterator<Item = OvidHash>) -> Self {
            Self {
                done: done.into_iter().collect(),
                request_lengths: Mutex::new(Vec::new()),
            }
        }

        fn request_lengths(&self) -> Vec<usize> {
            self.request_lengths
                .lock()
                .expect("request lengths lock")
                .clone()
        }
    }

    impl DoneLedger for TrackingDoneLedger {
        type Error = io::Error;
        type CommitHandle = ReadyCommitHandle<DoneLedgerCommitReceipt, io::Error>;

        fn batch_get(
            &self,
            tenant_id: gossip_contracts::identity::TenantId,
            policy_hash: gossip_contracts::identity::PolicyHash,
            ovid_hashes: &[OvidHash],
        ) -> Result<Vec<Option<DoneLedgerRecord>>, Self::Error> {
            if ovid_hashes.len() > RECOMMENDED_MAX_BATCH_SIZE {
                return Err(io::Error::other(
                    "batch_get exceeded recommended batch size",
                ));
            }
            self.request_lengths
                .lock()
                .expect("request lengths lock")
                .push(ovid_hashes.len());

            Ok(ovid_hashes
                .iter()
                .map(|ovid_hash| {
                    self.done
                        .contains(ovid_hash)
                        .then(|| done_record_for(tenant_id, policy_hash, *ovid_hash))
                })
                .collect())
        }

        fn batch_upsert(
            &self,
            _records: &[DoneLedgerRecord],
        ) -> Result<Self::CommitHandle, Self::Error> {
            Ok(ReadyCommitHandle::ok(DoneLedgerCommitReceipt::new(0, 0, 0)))
        }
    }

    /// Done ledger that always fails `batch_get` with an I/O error.
    struct FailingDoneLedger;

    impl DoneLedger for FailingDoneLedger {
        type Error = io::Error;
        type CommitHandle = ReadyCommitHandle<DoneLedgerCommitReceipt, io::Error>;

        fn batch_get(
            &self,
            _tenant_id: gossip_contracts::identity::TenantId,
            _policy_hash: gossip_contracts::identity::PolicyHash,
            _ovid_hashes: &[OvidHash],
        ) -> Result<Vec<Option<DoneLedgerRecord>>, Self::Error> {
            Err(io::Error::other("injected ledger failure"))
        }

        fn batch_upsert(
            &self,
            _records: &[DoneLedgerRecord],
        ) -> Result<Self::CommitHandle, Self::Error> {
            Ok(ReadyCommitHandle::ok(DoneLedgerCommitReceipt::new(0, 0, 0)))
        }
    }

    /// Done ledger whose `batch_get` returns an empty Vec regardless of input,
    /// violating the positional contract that requires one result per lookup key.
    struct MismatchLenDoneLedger;

    impl DoneLedger for MismatchLenDoneLedger {
        type Error = io::Error;
        type CommitHandle = ReadyCommitHandle<DoneLedgerCommitReceipt, io::Error>;

        fn batch_get(
            &self,
            _tenant_id: gossip_contracts::identity::TenantId,
            _policy_hash: gossip_contracts::identity::PolicyHash,
            _ovid_hashes: &[OvidHash],
        ) -> Result<Vec<Option<DoneLedgerRecord>>, Self::Error> {
            Ok(Vec::new())
        }

        fn batch_upsert(
            &self,
            _records: &[DoneLedgerRecord],
        ) -> Result<Self::CommitHandle, Self::Error> {
            Ok(ReadyCommitHandle::ok(DoneLedgerCommitReceipt::new(0, 0, 0)))
        }
    }

    #[test]
    fn execute_source_returns_finished_for_exhausted_source() {
        let mut source = ScriptedSource::returning(Ok(None));
        let outcome = OrderedContentRuntime::execute_source(
            &mut source,
            &runtime_input(
                ShardSpec::unbounded(),
                Cursor::initial(),
                CursorSemantics::Completed,
            ),
        )
        .expect("exhausted source");

        assert_eq!(outcome, OrderedContentExecutionOutcome::Finished);
    }

    #[test]
    fn execute_source_returns_validated_page_summary_and_resume_cursor() {
        let page = PageBuf::try_new(
            vec![item(b"a.txt", 3), item(b"b.txt", 5)],
            PageState::HasMore {
                cursor: Cursor::with_token(
                    ItemKey::try_from_slice(b"b.txt").expect("cursor key"),
                    TokenBytes::try_from_slice(b"resume-token").expect("token"),
                ),
            },
        )
        .expect("page");
        let mut source = ScriptedSource::returning(Ok(Some(page)));

        let outcome = OrderedContentRuntime::execute_source(
            &mut source,
            &runtime_input(
                ShardSpec::unbounded(),
                Cursor::initial(),
                CursorSemantics::Completed,
            ),
        )
        .expect("page fill");

        let OrderedContentExecutionOutcome::Page(page) = outcome else {
            panic!("expected page outcome");
        };
        assert_eq!(page.report().items_scanned, 2);
        assert_eq!(page.report().bytes_scanned, 8);
        assert_eq!(
            page.resume_cursor()
                .last_key()
                .expect("resume cursor last_key")
                .as_bytes(),
            b"b.txt"
        );
        assert_eq!(
            page.resume_cursor()
                .token()
                .expect("resume token")
                .as_bytes(),
            b"resume-token"
        );
    }

    #[test]
    fn execute_source_returns_classified_retryable_stop() {
        let mut source =
            ScriptedSource::returning(Err(EnumerateError::rate_limited("slow down", 25)));

        let outcome = OrderedContentRuntime::execute_source(
            &mut source,
            &runtime_input(
                ShardSpec::unbounded(),
                Cursor::initial(),
                CursorSemantics::Completed,
            ),
        )
        .expect("retryable stop");

        let OrderedContentExecutionOutcome::Stopped(stop) = outcome else {
            panic!("expected stopped outcome");
        };
        assert_eq!(stop.class(), ErrorClass::Retryable);
        assert_eq!(stop.retry_after_ms(), Some(25));
        assert_eq!(stop.message(), "slow down");
    }

    #[test]
    fn execute_source_rejects_non_completed_cursor_semantics() {
        let mut source = ScriptedSource::returning(Ok(None));

        let err = OrderedContentRuntime::execute_source(
            &mut source,
            &runtime_input(
                ShardSpec::unbounded(),
                Cursor::initial(),
                CursorSemantics::Dispatched,
            ),
        )
        .expect_err("non-completed semantics must fail fast");

        assert!(
            err.to_string().contains("Completed cursor semantics"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn execute_source_rejects_page_that_regresses_past_resume_cursor() {
        let page = PageBuf::try_new(vec![item(b"a.txt", 3)], PageState::Complete).expect("page");
        let mut source = ScriptedSource::returning(Ok(Some(page)));

        let err = OrderedContentRuntime::execute_source(
            &mut source,
            &runtime_input(
                ShardSpec::unbounded(),
                Cursor::with_last_key(ItemKey::try_from_slice(b"b.txt").expect("cursor key")),
                CursorSemantics::Completed,
            ),
        )
        .expect_err("regressing page must fail");

        assert!(
            err.to_string()
                .contains("did not advance past previous last key"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn execute_source_returns_validated_single_item_complete_page() {
        let page =
            PageBuf::try_new(vec![item(b"only.txt", 42)], PageState::Complete).expect("page");
        let mut source = ScriptedSource::returning(Ok(Some(page)));

        let outcome = OrderedContentRuntime::execute_source(
            &mut source,
            &runtime_input(
                ShardSpec::unbounded(),
                Cursor::initial(),
                CursorSemantics::Completed,
            ),
        )
        .expect("single-item complete page");

        let OrderedContentExecutionOutcome::Page(page) = outcome else {
            panic!("expected page outcome");
        };
        assert_eq!(page.report().items_scanned, 1);
        assert_eq!(page.report().bytes_scanned, 42);
        assert_eq!(
            page.resume_cursor()
                .last_key()
                .expect("last_key")
                .as_bytes(),
            b"only.txt"
        );
        // Complete page resume cursor carries no opaque continuation token.
        assert!(page.resume_cursor().token().is_none());
    }

    #[test]
    fn execute_source_rejects_has_more_cursor_without_last_key() {
        let page = PageBuf::try_new(
            vec![item(b"a.txt", 3)],
            PageState::HasMore {
                cursor: Cursor::initial(), // no last_key
            },
        )
        .expect("page");
        let mut source = ScriptedSource::returning(Ok(Some(page)));

        let err = OrderedContentRuntime::execute_source(
            &mut source,
            &runtime_input(
                ShardSpec::unbounded(),
                Cursor::initial(),
                CursorSemantics::Completed,
            ),
        )
        .expect_err("HasMore without last_key must fail");

        assert!(
            err.to_string()
                .contains("HasMore cursor is missing a last_key"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn execute_source_rejects_has_more_cursor_mismatch() {
        let page = PageBuf::try_new(
            vec![item(b"a.txt", 3), item(b"b.txt", 5)],
            PageState::HasMore {
                cursor: Cursor::with_last_key(
                    ItemKey::try_from_slice(b"c.txt").expect("mismatched cursor key"),
                ),
            },
        )
        .expect("page");
        let mut source = ScriptedSource::returning(Ok(Some(page)));

        let err = OrderedContentRuntime::execute_source(
            &mut source,
            &runtime_input(
                ShardSpec::unbounded(),
                Cursor::initial(),
                CursorSemantics::Completed,
            ),
        )
        .expect_err("cursor mismatch must fail");

        assert!(
            err.to_string()
                .contains("does not match page's last emitted key"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn execute_source_returns_page_for_complete_state() {
        let page = PageBuf::try_new(
            vec![item(b"a.txt", 3), item(b"b.txt", 5)],
            PageState::Complete,
        )
        .expect("page");
        let mut source = ScriptedSource::returning(Ok(Some(page)));

        let outcome = OrderedContentRuntime::execute_source(
            &mut source,
            &runtime_input(
                ShardSpec::unbounded(),
                Cursor::initial(),
                CursorSemantics::Completed,
            ),
        )
        .expect("complete page");

        let OrderedContentExecutionOutcome::Page(page) = outcome else {
            panic!("expected page outcome");
        };
        assert_eq!(page.report().items_scanned, 2);
        assert_eq!(page.report().bytes_scanned, 8);
        assert_eq!(
            page.resume_cursor()
                .last_key()
                .expect("last key")
                .as_bytes(),
            b"b.txt",
            "Complete pages derive resume cursor from the last emitted key"
        );
        assert!(
            page.resume_cursor().token().is_none(),
            "Complete pages carry no opaque token"
        );
    }

    #[test]
    fn execute_source_counts_only_items_with_size_hints() {
        let hinted = item(b"a.txt", 10);
        let unhinted = ScanItem::new(
            ItemKey::try_from_slice(b"b.txt").expect("item key"),
            ItemRef::try_from_slice(b"b.txt").expect("item ref"),
            StableItemId::from_bytes([b'b'; 32]),
            VersionId::Strong(ObjectVersionId::from_version_bytes(b"b.txt")),
        );
        let page = PageBuf::try_new(vec![hinted, unhinted], PageState::Complete).expect("page");
        let mut source = ScriptedSource::returning(Ok(Some(page)));

        let outcome = OrderedContentRuntime::execute_source(
            &mut source,
            &runtime_input(
                ShardSpec::unbounded(),
                Cursor::initial(),
                CursorSemantics::Completed,
            ),
        )
        .expect("mixed size_hint page");

        let OrderedContentExecutionOutcome::Page(page) = outcome else {
            panic!("expected page outcome");
        };
        assert_eq!(page.report().items_scanned, 2);
        assert_eq!(
            page.report().bytes_scanned,
            10,
            "only the item with a size_hint contributes to bytes_scanned"
        );
    }

    #[test]
    fn prefilter_done_ledger_classifies_all_miss_page() {
        let items = vec![item(b"a.txt", 3), item(b"b.txt", 5)];
        let page = OrderedContentPage::from_validated_page(
            PageBuf::try_new(items, PageState::Complete).expect("page"),
        );
        let ledger = TrackingDoneLedger::default();

        let filtered = page
            .prefilter_done_ledger(write_context(), &ledger)
            .expect("prefilter succeeds");

        assert_eq!(filtered.page_state(), &PageState::Complete);
        assert_eq!(filtered.report().items_scanned, 2);
        assert_eq!(filtered.already_done_len(), 0);
        assert_eq!(filtered.scan_miss_len(), 2);
        assert_eq!(
            filtered
                .scan_miss()
                .map(|item| item.item_key().as_bytes().to_vec())
                .collect::<Vec<_>>(),
            vec![b"a.txt".to_vec(), b"b.txt".to_vec()]
        );
        assert_eq!(ledger.request_lengths(), vec![2]);
    }

    #[test]
    fn prefilter_done_ledger_classifies_all_done_page() {
        let items = vec![item(b"a.txt", 3), item(b"b.txt", 5)];
        let ledger = TrackingDoneLedger::with_done(items.iter().map(item_ovid));
        let page = OrderedContentPage::from_validated_page(
            PageBuf::try_new(items, PageState::Complete).expect("page"),
        );

        let filtered = page
            .prefilter_done_ledger(write_context(), &ledger)
            .expect("prefilter succeeds");

        assert_eq!(filtered.already_done_len(), 2);
        assert_eq!(filtered.scan_miss_len(), 0);
        assert_eq!(
            filtered
                .already_done()
                .map(|item| item.item_key().as_bytes().to_vec())
                .collect::<Vec<_>>(),
            vec![b"a.txt".to_vec(), b"b.txt".to_vec()]
        );
    }

    #[test]
    fn prefilter_done_ledger_preserves_mixed_page_order_and_resume_state() {
        let items = vec![item(b"a.txt", 3), item(b"b.txt", 5), item(b"c.txt", 7)];
        let ledger = TrackingDoneLedger::with_done([item_ovid(&items[0]), item_ovid(&items[2])]);
        let page = OrderedContentPage::from_validated_page(
            PageBuf::try_new(
                items,
                PageState::HasMore {
                    cursor: Cursor::with_token(
                        ItemKey::try_from_slice(b"c.txt").expect("cursor key"),
                        TokenBytes::try_from_slice(b"token").expect("token"),
                    ),
                },
            )
            .expect("page"),
        );

        let filtered = page
            .prefilter_done_ledger(write_context(), &ledger)
            .expect("prefilter succeeds");

        assert_eq!(
            filtered
                .items()
                .iter()
                .map(|item| (
                    item.item().item_key().as_bytes().to_vec(),
                    item.disposition()
                ))
                .collect::<Vec<_>>(),
            vec![
                (
                    b"a.txt".to_vec(),
                    OrderedContentPrefilterDisposition::AlreadyDone
                ),
                (
                    b"b.txt".to_vec(),
                    OrderedContentPrefilterDisposition::ScanMiss
                ),
                (
                    b"c.txt".to_vec(),
                    OrderedContentPrefilterDisposition::AlreadyDone
                ),
            ]
        );
        assert_eq!(filtered.already_done_len(), 2);
        assert_eq!(filtered.scan_miss_len(), 1);
        assert_eq!(
            filtered
                .resume_cursor()
                .token()
                .expect("resume token")
                .as_bytes(),
            b"token"
        );
        assert!(!filtered.page_state().is_complete());
    }

    #[test]
    fn prefilter_done_ledger_is_version_sensitive_for_same_stable_item() {
        let stable_item = StableItemId::from_bytes([0xAB; 32]);
        let v1 = ObjectVersionId::from_bytes([0x01; 32]);
        let v2 = ObjectVersionId::from_bytes([0x02; 32]);
        let item_v1 = item_with_identity("a.txt", stable_item, v1);
        let item_v2 = item_with_identity("b.txt", stable_item, v2);
        let ledger = TrackingDoneLedger::with_done([item_ovid(&item_v1)]);
        let page = OrderedContentPage::from_validated_page(
            PageBuf::try_new(vec![item_v1, item_v2], PageState::Complete).expect("page"),
        );

        let filtered = page
            .prefilter_done_ledger(write_context(), &ledger)
            .expect("prefilter succeeds");

        assert_eq!(
            filtered
                .items()
                .iter()
                .map(|item| item.disposition())
                .collect::<Vec<_>>(),
            vec![
                OrderedContentPrefilterDisposition::AlreadyDone,
                OrderedContentPrefilterDisposition::ScanMiss,
            ]
        );
    }

    #[test]
    fn prefilter_done_ledger_chunks_large_pages_without_losing_alignment() {
        let total = RECOMMENDED_MAX_BATCH_SIZE + 2;
        let items = (0..total).map(indexed_item).collect::<Vec<_>>();
        let done_indexes = [
            0usize,
            RECOMMENDED_MAX_BATCH_SIZE - 1,
            RECOMMENDED_MAX_BATCH_SIZE,
        ];
        let ledger =
            TrackingDoneLedger::with_done(done_indexes.into_iter().map(|i| item_ovid(&items[i])));
        let page = OrderedContentPage::from_validated_page(
            PageBuf::try_new(items, PageState::Complete).expect("page"),
        );

        let filtered = page
            .prefilter_done_ledger(write_context(), &ledger)
            .expect("prefilter succeeds");

        assert_eq!(
            ledger.request_lengths(),
            vec![RECOMMENDED_MAX_BATCH_SIZE, 2],
            "lookups must honor the shared batch-size ceiling"
        );
        assert_eq!(filtered.already_done_len(), 3);
        assert_eq!(filtered.scan_miss_len(), total - 3);
        assert_eq!(
            filtered
                .items()
                .iter()
                .map(|item| item.disposition())
                .take(RECOMMENDED_MAX_BATCH_SIZE + 1)
                .enumerate()
                .filter_map(|(index, disposition)| {
                    (disposition == OrderedContentPrefilterDisposition::AlreadyDone)
                        .then_some(index)
                })
                .collect::<Vec<_>>(),
            vec![
                0,
                RECOMMENDED_MAX_BATCH_SIZE - 1,
                RECOMMENDED_MAX_BATCH_SIZE
            ]
        );
    }

    #[test]
    fn prefilter_done_ledger_propagates_batch_get_io_error() {
        let items = vec![item(b"a.txt", 3), item(b"b.txt", 5)];
        let page = OrderedContentPage::from_validated_page(
            PageBuf::try_new(items, PageState::Complete).expect("page"),
        );
        let ledger = FailingDoneLedger;

        let err = page
            .prefilter_done_ledger(write_context(), &ledger)
            .expect_err("I/O failure must propagate");

        assert!(
            err.to_string()
                .contains("ordered-content done-ledger prefilter failed"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn prefilter_done_ledger_rejects_batch_length_mismatch() {
        let items = vec![item(b"a.txt", 3), item(b"b.txt", 5)];
        let page = OrderedContentPage::from_validated_page(
            PageBuf::try_new(items, PageState::Complete).expect("page"),
        );
        let ledger = MismatchLenDoneLedger;

        let err = page
            .prefilter_done_ledger(write_context(), &ledger)
            .expect_err("length mismatch must be rejected");

        assert!(
            err.to_string().contains("result(s) for"),
            "unexpected error: {err}"
        );
        assert!(
            err.to_string().contains("lookup key(s)"),
            "unexpected error: {err}"
        );
    }
}
