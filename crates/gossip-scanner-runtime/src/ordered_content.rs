//! Ordered-content runtime boundary.
//!
//! This module owns three related ordered-content execution paths and a
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
//!    Items whose done-ledger row has a terminal status (scanned, permanently
//!    failed, or skipped) are skipped before any content is opened, saving
//!    I/O and scan budget. Items with `FailedRetryable` status are treated
//!    as scan misses so they can be retried on the next pass.
//! 3. **Scan-miss execution** — [`OrderedContentRuntime::execute_scan_misses`]
//!    consumes the prefiltered `ScanMiss` subset one item at a time, bridges
//!    runtime `ScanBudgets` into connector read budgets, scans bytes through
//!    the shared chunked engine path, and returns ordered non-durable item
//!    outcomes for later translation/commit stages.
//! 4. **Local filesystem scan** — `scan_local_filesystem` runs the direct
//!    scheduler-based parallel filesystem scan and forwards events and
//!    persistence batches through bounded channels.
//!
//! The ordered-content entrypoints handle page validation and bounded
//! `scan_miss` execution. Durable translation, receipt emission, and
//! checkpoint advancement occur in later runtime stages.
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

use std::io::{self, Read};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::sync_channel;
use std::time::Instant;

use anyhow::anyhow;
use gossip_contracts::{
    connector::{
        Budgets, Cursor, EnumerateError, ErrorClass, PageBuf, PageState, ReadError, ScanItem,
        ordered::OrderedContentSource, validate_page_sequence,
    },
    coordination::{CursorSemantics, RestoredShardState, ShardSpec},
    persistence::{
        DoneLedger, DoneLedgerStatus, OvidHashInputs, RECOMMENDED_MAX_BATCH_SIZE, WriteContext,
        derive_ovid_hash,
    },
};
use scanner_engine::content_policy::{CHECK_LEN, ContentVerdict, classify_content};
use scanner_scheduler::events::EventOutput;
use scanner_scheduler::scheduler::parallel_scan::{ParallelScanConfig, parallel_scan_dir};
use scanner_scheduler::{
    EngineScratch, FileId, FindingWithHashRecord, FsFindingRecord, RealEngineScratch, ScanEngine,
    WorkerMetricsLocal, carry_overlap_prefix, scan_chunk_postprocess,
};

use crate::{
    AssignmentOutcome, COMMIT_CHANNEL_CAP, CancellationToken, ChannelEventOutput,
    ChannelStoreProducer, EVENT_CHANNEL_CAP, FsScanConfig, ScanBudgets, ScanReport,
    ScanRuntimeError, build_runtime_engine, forward_commits, forward_core_events, join_scoped,
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
///
/// `budgets` are forwarded verbatim to the connector's `fill_page` call, so
/// callers should derive them from the same scheduling decision that restored
/// `state`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrderedContentRuntimeInput {
    state: RestoredShardState,
    budgets: Budgets,
}

impl OrderedContentRuntimeInput {
    /// Construct one ordered-content execution input bundle.
    ///
    /// `state` must carry [`CursorSemantics::Completed`] — the runtime
    /// rejects other semantics at execution time. `budgets` are copied into
    /// the bundle unchanged and later forwarded to
    /// [`OrderedContentSource::fill_page`].
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
    /// # Classification rules
    ///
    /// - [`DoneLedgerStatus::ScannedClean`],
    ///   [`DoneLedgerStatus::ScannedWithFindings`],
    ///   [`DoneLedgerStatus::FailedPermanent`], and
    ///   [`DoneLedgerStatus::Skipped`] map to
    ///   [`OrderedContentPrefilterDisposition::AlreadyDone`].
    /// - [`DoneLedgerStatus::FailedRetryable`] and missing rows map to
    ///   [`OrderedContentPrefilterDisposition::ScanMiss`], keeping the item
    ///   eligible for a later retry.
    /// - The lookup key includes both stable-item identity and version claim,
    ///   so a done row for one version does not suppress scanning for another.
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
    /// # Complexity
    ///
    /// O(n) total items submitted to the done-ledger (in O(n / batch) backend
    /// calls) and O(n) additional memory for the returned classified page,
    /// where `n` is the number of items in the source page.
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
        let total = items.len();
        let mut classified = Vec::with_capacity(total);
        let mut item_iter = items.into_iter();

        // Classify items in backend-sized chunks, building the final
        // classified list directly to avoid an intermediate boolean buffer.
        while classified.len() < total {
            let chunk: Vec<_> = item_iter
                .by_ref()
                .take(RECOMMENDED_MAX_BATCH_SIZE)
                .collect();
            let ovid_hashes: Vec<_> = chunk
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
                    ScanRuntimeError::Driver(
                        anyhow::Error::new(error)
                            .context("ordered-content done-ledger prefilter failed"),
                    )
                })?;
            if batch.len() != chunk.len() {
                return Err(ScanRuntimeError::Driver(anyhow!(
                    "ordered-content done-ledger prefilter returned {} result(s) for {} lookup key(s)",
                    batch.len(),
                    chunk.len()
                )));
            }
            // Exhaustive match so adding a new DoneLedgerStatus variant
            // forces a conscious classification decision here.
            classified.extend(chunk.into_iter().zip(batch).map(|(item, record)| {
                let disposition = match record {
                    Some(r) => match r.status() {
                        DoneLedgerStatus::ScannedClean
                        | DoneLedgerStatus::ScannedWithFindings
                        | DoneLedgerStatus::FailedPermanent
                        | DoneLedgerStatus::Skipped => {
                            OrderedContentPrefilterDisposition::AlreadyDone
                        }
                        DoneLedgerStatus::FailedRetryable => {
                            OrderedContentPrefilterDisposition::ScanMiss
                        }
                    },
                    None => OrderedContentPrefilterDisposition::ScanMiss,
                };
                OrderedContentClassifiedItem::new(item, disposition)
            }));
        }

        Ok(OrderedContentPrefilteredPage {
            items: classified,
            page_state,
            report,
            resume_cursor,
        })
    }
}

/// Done-ledger classification for a single ordered-content page item.
///
/// Assigned by [`OrderedContentPage::prefilter_done_ledger`] from the
/// done-ledger status for the item's `OvidHash` (derived from its stable
/// identity and version claim) within the current tenant and policy scope.
/// Items with no row or a `FailedRetryable` row map to `ScanMiss`;
/// terminal statuses map to `AlreadyDone`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OrderedContentPrefilterDisposition {
    /// The item has a done-ledger row with a terminal status (scanned,
    /// permanently failed, or skipped) for this exact stable-item + version
    /// pair. No scan work is needed; the runtime can skip content open
    /// entirely. `FailedRetryable` rows are excluded from this disposition
    /// so those items remain eligible for retry.
    AlreadyDone,
    /// The item either has no done-ledger entry or has a `FailedRetryable`
    /// row (transient failure eligible for retry). Content scan is still
    /// required.
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

    /// Consume the classified item and return its owned parts.
    #[must_use]
    pub fn into_parts(self) -> (ScanItem, OrderedContentPrefilterDisposition) {
        (self.item, self.disposition)
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
///
/// The variants separate three boundary conditions for one `fill_page` call:
/// source exhaustion (`Finished`), connector-reported enumerate failure with
/// retry classification preserved (`Stopped`), and a validated non-empty page
/// that downstream stages may inspect (`Page`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OrderedContentExecutionOutcome {
    /// The source reported no in-scope items for the current cursor position.
    Finished,
    /// The source returned one validated page.
    Page(Box<OrderedContentPage>),
    /// The source stopped with a classified enumerate failure.
    Stopped(OrderedContentStop),
}

/// Structured stop reason for connector open/read failure.
///
/// Mirrors [`OrderedContentStop`] but for item-content access. Retryability
/// and optional backoff hints come directly from the connector's
/// [`ReadError`] when available.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrderedContentReadStop {
    class: ErrorClass,
    message: String,
    retry_after_ms: Option<u64>,
}

impl OrderedContentReadStop {
    fn from_read_error(error: ReadError) -> Self {
        Self {
            class: error.class(),
            retry_after_ms: error.retry_after_ms(),
            message: error.into_message(),
        }
    }

    fn from_reader_io(error: io::Error) -> Self {
        let class = match error.kind() {
            io::ErrorKind::InvalidInput
            | io::ErrorKind::InvalidData
            | io::ErrorKind::Unsupported
            | io::ErrorKind::PermissionDenied
            | io::ErrorKind::NotFound => ErrorClass::Permanent,
            _ => ErrorClass::Retryable,
        };
        Self {
            class,
            message: error.to_string(),
            retry_after_ms: None,
        }
    }

    /// Retry classification supplied by the connector or reader fallback.
    #[must_use]
    pub fn class(&self) -> ErrorClass {
        self.class
    }

    /// Diagnostic message for the read failure.
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

impl std::fmt::Display for OrderedContentReadStop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.retry_after_ms {
            Some(retry_after_ms) => write!(
                f,
                "ordered-content item stopped with {} read error: {} (retry_after_ms={retry_after_ms})",
                self.class, self.message
            ),
            None => write!(
                f,
                "ordered-content item stopped with {} read error: {}",
                self.class, self.message
            ),
        }
    }
}

/// Non-failure item skip reasons during ordered-content execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OrderedContentSkipReason {
    /// Item content was classified as binary and `scan_binary` was disabled.
    Binary,
    /// Item is a known extractable binary format (`.ipynb`, `.class`, `.jar`,
    /// `.pyc`, `.env`); the extraction pipeline requires full-item buffering
    /// that the ordered-content chunked-read path does not support.
    BinaryExtractable,
}

/// Non-durable outcome for one ordered-content item execution attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OrderedContentItemOutcome {
    /// The connector returned EOF before the per-item byte budget was exhausted,
    /// meaning the full item content was read and scanned. Any findings
    /// discovered during scanning are included.
    Scanned { findings: Vec<FsFindingRecord> },
    /// The per-item byte budget was exhausted before the connector signaled EOF.
    /// Only a prefix of the item was scanned, so findings past the truncation
    /// point may have been missed. Downstream translation stages must NOT
    /// persist a terminal done-ledger status for truncated items so they are
    /// retried on the next pass.
    Truncated { findings: Vec<FsFindingRecord> },
    /// Connector open/read failed for this item.
    Failed(OrderedContentReadStop),
    /// The runtime intentionally skipped this item without treating it as an error.
    Skipped(OrderedContentSkipReason),
}

/// One executed ordered-content item plus its runtime-local scan report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrderedContentItemExecution {
    item: ScanItem,
    report: ScanReport,
    outcome: OrderedContentItemOutcome,
}

impl OrderedContentItemExecution {
    fn new(item: ScanItem, report: ScanReport, outcome: OrderedContentItemOutcome) -> Self {
        Self {
            item,
            report,
            outcome,
        }
    }

    /// Item metadata used for downstream translation and commit decisions.
    #[must_use]
    pub fn item(&self) -> &ScanItem {
        &self.item
    }

    /// Runtime-local report for just this item attempt.
    #[must_use]
    pub fn report(&self) -> ScanReport {
        self.report
    }

    /// Non-durable runtime outcome for the item.
    #[must_use]
    pub fn outcome(&self) -> &OrderedContentItemOutcome {
        &self.outcome
    }

    /// Consume the item execution and return its owned parts.
    #[must_use]
    pub fn into_parts(self) -> (ScanItem, ScanReport, OrderedContentItemOutcome) {
        (self.item, self.report, self.outcome)
    }
}

/// Ordered execution results for one prefiltered page's `ScanMiss` subset.
///
/// `outcomes` and `deferred` each preserve the original page order of their
/// miss items. Items whose `size_hint` exceeds the remaining byte budget are
/// individually deferred (skipped ahead) so smaller items behind them can still
/// be processed; this means `deferred` may contain items from the interior of
/// the page, not only a contiguous suffix.
/// The page-level `page_state`, `page_report`, and `resume_cursor` values are
/// carried through unchanged from the input prefiltered page.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrderedContentScanMissExecution {
    outcomes: Vec<OrderedContentItemExecution>,
    deferred: Vec<ScanItem>,
    already_done_len: usize,
    page_state: PageState,
    page_report: ScanReport,
    execution_report: ScanReport,
    resume_cursor: Cursor,
}

impl OrderedContentScanMissExecution {
    fn new(
        outcomes: Vec<OrderedContentItemExecution>,
        deferred: Vec<ScanItem>,
        already_done_len: usize,
        page_state: PageState,
        page_report: ScanReport,
        execution_report: ScanReport,
        resume_cursor: Cursor,
    ) -> Self {
        Self {
            outcomes,
            deferred,
            already_done_len,
            page_state,
            page_report,
            execution_report,
            resume_cursor,
        }
    }

    /// Executed miss outcomes in original page order.
    #[must_use]
    pub fn outcomes(&self) -> &[OrderedContentItemExecution] {
        &self.outcomes
    }

    /// Miss items deferred because the runtime budget could not admit them.
    #[must_use]
    pub fn deferred(&self) -> &[ScanItem] {
        &self.deferred
    }

    /// Count of prefiltered items classified as `AlreadyDone`.
    #[must_use]
    pub fn already_done_len(&self) -> usize {
        self.already_done_len
    }

    /// Original connector page state.
    #[must_use]
    pub fn page_state(&self) -> &PageState {
        &self.page_state
    }

    /// Original validated page summary from enumeration.
    #[must_use]
    pub fn page_report(&self) -> ScanReport {
        self.page_report
    }

    /// Aggregate report across executed `ScanMiss` items only.
    #[must_use]
    pub fn execution_report(&self) -> ScanReport {
        self.execution_report
    }

    /// Resume cursor carried through from the validated page.
    #[must_use]
    pub fn resume_cursor(&self) -> &Cursor {
        &self.resume_cursor
    }
}

/// Marker type for the ordered-content (filesystem) source family.
///
/// Provides the trait-dispatched entry point for connector-provided content
/// sources, validates the page contract, and executes prefiltered misses
/// under bounded open/read budgets.
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
    /// Returns:
    ///
    /// - [`OrderedContentExecutionOutcome::Finished`] when the source reports
    ///   no more in-scope items for the current cursor,
    /// - [`OrderedContentExecutionOutcome::Stopped`] when `fill_page` returns
    ///   an [`EnumerateError`], preserving the connector's retry
    ///   classification and optional backoff hint, and
    /// - [`OrderedContentExecutionOutcome::Page`] only after the returned page
    ///   satisfies the ordered-page contract.
    ///
    /// # Errors
    ///
    /// Returns [`ScanRuntimeError::Driver`] when the restored shard state is
    /// internally inconsistent for this runtime boundary (for example,
    /// non-`Completed` cursor semantics) or when the connector returns a page
    /// that violates the ordered-page contract.
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

    /// Build the runtime engine from [`FsScanConfig`] and execute the page's
    /// `ScanMiss` subset under the runtime budgets.
    pub fn execute_scan_misses<S: OrderedContentSource>(
        source: &mut S,
        page: OrderedContentPrefilteredPage,
        config: &FsScanConfig,
    ) -> Result<OrderedContentScanMissExecution, ScanRuntimeError> {
        let engine = build_runtime_engine(
            config.rules_file.as_deref(),
            &config.transform_filter,
            config.decode_depth,
            config.anchor_mode,
        )?;
        Self::execute_scan_misses_with_engine(
            source,
            page,
            config.budgets,
            config.scan_binary,
            engine,
            DEFAULT_ORDERED_CHUNK_SIZE,
        )
    }

    /// Execute one prefiltered page's `ScanMiss` items with a caller-supplied engine.
    ///
    /// `AlreadyDone` entries are counted but never opened. Execution keeps
    /// at most one miss in flight at a time. Item-count and byte limits are
    /// enforced before admitting an item, then bridged into per-item connector
    /// read budgets. A miss whose `size_hint` exceeds the remaining byte
    /// budget is individually deferred (skipped ahead) so that smaller items
    /// behind it can still be processed; when the budget is fully exhausted
    /// the remaining miss suffix is drained into `deferred`. The returned
    /// outcomes are non-durable: this stage does not emit receipts, advance
    /// checkpoints, or write the done ledger.
    pub fn execute_scan_misses_with_engine<S: OrderedContentSource>(
        source: &mut S,
        page: OrderedContentPrefilteredPage,
        budgets: ScanBudgets,
        scan_binary: bool,
        engine: Arc<scanner_engine::Engine>,
        chunk_size: usize,
    ) -> Result<OrderedContentScanMissExecution, ScanRuntimeError> {
        budgets.validate()?;
        if chunk_size == 0 {
            return Err(ScanRuntimeError::Driver(anyhow!(
                "ordered-content chunk_size must be greater than 0"
            )));
        }
        let overlap = <scanner_engine::Engine as ScanEngine>::required_overlap(&engine);
        let mut scan_buf = vec![0u8; chunk_size.saturating_add(overlap)];
        let mut scan_scratch = <scanner_engine::Engine as ScanEngine>::new_scratch(&engine);
        let mut scan_pending = Vec::with_capacity(
            <scanner_engine::Engine as ScanEngine>::max_findings_per_chunk(&engine),
        );
        let mut scan_metrics = WorkerMetricsLocal::new();

        let (classified, page_state, page_report, resume_cursor) = page.into_parts();
        let mut outcomes = Vec::new();
        let mut deferred = Vec::new();
        let mut execution_report = ScanReport::default();
        let mut already_done_len = 0usize;
        let mut remaining_items = budgets.max_items;
        let mut remaining_bytes = budgets.max_bytes;
        let range_read = source.capabilities().range_read;
        let mut next_file_id = 0u32;

        let mut classified_iter = classified.into_iter();
        while let Some(classified_item) = classified_iter.next() {
            let (item, disposition) = classified_item.into_parts();
            match disposition {
                OrderedContentPrefilterDisposition::AlreadyDone => {
                    already_done_len += 1;
                }
                OrderedContentPrefilterDisposition::ScanMiss => {
                    let budget_exhausted = remaining_items == 0 || remaining_bytes == 0;

                    if budget_exhausted {
                        drain_remaining_misses(
                            item,
                            &mut classified_iter,
                            &mut deferred,
                            &mut already_done_len,
                        );
                        break;
                    }

                    // Skip ahead past oversized items instead of deferring the
                    // entire remaining suffix. The item may be binary or
                    // extractable, and classification (which skips for free)
                    // requires reading content. By deferring only this item,
                    // smaller items behind it still get a chance to be
                    // processed in the current pass.
                    let exceeds_budget =
                        item.size_hint().is_some_and(|hint| hint > remaining_bytes);
                    if exceeds_budget {
                        deferred.push(item);
                        continue;
                    }

                    let file_id = FileId(next_file_id);
                    next_file_id = next_file_id.checked_add(1).ok_or_else(|| {
                        ScanRuntimeError::Driver(anyhow!("ordered-content file-id space exhausted"))
                    })?;

                    let item_result = if range_read {
                        execute_item_via_range_read(
                            source,
                            &engine,
                            item,
                            file_id,
                            scan_binary,
                            remaining_bytes,
                            chunk_size,
                            &mut scan_buf,
                            &mut scan_scratch,
                            &mut scan_pending,
                            &mut scan_metrics,
                        )?
                    } else {
                        execute_item_via_open(
                            source,
                            &engine,
                            item,
                            file_id,
                            scan_binary,
                            remaining_bytes,
                            chunk_size,
                            &mut scan_buf,
                            &mut scan_scratch,
                            &mut scan_pending,
                            &mut scan_metrics,
                        )?
                    };

                    remaining_items = remaining_items.saturating_sub(1);
                    remaining_bytes =
                        remaining_bytes.saturating_sub(item_result.connector_bytes_consumed);
                    execution_report += item_result.execution.report();
                    outcomes.push(item_result.execution);
                }
            }
        }

        Ok(OrderedContentScanMissExecution::new(
            outcomes,
            deferred,
            already_done_len,
            page_state,
            page_report,
            execution_report,
            resume_cursor,
        ))
    }
}

struct OrderedContentItemResult {
    execution: OrderedContentItemExecution,
    connector_bytes_consumed: u64,
}

/// Clamp an item's declared size to the remaining byte budget.
///
/// When the item carries a `size_hint`, that value (floored to 1) is
/// clamped to `remaining_bytes`.  When no hint is available the item's
/// true size is unknown, so a fixed cap ([`DEFAULT_UNKNOWN_ITEM_BYTE_CAP`])
/// prevents a single unbounded item from consuming the entire page
/// budget, which would otherwise cause a perpetual truncation loop: the
/// item gets the full budget, is truncated, is retried, gets the full
/// budget again, and so on.
fn item_byte_budget(item: &ScanItem, remaining_bytes: u64) -> u64 {
    item.size_hint()
        .map(|hint| hint.max(1))
        .unwrap_or(DEFAULT_UNKNOWN_ITEM_BYTE_CAP)
        .min(remaining_bytes)
}

/// Per-item byte cap applied when the connector does not provide a
/// `size_hint`.  16 MiB covers >99 % of source-code files while leaving
/// the majority of a 64 MiB page budget available for subsequent items.
const DEFAULT_UNKNOWN_ITEM_BYTE_CAP: u64 = 16 * 1024 * 1024;

/// Default chunk size for ordered-content scanning (256 KiB).
///
/// This value is validated by the engine's buffer-scaling benchmarks
/// (`scanner_throughput.rs`) and sits in the L2-cache sweet spot
/// (256 KiB–1 MiB on modern CPUs).  At 2 GB/s engine throughput each
/// chunk scans in ~128 µs with ~1.5 % per-call overhead — negligible
/// for Tiers 2–4.  Hyperscan/Vectorscan has no buffer-size preference
/// beyond "not tiny", so the value is driven by cache residency and
/// I/O amortization, not by the engine.
const DEFAULT_ORDERED_CHUNK_SIZE: usize = 256 * 1024;

fn connector_read_budgets(max_bytes: u64) -> Result<Budgets, ScanRuntimeError> {
    Budgets::try_new(1, max_bytes, None).map_err(ScanRuntimeError::ConnectorInput)
}

/// Push `first` into `deferred`, then drain the remaining iterator, collecting
/// `ScanMiss` items into `deferred` and counting `AlreadyDone` entries.
fn drain_remaining_misses(
    first: ScanItem,
    iter: &mut impl Iterator<Item = OrderedContentClassifiedItem>,
    deferred: &mut Vec<ScanItem>,
    already_done_len: &mut usize,
) {
    deferred.push(first);
    deferred.extend(iter.filter_map(|classified_item| {
        let (item, disposition) = classified_item.into_parts();
        match disposition {
            OrderedContentPrefilterDisposition::AlreadyDone => {
                *already_done_len += 1;
                None
            }
            OrderedContentPrefilterDisposition::ScanMiss => Some(item),
        }
    }));
}

fn build_item_report(
    metrics: &WorkerMetricsLocal,
    findings_emitted: u64,
    errors: u64,
    binary_skipped: u64,
    scan_ns: u64,
) -> ScanReport {
    ScanReport {
        items_scanned: 1,
        bytes_scanned: metrics.bytes_scanned,
        chunks_scanned: metrics.chunks_scanned,
        findings_emitted,
        errors,
        binary_skipped,
        binary_extracted: metrics.binary_extracted,
        dropped_findings: metrics.findings_dropped,
        scan_ns,
        ..ScanReport::default()
    }
}

fn append_findings<F: FindingWithHashRecord>(src: &[F], dst: &mut Vec<FsFindingRecord>) {
    dst.extend(src.iter().map(|finding| FsFindingRecord {
        rule_id: finding.rule_id(),
        root_hint_start: finding.root_hint_start(),
        root_hint_end: finding.root_hint_end(),
        span_start: finding.span_start(),
        span_end: finding.span_end(),
        norm_hash: *finding.norm_hash(),
        confidence_score: finding.confidence_score(),
    }));
}

/// Scan an item's content in chunks, enforcing the per-item byte budget.
///
/// `stateless_reads` indicates whether the `read_next` closure supports
/// offset-based stateless reads (e.g. `read_range`). When true, a one-byte
/// EOF probe after budget exhaustion reliably distinguishes real EOF from
/// budget-limit EOF. When false (open-based sequential readers that may be
/// budget-capped at creation), the probe would query the same budget-limited
/// reader and cannot detect trailing content, so budget exhaustion is always
/// treated as truncation.
#[allow(clippy::too_many_arguments)]
fn scan_item_chunks(
    engine: &scanner_engine::Engine,
    item: ScanItem,
    file_id: FileId,
    scan_binary: bool,
    item_byte_budget: u64,
    chunk_size: usize,
    buf: &mut [u8],
    scratch: &mut RealEngineScratch,
    pending: &mut Vec<<RealEngineScratch as EngineScratch>::Finding>,
    metrics: &mut WorkerMetricsLocal,
    stateless_reads: bool,
    mut read_next: impl FnMut(u64, &mut [u8], u64) -> Result<usize, OrderedContentReadStop>,
) -> OrderedContentItemResult {
    let overlap = <scanner_engine::Engine as ScanEngine>::required_overlap(engine);
    pending.clear();
    *metrics = WorkerMetricsLocal::new();
    let mut findings = Vec::new();
    let started_at = Instant::now();
    let mut connector_bytes_consumed = 0u64;
    let mut offset = 0u64;
    let mut carry = 0usize;
    let mut have = 0usize;
    let mut first_chunk = true;

    let outcome = loop {
        if carry > 0 && have > 0 {
            carry_overlap_prefix(buf, have, carry);
        }

        let remaining_item_bytes = item_byte_budget.saturating_sub(connector_bytes_consumed);
        if remaining_item_bytes == 0 {
            // Budget exhausted. For stateless read paths (range-read), probe
            // one more byte to distinguish real EOF from budget-limit EOF.
            // For stateful readers (open-based), the reader may be budget-
            // capped at creation, so the probe would see the wrapper's EOF
            // rather than the underlying content's — treat as truncated.
            if stateless_reads {
                let mut probe = [0u8; 1];
                let eof = match read_next(offset, &mut probe, 1) {
                    Ok(0) => true,
                    Ok(_) => false,
                    Err(_) => false,
                };
                if eof {
                    break OrderedContentItemOutcome::Scanned { findings };
                }
            }
            break OrderedContentItemOutcome::Truncated { findings };
        }
        let read_max = chunk_size
            .min(buf.len().saturating_sub(carry))
            .min(usize::try_from(remaining_item_bytes).unwrap_or(usize::MAX));
        if read_max == 0 {
            // Buffer too small to make progress; unreachable after the
            // chunk_size > 0 guard, but safe to treat as truncated.
            break OrderedContentItemOutcome::Truncated { findings };
        }

        let n = match read_next(
            offset,
            &mut buf[carry..carry + read_max],
            remaining_item_bytes,
        ) {
            Ok(n) => n.min(read_max),
            Err(stop) => break OrderedContentItemOutcome::Failed(stop),
        };
        if n == 0 {
            break OrderedContentItemOutcome::Scanned { findings };
        }

        connector_bytes_consumed = connector_bytes_consumed.saturating_add(n as u64);

        if std::mem::take(&mut first_chunk) && !scan_binary {
            let verdict = classify_content(
                &buf[carry..carry + n],
                item.item_key().as_bytes(),
                CHECK_LEN,
            );
            match verdict {
                ContentVerdict::Binary => {
                    // Probe bytes are not charged to the byte budget so that
                    // binary items are free from a budget perspective, matching
                    // the filesystem scan path semantics.
                    connector_bytes_consumed = 0;
                    break OrderedContentItemOutcome::Skipped(OrderedContentSkipReason::Binary);
                }
                ContentVerdict::BinaryExtractable(_) => {
                    // Extractable formats (.class, .jar, .pyc, .ipynb, .env)
                    // require full-item buffering for `extract_content`, which
                    // the ordered-content chunked-read path does not provide.
                    connector_bytes_consumed = 0;
                    break OrderedContentItemOutcome::Skipped(
                        OrderedContentSkipReason::BinaryExtractable,
                    );
                }
                ContentVerdict::Text => {}
            }
        }

        let total_len = carry + n;
        debug_assert!(
            offset >= carry as u64,
            "base_offset underflow: offset={offset}, carry={carry}"
        );
        let base_offset = offset.saturating_sub(carry as u64);
        scan_chunk_postprocess(
            engine,
            scratch,
            pending,
            file_id,
            base_offset,
            carry,
            &buf[..total_len],
            metrics,
        );
        append_findings(pending, &mut findings);

        offset = offset.saturating_add(n as u64);
        have = total_len;
        carry = overlap.min(total_len);
    };

    let wall_clock_scan_ns = u64::try_from(started_at.elapsed().as_nanos()).unwrap_or(u64::MAX);
    let (findings_emitted, errors, binary_skipped) = match &outcome {
        OrderedContentItemOutcome::Scanned { findings }
        | OrderedContentItemOutcome::Truncated { findings } => (findings.len() as u64, 0, 0),
        OrderedContentItemOutcome::Failed(_stop) => (0, 1, 0),
        OrderedContentItemOutcome::Skipped(
            OrderedContentSkipReason::Binary | OrderedContentSkipReason::BinaryExtractable,
        ) => (0, 0, 1),
    };
    let report = build_item_report(
        metrics,
        findings_emitted,
        errors,
        binary_skipped,
        wall_clock_scan_ns,
    );
    OrderedContentItemResult {
        execution: OrderedContentItemExecution::new(item, report, outcome),
        connector_bytes_consumed,
    }
}

#[allow(clippy::too_many_arguments)]
fn execute_item_via_range_read<S: OrderedContentSource>(
    source: &mut S,
    engine: &scanner_engine::Engine,
    item: ScanItem,
    file_id: FileId,
    scan_binary: bool,
    remaining_bytes: u64,
    chunk_size: usize,
    buf: &mut [u8],
    scratch: &mut RealEngineScratch,
    pending: &mut Vec<<RealEngineScratch as EngineScratch>::Finding>,
    metrics: &mut WorkerMetricsLocal,
) -> Result<OrderedContentItemResult, ScanRuntimeError> {
    let item_byte_budget = item_byte_budget(&item, remaining_bytes);
    let item_ref = item.item_ref().clone();
    Ok(scan_item_chunks(
        engine,
        item,
        file_id,
        scan_binary,
        item_byte_budget,
        chunk_size,
        buf,
        scratch,
        pending,
        metrics,
        true, // range-read: each call is offset-based and stateless
        move |offset, dst, remaining_item_bytes| {
            let budgets = connector_read_budgets(remaining_item_bytes).map_err(|error| {
                OrderedContentReadStop {
                    class: ErrorClass::Permanent,
                    message: error.to_string(),
                    retry_after_ms: None,
                }
            })?;
            source
                .read_range(&item_ref, offset, dst, budgets)
                .map_err(OrderedContentReadStop::from_read_error)
        },
    ))
}

#[allow(clippy::too_many_arguments)]
fn execute_item_via_open<S: OrderedContentSource>(
    source: &mut S,
    engine: &scanner_engine::Engine,
    item: ScanItem,
    file_id: FileId,
    scan_binary: bool,
    remaining_bytes: u64,
    chunk_size: usize,
    buf: &mut [u8],
    scratch: &mut RealEngineScratch,
    pending: &mut Vec<<RealEngineScratch as EngineScratch>::Finding>,
    metrics: &mut WorkerMetricsLocal,
) -> Result<OrderedContentItemResult, ScanRuntimeError> {
    let item_byte_budget = item_byte_budget(&item, remaining_bytes);
    let reader_budgets = connector_read_budgets(item_byte_budget)?;
    let mut reader = match source.open(item.item_ref(), reader_budgets) {
        Ok(reader) => reader,
        Err(error) => {
            let report = build_item_report(&WorkerMetricsLocal::new(), 0, 1, 0, 0);
            return Ok(OrderedContentItemResult {
                execution: OrderedContentItemExecution::new(
                    item,
                    report,
                    OrderedContentItemOutcome::Failed(OrderedContentReadStop::from_read_error(
                        error,
                    )),
                ),
                connector_bytes_consumed: 0,
            });
        }
    };
    Ok(scan_item_chunks(
        engine,
        item,
        file_id,
        scan_binary,
        item_byte_budget,
        chunk_size,
        buf,
        scratch,
        pending,
        metrics,
        false, // open: reader may be budget-capped, EOF probe unreliable
        // Sequential io::Read — offset tracking is implicit, no seek support.
        // The byte budget is enforced by scan_item_chunks, which sizes each
        // read slice to the remaining item budget.
        move |_offset, dst, _remaining_item_bytes| {
            reader
                .read(dst)
                .map_err(OrderedContentReadStop::from_reader_io)
        },
    ))
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
/// The forwarder threads are part of the function's correctness contract:
/// all senders are dropped before the joins so buffered events and commit
/// batches are fully drained before the caller observes the returned report.
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

    use std::collections::{HashMap, HashSet};
    use std::io;
    use std::io::Write;
    use std::sync::Mutex;

    use gossip_contracts::{
        connector::{
            ItemKey, ItemRef, ReadError, TokenBytes, VersionId, ordered::OrderedContentCapabilities,
        },
        identity::{LogicalTime, ObjectVersionId, StableItemId},
        persistence::{
            DoneLedgerCommitReceipt, DoneLedgerErrorCode, DoneLedgerKey, DoneLedgerProvenance,
            DoneLedgerRecord, DoneLedgerStatus, OvidHash, ReadyCommitHandle,
        },
    };
    use tempfile::NamedTempFile;

    use crate::test_fixtures::write_context;
    use crate::{AnchorMode, TransformFilter};

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

    fn item_no_hint(path: &[u8]) -> ScanItem {
        ScanItem::new(
            ItemKey::try_from_slice(path).expect("item key"),
            ItemRef::try_from_slice(path).expect("item ref"),
            StableItemId::from_bytes([path[0]; 32]),
            VersionId::Strong(ObjectVersionId::from_version_bytes(path)),
        )
    }

    fn runtime_input(
        shard: ShardSpec,
        cursor: Cursor,
        cursor_semantics: CursorSemantics,
    ) -> OrderedContentRuntimeInput {
        let state = RestoredShardState::new(shard, cursor, cursor_semantics);
        OrderedContentRuntimeInput::new(state, Budgets::try_new(8, 1_024, None).expect("budgets"))
    }

    fn write_runtime_rules() -> NamedTempFile {
        let mut file = NamedTempFile::new().expect("rules temp file");
        write!(
            file,
            "rules:\n  - name: \"runtime-fixture\"\n    regex: 'TOK_[A-Z0-9]{{8}}'\n    anchors: [\"TOK_\"]\n    radius: 32\n"
        )
        .expect("write rules");
        file
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct ReadCall {
        item_ref: Vec<u8>,
        offset: u64,
        max_items: usize,
        max_bytes: u64,
    }

    #[derive(Default)]
    struct ContentSource {
        capabilities: OrderedContentCapabilities,
        contents: HashMap<Vec<u8>, Vec<u8>>,
        open_errors: HashMap<Vec<u8>, ReadError>,
        range_errors: HashMap<(Vec<u8>, u64), ReadError>,
        open_calls: Vec<ReadCall>,
        range_calls: Vec<ReadCall>,
    }

    impl ContentSource {
        fn with_range_read() -> Self {
            Self {
                capabilities: OrderedContentCapabilities {
                    range_read: true,
                    ..OrderedContentCapabilities::default()
                },
                ..Self::default()
            }
        }

        fn insert(&mut self, item_ref: &[u8], bytes: &[u8]) {
            self.contents.insert(item_ref.to_vec(), bytes.to_vec());
        }

        fn set_open_error(&mut self, item_ref: &[u8], error: ReadError) {
            self.open_errors.insert(item_ref.to_vec(), error);
        }

        fn set_range_error(&mut self, item_ref: &[u8], offset: u64, error: ReadError) {
            self.range_errors.insert((item_ref.to_vec(), offset), error);
        }
    }

    impl OrderedContentSource for ContentSource {
        fn capabilities(&self) -> OrderedContentCapabilities {
            self.capabilities
        }

        fn fill_page(
            &mut self,
            _shard: &ShardSpec,
            _cursor: &Cursor,
            _budgets: Budgets,
        ) -> Result<Option<PageBuf<ScanItem>>, EnumerateError> {
            unreachable!("content tests inject prefiltered pages directly")
        }

        fn open(
            &mut self,
            item_ref: &ItemRef,
            budgets: Budgets,
        ) -> Result<Box<dyn std::io::Read + Send>, ReadError> {
            self.open_calls.push(ReadCall {
                item_ref: item_ref.as_bytes().to_vec(),
                offset: 0,
                max_items: budgets.max_items(),
                max_bytes: budgets.max_bytes(),
            });
            if let Some(error) = self.open_errors.get(item_ref.as_bytes()).cloned() {
                return Err(error);
            }
            let bytes = self
                .contents
                .get(item_ref.as_bytes())
                .cloned()
                .expect("content for open");
            Ok(Box::new(
                std::io::Cursor::new(bytes).take(budgets.max_bytes()),
            ))
        }

        fn read_range(
            &mut self,
            item_ref: &ItemRef,
            offset: u64,
            dst: &mut [u8],
            budgets: Budgets,
        ) -> Result<usize, ReadError> {
            self.range_calls.push(ReadCall {
                item_ref: item_ref.as_bytes().to_vec(),
                offset,
                max_items: budgets.max_items(),
                max_bytes: budgets.max_bytes(),
            });
            if let Some(error) = self
                .range_errors
                .get(&(item_ref.as_bytes().to_vec(), offset))
                .cloned()
            {
                return Err(error);
            }
            let bytes = self
                .contents
                .get(item_ref.as_bytes())
                .expect("content for range");
            let start = match usize::try_from(offset) {
                Ok(start) => start,
                Err(_) => return Ok(0),
            };
            if start >= bytes.len() {
                return Ok(0);
            }
            let allowed = dst
                .len()
                .min(usize::try_from(budgets.max_bytes()).unwrap_or(usize::MAX));
            let to_copy = (bytes.len() - start).min(allowed);
            dst[..to_copy].copy_from_slice(&bytes[start..start + to_copy]);
            Ok(to_copy)
        }
    }

    fn prefiltered_page(
        entries: Vec<(ScanItem, OrderedContentPrefilterDisposition)>,
        page_state: PageState,
    ) -> OrderedContentPrefilteredPage {
        let items_scanned = entries.len() as u64;
        let bytes_scanned = entries
            .iter()
            .filter_map(|(item, _)| item.size_hint())
            .sum::<u64>();
        let last_key = entries
            .last()
            .map(|(item, _)| item.item_key().clone())
            .expect("prefiltered page requires at least one item");
        let resume_cursor = match &page_state {
            PageState::HasMore { cursor } => cursor.clone(),
            PageState::Complete => Cursor::with_last_key(last_key),
        };
        OrderedContentPrefilteredPage {
            items: entries
                .into_iter()
                .map(|(item, disposition)| OrderedContentClassifiedItem::new(item, disposition))
                .collect(),
            page_state,
            report: ScanReport {
                items_scanned,
                bytes_scanned,
                ..ScanReport::default()
            },
            resume_cursor,
        }
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
        done_record_with_status(
            tenant_id,
            policy_hash,
            ovid_hash,
            DoneLedgerStatus::ScannedClean,
        )
    }

    /// Build a done-ledger record with the given status, supplying the
    /// error-code and findings-count values that `validate()` requires for
    /// each status variant.
    fn done_record_with_status(
        tenant_id: gossip_contracts::identity::TenantId,
        policy_hash: gossip_contracts::identity::PolicyHash,
        ovid_hash: OvidHash,
        status: DoneLedgerStatus,
    ) -> DoneLedgerRecord {
        let (findings_count, error_code) = match status {
            DoneLedgerStatus::ScannedClean => (0, None),
            DoneLedgerStatus::ScannedWithFindings => (1, None),
            DoneLedgerStatus::FailedRetryable
            | DoneLedgerStatus::FailedPermanent
            | DoneLedgerStatus::Skipped => (
                0,
                Some(DoneLedgerErrorCode::try_new("TEST_ERROR").expect("error code")),
            ),
        };
        let record = DoneLedgerRecord::try_new(
            DoneLedgerKey::new(tenant_id, policy_hash, ovid_hash),
            status,
            0,
            findings_count,
            DoneLedgerProvenance::from_write_context(
                write_context(),
                LogicalTime::from_raw(10),
                LogicalTime::from_raw(20),
            ),
            error_code,
        )
        .expect("done-ledger record");
        record
            .validate()
            .expect("done-ledger record cross-field invariants");
        record
    }

    struct TrackingDoneLedger {
        done: HashSet<OvidHash>,
        expected_tenant: gossip_contracts::identity::TenantId,
        expected_policy: gossip_contracts::identity::PolicyHash,
        request_lengths: Mutex<Vec<usize>>,
    }

    impl TrackingDoneLedger {
        fn empty() -> Self {
            let wc = write_context();
            Self {
                done: HashSet::new(),
                expected_tenant: wc.tenant_id(),
                expected_policy: wc.policy_hash(),
                request_lengths: Mutex::new(Vec::new()),
            }
        }

        fn with_done(done: impl IntoIterator<Item = OvidHash>) -> Self {
            let wc = write_context();
            Self {
                done: done.into_iter().collect(),
                expected_tenant: wc.tenant_id(),
                expected_policy: wc.policy_hash(),
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
            assert_eq!(tenant_id, self.expected_tenant, "batch_get tenant mismatch");
            assert_eq!(
                policy_hash, self.expected_policy,
                "batch_get policy mismatch"
            );
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

    /// Done ledger that returns per-item status values, allowing tests to
    /// exercise non-ScannedClean done-ledger states (e.g. FailedRetryable).
    struct StatusAwareDoneLedger {
        statuses: HashMap<OvidHash, DoneLedgerStatus>,
        expected_tenant: gossip_contracts::identity::TenantId,
        expected_policy: gossip_contracts::identity::PolicyHash,
    }

    impl StatusAwareDoneLedger {
        fn new(statuses: impl IntoIterator<Item = (OvidHash, DoneLedgerStatus)>) -> Self {
            let wc = write_context();
            Self {
                statuses: statuses.into_iter().collect(),
                expected_tenant: wc.tenant_id(),
                expected_policy: wc.policy_hash(),
            }
        }
    }

    impl DoneLedger for StatusAwareDoneLedger {
        type Error = io::Error;
        type CommitHandle = ReadyCommitHandle<DoneLedgerCommitReceipt, io::Error>;

        fn batch_get(
            &self,
            tenant_id: gossip_contracts::identity::TenantId,
            policy_hash: gossip_contracts::identity::PolicyHash,
            ovid_hashes: &[OvidHash],
        ) -> Result<Vec<Option<DoneLedgerRecord>>, Self::Error> {
            assert_eq!(tenant_id, self.expected_tenant, "batch_get tenant mismatch");
            assert_eq!(
                policy_hash, self.expected_policy,
                "batch_get policy mismatch"
            );
            Ok(ovid_hashes
                .iter()
                .map(|ovid_hash| {
                    self.statuses.get(ovid_hash).map(|&status| {
                        done_record_with_status(tenant_id, policy_hash, *ovid_hash, status)
                    })
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

    #[test]
    fn execute_scan_misses_scans_range_read_items_in_page_order() {
        let rules = write_runtime_rules();
        let mut source = ContentSource::with_range_read();
        let secret = b"prefix TOK_ABCDEFGH suffix";
        let clean = b"harmless";
        source.insert(b"secret.txt", secret);
        source.insert(b"clean.txt", clean);
        let page = prefiltered_page(
            vec![
                (
                    item(b"done.txt", 4),
                    OrderedContentPrefilterDisposition::AlreadyDone,
                ),
                (
                    item(b"secret.txt", secret.len() as u64),
                    OrderedContentPrefilterDisposition::ScanMiss,
                ),
                (
                    item(b"clean.txt", clean.len() as u64),
                    OrderedContentPrefilterDisposition::ScanMiss,
                ),
            ],
            PageState::Complete,
        );
        let config = FsScanConfig::new("/tmp/ordered-content-test")
            .with_rules_file(Some(rules.path().to_path_buf()))
            .with_budgets(ScanBudgets {
                max_items: 8,
                max_bytes: 1_024,
            });

        let execution = OrderedContentRuntime::execute_scan_misses(&mut source, page, &config)
            .expect("scan-miss execution succeeds");

        assert_eq!(execution.already_done_len(), 1);
        assert!(execution.deferred().is_empty());
        assert_eq!(execution.page_report().items_scanned, 3);
        assert_eq!(execution.outcomes().len(), 2);
        assert_eq!(
            execution.outcomes()[0].item().item_key().as_bytes(),
            b"secret.txt"
        );
        assert_eq!(
            execution.outcomes()[1].item().item_key().as_bytes(),
            b"clean.txt"
        );
        let OrderedContentItemOutcome::Scanned { findings } = execution.outcomes()[0].outcome()
        else {
            panic!("expected first item to scan successfully");
        };
        assert!(
            !findings.is_empty(),
            "custom rule should match the secret fixture"
        );
        let OrderedContentItemOutcome::Scanned { findings } = execution.outcomes()[1].outcome()
        else {
            panic!("expected second item to scan successfully");
        };
        assert!(findings.is_empty(), "clean content should stay clean");
        assert_eq!(execution.execution_report().items_scanned, 2);
        assert!(execution.execution_report().findings_emitted >= 1);
        assert_eq!(
            source.range_calls[0].max_bytes,
            secret.len() as u64,
            "per-item size_hint should become the connector byte budget"
        );
        assert_eq!(source.range_calls[0].max_items, 1);
        assert!(
            source.open_calls.is_empty(),
            "range-read path should not call open"
        );
    }

    #[test]
    fn execute_scan_misses_defers_suffix_when_item_limit_is_reached() {
        let rules = write_runtime_rules();
        let mut source = ContentSource::with_range_read();
        source.insert(b"a.txt", b"aaa");
        source.insert(b"b.txt", b"bbb");
        source.insert(b"c.txt", b"ccc");
        let page = prefiltered_page(
            vec![
                (
                    item(b"a.txt", 3),
                    OrderedContentPrefilterDisposition::ScanMiss,
                ),
                (
                    item(b"b.txt", 3),
                    OrderedContentPrefilterDisposition::ScanMiss,
                ),
                (
                    item(b"c.txt", 3),
                    OrderedContentPrefilterDisposition::ScanMiss,
                ),
            ],
            PageState::Complete,
        );
        let config = FsScanConfig::new("/tmp/ordered-content-test")
            .with_rules_file(Some(rules.path().to_path_buf()))
            .with_budgets(ScanBudgets {
                max_items: 2,
                max_bytes: 1_024,
            });

        let execution = OrderedContentRuntime::execute_scan_misses(&mut source, page, &config)
            .expect("scan-miss execution succeeds");

        assert_eq!(execution.outcomes().len(), 2);
        assert_eq!(execution.deferred().len(), 1);
        assert_eq!(execution.deferred()[0].item_key().as_bytes(), b"c.txt");
        let touched = source
            .range_calls
            .iter()
            .map(|call| call.item_ref.clone())
            .collect::<HashSet<_>>();
        assert!(touched.contains(b"a.txt".as_slice()));
        assert!(touched.contains(b"b.txt".as_slice()));
        assert!(!touched.contains(b"c.txt".as_slice()));
    }

    #[test]
    fn execute_scan_misses_skips_oversized_item_and_scans_smaller_items_behind_it() {
        let rules = write_runtime_rules();
        let mut source = ContentSource::with_range_read();
        source.insert(b"a.txt", b"aaa");
        source.insert(b"b.txt", b"bbbb");
        source.insert(b"c.txt", b"cc");
        let page = prefiltered_page(
            vec![
                (
                    item(b"a.txt", 3),
                    OrderedContentPrefilterDisposition::ScanMiss,
                ),
                (
                    item(b"b.txt", 4),
                    OrderedContentPrefilterDisposition::ScanMiss,
                ),
                (
                    item(b"c.txt", 2),
                    OrderedContentPrefilterDisposition::ScanMiss,
                ),
            ],
            PageState::Complete,
        );
        let config = FsScanConfig::new("/tmp/ordered-content-test")
            .with_rules_file(Some(rules.path().to_path_buf()))
            .with_budgets(ScanBudgets {
                max_items: 8,
                max_bytes: 5,
            });

        let execution = OrderedContentRuntime::execute_scan_misses(&mut source, page, &config)
            .expect("scan-miss execution succeeds");

        // a.txt (3 bytes) is admitted and scanned.
        // b.txt (4 bytes) exceeds remaining budget (5-3=2) — deferred, NOT
        // draining the entire suffix.
        // c.txt (2 bytes) fits remaining budget (2) — admitted and scanned.
        assert_eq!(execution.outcomes().len(), 2, "a.txt and c.txt are scanned");
        assert_eq!(
            execution.outcomes()[0].item().item_key().as_bytes(),
            b"a.txt"
        );
        assert_eq!(
            execution.outcomes()[1].item().item_key().as_bytes(),
            b"c.txt"
        );
        assert_eq!(execution.deferred().len(), 1, "only b.txt is deferred");
        assert_eq!(execution.deferred()[0].item_key().as_bytes(), b"b.txt");
        let touched = source
            .range_calls
            .iter()
            .map(|call| call.item_ref.clone())
            .collect::<HashSet<_>>();
        assert!(touched.contains(b"a.txt".as_slice()));
        assert!(
            !touched.contains(b"b.txt".as_slice()),
            "oversized item is not opened"
        );
        assert!(
            touched.contains(b"c.txt".as_slice()),
            "smaller item behind oversized is scanned"
        );
    }

    #[test]
    fn execute_scan_misses_counts_already_done_after_deferral_point() {
        let rules = write_runtime_rules();
        let mut source = ContentSource::with_range_read();
        source.insert(b"a.txt", b"aaa");
        source.insert(b"e.txt", b"ee");
        // Page: ScanMiss(a, fits), ScanMiss(b, over budget), AlreadyDone(c),
        // AlreadyDone(d), ScanMiss(e, fits remaining).
        // With skip-ahead admission: b.txt is deferred (oversized), then c/d
        // are counted as AlreadyDone, then e.txt fits the remaining budget.
        let page = prefiltered_page(
            vec![
                (
                    item(b"a.txt", 3),
                    OrderedContentPrefilterDisposition::ScanMiss,
                ),
                (
                    item(b"b.txt", 100),
                    OrderedContentPrefilterDisposition::ScanMiss,
                ),
                (
                    item(b"c.txt", 4),
                    OrderedContentPrefilterDisposition::AlreadyDone,
                ),
                (
                    item(b"d.txt", 5),
                    OrderedContentPrefilterDisposition::AlreadyDone,
                ),
                (
                    item(b"e.txt", 2),
                    OrderedContentPrefilterDisposition::ScanMiss,
                ),
            ],
            PageState::Complete,
        );
        let config = FsScanConfig::new("/tmp/ordered-content-test")
            .with_rules_file(Some(rules.path().to_path_buf()))
            .with_budgets(ScanBudgets {
                max_items: 8,
                max_bytes: 5,
            });

        let execution = OrderedContentRuntime::execute_scan_misses(&mut source, page, &config)
            .expect("scan-miss execution succeeds");

        // a.txt (3 bytes) scanned, b.txt deferred (oversized), e.txt (2 bytes)
        // scanned after skipping past the oversized item.
        assert_eq!(execution.outcomes().len(), 2, "a.txt and e.txt are scanned");
        assert_eq!(execution.deferred().len(), 1, "only b.txt is deferred");
        assert_eq!(execution.deferred()[0].item_key().as_bytes(), b"b.txt");
        assert_eq!(
            execution.already_done_len(),
            2,
            "c.txt and d.txt are counted as AlreadyDone"
        );
    }

    #[test]
    fn execute_scan_misses_preserves_retryable_and_permanent_range_read_errors() {
        let rules = write_runtime_rules();
        let mut source = ContentSource::with_range_read();
        source.insert(b"retry.txt", b"retry");
        source.insert(b"gone.txt", b"gone");
        source.insert(b"ok.txt", b"ok");
        source.set_range_error(b"retry.txt", 0, ReadError::rate_limited("slow down", 25));
        source.set_range_error(b"gone.txt", 0, ReadError::permanent("missing"));
        let page = prefiltered_page(
            vec![
                (
                    item(b"retry.txt", 5),
                    OrderedContentPrefilterDisposition::ScanMiss,
                ),
                (
                    item(b"gone.txt", 4),
                    OrderedContentPrefilterDisposition::ScanMiss,
                ),
                (
                    item(b"ok.txt", 2),
                    OrderedContentPrefilterDisposition::ScanMiss,
                ),
            ],
            PageState::Complete,
        );
        let config = FsScanConfig::new("/tmp/ordered-content-test")
            .with_rules_file(Some(rules.path().to_path_buf()))
            .with_budgets(ScanBudgets {
                max_items: 8,
                max_bytes: 1_024,
            });

        let execution = OrderedContentRuntime::execute_scan_misses(&mut source, page, &config)
            .expect("scan-miss execution succeeds");

        assert_eq!(execution.outcomes().len(), 3);
        let OrderedContentItemOutcome::Failed(stop) = execution.outcomes()[0].outcome() else {
            panic!("expected retryable failure");
        };
        assert_eq!(stop.class(), ErrorClass::Retryable);
        assert_eq!(stop.retry_after_ms(), Some(25));
        let OrderedContentItemOutcome::Failed(stop) = execution.outcomes()[1].outcome() else {
            panic!("expected permanent failure");
        };
        assert_eq!(stop.class(), ErrorClass::Permanent);
        assert_eq!(stop.retry_after_ms(), None);
        let OrderedContentItemOutcome::Scanned { findings } = execution.outcomes()[2].outcome()
        else {
            panic!("expected final item to scan successfully");
        };
        assert!(findings.is_empty());
        assert_eq!(execution.execution_report().errors, 2);
    }

    #[test]
    fn execute_scan_misses_uses_open_fallback_and_honors_binary_skip() {
        let rules = write_runtime_rules();
        let mut source = ContentSource::default();
        source.insert(b"binary.bin", b"\0BIN");
        source.set_open_error(b"denied.txt", ReadError::permanent("permission denied"));
        let page = prefiltered_page(
            vec![
                (
                    item(b"binary.bin", 4),
                    OrderedContentPrefilterDisposition::ScanMiss,
                ),
                (
                    item(b"denied.txt", 4),
                    OrderedContentPrefilterDisposition::ScanMiss,
                ),
            ],
            PageState::Complete,
        );
        let config = FsScanConfig::new("/tmp/ordered-content-test")
            .with_rules_file(Some(rules.path().to_path_buf()))
            .with_scan_binary(false)
            .with_budgets(ScanBudgets {
                max_items: 8,
                max_bytes: 1_024,
            });

        let execution = OrderedContentRuntime::execute_scan_misses(&mut source, page, &config)
            .expect("scan-miss execution succeeds");

        assert_eq!(execution.outcomes().len(), 2);
        assert_eq!(
            execution.outcomes()[0].outcome(),
            &OrderedContentItemOutcome::Skipped(OrderedContentSkipReason::Binary)
        );
        let OrderedContentItemOutcome::Failed(stop) = execution.outcomes()[1].outcome() else {
            panic!("expected open failure");
        };
        assert_eq!(stop.class(), ErrorClass::Permanent);
        assert_eq!(execution.execution_report().binary_skipped, 1);
        assert_eq!(execution.execution_report().errors, 1);
        assert_eq!(source.open_calls[0].max_bytes, 4);
        assert_eq!(source.open_calls[1].max_bytes, 4);
        assert!(
            source.range_calls.is_empty(),
            "open-fallback path should not call read_range"
        );
    }

    #[test]
    fn execute_scan_misses_admits_items_without_size_hint() {
        let rules = write_runtime_rules();
        let mut source = ContentSource::with_range_read();
        let content_a = b"prefix TOK_AAAAAAAA suffix";
        let content_b = b"prefix TOK_BBBBBBBB suffix";
        source.insert(b"no-hint-a.txt", content_a);
        source.insert(b"no-hint-b.txt", content_b);
        let page = prefiltered_page(
            vec![
                (
                    item_no_hint(b"no-hint-a.txt"),
                    OrderedContentPrefilterDisposition::ScanMiss,
                ),
                (
                    item_no_hint(b"no-hint-b.txt"),
                    OrderedContentPrefilterDisposition::ScanMiss,
                ),
            ],
            PageState::Complete,
        );
        let config = FsScanConfig::new("/tmp/ordered-content-test")
            .with_rules_file(Some(rules.path().to_path_buf()))
            .with_budgets(ScanBudgets {
                max_items: 8,
                max_bytes: 1_024,
            });

        let execution = OrderedContentRuntime::execute_scan_misses(&mut source, page, &config)
            .expect("scan-miss execution succeeds");

        assert!(
            execution.deferred().is_empty(),
            "both items should be admitted"
        );
        assert_eq!(execution.outcomes().len(), 2);
        let OrderedContentItemOutcome::Scanned { findings } = execution.outcomes()[0].outcome()
        else {
            panic!("expected first item scanned");
        };
        assert!(!findings.is_empty(), "rule should match TOK_AAAAAAAA");
        let OrderedContentItemOutcome::Scanned { findings } = execution.outcomes()[1].outcome()
        else {
            panic!("expected second item scanned");
        };
        assert!(!findings.is_empty(), "rule should match TOK_BBBBBBBB");
        assert_eq!(execution.execution_report().items_scanned, 2);
        // Without size_hint, item_byte_budget is min(DEFAULT_UNKNOWN_ITEM_BYTE_CAP,
        // remaining_bytes). Here 1_024 < 16 MiB, so remaining_bytes wins.
        assert_eq!(
            source.range_calls[0].max_bytes, 1_024,
            "capped budget still clamps to remaining_bytes when smaller"
        );
    }

    #[test]
    fn budget_exhaustion_before_eof_produces_truncated_outcome() {
        let rules = write_runtime_rules();
        let mut source = ContentSource::with_range_read();
        // Content is 100 bytes, but the page byte budget is only 32.
        // The item has no size_hint, so it is admitted with
        // item_byte_budget = remaining_bytes = 32. After reading 32 bytes
        // the budget is exhausted while the connector still has 68 bytes
        // remaining — the outcome must be Truncated, not Scanned.
        let content = vec![b'x'; 100];
        source.insert(b"big.txt", &content);
        let page = prefiltered_page(
            vec![(
                item_no_hint(b"big.txt"),
                OrderedContentPrefilterDisposition::ScanMiss,
            )],
            PageState::Complete,
        );
        let engine = build_runtime_engine(
            Some(rules.path()),
            &TransformFilter::default(),
            None,
            AnchorMode::default(),
        )
        .expect("engine builds");
        let execution = OrderedContentRuntime::execute_scan_misses_with_engine(
            &mut source,
            page,
            ScanBudgets {
                max_items: 8,
                max_bytes: 32,
            },
            false,
            engine,
            DEFAULT_ORDERED_CHUNK_SIZE,
        )
        .expect("execution succeeds");

        assert_eq!(execution.outcomes().len(), 1);
        assert!(
            matches!(
                execution.outcomes()[0].outcome(),
                OrderedContentItemOutcome::Truncated { .. }
            ),
            "budget-exhausted item must be Truncated, got {:?}",
            execution.outcomes()[0].outcome()
        );
    }

    #[test]
    fn unknown_size_item_is_capped_and_does_not_consume_entire_budget() {
        let rules = write_runtime_rules();
        let mut source = ContentSource::with_range_read();
        // Item a has no size_hint and is small — fits under the cap.
        // Item b has no size_hint and is small too.
        // With a large page budget (32 MiB) and two small no-hint items,
        // both should be admitted. The per-item connector budget must be
        // capped at DEFAULT_UNKNOWN_ITEM_BYTE_CAP (16 MiB), NOT the full
        // remaining page budget (32 MiB).
        let content_a = b"prefix TOK_AAAAAAAA suffix";
        let content_b = b"prefix TOK_BBBBBBBB suffix";
        source.insert(b"a.txt", content_a);
        source.insert(b"b.txt", content_b);
        let page = prefiltered_page(
            vec![
                (
                    item_no_hint(b"a.txt"),
                    OrderedContentPrefilterDisposition::ScanMiss,
                ),
                (
                    item_no_hint(b"b.txt"),
                    OrderedContentPrefilterDisposition::ScanMiss,
                ),
            ],
            PageState::Complete,
        );
        let config = FsScanConfig::new("/tmp/ordered-content-test")
            .with_rules_file(Some(rules.path().to_path_buf()))
            .with_budgets(ScanBudgets {
                max_items: 8,
                max_bytes: 32 * 1024 * 1024, // 32 MiB — well above the cap
            });

        let execution = OrderedContentRuntime::execute_scan_misses(&mut source, page, &config)
            .expect("scan-miss execution succeeds");

        assert_eq!(execution.outcomes().len(), 2, "both items admitted");
        assert!(execution.deferred().is_empty());

        // The connector byte budget for the first no-hint item must be
        // capped at DEFAULT_UNKNOWN_ITEM_BYTE_CAP, not the full 32 MiB
        // remaining budget.
        assert_eq!(
            source.range_calls[0].max_bytes,
            super::DEFAULT_UNKNOWN_ITEM_BYTE_CAP,
            "first no-hint item budget must be capped at DEFAULT_UNKNOWN_ITEM_BYTE_CAP"
        );
    }

    #[test]
    fn execute_scan_misses_deferred_suffix_excludes_already_done() {
        let rules = write_runtime_rules();
        let mut source = ContentSource::with_range_read();
        source.insert(b"a.txt", b"aaa");
        source.insert(b"c.txt", b"ccc");
        source.insert(b"e.txt", b"eee");
        // Pattern: ScanMiss, AlreadyDone, ScanMiss, AlreadyDone, ScanMiss
        // Budget: max_items=1 so only the first ScanMiss is scanned.
        let page = prefiltered_page(
            vec![
                (
                    item(b"a.txt", 3),
                    OrderedContentPrefilterDisposition::ScanMiss,
                ),
                (
                    item(b"b.txt", 3),
                    OrderedContentPrefilterDisposition::AlreadyDone,
                ),
                (
                    item(b"c.txt", 3),
                    OrderedContentPrefilterDisposition::ScanMiss,
                ),
                (
                    item(b"d.txt", 3),
                    OrderedContentPrefilterDisposition::AlreadyDone,
                ),
                (
                    item(b"e.txt", 3),
                    OrderedContentPrefilterDisposition::ScanMiss,
                ),
            ],
            PageState::Complete,
        );
        let config = FsScanConfig::new("/tmp/ordered-content-test")
            .with_rules_file(Some(rules.path().to_path_buf()))
            .with_budgets(ScanBudgets {
                max_items: 1,
                max_bytes: 1_024,
            });

        let execution = OrderedContentRuntime::execute_scan_misses(&mut source, page, &config)
            .expect("scan-miss execution succeeds");

        assert_eq!(execution.outcomes().len(), 1, "only first ScanMiss scanned");
        assert_eq!(
            execution.outcomes()[0].item().item_key().as_bytes(),
            b"a.txt"
        );
        // Deferred should contain only the remaining ScanMiss items, not AlreadyDone.
        assert_eq!(execution.deferred().len(), 2);
        assert_eq!(execution.deferred()[0].item_key().as_bytes(), b"c.txt");
        assert_eq!(execution.deferred()[1].item_key().as_bytes(), b"e.txt");
        // AlreadyDone count covers the full page: b.txt counted in the main
        // loop, d.txt counted during the post-budget-exhaustion drain.
        assert_eq!(execution.already_done_len(), 2);
    }

    #[test]
    fn execute_scan_misses_detects_token_across_chunk_boundary() {
        let rules = write_runtime_rules();
        let mut source = ContentSource::with_range_read();

        // Build content where the secret token straddles the chunk boundary.
        // With chunk_size=32, place the 16-byte token "TOK_CDEFGHIJ" so
        // its first half is at the end of chunk 1 and its second half at the
        // start of chunk 2. The overlap carry should allow the engine to
        // detect the full token across the boundary.
        let mut content = vec![b'x'; 24]; // 24 bytes of padding
        content.extend_from_slice(b"TOK_CDEFGHIJ"); // 12 bytes starting at offset 24
        content.extend_from_slice(&[b'y'; 20]); // tail padding, total 56 bytes
        source.insert(b"cross-chunk.txt", &content);

        let page = prefiltered_page(
            vec![(
                item(b"cross-chunk.txt", content.len() as u64),
                OrderedContentPrefilterDisposition::ScanMiss,
            )],
            PageState::Complete,
        );

        let engine = build_runtime_engine(
            Some(rules.path()),
            &TransformFilter::default(),
            None,
            AnchorMode::default(),
        )
        .expect("engine builds");
        let execution = OrderedContentRuntime::execute_scan_misses_with_engine(
            &mut source,
            page,
            ScanBudgets {
                max_items: 8,
                max_bytes: 1_024,
            },
            false,
            engine,
            32, // small chunk_size forces multi-chunk scanning
        )
        .expect("scan-miss execution succeeds");

        assert_eq!(execution.outcomes().len(), 1);
        let OrderedContentItemOutcome::Scanned { findings } = execution.outcomes()[0].outcome()
        else {
            panic!("expected item to scan successfully");
        };
        assert!(
            !findings.is_empty(),
            "token straddling chunk boundary should be detected via overlap carry"
        );
        assert!(
            execution.execution_report().chunks_scanned >= 2,
            "content should span at least 2 chunks with chunk_size=32"
        );
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
        let ledger = TrackingDoneLedger::empty();

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

    #[test]
    fn prefilter_treats_failed_retryable_as_scan_miss() {
        let items = vec![item(b"a.txt", 3), item(b"b.txt", 5), item(b"c.txt", 7)];

        // Item 0: ScannedClean    → AlreadyDone (terminal success)
        // Item 1: FailedRetryable → ScanMiss    (transient failure, must retry)
        // Item 2: absent          → ScanMiss    (never seen)
        let ledger = StatusAwareDoneLedger::new([
            (item_ovid(&items[0]), DoneLedgerStatus::ScannedClean),
            (item_ovid(&items[1]), DoneLedgerStatus::FailedRetryable),
        ]);
        let page = OrderedContentPage::from_validated_page(
            PageBuf::try_new(items, PageState::Complete).expect("page"),
        );

        let filtered = page
            .prefilter_done_ledger(write_context(), &ledger)
            .expect("prefilter succeeds");

        assert_eq!(
            filtered
                .items()
                .iter()
                .map(|ci| (ci.item().item_key().as_bytes().to_vec(), ci.disposition()))
                .collect::<Vec<_>>(),
            vec![
                (
                    b"a.txt".to_vec(),
                    OrderedContentPrefilterDisposition::AlreadyDone,
                ),
                (
                    b"b.txt".to_vec(),
                    OrderedContentPrefilterDisposition::ScanMiss,
                ),
                (
                    b"c.txt".to_vec(),
                    OrderedContentPrefilterDisposition::ScanMiss,
                ),
            ],
            "FailedRetryable done-ledger rows represent transient failures \
             and must be classified as ScanMiss so the item is retried"
        );
        assert_eq!(filtered.already_done_len(), 1);
        assert_eq!(filtered.scan_miss_len(), 2);
    }
}
