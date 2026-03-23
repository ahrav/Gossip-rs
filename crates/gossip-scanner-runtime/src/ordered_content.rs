//! Ordered-content runtime boundary.
//!
//! This module owns two related filesystem execution paths:
//!
//! 1. `OrderedContentRuntime::execute_source`, which performs one
//!    connector-driven ordered page acquisition and validates the page against
//!    the shard/cursor contract before any downstream read or scan work uses it.
//! 2. `scan_local_filesystem`, which runs the existing direct scheduler-based
//!    local filesystem scan and forwards events and persistence batches through
//!    bounded channels.
//!
//! The connector-facing entrypoint is intentionally narrower than the direct
//! scan path. It validates authoritative shard bounds, resume cursor progress,
//! and enumerate error classification without yet taking ownership of
//! item-open, byte-read, findings, or durability orchestration.
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

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::sync_channel;

use anyhow::anyhow;
use gossip_contracts::{
    connector::{
        Budgets, Cursor, EnumerateError, ErrorClass, PageBuf, PageState, ScanItem,
        ordered::OrderedContentSource, validate_filled_page,
    },
    coordination::{CursorSemantics, RestoredShardState, ShardSpec},
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrderedContentRuntimeInput {
    state: RestoredShardState,
    budgets: Budgets,
}

impl OrderedContentRuntimeInput {
    /// Construct one ordered-content execution input bundle.
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
/// This preserves the connector's retry posture and advisory backoff hint
/// without forcing callers to parse the connector message text.
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
        let resume_cursor = match page.state() {
            PageState::HasMore { cursor } => cursor.clone(),
            PageState::Complete => {
                let last_key = page
                    .items()
                    .last()
                    .expect("validated page is non-empty")
                    .item_key()
                    .clone();
                Cursor::with_last_key(last_key)
            }
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
    /// - progress monotonicity relative to the restored resume cursor; and
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

/// Validate three page-level invariants after a successful `fill_page`:
///
/// 1. **Shape** — page is non-empty, keys are in-bounds, and strictly increasing.
/// 2. **Monotonicity** — the first emitted key is strictly after the restored
///    resume cursor's `last_key`, preventing duplicate processing on resume.
/// 3. **Cursor agreement** — a `HasMore` cursor's `last_key` matches the page's
///    final emitted key, so the next `fill_page` call starts from the right point.
fn validate_page_contract(
    input: &OrderedContentRuntimeInput,
    page: &PageBuf<ScanItem>,
) -> Result<(), ScanRuntimeError> {
    validate_filled_page(
        page.items(),
        input.shard().key_range_start(),
        input.shard().key_range_end(),
    )
    .map_err(|error| {
        ScanRuntimeError::Driver(anyhow!(
            "ordered-content page for shard [{:?}, {:?}) violated the page contract: {error}",
            input.shard().key_range_start(),
            input.shard().key_range_end(),
        ))
    })?;

    let first_key = page
        .items()
        .first()
        .expect("validated page is non-empty")
        .item_key();
    if let Some(previous_last) = input.cursor().last_key()
        && first_key <= previous_last
    {
        return Err(ScanRuntimeError::Driver(anyhow!(
            "ordered-content page did not advance past the restored resume cursor",
        )));
    }

    let last_key = page
        .items()
        .last()
        .expect("validated page is non-empty")
        .item_key();
    if let PageState::HasMore { cursor } = page.state() {
        let Some(next_last) = cursor.last_key() else {
            return Err(ScanRuntimeError::Driver(anyhow!(
                "ordered-content resumable page omitted the authoritative last_key",
            )));
        };
        if next_last != last_key {
            return Err(ScanRuntimeError::Driver(anyhow!(
                "ordered-content resumable page returned a cursor that does not match the page's last emitted key",
            )));
        }
    }

    Ok(())
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
/// its commit-sink adapter.
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

    use gossip_contracts::{
        connector::{ItemKey, ItemRef, TokenBytes, VersionId},
        identity::{ObjectVersionId, StableItemId},
    };

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
                .contains("did not advance past the restored resume cursor"),
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
                .contains("omitted the authoritative last_key"),
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
                .contains("cursor that does not match the page's last emitted key"),
            "unexpected error: {err}"
        );
    }
}
