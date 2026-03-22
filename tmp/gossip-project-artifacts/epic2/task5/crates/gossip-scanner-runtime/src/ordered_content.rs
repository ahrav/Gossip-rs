//! Ordered-content (filesystem) runtime boundary.
//!
//! This module serves two roles:
//!
//! 1. The existing direct local-filesystem path built on
//!    [`parallel_scan_dir`], used by CLI scans and the current distributed
//!    receipt pipeline.
//! 2. The lease-aware ordered-page driver that will back the real
//!    ordered-content runtime for connector families such as filesystem.
//!
//! The page driver introduced here is intentionally narrow: it acquires pages
//! from an [`OrderedContentSource`], validates them defensively inside the
//! runtime, and hands each validated page to a caller-supplied callback. It
//! does **not** yet perform done-ledger prefiltering, byte reads, scan-miss
//! execution, or receipt-driven commit. Those remain later Epic 2 tasks.
//!
//! # Threading model for local filesystem scans
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
    connector::{Budgets, Cursor, ItemKey, PageBuf, PageState, ScanItem, validate_filled_page},
    connector::ordered::OrderedContentSource,
    coordination::ShardSpec,
};
use scanner_scheduler::events::EventOutput;
use scanner_scheduler::scheduler::parallel_scan::{ParallelScanConfig, parallel_scan_dir};

use crate::{
    AssignmentOutcome, COMMIT_CHANNEL_CAP, CancellationToken, ChannelEventOutput,
    ChannelStoreProducer, EVENT_CHANNEL_CAP, FsScanConfig, ScanReport, ScanRuntimeError,
    build_runtime_engine, forward_commits, forward_core_events, join_scoped,
};

/// Marker type for the ordered-content (filesystem) source family.
#[derive(Debug, Default)]
pub struct OrderedContentRuntime;

/// Lease/restore input for one ordered-content shard execution.
///
/// This packages the shard range together with the restored cursor state that
/// the runtime should resume from after lease acquisition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OrderedLeaseState {
    shard: ShardSpec,
    cursor: Cursor,
}

impl OrderedLeaseState {
    /// Start from the beginning of `shard` with an initial cursor.
    #[must_use]
    pub(crate) fn initial(shard: ShardSpec) -> Self {
        Self {
            shard,
            cursor: Cursor::initial(),
        }
    }

    /// Resume `shard` from a restored checkpoint cursor.
    #[must_use]
    pub(crate) fn restored(shard: ShardSpec, cursor: Cursor) -> Self {
        Self { shard, cursor }
    }

    #[inline]
    #[must_use]
    pub(crate) fn shard(&self) -> &ShardSpec {
        &self.shard
    }

    #[inline]
    #[must_use]
    pub(crate) fn cursor(&self) -> &Cursor {
        &self.cursor
    }
}

/// Lease-liveness check points around connector page acquisition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OrderedLeasePhase {
    /// Checked immediately before calling `fill_page`.
    BeforeFillPage,
    /// Checked immediately after `fill_page` returns and before the runtime
    /// consumes the result.
    AfterFillPage,
}

/// Lease guard used by the ordered-content runtime.
///
/// Ownership uncertainty must stop the shard quickly rather than risk overlap.
/// Callers that do not need lease checks can use [`NoopLeaseGuard`].
pub(crate) trait OrderedLeaseGuard {
    fn assert_active(&self, phase: OrderedLeasePhase) -> Result<(), ScanRuntimeError>;
}

/// Lease guard for local execution paths that do not have a coordination lease.
#[derive(Debug, Default)]
pub(crate) struct NoopLeaseGuard;

impl OrderedLeaseGuard for NoopLeaseGuard {
    #[inline]
    fn assert_active(&self, _phase: OrderedLeasePhase) -> Result<(), ScanRuntimeError> {
        Ok(())
    }
}

/// One validated page handed from the runtime to a downstream stage.
///
/// The runtime guarantees that `page` has already passed common page-shape
/// validation plus cursor-progression checks relative to `input_cursor`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OrderedPageBatch {
    input_cursor: Cursor,
    page: PageBuf<ScanItem>,
}

impl OrderedPageBatch {
    #[inline]
    #[must_use]
    pub(crate) fn new(input_cursor: Cursor, page: PageBuf<ScanItem>) -> Self {
        Self { input_cursor, page }
    }

    #[inline]
    #[must_use]
    pub(crate) fn input_cursor(&self) -> &Cursor {
        &self.input_cursor
    }

    #[inline]
    #[must_use]
    pub(crate) fn page(&self) -> &PageBuf<ScanItem> {
        &self.page
    }

    #[inline]
    #[must_use]
    pub(crate) fn items(&self) -> &[ScanItem] {
        self.page.items()
    }

    #[inline]
    #[must_use]
    pub(crate) fn state(&self) -> &PageState {
        self.page.state()
    }

    /// The last emitted key in the validated page.
    #[must_use]
    pub(crate) fn last_key(&self) -> &ItemKey {
        self.page
            .items()
            .last()
            .expect("runtime batches are constructed only from validated non-empty pages")
            .item_key()
    }

    /// Sum of page item size hints, saturating on overflow.
    #[must_use]
    pub(crate) fn enumerated_bytes(&self) -> u64 {
        self.page
            .items()
            .iter()
            .filter_map(ScanItem::size_hint)
            .fold(0u64, u64::saturating_add)
    }
}

/// Runtime counters from ordered page acquisition.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct OrderedPageStats {
    /// Number of validated non-empty pages emitted downstream.
    pub pages_filled: u64,
    /// Number of items carried across those pages.
    pub items_emitted: u64,
    /// Total page size-hint bytes observed.
    pub enumerated_bytes: u64,
    /// Number of terminal non-empty pages (`PageState::Complete`).
    pub complete_pages: u64,
}

enum OrderedPageDriverState {
    Active { cursor: Cursor },
    AwaitingExhaustion { cursor: Cursor },
    Exhausted,
}

impl OrderedContentRuntime {
    /// Execute one ordered-content source.
    ///
    /// The byte-read / scan / commit pipeline is not wired yet. Use
    /// [`drive_pages`](Self::drive_pages) for the runtime-side page acquisition
    /// and validation path added by this task.
    pub fn execute_source<S: OrderedContentSource>(
        _source: &mut S,
    ) -> Result<ScanReport, ScanRuntimeError> {
        Err(ScanRuntimeError::Driver(anyhow!(
            "ordered-content byte-read and scan execution for source '{}' is not implemented yet; use the page driver instead",
            std::any::type_name::<S>()
        )))
    }

    /// Acquire ordered pages from `source`, validate them inside the runtime,
    /// and hand each validated page to `on_page`.
    ///
    /// The driver performs one required exhausted-empty suffix call after a
    /// terminal non-empty page. This matches the connector family contract and
    /// prepares the runtime for later shard-completion and committed-prefix
    /// work.
    pub(crate) fn drive_pages<S, G, F>(
        source: &mut S,
        lease: &OrderedLeaseState,
        budgets: Budgets,
        guard: &G,
        cancel: &CancellationToken,
        mut on_page: F,
    ) -> Result<OrderedPageStats, ScanRuntimeError>
    where
        S: OrderedContentSource,
        G: OrderedLeaseGuard,
        F: FnMut(OrderedPageBatch) -> Result<(), ScanRuntimeError>,
    {
        let mut stats = OrderedPageStats::default();
        let mut state = OrderedPageDriverState::Active {
            cursor: lease.cursor().clone(),
        };

        loop {
            if cancel.is_cancelled() {
                return Ok(stats);
            }

            let input_cursor = match &state {
                OrderedPageDriverState::Active { cursor }
                | OrderedPageDriverState::AwaitingExhaustion { cursor } => cursor.clone(),
                OrderedPageDriverState::Exhausted => return Ok(stats),
            };

            guard.assert_active(OrderedLeasePhase::BeforeFillPage)?;
            let page = source
                .fill_page(lease.shard(), &input_cursor, budgets)
                .map_err(map_fill_page_error)?;
            guard.assert_active(OrderedLeasePhase::AfterFillPage)?;

            match (&state, page) {
                (_, None) => {
                    state = OrderedPageDriverState::Exhausted;
                    return Ok(stats);
                }
                (OrderedPageDriverState::AwaitingExhaustion { .. }, Some(_)) => {
                    return Err(ScanRuntimeError::Driver(anyhow!(
                        "ordered-content source emitted a non-empty page after reporting PageState::Complete"
                    )));
                }
                (OrderedPageDriverState::Active { .. }, Some(page)) => {
                    validate_runtime_page(lease.shard(), &input_cursor, &page)?;
                    let page_batch = OrderedPageBatch::new(input_cursor, page);
                    let next_state = match page_batch.state() {
                        PageState::HasMore { cursor } => OrderedPageDriverState::Active {
                            cursor: cursor.clone(),
                        },
                        PageState::Complete => OrderedPageDriverState::AwaitingExhaustion {
                            cursor: Cursor::with_last_key(page_batch.last_key().clone()),
                        },
                    };

                    let items_emitted = page_batch.items().len() as u64;
                    let enumerated_bytes = page_batch.enumerated_bytes();
                    let is_complete = page_batch.state().is_complete();

                    on_page(page_batch)?;

                    stats.pages_filled = stats.pages_filled.saturating_add(1);
                    stats.items_emitted = stats.items_emitted.saturating_add(items_emitted);
                    stats.enumerated_bytes =
                        stats.enumerated_bytes.saturating_add(enumerated_bytes);
                    if is_complete {
                        stats.complete_pages = stats.complete_pages.saturating_add(1);
                    }

                    state = next_state;
                }
                (OrderedPageDriverState::Exhausted, Some(_)) => {
                    unreachable!("exhausted state returns before calling fill_page");
                }
            }
        }
    }
}

fn map_fill_page_error(error: gossip_contracts::connector::EnumerateError) -> ScanRuntimeError {
    if error.is_retryable() {
        ScanRuntimeError::Driver(anyhow!("ordered-content fill_page retryable error: {error}"))
    } else {
        ScanRuntimeError::Driver(anyhow!("ordered-content fill_page permanent error: {error}"))
    }
}

fn validate_runtime_page(
    shard: &ShardSpec,
    input_cursor: &Cursor,
    page: &PageBuf<ScanItem>,
) -> Result<(), ScanRuntimeError> {
    validate_filled_page(page.items(), shard.key_range_start(), shard.key_range_end()).map_err(
        |error| ScanRuntimeError::Driver(anyhow!(
            "ordered-content fill_page produced an invalid page: {error}"
        )),
    )?;

    let first_key = page
        .items()
        .first()
        .expect("validated page must be non-empty")
        .item_key();
    if let Some(previous_last) = input_cursor.last_key()
        && first_key <= previous_last
    {
        return Err(ScanRuntimeError::Driver(anyhow!(
            "ordered-content page did not advance past the input cursor"
        )));
    }

    let last_key = page
        .items()
        .last()
        .expect("validated page must be non-empty")
        .item_key();

    if let PageState::HasMore { cursor } = page.state() {
        let Some(next_last) = cursor.last_key() else {
            return Err(ScanRuntimeError::Driver(anyhow!(
                "ordered-content resumable page omitted cursor.last_key"
            )));
        };
        if next_last != last_key {
            return Err(ScanRuntimeError::Driver(anyhow!(
                "ordered-content resume cursor last_key must equal the page's last emitted key"
            )));
        }
        if let Some(previous_last) = input_cursor.last_key()
            && next_last <= previous_last
        {
            return Err(ScanRuntimeError::Driver(anyhow!(
                "ordered-content resume cursor regressed relative to the input cursor"
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
            let store_producer = ChannelStoreProducer::try_new_with_identity(
                commit_tx.clone(),
                canonical_path.clone(),
                config.resolved_identity_scope(&canonical_path),
            )
            .map_err(ScanRuntimeError::Driver)?;
            scan_cfg.store_producer = Some(Arc::new(store_producer));
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
    use std::collections::VecDeque;
    use std::io;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use gossip_contracts::{
        connector::{EnumerateError, ItemRef, VersionId},
        coordination::ShardSpec,
        identity::{ObjectVersionId, StableItemId},
    };

    use super::*;

    #[cfg(test)]
    use gossip_connectors::FilesystemConnector;

    struct ScriptedSource {
        steps: VecDeque<Result<Option<PageBuf<ScanItem>>, EnumerateError>>,
        fill_calls: usize,
    }

    impl ScriptedSource {
        fn new(steps: Vec<Result<Option<PageBuf<ScanItem>>, EnumerateError>>) -> Self {
            Self {
                steps: VecDeque::from(steps),
                fill_calls: 0,
            }
        }
    }

    impl OrderedContentSource for ScriptedSource {
        fn capabilities(&self) -> gossip_contracts::connector::ordered::OrderedContentCapabilities {
            Default::default()
        }

        fn fill_page(
            &mut self,
            _shard: &ShardSpec,
            _cursor: &Cursor,
            _budgets: Budgets,
        ) -> Result<Option<PageBuf<ScanItem>>, EnumerateError> {
            self.fill_calls += 1;
            self.steps
                .pop_front()
                .expect("scripted source should have enough steps")
        }

        fn open(
            &mut self,
            _item_ref: &ItemRef,
            _budgets: Budgets,
        ) -> Result<Box<dyn io::Read + Send>, gossip_contracts::connector::ReadError> {
            unreachable!("open is not used in ordered page driver tests")
        }
    }

    #[derive(Default)]
    struct FailOnPhaseGuard {
        before_fill_failures: AtomicUsize,
        after_fill_failures: AtomicUsize,
    }

    impl FailOnPhaseGuard {
        fn fail_after_fill_once() -> Self {
            Self {
                before_fill_failures: AtomicUsize::new(0),
                after_fill_failures: AtomicUsize::new(1),
            }
        }
    }

    impl OrderedLeaseGuard for FailOnPhaseGuard {
        fn assert_active(&self, phase: OrderedLeasePhase) -> Result<(), ScanRuntimeError> {
            let failures = match phase {
                OrderedLeasePhase::BeforeFillPage => &self.before_fill_failures,
                OrderedLeasePhase::AfterFillPage => &self.after_fill_failures,
            };
            let remaining = failures.load(Ordering::Relaxed);
            if remaining == 0 {
                return Ok(());
            }
            failures.fetch_sub(1, Ordering::Relaxed);
            Err(ScanRuntimeError::Driver(anyhow!(
                "ordered-content lease became uncertain during {phase:?}"
            )))
        }
    }

    fn budgets() -> Budgets {
        Budgets::try_new(16, u64::MAX, None).expect("valid budgets")
    }

    fn scan_item(key: &[u8]) -> ScanItem {
        let item_key = gossip_contracts::connector::ItemKey::try_from_slice(key).unwrap();
        let item_ref = ItemRef::try_from_slice(key).unwrap();
        let stable_item_id = StableItemId::from_bytes([key[0]; 32]);
        let version = VersionId::Weak(ObjectVersionId::from_version_bytes(key));
        ScanItem::new(item_key, item_ref, stable_item_id, version)
            .with_size_hint(key.len() as u64)
    }

    fn unbounded_lease() -> OrderedLeaseState {
        OrderedLeaseState::initial(ShardSpec::unbounded())
    }

    #[test]
    fn drive_pages_drains_valid_pages_and_requires_exhausted_suffix() {
        let first = PageBuf::try_new_validated(
            vec![scan_item(b"a.txt")],
            PageState::HasMore {
                cursor: Cursor::with_last_key(gossip_contracts::connector::ItemKey::try_from_slice(b"a.txt").unwrap()),
            },
            b"",
            b"",
        )
        .expect("valid first page");
        let second = PageBuf::try_new_validated(
            vec![scan_item(b"b.txt")],
            PageState::Complete,
            b"",
            b"",
        )
        .expect("valid second page");
        let mut source = ScriptedSource::new(vec![Ok(Some(first)), Ok(Some(second)), Ok(None)]);
        let cancel = CancellationToken::new();
        let mut seen = Vec::new();

        let stats = OrderedContentRuntime::drive_pages(
            &mut source,
            &unbounded_lease(),
            budgets(),
            &NoopLeaseGuard,
            &cancel,
            |batch| {
                seen.extend(
                    batch
                        .items()
                        .iter()
                        .map(|item| item.item_key().as_bytes().to_vec()),
                );
                Ok(())
            },
        )
        .expect("page drain should succeed");

        assert_eq!(seen, vec![b"a.txt".to_vec(), b"b.txt".to_vec()]);
        assert_eq!(source.fill_calls, 3, "driver must perform the exhausted-empty suffix call");
        assert_eq!(
            stats,
            OrderedPageStats {
                pages_filled: 2,
                items_emitted: 2,
                enumerated_bytes: 10,
                complete_pages: 1,
            }
        );
    }

    #[test]
    fn drive_pages_rejects_has_more_without_cursor_last_key() {
        let invalid_page = PageBuf::try_new(
            vec![scan_item(b"a.txt")],
            PageState::HasMore {
                cursor: Cursor::initial(),
            },
        )
        .expect("non-empty page");
        let mut source = ScriptedSource::new(vec![Ok(Some(invalid_page))]);

        let error = OrderedContentRuntime::drive_pages(
            &mut source,
            &unbounded_lease(),
            budgets(),
            &NoopLeaseGuard,
            &CancellationToken::new(),
            |_batch| Ok(()),
        )
        .expect_err("missing cursor.last_key must fail");

        assert!(
            error
                .to_string()
                .contains("omitted cursor.last_key"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn drive_pages_rejects_page_shape_violations_in_runtime() {
        let invalid_page = PageBuf::try_new(
            vec![scan_item(b"b.txt"), scan_item(b"a.txt")],
            PageState::Complete,
        )
        .expect("non-empty page");
        let mut source = ScriptedSource::new(vec![Ok(Some(invalid_page))]);

        let error = OrderedContentRuntime::drive_pages(
            &mut source,
            &unbounded_lease(),
            budgets(),
            &NoopLeaseGuard,
            &CancellationToken::new(),
            |_batch| Ok(()),
        )
        .expect_err("unsorted page must be rejected by runtime validation");

        assert!(
            error.to_string().contains("invalid page"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn drive_pages_rejects_page_that_does_not_advance_past_cursor() {
        let stagnant_page = PageBuf::try_new(
            vec![scan_item(b"a.txt")],
            PageState::Complete,
        )
        .expect("non-empty page");
        let mut source = ScriptedSource::new(vec![Ok(Some(stagnant_page))]);
        let lease = OrderedLeaseState::restored(
            ShardSpec::unbounded(),
            Cursor::with_last_key(ItemKey::try_from_slice(b"a.txt").expect("valid key")),
        );

        let error = OrderedContentRuntime::drive_pages(
            &mut source,
            &lease,
            budgets(),
            &NoopLeaseGuard,
            &CancellationToken::new(),
            |_batch| Ok(()),
        )
        .expect_err("page that does not advance must fail");

        assert!(
            error.to_string().contains("did not advance past the input cursor"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn drive_pages_maps_retryable_fill_errors() {
        let mut source = ScriptedSource::new(vec![Err(EnumerateError::retryable("transient"))]);

        let error = OrderedContentRuntime::drive_pages(
            &mut source,
            &unbounded_lease(),
            budgets(),
            &NoopLeaseGuard,
            &CancellationToken::new(),
            |_batch| Ok(()),
        )
        .expect_err("retryable fill_page error must surface");

        assert!(
            error.to_string().contains("retryable error"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn drive_pages_stops_when_lease_becomes_uncertain_after_fill() {
        let page = PageBuf::try_new_validated(
            vec![scan_item(b"a.txt")],
            PageState::Complete,
            b"",
            b"",
        )
        .expect("valid page");
        let mut source = ScriptedSource::new(vec![Ok(Some(page))]);
        let guard = FailOnPhaseGuard::fail_after_fill_once();
        let mut callback_called = false;

        let error = OrderedContentRuntime::drive_pages(
            &mut source,
            &unbounded_lease(),
            budgets(),
            &guard,
            &CancellationToken::new(),
            |_batch| {
                callback_called = true;
                Ok(())
            },
        )
        .expect_err("lease loss must stop the page driver");

        assert!(!callback_called, "page must not be handed downstream after lease uncertainty");
        assert!(
            error.to_string().contains("lease became uncertain"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn drive_pages_rejects_non_empty_page_after_complete() {
        let terminal = PageBuf::try_new_validated(
            vec![scan_item(b"a.txt")],
            PageState::Complete,
            b"",
            b"",
        )
        .expect("valid terminal page");
        let extra = PageBuf::try_new_validated(
            vec![scan_item(b"b.txt")],
            PageState::Complete,
            b"",
            b"",
        )
        .expect("valid extra page");
        let mut source = ScriptedSource::new(vec![Ok(Some(terminal)), Ok(Some(extra))]);

        let error = OrderedContentRuntime::drive_pages(
            &mut source,
            &unbounded_lease(),
            budgets(),
            &NoopLeaseGuard,
            &CancellationToken::new(),
            |_batch| Ok(()),
        )
        .expect_err("extra non-empty page after terminal page must fail");

        assert!(
            error
                .to_string()
                .contains("non-empty page after reporting PageState::Complete"),
            "unexpected error: {error}"
        );
    }


    #[test]
    fn drive_pages_honors_restored_cursor_with_real_filesystem_connector() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("a.txt"), b"a").expect("write a");
        std::fs::write(dir.path().join("b.txt"), b"bb").expect("write b");
        let mut source = FilesystemConnector::new(dir.path());
        let mut seen = Vec::new();
        let restored = OrderedLeaseState::restored(
            ShardSpec::unbounded(),
            Cursor::with_last_key(gossip_contracts::connector::ItemKey::try_from_slice(b"a.txt").unwrap()),
        );

        let stats = OrderedContentRuntime::drive_pages(
            &mut source,
            &restored,
            budgets(),
            &NoopLeaseGuard,
            &CancellationToken::new(),
            |batch| {
                seen.extend(
                    batch
                        .items()
                        .iter()
                        .map(|item| item.item_key().as_bytes().to_vec()),
                );
                Ok(())
            },
        )
        .expect("restored filesystem connector page driver should succeed");

        assert_eq!(seen, vec![b"b.txt".to_vec()]);
        assert_eq!(stats.pages_filled, 1);
        assert_eq!(stats.items_emitted, 1);
        assert_eq!(stats.enumerated_bytes, 2);
        assert_eq!(stats.complete_pages, 1);
    }

    #[test]
    fn drive_pages_accepts_real_filesystem_connector_pages() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("a.txt"), b"a").expect("write a");
        std::fs::write(dir.path().join("b.txt"), b"bb").expect("write b");
        let mut source = FilesystemConnector::new(dir.path());
        let mut seen = Vec::new();

        let stats = OrderedContentRuntime::drive_pages(
            &mut source,
            &unbounded_lease(),
            budgets(),
            &NoopLeaseGuard,
            &CancellationToken::new(),
            |batch| {
                seen.extend(
                    batch
                        .items()
                        .iter()
                        .map(|item| item.item_key().as_bytes().to_vec()),
                );
                Ok(())
            },
        )
        .expect("filesystem connector page driver should succeed");

        assert_eq!(seen, vec![b"a.txt".to_vec(), b"b.txt".to_vec()]);
        assert_eq!(stats.pages_filled, 1);
        assert_eq!(stats.items_emitted, 2);
        assert_eq!(stats.enumerated_bytes, 3);
        assert_eq!(stats.complete_pages, 1);
    }
}
