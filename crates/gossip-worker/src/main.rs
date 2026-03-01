//! Entry point for the gossip-worker binary.
//!
//! This binary wires together the coordination layer, connectors, scan
//! pipeline, and scanner-core page processing into a running worker process.
//! The control loop follows the canonical claim-scan-resolve cycle:
//!
//! ```text
//! ┌─────────┐    ┌───────────┐    ┌─────────────────────┐
//! │  claim  │───▶│  scan     │───▶│  terminal outcome   │──┐
//! │  shard  │    │  pages    │    │  (complete/park/     │  │
//! └─────────┘    └───────────┘    │   lease-lost/error)  │  │
//!      ▲                          └─────────────────────┘  │
//!      └───────────────────────────────────────────────────┘
//! ```
//!
//! # Current limitations
//!
//! The implementation intentionally uses in-memory placeholders so we
//! can validate runtime wiring end-to-end without production infrastructure.
//! Production workers should replace these with persistent backends,
//! long-lived scheduling, and robust retry/backoff orchestration.

use std::{fmt, thread, time::Duration};

use gossip_connectors::{InMemoryDeterministicConnector, MemItem};
use gossip_contracts::{
    connector::{Budgets, ConnectorInputError, ItemKey},
    identity::ConnectorTag,
};
use gossip_coordination::{
    AcquireScratch, ClaimError, CreateRunError, CursorSemantics, InMemoryCoordinator,
    InitialShardInput, LogicalTime, OpId, RegisterShardsError, RunConfig, RunConfigError, RunId,
    RunManagement, ShardClaiming, ShardId, ShardSpec, TenantId, WorkerId, WorkerSession,
};
use gossip_engine::{
    PageScanContext, PageScanOutput, PageScanRequest, ScanDedupState, ScanDiagnostic, ScannerCore,
    ScannerCoreError,
};
use gossip_scan_pipeline::{
    DEFAULT_MAX_TRANSIENT_RETRIES, PageProcessingContext, PageProcessingError, ScanLoopError,
    ScanLoopOutcome, run_scan_loop_with_page_processor,
};
use tracing_subscriber::EnvFilter;

/// Concrete error type for the placeholder worker.
///
/// Each variant corresponds to a distinct failure class in the
/// claim → scan → resolve lifecycle so callers (and structured logs)
/// can distinguish setup and runtime failures.
#[derive(Debug)]
enum WorkerError {
    /// Run manifest setup failed (config validation, create, or register).
    Setup(String),
    /// Connector or budget wiring failed.
    Connector(ConnectorInputError),
    /// Shard claim failed with an unrecoverable error.
    Claim(ClaimError),
    /// The scan loop terminated with an error outcome.
    ScanLoop(Box<ScanLoopError>),
}

impl fmt::Display for WorkerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Setup(e) => write!(f, "run setup failed: {e}"),
            Self::Connector(e) => write!(f, "connector wiring failed: {e}"),
            Self::Claim(e) => write!(f, "claim failed: {e}"),
            Self::ScanLoop(e) => write!(f, "scan loop error: {}", e.as_ref()),
        }
    }
}

impl std::error::Error for WorkerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Setup(_) => None,
            Self::Connector(e) => Some(e),
            Self::Claim(e) => Some(e),
            Self::ScanLoop(e) => Some(e.as_ref()),
        }
    }
}

impl From<RunConfigError> for WorkerError {
    fn from(e: RunConfigError) -> Self {
        Self::Setup(e.to_string())
    }
}

impl From<CreateRunError> for WorkerError {
    fn from(e: CreateRunError) -> Self {
        Self::Setup(e.to_string())
    }
}

impl From<RegisterShardsError> for WorkerError {
    fn from(e: RegisterShardsError) -> Self {
        Self::Setup(e.to_string())
    }
}

impl From<ConnectorInputError> for WorkerError {
    fn from(e: ConnectorInputError) -> Self {
        Self::Connector(e)
    }
}

impl From<ScanLoopError> for WorkerError {
    fn from(e: ScanLoopError) -> Self {
        Self::ScanLoop(Box::new(e))
    }
}

/// Aggregate scanner-core stats across one shard scan-loop execution.
#[derive(Clone, Debug, Default)]
struct EngineScanStats {
    pages_scanned: u64,
    items_scanned: u64,
    findings_emitted: u64,
    diagnostics_emitted: u64,
}

impl EngineScanStats {
    fn record_page(&mut self, output: &PageScanOutput) {
        let stats = output.stats();
        self.pages_scanned = self.pages_scanned.saturating_add(stats.pages_scanned());
        self.items_scanned = self.items_scanned.saturating_add(stats.items_scanned());
        self.findings_emitted = self
            .findings_emitted
            .saturating_add(output.findings().len() as u64);
        self.diagnostics_emitted = self
            .diagnostics_emitted
            .saturating_add(output.diagnostics().len() as u64);
    }

    fn log_summary(&self) {
        tracing::info!(
            pages_scanned = self.pages_scanned,
            items_scanned = self.items_scanned,
            findings_emitted = self.findings_emitted,
            diagnostics_emitted = self.diagnostics_emitted,
            "scanner-core page processing summary",
        );
    }
}

fn scan_page_with_engine(
    scanner: &ScannerCore,
    dedupe: &mut ScanDedupState,
    context: PageProcessingContext<'_>,
) -> Result<PageScanOutput, ScannerCoreError> {
    let request = PageScanRequest::metadata_only(
        PageScanContext::new(
            context.spec().key_range_start(),
            context.spec().key_range_end(),
            context.cursor(),
            context.next_cursor(),
            context.page_num(),
        ),
        context.items(),
    );
    scanner.scan_page_with_dedupe(request, dedupe)
}

fn process_page_with_engine(
    scanner: &ScannerCore,
    dedupe: &mut ScanDedupState,
    stats: &mut EngineScanStats,
    context: PageProcessingContext<'_>,
) -> Result<(), PageProcessingError> {
    let output = scan_page_with_engine(scanner, dedupe, context).map_err(|error| {
        PageProcessingError::new(format!(
            "scanner core failed on page {}: {error}",
            context.page_num()
        ))
    })?;

    stats.record_page(&output);

    for finding in output.findings() {
        tracing::info!(
            page_num = finding.page_num(),
            item_index = finding.item_index(),
            fingerprint = finding.fingerprint(),
            payload_bytes = finding.payload_bytes(),
            stable_item_id = %finding.stable_item_id(),
            version = ?finding.version(),
            "scanner finding emitted",
        );
    }

    for diagnostic in output.diagnostics() {
        match diagnostic {
            ScanDiagnostic::MetadataOnlyInputs {
                page_num,
                item_count,
            } => tracing::debug!(
                page_num,
                item_count,
                "scanner-core received metadata-only page inputs"
            ),
            ScanDiagnostic::FindingsTruncated {
                page_num,
                max_findings_per_page,
                suppressed,
            } => tracing::warn!(
                page_num,
                max_findings_per_page,
                suppressed,
                "scanner-core findings truncated",
            ),
        }
    }

    Ok(())
}

/// Monotonic generators for logical time and operation IDs in the placeholder
/// worker binary.
///
/// Keeping both values explicit (rather than reading a wall clock/random source)
/// makes local runs easier to reason about and keeps behavior deterministic
/// under simulation-style test harnesses.
#[derive(Debug)]
struct WorkerClock {
    next_now: u64,
    next_op_id: u64,
}

impl WorkerClock {
    /// Create a clock starting at the given logical time and op-id seeds.
    fn new(next_now: u64, next_op_id: u64) -> Self {
        Self {
            next_now,
            next_op_id,
        }
    }

    /// Return the current logical time and advance the counter by one.
    ///
    /// Panics on overflow (would require 2^64 ticks).
    fn now(&mut self) -> LogicalTime {
        let now = LogicalTime::from_raw(self.next_now);
        self.next_now = self.next_now.checked_add(1).expect("now counter overflow");
        now
    }

    /// Return a fresh operation ID and advance the counter by one.
    ///
    /// Panics on overflow (would require 2^64 operations).
    fn op_id(&mut self) -> OpId {
        let op_id = OpId::from_raw(self.next_op_id);
        self.next_op_id = self
            .next_op_id
            .checked_add(1)
            .expect("op_id counter overflow");
        op_id
    }
}

/// Initialize process-level tracing from `RUST_LOG` (default `info`).
fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .init();
}

/// Run the current in-memory demonstration worker loop.
///
/// This function intentionally favors clarity over production concerns:
/// it seeds one run/shard in memory, repeatedly claims work, scans until a
/// terminal outcome, and exits once no shard is available.
fn run_placeholder_worker() -> Result<(), WorkerError> {
    let tenant = TenantId::from_bytes([0x21; 32]);
    let run = RunId::from_raw(1);
    let worker = WorkerId::from_raw(1);
    let mut clock = WorkerClock::new(1_000, 50_000);

    // Placeholder coordination backend and run manifest wiring.
    let mut coordinator = InMemoryCoordinator::new(60);
    coordinator.create_run(
        clock.now(),
        tenant,
        run,
        RunConfig::try_new(CursorSemantics::Completed, 60, None)?,
    )?;

    let spec = ShardSpec::with_range(b"a", b"z");
    let shards = [InitialShardInput::new(
        ShardId::from_raw(1),
        spec.as_ref(),
        gossip_coordination::CursorUpdate::initial(),
    )];
    let _ = coordinator.register_shards(clock.now(), tenant, run, &shards, clock.op_id())?;

    // Placeholder connector wiring.
    let mut connector = InMemoryDeterministicConnector::new(
        ConnectorTag::from_ascii(b"worker"),
        vec![
            MemItem::new(
                ItemKey::try_from_slice(b"alpha")?,
                b"payload-alpha".to_vec(),
            ),
            MemItem::new(
                ItemKey::try_from_slice(b"bravo")?,
                b"payload-bravo".to_vec(),
            ),
            MemItem::new(
                ItemKey::try_from_slice(b"charlie")?,
                b"payload-charlie".to_vec(),
            ),
        ],
    );

    // 2 items per page, 1 MB byte budget — small enough to exercise
    // multi-page cursor progression with the 3-item demo dataset.
    let scan_budgets = Budgets::try_new(2, 1_000_000, None)?;
    let mut claim_scratch = AcquireScratch::new();
    let scanner = ScannerCore::default();

    loop {
        let claim_now = clock.now();
        match coordinator.claim_next_available(claim_now, tenant, run, worker, &mut claim_scratch) {
            Ok(acquired) => {
                tracing::info!(
                    shard_key = ?acquired.lease.shard_key(),
                    available_shards = acquired.capacity.available_count,
                    "claimed shard",
                );

                let session = WorkerSession::from_acquire_result(&mut coordinator, acquired);
                let next_op_id = &mut clock.next_op_id;
                let next_now = &mut clock.next_now;
                let mut dedupe = ScanDedupState::default();
                let mut engine_stats = EngineScanStats::default();

                let outcome = run_scan_loop_with_page_processor(
                    session,
                    &mut connector,
                    scan_budgets,
                    DEFAULT_MAX_TRANSIENT_RETRIES,
                    || {
                        let op_id = OpId::from_raw(*next_op_id);
                        *next_op_id = (*next_op_id)
                            .checked_add(1)
                            .expect("op_id counter overflow");
                        op_id
                    },
                    || {
                        let now = LogicalTime::from_raw(*next_now);
                        *next_now = (*next_now).checked_add(1).expect("now counter overflow");
                        now
                    },
                    |context| {
                        process_page_with_engine(&scanner, &mut dedupe, &mut engine_stats, context)
                    },
                );
                engine_stats.log_summary();

                match outcome {
                    ScanLoopOutcome::Completed => {
                        tracing::info!("shard completed; claiming next shard");
                    }
                    ScanLoopOutcome::Parked {
                        reason,
                        retry_after_ms,
                    } => {
                        tracing::warn!(
                            reason = %reason,
                            retry_after_ms = ?retry_after_ms,
                            "shard parked; claiming next shard",
                        );
                    }
                    ScanLoopOutcome::LeaseLost {
                        pages_completed,
                        cause,
                    } => {
                        tracing::warn!(
                            pages_completed,
                            cause = %cause,
                            "lease lost; backing off before re-claim",
                        );
                        thread::sleep(Duration::from_millis(200));
                    }
                    ScanLoopOutcome::Error(error) => {
                        tracing::error!(error = %error, "scan loop failed");
                        return Err(WorkerError::ScanLoop(Box::new(error)));
                    }
                }
            }
            Err(ClaimError::NoneAvailable { earliest_deadline }) => {
                tracing::info!(
                    earliest_deadline = ?earliest_deadline,
                    "no shard available; sleeping then exiting placeholder worker",
                );
                // Placeholder behavior: exit after a short grace delay.
                // A production worker would usually keep polling or wait on
                // notifications instead of terminating here.
                thread::sleep(Duration::from_millis(200));
                break;
            }
            Err(ClaimError::Throttled { retry_after }) => {
                tracing::warn!(
                    retry_after = retry_after.as_raw(),
                    "claim throttled; backing off"
                );
                thread::sleep(Duration::from_millis(200));
            }
            Err(error) => return Err(WorkerError::Claim(error)),
        }
    }

    Ok(())
}

fn main() {
    init_tracing();
    let span = tracing::info_span!("gossip_worker");
    let _guard = span.enter();
    tracing::info!("gossip-worker starting");

    if let Err(error) = run_placeholder_worker() {
        tracing::error!(error = %error, "gossip-worker exiting with error");
        std::process::exit(1);
    }

    tracing::info!("gossip-worker finished");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_page_with_engine_emits_findings_and_diagnostics() {
        use gossip_contracts::connector::{Cursor, ItemRef, ScanItem, VersionId};
        use gossip_contracts::identity::{ObjectVersionId, StableItemId};

        let spec = ShardSpec::with_range(b"a", b"z");
        let cursor = Cursor::initial();
        let next_cursor = Cursor::with_last_key(ItemKey::try_from_slice(b"alpha").unwrap());
        let items = [ScanItem::new(
            ItemKey::try_from_slice(b"alpha").unwrap(),
            ItemRef::try_from_slice(b"ref-alpha").unwrap(),
            StableItemId::from_bytes([0x11; 32]),
            VersionId::Strong(ObjectVersionId::from_version_bytes(b"v1")),
        )];

        let ctx = PageProcessingContext::new(&spec, &cursor, &items, &next_cursor, 1, 0);
        let mut dedupe = ScanDedupState::default();
        let output = scan_page_with_engine(&ScannerCore::default(), &mut dedupe, ctx).unwrap();

        assert_eq!(output.summary().page_num(), 1);
        assert_eq!(output.summary().item_count(), 1);
        assert_eq!(output.findings().len(), 1);
        assert_eq!(output.diagnostics().len(), 1);
    }

    #[test]
    fn scan_page_with_engine_deduplicates_across_pages() {
        use gossip_contracts::connector::{Cursor, ItemRef, ScanItem, VersionId};
        use gossip_contracts::identity::{ObjectVersionId, StableItemId};

        let spec = ShardSpec::with_range(b"a", b"z");
        let item = ScanItem::new(
            ItemKey::try_from_slice(b"alpha").unwrap(),
            ItemRef::try_from_slice(b"ref-alpha").unwrap(),
            StableItemId::from_bytes([0x11; 32]),
            VersionId::Strong(ObjectVersionId::from_version_bytes(b"v1")),
        );

        let cursor1 = Cursor::initial();
        let next1 = Cursor::with_last_key(ItemKey::try_from_slice(b"alpha").unwrap());
        let page1 =
            PageProcessingContext::new(&spec, &cursor1, std::slice::from_ref(&item), &next1, 1, 0);

        let cursor2 = next1.clone();
        let next2 = Cursor::with_last_key(ItemKey::try_from_slice(b"alpha").unwrap());
        let page2 =
            PageProcessingContext::new(&spec, &cursor2, std::slice::from_ref(&item), &next2, 2, 1);

        let scanner = ScannerCore::default();
        let mut dedupe = ScanDedupState::default();
        let first = scan_page_with_engine(&scanner, &mut dedupe, page1).unwrap();
        let second = scan_page_with_engine(&scanner, &mut dedupe, page2).unwrap();

        assert_eq!(first.findings().len(), 1);
        assert_eq!(second.findings().len(), 0);
        assert_eq!(second.dedupe().duplicate_suppressed(), 1);
    }

    /// Compile-time integration guard: verifies that worker page contexts still
    /// map cleanly to scanner-core request types.
    #[test]
    fn worker_page_context_compiles_against_scanner_core_api() {
        use gossip_contracts::connector::{Cursor, ItemRef, ScanItem, VersionId};
        use gossip_contracts::identity::{ObjectVersionId, StableItemId};

        let spec = ShardSpec::with_range(b"a", b"z");
        let cursor = Cursor::initial();
        let next_cursor = Cursor::with_last_key(ItemKey::try_from_slice(b"alpha").unwrap());
        let items = [ScanItem::new(
            ItemKey::try_from_slice(b"alpha").unwrap(),
            ItemRef::try_from_slice(b"ref-alpha").unwrap(),
            StableItemId::from_bytes([0x11; 32]),
            VersionId::Strong(ObjectVersionId::from_version_bytes(b"v1")),
        )];

        let request = PageScanRequest::metadata_only(
            PageScanContext::new(
                spec.key_range_start(),
                spec.key_range_end(),
                &cursor,
                &next_cursor,
                1,
            ),
            &items,
        );
        let output = ScannerCore::default().scan_page(request).unwrap();
        assert_eq!(output.summary().item_count(), 1);
        assert_eq!(output.summary().page_num(), 1);
    }

    #[test]
    fn worker_error_display_includes_variant_context() {
        let err = WorkerError::Setup("run config invalid".to_string());
        assert!(err.to_string().contains("run setup failed"));

        let err = WorkerError::ScanLoop(Box::new(ScanLoopError::PageProcessing(
            PageProcessingError::new("scanner failed"),
        )));
        assert!(err.to_string().contains("scan loop error"));
    }
}
