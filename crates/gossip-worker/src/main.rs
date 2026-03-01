//! Entry point for the gossip-worker binary.
//!
//! This binary wires together the coordination layer, connectors, scan
//! pipeline, and sinks into a running worker process. The control loop
//! follows the canonical claim-scan-resolve cycle:
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
//! # Shared-core shadow mode
//!
//! The worker supports two page-processing modes, controlled by the
//! `GOSSIP_SHARED_CORE_MODE` environment variable:
//!
//! | Value      | Behavior |
//! |------------|----------|
//! | `direct`   | Default. No per-page hook — historical behavior. |
//! | `shadow`   | Runs both the direct and connector-fed shared-core |
//! |            | evaluators on every page and compares results, tracking |
//! |            | mismatch counts and relative latency. |
//!
//! Shadow mode exists to validate that the connector adapter produces
//! byte-identical results to the direct path before traffic is migrated.
//!
//! # Current limitations
//!
//! The implementation intentionally uses in-memory placeholders so we
//! can validate runtime wiring end-to-end without production infrastructure.
//! Production workers should replace these with persistent backends,
//! long-lived scheduling, and robust retry/backoff orchestration.

use std::{env, fmt, io, thread, time::Duration};

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
use gossip_scan_pipeline::{
    DEFAULT_MAX_TRANSIENT_RETRIES, PageProcessingContext, PageProcessingError, ScanLoopError,
    ScanLoopOutcome, run_scan_loop, run_scan_loop_with_page_processor,
};
use tracing_subscriber::EnvFilter;

const SHARED_CORE_MODE_ENV: &str = "GOSSIP_SHARED_CORE_MODE";
const SHARED_CORE_DIRECT: &str = "direct";
const SHARED_CORE_SHADOW: &str = "shadow";

/// Shared-core integration mode for page processing in the worker.
///
/// - `Direct`: preserve historical behavior (no page hook).
/// - `Shadow`: run direct and connector adapters side-by-side and compare outputs/perf.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SharedCoreMode {
    Direct,
    Shadow,
}

impl SharedCoreMode {
    /// Parse a mode string (case-insensitive, whitespace-trimmed).
    ///
    /// Returns `None` for unrecognized values so callers can produce
    /// context-rich error messages.
    fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            SHARED_CORE_DIRECT => Some(Self::Direct),
            SHARED_CORE_SHADOW => Some(Self::Shadow),
            _ => None,
        }
    }

    /// Read the shared-core mode from `GOSSIP_SHARED_CORE_MODE`.
    ///
    /// Defaults to [`Direct`](Self::Direct) when the variable is absent or
    /// contains only whitespace. Returns `io::Error` for non-UTF-8 or
    /// unrecognized values.
    fn from_env() -> Result<Self, io::Error> {
        match env::var(SHARED_CORE_MODE_ENV) {
            Ok(raw) if raw.trim().is_empty() => Ok(Self::Direct),
            Ok(raw) => Self::parse(&raw).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "invalid {SHARED_CORE_MODE_ENV}='{raw}' (expected '{SHARED_CORE_DIRECT}' or '{SHARED_CORE_SHADOW}')"
                    ),
                )
            }),
            Err(env::VarError::NotPresent) => Ok(Self::Direct),
            Err(env::VarError::NotUnicode(_)) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{SHARED_CORE_MODE_ENV} is not valid UTF-8"),
            )),
        }
    }

    /// Stable string representation for structured logging.
    fn as_str(self) -> &'static str {
        match self {
            Self::Direct => SHARED_CORE_DIRECT,
            Self::Shadow => SHARED_CORE_SHADOW,
        }
    }
}

/// Concrete error type for the placeholder worker.
///
/// Each variant corresponds to a distinct failure class in the
/// claim → scan → resolve lifecycle so callers (and structured logs)
/// can distinguish configuration problems from runtime failures.
#[derive(Debug)]
enum WorkerError {
    /// Environment configuration is invalid (e.g. unrecognized shared-core mode).
    Config(io::Error),
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
            Self::Config(e) => write!(f, "configuration error: {e}"),
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
            Self::Config(e) => Some(e),
            Self::Setup(_) => None,
            Self::Connector(e) => Some(e),
            Self::Claim(e) => Some(e),
            Self::ScanLoop(e) => Some(e.as_ref()),
        }
    }
}

impl From<io::Error> for WorkerError {
    fn from(e: io::Error) -> Self {
        Self::Config(e)
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

use gossip_stdx::{FNV_OFFSET, fnv_mix_byte, fnv_mix_bytes, fnv_mix_opt_bytes, fnv_mix_u64};

/// Result of evaluating one page through the shared-core path.
///
/// Two outputs are considered equivalent if and only if all fields match.
/// Shadow mode uses this equality to detect drift between the direct and
/// connector-fed evaluators.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SharedCorePageOutput {
    /// FNV-1a fingerprint over all contract-safe page identity and item
    /// metadata. Sensitive to field ordering — see [`evaluate_shared_core_page`].
    signature: u64,
    /// Number of items on this page (denormalized for logging convenience).
    item_count: usize,
}

/// Adapter representing the scanner-rs direct shared-core evaluation surface.
///
/// Today both adapters delegate to the same deterministic evaluator
/// ([`evaluate_shared_core_page`]). They exist as separate functions so
/// the shadow-mode comparison infrastructure is wired end-to-end *before*
/// the real direct and connector paths diverge. Once the connector adapter
/// begins producing results from a different code path, this separation
/// ensures the comparison hooks do not need structural changes.
///
/// Once the connector adapter begins surfacing per-item payload bytes,
/// these adapters should mix payload into the signature to converge
/// with the engine's `mix_page_item_signature` field set.
fn run_direct_shared_core(ctx: &PageProcessingContext<'_>) -> SharedCorePageOutput {
    evaluate_shared_core_page(ctx)
}

/// Adapter representing the connector-fed shared-core evaluation surface.
///
/// See [`run_direct_shared_core`] for why this is a separate function.
///
/// Once the connector adapter begins surfacing per-item payload bytes,
/// these adapters should mix payload into the signature to converge
/// with the engine's `mix_page_item_signature` field set.
fn run_connector_shared_core(ctx: &PageProcessingContext<'_>) -> SharedCorePageOutput {
    evaluate_shared_core_page(ctx)
}

/// Deterministic fingerprint over page identity for shadow-mode comparison.
///
/// Produces an FNV-1a fingerprint over all contract-safe page identity and
/// item metadata directly from the borrowed [`PageProcessingContext`],
/// without materializing any owned copies. The mixing order is:
///
/// 1. Page number (`page_num`)
/// 2. Shard key range boundaries (`key_range_start`, `key_range_end`)
/// 3. Current cursor position (`last_key`, `token`)
/// 4. Next cursor position (`last_key`, `token`)
/// 5. Items in iteration order (`item_key`, `item_ref`, `stable_item_id`,
///    `version` (domain-separated), `size_hint`)
///
/// This order is **position-sensitive**: reordering items produces a
/// different fingerprint, which catches ordering bugs that a set-based
/// comparison would miss.
///
/// # Payload exclusion (intentional divergence from gossip-engine)
///
/// Unlike the engine's `mix_page_item_signature`, this evaluator does **not**
/// mix `item_bytes` / payload content into the signature. The worker's shadow
/// mode compares structural metadata only because payload bytes are not
/// available in the `PageProcessingContext` at this layer. Once the connector
/// adapter surfaces per-item content, the field set should converge with the
/// engine.
fn evaluate_shared_core_page(ctx: &PageProcessingContext<'_>) -> SharedCorePageOutput {
    use gossip_contracts::connector::VersionId;

    let mut signature = FNV_OFFSET;
    fnv_mix_u64(&mut signature, ctx.page_num());
    fnv_mix_bytes(&mut signature, ctx.spec().key_range_start());
    fnv_mix_bytes(&mut signature, ctx.spec().key_range_end());
    fnv_mix_opt_bytes(
        &mut signature,
        ctx.cursor().last_key().map(|k| k.as_bytes()),
    );
    fnv_mix_opt_bytes(&mut signature, ctx.cursor().token().map(|t| t.as_bytes()));
    fnv_mix_opt_bytes(
        &mut signature,
        ctx.next_cursor().last_key().map(|k| k.as_bytes()),
    );
    fnv_mix_opt_bytes(
        &mut signature,
        ctx.next_cursor().token().map(|t| t.as_bytes()),
    );

    for item in ctx.items() {
        fnv_mix_bytes(&mut signature, item.item_key().as_bytes());
        fnv_mix_bytes(&mut signature, item.item_ref().as_bytes());
        fnv_mix_bytes(&mut signature, item.stable_item_id().as_bytes());
        match item.version() {
            VersionId::Strong(v) => {
                fnv_mix_byte(&mut signature, 1);
                fnv_mix_bytes(&mut signature, v.as_bytes());
            }
            VersionId::Weak(v) => {
                fnv_mix_byte(&mut signature, 2);
                fnv_mix_bytes(&mut signature, v.as_bytes());
            }
        }
        fnv_mix_u64(&mut signature, item.size_hint().unwrap_or(u64::MAX));
    }

    SharedCorePageOutput {
        signature,
        item_count: ctx.items().len(),
    }
}

/// Accumulator for shadow-mode comparison metrics across all pages in a
/// single shard scan.
///
/// Created at the start of each shard's scan loop (in shadow mode) and
/// logged via [`log_summary`](Self::log_summary) after the scan completes
/// or terminates. Mismatch counts and relative latencies let operators
/// decide when the connector path is safe to promote to primary.
#[derive(Clone, Debug, Default)]
struct ShadowComparisonStats {
    pages_compared: u64,
    items_compared: u64,
    /// Wall-clock time spent in the direct evaluator across all pages.
    direct_elapsed: Duration,
    /// Wall-clock time spent in the connector evaluator across all pages.
    connector_elapsed: Duration,
    mismatches: u64,
}

impl ShadowComparisonStats {
    /// Run both shared-core evaluators on `context` and record timing and
    /// equality results.
    ///
    /// Operates entirely on borrowed data from the [`PageProcessingContext`]
    /// — no heap allocations per page.
    ///
    /// Shadow mode is observational: mismatches are logged and counted but
    /// do not abort the scan. This keeps the scan progressing while
    /// operators monitor the mismatch rate to decide when the connector
    /// path is safe to promote.
    fn process_page(
        &mut self,
        context: PageProcessingContext<'_>,
    ) -> Result<(), PageProcessingError> {
        let direct_start = std::time::Instant::now();
        let direct_output = run_direct_shared_core(&context);
        self.direct_elapsed += direct_start.elapsed();

        let connector_start = std::time::Instant::now();
        let connector_output = run_connector_shared_core(&context);
        self.connector_elapsed += connector_start.elapsed();

        self.pages_compared = self.pages_compared.saturating_add(1);
        self.items_compared = self
            .items_compared
            .saturating_add(direct_output.item_count as u64);

        if direct_output != connector_output {
            self.mismatches = self.mismatches.saturating_add(1);
            tracing::warn!(
                page_num = context.page_num(),
                direct_sig = direct_output.signature,
                connector_sig = connector_output.signature,
                direct_items = direct_output.item_count,
                connector_items = connector_output.item_count,
                total_mismatches = self.mismatches,
                "shadow mismatch detected",
            );
        }

        Ok(())
    }

    /// Emit a structured `tracing::info` event with aggregate shadow stats.
    fn log_summary(&self) {
        tracing::info!(
            pages_compared = self.pages_compared,
            items_compared = self.items_compared,
            mismatches = self.mismatches,
            direct_ms = self.direct_elapsed.as_secs_f64() * 1000.0,
            connector_ms = self.connector_elapsed.as_secs_f64() * 1000.0,
            "shared-core shadow comparison summary",
        );
    }
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
///
/// The inner scan dispatch routes through [`SharedCoreMode`]: in `Direct`
/// mode the loop runs with a no-op page hook; in `Shadow` mode it attaches
/// a [`ShadowComparisonStats`] page processor that runs both evaluators and
/// logs aggregate mismatch/timing stats after each shard completes.
///
/// Production workers should replace the in-memory coordinator and connector
/// with persistent backends, long-lived scheduling, and robust retry/backoff
/// orchestration.
fn run_placeholder_worker() -> Result<(), WorkerError> {
    let tenant = TenantId::from_bytes([0x21; 32]);
    let run = RunId::from_raw(1);
    let worker = WorkerId::from_raw(1);
    let mut clock = WorkerClock::new(1_000, 50_000);
    let shared_core_mode = SharedCoreMode::from_env()?;
    tracing::info!(
        shared_core_mode = shared_core_mode.as_str(),
        env = SHARED_CORE_MODE_ENV,
        "starting placeholder worker",
    );

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
                // Feed the scan loop from the same monotonic sources used for
                // run setup/claiming so checkpoint and terminal op ordering is
                // easy to audit in logs.
                //
                // Field-level borrows (`&mut clock.next_op_id`, `&mut clock.next_now`)
                // are used instead of `clock.now()` / `clock.op_id()` because the
                // closures capture disjoint fields. `&mut clock` would conflict with
                // the `&mut coordinator` borrow held by `session`.
                let next_op_id = &mut clock.next_op_id;
                let next_now = &mut clock.next_now;
                let outcome = match shared_core_mode {
                    SharedCoreMode::Direct => run_scan_loop(
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
                    ),
                    SharedCoreMode::Shadow => {
                        let mut shadow_stats = ShadowComparisonStats::default();
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
                                *next_now =
                                    (*next_now).checked_add(1).expect("now counter overflow");
                                now
                            },
                            |context| shadow_stats.process_page(context),
                        );
                        shadow_stats.log_summary();
                        outcome
                    }
                };

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
    fn shared_core_mode_parse_accepts_supported_values() {
        assert_eq!(
            SharedCoreMode::parse("direct"),
            Some(SharedCoreMode::Direct)
        );
        assert_eq!(
            SharedCoreMode::parse("shadow"),
            Some(SharedCoreMode::Shadow)
        );
        assert_eq!(
            SharedCoreMode::parse("SHADOW"),
            Some(SharedCoreMode::Shadow)
        );
        assert_eq!(SharedCoreMode::parse("unknown"), None);
    }

    #[test]
    fn shared_core_evaluators_are_parity_stable() {
        use gossip_contracts::connector::{Cursor, ItemRef, ScanItem, TokenBytes, VersionId};
        use gossip_contracts::identity::{ObjectVersionId, StableItemId};

        let spec = ShardSpec::with_range(b"a", b"z");
        let cursor = Cursor::with_token(
            ItemKey::try_from_slice(b"alpha").unwrap(),
            TokenBytes::try_from_slice(b"tok-a").unwrap(),
        );
        let next_cursor = Cursor::with_token(
            ItemKey::try_from_slice(b"bravo").unwrap(),
            TokenBytes::try_from_slice(b"tok-b").unwrap(),
        );
        let items = [
            ScanItem::new(
                ItemKey::try_from_slice(b"alpha").unwrap(),
                ItemRef::try_from_slice(b"ref-alpha").unwrap(),
                StableItemId::from_bytes([0x11; 32]),
                VersionId::Strong(ObjectVersionId::from_version_bytes(b"v1")),
            )
            .with_size_hint(12),
            ScanItem::new(
                ItemKey::try_from_slice(b"bravo").unwrap(),
                ItemRef::try_from_slice(b"ref-bravo").unwrap(),
                StableItemId::from_bytes([0x22; 32]),
                VersionId::Strong(ObjectVersionId::from_version_bytes(b"v2")),
            )
            .with_size_hint(18),
        ];

        let ctx = PageProcessingContext::new(&spec, &cursor, &items, &next_cursor, 1, 0);
        let direct = run_direct_shared_core(&ctx);
        let connector = run_connector_shared_core(&ctx);
        assert_eq!(direct, connector);
        assert_eq!(direct.item_count, 2);
    }

    /// Compile-time integration guard: verifies that the worker's page context
    /// types (`ShardSpec`, `Cursor`, `ScanItem`) are ABI-compatible with the
    /// `gossip_engine::ScannerCore` API. If the engine crate changes its
    /// request types, this test fails at compile time rather than at runtime
    /// in shadow mode.
    #[test]
    fn worker_page_context_compiles_against_scanner_core_api() {
        use gossip_contracts::connector::{Cursor, ItemRef, ScanItem, VersionId};
        use gossip_contracts::identity::{ObjectVersionId, StableItemId};
        use gossip_engine::{PageScanContext, PageScanRequest, ScannerCore};

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
    fn evaluator_handles_empty_page() {
        use gossip_contracts::connector::Cursor;

        let spec = ShardSpec::with_range(b"a", b"z");
        let cursor = Cursor::initial();
        let items: [gossip_contracts::connector::ScanItem; 0] = [];
        let next_cursor = Cursor::initial();

        let ctx = PageProcessingContext::new(&spec, &cursor, &items, &next_cursor, 1, 0);
        let output = evaluate_shared_core_page(&ctx);
        assert_eq!(output.item_count, 0);
        // Signature should be deterministic even for empty pages.
        let output2 = evaluate_shared_core_page(&ctx);
        assert_eq!(output.signature, output2.signature);
    }

    #[test]
    fn evaluator_initial_cursor_all_none() {
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
        let output = evaluate_shared_core_page(&ctx);
        assert_eq!(output.item_count, 1);

        // Verify a different cursor produces a different hash.
        let cursor2 = Cursor::with_last_key(ItemKey::try_from_slice(b"other").unwrap());
        let ctx2 = PageProcessingContext::new(&spec, &cursor2, &items, &next_cursor, 1, 0);
        let output2 = evaluate_shared_core_page(&ctx2);
        assert_ne!(output.signature, output2.signature);
    }

    #[test]
    fn evaluator_is_order_sensitive() {
        use gossip_contracts::connector::{Cursor, ItemRef, ScanItem, VersionId};
        use gossip_contracts::identity::{ObjectVersionId, StableItemId};

        let spec = ShardSpec::with_range(b"a", b"z");
        let cursor = Cursor::initial();
        let next_cursor = Cursor::initial();

        let item_a = ScanItem::new(
            ItemKey::try_from_slice(b"alpha").unwrap(),
            ItemRef::try_from_slice(b"ref-a").unwrap(),
            StableItemId::from_bytes([0x11; 32]),
            VersionId::Strong(ObjectVersionId::from_version_bytes(b"v1")),
        );
        let item_b = ScanItem::new(
            ItemKey::try_from_slice(b"bravo").unwrap(),
            ItemRef::try_from_slice(b"ref-b").unwrap(),
            StableItemId::from_bytes([0x22; 32]),
            VersionId::Strong(ObjectVersionId::from_version_bytes(b"v2")),
        );

        let forward = [item_a.clone(), item_b.clone()];
        let reversed = [item_b, item_a];

        let ctx_fwd = PageProcessingContext::new(&spec, &cursor, &forward, &next_cursor, 1, 0);
        let ctx_rev = PageProcessingContext::new(&spec, &cursor, &reversed, &next_cursor, 1, 0);
        assert_ne!(
            evaluate_shared_core_page(&ctx_fwd).signature,
            evaluate_shared_core_page(&ctx_rev).signature,
            "different item order must produce different signatures",
        );
    }

    #[test]
    fn shadow_stats_accumulate_across_pages() {
        use gossip_contracts::connector::{Cursor, ItemRef, ScanItem, VersionId};
        use gossip_contracts::identity::{ObjectVersionId, StableItemId};

        let spec = ShardSpec::with_range(b"a", b"z");
        let cursor = Cursor::initial();
        let next_cursor = Cursor::initial();
        let items = [ScanItem::new(
            ItemKey::try_from_slice(b"alpha").unwrap(),
            ItemRef::try_from_slice(b"ref-alpha").unwrap(),
            StableItemId::from_bytes([0x11; 32]),
            VersionId::Strong(ObjectVersionId::from_version_bytes(b"v1")),
        )];

        let mut stats = ShadowComparisonStats::default();
        for page_num in 1..=5 {
            let ctx = PageProcessingContext::new(&spec, &cursor, &items, &next_cursor, page_num, 0);
            assert!(stats.process_page(ctx).is_ok());
        }
        assert_eq!(stats.pages_compared, 5);
        assert_eq!(stats.items_compared, 5);
        assert_eq!(stats.mismatches, 0);
        assert!(stats.direct_elapsed > Duration::ZERO || stats.connector_elapsed > Duration::ZERO);
    }

    #[test]
    fn shared_core_mode_parse_whitespace_only_is_none() {
        assert_eq!(SharedCoreMode::parse(""), None);
        assert_eq!(SharedCoreMode::parse("   "), None);
    }

    #[test]
    fn shared_core_mode_as_str_round_trips() {
        assert_eq!(
            SharedCoreMode::parse(SharedCoreMode::Direct.as_str()),
            Some(SharedCoreMode::Direct),
        );
        assert_eq!(
            SharedCoreMode::parse(SharedCoreMode::Shadow.as_str()),
            Some(SharedCoreMode::Shadow),
        );
    }

    #[test]
    fn worker_error_display_includes_variant_context() {
        let err = WorkerError::Config(io::Error::new(io::ErrorKind::InvalidInput, "bad mode"));
        assert!(err.to_string().contains("configuration error"));
        assert!(err.to_string().contains("bad mode"));

        let err = WorkerError::Setup("run config invalid".to_string());
        assert!(err.to_string().contains("run setup failed"));
    }
}
