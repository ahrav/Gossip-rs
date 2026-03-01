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

use std::{env, io, thread, time::Duration};

use gossip_connectors::{InMemoryDeterministicConnector, MemItem};
use gossip_contracts::{
    connector::{Budgets, ItemKey},
    identity::ConnectorTag,
};
use gossip_coordination::{
    AcquireScratch, ClaimError, CursorSemantics, InMemoryCoordinator, InitialShardInput,
    LogicalTime, OpId, RunConfig, RunId, RunManagement, ShardClaiming, ShardId, ShardSpec,
    TenantId, WorkerId, WorkerSession,
};
use gossip_scan_pipeline::{
    DEFAULT_MAX_TRANSIENT_RETRIES, PageProcessingContext, PageProcessingError, ScanLoopOutcome,
    run_scan_loop, run_scan_loop_with_page_processor,
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
    /// Defaults to [`Direct`](Self::Direct) when the variable is absent.
    /// Returns `io::Error` for non-UTF-8 or unrecognized values.
    fn from_env() -> Result<Self, io::Error> {
        match env::var(SHARED_CORE_MODE_ENV) {
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

/// Owned snapshot of a single connector item, extracted from the borrowed
/// [`PageProcessingContext`] for use by the shared-core evaluator.
///
/// Each field mirrors a contract-level item property so that direct and
/// connector-fed code paths can be compared on identical inputs.
#[derive(Clone, Debug, PartialEq, Eq)]
struct SharedCoreItemInput {
    /// Opaque key that positions this item within its shard's key range.
    item_key: Vec<u8>,
    /// Provider-specific reference (e.g. object path, API cursor token).
    item_ref: Vec<u8>,
    /// Content-addressed identity (SHA-256) that survives renames and moves.
    stable_item_id: [u8; 32],
    /// Optional upstream size hint in bytes; `None` when the provider cannot
    /// report size without fetching the full object.
    size_hint: Option<u64>,
}

/// Owned snapshot of one page of connector results, ready for shared-core
/// evaluation.
///
/// A "page" is a single batch of items returned by the connector for a
/// shard.  The struct captures both the current and next cursor positions
/// so the evaluator can verify pagination continuity.
#[derive(Clone, Debug, PartialEq, Eq)]
struct SharedCorePageInput {
    /// Inclusive lower bound of the shard's key range.
    shard_start: Vec<u8>,
    /// Exclusive upper bound of the shard's key range.
    shard_end: Vec<u8>,
    /// Last-key component of the cursor *before* this page was fetched.
    cursor_last_key: Option<Vec<u8>>,
    /// Opaque token component of the cursor *before* this page was fetched.
    cursor_token: Option<Vec<u8>>,
    /// Last-key component of the cursor *after* this page (next page start).
    next_cursor_last_key: Option<Vec<u8>>,
    /// Opaque token component of the cursor *after* this page.
    next_cursor_token: Option<Vec<u8>>,
    /// Items returned on this page, in connector-provided order.
    items: Vec<SharedCoreItemInput>,
}

impl SharedCorePageInput {
    /// Materialize an owned page snapshot from the borrowed processing context.
    ///
    /// Allocates because the shared-core evaluators need to outlive the
    /// borrow scope of the scan-loop page callback.
    fn from_context(ctx: PageProcessingContext<'_>) -> Self {
        let items = ctx
            .items()
            .iter()
            .map(|item| SharedCoreItemInput {
                item_key: item.item_key().as_bytes().to_vec(),
                item_ref: item.item_ref().as_bytes().to_vec(),
                stable_item_id: *item.stable_item_id().as_bytes(),
                size_hint: item.size_hint(),
            })
            .collect();

        Self {
            shard_start: ctx.spec().key_range_start().to_vec(),
            shard_end: ctx.spec().key_range_end().to_vec(),
            cursor_last_key: ctx.cursor().last_key().map(|key| key.as_bytes().to_vec()),
            cursor_token: ctx.cursor().token().map(|tok| tok.as_bytes().to_vec()),
            next_cursor_last_key: ctx
                .next_cursor()
                .last_key()
                .map(|key| key.as_bytes().to_vec()),
            next_cursor_token: ctx.next_cursor().token().map(|tok| tok.as_bytes().to_vec()),
            items,
        }
    }
}

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

/// Adapter representing the scanner-rs direct shared-core surface.
///
/// Today both adapters delegate to the same deterministic evaluator.
/// They exist as separate functions so the shadow-mode comparison infra
/// is in place when the real direct and connector paths diverge.
fn run_direct_shared_core(input: &SharedCorePageInput) -> SharedCorePageOutput {
    evaluate_shared_core_page(input)
}

/// Adapter representing the connector-fed shared-core invocation.
///
/// See [`run_direct_shared_core`] for why this is a separate function.
fn run_connector_shared_core(input: &SharedCorePageInput) -> SharedCorePageOutput {
    evaluate_shared_core_page(input)
}

/// Deterministic stand-in for shared-core result identity used by shadow compare.
///
/// Produces an FNV-1a fingerprint over all contract-safe page identity and
/// item metadata. The hash is **order-sensitive**: shard boundaries, both
/// cursor positions, and then items are mixed in sequence. This catches
/// reordering bugs that a set-based comparison would miss.
///
/// FNV-1a was chosen because it is simple, non-cryptographic, and adequate
/// for equality testing in shadow mode. It is not used for security.
fn evaluate_shared_core_page(input: &SharedCorePageInput) -> SharedCorePageOutput {
    // FNV-1a 64-bit constants (http://www.isthe.com/chongo/tech/comp/fnv/).
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;

    #[inline]
    fn mix_byte(sig: &mut u64, byte: u8) {
        *sig ^= u64::from(byte);
        *sig = sig.wrapping_mul(FNV_PRIME);
    }

    #[inline]
    fn mix_u64(sig: &mut u64, value: u64) {
        for byte in value.to_le_bytes() {
            mix_byte(sig, byte);
        }
    }

    #[inline]
    fn mix_bytes(sig: &mut u64, bytes: &[u8]) {
        mix_u64(sig, bytes.len() as u64);
        for byte in bytes {
            mix_byte(sig, *byte);
        }
    }

    #[inline]
    fn mix_opt_bytes(sig: &mut u64, bytes: &Option<Vec<u8>>) {
        match bytes {
            Some(bytes) => {
                mix_byte(sig, 1);
                mix_bytes(sig, bytes);
            }
            None => mix_byte(sig, 0),
        }
    }

    let mut signature = FNV_OFFSET;
    mix_bytes(&mut signature, &input.shard_start);
    mix_bytes(&mut signature, &input.shard_end);
    mix_opt_bytes(&mut signature, &input.cursor_last_key);
    mix_opt_bytes(&mut signature, &input.cursor_token);
    mix_opt_bytes(&mut signature, &input.next_cursor_last_key);
    mix_opt_bytes(&mut signature, &input.next_cursor_token);

    for item in &input.items {
        mix_bytes(&mut signature, &item.item_key);
        mix_bytes(&mut signature, &item.item_ref);
        mix_bytes(&mut signature, &item.stable_item_id);
        mix_u64(&mut signature, item.size_hint.unwrap_or(u64::MAX));
    }

    SharedCorePageOutput {
        signature,
        item_count: input.items.len(),
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
    /// Returns `Err` on the first mismatch so the scan loop can surface it
    /// as a transient page-processing failure (retried up to the configured
    /// max).
    fn process_page(
        &mut self,
        context: PageProcessingContext<'_>,
    ) -> Result<(), PageProcessingError> {
        let input = SharedCorePageInput::from_context(context);

        let direct_start = std::time::Instant::now();
        let direct_output = run_direct_shared_core(&input);
        self.direct_elapsed += direct_start.elapsed();

        let connector_start = std::time::Instant::now();
        let connector_output = run_connector_shared_core(&input);
        self.connector_elapsed += connector_start.elapsed();

        self.pages_compared = self.pages_compared.saturating_add(1);
        self.items_compared = self
            .items_compared
            .saturating_add(direct_output.item_count as u64);

        if direct_output != connector_output {
            self.mismatches = self.mismatches.saturating_add(1);
            return Err(PageProcessingError::new(format!(
                "shadow mismatch on page {}: direct={:?} connector={:?}",
                context.page_num(),
                direct_output,
                connector_output
            )));
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
/// terminal outcome, and exits once no shard is available. Production workers
/// should replace this with persistent backends, long-lived scheduling, and
/// robust retry/backoff orchestration.
fn run_placeholder_worker() -> Result<(), Box<dyn std::error::Error>> {
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
                        return Err(Box::new(error));
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
            Err(error) => return Err(Box::new(error)),
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
        let input = SharedCorePageInput {
            shard_start: b"a".to_vec(),
            shard_end: b"z".to_vec(),
            cursor_last_key: Some(b"alpha".to_vec()),
            cursor_token: Some(b"tok-a".to_vec()),
            next_cursor_last_key: Some(b"bravo".to_vec()),
            next_cursor_token: Some(b"tok-b".to_vec()),
            items: vec![
                SharedCoreItemInput {
                    item_key: b"alpha".to_vec(),
                    item_ref: b"ref-alpha".to_vec(),
                    stable_item_id: [0x11; 32],
                    size_hint: Some(12),
                },
                SharedCoreItemInput {
                    item_key: b"bravo".to_vec(),
                    item_ref: b"ref-bravo".to_vec(),
                    stable_item_id: [0x22; 32],
                    size_hint: Some(18),
                },
            ],
        };

        let direct = run_direct_shared_core(&input);
        let connector = run_connector_shared_core(&input);
        assert_eq!(direct, connector);
        assert_eq!(direct.item_count, 2);
    }
}
