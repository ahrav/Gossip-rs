//! Entry point for the gossip-worker binary.
//!
//! This binary wires together the coordination layer, connectors, scan
//! pipeline, and sinks into a running worker process.
//!
//! The current implementation intentionally uses in-memory placeholders so we
//! can validate runtime wiring end-to-end without production infrastructure.
//! The outer control loop demonstrates the contract shape:
//! `claim -> scan -> terminal outcome handling -> claim next`.

use std::{thread, time::Duration};

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
use gossip_scan_pipeline::{DEFAULT_MAX_TRANSIENT_RETRIES, ScanLoopOutcome, run_scan_loop};
use tracing_subscriber::EnvFilter;

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
    fn new(next_now: u64, next_op_id: u64) -> Self {
        Self {
            next_now,
            next_op_id,
        }
    }

    fn now(&mut self) -> LogicalTime {
        let now = LogicalTime::from_raw(self.next_now);
        self.next_now = self.next_now.saturating_add(1);
        now
    }

    fn op_id(&mut self) -> OpId {
        let op_id = OpId::from_raw(self.next_op_id);
        self.next_op_id = self.next_op_id.saturating_add(1);
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
                let next_op_id = &mut clock.next_op_id;
                let next_now = &mut clock.next_now;
                let outcome = run_scan_loop(
                    session,
                    &mut connector,
                    scan_budgets,
                    DEFAULT_MAX_TRANSIENT_RETRIES,
                    || {
                        let op_id = OpId::from_raw(*next_op_id);
                        *next_op_id = (*next_op_id).saturating_add(1);
                        op_id
                    },
                    || {
                        let now = LogicalTime::from_raw(*next_now);
                        *next_now = (*next_now).saturating_add(1);
                        now
                    },
                );

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
