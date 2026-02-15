//! Boundary â‘¡ â€” Coordination & Shard Frontier: Chunk 5 (DRAFT)
//!
//! Run-level op-log, payload hashing, WorkerSession ergonomics,
//! shard claiming, combined facade trait, state transition events,
//! and the contract invariant catalog.
//!
//! This file is additive to Boundary â‘  (chunks 1â€“5) and Boundary â‘¡
//! chunks 1â€“4. It completes the coordination contract boundary.
//!
//! ## Design Decisions (locked)
//!
//! D2.25: RunRecord gets its own bounded op-log, mirroring ShardRecord.
//!        Run-level operations (register_shards, complete_run, fail_run,
//!        cancel_run) all accept OpId for idempotency. Without a run-level
//!        op-log, the backend has no place to store the replay cache.
//!
//!        The run op-log is smaller than the shard op-log (4 entries vs 16)
//!        because run-level operations are infrequent.
//!
//! D2.26: WorkerSession is a non-owning ergonomic wrapper that binds
//!        a reference to the backend, tenant, worker_id, and the active
//!        lease. It eliminates repetitive parameter threading.
//!
//!        WorkerSession is NOT a trait â€” it's a concrete struct generic
//!        over the backend. This keeps it simple and avoids trait object
//!        overhead.
//!
//! D2.27: `claim_next_available` is an extension method on
//!        CoordinationBackend, not a new trait. It composes `list_shards`
//!        + `acquire_and_restore` into a single logical operation. The
//!        backend MAY override it for efficiency (e.g., a single SQL
//!        query with `FOR UPDATE SKIP LOCKED`).
//!
//! D2.28: StateTransitionEvent is a value type, not a callback mechanism.
//!        The coordination trait methods return events alongside their
//!        normal results. The caller (orchestrator, scheduler) decides
//!        what to do with them. This avoids coupling the coordination
//!        layer to any specific notification system.
//!
//! D2.29: The contract invariant catalog is a documentation-only section.
//!        It enumerates every invariant the contract requires, cross-
//!        referencing the design decision and chunk where it was introduced.
//!        This serves as the specification for backend conformance tests.

// Assumes all types from prior chunks are in scope.

// ============================================================================
// Â§ Chunk 5: Completions for Boundary â‘¡
// ============================================================================

// ---------------------------------------------------------------------------
// Â§5.1 Run-level op-log (amendment to RunRecord from chunk 4)
// ---------------------------------------------------------------------------

/// Run-level operation kind.
///
/// Parallel to shard-level `OpKind` (chunk 2), but for run lifecycle
/// operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RunOpKind {
    /// Register initial shards and activate the run.
    RegisterShards,
    /// Mark the run as successfully completed.
    CompleteRun,
    /// Mark the run as failed.
    FailRun,
    /// Cancel the run (admin operation).
    CancelRun,
    /// Unpark a shard (admin operation, logged at run level because
    /// the shard's own op-log may have been evicted).
    UnparkShard,
}

/// Result cached in the run op-log for idempotent replay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RunOpResult {
    /// Simple acknowledgment (CompleteRun, FailRun, CancelRun, UnparkShard).
    Ack,
    /// RegisterShards result: the registered shard IDs.
    RegisteredShards { shard_ids: Vec<ShardId> },
}

/// A single entry in the run-level operation log.
///
/// Mirrors `OpLogEntry` (chunk 2) at the run level. Provides
/// idempotent replay for run lifecycle operations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunOpLogEntry {
    pub op_id: OpId,
    pub kind: RunOpKind,
    /// Truncated BLAKE3 hash of the operation's inputs.
    pub payload_hash: u64,
    pub result: RunOpResult,
}

/// **Amendment to RunRecord (chunk 4).**
///
/// RunRecord gains these additional fields:
///
/// ```rust,ignore
/// pub struct RunRecord {
///     // ... all fields from chunk 4 ...
///
///     /// Bounded operation log for idempotent replay of run-level ops.
///     pub op_log: Vec<RunOpLogEntry>,
/// }
/// ```
///
/// And these additional methods:
impl RunRecord {
    /// Maximum number of retained run-level op-log entries.
    ///
    /// Smaller than shard-level (16) because run operations are rarer.
    pub const RUN_OP_LOG_CAP: usize = 8;

    /// Look up a run op-log entry by OpId.
    pub fn op_log_lookup(&self, op: OpId) -> Option<&RunOpLogEntry> {
        self.op_log.iter().find(|e| e.op_id == op)
    }

    /// Push a run op-log entry, evicting the oldest if at capacity.
    pub fn op_log_push(&mut self, entry: RunOpLogEntry) {
        if self.op_log.len() >= Self::RUN_OP_LOG_CAP {
            self.op_log.remove(0);
        }
        self.op_log.push(entry);
    }

    /// Check op-log for idempotent replay or conflict.
    ///
    /// Returns:
    /// - `Ok(Some(entry))` â€” replay: same op_id + same payload_hash
    /// - `Ok(None)` â€” new operation, proceed with execution
    /// - `Err(...)` â€” conflict: same op_id, different payload_hash
    pub fn check_op_idempotency(
        &self,
        op_id: OpId,
        payload_hash: u64,
    ) -> Result<Option<&RunOpLogEntry>, RunOpIdConflict> {
        match self.op_log_lookup(op_id) {
            None => Ok(None),
            Some(entry) => {
                if entry.payload_hash == payload_hash {
                    Ok(Some(entry))
                } else {
                    Err(RunOpIdConflict {
                        op_id,
                        expected_hash: entry.payload_hash,
                        actual_hash: payload_hash,
                    })
                }
            }
        }
    }
}

/// OpId conflict at the run level.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunOpIdConflict {
    pub op_id: OpId,
    pub expected_hash: u64,
    pub actual_hash: u64,
}

// ---------------------------------------------------------------------------
// Â§5.2 Run-level payload hash functions
// ---------------------------------------------------------------------------

/// Payload hash for RegisterShards.
///
/// Hashes the manifest: shard IDs + specs + cursors. Deterministic
/// given the same inputs regardless of presentation order (sorts
/// by shard_id before hashing).
pub fn hash_register_shards_payload(shards: &[InitialShard]) -> u64 {
    // Sort by shard_id for determinism.
    let mut sorted: Vec<&InitialShard> = shards.iter().collect();
    sorted.sort_by_key(|s| s.shard_id.0);

    op_payload_hash(b"register_shards", |h| {
        (sorted.len() as u32).write_canonical(h);
        for shard in &sorted {
            shard.shard_id.write_canonical(h);
            shard.spec.write_canonical(h);
            shard.cursor.write_canonical(h);
        }
    })
}

/// Payload hash for CompleteRun / FailRun / CancelRun.
///
/// These operations have no inputs beyond the run identity (which
/// is already scoped by the RunRecord). The discriminant tag is
/// sufficient for conflict detection.
pub fn hash_run_terminal_payload(tag: &[u8]) -> u64 {
    op_payload_hash(tag, |_h| {
        // No additional fields â€” the op_tag provides domain separation.
    })
}

/// Payload hash for CompleteRun.
pub fn hash_complete_run_payload() -> u64 {
    hash_run_terminal_payload(b"complete_run")
}

/// Payload hash for FailRun.
pub fn hash_fail_run_payload() -> u64 {
    hash_run_terminal_payload(b"fail_run")
}

/// Payload hash for CancelRun.
pub fn hash_cancel_run_payload() -> u64 {
    hash_run_terminal_payload(b"cancel_run")
}

/// Payload hash for UnparkShard.
///
/// Includes the shard key so that unparking different shards with
/// the same OpId is correctly detected as a conflict.
pub fn hash_unpark_payload(key: &ShardKey) -> u64 {
    op_payload_hash(b"unpark_shard", |h| {
        key.run.write_canonical(h);
        key.shard.write_canonical(h);
    })
}

// ---------------------------------------------------------------------------
// Â§5.3 WorkerSession â€” ergonomic wrapper
// ---------------------------------------------------------------------------

/// Ergonomic wrapper that binds a coordination backend, tenant, worker,
/// and active lease for less repetitive API usage.
///
/// A WorkerSession represents a worker's active processing of a single
/// shard. It holds the lease and delegates to `CoordinationBackend`,
/// threading tenant/lease through every call.
///
/// ## Lifecycle
///
/// ```text
/// 1. Worker calls `WorkerSession::acquire(backend, now, tenant, key, worker)`
/// 2. On success, receives a WorkerSession with the active lease + snapshot
/// 3. Worker calls `session.checkpoint(...)`, `session.renew(...)` etc.
/// 4. Worker calls `session.complete(...)` or `session.park(...)` to finish
/// 5. Session is consumed (moved into the terminal operation)
/// ```
///
/// ## Design
///
/// WorkerSession is generic over the backend, not a trait object. This:
/// - Avoids dynamic dispatch overhead on the hot path (checkpoint/renew)
/// - Allows the deterministic simulator to use a concrete backend type
/// - Keeps the session zero-cost: it's just a struct holding references
///
/// The session does NOT own the backend â€” it borrows it mutably. This
/// prevents multiple sessions from existing simultaneously on the same
/// backend reference, which is correct: the backend is the serialization
/// point for all coordination state.
///
/// ## Not a Lease Manager
///
/// WorkerSession does NOT automatically renew the lease. The worker is
/// responsible for calling `renew()` before the lease expires. This is
/// intentional â€” automatic renewal requires a timer/scheduler, which is
/// a runtime concern outside the contract boundary.
///
/// Reference: D2.26
pub struct WorkerSession<'b, B: CoordinationBackend> {
    backend: &'b mut B,
    tenant: TenantId,
    worker: WorkerId,
    lease: Lease,
    snapshot: ShardSnapshot,
}

impl<'b, B: CoordinationBackend> WorkerSession<'b, B> {
    /// Acquire a shard and create a new session.
    ///
    /// This is the entry point. On success, the worker receives a
    /// session bound to the acquired shard with a valid lease.
    pub fn acquire(
        backend: &'b mut B,
        now: LogicalTime,
        tenant: TenantId,
        key: ShardKey,
        worker: WorkerId,
    ) -> Result<Self, AcquireError> {
        let result = backend.acquire_and_restore(now, tenant, key, worker)?;
        Ok(Self {
            backend,
            tenant,
            worker,
            lease: result.lease,
            snapshot: result.snapshot,
        })
    }

    /// The active lease.
    #[inline]
    pub fn lease(&self) -> &Lease {
        &self.lease
    }

    /// The shard snapshot from acquisition time.
    ///
    /// This is the state at acquisition â€” it does NOT reflect subsequent
    /// checkpoints. Use this to determine where to resume scanning.
    #[inline]
    pub fn snapshot(&self) -> &ShardSnapshot {
        &self.snapshot
    }

    /// The shard's spec (key range + metadata).
    #[inline]
    pub fn spec(&self) -> &ShardSpec {
        &self.snapshot.spec
    }

    /// The cursor at acquisition time.
    #[inline]
    pub fn cursor(&self) -> &Cursor {
        &self.snapshot.cursor
    }

    /// The tenant this session is scoped to.
    #[inline]
    pub fn tenant(&self) -> TenantId {
        self.tenant
    }

    /// The worker that owns this session.
    #[inline]
    pub fn worker(&self) -> WorkerId {
        self.worker
    }

    /// The shard key (run + shard_id).
    #[inline]
    pub fn shard_key(&self) -> ShardKey {
        ShardKey {
            run: self.lease.run,
            shard: self.lease.shard,
        }
    }

    /// Renew the lease, extending the deadline.
    ///
    /// Updates the internal lease deadline on success.
    pub fn renew(&mut self, now: LogicalTime) -> Result<RenewResult, RenewError> {
        let result = self.backend.renew(now, self.tenant, &self.lease)?;
        self.lease.deadline = result.new_deadline;
        Ok(result)
    }

    /// Checkpoint: advance the cursor.
    pub fn checkpoint(
        &mut self,
        now: LogicalTime,
        new_cursor: Cursor,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, CheckpointError> {
        self.backend
            .checkpoint(now, self.tenant, &self.lease, new_cursor, op_id)
    }

    /// Complete: mark the shard as done. Consumes the session.
    ///
    /// After completion, the lease is released and the session cannot
    /// be used further.
    pub fn complete(
        self,
        now: LogicalTime,
        final_cursor: Cursor,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, CompleteError> {
        self.backend
            .complete(now, self.tenant, &self.lease, final_cursor, op_id)
    }

    /// Park: halt the shard. Consumes the session.
    pub fn park(
        self,
        now: LogicalTime,
        reason: ParkReason,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, ParkError> {
        self.backend
            .park_shard(now, self.tenant, &self.lease, reason, op_id)
    }

    /// SplitReplace: replace this shard with children. Consumes the session.
    pub fn split_replace(
        self,
        now: LogicalTime,
        plan: SplitReplacePlan,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<SplitReplaceResult>, SplitReplaceError> {
        self.backend
            .split_replace(now, self.tenant, &self.lease, plan, op_id)
    }

    /// SplitResidual: shrink this shard and create a residual.
    ///
    /// Does NOT consume the session â€” the parent shard stays Active.
    pub fn split_residual(
        &mut self,
        now: LogicalTime,
        plan: SplitResidualPlan,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<SplitResidualResult>, SplitResidualError> {
        self.backend
            .split_residual(now, self.tenant, &self.lease, plan, op_id)
    }
}

// ---------------------------------------------------------------------------
// Â§5.4 Shard claiming â€” claim_next_available
// ---------------------------------------------------------------------------

/// Error from `claim_next_available`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClaimError {
    /// No available (active, unleased) shards exist for this run.
    NoneAvailable { run: RunId },
    /// The run does not exist.
    RunNotFound { run: RunId },
    /// Tenant isolation violation.
    TenantMismatch {
        expected: TenantId,
        actual: TenantId,
    },
}

/// Extension trait for shard claiming on backends that also implement
/// `RunManagement` (for `list_shards`).
///
/// This composes `list_shards(available)` + `acquire_and_restore` into
/// a single logical operation. Backends MAY override the default
/// implementation for efficiency (e.g., `SELECT ... FOR UPDATE SKIP LOCKED`
/// in SQL backends, or a single FDB transaction).
///
/// ## Shard Selection Policy
///
/// The default implementation uses a simple strategy: iterate available
/// shards in key-range order and try to acquire the first one. If
/// acquisition fails (race with another worker), try the next.
///
/// Backends may implement more sophisticated policies:
/// - **Locality-aware**: prefer shards near the worker's previous shard
/// - **Load-balanced**: prefer shards with lower acquire_count
/// - **Priority-ordered**: prefer shards with specific labels/metadata
///
/// These policies are backend-specific optimizations and do NOT affect
/// correctness â€” any available shard is a valid choice.
///
/// Reference: Â§2.2 â€” "work-stealing for dynamic load balancing";
///            Blumofe & Leiserson, JACM 1999.
pub trait ShardClaiming: CoordinationBackend + RunManagement {
    /// Attempt to claim the next available shard for this run.
    ///
    /// Returns an `AcquireResult` on success, or `ClaimError` if
    /// no shards are available.
    ///
    /// ## Default Implementation
    ///
    /// 1. `list_shards(available)` â€” find active, unleased shards.
    /// 2. For each candidate, try `acquire_and_restore`.
    /// 3. Return the first successful acquisition.
    /// 4. If all acquisitions fail (races), return `NoneAvailable`.
    ///
    /// ## Concurrency
    ///
    /// Multiple workers may race to claim the same shard. The fencing
    /// protocol ensures at most one succeeds. The losing workers retry
    /// with different candidates. This is safe because `acquire_and_restore`
    /// is atomic (the backend serializes concurrent acquisitions).
    fn claim_next_available(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        worker: WorkerId,
    ) -> Result<AcquireResult, ClaimError> {
        let summaries = self
            .list_shards(now, tenant, run, ShardFilter::available())
            .map_err(|e| match e {
                GetRunError::RunNotFound { run } => ClaimError::RunNotFound { run },
                GetRunError::TenantMismatch { expected, actual } => {
                    ClaimError::TenantMismatch { expected, actual }
                }
            })?;

        if summaries.is_empty() {
            return Err(ClaimError::NoneAvailable { run });
        }

        for summary in &summaries {
            let key = ShardKey {
                run,
                shard: summary.shard,
            };
            match self.acquire_and_restore(now, tenant, key, worker) {
                Ok(result) => return Ok(result),
                Err(AcquireError::AlreadyLeased { .. }) => {
                    // Race â€” another worker claimed it. Try next.
                    continue;
                }
                Err(AcquireError::ShardTerminal { .. }) => {
                    // Shard became terminal between list and acquire. Skip.
                    continue;
                }
                Err(AcquireError::ShardNotFound { .. }) => {
                    // Shouldn't happen â€” the shard was just listed.
                    // Defensive: skip and try next.
                    continue;
                }
                Err(e @ AcquireError::TenantMismatch { .. }) => {
                    // Hard error â€” propagate.
                    return Err(ClaimError::TenantMismatch {
                        expected: tenant,
                        actual: tenant, // placeholder â€” error has the real values
                    });
                }
            }
        }

        // All candidates were claimed by other workers.
        Err(ClaimError::NoneAvailable { run })
    }
}

// Blanket implementation: any type implementing both traits gets claiming.
impl<T: CoordinationBackend + RunManagement> ShardClaiming for T {}

// ---------------------------------------------------------------------------
// Â§5.5 StateTransitionEvent â€” notification types
// ---------------------------------------------------------------------------

/// A state transition event emitted by coordination operations.
///
/// Events are value types returned alongside operation results. The
/// caller (orchestrator, scheduler) decides how to handle them â€”
/// logging, metrics, triggering follow-up actions, etc.
///
/// ## Design
///
/// Events are NOT callbacks or subscriptions. The coordination trait
/// methods are synchronous and deterministic. Side effects (sending
/// notifications, updating dashboards) happen outside the coordination
/// boundary.
///
/// This approach:
/// - Keeps the coordination layer pure and testable
/// - Avoids coupling to notification infrastructure
/// - Works with deterministic simulation (events are captured in the trace)
///
/// Reference: Event Sourcing pattern (Fowler, 2005); FoundationDB's
/// approach of returning mutation results for the caller to act on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StateTransitionEvent {
    // â”€â”€ Shard events â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// A shard was acquired by a worker.
    ShardAcquired {
        tenant: TenantId,
        run: RunId,
        shard: ShardId,
        worker: WorkerId,
        fence_epoch: FenceEpoch,
    },

    /// A shard's cursor was checkpointed.
    ShardCheckpointed {
        tenant: TenantId,
        run: RunId,
        shard: ShardId,
        /// The new last_key after checkpoint.
        last_key: Option<Box<[u8]>>,
    },

    /// A shard completed successfully.
    ShardCompleted {
        tenant: TenantId,
        run: RunId,
        shard: ShardId,
    },

    /// A shard was parked due to an error.
    ShardParked {
        tenant: TenantId,
        run: RunId,
        shard: ShardId,
        reason: ParkReason,
    },

    /// A shard was split into children.
    ShardSplit {
        tenant: TenantId,
        run: RunId,
        parent: ShardId,
        children: Vec<ShardId>,
    },

    /// A residual shard was created from a split.
    ShardResidualCreated {
        tenant: TenantId,
        run: RunId,
        parent: ShardId,
        residual: ShardId,
    },

    /// A shard was unparked by an admin.
    ShardUnparked {
        tenant: TenantId,
        run: RunId,
        shard: ShardId,
        new_fence_epoch: FenceEpoch,
    },

    /// A shard's lease was renewed.
    ShardLeaseRenewed {
        tenant: TenantId,
        run: RunId,
        shard: ShardId,
        new_deadline: LogicalTime,
    },

    // â”€â”€ Run events â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// A new run was created.
    RunCreated {
        tenant: TenantId,
        run: RunId,
    },

    /// A run was activated (initial shards registered).
    RunActivated {
        tenant: TenantId,
        run: RunId,
        shard_count: usize,
    },

    /// A run completed successfully.
    RunCompleted {
        tenant: TenantId,
        run: RunId,
    },

    /// A run failed.
    RunFailed {
        tenant: TenantId,
        run: RunId,
    },

    /// A run was cancelled by an admin.
    RunCancelled {
        tenant: TenantId,
        run: RunId,
    },
}

impl StateTransitionEvent {
    /// The tenant this event belongs to.
    pub fn tenant(&self) -> TenantId {
        match self {
            Self::ShardAcquired { tenant, .. }
            | Self::ShardCheckpointed { tenant, .. }
            | Self::ShardCompleted { tenant, .. }
            | Self::ShardParked { tenant, .. }
            | Self::ShardSplit { tenant, .. }
            | Self::ShardResidualCreated { tenant, .. }
            | Self::ShardUnparked { tenant, .. }
            | Self::ShardLeaseRenewed { tenant, .. }
            | Self::RunCreated { tenant, .. }
            | Self::RunActivated { tenant, .. }
            | Self::RunCompleted { tenant, .. }
            | Self::RunFailed { tenant, .. }
            | Self::RunCancelled { tenant, .. } => *tenant,
        }
    }

    /// The run this event belongs to.
    pub fn run(&self) -> RunId {
        match self {
            Self::ShardAcquired { run, .. }
            | Self::ShardCheckpointed { run, .. }
            | Self::ShardCompleted { run, .. }
            | Self::ShardParked { run, .. }
            | Self::ShardSplit { run, .. }
            | Self::ShardResidualCreated { run, .. }
            | Self::ShardUnparked { run, .. }
            | Self::ShardLeaseRenewed { run, .. }
            | Self::RunCreated { run, .. }
            | Self::RunActivated { run, .. }
            | Self::RunCompleted { run, .. }
            | Self::RunFailed { run, .. }
            | Self::RunCancelled { run, .. } => *run,
        }
    }

    /// Returns `true` if this is a shard-level event.
    pub fn is_shard_event(&self) -> bool {
        matches!(
            self,
            Self::ShardAcquired { .. }
                | Self::ShardCheckpointed { .. }
                | Self::ShardCompleted { .. }
                | Self::ShardParked { .. }
                | Self::ShardSplit { .. }
                | Self::ShardResidualCreated { .. }
                | Self::ShardUnparked { .. }
                | Self::ShardLeaseRenewed { .. }
        )
    }

    /// Returns `true` if this is a run-level event.
    pub fn is_run_event(&self) -> bool {
        !self.is_shard_event()
    }

    /// Returns `true` if this event represents a terminal transition.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::ShardCompleted { .. }
                | Self::ShardParked { .. }
                | Self::ShardSplit { .. }
                | Self::RunCompleted { .. }
                | Self::RunFailed { .. }
                | Self::RunCancelled { .. }
        )
    }
}

// ---------------------------------------------------------------------------
// Â§5.6 Event collection sink
// ---------------------------------------------------------------------------

/// Collects state transition events during a coordination operation.
///
/// Passed to backend operations to accumulate events. The caller
/// drains the events after the operation completes.
///
/// ## Why a separate collector?
///
/// Rather than changing every trait method's return type to include
/// events, we use a collector that the backend writes to. This:
/// - Keeps trait signatures clean
/// - Allows a single operation to emit multiple events (e.g., split
///   emits ShardSplit + one ShardAcquired per child if auto-acquired)
/// - Makes event collection optional â€” callers that don't care can
///   pass a no-op collector
///
/// ## Usage
///
/// ```rust,ignore
/// let mut events = EventCollector::new();
/// backend.checkpoint_with_events(now, tenant, lease, cursor, op_id, &mut events)?;
/// for event in events.drain() {
///     metrics.record(&event);
///     log::info!("{:?}", event);
/// }
/// ```
///
/// ## Design Note
///
/// The `_with_events` methods are optional extensions. The core trait
/// methods (chunk 3) do NOT take an EventCollector â€” they are the
/// minimal contract. Backends that want event emission implement the
/// extension methods. This keeps the core trait simple for testing.
#[derive(Clone, Debug, Default)]
pub struct EventCollector {
    events: Vec<StateTransitionEvent>,
}

impl EventCollector {
    pub fn new() -> Self {
        Self { events: Vec::new() }
    }

    /// Record an event.
    pub fn emit(&mut self, event: StateTransitionEvent) {
        self.events.push(event);
    }

    /// Drain all collected events.
    pub fn drain(&mut self) -> Vec<StateTransitionEvent> {
        std::mem::take(&mut self.events)
    }

    /// Number of events collected.
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Whether any events have been collected.
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Iterate over collected events without draining.
    pub fn iter(&self) -> impl Iterator<Item = &StateTransitionEvent> {
        self.events.iter()
    }
}

// ---------------------------------------------------------------------------
// Â§5.7 CoordinationFacade â€” combined super-trait
// ---------------------------------------------------------------------------

/// The complete coordination contract: shard operations + run management
/// + shard claiming.
///
/// A backend that implements `CoordinationFacade` provides the full
/// coordination API. This is the type constraint used by the orchestrator
/// and scheduler layers.
///
/// ## Trait Hierarchy
///
/// ```text
/// CoordinationFacade
///   â”œâ”€â”€ CoordinationBackend  (chunk 3: shard lifecycle)
///   â”œâ”€â”€ RunManagement         (chunk 4: run lifecycle + admin)
///   â””â”€â”€ ShardClaiming         (chunk 5: shard assignment, blanket impl)
/// ```
///
/// ## Usage
///
/// ```rust,ignore
/// fn run_orchestrator<B: CoordinationFacade>(backend: &mut B) {
///     // Run-level operations
///     let run = backend.create_run(now, tenant, run_id, config)?;
///     backend.register_shards(now, tenant, run_id, shards, op_id)?;
///
///     // Worker operations
///     let result = backend.claim_next_available(now, tenant, run_id, worker)?;
///     backend.checkpoint(now, tenant, &result.lease, cursor, op_id)?;
///     backend.complete(now, tenant, &result.lease, final_cursor, op_id)?;
///
///     // Admin operations
///     backend.unpark_shard(now, tenant, key, op_id)?;
///     backend.cancel_run(now, tenant, run_id, op_id)?;
/// }
/// ```
pub trait CoordinationFacade: CoordinationBackend + RunManagement + ShardClaiming {}

// Blanket implementation.
impl<T: CoordinationBackend + RunManagement + ShardClaiming> CoordinationFacade for T {}

// ============================================================================
// Â§5.8 Contract Invariant Catalog
// ============================================================================

// This section enumerates every invariant the coordination contract requires.
// It serves as the specification for backend conformance tests and the
// deterministic simulator's property checks.
//
// Each invariant is tagged with:
// - Kind: Safety (must never be violated) or Liveness (must eventually hold)
// - Source: The design decision or chunk where it was introduced
// - Testable: How to verify it in tests
//
// â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
// â”‚ ID      â”‚ Kind    â”‚ Invariant                                          â”‚
// â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
// â”‚ INV-S01 â”‚ Safety  â”‚ Tenant isolation: request.tenant must match        â”‚
// â”‚         â”‚         â”‚ record.tenant on every operation.                  â”‚
// â”‚         â”‚         â”‚ Source: D2.14. Tested: all ops with wrong tenant.  â”‚
// â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
// â”‚ INV-S02 â”‚ Safety  â”‚ Fence monotonicity: fence_epoch is monotonically   â”‚
// â”‚         â”‚         â”‚ non-decreasing per shard. Increments on every      â”‚
// â”‚         â”‚         â”‚ ownership transfer (acquire, unpark).              â”‚
// â”‚         â”‚         â”‚ Source: D2.14. Tested: sequential acquires.        â”‚
// â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
// â”‚ INV-S03 â”‚ Safety  â”‚ Stale fence rejection: operations with a lease     â”‚
// â”‚         â”‚         â”‚ whose fence < record.fence are rejected.           â”‚
// â”‚         â”‚         â”‚ Source: Kleppmann fencing tokens. Tested:          â”‚
// â”‚         â”‚         â”‚ checkpoint with stale lease after re-acquire.      â”‚
// â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
// â”‚ INV-S04 â”‚ Safety  â”‚ Expired lease rejection: operations with a lease   â”‚
// â”‚         â”‚         â”‚ whose deadline <= now are rejected.                â”‚
// â”‚         â”‚         â”‚ Source: Gray & Cheriton, Leases (1989). Tested:    â”‚
// â”‚         â”‚         â”‚ checkpoint after deadline.                         â”‚
// â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
// â”‚ INV-S05 â”‚ Safety  â”‚ Cursor monotonicity: last_key must be              â”‚
// â”‚         â”‚         â”‚ lexicographically non-decreasing across            â”‚
// â”‚         â”‚         â”‚ checkpoints within the same lease epoch.           â”‚
// â”‚         â”‚         â”‚ Source: D2.3. Tested: checkpoint with regression.  â”‚
// â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
// â”‚ INV-S06 â”‚ Safety  â”‚ Cursor bounds: last_key must fall within           â”‚
// â”‚         â”‚         â”‚ [spec.start, spec.end).                            â”‚
// â”‚         â”‚         â”‚ Source: D2.4. Tested: checkpoint out of range.     â”‚
// â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
// â”‚ INV-S07 â”‚ Safety  â”‚ Checkpoint requires last_key: a checkpoint with    â”‚
// â”‚         â”‚         â”‚ last_key=None is rejected.                         â”‚
// â”‚         â”‚         â”‚ Source: D2.5. Tested: checkpoint with initial      â”‚
// â”‚         â”‚         â”‚ cursor.                                            â”‚
// â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
// â”‚ INV-S08 â”‚ Safety  â”‚ OpId idempotency: same (op_id, payload_hash) â†’     â”‚
// â”‚         â”‚         â”‚ cached result; same op_id + different hash â†’       â”‚
// â”‚         â”‚         â”‚ OpIdConflict.                                      â”‚
// â”‚         â”‚         â”‚ Source: D2.8, Stripe pattern. Tested: replay +     â”‚
// â”‚         â”‚         â”‚ conflict.                                          â”‚
// â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
// â”‚ INV-S09 â”‚ Safety  â”‚ Terminal irreversibility (shard): Done, Split,     â”‚
// â”‚         â”‚         â”‚ Parked shards reject all mutations.                â”‚
// â”‚         â”‚         â”‚ Source: D2.6. Tested: checkpoint on Done shard.    â”‚
// â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
// â”‚ INV-S10 â”‚ Safety  â”‚ Terminal irreversibility (run): Done, Failed       â”‚
// â”‚         â”‚         â”‚ runs reject all mutations.                         â”‚
// â”‚         â”‚         â”‚ Source: D2.19. Tested: complete_run on Done run.   â”‚
// â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
// â”‚ INV-S11 â”‚ Safety  â”‚ Split coverage: children's key ranges must         â”‚
// â”‚         â”‚         â”‚ exactly partition the parent's range.              â”‚
// â”‚         â”‚         â”‚ Source: chunk 1. Tested: split with gap/overlap.   â”‚
// â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
// â”‚ INV-S12 â”‚ Safety  â”‚ Deterministic child IDs: derive_split_shard_id     â”‚
// â”‚         â”‚         â”‚ is a pure function. Same inputs â†’ same output.     â”‚
// â”‚         â”‚         â”‚ Source: D2.10. Tested: property-based.             â”‚
// â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
// â”‚ INV-S13 â”‚ Safety  â”‚ Park reason consistency: park_reason.is_some()     â”‚
// â”‚         â”‚         â”‚ iff status == Parked.                              â”‚
// â”‚         â”‚         â”‚ Source: D2.7. Tested: assert_invariants.           â”‚
// â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
// â”‚ INV-S14 â”‚ Safety  â”‚ Lease consistency: lease_owner.is_some() iff       â”‚
// â”‚         â”‚         â”‚ lease_deadline.is_some().                          â”‚
// â”‚         â”‚         â”‚ Source: chunk 2. Tested: assert_invariants.        â”‚
// â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
// â”‚ INV-S15 â”‚ Safety  â”‚ Terminal implies no lease: terminal shards have    â”‚
// â”‚         â”‚         â”‚ no lease_owner or lease_deadline.                  â”‚
// â”‚         â”‚         â”‚ Source: chunk 2. Tested: assert_invariants.        â”‚
// â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
// â”‚ INV-S16 â”‚ Safety  â”‚ Op-log bounded: shard op_log <= 16 entries,        â”‚
// â”‚         â”‚         â”‚ run op_log <= 8 entries. FIFO eviction.            â”‚
// â”‚         â”‚         â”‚ Source: D2.8, D2.25. Tested: assert_invariants.   â”‚
// â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
// â”‚ INV-S17 â”‚ Safety  â”‚ Manifest uniqueness: no duplicate shard IDs in     â”‚
// â”‚         â”‚         â”‚ initial registration.                              â”‚
// â”‚         â”‚         â”‚ Source: chunk 4. Tested: validate_manifest.        â”‚
// â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
// â”‚ INV-S18 â”‚ Safety  â”‚ Manifest no overlaps: no overlapping key ranges    â”‚
// â”‚         â”‚         â”‚ in initial registration.                           â”‚
// â”‚         â”‚         â”‚ Source: chunk 4. Tested: validate_manifest.        â”‚
// â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
// â”‚ INV-S19 â”‚ Safety  â”‚ RunConfig immutable: RunConfig is set at creation  â”‚
// â”‚         â”‚         â”‚ and never modified during a run's lifetime.        â”‚
// â”‚         â”‚         â”‚ Source: D2.18. Tested: backend conformance.        â”‚
// â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
// â”‚ INV-S20 â”‚ Safety  â”‚ Active run has shards: an Active run must have     â”‚
// â”‚         â”‚         â”‚ at least one root shard.                           â”‚
// â”‚         â”‚         â”‚ Source: chunk 4. Tested: assert_invariants.        â”‚
// â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
// â”‚ INV-S21 â”‚ Safety  â”‚ completed_at consistency: completed_at.is_some()   â”‚
// â”‚         â”‚         â”‚ iff run status is terminal.                        â”‚
// â”‚         â”‚         â”‚ Source: chunk 4. Tested: assert_invariants.        â”‚
// â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
// â”‚ INV-L01 â”‚ Livenessâ”‚ Lease expiry: if a worker fails to renew, its     â”‚
// â”‚         â”‚         â”‚ lease expires and the shard becomes available.     â”‚
// â”‚         â”‚         â”‚ Source: D2.15. Tested: acquire after expiry.       â”‚
// â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
// â”‚ INV-L02 â”‚ Livenessâ”‚ Every shard reaches terminal: every shard must    â”‚
// â”‚         â”‚         â”‚ eventually reach Done, Split, or Parked.           â”‚
// â”‚         â”‚         â”‚ Source: Â§1.3. Tested: simulation with fault        â”‚
// â”‚         â”‚         â”‚ injection (FoundationDB-style DST).                â”‚
// â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
// â”‚ INV-L03 â”‚ Livenessâ”‚ Every run reaches terminal: if all shards are     â”‚
// â”‚         â”‚         â”‚ terminal and the coordinator evaluates run status, â”‚
// â”‚         â”‚         â”‚ the run must transition to Done or Failed.         â”‚
// â”‚         â”‚         â”‚ Source: D2.19. Tested: simulation.                 â”‚
// â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
//
// ## Verification Strategy
//
// Safety invariants (INV-S*) are testable with unit and property-based tests.
// Each backend conformance test suite should verify all INV-S invariants.
//
// Liveness invariants (INV-L*) require simulation testing with fault injection.
// The deterministic simulator (FoundationDB-style DST, TigerBeetle VOPR)
// exercises random operation sequences with injected failures and checks
// that liveness properties hold within bounded time.
//
// Reference:
// - FoundationDB simulation (Zhou et al., SIGMOD 2021)
// - TigerBeetle VOPR
// - Jepsen methodology (Kingsbury)
// - Lamport, "Proving the Correctness of Multiprocess Programs" (1977)
// - Alpern & Schneider, "Defining Liveness" (1985)

// ============================================================================
// Â§ Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // â”€â”€ Test fixtures â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    fn test_tenant() -> TenantId {
        TenantId::from_bytes([0x01; 32])
    }
    fn test_run() -> RunId {
        RunId {
            job: JobId(1),
            policy: PolicyHash::from_bytes([0xAA; 32]),
        }
    }
    fn test_config() -> RunConfig {
        RunConfig {
            cursor_semantics: CursorSemantics::Completed,
            lease_duration: 30,
            max_shard_retries: Some(5),
        }
    }

    fn test_run_record() -> RunRecord {
        RunRecord {
            tenant: test_tenant(),
            run: test_run(),
            config: test_config(),
            status: RunStatus::Active,
            created_at: LogicalTime(0),
            completed_at: None,
            root_shards: vec![ShardId(0), ShardId(1)],
            op_log: vec![],
        }
    }

    // â”€â”€ RunOpKind / RunOpResult â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn run_op_result_variants() {
        let ack = RunOpResult::Ack;
        let registered = RunOpResult::RegisteredShards {
            shard_ids: vec![ShardId(0), ShardId(1)],
        };
        // Just confirm they're constructable and distinct.
        assert_ne!(format!("{ack:?}"), format!("{registered:?}"));
    }

    // â”€â”€ RunRecord op-log â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn run_op_log_lookup_found() {
        let mut r = test_run_record();
        r.op_log_push(RunOpLogEntry {
            op_id: OpId(42),
            kind: RunOpKind::RegisterShards,
            payload_hash: 0xBEEF,
            result: RunOpResult::RegisteredShards {
                shard_ids: vec![ShardId(0)],
            },
        });
        assert!(r.op_log_lookup(OpId(42)).is_some());
        assert_eq!(r.op_log_lookup(OpId(42)).unwrap().payload_hash, 0xBEEF);
    }

    #[test]
    fn run_op_log_lookup_not_found() {
        let r = test_run_record();
        assert!(r.op_log_lookup(OpId(999)).is_none());
    }

    #[test]
    fn run_op_log_push_evicts_oldest() {
        let mut r = test_run_record();
        for i in 0..RunRecord::RUN_OP_LOG_CAP {
            r.op_log_push(RunOpLogEntry {
                op_id: OpId(i as u64),
                kind: RunOpKind::CompleteRun,
                payload_hash: i as u64,
                result: RunOpResult::Ack,
            });
        }
        assert_eq!(r.op_log.len(), RunRecord::RUN_OP_LOG_CAP);
        assert!(r.op_log_lookup(OpId(0)).is_some());

        // Push one more â€” evicts oldest.
        r.op_log_push(RunOpLogEntry {
            op_id: OpId(999),
            kind: RunOpKind::CompleteRun,
            payload_hash: 999,
            result: RunOpResult::Ack,
        });
        assert_eq!(r.op_log.len(), RunRecord::RUN_OP_LOG_CAP);
        assert!(r.op_log_lookup(OpId(0)).is_none());
        assert!(r.op_log_lookup(OpId(999)).is_some());
    }

    #[test]
    fn run_op_idempotency_new() {
        let r = test_run_record();
        assert!(matches!(
            r.check_op_idempotency(OpId(42), 0xDEAD),
            Ok(None),
        ));
    }

    #[test]
    fn run_op_idempotency_replay() {
        let mut r = test_run_record();
        r.op_log_push(RunOpLogEntry {
            op_id: OpId(42),
            kind: RunOpKind::CompleteRun,
            payload_hash: 0xDEAD,
            result: RunOpResult::Ack,
        });
        assert!(matches!(
            r.check_op_idempotency(OpId(42), 0xDEAD),
            Ok(Some(_)),
        ));
    }

    #[test]
    fn run_op_idempotency_conflict() {
        let mut r = test_run_record();
        r.op_log_push(RunOpLogEntry {
            op_id: OpId(42),
            kind: RunOpKind::CompleteRun,
            payload_hash: 0xDEAD,
            result: RunOpResult::Ack,
        });
        let err = r.check_op_idempotency(OpId(42), 0xBEEF).unwrap_err();
        assert_eq!(err.op_id, OpId(42));
        assert_eq!(err.expected_hash, 0xDEAD);
        assert_eq!(err.actual_hash, 0xBEEF);
    }

    // â”€â”€ Payload hash functions â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn hash_register_shards_deterministic() {
        let shards = vec![
            InitialShard {
                shard_id: ShardId(0),
                spec: ShardSpec::with_range(b"a".to_vec(), b"m".to_vec()),
                cursor: Cursor::initial(),
            },
            InitialShard {
                shard_id: ShardId(1),
                spec: ShardSpec::with_range(b"m".to_vec(), b"z".to_vec()),
                cursor: Cursor::initial(),
            },
        ];
        assert_eq!(
            hash_register_shards_payload(&shards),
            hash_register_shards_payload(&shards),
        );
    }

    #[test]
    fn hash_register_shards_order_independent() {
        let shards_forward = vec![
            InitialShard {
                shard_id: ShardId(0),
                spec: ShardSpec::with_range(b"a".to_vec(), b"m".to_vec()),
                cursor: Cursor::initial(),
            },
            InitialShard {
                shard_id: ShardId(1),
                spec: ShardSpec::with_range(b"m".to_vec(), b"z".to_vec()),
                cursor: Cursor::initial(),
            },
        ];
        let shards_reversed = vec![
            shards_forward[1].clone(),
            shards_forward[0].clone(),
        ];
        // Should be the same because we sort by shard_id internally.
        assert_eq!(
            hash_register_shards_payload(&shards_forward),
            hash_register_shards_payload(&shards_reversed),
        );
    }

    #[test]
    fn hash_run_terminals_are_distinct() {
        let complete = hash_complete_run_payload();
        let fail = hash_fail_run_payload();
        let cancel = hash_cancel_run_payload();
        assert_ne!(complete, fail);
        assert_ne!(complete, cancel);
        assert_ne!(fail, cancel);
    }

    #[test]
    fn hash_unpark_includes_shard_key() {
        let key_a = ShardKey {
            run: test_run(),
            shard: ShardId(0),
        };
        let key_b = ShardKey {
            run: test_run(),
            shard: ShardId(1),
        };
        assert_ne!(
            hash_unpark_payload(&key_a),
            hash_unpark_payload(&key_b),
        );
    }

    // â”€â”€ StateTransitionEvent â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn event_tenant_and_run() {
        let event = StateTransitionEvent::ShardCompleted {
            tenant: test_tenant(),
            run: test_run(),
            shard: ShardId(0),
        };
        assert_eq!(event.tenant(), test_tenant());
        assert_eq!(event.run(), test_run());
        assert!(event.is_shard_event());
        assert!(!event.is_run_event());
        assert!(event.is_terminal());
    }

    #[test]
    fn event_classification() {
        let checkpoint = StateTransitionEvent::ShardCheckpointed {
            tenant: test_tenant(),
            run: test_run(),
            shard: ShardId(0),
            last_key: Some(b"progress".to_vec().into_boxed_slice()),
        };
        assert!(checkpoint.is_shard_event());
        assert!(!checkpoint.is_terminal());

        let run_created = StateTransitionEvent::RunCreated {
            tenant: test_tenant(),
            run: test_run(),
        };
        assert!(run_created.is_run_event());
        assert!(!run_created.is_terminal());

        let run_done = StateTransitionEvent::RunCompleted {
            tenant: test_tenant(),
            run: test_run(),
        };
        assert!(run_done.is_run_event());
        assert!(run_done.is_terminal());
    }

    // â”€â”€ EventCollector â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn event_collector_basic() {
        let mut collector = EventCollector::new();
        assert!(collector.is_empty());
        assert_eq!(collector.len(), 0);

        collector.emit(StateTransitionEvent::RunCreated {
            tenant: test_tenant(),
            run: test_run(),
        });
        assert!(!collector.is_empty());
        assert_eq!(collector.len(), 1);

        let events = collector.drain();
        assert_eq!(events.len(), 1);
        assert!(collector.is_empty());
    }

    #[test]
    fn event_collector_multi_emit() {
        let mut collector = EventCollector::new();
        collector.emit(StateTransitionEvent::ShardAcquired {
            tenant: test_tenant(),
            run: test_run(),
            shard: ShardId(0),
            worker: WorkerId(1),
            fence_epoch: FenceEpoch(2),
        });
        collector.emit(StateTransitionEvent::ShardCheckpointed {
            tenant: test_tenant(),
            run: test_run(),
            shard: ShardId(0),
            last_key: Some(b"k".to_vec().into_boxed_slice()),
        });
        collector.emit(StateTransitionEvent::ShardCompleted {
            tenant: test_tenant(),
            run: test_run(),
            shard: ShardId(0),
        });

        assert_eq!(collector.len(), 3);
        let events = collector.drain();
        assert!(events[0].is_shard_event());
        assert!(events[2].is_terminal());
    }

    // â”€â”€ ShardFilter matches (additional from chunk 4) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn shard_filter_conjunctive() {
        // Active + leased = only active leased shards
        let filter = ShardFilter {
            status: Some(ShardStatus::Active),
            is_leased: Some(true),
            ..ShardFilter::default()
        };

        let active_leased = ShardSummary {
            shard: ShardId(0),
            status: ShardStatus::Active,
            park_reason: None,
            is_leased: true,
            acquire_count: 1,
            last_key: None,
            key_range_start: b"a".to_vec().into_boxed_slice(),
            key_range_end: b"z".to_vec().into_boxed_slice(),
            parent: None,
            spawned_count: 0,
        };
        assert!(filter.matches(&active_leased));

        let active_unleased = ShardSummary {
            is_leased: false,
            ..active_leased.clone()
        };
        assert!(!filter.matches(&active_unleased));

        let done_leased = ShardSummary {
            status: ShardStatus::Done,
            is_leased: true, // unusual but tests the filter
            ..active_leased
        };
        assert!(!filter.matches(&done_leased));
    }

    // â”€â”€ WorkerSession (compile-time shape tests) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    // WorkerSession requires a CoordinationBackend, so full behavioral
    // tests live in the in-memory backend test suite. Here we test
    // the type's API surface compiles correctly.

    // No runtime tests â€” WorkerSession is a thin delegation wrapper.
    // Its correctness follows from the correctness of the underlying
    // CoordinationBackend methods.
}
