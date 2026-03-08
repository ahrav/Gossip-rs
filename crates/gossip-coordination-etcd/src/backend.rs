//! etcd-backed coordination backend implementation.
//!
//! This module owns [`EtcdCoordinator`], the concrete [`CoordinationBackend`]
//! that persists run and shard lifecycle state in etcd. It implements:
//!
//! - **Run management** (`create_run`, `register_shards`, `get_run`,
//!   `get_run_progress`, `list_shards_into`, `collect_claim_candidates_into`,
//!   `complete_run`, `fail_run`, `cancel_run`)
//! - **Shard hot path** (`acquire_and_restore_into`, `renew`, `checkpoint`)
//! - **Shard lifecycle** (`split_replace`, `split_residual`, `unpark_shard`)
//! - **Shard claiming** (via [`default_claim_next_available`])
//! - **Cold-path maintenance** (`list_active_runs_into`,
//!   `gc_stale_initializing_runs_into`)
//! - **Not yet persisted** (`complete`, `park_shard`) — panic until their
//!   etcd transaction semantics are defined
//!
//! # Concurrency model
//!
//! All mutating operations use optimistic compare-and-swap (CAS) transactions
//! against etcd. Each operation follows the same pattern:
//!
//! 1. **Read** — Load the current record (shard or run) and its `mod_revision`.
//! 2. **Validate** — Check preconditions locally (lease, status, fencing epoch).
//! 3. **CAS** — Submit an etcd `Txn` conditioned on `mod_revision` equality.
//! 4. **Retry** — On CAS failure, backoff with jitter and retry from step 1
//!    (up to `optimistic_txn_retries`).
//!
//! If retries exhaust without success, the operation re-reads and returns
//! whatever domain error is appropriate (stale fence, already leased, etc.)
//! or panics if the contention is unexplainable. This last-resort re-read
//! ensures the caller never silently loses work.
//!
//! # Shard ownership
//!
//! Each shard has a separate `/owner` key holding a `(WorkerId, FenceEpoch)`
//! binding, attached to an etcd lease. When the etcd lease expires (e.g.,
//! worker crash), the `/owner` key is automatically deleted by etcd's TTL
//! mechanism. The shard record itself persists the logical lease deadline
//! for coordinators to make availability decisions without watching etcd
//! lease events.
//!
//! This dual-key design means ownership depends on *two* conditions being
//! true simultaneously: (a) the `/owner` key exists and matches, and
//! (b) the shard record's logical deadline has not passed. CAS transactions
//! guard both.
//!
//! # Idempotency
//!
//! Op-log-backed mutations (`checkpoint`, `complete`, `park_shard`,
//! `split_replace`, `split_residual`, `register_shards`, terminal run
//! transitions, and `unpark_shard`) carry an `OpId` and a payload hash.
//! If a retry finds the operation already recorded in the shard's or run's
//! op-log, it returns [`IdempotentOutcome::Replayed`] with the previously
//! computed result, making these mutations safe to retry across network
//! partitions.
//!
//! `acquire_and_restore_into` and `renew` do **not** use OpId-based
//! idempotency. They rely on CAS fencing (lease + epoch checks) for
//! correctness instead.
//!
//! # Unimplemented operations
//!
//! Operations not yet persisted (`complete`, `park_shard`) panic with a
//! descriptive message. They remain fail-closed until their etcd
//! transaction semantics are defined.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::time::Duration;

use crate::codec::{
    EtcdCodecError, OwnerLeaseValue, decode_owner_value, decode_run_record, decode_shard_record,
    encode_owner_value, encode_owner_value_into, encode_run_record, encode_shard_record,
    encode_shard_record_into,
};
use crate::config::{DEFAULT_CONNECT_TIMEOUT, EtcdCoordinatorConfig};
use crate::error::{EtcdCoordinatorError, EtcdOperation};
use crate::keyspace::EtcdKeyspace;
use etcd_client::{Compare, CompareOp, DeleteOptions, GetOptions, PutOptions, Txn, TxnOp};
use gossip_contracts::coordination::shard_spec::{
    ShardLimitScope, ShardSpecRef, SplitValidationError,
};
#[cfg(test)]
use gossip_contracts::test_util::TestSlab;
#[cfg(test)]
use gossip_coordination::FenceEpoch;
use gossip_coordination::validation::validate_cursor_update_pooled;
use gossip_coordination::{
    AcquireError, AcquireResultView, AcquireScratch, ByteSlab, CapacityHint, CheckpointError,
    ClaimError, CompleteError, CoordinationBackend, CreateRunError, CursorUpdate, DerivedShardKind,
    GetRunError, IdempotentOutcome, InitialShardInput, Lease, LeaseHolder, LogicalTime, OpId,
    OpKind, OpLogEntry, OpResult, ParkError, ParkReason, RegisterShardsError, RenewError,
    RenewResult, RingBuffer, RunConfig, RunId, RunManagement, RunOpKind, RunOpLogEntry,
    RunOpResult, RunProgress, RunRecord, RunStatus, RunTransitionError, ShardClaiming, ShardFilter,
    ShardId, ShardKey, ShardRecord, ShardStatus, ShardSummary, SplitChildIds, SplitReplaceError,
    SplitReplacePlan, SplitReplaceResult, SplitResidualError, SplitResidualPlan,
    SplitResidualResult, TenantId, UnparkError, WorkerId, check_op_idempotency,
    default_claim_next_available, derive_split_shard_id, hash_cancel_run_payload,
    hash_checkpoint_payload, hash_complete_run_payload, hash_fail_run_payload,
    hash_register_shards_payload, hash_split_replace_payload, hash_split_residual_payload,
    hash_unpark_payload, split_replace_apply_parent, split_replace_validate_preconditions,
    split_residual_apply_parent, split_residual_build_record, split_residual_check_replay,
    split_residual_validate_preconditions, validate_lease, validate_manifest,
};

/// Minimum slab capacity allocated for decoding a shard record blob.
///
/// Ensures small blobs (e.g. a shard with empty key range and no metadata)
/// still get a workable slab for pooled field allocation without
/// triggering immediate `SlabFull`.
const MIN_DECODE_SLAB_CAPACITY: usize = 4 * 1024;

/// Maximum slab capacity allocated for decoding a shard record blob.
///
/// Caps the scaling heuristic in [`EtcdCoordinator::make_decode_slab`]
/// to prevent a single oversized blob from causing a disproportionate
/// one-shot allocation.
const MAX_DECODE_SLAB_CAPACITY: usize = 256 * 1024;

/// Floor capacity for slabs built during shard registration encoding.
///
/// Prevents tiny slabs when a shard's combined spec + cursor content is
/// nearly empty.
const DEFAULT_BUILD_SLAB_FLOOR: usize = 1024;

/// Maximum shards per `register_shards` etcd transaction.
///
/// Derived from etcd's default `--max-txn-ops` limit of 128. Each shard
/// generates 2 ops (put-record, put-active-index) and 1 compare
/// (compare-absent). The run itself adds 3 fixed ops
/// (compare-run-revision, put-run-record, put-run-active-index), giving
/// `(128 - 3) / 3 = 41` as the maximum shard count per transaction.
const MAX_SHARDS_PER_ETCD_TXN: usize = 41;

/// Maximum children per `split_replace` etcd transaction.
///
/// Each child generates 2 ops (put-record, put-active-index) and 1 compare
/// (compare-absent). The parent side adds 4 compares (shard-revision,
/// owner-version, owner-value, owner-lease) and 3 ops (put-parent,
/// delete-owner, delete-active-index), giving `(128 - 7) / 3 = 40`.
pub(crate) const MAX_CHILDREN_PER_SPLIT_TXN: usize = 40;

/// Marker segment that appears exactly once in persisted shard record keys.
const SHARD_RECORD_KEY_SEGMENT: &[u8] = b"/shards/";

/// Snapshot of persisted shard counts used for shard-limit enforcement.
///
/// Both counters are computed from keys-only prefix scans at read time
/// (no dedicated counter keys). The etcd backend reads from storage
/// directly, so the counts already include any shard being operated on
/// (unlike the in-memory backend, which temporarily removes the parent
/// during split validation).
#[derive(Clone, Copy, Debug, Default)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub(crate) struct ShardCountSnapshot {
    /// Shards under the requesting tenant's prefix.
    pub(crate) tenant: usize,
    /// Shards across all tenants.
    pub(crate) total: usize,
}

/// Details for the first shard-limit violation detected in a growth check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ShardLimitViolation {
    pub(crate) current: usize,
    pub(crate) additional: usize,
    pub(crate) max: usize,
    pub(crate) scope: ShardLimitScope,
}

/// Returns the first shard-count ceiling that `additional` would exceed.
pub(crate) fn shard_limit_violation(
    counts: ShardCountSnapshot,
    additional: usize,
    max_shards_per_tenant: usize,
    max_total_shards: usize,
) -> Option<ShardLimitViolation> {
    if counts.tenant.saturating_add(additional) > max_shards_per_tenant {
        return Some(ShardLimitViolation {
            current: counts.tenant,
            additional,
            max: max_shards_per_tenant,
            scope: ShardLimitScope::PerTenant,
        });
    }

    if counts.total.saturating_add(additional) > max_total_shards {
        return Some(ShardLimitViolation {
            current: counts.total,
            additional,
            max: max_total_shards,
            scope: ShardLimitScope::Global,
        });
    }

    None
}

/// Returns `true` when `key` is a shard record path rather than an owner or
/// active-index key.
///
/// The shard-record key is the leaf under `…/shards/{hex}` with no further
/// path segments. Owner keys (`…/shards/{hex}/owner`) and active-index
/// keys (`…/shards_active/{hex}`) are excluded by checking that nothing
/// follows the last `/shards/` segment except a single path component
/// (no further `/` separators).
fn is_persisted_shard_record_key(key: &[u8]) -> bool {
    let Some(segment_pos) = key
        .windows(SHARD_RECORD_KEY_SEGMENT.len())
        .rposition(|window| window == SHARD_RECORD_KEY_SEGMENT)
    else {
        return false;
    };

    !key[segment_pos + SHARD_RECORD_KEY_SEGMENT.len()..].contains(&b'/')
}

/// Compute a backoff delay for CAS retry loops.
///
/// Uses exponential backoff (5 ms base, 2× per attempt, capped at 200 ms)
/// with jitter in `[0.5×, 1.5×)` of the exponential value to prevent
/// thundering-herd contention when multiple workers race on the same shard.
///
/// Jitter is derived from the current system time's sub-second nanoseconds
/// rather than an RNG. This avoids adding a CSPRNG or thread-local RNG
/// dependency for a best-effort delay that only needs approximate
/// decorrelation between independent callers.
fn cas_retry_delay(attempt: usize) -> Duration {
    let base_ms: u64 = 5;
    let max_ms: u64 = 200;
    let exp_ms = base_ms.saturating_mul(1u64 << attempt.min(6)).min(max_ms);

    let jitter_source = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .subsec_nanos();
    let jitter_frac = (jitter_source % 1000) as f64 / 1000.0;
    let jittered = (exp_ms as f64) * (0.5 + jitter_frac);

    Duration::from_micros((jittered * 1000.0) as u64)
}

/// Outcome of a single CAS attempt within a retry loop.
enum CasOutcome<T> {
    /// Transaction committed successfully.
    Committed(T),
    /// CAS precondition failed; caller should retry after backoff.
    RetryNeeded,
}

/// A run record loaded from etcd, paired with its `mod_revision` for
/// compare-and-swap transaction guards.
///
/// `mod_revision` is the etcd key revision at the time of the read; the
/// subsequent CAS transaction conditions on this revision to detect
/// concurrent writes between the read and the write.
#[derive(Debug)]
struct PersistedRun {
    record: RunRecord,
    /// etcd key modification revision used as a CAS precondition.
    mod_revision: i64,
}

/// Decoded owner-key state for a single shard, including the etcd lease
/// ID that controls the key's TTL-based automatic deletion.
///
/// The `lease_id` is the etcd-level lease (distinct from the coordination
/// protocol's logical `Lease`). When etcd's TTL expires, it deletes the
/// owner key automatically, which the backend detects on the next read
/// as an absent owner.
#[derive(Clone, Debug)]
struct PersistedOwner {
    binding: OwnerLeaseValue,
    /// etcd lease ID attached to the owner key. Revocation of this lease
    /// causes etcd to delete the owner key, signaling ownership loss.
    lease_id: i64,
}

/// A shard record loaded from etcd with its associated slab, revision,
/// and optional owner binding.
///
/// This is the internal read model: every mutating operation loads one or
/// more `PersistedShard` values, validates preconditions against them,
/// then builds a CAS transaction conditioned on `mod_revision`. The slab
/// is co-located with the record because `ShardRecord` pools its
/// variable-length fields (spec, cursor, spawned) in a `ByteSlab`.
struct PersistedShard {
    record: ShardRecord,
    /// Slab backing the pooled fields in `record` (`spec`, `cursor`, `spawned`).
    slab: ByteSlab,
    /// etcd key modification revision used as a CAS precondition.
    mod_revision: i64,
    /// Decoded owner-key binding, present only if the shard has a live
    /// `/owner` key in etcd.
    owner: Option<PersistedOwner>,
}

impl PersistedShard {
    /// Returns `true` if the shard has a live owner whose logical lease
    /// has not yet expired at `now`.
    fn owner_is_live_at(&self, now: LogicalTime) -> bool {
        self.owner.is_some()
            && self
                .record
                .lease_deadline()
                .is_some_and(|deadline| now < deadline)
    }

    /// Re-encode the current owner binding for use as a CAS comparison
    /// value. Returns `None` if there is no owner.
    fn expected_owner_value(&self) -> Option<Vec<u8>> {
        self.owner
            .as_ref()
            .map(|owner| encode_owner_value(owner.binding.worker, owner.binding.fence))
    }

    /// Returns `true` if the persisted owner binding matches the
    /// presented lease's worker and fence epoch.
    fn owner_matches_lease(&self, lease: &Lease) -> bool {
        self.owner.as_ref().is_some_and(|owner| {
            owner.binding.worker == lease.owner() && owner.binding.fence == lease.fence()
        })
    }
}

/// Recover split-replace child IDs from the parent's spawned lineage tail.
///
/// `split_replace` makes the parent terminal (`Split` status), so once the
/// first execution commits, no later mutation can reorder or append
/// additional children. Replays therefore recover the previously published
/// child set directly from the last `plan_len` spawned entries.
///
/// # Panics
///
/// Panics if `parent.spawned.len() < plan_len`, indicating state corruption
/// (the spawned list is shorter than the plan that produced it).
fn split_replace_replay_child_ids(
    parent: &ShardRecord,
    slab: &ByteSlab,
    plan_len: usize,
) -> SplitChildIds {
    let base_index = parent
        .spawned
        .len()
        .checked_sub(plan_len)
        .expect("split_replace replay: parent.spawned shorter than plan; state corruption");

    let mut ids = SplitChildIds::new();
    for child_id in parent.spawned.iter(slab).skip(base_index) {
        ids.push(child_id);
    }

    debug_assert_eq!(ids.len(), plan_len);
    ids
}

/// Extract a `u64` from the 16-character lowercase hex suffix
/// immediately after `prefix` in `key`.
fn parse_hex_u64_suffix(prefix: &str, key: &[u8]) -> Option<u64> {
    let suffix = key.strip_prefix(prefix.as_bytes())?;
    if suffix.len() != 16 || suffix.contains(&b'/') {
        return None;
    }
    u64::from_str_radix(std::str::from_utf8(suffix).ok()?, 16).ok()
}

/// Parse a direct run-record or active-run key suffix into a [`RunId`].
///
/// Returns `None` when `key` is not an immediate child of `prefix` or the
/// suffix is not a 16-character lowercase hex run ID.
fn parse_direct_run_id_from_key(prefix: &str, key: &[u8]) -> Option<RunId> {
    parse_hex_u64_suffix(prefix, key).map(RunId::from_raw)
}

/// Parse a shard-active-index key suffix into a [`ShardId`].
///
/// Returns `None` when `key` is not an immediate child of `prefix` or the
/// suffix is not a 16-character lowercase hex shard ID.
fn parse_shard_id_from_index_key(prefix: &str, key: &[u8]) -> Option<ShardId> {
    parse_hex_u64_suffix(prefix, key).map(ShardId::from_raw)
}

/// Extract a [`ShardId`] from a shard owner key.
///
/// Owner keys have the form `{shards_scan_prefix}{16-char hex}/owner`.
/// Returns `None` if the key does not match this pattern.
fn parse_owned_shard_from_key(shards_scan_prefix: &[u8], key: &[u8]) -> Option<ShardId> {
    let suffix = key.strip_prefix(shards_scan_prefix)?;
    let shard_hex = suffix.strip_suffix(b"/owner")?;
    if shard_hex.len() != 16 {
        return None;
    }
    let hex = std::str::from_utf8(shard_hex).ok()?;
    let raw = u64::from_str_radix(hex, 16).ok()?;
    Some(ShardId::from_raw(raw))
}

/// Apply a terminal run transition (Done / Failed / Cancelled) and append
/// an acknowledged op-log entry.
///
/// # Preconditions
///
/// The caller must verify that:
/// - `target_status` is a terminal variant (`is_terminal() == true`).
/// - `record.status` is not already terminal.
/// - The transition from `record.status` to `target_status` is legal
///   according to the run state machine.
///
/// All three are assert-guarded; violating any panics immediately.
///
/// # Effects
///
/// Sets the run status, records the completion timestamp, pushes an `Ack`
/// op-log entry, and re-validates all record invariants.
fn apply_terminal_run_transition(
    record: &mut RunRecord,
    now: LogicalTime,
    target_status: RunStatus,
    op_id: OpId,
    op_kind: RunOpKind,
    payload_hash: u64,
) {
    assert!(target_status.is_terminal());
    assert!(!record.status.is_terminal());
    record.assert_transition_legal(target_status);
    record.status = target_status;
    record.completed_at = Some(now);
    record.op_log_push(RunOpLogEntry::new(
        op_id,
        op_kind,
        payload_hash,
        now,
        RunOpResult::Ack,
    ));
    record.assert_invariants();
}

/// etcd-backed coordination backend.
///
/// Persists run creation, run lifecycle transitions, shard registration,
/// read-side queries, and the acquire/renew/checkpoint/split/unpark surface
/// directly in etcd. Only shard `complete` and `park_shard` remain fail-closed
/// until their persistence logic is implemented.
///
/// ## Threading model
///
/// Internally owns a single-threaded Tokio runtime and synchronizes via
/// `block_on`. Callers **must not** invoke methods from within an existing
/// Tokio runtime — `block_on` within `block_on` deadlocks. Debug-asserts
/// guard against this in `connect()` and `status()`.
///
/// ## Scratch allocation
///
/// `claim_candidates_scratch` is a reusable buffer for
/// [`default_claim_next_available`]. It is `mem::take`-ed at the start of
/// each claim and restored afterward, avoiding per-claim heap allocation
/// in the common case where the buffer capacity is already sufficient.
pub struct EtcdCoordinator {
    config: EtcdCoordinatorConfig,
    keyspace: EtcdKeyspace,
    runtime: tokio::runtime::Runtime,
    client: etcd_client::Client,
    /// Reusable buffer for shard-claim candidate collection, avoiding
    /// per-claim allocation.
    claim_candidates_scratch: Vec<ShardId>,
}

impl EtcdCoordinator {
    /// Connect to etcd, verify connectivity with `status`, and create the
    /// backend.
    ///
    /// # Panics
    ///
    /// Debug-asserts that no Tokio runtime is active on the current thread.
    /// The backend owns a single-threaded runtime internally and
    /// `block_on` within an existing runtime would deadlock.
    ///
    /// # Errors
    ///
    /// Returns [`EtcdCoordinatorError`] on config validation failure,
    /// Tokio runtime creation failure, connection failure, or if the
    /// initial `status` health check fails.
    pub fn connect(config: EtcdCoordinatorConfig) -> Result<Self, EtcdCoordinatorError> {
        config.validate()?;

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .map_err(EtcdCoordinatorError::RuntimeBuild)?;

        let endpoints = config.endpoints().to_vec();
        let mut connect_opts =
            etcd_client::ConnectOptions::new().with_connect_timeout(DEFAULT_CONNECT_TIMEOUT);
        if let Some((user, password)) = config.auth() {
            connect_opts = connect_opts.with_user(user, password);
        }
        #[cfg(feature = "tls")]
        if let Some(tls) = config.tls().cloned() {
            connect_opts = connect_opts.with_tls(tls);
        }

        assert!(
            tokio::runtime::Handle::try_current().is_err(),
            "connect() must not be called from within an active Tokio runtime"
        );

        let mut client = runtime
            .block_on(etcd_client::Client::connect(endpoints, Some(connect_opts)))
            .map_err(|source| EtcdCoordinatorError::Etcd {
                operation: EtcdOperation::Connect,
                source,
            })?;

        runtime
            .block_on(client.status())
            .map_err(|source| EtcdCoordinatorError::Etcd {
                operation: EtcdOperation::Status,
                source,
            })?;

        let keyspace = EtcdKeyspace::new(config.namespace_prefix())?;

        Ok(Self {
            config,
            keyspace,
            runtime,
            client,
            claim_candidates_scratch: Vec::new(),
        })
    }

    /// The validated configuration used to construct this backend.
    #[must_use]
    pub fn config(&self) -> &EtcdCoordinatorConfig {
        &self.config
    }

    /// The keyspace builder used for all etcd key construction.
    #[must_use]
    pub fn keyspace(&self) -> &EtcdKeyspace {
        &self.keyspace
    }

    /// Round-trip a maintenance `status` request against etcd.
    pub fn status(&self) -> Result<etcd_client::StatusResponse, EtcdCoordinatorError> {
        assert!(
            tokio::runtime::Handle::try_current().is_err(),
            "status() must not be called from within an active Tokio runtime"
        );

        let mut client = self.client.clone();
        self.runtime
            .block_on(client.status())
            .map_err(|source| EtcdCoordinatorError::Etcd {
                operation: EtcdOperation::Status,
                source,
            })
    }

    /// Panics with a message identifying the unimplemented operation.
    ///
    /// Used as a placeholder for coordination operations whose etcd
    /// persistence logic has not been implemented. Callers should not
    /// catch this panic — it indicates a code path that must not be
    /// reached until the operation is persisted.
    fn fail_unimplemented<T>(&self, operation: &'static str) -> T {
        panic!(
            "EtcdCoordinator::{operation} is not yet persisted to etcd; \
             this operation must be implemented before it is callable"
        );
    }

    /// Panics on an unrecoverable storage error.
    ///
    /// Called when an etcd operation fails in a context where there is no
    /// meaningful recovery (e.g., encoding a shard record that was just
    /// successfully decoded). The panic message includes `context` for
    /// diagnosis.
    fn fatal_storage_error<T>(&self, context: &'static str, err: impl fmt::Display) -> T {
        panic!("etcd coordination backend {context} failed: {err}");
    }

    /// Execute a CAS retry loop with exponential backoff and jitter.
    ///
    /// Calls `attempt` up to `optimistic_txn_retries` times. On
    /// [`CasOutcome::RetryNeeded`], sleeps with jittered backoff and
    /// retries. On [`CasOutcome::Committed`], returns immediately.
    /// If retries exhaust, calls `on_exhaustion` immediately (no
    /// additional backoff) to re-read state and produce a domain error
    /// or panic. Callers that perform network I/O in `on_exhaustion`
    /// should be aware this executes at peak-contention time.
    fn cas_retry<T, E>(
        &mut self,
        mut attempt: impl FnMut(&mut Self, usize) -> Result<CasOutcome<T>, E>,
        on_exhaustion: impl FnOnce(&mut Self) -> Result<T, E>,
    ) -> Result<T, E> {
        for attempt_num in 0..self.config.optimistic_txn_retries() {
            match attempt(self, attempt_num)? {
                CasOutcome::Committed(val) => return Ok(val),
                CasOutcome::RetryNeeded => {
                    std::thread::sleep(cas_retry_delay(attempt_num));
                }
            }
        }
        on_exhaustion(self)
    }

    /// Create a decode slab sized from the blob length, clamped to
    /// `[MIN_DECODE_SLAB_CAPACITY, MAX_DECODE_SLAB_CAPACITY]`.
    ///
    /// Pooled fields (spec key/range, cursor key/token, spawned IDs) are
    /// copied into the slab during decode. The raw blob stores them
    /// length-prefixed; the slab stores them contiguously. A 3×
    /// multiplier on the blob plus a fixed pad for small-record overhead
    /// covers typical records without over-allocating.
    fn make_decode_slab(blob_len: usize) -> ByteSlab {
        let cap = blob_len
            .saturating_mul(3)
            .saturating_add(1024)
            .clamp(MIN_DECODE_SLAB_CAPACITY, MAX_DECODE_SLAB_CAPACITY);
        ByteSlab::with_capacity(cap)
    }

    /// Estimate the slab capacity needed to encode one shard's pooled
    /// fields (spec + cursor + padding). Returns at least
    /// `DEFAULT_BUILD_SLAB_FLOOR`.
    fn build_slab_capacity_for_spec_and_cursor(
        spec: ShardSpecRef<'_>,
        cursor: CursorUpdate<'_>,
    ) -> usize {
        let cursor_last = cursor.last_key().map_or(0, |key| key.len());
        let cursor_token = cursor.token().map_or(0, |token| token.len());
        let needed = spec.key_range_start().len()
            + spec.key_range_end().len()
            + spec.metadata().len()
            + cursor_last
            + cursor_token
            + 256;
        needed.max(DEFAULT_BUILD_SLAB_FLOOR)
    }

    /// Estimate the slab capacity needed to encode one initial shard's
    /// pooled fields (spec + cursor + padding). Returns at least
    /// `DEFAULT_BUILD_SLAB_FLOOR`.
    fn build_slab_capacity_for_initial_shard(input: &InitialShardInput<'_>) -> usize {
        Self::build_slab_capacity_for_spec_and_cursor(input.spec(), input.cursor())
    }

    /// Execute a `get` RPC on the internal single-threaded Tokio runtime.
    fn etcd_get(
        &self,
        key: Vec<u8>,
        options: Option<GetOptions>,
    ) -> Result<etcd_client::GetResponse, EtcdCoordinatorError> {
        let mut client = self.client.clone();
        self.runtime
            .block_on(client.get(key, options))
            .map_err(|source| EtcdCoordinatorError::Etcd {
                operation: EtcdOperation::Get,
                source,
            })
    }

    /// Execute a `txn` (compare-and-swap) RPC on the internal runtime.
    fn etcd_txn(&self, txn: Txn) -> Result<etcd_client::TxnResponse, EtcdCoordinatorError> {
        let mut client = self.client.clone();
        self.runtime
            .block_on(client.txn(txn))
            .map_err(|source| EtcdCoordinatorError::Etcd {
                operation: EtcdOperation::Txn,
                source,
            })
    }

    /// Grant an etcd lease with the given TTL in seconds.
    fn etcd_lease_grant(
        &self,
        ttl: i64,
    ) -> Result<etcd_client::LeaseGrantResponse, EtcdCoordinatorError> {
        let mut client = self.client.clone();
        self.runtime
            .block_on(client.lease_grant(ttl, None))
            .map_err(|source| EtcdCoordinatorError::Etcd {
                operation: EtcdOperation::LeaseGrant,
                source,
            })
    }

    /// Send a single keep-alive ping for an existing etcd lease and
    /// consume the server ACK to confirm the renewal succeeded.
    fn etcd_lease_keep_alive_once(&self, lease_id: i64) -> Result<(), EtcdCoordinatorError> {
        let mut client = self.client.clone();
        self.runtime
            .block_on(async move {
                let (mut keeper, mut stream) = client.lease_keep_alive(lease_id).await?;
                keeper.keep_alive().await?;
                // The keep_alive() call only sends the request; the server
                // ACK (or error) arrives on the response stream. Read it to
                // confirm the lease was actually renewed.
                match stream.message().await? {
                    Some(resp) if resp.ttl() > 0 => Ok(()),
                    _ => Err(etcd_client::Error::LeaseKeepAliveError(
                        "lease expired or keep-alive rejected by server".into(),
                    )),
                }
            })
            .map_err(|source| EtcdCoordinatorError::Etcd {
                operation: EtcdOperation::LeaseKeepAlive,
                source,
            })
    }

    /// Immediately revoke an etcd lease, causing all keys attached to it
    /// to be deleted.
    fn etcd_lease_revoke(
        &self,
        lease_id: i64,
    ) -> Result<etcd_client::LeaseRevokeResponse, EtcdCoordinatorError> {
        let mut client = self.client.clone();
        self.runtime
            .block_on(client.lease_revoke(lease_id))
            .map_err(|source| EtcdCoordinatorError::Etcd {
                operation: EtcdOperation::LeaseRevoke,
                source,
            })
    }

    /// Load a single run record by exact key. Returns `None` if the key
    /// does not exist in etcd.
    fn load_run_record(
        &self,
        tenant: TenantId,
        run: RunId,
    ) -> Result<Option<PersistedRun>, EtcdCoordinatorError> {
        let key = self.keyspace.run_record_key(tenant, run).into_bytes();
        let response = self.etcd_get(key, None)?;
        let Some(kv) = response.kvs().first() else {
            return Ok(None);
        };

        let record =
            decode_run_record(kv.value()).map_err(|source| EtcdCoordinatorError::Codec {
                operation: EtcdOperation::Get,
                source,
            })?;

        Ok(Some(PersistedRun {
            record,
            mod_revision: kv.mod_revision(),
        }))
    }

    /// Decode an owner-key blob, wrapping codec errors with the given
    /// operation context.
    fn decode_owner_binding(
        &self,
        operation: EtcdOperation,
        bytes: &[u8],
    ) -> Result<OwnerLeaseValue, EtcdCoordinatorError> {
        decode_owner_value(bytes)
            .map_err(|source| EtcdCoordinatorError::Codec { operation, source })
    }

    /// Decode an owner-key KV pair, validating the non-zero lease invariant.
    ///
    /// Combines codec decoding with the structural check that every owner
    /// key must be attached to a real etcd lease (lease ID > 0).
    fn decode_owner_kv(
        &self,
        kv: &etcd_client::KeyValue,
    ) -> Result<PersistedOwner, EtcdCoordinatorError> {
        let binding = self.decode_owner_binding(EtcdOperation::Get, kv.value())?;
        if kv.lease() == 0 {
            return Err(EtcdCoordinatorError::Codec {
                operation: EtcdOperation::Get,
                source: EtcdCodecError::InvariantViolation {
                    kind: "OwnerKey",
                    detail: "owner key must be attached to a non-zero etcd lease",
                },
            });
        }
        Ok(PersistedOwner {
            binding,
            lease_id: kv.lease(),
        })
    }

    /// Verify that a persisted owner binding is consistent with the shard
    /// record's lease holder and fence epoch.
    ///
    /// Returns an invariant-violation error if the owner key exists but the
    /// shard record has no lease, or if the worker/fence fields disagree.
    fn validate_owner_consistency(
        owner: &PersistedOwner,
        record: &ShardRecord,
    ) -> Result<(), EtcdCoordinatorError> {
        let Some(holder) = record.lease() else {
            return Err(EtcdCoordinatorError::Codec {
                operation: EtcdOperation::Get,
                source: EtcdCodecError::InvariantViolation {
                    kind: "ShardRecord",
                    detail: "owner key exists but shard record lease is None",
                },
            });
        };
        if holder.owner() != owner.binding.worker || record.fence_epoch != owner.binding.fence {
            return Err(EtcdCoordinatorError::Codec {
                operation: EtcdOperation::Get,
                source: EtcdCodecError::InvariantViolation {
                    kind: "ShardRecord",
                    detail: "owner key binding disagrees with shard record lease or fence",
                },
            });
        }
        Ok(())
    }

    /// Load a single shard record and its owner binding by exact key.
    ///
    /// Uses a single prefix-range GET on the shard record key. Because
    /// shard IDs are fixed-width 16-char hex and the only child key is
    /// `/owner`, the prefix scan returns exactly the record KV and
    /// (optionally) the owner KV — no false matches against other shard
    /// IDs. Cross-validates the owner binding against the shard record's
    /// lease fields. Returns `None` if the shard record key does not exist.
    ///
    /// # Errors
    ///
    /// Returns [`EtcdCoordinatorError::Codec`] with an invariant violation
    /// if the owner key exists but disagrees with the shard record's
    /// lease holder or fence epoch.
    fn load_shard_record(
        &self,
        tenant: TenantId,
        key: ShardKey,
    ) -> Result<Option<PersistedShard>, EtcdCoordinatorError> {
        let shard_record_key = self
            .keyspace
            .shard_record_key(tenant, key.run(), key.shard());

        // Single prefix-range scan fetches both the shard record and its
        // `/owner` child key in one etcd RPC.
        let response = self.etcd_get(
            shard_record_key.clone().into_bytes(),
            Some(GetOptions::new().with_prefix()),
        )?;

        let mut record_kv: Option<&etcd_client::KeyValue> = None;
        let mut owner_kv: Option<&etcd_client::KeyValue> = None;

        for kv in response.kvs() {
            if kv.key() == shard_record_key.as_bytes() {
                record_kv = Some(kv);
            } else if kv.key().ends_with(b"/owner") {
                owner_kv = Some(kv);
            }
        }

        let Some(kv) = record_kv else {
            return Ok(None);
        };

        let mut slab = Self::make_decode_slab(kv.value().len());
        let record = decode_shard_record(kv.value(), &mut slab).map_err(|source| {
            EtcdCoordinatorError::Codec {
                operation: EtcdOperation::Get,
                source,
            }
        })?;
        let mod_revision = kv.mod_revision();

        let owner = match owner_kv {
            None => None,
            Some(okv) => Some(self.decode_owner_kv(okv)?),
        };

        if let Some(owner) = &owner {
            Self::validate_owner_consistency(owner, &record)?;
        }

        Ok(Some(PersistedShard {
            record,
            slab,
            mod_revision,
            owner,
        }))
    }

    /// Prefix-scan all shard records (and their `/owner` keys) under a run.
    ///
    /// Issues a single etcd prefix-range `get` on the `shards/` subtree,
    /// then partitions the response into record KVs and owner KVs.
    /// Owner bindings are matched to their parent shard record by
    /// key suffix convention (`{shard_key}/owner`).
    ///
    /// Cross-validates every owner binding against its shard record and
    /// rejects orphaned owner keys (owner with no matching shard record).
    fn scan_run_shards(
        &self,
        tenant: TenantId,
        run: RunId,
    ) -> Result<Vec<PersistedShard>, EtcdCoordinatorError> {
        let prefix = self
            .keyspace
            .shard_records_scan_prefix(tenant, run)
            .into_bytes();
        let response = self.etcd_get(prefix, Some(GetOptions::new().with_prefix()))?;

        let mut owner_map = HashMap::<Vec<u8>, PersistedOwner>::new();
        let mut record_kvs = Vec::<(Vec<u8>, Vec<u8>, i64)>::new();

        for kv in response.kvs() {
            if kv.key().ends_with(b"/owner") {
                let owner = self.decode_owner_kv(kv)?;
                owner_map.insert(kv.key().to_vec(), owner);
            } else {
                record_kvs.push((kv.key().to_vec(), kv.value().to_vec(), kv.mod_revision()));
            }
        }

        let mut out = Vec::with_capacity(record_kvs.len());
        for (record_key, value, mod_revision) in record_kvs {
            let mut slab = Self::make_decode_slab(value.len());
            let record = decode_shard_record(&value, &mut slab).map_err(|source| {
                EtcdCoordinatorError::Codec {
                    operation: EtcdOperation::Get,
                    source,
                }
            })?;

            let mut owner_key = record_key.clone();
            owner_key.extend_from_slice(b"/owner");
            let owner = owner_map.remove(&owner_key);

            if let Some(owner) = &owner {
                Self::validate_owner_consistency(owner, &record)?;
            }

            out.push(PersistedShard {
                record,
                slab,
                mod_revision,
                owner,
            });
        }

        if !owner_map.is_empty() {
            return Err(EtcdCoordinatorError::Codec {
                operation: EtcdOperation::Get,
                source: EtcdCodecError::InvariantViolation {
                    kind: "OwnerKey",
                    detail: "owner key exists without a corresponding shard record",
                },
            });
        }

        Ok(out)
    }

    /// Prefix-scan direct run records under a tenant, skipping shard and
    /// active-index descendants.
    ///
    /// Uses [`parse_direct_run_id_from_key`] to filter the prefix-range
    /// response down to immediate `runs/{hex}` children, ignoring deeper
    /// keys (`runs/{hex}/shards/…`, `runs_active/…`). Cross-validates that
    /// each decoded record's tenant and run ID match the key path. Results
    /// are sorted by raw run ID.
    fn scan_tenant_runs(
        &self,
        tenant: TenantId,
    ) -> Result<Vec<PersistedRun>, EtcdCoordinatorError> {
        let prefix = self.keyspace.run_records_scan_prefix(tenant);
        let response = self.etcd_get(
            prefix.as_bytes().to_vec(),
            Some(GetOptions::new().with_prefix()),
        )?;

        let mut out = Vec::new();
        for kv in response.kvs() {
            let Some(run_from_key) = parse_direct_run_id_from_key(&prefix, kv.key()) else {
                continue;
            };

            let record =
                decode_run_record(kv.value()).map_err(|source| EtcdCoordinatorError::Codec {
                    operation: EtcdOperation::Get,
                    source,
                })?;

            if record.tenant != tenant {
                return Err(EtcdCoordinatorError::Codec {
                    operation: EtcdOperation::Get,
                    source: EtcdCodecError::InvariantViolation {
                        kind: "RunRecord",
                        detail: "run record tenant disagrees with keyspace tenant",
                    },
                });
            }
            if record.run != run_from_key {
                return Err(EtcdCoordinatorError::Codec {
                    operation: EtcdOperation::Get,
                    source: EtcdCodecError::InvariantViolation {
                        kind: "RunRecord",
                        detail: "run record run id disagrees with key suffix",
                    },
                });
            }

            out.push(PersistedRun {
                record,
                mod_revision: kv.mod_revision(),
            });
        }

        out.sort_unstable_by_key(|persisted| persisted.record.run.as_raw());
        Ok(out)
    }

    /// Determine the effective observation time for `ShardFilter` evaluation.
    ///
    /// When a shard's owner is live at `now`, the observation time is `now`
    /// itself. When the owner's etcd key has been deleted (TTL expiry or
    /// explicit revocation), the shard's persisted lease deadline is used
    /// instead. This guarantees that expired leases appear expired in
    /// filter evaluations, even when the caller's `LogicalTime` value lags
    /// behind the actual deadline (e.g., in unit tests or skewed clocks).
    fn visible_now(persisted: &PersistedShard, now: LogicalTime) -> LogicalTime {
        if persisted.owner_is_live_at(now) {
            now
        } else {
            persisted.record.lease_deadline().unwrap_or(now)
        }
    }

    /// Lightweight capacity hint using count-only and keys-only RPCs.
    ///
    /// Returns an approximate count of active shards without an owner key,
    /// suitable for `CapacityHint`. Uses two etcd RPCs with minimal data
    /// transfer (no shard record values are decoded):
    ///
    /// 1. `count_only` on the `shards_active/` prefix → total active shards.
    /// 2. `keys_only` on the `shards/` prefix, counting `/owner` suffixes →
    ///    owned shard count.
    ///
    /// The result is approximate because the two RPCs are not transactional:
    /// a concurrent acquire between them may cause a brief undercount or
    /// overcount. This is acceptable for a capacity hint used in claim
    /// scheduling.
    ///
    /// `earliest_deadline` is always `None` because computing it would
    /// require decoding shard record values, defeating the purpose.
    fn count_available_lightweight(
        &self,
        tenant: TenantId,
        run: RunId,
    ) -> Result<CapacityHint, EtcdCoordinatorError> {
        let active_prefix = self.keyspace.shards_active_prefix(tenant, run).into_bytes();
        let active_response = self.etcd_get(
            active_prefix,
            Some(GetOptions::new().with_prefix().with_count_only()),
        )?;
        let total_active = u32::try_from(active_response.count()).unwrap_or_else(|_| {
            tracing::warn!(
                count = active_response.count(),
                "etcd active count exceeds u32 range; clamping to u32::MAX"
            );
            u32::MAX
        });

        let shards_prefix = self
            .keyspace
            .shard_records_scan_prefix(tenant, run)
            .into_bytes();
        let keys_response = self.etcd_get(
            shards_prefix,
            Some(GetOptions::new().with_prefix().with_keys_only()),
        )?;
        let owned_count = u32::try_from(
            keys_response
                .kvs()
                .iter()
                .filter(|kv| kv.key().ends_with(b"/owner"))
                .count(),
        )
        .unwrap_or(u32::MAX);

        Ok(CapacityHint {
            available_count: total_active.saturating_sub(owned_count),
            earliest_deadline: None,
        })
    }

    /// Count persisted shard records under `prefix` using a keys-only scan.
    ///
    /// The subtree contains run records, owner keys, and active indexes in
    /// addition to shard records, so the caller filters keys structurally.
    ///
    /// This is intentionally an O(N) preflight read. The backend does not yet
    /// maintain dedicated shard-count keys, and these paths are setup/lifecycle
    /// operations where correctness is more important than constant-time reads.
    fn count_persisted_shards_under_prefix(
        &self,
        prefix: String,
    ) -> Result<usize, EtcdCoordinatorError> {
        let response = self.etcd_get(
            prefix.into_bytes(),
            Some(GetOptions::new().with_prefix().with_keys_only()),
        )?;
        Ok(response
            .kvs()
            .iter()
            .filter(|kv| is_persisted_shard_record_key(kv.key()))
            .count())
    }

    /// Load current persisted shard counts for one tenant and for the whole
    /// backend.
    ///
    /// Unlike the in-memory backend's remove-mutate-restore flow, etcd reads
    /// the parent shard directly from storage, so the current counts already
    /// include the parent being split.
    fn current_shard_counts(
        &self,
        tenant: TenantId,
    ) -> Result<ShardCountSnapshot, EtcdCoordinatorError> {
        Ok(ShardCountSnapshot {
            tenant: self
                .count_persisted_shards_under_prefix(self.keyspace.tenant_prefix(tenant))?,
            total: self.count_persisted_shards_under_prefix(self.keyspace.tenants_prefix())?,
        })
    }

    /// List runs visible to workers by scanning only the active-run index.
    ///
    /// Initializing runs remain invisible until `register_shards` publishes
    /// the corresponding active-run marker.
    pub fn list_active_runs_into(
        &self,
        tenant: TenantId,
        out: &mut Vec<RunId>,
    ) -> Result<(), EtcdCoordinatorError> {
        let mut prefix = self.keyspace.runs_active_prefix(tenant);
        prefix.push('/');
        let response = self.etcd_get(
            prefix.as_bytes().to_vec(),
            Some(GetOptions::new().with_prefix().with_keys_only()),
        )?;

        out.clear();
        for kv in response.kvs() {
            if let Some(run) = parse_direct_run_id_from_key(&prefix, kv.key()) {
                out.push(run);
            }
        }
        out.sort_unstable_by_key(|run| run.as_raw());
        Ok(())
    }

    /// Garbage-collect stale runs that never left `Initializing`.
    ///
    /// Scans all runs under `tenant`, retains those that are still
    /// `Initializing` with `created_at < cutoff`, and attempts to delete
    /// each one. Each candidate is deleted behind a single CAS transaction
    /// guarded by the run revision and the absence of the active-run marker.
    /// A concurrently activated run simply fails the compare and is skipped.
    ///
    /// Deletion is total: the run record, any shard records, and any
    /// active-shard index entries are removed in a single transaction.
    /// Successfully deleted run IDs are appended to `out`.
    ///
    /// On error, `out` may contain a partial list of the runs that were
    /// successfully deleted before the failure. Callers must not rely on
    /// `out` contents when the return value is `Err`.
    pub fn gc_stale_initializing_runs_into(
        &mut self,
        tenant: TenantId,
        cutoff: LogicalTime,
        out: &mut Vec<RunId>,
    ) -> Result<(), EtcdCoordinatorError> {
        let mut candidates = self.scan_tenant_runs(tenant)?;
        candidates.retain(|persisted| {
            persisted.record.status == RunStatus::Initializing
                && persisted.record.created_at < cutoff
        });
        candidates.sort_by(|left, right| {
            left.record
                .created_at
                .cmp(&right.record.created_at)
                .then_with(|| left.record.run.as_raw().cmp(&right.record.run.as_raw()))
        });

        out.clear();
        for persisted in candidates {
            let run = persisted.record.run;
            let run_key = self.keyspace.run_record_key(tenant, run);
            let active_key = self.keyspace.run_active_index_key(tenant, run);
            let shard_prefix = self.keyspace.shard_records_scan_prefix(tenant, run);
            let mut active_shard_prefix = self.keyspace.shards_active_prefix(tenant, run);
            active_shard_prefix.push('/');

            let txn = Txn::new()
                .when(vec![
                    Self::compare_run_revision(run_key.clone(), persisted.mod_revision),
                    Self::compare_absent(active_key.clone()),
                ])
                .and_then(vec![
                    TxnOp::delete(run_key.into_bytes(), None),
                    TxnOp::delete(active_key.into_bytes(), None),
                    TxnOp::delete(
                        shard_prefix.into_bytes(),
                        Some(DeleteOptions::new().with_prefix()),
                    ),
                    TxnOp::delete(
                        active_shard_prefix.into_bytes(),
                        Some(DeleteOptions::new().with_prefix()),
                    ),
                ]);
            let response = self.etcd_txn(txn)?;
            if response.succeeded() {
                out.push(run);
            } else {
                tracing::debug!(
                    ?run,
                    "GC: skipped stale run (concurrent activation or revision change)"
                );
            }
        }

        Ok(())
    }

    /// Shared optimistic-CAS implementation for terminal run transitions
    /// (`complete_run`, `fail_run`, `cancel_run`).
    ///
    /// Each iteration:
    /// 1. Loads the run record and checks idempotent replay.
    /// 2. Validates status preconditions (e.g., `complete_run` requires
    ///    `Active`; `cancel_run` accepts both `Active` and `Initializing`).
    /// 3. Applies the terminal transition locally.
    /// 4. Commits the updated run record and deletes the active-run index
    ///    entry in a single CAS transaction.
    ///
    /// The active-run index guard adapts to the prior status: `Active` runs
    /// require the index entry to exist (`compare_present`), while
    /// `Initializing` runs require it to be absent (`compare_absent`). This
    /// prevents cancelling a run that was concurrently activated between the
    /// read and the write.
    ///
    /// On CAS exhaustion, re-reads the run to return the appropriate domain
    /// error or confirm idempotent replay.
    fn transition_run_terminal(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        op_id: OpId,
        op_kind: RunOpKind,
    ) -> Result<IdempotentOutcome<()>, RunTransitionError> {
        let (target_status, payload_hash, require_active) = match op_kind {
            RunOpKind::CompleteRun => (RunStatus::Done, hash_complete_run_payload(), true),
            RunOpKind::FailRun => (RunStatus::Failed, hash_fail_run_payload(), true),
            RunOpKind::CancelRun => (RunStatus::Cancelled, hash_cancel_run_payload(), false),
            RunOpKind::RegisterShards => {
                unreachable!("transition_run_terminal does not handle RegisterShards")
            }
        };

        self.cas_retry(
            |this, _attempt| {
                let persisted = match this.load_run_record(tenant, run) {
                    Ok(Some(run_record)) => run_record,
                    Ok(None) => return Err(RunTransitionError::RunNotFound),
                    Err(err) => {
                        return Err(RunTransitionError::BackendError {
                            message: format!("run_terminal.load_run: {err}"),
                        });
                    }
                };
                let prior_status = persisted.record.status;
                let mut record = persisted.record;

                if record.tenant != tenant {
                    return Err(RunTransitionError::TenantMismatch { expected: tenant });
                }
                if let Some(entry) = record.check_op_idempotency(op_id, payload_hash)? {
                    if entry.kind() != op_kind {
                        return Err(RunTransitionError::BackendError {
                            message: format!(
                                "idempotent replay kind mismatch: expected {op_kind:?}, got {:?}",
                                entry.kind()
                            ),
                        });
                    }
                    return Ok(CasOutcome::Committed(IdempotentOutcome::Replayed(())));
                }
                if record.status.is_terminal() {
                    return Err(RunTransitionError::RunTerminal {
                        status: record.status,
                    });
                }
                if require_active && record.status != RunStatus::Active {
                    return Err(RunTransitionError::WrongStatus {
                        status: record.status,
                        target: target_status,
                    });
                }

                apply_terminal_run_transition(
                    &mut record,
                    now,
                    target_status,
                    op_id,
                    op_kind,
                    payload_hash,
                );
                let run_blob = encode_run_record(&record);
                let run_key = this.keyspace.run_record_key(tenant, run);
                let active_key = this.keyspace.run_active_index_key(tenant, run);
                let mut compares = vec![Self::compare_run_revision(
                    run_key.clone(),
                    persisted.mod_revision,
                )];
                match prior_status {
                    RunStatus::Active => {
                        compares.push(Self::compare_present(active_key.clone()));
                    }
                    RunStatus::Initializing => {
                        compares.push(Self::compare_absent(active_key.clone()));
                    }
                    RunStatus::Done | RunStatus::Failed | RunStatus::Cancelled => {
                        unreachable!("terminal statuses return early")
                    }
                }

                let txn = Txn::new().when(compares).and_then(vec![
                    TxnOp::put(run_key.into_bytes(), run_blob, None),
                    TxnOp::delete(active_key.into_bytes(), None),
                ]);
                let response = match this.etcd_txn(txn) {
                    Ok(r) => r,
                    Err(err) => {
                        return Err(RunTransitionError::BackendError {
                            message: format!("run_terminal.txn: {err}"),
                        });
                    }
                };
                if response.succeeded() {
                    return Ok(CasOutcome::Committed(IdempotentOutcome::Executed(())));
                }
                Ok(CasOutcome::RetryNeeded)
            },
            |this| {
                let persisted = this.load_run_or_panic(tenant, run);
                if persisted.record.tenant != tenant {
                    return Err(RunTransitionError::TenantMismatch { expected: tenant });
                }
                if let Some(entry) = persisted.record.check_op_idempotency(op_id, payload_hash)? {
                    if entry.kind() != op_kind {
                        return Err(RunTransitionError::BackendError {
                            message: format!(
                                "idempotent replay kind mismatch: expected {op_kind:?}, got {:?}",
                                entry.kind()
                            ),
                        });
                    }
                    return Ok(IdempotentOutcome::Replayed(()));
                }
                if persisted.record.status.is_terminal() {
                    return Err(RunTransitionError::RunTerminal {
                        status: persisted.record.status,
                    });
                }
                if require_active && persisted.record.status != RunStatus::Active {
                    return Err(RunTransitionError::WrongStatus {
                        status: persisted.record.status,
                        target: target_status,
                    });
                }

                Err(RunTransitionError::BackendError {
                    message: "run_terminal: CAS retry budget exhausted".into(),
                })
            },
        )
    }

    // -----------------------------------------------------------------------
    // etcd CAS guard helpers
    // -----------------------------------------------------------------------
    //
    // Each helper builds one or more `Compare` clauses for an etcd
    // transaction. The transaction succeeds only if all comparisons pass;
    // failure means a concurrent writer modified the guarded key(s).

    /// CAS guard: shard record key has not been modified since `mod_revision`.
    fn compare_shard_revision(shard_record_key: String, mod_revision: i64) -> Compare {
        Compare::mod_revision(shard_record_key, CompareOp::Equal, mod_revision)
    }

    /// CAS guard: run record key has not been modified since `mod_revision`.
    fn compare_run_revision(run_record_key: String, mod_revision: i64) -> Compare {
        Compare::mod_revision(run_record_key, CompareOp::Equal, mod_revision)
    }

    /// CAS guard: the key must not exist (etcd version == 0).
    ///
    /// Used to ensure a shard or run record is being created for the first
    /// time, preventing double-registration.
    fn compare_absent(key: String) -> Compare {
        Compare::version(key, CompareOp::Equal, 0)
    }

    /// CAS guard: the key must already exist (etcd version > 0).
    fn compare_present(key: String) -> Compare {
        Compare::version(key, CompareOp::Greater, 0)
    }

    /// CAS guard: owner key must exist (version > 0) with the given value
    /// and be attached to the expected etcd lease.
    ///
    /// Returns three `Compare` clauses: existence, value equality, and
    /// lease identity. The lease check prevents a stale worker from
    /// passing the value guard after another worker reuses the same
    /// worker ID + fence epoch with a different etcd lease.
    fn compare_owner_present(
        owner_key: String,
        owner_value: Vec<u8>,
        lease_id: i64,
    ) -> [Compare; 3] {
        [
            Compare::version(owner_key.clone(), CompareOp::Greater, 0),
            Compare::value(owner_key.clone(), CompareOp::Equal, owner_value),
            Compare::lease(owner_key, CompareOp::Equal, lease_id),
        ]
    }

    /// Attempt to revoke an etcd lease, logging on failure.
    ///
    /// Used for cleanup after a CAS failure when the lease is no longer
    /// needed. If the revocation fails (e.g., network error), the lease
    /// will eventually expire via etcd's TTL mechanism. Failures are
    /// logged at `warn` level so operators can detect accumulation of
    /// orphaned leases during etcd instability.
    fn best_effort_revoke_lease(&self, lease_id: i64) {
        if lease_id <= 0 {
            return;
        }
        if let Err(err) = self.etcd_lease_revoke(lease_id) {
            tracing::warn!(
                lease_id,
                %err,
                ttl_secs = self.config.owner_lease_ttl_secs(),
                "failed to revoke etcd lease; will expire via TTL",
            );
        }
    }

    /// Load a run record, panicking if the key is missing or unreadable.
    ///
    /// Used in paths where the run is expected to exist (e.g., after
    /// a successful `create_run`).
    fn load_run_or_panic(&self, tenant: TenantId, run: RunId) -> PersistedRun {
        match self.load_run_record(tenant, run) {
            Ok(Some(run_record)) => run_record,
            Ok(None) => self.fatal_storage_error("load run", format!("run {run:?} missing")),
            Err(err) => self.fatal_storage_error("load run", err),
        }
    }

    /// Load a shard record, panicking if the key is missing or unreadable.
    fn load_shard_or_panic(&self, tenant: TenantId, key: ShardKey) -> PersistedShard {
        match self.load_shard_record(tenant, key) {
            Ok(Some(shard)) => shard,
            Ok(None) => self.fatal_storage_error("load shard", format!("shard {key:?} missing")),
            Err(err) => self.fatal_storage_error("load shard", err),
        }
    }

    /// Construct a new `ShardRecord` from registration input and encode it
    /// into a binary blob ready for etcd storage.
    fn build_root_shard_blob(
        &self,
        tenant: TenantId,
        run: RunId,
        cursor_semantics: gossip_coordination::CursorSemantics,
        input: &InitialShardInput<'_>,
    ) -> Result<Vec<u8>, RegisterShardsError> {
        let mut slab = ByteSlab::with_capacity(Self::build_slab_capacity_for_initial_shard(input));
        let record = ShardRecord::new_active_with_cursor(
            tenant,
            run,
            input.shard(),
            input.spec(),
            input.cursor(),
            cursor_semantics,
            &mut slab,
        )
        .map_err(|_| RegisterShardsError::ResourceExhausted {
            resource: "shard_slab",
        })?;

        Ok(encode_shard_record(&record, &slab)
            .unwrap_or_else(|err| self.fatal_storage_error("register_shards.encode_shard", err)))
    }

    /// Load the raw owner binding for a shard, returning the worker ID,
    /// fence epoch, and etcd lease ID. Test-only: used to verify ownership
    /// state in integration tests without going through the full
    /// `load_shard_record` path.
    #[cfg(test)]
    pub(crate) fn test_load_owner_binding(
        &self,
        tenant: TenantId,
        key: ShardKey,
    ) -> Result<Option<(WorkerId, FenceEpoch, i64)>, EtcdCoordinatorError> {
        let owner_key = self
            .keyspace
            .shard_owner_key(tenant, key.run(), key.shard())
            .into_bytes();
        let response = self.etcd_get(owner_key, None)?;
        let Some(kv) = response.kvs().first() else {
            return Ok(None);
        };
        let binding = self.decode_owner_binding(EtcdOperation::Get, kv.value())?;
        Ok(Some((binding.worker, binding.fence, kv.lease())))
    }

    /// Load a shard record and its backing slab, returning a `TestSlab`
    /// wrapper for assertion-friendly field access. Test-only.
    #[cfg(test)]
    pub(crate) fn test_load_shard_snapshot(
        &self,
        tenant: TenantId,
        key: ShardKey,
    ) -> Result<Option<(ShardRecord, TestSlab)>, EtcdCoordinatorError> {
        match self.load_shard_record(tenant, key)? {
            None => Ok(None),
            Some(persisted) => Ok(Some((
                persisted.record,
                TestSlab::from_slab(persisted.slab),
            ))),
        }
    }

    /// Overwrite a shard record in etcd, bypassing all CAS guards. Test-only:
    /// allows integration tests to seed states not yet reachable through the
    /// public API (e.g., `Parked` status while `park_shard` is unimplemented).
    #[cfg(test)]
    pub(crate) fn test_seed_shard_record(
        &self,
        record: &ShardRecord,
        slab: &ByteSlab,
    ) -> Result<(), EtcdCoordinatorError> {
        // Test helpers overwrite the shard record in place so integration
        // tests can seed states that are not otherwise reachable yet (for
        // example, a parked shard while `park_shard` remains fail-closed).
        let key = self
            .keyspace
            .shard_record_key(record.tenant, record.run, record.shard)
            .into_bytes();
        let value =
            encode_shard_record(record, slab).map_err(|source| EtcdCoordinatorError::Codec {
                operation: EtcdOperation::Put,
                source,
            })?;

        let mut client = self.client.clone();
        self.runtime
            .block_on(client.put(key, value, None))
            .map_err(|source| EtcdCoordinatorError::Etcd {
                operation: EtcdOperation::Put,
                source,
            })?;
        Ok(())
    }
}

impl fmt::Debug for EtcdCoordinator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EtcdCoordinator")
            .field("endpoint_count", &self.config.endpoints().len())
            .field("namespace_prefix", &self.keyspace.prefix())
            .field(
                "coordination_storage_mode",
                &"persisted acquire/renew/checkpoint/split/unpark + run lifecycle in etcd",
            )
            .finish()
    }
}

impl CoordinationBackend for EtcdCoordinator {
    /// Atomically take ownership of a shard, restoring its persisted state
    /// into `out`.
    ///
    /// Grants a new etcd lease, bumps the fence epoch, and commits both the
    /// updated shard record and a new `/owner` key in a single CAS
    /// transaction. On CAS failure (concurrent writer), retries with
    /// exponential backoff up to `optimistic_txn_retries`.
    ///
    /// The previous owner's etcd lease (if any) is revoked best-effort after
    /// a successful CAS. If the revocation fails, the old lease expires via
    /// etcd's TTL mechanism.
    ///
    /// # Errors
    ///
    /// - [`AcquireError::ShardNotFound`] — shard key does not exist in etcd.
    /// - [`AcquireError::ShardTerminal`] — shard is in a terminal status.
    /// - [`AcquireError::AlreadyLeased`] — another owner's lease is still
    ///   live at `now`.
    /// - [`AcquireError::TenantMismatch`] — persisted tenant differs from
    ///   the requested tenant.
    /// - [`AcquireError::BackendError`] — etcd RPC failure.
    fn acquire_and_restore_into<'a>(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        key: ShardKey,
        worker: WorkerId,
        out: &'a mut AcquireScratch,
    ) -> Result<AcquireResultView<'a>, AcquireError> {
        let mut shard_buf: Vec<u8> = Vec::with_capacity(2048);
        let mut owner_buf: Vec<u8> = Vec::with_capacity(32);

        // The closure returns intermediate owned data to avoid lifetime
        // conflicts between the closure's capture of `out` and the
        // returned `AcquireResultView` which borrows from `out`.
        let (persisted, lease, capacity) = self.cas_retry(
            |this, _attempt| {
                let persisted = match this.load_shard_record(tenant, key) {
                    Ok(Some(shard)) => shard,
                    Ok(None) => return Err(AcquireError::ShardNotFound { shard: key }),
                    Err(err) => {
                        return Err(AcquireError::BackendError {
                            message: format!("acquire.load_shard: {err}"),
                        });
                    }
                };

                if persisted.record.tenant != tenant {
                    return Err(AcquireError::TenantMismatch { expected: tenant });
                }
                if persisted.record.status != ShardStatus::Active {
                    return Err(AcquireError::ShardTerminal {
                        shard: key,
                        status: persisted.record.status,
                    });
                }
                if persisted.owner_is_live_at(now) {
                    return Err(AcquireError::AlreadyLeased {
                        current_owner: persisted
                            .record
                            .lease_owner()
                            .expect("live owner key must match shard record lease"),
                        lease_deadline: persisted
                            .record
                            .lease_deadline()
                            .expect("live owner key must match shard record deadline"),
                    });
                }

                let run_record = this.load_run_or_panic(tenant, key.run());
                let lease_duration = run_record.record.config.lease_duration();
                let new_deadline = now
                    .checked_add(lease_duration)
                    .unwrap_or(LogicalTime::from_raw(u64::MAX));
                let grant = match this.etcd_lease_grant(this.config.owner_lease_ttl_secs()) {
                    Ok(g) => g,
                    Err(err) => {
                        return Err(AcquireError::BackendError {
                            message: format!("acquire.lease_grant: {err}"),
                        });
                    }
                };
                let new_lease_id = grant.id();
                let prior_lease_id = persisted.owner.as_ref().map(|owner| owner.lease_id);

                let mut persisted = persisted;
                let new_fence = persisted.record.advance_fence();
                persisted.record.lease = Some(LeaseHolder::new(worker, new_deadline));
                persisted.record.assert_invariants(&persisted.slab);
                encode_shard_record_into(&persisted.record, &persisted.slab, &mut shard_buf)
                    .map_err(|err| {
                        this.best_effort_revoke_lease(new_lease_id);
                        AcquireError::BackendError {
                            message: format!("acquire.encode_shard: {err}"),
                        }
                    })?;
                encode_owner_value_into(worker, new_fence, &mut owner_buf);

                let shard_record_key =
                    this.keyspace
                        .shard_record_key(tenant, key.run(), key.shard());
                let owner_key = this
                    .keyspace
                    .shard_owner_key(tenant, key.run(), key.shard());
                let mut compares = vec![Self::compare_shard_revision(
                    shard_record_key.clone(),
                    persisted.mod_revision,
                )];
                if let Some(expected_owner) = persisted.expected_owner_value() {
                    let prior_etcd_lease = prior_lease_id
                        .expect("owner value present implies owner lease_id is known");
                    compares.extend(Self::compare_owner_present(
                        owner_key.clone(),
                        expected_owner,
                        prior_etcd_lease,
                    ));
                } else {
                    compares.push(Self::compare_absent(owner_key.clone()));
                }

                let txn = Txn::new().when(compares).and_then(vec![
                    TxnOp::put(shard_record_key.into_bytes(), shard_buf.clone(), None),
                    TxnOp::put(
                        owner_key.into_bytes(),
                        owner_buf.clone(),
                        Some(PutOptions::new().with_lease(new_lease_id)),
                    ),
                ]);
                let response = match this.etcd_txn(txn) {
                    Ok(r) => r,
                    Err(err) => {
                        this.best_effort_revoke_lease(new_lease_id);
                        return Err(AcquireError::BackendError {
                            message: format!("acquire.txn: {err}"),
                        });
                    }
                };
                if !response.succeeded() {
                    this.best_effort_revoke_lease(new_lease_id);
                    return Ok(CasOutcome::RetryNeeded);
                }

                if let Some(old_lease_id) = prior_lease_id {
                    this.best_effort_revoke_lease(old_lease_id);
                }
                let capacity = this
                    .count_available_lightweight(tenant, key.run())
                    .unwrap_or_else(|err| {
                        tracing::warn!(%err, "capacity hint unavailable; defaulting to zero");
                        CapacityHint::ZERO
                    });
                let lease = Lease::new(
                    tenant,
                    key.run(),
                    key.shard(),
                    worker,
                    new_fence,
                    new_deadline,
                );

                Ok(CasOutcome::Committed((persisted, lease, capacity)))
            },
            |this| {
                let persisted = this.load_shard_or_panic(tenant, key);
                if persisted.record.tenant != tenant {
                    return Err(AcquireError::TenantMismatch { expected: tenant });
                }
                if persisted.record.status != ShardStatus::Active {
                    return Err(AcquireError::ShardTerminal {
                        shard: key,
                        status: persisted.record.status,
                    });
                }
                if persisted.owner_is_live_at(now) {
                    return Err(AcquireError::AlreadyLeased {
                        current_owner: persisted
                            .record
                            .lease_owner()
                            .expect("live owner key must match record owner"),
                        lease_deadline: persisted
                            .record
                            .lease_deadline()
                            .expect("live owner key must match record deadline"),
                    });
                }

                this.fatal_storage_error(
                    "acquire.compare_retry_budget",
                    "compare contention did not converge",
                )
            },
        )?;

        out.reset();
        out.write_spec(
            persisted.record.spec.key_range_start(&persisted.slab),
            persisted.record.spec.key_range_end(&persisted.slab),
            persisted.record.spec.metadata(&persisted.slab),
        );
        out.write_cursor(
            persisted.record.cursor.last_key(&persisted.slab),
            persisted.record.cursor.token(&persisted.slab),
        );
        out.write_spawned_iter(persisted.record.spawned.iter(&persisted.slab));
        let snapshot = out.view(
            persisted.record.status,
            persisted.record.cursor_semantics,
            persisted.record.parent,
        );

        Ok(AcquireResultView {
            lease,
            snapshot,
            capacity,
        })
    }

    /// Extend a shard's logical lease deadline without changing ownership.
    ///
    /// Validates the presented lease (worker, fence epoch, deadline), then
    /// CAS-updates the shard record with a new deadline computed from the
    /// run's `lease_duration`. The etcd lease TTL is extended best-effort
    /// via `keep_alive` after the CAS succeeds.
    ///
    /// Unlike `acquire_and_restore_into`, renew does **not** bump the fence
    /// epoch or grant a new etcd lease — it reuses the existing owner binding.
    ///
    /// # Errors
    ///
    /// - [`RenewError::StaleFence`] — the persisted owner binding does not
    ///   match the presented lease's worker/fence.
    /// - [`RenewError::ShardNotFound`] — shard does not exist in etcd.
    /// - [`RenewError::BackendError`] — etcd RPC failure.
    fn renew(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        lease: &Lease,
    ) -> Result<RenewResult, RenewError> {
        let key = lease.shard_key();
        let mut shard_buf: Vec<u8> = Vec::with_capacity(2048);
        let mut owner_buf: Vec<u8> = Vec::with_capacity(32);

        self.cas_retry(
            |this, _attempt| {
                let persisted = match this.load_shard_record(tenant, key) {
                    Ok(Some(shard)) => shard,
                    Ok(None) => return Err(RenewError::ShardNotFound { shard: key }),
                    Err(err) => {
                        return Err(RenewError::BackendError {
                            message: format!("renew.load_shard: {err}"),
                        });
                    }
                };

                validate_lease(now, tenant, lease, &persisted.record)?;
                if !persisted.owner_matches_lease(lease) {
                    return Err(RenewError::StaleFence {
                        presented: lease.fence(),
                        current: persisted.record.fence_epoch,
                    });
                }

                let run_record = this.load_run_or_panic(tenant, key.run());
                let lease_duration = run_record.record.config.lease_duration();
                let new_deadline = now
                    .checked_add(lease_duration)
                    .unwrap_or(LogicalTime::from_raw(u64::MAX));

                let old_lease_id = persisted
                    .owner
                    .as_ref()
                    .map(|owner| owner.lease_id)
                    .expect("validated owner must exist");

                let mut persisted = persisted;
                persisted.record.lease = Some(LeaseHolder::new(lease.owner(), new_deadline));
                persisted.record.assert_invariants(&persisted.slab);
                encode_shard_record_into(&persisted.record, &persisted.slab, &mut shard_buf)
                    .map_err(|err| RenewError::BackendError {
                        message: format!("renew.encode_shard: {err}"),
                    })?;
                let owner = persisted
                    .owner
                    .as_ref()
                    .expect("validated owner must have binding");
                encode_owner_value_into(owner.binding.worker, owner.binding.fence, &mut owner_buf);

                let shard_record_key =
                    this.keyspace
                        .shard_record_key(tenant, key.run(), key.shard());
                let owner_key = this
                    .keyspace
                    .shard_owner_key(tenant, key.run(), key.shard());
                let mut compares = vec![Self::compare_shard_revision(
                    shard_record_key.clone(),
                    persisted.mod_revision,
                )];
                compares.extend(Self::compare_owner_present(
                    owner_key,
                    owner_buf.clone(),
                    old_lease_id,
                ));

                let txn = Txn::new().when(compares).and_then(vec![TxnOp::put(
                    shard_record_key.into_bytes(),
                    shard_buf.clone(),
                    None,
                )]);
                let response = match this.etcd_txn(txn) {
                    Ok(r) => r,
                    Err(err) => {
                        return Err(RenewError::BackendError {
                            message: format!("renew.txn: {err}"),
                        });
                    }
                };
                if response.succeeded() {
                    // Best-effort: extend the etcd lease TTL after the CAS
                    // succeeds. If the keep-alive fails, the CAS already
                    // committed the new deadline to the shard record.
                    if let Err(err) = this.etcd_lease_keep_alive_once(old_lease_id) {
                        tracing::warn!(
                            lease_id = old_lease_id,
                            %err,
                            "renew: failed to extend etcd lease TTL; \
                             logical deadline was committed but etcd lease may expire early",
                        );
                    }
                    let capacity = this
                        .count_available_lightweight(tenant, key.run())
                        .unwrap_or_else(|err| {
                            tracing::warn!(%err, "capacity hint unavailable; defaulting to zero");
                            CapacityHint::ZERO
                        });
                    return Ok(CasOutcome::Committed(RenewResult {
                        new_deadline,
                        capacity,
                    }));
                }
                Ok(CasOutcome::RetryNeeded)
            },
            |this| {
                let persisted = this.load_shard_or_panic(tenant, key);
                validate_lease(now, tenant, lease, &persisted.record)?;
                if !persisted.owner_matches_lease(lease) {
                    return Err(RenewError::StaleFence {
                        presented: lease.fence(),
                        current: persisted.record.fence_epoch,
                    });
                }

                this.fatal_storage_error(
                    "renew.compare_retry_budget",
                    "compare contention did not converge",
                )
            },
        )
    }

    /// Persist a new cursor position for an owned shard.
    ///
    /// Validates the lease, checks cursor monotonicity and bounds, then
    /// CAS-updates the shard record with the new cursor and an op-log
    /// entry. The owner key and its etcd lease are included as CAS
    /// preconditions but are not modified.
    ///
    /// Idempotent: replays with the same `op_id` and matching payload hash
    /// return [`IdempotentOutcome::Replayed`] without re-applying the
    /// cursor update.
    fn checkpoint(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        lease: &Lease,
        new_cursor: &CursorUpdate<'_>,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, CheckpointError> {
        let key = lease.shard_key();
        let payload_hash = hash_checkpoint_payload(new_cursor);
        let mut shard_buf: Vec<u8> = Vec::with_capacity(2048);
        let mut owner_buf: Vec<u8> = Vec::with_capacity(32);

        self.cas_retry(
            |this, _attempt| {
                let persisted = match this.load_shard_record(tenant, key) {
                    Ok(Some(shard)) => shard,
                    Ok(None) => return Err(CheckpointError::ShardNotFound { shard: key }),
                    Err(err) => {
                        return Err(CheckpointError::BackendError {
                            message: format!("checkpoint.load_shard: {err}"),
                        });
                    }
                };

                if check_op_idempotency(&persisted.record, op_id, payload_hash)?.is_some() {
                    return Ok(CasOutcome::Committed(IdempotentOutcome::Replayed(())));
                }
                validate_lease(now, tenant, lease, &persisted.record)?;
                if !persisted.owner_matches_lease(lease) {
                    return Err(CheckpointError::StaleFence {
                        presented: lease.fence(),
                        current: persisted.record.fence_epoch,
                    });
                }
                validate_cursor_update_pooled(
                    new_cursor,
                    persisted.record.cursor.last_key(&persisted.slab),
                    persisted.record.spec.key_range_start(&persisted.slab),
                    persisted.record.spec.key_range_end(&persisted.slab),
                )?;

                let mut persisted = persisted;
                persisted
                    .record
                    .cursor
                    .update_from_ref(new_cursor, &mut persisted.slab)?;
                persisted.record.op_log_push(OpLogEntry::new(
                    op_id,
                    OpKind::Checkpoint,
                    OpResult::Completed,
                    payload_hash,
                    now,
                ));
                persisted.record.assert_invariants(&persisted.slab);
                encode_shard_record_into(&persisted.record, &persisted.slab, &mut shard_buf)
                    .map_err(|err| CheckpointError::BackendError {
                        message: format!("checkpoint.encode_shard: {err}"),
                    })?;
                let owner = persisted
                    .owner
                    .as_ref()
                    .expect("validated owner must have binding");
                encode_owner_value_into(owner.binding.worker, owner.binding.fence, &mut owner_buf);
                let owner_lease_id = owner.lease_id;

                let shard_record_key =
                    this.keyspace
                        .shard_record_key(tenant, key.run(), key.shard());
                let owner_key = this
                    .keyspace
                    .shard_owner_key(tenant, key.run(), key.shard());
                let mut compares = vec![Self::compare_shard_revision(
                    shard_record_key.clone(),
                    persisted.mod_revision,
                )];
                compares.extend(Self::compare_owner_present(
                    owner_key,
                    owner_buf.clone(),
                    owner_lease_id,
                ));

                let txn = Txn::new().when(compares).and_then(vec![TxnOp::put(
                    shard_record_key.into_bytes(),
                    shard_buf.clone(),
                    None,
                )]);
                let response = match this.etcd_txn(txn) {
                    Ok(r) => r,
                    Err(err) => {
                        return Err(CheckpointError::BackendError {
                            message: format!("checkpoint.txn: {err}"),
                        });
                    }
                };
                if response.succeeded() {
                    return Ok(CasOutcome::Committed(IdempotentOutcome::Executed(())));
                }
                Ok(CasOutcome::RetryNeeded)
            },
            |this| {
                let persisted = this.load_shard_or_panic(tenant, key);
                if check_op_idempotency(&persisted.record, op_id, payload_hash)?.is_some() {
                    return Ok(IdempotentOutcome::Replayed(()));
                }
                validate_lease(now, tenant, lease, &persisted.record)?;
                if !persisted.owner_matches_lease(lease) {
                    return Err(CheckpointError::StaleFence {
                        presented: lease.fence(),
                        current: persisted.record.fence_epoch,
                    });
                }

                this.fatal_storage_error(
                    "checkpoint.compare_retry_budget",
                    "compare contention did not converge",
                )
            },
        )
    }

    /// Mark a shard as completed with a final cursor position.
    ///
    /// **Not yet implemented** — panics unconditionally. Remains fail-closed
    /// until the etcd transaction semantics for shard completion are defined.
    fn complete(
        &mut self,
        _now: LogicalTime,
        _tenant: TenantId,
        _lease: &Lease,
        _final_cursor: &CursorUpdate<'_>,
        _op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, CompleteError> {
        self.fail_unimplemented("complete")
    }

    /// Park a shard (temporarily suspend processing) for the given reason.
    ///
    /// **Not yet implemented** — panics unconditionally. Remains fail-closed
    /// until the etcd transaction semantics for shard parking are defined.
    fn park_shard(
        &mut self,
        _now: LogicalTime,
        _tenant: TenantId,
        _lease: &Lease,
        _reason: ParkReason,
        _op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, ParkError> {
        self.fail_unimplemented("park_shard")
    }

    /// Replace an owned shard with N child shards in a single atomic
    /// transaction.
    ///
    /// The parent transitions to `ShardStatus::Split` (terminal), its owner
    /// key and active-index entry are deleted, and each child is created as
    /// an unowned `Active` shard with its own active-index entry. The child
    /// IDs are deterministically derived from the parent identity, op_id,
    /// and spawned index via BLAKE3.
    ///
    /// The CAS transaction guards:
    /// - Parent shard record `mod_revision` (no concurrent mutation).
    /// - Owner key presence, value, and etcd lease ID (ownership proof).
    /// - Each child key absent (prevents double-creation and collision).
    ///
    /// On replay with the same `op_id`, recovers child IDs from the
    /// parent's permanent `spawned` lineage list.
    ///
    /// If CAS retries exhaust and all preconditions still hold, probes
    /// each derived child key for an existing record and returns
    /// `DerivedIdCollision` if found.
    fn split_replace(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        lease: &Lease,
        plan: SplitReplacePlan<'_>,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<SplitReplaceResult>, SplitReplaceError> {
        let key = lease.shard_key();
        let payload_hash = hash_split_replace_payload(&plan);

        // Pre-allocate Vecs outside the retry loop; cleared per iteration.
        let cap = self.config.max_children_per_op();
        let mut child_puts: Vec<TxnOp> = Vec::with_capacity(cap);
        let mut child_index_ops: Vec<TxnOp> = Vec::with_capacity(cap);
        let mut child_absent_compares: Vec<Compare> = Vec::with_capacity(cap);

        self.cas_retry(
            |this, _attempt| {
                let persisted = match this.load_shard_record(tenant, key) {
                    Ok(Some(shard)) => shard,
                    Ok(None) => return Err(SplitReplaceError::ShardNotFound { shard: key }),
                    Err(err) => {
                        return Err(SplitReplaceError::BackendError {
                            message: format!("split_replace.load_shard: {err}"),
                        });
                    }
                };

                if persisted.record.tenant != tenant {
                    return Err(SplitReplaceError::TenantMismatch { expected: tenant });
                }
                if check_op_idempotency(&persisted.record, op_id, payload_hash)?.is_some() {
                    let children = split_replace_replay_child_ids(
                        &persisted.record,
                        &persisted.slab,
                        plan.children().len(),
                    );
                    return Ok(CasOutcome::Committed(IdempotentOutcome::Replayed(
                        SplitReplaceResult { children },
                    )));
                }
                if persisted.record.status != ShardStatus::Active {
                    return Err(SplitReplaceError::ShardTerminal {
                        shard: key,
                        status: persisted.record.status,
                    });
                }
                validate_lease(now, tenant, lease, &persisted.record)?;
                if !persisted.owner_matches_lease(lease) {
                    return Err(SplitReplaceError::StaleFence {
                        presented: lease.fence(),
                        current: persisted.record.fence_epoch,
                    });
                }

                // Backend-specific fanout cap: reject before shared validation.
                let child_count = plan.children().len();
                if child_count > this.config.max_children_per_op() {
                    return Err(SplitReplaceError::SplitInvalid(
                        SplitValidationError::BackendChildLimitExceeded {
                            requested: child_count,
                            backend_max: this.config.max_children_per_op(),
                        },
                    ));
                }

                let sorted = split_replace_validate_preconditions(
                    &persisted.record,
                    &plan,
                    &persisted.slab,
                )?;
                let counts = this.current_shard_counts(tenant).map_err(|err| {
                    SplitReplaceError::BackendError {
                        message: format!("split_replace.count_shards: {err}"),
                    }
                })?;
                // The persisted count already includes the parent shard (it is
                // still stored in etcd). After split, the parent becomes terminal
                // (Split status) while N children are created, so the net growth
                // in live shards is N - 1, not N.
                if let Some(limit) = shard_limit_violation(
                    counts,
                    sorted.len().saturating_sub(1),
                    this.config.max_shards_per_tenant(),
                    this.config.max_total_shards(),
                ) {
                    return Err(SplitReplaceError::SplitInvalid(
                        SplitValidationError::ShardLimitExceeded {
                            current: limit.current,
                            additional: limit.additional,
                            max: limit.max,
                            scope: limit.scope,
                        },
                    ));
                }

                let mut child_ids = SplitChildIds::new();
                child_puts.clear();
                child_index_ops.clear();
                child_absent_compares.clear();

                for sorted_index in 0..sorted.len() {
                    let child = sorted.child(&plan, sorted_index);
                    let child_id = derive_split_shard_id(
                        persisted.record.run,
                        persisted.record.shard,
                        op_id,
                        DerivedShardKind::Child,
                        u32::try_from(persisted.record.spawned.len() + sorted_index)
                            .expect("child index exceeds u32"),
                    );
                    let mut child_slab = ByteSlab::with_capacity(
                        Self::build_slab_capacity_for_spec_and_cursor(child.spec(), child.cursor()),
                    );
                    let child_record = ShardRecord::new_split_child(
                        tenant,
                        persisted.record.run,
                        child_id,
                        child.spec(),
                        child.cursor(),
                        persisted.record.cursor_semantics,
                        persisted.record.shard,
                        &mut child_slab,
                    )?;
                    child_record.assert_invariants(&child_slab);

                    let child_record_key =
                        this.keyspace
                            .shard_record_key(tenant, persisted.record.run, child_id);
                    child_absent_compares.push(Self::compare_absent(child_record_key.clone()));
                    child_puts.push(TxnOp::put(
                        child_record_key.into_bytes(),
                        encode_shard_record(&child_record, &child_slab).unwrap_or_else(|err| {
                            this.fatal_storage_error("split_replace.encode_child", err)
                        }),
                        None,
                    ));
                    child_index_ops.push(TxnOp::put(
                        this.keyspace
                            .shard_active_index_key(tenant, persisted.record.run, child_id)
                            .into_bytes(),
                        Vec::new(),
                        None,
                    ));
                    child_ids.push(child_id);
                }

                let mut persisted = persisted;
                split_replace_apply_parent(
                    &mut persisted.record,
                    child_ids.as_slice(),
                    op_id,
                    payload_hash,
                    now,
                    &mut persisted.slab,
                )?;
                let parent_blob = encode_shard_record(&persisted.record, &persisted.slab)
                    .unwrap_or_else(|err| {
                        this.fatal_storage_error("split_replace.encode_parent", err)
                    });
                let owner_blob = persisted
                    .expected_owner_value()
                    .expect("validated owner must produce an owner value");
                let owner_lease_id = persisted
                    .owner
                    .as_ref()
                    .expect("validated owner must carry an etcd lease id")
                    .lease_id;

                let shard_record_key =
                    this.keyspace
                        .shard_record_key(tenant, key.run(), key.shard());
                let owner_key = this
                    .keyspace
                    .shard_owner_key(tenant, key.run(), key.shard());
                let mut compares = vec![Self::compare_shard_revision(
                    shard_record_key.clone(),
                    persisted.mod_revision,
                )];
                compares.extend(Self::compare_owner_present(
                    owner_key.clone(),
                    owner_blob,
                    owner_lease_id,
                ));
                compares.append(&mut child_absent_compares);

                // Atomically: update parent to Split status, delete its owner
                // and active-index keys, then create all child records and their
                // active-index entries.
                let mut ops = Vec::with_capacity(3 + child_puts.len() + child_index_ops.len());
                ops.push(TxnOp::put(shard_record_key.into_bytes(), parent_blob, None));
                ops.push(TxnOp::delete(owner_key.into_bytes(), None));
                ops.push(TxnOp::delete(
                    this.keyspace
                        .shard_active_index_key(tenant, key.run(), key.shard())
                        .into_bytes(),
                    None,
                ));
                ops.append(&mut child_puts);
                ops.append(&mut child_index_ops);

                let txn = Txn::new().when(compares).and_then(ops);
                let response = match this.etcd_txn(txn) {
                    Ok(r) => r,
                    Err(err) => {
                        return Err(SplitReplaceError::BackendError {
                            message: format!("split_replace.txn: {err}"),
                        });
                    }
                };
                if response.succeeded() {
                    return Ok(CasOutcome::Committed(IdempotentOutcome::Executed(
                        SplitReplaceResult {
                            children: child_ids,
                        },
                    )));
                }
                Ok(CasOutcome::RetryNeeded)
            },
            |this| {
                let persisted = this.load_shard_or_panic(tenant, key);
                if check_op_idempotency(&persisted.record, op_id, payload_hash)?.is_some() {
                    let children = split_replace_replay_child_ids(
                        &persisted.record,
                        &persisted.slab,
                        plan.children().len(),
                    );
                    return Ok(IdempotentOutcome::Replayed(SplitReplaceResult { children }));
                }
                if persisted.record.status != ShardStatus::Active {
                    return Err(SplitReplaceError::ShardTerminal {
                        shard: key,
                        status: persisted.record.status,
                    });
                }
                validate_lease(now, tenant, lease, &persisted.record)?;
                if !persisted.owner_matches_lease(lease) {
                    return Err(SplitReplaceError::StaleFence {
                        presented: lease.fence(),
                        current: persisted.record.fence_epoch,
                    });
                }

                // All standard preconditions still hold, yet the CAS failed
                // every attempt. The most likely non-transient cause is a
                // derived child key that already exists (hash collision). Probe
                // each derived child key and surface DerivedIdCollision if found.
                let sorted = split_replace_validate_preconditions(
                    &persisted.record,
                    &plan,
                    &persisted.slab,
                )?;
                for sorted_index in 0..sorted.len() {
                    let child_id = derive_split_shard_id(
                        persisted.record.run,
                        persisted.record.shard,
                        op_id,
                        DerivedShardKind::Child,
                        u32::try_from(persisted.record.spawned.len() + sorted_index)
                            .expect("child index exceeds u32"),
                    );
                    let child_key = ShardKey::new(persisted.record.run, child_id);
                    match this.load_shard_record(tenant, child_key) {
                        Ok(Some(_)) => {
                            return Err(SplitReplaceError::SplitInvalid(
                                SplitValidationError::DerivedIdCollision {
                                    derived_id: child_id,
                                },
                            ));
                        }
                        Ok(None) => {}
                        Err(err) => {
                            return Err(SplitReplaceError::BackendError {
                                message: format!("split_replace.collision_probe: {err}"),
                            });
                        }
                    }
                }

                this.fatal_storage_error(
                    "split_replace.compare_retry_budget",
                    "compare contention did not converge",
                )
            },
        )
    }

    /// Shrink an owned shard's key range and spawn a residual shard
    /// covering the removed range.
    ///
    /// Unlike `split_replace`, the parent remains `Active` and retains its
    /// owner binding. Only the parent's spec (key range) is narrowed and
    /// a single new residual shard is created. The residual starts unowned
    /// with an empty cursor.
    ///
    /// The CAS transaction guards:
    /// - Parent shard record `mod_revision`.
    /// - Owner key presence, value, and etcd lease ID.
    /// - Residual key absent (prevents double-creation).
    ///
    /// On replay, the residual ID is recovered from the parent's `spawned`
    /// lineage list (permanent, not bounded by the op-log). This means
    /// replays succeed even after the op-log entry has been evicted by
    /// subsequent operations.
    fn split_residual(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        lease: &Lease,
        plan: SplitResidualPlan<'_>,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<SplitResidualResult>, SplitResidualError> {
        let key = lease.shard_key();
        let payload_hash = hash_split_residual_payload(&plan);

        self.cas_retry(
            |this, _attempt| {
                let persisted = match this.load_shard_record(tenant, key) {
                    Ok(Some(shard)) => shard,
                    Ok(None) => return Err(SplitResidualError::ShardNotFound { shard: key }),
                    Err(err) => {
                        return Err(SplitResidualError::BackendError {
                            message: format!("split_residual.load_shard: {err}"),
                        });
                    }
                };

                if persisted.record.tenant != tenant {
                    return Err(SplitResidualError::TenantMismatch { expected: tenant });
                }
                if let Some(replay) = split_residual_check_replay(
                    &persisted.record,
                    op_id,
                    payload_hash,
                    &persisted.slab,
                )? {
                    return Ok(CasOutcome::Committed(replay));
                }
                if persisted.record.status != ShardStatus::Active {
                    return Err(SplitResidualError::ShardTerminal {
                        shard: key,
                        status: persisted.record.status,
                    });
                }
                split_residual_validate_preconditions(
                    now,
                    tenant,
                    lease,
                    &persisted.record,
                    &plan,
                    &persisted.slab,
                )?;
                let counts = this.current_shard_counts(tenant).map_err(|err| {
                    SplitResidualError::BackendError {
                        message: format!("split_residual.count_shards: {err}"),
                    }
                })?;
                if let Some(limit) = shard_limit_violation(
                    counts,
                    1,
                    this.config.max_shards_per_tenant(),
                    this.config.max_total_shards(),
                ) {
                    return Err(SplitResidualError::SplitInvalid(
                        SplitValidationError::ShardLimitExceeded {
                            current: limit.current,
                            additional: limit.additional,
                            max: limit.max,
                            scope: limit.scope,
                        },
                    ));
                }
                if !persisted.owner_matches_lease(lease) {
                    return Err(SplitResidualError::StaleFence {
                        presented: lease.fence(),
                        current: persisted.record.fence_epoch,
                    });
                }

                let residual_id = derive_split_shard_id(
                    persisted.record.run,
                    persisted.record.shard,
                    op_id,
                    DerivedShardKind::Residual,
                    u32::try_from(persisted.record.spawned.len())
                        .expect("spawned index exceeds u32"),
                );
                let mut residual_slab =
                    ByteSlab::with_capacity(Self::build_slab_capacity_for_spec_and_cursor(
                        plan.residual_spec(),
                        CursorUpdate::initial(),
                    ));
                let residual_record = split_residual_build_record(
                    &persisted.record,
                    tenant,
                    residual_id,
                    &plan,
                    &mut residual_slab,
                )?;
                residual_record.assert_invariants(&residual_slab);

                let residual_record_key =
                    this.keyspace
                        .shard_record_key(tenant, persisted.record.run, residual_id);

                let mut persisted = persisted;
                split_residual_apply_parent(
                    &mut persisted.record,
                    residual_id,
                    plan.parent_new_spec(),
                    op_id,
                    payload_hash,
                    now,
                    &mut persisted.slab,
                )?;
                let parent_blob = encode_shard_record(&persisted.record, &persisted.slab)
                    .unwrap_or_else(|err| {
                        this.fatal_storage_error("split_residual.encode_parent", err)
                    });
                let owner_blob = persisted
                    .expected_owner_value()
                    .expect("validated owner must produce an owner value");
                let owner_lease_id = persisted
                    .owner
                    .as_ref()
                    .expect("validated owner must carry an etcd lease id")
                    .lease_id;

                let shard_record_key =
                    this.keyspace
                        .shard_record_key(tenant, key.run(), key.shard());
                let owner_key = this
                    .keyspace
                    .shard_owner_key(tenant, key.run(), key.shard());
                let mut compares = vec![Self::compare_shard_revision(
                    shard_record_key.clone(),
                    persisted.mod_revision,
                )];
                compares.extend(Self::compare_owner_present(
                    owner_key,
                    owner_blob,
                    owner_lease_id,
                ));
                compares.push(Self::compare_absent(residual_record_key.clone()));

                let ops = vec![
                    TxnOp::put(shard_record_key.into_bytes(), parent_blob, None),
                    TxnOp::put(
                        residual_record_key.into_bytes(),
                        encode_shard_record(&residual_record, &residual_slab).unwrap_or_else(
                            |err| this.fatal_storage_error("split_residual.encode_residual", err),
                        ),
                        None,
                    ),
                    TxnOp::put(
                        this.keyspace
                            .shard_active_index_key(tenant, persisted.record.run, residual_id)
                            .into_bytes(),
                        Vec::new(),
                        None,
                    ),
                ];

                let txn = Txn::new().when(compares).and_then(ops);
                let response = match this.etcd_txn(txn) {
                    Ok(r) => r,
                    Err(err) => {
                        return Err(SplitResidualError::BackendError {
                            message: format!("split_residual.txn: {err}"),
                        });
                    }
                };
                if response.succeeded() {
                    return Ok(CasOutcome::Committed(IdempotentOutcome::Executed(
                        SplitResidualResult {
                            residual: residual_id,
                        },
                    )));
                }
                Ok(CasOutcome::RetryNeeded)
            },
            |this| {
                let persisted = this.load_shard_or_panic(tenant, key);
                if let Some(replay) = split_residual_check_replay(
                    &persisted.record,
                    op_id,
                    payload_hash,
                    &persisted.slab,
                )? {
                    return Ok(replay);
                }
                if persisted.record.status != ShardStatus::Active {
                    return Err(SplitResidualError::ShardTerminal {
                        shard: key,
                        status: persisted.record.status,
                    });
                }
                validate_lease(now, tenant, lease, &persisted.record)?;
                if !persisted.owner_matches_lease(lease) {
                    return Err(SplitResidualError::StaleFence {
                        presented: lease.fence(),
                        current: persisted.record.fence_epoch,
                    });
                }

                // All standard preconditions still hold, yet the CAS failed
                // every attempt. Check if the derived residual key already
                // exists (hash collision) and surface DerivedIdCollision if so.
                let residual_id = derive_split_shard_id(
                    persisted.record.run,
                    persisted.record.shard,
                    op_id,
                    DerivedShardKind::Residual,
                    u32::try_from(persisted.record.spawned.len())
                        .expect("spawned index exceeds u32"),
                );
                let residual_key = ShardKey::new(persisted.record.run, residual_id);
                match this.load_shard_record(tenant, residual_key) {
                    Ok(Some(_)) => {
                        return Err(SplitResidualError::SplitInvalid(
                            SplitValidationError::DerivedIdCollision {
                                derived_id: residual_id,
                            },
                        ));
                    }
                    Ok(None) => {}
                    Err(err) => {
                        return Err(SplitResidualError::BackendError {
                            message: format!("split_residual.collision_probe: {err}"),
                        });
                    }
                }

                this.fatal_storage_error(
                    "split_residual.compare_retry_budget",
                    "compare contention did not converge",
                )
            },
        )
    }
}

impl RunManagement for EtcdCoordinator {
    /// Create a new run in `Initializing` status.
    ///
    /// Uses a single CAS transaction guarded by key absence to prevent
    /// double-creation. No active-run index entry is published at this
    /// stage — the run becomes visible to workers only after
    /// `register_shards` transitions it to `Active`.
    fn create_run(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        config: RunConfig,
    ) -> Result<RunRecord, CreateRunError> {
        config.assert_valid();

        let record = RunRecord {
            tenant,
            run,
            config,
            status: RunStatus::Initializing,
            created_at: now,
            completed_at: None,
            root_shards: Vec::new(),
            op_log: RingBuffer::new(),
        };
        record.assert_invariants();

        let key = self.keyspace.run_record_key(tenant, run);
        let blob = encode_run_record(&record);
        let txn = Txn::new()
            .when(vec![Self::compare_absent(key.clone())])
            .and_then(vec![TxnOp::put(key.into_bytes(), blob, None)]);
        let response = match self.etcd_txn(txn) {
            Ok(r) => r,
            Err(err) => {
                return Err(CreateRunError::BackendError {
                    message: format!("create_run.txn: {err}"),
                });
            }
        };
        if response.succeeded() {
            return Ok(record);
        }

        Err(CreateRunError::RunAlreadyExists { run })
    }

    /// Atomically register root shards and activate the run.
    ///
    /// Performs all of the following in a single CAS transaction:
    /// 1. Validates the run is `Initializing` and the manifest is valid.
    /// 2. Checks shard-count limits (per-tenant and global).
    /// 3. Creates each shard record and its active-index entry.
    /// 4. Transitions the run to `Active`, records `root_shards`, and
    ///    publishes the active-run index entry.
    ///
    /// The batch size is capped at `MAX_SHARDS_PER_ETCD_TXN` (41) due
    /// to etcd's default `--max-txn-ops` limit of 128. Each shard
    /// contributes 3 operations (compare-absent, put-record,
    /// put-active-index), plus 3 fixed ops for the run record.
    ///
    /// Idempotent: replays return the shard IDs from the op-log.
    fn register_shards(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        shards: &[InitialShardInput<'_>],
        op_id: OpId,
    ) -> Result<IdempotentOutcome<Vec<ShardId>>, RegisterShardsError> {
        if shards.len() > MAX_SHARDS_PER_ETCD_TXN {
            return Err(RegisterShardsError::ResourceExhausted {
                resource: "etcd_txn_ops",
            });
        }

        let payload_hash = hash_register_shards_payload(shards);

        self.cas_retry(
            |this, _attempt| {
                let persisted_run = match this.load_run_record(tenant, run) {
                    Ok(Some(run_record)) => run_record,
                    Ok(None) => return Err(RegisterShardsError::RunNotFound),
                    Err(err) => {
                        return Err(RegisterShardsError::BackendError {
                            message: format!("register_shards.load_run: {err}"),
                        });
                    }
                };
                let mut run_record = persisted_run.record;

                if run_record.tenant != tenant {
                    return Err(RegisterShardsError::TenantMismatch { expected: tenant });
                }
                if let Some(entry) = run_record.check_op_idempotency(op_id, payload_hash)? {
                    if entry.kind() != RunOpKind::RegisterShards {
                        return Err(RegisterShardsError::BackendError {
                            message: format!(
                                "idempotent replay kind mismatch: expected RegisterShards, got {:?}",
                                entry.kind()
                            ),
                        });
                    }
                    match entry.result() {
                        RunOpResult::RegisteredShards { shard_ids } => {
                            return Ok(CasOutcome::Committed(IdempotentOutcome::Replayed(
                                shard_ids.to_vec(),
                            )));
                        }
                        RunOpResult::Ack => {
                            return Err(RegisterShardsError::BackendError {
                                message: format!(
                                    "run {run:?}: RegisterShards op-log entry has Ack result \
                                     (expected RegisteredShards) — data corruption"
                                ),
                            });
                        }
                    }
                }
                if run_record.status != RunStatus::Initializing {
                    return Err(RegisterShardsError::WrongStatus {
                        status: run_record.status,
                    });
                }

                validate_manifest(shards).map_err(RegisterShardsError::ManifestInvalid)?;

                let cursor_semantics = run_record.config.cursor_semantics();
                let shard_ids: Vec<ShardId> = shards.iter().map(InitialShardInput::shard).collect();
                let counts = this.current_shard_counts(tenant).map_err(|err| {
                    RegisterShardsError::BackendError {
                        message: format!("register_shards.count_shards: {err}"),
                    }
                })?;
                if let Some(limit) = shard_limit_violation(
                    counts,
                    shard_ids.len(),
                    this.config.max_shards_per_tenant(),
                    this.config.max_total_shards(),
                ) {
                    return Err(RegisterShardsError::ShardLimitExceeded {
                        current: limit.current,
                        additional: limit.additional,
                        max: limit.max,
                        scope: limit.scope,
                    });
                }

                let mut txn_ops = Vec::with_capacity(1 + (shards.len() * 2) + 1);
                let mut compares = Vec::with_capacity(1 + shards.len());
                let run_key = this.keyspace.run_record_key(tenant, run);
                compares.push(Self::compare_run_revision(
                    run_key.clone(),
                    persisted_run.mod_revision,
                ));

                for shard in shards {
                    let shard_key = this.keyspace.shard_record_key(tenant, run, shard.shard());
                    compares.push(Self::compare_absent(shard_key.clone()));
                    let shard_blob =
                        this.build_root_shard_blob(tenant, run, cursor_semantics, shard)?;
                    txn_ops.push(TxnOp::put(shard_key.into_bytes(), shard_blob, None));

                    let active_index =
                        this.keyspace
                            .shard_active_index_key(tenant, run, shard.shard());
                    txn_ops.push(TxnOp::put(
                        active_index.into_bytes(),
                        Vec::<u8>::new(),
                        None,
                    ));
                }

                run_record.assert_transition_legal(RunStatus::Active);
                run_record.status = RunStatus::Active;
                run_record.root_shards = shard_ids.clone();
                run_record.op_log_push(RunOpLogEntry::new(
                    op_id,
                    RunOpKind::RegisterShards,
                    payload_hash,
                    now,
                    RunOpResult::RegisteredShards {
                        shard_ids: shard_ids.clone().into_boxed_slice(),
                    },
                ));
                run_record.assert_invariants();
                let run_blob = encode_run_record(&run_record);

                txn_ops.insert(0, TxnOp::put(run_key.into_bytes(), run_blob, None));
                let run_active_key = this.keyspace.run_active_index_key(tenant, run);
                txn_ops.push(TxnOp::put(
                    run_active_key.into_bytes(),
                    Vec::<u8>::new(),
                    None,
                ));

                let txn = Txn::new().when(compares).and_then(txn_ops);
                let response = match this.etcd_txn(txn) {
                    Ok(r) => r,
                    Err(err) => {
                        return Err(RegisterShardsError::BackendError {
                            message: format!("register_shards.txn: {err}"),
                        });
                    }
                };
                if response.succeeded() {
                    return Ok(CasOutcome::Committed(IdempotentOutcome::Executed(
                        shard_ids,
                    )));
                }
                Ok(CasOutcome::RetryNeeded)
            },
            |this| {
                let persisted_run = this.load_run_or_panic(tenant, run);
                if let Some(entry) = persisted_run
                    .record
                    .check_op_idempotency(op_id, payload_hash)?
                {
                    match entry.result() {
                        RunOpResult::RegisteredShards { shard_ids } => {
                            return Ok(IdempotentOutcome::Replayed(shard_ids.to_vec()));
                        }
                        RunOpResult::Ack => {
                            panic!(
                                "Run {run:?}: RegisterShards op-log entry has Ack result \
                                 (expected RegisteredShards) — data corruption"
                            );
                        }
                    }
                }
                if persisted_run.record.status != RunStatus::Initializing {
                    return Err(RegisterShardsError::WrongStatus {
                        status: persisted_run.record.status,
                    });
                }

                this.fatal_storage_error(
                    "register_shards.compare_retry_budget",
                    "compare contention did not converge",
                )
            },
        )
    }

    /// Load a run record by exact key. Returns `GetRunError::RunNotFound` if
    /// the key does not exist. Validates tenant consistency.
    fn get_run(&self, tenant: TenantId, run: RunId) -> Result<RunRecord, GetRunError> {
        match self.load_run_record(tenant, run) {
            Ok(Some(persisted)) => {
                if persisted.record.tenant != tenant {
                    Err(GetRunError::TenantMismatch { expected: tenant })
                } else {
                    Ok(persisted.record)
                }
            }
            Ok(None) => Err(GetRunError::RunNotFound),
            Err(err) => Err(GetRunError::BackendError {
                message: format!("get_run.load: {err}"),
            }),
        }
    }

    /// Compute aggregate progress across all shards in a run.
    ///
    /// Performs a full prefix scan of all shard records under the run,
    /// observing each shard's status, ownership liveness, and cursor
    /// position. This is an O(shards) read operation.
    fn get_run_progress(
        &self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
    ) -> Result<RunProgress, GetRunError> {
        let _ = self.get_run(tenant, run)?;
        let shards =
            self.scan_run_shards(tenant, run)
                .map_err(|err| GetRunError::BackendError {
                    message: format!("get_run_progress.scan: {err}"),
                })?;

        let mut progress = RunProgress::default();
        for persisted in &shards {
            progress.observe_shard(
                persisted.record.status,
                persisted.owner_is_live_at(now),
                persisted.record.cursor.last_key(&persisted.slab),
            );
        }
        Ok(progress)
    }

    /// List shard summaries matching `filter`, sorted by key range start
    /// then shard ID.
    ///
    /// Performs a full prefix scan, decodes all shard records, applies the
    /// filter using `visible_now` for expired-lease visibility, and
    /// collects matching summaries into `out`.
    fn list_shards_into(
        &self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        filter: ShardFilter,
        out: &mut Vec<ShardSummary>,
    ) -> Result<(), GetRunError> {
        let _ = self.get_run(tenant, run)?;
        let shards =
            self.scan_run_shards(tenant, run)
                .map_err(|err| GetRunError::BackendError {
                    message: format!("list_shards_into.scan: {err}"),
                })?;

        out.clear();
        for persisted in &shards {
            let visible_now = Self::visible_now(persisted, now);
            if !filter.matches_record(&persisted.record, visible_now) {
                continue;
            }
            out.push(ShardSummary::from_record(
                &persisted.record,
                visible_now,
                &persisted.slab,
            ));
        }

        out.sort_by(|a, b| {
            a.key_range_start()
                .cmp(b.key_range_start())
                .then_with(|| a.shard().cmp(&b.shard()))
        });
        Ok(())
    }

    /// Collect shard IDs eligible for claiming (active and unowned).
    ///
    /// Uses two keys-only prefix scans instead of loading full shard
    /// record blobs:
    ///
    /// 1. **Active-index scan** — entries in `shards_active/` exist only
    ///    for `Active` shards, skipping terminal records entirely.
    /// 2. **Owner-key scan** — owner keys (`shards/{hex}/owner`) indicate
    ///    a live etcd-level owner binding. Their presence means the shard
    ///    is owned; absence means it is available for claiming.
    ///
    /// Active shards without an owner key are candidates. The earliest
    /// lease deadline among owned shards is not computed (would require
    /// loading full record blobs); `None` is returned instead. The
    /// caller ([`default_claim_next_available`]) handles `None`
    /// gracefully — per-shard acquire attempts refine the deadline as
    /// `AlreadyLeased` errors are encountered.
    ///
    /// The candidate list is sorted by shard ID for deterministic claim
    /// ordering.
    fn collect_claim_candidates_into(
        &self,
        _now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        candidates: &mut Vec<ShardId>,
    ) -> Result<Option<LogicalTime>, GetRunError> {
        let _ = self.get_run(tenant, run)?;

        // Phase 1: keys-only scan of the active-shard index.
        let mut active_prefix = self.keyspace.shards_active_prefix(tenant, run);
        active_prefix.push('/');
        let active_resp = self
            .etcd_get(
                active_prefix.as_bytes().to_vec(),
                Some(GetOptions::new().with_prefix().with_keys_only()),
            )
            .map_err(|err| GetRunError::BackendError {
                message: format!("collect_claim_candidates.active_scan: {err}"),
            })?;

        let active_ids: Vec<ShardId> = active_resp
            .kvs()
            .iter()
            .filter_map(|kv| parse_shard_id_from_index_key(&active_prefix, kv.key()))
            .collect();

        if active_ids.is_empty() {
            candidates.clear();
            return Ok(None);
        }

        // Phase 2: keys-only scan of the shard record prefix to discover
        // which active shards have a live `/owner` key.
        let shards_prefix = self.keyspace.shard_records_scan_prefix(tenant, run);
        let keys_resp = self
            .etcd_get(
                shards_prefix.as_bytes().to_vec(),
                Some(GetOptions::new().with_prefix().with_keys_only()),
            )
            .map_err(|err| GetRunError::BackendError {
                message: format!("collect_claim_candidates.keys_scan: {err}"),
            })?;

        let owned_ids: HashSet<ShardId> = keys_resp
            .kvs()
            .iter()
            .filter_map(|kv| parse_owned_shard_from_key(shards_prefix.as_bytes(), kv.key()))
            .collect();

        candidates.clear();
        for shard_id in &active_ids {
            if !owned_ids.contains(shard_id) {
                candidates.push(*shard_id);
            }
        }
        candidates.sort_unstable();

        Ok(None)
    }

    /// Transition an `Active` run to `Done`. Requires the active-run index
    /// entry to exist.
    fn complete_run(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, RunTransitionError> {
        self.transition_run_terminal(now, tenant, run, op_id, RunOpKind::CompleteRun)
    }

    /// Transition an `Active` run to `Failed`. Requires the active-run
    /// index entry to exist.
    fn fail_run(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, RunTransitionError> {
        self.transition_run_terminal(now, tenant, run, op_id, RunOpKind::FailRun)
    }

    /// Transition an `Initializing` or `Active` run to `Cancelled`.
    ///
    /// Unlike `complete_run` and `fail_run`, this accepts `Initializing`
    /// runs (which have no active-run index entry) as well as `Active`
    /// runs. The CAS transaction adapts its index-key guard accordingly.
    fn cancel_run(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, RunTransitionError> {
        self.transition_run_terminal(now, tenant, run, op_id, RunOpKind::CancelRun)
    }

    /// Re-activate a parked shard, making it available for claiming.
    ///
    /// Transitions the shard from `Parked` to `Active`, clears the park
    /// reason, bumps the fence epoch, and publishes a new active-shard
    /// index entry. No owner binding is created — the shard must be
    /// explicitly acquired after unparking.
    ///
    /// The CAS transaction guards:
    /// - Shard record `mod_revision` (no concurrent mutation).
    /// - Run record `mod_revision` and active-run index presence (run
    ///   must still be `Active`).
    /// - Owner key absent (parked shards must not have an owner).
    ///
    /// Idempotent via op-log replay.
    fn unpark_shard(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        key: ShardKey,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, UnparkError> {
        let payload_hash = hash_unpark_payload(&key);
        let mut shard_buf: Vec<u8> = Vec::with_capacity(2048);

        self.cas_retry(
            |this, _attempt| {
                let persisted = match this.load_shard_record(tenant, key) {
                    Ok(Some(shard)) => shard,
                    Ok(None) => return Err(UnparkError::ShardNotFound),
                    Err(err) => {
                        return Err(UnparkError::BackendError {
                            message: format!("unpark.load_shard: {err}"),
                        });
                    }
                };

                if persisted.record.tenant != tenant {
                    return Err(UnparkError::TenantMismatch { expected: tenant });
                }

                let persisted_run = match this.load_run_record(tenant, key.run()) {
                    Ok(Some(r)) => r,
                    Ok(None) => {
                        return Err(UnparkError::BackendError {
                            message: format!("unpark: run {:?} missing", key.run()),
                        });
                    }
                    Err(err) => {
                        return Err(UnparkError::BackendError {
                            message: format!("unpark.load_run: {err}"),
                        });
                    }
                };
                if persisted_run.record.tenant != tenant {
                    return Err(UnparkError::TenantMismatch { expected: tenant });
                }
                if persisted_run.record.status.is_terminal() {
                    return Err(UnparkError::RunTerminal {
                        status: persisted_run.record.status,
                    });
                }
                if persisted_run.record.status != RunStatus::Active {
                    return Err(UnparkError::BackendError {
                        message: format!(
                            "shard {key:?} belongs to non-active run (status: {:?})",
                            persisted_run.record.status
                        ),
                    });
                }

                if check_op_idempotency(&persisted.record, op_id, payload_hash)?.is_some() {
                    return Ok(CasOutcome::Committed(IdempotentOutcome::Replayed(())));
                }

                if persisted.record.status != ShardStatus::Parked {
                    return Err(UnparkError::NotParked {
                        status: persisted.record.status,
                    });
                }

                let mut persisted = persisted;
                persisted.record.advance_fence();
                persisted.record.park_reason = None;
                persisted.record.status = ShardStatus::Active;
                persisted.record.lease = None;
                persisted.record.op_log_push(OpLogEntry::new(
                    op_id,
                    OpKind::Unpark,
                    OpResult::Completed,
                    payload_hash,
                    now,
                ));
                persisted.record.assert_invariants(&persisted.slab);
                encode_shard_record_into(&persisted.record, &persisted.slab, &mut shard_buf)
                    .map_err(|err| UnparkError::BackendError {
                        message: format!("unpark.encode_shard: {err}"),
                    })?;

                let shard_record_key =
                    this.keyspace
                        .shard_record_key(tenant, key.run(), key.shard());
                let owner_key = this
                    .keyspace
                    .shard_owner_key(tenant, key.run(), key.shard());
                let run_key = this.keyspace.run_record_key(tenant, key.run());
                let run_active_key = this.keyspace.run_active_index_key(tenant, key.run());
                let active_shard_key =
                    this.keyspace
                        .shard_active_index_key(tenant, key.run(), key.shard());

                let txn = Txn::new()
                    .when(vec![
                        Self::compare_shard_revision(
                            shard_record_key.clone(),
                            persisted.mod_revision,
                        ),
                        Self::compare_run_revision(run_key, persisted_run.mod_revision),
                        Self::compare_present(run_active_key),
                        Self::compare_absent(owner_key),
                    ])
                    .and_then(vec![
                        TxnOp::put(shard_record_key.into_bytes(), shard_buf.clone(), None),
                        TxnOp::put(active_shard_key.into_bytes(), Vec::<u8>::new(), None),
                    ]);
                let response = match this.etcd_txn(txn) {
                    Ok(r) => r,
                    Err(err) => {
                        return Err(UnparkError::BackendError {
                            message: format!("unpark.txn: {err}"),
                        });
                    }
                };
                if response.succeeded() {
                    return Ok(CasOutcome::Committed(IdempotentOutcome::Executed(())));
                }
                Ok(CasOutcome::RetryNeeded)
            },
            |this| {
                let persisted = match this.load_shard_record(tenant, key) {
                    Ok(Some(s)) => s,
                    Ok(None) => return Err(UnparkError::ShardNotFound),
                    Err(err) => {
                        return Err(UnparkError::BackendError {
                            message: format!("unpark.exhaust.load_shard: {err}"),
                        });
                    }
                };
                if persisted.record.tenant != tenant {
                    return Err(UnparkError::TenantMismatch { expected: tenant });
                }
                let persisted_run = match this.load_run_record(tenant, key.run()) {
                    Ok(Some(r)) => r,
                    Ok(None) => {
                        return Err(UnparkError::BackendError {
                            message: format!("unpark.exhaust: run {:?} missing", key.run()),
                        });
                    }
                    Err(err) => {
                        return Err(UnparkError::BackendError {
                            message: format!("unpark.exhaust.load_run: {err}"),
                        });
                    }
                };
                if persisted_run.record.tenant != tenant {
                    return Err(UnparkError::TenantMismatch { expected: tenant });
                }
                if persisted_run.record.status.is_terminal() {
                    return Err(UnparkError::RunTerminal {
                        status: persisted_run.record.status,
                    });
                }
                if persisted_run.record.status != RunStatus::Active {
                    return Err(UnparkError::BackendError {
                        message: format!(
                            "shard {key:?} belongs to non-active run (status: {:?})",
                            persisted_run.record.status
                        ),
                    });
                }

                if check_op_idempotency(&persisted.record, op_id, payload_hash)?.is_some() {
                    return Ok(IdempotentOutcome::Replayed(()));
                }
                if persisted.record.status != ShardStatus::Parked {
                    return Err(UnparkError::NotParked {
                        status: persisted.record.status,
                    });
                }

                Err(UnparkError::BackendError {
                    message: "unpark: CAS retry budget exhausted".into(),
                })
            },
        )
    }
}

impl ShardClaiming for EtcdCoordinator {
    /// Claim the next available shard using the default round-robin
    /// strategy.
    ///
    /// Delegates to [`default_claim_next_available`], passing a reusable
    /// candidate buffer (`claim_candidates_scratch`) that is `mem::take`-ed
    /// before the call and restored afterward. This avoids per-claim heap
    /// allocation when the buffer capacity is already sufficient from a
    /// prior call.
    fn claim_next_available<'a>(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        worker: WorkerId,
        out: &'a mut AcquireScratch,
    ) -> Result<AcquireResultView<'a>, ClaimError> {
        let mut candidates = std::mem::take(&mut self.claim_candidates_scratch);
        let result =
            default_claim_next_available(self, now, tenant, run, worker, out, &mut candidates);
        // Shrink if capacity grew disproportionate to actual usage,
        // preventing unbounded growth from transient shard-count spikes.
        if candidates.capacity() > 1024 && candidates.len() < candidates.capacity() / 4 {
            candidates.shrink_to(candidates.len().max(256));
        }
        self.claim_candidates_scratch = candidates;
        result
    }
}
