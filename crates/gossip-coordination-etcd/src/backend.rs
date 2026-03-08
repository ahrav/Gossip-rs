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

use std::fmt;
use std::time::Duration;

use etcd_client::{Compare, CompareOp};
use gossip_contracts::coordination::shard_spec::{ShardLimitScope, ShardSpecRef};
use gossip_coordination::{
    ByteSlab, CursorSemantics, CursorUpdate, InitialShardInput, Lease, LogicalTime, OpId,
    RegisterShardsError, RunId, RunOpKind, RunOpLogEntry, RunOpResult, RunRecord, RunStatus,
    ShardId, ShardRecord, SplitChildIds, TenantId,
};

use crate::codec::{
    EtcdCodecError, OwnerLeaseValue, decode_owner_value, encode_owner_value, encode_shard_record,
};
use crate::error::{EtcdCoordinatorError, EtcdOperation};

mod coordinator;
mod run_management;
mod shard_coordination;
mod test_support;

#[cfg(any(test, feature = "test-support"))]
pub use self::test_support::{EtcdTestFault, EtcdTestShardSnapshot};
pub use coordinator::{AsyncEtcdCoordinator, EtcdCoordinator};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Minimum slab capacity allocated for decoding a shard record blob.
///
/// Ensures small blobs (e.g. a shard with empty key range and no metadata)
/// still get a workable slab for pooled field allocation without
/// triggering immediate `SlabFull`.
const MIN_DECODE_SLAB_CAPACITY: usize = 4 * 1024;

/// Maximum slab capacity allocated for decoding a shard record blob.
///
/// Caps the scaling heuristic in [`make_decode_slab`] to prevent a single
/// oversized blob from causing a disproportionate one-shot allocation.
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

// ---------------------------------------------------------------------------
// Shared types
// ---------------------------------------------------------------------------

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

impl Drop for PersistedShard {
    fn drop(&mut self) {
        self.record.deallocate_fields(&mut self.slab);
    }
}

// ---------------------------------------------------------------------------
// Free functions — key parsing, CAS delay, terminal transitions
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// De-duplicated helpers — shared by both EtcdCoordinator and
// AsyncEtcdCoordinator (previously identical associated functions on each)
// ---------------------------------------------------------------------------

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
    build_slab_capacity_for_spec_and_cursor(input.spec(), input.cursor())
}

/// Encode a shard record into a binary blob, then deallocate its pooled
/// fields and clear the slab. Panics via [`fatal_storage_error`] on
/// encode failure — encoding a just-constructed record should never fail
/// under normal operation; failure indicates a codec or invariant bug.
fn encode_ephemeral_shard_blob(
    context: &'static str,
    mut record: ShardRecord,
    mut slab: ByteSlab,
) -> Vec<u8> {
    let blob =
        encode_shard_record(&record, &slab).unwrap_or_else(|err| fatal_storage_error(context, err));
    record.deallocate_fields(&mut slab);
    slab.clear();
    blob
}

/// Construct a root shard record from registration input, validate its
/// invariants, and encode it into a binary blob ready for etcd storage.
///
/// Returns [`RegisterShardsError::ResourceExhausted`] if the slab cannot
/// accommodate the shard's pooled fields.
fn build_root_shard_blob(
    tenant: TenantId,
    run: RunId,
    cursor_semantics: CursorSemantics,
    input: &InitialShardInput<'_>,
) -> Result<Vec<u8>, RegisterShardsError> {
    let mut slab = ByteSlab::with_capacity(build_slab_capacity_for_initial_shard(input));
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
    record.assert_invariants(&slab);
    Ok(encode_ephemeral_shard_blob(
        "register_shards.encode_shard",
        record,
        slab,
    ))
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

// -- CAS guard helpers --

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
fn compare_owner_present(owner_key: String, owner_value: Vec<u8>, lease_id: i64) -> [Compare; 3] {
    [
        Compare::version(owner_key.clone(), CompareOp::Greater, 0),
        Compare::value(owner_key.clone(), CompareOp::Equal, owner_value),
        Compare::lease(owner_key, CompareOp::Equal, lease_id),
    ]
}

// -- Codec helpers --

/// Decode an owner-key blob, wrapping codec errors with the given
/// operation context.
fn decode_owner_binding(
    operation: EtcdOperation,
    bytes: &[u8],
) -> Result<OwnerLeaseValue, EtcdCoordinatorError> {
    decode_owner_value(bytes).map_err(|source| EtcdCoordinatorError::Codec { operation, source })
}

/// Decode an owner-key KV pair, validating the non-zero lease invariant.
///
/// Combines codec decoding with the structural check that every owner
/// key must be attached to a real etcd lease (lease ID > 0).
fn decode_owner_kv(kv: &etcd_client::KeyValue) -> Result<PersistedOwner, EtcdCoordinatorError> {
    let binding = decode_owner_binding(EtcdOperation::Get, kv.value())?;
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

/// Panics on an unrecoverable storage error.
///
/// Called when an etcd operation fails in a context where there is no
/// meaningful recovery (e.g., encoding a shard record that was just
/// successfully decoded). The panic message includes `context` for
/// diagnosis.
fn fatal_storage_error<T>(context: &'static str, err: impl fmt::Display) -> T {
    panic!("etcd coordination backend {context} failed: {err}");
}
