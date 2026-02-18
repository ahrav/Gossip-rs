//! Validation helpers for coordination operations.
//!
//! These pure, side-effect-free functions extract shared precondition checks
//! from the coordinator backend. Each returns `Result<(), CoordError>` (or
//! `Result<Option<&OpLogEntry>, CoordError>` for idempotency) so callers
//! can convert into operation-specific error types via `From<CoordError>`.
//!
//! ## Composition
//!
//! A lease-gated mutation (e.g. checkpoint, complete) typically chains:
//!
//! 1. **[`check_op_idempotency`]** — replay detection first, so replays
//!    succeed even after lease expiry or terminal status.
//! 2. **[`validate_lease`]** — tenant, terminal, fence, expiry checks.
//! 3. **Operation-specific validation** (e.g. [`validate_cursor_update`]
//!    for checkpoint).
//!
//! Step 1 is checked first on every idempotent path so that a successful
//! replay is never blocked by an expired lease or terminal status.
//! Step 2 is mandatory for every lease-gated path.
//!
//! ## Check ordering
//!
//! `validate_lease` checks in priority order:
//! 1. **Tenant isolation** — security-first; never leak cross-tenant info
//! 2. **Terminal status** — fast rejection of dead shards
//! 3. **Fence epoch** — zombie fencing
//! 4. **Lease expiry** — time-based rejection
//! 5. **Owner divergence** — catches identity mismatches when fence epochs agree
//!
//! This order ensures that a tenant-mismatch error never reveals whether
//! the shard is terminal, has a stale fence, or has an expired lease.
//!
//! ## Invariants
//!
//! - **Lease deadline existence:** When a caller's fence epoch matches the
//!   record's current fence epoch, the record's lease deadline MUST be `Some`.
//!   If it is `None`, the record is in an inconsistent state and `validate_lease`
//!   returns `StaleFence` to force re-acquisition (see check 4).

use crate::coordination::cursor::{Cursor, check_cursor_advance, check_cursor_bounds};
use crate::coordination::cursor::{CursorAdvance, CursorBoundsCheck};
use crate::coordination::error::CoordError;
use crate::coordination::lease::{Lease, OpLogEntry};
use crate::coordination::record::ShardRecord;
use crate::identity::{LogicalTime, OpId, ShardKey, TenantId};

/// Validate lease preconditions for a lease-gated operation.
///
/// Checks (in priority order):
/// 1. Tenant isolation — the provided `tenant` must match the record's tenant.
/// 2. Terminal status — terminal shards reject all mutations.
/// 3. Fence epoch — the lease's epoch must match the record's current epoch.
/// 4. Lease expiry — `now` must be before the record's lease deadline.
/// 5. Owner divergence — the lease's owner must match the record's current lease holder.
///
/// # Preconditions
///
/// The caller MUST have looked up the shard record by `ShardKey` before
/// calling this function. If the shard is not found, return
/// `CoordError::ShardNotFound` directly (this function cannot check that).
///
/// # Errors
///
/// Returns the first violated check as a `CoordError`.
pub fn validate_lease(
    now: LogicalTime,
    tenant: TenantId,
    lease: &Lease,
    record: &ShardRecord,
) -> Result<(), CoordError> {
    // Precondition: time must be positive. A zero timestamp indicates a
    // broken clock — this is a caller bug, not a protocol error.
    assert!(
        now > LogicalTime::ZERO,
        "validate_lease: now must be > ZERO"
    );

    // 1. Tenant isolation (SEC-1: no `actual` field).
    if record.tenant != tenant {
        return Err(CoordError::TenantMismatch { expected: tenant });
    }

    // 2. Terminal status.
    if record.status.is_terminal() {
        return Err(CoordError::ShardTerminal {
            shard: ShardKey::new(record.run, record.shard),
            status: record.status,
        });
    }

    // 3. Fence epoch.
    if lease.fence() != record.fence_epoch {
        return Err(CoordError::StaleFence {
            presented: lease.fence(),
            current: record.fence_epoch,
        });
    }

    // 4. Lease expiry. If the fence epoch check passed, the record
    // should have a lease holder. If it doesn't, the record is in
    // an inconsistent state — treat as stale so the caller re-acquires.
    let Some(deadline) = record.lease_deadline() else {
        return Err(CoordError::StaleFence {
            presented: lease.fence(),
            current: record.fence_epoch,
        });
    };
    if now >= deadline {
        return Err(CoordError::LeaseExpired { deadline, now });
    }

    // 5. Owner divergence. The fence epoch alone is the authoritative
    // guard, but a bug in lease-handoff or state reconstruction could
    // leave fence == current while the recorded owner differs. This
    // runtime check catches that class of logic error before the
    // mutation proceeds with the wrong identity.
    if record.lease_owner() != Some(lease.owner()) {
        return Err(CoordError::StaleFence {
            presented: lease.fence(),
            current: record.fence_epoch,
        });
    }

    // Postconditions: all checks passed.
    debug_assert!(record.tenant == tenant);
    debug_assert!(!record.status.is_terminal());
    debug_assert!(lease.fence() == record.fence_epoch);
    debug_assert!(record.is_leased_at(now));

    Ok(())
}

/// Validate a cursor update against the shard record's current cursor
/// and spec.
///
/// Checks:
/// 1. The new cursor has a `last_key` — an initial (keyless) cursor means
///    no data has been processed yet, so there is nothing to checkpoint.
/// 2. Monotonicity: `new.last_key >= old.last_key` (lexicographic).
/// 3. Bounds: `new.last_key ∈ [spec.start, spec.end)`.
///
/// # Preconditions
///
/// The caller MUST call [`validate_lease`] before this function on every
/// lease-gated code path. This function does not check lease validity.
///
/// # Errors
///
/// Returns the first violated check as a `CoordError`.
pub fn validate_cursor_update(new_cursor: &Cursor, record: &ShardRecord) -> Result<(), CoordError> {
    // 1. Key presence.
    if new_cursor.last_key().is_none() {
        return Err(CoordError::CheckpointMissingKey);
    }

    // 2. Monotonicity.
    match check_cursor_advance(&record.cursor, new_cursor) {
        CursorAdvance::Forward => { /* ok */ }
        CursorAdvance::Regression | CursorAdvance::ResetToNone => {
            return Err(CoordError::CursorRegression {
                old_key: record
                    .cursor
                    .last_key()
                    .map(|k| k.to_vec().into_boxed_slice()),
                new_key: new_cursor.last_key().map(|k| k.to_vec().into_boxed_slice()),
            });
        }
    }

    // 3. Bounds checking.
    match check_cursor_bounds(new_cursor, &record.spec) {
        CursorBoundsCheck::InBounds => { /* ok */ }
        CursorBoundsCheck::NoKey => {
            // We already checked last_key().is_some() above, so this
            // branch is unreachable. If it fires, our logic is wrong.
            unreachable!("CursorBoundsCheck::NoKey after last_key presence check");
        }
        CursorBoundsCheck::BelowRange | CursorBoundsCheck::AboveRange => {
            let last_key = new_cursor
                .last_key()
                .expect("last_key validated as Some in check 1")
                .to_vec()
                .into_boxed_slice();
            return Err(CoordError::CursorOutOfBounds(Box::new(
                crate::coordination::error::CursorOutOfBoundsDetail {
                    last_key,
                    spec_start: record.spec.key_range_start().to_vec().into_boxed_slice(),
                    spec_end: record.spec.key_range_end().to_vec().into_boxed_slice(),
                },
            )));
        }
    }

    // Postcondition.
    debug_assert!(new_cursor.last_key().is_some());

    Ok(())
}

/// Check whether an operation is a replay (idempotent retry) or a new
/// operation.
///
/// - Returns `Ok(None)` if the `OpId` is not in the op-log (new operation).
/// - Returns `Ok(Some(entry))` if the `OpId` is found and the payload hash
///   matches (idempotent replay — return the cached result).
/// - Returns `Err(CoordError::OpIdConflict)` if the `OpId` is found but
///   the payload hash differs (mutation conflict — reject).
///
/// # Preconditions
///
/// The caller MUST call [`validate_lease`] before this function on every
/// lease-gated code path. This function does not check lease validity.
///
/// `payload_hash` must be non-zero; a zero hash indicates the caller
/// failed to compute a hash (see `OpLogEntry::new` assertion).
///
/// # Op-log capacity
///
/// The op-log is bounded to [`ShardRecord::OP_LOG_CAP`] entries. If an
/// `OpId` has been evicted from the log, this function returns `Ok(None)`
/// (treats it as new). Callers rely on the fence epoch as the primary
/// deduplication guard; the op-log is a secondary defense for in-lease
/// retries only.
///
/// # Errors
///
/// Returns `CoordError::OpIdConflict` if the `OpId` was previously used
/// with a different payload hash.
pub fn check_op_idempotency(
    record: &ShardRecord,
    op_id: OpId,
    payload_hash: u64,
) -> Result<Option<&OpLogEntry>, CoordError> {
    // Precondition: payload hash must be non-zero. A zero hash indicates
    // broken hashing — this is a caller bug, not a protocol error.
    assert!(
        payload_hash != 0,
        "check_op_idempotency: payload_hash must be non-zero"
    );

    let Some(entry) = record.op_log_lookup(op_id) else {
        return Ok(None);
    };

    if entry.payload_hash() == payload_hash {
        Ok(Some(entry))
    } else {
        Err(CoordError::OpIdConflict {
            op_id,
            expected_hash: entry.payload_hash(),
            actual_hash: payload_hash,
        })
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;
    use crate::coordination::cursor::Cursor;
    use crate::coordination::lease::{LeaseHolder, OpKind, OpResult};
    use crate::coordination::record::ShardRecord;
    use crate::coordination::shard_spec::{CursorSemantics, ShardSpec};
    use crate::identity::{FenceEpoch, LogicalTime, OpId, RunId, ShardId, TenantId, WorkerId};

    // -- Test fixtures ---------------------------------------------------

    fn test_tenant() -> TenantId {
        TenantId::from_bytes([0x01; 32])
    }

    fn other_tenant() -> TenantId {
        TenantId::from_bytes([0x02; 32])
    }

    fn test_run() -> RunId {
        RunId::from_raw(1)
    }

    fn test_shard() -> ShardId {
        ShardId::from_raw(10)
    }

    fn test_spec() -> ShardSpec {
        ShardSpec::with_range(b"a".to_vec(), b"z".to_vec())
    }

    /// Active record, no lease, fence=INITIAL.
    fn active_unleased_record() -> ShardRecord {
        ShardRecord::new_active(
            test_tenant(),
            test_run(),
            test_shard(),
            test_spec(),
            CursorSemantics::Completed,
        )
    }

    /// Active record, leased (owner=99, fence=2, deadline=100).
    fn active_leased_record() -> ShardRecord {
        let r = ShardRecord::from_raw_parts(
            test_tenant(),
            test_run(),
            test_shard(),
            crate::coordination::record::ShardStatus::Active,
            None,
            test_spec(),
            Cursor::initial(),
            CursorSemantics::Completed,
            Some(LeaseHolder::new(
                WorkerId::from_raw(99),
                LogicalTime::from_raw(100),
            )),
            FenceEpoch::from_raw(2),
            None,
            vec![],
            vec![],
        );
        r.assert_invariants();
        r
    }

    /// A lease matching the leased record.
    fn valid_lease_for(record: &ShardRecord) -> Lease {
        Lease::new(
            record.tenant,
            record.run,
            record.shard,
            record.lease_owner().expect("record must be leased"),
            record.fence_epoch,
            record.lease_deadline().expect("record must have deadline"),
        )
    }

    // -- validate_lease: basic tests -------------------------------------

    #[test]
    fn validate_lease_ok() {
        let record = active_leased_record();
        let lease = valid_lease_for(&record);
        let now = LogicalTime::from_raw(50); // before deadline=100
        assert!(validate_lease(now, test_tenant(), &lease, &record).is_ok());
    }

    #[test]
    fn validate_lease_tenant_mismatch() {
        let record = active_leased_record();
        let lease = valid_lease_for(&record);
        let now = LogicalTime::from_raw(50);
        let result = validate_lease(now, other_tenant(), &lease, &record);
        assert!(
            matches!(result, Err(CoordError::TenantMismatch { .. })),
            "expected TenantMismatch, got {result:?}"
        );
    }

    #[test]
    fn validate_lease_terminal_shard() {
        let mut record = active_leased_record();
        record.status = crate::coordination::record::ShardStatus::Done;
        record.lease = None; // terminal shards don't hold leases
        let lease = Lease::new(
            test_tenant(),
            test_run(),
            test_shard(),
            WorkerId::from_raw(99),
            record.fence_epoch,
            LogicalTime::from_raw(100),
        );
        let now = LogicalTime::from_raw(50);
        let result = validate_lease(now, test_tenant(), &lease, &record);
        assert!(
            matches!(result, Err(CoordError::ShardTerminal { .. })),
            "expected ShardTerminal, got {result:?}"
        );
    }

    #[test]
    fn validate_lease_stale_fence() {
        let record = active_leased_record();
        // Create a lease with an outdated fence.
        let stale_lease = Lease::new(
            test_tenant(),
            test_run(),
            test_shard(),
            WorkerId::from_raw(99),
            FenceEpoch::INITIAL, // record has fence=2
            LogicalTime::from_raw(100),
        );
        let now = LogicalTime::from_raw(50);
        let result = validate_lease(now, test_tenant(), &stale_lease, &record);
        assert!(
            matches!(result, Err(CoordError::StaleFence { .. })),
            "expected StaleFence, got {result:?}"
        );
    }

    #[test]
    fn validate_lease_expired() {
        let record = active_leased_record();
        let lease = valid_lease_for(&record);
        let now = LogicalTime::from_raw(200); // after deadline=100
        let result = validate_lease(now, test_tenant(), &lease, &record);
        assert!(
            matches!(result, Err(CoordError::LeaseExpired { .. })),
            "expected LeaseExpired, got {result:?}"
        );
    }

    #[test]
    fn validate_lease_no_lease_returns_stale_fence() {
        // Active record with INITIAL fence and no lease holder.
        let record = active_unleased_record();
        // Caller presents a lease with INITIAL fence (matches record).
        let lease = Lease::new(
            test_tenant(),
            test_run(),
            test_shard(),
            WorkerId::from_raw(1),
            FenceEpoch::INITIAL,
            LogicalTime::from_raw(100),
        );
        let now = LogicalTime::from_raw(50);
        let result = validate_lease(now, test_tenant(), &lease, &record);
        assert!(
            matches!(
                result,
                Err(CoordError::StaleFence {
                    presented,
                    current,
                }) if presented == FenceEpoch::INITIAL && current == FenceEpoch::INITIAL
            ),
            "unleased record with matching fence should return StaleFence, got {result:?}"
        );
    }

    #[test]
    fn validate_lease_owner_divergence_returns_stale_fence() {
        let record = active_leased_record(); // owner=99, fence=2
        // Create a lease with matching fence but different owner.
        let lease = Lease::new(
            test_tenant(),
            test_run(),
            test_shard(),
            WorkerId::from_raw(999), // different owner
            record.fence_epoch,
            record.lease_deadline().unwrap(),
        );
        let now = LogicalTime::from_raw(50);
        let result = validate_lease(now, test_tenant(), &lease, &record);
        assert!(
            matches!(result, Err(CoordError::StaleFence { .. })),
            "owner divergence should return StaleFence, got {result:?}"
        );
    }

    // -- validate_lease: precondition tests --------------------------------

    #[test]
    #[should_panic(expected = "now must be > ZERO")]
    fn validate_lease_panics_on_zero_time() {
        let record = active_leased_record();
        let lease = valid_lease_for(&record);
        let _ = validate_lease(LogicalTime::ZERO, test_tenant(), &lease, &record);
    }

    // -- validate_lease: error priority ordering --------------------------
    // Table-driven test covering all C(4,2)+C(4,3)+C(4,4) = 11 multi-
    // condition combinations. Verifies the documented check priority:
    //   TenantMismatch > ShardTerminal > StaleFence > LeaseExpired

    #[rstest]
    #[case::tenant_over_terminal(true, true, false, false, "TenantMismatch")]
    #[case::tenant_over_fence(true, false, true, false, "TenantMismatch")]
    #[case::tenant_over_expired(true, false, false, true, "TenantMismatch")]
    #[case::terminal_over_fence(false, true, true, false, "ShardTerminal")]
    #[case::terminal_over_expired(false, true, false, true, "ShardTerminal")]
    #[case::fence_over_expired(false, false, true, true, "StaleFence")]
    #[case::triple_tenant_terminal_fence(true, true, true, false, "TenantMismatch")]
    #[case::triple_tenant_terminal_expired(true, true, false, true, "TenantMismatch")]
    #[case::triple_tenant_fence_expired(true, false, true, true, "TenantMismatch")]
    #[case::triple_terminal_fence_expired(false, true, true, true, "ShardTerminal")]
    #[case::all_four(true, true, true, true, "TenantMismatch")]
    fn validate_lease_error_priority_ordering(
        #[case] wrong_tenant: bool,
        #[case] terminal: bool,
        #[case] stale_fence: bool,
        #[case] expired: bool,
        #[case] expected: &str,
    ) {
        let mut record = active_leased_record();
        let valid_fence = record.fence_epoch;

        if wrong_tenant {
            record.tenant = other_tenant();
        }
        if terminal {
            record.status = crate::coordination::record::ShardStatus::Done;
            record.lease = None;
        }

        let lease = Lease::new(
            test_tenant(),
            test_run(),
            test_shard(),
            WorkerId::from_raw(99),
            if stale_fence {
                FenceEpoch::INITIAL
            } else {
                valid_fence
            },
            LogicalTime::from_raw(100),
        );

        let now = if expired {
            LogicalTime::from_raw(200)
        } else {
            LogicalTime::from_raw(50)
        };

        let result = validate_lease(now, test_tenant(), &lease, &record);
        let err = result.unwrap_err();
        let actual = match &err {
            CoordError::TenantMismatch { .. } => "TenantMismatch",
            CoordError::ShardTerminal { .. } => "ShardTerminal",
            CoordError::StaleFence { .. } => "StaleFence",
            CoordError::LeaseExpired { .. } => "LeaseExpired",
            other => panic!("unexpected error: {other:?}"),
        };
        assert_eq!(actual, expected);
    }

    // -- validate_lease: boundary tests ----------------------------------

    #[test]
    fn validate_lease_expired_at_exact_deadline() {
        let record = active_leased_record(); // deadline=100
        let lease = valid_lease_for(&record);
        let now = LogicalTime::from_raw(100); // exactly at deadline
        let result = validate_lease(now, test_tenant(), &lease, &record);
        assert!(
            matches!(result, Err(CoordError::LeaseExpired { .. })),
            "now == deadline should be expired (half-open interval)"
        );
    }

    #[test]
    fn validate_lease_valid_one_tick_before_deadline() {
        let record = active_leased_record(); // deadline=100
        let lease = valid_lease_for(&record);
        let now = LogicalTime::from_raw(99); // one tick before deadline
        assert!(validate_lease(now, test_tenant(), &lease, &record).is_ok());
    }

    // -- validate_cursor_update tests ------------------------------------

    #[test]
    fn validate_cursor_update_ok_first_checkpoint() {
        let record = active_unleased_record(); // cursor=initial
        let new_cursor = Cursor::with_last_key(b"f".to_vec());
        assert!(validate_cursor_update(&new_cursor, &record).is_ok());
    }

    #[test]
    fn validate_cursor_update_ok_forward() {
        let mut record = active_unleased_record();
        record.cursor = Cursor::with_last_key(b"f".to_vec());
        let new_cursor = Cursor::with_last_key(b"m".to_vec());
        assert!(validate_cursor_update(&new_cursor, &record).is_ok());
    }

    #[test]
    fn validate_cursor_update_missing_key() {
        let record = active_unleased_record();
        let new_cursor = Cursor::initial(); // no last_key
        let result = validate_cursor_update(&new_cursor, &record);
        assert!(matches!(result, Err(CoordError::CheckpointMissingKey)));
    }

    #[test]
    fn validate_cursor_update_regression() {
        let mut record = active_unleased_record();
        record.cursor = Cursor::with_last_key(b"m".to_vec());
        let new_cursor = Cursor::with_last_key(b"f".to_vec()); // regression
        let result = validate_cursor_update(&new_cursor, &record);
        assert!(matches!(result, Err(CoordError::CursorRegression { .. })));
    }

    #[test]
    fn validate_cursor_update_below_range() {
        // spec range is [a, z), cursor at byte 0x00 which is below 'a'.
        let record = active_unleased_record();
        let new_cursor = Cursor::with_last_key(vec![0x00]);
        let result = validate_cursor_update(&new_cursor, &record);
        assert!(
            matches!(result, Err(CoordError::CursorOutOfBounds(_))),
            "expected CursorOutOfBounds, got {result:?}"
        );
    }

    #[test]
    fn validate_cursor_update_above_range() {
        // spec range is [a, z), cursor at 'z' (exclusive end).
        let record = active_unleased_record();
        let new_cursor = Cursor::with_last_key(b"z".to_vec());
        let result = validate_cursor_update(&new_cursor, &record);
        assert!(
            matches!(result, Err(CoordError::CursorOutOfBounds(_))),
            "expected CursorOutOfBounds, got {result:?}"
        );
    }

    // -- validate_cursor_update: boundary tests --------------------------

    #[test]
    fn validate_cursor_update_idempotent_same_key() {
        let mut record = active_unleased_record();
        record.cursor = Cursor::with_last_key(b"f".to_vec());
        let new_cursor = Cursor::with_last_key(b"f".to_vec()); // same key
        assert!(
            validate_cursor_update(&new_cursor, &record).is_ok(),
            "same key should be Forward (idempotent)"
        );
    }

    #[test]
    fn validate_cursor_update_key_at_spec_start() {
        let record = active_unleased_record(); // spec [a, z)
        let new_cursor = Cursor::with_last_key(b"a".to_vec()); // at start (inclusive)
        assert!(
            validate_cursor_update(&new_cursor, &record).is_ok(),
            "key at spec start should be InBounds (inclusive)"
        );
    }

    #[test]
    fn validate_cursor_update_key_at_spec_end() {
        let record = active_unleased_record(); // spec [a, z)
        let new_cursor = Cursor::with_last_key(b"z".to_vec()); // at end (exclusive)
        let result = validate_cursor_update(&new_cursor, &record);
        assert!(
            matches!(result, Err(CoordError::CursorOutOfBounds(_))),
            "key at spec end should be AboveRange (exclusive)"
        );
    }

    // -- check_op_idempotency tests --------------------------------------

    fn make_entry(op_raw: u64, hash: u64) -> OpLogEntry {
        OpLogEntry::new(
            OpId::from_raw(op_raw),
            OpKind::Checkpoint,
            OpResult::Completed,
            hash,
            LogicalTime::from_raw(100),
        )
    }

    #[test]
    fn check_op_idempotency_new_op() {
        let record = active_unleased_record();
        let result = check_op_idempotency(&record, OpId::from_raw(42), 0xABCD);
        assert!(matches!(result, Ok(None)));
    }

    #[test]
    fn check_op_idempotency_replay() {
        let mut record = active_unleased_record();
        record.op_log.push(make_entry(42, 0xABCD));
        let result = check_op_idempotency(&record, OpId::from_raw(42), 0xABCD);
        assert!(matches!(result, Ok(Some(_))));
    }

    #[test]
    fn check_op_idempotency_conflict() {
        let mut record = active_unleased_record();
        record.op_log.push(make_entry(42, 0xABCD));
        let result = check_op_idempotency(&record, OpId::from_raw(42), 0xDEAD);
        assert!(
            matches!(result, Err(CoordError::OpIdConflict { .. })),
            "expected OpIdConflict, got {result:?}"
        );
    }

    #[test]
    fn check_op_idempotency_at_op_log_capacity() {
        let mut record = active_unleased_record();
        // Fill op-log to capacity.
        for i in 0..ShardRecord::OP_LOG_CAP as u64 {
            record.op_log.push(make_entry(i + 1, 0x1000 + i));
        }
        assert_eq!(record.op_log.len(), ShardRecord::OP_LOG_CAP);
        // Query the oldest entry — should still be found.
        let result = check_op_idempotency(&record, OpId::from_raw(1), 0x1000);
        assert!(
            matches!(result, Ok(Some(_))),
            "oldest entry in full op-log should be found"
        );
    }

    #[test]
    #[should_panic(expected = "check_op_idempotency: payload_hash must be non-zero")]
    fn check_op_idempotency_panics_on_zero_hash() {
        let record = active_unleased_record();
        let _ = check_op_idempotency(&record, OpId::from_raw(1), 0);
    }

    #[test]
    fn check_op_idempotency_evicted_entry_returns_none() {
        let mut record = active_unleased_record();
        for i in 0..ShardRecord::OP_LOG_CAP as u64 {
            record.op_log.push(make_entry(i + 1, 0x1000 + i));
        }
        // Evict oldest (op_id=1) by pushing beyond capacity.
        record.op_log_push(make_entry(ShardRecord::OP_LOG_CAP as u64 + 1, 0x2000));

        // Evicted entry should be treated as a new operation.
        let result = check_op_idempotency(&record, OpId::from_raw(1), 0x1000);
        assert!(
            matches!(result, Ok(None)),
            "evicted op should return Ok(None)"
        );

        // A surviving entry should still be found.
        let result = check_op_idempotency(&record, OpId::from_raw(2), 0x1001);
        assert!(
            matches!(result, Ok(Some(_))),
            "surviving op should be found"
        );
    }

    // -- Property-based test for validate_cursor_update ------------------

    use proptest::prelude::*;

    proptest! {
        #![proptest_config(crate::test_util::miri_proptest_config())]

        #[test]
        fn prop_validate_cursor_update_matches_spec(
            old_key in proptest::option::of(proptest::collection::vec(any::<u8>(), 1..32)),
            new_key in proptest::option::of(proptest::collection::vec(any::<u8>(), 1..32)),
            spec in crate::test_util::arb_bounded_shard_spec(),
        ) {
            // Build the record.
            let cursor = match old_key {
                Some(k) => Cursor::with_last_key(k),
                None => Cursor::initial(),
            };
            let record = ShardRecord::from_raw_parts(
                test_tenant(),
                test_run(),
                test_shard(),
                crate::coordination::record::ShardStatus::Active,
                None,
                spec.clone(),
                cursor,
                CursorSemantics::Completed,
                None,
                FenceEpoch::INITIAL,
                None,
                vec![],
                vec![],
            );

            let new_cursor = match new_key {
                Some(k) => Cursor::with_last_key(k),
                None => Cursor::initial(),
            };

            let result = validate_cursor_update(&new_cursor, &record);

            // Verify result matches the invariant that was violated (if any).
            match result {
                Ok(()) => {
                    // Must have a key.
                    prop_assert!(new_cursor.last_key().is_some());
                    // Must be forward.
                    prop_assert_eq!(
                        check_cursor_advance(&record.cursor, &new_cursor),
                        CursorAdvance::Forward,
                    );
                    // Must be in bounds.
                    prop_assert_eq!(
                        check_cursor_bounds(&new_cursor, &record.spec),
                        CursorBoundsCheck::InBounds,
                    );
                }
                Err(CoordError::CheckpointMissingKey) => {
                    prop_assert!(new_cursor.last_key().is_none());
                }
                Err(CoordError::CursorRegression { .. }) => {
                    let adv = check_cursor_advance(&record.cursor, &new_cursor);
                    prop_assert!(
                        adv == CursorAdvance::Regression || adv == CursorAdvance::ResetToNone,
                    );
                }
                Err(CoordError::CursorOutOfBounds(_)) => {
                    let bounds = check_cursor_bounds(&new_cursor, &record.spec);
                    prop_assert!(
                        bounds == CursorBoundsCheck::BelowRange
                            || bounds == CursorBoundsCheck::AboveRange,
                    );
                }
                Err(other) => {
                    prop_assert!(false, "unexpected error: {other:?}");
                }
            }
        }
    }
}
