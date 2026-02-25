//! Shared validation helpers for lease-gated coordination operations.
//!
//! These are pure, side-effect-free functions that extract precondition
//! checks shared across [`CoordinationBackend`] implementations. Keeping
//! them as free functions (rather than methods on a backend type) ensures
//! that validation logic is identical across all backends and is
//! independently testable without coordinator setup.
//!
//! Each function returns `Result<_, CoordError>` so callers can convert
//! into operation-specific error types via the `From<CoordError>` impls
//! defined in [`super::error`].
//!
//! [`CoordinationBackend`]: super::traits::CoordinationBackend
//!
//! ## Composition pattern
//!
//! Every lease-gated mutation (checkpoint, complete, park, split) follows
//! the same three-step validation pipeline:
//!
//! 1. **[`check_op_idempotency`]** — replay detection. Checked first so
//!    that replays succeed even after the lease expires or the shard
//!    reaches a terminal state. This ordering is critical: without it,
//!    a worker that successfully completed an operation but failed to
//!    receive the response would be unable to retry.
//!
//! 2. **[`validate_lease`]** — tenant isolation, terminal status, fence
//!    epoch, lease expiry, and owner identity. These checks are ordered
//!    by security priority (see below).
//!
//! 3. **Operation-specific validation** — e.g.,
//!    `validate_cursor_update_pooled` for checkpoint/complete, or
//!    split coverage validation for split operations.
//!
//! ## `validate_lease` check ordering
//!
//! The five checks in `validate_lease` are deliberately ordered by
//! information-security priority:
//!
//! 1. **Tenant isolation** — security-first; a tenant-mismatch error
//!    never reveals whether the shard is terminal, has a stale fence,
//!    or has an expired lease.
//! 2. **Terminal status** — fast rejection of dead shards before more
//!    expensive checks.
//! 3. **Fence epoch** — zombie worker fencing (Kleppmann protocol).
//! 4. **Lease expiry** — time-based rejection.
//! 5. **Owner divergence** — catches identity mismatches when fence
//!    epochs agree (defense-in-depth against state reconstruction bugs).
//!
//! ## `validate_cursor_update_pooled`
//!
//! Validates a [`CursorUpdate`] against pooled/slice views of the previous
//! cursor key and shard spec boundaries. Checks four properties in order:
//! key presence, key size limit, monotonicity (new >= old), and bounds
//! (`last_key` in `[spec.start, spec.end)`). Operates entirely on borrowed
//! slices to avoid materializing owned cursor/spec values on the
//! checkpoint hot path.
//!
//! ## Invariants
//!
//! - **Lease deadline existence:** When a caller's fence epoch matches the
//!   record's current epoch, the record's lease deadline MUST be `Some`.
//!   If it is `None`, the record is in an inconsistent state and
//!   `validate_lease` returns `StaleFence` to force re-acquisition.

use crate::coordination::cursor::{CursorUpdate, MAX_KEY_SIZE, MAX_TOKEN_SIZE};
use crate::coordination::error::CoordError;
use crate::coordination::lease::{Lease, OpLogEntry};
use crate::coordination::record::ShardRecord;
use crate::identity::{LogicalTime, OpId, ShardKey, TenantId};

/// Validate lease preconditions for a lease-gated operation.
///
/// Checks (in priority order -- see module docs for rationale):
///
/// 1. **Tenant isolation** — `record.tenant == tenant`. Checked first so
///    that a mismatch never reveals whether the shard is terminal, has a
///    stale fence, or has an expired lease.
/// 2. **Terminal status** — `!record.status.is_terminal()`. Terminal shards
///    reject all mutations. Checked before fence/lease to avoid confusing
///    "stale fence" errors on shards that are simply dead.
/// 3. **Fence epoch** — `lease.fence() == record.fence_epoch`. A mismatch
///    means another worker has since acquired the shard (Kleppmann fencing).
/// 4. **Lease expiry** — `now < record.lease_deadline()`. If the fence check
///    passes but the record has no lease holder (`deadline == None`), the
///    record is in an inconsistent state and `StaleFence` is returned to
///    force re-acquisition.
/// 5. **Owner divergence** — `record.lease_owner() == Some(lease.owner())`.
///    Defense-in-depth: catches identity mismatches when fence epochs agree
///    (e.g., state reconstruction bugs).
///
/// ## Postconditions (on `Ok(())`)
///
/// - `record.tenant == tenant`
/// - `record.status` is non-terminal
/// - `lease.fence() == record.fence_epoch`
/// - `record.is_leased_at(now)` is `true`
///
/// ## Preconditions
///
/// - `now > LogicalTime::ZERO` (asserted at runtime).
/// - The caller MUST have looked up the shard record by `ShardKey` before
///   calling this function. If the shard is not found, return
///   `CoordError::ShardNotFound` directly (this function cannot check that).
///
/// # Panics
///
/// Panics if `now == LogicalTime::ZERO`. A zero timestamp indicates a broken
/// clock or uninitialized time source -- this is a caller bug, not a protocol
/// error.
///
/// # Errors
///
/// Returns the first violated check as a [`CoordError`].
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

    // 1. Tenant isolation (no `actual` field — prevents cross-tenant enumeration).
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

/// Validate a cursor update against borrowed slices of the previous cursor
/// key and shard-spec boundaries.
///
/// This is the canonical cursor validator for all mutation paths (checkpoint,
/// complete). It operates entirely on borrowed slices so callers can validate
/// without materializing owned cursor/spec values -- critical on
/// the checkpoint hot path where the previous key and spec bounds live in the
/// slab as `PooledCursor` / `PooledShardSpec`.
///
/// ## Check order
///
/// 1. **Key presence** -- `new_cursor.last_key()` must be `Some`. A
///    checkpoint with no key represents no progress, which is meaningless.
/// 2. **Key size** -- `last_key.len() <= MAX_KEY_SIZE`. Defense-in-depth
///    against oversized keys that could bloat slab storage.
/// 3. **Monotonicity** -- `new_last_key >= old_last_key` (lexicographic).
///    Prevents cursor regression within a lease epoch.
/// 4. **Bounds** -- `last_key` must fall within `[spec_start, spec_end)`.
///    Empty `spec_start` / `spec_end` are treated as unbounded on that side.
///
/// The ordering matters: a missing key is reported before monotonicity, and
/// monotonicity is reported before bounds. This gives the caller the most
/// actionable error first.
///
/// # Errors
///
/// Returns the first violated check as a [`CoordError`].
pub(crate) fn validate_cursor_update_pooled(
    new_cursor: &CursorUpdate<'_>,
    old_last_key: Option<&[u8]>,
    spec_start: &[u8],
    spec_end: &[u8],
) -> Result<(), CoordError> {
    // 1. Key presence.
    let Some(new_last_key) = new_cursor.last_key() else {
        return Err(CoordError::CheckpointMissingKey);
    };

    // 2. Key size.
    if new_last_key.len() > MAX_KEY_SIZE {
        return Err(CoordError::CursorKeyTooLarge {
            size: new_last_key.len(),
            max: MAX_KEY_SIZE,
        });
    }

    // 2b. Token size.
    if let Some(token) = new_cursor.token()
        && token.len() > MAX_TOKEN_SIZE
    {
        return Err(CoordError::CursorTokenTooLarge {
            size: token.len(),
            max: MAX_TOKEN_SIZE,
        });
    }

    // 3. Monotonicity.
    if let Some(old_key) = old_last_key
        && new_last_key < old_key
    {
        return Err(CoordError::CursorRegression {
            old_key: Some(old_key.len()),
            new_key: Some(new_last_key.len()),
        });
    }

    // 4. Bounds checking against [start, end).
    if (!spec_start.is_empty() && new_last_key < spec_start)
        || (!spec_end.is_empty() && new_last_key >= spec_end)
    {
        return Err(CoordError::CursorOutOfBounds(
            crate::coordination::error::CursorOutOfBoundsDetail {
                last_key: new_last_key.len(),
                spec_start: spec_start.len(),
                spec_end: spec_end.len(),
            },
        ));
    }

    Ok(())
}

/// Check whether an operation is a replay (idempotent retry) or a new
/// operation by looking up `op_id` in the shard's bounded op-log.
///
/// ## Three-way return
///
/// | Condition | Return | Caller action |
/// |-----------|--------|---------------|
/// | `op_id` not in log | `Ok(None)` | Proceed with fresh execution |
/// | `op_id` found, hash matches | `Ok(Some(entry))` | Return cached result (replay) |
/// | `op_id` found, hash differs | `Err(OpIdConflict)` | Reject -- caller reused an OpId with different parameters |
///
/// ## Call ordering
///
/// On every idempotent path this function is called **before**
/// [`validate_lease`], so that a successful replay is never blocked by
/// an expired lease or terminal shard status. This ordering is critical:
/// a worker that successfully completed an operation but crashed before
/// receiving the response must be able to retry and get the cached result,
/// even if the lease has since expired or the shard has transitioned.
///
/// ## Op-log capacity and eviction
///
/// The op-log is bounded to [`ShardRecord::OP_LOG_CAP`] (16) entries.
/// If an `OpId` has been evicted, this function returns `Ok(None)` and
/// the caller treats it as a new operation. This is safe because:
///
/// - For terminal operations (complete, park, split_replace): the shard
///   is terminal after first execution, so no further ops can push entries
///   and the terminal op's entry is never evicted.
/// - For non-terminal operations (checkpoint, split_residual): eviction
///   requires 16+ intervening ops within the same lease epoch. The fence
///   epoch is the primary deduplication guard; the op-log is a secondary
///   defense for in-lease retries only.
///
/// ## Preconditions
///
/// `payload_hash` must be non-zero (asserted at runtime). A zero hash
/// indicates the caller failed to compute a hash.
///
/// # Panics
///
/// Panics if `payload_hash == 0`. A zero hash indicates the caller failed to
/// compute a payload hash -- this is a caller bug, not a protocol error.
///
/// # Errors
///
/// Returns [`CoordError::OpIdConflict`] if the `OpId` was previously used
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
    use crate::coordination::cursor::{
        CursorAdvance, CursorBoundsCheck, CursorUpdate, check_cursor_advance, check_cursor_bounds,
    };
    use crate::coordination::lease::{LeaseHolder, OpKind, OpResult};
    use crate::coordination::record::ShardRecord;
    use crate::coordination::shard_spec::{CursorSemantics, ShardSpec};
    use crate::coordination::test_fixtures::{
        other_tenant, test_run, test_shard, test_spec, test_tenant,
    };
    use crate::identity::{FenceEpoch, LogicalTime, OpId, WorkerId};
    use crate::test_util::TestSlab;
    use gossip_stdx::{ByteSlab, RingBuffer};

    // -- Test fixtures ---------------------------------------------------

    /// Active record, no lease, fence=INITIAL.
    fn active_unleased_record(slab: &mut ByteSlab) -> ShardRecord {
        let spec = test_spec();
        ShardRecord::new_active(
            test_tenant(),
            test_run(),
            test_shard(),
            spec.as_ref(),
            CursorSemantics::Completed,
            slab,
        )
        .expect("slab large enough for test record")
    }

    /// Active record, leased (owner=99, fence=2, deadline=100).
    fn active_leased_record(slab: &mut ByteSlab) -> ShardRecord {
        let r = ShardRecord::from_raw_parts(
            test_tenant(),
            test_run(),
            test_shard(),
            crate::coordination::record::ShardStatus::Active,
            None,
            &test_spec(),
            CursorUpdate::initial(),
            CursorSemantics::Completed,
            Some(LeaseHolder::new(
                WorkerId::from_raw(99),
                LogicalTime::from_raw(100),
            )),
            FenceEpoch::from_raw(2),
            None,
            gossip_stdx::InlineVec::new(),
            RingBuffer::new(),
            slab,
        );
        r.assert_invariants(slab);
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

    fn validate_cursor_update_for_tests(
        new_cursor: &CursorUpdate<'_>,
        old_cursor: &CursorUpdate<'_>,
        spec: &ShardSpec,
    ) -> Result<(), CoordError> {
        validate_cursor_update_pooled(
            new_cursor,
            old_cursor.last_key(),
            spec.key_range_start(),
            spec.key_range_end(),
        )
    }

    // -- validate_lease: basic tests -------------------------------------

    #[test]
    fn validate_lease_ok() {
        let mut slab = TestSlab::new();
        let record = active_leased_record(&mut slab);
        let lease = valid_lease_for(&record);
        let now = LogicalTime::from_raw(50); // before deadline=100
        assert!(validate_lease(now, test_tenant(), &lease, &record).is_ok());
    }

    #[test]
    fn validate_lease_tenant_mismatch() {
        let mut slab = TestSlab::new();
        let record = active_leased_record(&mut slab);
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
        let mut slab = TestSlab::new();
        let mut record = active_leased_record(&mut slab);
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
        let mut slab = TestSlab::new();
        let record = active_leased_record(&mut slab);
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
        let mut slab = TestSlab::new();
        let record = active_leased_record(&mut slab);
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
        let mut slab = TestSlab::new();
        // Active record with INITIAL fence and no lease holder.
        let record = active_unleased_record(&mut slab);
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
        let mut slab = TestSlab::new();
        let record = active_leased_record(&mut slab); // owner=99, fence=2
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
        let mut slab = TestSlab::new();
        let record = active_leased_record(&mut slab);
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
        let mut slab = TestSlab::new();
        let mut record = active_leased_record(&mut slab);
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
        let mut slab = TestSlab::new();
        let record = active_leased_record(&mut slab); // deadline=100
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
        let mut slab = TestSlab::new();
        let record = active_leased_record(&mut slab); // deadline=100
        let lease = valid_lease_for(&record);
        let now = LogicalTime::from_raw(99); // one tick before deadline
        assert!(validate_lease(now, test_tenant(), &lease, &record).is_ok());
    }

    // -- validate_cursor_update tests ------------------------------------

    #[test]
    fn validate_cursor_update_ok_first_checkpoint() {
        let spec = test_spec();
        let old_cursor = CursorUpdate::initial();
        let new_cursor = CursorUpdate::with_last_key(b"f");
        assert!(validate_cursor_update_for_tests(&new_cursor, &old_cursor, &spec).is_ok());
    }

    #[test]
    fn validate_cursor_update_ok_forward() {
        let spec = test_spec();
        let old_cursor = CursorUpdate::with_last_key(b"f");
        let new_cursor = CursorUpdate::with_last_key(b"m");
        assert!(validate_cursor_update_for_tests(&new_cursor, &old_cursor, &spec).is_ok());
    }

    #[test]
    fn validate_cursor_update_missing_key() {
        let spec = test_spec();
        let old_cursor = CursorUpdate::initial();
        let new_cursor = CursorUpdate::initial(); // no last_key
        let result = validate_cursor_update_for_tests(&new_cursor, &old_cursor, &spec);
        assert!(matches!(result, Err(CoordError::CheckpointMissingKey)));
    }

    #[test]
    fn validate_cursor_update_rejects_oversized_key() {
        let spec = test_spec();
        let old_cursor = CursorUpdate::initial();
        let new_cursor = CursorUpdate::with_last_key(&[0xAB; MAX_KEY_SIZE + 1]);
        let result = validate_cursor_update_for_tests(&new_cursor, &old_cursor, &spec);
        assert!(
            matches!(
                result,
                Err(CoordError::CursorKeyTooLarge { size, max })
                    if size == MAX_KEY_SIZE + 1 && max == MAX_KEY_SIZE
            ),
            "expected CursorKeyTooLarge, got {result:?}",
        );
    }

    #[test]
    fn validate_cursor_update_rejects_oversized_token() {
        use crate::coordination::cursor::MAX_TOKEN_SIZE;

        let spec = test_spec();
        let old_cursor = CursorUpdate::initial();
        let oversized_token = vec![0xCD; MAX_TOKEN_SIZE + 1];
        let new_cursor = CursorUpdate::with_token(b"b", &oversized_token);
        let result = validate_cursor_update_for_tests(&new_cursor, &old_cursor, &spec);
        assert!(
            matches!(
                result,
                Err(CoordError::CursorTokenTooLarge { size, max })
                    if size == MAX_TOKEN_SIZE + 1 && max == MAX_TOKEN_SIZE
            ),
            "expected CursorTokenTooLarge, got {result:?}",
        );
    }

    #[test]
    fn validate_cursor_update_regression() {
        let spec = test_spec();
        let old_cursor = CursorUpdate::with_last_key(b"m");
        let new_cursor = CursorUpdate::with_last_key(b"f"); // regression
        let result = validate_cursor_update_for_tests(&new_cursor, &old_cursor, &spec);
        assert!(matches!(result, Err(CoordError::CursorRegression { .. })));
    }

    #[test]
    fn validate_cursor_update_below_range() {
        // spec range is [a, z), cursor at byte 0x00 which is below 'a'.
        let spec = test_spec();
        let old_cursor = CursorUpdate::initial();
        let new_cursor = CursorUpdate::with_last_key(&[0x00]);
        let result = validate_cursor_update_for_tests(&new_cursor, &old_cursor, &spec);
        assert!(
            matches!(result, Err(CoordError::CursorOutOfBounds(_))),
            "expected CursorOutOfBounds, got {result:?}"
        );
    }

    #[test]
    fn validate_cursor_update_above_range() {
        // spec range is [a, z), cursor at 'z' (exclusive end).
        let spec = test_spec();
        let old_cursor = CursorUpdate::initial();
        let new_cursor = CursorUpdate::with_last_key(b"z");
        let result = validate_cursor_update_for_tests(&new_cursor, &old_cursor, &spec);
        assert!(
            matches!(result, Err(CoordError::CursorOutOfBounds(_))),
            "expected CursorOutOfBounds, got {result:?}"
        );
    }

    // -- validate_cursor_update: boundary tests --------------------------

    #[test]
    fn validate_cursor_update_idempotent_same_key() {
        let spec = test_spec();
        let old_cursor = CursorUpdate::with_last_key(b"f");
        let new_cursor = CursorUpdate::with_last_key(b"f"); // same key
        assert!(
            validate_cursor_update_for_tests(&new_cursor, &old_cursor, &spec).is_ok(),
            "same key should be Forward (idempotent)"
        );
    }

    #[test]
    fn validate_cursor_update_key_at_spec_start() {
        let spec = test_spec(); // spec [a, z)
        let old_cursor = CursorUpdate::initial();
        let new_cursor = CursorUpdate::with_last_key(b"a"); // at start (inclusive)
        assert!(
            validate_cursor_update_for_tests(&new_cursor, &old_cursor, &spec).is_ok(),
            "key at spec start should be InBounds (inclusive)"
        );
    }

    #[test]
    fn validate_cursor_update_key_at_spec_end() {
        let spec = test_spec(); // spec [a, z)
        let old_cursor = CursorUpdate::initial();
        let new_cursor = CursorUpdate::with_last_key(b"z"); // at end (exclusive)
        let result = validate_cursor_update_for_tests(&new_cursor, &old_cursor, &spec);
        assert!(
            matches!(result, Err(CoordError::CursorOutOfBounds(_))),
            "key at spec end should be AboveRange (exclusive)"
        );
    }

    #[test]
    fn validate_cursor_update_pooled_matches_owned_validation() {
        let cases = [
            (CursorUpdate::initial(), CursorUpdate::with_last_key(b"f")),
            (
                CursorUpdate::with_last_key(b"f"),
                CursorUpdate::with_last_key(b"m"),
            ),
            (
                CursorUpdate::with_last_key(b"m"),
                CursorUpdate::with_last_key(b"f"),
            ),
            (CursorUpdate::initial(), CursorUpdate::initial()),
            (
                CursorUpdate::initial(),
                CursorUpdate::with_last_key(&[0x00]),
            ),
            (CursorUpdate::initial(), CursorUpdate::with_last_key(b"z")),
            (
                CursorUpdate::initial(),
                CursorUpdate::with_last_key(&[0xAB; MAX_KEY_SIZE + 1]),
            ),
        ];
        let spec = test_spec();

        for (old_cursor, new_cursor) in cases {
            let owned = validate_cursor_update_for_tests(&new_cursor, &old_cursor, &spec);
            let update = match (new_cursor.last_key(), new_cursor.token()) {
                (None, _) => CursorUpdate::initial(),
                (Some(last_key), None) => CursorUpdate::new(last_key),
                (Some(last_key), Some(token)) => CursorUpdate::with_token(last_key, token),
            };
            let pooled = validate_cursor_update_pooled(
                &update,
                old_cursor.last_key(),
                spec.key_range_start(),
                spec.key_range_end(),
            );

            let owned_kind = match &owned {
                Ok(()) => "ok",
                Err(CoordError::CheckpointMissingKey) => "missing_key",
                Err(CoordError::CursorRegression { .. }) => "regression",
                Err(CoordError::CursorOutOfBounds(_)) => "out_of_bounds",
                Err(CoordError::CursorKeyTooLarge { .. }) => "key_too_large",
                Err(other) => panic!("unexpected owned error variant: {other:?}"),
            };
            let pooled_kind = match &pooled {
                Ok(()) => "ok",
                Err(CoordError::CheckpointMissingKey) => "missing_key",
                Err(CoordError::CursorRegression { .. }) => "regression",
                Err(CoordError::CursorOutOfBounds(_)) => "out_of_bounds",
                Err(CoordError::CursorKeyTooLarge { .. }) => "key_too_large",
                Err(other) => panic!("unexpected pooled error variant: {other:?}"),
            };
            assert_eq!(
                owned_kind, pooled_kind,
                "owned={owned:?}, pooled={pooled:?}",
            );
        }
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
        let mut slab = TestSlab::new();
        let record = active_unleased_record(&mut slab);
        let result = check_op_idempotency(&record, OpId::from_raw(42), 0xABCD);
        assert!(matches!(result, Ok(None)));
    }

    #[test]
    fn check_op_idempotency_replay() {
        let mut slab = TestSlab::new();
        let mut record = active_unleased_record(&mut slab);
        record.op_log.push_back(make_entry(42, 0xABCD)).unwrap();
        let result = check_op_idempotency(&record, OpId::from_raw(42), 0xABCD);
        assert!(matches!(result, Ok(Some(_))));
    }

    #[test]
    fn check_op_idempotency_conflict() {
        let mut slab = TestSlab::new();
        let mut record = active_unleased_record(&mut slab);
        record.op_log.push_back(make_entry(42, 0xABCD)).unwrap();
        let result = check_op_idempotency(&record, OpId::from_raw(42), 0xDEAD);
        assert!(
            matches!(result, Err(CoordError::OpIdConflict { .. })),
            "expected OpIdConflict, got {result:?}"
        );
    }

    #[test]
    fn check_op_idempotency_at_op_log_capacity() {
        let mut slab = TestSlab::new();
        let mut record = active_unleased_record(&mut slab);
        // Fill op-log to capacity.
        for i in 0..ShardRecord::OP_LOG_CAP as u64 {
            record
                .op_log
                .push_back(make_entry(i + 1, 0x1000 + i))
                .unwrap();
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
        let mut slab = TestSlab::new();
        let record = active_unleased_record(&mut slab);
        let _ = check_op_idempotency(&record, OpId::from_raw(1), 0);
    }

    #[test]
    fn check_op_idempotency_evicted_entry_returns_none() {
        let mut slab = TestSlab::new();
        let mut record = active_unleased_record(&mut slab);
        for i in 0..ShardRecord::OP_LOG_CAP as u64 {
            record
                .op_log
                .push_back(make_entry(i + 1, 0x1000 + i))
                .unwrap();
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
            let old_cursor = match old_key.as_deref() {
                Some(k) => CursorUpdate::with_last_key(k),
                None => CursorUpdate::initial(),
            };

            let new_cursor = match new_key.as_deref() {
                Some(k) => CursorUpdate::with_last_key(k),
                None => CursorUpdate::initial(),
            };

            let result = validate_cursor_update_for_tests(&new_cursor, &old_cursor, &spec);

            // Verify result matches the invariant that was violated (if any).
            match result {
                Ok(()) => {
                    // Must have a key.
                    prop_assert!(new_cursor.last_key().is_some());
                    // Must be forward.
                    prop_assert_eq!(
                        check_cursor_advance(old_cursor, new_cursor),
                        CursorAdvance::Forward,
                    );
                    // Must be in bounds.
                    prop_assert_eq!(
                        check_cursor_bounds(new_cursor, spec.as_ref()),
                        CursorBoundsCheck::InBounds,
                    );
                }
                Err(CoordError::CheckpointMissingKey) => {
                    prop_assert!(new_cursor.last_key().is_none());
                }
                Err(CoordError::CursorRegression { .. }) => {
                    let adv = check_cursor_advance(old_cursor, new_cursor);
                    prop_assert!(
                        adv == CursorAdvance::Regression || adv == CursorAdvance::ResetToNone,
                    );
                }
                Err(CoordError::CursorOutOfBounds(_)) => {
                    let bounds = check_cursor_bounds(new_cursor, spec.as_ref());
                    prop_assert!(
                        bounds == CursorBoundsCheck::BelowRange
                            || bounds == CursorBoundsCheck::AboveRange,
                    );
                }
                Err(CoordError::CursorKeyTooLarge { .. }) => {
                    // Generated keys are capped at 31 bytes, so this should
                    // never fire in this property domain.
                    prop_assert!(false, "unexpected CursorKeyTooLarge");
                }
                Err(other) => {
                    prop_assert!(false, "unexpected error: {other:?}");
                }
            }
        }
    }
}
