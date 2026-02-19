//! Validation helpers for the coordination protocol.
//!
//! These are the reusable preamble functions that every backend operation
//! calls before executing. They validate lease credentials, cursor updates,
//! and op-log idempotency in isolation from the backend implementation.
//!
//! ## Check Order (validate_lease)
//!
//! The order matters for error reporting — the most actionable error
//! is returned first:
//! 1. Tenant mismatch (always a bug — fail loudly)
//! 2. Shard terminal (no mutations possible)
//! 3. Stale fence (zombie detection — most common operational error)
//! 4. Lease expired (timing issue — second most common)
//!
//! Reference: D2.14 — fencing token protocol;
//!            Kleppmann, "How to do distributed locking" (2016);
//!            Gray & Cheriton, "Leases" (SOSP 1989).

use crate::identity::{
    LogicalTime, OpId, ShardKey, TenantId,
};
use crate::coordination::cursor::{
    Cursor, CursorAdvance, CursorBoundsCheck,
    check_cursor_advance, check_cursor_bounds,
};
use crate::coordination::lease::{Lease, OpLogEntry};
use crate::coordination::record::ShardRecord;
use crate::coordination::error::CoordError;

// ============================================================================
// § validate_lease
// ============================================================================

/// Validate a lease against a shard record.
///
/// This is the common preamble for all lease-gated operations. It checks
/// tenant isolation, terminal status, fence epoch, and lease expiry in
/// a fixed order.
///
/// Returns `Ok(())` if the lease is valid for the given record at `now`.
pub fn validate_lease(
    now: LogicalTime,
    tenant: TenantId,
    lease: &Lease,
    record: &ShardRecord,
) -> Result<(), CoordError> {
    // 1. Tenant isolation.
    if record.tenant != tenant {
        return Err(CoordError::TenantMismatch {
            expected: tenant,
            actual: record.tenant,
        });
    }

    // 2. Terminal check.
    if record.status.is_terminal() {
        return Err(CoordError::ShardTerminal {
            shard: ShardKey {
                run: record.run,
                shard: record.shard,
            },
            status: record.status,
        });
    }

    // 3. Fence epoch.
    if lease.fence != record.fence_epoch {
        return Err(CoordError::StaleFence {
            presented: lease.fence,
            current: record.fence_epoch,
        });
    }

    // 4. Lease expiry.
    if !record.is_leased_at(now) {
        return Err(CoordError::LeaseExpired {
            deadline: record.lease_deadline.unwrap_or(LogicalTime::ZERO),
            now,
        });
    }

    // Note: We intentionally do NOT check `lease.owner == record.lease_owner`
    // separately. The fence epoch is the canonical ownership proof — if
    // epochs match, ownership must match (invariant maintained by
    // acquire_and_restore). Belt-and-suspenders owner checks can be added
    // in debug builds via `debug_assert!`.

    Ok(())
}

// ============================================================================
// § validate_cursor_update
// ============================================================================

/// Validate a cursor update against the current record.
///
/// Checks in order:
/// 1. Non-empty key: `new_cursor.last_key.is_some()`
/// 2. Monotonicity: `new_cursor.last_key >= old_cursor.last_key`
/// 3. Bounds: `new_cursor.last_key ∈ [spec.start, spec.end)`
///
/// Returns `Ok(())` if the new cursor is valid.
pub fn validate_cursor_update(
    new_cursor: &Cursor,
    record: &ShardRecord,
) -> Result<(), CoordError> {
    // Must have a last_key.
    if new_cursor.last_key.is_none() {
        return Err(CoordError::CheckpointMissingKey);
    }

    // Monotonicity.
    match check_cursor_advance(&record.cursor, new_cursor) {
        CursorAdvance::Forward => {}
        CursorAdvance::Regression => {
            return Err(CoordError::CursorRegression {
                old_key: record.cursor.last_key.clone(),
                new_key: new_cursor.last_key.clone(),
            });
        }
        CursorAdvance::ResetToNone => {
            return Err(CoordError::CursorRegression {
                old_key: record.cursor.last_key.clone(),
                new_key: None,
            });
        }
    }

    // Bounds.
    match check_cursor_bounds(new_cursor, &record.spec) {
        CursorBoundsCheck::NoKey => {
            // Unreachable — we checked for None above.
            return Err(CoordError::CheckpointMissingKey);
        }
        CursorBoundsCheck::InBounds => {}
        CursorBoundsCheck::BelowRange | CursorBoundsCheck::AboveRange => {
            return Err(CoordError::CursorOutOfBounds {
                last_key: new_cursor.last_key.clone().unwrap(),
                spec_start: record.spec.key_range_start.clone(),
                spec_end: record.spec.key_range_end.clone(),
            });
        }
    }

    Ok(())
}

// ============================================================================
// § check_op_idempotency
// ============================================================================

/// Check op-log for idempotent replay or conflict.
///
/// Returns:
/// - `Ok(Some(entry))` — replay: same op_id + same payload_hash
/// - `Ok(None)` — new operation, proceed with execution
/// - `Err(OpIdConflict)` — same op_id, different payload_hash
pub fn check_op_idempotency(
    record: &ShardRecord,
    op_id: OpId,
    payload_hash: u64,
) -> Result<Option<&OpLogEntry>, CoordError> {
    match record.op_log_lookup(op_id) {
        None => Ok(None),
        Some(entry) => {
            if entry.payload_hash == payload_hash {
                Ok(Some(entry))
            } else {
                Err(CoordError::OpIdConflict {
                    op_id,
                    expected_hash: entry.payload_hash,
                    actual_hash: payload_hash,
                })
            }
        }
    }
}

// ============================================================================
// § Tests
// ============================================================================

#[cfg(test)]
mod tests {
    // -- Test fixtures --

    // TODO: fn test_tenant() -> TenantId
    // TODO: fn other_tenant() -> TenantId
    // TODO: fn test_run() -> RunId
    // TODO: fn test_key() -> ShardKey
    // TODO: fn test_spec() -> ShardSpec
    // TODO: fn active_unleased_record() -> ShardRecord
    // TODO: fn active_leased_record() -> ShardRecord (fence=2, deadline=100)
    // TODO: fn valid_lease_for(record: &ShardRecord) -> Lease

    // -- validate_lease --

    // TODO: test validate_lease_ok
    //   - Active, leased, matching tenant+fence, now < deadline → Ok(())

    // TODO: test validate_lease_tenant_mismatch
    //   - Pass other_tenant() → Err(TenantMismatch)

    // TODO: test validate_lease_terminal_shard
    //   - Status::Done → Err(ShardTerminal)

    // TODO: test validate_lease_stale_fence
    //   - Lease fence < record fence → Err(StaleFence)

    // TODO: test validate_lease_expired
    //   - now >= deadline → Err(LeaseExpired)

    // TODO: test validate_lease_error_priority_tenant_before_fence
    //   - Both tenant mismatch and stale fence → TenantMismatch wins

    // TODO: test validate_lease_error_priority_terminal_before_fence
    //   - Both terminal and stale fence → ShardTerminal wins

    // -- validate_cursor_update --

    // TODO: test validate_cursor_update_ok_first_checkpoint
    //   - Record has initial cursor, new cursor has key "f" → Ok(())

    // TODO: test validate_cursor_update_ok_forward
    //   - Record cursor at "f", new cursor at "m" → Ok(())

    // TODO: test validate_cursor_update_missing_key
    //   - New cursor is initial (no last_key) → Err(CheckpointMissingKey)

    // TODO: test validate_cursor_update_regression
    //   - Record cursor at "m", new cursor at "f" → Err(CursorRegression)

    // TODO: test validate_cursor_update_below_range
    //   - Spec [m, z), cursor at "a" → Err(CursorOutOfBounds)

    // TODO: test validate_cursor_update_above_range
    //   - Spec [a, m), cursor at "z" → Err(CursorOutOfBounds)

    // -- check_op_idempotency --

    // TODO: test check_op_idempotency_new_op
    //   - Empty op-log, any op_id → Ok(None)

    // TODO: test check_op_idempotency_replay
    //   - Op-log has (op=42, hash=0xDEAD), query (42, 0xDEAD) → Ok(Some(_))

    // TODO: test check_op_idempotency_conflict
    //   - Op-log has (op=42, hash=0xDEAD), query (42, 0xBEEF) → Err(OpIdConflict)
}
