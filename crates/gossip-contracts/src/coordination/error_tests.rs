use std::error::Error;

use super::*;
use crate::identity::{FenceEpoch, LogicalTime, OpId, RunId, ShardId, ShardKey, TenantId};

// -- Test fixtures ---------------------------------------------------

fn test_tenant() -> TenantId {
    TenantId::from_bytes([0x01; 32])
}

fn test_key() -> ShardKey {
    ShardKey::new(RunId::from_raw(1), ShardId::from_raw(10))
}

// -- Variant group builders ------------------------------------------
//
// Shared `CoordError` construction extracted from 6 From tests.
// Adding a new CoordError variant: add it to the appropriate group
// (or `all_coord_error_variants`) and the compiler will ensure the
// From impls handle it.

/// 5 common precondition variants shared by all 6 From impls.
fn common_precondition_variants() -> Vec<CoordError> {
    vec![
        CoordError::ShardNotFound { shard: test_key() },
        CoordError::TenantMismatch {
            expected: test_tenant(),
        },
        CoordError::StaleFence {
            presented: FenceEpoch::INITIAL,
            current: FenceEpoch::INITIAL.increment(),
        },
        CoordError::LeaseExpired {
            deadline: LogicalTime::from_raw(100),
            now: LogicalTime::from_raw(200),
        },
        CoordError::ShardTerminal {
            shard: test_key(),
            status: ShardStatus::Done,
        },
    ]
}

fn op_id_conflict_variant() -> CoordError {
    CoordError::OpIdConflict {
        op_id: OpId::from_raw(1),
        expected_hash: 1,
        actual_hash: 2,
    }
}

fn cursor_variants() -> Vec<CoordError> {
    vec![
        CoordError::CursorRegression {
            old_key: None,
            new_key: None,
        },
        CoordError::CursorOutOfBounds(Box::new(CursorOutOfBoundsDetail {
            last_key: b"k".as_slice().into(),
            spec_start: b"a".as_slice().into(),
            spec_end: b"z".as_slice().into(),
        })),
    ]
}

fn split_invalid_variant() -> CoordError {
    CoordError::SplitInvalid(Box::new(SplitValidationError::NoChildren))
}

fn checkpoint_missing_key_variant() -> CoordError {
    CoordError::CheckpointMissingKey
}

/// All 10 `CoordError` variants. Used by the display-determinism test.
fn all_coord_error_variants() -> Vec<CoordError> {
    let mut v = common_precondition_variants();
    v.push(op_id_conflict_variant());
    v.extend(cursor_variants());
    v.push(split_invalid_variant());
    v.push(checkpoint_missing_key_variant());
    v
}

/// Assert every variant in `variants` converts to `E` without panicking.
fn assert_from_coord_error_accepted<E: From<CoordError> + fmt::Debug>(variants: Vec<CoordError>) {
    for v in variants {
        let _: E = v.into();
    }
}

/// Assert every variant in `variants` panics via `unreachable!()` when
/// converting to `E`.
fn assert_from_coord_error_rejected<E: From<CoordError> + fmt::Debug + 'static>(
    variants: Vec<CoordError>,
) {
    for v in variants {
        let label = format!("{v}");
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _: E = v.into();
        }));
        assert!(
            result.is_err(),
            "expected unreachable!() panic converting {label} -> {}",
            std::any::type_name::<E>(),
        );
    }
}

// -- IdempotentOutcome -----------------------------------------------

#[test]
fn idempotent_outcome_into_inner() {
    assert_eq!(IdempotentOutcome::Executed(42).into_inner(), 42);
    assert_eq!(IdempotentOutcome::Replayed(42).into_inner(), 42);
}

#[test]
fn idempotent_outcome_is_replay() {
    assert!(!IdempotentOutcome::Executed(()).is_replay());
    assert!(IdempotentOutcome::Replayed(()).is_replay());
}

#[test]
fn idempotent_outcome_is_executed() {
    assert!(IdempotentOutcome::Executed(()).is_executed());
    assert!(!IdempotentOutcome::Replayed(()).is_executed());
}

#[test]
fn idempotent_outcome_map() {
    let ex = IdempotentOutcome::Executed(21).map(|v| v * 2);
    assert_eq!(ex, IdempotentOutcome::Executed(42));
    assert!(!ex.is_replay());

    let re = IdempotentOutcome::Replayed(21).map(|v| v * 2);
    assert_eq!(re, IdempotentOutcome::Replayed(42));
    assert!(re.is_replay());
}

#[test]
fn idempotent_outcome_as_ref() {
    let ex = IdempotentOutcome::Executed(42);
    assert_eq!(ex.as_ref(), &42);
    let re = IdempotentOutcome::Replayed(99);
    assert_eq!(re.as_ref(), &99);
}

// -- From<CoordError> exhaustiveness tests ---------------------------
//
// Each test composes variant groups and converts them, verifying every
// valid conversion succeeds. The explicit rejection arms in the From
// impls (not wildcard `_`) guarantee that adding a new CoordError
// variant triggers a compile error.

#[test]
fn checkpoint_error_from_coord_error_exhaustive() {
    let mut v = common_precondition_variants();
    v.push(op_id_conflict_variant());
    v.extend(cursor_variants());
    v.push(checkpoint_missing_key_variant());
    assert_from_coord_error_accepted::<CheckpointError>(v);

    // Rejected: SplitInvalid
    assert_from_coord_error_rejected::<CheckpointError>(vec![split_invalid_variant()]);
}

#[test]
fn complete_error_from_coord_error_exhaustive() {
    let mut v = common_precondition_variants();
    v.push(op_id_conflict_variant());
    v.extend(cursor_variants());
    v.push(checkpoint_missing_key_variant());
    assert_from_coord_error_accepted::<CompleteError>(v);

    // Rejected: SplitInvalid
    assert_from_coord_error_rejected::<CompleteError>(vec![split_invalid_variant()]);
}

#[test]
fn park_error_from_coord_error_exhaustive() {
    let mut v = common_precondition_variants();
    v.push(op_id_conflict_variant());
    assert_from_coord_error_accepted::<ParkError>(v);

    // Rejected: CursorRegression, CursorOutOfBounds,
    //           SplitInvalid, CheckpointMissingKey
    let mut rejected = cursor_variants();
    rejected.push(split_invalid_variant());
    rejected.push(checkpoint_missing_key_variant());
    assert_from_coord_error_rejected::<ParkError>(rejected);
}

#[test]
fn split_error_from_coord_error_exhaustive() {
    let mut v = common_precondition_variants();
    v.push(op_id_conflict_variant());
    v.push(split_invalid_variant());
    assert_from_coord_error_accepted::<SplitError>(v);

    // Rejected: CursorRegression, CursorOutOfBounds,
    //           CheckpointMissingKey
    let mut rejected = cursor_variants();
    rejected.push(checkpoint_missing_key_variant());
    assert_from_coord_error_rejected::<SplitError>(rejected);
}

#[test]
fn renew_error_from_coord_error_exhaustive() {
    let v = common_precondition_variants();
    assert_from_coord_error_accepted::<RenewError>(v);

    // Rejected: OpIdConflict, CursorRegression,
    //           CursorOutOfBounds, SplitInvalid, CheckpointMissingKey
    let mut rejected = vec![op_id_conflict_variant()];
    rejected.extend(cursor_variants());
    rejected.push(split_invalid_variant());
    rejected.push(checkpoint_missing_key_variant());
    assert_from_coord_error_rejected::<RenewError>(rejected);
}

// -- Display + Security tests ----------------------------------------

#[test]
fn coord_error_display_no_actual_tenant() {
    let err = CoordError::TenantMismatch {
        expected: test_tenant(),
    };
    let display = err.to_string();
    // The display must contain "expected" but must not leak an "actual" tenant.
    assert!(display.contains("expected"), "should mention expected");
    assert!(
        !display.contains("actual"),
        "must not contain 'actual' tenant: {display}"
    );
}

#[test]
fn coord_error_display_already_leased_no_owner() {
    let err = AcquireError::AlreadyLeased {
        current_owner: WorkerId::from_raw(42),
        lease_deadline: LogicalTime::from_raw(999),
    };
    let display = err.to_string();
    // Deadline is ok to show, but worker identity must not leak.
    assert!(
        !display.contains("42"),
        "must not contain worker id: {display}"
    );
    assert!(display.contains("999"), "should contain deadline");
}

#[test]
fn error_display_deterministic() {
    let errors: Vec<CoordError> = all_coord_error_variants();
    for err in &errors {
        let s1 = err.to_string();
        let s2 = err.to_string();
        assert_eq!(s1, s2, "Display must be deterministic");
    }
}

fn assert_op_id_conflict_no_hash_leak(display: &str, debug: &str, type_name: &str) {
    // Display checks.
    assert!(
        !display.contains("DEAD") && !display.contains("CAFE"),
        "{type_name} Display leaks hex hash: {display}"
    );
    assert!(
        !display.contains("3735928559") && !display.contains("3405691582"),
        "{type_name} Display leaks decimal hash: {display}"
    );
    // Debug checks.
    assert!(
        debug.contains("<redacted>"),
        "{type_name} Debug must contain <redacted>: {debug}"
    );
    assert!(
        !debug.contains("DEAD") && !debug.contains("CAFE"),
        "{type_name} Debug leaks hex hash: {debug}"
    );
    assert!(
        !debug.contains("3735928559") && !debug.contains("3405691582"),
        "{type_name} Debug leaks decimal hash: {debug}"
    );
}

#[test]
fn op_id_conflict_no_hash_leak_all_types() {
    let op = OpId::from_raw(1);
    let ha = 0xDEAD_BEEF_u64;
    let hb = 0xCAFE_BABE_u64;

    // CoordError
    let e = CoordError::OpIdConflict {
        op_id: op,
        expected_hash: ha,
        actual_hash: hb,
    };
    assert_op_id_conflict_no_hash_leak(&e.to_string(), &format!("{e:?}"), "CoordError");

    // CheckpointError
    let e = CheckpointError::OpIdConflict {
        op_id: op,
        expected_hash: ha,
        actual_hash: hb,
    };
    assert_op_id_conflict_no_hash_leak(&e.to_string(), &format!("{e:?}"), "CheckpointError");

    // CompleteError
    let e = CompleteError::OpIdConflict {
        op_id: op,
        expected_hash: ha,
        actual_hash: hb,
    };
    assert_op_id_conflict_no_hash_leak(&e.to_string(), &format!("{e:?}"), "CompleteError");

    // ParkError
    let e = ParkError::OpIdConflict {
        op_id: op,
        expected_hash: ha,
        actual_hash: hb,
    };
    assert_op_id_conflict_no_hash_leak(&e.to_string(), &format!("{e:?}"), "ParkError");

    // SplitError
    let e = SplitError::OpIdConflict {
        op_id: op,
        expected_hash: ha,
        actual_hash: hb,
    };
    assert_op_id_conflict_no_hash_leak(&e.to_string(), &format!("{e:?}"), "SplitError");
}

// -- source() chain tests --------------------------------------------

#[test]
fn coord_error_split_invalid_source_returns_inner() {
    let inner = SplitValidationError::NoChildren;
    let err = CoordError::SplitInvalid(Box::new(inner.clone()));
    let src = err.source().expect("SplitInvalid should return source");
    assert_eq!(src.to_string(), inner.to_string());
}

#[test]
fn coord_error_non_split_source_returns_none() {
    let err = CoordError::ShardNotFound { shard: test_key() };
    assert!(err.source().is_none());
}

#[test]
fn split_error_source_propagates() {
    let inner = SplitValidationError::NoChildren;
    let err = SplitError::SplitInvalid(Box::new(inner.clone()));
    let src = err.source().expect("SplitInvalid should return source");
    assert_eq!(src.to_string(), inner.to_string());

    // Non-SplitInvalid variant returns None.
    let err = SplitError::ShardNotFound { shard: test_key() };
    assert!(err.source().is_none());
}

// -- PartialEq value-equality tests ----------------------------------

#[test]
fn coord_error_eq_compares_box_bytes_by_value() {
    let a = CoordError::CursorOutOfBounds(Box::new(CursorOutOfBoundsDetail {
        last_key: b"key".to_vec().into_boxed_slice(),
        spec_start: b"a".to_vec().into_boxed_slice(),
        spec_end: b"z".to_vec().into_boxed_slice(),
    }));
    let b = CoordError::CursorOutOfBounds(Box::new(CursorOutOfBoundsDetail {
        last_key: b"key".to_vec().into_boxed_slice(),
        spec_start: b"a".to_vec().into_boxed_slice(),
        spec_end: b"z".to_vec().into_boxed_slice(),
    }));
    // Different allocations, same content -- should be equal.
    assert_eq!(a, b);
}

#[test]
fn cursor_regression_eq_compares_option_box_by_value() {
    let a = CoordError::CursorRegression {
        old_key: Some(b"old".to_vec().into_boxed_slice()),
        new_key: Some(b"new".to_vec().into_boxed_slice()),
    };
    let b = CoordError::CursorRegression {
        old_key: Some(b"old".to_vec().into_boxed_slice()),
        new_key: Some(b"new".to_vec().into_boxed_slice()),
    };
    assert_eq!(a, b);

    // None vs Some should not be equal.
    let c = CoordError::CursorRegression {
        old_key: None,
        new_key: Some(b"new".to_vec().into_boxed_slice()),
    };
    assert_ne!(a, c);
}

// -- Debug redaction tests -------------------------------------------

#[test]
fn already_leased_debug_no_owner_leak() {
    let err = AcquireError::AlreadyLeased {
        current_owner: WorkerId::from_raw(42),
        lease_deadline: LogicalTime::from_raw(999),
    };
    let debug = format!("{err:?}");
    assert!(
        debug.contains("<redacted>"),
        "debug must redact current_owner: {debug}"
    );
    assert!(
        !debug.contains("42"),
        "debug must not leak worker id: {debug}"
    );
    assert!(debug.contains("999"), "debug should contain deadline");
}

#[test]
fn cursor_out_of_bounds_display_no_key_leak() {
    let err = CoordError::CursorOutOfBounds(Box::new(CursorOutOfBoundsDetail {
        last_key: b"SECRET_KEY_DATA".to_vec().into_boxed_slice(),
        spec_start: b"SPEC_START_BYTES".to_vec().into_boxed_slice(),
        spec_end: b"SPEC_END_BYTES".to_vec().into_boxed_slice(),
    }));
    let display = err.to_string();
    assert!(
        !display.contains("SECRET") && !display.contains("SPEC_"),
        "display must not leak raw key bytes: {display}"
    );
    assert!(
        display.contains("15"),
        "display should contain key byte length: {display}"
    );
}

#[test]
fn cursor_regression_display_no_key_leak() {
    let err = CoordError::CursorRegression {
        old_key: Some(b"OLD_SECRET_KEY".to_vec().into_boxed_slice()),
        new_key: Some(b"NEW_SECRET_KEY".to_vec().into_boxed_slice()),
    };
    let display = err.to_string();
    assert!(
        !display.contains("OLD_SECRET") && !display.contains("NEW_SECRET"),
        "display must not leak raw key bytes: {display}"
    );
}

#[test]
fn cursor_out_of_bounds_debug_no_key_leak() {
    let err = CoordError::CursorOutOfBounds(Box::new(CursorOutOfBoundsDetail {
        last_key: b"SECRET_KEY_DATA".to_vec().into_boxed_slice(),
        spec_start: b"SPEC_START_BYTES".to_vec().into_boxed_slice(),
        spec_end: b"SPEC_END_BYTES".to_vec().into_boxed_slice(),
    }));
    let debug = format!("{err:?}");
    assert!(
        !debug.contains("SECRET") && !debug.contains("SPEC_"),
        "debug must not leak raw key bytes: {debug}"
    );
    // Verify byte lengths are shown.
    assert!(
        debug.contains("15 bytes") && debug.contains("16 bytes") && debug.contains("14 bytes"),
        "debug should contain byte lengths: {debug}"
    );
}

#[test]
fn cursor_regression_debug_no_key_leak() {
    let err = CoordError::CursorRegression {
        old_key: Some(b"OLD_SECRET_KEY".to_vec().into_boxed_slice()),
        new_key: Some(b"NEW_SECRET_KEY".to_vec().into_boxed_slice()),
    };
    let debug = format!("{err:?}");
    assert!(
        !debug.contains("OLD_SECRET") && !debug.contains("NEW_SECRET"),
        "debug must not leak raw key bytes: {debug}"
    );
    // Verify byte lengths are shown.
    assert!(
        debug.contains("14 bytes"),
        "debug should contain byte lengths: {debug}"
    );
}

// -- AcquireScratch edge cases (F8) ----------------------------------

#[test]
#[should_panic(expected = "spec start exceeds MAX_KEY_SIZE")]
fn acquire_scratch_write_spec_panics_on_oversized_start() {
    let mut scratch = AcquireScratch::new();
    scratch.write_spec(&[0x01; MAX_KEY_SIZE + 1], b"z", &[]);
}

#[test]
#[should_panic(expected = "spec end exceeds MAX_KEY_SIZE")]
fn acquire_scratch_write_spec_panics_on_oversized_end() {
    let mut scratch = AcquireScratch::new();
    scratch.write_spec(b"a", &[0xFF; MAX_KEY_SIZE + 1], &[]);
}

#[test]
#[should_panic(expected = "spec metadata exceeds MAX_METADATA_SIZE")]
fn acquire_scratch_write_spec_panics_on_oversized_metadata() {
    let mut scratch = AcquireScratch::new();
    let meta = vec![0xAA; crate::coordination::shard_spec::MAX_METADATA_SIZE + 1];
    scratch.write_spec(b"a", b"z", &meta);
}

#[test]
fn acquire_scratch_cursor_view_with_token_but_no_last_key_returns_initial() {
    let mut scratch = AcquireScratch::new();
    // Write a cursor with no last_key but with token.
    // CursorUpdate::initial() should be returned because
    // cursor_view gates token on has_cursor_last_key.
    scratch.write_cursor(None, Some(b"some_token"));
    let view = scratch.view(ShardStatus::Active, CursorSemantics::Completed, None);
    let cursor = view.cursor();
    assert!(cursor.last_key().is_none());
    assert!(cursor.token().is_none());
}

#[test]
fn acquire_scratch_reset_then_view_returns_empty_state() {
    let mut scratch = AcquireScratch::new();
    scratch.write_spec(b"start", b"end", b"meta");
    scratch.write_cursor(Some(b"key"), Some(b"token"));
    scratch.reset();

    let view = scratch.view(ShardStatus::Active, CursorSemantics::Completed, None);
    assert!(view.spec().key_range_start().is_empty());
    assert!(view.spec().key_range_end().is_empty());
    assert!(view.spec().metadata().is_empty());
    assert!(view.cursor().last_key().is_none());
    assert!(view.cursor().token().is_none());
}

// -- Size regression test --------------------------------------------

#[test]
fn coord_error_size_regression() {
    assert!(
        std::mem::size_of::<CoordError>() <= 48,
        "CoordError is {} bytes, expected <= 48",
        std::mem::size_of::<CoordError>()
    );
}
