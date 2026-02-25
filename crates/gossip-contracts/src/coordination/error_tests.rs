use std::error::Error;

use rstest::rstest;

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
        CoordError::CursorOutOfBounds(CursorOutOfBoundsDetail {
            last_key: 1,
            spec_start: 1,
            spec_end: 1,
        }),
        CoordError::CursorKeyTooLarge {
            size: MAX_KEY_SIZE + 1,
            max: MAX_KEY_SIZE,
        },
    ]
}

fn split_invalid_variant() -> CoordError {
    CoordError::SplitInvalid(SplitValidationError::NoChildren)
}

fn checkpoint_missing_key_variant() -> CoordError {
    CoordError::CheckpointMissingKey
}

/// All 11 `CoordError` variants. Used by the display-determinism test.
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
// Each invocation composes variant groups and converts them, verifying
// every valid conversion succeeds. The explicit rejection arms in the
// From impls (not wildcard `_`) guarantee that adding a new CoordError
// variant triggers a compile error.

macro_rules! from_coord_error_exhaustive {
    ($name:ident, $ty:ty,
     accepted: [$($acc:expr),* $(,)?],
     rejected: [$($rej:expr),* $(,)?]) => {
        #[test]
        fn $name() {
            let mut accepted = Vec::new();
            $(accepted.extend($acc);)*
            assert_from_coord_error_accepted::<$ty>(accepted);
            let mut rejected = Vec::new();
            $(rejected.extend($rej);)*
            assert_from_coord_error_rejected::<$ty>(rejected);
        }
    };
}

from_coord_error_exhaustive!(checkpoint_error_from_coord_error_exhaustive, CheckpointError,
    accepted: [common_precondition_variants(), vec![op_id_conflict_variant()],
               cursor_variants(), vec![checkpoint_missing_key_variant()]],
    rejected: [vec![split_invalid_variant()]]);

from_coord_error_exhaustive!(complete_error_from_coord_error_exhaustive, CompleteError,
    accepted: [common_precondition_variants(), vec![op_id_conflict_variant()],
               cursor_variants(), vec![checkpoint_missing_key_variant()]],
    rejected: [vec![split_invalid_variant()]]);

from_coord_error_exhaustive!(park_error_from_coord_error_exhaustive, ParkError,
    accepted: [common_precondition_variants(), vec![op_id_conflict_variant()]],
    rejected: [cursor_variants(), vec![split_invalid_variant()],
               vec![checkpoint_missing_key_variant()]]);

from_coord_error_exhaustive!(split_error_from_coord_error_exhaustive, SplitError,
    accepted: [common_precondition_variants(), vec![op_id_conflict_variant()],
               vec![split_invalid_variant()]],
    rejected: [cursor_variants(), vec![checkpoint_missing_key_variant()]]);

from_coord_error_exhaustive!(renew_error_from_coord_error_exhaustive, RenewError,
    accepted: [common_precondition_variants()],
    rejected: [vec![op_id_conflict_variant()], cursor_variants(),
               vec![split_invalid_variant()], vec![checkpoint_missing_key_variant()]]);

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
    let err = CoordError::SplitInvalid(inner.clone());
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
    let err = SplitError::SplitInvalid(inner.clone());
    let src = err.source().expect("SplitInvalid should return source");
    assert_eq!(src.to_string(), inner.to_string());

    // Non-SplitInvalid variant returns None.
    let err = SplitError::ShardNotFound { shard: test_key() };
    assert!(err.source().is_none());
}

// -- PartialEq value-equality tests ----------------------------------

#[test]
fn coord_error_eq_compares_cursor_oob_lengths_by_value() {
    let a = CoordError::CursorOutOfBounds(CursorOutOfBoundsDetail {
        last_key: 3,
        spec_start: 1,
        spec_end: 1,
    });
    let b = CoordError::CursorOutOfBounds(CursorOutOfBoundsDetail {
        last_key: 3,
        spec_start: 1,
        spec_end: 1,
    });
    assert_eq!(a, b);
}

#[test]
fn cursor_regression_eq_compares_option_lengths_by_value() {
    let a = CoordError::CursorRegression {
        old_key: Some(3),
        new_key: Some(3),
    };
    let b = CoordError::CursorRegression {
        old_key: Some(3),
        new_key: Some(3),
    };
    assert_eq!(a, b);

    // None vs Some should not be equal.
    let c = CoordError::CursorRegression {
        old_key: None,
        new_key: Some(3),
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

fn oob_error() -> CoordError {
    CoordError::CursorOutOfBounds(CursorOutOfBoundsDetail {
        last_key: b"SECRET_KEY_DATA".len(),
        spec_start: b"SPEC_START_BYTES".len(),
        spec_end: b"SPEC_END_BYTES".len(),
    })
}

fn regression_error() -> CoordError {
    CoordError::CursorRegression {
        old_key: Some(b"OLD_SECRET_KEY".len()),
        new_key: Some(b"NEW_SECRET_KEY".len()),
    }
}

#[rstest]
#[case::oob_display(oob_error(), false, &["SECRET", "SPEC_"], &["15"])]
#[case::oob_debug(oob_error(), true, &["SECRET", "SPEC_"], &["15 bytes", "16 bytes", "14 bytes"])]
#[case::regression_display(regression_error(), false, &["OLD_SECRET", "NEW_SECRET"], &[])]
#[case::regression_debug(regression_error(), true, &["OLD_SECRET", "NEW_SECRET"], &["14 bytes"])]
fn cursor_data_redaction(
    #[case] err: CoordError,
    #[case] use_debug: bool,
    #[case] forbidden: &[&str],
    #[case] required: &[&str],
) {
    let output = if use_debug {
        format!("{err:?}")
    } else {
        err.to_string()
    };
    let mode = if use_debug { "Debug" } else { "Display" };
    for needle in forbidden {
        assert!(
            !output.contains(needle),
            "{mode} must not leak raw key bytes (found {needle:?}): {output}"
        );
    }
    for needle in required {
        assert!(
            output.contains(needle),
            "{mode} should contain {needle:?}: {output}"
        );
    }
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
#[should_panic(expected = "cursor last_key exceeds MAX_KEY_SIZE")]
fn acquire_scratch_write_cursor_panics_on_oversized_last_key() {
    let mut scratch = AcquireScratch::new();
    scratch.write_cursor(Some(&[0x01; MAX_KEY_SIZE + 1]), None);
}

#[test]
#[should_panic(expected = "cursor token exceeds MAX_TOKEN_SIZE")]
fn acquire_scratch_write_cursor_panics_on_oversized_token() {
    let mut scratch = AcquireScratch::new();
    scratch.write_cursor(Some(b"k"), Some(&[0x02; MAX_TOKEN_SIZE + 1]));
}

#[test]
fn acquire_scratch_cursor_view_with_token_but_no_last_key_returns_initial() {
    let mut scratch = AcquireScratch::new();
    // Write a cursor with no last_key but with token.
    // CursorUpdate::initial() should be returned because
    // cursor_view derives presence from len > 0.
    scratch.write_cursor(None, Some(b"some_token"));
    let view = scratch.view(ShardStatus::Active, CursorSemantics::Completed, None);
    let cursor = view.cursor();
    assert!(cursor.last_key().is_none());
    assert!(cursor.token().is_none());
}

#[test]
fn acquire_scratch_cursor_view_with_empty_last_key_returns_initial() {
    let mut scratch = AcquireScratch::new();
    scratch.write_cursor(Some(b"key"), Some(b"token"));
    scratch.write_cursor(Some(&[]), Some(b"updated_token"));
    let view = scratch.view(ShardStatus::Active, CursorSemantics::Completed, None);
    let cursor = view.cursor();
    assert!(cursor.last_key().is_none());
    assert!(cursor.token().is_none());
}

#[test]
fn acquire_scratch_cursor_view_with_empty_token_returns_last_key_only() {
    let mut scratch = AcquireScratch::new();
    scratch.write_cursor(Some(b"key"), Some(&[]));
    let view = scratch.view(ShardStatus::Active, CursorSemantics::Completed, None);
    let cursor = view.cursor();
    assert_eq!(cursor.last_key(), Some(&b"key"[..]));
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

// -- FixedBuf ---------------------------------------------------------------

#[test]
#[should_panic(expected = "oversized")]
fn fixed_buf_write_oversized_panics() {
    let mut buf = FixedBuf::<4>::new();
    buf.write(b"abcde", "oversized");
}

#[test]
fn fixed_buf_reset_clears_logically() {
    let mut buf = FixedBuf::<16>::new();
    buf.write(b"data", "test");
    assert!(buf.has_data());
    buf.reset();
    assert!(!buf.has_data());
    assert!(buf.read().is_empty());
}

#[test]
fn fixed_buf_debug_output_format() {
    let buf = FixedBuf::<16>::from_slice(b"abcdef", "test");
    let dbg = format!("{buf:?}");
    assert!(dbg.contains("6 bytes"), "should contain byte count: {dbg}");

    let empty = FixedBuf::<8>::new();
    let dbg_empty = format!("{empty:?}");
    assert!(dbg_empty.contains("empty"), "should say empty: {dbg_empty}");
}

proptest::proptest! {
    #![proptest_config(crate::test_util::miri_proptest_config())]

    /// write→read roundtrip: any slice that fits is returned verbatim.
    /// Subsumes individual roundtrip, at-capacity, and replace-shorter tests.
    #[test]
    fn fixed_buf_write_read_roundtrip(
        first in proptest::collection::vec(proptest::num::u8::ANY, 0..=64),
        second in proptest::collection::vec(proptest::num::u8::ANY, 0..=64),
    ) {
        let mut buf = FixedBuf::<64>::new();

        buf.write(&first, "test");
        proptest::prop_assert_eq!(buf.read(), first.as_slice());
        proptest::prop_assert_eq!(buf.has_data(), !first.is_empty());

        // Overwrite with second value — only new content survives.
        buf.write(&second, "test");
        proptest::prop_assert_eq!(buf.read(), second.as_slice());
    }

    /// Equality tracks logical content, not backing-array padding bytes.
    #[test]
    fn fixed_buf_equality_matches_content(
        a in proptest::collection::vec(proptest::num::u8::ANY, 0..=32),
        b in proptest::collection::vec(proptest::num::u8::ANY, 0..=32),
    ) {
        let fa = FixedBuf::<32>::from_slice(&a, "test");
        let fb = FixedBuf::<32>::from_slice(&b, "test");

        if a == b {
            proptest::prop_assert_eq!(&fa, &fb);
        } else {
            proptest::prop_assert_ne!(&fa, &fb);
        }
    }
}
