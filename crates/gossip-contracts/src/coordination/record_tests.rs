use super::*;
use crate::coordination::lease::{OpKind, OpResult};
use crate::test_util::canonical_digest;
use gossip_stdx::{InlineVec, RingBuffer};
use proptest::prelude::*;

// -- Test fixtures ---------------------------------------------------

fn test_tenant() -> TenantId {
    TenantId::from_bytes([0x01; 32])
}

fn test_run() -> RunId {
    RunId::from_raw(1)
}

fn test_spec() -> ShardSpec {
    ShardSpec::with_range(b"a".to_vec(), b"z".to_vec())
}

fn active_record() -> ShardRecord {
    ShardRecord::new_active(
        test_tenant(),
        test_run(),
        ShardId::from_raw(10),
        test_spec(),
        CursorSemantics::Completed,
    )
}

fn leased_record() -> ShardRecord {
    let mut r = active_record();
    r.lease = Some(LeaseHolder::new(
        WorkerId::from_raw(99),
        LogicalTime::from_raw(1000),
    ));
    r
}

fn make_entry(op_raw: u64) -> OpLogEntry {
    OpLogEntry::new(
        OpId::from_raw(op_raw),
        OpKind::Checkpoint,
        OpResult::Completed,
        0xABCD,
        LogicalTime::from_raw(100),
    )
}

/// Helper to create a derived ShardId (bit 63 set).
fn derived_shard_id(base: u64) -> ShardId {
    ShardId::from_raw(base | (1u64 << 63))
}

// -- ShardStatus -----------------------------------------------------

#[test]
fn shard_status_terminal_truth_table() {
    assert!(!ShardStatus::Active.is_terminal());
    assert!(ShardStatus::Done.is_terminal());
    assert!(ShardStatus::Split.is_terminal());
    assert!(ShardStatus::Parked.is_terminal());
}

#[test]
fn shard_status_roundtrip_table() {
    let cases: &[(u8, Option<ShardStatus>, Option<&str>)] = &[
        (0, Some(ShardStatus::Active), Some("Active")),
        (1, Some(ShardStatus::Done), Some("Done")),
        (2, Some(ShardStatus::Split), Some("Split")),
        (3, Some(ShardStatus::Parked), Some("Parked")),
        (4, None, None),
        (u8::MAX, None, None),
    ];
    for &(disc, expected, display) in cases {
        assert_eq!(
            ShardStatus::from_u8(disc),
            expected,
            "ShardStatus::from_u8({disc})"
        );
        if let Some(status) = expected {
            assert_eq!(status.as_u8(), disc, "ShardStatus::as_u8({status:?})");
            assert_eq!(
                status.to_string(),
                display.unwrap(),
                "ShardStatus::Display({status:?})"
            );
        }
    }
}

// -- ParkReason ------------------------------------------------------

#[test]
fn park_reason_roundtrip_table() {
    let cases: &[(u8, Option<ParkReason>, Option<&str>)] = &[
        (
            0,
            Some(ParkReason::PermissionDenied),
            Some("permission denied"),
        ),
        (1, Some(ParkReason::NotFound), Some("not found")),
        (2, Some(ParkReason::Poisoned), Some("poisoned")),
        (3, Some(ParkReason::TooManyErrors), Some("too many errors")),
        (4, Some(ParkReason::Other), Some("other")),
        (5, None, None),
        (u8::MAX, None, None),
    ];
    for &(disc, expected, display) in cases {
        assert_eq!(
            ParkReason::from_u8(disc),
            expected,
            "ParkReason::from_u8({disc})"
        );
        if let Some(reason) = expected {
            assert_eq!(reason.as_u8(), disc, "ParkReason::as_u8({reason:?})");
            assert_eq!(
                reason.to_string(),
                display.unwrap(),
                "ParkReason::Display({reason:?})"
            );
        }
    }
}

// -- assert_invariants (success) -------------------------------------

#[test]
fn assert_invariants_active_unleased_ok() {
    active_record().assert_invariants();
}

#[test]
fn assert_invariants_active_leased_ok() {
    leased_record().assert_invariants();
}

#[test]
fn assert_invariants_done_ok() {
    let mut r = active_record();
    r.status = ShardStatus::Done;
    r.assert_invariants();
}

#[test]
fn assert_invariants_parked_ok() {
    let mut r = active_record();
    r.status = ShardStatus::Parked;
    r.park_reason = Some(ParkReason::TooManyErrors);
    r.assert_invariants();
}

#[test]
fn assert_invariants_split_ok() {
    let mut r = active_record();
    r.status = ShardStatus::Split;
    r.spawned = InlineVec::from_slice(&[derived_shard_id(1), derived_shard_id(2)]);
    r.assert_invariants();
}

// -- assert_invariants (panics) --------------------------------------

#[test]
#[should_panic(expected = "must have park_reason")]
fn assert_invariants_parked_without_reason_panics() {
    let mut r = active_record();
    r.status = ShardStatus::Parked;
    // park_reason left as None.
    r.assert_invariants();
}

#[test]
#[should_panic(expected = "must not have park_reason")]
fn assert_invariants_active_with_reason_panics() {
    let mut r = active_record();
    r.park_reason = Some(ParkReason::Other);
    r.assert_invariants();
}

#[test]
fn assert_invariants_terminal_with_lease_panics() {
    let lease = Some(LeaseHolder::new(
        WorkerId::from_raw(1),
        LogicalTime::from_raw(100),
    ));
    let cases: Vec<(&str, ShardRecord)> = vec![
        (
            "Done",
            ShardRecord::from_raw_parts(
                test_tenant(),
                test_run(),
                ShardId::from_raw(10),
                ShardStatus::Done,
                None,
                test_spec(),
                Cursor::initial(),
                CursorSemantics::Completed,
                lease,
                FenceEpoch::INITIAL,
                None,
                InlineVec::new(),
                RingBuffer::new(),
            ),
        ),
        (
            "Parked",
            ShardRecord::from_raw_parts(
                test_tenant(),
                test_run(),
                ShardId::from_raw(10),
                ShardStatus::Parked,
                Some(ParkReason::TooManyErrors),
                test_spec(),
                Cursor::initial(),
                CursorSemantics::Completed,
                lease,
                FenceEpoch::INITIAL,
                None,
                InlineVec::new(),
                RingBuffer::new(),
            ),
        ),
        (
            "Split",
            ShardRecord::from_raw_parts(
                test_tenant(),
                test_run(),
                ShardId::from_raw(10),
                ShardStatus::Split,
                None,
                test_spec(),
                Cursor::initial(),
                CursorSemantics::Completed,
                lease,
                FenceEpoch::INITIAL,
                None,
                InlineVec::from_slice(&[derived_shard_id(1), derived_shard_id(2)]),
                RingBuffer::new(),
            ),
        ),
    ];
    for (label, record) in cases {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            record.assert_invariants();
        }));
        let err = result.expect_err(&format!(
            "{label}: assert_invariants should panic for terminal shard with lease"
        ));
        let msg = err
            .downcast_ref::<String>()
            .map(|s| s.as_str())
            .or_else(|| err.downcast_ref::<&str>().copied())
            .unwrap_or("<non-string panic>");
        assert!(
            msg.contains("must not have a lease"),
            "{label}: expected 'must not have a lease' in panic, got: {msg}"
        );
    }
}

// NOTE: op_log overflow test removed — RingBuffer prevents overflow at the
// type level, making the scenario unrepresentable.

#[test]
#[should_panic(expected = "not derived")]
fn assert_invariants_parent_some_but_not_derived_panics() {
    // ShardId with bit 63 clear but claiming a parent.
    let r = ShardRecord::from_raw_parts(
        test_tenant(),
        test_run(),
        ShardId::from_raw(10), // NOT derived
        ShardStatus::Active,
        None,
        test_spec(),
        Cursor::initial(),
        CursorSemantics::Completed,
        None,
        FenceEpoch::INITIAL,
        Some(ShardId::from_raw(5)), // has parent
        InlineVec::new(),
        RingBuffer::new(),
    );
    r.assert_invariants();
}

#[test]
#[should_panic(expected = "not derived")]
fn assert_invariants_spawned_contains_non_derived_panics() {
    let mut r = active_record();
    r.status = ShardStatus::Split;
    r.spawned = InlineVec::from_slice(&[ShardId::from_raw(42)]); // NOT derived (bit 63 clear)
    r.assert_invariants();
}

#[test]
#[should_panic(expected = "fence_epoch must be >= INITIAL")]
fn assert_invariants_fence_epoch_zero_panics() {
    let r = ShardRecord::from_raw_parts(
        test_tenant(),
        test_run(),
        ShardId::from_raw(10),
        ShardStatus::Active,
        None,
        test_spec(),
        Cursor::initial(),
        CursorSemantics::Completed,
        None,
        FenceEpoch::ZERO,
        None,
        InlineVec::new(),
        RingBuffer::new(),
    );
    r.assert_invariants();
}

#[test]
#[should_panic(expected = "must have spawned children")]
fn assert_invariants_split_without_spawned_panics() {
    let r = ShardRecord::from_raw_parts(
        test_tenant(),
        test_run(),
        ShardId::from_raw(10),
        ShardStatus::Split,
        None,
        test_spec(),
        Cursor::initial(),
        CursorSemantics::Completed,
        None,
        FenceEpoch::INITIAL,
        None,
        InlineVec::new(), // empty spawned
        RingBuffer::new(),
    );
    r.assert_invariants();
}

#[test]
#[should_panic(expected = "duplicate OpId")]
fn assert_invariants_duplicate_op_id_panics() {
    let mut entries = RingBuffer::<OpLogEntry, { ShardRecord::OP_LOG_CAP }>::new();
    entries.push_back(make_entry(42)).unwrap();
    entries.push_back(make_entry(42)).unwrap();
    let r = ShardRecord::from_raw_parts(
        test_tenant(),
        test_run(),
        ShardId::from_raw(10),
        ShardStatus::Active,
        None,
        test_spec(),
        Cursor::initial(),
        CursorSemantics::Completed,
        None,
        FenceEpoch::INITIAL,
        None,
        InlineVec::new(),
        entries,
    );
    r.assert_invariants();
}

#[test]
#[should_panic(expected = "spawned count")]
fn assert_invariants_spawned_exceeds_cap_panics() {
    let spawned: SpawnedList = (0..=MAX_SPAWNED_PER_SHARD as u64)
        .map(|i| derived_shard_id(i + 1))
        .collect();
    let r = ShardRecord::from_raw_parts(
        test_tenant(),
        test_run(),
        ShardId::from_raw(10),
        ShardStatus::Split,
        None,
        test_spec(),
        Cursor::initial(),
        CursorSemantics::Completed,
        None,
        FenceEpoch::INITIAL,
        None,
        spawned,
        RingBuffer::new(),
    );
    r.assert_invariants();
}

// -- Op-log ----------------------------------------------------------

#[test]
fn op_log_lookup_found() {
    let mut r = active_record();
    let entry = make_entry(42);
    r.op_log_push(entry);
    assert_eq!(
        r.op_log_lookup(OpId::from_raw(42)).unwrap().op_id(),
        OpId::from_raw(42)
    );
}

#[test]
fn op_log_lookup_not_found() {
    let r = active_record();
    assert!(r.op_log_lookup(OpId::from_raw(999)).is_none());
}

#[test]
fn op_log_push_evicts_oldest() {
    let mut r = active_record();
    // Fill to capacity.
    for i in 0..ShardRecord::OP_LOG_CAP as u64 {
        r.op_log_push(make_entry(i));
    }
    assert_eq!(r.op_log.len(), ShardRecord::OP_LOG_CAP);

    // Push one more — oldest (op_id=0) should be evicted.
    r.op_log_push(make_entry(999));
    assert_eq!(r.op_log.len(), ShardRecord::OP_LOG_CAP);
    assert!(r.op_log_lookup(OpId::from_raw(0)).is_none());
    assert!(r.op_log_lookup(OpId::from_raw(999)).is_some());
    // Second-oldest (op_id=1) must survive eviction.
    assert!(r.op_log_lookup(OpId::from_raw(1)).is_some());
}

#[test]
fn op_log_lookup_reverse_finds_recent_first() {
    let mut r = active_record();
    r.op_log_push(make_entry(1));
    r.op_log_push(make_entry(2));
    r.op_log_push(make_entry(3));
    // Should find op 3 first (reverse scan).
    assert_eq!(
        r.op_log_lookup(OpId::from_raw(3)).unwrap().op_id(),
        OpId::from_raw(3)
    );
}

// -- Snapshot --------------------------------------------------------

#[test]
fn snapshot_preserves_fields() {
    let r = active_record();
    let snap = r.snapshot();
    assert_eq!(snap.status(), r.status);
    assert_eq!(snap.spec(), &r.spec);
    assert_eq!(snap.cursor(), &r.cursor);
    assert_eq!(snap.cursor_semantics(), r.cursor_semantics);
    assert_eq!(snap.parent(), r.parent);
    assert_eq!(snap.spawned(), r.spawned.as_slice());
}

#[test]
fn snapshot_does_not_leak_coordination_state() {
    let r = leased_record();
    let snap = r.snapshot();
    let debug = format!("{snap:?}");
    assert!(
        !debug.contains("TenantId"),
        "snapshot Debug must not contain TenantId"
    );
    assert!(
        !debug.contains("WorkerId"),
        "snapshot Debug must not contain WorkerId"
    );
    assert!(
        !debug.contains("FenceEpoch"),
        "snapshot Debug must not contain FenceEpoch"
    );
}

// -- INV-7b: derived without parent -----------------------------------

#[test]
#[should_panic(expected = "derived (bit 63 set) but has no parent")]
fn assert_invariants_derived_without_parent_panics() {
    let r = ShardRecord::from_raw_parts(
        test_tenant(),
        test_run(),
        derived_shard_id(42), // derived, but parent is None
        ShardStatus::Active,
        None,
        test_spec(),
        Cursor::initial(),
        CursorSemantics::Completed,
        None,
        FenceEpoch::INITIAL,
        None, // parent = None -- violates INV-7b
        InlineVec::new(),
        RingBuffer::new(),
    );
    r.assert_invariants();
}

// -- assert_transition_legal -----------------------------------------

#[test]
fn assert_transition_legal_active_to_done_ok() {
    let r = active_record();
    r.assert_transition_legal(ShardStatus::Done);
}

#[test]
fn assert_transition_legal_active_to_parked_ok() {
    let r = active_record();
    r.assert_transition_legal(ShardStatus::Parked);
}

#[test]
fn assert_transition_legal_active_to_split_ok() {
    let r = active_record();
    r.assert_transition_legal(ShardStatus::Split);
}

#[test]
fn assert_transition_legal_done_to_done_ok() {
    let mut r = active_record();
    r.status = ShardStatus::Done;
    r.assert_transition_legal(ShardStatus::Done);
}

#[test]
#[should_panic(expected = "illegal transition from terminal")]
fn assert_transition_legal_done_to_active_panics() {
    let mut r = active_record();
    r.status = ShardStatus::Done;
    r.assert_transition_legal(ShardStatus::Active);
}

#[test]
#[should_panic(expected = "illegal transition from terminal")]
fn assert_transition_legal_parked_to_active_panics() {
    let mut r = active_record();
    r.status = ShardStatus::Parked;
    r.park_reason = Some(ParkReason::TooManyErrors);
    r.assert_transition_legal(ShardStatus::Active);
}

#[test]
#[should_panic(expected = "illegal transition from terminal")]
fn assert_transition_legal_split_to_done_panics() {
    let mut r = active_record();
    r.status = ShardStatus::Split;
    r.spawned = InlineVec::from_slice(&[derived_shard_id(1), derived_shard_id(2)]);
    r.assert_transition_legal(ShardStatus::Done);
}

// -- advance_fence ---------------------------------------------------

#[test]
fn advance_fence_increments() {
    let mut r = active_record();
    assert_eq!(r.fence_epoch, FenceEpoch::INITIAL);
    let new = r.advance_fence();
    assert_eq!(new, FenceEpoch::INITIAL.increment());
}

#[test]
fn advance_fence_monotonic() {
    let mut r = active_record();
    let f1 = r.advance_fence();
    let f2 = r.advance_fence();
    let f3 = r.advance_fence();
    assert!(f1 < f2);
    assert!(f2 < f3);
}

// -- is_leased_at ----------------------------------------------------

#[test]
fn is_leased_at_no_lease() {
    let r = active_record();
    assert!(!r.is_leased_at(LogicalTime::from_raw(0)));
}

// -- can_spawn -------------------------------------------------------

#[test]
fn can_spawn_within_cap() {
    let r = active_record();
    assert!(r.can_spawn(1));
    assert!(r.can_spawn(MAX_SPAWNED_PER_SHARD));
}

#[test]
fn can_spawn_at_cap() {
    let mut r = active_record();
    r.spawned = (0..MAX_SPAWNED_PER_SHARD as u64)
        .map(|i| derived_shard_id(i + 1))
        .collect();
    assert!(!r.can_spawn(1));
    assert!(r.can_spawn(0));
}

#[test]
fn can_spawn_overflow() {
    let r = active_record();
    assert!(!r.can_spawn(usize::MAX));
}

// -- op_log_push duplicate rejection ----------------------------------

#[test]
#[should_panic(expected = "duplicate OpId")]
fn op_log_push_rejects_duplicate() {
    let mut r = active_record();
    r.op_log_push(make_entry(42));
    r.op_log_push(make_entry(42)); // same OpId — should panic
}

// -- new_split_child construction ------------------------------------

#[test]
fn new_split_child_construction_and_fields() {
    let parent_id = ShardId::from_raw(10);
    let child_id = derived_shard_id(1);
    let cursor = Cursor::with_last_key(b"middle-key".to_vec());

    let record = ShardRecord::new_split_child(
        test_tenant(),
        test_run(),
        child_id,
        test_spec(),
        cursor.clone(),
        CursorSemantics::Dispatched,
        parent_id,
    );

    assert_eq!(record.status, ShardStatus::Active);
    assert_eq!(record.parent, Some(parent_id));
    assert_eq!(record.cursor, cursor);
    assert_eq!(record.cursor_semantics, CursorSemantics::Dispatched);
    assert_eq!(record.shard, child_id);
    assert!(record.spawned.is_empty());
    assert!(record.op_log.is_empty());
    assert_eq!(record.fence_epoch, FenceEpoch::INITIAL);
}

#[test]
#[should_panic(expected = "not derived")]
fn new_split_child_non_derived_shard_panics() {
    let _ = ShardRecord::new_split_child(
        test_tenant(),
        test_run(),
        ShardId::from_raw(10), // NOT derived
        test_spec(),
        Cursor::initial(),
        CursorSemantics::Completed,
        ShardId::from_raw(5),
    );
}

// -- Property tests --------------------------------------------------

proptest! {
    #![proptest_config(crate::test_util::miri_proptest_config())]

    #[test]
    fn op_log_push_bounded(ops in proptest::collection::vec(1u64..10000, 0..64)) {
        let mut r = active_record();
        for (i, &raw) in ops.iter().enumerate() {
            // Ensure unique op IDs by adding index offset.
            r.op_log_push(make_entry(raw * 10000 + i as u64));
        }
        prop_assert!(r.op_log.len() <= ShardRecord::OP_LOG_CAP);
    }

    #[test]
    fn park_reason_canonical_stable(v in 0u8..5) {
        let reason = ParkReason::from_u8(v).unwrap();
        prop_assert_eq!(canonical_digest(&reason), canonical_digest(&reason));
    }

    #[test]
    fn park_reason_canonical_collision_free(a in 0u8..5, b in 0u8..5) {
        prop_assume!(a != b);
        let ra = ParkReason::from_u8(a).unwrap();
        let rb = ParkReason::from_u8(b).unwrap();
        prop_assert_ne!(canonical_digest(&ra), canonical_digest(&rb));
    }

    #[test]
    fn is_leased_at_boundary_property(
        deadline_raw in 1u64..u64::MAX,
        now_raw in 0u64..u64::MAX,
    ) {
        let mut r = active_record();
        r.lease = Some(LeaseHolder::new(
            WorkerId::from_raw(99),
            LogicalTime::from_raw(deadline_raw),
        ));
        prop_assert_eq!(
            r.is_leased_at(LogicalTime::from_raw(now_raw)),
            now_raw < deadline_raw,
        );
    }
}
