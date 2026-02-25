//! Tests for [`ShardRecord`] and its supporting types (`ShardStatus`,
//! `ParkReason`, `OpLogEntry`, `ShardSnapshot`).
//!
//! `ShardRecord` is the single source of truth for a shard's state in the
//! coordinator. Every field on it has invariants that are enforced by
//! `assert_invariants()`, and the record's op-log provides bounded
//! idempotency detection. This module tests those invariants exhaustively.
//!
//! # Coverage Areas
//!
//! - **Enum discriminant stability**: `ShardStatus` and `ParkReason`
//!   roundtrip through `as_u8`/`from_u8` and produce the expected
//!   `Display` output. These are persisted values; discriminant drift
//!   is a data-corruption bug.
//!
//! - **`assert_invariants` truth table**: every valid record configuration
//!   passes, and every illegal configuration (Parked without reason,
//!   Active with reason, terminal with lease, derived without parent,
//!   parent without derived bit, zero fence epoch, Split without
//!   spawned, duplicate op-log entries, spawned exceeding cap) panics
//!   with a specific message.
//!
//! - **Op-log mechanics**: lookup (found/not-found), reverse-scan bias
//!   toward recent entries, FIFO eviction at capacity, and duplicate
//!   rejection.
//!
//! - **Snapshot fidelity**: all record fields are faithfully projected
//!   into `ShardSnapshot`, and coordination-internal state (tenant,
//!   worker, fence) is excluded from the snapshot's `Debug` output.
//!
//! - **State-transition legality**: the `assert_transition_legal`
//!   guard allows Active-to-{Done,Parked,Split} and idempotent
//!   terminal-to-same, but panics on terminal-to-different.
//!
//! - **Fence monotonicity**: `advance_fence` increments strictly.
//!
//! - **Lease boundary**: `is_leased_at` uses a half-open interval.
//!
//! - **Spawned capacity**: `can_spawn` respects the per-shard cap and
//!   handles overflow.
//!
//! - **Split child construction**: `new_split_child` sets the correct
//!   parent, status, cursor, and fence, and rejects non-derived IDs.

use super::*;
use crate::coordination::lease::{OpKind, OpResult};
use crate::coordination::test_fixtures::{derived_shard_id, test_run, test_spec, test_tenant};
use crate::test_util::{TestSlab, canonical_digest};
use gossip_stdx::{ByteSlab, InlineVec, RingBuffer};
use proptest::prelude::*;
use rstest::rstest;

// -- Test fixtures ---------------------------------------------------

fn active_record(slab: &mut ByteSlab) -> ShardRecord {
    let spec = test_spec();
    ShardRecord::new_active(
        test_tenant(),
        test_run(),
        ShardId::from_raw(10),
        spec.as_ref(),
        CursorSemantics::Completed,
        slab,
    )
    .expect("slab large enough for test fixture")
}

fn leased_record(slab: &mut ByteSlab) -> ShardRecord {
    let mut r = active_record(slab);
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

// ============================================================================
// ShardStatus discriminant stability and terminal classification
//
// ShardStatus is persisted as `#[repr(u8)]`. These tests pin the exact
// discriminant-to-variant mapping and the terminal/non-terminal partition.
// ============================================================================

/// Each valid discriminant roundtrips through `as_u8`/`from_u8`, produces
/// the expected `Display` output, and is correctly classified as terminal
/// or non-terminal.
#[rstest]
#[case::active(0, ShardStatus::Active, "Active", false)]
#[case::done(1, ShardStatus::Done, "Done", true)]
#[case::split(2, ShardStatus::Split, "Split", true)]
#[case::parked(3, ShardStatus::Parked, "Parked", true)]
fn shard_status_properties(
    #[case] disc: u8,
    #[case] status: ShardStatus,
    #[case] display: &str,
    #[case] terminal: bool,
) {
    assert_eq!(ShardStatus::from_u8(disc), Some(status));
    assert_eq!(status.as_u8(), disc);
    assert_eq!(status.to_string(), display);
    assert_eq!(status.is_terminal(), terminal);
}

/// Out-of-range discriminants must return `None`.
#[rstest]
#[case::out_of_range_4(4)]
#[case::out_of_range_max(u8::MAX)]
fn shard_status_from_u8_rejects_invalid(#[case] disc: u8) {
    assert_eq!(ShardStatus::from_u8(disc), None);
}

// ============================================================================
// ParkReason discriminant stability
// ============================================================================

/// Each valid discriminant roundtrips through `as_u8`/`from_u8` and produces
/// the expected `Display` output.
#[rstest]
#[case::permission_denied(0, ParkReason::PermissionDenied, "permission denied")]
#[case::not_found(1, ParkReason::NotFound, "not found")]
#[case::poisoned(2, ParkReason::Poisoned, "poisoned")]
#[case::too_many_errors(3, ParkReason::TooManyErrors, "too many errors")]
#[case::other(4, ParkReason::Other, "other")]
fn park_reason_properties(#[case] disc: u8, #[case] reason: ParkReason, #[case] display: &str) {
    assert_eq!(ParkReason::from_u8(disc), Some(reason));
    assert_eq!(reason.as_u8(), disc);
    assert_eq!(reason.to_string(), display);
}

/// Out-of-range discriminants must return `None`.
#[rstest]
#[case::out_of_range_5(5)]
#[case::out_of_range_max(u8::MAX)]
fn park_reason_from_u8_rejects_invalid(#[case] disc: u8) {
    assert_eq!(ParkReason::from_u8(disc), None);
}

// ============================================================================
// assert_invariants — valid configurations
//
// Each test constructs one valid record state and verifies assert_invariants
// does not panic. Together these cover every ShardStatus variant.
// ============================================================================

/// Active with no lease is the initial post-registration state.
#[test]
fn assert_invariants_active_unleased_ok() {
    let mut slab = TestSlab::new();
    active_record(&mut slab).assert_invariants();
}

#[test]
fn assert_invariants_active_leased_ok() {
    let mut slab = TestSlab::new();
    leased_record(&mut slab).assert_invariants();
}

#[test]
fn assert_invariants_done_ok() {
    let mut slab = TestSlab::new();
    let mut r = active_record(&mut slab);
    r.status = ShardStatus::Done;
    r.assert_invariants();
}

#[test]
fn assert_invariants_parked_ok() {
    let mut slab = TestSlab::new();
    let mut r = active_record(&mut slab);
    r.status = ShardStatus::Parked;
    r.park_reason = Some(ParkReason::TooManyErrors);
    r.assert_invariants();
}

#[test]
fn assert_invariants_split_ok() {
    let mut slab = TestSlab::new();
    let mut r = active_record(&mut slab);
    r.status = ShardStatus::Split;
    r.spawned = InlineVec::from_slice(&[derived_shard_id(1), derived_shard_id(2)]);
    r.assert_invariants();
}

// ============================================================================
// assert_invariants — illegal configurations (must panic)
//
// Each test constructs exactly one invariant violation and verifies the
// panic message. The expected-string in `#[should_panic]` pins the exact
// invariant being violated, so regressions that silently accept bad state
// are caught.
// ============================================================================

/// Parked status requires a `park_reason` explaining why the shard was parked.
#[test]
#[should_panic(expected = "must have park_reason")]
fn assert_invariants_parked_without_reason_panics() {
    let mut slab = TestSlab::new();
    let mut r = active_record(&mut slab);
    r.status = ShardStatus::Parked;
    // park_reason left as None.
    r.assert_invariants();
}

/// Non-Parked statuses must not carry a `park_reason` (it would be stale).
#[test]
#[should_panic(expected = "must not have park_reason")]
fn assert_invariants_active_with_reason_panics() {
    let mut slab = TestSlab::new();
    let mut r = active_record(&mut slab);
    r.park_reason = Some(ParkReason::Other);
    r.assert_invariants();
}

/// Terminal shards (Done, Parked, Split) must have their lease cleared.
/// A lingering lease would block future admin operations and violate the
/// "terminal = no owner" invariant.
#[rstest]
#[case::done(ShardStatus::Done, None, InlineVec::new())]
#[case::parked(ShardStatus::Parked, Some(ParkReason::TooManyErrors), InlineVec::new())]
#[case::split(ShardStatus::Split, None, InlineVec::from_slice(&[derived_shard_id(1), derived_shard_id(2)]))]
#[should_panic(expected = "must not have a lease")]
fn assert_invariants_terminal_with_lease_panics(
    #[case] status: ShardStatus,
    #[case] park_reason: Option<ParkReason>,
    #[case] spawned: SpawnedList,
) {
    let mut slab = TestSlab::new();
    let lease = Some(LeaseHolder::new(
        WorkerId::from_raw(1),
        LogicalTime::from_raw(100),
    ));
    let r = ShardRecord::from_raw_parts(
        test_tenant(),
        test_run(),
        ShardId::from_raw(10),
        status,
        park_reason,
        &test_spec(),
        &Cursor::initial(),
        CursorSemantics::Completed,
        lease,
        FenceEpoch::INITIAL,
        None,
        spawned,
        RingBuffer::new(),
        &mut slab,
    );
    r.assert_invariants();
}

// NOTE: op_log overflow test removed — RingBuffer prevents overflow at the
// type level, making the scenario unrepresentable.

/// A shard with a `parent` field set must have its derived bit (bit 63) set
/// on its `ShardId`. A non-derived ID claiming a parent is a construction bug.
#[test]
#[should_panic(expected = "not derived")]
fn assert_invariants_parent_some_but_not_derived_panics() {
    let mut slab = TestSlab::new();
    // ShardId with bit 63 clear but claiming a parent.
    let r = ShardRecord::from_raw_parts(
        test_tenant(),
        test_run(),
        ShardId::from_raw(10), // NOT derived
        ShardStatus::Active,
        None,
        &test_spec(),
        &Cursor::initial(),
        CursorSemantics::Completed,
        None,
        FenceEpoch::INITIAL,
        Some(ShardId::from_raw(5)), // has parent
        InlineVec::new(),
        RingBuffer::new(),
        &mut slab,
    );
    r.assert_invariants();
}

/// Every entry in `spawned` must be a derived ShardId. A non-derived ID in the
/// spawned list means a split operation generated an ID incorrectly.
#[test]
#[should_panic(expected = "not derived")]
fn assert_invariants_spawned_contains_non_derived_panics() {
    let mut slab = TestSlab::new();
    let mut r = active_record(&mut slab);
    r.status = ShardStatus::Split;
    r.spawned = InlineVec::from_slice(&[ShardId::from_raw(42)]); // NOT derived (bit 63 clear)
    r.assert_invariants();
}

/// `FenceEpoch::ZERO` is reserved as a sentinel. All records must start at
/// `INITIAL` (which is 1) and only increase from there.
#[test]
#[should_panic(expected = "fence_epoch must be >= INITIAL")]
fn assert_invariants_fence_epoch_zero_panics() {
    let mut slab = TestSlab::new();
    let r = ShardRecord::from_raw_parts(
        test_tenant(),
        test_run(),
        ShardId::from_raw(10),
        ShardStatus::Active,
        None,
        &test_spec(),
        &Cursor::initial(),
        CursorSemantics::Completed,
        None,
        FenceEpoch::ZERO,
        None,
        InlineVec::new(),
        RingBuffer::new(),
        &mut slab,
    );
    r.assert_invariants();
}

#[test]
#[should_panic(expected = "must have spawned children")]
fn assert_invariants_split_without_spawned_panics() {
    let mut slab = TestSlab::new();
    let r = ShardRecord::from_raw_parts(
        test_tenant(),
        test_run(),
        ShardId::from_raw(10),
        ShardStatus::Split,
        None,
        &test_spec(),
        &Cursor::initial(),
        CursorSemantics::Completed,
        None,
        FenceEpoch::INITIAL,
        None,
        InlineVec::new(), // empty spawned
        RingBuffer::new(),
        &mut slab,
    );
    r.assert_invariants();
}

#[test]
#[should_panic(expected = "duplicate OpId")]
fn assert_invariants_duplicate_op_id_panics() {
    let mut slab = TestSlab::new();
    let mut entries = RingBuffer::<OpLogEntry, { ShardRecord::OP_LOG_CAP }>::new();
    entries.push_back(make_entry(42)).unwrap();
    entries.push_back(make_entry(42)).unwrap();
    let r = ShardRecord::from_raw_parts(
        test_tenant(),
        test_run(),
        ShardId::from_raw(10),
        ShardStatus::Active,
        None,
        &test_spec(),
        &Cursor::initial(),
        CursorSemantics::Completed,
        None,
        FenceEpoch::INITIAL,
        None,
        InlineVec::new(),
        entries,
        &mut slab,
    );
    r.assert_invariants();
}

#[test]
#[should_panic(expected = "spawned count")]
fn assert_invariants_spawned_exceeds_cap_panics() {
    let mut slab = TestSlab::new();
    let spawned: SpawnedList = (0..=MAX_SPAWNED_PER_SHARD as u64)
        .map(|i| derived_shard_id(i + 1))
        .collect();
    let r = ShardRecord::from_raw_parts(
        test_tenant(),
        test_run(),
        ShardId::from_raw(10),
        ShardStatus::Split,
        None,
        &test_spec(),
        &Cursor::initial(),
        CursorSemantics::Completed,
        None,
        FenceEpoch::INITIAL,
        None,
        spawned,
        RingBuffer::new(),
        &mut slab,
    );
    r.assert_invariants();
}

// ============================================================================
// Op-log mechanics
//
// The shard op-log is a bounded ring buffer (OP_LOG_CAP = 16) used for
// idempotency detection. Lookup is reverse-biased (most recent first) since
// replays typically hit the last few entries. Eviction is FIFO: when full,
// push evicts the oldest entry. Duplicate op_ids are rejected at push time.
// ============================================================================

/// Lookup finds an entry that was just pushed.
#[test]
fn op_log_lookup_found() {
    let mut slab = TestSlab::new();
    let mut r = active_record(&mut slab);
    let entry = make_entry(42);
    r.op_log_push(entry);
    assert_eq!(
        r.op_log_lookup(OpId::from_raw(42)).unwrap().op_id(),
        OpId::from_raw(42)
    );
}

/// Lookup on an empty op-log returns `None`.
#[test]
fn op_log_lookup_not_found() {
    let mut slab = TestSlab::new();
    let r = active_record(&mut slab);
    assert!(r.op_log_lookup(OpId::from_raw(999)).is_none());
}

/// At capacity, the oldest entry (op_id=0) is evicted; the newest and
/// second-oldest survive. This is the FIFO ring-buffer contract.
#[test]
fn op_log_push_evicts_oldest() {
    let mut slab = TestSlab::new();
    let mut r = active_record(&mut slab);
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

/// Reverse scan finds the most recent entry first, optimizing for the
/// common case where replays target the latest operation.
#[test]
fn op_log_lookup_reverse_finds_recent_first() {
    let mut slab = TestSlab::new();
    let mut r = active_record(&mut slab);
    r.op_log_push(make_entry(1));
    r.op_log_push(make_entry(2));
    r.op_log_push(make_entry(3));
    // Should find op 3 first (reverse scan).
    assert_eq!(
        r.op_log_lookup(OpId::from_raw(3)).unwrap().op_id(),
        OpId::from_raw(3)
    );
}

// ============================================================================
// Snapshot fidelity and information hiding
//
// ShardSnapshot is the worker-visible projection of a ShardRecord. It must
// contain all fields a worker needs (spec, cursor, status, lineage) but must
// NOT expose coordination-internal state (tenant, worker, fence).
// ============================================================================

/// All domain-relevant fields survive the record-to-snapshot projection.
#[test]
fn snapshot_preserves_fields() {
    let mut slab = TestSlab::new();
    let r = active_record(&mut slab);
    let snap = r.snapshot(&slab);

    // Materialize pooled fields for comparison.
    let spec = r.spec.to_spec(&slab);
    let cursor = r.cursor.to_cursor(&slab);

    assert_eq!(snap.status(), r.status);
    assert_eq!(snap.spec(), &spec);
    assert_eq!(snap.cursor(), &cursor);
    assert_eq!(snap.cursor_semantics(), r.cursor_semantics);
    assert_eq!(snap.parent(), r.parent);
    assert_eq!(snap.spawned(), r.spawned.as_slice());
}

/// The Debug output of a snapshot must not contain TenantId, WorkerId, or
/// FenceEpoch. Leaking these into worker-visible output would violate the
/// information-hiding boundary between coordination and processing.
#[test]
fn snapshot_does_not_leak_coordination_state() {
    let mut slab = TestSlab::new();
    let r = leased_record(&mut slab);
    let snap = r.snapshot(&slab);
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

// ============================================================================
// INV-7b: derived-bit / parent biconditional
//
// A derived ShardId (bit 63 set) must always have a parent, and vice versa.
// This is the inverse of the parent-without-derived test above.
// ============================================================================

/// A derived ShardId without a parent violates INV-7b.
#[test]
#[should_panic(expected = "derived (bit 63 set) but has no parent")]
fn assert_invariants_derived_without_parent_panics() {
    let mut slab = TestSlab::new();
    let r = ShardRecord::from_raw_parts(
        test_tenant(),
        test_run(),
        derived_shard_id(42), // derived, but parent is None
        ShardStatus::Active,
        None,
        &test_spec(),
        &Cursor::initial(),
        CursorSemantics::Completed,
        None,
        FenceEpoch::INITIAL,
        None, // parent = None -- violates INV-7b
        InlineVec::new(),
        RingBuffer::new(),
        &mut slab,
    );
    r.assert_invariants();
}

// ============================================================================
// State-transition legality
//
// The shard state machine allows Active -> {Done, Parked, Split} and
// idempotent terminal -> same-terminal. All other transitions (e.g.
// Done -> Active, Parked -> Active, Split -> Done) are illegal.
// ============================================================================

/// Active -> {Done, Parked, Split} are the three valid terminal transitions.
#[rstest]
#[case::to_done(ShardStatus::Done)]
#[case::to_parked(ShardStatus::Parked)]
#[case::to_split(ShardStatus::Split)]
fn transition_legal_active_to_terminal(#[case] target: ShardStatus) {
    let mut slab = TestSlab::new();
    let r = active_record(&mut slab);
    r.assert_transition_legal(target);
}

/// Done -> Done is allowed (idempotent terminal replay).
#[test]
fn assert_transition_legal_done_to_done_ok() {
    let mut slab = TestSlab::new();
    let mut r = active_record(&mut slab);
    r.status = ShardStatus::Done;
    r.assert_transition_legal(ShardStatus::Done);
}

/// Terminal -> different-terminal or terminal -> Active are all illegal.
#[rstest]
#[case::done_to_active(ShardStatus::Done, ShardStatus::Active)]
#[case::parked_to_active(ShardStatus::Parked, ShardStatus::Active)]
#[case::split_to_done(ShardStatus::Split, ShardStatus::Done)]
#[should_panic(expected = "illegal transition from terminal")]
fn transition_illegal_from_terminal(#[case] from: ShardStatus, #[case] to: ShardStatus) {
    let mut slab = TestSlab::new();
    let mut r = active_record(&mut slab);
    r.status = from;
    if from == ShardStatus::Parked {
        r.park_reason = Some(ParkReason::TooManyErrors);
    }
    if from == ShardStatus::Split {
        r.spawned = InlineVec::from_slice(&[derived_shard_id(1), derived_shard_id(2)]);
    }
    r.assert_transition_legal(to);
}

// ============================================================================
// Fence monotonicity
//
// advance_fence is called on every acquire. It must strictly increment the
// epoch on every call, never repeat a value, and never decrease.
// ============================================================================

/// First advance moves from INITIAL to INITIAL+1.
#[test]
fn advance_fence_increments() {
    let mut slab = TestSlab::new();
    let mut r = active_record(&mut slab);
    assert_eq!(r.fence_epoch, FenceEpoch::INITIAL);
    let new = r.advance_fence();
    assert_eq!(new, FenceEpoch::INITIAL.increment());
}

/// Three successive advances produce a strictly increasing sequence.
#[test]
fn advance_fence_monotonic() {
    let mut slab = TestSlab::new();
    let mut r = active_record(&mut slab);
    let f1 = r.advance_fence();
    let f2 = r.advance_fence();
    let f3 = r.advance_fence();
    assert!(f1 < f2);
    assert!(f2 < f3);
}

// ============================================================================
// Lease boundary (is_leased_at)
//
// A shard is leased at time `now` iff it has a lease and `now < deadline`
// (half-open interval). No lease means never leased.
// ============================================================================

/// A record with no lease is never leased, regardless of the time argument.
#[test]
fn is_leased_at_no_lease() {
    let mut slab = TestSlab::new();
    let r = active_record(&mut slab);
    assert!(!r.is_leased_at(LogicalTime::from_raw(0)));
}

// ============================================================================
// Spawned capacity (can_spawn)
//
// Each shard has a maximum number of children it can spawn
// (MAX_SPAWNED_PER_SHARD). can_spawn checks whether `current + requested`
// fits within the cap, handling overflow safely.
// ============================================================================

/// A fresh record can spawn 1 or up to MAX_SPAWNED_PER_SHARD children.
#[test]
fn can_spawn_within_cap() {
    let mut slab = TestSlab::new();
    let r = active_record(&mut slab);
    assert!(r.can_spawn(1));
    assert!(r.can_spawn(MAX_SPAWNED_PER_SHARD));
}

/// At exactly MAX_SPAWNED_PER_SHARD, spawning 1 more fails; spawning 0 succeeds.
#[test]
fn can_spawn_at_cap() {
    let mut slab = TestSlab::new();
    let mut r = active_record(&mut slab);
    r.spawned = (0..MAX_SPAWNED_PER_SHARD as u64)
        .map(|i| derived_shard_id(i + 1))
        .collect();
    assert!(!r.can_spawn(1));
    assert!(r.can_spawn(0));
}

/// usize::MAX as the requested count must not panic or wrap; it returns false.
#[test]
fn can_spawn_overflow() {
    let mut slab = TestSlab::new();
    let r = active_record(&mut slab);
    assert!(!r.can_spawn(usize::MAX));
}

// ============================================================================
// Op-log duplicate rejection
// ============================================================================

/// Pushing the same OpId twice panics. This is a programming error (callers
/// must check idempotency before pushing), not a runtime condition.
#[test]
#[should_panic(expected = "duplicate OpId")]
fn op_log_push_rejects_duplicate() {
    let mut slab = TestSlab::new();
    let mut r = active_record(&mut slab);
    r.op_log_push(make_entry(42));
    r.op_log_push(make_entry(42)); // same OpId — should panic
}

// ============================================================================
// new_split_child construction
//
// Split children are created with a derived ShardId (bit 63 set), a parent
// reference, an inherited cursor, and a fresh fence epoch. The constructor
// rejects non-derived IDs.
// ============================================================================

/// A split child has Active status, the correct parent, inherited cursor and
/// semantics, an empty spawned list and op-log, and INITIAL fence epoch.
#[test]
fn new_split_child_construction_and_fields() {
    let mut slab = TestSlab::new();
    let parent_id = ShardId::from_raw(10);
    let child_id = derived_shard_id(1);
    let cursor = Cursor::with_last_key(b"middle-key".to_vec());
    let spec = test_spec();

    let record = ShardRecord::new_split_child(
        test_tenant(),
        test_run(),
        child_id,
        spec.as_ref(),
        CursorUpdate::from_cursor(&cursor),
        CursorSemantics::Dispatched,
        parent_id,
        &mut slab,
    )
    .expect("slab large enough for test");

    assert_eq!(record.status, ShardStatus::Active);
    assert_eq!(record.parent, Some(parent_id));

    // Materialize pooled cursor for comparison.
    let materialized_cursor = record.cursor.to_cursor(&slab);
    assert_eq!(materialized_cursor, cursor);

    assert_eq!(record.cursor_semantics, CursorSemantics::Dispatched);
    assert_eq!(record.shard, child_id);
    assert!(record.spawned.is_empty());
    assert!(record.op_log.is_empty());
    assert_eq!(record.fence_epoch, FenceEpoch::INITIAL);
}

/// Passing a non-derived ShardId (bit 63 clear) to `new_split_child` panics.
#[test]
#[should_panic(expected = "not derived")]
fn new_split_child_non_derived_shard_panics() {
    let mut slab = TestSlab::new();
    let spec = test_spec();
    let cursor = Cursor::initial();
    let _ = ShardRecord::new_split_child(
        test_tenant(),
        test_run(),
        ShardId::from_raw(10), // NOT derived
        spec.as_ref(),
        CursorUpdate::from_cursor(&cursor),
        CursorSemantics::Completed,
        ShardId::from_raw(5),
        &mut slab,
    );
}

// ============================================================================
// Property tests
//
// Randomized invariant checks: op-log remains bounded regardless of push
// count, ParkReason canonical encoding is stable and collision-free,
// is_leased_at matches the half-open `now < deadline` predicate for all
// (deadline, now) pairs.
// ============================================================================

proptest! {
    #![proptest_config(crate::test_util::miri_proptest_config())]

    /// Regardless of how many ops are pushed, the op-log never exceeds OP_LOG_CAP.
    #[test]
    fn op_log_push_bounded(ops in proptest::collection::vec(1u64..10000, 0..64)) {
        let mut slab = TestSlab::new();
        let mut r = active_record(&mut slab);
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
        let mut slab = TestSlab::new();
        let mut r = active_record(&mut slab);
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
