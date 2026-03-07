use super::*;

use gossip_contracts::coordination::{CursorSemantics, CursorUpdate, PooledSpawned, ShardSpecRef};
use gossip_contracts::identity::{
    FenceEpoch, LogicalTime, OpId, RunId, ShardId, TenantId, WorkerId,
};
use gossip_coordination::{
    LeaseHolder, OpKind, OpLogEntry, OpResult, ParkReason, RunConfig, RunOpKind, RunOpLogEntry,
    RunOpResult, RunRecord, RunStatus, ShardRecord, ShardStatus,
};
use gossip_stdx::{ByteSlab, RingBuffer};
use proptest::prelude::*;
use rstest::rstest;

// ---------------------------------------------------------------------------
// RunRecord v1 round-trips (rstest)
// ---------------------------------------------------------------------------

#[rstest]
#[case::initializing_completed(RunStatus::Initializing, CursorSemantics::Completed)]
#[case::initializing_dispatched(RunStatus::Initializing, CursorSemantics::Dispatched)]
#[case::active_completed(RunStatus::Active, CursorSemantics::Completed)]
#[case::active_dispatched(RunStatus::Active, CursorSemantics::Dispatched)]
#[case::done_completed(RunStatus::Done, CursorSemantics::Completed)]
#[case::done_dispatched(RunStatus::Done, CursorSemantics::Dispatched)]
#[case::failed_completed(RunStatus::Failed, CursorSemantics::Completed)]
#[case::failed_dispatched(RunStatus::Failed, CursorSemantics::Dispatched)]
#[case::cancelled_completed(RunStatus::Cancelled, CursorSemantics::Completed)]
#[case::cancelled_dispatched(RunStatus::Cancelled, CursorSemantics::Dispatched)]
fn run_record_v1_round_trips(#[case] status: RunStatus, #[case] semantics: CursorSemantics) {
    let record = sample_run_record(status, semantics);
    let encoded = encode_run_record_v1(&record);
    let decoded = decode_run_record_v1(&encoded).expect("run record should decode");
    let reencoded = encode_run_record_v1(&decoded);

    assert_eq!(
        decoded, record,
        "round-trip mismatch for {status:?}/{semantics:?}"
    );
    assert_eq!(
        reencoded, encoded,
        "re-encode mismatch for {status:?}/{semantics:?}"
    );
}

// ---------------------------------------------------------------------------
// ShardRecord v1 round-trips (rstest)
// ---------------------------------------------------------------------------

#[rstest]
#[case::completed(CursorSemantics::Completed)]
#[case::dispatched(CursorSemantics::Dispatched)]
fn shard_record_v1_round_trips_active(#[case] semantics: CursorSemantics) {
    let (mut record, mut slab) = sample_active_child_shard_record(semantics);
    let encoded = encode_shard_record_v1(&record, &slab);

    let mut decode_slab = ByteSlab::with_capacity(4096);
    let mut decoded =
        decode_shard_record_v1(&encoded, &mut decode_slab).expect("shard record should decode");
    let reencoded = encode_shard_record_v1(&decoded, &decode_slab);

    assert_shard_record_eq(&record, &slab, &decoded, &decode_slab);
    assert_eq!(reencoded, encoded);

    release_shard_record(&mut record, &mut slab);
    release_shard_record(&mut decoded, &mut decode_slab);
}

#[test]
fn shard_record_v1_round_trips_done() {
    let (mut done_record, mut done_slab) = sample_done_shard_record();
    let done_encoded = encode_shard_record_v1(&done_record, &done_slab);
    let mut done_decode_slab = ByteSlab::with_capacity(4096);
    let mut done_decoded = decode_shard_record_v1(&done_encoded, &mut done_decode_slab)
        .expect("done record should decode");
    assert_shard_record_eq(&done_record, &done_slab, &done_decoded, &done_decode_slab);
    release_shard_record(&mut done_record, &mut done_slab);
    release_shard_record(&mut done_decoded, &mut done_decode_slab);
}

#[test]
fn shard_record_v1_round_trips_split() {
    let (mut split_record, mut split_slab) = sample_split_shard_record();
    let split_encoded = encode_shard_record_v1(&split_record, &split_slab);
    let mut split_decode_slab = ByteSlab::with_capacity(4096);
    let mut split_decoded = decode_shard_record_v1(&split_encoded, &mut split_decode_slab)
        .expect("split record should decode");
    assert_shard_record_eq(
        &split_record,
        &split_slab,
        &split_decoded,
        &split_decode_slab,
    );
    release_shard_record(&mut split_record, &mut split_slab);
    release_shard_record(&mut split_decoded, &mut split_decode_slab);
}

#[rstest]
#[case::permission_denied(ParkReason::PermissionDenied)]
#[case::not_found(ParkReason::NotFound)]
#[case::poisoned(ParkReason::Poisoned)]
#[case::too_many_errors(ParkReason::TooManyErrors)]
#[case::other(ParkReason::Other)]
fn shard_record_v1_round_trips_parked(#[case] park_reason: ParkReason) {
    let (mut record, mut slab) = sample_parked_shard_record(park_reason);
    let encoded = encode_shard_record_v1(&record, &slab);

    let mut decode_slab = ByteSlab::with_capacity(4096);
    let mut decoded =
        decode_shard_record_v1(&encoded, &mut decode_slab).expect("parked record should decode");
    let reencoded = encode_shard_record_v1(&decoded, &decode_slab);

    assert_shard_record_eq(&record, &slab, &decoded, &decode_slab);
    assert_eq!(reencoded, encoded);

    release_shard_record(&mut record, &mut slab);
    release_shard_record(&mut decoded, &mut decode_slab);
}

// ---------------------------------------------------------------------------
// Error rejection tests
// ---------------------------------------------------------------------------

#[test]
fn decode_run_record_rejects_wrong_version_prefix() {
    let mut blob = encode_run_record_v1(&sample_run_record(
        RunStatus::Active,
        CursorSemantics::Completed,
    ));
    blob[0] = b'x';

    let error = decode_run_record_v1(&blob).expect_err("bad prefix must fail");
    assert!(matches!(
        error,
        EtcdCodecError::InvalidVersionPrefix { actual } if actual == [b'x', b'1']
    ));
}

#[test]
fn decode_run_record_rejects_trailing_bytes() {
    let mut blob = encode_run_record_v1(&sample_run_record(
        RunStatus::Active,
        CursorSemantics::Completed,
    ));
    blob.push(0xff);

    let error = decode_run_record_v1(&blob).expect_err("trailing bytes must fail");
    assert!(matches!(
        error,
        EtcdCodecError::TrailingBytes { remaining: 1 }
    ));
}

#[test]
fn decode_run_record_rejects_truncated_blob() {
    let blob = encode_run_record_v1(&sample_run_record(
        RunStatus::Done,
        CursorSemantics::Completed,
    ));
    let error =
        decode_run_record_v1(&blob[..blob.len() - 1]).expect_err("truncated blob must fail");
    assert!(matches!(error, EtcdCodecError::Truncated { .. }));
}

#[test]
fn decode_run_record_rejects_active_without_root_shards() {
    let blob = invalid_active_run_without_roots_blob();
    let error = decode_run_record_v1(&blob).expect_err("invalid run should fail");
    assert!(matches!(
        error,
        EtcdCodecError::InvariantViolation {
            kind: "RunRecord",
            detail: "Active run must have at least one root shard",
        }
    ));
}

#[test]
fn decode_shard_record_rejects_wrong_blob_kind() {
    let blob = encode_run_record_v1(&sample_run_record(
        RunStatus::Active,
        CursorSemantics::Completed,
    ));
    let mut slab = ByteSlab::with_capacity(4096);
    let error = decode_shard_record_v1(&blob, &mut slab).expect_err("wrong kind must fail");
    assert!(matches!(
        error,
        EtcdCodecError::UnexpectedBlobKind {
            expected: BlobKind::ShardRecord,
            actual: BlobKind::RunRecord,
        }
    ));
}

#[test]
fn decode_shard_record_rejects_cursor_token_without_last_key() {
    let blob = invalid_shard_token_without_last_key_blob();
    let mut slab = ByteSlab::with_capacity(4096);
    let error = decode_shard_record_v1(&blob, &mut slab).expect_err("invalid shard should fail");
    assert!(matches!(
        error,
        EtcdCodecError::InvariantViolation {
            kind: "ShardRecord",
            detail: "cursor token without cursor last_key is invalid",
        }
    ));
}

#[test]
fn decode_shard_record_rolls_back_on_slab_exhaustion() {
    let (mut record, mut slab) = sample_active_child_shard_record(CursorSemantics::Dispatched);
    let blob = encode_shard_record_v1(&record, &slab);
    let mut tiny_slab = ByteSlab::with_capacity(48);

    let error = decode_shard_record_v1(&blob, &mut tiny_slab).expect_err("small slab must fail");
    assert!(matches!(error, EtcdCodecError::SlabFull(_)));
    assert_eq!(
        tiny_slab.live_count(),
        0,
        "decode rollback must release all staged allocations"
    );

    release_shard_record(&mut record, &mut slab);
}

// ---------------------------------------------------------------------------
// Proptest: RunRecord round-trip with random fields
// ---------------------------------------------------------------------------

fn miri_proptest_config() -> proptest::test_runner::Config {
    if cfg!(miri) {
        proptest::test_runner::Config {
            failure_persistence: None,
            cases: 32,
            ..Default::default()
        }
    } else {
        proptest::test_runner::Config::default()
    }
}

fn arb_cursor_semantics() -> impl Strategy<Value = CursorSemantics> {
    prop_oneof![
        Just(CursorSemantics::Completed),
        Just(CursorSemantics::Dispatched),
    ]
}

fn arb_run_status() -> impl Strategy<Value = RunStatus> {
    prop_oneof![
        Just(RunStatus::Initializing),
        Just(RunStatus::Active),
        Just(RunStatus::Done),
        Just(RunStatus::Failed),
        Just(RunStatus::Cancelled),
    ]
}

/// Strategy that generates a structurally valid `RunRecord`.
///
/// Status-dependent fields are kept consistent:
/// - `root_shards` is empty for Initializing, non-empty otherwise.
/// - `completed_at` is `Some` for terminal statuses, `None` otherwise.
/// - Op-log entries have kind/result consistency matching `RunOpLogEntry::new`.
fn arb_run_record() -> impl Strategy<Value = RunRecord> {
    (
        proptest::array::uniform32(any::<u8>()),
        any::<u64>(),
        arb_cursor_semantics(),
        1u64..=1_000_000u64,
        proptest::option::of(0u32..100),
        arb_run_status(),
        1u64..=1_000_000u64,
    )
        .prop_flat_map(
            |(tenant_bytes, run_raw, semantics, lease_dur, retries, status, created_raw)| {
                let root_count = if status == RunStatus::Initializing {
                    0usize..=0usize
                } else {
                    1usize..=4usize
                };

                // Generate between 0 and 4 op-log entries.
                let op_count = 0usize..=4usize;

                (
                    Just(tenant_bytes),
                    Just(run_raw),
                    Just(semantics),
                    Just(lease_dur),
                    Just(retries),
                    Just(status),
                    Just(created_raw),
                    proptest::collection::vec(1u64..=100_000u64, root_count),
                    proptest::collection::vec(
                        (
                            1u64..=100_000u64,
                            1u64..=0xFFFF_FFFF_FFFF_FFFEu64,
                            1u64..=1_000_000u64,
                        ),
                        op_count,
                    ),
                )
            },
        )
        .prop_map(
            |(
                tenant_bytes,
                run_raw,
                semantics,
                lease_dur,
                retries,
                status,
                created_raw,
                root_raws,
                op_entries,
            )| {
                let tenant = TenantId::from_bytes(tenant_bytes);
                let run = RunId::from_raw(run_raw);
                let config = RunConfig::try_new(semantics, lease_dur, retries).unwrap();
                let root_shards: Vec<ShardId> =
                    root_raws.into_iter().map(ShardId::from_raw).collect();

                let mut op_log = RingBuffer::<RunOpLogEntry, { RunRecord::OP_LOG_CAP }>::new();

                // Build a consistent op-log: first entry is RegisterShards if
                // the run is past Initializing, subsequent entries are terminal
                // transitions with Ack results. Timestamps are monotonically
                // increasing (invariant enforced by assert_invariants).
                let terminal_kinds = [
                    RunOpKind::CompleteRun,
                    RunOpKind::FailRun,
                    RunOpKind::CancelRun,
                ];

                let mut clock = created_raw;
                for (i, (op_raw, hash, time_delta)) in op_entries.into_iter().enumerate() {
                    clock += time_delta;
                    let op_id = OpId::from_raw(op_raw + i as u64);
                    let executed_at = LogicalTime::from_raw(clock);

                    if i == 0 && status != RunStatus::Initializing {
                        // First op for non-Initializing: RegisterShards.
                        op_log.push_back_overwrite(RunOpLogEntry::new(
                            op_id,
                            RunOpKind::RegisterShards,
                            hash,
                            executed_at,
                            RunOpResult::RegisteredShards {
                                shard_ids: root_shards.clone().into_boxed_slice(),
                            },
                        ));
                    } else {
                        // Use a terminal kind, cycling through the options.
                        let kind = terminal_kinds[i % terminal_kinds.len()];
                        op_log.push_back_overwrite(RunOpLogEntry::new(
                            op_id,
                            kind,
                            hash,
                            executed_at,
                            RunOpResult::Ack,
                        ));
                    }
                }

                let completed_at = status
                    .is_terminal()
                    .then(|| LogicalTime::from_raw(clock + 1));

                let record = RunRecord {
                    tenant,
                    run,
                    config,
                    status,
                    created_at: LogicalTime::from_raw(created_raw),
                    completed_at,
                    root_shards,
                    op_log,
                };
                record.assert_invariants();
                record
            },
        )
}

proptest! {
    #![proptest_config(miri_proptest_config())]

    /// `decode(encode(record)) == record` AND `encode(decode(encode(r))) == encode(r)`.
    #[test]
    fn run_record_v1_proptest_round_trip(record in arb_run_record()) {
        let encoded = encode_run_record_v1(&record);
        let decoded = decode_run_record_v1(&encoded)
            .expect("proptest-generated record must decode");
        let reencoded = encode_run_record_v1(&decoded);

        prop_assert_eq!(&decoded, &record, "decode(encode(r)) != r");
        prop_assert_eq!(&reencoded, &encoded, "encode(decode(encode(r))) != encode(r)");
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn sample_run_record(status: RunStatus, cursor_semantics: CursorSemantics) -> RunRecord {
    let tenant = TenantId::from_bytes([0x11; 32]);
    let run = RunId::from_raw(0x0102_0304_0506_0708);
    let root_a = ShardId::from_raw(1);
    let root_b = ShardId::from_raw(2);
    let config = RunConfig::try_new(cursor_semantics, 30, Some(7)).unwrap();

    let mut op_log = RingBuffer::<RunOpLogEntry, { RunRecord::OP_LOG_CAP }>::new();
    if status != RunStatus::Initializing {
        op_log.push_back_overwrite(RunOpLogEntry::new(
            OpId::from_raw(1),
            RunOpKind::RegisterShards,
            0x1111_1111,
            LogicalTime::from_raw(10),
            RunOpResult::RegisteredShards {
                shard_ids: vec![root_a, root_b].into_boxed_slice(),
            },
        ));
    }

    match status {
        RunStatus::Done => {
            op_log.push_back_overwrite(RunOpLogEntry::new(
                OpId::from_raw(2),
                RunOpKind::CompleteRun,
                0x2222_2222,
                LogicalTime::from_raw(11),
                RunOpResult::Ack,
            ));
        }
        RunStatus::Failed => {
            op_log.push_back_overwrite(RunOpLogEntry::new(
                OpId::from_raw(3),
                RunOpKind::FailRun,
                0x3333_3333,
                LogicalTime::from_raw(11),
                RunOpResult::Ack,
            ));
        }
        RunStatus::Cancelled => {
            op_log.push_back_overwrite(RunOpLogEntry::new(
                OpId::from_raw(4),
                RunOpKind::CancelRun,
                0x4444_4444,
                LogicalTime::from_raw(11),
                RunOpResult::Ack,
            ));
        }
        RunStatus::Initializing | RunStatus::Active => {}
    }

    let record = RunRecord {
        tenant,
        run,
        config,
        status,
        created_at: LogicalTime::from_raw(5),
        completed_at: status.is_terminal().then(|| LogicalTime::from_raw(20)),
        root_shards: if status == RunStatus::Initializing {
            Vec::new()
        } else {
            vec![root_a, root_b]
        },
        op_log,
    };
    record.assert_invariants();
    record
}

fn sample_active_child_shard_record(cursor_semantics: CursorSemantics) -> (ShardRecord, ByteSlab) {
    let tenant = TenantId::from_bytes([0x22; 32]);
    let run = RunId::from_raw(0x9999);
    let shard = derived_shard(0x0000_0000_0000_0001);
    let parent = ShardId::from_raw(17);
    let spawned_child = derived_shard(0x0000_0000_0000_0002);

    let mut slab = ByteSlab::with_capacity(4096);
    let spec = ShardSpecRef::with_range_and_metadata(b"aa", b"zz", b"repo=alpha");
    let cursor = CursorUpdate::with_token(b"mm", b"tok-1");
    let mut record = ShardRecord::new_split_child(
        tenant,
        run,
        shard,
        spec,
        cursor,
        cursor_semantics,
        parent,
        &mut slab,
    )
    .expect("sample shard record should fit in slab");

    record.lease = Some(LeaseHolder::new(
        WorkerId::from_raw(7),
        LogicalTime::from_raw(100),
    ));
    record.fence_epoch = FenceEpoch::from_raw(9);
    record.spawned = pooled_spawned(&[spawned_child], &mut slab);

    record.op_log.push_back_overwrite(OpLogEntry::new(
        OpId::from_raw(11),
        OpKind::Checkpoint,
        OpResult::Error,
        0xaaaa,
        LogicalTime::from_raw(11),
    ));
    record.op_log.push_back_overwrite(OpLogEntry::new(
        OpId::from_raw(12),
        OpKind::SplitResidual,
        OpResult::Superseded,
        0xbbbb,
        LogicalTime::from_raw(12),
    ));
    record.op_log.push_back_overwrite(OpLogEntry::new(
        OpId::from_raw(13),
        OpKind::Unpark,
        OpResult::Completed,
        0xcccc,
        LogicalTime::from_raw(13),
    ));

    record.assert_invariants(&slab);
    (record, slab)
}

fn sample_done_shard_record() -> (ShardRecord, ByteSlab) {
    let tenant = TenantId::from_bytes([0x33; 32]);
    let run = RunId::from_raw(0x1001);
    let shard = ShardId::from_raw(41);

    let mut slab = ByteSlab::with_capacity(4096);
    let mut record = ShardRecord::new_active_with_cursor(
        tenant,
        run,
        shard,
        ShardSpecRef::with_range_and_metadata(b"00", b"99", b"done"),
        CursorUpdate::with_last_key(b"55"),
        CursorSemantics::Completed,
        &mut slab,
    )
    .expect("done shard should fit in slab");

    record.status = ShardStatus::Done;
    record.op_log.push_back_overwrite(OpLogEntry::new(
        OpId::from_raw(21),
        OpKind::Complete,
        OpResult::Completed,
        0xd0d0,
        LogicalTime::from_raw(21),
    ));

    record.assert_invariants(&slab);
    (record, slab)
}

fn sample_split_shard_record() -> (ShardRecord, ByteSlab) {
    let tenant = TenantId::from_bytes([0x44; 32]);
    let run = RunId::from_raw(0x1002);
    let shard = ShardId::from_raw(52);

    let mut slab = ByteSlab::with_capacity(4096);
    let mut record = ShardRecord::new_active(
        tenant,
        run,
        shard,
        ShardSpecRef::with_range_and_metadata(b"aa", b"zz", b"split"),
        CursorSemantics::Completed,
        &mut slab,
    )
    .expect("split shard should fit in slab");

    record.status = ShardStatus::Split;
    record.spawned = pooled_spawned(&[derived_shard(0x10), derived_shard(0x11)], &mut slab);
    record.op_log.push_back_overwrite(OpLogEntry::new(
        OpId::from_raw(31),
        OpKind::SplitReplace,
        OpResult::Completed,
        0xe0e0,
        LogicalTime::from_raw(31),
    ));

    record.assert_invariants(&slab);
    (record, slab)
}

fn sample_parked_shard_record(park_reason: ParkReason) -> (ShardRecord, ByteSlab) {
    let tenant = TenantId::from_bytes([0x55; 32]);
    let run = RunId::from_raw(0x1003);
    let shard = ShardId::from_raw(63);

    let mut slab = ByteSlab::with_capacity(4096);
    let mut record = ShardRecord::new_active(
        tenant,
        run,
        shard,
        ShardSpecRef::with_range_and_metadata(b"ab", b"yz", b"parked"),
        CursorSemantics::Completed,
        &mut slab,
    )
    .expect("parked shard should fit in slab");

    record.status = ShardStatus::Parked;
    record.park_reason = Some(park_reason);
    record.op_log.push_back_overwrite(OpLogEntry::new(
        OpId::from_raw(41),
        OpKind::Park,
        OpResult::Completed,
        0xf0f0,
        LogicalTime::from_raw(41),
    ));

    record.assert_invariants(&slab);
    (record, slab)
}

fn assert_shard_record_eq(
    expected: &ShardRecord,
    expected_slab: &ByteSlab,
    actual: &ShardRecord,
    actual_slab: &ByteSlab,
) {
    assert_eq!(actual.validate_invariants(actual_slab), Ok(()));
    assert_eq!(actual.tenant, expected.tenant);
    assert_eq!(actual.run, expected.run);
    assert_eq!(actual.shard, expected.shard);
    assert_eq!(actual.status, expected.status);
    assert_eq!(actual.park_reason, expected.park_reason);
    assert_eq!(actual.cursor_semantics, expected.cursor_semantics);
    assert_eq!(actual.lease, expected.lease);
    assert_eq!(actual.fence_epoch, expected.fence_epoch);
    assert_eq!(actual.parent, expected.parent);

    let expected_spec = expected.spec.as_spec_ref(expected_slab);
    let actual_spec = actual.spec.as_spec_ref(actual_slab);
    assert_eq!(
        actual_spec.key_range_start(),
        expected_spec.key_range_start()
    );
    assert_eq!(actual_spec.key_range_end(), expected_spec.key_range_end());
    assert_eq!(actual_spec.metadata(), expected_spec.metadata());

    assert_eq!(
        actual.cursor.last_key(actual_slab),
        expected.cursor.last_key(expected_slab)
    );
    assert_eq!(
        actual.cursor.token(actual_slab),
        expected.cursor.token(expected_slab)
    );

    let expected_spawned: Vec<_> = expected.spawned.iter(expected_slab).collect();
    let actual_spawned: Vec<_> = actual.spawned.iter(actual_slab).collect();
    assert_eq!(actual_spawned, expected_spawned);

    assert_eq!(actual.op_log.len(), expected.op_log.len());
    for (actual_entry, expected_entry) in actual.op_log.iter().zip(expected.op_log.iter()) {
        assert_eq!(actual_entry.op_id(), expected_entry.op_id());
        assert_eq!(actual_entry.kind(), expected_entry.kind());
        assert_eq!(actual_entry.result(), expected_entry.result());
        assert_eq!(actual_entry.payload_hash(), expected_entry.payload_hash());
        assert_eq!(actual_entry.executed_at(), expected_entry.executed_at());
    }
}

fn release_shard_record(record: &mut ShardRecord, slab: &mut ByteSlab) {
    record.deallocate_fields(slab);
}

fn pooled_spawned(spawned: &[ShardId], slab: &mut ByteSlab) -> PooledSpawned {
    let mut pooled = PooledSpawned::new();
    if !spawned.is_empty() {
        let (slot, len) = pooled
            .allocate_appended_slot(spawned, slab)
            .expect("spawned ids should fit in slab");
        pooled.install_slot(slot, len, slab);
    }
    pooled
}

fn derived_shard(base: u64) -> ShardId {
    ShardId::from_raw(base | (1u64 << 63))
}

fn invalid_active_run_without_roots_blob() -> Vec<u8> {
    let mut blob = Vec::new();
    blob.extend_from_slice(b"v1");
    blob.push(BlobKind::RunRecord as u8);
    blob.extend_from_slice(TenantId::from_bytes([0x66; 32]).as_bytes());
    push_u64(&mut blob, RunId::from_raw(9).as_raw());
    blob.push(CursorSemantics::Completed.as_u8());
    push_u64(&mut blob, 30);
    blob.push(0); // max_shard_retries absent
    blob.push(RunStatus::Active.as_u8());
    push_u64(&mut blob, LogicalTime::from_raw(5).as_raw());
    blob.push(0); // completed_at absent
    push_u32(&mut blob, 0); // root_shards len
    push_u32(&mut blob, 0); // op_log len
    blob
}

fn invalid_shard_token_without_last_key_blob() -> Vec<u8> {
    let mut blob = Vec::new();
    blob.extend_from_slice(b"v1");
    blob.push(BlobKind::ShardRecord as u8);
    blob.extend_from_slice(TenantId::from_bytes([0x77; 32]).as_bytes());
    push_u64(&mut blob, RunId::from_raw(10).as_raw());
    push_u64(&mut blob, ShardId::from_raw(20).as_raw());
    blob.push(ShardStatus::Active.as_u8());
    blob.push(0); // park_reason absent
    push_bytes(&mut blob, b"a");
    push_bytes(&mut blob, b"z");
    push_bytes(&mut blob, b"meta");
    blob.push(0); // cursor_last_key absent
    blob.push(1); // cursor_token present
    push_bytes(&mut blob, b"tok");
    blob.push(CursorSemantics::Completed.as_u8());
    blob.push(0); // no lease
    push_u64(&mut blob, FenceEpoch::INITIAL.as_raw());
    blob.push(0); // parent absent
    push_u32(&mut blob, 0); // spawned len
    push_u32(&mut blob, 0); // op_log len
    blob
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_bytes(out: &mut Vec<u8>, value: &[u8]) {
    push_u32(
        out,
        u32::try_from(value.len()).expect("test payload length exceeds u32"),
    );
    out.extend_from_slice(value);
}
