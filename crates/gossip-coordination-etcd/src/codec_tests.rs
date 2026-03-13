use super::*;

use gossip_contracts::coordination::{CursorSemantics, CursorUpdate, PooledSpawned, ShardSpecRef};
use gossip_contracts::identity::{
    FenceEpoch, LogicalTime, OpId, RunId, ShardId, TenantId, WorkerId,
};
use gossip_contracts::test_util::miri_proptest_config;
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
    let encoded = encode_run_record(&record);
    let decoded = decode_run_record(&encoded).expect("run record should decode");
    let reencoded = encode_run_record(&decoded);

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
    let encoded = encode_shard_record(&record, &slab).expect("valid record encodes");

    let mut decode_slab = ByteSlab::with_capacity(4096);
    let mut decoded =
        decode_shard_record(&encoded, &mut decode_slab).expect("shard record should decode");
    let reencoded = encode_shard_record(&decoded, &decode_slab).expect("re-encode succeeds");

    assert_shard_record_eq(&record, &slab, &decoded, &decode_slab);
    assert_eq!(reencoded, encoded);

    release_shard_record(&mut record, &mut slab);
    release_shard_record(&mut decoded, &mut decode_slab);
}

#[test]
fn shard_record_v1_round_trips_done() {
    let (mut done_record, mut done_slab) = sample_done_shard_record();
    let done_encoded = encode_shard_record(&done_record, &done_slab).expect("valid record encodes");
    let mut done_decode_slab = ByteSlab::with_capacity(4096);
    let mut done_decoded = decode_shard_record(&done_encoded, &mut done_decode_slab)
        .expect("done record should decode");
    assert_shard_record_eq(&done_record, &done_slab, &done_decoded, &done_decode_slab);
    release_shard_record(&mut done_record, &mut done_slab);
    release_shard_record(&mut done_decoded, &mut done_decode_slab);
}

#[test]
fn owner_value_round_trips() {
    let encoded = encode_owner_value(WorkerId::from_raw(7), FenceEpoch::from_raw(42));
    let decoded = decode_owner_value(&encoded).expect("owner value should decode");

    assert_eq!(decoded.worker, WorkerId::from_raw(7));
    assert_eq!(decoded.fence, FenceEpoch::from_raw(42));
}

#[test]
fn owner_value_with_u64_max_fields_round_trips() {
    let encoded = encode_owner_value(WorkerId::from_raw(u64::MAX), FenceEpoch::from_raw(u64::MAX));
    let decoded = decode_owner_value(&encoded).expect("owner value should decode");

    assert_eq!(decoded.worker, WorkerId::from_raw(u64::MAX));
    assert_eq!(decoded.fence, FenceEpoch::from_raw(u64::MAX));
}

#[test]
fn owner_value_decode_rejects_zero_fence_epoch() {
    let encoded = encode_owner_value(WorkerId::from_raw(7), FenceEpoch::from_raw(0));
    let result = decode_owner_value(&encoded);
    assert!(
        result.is_err(),
        "fence epoch 0 is below INITIAL and must be rejected, but decode succeeded: {result:?}"
    );
}

#[test]
fn owner_value_rejects_wrong_blob_kind() {
    let blob = encode_run_record(&sample_run_record(
        RunStatus::Active,
        CursorSemantics::Completed,
    ));
    let error = decode_owner_value(&blob).expect_err("wrong kind must fail");
    assert!(matches!(
        error,
        EtcdCodecError::UnexpectedBlobKind {
            expected: BlobKind::ShardOwner,
            actual: BlobKind::RunRecord,
        }
    ));
}

#[test]
fn shard_record_v1_round_trips_split() {
    let (mut split_record, mut split_slab) = sample_split_shard_record();
    let split_encoded =
        encode_shard_record(&split_record, &split_slab).expect("valid record encodes");
    let mut split_decode_slab = ByteSlab::with_capacity(4096);
    let mut split_decoded = decode_shard_record(&split_encoded, &mut split_decode_slab)
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
    let encoded = encode_shard_record(&record, &slab).expect("valid record encodes");

    let mut decode_slab = ByteSlab::with_capacity(4096);
    let mut decoded =
        decode_shard_record(&encoded, &mut decode_slab).expect("parked record should decode");
    let reencoded = encode_shard_record(&decoded, &decode_slab).expect("re-encode succeeds");

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
    let mut blob = encode_run_record(&sample_run_record(
        RunStatus::Active,
        CursorSemantics::Completed,
    ));
    blob[0] = b'x';

    let error = decode_run_record(&blob).expect_err("bad prefix must fail");
    assert!(matches!(
        error,
        EtcdCodecError::InvalidVersionPrefix { actual } if actual == [b'x', b'1']
    ));
}

#[test]
fn decode_run_record_rejects_trailing_bytes() {
    let mut blob = encode_run_record(&sample_run_record(
        RunStatus::Active,
        CursorSemantics::Completed,
    ));
    blob.push(0xff);

    let error = decode_run_record(&blob).expect_err("trailing bytes must fail");
    assert!(matches!(
        error,
        EtcdCodecError::TrailingBytes { remaining: 1 }
    ));
}

#[test]
fn decode_shard_record_rejects_trailing_bytes() {
    let (mut record, mut slab) = sample_active_child_shard_record(CursorSemantics::Completed);
    let mut blob = encode_shard_record(&record, &slab).expect("valid record encodes");
    blob.push(0xff);

    let mut decode_slab = ByteSlab::with_capacity(4096);
    let error = decode_shard_record(&blob, &mut decode_slab).expect_err("trailing bytes must fail");
    assert!(matches!(
        error,
        EtcdCodecError::TrailingBytes { remaining: 1 }
    ));
    assert_eq!(
        decode_slab.live_count(),
        0,
        "trailing-byte rejection must not leave staged allocations behind"
    );

    release_shard_record(&mut record, &mut slab);
}

#[test]
fn decode_owner_value_rejects_trailing_bytes() {
    let mut blob = encode_owner_value(WorkerId::from_raw(7), FenceEpoch::from_raw(42));
    blob.push(0xff);

    let error = decode_owner_value(&blob).expect_err("trailing bytes must fail");
    assert!(matches!(
        error,
        EtcdCodecError::TrailingBytes { remaining: 1 }
    ));
}

#[test]
fn decode_run_record_rejects_truncated_blob() {
    let blob = encode_run_record(&sample_run_record(
        RunStatus::Done,
        CursorSemantics::Completed,
    ));
    let error = decode_run_record(&blob[..blob.len() - 1]).expect_err("truncated blob must fail");
    assert!(matches!(error, EtcdCodecError::Truncated { .. }));
}

#[test]
fn decode_run_record_rejects_active_without_root_shards() {
    let blob = invalid_active_run_without_roots_blob();
    let error = decode_run_record(&blob).expect_err("invalid run should fail");
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
    let blob = encode_run_record(&sample_run_record(
        RunStatus::Active,
        CursorSemantics::Completed,
    ));
    let mut slab = ByteSlab::with_capacity(4096);
    let error = decode_shard_record(&blob, &mut slab).expect_err("wrong kind must fail");
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
    let error = decode_shard_record(&blob, &mut slab).expect_err("invalid shard should fail");
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
    let blob = encode_shard_record(&record, &slab).expect("valid record encodes");
    let mut tiny_slab = ByteSlab::with_capacity(48);

    let error = decode_shard_record(&blob, &mut tiny_slab).expect_err("small slab must fail");
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
                    proptest::collection::hash_set(1u64..=100_000u64, root_count)
                        .prop_map(|s| s.into_iter().collect::<Vec<_>>()),
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
                    // Stride by 5 (> max entries 4) so no two (op_raw, i)
                    // pairs can collide: (a*5+i) == (b*5+j) requires
                    // 5*(a-b) == j-i, impossible when |j-i| ∈ {1..4}.
                    let op_id = OpId::from_raw(op_raw * 5 + i as u64);
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
        let encoded = encode_run_record(&record);
        let decoded = decode_run_record(&encoded)
            .expect("proptest-generated record must decode");
        let reencoded = encode_run_record(&decoded);

        prop_assert_eq!(&decoded, &record, "decode(encode(r)) != r");
        prop_assert_eq!(&reencoded, &encoded, "encode(decode(encode(r))) != encode(r)");
    }
}

// ---------------------------------------------------------------------------
// Proptest: ShardRecord round-trip with random fields
// ---------------------------------------------------------------------------

fn arb_shard_status() -> impl Strategy<Value = ShardStatus> {
    prop_oneof![
        Just(ShardStatus::Active),
        Just(ShardStatus::Done),
        Just(ShardStatus::Split),
        Just(ShardStatus::Parked),
    ]
}

fn arb_park_reason() -> impl Strategy<Value = ParkReason> {
    prop_oneof![
        Just(ParkReason::PermissionDenied),
        Just(ParkReason::NotFound),
        Just(ParkReason::Poisoned),
        Just(ParkReason::TooManyErrors),
        Just(ParkReason::Other),
    ]
}

fn arb_op_kind() -> impl Strategy<Value = OpKind> {
    prop_oneof![
        Just(OpKind::Checkpoint),
        Just(OpKind::Complete),
        Just(OpKind::Park),
        Just(OpKind::SplitReplace),
        Just(OpKind::SplitResidual),
        Just(OpKind::Unpark),
    ]
}

fn arb_op_result() -> impl Strategy<Value = OpResult> {
    prop_oneof![
        Just(OpResult::Completed),
        Just(OpResult::Error),
        Just(OpResult::Superseded),
    ]
}

/// Proptest input for a structurally valid `ShardRecord`.
///
/// Holds all primitive building blocks needed to construct a record.
/// `ByteSlab` does not implement `Debug`, so the strategy generates this
/// intermediate and the test body materializes the record + slab.
#[derive(Clone, Debug)]
struct ArbShardInput {
    tenant_bytes: [u8; 32],
    run_raw: u64,
    shard_raw: u64,
    status: ShardStatus,
    park_reason: ParkReason,
    cursor_semantics: CursorSemantics,
    key_start: Vec<u8>,
    key_end: Vec<u8>,
    metadata: Vec<u8>,
    has_last_key: bool,
    last_key_content: Vec<u8>,
    has_token: bool,
    token_content: Vec<u8>,
    has_lease: bool,
    worker_raw: u64,
    lease_deadline: u64,
    fence_raw: u64,
    has_parent: bool,
    parent_raw: u64,
    spawned_raws: Vec<u64>,
    op_entries: Vec<(u64, OpKind, OpResult, u64, u64)>,
}

impl ArbShardInput {
    /// Materialize a `ShardRecord` + `ByteSlab` with status-consistent fields.
    fn build(self) -> (ShardRecord, ByteSlab) {
        let tenant = TenantId::from_bytes(self.tenant_bytes);
        let run = RunId::from_raw(self.run_raw);
        // Derived shards (bit 63 set) require a parent. Root shards
        // (bit 63 clear) must not have one. Enforce consistency.
        let shard = if self.has_parent {
            ShardId::from_raw(self.shard_raw | (1u64 << 63))
        } else {
            ShardId::from_raw(self.shard_raw & !(1u64 << 63))
        };
        let status = self.status;

        let mut slab = ByteSlab::with_capacity(4096);

        let mut key_end = self.key_end;
        if key_end <= self.key_start {
            key_end = self
                .key_start
                .iter()
                .copied()
                .chain(std::iter::once(0xFF))
                .collect();
        }

        let spec = ShardSpecRef::with_range_and_metadata(&self.key_start, &key_end, &self.metadata);

        let mut record = if self.has_last_key {
            let cursor = if self.has_token {
                CursorUpdate::with_token(&self.last_key_content, &self.token_content)
            } else {
                CursorUpdate::with_last_key(&self.last_key_content)
            };
            if self.has_parent {
                ShardRecord::new_split_child(
                    tenant,
                    run,
                    shard,
                    spec,
                    cursor,
                    self.cursor_semantics,
                    ShardId::from_raw(self.parent_raw),
                    &mut slab,
                )
                .expect("shard record should fit in slab")
            } else {
                ShardRecord::new_active_with_cursor(
                    tenant,
                    run,
                    shard,
                    spec,
                    cursor,
                    self.cursor_semantics,
                    &mut slab,
                )
                .expect("shard record should fit in slab")
            }
        } else if self.has_parent {
            ShardRecord::new_split_child(
                tenant,
                run,
                shard,
                spec,
                CursorUpdate::initial(),
                self.cursor_semantics,
                ShardId::from_raw(self.parent_raw),
                &mut slab,
            )
            .expect("shard record should fit in slab")
        } else {
            ShardRecord::new_active(tenant, run, shard, spec, self.cursor_semantics, &mut slab)
                .expect("shard record should fit in slab")
        };

        record.status = status;
        record.park_reason = if status == ShardStatus::Parked {
            Some(self.park_reason)
        } else {
            None
        };

        record.lease = if status == ShardStatus::Active && self.has_lease {
            Some(LeaseHolder::new(
                WorkerId::from_raw(self.worker_raw),
                LogicalTime::from_raw(self.lease_deadline),
            ))
        } else {
            None
        };

        record.fence_epoch = FenceEpoch::from_raw(self.fence_raw);

        let mut spawned_ids: Vec<ShardId> = self
            .spawned_raws
            .into_iter()
            .map(|r| derived_shard(r.wrapping_add(1)))
            .collect();
        if status == ShardStatus::Split && spawned_ids.is_empty() {
            spawned_ids.push(derived_shard(0x0000_0000_0000_FFFF));
        }
        record.spawned = pooled_spawned(&spawned_ids, &mut slab);

        let mut clock = 1u64;
        for (op_raw, kind, result, hash, time_delta) in self.op_entries {
            clock += time_delta;
            record.op_log.push_back_overwrite(OpLogEntry::new(
                OpId::from_raw(op_raw.wrapping_add(1)),
                kind,
                result,
                hash,
                LogicalTime::from_raw(clock),
            ));
        }

        (record, slab)
    }
}

/// Strategy generating structurally valid shard record inputs.
///
/// Status-dependent fields are kept consistent in `ArbShardInput::build`:
/// - `park_reason` is `Some` iff status == Parked (INV-1)
/// - Terminal statuses (Done, Split, Parked) have no lease (INV-3)
/// - Split status always has at least one spawned child
/// - Cursor token is only present when last_key is present
/// - Op-log timestamps are monotonically increasing
fn arb_shard_input() -> impl Strategy<Value = ArbShardInput> {
    let identity_and_spec = (
        proptest::array::uniform32(any::<u8>()),
        any::<u64>(),
        any::<u64>(),
        arb_shard_status(),
        arb_park_reason(),
        arb_cursor_semantics(),
        proptest::collection::vec(any::<u8>(), 1..=8usize),
        proptest::collection::vec(any::<u8>(), 1..=8usize),
        proptest::collection::vec(any::<u8>(), 0..=16usize),
        any::<bool>(),
        proptest::collection::vec(any::<u8>(), 1..=8usize),
    );
    let ownership_and_ops = (
        any::<bool>(),
        proptest::collection::vec(any::<u8>(), 1..=8usize),
        any::<bool>(),
        any::<u64>(),
        1u64..=1_000_000u64,
        1u64..=u64::MAX, // fence_raw: must be >= FenceEpoch::INITIAL (1)
        any::<bool>(),
        any::<u64>(),
        proptest::collection::vec(any::<u64>(), 0..=3usize),
        proptest::collection::vec(
            (
                any::<u64>(),
                arb_op_kind(),
                arb_op_result(),
                1u64..=0xFFFF_FFFF_FFFF_FFFEu64,
                1u64..=1_000u64,
            ),
            0..=4usize,
        ),
    );

    (identity_and_spec, ownership_and_ops).prop_map(
        |(
            (
                tenant_bytes,
                run_raw,
                shard_raw,
                status,
                park_reason,
                cursor_semantics,
                key_start,
                key_end,
                metadata,
                has_last_key,
                last_key_content,
            ),
            (
                has_token,
                token_content,
                has_lease,
                worker_raw,
                lease_deadline,
                fence_raw,
                has_parent,
                parent_raw,
                spawned_raws,
                op_entries,
            ),
        )| {
            ArbShardInput {
                tenant_bytes,
                run_raw,
                shard_raw,
                status,
                park_reason,
                cursor_semantics,
                key_start,
                key_end,
                metadata,
                has_last_key,
                last_key_content,
                has_token,
                token_content,
                has_lease,
                worker_raw,
                lease_deadline,
                fence_raw,
                has_parent,
                parent_raw,
                spawned_raws,
                op_entries,
            }
        },
    )
}

proptest! {
    #![proptest_config(miri_proptest_config())]

    /// Shard record round-trip: `decode(encode(r)) == r` and
    /// `encode(decode(encode(r))) == encode(r)`.
    #[test]
    fn shard_record_proptest_round_trip(input in arb_shard_input()) {
        let (mut record, mut slab) = input.build();
        let encoded = encode_shard_record(&record, &slab)
            .expect("proptest-generated shard record must encode");

        let mut decode_slab = ByteSlab::with_capacity(4096);
        let mut decoded = decode_shard_record(&encoded, &mut decode_slab)
            .expect("proptest-generated shard record must decode");
        let reencoded = encode_shard_record(&decoded, &decode_slab)
            .expect("re-encode must succeed");

        assert_shard_record_eq(&record, &slab, &decoded, &decode_slab);
        prop_assert_eq!(&reencoded, &encoded, "encode(decode(encode(r))) != encode(r)");

        release_shard_record(&mut record, &mut slab);
        release_shard_record(&mut decoded, &mut decode_slab);
    }
}

proptest! {
    #![proptest_config(miri_proptest_config())]

    /// `encode_shard_record_into` must produce the exact same bytes
    /// as the allocating `encode_shard_record`.
    #[test]
    fn encode_shard_record_into_matches_allocating(input in arb_shard_input()) {
        let (mut record, mut slab) = input.build();
        let allocating = encode_shard_record(&record, &slab)
            .expect("allocating encode must succeed");
        let mut buf = Vec::new();
        encode_shard_record_into(&record, &slab, &mut buf)
            .expect("buffer-reuse encode must succeed");
        prop_assert_eq!(&buf, &allocating, "encode_shard_record_into diverged from allocating");
        release_shard_record(&mut record, &mut slab);
    }
}

/// `encode_owner_value_into` must produce the exact same bytes as the
/// allocating `encode_owner_value`.
#[test]
fn encode_owner_value_into_matches_allocating() {
    let worker = WorkerId::from_raw(42);
    let fence = FenceEpoch::from_raw(7);
    let allocating = encode_owner_value(worker, fence);
    let mut buf = Vec::new();
    encode_owner_value_into(worker, fence, &mut buf);
    assert_eq!(
        buf, allocating,
        "encode_owner_value_into diverged from allocating"
    );
}

// ---------------------------------------------------------------------------
// Decoder primitive unit tests
// ---------------------------------------------------------------------------

#[test]
fn decoder_read_bool_zero_is_false() {
    let mut d = Decoder::new(&[0]);
    assert!(!d.read_bool().unwrap());
}

#[test]
fn decoder_read_bool_one_is_true() {
    let mut d = Decoder::new(&[1]);
    assert!(d.read_bool().unwrap());
}

#[test]
fn decoder_read_bool_rejects_invalid() {
    for byte in 2..=255u8 {
        let buf = [byte];
        let mut d = Decoder::new(&buf);
        assert!(
            matches!(d.read_bool(), Err(EtcdCodecError::InvalidBool { actual }) if actual == byte),
            "byte {byte} should be rejected as invalid bool"
        );
    }
}

#[test]
fn decoder_read_u32_valid() {
    let expected = 0x0403_0201u32;
    let buf = expected.to_le_bytes();
    let mut d = Decoder::new(&buf);
    assert_eq!(d.read_u32().unwrap(), expected);
}

#[test]
fn decoder_read_u32_truncated() {
    let mut d = Decoder::new(&[0x01, 0x02, 0x03]);
    assert!(matches!(
        d.read_u32(),
        Err(EtcdCodecError::Truncated {
            needed: 4,
            remaining: 3
        })
    ));
}

#[test]
fn decoder_read_u64_valid() {
    let expected = 0x0807_0605_0403_0201u64;
    let buf = expected.to_le_bytes();
    let mut d = Decoder::new(&buf);
    assert_eq!(d.read_u64().unwrap(), expected);
}

#[test]
fn decoder_read_u64_truncated() {
    let mut d = Decoder::new(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
    assert!(matches!(
        d.read_u64(),
        Err(EtcdCodecError::Truncated {
            needed: 8,
            remaining: 7
        })
    ));
}

#[test]
fn decoder_read_vec_valid() {
    let payload = b"hello";
    let mut buf = Vec::new();
    push_u32(&mut buf, payload.len() as u32);
    buf.extend_from_slice(payload);
    let mut d = Decoder::new(&buf);
    assert_eq!(d.read_vec().unwrap(), payload);
}

#[test]
fn decoder_read_vec_accepts_max_field_size() {
    let payload = vec![0xAB; MAX_FIELD_SIZE];
    let mut buf = Vec::with_capacity(4 + payload.len());
    push_u32(&mut buf, MAX_FIELD_SIZE as u32);
    buf.extend_from_slice(&payload);

    let mut d = Decoder::new(&buf);
    assert_eq!(d.read_vec().unwrap(), payload);
    assert!(
        d.finish().is_ok(),
        "decoder should consume the full payload"
    );
}

#[test]
fn decoder_read_vec_preserves_zero_filled_payload() {
    let payload = vec![0; 32];
    let mut buf = Vec::with_capacity(4 + payload.len());
    push_u32(&mut buf, payload.len() as u32);
    buf.extend_from_slice(&payload);

    let mut d = Decoder::new(&buf);
    assert_eq!(d.read_vec().unwrap(), payload);
    assert!(
        d.finish().is_ok(),
        "decoder should consume the full payload"
    );
}

#[test]
fn decoder_read_vec_truncated_body() {
    let mut buf = Vec::new();
    push_u32(&mut buf, 10);
    buf.extend_from_slice(&[0u8; 5]); // only 5 of 10 bytes present
    let mut d = Decoder::new(&buf);
    assert!(matches!(
        d.read_vec(),
        Err(EtcdCodecError::Truncated {
            needed: 10,
            remaining: 5
        })
    ));
}

#[test]
fn decoder_read_vec_rejects_too_large() {
    let oversized_len = (MAX_FIELD_SIZE + 1) as u32;
    let buf = oversized_len.to_le_bytes();
    let mut d = Decoder::new(&buf);
    assert!(matches!(
        d.read_vec(),
        Err(EtcdCodecError::FieldTooLarge {
            actual,
            max,
        }) if actual == MAX_FIELD_SIZE + 1 && max == MAX_FIELD_SIZE
    ));
}

#[test]
fn decoder_read_opt_vec_none() {
    let mut d = Decoder::new(&[0x00]);
    assert_eq!(d.read_opt_vec().unwrap(), None);
}

#[test]
fn decoder_read_opt_vec_some() {
    let payload = b"data";
    let mut buf = vec![0x01]; // presence tag
    push_u32(&mut buf, payload.len() as u32);
    buf.extend_from_slice(payload);
    let mut d = Decoder::new(&buf);
    assert_eq!(d.read_opt_vec().unwrap(), Some(payload.to_vec()));
}

#[test]
fn decoder_read_tenant_valid() {
    let bytes = [0xAB; 32];
    let mut d = Decoder::new(&bytes);
    let tenant = d.read_tenant().unwrap();
    assert_eq!(tenant, TenantId::from_bytes(bytes));
}

#[test]
fn decoder_read_tenant_truncated() {
    let buf = [0xAB; 31];
    let mut d = Decoder::new(&buf);
    assert!(matches!(
        d.read_tenant(),
        Err(EtcdCodecError::Truncated {
            needed: 32,
            remaining: 31
        })
    ));
}

// ---------------------------------------------------------------------------
// Collection-cap boundary condition tests
// ---------------------------------------------------------------------------

#[test]
fn shard_record_at_op_log_cap_round_trips() {
    let tenant = TenantId::from_bytes([0xC1; 32]);
    let run = RunId::from_raw(0xC100);
    let shard = ShardId::from_raw(0xC1);

    let mut slab = ByteSlab::with_capacity(4096);
    let spec = ShardSpecRef::with_range_and_metadata(b"a", b"z", b"cap-test");
    let mut record = ShardRecord::new_active(
        tenant,
        run,
        shard,
        spec,
        CursorSemantics::Completed,
        &mut slab,
    )
    .expect("shard record should fit in slab");

    // Fill op_log to exactly ShardRecord::OP_LOG_CAP (16) entries.
    for i in 0..ShardRecord::OP_LOG_CAP {
        let ts = (i as u64) + 1;
        record.op_log.push_back_overwrite(OpLogEntry::new(
            OpId::from_raw(ts),
            OpKind::Checkpoint,
            OpResult::Completed,
            0xAAAA + ts,
            LogicalTime::from_raw(ts),
        ));
    }
    assert_eq!(record.op_log.len(), ShardRecord::OP_LOG_CAP);
    record.assert_invariants(&slab);

    let encoded = encode_shard_record(&record, &slab).expect("at-cap shard record must encode");
    let mut decode_slab = ByteSlab::with_capacity(4096);
    let mut decoded =
        decode_shard_record(&encoded, &mut decode_slab).expect("at-cap shard record must decode");

    assert_shard_record_eq(&record, &slab, &decoded, &decode_slab);

    release_shard_record(&mut record, &mut slab);
    release_shard_record(&mut decoded, &mut decode_slab);
}

#[test]
fn shard_record_over_op_log_cap_rejected() {
    let over_cap = (ShardRecord::OP_LOG_CAP + 1) as u32;

    let mut blob = Vec::new();
    blob.extend_from_slice(b"v1");
    blob.push(BlobKind::ShardRecord as u8);
    blob.extend_from_slice(TenantId::from_bytes([0xC2; 32]).as_bytes());
    push_u64(&mut blob, RunId::from_raw(0xC200).as_raw());
    push_u64(&mut blob, ShardId::from_raw(0xC2).as_raw());
    blob.push(ShardStatus::Active.as_u8());
    blob.push(0); // park_reason absent
    push_bytes(&mut blob, b"a"); // key_range_start
    push_bytes(&mut blob, b"z"); // key_range_end
    push_bytes(&mut blob, b"meta"); // metadata
    blob.push(0); // cursor_last_key absent
    blob.push(0); // cursor_token absent
    blob.push(CursorSemantics::Completed.as_u8());
    blob.push(0); // no lease
    push_u64(&mut blob, FenceEpoch::INITIAL.as_raw());
    blob.push(0); // parent absent
    push_u32(&mut blob, 0); // spawned len
    push_u32(&mut blob, over_cap); // op_log len exceeds cap

    let mut slab = ByteSlab::with_capacity(4096);
    let error = decode_shard_record(&blob, &mut slab).expect_err("over-cap op_log must fail");
    assert!(
        matches!(
            error,
            EtcdCodecError::InvariantViolation {
                kind: "ShardRecord",
                detail: "op_log exceeds cap",
            }
        ),
        "expected InvariantViolation for over-cap op_log, got: {error:?}"
    );
}

#[test]
fn shard_record_at_max_spawned_round_trips() {
    let tenant = TenantId::from_bytes([0xC3; 32]);
    let run = RunId::from_raw(0xC300);
    // Split status requires at least one spawned child, so a root shard is fine.
    let shard = ShardId::from_raw(0xC3);

    let mut slab = ByteSlab::with_capacity(64 * 1024);
    let spec = ShardSpecRef::with_range_and_metadata(b"a", b"z", b"spawned-cap");
    let mut record = ShardRecord::new_active(
        tenant,
        run,
        shard,
        spec,
        CursorSemantics::Completed,
        &mut slab,
    )
    .expect("shard record should fit in slab");

    record.status = ShardStatus::Split;

    let spawned_ids: Vec<ShardId> = (0..MAX_SPAWNED_PER_SHARD)
        .map(|i| derived_shard(i as u64))
        .collect();
    record.spawned = pooled_spawned(&spawned_ids, &mut slab);

    // Add one op_log entry so invariants pass (split needs at least one entry).
    record.op_log.push_back_overwrite(OpLogEntry::new(
        OpId::from_raw(1),
        OpKind::SplitReplace,
        OpResult::Completed,
        0xBBBB,
        LogicalTime::from_raw(1),
    ));
    record.assert_invariants(&slab);

    let encoded =
        encode_shard_record(&record, &slab).expect("at-max-spawned shard record must encode");
    let mut decode_slab = ByteSlab::with_capacity(64 * 1024);
    let mut decoded = decode_shard_record(&encoded, &mut decode_slab)
        .expect("at-max-spawned shard record must decode");

    assert_shard_record_eq(&record, &slab, &decoded, &decode_slab);

    release_shard_record(&mut record, &mut slab);
    release_shard_record(&mut decoded, &mut decode_slab);
}

#[test]
fn shard_record_over_max_spawned_rejected() {
    let over_max = (MAX_SPAWNED_PER_SHARD + 1) as u32;

    let mut blob = Vec::new();
    blob.extend_from_slice(b"v1");
    blob.push(BlobKind::ShardRecord as u8);
    blob.extend_from_slice(TenantId::from_bytes([0xC4; 32]).as_bytes());
    push_u64(&mut blob, RunId::from_raw(0xC400).as_raw());
    push_u64(&mut blob, ShardId::from_raw(0xC4).as_raw());
    blob.push(ShardStatus::Split.as_u8());
    blob.push(0); // park_reason absent
    push_bytes(&mut blob, b"a"); // key_range_start
    push_bytes(&mut blob, b"z"); // key_range_end
    push_bytes(&mut blob, b"meta"); // metadata
    blob.push(0); // cursor_last_key absent
    blob.push(0); // cursor_token absent
    blob.push(CursorSemantics::Completed.as_u8());
    blob.push(0); // no lease
    push_u64(&mut blob, FenceEpoch::INITIAL.as_raw());
    blob.push(0); // parent absent
    push_u32(&mut blob, over_max); // spawned len exceeds MAX_SPAWNED_PER_SHARD

    let mut slab = ByteSlab::with_capacity(4096);
    let error = decode_shard_record(&blob, &mut slab).expect_err("over-max spawned must fail");
    assert!(
        matches!(
            error,
            EtcdCodecError::InvariantViolation {
                kind: "ShardRecord",
                detail: "spawned exceeds MAX_SPAWNED_PER_SHARD",
            }
        ),
        "expected InvariantViolation for over-max spawned, got: {error:?}"
    );
}

#[test]
fn run_record_at_op_log_cap_round_trips() {
    let tenant = TenantId::from_bytes([0xC5; 32]);
    let run = RunId::from_raw(0xC500);
    let root_a = ShardId::from_raw(1);
    let root_b = ShardId::from_raw(2);
    let config = RunConfig::try_new(CursorSemantics::Completed, 30, Some(5)).unwrap();

    let mut op_log = RingBuffer::<RunOpLogEntry, { RunRecord::OP_LOG_CAP }>::new();

    // First entry must be RegisterShards for a non-Initializing record.
    op_log.push_back_overwrite(RunOpLogEntry::new(
        OpId::from_raw(1),
        RunOpKind::RegisterShards,
        0x1111,
        LogicalTime::from_raw(1),
        RunOpResult::RegisteredShards {
            shard_ids: vec![root_a, root_b].into_boxed_slice(),
        },
    ));

    // Fill the remaining slots with terminal ops (monotonically increasing timestamps).
    let terminal_kinds = [
        RunOpKind::CompleteRun,
        RunOpKind::FailRun,
        RunOpKind::CancelRun,
    ];
    for i in 1..RunRecord::OP_LOG_CAP {
        let ts = (i as u64) + 1;
        op_log.push_back_overwrite(RunOpLogEntry::new(
            OpId::from_raw(ts),
            terminal_kinds[i % terminal_kinds.len()],
            0x2222 + ts,
            LogicalTime::from_raw(ts),
            RunOpResult::Ack,
        ));
    }
    assert_eq!(op_log.len(), RunRecord::OP_LOG_CAP);

    let record = RunRecord {
        tenant,
        run,
        config,
        status: RunStatus::Active,
        created_at: LogicalTime::from_raw(1),
        completed_at: None,
        root_shards: vec![root_a, root_b],
        op_log,
    };
    record.assert_invariants();

    let encoded = encode_run_record(&record);
    let decoded = decode_run_record(&encoded).expect("at-cap run record must decode");
    assert_eq!(decoded, record);
}

#[test]
fn shard_record_with_empty_key_range_round_trips() {
    let tenant = TenantId::from_bytes([0xD1; 32]);
    let run = RunId::from_raw(0xD100);
    let shard = ShardId::from_raw(0xD1);

    let mut slab = ByteSlab::with_capacity(4096);
    let spec = ShardSpecRef::with_range_and_metadata(b"", b"", b"empty-range");
    let mut record = ShardRecord::new_active(
        tenant,
        run,
        shard,
        spec,
        CursorSemantics::Completed,
        &mut slab,
    )
    .expect("shard record should fit in slab");
    record.assert_invariants(&slab);

    let encoded = encode_shard_record(&record, &slab).expect("valid record encodes");
    let mut decode_slab = ByteSlab::with_capacity(4096);
    let mut decoded =
        decode_shard_record(&encoded, &mut decode_slab).expect("shard record should decode");

    assert_shard_record_eq(&record, &slab, &decoded, &decode_slab);
    assert_eq!(decoded.spec.key_range_start(&decode_slab), b"");
    assert_eq!(decoded.spec.key_range_end(&decode_slab), b"");

    release_shard_record(&mut record, &mut slab);
    release_shard_record(&mut decoded, &mut decode_slab);
}

#[test]
fn shard_record_with_empty_metadata_round_trips() {
    let tenant = TenantId::from_bytes([0xD2; 32]);
    let run = RunId::from_raw(0xD200);
    let shard = ShardId::from_raw(0xD2);

    let mut slab = ByteSlab::with_capacity(4096);
    let spec = ShardSpecRef::with_range_and_metadata(b"aa", b"zz", b"");
    let mut record = ShardRecord::new_active_with_cursor(
        tenant,
        run,
        shard,
        spec,
        CursorUpdate::with_last_key(b"mm"),
        CursorSemantics::Completed,
        &mut slab,
    )
    .expect("shard record should fit in slab");
    record.assert_invariants(&slab);

    let encoded = encode_shard_record(&record, &slab).expect("valid record encodes");
    let mut decode_slab = ByteSlab::with_capacity(4096);
    let mut decoded =
        decode_shard_record(&encoded, &mut decode_slab).expect("shard record should decode");

    assert_shard_record_eq(&record, &slab, &decoded, &decode_slab);
    assert_eq!(decoded.spec.metadata(&decode_slab), b"");

    release_shard_record(&mut record, &mut slab);
    release_shard_record(&mut decoded, &mut decode_slab);
}

#[test]
fn shard_record_with_zero_op_log_entries_round_trips() {
    let tenant = TenantId::from_bytes([0xD3; 32]);
    let run = RunId::from_raw(0xD300);
    let shard = ShardId::from_raw(0xD3);

    let mut slab = ByteSlab::with_capacity(4096);
    let spec = ShardSpecRef::with_range_and_metadata(b"aa", b"zz", b"zero-op-log");
    let mut record = ShardRecord::new_active(
        tenant,
        run,
        shard,
        spec,
        CursorSemantics::Dispatched,
        &mut slab,
    )
    .expect("shard record should fit in slab");
    record.assert_invariants(&slab);

    let encoded = encode_shard_record(&record, &slab).expect("valid record encodes");
    let mut decode_slab = ByteSlab::with_capacity(4096);
    let mut decoded =
        decode_shard_record(&encoded, &mut decode_slab).expect("shard record should decode");

    assert_shard_record_eq(&record, &slab, &decoded, &decode_slab);
    assert_eq!(decoded.op_log.len(), 0);

    release_shard_record(&mut record, &mut slab);
    release_shard_record(&mut decoded, &mut decode_slab);
}

#[test]
fn shard_record_with_u64_max_run_and_shard_ids_round_trips() {
    let tenant = TenantId::from_bytes([0xD4; 32]);
    let run = RunId::from_raw(u64::MAX);
    let shard = ShardId::from_raw(u64::MAX);
    let parent = ShardId::from_raw(17);

    let mut slab = ByteSlab::with_capacity(4096);
    let mut record = ShardRecord::new_split_child(
        tenant,
        run,
        shard,
        ShardSpecRef::with_range_and_metadata(b"hi", b"lo", b"max-ids"),
        CursorUpdate::with_token(b"mid", b"tok"),
        CursorSemantics::Completed,
        parent,
        &mut slab,
    )
    .expect("shard record should fit in slab");
    record.lease = Some(LeaseHolder::new(
        WorkerId::from_raw(u64::MAX),
        LogicalTime::from_raw(u64::MAX),
    ));
    record.fence_epoch = FenceEpoch::from_raw(u64::MAX);
    record.op_log.push_back_overwrite(OpLogEntry::new(
        OpId::from_raw(u64::MAX),
        OpKind::Checkpoint,
        OpResult::Completed,
        u64::MAX,
        LogicalTime::from_raw(u64::MAX),
    ));
    record.assert_invariants(&slab);

    let encoded = encode_shard_record(&record, &slab).expect("valid record encodes");
    let mut decode_slab = ByteSlab::with_capacity(4096);
    let mut decoded =
        decode_shard_record(&encoded, &mut decode_slab).expect("shard record should decode");

    assert_shard_record_eq(&record, &slab, &decoded, &decode_slab);

    release_shard_record(&mut record, &mut slab);
    release_shard_record(&mut decoded, &mut decode_slab);
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

/// Constructs a blob with valid spec fields but an empty cursor_last_key
/// (present but zero-length), which should be rejected by
/// `CursorUpdate::try_with_last_key`. If the slab's live count is nonzero
/// after the decode error, the spec allocation was leaked.
#[test]
fn decode_shard_record_rolls_back_spec_on_cursor_parse_failure() {
    // Build a blob with a valid spec (start < end) but an invalid cursor
    // (present but empty last_key, which CursorUpdate::try_with_last_key rejects).
    let mut blob = Vec::new();
    blob.extend_from_slice(b"v1");
    blob.push(BlobKind::ShardRecord as u8);
    blob.extend_from_slice(TenantId::from_bytes([0x88; 32]).as_bytes());
    push_u64(&mut blob, RunId::from_raw(1).as_raw());
    push_u64(&mut blob, ShardId::from_raw(2).as_raw());
    blob.push(ShardStatus::Active.as_u8());
    blob.push(0); // park_reason absent
    push_bytes(&mut blob, b"a"); // key_range_start
    push_bytes(&mut blob, b"z"); // key_range_end
    push_bytes(&mut blob, b"m"); // metadata
    // cursor_last_key: present but empty — triggers EmptyLastKey error
    // in CursorUpdate::try_with_last_key AFTER PooledShardSpec is allocated.
    blob.push(1); // present
    push_bytes(&mut blob, b""); // empty last_key
    blob.push(0); // cursor_token absent
    blob.push(CursorSemantics::Completed.as_u8());
    blob.push(0); // no lease owner
    push_u64(&mut blob, FenceEpoch::INITIAL.as_raw());
    blob.push(0); // parent absent
    push_u32(&mut blob, 0); // spawned len
    push_u32(&mut blob, 0); // op_log len

    let mut slab = ByteSlab::with_capacity(4096);
    let result = decode_shard_record(&blob, &mut slab);
    let err = result.expect_err("empty cursor last_key should be rejected");
    assert!(
        matches!(err, EtcdCodecError::InvalidCursor { .. }),
        "expected InvalidCursor error from CursorUpdate validation, got: {err:?}"
    );
    assert_eq!(
        slab.live_count(),
        0,
        "slab must have zero live allocations after cursor-parse failure — spec was leaked"
    );
}

/// Crafted blob with root_shards length exceeding MAX_ROOT_SHARDS is
/// rejected with an InvariantViolation before any allocation occurs.
#[test]
fn decode_run_record_rejects_oversized_root_shards() {
    let mut blob = Vec::new();
    blob.extend_from_slice(b"v1");
    blob.push(BlobKind::RunRecord as u8);
    blob.extend_from_slice(TenantId::from_bytes([0x99; 32]).as_bytes());
    push_u64(&mut blob, RunId::from_raw(1).as_raw());
    blob.push(CursorSemantics::Completed.as_u8());
    push_u64(&mut blob, 30); // lease_duration
    blob.push(0); // max_shard_retries absent
    blob.push(RunStatus::Active.as_u8());
    push_u64(&mut blob, LogicalTime::from_raw(5).as_raw()); // created_at
    blob.push(0); // completed_at absent
    push_u32(&mut blob, 1_000_000); // exceeds MAX_ROOT_SHARDS

    let error = decode_run_record(&blob).expect_err("oversized root_shards must fail decode");
    assert!(
        matches!(
            error,
            EtcdCodecError::FieldTooLarge {
                actual: 1_000_000,
                max: 10_000,
            }
        ),
        "expected FieldTooLarge for oversized root_shards, got: {error:?}"
    );
}

/// Crafted blob with a `RegisteredShards` op-log entry whose length prefix
/// exceeds `MAX_REGISTERED_SHARDS` is rejected with `FieldTooLarge` before
/// any allocation occurs.
#[test]
fn decode_run_record_rejects_oversized_registered_shards() {
    let mut blob = Vec::new();
    // -- header --
    blob.extend_from_slice(b"v1");
    blob.push(BlobKind::RunRecord as u8);
    // -- run record fields --
    blob.extend_from_slice(TenantId::from_bytes([0x99; 32]).as_bytes());
    push_u64(&mut blob, RunId::from_raw(1).as_raw());
    blob.push(CursorSemantics::Completed.as_u8());
    push_u64(&mut blob, 30); // lease_duration
    blob.push(0); // max_shard_retries absent
    blob.push(RunStatus::Active.as_u8());
    push_u64(&mut blob, LogicalTime::from_raw(5).as_raw()); // created_at
    blob.push(0); // completed_at absent
    push_u32(&mut blob, 0); // root_shards: empty
    // -- op_log: 1 entry --
    push_u32(&mut blob, 1);
    // op_log[0]:
    push_u64(&mut blob, OpId::from_raw(42).as_raw()); // op_id
    blob.push(0); // kind = RegisterShards
    push_u64(&mut blob, 0xDEAD); // payload_hash
    push_u64(&mut blob, LogicalTime::from_raw(10).as_raw()); // executed_at
    // result tag = RegisteredShards (1)
    blob.push(1);
    // length prefix = 1,000,000 (exceeds MAX_REGISTERED_SHARDS = 10,000)
    push_u32(&mut blob, 1_000_000);

    let error = decode_run_record(&blob).expect_err("oversized RegisteredShards must fail decode");
    assert!(
        matches!(
            error,
            EtcdCodecError::FieldTooLarge {
                actual: 1_000_000,
                max: 10_000,
            }
        ),
        "expected FieldTooLarge for oversized RegisteredShards, got: {error:?}"
    );
}

/// Verify: shard op_log timestamps are not checked for monotonicity.
///
/// Encodes a shard record with out-of-order op_log timestamps. If this
/// decodes successfully, the monotonicity check is missing.
#[test]
fn decode_shard_record_rejects_non_monotonic_op_log_timestamps() {
    let mut blob = Vec::new();
    blob.extend_from_slice(b"v1");
    blob.push(BlobKind::ShardRecord as u8);
    blob.extend_from_slice(TenantId::from_bytes([0xAA; 32]).as_bytes());
    push_u64(&mut blob, RunId::from_raw(1).as_raw());
    push_u64(&mut blob, ShardId::from_raw(2).as_raw());
    blob.push(ShardStatus::Active.as_u8());
    blob.push(0); // park_reason absent
    push_bytes(&mut blob, b"a"); // key_range_start
    push_bytes(&mut blob, b"z"); // key_range_end
    push_bytes(&mut blob, b"m"); // metadata
    blob.push(0); // cursor_last_key absent
    blob.push(0); // cursor_token absent
    blob.push(CursorSemantics::Completed.as_u8());
    blob.push(0); // no lease
    push_u64(&mut blob, FenceEpoch::INITIAL.as_raw());
    blob.push(0); // parent absent
    push_u32(&mut blob, 0); // spawned len

    // Two op_log entries with decreasing timestamps (20, then 10).
    push_u32(&mut blob, 2); // op_log len
    // Entry 0: op_id=1, kind=Checkpoint, result=Completed, hash=0xAA, executed_at=20
    push_u64(&mut blob, OpId::from_raw(1).as_raw());
    blob.push(OpKind::Checkpoint.as_u8());
    blob.push(OpResult::Completed.as_u8());
    push_u64(&mut blob, 0xAA); // payload_hash (must be non-zero)
    push_u64(&mut blob, LogicalTime::from_raw(20).as_raw());
    // Entry 1: op_id=2, kind=Checkpoint, result=Completed, hash=0xBB, executed_at=10
    push_u64(&mut blob, OpId::from_raw(2).as_raw());
    blob.push(OpKind::Checkpoint.as_u8());
    blob.push(OpResult::Completed.as_u8());
    push_u64(&mut blob, 0xBB); // payload_hash (must be non-zero)
    push_u64(&mut blob, LogicalTime::from_raw(10).as_raw());

    let mut slab = ByteSlab::with_capacity(4096);
    let result = decode_shard_record(&blob, &mut slab);
    assert!(
        result.is_err(),
        "shard record with non-monotonic op_log timestamps should be rejected"
    );
    match result {
        Err(EtcdCodecError::InvariantViolation { detail, .. }) => {
            assert!(
                detail.contains("non-decreasing"),
                "error should mention timestamp monotonicity, got: {detail}"
            );
        }
        Err(other) => panic!("expected InvariantViolation, got: {other:?}"),
        Ok(_) => unreachable!(),
    }
}

// ---------------------------------------------------------------------------
// Large root-shard count round-trip (structural bound, no hard cap)
// ---------------------------------------------------------------------------

/// Records with >1024 root shards round-trip correctly now that the decoder
/// derives its allocation guard from remaining wire bytes rather than a
/// hard-coded constant.
#[test]
fn run_record_large_root_shard_count_round_trips() {
    let tenant = TenantId::from_bytes([0xFD; 32]);
    let run = RunId::from_raw(0xFD00);
    let config = RunConfig::try_new(CursorSemantics::Completed, 30, Some(5)).unwrap();
    let root_shards: Vec<ShardId> = (1..=2048).map(ShardId::from_raw).collect();

    let mut op_log = RingBuffer::<RunOpLogEntry, { RunRecord::OP_LOG_CAP }>::new();
    op_log.push_back_overwrite(RunOpLogEntry::new(
        OpId::from_raw(1),
        RunOpKind::RegisterShards,
        0x1111,
        LogicalTime::from_raw(1),
        RunOpResult::RegisteredShards {
            shard_ids: root_shards.clone().into_boxed_slice(),
        },
    ));

    let record = RunRecord {
        tenant,
        run,
        config,
        status: RunStatus::Active,
        created_at: LogicalTime::from_raw(1),
        completed_at: None,
        root_shards,
        op_log,
    };

    let encoded = encode_run_record(&record);
    let decoded = decode_run_record(&encoded)
        .expect("record with 2048 root shards must decode with structural bound");
    assert_eq!(&decoded, &record);
}
