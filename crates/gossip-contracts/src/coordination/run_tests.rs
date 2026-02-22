use super::*;
use crate::coordination::cursor::Cursor;
use crate::coordination::shard_spec::CursorSemantics;
use crate::identity::{OpId, RunId, ShardId};
use gossip_stdx::RingBuffer;
use rstest::rstest;

// -- Test fixtures --

fn test_tenant() -> TenantId {
    TenantId::from_bytes([0x01; 32])
}

fn test_run() -> RunId {
    RunId::from_raw(1)
}

fn test_config() -> RunConfig {
    RunConfig::try_new(CursorSemantics::Completed, 30, Some(5)).unwrap()
}

fn test_run_record() -> RunRecord {
    RunRecord {
        tenant: test_tenant(),
        run: test_run(),
        config: test_config(),
        status: RunStatus::Active,
        created_at: LogicalTime::from_raw(1),
        completed_at: None,
        root_shards: vec![ShardId::from_raw(0), ShardId::from_raw(1)],
        op_log: RingBuffer::new(),
    }
}

fn make_initial_shard(id: u64, start: &[u8], end: &[u8]) -> InitialShard {
    InitialShard::new(
        ShardId::from_raw(id),
        ShardSpec::with_range(start.to_vec(), end.to_vec()),
        Cursor::initial(),
    )
}

fn make_op_log_entry(op_id: u64, kind: RunOpKind) -> RunOpLogEntry {
    let result = match kind {
        RunOpKind::RegisterShards => RunOpResult::RegisteredShards {
            shard_ids: Box::new([ShardId::from_raw(0)]),
        },
        _ => RunOpResult::Ack,
    };
    RunOpLogEntry::new(
        OpId::from_raw(op_id),
        kind,
        42, // non-zero payload hash
        LogicalTime::from_raw(1),
        result,
    )
}

// -- RunStatus --

#[rstest]
#[case::initializing(RunStatus::Initializing, 0, false, "Initializing")]
#[case::active(RunStatus::Active, 1, false, "Active")]
#[case::done(RunStatus::Done, 2, true, "Done")]
#[case::failed(RunStatus::Failed, 3, true, "Failed")]
#[case::cancelled(RunStatus::Cancelled, 4, true, "Cancelled")]
fn run_status_properties(
    #[case] status: RunStatus,
    #[case] disc: u8,
    #[case] terminal: bool,
    #[case] display: &str,
) {
    assert_eq!(status.as_u8(), disc);
    assert_eq!(RunStatus::from_u8(disc), Some(status));
    assert_eq!(status.is_terminal(), terminal);
    assert_eq!(status.to_string(), display);
}

#[test]
fn run_status_from_u8_out_of_range() {
    assert_eq!(RunStatus::from_u8(5), None);
    assert_eq!(RunStatus::from_u8(u8::MAX), None);
}

// -- RunConfig --

#[test]
fn run_config_try_new_ok() {
    let cfg = RunConfig::try_new(CursorSemantics::Completed, 30, Some(5)).unwrap();
    assert_eq!(cfg.cursor_semantics(), CursorSemantics::Completed);
    assert_eq!(cfg.lease_duration(), 30);
    assert_eq!(cfg.max_shard_retries(), Some(5));
}

#[test]
fn run_config_try_new_zero_lease() {
    let err = RunConfig::try_new(CursorSemantics::Completed, 0, None).unwrap_err();
    assert_eq!(err, RunConfigError::ZeroLeaseDuration);
}

#[test]
fn run_config_assert_valid_ok() {
    test_config().assert_valid();
}

// Zero-lease-duration panicking test removed — `NonZeroU64` enforces
// this invariant at the type level; you can't construct the invalid state.

// -- RunOpKind --

#[rstest]
#[case::register_shards(RunOpKind::RegisterShards, 0, "RegisterShards")]
#[case::complete_run(RunOpKind::CompleteRun, 1, "CompleteRun")]
#[case::fail_run(RunOpKind::FailRun, 2, "FailRun")]
#[case::cancel_run(RunOpKind::CancelRun, 3, "CancelRun")]
fn run_op_kind_properties(#[case] kind: RunOpKind, #[case] disc: u8, #[case] display: &str) {
    assert_eq!(kind.as_u8(), disc);
    assert_eq!(RunOpKind::from_u8(disc), Some(kind));
    assert_eq!(kind.to_string(), display);
}

#[test]
fn run_op_kind_from_u8_out_of_range() {
    assert_eq!(RunOpKind::from_u8(4), None);
}

// -- RunOpLogEntry --

#[test]
fn run_op_log_entry_accessors() {
    let entry = RunOpLogEntry::new(
        OpId::from_raw(1),
        RunOpKind::CompleteRun,
        42,
        LogicalTime::from_raw(10),
        RunOpResult::Ack,
    );
    assert_eq!(entry.op_id(), OpId::from_raw(1));
    assert_eq!(entry.kind(), RunOpKind::CompleteRun);
    assert_eq!(entry.payload_hash(), 42);
    assert_eq!(entry.executed_at(), LogicalTime::from_raw(10));
    assert_eq!(entry.result(), &RunOpResult::Ack);
}

#[test]
#[should_panic(expected = "payload_hash must not be zero")]
fn run_op_log_entry_zero_hash_panics() {
    RunOpLogEntry::new(
        OpId::from_raw(1),
        RunOpKind::CompleteRun,
        0,
        LogicalTime::from_raw(1),
        RunOpResult::Ack,
    );
}

#[test]
#[should_panic(expected = "executed_at must be > ZERO")]
fn run_op_log_entry_zero_time_panics() {
    RunOpLogEntry::new(
        OpId::from_raw(1),
        RunOpKind::CompleteRun,
        42,
        LogicalTime::ZERO,
        RunOpResult::Ack,
    );
}

// -- RunOpIdConflict security --

#[test]
fn run_op_id_conflict_debug_redacts_hashes() {
    let c = RunOpIdConflict {
        op_id: OpId::from_raw(1),
        expected_hash: 0xDEAD_BEEF,
        actual_hash: 0xCAFE_BABE,
    };
    let debug = format!("{c:?}");
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains("DEAD"));
    assert!(!debug.contains("CAFE"));
    assert!(
        !debug.contains("3735928559") && !debug.contains("3405691582"),
        "debug leaks decimal hash: {debug}"
    );
}

// -- RunRecord invariants --

#[test]
fn run_record_valid_states_pass_invariants() {
    test_run_record().assert_invariants();

    RunRecord {
        status: RunStatus::Done,
        completed_at: Some(LogicalTime::from_raw(100)),
        ..test_run_record()
    }
    .assert_invariants();

    RunRecord {
        status: RunStatus::Initializing,
        root_shards: vec![],
        ..test_run_record()
    }
    .assert_invariants();

    RunRecord {
        status: RunStatus::Cancelled,
        completed_at: Some(LogicalTime::from_raw(100)),
        ..test_run_record()
    }
    .assert_invariants();
}

#[test]
#[should_panic(expected = "completed_at must be Some")]
fn rr_done_no_completed_at() {
    RunRecord {
        status: RunStatus::Done,
        completed_at: None,
        ..test_run_record()
    }
    .assert_invariants();
}

#[test]
#[should_panic(expected = "completed_at must be Some")]
fn rr_active_has_completed_at() {
    RunRecord {
        completed_at: Some(LogicalTime::from_raw(100)),
        ..test_run_record()
    }
    .assert_invariants();
}

#[test]
#[should_panic(expected = "must have at least one root shard")]
fn rr_active_no_shards() {
    RunRecord {
        root_shards: vec![],
        ..test_run_record()
    }
    .assert_invariants();
}

#[test]
#[should_panic(expected = "created_at must be > ZERO")]
fn rr_created_at_zero() {
    RunRecord {
        created_at: LogicalTime::ZERO,
        ..test_run_record()
    }
    .assert_invariants();
}

#[test]
#[should_panic(expected = "must have empty root_shards")]
fn rr_initializing_with_shards() {
    RunRecord {
        status: RunStatus::Initializing,
        // root_shards from test_run_record is non-empty
        ..test_run_record()
    }
    .assert_invariants();
}

#[test]
#[should_panic(expected = "completed_at")]
fn rr_completed_before_created() {
    RunRecord {
        status: RunStatus::Done,
        created_at: LogicalTime::from_raw(200),
        completed_at: Some(LogicalTime::from_raw(100)),
        ..test_run_record()
    }
    .assert_invariants();
}

// -- RunRecord op-log --

#[test]
fn run_op_log_push_and_lookup() {
    let mut r = test_run_record();
    r.op_log_push(make_op_log_entry(42, RunOpKind::CompleteRun));
    assert!(r.op_log_lookup(OpId::from_raw(42)).is_some());
    assert!(r.op_log_lookup(OpId::from_raw(99)).is_none());
}

#[test]
fn run_op_log_reverse_lookup() {
    let mut r = test_run_record();
    r.op_log_push(make_op_log_entry(1, RunOpKind::RegisterShards));
    r.op_log_push(make_op_log_entry(2, RunOpKind::CompleteRun));
    // Reverse scan means op_id=2 found first (most recent).
    let found = r.op_log_lookup(OpId::from_raw(2)).unwrap();
    assert_eq!(found.kind(), RunOpKind::CompleteRun);
}

#[test]
fn run_op_log_bounded() {
    let mut r = test_run_record();
    for i in 0..(RunRecord::OP_LOG_CAP + 5) {
        r.op_log_push(make_op_log_entry(i as u64, RunOpKind::CompleteRun));
    }
    assert_eq!(r.op_log.len(), RunRecord::OP_LOG_CAP);
    // Oldest entries evicted.
    assert!(r.op_log_lookup(OpId::from_raw(0)).is_none());
    assert!(
        r.op_log_lookup(OpId::from_raw((RunRecord::OP_LOG_CAP + 4) as u64))
            .is_some()
    );
}

#[test]
#[should_panic(expected = "duplicate OpId")]
fn run_op_log_push_duplicate_panics() {
    let mut r = test_run_record();
    r.op_log_push(make_op_log_entry(1, RunOpKind::CompleteRun));
    r.op_log_push(make_op_log_entry(1, RunOpKind::FailRun));
}

// -- check_op_idempotency --

#[test]
fn run_idem_new_op() {
    assert!(
        test_run_record()
            .check_op_idempotency(OpId::from_raw(1), 100)
            .unwrap()
            .is_none()
    );
}

#[test]
fn run_idem_replay() {
    let mut r = test_run_record();
    r.op_log_push(RunOpLogEntry::new(
        OpId::from_raw(1),
        RunOpKind::CompleteRun,
        100,
        LogicalTime::from_raw(1),
        RunOpResult::Ack,
    ));
    assert!(
        r.check_op_idempotency(OpId::from_raw(1), 100)
            .unwrap()
            .is_some()
    );
}

#[test]
fn run_idem_conflict() {
    let mut r = test_run_record();
    r.op_log_push(RunOpLogEntry::new(
        OpId::from_raw(1),
        RunOpKind::CompleteRun,
        100,
        LogicalTime::from_raw(1),
        RunOpResult::Ack,
    ));
    let err = r.check_op_idempotency(OpId::from_raw(1), 999).unwrap_err();
    assert_eq!(err.expected_hash, 100);
    assert_eq!(err.actual_hash, 999);
}

#[test]
#[should_panic(expected = "payload_hash must not be zero")]
fn run_idem_zero_hash_panics() {
    test_run_record()
        .check_op_idempotency(OpId::from_raw(1), 0)
        .unwrap();
}

// -- RunProgress --

#[test]
fn progress_count_shard() {
    let mut p = RunProgress::default();
    p.count_shard(ShardStatus::Active, true);
    p.count_shard(ShardStatus::Active, false);
    p.count_shard(ShardStatus::Done, false);
    p.count_shard(ShardStatus::Split, false);
    p.count_shard(ShardStatus::Parked, false);
    assert_eq!(p.total(), 5);
    assert_eq!(p.active(), 2);
    assert_eq!(p.leased(), 1);
    assert_eq!(p.done(), 1);
    assert_eq!(p.split(), 1);
    assert_eq!(p.parked(), 1);
}

#[test]
fn progress_predicates() {
    let settled_success = RunProgress {
        total: 3,
        done: 2,
        split: 1,
        ..Default::default()
    };
    assert!(settled_success.is_settled());
    assert!(settled_success.is_success());
    assert!(!settled_success.has_failures());

    let settled_failures = RunProgress {
        total: 3,
        done: 1,
        parked: 2,
        ..Default::default()
    };
    assert!(settled_failures.is_settled());
    assert!(!settled_failures.is_success());
    assert!(settled_failures.has_failures());

    let still_active = RunProgress {
        total: 3,
        active: 1,
        done: 2,
        ..Default::default()
    };
    assert!(!still_active.is_settled());
}

// -- evaluate_run_terminal --

#[rstest]
#[case::still_active(
    RunProgress { total: 1, active: 1, ..Default::default() },
    RunTerminalEvaluation::StillActive,
)]
#[case::all_done(
    RunProgress { total: 3, done: 2, split: 1, ..Default::default() },
    RunTerminalEvaluation::AllDone,
)]
#[case::has_failures(
    RunProgress { total: 3, done: 1, parked: 2, ..Default::default() },
    RunTerminalEvaluation::HasFailures,
)]
fn evaluate_run_terminal_cases(
    #[case] progress: RunProgress,
    #[case] expected: RunTerminalEvaluation,
) {
    assert_eq!(evaluate_run_terminal(&progress), expected);
}

// -- validate_manifest --

#[rstest]
#[case::two_adjacent(
    vec![make_initial_shard(0, b"a", b"m"), make_initial_shard(1, b"m", b"z")]
)]
#[case::gap_between_shards(
    vec![make_initial_shard(0, b"a", b"f"), make_initial_shard(1, b"m", b"z")]
)]
#[case::unordered_input(
    vec![make_initial_shard(1, b"m", b"z"), make_initial_shard(0, b"a", b"m")]
)]
#[case::single_shard(vec![make_initial_shard(0, b"a", b"z")])]
fn manifest_valid_cases(#[case] shards: Vec<InitialShard>) {
    assert!(validate_manifest(&shards).is_ok());
}

#[test]
fn manifest_empty() {
    assert_eq!(validate_manifest(&[]), Err(ManifestValidationError::Empty));
}

#[test]
fn manifest_too_many() {
    let shards: Vec<_> = (0..MAX_INITIAL_SHARDS + 1)
        .map(|i| {
            let start = format!("{:05}", i);
            let end = format!("{:05}", i + 1);
            make_initial_shard(i as u64, start.as_bytes(), end.as_bytes())
        })
        .collect();
    assert!(matches!(
        validate_manifest(&shards),
        Err(ManifestValidationError::TooManyShards { .. })
    ));
}

#[test]
fn manifest_dup_id() {
    assert!(matches!(
        validate_manifest(&[
            make_initial_shard(0, b"a", b"m"),
            make_initial_shard(0, b"m", b"z"),
        ]),
        Err(ManifestValidationError::DuplicateIds { .. })
    ));
}

#[test]
fn manifest_overlap() {
    assert!(matches!(
        validate_manifest(&[
            make_initial_shard(0, b"a", b"n"),
            make_initial_shard(1, b"m", b"z"),
        ]),
        Err(ManifestValidationError::OverlappingRanges { .. })
    ));
}

#[test]
fn manifest_inverted_spec() {
    // Use try_with_range to avoid the panic in with_range on inverted range,
    // then bypass via unbounded spec manipulation. Actually, ShardSpec::with_range
    // enforces start < end at construction. Validate that validate_manifest
    // also catches this via try_with_range.
    let result = ShardSpec::try_with_range(b"z".to_vec(), b"a".to_vec());
    assert!(result.is_err(), "ShardSpec should reject inverted range");
}

#[test]
fn manifest_cursor_out_of_bounds() {
    let shard = InitialShard::new(
        ShardId::from_raw(0),
        ShardSpec::with_range(b"m".to_vec(), b"z".to_vec()),
        Cursor::with_last_key(b"a".to_vec()), // before range start
    );
    assert!(matches!(
        validate_manifest(&[shard]),
        Err(ManifestValidationError::CursorOutOfBounds { .. })
    ));
}

#[test]
fn manifest_cursor_key_too_large() {
    use crate::coordination::cursor::MAX_KEY_SIZE;

    let oversized_key = vec![0xAA; MAX_KEY_SIZE + 1];
    let shard = InitialShard::new(
        ShardId::from_raw(0),
        ShardSpec::with_range(vec![0x00], vec![0xFF]),
        Cursor::with_last_key(oversized_key),
    );
    let result = validate_manifest(&[shard]);
    assert!(
        matches!(
            result,
            Err(ManifestValidationError::CursorKeyTooLarge { size, max, .. })
                if size == MAX_KEY_SIZE + 1 && max == MAX_KEY_SIZE
        ),
        "expected CursorKeyTooLarge, got: {result:?}",
    );
}

#[test]
fn manifest_cursor_key_at_exact_max_succeeds() {
    use crate::coordination::cursor::MAX_KEY_SIZE;

    let exact_key = vec![0xBB; MAX_KEY_SIZE];
    let shard = InitialShard::new(
        ShardId::from_raw(0),
        ShardSpec::with_range(vec![0x00], vec![0xFF]),
        Cursor::with_last_key(exact_key),
    );
    assert!(validate_manifest(&[shard]).is_ok());
}

#[test]
fn manifest_cursor_key_too_large_display() {
    let err = ManifestValidationError::CursorKeyTooLarge {
        shard_id: ShardId::from_raw(42),
        size: 5000,
        max: 4096,
    };
    let msg = err.to_string();
    assert!(msg.contains("5000"), "display must include actual size");
    assert!(msg.contains("4096"), "display must include max size");
}

// -- ShardFilter --

fn make_shard_summary(status: ShardStatus, leased: bool, parent: Option<ShardId>) -> ShardSummary {
    ShardSummary {
        shard: ShardId::from_raw(0),
        status,
        park_reason: None,
        is_leased: leased,
        lease_deadline: None,
        acquire_count: 0,
        last_key: None,
        key_range_start: b"a".to_vec().into(),
        key_range_end: b"z".to_vec().into(),
        parent,
        spawned_count: 0,
    }
}

#[rstest]
#[case::all_matches_everything(
    ShardFilter::all(),
    make_shard_summary(ShardStatus::Active, false, None),
    true
)]
#[case::active_rejects_done(
    ShardFilter::active(),
    make_shard_summary(ShardStatus::Done, false, None),
    false
)]
#[case::available_rejects_leased(
    ShardFilter::available(),
    make_shard_summary(ShardStatus::Active, true, None),
    false
)]
#[case::root_only_rejects_children(
    ShardFilter { root_only: true, ..ShardFilter::default() },
    make_shard_summary(ShardStatus::Active, false, Some(ShardId::from_raw(99))),
    false,
)]
fn shard_filter_matching(
    #[case] filter: ShardFilter,
    #[case] summary: ShardSummary,
    #[case] expected: bool,
) {
    assert_eq!(filter.matches(&summary), expected);
}

// -- Payload hashes --

#[test]
fn hash_register_shards_order_independent() {
    let s1 = make_initial_shard(0, b"a", b"m");
    let s2 = make_initial_shard(1, b"m", b"z");
    let h_forward = hash_register_shards_payload(&[s1.clone(), s2.clone()]);
    let h_reverse = hash_register_shards_payload(&[s2, s1]);
    assert_eq!(h_forward, h_reverse);
    assert_ne!(h_forward, 0);
}

#[test]
fn hash_terminal_ops_distinct() {
    let hc = hash_complete_run_payload();
    let hf = hash_fail_run_payload();
    let hx = hash_cancel_run_payload();
    assert_ne!(hc, 0);
    assert_ne!(hf, 0);
    assert_ne!(hx, 0);
    assert_ne!(hc, hf);
    assert_ne!(hc, hx);
    assert_ne!(hf, hx);
}

#[test]
fn hash_unpark_different_shards_differ() {
    let k1 = ShardKey::new(RunId::from_raw(1), ShardId::from_raw(10));
    let k2 = ShardKey::new(RunId::from_raw(1), ShardId::from_raw(20));
    let h1 = hash_unpark_payload(&k1);
    let h2 = hash_unpark_payload(&k2);
    assert_ne!(h1, h2);
    assert_ne!(h1, 0);
    assert_ne!(h2, 0);
}

// -- INV-11: Kind-result consistency --

#[test]
#[should_panic(expected = "RegisterShards must have RegisteredShards result")]
fn construction_rejects_register_shards_with_ack() {
    // INV-11 now enforced at construction time in RunOpLogEntry::new().
    let _ = RunOpLogEntry::new(
        OpId::from_raw(1),
        RunOpKind::RegisterShards,
        42,
        LogicalTime::from_raw(1),
        RunOpResult::Ack,
    );
}

#[test]
#[should_panic(expected = "must have Ack result, not RegisteredShards")]
fn construction_rejects_terminal_op_with_registered_shards() {
    // INV-11 now enforced at construction time in RunOpLogEntry::new().
    let _ = RunOpLogEntry::new(
        OpId::from_raw(1),
        RunOpKind::CompleteRun,
        42,
        LogicalTime::from_raw(1),
        RunOpResult::RegisteredShards {
            shard_ids: Box::new([]),
        },
    );
}

#[test]
#[should_panic(expected = "duplicate ShardId")]
fn rr_duplicate_root_shards_panics() {
    let dup = ShardId::from_raw(0);
    RunRecord {
        root_shards: vec![dup, dup],
        ..test_run_record()
    }
    .assert_invariants();
}

#[test]
#[should_panic(expected = "timestamps not non-decreasing")]
fn rr_oplog_timestamps_non_decreasing_panics() {
    let mut r = test_run_record();
    r.op_log
        .push_back(RunOpLogEntry::new(
            OpId::from_raw(1),
            RunOpKind::CompleteRun,
            42,
            LogicalTime::from_raw(10),
            RunOpResult::Ack,
        ))
        .unwrap();
    r.op_log
        .push_back(RunOpLogEntry::new(
            OpId::from_raw(2),
            RunOpKind::FailRun,
            43,
            LogicalTime::from_raw(5), // earlier than previous — violates INV-10
            RunOpResult::Ack,
        ))
        .unwrap();
    r.assert_invariants();
}

// -- Finding 3: ShardSummary acquire_count saturation --

#[test]
fn shard_summary_acquire_count_saturates_at_u32_max() {
    use crate::coordination::record::ShardRecord;

    let large_epoch = FenceEpoch::from_raw(u64::from(u32::MAX) + 2);
    let record = ShardRecord::from_raw_parts(
        test_tenant(),
        test_run(),
        ShardId::from_raw(1),
        ShardStatus::Active,
        None,
        ShardSpec::with_range(b"a".to_vec(), b"z".to_vec()),
        Cursor::initial(),
        CursorSemantics::Completed,
        None,
        large_epoch,
        None,
        gossip_stdx::InlineVec::new(),
        RingBuffer::new(),
    );
    let summary = ShardSummary::from_record(&record, LogicalTime::from_raw(1));
    assert_eq!(
        summary.acquire_count(),
        u32::MAX,
        "acquire_count must saturate at u32::MAX, not truncate"
    );
}

// -- Finding 2: validate_manifest InvalidSpec path --

#[test]
fn manifest_inverted_spec_detected_by_validate_manifest() {
    let inverted_spec = ShardSpec::from_raw_parts(
        b"z".to_vec().into_boxed_slice(),
        b"a".to_vec().into_boxed_slice(),
        Box::new([]),
    );
    let shard = InitialShard::new(ShardId::from_raw(0), inverted_spec, Cursor::initial());
    let result = validate_manifest(&[shard]);
    assert!(
        matches!(result, Err(ManifestValidationError::InvalidSpec { .. })),
        "validate_manifest must catch inverted specs: {result:?}"
    );
}

// -- Finding 4: count_shard assert (promoted from debug_assert) --

#[test]
#[should_panic(expected = "is_leased=true is only valid for Active shards")]
fn count_shard_leased_non_active_panics() {
    let mut p = RunProgress::default();
    p.count_shard(ShardStatus::Done, true);
}

// -- Finding 5: evaluate_run_terminal debug_assert --

#[test]
#[should_panic(expected = "evaluate_run_terminal called with zero-total progress")]
fn evaluate_run_terminal_zero_total_panics() {
    let _ = evaluate_run_terminal(&RunProgress::default());
}

// -- RunOpIdConflict Display does not leak hashes --

#[test]
fn run_op_id_conflict_display_no_hash_leak() {
    let c = RunOpIdConflict {
        op_id: OpId::from_raw(1),
        expected_hash: 0xDEAD_BEEF,
        actual_hash: 0xCAFE_BABE,
    };
    let display = c.to_string();
    assert!(
        !display.contains("DEAD") && !display.contains("CAFE"),
        "Display leaks hex hash: {display}"
    );
    assert!(
        !display.contains("3735928559") && !display.contains("3405691582"),
        "Display leaks decimal hash: {display}"
    );
}

// -- Exact boundary tests --

#[test]
fn manifest_exactly_max_initial_shards_succeeds() {
    let shards: Vec<_> = (0..MAX_INITIAL_SHARDS)
        .map(|i| {
            let start = format!("{:05}", i);
            let end = format!("{:05}", i + 1);
            make_initial_shard(i as u64, start.as_bytes(), end.as_bytes())
        })
        .collect();
    assert!(validate_manifest(&shards).is_ok());
}

#[test]
fn op_log_exactly_at_cap_maintains_invariants() {
    let mut r = test_run_record();
    for i in 0..RunRecord::OP_LOG_CAP {
        r.op_log_push(make_op_log_entry(i as u64, RunOpKind::CompleteRun));
    }
    assert_eq!(r.op_log.len(), RunRecord::OP_LOG_CAP);
    r.assert_invariants();

    // One more should evict the oldest.
    r.op_log_push(make_op_log_entry(
        RunRecord::OP_LOG_CAP as u64,
        RunOpKind::FailRun,
    ));
    assert_eq!(r.op_log.len(), RunRecord::OP_LOG_CAP);
    // Oldest (op_id=0) evicted.
    assert!(r.op_log_lookup(OpId::from_raw(0)).is_none());
    // Newest still present.
    assert!(
        r.op_log_lookup(OpId::from_raw(RunRecord::OP_LOG_CAP as u64))
            .is_some()
    );
    r.assert_invariants();
}

#[test]
fn count_shard_overflow_panics() {
    let mut p = RunProgress {
        total: u32::MAX,
        active: u32::MAX,
        ..Default::default()
    };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        p.count_shard(ShardStatus::Active, false);
    }));
    assert!(result.is_err(), "count_shard must panic on u32 overflow");
}

// -- Proptest for validate_manifest --

mod prop_manifest {
    use super::*;
    use crate::test_util::miri_proptest_config;
    use proptest::prelude::*;

    /// Strategy for a valid shard ID (non-zero, bounded).
    fn arb_shard_id() -> impl Strategy<Value = ShardId> {
        (1u64..10_000).prop_map(ShardId::from_raw)
    }

    /// Strategy for a valid InitialShard with non-overlapping key range.
    fn arb_initial_shard(idx: usize) -> impl Strategy<Value = InitialShard> {
        arb_shard_id().prop_map(move |id| {
            let start = format!("{:06}", idx);
            let end = format!("{:06}", idx + 1);
            InitialShard::new(
                id,
                ShardSpec::with_range(start.into_bytes(), end.into_bytes()),
                Cursor::initial(),
            )
        })
    }

    /// Generate a vec of `n` initial shards with unique, non-overlapping
    /// key ranges (indexed by position).
    fn arb_manifest(max_len: usize) -> impl Strategy<Value = Vec<InitialShard>> {
        (1..=max_len).prop_flat_map(|n| {
            // Generate n unique shard IDs.
            proptest::collection::hash_set(1u64..100_000, n).prop_map(move |ids| {
                ids.into_iter()
                    .enumerate()
                    .map(|(idx, raw)| {
                        let start = format!("{:06}", idx);
                        let end = format!("{:06}", idx + 1);
                        InitialShard::new(
                            ShardId::from_raw(raw),
                            ShardSpec::with_range(start.into_bytes(), end.into_bytes()),
                            Cursor::initial(),
                        )
                    })
                    .collect()
            })
        })
    }

    proptest! {
        #![proptest_config(miri_proptest_config())]

        /// Well-formed manifests always pass validation.
        #[test]
        fn valid_manifests_accepted(shards in arb_manifest(50)) {
            prop_assert!(validate_manifest(&shards).is_ok());
        }

        /// Manifests with a duplicate ID always fail.
        #[test]
        fn duplicate_id_always_rejected(base in arb_initial_shard(0)) {
            let dup = InitialShard::new(
                base.shard(),
                ShardSpec::with_range(b"x".to_vec(), b"y".to_vec()),
                Cursor::initial(),
            );
            let result = validate_manifest(&[base, dup]);
            prop_assert!(
                matches!(result, Err(ManifestValidationError::DuplicateIds { .. })),
                "expected DuplicateIds, got: {result:?}",
            );
        }

        /// Overlapping ranges always fail.
        #[test]
        fn overlapping_ranges_always_rejected(
            id_a in 1u64..50_000,
            id_b in 50_000u64..100_000,
        ) {
            let a = InitialShard::new(
                ShardId::from_raw(id_a),
                ShardSpec::with_range(b"a".to_vec(), b"n".to_vec()),
                Cursor::initial(),
            );
            let b = InitialShard::new(
                ShardId::from_raw(id_b),
                ShardSpec::with_range(b"m".to_vec(), b"z".to_vec()),
                Cursor::initial(),
            );
            let result = validate_manifest(&[a, b]);
            prop_assert!(
                matches!(result, Err(ManifestValidationError::OverlappingRanges { .. })),
                "expected OverlappingRanges, got: {result:?}",
            );
        }
    }
}

// -- Unbounded range rejection tests --

#[test]
fn manifest_detects_overlap_with_unbounded_end() {
    // Unbounded end is now rejected before overlap detection.
    let shard_a = InitialShard::new(
        ShardId::from_raw(0),
        ShardSpec::from_raw_parts(
            b"a".to_vec().into_boxed_slice(),
            Box::new([]), // unbounded end = [a, ∞)
            Box::new([]),
        ),
        Cursor::initial(),
    );
    let shard_b = make_initial_shard(1, b"m", b"z");
    let result = validate_manifest(&[shard_a, shard_b]);
    assert!(
        matches!(result, Err(ManifestValidationError::UnboundedRange { .. })),
        "unbounded end must be rejected: {result:?}"
    );
}

#[test]
fn manifest_detects_overlap_with_both_starts_empty() {
    // Unbounded start is now rejected before overlap detection.
    let shard_a = InitialShard::new(
        ShardId::from_raw(0),
        ShardSpec::from_raw_parts(
            Box::new([]), // unbounded start
            b"m".to_vec().into_boxed_slice(),
            Box::new([]),
        ),
        Cursor::initial(),
    );
    let shard_b = InitialShard::new(
        ShardId::from_raw(1),
        ShardSpec::from_raw_parts(
            Box::new([]), // unbounded start
            b"z".to_vec().into_boxed_slice(),
            Box::new([]),
        ),
        Cursor::initial(),
    );
    let result = validate_manifest(&[shard_a, shard_b]);
    assert!(
        matches!(result, Err(ManifestValidationError::UnboundedRange { .. })),
        "unbounded start must be rejected: {result:?}"
    );
}

#[test]
fn manifest_unbounded_start_rejected() {
    // Unbounded start is no longer accepted in production manifests.
    let shard_a = InitialShard::new(
        ShardId::from_raw(0),
        ShardSpec::from_raw_parts(
            Box::new([]), // unbounded start
            b"m".to_vec().into_boxed_slice(),
            Box::new([]),
        ),
        Cursor::initial(),
    );
    let shard_b = make_initial_shard(1, b"m", b"z");
    let result = validate_manifest(&[shard_a, shard_b]);
    assert!(
        matches!(result, Err(ManifestValidationError::UnboundedRange { .. })),
        "unbounded start must be rejected: {result:?}"
    );
}

#[test]
fn manifest_unbounded_end_rejected() {
    let shard = InitialShard::new(
        ShardId::from_raw(0),
        ShardSpec::from_raw_parts(b"a".to_vec().into_boxed_slice(), Box::new([]), Box::new([])),
        Cursor::initial(),
    );
    assert!(
        matches!(
            validate_manifest(&[shard]),
            Err(ManifestValidationError::UnboundedRange { .. })
        ),
        "shard with unbounded end must be rejected"
    );
}

#[test]
fn manifest_fully_unbounded_rejected() {
    let shard = InitialShard::new(
        ShardId::from_raw(0),
        ShardSpec::unbounded(),
        Cursor::initial(),
    );
    assert!(
        matches!(
            validate_manifest(&[shard]),
            Err(ManifestValidationError::UnboundedRange { .. })
        ),
        "fully unbounded shard must be rejected"
    );
}
