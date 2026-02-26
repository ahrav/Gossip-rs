//! Tests for run-level types, validation, and the run lifecycle state machine.
//!
//! A "run" is a single scan invocation that groups shards covering a target data
//! source. This module tests the types that model runs (`RunStatus`, `RunConfig`,
//! `RunRecord`, `RunProgress`) and the validation logic that gates shard
//! registration (`validate_manifest`).
//!
//! # Coverage Areas
//!
//! - **Enum discriminant stability**: `RunStatus` and `RunOpKind` round-trip
//!   through `as_u8`/`from_u8` and produce the expected `Display` output.
//!   These are persisted values; discriminant drift is a data-corruption bug.
//!
//! - **RunConfig construction**: valid configs succeed, zero-lease-duration is
//!   rejected.
//!
//! - **RunOpLogEntry construction guards**: zero payload hash and zero timestamp
//!   are rejected at construction time. Kind-result consistency (INV-11) is
//!   enforced: `RegisterShards` requires `RegisteredShards` result, terminal
//!   ops require `Ack`.
//!
//! - **RunOpIdConflict security**: `Debug` and `Display` redact payload hashes
//!   to prevent leaking internal state into logs.
//!
//! - **RunRecord invariants**: `assert_invariants` rejects every illegal
//!   configuration (Done without `completed_at`, Active with `completed_at`,
//!   Initializing with shards, Active without shards, zero `created_at`,
//!   `completed_at` before `created_at`, duplicate root shards, non-monotonic
//!   op-log timestamps).
//!
//! - **RunRecord op-log**: push/lookup, reverse-scan bias, bounded eviction,
//!   duplicate rejection.
//!
//! - **Idempotency detection**: `check_op_idempotency` returns `None` for new
//!   ops, `Some` for replays with matching hash, and `Err` for hash conflicts.
//!
//! - **RunProgress**: `count_shard` accumulates correctly, `is_settled` /
//!   `is_success` / `has_failures` predicates, overflow protection, watermark
//!   accessor.
//!
//! - **evaluate_run_terminal**: maps progress to the three terminal evaluation
//!   outcomes.
//!
//! - **validate_manifest**: accepts valid manifests (adjacent, gapped, unordered,
//!   single-shard); rejects empty, too-many, duplicate-IDs, overlapping ranges,
//!   inverted specs, out-of-bounds cursors, oversized cursor keys, and unbounded
//!   ranges. Property tests verify these conditions hold across random inputs.
//!
//! - **ShardFilter**: `all()`, `active()`, `available()`, and `root_only`
//!   predicates match/reject the expected shard summaries.
//!
//! - **Payload hashes**: register-shards hash is order-independent, terminal-op
//!   hashes are distinct and non-zero, unpark hashes vary by shard key.

use super::*;
use gossip_contracts::coordination::cursor::CursorUpdate;
use gossip_contracts::coordination::shard_spec::{CursorSemantics, ShardSpec, ShardSpecRef};
use gossip_contracts::identity::{OpId, RunId, ShardId};
use gossip_stdx::{ByteSlab, RingBuffer};
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

#[derive(Clone, Debug)]
struct InitialShardFixture {
    shard: ShardId,
    spec: ShardSpec,
    cursor: CursorUpdate<'static>,
}

impl InitialShardFixture {
    fn as_input(&self) -> InitialShardInput<'_> {
        InitialShardInput::new(self.shard, self.spec.as_ref(), self.cursor)
    }
}

fn validate_manifest_fixtures(
    shards: &[InitialShardFixture],
) -> Result<(), ManifestValidationError> {
    let inputs: Vec<_> = shards.iter().map(InitialShardFixture::as_input).collect();
    validate_manifest(&inputs)
}

fn hash_register_shards_payload_fixtures(shards: &[InitialShardFixture]) -> u64 {
    let inputs: Vec<_> = shards.iter().map(InitialShardFixture::as_input).collect();
    hash_register_shards_payload(&inputs)
}

fn make_initial_shard(id: u64, start: &[u8], end: &[u8]) -> InitialShardFixture {
    InitialShardFixture {
        shard: ShardId::from_raw(id),
        spec: ShardSpec::with_range(start, end),
        cursor: CursorUpdate::initial(),
    }
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

// ============================================================================
// RunStatus discriminant stability
//
// RunStatus is persisted as `#[repr(u8)]`. These tests pin every variant's
// discriminant, terminal flag, and Display string.
// ============================================================================

/// Exhaustive roundtrip for all five RunStatus variants plus out-of-range
/// rejection. Terminal variants are Done, Failed, Cancelled.
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

// ============================================================================
// RunConfig construction and validation
// ============================================================================

/// Valid config preserves all fields through accessors.
#[test]
fn run_config_try_new_ok() {
    let cfg = RunConfig::try_new(CursorSemantics::Completed, 30, Some(5)).unwrap();
    assert_eq!(cfg.cursor_semantics(), CursorSemantics::Completed);
    assert_eq!(cfg.lease_duration(), 30);
    assert_eq!(cfg.max_shard_retries(), Some(5));
}

/// Zero lease duration is rejected at construction time.
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

// ============================================================================
// RunOpKind discriminant stability
// ============================================================================

/// All four RunOpKind variants roundtrip; values 4+ are invalid.
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

// ============================================================================
// RunOpLogEntry construction and guards
//
// RunOpLogEntry enforces preconditions at construction: non-zero payload hash,
// non-zero timestamp, and kind-result consistency (INV-11).
// ============================================================================

/// All accessor methods return the values passed to the constructor.
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

/// Zero payload hash would make idempotency detection unsound (every op
/// would appear to match), so it is rejected at construction.
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

// ============================================================================
// RunOpIdConflict security
//
// Payload hashes are internal integrity tokens. Leaking them in logs could
// help an attacker forge idempotent replays, so both Debug and Display
// must redact the actual hash values.
// ============================================================================

/// `Debug` output replaces hash values with `<redacted>` and does not
/// leak hex or decimal representations.
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

// ============================================================================
// RunRecord invariants
//
// RunRecord::assert_invariants enforces the biconditional between status and
// field values: terminal status requires completed_at, non-terminal forbids
// it; Active requires root_shards, Initializing forbids them; created_at
// must be non-zero; completed_at >= created_at; root_shards are unique;
// op-log timestamps are non-decreasing.
// ============================================================================

/// Active, Done, Initializing, and Cancelled are all valid when their
/// field invariants are satisfied.
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

/// Done status without completed_at violates the "terminal implies timestamp" invariant.
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

/// Active status with completed_at violates the "non-terminal implies no timestamp" invariant.
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

// ============================================================================
// RunRecord op-log
//
// The run op-log is a bounded ring buffer for idempotency detection. Same
// mechanics as the shard op-log: push/lookup, reverse-scan, FIFO eviction,
// duplicate rejection.
// ============================================================================

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

// ============================================================================
// check_op_idempotency
//
// Three outcomes: new op (None), replay with matching hash (Some), or
// hash conflict (Err). Zero hash is rejected as a precondition.
// ============================================================================

/// An op_id not in the log returns `None` (new operation).
#[test]
fn run_idem_new_op() {
    assert!(
        test_run_record()
            .check_op_idempotency(OpId::from_raw(1), 100)
            .unwrap()
            .is_none()
    );
}

/// An op_id in the log with matching hash returns `Some` (idempotent replay).
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

/// An op_id in the log with a different hash returns `Err(RunOpIdConflict)`.
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

// ============================================================================
// RunProgress
//
// RunProgress accumulates shard counts by status and leased flag. The
// predicates (is_settled, is_success, has_failures) drive the orchestrator's
// decision to complete or fail the run.
// ============================================================================

/// Counting one of each status produces the expected totals and per-status
/// counts. Leased count only tracks Active shards.
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
fn progress_watermark_accessor_and_default_behavior() {
    let default_progress = RunProgress::default();
    assert_eq!(default_progress.watermark(), None);

    let mut progress = RunProgress::default();
    progress.observe_shard(ShardStatus::Active, false, Some(b"abc"));
    assert_eq!(progress.watermark(), Some(b"abc".as_slice()));
}

#[test]
fn progress_observe_shard_reuses_watermark_storage() {
    let mut progress = RunProgress::default();
    progress.observe_shard(ShardStatus::Active, false, Some(b"m"));

    let watermark_ptr = progress
        .watermark()
        .expect("watermark must be set after observing active shard with key")
        .as_ptr();

    // Larger key should not change the tracked minimum or backing storage.
    progress.observe_shard(ShardStatus::Active, false, Some(b"z"));
    assert_eq!(progress.watermark(), Some(b"m".as_slice()));
    assert_eq!(
        progress
            .watermark()
            .expect("watermark must remain set after larger key")
            .as_ptr(),
        watermark_ptr
    );

    // Smaller key updates in place without replacing storage.
    progress.observe_shard(ShardStatus::Active, false, Some(b"a"));
    assert_eq!(progress.watermark(), Some(b"a".as_slice()));
    assert_eq!(
        progress
            .watermark()
            .expect("watermark must remain set after smaller key")
            .as_ptr(),
        watermark_ptr
    );
}

/// Settled = no active shards. Success = settled with no parked. Failures =
/// settled with at least one parked. Still-active = not settled.
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

// ============================================================================
// evaluate_run_terminal
//
// Maps RunProgress to one of three outcomes: StillActive (has active shards),
// AllDone (settled with no parked), HasFailures (settled with parked).
// ============================================================================

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

// ============================================================================
// validate_manifest
//
// The manifest is the initial shard layout for a run. Validation enforces:
// non-empty, within max count, unique IDs, non-overlapping ranges, valid
// specs, bounded key ranges, and cursor-in-bounds. These tests cover both
// the happy path and each rejection reason.
// ============================================================================

/// Valid manifests: adjacent shards, gapped shards, unordered input (sorted
/// internally), and single shard.
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
fn manifest_valid_cases(#[case] shards: Vec<InitialShardFixture>) {
    assert!(validate_manifest_fixtures(&shards).is_ok());
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
        validate_manifest_fixtures(&shards),
        Err(ManifestValidationError::TooManyShards { .. })
    ));
}

#[test]
fn manifest_dup_id() {
    let shards = vec![
        make_initial_shard(0, b"a", b"m"),
        make_initial_shard(0, b"m", b"z"),
    ];
    assert!(matches!(
        validate_manifest_fixtures(&shards),
        Err(ManifestValidationError::DuplicateIds { .. })
    ));
}

#[test]
fn manifest_overlap() {
    let shards = vec![
        make_initial_shard(0, b"a", b"n"),
        make_initial_shard(1, b"m", b"z"),
    ];
    assert!(matches!(
        validate_manifest_fixtures(&shards),
        Err(ManifestValidationError::OverlappingRanges { .. })
    ));
}

#[test]
fn manifest_inverted_spec() {
    // Use try_with_range to avoid the panic in with_range on inverted range,
    // then bypass via unbounded spec manipulation. Actually, ShardSpec::with_range
    // enforces start < end at construction. Validate that validate_manifest
    // also catches this via try_with_range.
    let result = ShardSpec::try_with_range(b"z", b"a");
    assert!(result.is_err(), "ShardSpec should reject inverted range");
}

#[test]
fn manifest_cursor_out_of_bounds() {
    let spec = ShardSpec::with_range(b"m", b"z");
    let cursor = CursorUpdate::with_last_key(b"a"); // before range start
    let shard = InitialShardInput::new(ShardId::from_raw(0), spec.as_ref(), cursor);
    assert!(matches!(
        validate_manifest(&[shard]),
        Err(ManifestValidationError::CursorOutOfBounds { .. })
    ));
}

#[test]
fn manifest_cursor_key_too_large() {
    use gossip_contracts::coordination::cursor::MAX_KEY_SIZE;

    let oversized_key = vec![0xAA; MAX_KEY_SIZE + 1];
    let spec = ShardSpec::with_range(vec![0x00], vec![0xFF]);
    let cursor = CursorUpdate::with_last_key(&oversized_key);
    let shard = InitialShardInput::new(ShardId::from_raw(0), spec.as_ref(), cursor);
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
    use gossip_contracts::coordination::cursor::MAX_KEY_SIZE;

    let exact_key = vec![0xBB; MAX_KEY_SIZE];
    let spec = ShardSpec::with_range(vec![0x00], vec![0xFF]);
    let cursor = CursorUpdate::with_last_key(&exact_key);
    let shard = InitialShardInput::new(ShardId::from_raw(0), spec.as_ref(), cursor);
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

#[test]
fn manifest_rejects_oversized_spec_key() {
    use gossip_contracts::coordination::shard_spec::MAX_KEY_SIZE;

    // Construct a ShardSpecRef with an oversized start key directly,
    // bypassing ShardSpec's validating constructor.
    let oversized_start = vec![0x01; MAX_KEY_SIZE + 1];
    let end = vec![0xFF];
    let spec = ShardSpecRef::new(&oversized_start, &end, &[]);
    let shard = InitialShardInput::new(ShardId::from_raw(0), spec, CursorUpdate::initial());
    assert!(
        validate_manifest(&[shard]).is_err(),
        "validate_manifest should reject specs with keys exceeding MAX_KEY_SIZE",
    );
}

#[test]
fn manifest_rejects_oversized_spec_metadata() {
    use gossip_contracts::coordination::shard_spec::MAX_METADATA_SIZE;

    let oversized_meta = vec![0xAA; MAX_METADATA_SIZE + 1];
    let spec = ShardSpecRef::new(b"a", b"z", &oversized_meta);
    let shard = InitialShardInput::new(ShardId::from_raw(0), spec, CursorUpdate::initial());
    assert!(
        validate_manifest(&[shard]).is_err(),
        "validate_manifest should reject specs with metadata exceeding MAX_METADATA_SIZE",
    );
}

// ============================================================================
// ShardFilter
//
// Predicate-based filtering over shard summaries. Used by list_shards to
// scope queries (all shards, active only, available = active + unleased,
// root-only = no parent).
// ============================================================================

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

// ============================================================================
// Payload hashes
//
// Payload hashes are used for idempotency detection: same op_id + same hash
// = replay, same op_id + different hash = conflict. These tests verify the
// hash functions produce non-zero, distinct, and order-independent values.
// ============================================================================

/// Register-shards hash must be order-independent so that the same set of
/// shards produces the same hash regardless of iteration order.
#[test]
fn hash_register_shards_order_independent() {
    let s1 = make_initial_shard(0, b"a", b"m");
    let s2 = make_initial_shard(1, b"m", b"z");
    let h_forward = hash_register_shards_payload_fixtures(&[s1.clone(), s2.clone()]);
    let h_reverse = hash_register_shards_payload_fixtures(&[s2, s1]);
    assert_eq!(h_forward, h_reverse);
    assert_ne!(h_forward, 0);
}

#[test]
fn hash_register_shards_duplicate_ids_preserve_input_order() {
    let a = make_initial_shard(7, b"a", b"m");
    let b = make_initial_shard(7, b"m", b"z");

    let h_ab = hash_register_shards_payload_fixtures(&[a.clone(), b.clone()]);
    let h_ba = hash_register_shards_payload_fixtures(&[b, a]);
    assert_ne!(
        h_ab, h_ba,
        "equal shard ids keep stable input order in canonical payload"
    );
}

/// The three terminal-op hashes (complete, fail, cancel) must be non-zero
/// and pairwise distinct so that replaying one terminal op cannot be confused
/// with another.
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

// ============================================================================
// INV-11: Kind-result consistency
//
// RunOpLogEntry::new enforces that RegisterShards ops carry a
// RegisteredShards result, and terminal ops carry Ack. Mismatches panic
// at construction, preventing malformed entries from entering the op-log.
// ============================================================================

/// RegisterShards kind paired with Ack result violates INV-11.
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

/// Terminal op kind (CompleteRun) paired with RegisteredShards result violates INV-11.
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

// ============================================================================
// ShardSummary acquire_count saturation
//
// acquire_count is derived from FenceEpoch (u64) but exposed as u32 in the
// summary. Values exceeding u32::MAX must saturate rather than truncate.
// ============================================================================

/// A FenceEpoch exceeding u32::MAX saturates acquire_count to u32::MAX
/// rather than wrapping or truncating, preventing misleading metrics.
#[test]
fn shard_summary_acquire_count_saturates_at_u32_max() {
    use crate::record::ShardRecord;

    let mut slab = ByteSlab::with_capacity(64 * 1024);
    let large_epoch = FenceEpoch::from_raw(u64::from(u32::MAX) + 2);
    let record = ShardRecord::from_raw_parts(
        test_tenant(),
        test_run(),
        ShardId::from_raw(1),
        ShardStatus::Active,
        None,
        &ShardSpec::with_range(b"a", b"z"),
        CursorUpdate::initial(),
        CursorSemantics::Completed,
        None,
        large_epoch,
        None,
        gossip_stdx::InlineVec::new(),
        RingBuffer::new(),
        &mut slab,
    );
    let summary = ShardSummary::from_record(&record, LogicalTime::from_raw(1), &slab);
    assert_eq!(
        summary.acquire_count(),
        u32::MAX,
        "acquire_count must saturate at u32::MAX, not truncate"
    );
    let mut record = record;
    record.deallocate_fields(&mut slab);
}

// ============================================================================
// validate_manifest: inverted spec detection
//
// ShardSpec::with_range rejects inverted ranges at construction, but
// from_raw_parts bypasses the check. validate_manifest must catch inverted
// specs that slip through raw construction.
// ============================================================================

/// An inverted spec (start > end) constructed via `from_raw_parts` is
/// caught by `validate_manifest` as `InvalidSpec`.
#[test]
fn manifest_inverted_spec_detected_by_validate_manifest() {
    let inverted_spec = ShardSpec::from_raw_parts(
        b"z".to_vec().into_boxed_slice(),
        b"a".to_vec().into_boxed_slice(),
        Box::new([]),
    );
    let cursor = CursorUpdate::initial();
    let shard = InitialShardInput::new(ShardId::from_raw(0), inverted_spec.as_ref(), cursor);
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

// ============================================================================
// Exact boundary tests
//
// Tests at the exact limits of capacity constants: MAX_INITIAL_SHARDS for
// manifests, OP_LOG_CAP for op-logs, u32::MAX for progress counters.
// ============================================================================

/// A manifest with exactly MAX_INITIAL_SHARDS succeeds (off-by-one guard).
#[test]
fn manifest_exactly_max_initial_shards_succeeds() {
    let shards: Vec<_> = (0..MAX_INITIAL_SHARDS)
        .map(|i| {
            let start = format!("{:05}", i);
            let end = format!("{:05}", i + 1);
            make_initial_shard(i as u64, start.as_bytes(), end.as_bytes())
        })
        .collect();
    assert!(validate_manifest_fixtures(&shards).is_ok());
}

/// Op-log at exactly OP_LOG_CAP entries passes invariants; one more evicts
/// the oldest without breaking invariants.
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
    use gossip_contracts::test_util::miri_proptest_config;
    use proptest::prelude::*;

    /// Strategy for a valid shard ID (non-zero, bounded).
    fn arb_shard_id() -> impl Strategy<Value = ShardId> {
        (1u64..10_000).prop_map(ShardId::from_raw)
    }

    /// Strategy for a valid InitialShardInput with non-overlapping key range.
    fn arb_initial_shard(idx: usize) -> impl Strategy<Value = InitialShardFixture> {
        arb_shard_id().prop_map(move |id| {
            let start = format!("{:06}", idx);
            let end = format!("{:06}", idx + 1);
            InitialShardFixture {
                shard: id,
                spec: ShardSpec::with_range(start.into_bytes(), end.into_bytes()),
                cursor: CursorUpdate::initial(),
            }
        })
    }

    /// Generate a vec of `n` initial shards with unique, non-overlapping
    /// key ranges (indexed by position).
    fn arb_manifest(max_len: usize) -> impl Strategy<Value = Vec<InitialShardFixture>> {
        (1..=max_len).prop_flat_map(|n| {
            // Generate n unique shard IDs.
            proptest::collection::hash_set(1u64..100_000, n).prop_map(move |ids| {
                ids.into_iter()
                    .enumerate()
                    .map(|(idx, raw)| {
                        let start = format!("{:06}", idx);
                        let end = format!("{:06}", idx + 1);
                        InitialShardFixture {
                            shard: ShardId::from_raw(raw),
                            spec: ShardSpec::with_range(start.into_bytes(), end.into_bytes()),
                            cursor: CursorUpdate::initial(),
                        }
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
            prop_assert!(validate_manifest_fixtures(&shards).is_ok());
        }

        /// Manifests with a duplicate ID always fail.
        #[test]
        fn duplicate_id_always_rejected(base in arb_initial_shard(0)) {
            let dup = InitialShardFixture {
                shard: base.shard,
                spec: ShardSpec::with_range(b"x", b"y"),
                cursor: CursorUpdate::initial(),
            };
            let result = validate_manifest_fixtures(&[base, dup]);
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
            let a = InitialShardFixture {
                shard: ShardId::from_raw(id_a),
                spec: ShardSpec::with_range(b"a", b"n"),
                cursor: CursorUpdate::initial(),
            };
            let b = InitialShardFixture {
                shard: ShardId::from_raw(id_b),
                spec: ShardSpec::with_range(b"m", b"z"),
                cursor: CursorUpdate::initial(),
            };
            let result = validate_manifest_fixtures(&[a, b]);
            prop_assert!(
                matches!(result, Err(ManifestValidationError::OverlappingRanges { .. })),
                "expected OverlappingRanges, got: {result:?}",
            );
        }
    }
}

// ============================================================================
// Unbounded range rejection
//
// Production manifests must have bounded key ranges on both ends. Unbounded
// ranges (empty start or empty end) are rejected before overlap detection.
// ============================================================================

/// Unbounded end (`[a, inf)`) is rejected as `UnboundedRange`, not as overlap.
#[test]
fn manifest_detects_overlap_with_unbounded_end() {
    // Unbounded end is now rejected before overlap detection.
    let spec_a = ShardSpec::from_raw_parts(
        b"a".to_vec().into_boxed_slice(),
        Box::new([]), // unbounded end = [a, ∞)
        Box::new([]),
    );
    let cursor_a = CursorUpdate::initial();
    let shard_a = InitialShardInput::new(ShardId::from_raw(0), spec_a.as_ref(), cursor_a);
    let shard_b = make_initial_shard(1, b"m", b"z");
    let shard_b_input = shard_b.as_input();
    let result = validate_manifest(&[shard_a, shard_b_input]);
    assert!(
        matches!(result, Err(ManifestValidationError::UnboundedRange { .. })),
        "unbounded end must be rejected: {result:?}"
    );
}

#[test]
fn manifest_detects_overlap_with_both_starts_empty() {
    // Unbounded start is now rejected before overlap detection.
    let spec_a = ShardSpec::from_raw_parts(
        Box::new([]), // unbounded start
        b"m".to_vec().into_boxed_slice(),
        Box::new([]),
    );
    let spec_b = ShardSpec::from_raw_parts(
        Box::new([]), // unbounded start
        b"z".to_vec().into_boxed_slice(),
        Box::new([]),
    );
    let cursor_a = CursorUpdate::initial();
    let cursor_b = CursorUpdate::initial();
    let shard_a = InitialShardInput::new(ShardId::from_raw(0), spec_a.as_ref(), cursor_a);
    let shard_b = InitialShardInput::new(ShardId::from_raw(1), spec_b.as_ref(), cursor_b);
    let result = validate_manifest(&[shard_a, shard_b]);
    assert!(
        matches!(result, Err(ManifestValidationError::UnboundedRange { .. })),
        "unbounded start must be rejected: {result:?}"
    );
}

#[test]
fn manifest_unbounded_start_rejected() {
    // Unbounded start is no longer accepted in production manifests.
    let spec_a = ShardSpec::from_raw_parts(
        Box::new([]), // unbounded start
        b"m".to_vec().into_boxed_slice(),
        Box::new([]),
    );
    let cursor_a = CursorUpdate::initial();
    let shard_a = InitialShardInput::new(ShardId::from_raw(0), spec_a.as_ref(), cursor_a);
    let shard_b = make_initial_shard(1, b"m", b"z");
    let shard_b_input = shard_b.as_input();
    let result = validate_manifest(&[shard_a, shard_b_input]);
    assert!(
        matches!(result, Err(ManifestValidationError::UnboundedRange { .. })),
        "unbounded start must be rejected: {result:?}"
    );
}

#[test]
fn manifest_unbounded_end_rejected() {
    let spec =
        ShardSpec::from_raw_parts(b"a".to_vec().into_boxed_slice(), Box::new([]), Box::new([]));
    let cursor = CursorUpdate::initial();
    let shard = InitialShardInput::new(ShardId::from_raw(0), spec.as_ref(), cursor);
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
    let spec = ShardSpec::unbounded();
    let cursor = CursorUpdate::initial();
    let shard = InitialShardInput::new(ShardId::from_raw(0), spec.as_ref(), cursor);
    assert!(
        matches!(
            validate_manifest(&[shard]),
            Err(ManifestValidationError::UnboundedRange { .. })
        ),
        "fully unbounded shard must be rejected"
    );
}
