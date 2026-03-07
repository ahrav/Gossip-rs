//! Tests for the etcd coordination backend.
//!
//! These cover three layers:
//! - config validation (pure, deterministic)
//! - keyspace path construction
//! - v1 record codec round-trips and malformed blob rejection

use std::env;

use crate::{
    BlobKind, EtcdCodecError, EtcdCoordinator, EtcdCoordinatorConfig, EtcdCoordinatorConfigError,
    EtcdCoordinatorError, EtcdKeyspace, EtcdKeyspaceError, EtcdOperation, decode_run_record_v1,
    decode_shard_record_v1, encode_run_record_v1, encode_shard_record_v1,
};
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

#[test]
fn config_rejects_empty_endpoint_list() {
    let error = EtcdCoordinatorConfig::new(Vec::<String>::new(), "/gossip/v1")
        .expect_err("empty endpoints must fail validation");
    assert!(matches!(error, EtcdCoordinatorConfigError::NoEndpoints));
}

#[test]
fn config_rejects_empty_endpoint_after_trimming() {
    let error = EtcdCoordinatorConfig::new(["   "], "/gossip/v1")
        .expect_err("blank endpoints must fail validation");
    assert!(matches!(
        error,
        EtcdCoordinatorConfigError::EmptyEndpoint { index: 0 }
    ));
}

#[test]
fn config_rejects_empty_namespace_prefix() {
    let error = EtcdCoordinatorConfig::new(["http://127.0.0.1:2379"], "   ")
        .expect_err("blank namespace prefix must fail validation");
    assert!(matches!(
        error,
        EtcdCoordinatorConfigError::EmptyNamespacePrefix
    ));
}

#[test]
fn config_rejects_invalid_namespace_prefix() {
    let error = EtcdCoordinatorConfig::new(["http://127.0.0.1:2379"], "gossip/v1")
        .expect_err("namespace prefix without leading slash must fail");
    assert!(matches!(
        error,
        EtcdCoordinatorConfigError::NamespacePrefixMustStartWithSlash
    ));
}

#[test]
fn config_rejects_namespace_prefix_with_trailing_slash() {
    let error = EtcdCoordinatorConfig::new(["http://127.0.0.1:2379"], "/gossip/v1/")
        .expect_err("namespace prefix with trailing slash must fail");
    assert!(matches!(
        error,
        EtcdCoordinatorConfigError::NamespacePrefixMustNotEndWithSlash
    ));
}

#[test]
fn localhost_config_uses_expected_defaults() {
    let config = EtcdCoordinatorConfig::localhost();
    assert_eq!(config.endpoints(), ["http://127.0.0.1:2379"]);
    assert_eq!(config.namespace_prefix(), "/gossip/v1");
}

#[test]
fn from_endpoints_csv_trims_and_filters_empty_items() {
    let config = EtcdCoordinatorConfig::from_endpoints_csv(
        " http://127.0.0.1:2379, ,http://127.0.0.1:32379 ",
        "/gossip/v1",
    )
    .expect("csv endpoints should parse");

    assert_eq!(
        config.endpoints(),
        ["http://127.0.0.1:2379", "http://127.0.0.1:32379"]
    );
}

#[test]
fn from_endpoints_csv_with_all_empty_segments_returns_no_endpoints() {
    for input in [",", ",,,", "  ,  ,  "] {
        let error = EtcdCoordinatorConfig::from_endpoints_csv(input, "/gossip/v1").expect_err(
            &format!("all-empty segments '{input}' must fail validation"),
        );
        assert!(
            matches!(error, EtcdCoordinatorConfigError::NoEndpoints),
            "expected NoEndpoints for input '{input}', got {error:?}"
        );
    }
}

#[test]
fn from_endpoints_csv_drops_trailing_empty_segments() {
    let config = EtcdCoordinatorConfig::from_endpoints_csv("http://a:2379,,", "/gossip/v1")
        .expect("trailing empty segments should be silently dropped");
    assert_eq!(config.endpoints(), ["http://a:2379"]);
}

#[test]
fn config_accepts_root_namespace_slash() {
    let config = EtcdCoordinatorConfig::new(["http://127.0.0.1:2379"], "/")
        .expect("root namespace '/' should be accepted");
    assert_eq!(config.namespace_prefix(), "/");
}

#[test]
fn config_rejects_endpoint_without_http_scheme() {
    let error = EtcdCoordinatorConfig::new(["etcd-0:2379"], "/gossip/v1")
        .expect_err("endpoint without http:// or https:// must fail");
    assert!(matches!(
        error,
        EtcdCoordinatorConfigError::InvalidEndpointScheme { index: 0 }
    ));
}

#[test]
fn config_rejects_endpoint_with_ftp_scheme() {
    let error = EtcdCoordinatorConfig::new(["ftp://etcd-0:2379"], "/gossip/v1")
        .expect_err("endpoint with ftp:// scheme must fail");
    assert!(matches!(
        error,
        EtcdCoordinatorConfigError::InvalidEndpointScheme { index: 0 }
    ));
}

#[test]
fn config_accepts_https_endpoint() {
    let config = EtcdCoordinatorConfig::new(["https://etcd-0:2379"], "/gossip/v1")
        .expect("https:// endpoint should be accepted");
    assert_eq!(config.endpoints(), ["https://etcd-0:2379"]);
}

#[test]
fn config_rejects_second_endpoint_with_bad_scheme() {
    let error = EtcdCoordinatorConfig::new(["http://etcd-0:2379", "etcd-1:2379"], "/gossip/v1")
        .expect_err("second endpoint without scheme must fail");
    assert!(matches!(
        error,
        EtcdCoordinatorConfigError::InvalidEndpointScheme { index: 1 }
    ));
}

#[test]
fn etcd_operation_display_connect() {
    assert_eq!(EtcdOperation::Connect.to_string(), "connect");
}

#[test]
fn etcd_operation_display_status() {
    assert_eq!(EtcdOperation::Status.to_string(), "status");
}

#[test]
fn coordinator_error_display_wraps_config_error() {
    let inner = EtcdCoordinatorConfigError::NoEndpoints;
    let outer = EtcdCoordinatorError::Config(inner);
    assert!(
        outer
            .to_string()
            .contains("invalid etcd coordinator config"),
        "display should wrap the config error message"
    );
}

#[test]
fn coordinator_error_config_source_returns_inner() {
    use std::error::Error;

    let inner = EtcdCoordinatorConfigError::NoEndpoints;
    let outer = EtcdCoordinatorError::Config(inner);
    let source = outer.source().expect("Config variant must have a source");
    assert!(
        source
            .downcast_ref::<EtcdCoordinatorConfigError>()
            .is_some(),
        "source should downcast to EtcdCoordinatorConfigError"
    );
}

#[test]
fn coordinator_error_runtime_source_returns_inner() {
    use std::error::Error;

    let io_err = std::io::Error::other("test");
    let outer = EtcdCoordinatorError::RuntimeBuild(io_err);
    let source = outer
        .source()
        .expect("RuntimeBuild variant must have a source");
    assert!(
        source.downcast_ref::<std::io::Error>().is_some(),
        "source should downcast to io::Error"
    );
}

#[test]
fn config_error_converts_to_coordinator_error_via_from() {
    let config_err = EtcdCoordinatorConfigError::NoEndpoints;
    let coord_err: EtcdCoordinatorError = config_err.into();
    assert!(matches!(coord_err, EtcdCoordinatorError::Config(_)));
}

#[test]
fn keyspace_builds_expected_paths() {
    let tenant = TenantId::from_bytes([0xAB; 32]);
    let run = RunId::from_raw(0x0123_4567_89ab_cdef);
    let shard = ShardId::from_raw(0x8000_0000_0000_0042);

    let keyspace = EtcdKeyspace::new("/gossip/v1").expect("valid keyspace prefix");
    assert_eq!(
        keyspace.run_record_key(tenant, run),
        "/gossip/v1/tenants/abababababababababababababababababababababababababababababababab/runs/0123456789abcdef"
    );
    assert_eq!(
        keyspace.shard_record_key(tenant, run, shard),
        "/gossip/v1/tenants/abababababababababababababababababababababababababababababababab/runs/0123456789abcdef/shards/8000000000000042"
    );
    assert_eq!(
        keyspace.shard_owner_key(tenant, run, shard),
        "/gossip/v1/tenants/abababababababababababababababababababababababababababababababab/runs/0123456789abcdef/shards/8000000000000042/owner"
    );
    assert_eq!(
        keyspace.run_active_index_key(tenant, run),
        "/gossip/v1/tenants/abababababababababababababababababababababababababababababababab/runs_active/0123456789abcdef"
    );
    assert_eq!(
        keyspace.active_shard_index_key(tenant, run, shard),
        "/gossip/v1/tenants/abababababababababababababababababababababababababababababababab/runs/0123456789abcdef/shards_active/8000000000000042"
    );
    assert_eq!(
        keyspace.shard_records_scan_prefix(tenant, run),
        "/gossip/v1/tenants/abababababababababababababababababababababababababababababababab/runs/0123456789abcdef/shards/"
    );
}

#[test]
fn keyspace_root_prefix_does_not_emit_double_slashes() {
    let tenant = TenantId::from_bytes([0x11; 32]);
    let run = RunId::from_raw(0x42);
    let keyspace = EtcdKeyspace::new("/").expect("root prefix should be valid");

    assert_eq!(
        keyspace.run_record_key(tenant, run),
        "/tenants/1111111111111111111111111111111111111111111111111111111111111111/runs/0000000000000042"
    );
    assert_eq!(keyspace.tenants_prefix(), "/tenants");
}

// ---------------------------------------------------------------------------
// Keyspace prefix validation (rstest)
// ---------------------------------------------------------------------------

#[rstest]
#[case::normal("/gossip/v1", Ok(()))]
#[case::root("/", Ok(()))]
#[case::single_segment("/a", Ok(()))]
#[case::deep_nesting("/a/b/c/d", Ok(()))]
#[case::trimmed_whitespace("  /gossip  ", Ok(()))]
#[case::empty("", Err(EtcdKeyspaceError::EmptyPrefix))]
#[case::whitespace_only("   ", Err(EtcdKeyspaceError::EmptyPrefix))]
#[case::no_leading_slash("gossip/v1", Err(EtcdKeyspaceError::PrefixMustStartWithSlash))]
#[case::trailing_slash("/gossip/", Err(EtcdKeyspaceError::PrefixMustNotEndWithSlash))]
#[case::trailing_slash_deep("/a/b/c/", Err(EtcdKeyspaceError::PrefixMustNotEndWithSlash))]
fn keyspace_prefix_validation(
    #[case] input: &str,
    #[case] expected: Result<(), EtcdKeyspaceError>,
) {
    let result = EtcdKeyspace::new(input).map(|_| ());
    assert_eq!(result, expected);
}

/// Whitespace-trimmed prefix stores the trimmed value, not the raw input.
#[test]
fn keyspace_trims_whitespace_and_stores_clean_prefix() {
    let ks = EtcdKeyspace::new("  /gossip/v1  ").unwrap();
    assert_eq!(ks.prefix(), "/gossip/v1");
}

// ---------------------------------------------------------------------------
// Keyspace structural invariants (proptest)
// ---------------------------------------------------------------------------

proptest! {
    /// Every generated key starts with the configured prefix, contains no
    /// double slashes, is pure ASCII, and respects the hierarchical
    /// containment relationships between parent prefixes and child keys.
    #[test]
    fn keyspace_structural_invariants(
        // Generate valid prefixes: `/` followed by 1-3 path segments.
        prefix in "/[a-z]{1,8}(/[a-z]{1,8}){0,3}",
        tenant_bytes in proptest::array::uniform32(any::<u8>()),
        run_raw in any::<u64>(),
        shard_raw in any::<u64>(),
    ) {
        let ks = EtcdKeyspace::new(&prefix).unwrap();
        let tenant = TenantId::from_bytes(tenant_bytes);
        let run = RunId::from_raw(run_raw);
        let shard = ShardId::from_raw(shard_raw);

        // -- Prefix containment --
        let tenants = ks.tenants_prefix();
        let tenant_pfx = ks.tenant_prefix(tenant);
        let runs = ks.runs_prefix(tenant);
        let run_key = ks.run_record_key(tenant, run);
        let shards_pfx = ks.run_shards_prefix(tenant, run);
        let scan_pfx = ks.shard_records_scan_prefix(tenant, run);
        let shard_key = ks.shard_record_key(tenant, run, shard);
        let owner_key = ks.shard_owner_key(tenant, run, shard);
        let runs_active = ks.runs_active_prefix(tenant);
        let run_active = ks.run_active_index_key(tenant, run);
        let shards_active = ks.shards_active_prefix(tenant, run);
        let shard_active = ks.active_shard_index_key(tenant, run, shard);

        let all_keys = [
            &tenants, &tenant_pfx, &runs, &run_key, &shards_pfx, &scan_pfx,
            &shard_key, &owner_key, &runs_active, &run_active,
            &shards_active, &shard_active,
        ];

        for key in &all_keys {
            // Every key starts with the configured prefix.
            prop_assert!(
                key.starts_with(&prefix),
                "key {key:?} must start with prefix {prefix:?}"
            );
            // No double slashes.
            prop_assert!(
                !key.contains("//"),
                "key {key:?} contains double slash"
            );
            // All output is ASCII.
            prop_assert!(key.is_ascii(), "key {key:?} is not ASCII");
        }

        // Hierarchical containment: each child starts with its parent.
        prop_assert!(tenant_pfx.starts_with(&tenants));
        prop_assert!(runs.starts_with(&tenant_pfx));
        prop_assert!(run_key.starts_with(&runs));
        prop_assert!(shards_pfx.starts_with(&run_key));
        prop_assert!(shard_key.starts_with(&shards_pfx));
        prop_assert!(owner_key.starts_with(&shard_key));
        prop_assert!(owner_key.ends_with("/owner"));

        // Scan prefix ends with trailing slash.
        prop_assert!(scan_pfx.ends_with('/'));
        prop_assert!(scan_pfx.starts_with(&shards_pfx));

        // Active-index keys live under tenant, not under runs/.
        prop_assert!(runs_active.starts_with(&tenant_pfx));
        prop_assert!(run_active.starts_with(&runs_active));
        prop_assert!(runs_active.contains("/runs_active"));

        // Active-shard index keys are siblings of shards/, not children.
        prop_assert!(shards_active.starts_with(&run_key));
        prop_assert!(shard_active.starts_with(&shards_active));
        prop_assert!(shards_active.contains("/shards_active"));

        // Scan isolation: shard_records_scan_prefix must NOT match
        // shards_active keys (the trailing slash prevents this).
        prop_assert!(!shard_active.starts_with(&scan_pfx));

        // Hex encoding: tenant segment is 64 hex chars, run/shard are 16.
        let tenant_segment = tenant_pfx
            .strip_prefix(&format!("{}/", tenants))
            .unwrap_or("");
        prop_assert_eq!(tenant_segment.len(), 64);
        prop_assert!(tenant_segment.chars().all(|c| c.is_ascii_hexdigit()));

        let run_segment = run_key
            .strip_prefix(&format!("{}/", runs))
            .unwrap_or("");
        prop_assert_eq!(run_segment.len(), 16);
        prop_assert!(run_segment.chars().all(|c| c.is_ascii_hexdigit()));

        let shard_segment = shard_key
            .strip_prefix(&format!("{}/", shards_pfx))
            .unwrap_or("");
        prop_assert_eq!(shard_segment.len(), 16);
        prop_assert!(shard_segment.chars().all(|c| c.is_ascii_hexdigit()));
    }
}

#[test]
fn run_record_v1_round_trips_all_statuses_and_semantics() {
    let statuses = [
        RunStatus::Initializing,
        RunStatus::Active,
        RunStatus::Done,
        RunStatus::Failed,
        RunStatus::Cancelled,
    ];
    let semantics = [CursorSemantics::Completed, CursorSemantics::Dispatched];

    for status in statuses {
        for cursor_semantics in semantics {
            let record = sample_run_record(status, cursor_semantics);
            let encoded = encode_run_record_v1(&record);
            let decoded = decode_run_record_v1(&encoded).expect("run record should decode");
            let reencoded = encode_run_record_v1(&decoded);

            assert_eq!(
                decoded, record,
                "round-trip mismatch for {status:?}/{cursor_semantics:?}"
            );
            assert_eq!(
                reencoded, encoded,
                "re-encode mismatch for {status:?}/{cursor_semantics:?}"
            );
        }
    }
}

#[test]
fn shard_record_v1_round_trips_active_semantics_variants() {
    for semantics in [CursorSemantics::Completed, CursorSemantics::Dispatched] {
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
}

#[test]
fn shard_record_v1_round_trips_terminal_variants_and_park_reasons() {
    let (mut done_record, mut done_slab) = sample_done_shard_record();
    let done_encoded = encode_shard_record_v1(&done_record, &done_slab);
    let mut done_decode_slab = ByteSlab::with_capacity(4096);
    let mut done_decoded = decode_shard_record_v1(&done_encoded, &mut done_decode_slab)
        .expect("done record should decode");
    assert_shard_record_eq(&done_record, &done_slab, &done_decoded, &done_decode_slab);
    release_shard_record(&mut done_record, &mut done_slab);
    release_shard_record(&mut done_decoded, &mut done_decode_slab);

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

    for park_reason in [
        ParkReason::PermissionDenied,
        ParkReason::NotFound,
        ParkReason::Poisoned,
        ParkReason::TooManyErrors,
        ParkReason::Other,
    ] {
        let (mut record, mut slab) = sample_parked_shard_record(park_reason);
        let encoded = encode_shard_record_v1(&record, &slab);

        let mut decode_slab = ByteSlab::with_capacity(4096);
        let mut decoded = decode_shard_record_v1(&encoded, &mut decode_slab)
            .expect("parked record should decode");
        let reencoded = encode_shard_record_v1(&decoded, &decode_slab);

        assert_shard_record_eq(&record, &slab, &decoded, &decode_slab);
        assert_eq!(reencoded, encoded);

        release_shard_record(&mut record, &mut slab);
        release_shard_record(&mut decoded, &mut decode_slab);
    }
}

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

#[test]
#[ignore = "requires a local etcd on ETCD_ENDPOINTS or localhost:2379"]
fn connects_to_local_etcd_and_fetches_status() {
    let endpoints = env::var("ETCD_ENDPOINTS")
        .ok()
        .and_then(|raw| {
            let trimmed = raw.trim().to_owned();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        })
        .unwrap_or_else(|| "http://127.0.0.1:2379".to_owned());

    let config = EtcdCoordinatorConfig::from_endpoints_csv(&endpoints, "/gossip/v1")
        .expect("test endpoint configuration should be valid");

    let backend = EtcdCoordinator::connect(config).expect("local etcd should be reachable");
    let status = backend.status().expect("status call should succeed");

    assert!(
        !status.version().is_empty(),
        "connected member should report a version"
    );
}

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
