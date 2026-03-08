//! Tests for the etcd coordination backend.
//!
//! ## Test layers
//!
//! Tests are organized in three tiers of increasing infrastructure
//! requirements:
//!
//! 1. **Config validation** — pure, deterministic unit tests that verify
//!    `EtcdCoordinatorConfig` rejects invalid parameters and accepts valid
//!    ones. No network, no etcd. Includes credential redaction tests for
//!    the custom `Debug` impl.
//!
//! 2. **Keyspace path construction** — deterministic tests that verify
//!    `EtcdKeyspace` produces correct, collision-free etcd key paths.
//!    Includes proptest-based structural invariant checks (prefix
//!    containment, scan isolation, fixed-width hex encoding).
//!
//! 3. **etcd integration** — round-trip tests that connect to a local
//!    etcd cluster. These are marked `#[ignore]` and require either a
//!    running etcd at `http://127.0.0.1:2379` or the `ETCD_ENDPOINTS`
//!    environment variable pointing to a reachable cluster. They cover
//!    the full acquire/checkpoint/renew/split lifecycle including
//!    idempotent replay, lease expiry, and concurrent acquire contention.
//!
//! ## Running integration tests
//!
//! ```bash
//! # Start a local etcd (e.g., via Docker):
//! docker run --rm -p 2379:2379 quay.io/coreos/etcd:v3.5.21 \
//!   /usr/local/bin/etcd --advertise-client-urls http://0.0.0.0:2379 \
//!   --listen-client-urls http://0.0.0.0:2379
//!
//! # Run all etcd integration tests:
//! cargo test -p gossip-coordination-etcd -- --ignored
//!
//! # Or point to a custom cluster:
//! ETCD_ENDPOINTS="http://10.0.0.1:2379,http://10.0.0.2:2379" \
//!   cargo test -p gossip-coordination-etcd -- --ignored
//! ```

use std::env;

use crate::{
    EtcdCoordinator, EtcdCoordinatorConfig, EtcdCoordinatorConfigError, EtcdCoordinatorError,
    EtcdKeyspace, EtcdKeyspaceError, EtcdOperation,
};
use gossip_contracts::coordination::{
    CursorSemantics, CursorUpdate, ShardSpec, ShardSpecRef, SplitReplaceChild, SplitReplacePlan,
    SplitResidualPlan,
};
use gossip_contracts::identity::{LogicalTime, OpId, RunId, ShardId, ShardKey, TenantId, WorkerId};
use gossip_coordination::{
    AcquireError, AcquireScratch, CheckpointError, CoordinationBackend, IdempotentOutcome,
    InitialShardInput, RegisterShardsError, RunConfig, RunManagement, ShardStatus,
};
use proptest::prelude::*;
use rstest::rstest;

// ---------------------------------------------------------------------------
// Config validation (pure, no etcd required)
// ---------------------------------------------------------------------------

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
    assert_eq!(config.owner_lease_ttl_secs(), 60);
    assert_eq!(config.optimistic_txn_retries(), 8);
    assert_eq!(config.max_children_per_op(), 8);
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
fn config_accepts_explicit_tuning_values() {
    let config =
        EtcdCoordinatorConfig::new_with_tuning(["http://127.0.0.1:2379"], "/gossip/v1", 90, 16, 12)
            .expect("explicit tuning should pass validation");
    assert_eq!(config.owner_lease_ttl_secs(), 90);
    assert_eq!(config.optimistic_txn_retries(), 16);
    assert_eq!(config.max_children_per_op(), 12);
}

#[test]
fn config_rejects_non_positive_owner_lease_ttl() {
    let error =
        EtcdCoordinatorConfig::new_with_tuning(["http://127.0.0.1:2379"], "/gossip/v1", 0, 8, 8)
            .expect_err("non-positive owner lease ttl must fail validation");
    assert!(matches!(
        error,
        EtcdCoordinatorConfigError::NonPositiveOwnerLeaseTtl
    ));
}

#[test]
fn config_rejects_zero_optimistic_txn_retries() {
    let error =
        EtcdCoordinatorConfig::new_with_tuning(["http://127.0.0.1:2379"], "/gossip/v1", 60, 0, 8)
            .expect_err("zero retry budget must fail validation");
    assert!(matches!(
        error,
        EtcdCoordinatorConfigError::ZeroOptimisticTxnRetries
    ));
}

#[test]
fn config_rejects_zero_max_children_per_op() {
    let error =
        EtcdCoordinatorConfig::new_with_tuning(["http://127.0.0.1:2379"], "/gossip/v1", 60, 8, 0)
            .expect_err("zero max_children_per_op must fail validation");
    assert!(matches!(
        error,
        EtcdCoordinatorConfigError::ZeroMaxChildrenPerOp
    ));
}

#[test]
fn config_rejects_max_children_per_op_above_global_limit() {
    let error =
        EtcdCoordinatorConfig::new_with_tuning(["http://127.0.0.1:2379"], "/gossip/v1", 60, 8, 257)
            .expect_err("max_children_per_op above MAX_SPLIT_CHILDREN must fail validation");
    assert!(matches!(
        error,
        EtcdCoordinatorConfigError::MaxChildrenPerOpExceedsGlobalLimit {
            requested: 257,
            global_max: 256,
        }
    ));
}

// ---------------------------------------------------------------------------
// Debug output tests
// ---------------------------------------------------------------------------

#[test]
fn config_debug_does_not_expose_raw_endpoint_credentials() {
    // Endpoints with embedded credentials pass validation (only scheme is checked).
    // Debug output must not leak the full URI including user:pass.
    let config = EtcdCoordinatorConfig::new(["http://admin:secret@etcd-0:2379"], "/gossip/v1")
        .expect("endpoint with userinfo should pass scheme-only validation");

    let debug_output = format!("{config:?}");
    assert!(
        !debug_output.contains("secret"),
        "Debug output must not contain credentials, got: {debug_output}"
    );
    assert!(
        debug_output.contains("***@etcd-0:2379"),
        "Debug output should show redacted host, got: {debug_output}"
    );
}

#[test]
fn config_debug_shows_endpoints_without_credentials_normally() {
    let config = EtcdCoordinatorConfig::new(["http://etcd-0:2379"], "/gossip/v1")
        .expect("plain endpoint should pass validation");

    let debug_output = format!("{config:?}");
    assert!(
        debug_output.contains("http://etcd-0:2379"),
        "Debug output should show plain endpoints unchanged, got: {debug_output}"
    );
}

#[test]
fn config_debug_redacts_auth_password() {
    let config = EtcdCoordinatorConfig::new(["http://etcd-0:2379"], "/gossip/v1")
        .expect("valid config")
        .with_auth("admin", "super_secret_pass");

    let debug_output = format!("{config:?}");
    assert!(
        debug_output.contains("admin"),
        "Debug output should show auth username, got: {debug_output}"
    );
    assert!(
        !debug_output.contains("super_secret_pass"),
        "Debug output must not contain auth password, got: {debug_output}"
    );
    assert!(
        debug_output.contains("[REDACTED]"),
        "Debug output should show [REDACTED] for password, got: {debug_output}"
    );
}

#[test]
fn config_with_auth_exposes_credentials_via_accessor() {
    let config = EtcdCoordinatorConfig::new(["http://etcd-0:2379"], "/gossip/v1")
        .expect("valid config")
        .with_auth("admin", "password123");

    let (user, pass) = config.auth().expect("auth should be set");
    assert_eq!(user, "admin");
    assert_eq!(pass, "password123");
}

#[test]
fn config_without_auth_returns_none() {
    let config =
        EtcdCoordinatorConfig::new(["http://etcd-0:2379"], "/gossip/v1").expect("valid config");

    assert!(config.auth().is_none());
}

// ---------------------------------------------------------------------------
// URL scheme validation tests
// ---------------------------------------------------------------------------

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
fn etcd_operation_display_lease_grant() {
    assert_eq!(EtcdOperation::LeaseGrant.to_string(), "lease_grant");
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

// ---------------------------------------------------------------------------
// Keyspace path construction (pure, no etcd required)
// ---------------------------------------------------------------------------

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
        keyspace.shard_active_index_key(tenant, run, shard),
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
#[case::double_slash("/gossip//v1", Err(EtcdKeyspaceError::PrefixContainsDoubleSlash))]
#[case::double_slash_deep("/a//b/c", Err(EtcdKeyspaceError::PrefixContainsDoubleSlash))]
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
        let shard_active = ks.shard_active_index_key(tenant, run, shard);

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

        // Scan isolation: run_records_scan_prefix must NOT match
        // runs_active keys (the trailing slash prevents this).
        let run_scan_pfx = ks.run_records_scan_prefix(tenant);
        prop_assert!(run_scan_pfx.ends_with('/'));
        prop_assert!(!run_active.starts_with(&run_scan_pfx));

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

/// Verify: `EtcdKeyspace::new` accepts prefixes with interior double-slashes.
///
/// If this test passes (construction succeeds), the double-slash rejection
/// is missing.
#[test]
fn keyspace_rejects_interior_double_slashes() {
    let result = EtcdKeyspace::new("/gossip//v1");
    assert!(
        result.is_err(),
        "prefix with interior double-slash must be rejected, but was accepted"
    );
}

/// Verify: `run_records_scan_prefix` isolates run records from `runs_active`.
///
/// The scan prefix must end with `/` so an etcd byte-prefix scan does not
/// accidentally match `runs_active/` sibling keys.
#[test]
fn run_records_scan_prefix_is_scan_safe() {
    let ks = EtcdKeyspace::new("/gossip/v1").unwrap();
    let tenant = TenantId::from_bytes([0xCC; 32]);

    let scan_prefix = ks.run_records_scan_prefix(tenant);
    let runs_active = ks.runs_active_prefix(tenant);

    assert!(
        scan_prefix.ends_with('/'),
        "run_records_scan_prefix must end with trailing slash"
    );
    assert!(
        !runs_active.starts_with(&scan_prefix),
        "runs_active ({runs_active}) must not be matched by run_records_scan_prefix ({scan_prefix})"
    );
}

// ---------------------------------------------------------------------------
// etcd integration tests (require running etcd, #[ignore])
// ---------------------------------------------------------------------------

#[test]
#[ignore = "requires a local etcd on ETCD_ENDPOINTS or localhost:2379"]
fn register_shards_rejects_batch_exceeding_etcd_txn_limit() {
    let mut backend = local_backend("/gossip/tests/register-batch-limit");
    backend
        .test_clear_namespace()
        .expect("namespace cleanup should succeed");

    let config = RunConfig::try_new(CursorSemantics::Completed, 30, Some(5)).unwrap();
    backend
        .create_run(now(1), test_tenant(), test_run(), config)
        .expect("create_run should succeed");

    // 42 shards exceed the MAX_SHARDS_PER_ETCD_TXN limit of 41.
    let ranges: Vec<(String, String)> = (0..42u64)
        .map(|i| (format!("{i:04}"), format!("{:04}", i + 1)))
        .collect();
    let shards: Vec<InitialShardInput<'_>> = ranges
        .iter()
        .enumerate()
        .map(|(i, (start, end))| {
            InitialShardInput::new(
                ShardId::from_raw(i as u64 + 1),
                ShardSpecRef::new(start.as_bytes(), end.as_bytes(), b""),
                CursorUpdate::initial(),
            )
        })
        .collect();

    let err = backend
        .register_shards(
            now(2),
            test_tenant(),
            test_run(),
            &shards,
            OpId::from_raw(99),
        )
        .expect_err("42 shards must exceed etcd txn op limit");

    assert!(
        matches!(
            err,
            RegisterShardsError::ResourceExhausted {
                resource: "etcd_txn_ops"
            }
        ),
        "expected ResourceExhausted(etcd_txn_ops), got {err:?}"
    );
}

#[test]
#[ignore = "requires a local etcd on ETCD_ENDPOINTS or localhost:2379"]
fn connects_to_local_etcd_and_fetches_status() {
    let backend = local_backend("/gossip/tests/status");
    let status = backend.status().expect("status call should succeed");

    assert!(
        !status.version().is_empty(),
        "connected member should report a version"
    );
}

#[test]
#[ignore = "requires a local etcd on ETCD_ENDPOINTS or localhost:2379"]
fn acquire_checkpoint_and_renew_round_trip_against_local_etcd() {
    let mut backend = local_backend("/gossip/tests/acquire-checkpoint-renew");
    backend
        .test_clear_namespace()
        .expect("namespace cleanup should succeed");

    let config = RunConfig::try_new(CursorSemantics::Completed, 30, Some(5)).unwrap();
    backend
        .create_run(now(1), test_tenant(), test_run(), config)
        .expect("create_run should succeed");

    let manifest = [InitialShardInput::new(
        test_shard(),
        ShardSpecRef::new(b"a", b"z", b""),
        CursorUpdate::initial(),
    )];
    let reg = backend
        .register_shards(
            now(2),
            test_tenant(),
            test_run(),
            &manifest,
            OpId::from_raw(99),
        )
        .expect("register_shards should succeed");
    assert!(matches!(reg, IdempotentOutcome::Executed(_)));

    let key = ShardKey::new(test_run(), test_shard());
    let mut scratch = AcquireScratch::new();
    let acquire = backend
        .acquire_and_restore_into(now(3), test_tenant(), key, test_worker(7), &mut scratch)
        .expect("acquire should succeed");
    let owner = backend
        .test_load_owner_binding(test_tenant(), key)
        .expect("owner lookup should succeed")
        .expect("owner key must exist after acquire");
    assert_eq!(owner.0, test_worker(7));
    assert_eq!(owner.1, acquire.lease.fence());
    assert!(
        owner.2 > 0,
        "owner key must be attached to a real etcd lease"
    );

    let outcome = backend
        .checkpoint(
            now(4),
            test_tenant(),
            &acquire.lease,
            &CursorUpdate::new(b"m"),
            OpId::from_raw(100),
        )
        .expect("checkpoint should succeed");
    assert!(matches!(outcome, IdempotentOutcome::Executed(())));

    let (shard, slab) = backend
        .test_load_shard_snapshot(test_tenant(), key)
        .expect("shard lookup should succeed")
        .expect("shard must exist");
    assert_eq!(shard.cursor.last_key(&slab), Some(b"m".as_slice()));

    let renew = backend
        .renew(now(5), test_tenant(), &acquire.lease)
        .expect("renew should succeed");
    assert!(
        renew.new_deadline > acquire.lease.deadline(),
        "renew must extend the logical lease deadline"
    );

    let owner_after = backend
        .test_load_owner_binding(test_tenant(), key)
        .expect("owner lookup should succeed")
        .expect("owner key must still exist after renew");
    assert_eq!(owner_after.0, test_worker(7));
    assert_eq!(
        owner_after.1,
        acquire.lease.fence(),
        "renew must not change the fence epoch"
    );
}

#[test]
#[ignore = "requires a local etcd on ETCD_ENDPOINTS or localhost:2379"]
fn split_replace_round_trip_against_local_etcd() {
    let mut backend = local_backend("/gossip/tests/split-replace");
    backend
        .test_clear_namespace()
        .expect("namespace cleanup should succeed");

    let config = RunConfig::try_new(CursorSemantics::Completed, 30, Some(5)).unwrap();
    backend
        .create_run(now(1), test_tenant(), test_run(), config)
        .expect("create_run should succeed");

    let manifest = [InitialShardInput::new(
        test_shard(),
        ShardSpecRef::new(b"a", b"z", b""),
        CursorUpdate::initial(),
    )];
    let register = backend
        .register_shards(
            now(2),
            test_tenant(),
            test_run(),
            &manifest,
            OpId::from_raw(99),
        )
        .expect("register_shards should succeed");
    assert!(register.is_executed());

    let key = ShardKey::new(test_run(), test_shard());
    let mut scratch = AcquireScratch::new();
    let acquire = backend
        .acquire_and_restore_into(now(3), test_tenant(), key, test_worker(7), &mut scratch)
        .expect("acquire should succeed");

    let left = ShardSpec::with_range(b"a", b"m");
    let right = ShardSpec::with_range(b"m", b"z");
    let plan = SplitReplacePlan::try_new(vec![
        SplitReplaceChild::new(left.as_ref(), CursorUpdate::initial()),
        SplitReplaceChild::new(right.as_ref(), CursorUpdate::initial()),
    ])
    .expect("split plan should be valid");

    let op = OpId::from_raw(200);
    let first = backend
        .split_replace(now(4), test_tenant(), &acquire.lease, plan.clone(), op)
        .expect("split_replace should succeed");
    assert!(first.is_executed());
    assert_eq!(first.as_ref().children.len(), 2);

    let (parent, parent_slab) = backend
        .test_load_shard_snapshot(test_tenant(), key)
        .expect("parent lookup should succeed")
        .expect("parent must still exist");
    assert_eq!(parent.status, ShardStatus::Split);
    assert!(parent.lease.is_none());
    assert_eq!(parent.spawned.len(), 2);
    let spawned: Vec<_> = parent.spawned.iter(&parent_slab).collect();
    assert_eq!(spawned, first.as_ref().children.as_slice());

    assert!(
        backend
            .test_load_owner_binding(test_tenant(), key)
            .expect("owner lookup should succeed")
            .is_none(),
        "split parent must not retain an owner key"
    );

    let mut candidates = Vec::new();
    backend
        .collect_claim_candidates_into(now(5), test_tenant(), test_run(), &mut candidates)
        .expect("claim candidate scan should succeed");
    assert_eq!(candidates, first.as_ref().children.as_slice());

    for &child_id in &first.as_ref().children {
        let child_key = ShardKey::new(test_run(), child_id);
        let (child, _slab) = backend
            .test_load_shard_snapshot(test_tenant(), child_key)
            .expect("child lookup should succeed")
            .expect("child must exist");
        assert_eq!(child.status, ShardStatus::Active);
        assert_eq!(child.parent, Some(test_shard()));
    }

    let replay = backend
        .split_replace(now(6), test_tenant(), &acquire.lease, plan, op)
        .expect("split_replace replay should succeed");
    assert!(replay.is_replay());
    assert_eq!(replay.as_ref().children, first.as_ref().children);
}

#[test]
#[ignore = "requires a local etcd on ETCD_ENDPOINTS or localhost:2379"]
fn split_residual_round_trip_against_local_etcd() {
    let mut backend = local_backend("/gossip/tests/split-residual");
    backend
        .test_clear_namespace()
        .expect("namespace cleanup should succeed");

    let config = RunConfig::try_new(CursorSemantics::Completed, 30, Some(5)).unwrap();
    backend
        .create_run(now(1), test_tenant(), test_run(), config)
        .expect("create_run should succeed");

    let manifest = [InitialShardInput::new(
        test_shard(),
        ShardSpecRef::new(b"a", b"z", b""),
        CursorUpdate::initial(),
    )];
    let register = backend
        .register_shards(
            now(2),
            test_tenant(),
            test_run(),
            &manifest,
            OpId::from_raw(99),
        )
        .expect("register_shards should succeed");
    assert!(register.is_executed());

    let key = ShardKey::new(test_run(), test_shard());
    let mut scratch = AcquireScratch::new();
    let acquire = backend
        .acquire_and_restore_into(now(3), test_tenant(), key, test_worker(7), &mut scratch)
        .expect("acquire should succeed");

    let checkpoint = backend
        .checkpoint(
            now(4),
            test_tenant(),
            &acquire.lease,
            &CursorUpdate::new(b"f"),
            OpId::from_raw(100),
        )
        .expect("checkpoint should succeed");
    assert!(checkpoint.is_executed());

    let parent_new = ShardSpec::with_range(b"a", b"m");
    let residual = ShardSpec::with_range(b"m", b"z");
    let plan = SplitResidualPlan::try_new(parent_new.as_ref(), residual.as_ref())
        .expect("residual split plan should be valid");

    let op = OpId::from_raw(201);
    let first = backend
        .split_residual(now(5), test_tenant(), &acquire.lease, plan.clone(), op)
        .expect("split_residual should succeed");
    assert!(first.is_executed());

    let (parent, parent_slab) = backend
        .test_load_shard_snapshot(test_tenant(), key)
        .expect("parent lookup should succeed")
        .expect("parent must still exist");
    assert_eq!(parent.status, ShardStatus::Active);
    assert_eq!(parent.spec.key_range_start(&parent_slab), b"a");
    assert_eq!(parent.spec.key_range_end(&parent_slab), b"m");
    assert_eq!(parent.cursor.last_key(&parent_slab), Some(b"f".as_slice()));
    assert_eq!(parent.spawned.len(), 1);
    assert_eq!(
        parent.spawned.iter(&parent_slab).next(),
        Some(first.as_ref().residual)
    );

    let mut candidates = Vec::new();
    backend
        .collect_claim_candidates_into(now(6), test_tenant(), test_run(), &mut candidates)
        .expect("claim candidate scan should succeed");
    assert_eq!(candidates, vec![first.as_ref().residual]);

    let residual_key = ShardKey::new(test_run(), first.as_ref().residual);
    let (residual_record, residual_slab) = backend
        .test_load_shard_snapshot(test_tenant(), residual_key)
        .expect("residual lookup should succeed")
        .expect("residual must exist");
    assert_eq!(residual_record.status, ShardStatus::Active);
    assert_eq!(residual_record.parent, Some(test_shard()));
    assert_eq!(residual_record.spec.key_range_start(&residual_slab), b"m");
    assert_eq!(residual_record.spec.key_range_end(&residual_slab), b"z");
    assert_eq!(residual_record.cursor.last_key(&residual_slab), None);

    let replay = backend
        .split_residual(now(7), test_tenant(), &acquire.lease, plan, op)
        .expect("split_residual replay should succeed");
    assert!(replay.is_replay());
    assert_eq!(replay.as_ref().residual, first.as_ref().residual);
}

// ---------------------------------------------------------------------------
// Test fixture helpers
// ---------------------------------------------------------------------------
//
// Deterministic identity constructors and backend builders shared by all
// integration tests. Each integration test uses a unique namespace prefix
// to avoid cross-test interference when running against the same etcd
// cluster.

/// Read etcd endpoints from `ETCD_ENDPOINTS` or fall back to localhost.
fn test_endpoints() -> String {
    env::var("ETCD_ENDPOINTS")
        .ok()
        .and_then(|raw| {
            let trimmed = raw.trim().to_owned();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        })
        .unwrap_or_else(|| "http://127.0.0.1:2379".to_owned())
}

/// Connect to etcd with default tuning and the given namespace prefix.
fn local_backend(namespace: &str) -> EtcdCoordinator {
    let config = EtcdCoordinatorConfig::from_endpoints_csv(&test_endpoints(), namespace)
        .expect("test endpoint configuration should be valid");

    EtcdCoordinator::connect(config).expect("local etcd should be reachable")
}

/// Connect to etcd with a custom owner-lease TTL (for lease-expiry tests).
fn local_backend_with_ttl(namespace: &str, ttl_secs: i64) -> EtcdCoordinator {
    let config = EtcdCoordinatorConfig::from_endpoints_csv_with_tuning(
        &test_endpoints(),
        namespace,
        ttl_secs,
        8,
        8,
    )
    .expect("test endpoint configuration should be valid");

    EtcdCoordinator::connect(config).expect("local etcd should be reachable")
}

/// Stable tenant identity used across all tests.
fn test_tenant() -> TenantId {
    TenantId::from_bytes([0x11; 32])
}

/// Stable run identity used across all tests.
fn test_run() -> RunId {
    RunId::from_raw(0x0102_0304_0506_0708)
}

/// Stable shard identity used across all tests.
fn test_shard() -> ShardId {
    ShardId::from_raw(0x0000_0000_0000_0011)
}

/// Create a worker identity from a raw integer.
fn test_worker(id: u64) -> WorkerId {
    WorkerId::from_raw(id)
}

/// Create a logical timestamp from a raw integer.
fn now(t: u64) -> LogicalTime {
    LogicalTime::from_raw(t)
}

// ---------------------------------------------------------------------------
// Integration tests: error paths and contention
// ---------------------------------------------------------------------------

/// After the etcd lease expires (owner key auto-deleted), checkpoint must
/// fail because the owner binding no longer matches the presented lease.
#[test]
#[ignore = "requires a local etcd on ETCD_ENDPOINTS or localhost:2379"]
fn lease_expiry_rejects_stale_checkpoint() {
    // Use a short owner-lease TTL so the etcd lease expires quickly.
    // etcd enforces a minimum TTL of ~5s in most configurations.
    let ttl_secs = 5;
    let mut backend = local_backend_with_ttl("/gossip/tests/lease-expiry", ttl_secs);
    backend
        .test_clear_namespace()
        .expect("namespace cleanup should succeed");

    let config = RunConfig::try_new(CursorSemantics::Completed, 30, Some(5)).unwrap();
    backend
        .create_run(now(1), test_tenant(), test_run(), config)
        .expect("create_run should succeed");

    let manifest = [InitialShardInput::new(
        test_shard(),
        ShardSpecRef::new(b"a", b"z", b""),
        CursorUpdate::initial(),
    )];
    let _ = backend
        .register_shards(
            now(2),
            test_tenant(),
            test_run(),
            &manifest,
            OpId::from_raw(99),
        )
        .expect("register_shards should succeed");

    let key = ShardKey::new(test_run(), test_shard());
    let mut scratch = AcquireScratch::new();
    let acquire = backend
        .acquire_and_restore_into(now(3), test_tenant(), key, test_worker(7), &mut scratch)
        .expect("acquire should succeed");

    // Wait for the etcd lease to expire. The owner key is deleted by etcd's
    // TTL mechanism, leaving the shard without a live owner binding.
    std::thread::sleep(std::time::Duration::from_secs(ttl_secs as u64 + 3));

    let checkpoint_result = backend.checkpoint(
        now(4),
        test_tenant(),
        &acquire.lease,
        &CursorUpdate::new(b"m"),
        OpId::from_raw(100),
    );

    match checkpoint_result {
        Err(CheckpointError::StaleFence { .. }) => { /* expected */ }
        Err(CheckpointError::BackendError { .. }) => { /* acceptable: CAS failed after owner key vanished */
        }
        other => panic!("expected StaleFence or BackendError after lease expiry, got {other:?}"),
    }
}

/// When two workers race to acquire the same unowned shard, exactly one
/// succeeds and the other receives `AlreadyLeased`.
#[test]
#[ignore = "requires a local etcd on ETCD_ENDPOINTS or localhost:2379"]
fn concurrent_acquire_second_worker_gets_already_leased() {
    let mut backend = local_backend("/gossip/tests/concurrent-acquire");
    backend
        .test_clear_namespace()
        .expect("namespace cleanup should succeed");

    let config = RunConfig::try_new(CursorSemantics::Completed, 30, Some(5)).unwrap();
    backend
        .create_run(now(1), test_tenant(), test_run(), config)
        .expect("create_run should succeed");

    let manifest = [InitialShardInput::new(
        test_shard(),
        ShardSpecRef::new(b"a", b"z", b""),
        CursorUpdate::initial(),
    )];
    let _ = backend
        .register_shards(
            now(2),
            test_tenant(),
            test_run(),
            &manifest,
            OpId::from_raw(99),
        )
        .expect("register_shards should succeed");

    let key = ShardKey::new(test_run(), test_shard());

    // Worker A acquires the shard successfully.
    let mut scratch_a = AcquireScratch::new();
    let acquire_a = backend
        .acquire_and_restore_into(now(3), test_tenant(), key, test_worker(1), &mut scratch_a)
        .expect("worker A acquire should succeed");

    // Worker B attempts to acquire the same shard — must fail.
    let mut scratch_b = AcquireScratch::new();
    let result_b = backend.acquire_and_restore_into(
        now(4),
        test_tenant(),
        key,
        test_worker(2),
        &mut scratch_b,
    );

    match result_b {
        Err(AcquireError::AlreadyLeased {
            current_owner,
            lease_deadline,
        }) => {
            assert_eq!(
                current_owner,
                test_worker(1),
                "AlreadyLeased must report worker A as the current owner"
            );
            assert_eq!(
                lease_deadline,
                acquire_a.lease.deadline(),
                "AlreadyLeased must report the lease deadline from worker A's acquire"
            );
        }
        other => panic!("expected AlreadyLeased for worker B, got {other:?}"),
    }
}
