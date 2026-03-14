//! Tests for the etcd coordination backend.
//!
//! ## Test layers
//!
//! Tests are organized in four tiers of increasing infrastructure
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
//!    etcd cluster. When Docker is available, testcontainers
//!    auto-provisions `quay.io/coreos/etcd:v3.5.15`. Alternatively,
//!    set `ETCD_ENDPOINTS` to point at an existing cluster. They cover
//!    the full acquire/checkpoint/renew/split lifecycle, deterministic
//!    split atomicity fault injection, idempotent replay, lease expiry,
//!    and sequential acquire contention.
//!
//! 4. **Concurrent CAS contention** — multi-threaded tests that exercise
//!    real CAS retry paths. Each thread owns its own `EtcdCoordinator`
//!    (with its own Tokio runtime) but all target the same etcd
//!    keyspace. A `std::sync::Barrier` synchronizes threads to maximize
//!    CAS contention probability. These tests verify that `mod_revision`
//!    -based CAS guards on per-tenant shard counters correctly serialize
//!    concurrent shard-creating operations.
//!
//! ## Running integration tests
//!
//! ```bash
//! # With Docker installed, tests auto-provision etcd via testcontainers:
//! cargo test -p gossip-coordination-etcd
//!
//! # Or point to an existing cluster:
//! ETCD_ENDPOINTS="http://10.0.0.1:2379,http://10.0.0.2:2379" \
//!   cargo test -p gossip-coordination-etcd
//! ```

use crate::keyspace::PersistedShardSubtreeKey;
use crate::test_etcd::{
    contention_namespace, test_coordinator, test_coordinator_in_namespace,
    test_coordinator_in_namespace_with_limits, test_coordinator_with_limits,
    test_coordinator_with_ttl, test_coordinator_with_tuning,
};
use crate::{
    EtcdCoordinatorConfig, EtcdCoordinatorConfigError, EtcdCoordinatorError, EtcdKeyspace,
    EtcdKeyspaceError, EtcdOperation, EtcdTestFault,
};
use gossip_contracts::coordination::{
    CursorSemantics, CursorUpdate, ShardSpec, ShardSpecRef, SplitReplaceChild, SplitReplacePlan,
    SplitResidualPlan, SplitValidationError,
};
use gossip_contracts::identity::{LogicalTime, OpId, RunId, ShardId, ShardKey, TenantId, WorkerId};
use gossip_coordination::{
    AcquireError, AcquireScratch, ByteSlab, CheckpointError, CoordinationBackend,
    DEFAULT_MAX_SHARDS_PER_TENANT, DEFAULT_MAX_TOTAL_SHARDS, DerivedShardKind, GetRunError,
    IdempotentOutcome, InitialShardInput, ParkReason, RegisterShardsError, RunConfig,
    RunManagement, RunStatus, RunTransitionError, ShardFilter, ShardLimitScope, ShardRecord,
    ShardStatus, SplitReplaceError, SplitResidualError, UnparkError, derive_split_shard_id,
};
use proptest::prelude::*;
use rstest::rstest;

// ---------------------------------------------------------------------------
// Config validation (pure, no etcd required)
// ---------------------------------------------------------------------------

/// Empty endpoint list must be rejected at construction time.
#[test]
fn config_rejects_empty_endpoint_list() {
    let error = EtcdCoordinatorConfig::new(Vec::<String>::new(), "/gossip/v1")
        .expect_err("empty endpoints must fail validation");
    assert!(matches!(error, EtcdCoordinatorConfigError::NoEndpoints));
}

/// An endpoint that becomes empty after whitespace trimming must be rejected.
#[test]
fn config_rejects_empty_endpoint_after_trimming() {
    let error = EtcdCoordinatorConfig::new(["   "], "/gossip/v1")
        .expect_err("blank endpoints must fail validation");
    assert!(matches!(
        error,
        EtcdCoordinatorConfigError::EmptyEndpoint { index: 0 }
    ));
}

/// Blank namespace prefix (whitespace-only) must be rejected.
#[test]
fn config_rejects_empty_namespace_prefix() {
    let error = EtcdCoordinatorConfig::new(["http://127.0.0.1:2379"], "   ")
        .expect_err("blank namespace prefix must fail validation");
    assert!(matches!(
        error,
        EtcdCoordinatorConfigError::EmptyNamespacePrefix
    ));
}

/// Namespace prefix must begin with `/` to form a valid etcd key root.
#[test]
fn config_rejects_invalid_namespace_prefix() {
    let error = EtcdCoordinatorConfig::new(["http://127.0.0.1:2379"], "gossip/v1")
        .expect_err("namespace prefix without leading slash must fail");
    assert!(matches!(
        error,
        EtcdCoordinatorConfigError::NamespacePrefixMustStartWithSlash
    ));
}

/// Trailing slash in namespace prefix would produce double-slashes in keys.
#[test]
fn config_rejects_namespace_prefix_with_trailing_slash() {
    let error = EtcdCoordinatorConfig::new(["http://127.0.0.1:2379"], "/gossip/v1/")
        .expect_err("namespace prefix with trailing slash must fail");
    assert!(matches!(
        error,
        EtcdCoordinatorConfigError::NamespacePrefixMustNotEndWithSlash
    ));
}

/// `localhost()` convenience constructor must produce stable default values
/// that integration tests and local development depend on.
#[test]
fn localhost_config_uses_expected_defaults() {
    let config = EtcdCoordinatorConfig::localhost();
    assert_eq!(config.endpoints(), ["http://127.0.0.1:2379"]);
    assert_eq!(config.namespace_prefix(), "/gossip/v1");
    assert_eq!(config.owner_lease_ttl_secs(), 60);
    assert_eq!(config.optimistic_txn_retries(), 8);
    assert_eq!(
        config.max_shards_per_tenant(),
        DEFAULT_MAX_SHARDS_PER_TENANT
    );
    assert_eq!(config.max_total_shards(), DEFAULT_MAX_TOTAL_SHARDS);
    assert_eq!(config.max_children_per_op(), 8);
}

/// CSV parsing trims whitespace and drops empty segments between delimiters.
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

/// A CSV string containing only delimiters and whitespace must produce
/// `NoEndpoints` (same as an empty list).
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

/// Trailing commas in the CSV produce empty segments that are silently
/// dropped rather than treated as empty endpoints.
#[test]
fn from_endpoints_csv_drops_trailing_empty_segments() {
    let config = EtcdCoordinatorConfig::from_endpoints_csv("http://a:2379,,", "/gossip/v1")
        .expect("trailing empty segments should be silently dropped");
    assert_eq!(config.endpoints(), ["http://a:2379"]);
}

/// The bare `/` namespace places all keys directly under the root,
/// producing paths like `/tenants/…` with no doubled slashes.
#[test]
fn config_accepts_root_namespace_slash() {
    let config = EtcdCoordinatorConfig::new(["http://127.0.0.1:2379"], "/")
        .expect("root namespace '/' should be accepted");
    assert_eq!(config.namespace_prefix(), "/");
}

/// Custom tuning parameters (TTL, retry budget, child cap) pass through
/// validation and are accessible via the config accessors.
#[test]
fn config_accepts_explicit_tuning_values() {
    let config =
        EtcdCoordinatorConfig::new_with_tuning(["http://127.0.0.1:2379"], "/gossip/v1", 90, 16, 12)
            .expect("explicit tuning should pass validation");
    assert_eq!(config.owner_lease_ttl_secs(), 90);
    assert_eq!(config.optimistic_txn_retries(), 16);
    assert_eq!(config.max_children_per_op(), 12);
}

/// `with_shard_limits` overrides the default per-tenant and global caps.
#[test]
fn config_with_shard_limits_overrides_defaults() {
    let config = EtcdCoordinatorConfig::new(["http://127.0.0.1:2379"], "/gossip/v1")
        .expect("valid config")
        .with_shard_limits(12, 34)
        .expect("valid shard limits");
    assert_eq!(config.max_shards_per_tenant(), 12);
    assert_eq!(config.max_total_shards(), 34);
}

/// Zero TTL is invalid because etcd requires a positive lease duration.
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

/// Zero retries means every CAS operation gives up without attempting,
/// which is never useful.
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

/// Excessive retry budget would cause CAS operations to block for minutes
/// under contention.
#[test]
fn config_rejects_excessive_optimistic_txn_retries() {
    let error = EtcdCoordinatorConfig::new_with_tuning(
        ["http://127.0.0.1:2379"],
        "/gossip/v1",
        60,
        10_000,
        8,
    )
    .expect_err("excessive retry budget must fail");
    assert!(matches!(
        error,
        EtcdCoordinatorConfigError::ExcessiveOptimisticTxnRetries {
            requested: 10_000,
            max: 64,
        }
    ));
}

/// Zero per-tenant cap would prevent any shard registration.
#[test]
fn config_rejects_zero_max_shards_per_tenant() {
    let error = EtcdCoordinatorConfig::new(["http://127.0.0.1:2379"], "/gossip/v1")
        .expect("base config should be valid")
        .with_shard_limits(0, 8)
        .expect_err("zero per-tenant shard cap must fail validation");
    assert!(matches!(
        error,
        EtcdCoordinatorConfigError::ZeroMaxShardsPerTenant
    ));
}

/// Zero global cap would prevent any shard registration.
#[test]
fn config_rejects_zero_max_total_shards() {
    let error = EtcdCoordinatorConfig::new(["http://127.0.0.1:2379"], "/gossip/v1")
        .expect("base config should be valid")
        .with_shard_limits(8, 0)
        .expect_err("zero global shard cap must fail validation");
    assert!(matches!(
        error,
        EtcdCoordinatorConfigError::ZeroMaxTotalShards
    ));
}

/// Zero child cap would prevent all split operations.
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

/// The per-backend child cap must stay within the etcd `split_replace`
/// transaction budget. Each child adds 3 transaction entries (1 compare +
/// 2 ops) to a fixed overhead of 9 (parent CAS + tenant-counter CAS),
/// so `(128 - 9) / 3 = 39` is the max.
#[test]
fn config_rejects_max_children_per_op_above_etcd_txn_budget() {
    // 39 children should be accepted (boundary value).
    EtcdCoordinatorConfig::new_with_tuning(["http://127.0.0.1:2379"], "/gossip/v1", 60, 8, 39)
        .expect("39 children must be accepted — exactly at the etcd txn budget ceiling");

    // 40 children should be rejected: 9 + 3*40 = 129 > 128.
    let error =
        EtcdCoordinatorConfig::new_with_tuning(["http://127.0.0.1:2379"], "/gossip/v1", 60, 8, 40)
            .expect_err("40 children must fail — exceeds etcd txn budget");
    assert!(matches!(
        error,
        EtcdCoordinatorConfigError::MaxChildrenPerOpExceedsEtcdTxnBudget {
            requested: 40,
            max: 39,
        }
    ));
}

/// Values above `MAX_SPLIT_CHILDREN` (256) are also rejected, but the
/// tighter etcd txn budget check (39) fires first. This test verifies
/// that out-of-range values still produce a clear rejection.
#[test]
fn config_rejects_max_children_per_op_above_global_limit() {
    let error =
        EtcdCoordinatorConfig::new_with_tuning(["http://127.0.0.1:2379"], "/gossip/v1", 60, 8, 257)
            .expect_err("max_children_per_op above MAX_SPLIT_CHILDREN must fail validation");
    // The etcd txn budget check is stricter (39 < 256), so it fires first.
    assert!(matches!(
        error,
        EtcdCoordinatorConfigError::MaxChildrenPerOpExceedsEtcdTxnBudget {
            requested: 257,
            max: 39,
        }
    ));
}

// ---------------------------------------------------------------------------
// Debug output tests
// ---------------------------------------------------------------------------

/// Debug output must redact userinfo in endpoint URIs to prevent
/// credential leakage in logs and error messages.
#[test]
fn config_debug_does_not_expose_raw_endpoint_credentials() {
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

/// Endpoints without embedded credentials appear verbatim in Debug output.
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

/// The `with_auth` password field is replaced with `[REDACTED]` in Debug
/// output while the username remains visible for diagnostics.
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

/// The `auth()` accessor returns the raw credentials, unlike Debug output.
#[test]
fn config_with_auth_exposes_credentials_via_accessor() {
    let config = EtcdCoordinatorConfig::new(["http://etcd-0:2379"], "/gossip/v1")
        .expect("valid config")
        .with_auth("admin", "password123");

    let (user, pass) = config.auth().expect("auth should be set");
    assert_eq!(user, "admin");
    assert_eq!(pass, "password123");
}

/// Without `with_auth`, the auth accessor returns `None`.
#[test]
fn config_without_auth_returns_none() {
    let config =
        EtcdCoordinatorConfig::new(["http://etcd-0:2379"], "/gossip/v1").expect("valid config");

    assert!(config.auth().is_none());
}

// ---------------------------------------------------------------------------
// URL scheme validation tests
// ---------------------------------------------------------------------------

/// Endpoints must use `http://` or `https://` — bare host:port is rejected.
#[test]
fn config_rejects_endpoint_without_http_scheme() {
    let error = EtcdCoordinatorConfig::new(["etcd-0:2379"], "/gossip/v1")
        .expect_err("endpoint without http:// or https:// must fail");
    assert!(matches!(
        error,
        EtcdCoordinatorConfigError::InvalidEndpointScheme { index: 0 }
    ));
}

/// Non-HTTP schemes (e.g., `ftp://`) are rejected.
#[test]
fn config_rejects_endpoint_with_ftp_scheme() {
    let error = EtcdCoordinatorConfig::new(["ftp://etcd-0:2379"], "/gossip/v1")
        .expect_err("endpoint with ftp:// scheme must fail");
    assert!(matches!(
        error,
        EtcdCoordinatorConfigError::InvalidEndpointScheme { index: 0 }
    ));
}

/// `https://` endpoints are accepted for TLS-enabled clusters.
#[test]
fn config_accepts_https_endpoint() {
    let config = EtcdCoordinatorConfig::new(["https://etcd-0:2379"], "/gossip/v1")
        .expect("https:// endpoint should be accepted");
    assert_eq!(config.endpoints(), ["https://etcd-0:2379"]);
}

/// Scheme validation applies to every endpoint, not just the first.
#[test]
fn config_rejects_second_endpoint_with_bad_scheme() {
    let error = EtcdCoordinatorConfig::new(["http://etcd-0:2379", "etcd-1:2379"], "/gossip/v1")
        .expect_err("second endpoint without scheme must fail");
    assert!(matches!(
        error,
        EtcdCoordinatorConfigError::InvalidEndpointScheme { index: 1 }
    ));
}

/// `EtcdOperation::Connect` renders as lowercase `"connect"` in Display.
#[test]
fn etcd_operation_display_connect() {
    assert_eq!(EtcdOperation::Connect.to_string(), "connect");
}

/// `EtcdOperation::Status` renders as `"status"`.
#[test]
fn etcd_operation_display_status() {
    assert_eq!(EtcdOperation::Status.to_string(), "status");
}

/// `EtcdOperation::LeaseGrant` renders as `"lease_grant"`.
#[test]
fn etcd_operation_display_lease_grant() {
    assert_eq!(EtcdOperation::LeaseGrant.to_string(), "lease_grant");
}

/// The `Config` variant's Display includes context and the inner error.
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

/// `Error::source()` on the `Config` variant downcasts to
/// `EtcdCoordinatorConfigError`.
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

/// `Error::source()` on the `RuntimeBuild` variant downcasts to `io::Error`.
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

/// `From<EtcdCoordinatorConfigError>` produces the `Config` variant.
#[test]
fn config_error_converts_to_coordinator_error_via_from() {
    let config_err = EtcdCoordinatorConfigError::NoEndpoints;
    let coord_err: EtcdCoordinatorError = config_err.into();
    assert!(matches!(coord_err, EtcdCoordinatorError::Config(_)));
}

// ---------------------------------------------------------------------------
// Keyspace path construction (pure, no etcd required)
// ---------------------------------------------------------------------------

/// Golden-value test: verifies exact key paths for a representative
/// (tenant, run, shard) tuple under the `/gossip/v1` namespace.
#[test]
fn keyspace_builds_expected_paths() {
    let tenant = TenantId::from_bytes([0xAB; 32]);
    let run = RunId::from_raw(0x0123_4567_89ab_cdef);
    let shard = ShardId::from_raw(0x8000_0000_0000_0042);

    let keyspace = EtcdKeyspace::new("/gossip/v1").expect("valid keyspace prefix");
    assert_eq!(
        keyspace.run_record_key(tenant, run).as_str(),
        "/gossip/v1/tenants/abababababababababababababababababababababababababababababababab/runs/0123456789abcdef"
    );
    assert_eq!(
        keyspace.tenant_shard_count_key(tenant).as_str(),
        "/gossip/v1/tenants/abababababababababababababababababababababababababababababababab/shard_count"
    );
    assert_eq!(
        keyspace.shard_record_key(tenant, run, shard).as_str(),
        "/gossip/v1/tenants/abababababababababababababababababababababababababababababababab/runs/0123456789abcdef/shards/8000000000000042"
    );
    assert_eq!(
        keyspace.shard_owner_key(tenant, run, shard).as_str(),
        "/gossip/v1/tenants/abababababababababababababababababababababababababababababababab/runs/0123456789abcdef/shards/8000000000000042/owner"
    );
    assert_eq!(
        keyspace.run_active_index_key(tenant, run).as_str(),
        "/gossip/v1/tenants/abababababababababababababababababababababababababababababababab/runs_active/0123456789abcdef"
    );
    assert_eq!(
        keyspace.shard_active_index_key(tenant, run, shard).as_str(),
        "/gossip/v1/tenants/abababababababababababababababababababababababababababababababab/runs/0123456789abcdef/shards_active/8000000000000042"
    );
    assert_eq!(
        keyspace.shard_records_scan_prefix(tenant, run),
        "/gossip/v1/tenants/abababababababababababababababababababababababababababababababab/runs/0123456789abcdef/shards/"
    );
}

/// The root `/` prefix must not produce double slashes in generated paths.
#[test]
fn keyspace_root_prefix_does_not_emit_double_slashes() {
    let tenant = TenantId::from_bytes([0x11; 32]);
    let run = RunId::from_raw(0x42);
    let keyspace = EtcdKeyspace::new("/").expect("root prefix should be valid");

    assert_eq!(
        keyspace.run_record_key(tenant, run).as_str(),
        "/tenants/1111111111111111111111111111111111111111111111111111111111111111/runs/0000000000000042"
    );
    assert_eq!(keyspace.tenants_prefix(), "/tenants");
}

/// Typed key wrappers preserve their etcd path and classify persisted keys.
#[test]
fn keyspace_typed_keys_preserve_kind_and_relationships() {
    let tenant = TenantId::from_bytes([0xAB; 32]);
    let run = RunId::from_raw(0x0123_4567_89ab_cdef);
    let shard = ShardId::from_raw(0x8000_0000_0000_0042);

    let keyspace = EtcdKeyspace::new("/gossip/v1").expect("valid keyspace prefix");
    let shard_key = keyspace.shard_record_key(tenant, run, shard);
    let owner_key = shard_key.owner_key();
    let shard_active_key = keyspace.shard_active_index_key(tenant, run, shard);
    let run_key = keyspace.run_record_key(tenant, run);
    let tenant_counter_key = keyspace.tenant_shard_count_key(tenant);

    assert_eq!(
        owner_key.as_str(),
        keyspace.shard_owner_key(tenant, run, shard).as_str()
    );
    assert_eq!(
        PersistedShardSubtreeKey::classify(shard_key.as_bytes()),
        Some(PersistedShardSubtreeKey::Record)
    );
    assert_eq!(
        PersistedShardSubtreeKey::classify(owner_key.as_bytes()),
        Some(PersistedShardSubtreeKey::Owner)
    );
    assert_eq!(
        PersistedShardSubtreeKey::classify(shard_active_key.as_bytes()),
        None
    );
    assert_eq!(PersistedShardSubtreeKey::classify(run_key.as_bytes()), None);
    assert_eq!(
        PersistedShardSubtreeKey::classify(tenant_counter_key.as_bytes()),
        None
    );
}

/// Uppercase hex segments are rejected to preserve canonical lowercase keys.
#[test]
fn keyspace_rejects_uppercase_hex_suffixes() {
    let tenant = TenantId::from_bytes([0xAB; 32]);
    let run = RunId::from_raw(0x0123_4567_89ab_cdef);
    let keyspace = EtcdKeyspace::new("/gossip/v1").expect("valid keyspace prefix");

    let run_prefix = keyspace.run_records_scan_prefix(tenant);
    let run_key_upper = format!("{run_prefix}00000000000000AA");
    assert_eq!(
        crate::RunRecordKey::parse_direct_run_id(&run_prefix, run_key_upper.as_bytes()),
        None
    );

    let shard_prefix = keyspace.shard_records_scan_prefix(tenant, run);
    let shard_record_upper = format!("{shard_prefix}00000000000000AA");
    let shard_owner_upper = format!("{shard_prefix}00000000000000AA/owner");
    assert_eq!(
        PersistedShardSubtreeKey::classify(shard_record_upper.as_bytes()),
        None
    );
    assert_eq!(
        PersistedShardSubtreeKey::classify(shard_owner_upper.as_bytes()),
        None
    );
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
        let tenant_counter = ks.tenant_shard_count_key(tenant);
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
            tenants.as_str(),
            tenant_pfx.as_str(),
            runs.as_str(),
            tenant_counter.as_str(),
            run_key.as_str(),
            shards_pfx.as_str(),
            scan_pfx.as_str(),
            shard_key.as_str(),
            owner_key.as_str(),
            runs_active.as_str(),
            run_active.as_str(),
            shards_active.as_str(),
            shard_active.as_str(),
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
        prop_assert!(tenant_counter.as_str().starts_with(&tenant_pfx));
        prop_assert!(run_key.as_str().starts_with(&runs));
        prop_assert!(shards_pfx.starts_with(run_key.as_str()));
        prop_assert!(shard_key.as_str().starts_with(&shards_pfx));
        prop_assert!(owner_key.as_str().starts_with(shard_key.as_str()));
        prop_assert!(owner_key.as_str().ends_with("/owner"));

        // Scan prefix ends with trailing slash.
        prop_assert!(scan_pfx.ends_with('/'));
        prop_assert!(scan_pfx.starts_with(&shards_pfx));

        // Active-index keys live under tenant, not under runs/.
        prop_assert!(runs_active.starts_with(&tenant_pfx));
        prop_assert!(run_active.as_str().starts_with(&runs_active));
        prop_assert!(runs_active.contains("/runs_active"));

        // Scan isolation: run_records_scan_prefix must NOT match
        // runs_active keys (the trailing slash prevents this).
        let run_scan_pfx = ks.run_records_scan_prefix(tenant);
        prop_assert!(run_scan_pfx.ends_with('/'));
        prop_assert!(!run_active.as_str().starts_with(&run_scan_pfx));

        // Active-shard index keys are siblings of shards/, not children.
        prop_assert!(shards_active.starts_with(run_key.as_str()));
        prop_assert!(shard_active.as_str().starts_with(&shards_active));
        prop_assert!(shards_active.contains("/shards_active"));

        // Scan isolation: shard_records_scan_prefix must NOT match
        // shards_active keys (the trailing slash prevents this).
        prop_assert!(!shard_active.as_str().starts_with(&scan_pfx));

        // Hex encoding: tenant segment is 64 hex chars, run/shard are 16.
        let tenant_segment = tenant_pfx
            .strip_prefix(&format!("{}/", tenants))
            .unwrap_or("");
        prop_assert_eq!(tenant_segment.len(), 64);
        prop_assert!(tenant_segment.chars().all(|c| c.is_ascii_hexdigit()));

        let run_segment = run_key
            .as_str()
            .strip_prefix(&format!("{}/", runs))
            .unwrap_or("");
        prop_assert_eq!(run_segment.len(), 16);
        prop_assert!(run_segment.chars().all(|c| c.is_ascii_hexdigit()));

        let shard_segment = shard_key
            .as_str()
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
// etcd integration tests (require Docker or ETCD_ENDPOINTS)
// ---------------------------------------------------------------------------

/// A batch of 42 shards exceeds the per-transaction op limit (41) and must
/// be rejected before writing to etcd.
#[test]
fn register_shards_rejects_batch_exceeding_etcd_txn_limit() {
    let mut backend = test_coordinator();

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

/// Registering shards for a second tenant that would push the global shard
/// count above the configured cap must return `ShardLimitExceeded(Global)`.
/// The existing shard from a different tenant counts toward the global total.
#[test]
fn register_shards_rejects_global_shard_limit_against_local_etcd() {
    let mut backend = test_coordinator_with_limits(100, 2);

    let config = RunConfig::try_new(CursorSemantics::Completed, 30, Some(5)).unwrap();
    backend
        .create_run(now(1), other_tenant(), other_run(), config)
        .expect("create_run should succeed for other tenant");
    let seed_manifest = [InitialShardInput::new(
        ShardId::from_raw(0x21),
        ShardSpecRef::new(b"a", b"z", b""),
        CursorUpdate::initial(),
    )];
    let seed = backend
        .register_shards(
            now(2),
            other_tenant(),
            other_run(),
            &seed_manifest,
            OpId::from_raw(98),
        )
        .expect("seed registration should succeed");
    assert!(seed.is_executed());

    backend
        .create_run(now(3), test_tenant(), test_run(), config)
        .expect("create_run should succeed for target tenant");
    let shard_a = ShardSpec::with_range(b"a", b"m");
    let shard_b = ShardSpec::with_range(b"m", b"z");
    let manifest = [
        InitialShardInput::new(
            ShardId::from_raw(0x31),
            shard_a.as_ref(),
            CursorUpdate::initial(),
        ),
        InitialShardInput::new(
            ShardId::from_raw(0x32),
            shard_b.as_ref(),
            CursorUpdate::initial(),
        ),
    ];

    let err = backend
        .register_shards(
            now(4),
            test_tenant(),
            test_run(),
            &manifest,
            OpId::from_raw(99),
        )
        .expect_err("registration should exceed the global shard limit");

    assert!(
        matches!(
            err,
            RegisterShardsError::ShardLimitExceeded {
                scope: ShardLimitScope::Global,
                ..
            }
        ),
        "expected ShardLimitExceeded(Global), got {err:?}"
    );
}

/// If the tenant counter key is missing, `register_shards` bootstraps it
/// from the tenant prefix scan and creates the key in the same CAS txn.
#[test]
fn register_shards_bootstraps_counter_when_key_is_absent() {
    let mut backend = test_coordinator_with_limits(10, 100);
    let config = RunConfig::try_new(CursorSemantics::Completed, 30, Some(5)).unwrap();

    let run_a = RunId::from_raw(0x7001);
    backend
        .create_run(now(1), test_tenant(), run_a, config)
        .expect("create_run for run_a should succeed");
    let manifest_a = [InitialShardInput::new(
        ShardId::from_raw(0xA001),
        ShardSpecRef::new(b"a", b"m", b""),
        CursorUpdate::initial(),
    )];
    let register_a = backend
        .register_shards(now(2), test_tenant(), run_a, &manifest_a, OpId::from_raw(1))
        .expect("initial register_shards should succeed");
    assert!(register_a.is_executed());
    assert_eq!(
        backend
            .test_load_tenant_shard_count(test_tenant())
            .expect("counter load should succeed"),
        Some(1),
        "initial registration should set counter to 1"
    );

    backend
        .test_delete_tenant_shard_count(test_tenant())
        .expect("counter delete should succeed");
    assert_eq!(
        backend
            .test_load_tenant_shard_count(test_tenant())
            .expect("counter load should succeed"),
        None,
        "counter key should be absent before bootstrap"
    );

    let run_b = RunId::from_raw(0x7002);
    backend
        .create_run(now(3), test_tenant(), run_b, config)
        .expect("create_run for run_b should succeed");
    let manifest_b = [InitialShardInput::new(
        ShardId::from_raw(0xA002),
        ShardSpecRef::new(b"m", b"z", b""),
        CursorUpdate::initial(),
    )];
    let register_b = backend
        .register_shards(now(4), test_tenant(), run_b, &manifest_b, OpId::from_raw(2))
        .expect("register_shards should bootstrap absent counter");
    assert!(register_b.is_executed());

    assert_eq!(
        backend
            .test_load_tenant_shard_count(test_tenant())
            .expect("counter load should succeed"),
        Some(2),
        "bootstrap should scan existing shard count and publish updated value"
    );
}

/// Smoke test: connect to etcd and verify that the status RPC returns a
/// non-empty cluster version.
#[test]
fn connects_to_local_etcd_and_fetches_status() {
    let backend = test_coordinator();
    let status = backend.status().expect("status call should succeed");

    assert!(
        !status.version().is_empty(),
        "connected member should report a version"
    );
}

/// End-to-end happy path: create a run, register a shard, acquire it,
/// checkpoint a cursor position, and renew the lease. Verifies that the
/// owner binding, cursor state, and lease deadline are all persisted
/// correctly across the full lifecycle.
#[test]
fn acquire_checkpoint_and_renew_round_trip_against_local_etcd() {
    let mut backend = test_coordinator();

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

    let shard = backend
        .test_load_shard_snapshot(test_tenant(), key)
        .expect("shard lookup should succeed")
        .expect("shard must exist");
    assert_eq!(shard.cursor.last_key(shard.slab()), Some(b"m".as_slice()));

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

/// Full split_replace lifecycle: split a parent into two children, verify
/// the parent transitions to `Split` status with no owner, verify both
/// children are `Active` and claimable, and confirm idempotent replay
/// returns the same child IDs.
#[test]
fn split_replace_round_trip_against_local_etcd() {
    let mut backend = test_coordinator();

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
    assert_eq!(
        backend
            .test_load_tenant_shard_count(test_tenant())
            .expect("counter load should succeed"),
        Some(3),
        "counter should include parent + 2 children after split_replace"
    );

    let parent = backend
        .test_load_shard_snapshot(test_tenant(), key)
        .expect("parent lookup should succeed")
        .expect("parent must still exist");
    assert_eq!(parent.status, ShardStatus::Split);
    assert!(parent.lease.is_none());
    assert_eq!(parent.spawned.len(), 2);
    let spawned: Vec<_> = parent.spawned.iter(parent.slab()).collect();
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
    candidates.sort_unstable_by_key(|id| id.as_raw());
    let mut expected_children = first.as_ref().children.as_slice().to_vec();
    expected_children.sort_unstable_by_key(|id| id.as_raw());
    assert_eq!(candidates, expected_children);

    for &child_id in &first.as_ref().children {
        let child_key = ShardKey::new(test_run(), child_id);
        let child = backend
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

/// Splitting when the resulting child count would exceed the per-tenant
/// shard limit must fail, even if the global limit has room. Sibling
/// shards from a different run under the same tenant count toward the
/// per-tenant total.
#[test]
fn split_replace_rejects_per_tenant_shard_limit_against_local_etcd() {
    let mut backend = test_coordinator_with_limits(3, 100);

    let config = RunConfig::try_new(CursorSemantics::Completed, 30, Some(5)).unwrap();
    backend
        .create_run(now(1), test_tenant(), test_run(), config)
        .expect("create_run should succeed");
    let parent_manifest = [InitialShardInput::new(
        test_shard(),
        ShardSpecRef::new(b"a", b"z", b""),
        CursorUpdate::initial(),
    )];
    let register = backend
        .register_shards(
            now(2),
            test_tenant(),
            test_run(),
            &parent_manifest,
            OpId::from_raw(99),
        )
        .expect("register_shards should succeed");
    assert!(register.is_executed());

    backend
        .create_run(now(3), test_tenant(), other_run(), config)
        .expect("second run should be created");
    let shard_a = ShardSpec::with_range(b"a", b"m");
    let shard_b = ShardSpec::with_range(b"m", b"z");
    let sibling_manifest = [
        InitialShardInput::new(
            ShardId::from_raw(0x41),
            shard_a.as_ref(),
            CursorUpdate::initial(),
        ),
        InitialShardInput::new(
            ShardId::from_raw(0x42),
            shard_b.as_ref(),
            CursorUpdate::initial(),
        ),
    ];
    let sibling_register = backend
        .register_shards(
            now(4),
            test_tenant(),
            other_run(),
            &sibling_manifest,
            OpId::from_raw(100),
        )
        .expect("sibling registration should fill the tenant limit");
    assert!(sibling_register.is_executed());

    let key = ShardKey::new(test_run(), test_shard());
    let mut scratch = AcquireScratch::new();
    let acquire = backend
        .acquire_and_restore_into(now(5), test_tenant(), key, test_worker(7), &mut scratch)
        .expect("acquire should succeed");

    let left = ShardSpec::with_range(b"a", b"m");
    let right = ShardSpec::with_range(b"m", b"z");
    let plan = SplitReplacePlan::try_new(vec![
        SplitReplaceChild::new(left.as_ref(), CursorUpdate::initial()),
        SplitReplaceChild::new(right.as_ref(), CursorUpdate::initial()),
    ])
    .expect("split plan should be valid");

    let err = backend
        .split_replace(
            now(6),
            test_tenant(),
            &acquire.lease,
            plan,
            OpId::from_raw(200),
        )
        .expect_err("split_replace should exceed the per-tenant shard limit");

    assert!(
        matches!(
            err,
            SplitReplaceError::SplitInvalid(SplitValidationError::ShardLimitExceeded {
                scope: ShardLimitScope::PerTenant,
                ..
            })
        ),
        "expected ShardLimitExceeded(PerTenant), got {err:?}"
    );
}

/// Full split_residual lifecycle: narrow a parent's key range, create
/// a residual shard covering the removed range, verify the parent stays
/// `Active` with updated spec, verify the residual is claimable with an
/// empty cursor, and confirm idempotent replay returns the same residual ID.
#[test]
fn split_residual_round_trip_against_local_etcd() {
    let mut backend = test_coordinator();

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
    assert_eq!(
        backend
            .test_load_tenant_shard_count(test_tenant())
            .expect("counter load should succeed"),
        Some(2),
        "counter should grow by 1 after split_residual"
    );

    let parent = backend
        .test_load_shard_snapshot(test_tenant(), key)
        .expect("parent lookup should succeed")
        .expect("parent must still exist");
    assert_eq!(parent.status, ShardStatus::Active);
    assert_eq!(parent.spec.key_range_start(parent.slab()), b"a");
    assert_eq!(parent.spec.key_range_end(parent.slab()), b"m");
    assert_eq!(parent.cursor.last_key(parent.slab()), Some(b"f".as_slice()));
    assert_eq!(parent.spawned.len(), 1);
    assert_eq!(
        parent.spawned.iter(parent.slab()).next(),
        Some(first.as_ref().residual)
    );

    let mut candidates = Vec::new();
    backend
        .collect_claim_candidates_into(now(6), test_tenant(), test_run(), &mut candidates)
        .expect("claim candidate scan should succeed");
    assert_eq!(candidates, vec![first.as_ref().residual]);

    let residual_key = ShardKey::new(test_run(), first.as_ref().residual);
    let residual_record = backend
        .test_load_shard_snapshot(test_tenant(), residual_key)
        .expect("residual lookup should succeed")
        .expect("residual must exist");
    assert_eq!(residual_record.status, ShardStatus::Active);
    assert_eq!(residual_record.parent, Some(test_shard()));
    assert_eq!(
        residual_record.spec.key_range_start(residual_record.slab()),
        b"m"
    );
    assert_eq!(
        residual_record.spec.key_range_end(residual_record.slab()),
        b"z"
    );
    assert_eq!(
        residual_record.cursor.last_key(residual_record.slab()),
        None
    );

    let replay = backend
        .split_residual(now(7), test_tenant(), &acquire.lease, plan, op)
        .expect("split_residual replay should succeed");
    assert!(replay.is_replay());
    assert_eq!(replay.as_ref().residual, first.as_ref().residual);
}

/// Residual split that would push the global shard count above the cap
/// must fail with `ShardLimitExceeded(Global)`. A sibling shard from a
/// different tenant fills the global quota.
#[test]
fn split_residual_rejects_global_shard_limit_against_local_etcd() {
    let mut backend = test_coordinator_with_limits(100, 2);

    let config = RunConfig::try_new(CursorSemantics::Completed, 30, Some(5)).unwrap();
    backend
        .create_run(now(1), test_tenant(), test_run(), config)
        .expect("create_run should succeed");
    let parent_manifest = [InitialShardInput::new(
        test_shard(),
        ShardSpecRef::new(b"a", b"z", b""),
        CursorUpdate::initial(),
    )];
    let register = backend
        .register_shards(
            now(2),
            test_tenant(),
            test_run(),
            &parent_manifest,
            OpId::from_raw(99),
        )
        .expect("register_shards should succeed");
    assert!(register.is_executed());

    backend
        .create_run(now(3), other_tenant(), other_run(), config)
        .expect("other tenant run should be created");
    let sibling_manifest = [InitialShardInput::new(
        ShardId::from_raw(0x51),
        ShardSpecRef::new(b"a", b"z", b""),
        CursorUpdate::initial(),
    )];
    let sibling_register = backend
        .register_shards(
            now(4),
            other_tenant(),
            other_run(),
            &sibling_manifest,
            OpId::from_raw(100),
        )
        .expect("sibling registration should fill the global limit");
    assert!(sibling_register.is_executed());

    let key = ShardKey::new(test_run(), test_shard());
    let mut scratch = AcquireScratch::new();
    let acquire = backend
        .acquire_and_restore_into(now(5), test_tenant(), key, test_worker(7), &mut scratch)
        .expect("acquire should succeed");

    let checkpoint = backend
        .checkpoint(
            now(6),
            test_tenant(),
            &acquire.lease,
            &CursorUpdate::new(b"f"),
            OpId::from_raw(101),
        )
        .expect("checkpoint should succeed");
    assert!(checkpoint.is_executed());

    let parent_new = ShardSpec::with_range(b"a", b"m");
    let residual = ShardSpec::with_range(b"m", b"z");
    let plan = SplitResidualPlan::try_new(parent_new.as_ref(), residual.as_ref())
        .expect("residual split plan should be valid");

    let err = backend
        .split_residual(
            now(7),
            test_tenant(),
            &acquire.lease,
            plan,
            OpId::from_raw(201),
        )
        .expect_err("split_residual should exceed the global shard limit");

    assert!(
        matches!(
            err,
            SplitResidualError::SplitInvalid(SplitValidationError::ShardLimitExceeded {
                scope: ShardLimitScope::Global,
                ..
            })
        ),
        "expected ShardLimitExceeded(Global), got {err:?}"
    );
}

/// The active-run index controls worker-visible run discovery:
/// - `Initializing` runs are invisible (no index entry).
/// - `Active` runs appear after `register_shards` publishes the entry.
/// - Terminal transitions (`complete`, `fail`, `cancel`) delete the entry.
/// - `cancel_run` works for both `Initializing` and `Active` runs.
///
/// Also verifies idempotent replay of `cancel_run` and `complete_run`.
#[test]
fn active_run_index_hides_initializing_runs_and_unpublishes_terminal_runs() {
    let mut backend = test_coordinator();

    let config = RunConfig::try_new(CursorSemantics::Completed, 30, Some(5)).unwrap();
    let run_initializing = RunId::from_raw(0x2000);
    let run_active = RunId::from_raw(0x2001);
    let run_cancel_initializing = RunId::from_raw(0x2002);
    let run_cancel_active = RunId::from_raw(0x2003);
    let mut active = Vec::new();

    backend
        .create_run(now(1), test_tenant(), run_initializing, config)
        .expect("initializing run should be created");
    backend
        .list_active_runs_into(test_tenant(), &mut active)
        .expect("active run listing should succeed");
    assert!(active.is_empty(), "initializing runs must remain hidden");

    backend
        .create_run(now(2), test_tenant(), run_active, config)
        .expect("active run should be created");
    let active_manifest = [InitialShardInput::new(
        ShardId::from_raw(0x8100),
        ShardSpecRef::new(b"a", b"m", b""),
        CursorUpdate::initial(),
    )];
    let active_register = backend
        .register_shards(
            now(3),
            test_tenant(),
            run_active,
            &active_manifest,
            OpId::from_raw(1),
        )
        .expect("active run registration should succeed");
    assert!(active_register.is_executed());
    active.clear();
    backend
        .list_active_runs_into(test_tenant(), &mut active)
        .expect("active run listing should succeed");
    assert_eq!(active, vec![run_active]);

    backend
        .create_run(now(4), test_tenant(), run_cancel_initializing, config)
        .expect("cancellable initializing run should be created");
    let cancel_initializing = backend
        .cancel_run(
            now(5),
            test_tenant(),
            run_cancel_initializing,
            OpId::from_raw(2),
        )
        .expect("initializing cancel should succeed");
    assert!(cancel_initializing.is_executed());
    let cancel_initializing_replay = backend
        .cancel_run(
            now(6),
            test_tenant(),
            run_cancel_initializing,
            OpId::from_raw(2),
        )
        .expect("initializing cancel replay should succeed");
    assert!(cancel_initializing_replay.is_replay());

    backend
        .create_run(now(7), test_tenant(), run_cancel_active, config)
        .expect("cancellable active run should be created");
    let cancel_active_manifest = [InitialShardInput::new(
        ShardId::from_raw(0x8101),
        ShardSpecRef::new(b"m", b"z", b""),
        CursorUpdate::initial(),
    )];
    let cancel_active_register = backend
        .register_shards(
            now(8),
            test_tenant(),
            run_cancel_active,
            &cancel_active_manifest,
            OpId::from_raw(3),
        )
        .expect("active run registration should succeed");
    assert!(cancel_active_register.is_executed());
    active.clear();
    backend
        .list_active_runs_into(test_tenant(), &mut active)
        .expect("active run listing should succeed");
    assert_eq!(active, vec![run_active, run_cancel_active]);

    let cancel_active = backend
        .cancel_run(now(9), test_tenant(), run_cancel_active, OpId::from_raw(4))
        .expect("active cancel should succeed");
    assert!(cancel_active.is_executed());
    active.clear();
    backend
        .list_active_runs_into(test_tenant(), &mut active)
        .expect("active run listing should succeed");
    assert_eq!(active, vec![run_active]);

    let complete = backend
        .complete_run(now(10), test_tenant(), run_active, OpId::from_raw(5))
        .expect("complete_run should succeed");
    assert!(complete.is_executed());
    let complete_replay = backend
        .complete_run(now(11), test_tenant(), run_active, OpId::from_raw(5))
        .expect("complete_run replay should succeed");
    assert!(complete_replay.is_replay());

    active.clear();
    backend
        .list_active_runs_into(test_tenant(), &mut active)
        .expect("active run listing should succeed");
    assert!(
        active.is_empty(),
        "terminal runs must leave the active index"
    );
}

/// `fail_run` transitions an active run to `Failed`, removes its
/// active-run index entry, records the completion timestamp, and replays
/// idempotently with the same op_id.
#[test]
fn fail_run_removes_active_index_and_replays_idempotently() {
    let mut backend = test_coordinator();

    let config = RunConfig::try_new(CursorSemantics::Completed, 30, Some(5)).unwrap();
    let run = RunId::from_raw(0x3001);
    backend
        .create_run(now(1), test_tenant(), run, config)
        .expect("create_run should succeed");
    let manifest = [InitialShardInput::new(
        ShardId::from_raw(0x8200),
        ShardSpecRef::new(b"a", b"z", b""),
        CursorUpdate::initial(),
    )];
    let register = backend
        .register_shards(now(2), test_tenant(), run, &manifest, OpId::from_raw(11))
        .expect("register_shards should succeed");
    assert!(register.is_executed());

    let first = backend
        .fail_run(now(3), test_tenant(), run, OpId::from_raw(12))
        .expect("fail_run should succeed");
    assert!(first.is_executed());
    let replay = backend
        .fail_run(now(4), test_tenant(), run, OpId::from_raw(12))
        .expect("fail_run replay should succeed");
    assert!(replay.is_replay());

    let run_record = backend
        .get_run(test_tenant(), run)
        .expect("run lookup should succeed");
    assert_eq!(run_record.status(), RunStatus::Failed);
    assert_eq!(run_record.completed_at(), Some(now(3)));

    let mut active = Vec::new();
    backend
        .list_active_runs_into(test_tenant(), &mut active)
        .expect("active run listing should succeed");
    assert!(active.is_empty(), "failed runs must leave the active index");
}

/// GC deletes only `Initializing` runs created before the cutoff time,
/// leaving fresh initializing runs, active runs, and terminal runs intact.
#[test]
fn gc_stale_initializing_runs_deletes_only_old_orphans() {
    let mut backend = test_coordinator();

    let config = RunConfig::try_new(CursorSemantics::Completed, 30, Some(5)).unwrap();
    let run_old = RunId::from_raw(0x4001);
    let run_fresh = RunId::from_raw(0x4002);
    let run_active = RunId::from_raw(0x4003);
    let run_done = RunId::from_raw(0x4004);

    backend
        .create_run(now(1), test_tenant(), run_old, config)
        .expect("old run should be created");
    backend
        .create_run(now(100), test_tenant(), run_fresh, config)
        .expect("fresh run should be created");
    backend
        .create_run(now(2), test_tenant(), run_active, config)
        .expect("active run should be created");
    backend
        .create_run(now(3), test_tenant(), run_done, config)
        .expect("done run should be created");

    let active_manifest = [InitialShardInput::new(
        ShardId::from_raw(0x8300),
        ShardSpecRef::new(b"a", b"m", b""),
        CursorUpdate::initial(),
    )];
    let active_register = backend
        .register_shards(
            now(4),
            test_tenant(),
            run_active,
            &active_manifest,
            OpId::from_raw(21),
        )
        .expect("active registration should succeed");
    assert!(active_register.is_executed());

    let done_manifest = [InitialShardInput::new(
        ShardId::from_raw(0x8301),
        ShardSpecRef::new(b"m", b"z", b""),
        CursorUpdate::initial(),
    )];
    let done_register = backend
        .register_shards(
            now(5),
            test_tenant(),
            run_done,
            &done_manifest,
            OpId::from_raw(22),
        )
        .expect("done registration should succeed");
    assert!(done_register.is_executed());
    let done_complete = backend
        .complete_run(now(6), test_tenant(), run_done, OpId::from_raw(23))
        .expect("done completion should succeed");
    assert!(done_complete.is_executed());

    let mut deleted = Vec::new();
    backend
        .gc_stale_initializing_runs_into(test_tenant(), now(50), &mut deleted)
        .expect("gc should succeed");
    assert_eq!(deleted, vec![run_old]);

    let old_lookup = backend.get_run(test_tenant(), run_old);
    assert!(matches!(
        old_lookup,
        Err(gossip_coordination::GetRunError::RunNotFound)
    ));

    let fresh = backend
        .get_run(test_tenant(), run_fresh)
        .expect("fresh initializing run should remain");
    assert_eq!(fresh.status(), RunStatus::Initializing);

    let active_run = backend
        .get_run(test_tenant(), run_active)
        .expect("active run should remain");
    assert_eq!(active_run.status(), RunStatus::Active);

    let done_run = backend
        .get_run(test_tenant(), run_done)
        .expect("terminal run should remain");
    assert_eq!(done_run.status(), RunStatus::Done);

    let mut active = Vec::new();
    backend
        .list_active_runs_into(test_tenant(), &mut active)
        .expect("active run listing should succeed");
    assert_eq!(active, vec![run_active]);
}

/// GC decrements the tenant shard counter by the number of deleted shard
/// records when collecting a stale initializing run.
#[test]
fn gc_stale_initializing_runs_decrements_tenant_counter() {
    let mut backend = test_coordinator();
    let config = RunConfig::try_new(CursorSemantics::Completed, 30, Some(5)).unwrap();
    let run = RunId::from_raw(0x4F01);
    let shard = ShardId::from_raw(0x8F01);

    backend
        .create_run(now(1), test_tenant(), run, config)
        .expect("create_run should succeed");

    let spec = ShardSpec::with_range(b"a", b"z");
    let mut slab = ByteSlab::with_capacity(1024);
    let mut shard_record = ShardRecord::new_active_with_cursor(
        test_tenant(),
        run,
        shard,
        spec.as_ref(),
        CursorUpdate::initial(),
        CursorSemantics::Completed,
        &mut slab,
    )
    .expect("test shard record should be constructible");
    backend
        .test_seed_shard_record(&shard_record, &slab)
        .expect("seeding shard record should succeed");
    backend
        .test_seed_active_shard_index(test_tenant(), run, shard)
        .expect("seeding active-shard index should succeed");
    shard_record.deallocate_fields(&mut slab);
    slab.clear();

    backend
        .test_seed_tenant_shard_count(test_tenant(), 1)
        .expect("seeding tenant counter should succeed");

    let mut deleted = Vec::new();
    backend
        .gc_stale_initializing_runs_into(test_tenant(), now(2), &mut deleted)
        .expect("gc should succeed");
    assert_eq!(deleted, vec![run]);

    assert_eq!(
        backend
            .test_load_tenant_shard_count(test_tenant())
            .expect("counter load should succeed"),
        Some(0),
        "counter should decrement when GC deletes shard records"
    );
}

/// Unpark a shard that was manually seeded as `Parked` (via
/// `test_seed_shard_record`, since `park_shard` is unimplemented).
/// Verifies: shard transitions to `Active`, fence epoch is bumped,
/// owner binding is absent, cursor is preserved, park_reason is cleared,
/// and the operation replays idempotently.
#[test]
fn unpark_seeded_parked_shard_round_trip_against_local_etcd() {
    let mut backend = test_coordinator();

    let config = RunConfig::try_new(CursorSemantics::Completed, 30, Some(5)).unwrap();
    let run = RunId::from_raw(0x5001);
    let shard = ShardId::from_raw(0x8400);
    backend
        .create_run(now(1), test_tenant(), run, config)
        .expect("create_run should succeed");
    let manifest = [InitialShardInput::new(
        shard,
        ShardSpecRef::new(b"a", b"z", b""),
        CursorUpdate::new(b"k"),
    )];
    let register = backend
        .register_shards(now(2), test_tenant(), run, &manifest, OpId::from_raw(31))
        .expect("register_shards should succeed");
    assert!(register.is_executed());

    let key = ShardKey::new(run, shard);
    let mut parked = backend
        .test_load_shard_snapshot(test_tenant(), key)
        .expect("shard lookup should succeed")
        .expect("shard must exist");
    let fence_before = parked.fence_epoch;
    parked.status = ShardStatus::Parked;
    parked.park_reason = Some(ParkReason::TooManyErrors);
    parked.lease = None;
    parked.assert_invariants(parked.slab());
    backend
        .test_seed_shard_record(&parked, parked.slab())
        .expect("seed parked shard should succeed");

    let first = backend
        .unpark_shard(now(3), test_tenant(), key, OpId::from_raw(32))
        .expect("unpark should succeed");
    assert!(first.is_executed());
    let replay = backend
        .unpark_shard(now(4), test_tenant(), key, OpId::from_raw(32))
        .expect("unpark replay should succeed");
    assert!(replay.is_replay());

    let active = backend
        .test_load_shard_snapshot(test_tenant(), key)
        .expect("shard lookup should succeed")
        .expect("shard must exist");
    assert_eq!(active.status, ShardStatus::Active);
    assert!(
        active.fence_epoch > fence_before,
        "unpark must bump the fence"
    );
    assert!(active.lease.is_none(), "unparked shard must be unowned");
    assert_eq!(active.park_reason, None);
    assert_eq!(active.cursor.last_key(active.slab()), Some(b"k".as_slice()));
    assert!(
        backend
            .test_load_owner_binding(test_tenant(), key)
            .expect("owner lookup should succeed")
            .is_none(),
        "unpark should not create a new owner binding"
    );
}

// ---------------------------------------------------------------------------
// Test fixture helpers
// ---------------------------------------------------------------------------
//
// Deterministic identity constructors shared by all integration tests.
// Backend construction is handled by `test_etcd::test_coordinator*`.

/// Stable tenant identity used across all tests.
fn test_tenant() -> TenantId {
    TenantId::from_bytes([0x11; 32])
}

/// Stable alternate tenant identity used for cross-tenant limit tests.
fn other_tenant() -> TenantId {
    TenantId::from_bytes([0x22; 32])
}

/// Stable run identity used across all tests.
fn test_run() -> RunId {
    RunId::from_raw(0x0102_0304_0506_0708)
}

/// Stable alternate run identity for multi-run limit tests.
fn other_run() -> RunId {
    RunId::from_raw(0x1112_1314_1516_1718)
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

/// When worker A checkpoints and later loses ownership to worker B,
/// a stale checkpoint from worker A must be rejected and leave the
/// persisted cursor unchanged.
#[test]
fn stale_fence_checkpoint_rejected_after_reacquire() {
    let mut backend = test_coordinator();

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
    let lease_a = backend
        .acquire_and_restore_into(now(3), test_tenant(), key, test_worker(1), &mut scratch)
        .expect("worker A acquire should succeed")
        .lease;

    let checkpoint = backend
        .checkpoint(
            now(4),
            test_tenant(),
            &lease_a,
            &CursorUpdate::new(b"d"),
            OpId::from_raw(100),
        )
        .expect("worker A checkpoint should succeed");
    assert!(checkpoint.is_executed());

    let reacquire_at = lease_a.deadline().as_raw() + 1;
    let mut scratch_b = AcquireScratch::new();
    let lease_b = backend
        .acquire_and_restore_into(
            now(reacquire_at),
            test_tenant(),
            key,
            test_worker(2),
            &mut scratch_b,
        )
        .expect("worker B reacquire should succeed")
        .lease;
    assert!(
        lease_b.fence() > lease_a.fence(),
        "ownership transfer must bump the fence"
    );

    let err = backend
        .checkpoint(
            now(reacquire_at + 1),
            test_tenant(),
            &lease_a,
            &CursorUpdate::new(b"k"),
            OpId::from_raw(101),
        )
        .expect_err("stale checkpoint should fail");
    match err {
        CheckpointError::StaleFence { presented, current } => {
            assert_eq!(presented, lease_a.fence());
            assert_eq!(current, lease_b.fence());
        }
        other => panic!("expected StaleFence, got {other:?}"),
    }

    let shard = backend
        .test_load_shard_snapshot(test_tenant(), key)
        .expect("shard lookup should succeed")
        .expect("shard must exist");
    assert_eq!(shard.status, ShardStatus::Active);
    assert_eq!(shard.cursor.last_key(shard.slab()), Some(b"d".as_slice()));

    let owner = backend
        .test_load_owner_binding(test_tenant(), key)
        .expect("owner lookup should succeed")
        .expect("owner binding must exist");
    assert_eq!(owner.0, test_worker(2));
    assert_eq!(owner.1, lease_b.fence());
}

/// Retrying `checkpoint` with the same `(op_id, payload)` must replay
/// without appending a duplicate op-log entry.
#[test]
fn checkpoint_replay_remains_idempotent() {
    let mut backend = test_coordinator();

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
    let lease = backend
        .acquire_and_restore_into(now(3), test_tenant(), key, test_worker(7), &mut scratch)
        .expect("acquire should succeed")
        .lease;

    let cursor = CursorUpdate::new(b"m");
    let op = OpId::from_raw(100);
    let first = backend
        .checkpoint(now(4), test_tenant(), &lease, &cursor, op)
        .expect("first checkpoint should succeed");
    assert!(first.is_executed());

    let replay = backend
        .checkpoint(now(5), test_tenant(), &lease, &cursor, op)
        .expect("checkpoint replay should succeed");
    assert!(replay.is_replay());

    let shard = backend
        .test_load_shard_snapshot(test_tenant(), key)
        .expect("shard lookup should succeed")
        .expect("shard must exist");
    assert_eq!(shard.cursor.last_key(shard.slab()), Some(b"m".as_slice()));
    let checkpoint_entries = shard
        .op_log
        .iter()
        .filter(|entry| entry.op_id() == op)
        .count();
    assert_eq!(
        checkpoint_entries, 1,
        "replay must not duplicate op-log entries"
    );
}

/// After the etcd lease expires (owner key auto-deleted), checkpoint must
/// fail because the owner binding no longer matches the presented lease.
#[test]
fn lease_expiry_rejects_stale_checkpoint() {
    // Use a short owner-lease TTL so the etcd lease expires quickly.
    // etcd enforces a minimum TTL of ~5s in most configurations.
    let ttl_secs = 5;
    let mut backend = test_coordinator_with_ttl(ttl_secs);

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
fn concurrent_acquire_second_worker_gets_already_leased() {
    let mut backend = test_coordinator();

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

// ---------------------------------------------------------------------------
// Integration tests: split error paths
// ---------------------------------------------------------------------------

/// A split plan whose child count exceeds the backend's `max_children_per_op`
/// must be rejected with `BackendChildLimitExceeded` before any etcd writes.
/// This is a pre-validation gate that runs before shared split validation.
#[test]
fn split_replace_rejects_fanout_above_backend_cap() {
    let mut backend = test_coordinator_with_tuning(60, 8, 2);

    let run_config = RunConfig::try_new(CursorSemantics::Completed, 30, Some(5)).unwrap();
    backend
        .create_run(now(1), test_tenant(), test_run(), run_config)
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

    // Build a 3-child plan (exceeds cap of 2).
    let s1 = ShardSpec::with_range(b"a", b"k");
    let s2 = ShardSpec::with_range(b"k", b"r");
    let s3 = ShardSpec::with_range(b"r", b"z");
    let plan = SplitReplacePlan::try_new(vec![
        SplitReplaceChild::new(s1.as_ref(), CursorUpdate::initial()),
        SplitReplaceChild::new(s2.as_ref(), CursorUpdate::initial()),
        SplitReplaceChild::new(s3.as_ref(), CursorUpdate::initial()),
    ])
    .expect("plan should be valid");

    let err = backend
        .split_replace(
            now(4),
            test_tenant(),
            &acquire.lease,
            plan,
            OpId::from_raw(200),
        )
        .expect_err("split with 3 children should be rejected by cap of 2");

    assert!(
        matches!(
            err,
            SplitReplaceError::SplitInvalid(SplitValidationError::BackendChildLimitExceeded {
                requested: 3,
                backend_max: 2,
            })
        ),
        "expected BackendChildLimitExceeded, got {err:?}"
    );
}

/// After a successful split_replace, the parent is in terminal `Split`
/// status. A second split with a different op_id must be rejected with
/// `ShardTerminal` — only idempotent replay (same op_id) is allowed.
#[test]
fn split_replace_rejects_terminal_shard() {
    let mut backend = test_coordinator();

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

    // First split succeeds — parent becomes terminal.
    let left = ShardSpec::with_range(b"a", b"m");
    let right = ShardSpec::with_range(b"m", b"z");
    let plan = SplitReplacePlan::try_new(vec![
        SplitReplaceChild::new(left.as_ref(), CursorUpdate::initial()),
        SplitReplaceChild::new(right.as_ref(), CursorUpdate::initial()),
    ])
    .unwrap();

    let _ = backend
        .split_replace(
            now(4),
            test_tenant(),
            &acquire.lease,
            plan.clone(),
            OpId::from_raw(200),
        )
        .expect("first split should succeed");

    // Second split with a different op_id must be rejected.
    let err = backend
        .split_replace(
            now(5),
            test_tenant(),
            &acquire.lease,
            plan,
            OpId::from_raw(201),
        )
        .expect_err("splitting a terminal shard should fail");

    assert!(
        matches!(
            err,
            SplitReplaceError::ShardTerminal {
                status: ShardStatus::Split,
                ..
            }
        ),
        "expected ShardTerminal(Split), got {err:?}"
    );
}

/// When worker A's lease deadline passes and worker B acquires the shard
/// (bumping the fence epoch), worker A's original lease is stale. A split
/// attempt using worker A's lease must fail with `StaleFence`.
#[test]
fn split_replace_rejects_stale_fence() {
    let mut backend = test_coordinator();

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

    // Worker A acquires.
    let acquire_a = backend
        .acquire_and_restore_into(now(3), test_tenant(), key, test_worker(1), &mut scratch)
        .expect("worker A acquire should succeed");

    // Simulate lease deadline passing; worker B acquires (bumps fence).
    let deadline = acquire_a.lease.deadline().as_raw() + 1;
    let mut scratch_b = AcquireScratch::new();
    let _acquire_b = backend
        .acquire_and_restore_into(
            now(deadline),
            test_tenant(),
            key,
            test_worker(2),
            &mut scratch_b,
        )
        .expect("worker B acquire should succeed");

    // Worker A's old lease is now stale.
    let left = ShardSpec::with_range(b"a", b"m");
    let right = ShardSpec::with_range(b"m", b"z");
    let plan = SplitReplacePlan::try_new(vec![
        SplitReplaceChild::new(left.as_ref(), CursorUpdate::initial()),
        SplitReplaceChild::new(right.as_ref(), CursorUpdate::initial()),
    ])
    .unwrap();

    let err = backend
        .split_replace(
            now(deadline + 1),
            test_tenant(),
            &acquire_a.lease,
            plan,
            OpId::from_raw(300),
        )
        .expect_err("split with stale lease should fail");

    assert!(
        matches!(err, SplitReplaceError::StaleFence { .. }),
        "expected StaleFence, got {err:?}"
    );
}

/// If the owner binding disappears after the split plan is computed but
/// before the atomic `split_replace` transaction commits, the backend
/// must publish no child records or active-index entries.
#[test]
fn split_replace_abort_does_not_publish_partial_children() {
    let mut backend = test_coordinator();

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
    let lease = backend
        .acquire_and_restore_into(now(3), test_tenant(), key, test_worker(7), &mut scratch)
        .expect("acquire should succeed")
        .lease;

    let left = ShardSpec::with_range(b"a", b"m");
    let right = ShardSpec::with_range(b"m", b"z");
    let plan = SplitReplacePlan::try_new(vec![
        SplitReplaceChild::new(left.as_ref(), CursorUpdate::initial()),
        SplitReplaceChild::new(right.as_ref(), CursorUpdate::initial()),
    ])
    .expect("split plan should be valid");

    let op = OpId::from_raw(700);
    let child0 = derive_split_shard_id(test_run(), test_shard(), op, DerivedShardKind::Child, 0);
    let child1 = derive_split_shard_id(test_run(), test_shard(), op, DerivedShardKind::Child, 1);

    backend.test_arm_fault(EtcdTestFault::DropOwnerBeforeNextSplitReplaceTxn);
    let err = backend
        .split_replace(now(4), test_tenant(), &lease, plan, op)
        .expect_err("fault-injected split_replace should fail");
    assert!(matches!(err, SplitReplaceError::StaleFence { .. }));

    let parent = backend
        .test_load_shard_snapshot(test_tenant(), key)
        .expect("parent lookup should succeed")
        .expect("parent shard must exist");
    assert_eq!(parent.status, ShardStatus::Active);
    assert_eq!(parent.spec.key_range_start(parent.slab()), b"a");
    assert_eq!(parent.spec.key_range_end(parent.slab()), b"z");
    assert_eq!(parent.spawned.len(), 0);

    assert!(
        backend
            .test_active_shard_index_exists(test_tenant(), key)
            .expect("parent index lookup should succeed"),
        "parent active-index must remain published"
    );

    for child in [child0, child1] {
        let child_key = ShardKey::new(test_run(), child);
        assert!(
            backend
                .test_load_shard_snapshot(test_tenant(), child_key)
                .expect("child lookup should succeed")
                .is_none(),
            "child record must not be published on aborted split"
        );
        assert!(
            !backend
                .test_active_shard_index_exists(test_tenant(), child_key)
                .expect("child index lookup should succeed"),
            "child active-index must not be published on aborted split"
        );
    }
}

// ---------------------------------------------------------------------------
// Integration tests: derived-ID collision detection
// ---------------------------------------------------------------------------

/// When a derived child shard ID collides with an already-existing shard
/// key in etcd, the CAS transaction fails on the `compare_absent` guard
/// for every retry. After exhausting retries, the backend probes each
/// derived child key and must return `DerivedIdCollision` rather than
/// panicking.
///
/// This test simulates the collision by pre-registering a shard with the
/// exact ID that `derive_split_shard_id` will compute.
#[test]
fn split_replace_returns_collision_when_child_key_exists() {
    let mut backend = test_coordinator();

    let config = RunConfig::try_new(CursorSemantics::Completed, 30, Some(5)).unwrap();
    backend
        .create_run(now(1), test_tenant(), test_run(), config)
        .expect("create_run should succeed");

    let parent_manifest = [InitialShardInput::new(
        test_shard(),
        ShardSpecRef::new(b"a", b"z", b""),
        CursorUpdate::initial(),
    )];
    let _ = backend
        .register_shards(
            now(2),
            test_tenant(),
            test_run(),
            &parent_manifest,
            OpId::from_raw(99),
        )
        .expect("parent registration should succeed");

    // Pre-compute the derived child ID that split_replace will try to
    // create. The parent's spawned list is empty (len=0) so the first
    // child's index is 0.
    let split_op = OpId::from_raw(500);
    let collision_id = derive_split_shard_id(
        test_run(),
        test_shard(),
        split_op,
        DerivedShardKind::Child,
        0,
    );

    // Pre-register a shard with the collision ID so the key already
    // exists in etcd before the split is attempted.
    let collision_spec = ShardSpec::with_range(b"x", b"y");
    let mut collision_slab = ByteSlab::with_capacity(1024);
    let mut collision_record = ShardRecord::new_split_child(
        test_tenant(),
        test_run(),
        collision_id,
        collision_spec.as_ref(),
        CursorUpdate::initial(),
        CursorSemantics::Completed,
        test_shard(),
        &mut collision_slab,
    )
    .expect("collision shard seed should fit in slab");
    backend
        .test_seed_shard_record(&collision_record, &collision_slab)
        .expect("collision shard seed should succeed");
    backend
        .test_seed_active_shard_index(test_tenant(), test_run(), collision_id)
        .expect("collision active-index seed should succeed");
    collision_record.deallocate_fields(&mut collision_slab);
    collision_slab.clear();

    // Acquire the parent for splitting.
    let key = ShardKey::new(test_run(), test_shard());
    let mut scratch = AcquireScratch::new();
    let acquire = backend
        .acquire_and_restore_into(now(4), test_tenant(), key, test_worker(7), &mut scratch)
        .expect("acquire should succeed");

    let left = ShardSpec::with_range(b"a", b"m");
    let right = ShardSpec::with_range(b"m", b"z");
    let plan = SplitReplacePlan::try_new(vec![
        SplitReplaceChild::new(left.as_ref(), CursorUpdate::initial()),
        SplitReplaceChild::new(right.as_ref(), CursorUpdate::initial()),
    ])
    .expect("split plan should be valid");

    let err = backend
        .split_replace(now(5), test_tenant(), &acquire.lease, plan, split_op)
        .expect_err("split_replace should detect the child-key collision");

    assert!(
        matches!(
            err,
            SplitReplaceError::SplitInvalid(SplitValidationError::DerivedIdCollision { .. })
        ),
        "expected DerivedIdCollision, got {err:?}"
    );
}

/// Same collision detection as `split_replace_returns_collision_when_child_key_exists`,
/// but for the `split_residual` path. Pre-registers a shard with the
/// derived residual ID and verifies `DerivedIdCollision` is returned.
#[test]
fn split_residual_returns_collision_when_residual_key_exists() {
    let mut backend = test_coordinator();

    let config = RunConfig::try_new(CursorSemantics::Completed, 30, Some(5)).unwrap();
    backend
        .create_run(now(1), test_tenant(), test_run(), config)
        .expect("create_run should succeed");

    let parent_manifest = [InitialShardInput::new(
        test_shard(),
        ShardSpecRef::new(b"a", b"z", b""),
        CursorUpdate::initial(),
    )];
    let _ = backend
        .register_shards(
            now(2),
            test_tenant(),
            test_run(),
            &parent_manifest,
            OpId::from_raw(99),
        )
        .expect("parent registration should succeed");

    // Pre-compute the derived residual ID. The parent's spawned list is
    // empty (len=0) so index=0.
    let split_op = OpId::from_raw(600);
    let collision_id = derive_split_shard_id(
        test_run(),
        test_shard(),
        split_op,
        DerivedShardKind::Residual,
        0,
    );

    // Pre-register a shard with the residual collision ID.
    let collision_spec = ShardSpec::with_range(b"x", b"y");
    let mut collision_slab = ByteSlab::with_capacity(1024);
    let mut collision_record = ShardRecord::new_split_child(
        test_tenant(),
        test_run(),
        collision_id,
        collision_spec.as_ref(),
        CursorUpdate::initial(),
        CursorSemantics::Completed,
        test_shard(),
        &mut collision_slab,
    )
    .expect("collision shard seed should fit in slab");
    backend
        .test_seed_shard_record(&collision_record, &collision_slab)
        .expect("collision shard seed should succeed");
    backend
        .test_seed_active_shard_index(test_tenant(), test_run(), collision_id)
        .expect("collision active-index seed should succeed");
    collision_record.deallocate_fields(&mut collision_slab);
    collision_slab.clear();

    // Acquire the parent and checkpoint it (split_residual requires a
    // cursor checkpoint).
    let key = ShardKey::new(test_run(), test_shard());
    let mut scratch = AcquireScratch::new();
    let acquire = backend
        .acquire_and_restore_into(now(4), test_tenant(), key, test_worker(7), &mut scratch)
        .expect("acquire should succeed");

    let _ = backend
        .checkpoint(
            now(5),
            test_tenant(),
            &acquire.lease,
            &CursorUpdate::new(b"f"),
            OpId::from_raw(101),
        )
        .expect("checkpoint should succeed");

    let parent_new = ShardSpec::with_range(b"a", b"m");
    let residual_spec = ShardSpec::with_range(b"m", b"z");
    let plan = SplitResidualPlan::try_new(parent_new.as_ref(), residual_spec.as_ref())
        .expect("residual split plan should be valid");

    let err = backend
        .split_residual(now(6), test_tenant(), &acquire.lease, plan, split_op)
        .expect_err("split_residual should detect the residual-key collision");

    assert!(
        matches!(
            err,
            SplitResidualError::SplitInvalid(SplitValidationError::DerivedIdCollision { .. })
        ),
        "expected DerivedIdCollision, got {err:?}"
    );
}

/// The shard op-log is a bounded FIFO (16 entries). After enough
/// subsequent checkpoints evict the `split_residual` entry, retrying
/// with the same op_id must still succeed via the fallback path:
/// scanning the parent's permanent `spawned` lineage list to recover
/// the derived residual ID. This verifies the two-tier replay
/// mechanism (op-log first, spawned lineage second).
#[test]
fn split_residual_replay_via_spawned_after_oplog_eviction() {
    let mut backend = test_coordinator();

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

    // Checkpoint so the cursor is within the new parent's key range.
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

    // Perform split_residual with op_id X.
    let parent_new = ShardSpec::with_range(b"a", b"m");
    let residual = ShardSpec::with_range(b"m", b"z");
    let plan = SplitResidualPlan::try_new(parent_new.as_ref(), residual.as_ref())
        .expect("residual split plan should be valid");

    let split_op = OpId::from_raw(201);
    let first = backend
        .split_residual(
            now(5),
            test_tenant(),
            &acquire.lease,
            plan.clone(),
            split_op,
        )
        .expect("split_residual should succeed");
    assert!(first.is_executed());

    // Push 17 checkpoint operations with distinct OpIds to evict the
    // split_residual entry from the 16-entry FIFO op-log.
    for i in 1..=17u64 {
        let cursor_key = [
            b'l',
            u8::try_from(i).expect("checkpoint index must fit in u8"),
        ];
        let _ = backend
            .checkpoint(
                now(10 + i),
                test_tenant(),
                &acquire.lease,
                &CursorUpdate::new(&cursor_key),
                OpId::from_raw(300 + i),
            )
            .expect("eviction checkpoint should succeed");
    }

    // Retry split_residual with the same op_id. The op-log entry is gone,
    // but the spawned list still contains the derived residual ID.
    let replay = backend
        .split_residual(now(30), test_tenant(), &acquire.lease, plan, split_op)
        .expect("split_residual replay should succeed after op-log eviction");
    assert!(
        replay.is_replay(),
        "expected Replayed after op-log eviction, got Executed"
    );
    assert_eq!(
        replay.as_ref().residual,
        first.as_ref().residual,
        "replayed residual ID must match the original"
    );
}

/// If the owner binding disappears after the residual split is planned but
/// before the transaction commits, the parent state must remain unchanged
/// and the residual shard must not be published.
#[test]
fn split_residual_abort_does_not_publish_partial_residual() {
    let mut backend = test_coordinator();

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
    let lease = backend
        .acquire_and_restore_into(now(3), test_tenant(), key, test_worker(7), &mut scratch)
        .expect("acquire should succeed")
        .lease;

    let checkpoint = backend
        .checkpoint(
            now(4),
            test_tenant(),
            &lease,
            &CursorUpdate::new(b"f"),
            OpId::from_raw(710),
        )
        .expect("checkpoint should succeed");
    assert!(checkpoint.is_executed());

    let parent_new = ShardSpec::with_range(b"a", b"m");
    let residual = ShardSpec::with_range(b"m", b"z");
    let plan = SplitResidualPlan::try_new(parent_new.as_ref(), residual.as_ref())
        .expect("residual split plan should be valid");

    let op = OpId::from_raw(711);
    let residual_id =
        derive_split_shard_id(test_run(), test_shard(), op, DerivedShardKind::Residual, 0);

    backend.test_arm_fault(EtcdTestFault::DropOwnerBeforeNextSplitResidualTxn);
    let err = backend
        .split_residual(now(5), test_tenant(), &lease, plan, op)
        .expect_err("fault-injected split_residual should fail");
    assert!(matches!(err, SplitResidualError::StaleFence { .. }));

    let parent = backend
        .test_load_shard_snapshot(test_tenant(), key)
        .expect("parent lookup should succeed")
        .expect("parent shard must exist");
    assert_eq!(parent.status, ShardStatus::Active);
    assert_eq!(parent.spec.key_range_start(parent.slab()), b"a");
    assert_eq!(parent.spec.key_range_end(parent.slab()), b"z");
    assert_eq!(parent.cursor.last_key(parent.slab()), Some(b"f".as_slice()));
    assert_eq!(parent.spawned.len(), 0);

    assert!(
        backend
            .test_active_shard_index_exists(test_tenant(), key)
            .expect("parent index lookup should succeed"),
        "parent active-index must remain published"
    );

    let residual_key = ShardKey::new(test_run(), residual_id);
    assert!(
        backend
            .test_load_shard_snapshot(test_tenant(), residual_key)
            .expect("residual lookup should succeed")
            .is_none(),
        "residual record must not be published on aborted split"
    );
    assert!(
        !backend
            .test_active_shard_index_exists(test_tenant(), residual_key)
            .expect("residual index lookup should succeed"),
        "residual active-index must not be published on aborted split"
    );
}

/// With `max_children_per_op = 1`, any multi-child split plan is rejected.
/// Verifies that the rejection is clean: the parent shard remains `Active`
/// with the original owner binding unchanged (no partial mutation).
#[test]
fn split_replace_rejects_over_cap_max_children_per_op() {
    // max_children_per_op = 1: any multi-child split must be rejected.
    let mut backend = test_coordinator_with_tuning(60, 8, 1);

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

    // Two-child split plan exceeds the cap of 1.
    let left = ShardSpec::with_range(b"a", b"m");
    let right = ShardSpec::with_range(b"m", b"z");
    let plan = SplitReplacePlan::try_new(vec![
        SplitReplaceChild::new(left.as_ref(), CursorUpdate::initial()),
        SplitReplaceChild::new(right.as_ref(), CursorUpdate::initial()),
    ])
    .expect("split plan should be valid");

    let err = backend
        .split_replace(
            now(4),
            test_tenant(),
            &acquire.lease,
            plan,
            OpId::from_raw(200),
        )
        .expect_err("two-child split should be rejected by cap of 1");

    assert!(
        matches!(
            err,
            SplitReplaceError::SplitInvalid(SplitValidationError::BackendChildLimitExceeded {
                requested: 2,
                backend_max: 1,
            })
        ),
        "expected BackendChildLimitExceeded {{ requested: 2, backend_max: 1 }}, got {err:?}"
    );

    // Parent must still be Active with the original owner binding.
    let parent = backend
        .test_load_shard_snapshot(test_tenant(), key)
        .expect("parent lookup should succeed")
        .expect("parent must still exist");
    assert_eq!(
        parent.status,
        ShardStatus::Active,
        "parent must remain Active after rejected split"
    );
    let owner = backend
        .test_load_owner_binding(test_tenant(), key)
        .expect("owner lookup should succeed")
        .expect("owner binding must still exist");
    assert_eq!(
        owner.0,
        test_worker(7),
        "owner must still be the original worker"
    );
    assert_eq!(
        owner.1,
        acquire.lease.fence(),
        "fence epoch must be unchanged"
    );
}

// ---------------------------------------------------------------------------
// shard_limit_violation unit tests (pure, no etcd required)
// ---------------------------------------------------------------------------

/// Both backends count ALL persisted shard records (including terminal
/// Split-status parents). After split_replace the parent record stays
/// in storage and N children are added, so the total stored count grows
/// by N. The `additional` argument to `shard_limit_violation` must be N
/// (child count), matching the in-memory backend's accounting.
///
/// Scenario: 10 persisted records (including parent), max=11, 2-way split.
/// Post-split stored count = 10 + 2 = 12 > 11, so the split is rejected.
#[test]
fn shard_limit_split_replace_uses_full_child_count() {
    use gossip_coordination::{ShardCountSnapshot, shard_limit_violation};

    let num_children: usize = 2;
    let max_per_tenant: usize = 11;
    let max_total: usize = 100;

    let counts = ShardCountSnapshot {
        tenant: 10,
        total: 10,
    };

    // Post-split stored count = 10 + 2 = 12 > 11, must reject.
    let v = shard_limit_violation(counts, num_children, max_per_tenant, max_total)
        .expect("additional=N (child count) must reject when post-split stored count exceeds max");
    assert_eq!(v.current, 10);
    assert_eq!(v.additional, num_children);
    assert_eq!(v.max, max_per_tenant);
    assert_eq!(v.scope, ShardLimitScope::PerTenant);
}

/// Global-limit variant of the full-child-count test.
///
/// Scenario: 49 persisted records, max_total=51, 3-way split.
/// Post-split stored count = 49 + 3 = 52 > 51, so the split is rejected.
#[test]
fn shard_limit_split_replace_uses_full_child_count_global() {
    use gossip_coordination::{ShardCountSnapshot, shard_limit_violation};

    let num_children: usize = 3;
    let max_per_tenant: usize = 1000;
    let max_total: usize = 51;

    let counts = ShardCountSnapshot {
        tenant: 49,
        total: 49,
    };

    let v = shard_limit_violation(counts, num_children, max_per_tenant, max_total).expect(
        "additional=N (child count) must reject when post-split stored count exceeds global max",
    );
    assert_eq!(v.current, 49);
    assert_eq!(v.additional, num_children);
    assert_eq!(v.max, max_total);
    assert_eq!(v.scope, ShardLimitScope::Global);
}

/// A 1-way split (one child replaces the parent) adds 1 record to
/// storage. When the tenant is already at ceiling - 1, adding 1 lands
/// exactly at the limit and must be allowed.
#[test]
fn shard_limit_one_way_split_at_ceiling_is_allowed() {
    use gossip_coordination::{ShardCountSnapshot, shard_limit_violation};

    let num_children: usize = 1;
    let counts = ShardCountSnapshot {
        tenant: 10,
        total: 10,
    };
    let result = shard_limit_violation(
        counts,
        num_children, // 1 child added to storage
        11,           // tenant ceiling: 10 + 1 = 11, exactly at limit
        11,           // global ceiling: same
    );
    assert!(
        result.is_none(),
        "1-way split landing exactly at ceiling must be allowed"
    );
}

/// A 3-way split that pushes post-split count one past the tenant limit.
/// Verifies the violation carries exact field values for the +1 overshoot.
#[test]
fn shard_limit_three_way_split_just_over_tenant_limit() {
    use gossip_coordination::{ShardCountSnapshot, ShardLimitViolation, shard_limit_violation};

    let num_children: usize = 3;
    // 10 persisted. 3-way split → 3 children added. Post-split = 13.
    // Ceiling is 12 so 10 + 3 = 13 > 12 → violation by exactly 1.
    let counts = ShardCountSnapshot {
        tenant: 10,
        total: 10,
    };
    let v = shard_limit_violation(counts, num_children, 12, 100)
        .expect("3-way split exceeding tenant limit by 1 must be rejected");
    assert_eq!(
        v,
        ShardLimitViolation {
            current: 10,
            additional: 3,
            max: 12,
            scope: ShardLimitScope::PerTenant,
        }
    );
}

// ---------------------------------------------------------------------------
// Run lifecycle — terminal-state and wrong-status guards
// ---------------------------------------------------------------------------

/// `complete_run` requires `Active` status — must reject `Initializing` runs
/// with `WrongStatus`.
#[test]
fn complete_run_rejects_initializing_run() {
    let mut backend = test_coordinator();
    let config = RunConfig::try_new(CursorSemantics::Completed, 30, Some(5)).unwrap();
    let run = RunId::from_raw(0xF010);
    backend
        .create_run(now(1), test_tenant(), run, config)
        .expect("create_run should succeed");

    let err = backend
        .complete_run(now(2), test_tenant(), run, OpId::from_raw(1))
        .expect_err("complete_run on Initializing run must fail");
    assert!(
        matches!(
            err,
            RunTransitionError::WrongStatus {
                status: RunStatus::Initializing,
                target: RunStatus::Done,
            }
        ),
        "expected WrongStatus(Initializing, Done), got {err:?}"
    );
}

/// `fail_run` requires `Active` status — must reject `Initializing` runs
/// with `WrongStatus`.
#[test]
fn fail_run_rejects_initializing_run() {
    let mut backend = test_coordinator();
    let config = RunConfig::try_new(CursorSemantics::Completed, 30, Some(5)).unwrap();
    let run = RunId::from_raw(0xF011);
    backend
        .create_run(now(1), test_tenant(), run, config)
        .expect("create_run should succeed");

    let err = backend
        .fail_run(now(2), test_tenant(), run, OpId::from_raw(1))
        .expect_err("fail_run on Initializing run must fail");
    assert!(
        matches!(
            err,
            RunTransitionError::WrongStatus {
                status: RunStatus::Initializing,
                target: RunStatus::Failed,
            }
        ),
        "expected WrongStatus(Initializing, Failed), got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Unpark — wrong-status guard
// ---------------------------------------------------------------------------

/// `unpark_shard` requires `Parked` status — must reject `Active` shards
/// with `NotParked`.
#[test]
fn unpark_shard_rejects_active_shard() {
    let mut backend = test_coordinator();
    let config = RunConfig::try_new(CursorSemantics::Completed, 30, Some(5)).unwrap();
    let run = RunId::from_raw(0xF012);
    let shard = ShardId::from_raw(0x1234);
    backend
        .create_run(now(1), test_tenant(), run, config)
        .expect("create_run should succeed");

    let manifest = [InitialShardInput::new(
        shard,
        ShardSpecRef::new(b"a", b"z", b""),
        CursorUpdate::initial(),
    )];
    let _ = backend
        .register_shards(now(2), test_tenant(), run, &manifest, OpId::from_raw(99))
        .expect("register_shards should succeed");

    let key = ShardKey::new(run, shard);
    let err = backend
        .unpark_shard(now(3), test_tenant(), key, OpId::from_raw(1))
        .expect_err("unpark on Active shard must fail");
    assert!(
        matches!(
            err,
            UnparkError::NotParked {
                status: ShardStatus::Active
            }
        ),
        "expected NotParked(Active), got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Terminal re-transition — different op_id must yield RunTerminal
// ---------------------------------------------------------------------------

/// After a successful `complete_run`, calling `fail_run` with a different
/// op_id must return `RunTerminal` (not `WrongStatus`).
#[test]
fn complete_then_fail_with_different_op_id_returns_run_terminal() {
    let mut backend = test_coordinator();
    let config = RunConfig::try_new(CursorSemantics::Completed, 30, Some(5)).unwrap();
    let run = RunId::from_raw(0xF013);
    backend
        .create_run(now(1), test_tenant(), run, config)
        .expect("create_run should succeed");

    let manifest = [InitialShardInput::new(
        ShardId::from_raw(0x2001),
        ShardSpecRef::new(b"a", b"z", b""),
        CursorUpdate::initial(),
    )];
    let _ = backend
        .register_shards(now(2), test_tenant(), run, &manifest, OpId::from_raw(99))
        .expect("register_shards should succeed");

    let complete = backend
        .complete_run(now(3), test_tenant(), run, OpId::from_raw(1))
        .expect("complete_run should succeed");
    assert!(complete.is_executed());

    let err = backend
        .fail_run(now(4), test_tenant(), run, OpId::from_raw(2))
        .expect_err("fail_run on Done run must fail");
    assert!(
        matches!(
            err,
            RunTransitionError::RunTerminal {
                status: RunStatus::Done
            }
        ),
        "expected RunTerminal(Done), got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Unpark — terminal-run guard
// ---------------------------------------------------------------------------

/// Unparking a shard whose run has been completed must return
/// `RunTerminal`, regardless of the shard's own status.
#[test]
fn unpark_shard_rejects_terminal_run() {
    let mut backend = test_coordinator();
    let config = RunConfig::try_new(CursorSemantics::Completed, 30, Some(5)).unwrap();
    let run = RunId::from_raw(0xF014);
    let shard = ShardId::from_raw(0x3001);
    backend
        .create_run(now(1), test_tenant(), run, config)
        .expect("create_run should succeed");

    let manifest = [InitialShardInput::new(
        shard,
        ShardSpecRef::new(b"a", b"z", b""),
        CursorUpdate::initial(),
    )];
    let _ = backend
        .register_shards(now(2), test_tenant(), run, &manifest, OpId::from_raw(99))
        .expect("register_shards should succeed");

    let _ = backend
        .complete_run(now(3), test_tenant(), run, OpId::from_raw(1))
        .expect("complete_run should succeed");

    let key = ShardKey::new(run, shard);
    let err = backend
        .unpark_shard(now(4), test_tenant(), key, OpId::from_raw(2))
        .expect_err("unpark on terminal run must fail");
    assert!(
        matches!(
            err,
            UnparkError::RunTerminal {
                status: RunStatus::Done
            }
        ),
        "expected RunTerminal(Done), got {err:?}"
    );
}

// ---------------------------------------------------------------------------
// Integration tests: concurrent CAS contention
// ---------------------------------------------------------------------------
//
// These tests exercise the real TOCTOU CAS retry paths by running multiple
// EtcdCoordinator instances (each in its own thread with its own Tokio
// runtime) against the same shared etcd keyspace. They validate that
// revision-based CAS guards correctly serialize concurrent operations.
//
// Pattern: std::thread::scope + Barrier to synchronize N workers.

/// Multiple workers race to acquire the same unowned shard. Exactly one
/// must win; all others must receive `AlreadyLeased`. Each worker runs
/// in a separate thread with its own EtcdCoordinator targeting the same
/// namespace.
#[test]
fn concurrent_acquire_exactly_one_wins() {
    const N_WORKERS: usize = 5;
    let namespace = contention_namespace();

    // Phase 1: Setup (single thread seeds the run and shard).
    let run = RunId::from_raw(0xCA01);
    let shard = ShardId::from_raw(0xCA02);
    let config = RunConfig::try_new(CursorSemantics::Completed, 30, Some(5)).unwrap();
    {
        let mut setup = test_coordinator_in_namespace(&namespace);
        setup
            .create_run(now(1), test_tenant(), run, config)
            .expect("create_run should succeed");
        let manifest = [InitialShardInput::new(
            shard,
            ShardSpecRef::new(b"a", b"z", b""),
            CursorUpdate::initial(),
        )];
        let reg = setup
            .register_shards(now(2), test_tenant(), run, &manifest, OpId::from_raw(1))
            .expect("register_shards should succeed");
        assert!(reg.is_executed());
    } // Drop the setup coordinator (and its runtime) before spawning threads.

    // Phase 2: Contention (N threads race to acquire the same shard).
    let key = ShardKey::new(run, shard);
    let barrier = std::sync::Barrier::new(N_WORKERS);
    let results: Vec<Result<_, AcquireError>> = std::thread::scope(|s| {
        let handles: Vec<_> = (1..=N_WORKERS)
            .map(|i| {
                let b = &barrier;
                let ns = &namespace;
                s.spawn(move || {
                    let mut coord = test_coordinator_in_namespace(ns);
                    let mut scratch = AcquireScratch::new();
                    b.wait();
                    coord
                        .acquire_and_restore_into(
                            now(10),
                            test_tenant(),
                            key,
                            test_worker(i as u64),
                            &mut scratch,
                        )
                        .map(|view| view.lease)
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });

    // Phase 3: Assert exactly one winner, N-1 AlreadyLeased.
    let successes = results.iter().filter(|r| r.is_ok()).count();
    let already_leased = results
        .iter()
        .filter(|r| matches!(r, Err(AcquireError::AlreadyLeased { .. })))
        .count();
    assert_eq!(successes, 1, "exactly one worker must win the acquire race");
    assert_eq!(
        already_leased,
        N_WORKERS - 1,
        "all other workers must get AlreadyLeased"
    );
}

/// Two threads race to register shards for the same tenant with a tight
/// per-tenant limit. The CAS guard on the per-tenant counter key must
/// serialize the registrations, preventing both from exceeding the limit.
///
/// Setup: limit = 5 shards per tenant. Thread A registers 3 shards,
/// thread B registers 3 shards. Total would be 6 > 5, so at least one
/// must be rejected with `ShardLimitExceeded`.
#[test]
fn concurrent_register_shards_respects_per_tenant_limit() {
    let namespace = contention_namespace();

    let run_a = RunId::from_raw(0xCB01);
    let run_b = RunId::from_raw(0xCB02);
    let config = RunConfig::try_new(CursorSemantics::Completed, 30, Some(5)).unwrap();

    // Phase 1: Setup — create two runs under the same tenant. Use a
    // setup coordinator with tight limits to create runs (runs don't
    // count toward shard limits, only shards do).
    {
        let mut setup = test_coordinator_in_namespace_with_limits(&namespace, 5, 100);
        setup
            .create_run(now(1), test_tenant(), run_a, config)
            .expect("create_run A should succeed");
        setup
            .create_run(now(2), test_tenant(), run_b, config)
            .expect("create_run B should succeed");
    }

    // Phase 2: Two threads race to register 3 shards each.
    let barrier = std::sync::Barrier::new(2);
    let (result_a, result_b) = std::thread::scope(|s| {
        let b = &barrier;
        let ns = &namespace;

        let ha = s.spawn(move || {
            let mut coord = test_coordinator_in_namespace_with_limits(ns, 5, 100);
            let manifest = [
                InitialShardInput::new(
                    ShardId::from_raw(0xA001),
                    ShardSpecRef::new(b"\x10", b"\x19", b""),
                    CursorUpdate::initial(),
                ),
                InitialShardInput::new(
                    ShardId::from_raw(0xA002),
                    ShardSpecRef::new(b"\x20", b"\x29", b""),
                    CursorUpdate::initial(),
                ),
                InitialShardInput::new(
                    ShardId::from_raw(0xA003),
                    ShardSpecRef::new(b"\x30", b"\x39", b""),
                    CursorUpdate::initial(),
                ),
            ];
            b.wait();
            coord.register_shards(now(10), test_tenant(), run_a, &manifest, OpId::from_raw(10))
        });
        let hb = s.spawn(move || {
            let mut coord = test_coordinator_in_namespace_with_limits(ns, 5, 100);
            let manifest = [
                InitialShardInput::new(
                    ShardId::from_raw(0xA004),
                    ShardSpecRef::new(b"\x40", b"\x49", b""),
                    CursorUpdate::initial(),
                ),
                InitialShardInput::new(
                    ShardId::from_raw(0xA005),
                    ShardSpecRef::new(b"\x50", b"\x59", b""),
                    CursorUpdate::initial(),
                ),
                InitialShardInput::new(
                    ShardId::from_raw(0xA006),
                    ShardSpecRef::new(b"\x60", b"\x69", b""),
                    CursorUpdate::initial(),
                ),
            ];
            b.wait();
            coord.register_shards(now(10), test_tenant(), run_b, &manifest, OpId::from_raw(20))
        });
        (ha.join().unwrap(), hb.join().unwrap())
    });

    // Phase 3: At least one must fail with ShardLimitExceeded.
    let a_ok = result_a.is_ok();
    let b_ok = result_b.is_ok();
    assert!(
        !(a_ok && b_ok),
        "both register_shards succeeded ({a_ok}, {b_ok}) — \
         per-tenant limit of 5 should have rejected at least one. \
         a={result_a:?}, b={result_b:?}"
    );

    // Verify the limit violation error shape.
    let rejected = if a_ok { &result_b } else { &result_a };
    assert!(
        matches!(
            rejected,
            Err(RegisterShardsError::ShardLimitExceeded {
                scope: ShardLimitScope::PerTenant,
                ..
            })
        ),
        "rejected registration must cite per-tenant limit: {rejected:?}"
    );

    // Phase 4: Independent oracle — counter matches actual shard count.
    let verifier = test_coordinator_in_namespace(&namespace);
    let counter = verifier
        .test_load_tenant_shard_count(test_tenant())
        .expect("counter load should succeed");
    // The winner registered 3 shards; the loser registered 0.
    assert_eq!(
        counter,
        Some(3),
        "counter must match the single successful registration's shard count"
    );
}

/// Two threads concurrently split different shards under the same tenant
/// with a tight per-tenant limit. The CAS guard on the tenant counter
/// must prevent both splits from committing if their combined child
/// counts would exceed the limit.
#[test]
fn concurrent_split_replace_respects_per_tenant_limit() {
    let namespace = contention_namespace();

    let run = RunId::from_raw(0xCC01);
    let shard_a = ShardId::from_raw(0xCC11);
    let shard_b = ShardId::from_raw(0xCC12);
    // Per-tenant limit = 4. We start with 2 parent shards. Each split
    // creates 2 children (parent goes terminal but stays in storage, and
    // the counter increases by 2). First split brings the counter from
    // 2 to 4 (at the limit). Second split would bring it from 4 to 6,
    // exceeding limit=4. The CAS guard on the tenant counter serializes
    // them, so exactly one split succeeds.
    let config = RunConfig::try_new(CursorSemantics::Completed, 30, Some(5)).unwrap();

    // Phase 1: Setup — seed two shards, acquire them.
    let (lease_a, lease_b) = {
        let mut setup = test_coordinator_in_namespace_with_limits(&namespace, 4, 100);
        setup
            .create_run(now(1), test_tenant(), run, config)
            .expect("create_run should succeed");
        let manifest = [
            InitialShardInput::new(
                shard_a,
                ShardSpecRef::new(b"\x00", b"\x80", b""),
                CursorUpdate::initial(),
            ),
            InitialShardInput::new(
                shard_b,
                ShardSpecRef::new(b"\x80", b"\xff", b""),
                CursorUpdate::initial(),
            ),
        ];
        let _ = setup
            .register_shards(now(2), test_tenant(), run, &manifest, OpId::from_raw(1))
            .expect("register_shards should succeed");

        let key_a = ShardKey::new(run, shard_a);
        let key_b = ShardKey::new(run, shard_b);
        let mut scratch = AcquireScratch::new();
        let la = setup
            .acquire_and_restore_into(now(3), test_tenant(), key_a, test_worker(1), &mut scratch)
            .expect("acquire A should succeed")
            .lease;
        let lb = setup
            .acquire_and_restore_into(now(4), test_tenant(), key_b, test_worker(2), &mut scratch)
            .expect("acquire B should succeed")
            .lease;
        (la, lb)
    };

    // Phase 2: Two threads race to split their respective shards.
    let barrier = std::sync::Barrier::new(2);
    let (result_a, result_b) = std::thread::scope(|s| {
        let b = &barrier;
        let ns = &namespace;
        let la = &lease_a;
        let lb = &lease_b;

        let ha = s.spawn(move || {
            let mut coord = test_coordinator_in_namespace_with_limits(ns, 4, 100);
            let left = ShardSpec::with_range(b"\x00", b"\x40");
            let right = ShardSpec::with_range(b"\x40", b"\x80");
            let plan = SplitReplacePlan::try_new(vec![
                SplitReplaceChild::new(left.as_ref(), CursorUpdate::initial()),
                SplitReplaceChild::new(right.as_ref(), CursorUpdate::initial()),
            ])
            .expect("split plan A should be valid");
            b.wait();
            coord.split_replace(now(10), test_tenant(), la, plan, OpId::from_raw(100))
        });
        let hb = s.spawn(move || {
            let mut coord = test_coordinator_in_namespace_with_limits(ns, 4, 100);
            let left = ShardSpec::with_range(b"\x80", b"\xC0");
            let right = ShardSpec::with_range(b"\xC0", b"\xff");
            let plan = SplitReplacePlan::try_new(vec![
                SplitReplaceChild::new(left.as_ref(), CursorUpdate::initial()),
                SplitReplaceChild::new(right.as_ref(), CursorUpdate::initial()),
            ])
            .expect("split plan B should be valid");
            b.wait();
            coord.split_replace(now(10), test_tenant(), lb, plan, OpId::from_raw(200))
        });
        (ha.join().unwrap(), hb.join().unwrap())
    });

    // Phase 3: At most one split should succeed if combined children
    // would exceed the per-tenant limit.
    let a_ok = result_a.is_ok();
    let b_ok = result_b.is_ok();

    // Each split_replace adds 2 children to the counter. Starting
    // from 2, the first split brings the counter to 4 (at the limit).
    // The second split would need 4+2=6 > limit=4, so the CAS guard
    // ensures at most one succeeds. Verify the counter is consistent.
    let verifier = test_coordinator_in_namespace(&namespace);
    let counter = verifier
        .test_load_tenant_shard_count(test_tenant())
        .expect("counter load should succeed");

    // Each split_replace creates 2 children and adds 2 to the counter
    // (the parent goes terminal but remains persisted). Starting from
    // counter=2, the first split brings it to 4 (at the limit). The
    // second split would need 4+2=6 > limit=4, so the CAS guard
    // ensures exactly one succeeds.
    let successes = usize::from(a_ok) + usize::from(b_ok);
    assert_eq!(
        successes, 1,
        "exactly one split should succeed under the per-tenant limit: a={result_a:?}, b={result_b:?}"
    );
    assert_eq!(
        counter,
        Some(4),
        "one split succeeded: 2 initial parents + 2 children = 4 persisted shards"
    );
}

/// When the per-tenant counter key is absent, two concurrent
/// register_shards operations on the same tenant must both succeed
/// via the bootstrap path: one creates the counter (compare_absent CAS),
/// the other retries after the CAS failure and reads the established
/// counter.
#[test]
fn concurrent_register_shards_bootstraps_counter_under_contention() {
    let namespace = contention_namespace();

    let run_a = RunId::from_raw(0xCD01);
    let run_b = RunId::from_raw(0xCD02);
    let config = RunConfig::try_new(CursorSemantics::Completed, 30, Some(5)).unwrap();

    // Phase 1: Setup — create two runs, register nothing yet (so the
    // counter key is absent for this tenant).
    {
        let mut setup = test_coordinator_in_namespace(&namespace);
        setup
            .create_run(now(1), test_tenant(), run_a, config)
            .expect("create_run A should succeed");
        setup
            .create_run(now(2), test_tenant(), run_b, config)
            .expect("create_run B should succeed");
    }

    // Verify counter is absent.
    {
        let checker = test_coordinator_in_namespace(&namespace);
        let counter = checker
            .test_load_tenant_shard_count(test_tenant())
            .expect("counter load should succeed");
        assert_eq!(
            counter, None,
            "counter must be absent before any registration"
        );
    }

    // Phase 2: Two threads race to register_shards. Each targets a
    // different run (non-overlapping shard IDs, non-overlapping key
    // ranges). Both will attempt bootstrap because the counter is absent.
    let barrier = std::sync::Barrier::new(2);
    let (result_a, result_b) = std::thread::scope(|s| {
        let b = &barrier;
        let ns = &namespace;

        let ha = s.spawn(move || {
            let mut coord = test_coordinator_in_namespace(ns);
            let manifest = [InitialShardInput::new(
                ShardId::from_raw(0xD001),
                ShardSpecRef::new(b"a", b"m", b""),
                CursorUpdate::initial(),
            )];
            b.wait();
            coord.register_shards(now(10), test_tenant(), run_a, &manifest, OpId::from_raw(10))
        });
        let hb = s.spawn(move || {
            let mut coord = test_coordinator_in_namespace(ns);
            let manifest = [InitialShardInput::new(
                ShardId::from_raw(0xD002),
                ShardSpecRef::new(b"m", b"z", b""),
                CursorUpdate::initial(),
            )];
            b.wait();
            coord.register_shards(now(10), test_tenant(), run_b, &manifest, OpId::from_raw(20))
        });
        (ha.join().unwrap(), hb.join().unwrap())
    });

    // Phase 3: Both must succeed. The CAS retry loop handles the
    // counter bootstrap race: one creates the key, the other retries
    // and reads the established counter.
    let _ = result_a.expect("register_shards A should succeed via bootstrap or retry");
    let _ = result_b.expect("register_shards B should succeed via bootstrap or retry");

    // Phase 4: Independent oracle — counter matches actual shard count.
    let verifier = test_coordinator_in_namespace(&namespace);
    let counter = verifier
        .test_load_tenant_shard_count(test_tenant())
        .expect("counter load should succeed");
    assert_eq!(
        counter,
        Some(2),
        "counter must equal the sum of both registrations (1 + 1 = 2)"
    );
}

// ---------------------------------------------------------------------------
// Tenant isolation (cross-tenant data must never leak)
// ---------------------------------------------------------------------------
//
// The etcd keyspace uses `tenants/{tenant_hex}/` path prefixes, so each
// tenant's data lives in a physically disjoint key range. These tests
// verify that query and mutation operations are correctly scoped: data
// written under tenant A is invisible to tenant B, and vice versa.

/// `list_shards_into` returns only shards belonging to the queried tenant.
/// Shards registered under a different tenant must never appear.
///
/// Both tenants share the same `RunId` and `ShardId` so the tenant prefix
/// is the only discriminator. A backend that ignores the tenant prefix
/// would return both tenants' shards in a single query.
#[test]
fn list_shards_returns_only_shards_from_requested_tenant() {
    let mut backend = test_coordinator();

    let config = RunConfig::try_new(CursorSemantics::Completed, 30, Some(5)).unwrap();
    let shared_run = test_run();
    let shared_shard = ShardId::from_raw(0x01);

    // Tenant A: one shard under the shared run.
    backend
        .create_run(now(1), test_tenant(), shared_run, config)
        .expect("create_run A");
    let manifest_a = [InitialShardInput::new(
        shared_shard,
        ShardSpecRef::new(b"a", b"m", b""),
        CursorUpdate::initial(),
    )];
    let _ = backend
        .register_shards(
            now(2),
            test_tenant(),
            shared_run,
            &manifest_a,
            OpId::from_raw(1),
        )
        .expect("register A");

    // Tenant B: same RunId, same ShardId, different key range.
    backend
        .create_run(now(3), other_tenant(), shared_run, config)
        .expect("create_run B");
    let manifest_b = [InitialShardInput::new(
        shared_shard,
        ShardSpecRef::new(b"m", b"z", b""),
        CursorUpdate::initial(),
    )];
    let _ = backend
        .register_shards(
            now(4),
            other_tenant(),
            shared_run,
            &manifest_b,
            OpId::from_raw(2),
        )
        .expect("register B");

    // Query tenant A — should see only A's shard.
    let mut shards_a = Vec::new();
    backend
        .list_shards_into(
            now(5),
            test_tenant(),
            shared_run,
            ShardFilter::all(),
            &mut shards_a,
        )
        .expect("list A");
    assert_eq!(shards_a.len(), 1);
    assert_eq!(shards_a[0].shard, shared_shard);

    // Query tenant B — should see only B's shard (not a merged 2-element list).
    let mut shards_b = Vec::new();
    backend
        .list_shards_into(
            now(5),
            other_tenant(),
            shared_run,
            ShardFilter::all(),
            &mut shards_b,
        )
        .expect("list B");
    assert_eq!(shards_b.len(), 1);
    assert_eq!(shards_b[0].shard, shared_shard);
}

/// Acquiring a shard in one tenant must not affect the lease state of the
/// same shard ID registered under a different tenant. Both tenants share
/// the same `RunId` and `ShardId` so the tenant prefix is the only
/// discriminator.
#[test]
fn acquire_in_one_tenant_does_not_affect_other_tenant() {
    let mut backend = test_coordinator();

    let config = RunConfig::try_new(CursorSemantics::Completed, 30, Some(5)).unwrap();
    let shared_run = test_run();
    let shared_shard = ShardId::from_raw(0x42);

    // Both tenants register the same RunId + ShardId.
    backend
        .create_run(now(1), test_tenant(), shared_run, config)
        .expect("create_run A");
    let manifest = [InitialShardInput::new(
        shared_shard,
        ShardSpecRef::new(b"a", b"z", b""),
        CursorUpdate::initial(),
    )];
    let _ = backend
        .register_shards(
            now(2),
            test_tenant(),
            shared_run,
            &manifest,
            OpId::from_raw(1),
        )
        .expect("register A");

    backend
        .create_run(now(3), other_tenant(), shared_run, config)
        .expect("create_run B");
    let _ = backend
        .register_shards(
            now(4),
            other_tenant(),
            shared_run,
            &manifest,
            OpId::from_raw(2),
        )
        .expect("register B");

    // Acquire in tenant A — the shard becomes leased.
    let key_a = ShardKey::new(shared_run, shared_shard);
    let mut scratch = AcquireScratch::new();
    let _acquire_a = backend
        .acquire_and_restore_into(now(5), test_tenant(), key_a, test_worker(1), &mut scratch)
        .expect("acquire A");

    // Tenant B's identical shard must still be available (unleased).
    let mut shards_b = Vec::new();
    backend
        .list_shards_into(
            now(6),
            other_tenant(),
            shared_run,
            ShardFilter::available(),
            &mut shards_b,
        )
        .expect("list B");
    assert_eq!(shards_b.len(), 1, "tenant B's shard must remain available");
    assert_eq!(shards_b[0].shard, shared_shard);
    assert!(
        !shards_b[0].is_leased,
        "tenant B's shard must be unleased after tenant A acquires"
    );
}

/// `collect_claim_candidates_into` returns only candidates from the queried
/// tenant's run. Shards in a different tenant's run must not appear.
///
/// Both tenants share the same `RunId` and overlapping `ShardId`s so the
/// tenant prefix is the only discriminator. Tenant A registers two shards,
/// tenant B registers one; a backend that ignores the prefix would return
/// three candidates for tenant A.
#[test]
fn collect_claim_candidates_scoped_to_tenant() {
    let mut backend = test_coordinator();

    let config = RunConfig::try_new(CursorSemantics::Completed, 30, Some(5)).unwrap();
    let shared_run = test_run();

    // Tenant A: two shards (0x01, 0x02).
    backend
        .create_run(now(1), test_tenant(), shared_run, config)
        .expect("create_run A");
    let manifest_a = [
        InitialShardInput::new(
            ShardId::from_raw(0x01),
            ShardSpecRef::new(b"a", b"m", b""),
            CursorUpdate::initial(),
        ),
        InitialShardInput::new(
            ShardId::from_raw(0x02),
            ShardSpecRef::new(b"m", b"z", b""),
            CursorUpdate::initial(),
        ),
    ];
    let _ = backend
        .register_shards(
            now(2),
            test_tenant(),
            shared_run,
            &manifest_a,
            OpId::from_raw(1),
        )
        .expect("register A");

    // Tenant B: one shard (0x01) — same ID as one of A's shards.
    backend
        .create_run(now(3), other_tenant(), shared_run, config)
        .expect("create_run B");
    let manifest_b = [InitialShardInput::new(
        ShardId::from_raw(0x01),
        ShardSpecRef::new(b"a", b"z", b""),
        CursorUpdate::initial(),
    )];
    let _ = backend
        .register_shards(
            now(4),
            other_tenant(),
            shared_run,
            &manifest_b,
            OpId::from_raw(2),
        )
        .expect("register B");

    // Candidates for tenant A — should see exactly A's two shards.
    let mut candidates_a = Vec::new();
    backend
        .collect_claim_candidates_into(now(5), test_tenant(), shared_run, &mut candidates_a)
        .expect("candidates A");
    assert_eq!(candidates_a.len(), 2, "tenant A has two available shards");
    assert!(candidates_a.contains(&ShardId::from_raw(0x01)));
    assert!(candidates_a.contains(&ShardId::from_raw(0x02)));

    // Candidates for tenant B — should see exactly B's one shard.
    let mut candidates_b = Vec::new();
    backend
        .collect_claim_candidates_into(now(5), other_tenant(), shared_run, &mut candidates_b)
        .expect("candidates B");
    assert_eq!(candidates_b.len(), 1, "tenant B has one available shard");
    assert_eq!(candidates_b[0], ShardId::from_raw(0x01));
}

/// `list_active_runs_into` returns only runs belonging to the queried tenant.
/// Runs created under a different tenant must not appear.
///
/// Both tenants share the same `RunId` so the tenant prefix is the only
/// discriminator — a backend that keys on `run` alone would see duplicates.
/// Each run must be activated via `register_shards` to appear in the
/// active-run index; `create_run` alone leaves them in `Initializing`.
#[test]
fn list_active_runs_scoped_to_tenant() {
    let mut backend = test_coordinator();

    let config = RunConfig::try_new(CursorSemantics::Completed, 30, Some(5)).unwrap();
    let shared_run = test_run();

    // Create and activate a run under tenant A.
    backend
        .create_run(now(1), test_tenant(), shared_run, config)
        .expect("create_run A");
    let manifest_a = [InitialShardInput::new(
        ShardId::from_raw(0x01),
        ShardSpecRef::new(b"a", b"m", b""),
        CursorUpdate::initial(),
    )];
    let _ = backend
        .register_shards(
            now(2),
            test_tenant(),
            shared_run,
            &manifest_a,
            OpId::from_raw(1),
        )
        .expect("register A");

    // Create and activate a run under tenant B with the same RunId.
    backend
        .create_run(now(3), other_tenant(), shared_run, config)
        .expect("create_run B");
    let manifest_b = [InitialShardInput::new(
        ShardId::from_raw(0x02),
        ShardSpecRef::new(b"m", b"z", b""),
        CursorUpdate::initial(),
    )];
    let _ = backend
        .register_shards(
            now(4),
            other_tenant(),
            shared_run,
            &manifest_b,
            OpId::from_raw(2),
        )
        .expect("register B");

    // List runs for tenant A — should see only A's run.
    let mut runs_a = Vec::new();
    backend
        .list_active_runs_into(test_tenant(), &mut runs_a)
        .expect("list runs A");
    assert_eq!(runs_a.len(), 1);
    assert_eq!(runs_a[0], shared_run);

    // List runs for tenant B — should see only B's run.
    let mut runs_b = Vec::new();
    backend
        .list_active_runs_into(other_tenant(), &mut runs_b)
        .expect("list runs B");
    assert_eq!(runs_b.len(), 1);
    assert_eq!(runs_b[0], shared_run);
}

/// `get_run` with a tenant that does not own the run must return `RunNotFound`.
/// Tenant B cannot see tenant A's run metadata.
#[test]
fn get_run_returns_not_found_for_wrong_tenant() {
    let mut backend = test_coordinator();

    let config = RunConfig::try_new(CursorSemantics::Completed, 30, Some(5)).unwrap();

    // Create a run under tenant A only.
    backend
        .create_run(now(1), test_tenant(), test_run(), config)
        .expect("create_run A");

    // Tenant A can see its own run.
    let _ = backend
        .get_run(test_tenant(), test_run())
        .expect("tenant A should see its own run");

    // Tenant B cannot see tenant A's run.
    let err = backend
        .get_run(other_tenant(), test_run())
        .expect_err("tenant B should not see tenant A's run");
    assert!(
        matches!(err, GetRunError::RunNotFound),
        "expected RunNotFound, got {err:?}"
    );
}
