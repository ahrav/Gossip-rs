//! Tests for the etcd coordination backend.
//!
//! The bulk of this module covers [`EtcdCoordinatorConfig`] validation —
//! these are pure, deterministic tests that require no external services.
//!
//! A single `#[ignore]`-gated integration test (`connects_to_local_etcd_and_fetches_status`)
//! exercises the full connect → status round-trip against a live etcd instance.

use std::env;

use crate::{EtcdCoordinator, EtcdCoordinatorConfig, EtcdCoordinatorConfigError};

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

/// Integration smoke-test: connect to a real etcd and verify the status RPC.
///
/// Ignored by default — run with `cargo test -p gossip-coordination-etcd -- --ignored`.
///
/// Override the target cluster by setting `ETCD_ENDPOINTS` to a comma-separated
/// list of gRPC endpoints (e.g. `http://10.0.0.1:2379,http://10.0.0.2:2379`).
/// Falls back to `http://127.0.0.1:2379` when the variable is unset or blank.
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
        !status.version.is_empty(),
        "connected member should report a version"
    );
}
