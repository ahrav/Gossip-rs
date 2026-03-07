//! Tests for the etcd coordination backend.
//!
//! The bulk of this module covers [`EtcdCoordinatorConfig`] validation —
//! these are pure, deterministic tests that require no external services.
//!
//! A single `#[ignore]`-gated integration test (`connects_to_local_etcd_and_fetches_status`)
//! exercises the full connect → status round-trip against a live etcd instance.

use std::env;

use crate::{
    EtcdCoordinator, EtcdCoordinatorConfig, EtcdCoordinatorConfigError, EtcdCoordinatorError,
    EtcdOperation,
};

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
    // Trailing commas (common in env vars) are silently accepted
    // rather than failing with EmptyEndpoint.
    let config = EtcdCoordinatorConfig::from_endpoints_csv("http://a:2379,,", "/gossip/v1")
        .expect("trailing empty segments should be silently dropped");
    assert_eq!(config.endpoints(), ["http://a:2379"]);
}

// ---------------------------------------------------------------------------
// Error Display tests
// ---------------------------------------------------------------------------

#[test]
fn etcd_operation_display_connect() {
    assert_eq!(EtcdOperation::Connect.to_string(), "connect");
}

#[test]
fn etcd_operation_display_status() {
    assert_eq!(EtcdOperation::Status.to_string(), "status");
}

#[test]
fn config_error_display_no_endpoints() {
    let error = EtcdCoordinatorConfigError::NoEndpoints;
    assert_eq!(error.to_string(), "at least one etcd endpoint is required");
}

#[test]
fn config_error_display_invalid_scheme() {
    let error = EtcdCoordinatorConfigError::InvalidEndpointScheme { index: 2 };
    assert_eq!(
        error.to_string(),
        "etcd endpoint at index 2 has invalid scheme (expected http:// or https://)"
    );
}

#[test]
fn coordinator_error_display_wraps_config_error() {
    let inner = EtcdCoordinatorConfigError::NoEndpoints;
    let outer = EtcdCoordinatorError::Config(inner);
    assert!(
        outer
            .to_string()
            .contains("invalid etcd coordinator config"),
        "Display should wrap the config error message"
    );
}

// ---------------------------------------------------------------------------
// Error source chain tests
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// From conversion test
// ---------------------------------------------------------------------------

#[test]
fn config_error_converts_to_coordinator_error_via_from() {
    let config_err = EtcdCoordinatorConfigError::NoEndpoints;
    let coord_err: EtcdCoordinatorError = config_err.into();
    assert!(
        matches!(coord_err, EtcdCoordinatorError::Config(_)),
        "From should produce Config variant"
    );
}

// ---------------------------------------------------------------------------
// Config edge cases
// ---------------------------------------------------------------------------

#[test]
fn config_accepts_root_namespace_slash() {
    let config = EtcdCoordinatorConfig::new(["http://127.0.0.1:2379"], "/")
        .expect("root namespace '/' should be accepted");
    assert_eq!(config.namespace_prefix(), "/");
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
        !status.version().is_empty(),
        "connected member should report a version"
    );
}
