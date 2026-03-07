use std::env;

use crate::{EtcdCoordinator, EtcdCoordinatorConfig};

#[test]
fn config_rejects_empty_endpoint_list() {
    let err = EtcdCoordinatorConfig::new(Vec::<String>::new(), "/gossip/v1")
        .expect_err("empty endpoints must fail validation");
    assert!(matches!(
        err,
        crate::EtcdCoordinatorConfigError::NoEndpoints
    ));
}

#[test]
fn config_rejects_invalid_namespace_prefix() {
    let err = EtcdCoordinatorConfig::new(["http://127.0.0.1:2379"], "gossip/v1")
        .expect_err("namespace prefix without leading slash must fail");
    assert!(matches!(
        err,
        crate::EtcdCoordinatorConfigError::NamespacePrefixMustStartWithSlash
    ));
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
        !status.version.is_empty(),
        "connected member should report a version"
    );
}
