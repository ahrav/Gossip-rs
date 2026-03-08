//! Testcontainers-based etcd lifecycle management for integration tests.
//!
//! Provides [`test_coordinator`], [`test_coordinator_with_limits`], and
//! [`test_coordinator_with_ttl`] to create [`EtcdCoordinator`] instances
//! backed by either:
//!
//! - An auto-provisioned Docker container (default), or
//! - A pre-existing etcd at the address in `ETCD_ENDPOINTS`.
//!
//! A single etcd container is shared across all tests in a binary via
//! [`OnceLock`]; each test gets its own namespace prefix for complete
//! key isolation.
//!
//! # Runtime sequencing
//!
//! [`EtcdCoordinator::connect`] creates its own Tokio runtime and
//! `debug_assert!`s that no runtime is active on the calling thread.
//! The testcontainers `SyncRunner` also uses a Tokio runtime internally
//! for Docker operations. The helper extracts all container metadata
//! (host, port) as owned values before any `EtcdCoordinator` is
//! constructed, ensuring the two runtimes never overlap on the same
//! thread.
//!
//! # Running tests
//!
//! ```bash
//! # With Docker running (auto-provisions etcd):
//! cargo test -p gossip-coordination-etcd -- --ignored
//!
//! # With a pre-existing etcd (no Docker needed):
//! ETCD_ENDPOINTS="http://127.0.0.1:2379" \
//!   cargo test -p gossip-coordination-etcd -- --ignored
//! ```

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::runners::SyncRunner;
use testcontainers::{Container, ContainerRequest, GenericImage, ImageExt};

use crate::{EtcdCoordinator, EtcdCoordinatorConfig};

/// Monotonic counter for generating unique namespace prefixes across
/// tests in the same binary. Combined with `std::process::id()` for
/// cross-binary uniqueness when nextest runs test binaries in parallel.
static NAMESPACE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Etcd connection source: either a testcontainers-managed Docker
/// container or a pre-existing external endpoint from `ETCD_ENDPOINTS`.
struct EtcdEndpoint {
    endpoint: String,
    /// Held alive to prevent container reaping. `None` when using an
    /// external etcd (no container lifecycle to manage).
    _container: Option<Container<GenericImage>>,
}

/// SAFETY: `Container<GenericImage>` is `Send + Sync`, and `String`
/// is trivially `Send + Sync`. OnceLock requires `Sync`.
static SHARED_ETCD: OnceLock<EtcdEndpoint> = OnceLock::new();

/// Build the etcd container image definition.
///
/// Uses `bitnami/etcd:3.5` with authentication disabled and
/// single-node configuration. Waits for the "ready to serve client
/// requests" log line on stderr before declaring readiness.
fn etcd_image() -> ContainerRequest<GenericImage> {
    GenericImage::new("bitnami/etcd", "3.5")
        .with_wait_for(WaitFor::message_on_stderr("ready to serve client requests"))
        .with_exposed_port(2379.tcp())
        .with_env_var("ALLOW_NONE_AUTHENTICATION", "yes")
        .with_env_var("ETCD_ADVERTISE_CLIENT_URLS", "http://0.0.0.0:2379")
        .with_env_var("ETCD_LISTEN_CLIENT_URLS", "http://0.0.0.0:2379")
}

/// Start (or reuse) the shared etcd endpoint.
///
/// Resolution order:
/// 1. If `ETCD_ENDPOINTS` is set and non-empty, use it directly.
/// 2. Otherwise, start an etcd container via testcontainers.
fn shared_endpoint() -> &'static EtcdEndpoint {
    SHARED_ETCD.get_or_init(|| {
        // Check for a pre-existing etcd endpoint.
        if let Some(endpoint) = external_endpoint() {
            return EtcdEndpoint {
                endpoint,
                _container: None,
            };
        }

        // No external endpoint — start a container.
        let container = etcd_image()
            .start()
            .expect("failed to start etcd container — is Docker running?");

        // Extract host and port as owned values before any
        // EtcdCoordinator is created. This ensures the SyncRunner's
        // internal Tokio runtime is not active on the calling thread
        // when EtcdCoordinator::connect() creates its own runtime.
        let host = container.get_host().expect("failed to get container host");
        let port = container
            .get_host_port_ipv4(2379)
            .expect("failed to get mapped port for 2379");

        let endpoint = format!("http://{host}:{port}");
        EtcdEndpoint {
            endpoint,
            _container: Some(container),
        }
    })
}

/// Read `ETCD_ENDPOINTS` and return the first non-empty value, or `None`.
fn external_endpoint() -> Option<String> {
    std::env::var("ETCD_ENDPOINTS")
        .ok()
        .map(|raw| raw.trim().to_owned())
        .filter(|s| !s.is_empty())
}

/// Generate a unique namespace prefix for test isolation.
///
/// Format: `/test/{pid}/{counter}` — unique within and across test
/// binaries (nextest runs each binary in its own process).
fn unique_namespace() -> String {
    let pid = std::process::id();
    let seq = NAMESPACE_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("/test/{pid}/{seq}")
}

/// Create an [`EtcdCoordinator`] connected to the shared test etcd
/// with default tuning and a unique namespace prefix.
///
/// Each call returns a coordinator with its own keyspace, so tests run
/// in full isolation without needing `test_clear_namespace`.
pub(crate) fn test_coordinator() -> EtcdCoordinator {
    let ep = shared_endpoint();
    let namespace = unique_namespace();
    let config = EtcdCoordinatorConfig::from_endpoints_csv(&ep.endpoint, &namespace)
        .expect("test endpoint config should be valid");
    EtcdCoordinator::connect(config).expect("test etcd should be reachable")
}

/// Create an [`EtcdCoordinator`] with explicit shard count limits.
pub(crate) fn test_coordinator_with_limits(
    max_shards_per_tenant: usize,
    max_total_shards: usize,
) -> EtcdCoordinator {
    let ep = shared_endpoint();
    let namespace = unique_namespace();
    let config = EtcdCoordinatorConfig::from_endpoints_csv(&ep.endpoint, &namespace)
        .expect("test endpoint config should be valid")
        .with_shard_limits(max_shards_per_tenant, max_total_shards)
        .expect("test shard limits should be valid");
    EtcdCoordinator::connect(config).expect("test etcd should be reachable")
}

/// Create an [`EtcdCoordinator`] with a custom owner-lease TTL
/// for testing lease expiry behavior.
pub(crate) fn test_coordinator_with_ttl(ttl_secs: i64) -> EtcdCoordinator {
    let ep = shared_endpoint();
    let namespace = unique_namespace();
    let config = EtcdCoordinatorConfig::from_endpoints_csv_with_tuning(
        &ep.endpoint,
        &namespace,
        ttl_secs,
        8,
        8,
    )
    .expect("test endpoint config should be valid");
    EtcdCoordinator::connect(config).expect("test etcd should be reachable")
}

/// Create an [`EtcdCoordinator`] with explicit persistence-tuning
/// values for testing backend-specific behavior (e.g., reduced
/// `max_children_per_op` to test fanout rejection).
pub(crate) fn test_coordinator_with_tuning(
    owner_lease_ttl_secs: i64,
    optimistic_txn_retries: usize,
    max_children_per_op: usize,
) -> EtcdCoordinator {
    let ep = shared_endpoint();
    let namespace = unique_namespace();
    let config = EtcdCoordinatorConfig::from_endpoints_csv_with_tuning(
        &ep.endpoint,
        &namespace,
        owner_lease_ttl_secs,
        optimistic_txn_retries,
        max_children_per_op,
    )
    .expect("test endpoint config should be valid");
    EtcdCoordinator::connect(config).expect("test etcd should be reachable")
}
