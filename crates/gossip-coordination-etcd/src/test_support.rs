//! Testcontainers-based etcd lifecycle management for integration tests.
//!
//! Provides helpers to create test coordinators or async-ready configs.
//!
//! **Isolated namespace** (unique per call):
//! [`test_coordinator`], [`test_coordinator_with_limits`],
//! [`test_coordinator_with_tuning`], [`test_async_coordinator_config`].
//!
//! **Shared namespace** (caller-controlled):
//! [`contention_namespace`], [`test_coordinator_in_namespace`],
//! [`test_coordinator_in_namespace_with_limits`],
//! [`test_coordinator_in_namespace_with_tuning`].
//!
//! All helpers are backed by either:
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
//! cargo test -p gossip-coordination-etcd
//!
//! # With a pre-existing etcd (no Docker needed):
//! ETCD_ENDPOINTS="http://127.0.0.1:2379" \
//!   cargo test -p gossip-coordination-etcd
//! ```

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::runners::SyncRunner;
use testcontainers::{Container, ContainerRequest, GenericImage, ImageExt};

use gossip_contracts::identity::TenantId;
use gossip_coordination::ShardKey;

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

/// Both `Container<GenericImage>` and `String` are `Send + Sync`,
/// satisfying the `OnceLock` bound.
static SHARED_ETCD: OnceLock<EtcdEndpoint> = OnceLock::new();

/// Build the etcd container image definition.
///
/// Uses a pinned upstream etcd image with explicit single-node startup
/// flags. Waits for the "ready to serve client requests" log line on
/// stderr before declaring readiness.
fn etcd_image() -> ContainerRequest<GenericImage> {
    GenericImage::new("quay.io/coreos/etcd", "v3.5.15")
        .with_wait_for(WaitFor::message_on_stderr("ready to serve client requests"))
        .with_exposed_port(2379.tcp())
        .with_hostname("node1")
        .with_cmd([
            "etcd",
            "--name=node1",
            "--data-dir=/etcd-data",
            "--listen-client-urls=http://0.0.0.0:2379",
            "--advertise-client-urls=http://node1:2379",
            "--listen-peer-urls=http://0.0.0.0:2380",
            "--initial-advertise-peer-urls=http://node1:2380",
            "--initial-cluster=node1=http://node1:2380",
            "--initial-cluster-token=gossip-rs-test-cluster",
            "--initial-cluster-state=new",
        ])
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
            .expect("failed to start etcd container — is Docker running and able to pull quay.io/coreos/etcd:v3.5.15?");

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
pub fn test_coordinator() -> EtcdCoordinator {
    let ep = shared_endpoint();
    let namespace = unique_namespace();
    let config = EtcdCoordinatorConfig::from_endpoints_csv(&ep.endpoint, &namespace)
        .expect("test endpoint config should be valid");
    EtcdCoordinator::connect(config).expect("test etcd should be reachable")
}

/// Build a unique async-ready config for [`crate::AsyncEtcdCoordinator`] tests.
///
/// This helper performs Docker / endpoint discovery before the caller enters a
/// Tokio runtime, so `AsyncEtcdCoordinator::connect(config).await` can run
/// entirely inside that runtime without overlapping testcontainers startup on
/// the same thread.
pub fn test_async_coordinator_config() -> EtcdCoordinatorConfig {
    let ep = shared_endpoint();
    let namespace = unique_namespace();
    EtcdCoordinatorConfig::from_endpoints_csv(&ep.endpoint, &namespace)
        .expect("test endpoint config should be valid")
}

/// Create an [`EtcdCoordinator`] with explicit shard count limits.
pub fn test_coordinator_with_limits(
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

/// Create an [`EtcdCoordinator`] with explicit persistence-tuning
/// values for testing backend-specific behavior (e.g., reduced
/// `max_children_per_op` to test fanout rejection).
pub fn test_coordinator_with_tuning(
    owner_lease_ttl_secs: i64,
    optimistic_txn_retries: usize,
    max_children_per_op: usize,
) -> EtcdCoordinator {
    let namespace = unique_namespace();
    test_coordinator_in_namespace_with_tuning(
        &namespace,
        owner_lease_ttl_secs,
        optimistic_txn_retries,
        max_children_per_op,
    )
}

/// Create an [`EtcdCoordinator`] targeting a specific shared namespace with
/// explicit persistence tuning.
///
/// Multi-coordinator tests use this helper when they need both a shared etcd
/// keyspace and non-default lease or retry settings.
pub fn test_coordinator_in_namespace_with_tuning(
    namespace: &str,
    owner_lease_ttl_secs: i64,
    optimistic_txn_retries: usize,
    max_children_per_op: usize,
) -> EtcdCoordinator {
    let ep = shared_endpoint();
    let config = EtcdCoordinatorConfig::from_endpoints_csv_with_tuning(
        &ep.endpoint,
        namespace,
        owner_lease_ttl_secs,
        optimistic_txn_retries,
        max_children_per_op,
    )
    .expect("test endpoint config should be valid");
    EtcdCoordinator::connect(config).expect("test etcd should be reachable")
}

// ---------------------------------------------------------------------------
// Shared-namespace helpers for multi-coordinator CAS contention tests
// ---------------------------------------------------------------------------

/// Generate a unique namespace prefix that can be shared across multiple
/// coordinators in a single test. Unlike the internal `unique_namespace`
/// (which is called implicitly by [`test_coordinator`] and friends), this
/// returns the raw namespace string so multiple coordinators can target the
/// same etcd keyspace.
pub fn contention_namespace() -> String {
    unique_namespace()
}

/// Create an [`EtcdCoordinator`] targeting a specific shared namespace.
///
/// Unlike [`test_coordinator`] which creates a unique namespace per call,
/// this allows multiple coordinators to share one keyspace for CAS
/// contention testing. Each coordinator still owns its own Tokio runtime
/// and connection, so they can be used from separate threads.
pub fn test_coordinator_in_namespace(namespace: &str) -> EtcdCoordinator {
    let ep = shared_endpoint();
    let config = EtcdCoordinatorConfig::from_endpoints_csv(&ep.endpoint, namespace)
        .expect("test endpoint config should be valid");
    EtcdCoordinator::connect(config).expect("test etcd should be reachable")
}

/// Create an [`EtcdCoordinator`] in a shared namespace with explicit
/// shard count limits for limit enforcement contention tests.
pub fn test_coordinator_in_namespace_with_limits(
    namespace: &str,
    max_shards_per_tenant: usize,
    max_total_shards: usize,
) -> EtcdCoordinator {
    let ep = shared_endpoint();
    let config = EtcdCoordinatorConfig::from_endpoints_csv(&ep.endpoint, namespace)
        .expect("test endpoint config should be valid")
        .with_shard_limits(max_shards_per_tenant, max_total_shards)
        .expect("test shard limits should be valid");
    EtcdCoordinator::connect(config).expect("test etcd should be reachable")
}

/// Poll until the owner binding for `key` disappears, or panic if
/// `ttl_secs + 10s` elapses without cleanup.  The generous fixed margin
/// absorbs CI-host scheduling jitter.
pub fn wait_for_owner_binding_expiry(
    backend: &EtcdCoordinator,
    tenant: TenantId,
    key: ShardKey,
    ttl_secs: i64,
) {
    let deadline = std::time::Instant::now()
        + std::time::Duration::from_secs(
            u64::try_from(ttl_secs).expect("TTL must be non-negative") + 10,
        );
    let interval = std::time::Duration::from_millis(250);
    loop {
        if backend
            .test_load_owner_binding(tenant, key)
            .expect("owner lookup should succeed while polling")
            .is_none()
        {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "owner binding was not cleaned up within {ttl_secs}s + 10s margin"
        );
        std::thread::sleep(interval);
    }
}
