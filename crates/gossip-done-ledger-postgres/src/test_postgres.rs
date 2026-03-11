//! Testcontainers-based PostgreSQL lifecycle management for integration tests.
//!
//! Provides [`test_client`] and [`test_client_bare`] to create
//! [`postgres::Client`] instances backed by either:
//!
//! - An auto-provisioned Docker container (default), or
//! - A pre-existing PostgreSQL at the URL in `GOSSIP_POSTGRES_TEST_URL`.
//!
//! A single PostgreSQL container is shared across all tests in a binary via
//! [`OnceLock`]; each test gets its own freshly-created database for complete
//! isolation.
//!
//! # Running tests
//!
//! ```bash
//! # With Docker running (auto-provisions postgres:16-alpine):
//! cargo test -p gossip-done-ledger-postgres -- --ignored
//!
//! # With a pre-existing PostgreSQL (no Docker needed):
//! GOSSIP_POSTGRES_TEST_URL="host=localhost user=postgres password=postgres" \
//!   cargo test -p gossip-done-ledger-postgres -- --ignored
//! ```

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

use postgres::{Client, NoTls};
use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::runners::SyncRunner;
use testcontainers::{Container, ContainerRequest, GenericImage, ImageExt};

/// Monotonic counter for generating unique database names across tests
/// in the same binary. Combined with `std::process::id()` for
/// cross-binary uniqueness when nextest runs test binaries in parallel.
static DB_COUNTER: AtomicU64 = AtomicU64::new(0);

/// PostgreSQL connection source: either a testcontainers-managed Docker
/// container or a pre-existing external instance from
/// `GOSSIP_POSTGRES_TEST_URL`.
struct PgEndpoint {
    /// Base connection URL pointing at the `postgres` maintenance database.
    url: String,
    /// Held alive to prevent container reaping. `None` when using an
    /// external PostgreSQL (no container lifecycle to manage).
    _container: Option<Container<GenericImage>>,
}

static SHARED_PG: OnceLock<PgEndpoint> = OnceLock::new();

/// Build the PostgreSQL container image definition.
fn pg_image() -> ContainerRequest<GenericImage> {
    GenericImage::new("postgres", "16-alpine")
        .with_wait_for(WaitFor::message_on_stderr(
            "database system is ready to accept connections",
        ))
        .with_exposed_port(5432.tcp())
        .with_env_var("POSTGRES_USER", "postgres")
        .with_env_var("POSTGRES_PASSWORD", "postgres")
        .with_env_var("POSTGRES_DB", "postgres")
}

/// Start (or reuse) the shared PostgreSQL endpoint.
///
/// Resolution order:
/// 1. If `GOSSIP_POSTGRES_TEST_URL` is set and non-empty, use it directly.
/// 2. Otherwise, start a PostgreSQL container via testcontainers.
fn shared_endpoint() -> &'static PgEndpoint {
    SHARED_PG.get_or_init(|| {
        if let Some(url) = external_url() {
            return PgEndpoint {
                url,
                _container: None,
            };
        }

        let container = pg_image()
            .start()
            .expect("failed to start postgres container — is Docker running?");

        let host = container.get_host().expect("failed to get container host");
        let port = container
            .get_host_port_ipv4(5432)
            .expect("failed to get mapped port for 5432");

        let url =
            format!("host={host} port={port} user=postgres password=postgres dbname=postgres");
        PgEndpoint {
            url,
            _container: Some(container),
        }
    })
}

/// Read `GOSSIP_POSTGRES_TEST_URL` and return the first non-empty value, or
/// `None`.
fn external_url() -> Option<String> {
    std::env::var("GOSSIP_POSTGRES_TEST_URL")
        .ok()
        .map(|raw| raw.trim().to_owned())
        .filter(|s| !s.is_empty())
}

/// Generate a unique database name for test isolation.
///
/// Format: `test_{pid}_{counter}` — unique within and across test binaries.
fn unique_db_name() -> String {
    let pid = std::process::id();
    let seq = DB_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("test_{pid}_{seq}")
}

/// Create a fresh test database and return a connection URL pointing at it.
pub(crate) fn create_test_db() -> String {
    let ep = shared_endpoint();
    let db_name = unique_db_name();

    // Connect to the maintenance database to create the test database.
    let mut admin = Client::connect(&ep.url, NoTls)
        .expect("failed to connect to postgres maintenance database");
    admin
        .batch_execute(&format!("CREATE DATABASE {db_name}"))
        .expect("failed to create test database");

    // Build a connection string for the new database.
    // Replace dbname in the URL or append it.
    if ep.url.contains("dbname=") {
        ep.url
            .split_whitespace()
            .map(|part| {
                if part.starts_with("dbname=") {
                    format!("dbname={db_name}")
                } else {
                    part.to_owned()
                }
            })
            .collect::<Vec<_>>()
            .join(" ")
    } else {
        format!("{} dbname={db_name}", ep.url)
    }
}

/// Create a fresh test database, connect, and apply all migrations.
///
/// Returns a [`Client`] connected to an isolated database with the full
/// done-ledger schema applied.
pub(crate) fn test_client() -> Client {
    let url = create_test_db();
    let mut client = Client::connect(&url, NoTls).expect("failed to connect to test database");
    crate::apply_all_migrations(&mut client).expect("failed to apply migrations");
    client
}

/// Create a fresh test database and connect without applying migrations.
///
/// Useful for testing the migration runner itself.
pub(crate) fn test_client_bare() -> Client {
    let url = create_test_db();
    Client::connect(&url, NoTls).expect("failed to connect to test database")
}
