//! Test-support wrappers for done-ledger PostgreSQL tests.

use postgres::Client;

pub(crate) use gossip_pg_common::test_support::create_test_db;
pub(crate) use gossip_pg_common::test_support::test_client_bare;

/// Create a fresh test database and apply the done-ledger schema migrations.
pub(crate) fn test_client() -> Client {
    gossip_pg_common::test_support::test_client_with(|client| {
        crate::apply_all_migrations(client).expect("failed to apply migrations");
    })
}
