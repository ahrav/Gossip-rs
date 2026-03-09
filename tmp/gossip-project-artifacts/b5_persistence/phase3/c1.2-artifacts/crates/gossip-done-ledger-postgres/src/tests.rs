use std::{env, time::Duration};

use gossip_contracts::persistence::conformance::run_done_ledger_conformance;

use crate::DoneLedgerPg;

fn test_database_url() -> String {
    env::var("GOSSIP_POSTGRES_TEST_URL").unwrap_or_else(|_| {
        "host=127.0.0.1 user=postgres password=postgres dbname=postgres".to_owned()
    })
}

/// Live Postgres conformance test for the done-ledger backend.
///
/// This test is ignored by default because it requires a running local
/// PostgreSQL instance. Run it with:
///
/// `cargo test -p gossip-done-ledger-postgres -- --ignored`
#[test]
#[ignore = "requires a live Postgres instance"]
fn done_ledger_pg_passes_conformance_suite() {
    let backend = DoneLedgerPg::connect_and_migrate(&test_database_url())
        .expect("connect_and_migrate should succeed against live postgres");
    backend
        .validate_connection(Duration::from_secs(2))
        .expect("postgres connection should be valid");
    backend
        .truncate_all_for_tests()
        .expect("truncate should succeed before conformance");

    run_done_ledger_conformance(&backend)
        .unwrap_or_else(|err| panic!("postgres done-ledger conformance failed: {err}"));
}
