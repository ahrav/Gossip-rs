use gossip_contracts::persistence::{self, run_conformance};
use gossip_persistence_inmemory::{InMemoryDoneLedger, InMemoryFindingsSink};

#[test]
fn in_memory_backends_pass_persistence_conformance() {
    let done_ledger = InMemoryDoneLedger::new();
    let findings = InMemoryFindingsSink::new();

    let report = run_conformance(&done_ledger, &findings)
        .unwrap_or_else(|err| panic!("in-memory persistence conformance failed: {err}"));

    assert_eq!(report.done_ledger_checks, 3);
    assert_eq!(report.findings_checks, 3);
    assert_eq!(report.redaction_checks, 3);
    assert_eq!(report.total_checks(), 9);
}

/// The reference in-memory backend intentionally accepts batches of any size.
/// Real persistence backends may enforce `RECOMMENDED_MAX_BATCH_SIZE` as a hard
/// limit, but the test-support backend deliberately omits this constraint so
/// that conformance tests and simulations can submit arbitrarily large batches
/// without tripping resource guards.
///
/// This test documents that design choice by asserting the constant exists and
/// has the expected value — a compile-time canary that fires if the contract
/// constant is ever removed or renamed.
#[test]
fn recommended_max_batch_size_constant_is_documented() {
    assert_eq!(
        persistence::RECOMMENDED_MAX_BATCH_SIZE,
        10_000,
        "RECOMMENDED_MAX_BATCH_SIZE should remain at 10,000; \
         in-memory backends intentionally do not enforce it"
    );
}
