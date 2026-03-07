use gossip_contracts::persistence::run_conformance;
use gossip_persistence_inmemory::{InMemoryDoneLedger, InMemoryFindingsSink};

#[test]
fn in_memory_backends_pass_persistence_conformance() {
    let done_ledger = InMemoryDoneLedger::new();
    let findings = InMemoryFindingsSink::new();

    let report = run_conformance(&done_ledger, &findings)
        .unwrap_or_else(|err| panic!("in-memory persistence conformance failed: {err}"));

    assert_eq!(report.done_ledger_checks(), 4);
    assert_eq!(report.findings_checks(), 4);
    assert_eq!(report.redaction_checks(), 3);
}
