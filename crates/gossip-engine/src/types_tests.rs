use proptest::prelude::*;

use super::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build `ScanDedupeCounters` from small integer values via the builder chain.
///
/// The struct has private fields, so arbitrary values must be constructed
/// through the public builder API. We keep values small (u8) for practical
/// proptest generation.
fn make_counters(candidates: u8, emitted: u8, dup: u8, limit: u8) -> ScanDedupeCounters {
    let mut c = ScanDedupeCounters::default();
    for _ in 0..candidates {
        c.increment_candidate();
    }
    for _ in 0..emitted {
        c.increment_emitted();
    }
    for _ in 0..dup {
        c.increment_duplicate_suppressed();
    }
    for _ in 0..limit {
        c.increment_limit_suppressed();
    }
    c
}

/// Proptest strategy for arbitrary `ScanDedupeCounters`.
fn arb_counters() -> impl Strategy<Value = ScanDedupeCounters> {
    (0..10_u8, 0..10_u8, 0..10_u8, 0..10_u8).prop_map(|(c, e, d, l)| make_counters(c, e, d, l))
}

/// Proptest strategy for arbitrary `ScanStats`.
fn arb_stats() -> impl Strategy<Value = ScanStats> {
    (0..100_u64, 0..1000_u64, 0..10000_u64).prop_map(|(p, i, b)| ScanStats::new(p, i, b))
}

// ---------------------------------------------------------------------------
// Property tests — merge algebra
//
// Each set of 3 (associativity, commutativity, identity) subsumes individual
// unit tests that would verify merge behavior with specific value pairs.
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn counters_merge_associative(
        a in arb_counters(),
        b in arb_counters(),
        c in arb_counters(),
    ) {
        prop_assert_eq!(a.merge(b).merge(c), a.merge(b.merge(c)));
    }

    #[test]
    fn counters_merge_commutative(a in arb_counters(), b in arb_counters()) {
        prop_assert_eq!(a.merge(b), b.merge(a));
    }

    #[test]
    fn counters_merge_identity(a in arb_counters()) {
        prop_assert_eq!(a.merge(ScanDedupeCounters::default()), a);
    }

    #[test]
    fn stats_merge_associative(
        a in arb_stats(),
        b in arb_stats(),
        c in arb_stats(),
    ) {
        prop_assert_eq!(a.merge(b).merge(c), a.merge(b.merge(c)));
    }

    #[test]
    fn stats_merge_commutative(a in arb_stats(), b in arb_stats()) {
        prop_assert_eq!(a.merge(b), b.merge(a));
    }

    #[test]
    fn stats_merge_identity(a in arb_stats()) {
        prop_assert_eq!(a.merge(ScanStats::default()), a);
    }
}

// ---------------------------------------------------------------------------
// ScanDedupeCounters — builder chain correctness
// ---------------------------------------------------------------------------

#[test]
fn counters_merge_accumulates_all_fields() {
    let a = make_counters(3, 2, 1, 0);
    let b = make_counters(1, 0, 2, 3);
    let merged = a.merge(b);
    assert_eq!(merged.candidates(), 4);
    assert_eq!(merged.emitted(), 2);
    assert_eq!(merged.duplicate_suppressed(), 3);
    assert_eq!(merged.limit_suppressed(), 3);
}

// ---------------------------------------------------------------------------
// ScanDedupState — HashSet wrapper semantics
// ---------------------------------------------------------------------------

#[test]
fn mark_seen_returns_true_on_first_insert() {
    let mut state = ScanDedupState::new();
    assert!(state.mark_seen(42), "first insert should return true");
    assert_eq!(state.len(), 1);
}

#[test]
fn mark_seen_returns_false_on_duplicate() {
    let mut state = ScanDedupState::new();
    state.mark_seen(42);
    assert!(!state.mark_seen(42), "duplicate insert should return false");
    assert_eq!(state.len(), 1);
}

#[test]
fn clear_resets_dedupe_state() {
    let mut state = ScanDedupState::new();
    state.mark_seen(1);
    state.mark_seen(2);
    assert_eq!(state.len(), 2);

    state.clear();
    assert!(state.is_empty());

    // Re-insertion after clear returns true (freshly inserted).
    assert!(state.mark_seen(1));
}

// ---------------------------------------------------------------------------
// PageScanOutput — clear + reuse contract
// ---------------------------------------------------------------------------

#[test]
fn page_output_clear_resets_all_fields() {
    let mut output = PageScanOutput::empty();
    output.set_summary(PageScanSummary::new(5, 0xDEAD, 10, 1000));
    output.set_stats(ScanStats::new(1, 10, 1000));
    output.set_dedupe(make_counters(3, 2, 1, 0));
    output.push_finding(ScanFinding::new(
        gossip_contracts::identity::StableItemId::from_bytes([0x01; 32]),
        gossip_contracts::connector::VersionId::Strong(
            gossip_contracts::identity::ObjectVersionId::from_version_bytes(b"v1"),
        ),
        5,
        0,
        0xCAFE,
        100,
    ));
    output.push_diagnostic(ScanDiagnostic::MetadataOnlyInputs {
        page_num: 5,
        item_count: 10,
    });

    output.clear();

    assert!(output.findings().is_empty());
    assert!(output.diagnostics().is_empty());
    assert_eq!(output.summary().page_num(), 0);
    assert_eq!(output.stats().pages_scanned(), 0);
    assert_eq!(output.dedupe().candidates(), 0);
}

// ---------------------------------------------------------------------------
// StreamScanOutput — push_page accumulation
// ---------------------------------------------------------------------------

#[test]
fn stream_output_push_page_accumulates() {
    let mut stream = StreamScanOutput::empty();

    // Build a page output with known values.
    let mut page = PageScanOutput::empty();
    page.set_summary(PageScanSummary::new(1, 0xAA, 3, 100));
    page.set_stats(ScanStats::new(1, 3, 100));
    page.set_dedupe(make_counters(3, 2, 1, 0));

    stream.push_page(&page);

    assert_eq!(stream.page_summaries().len(), 1);
    assert_eq!(stream.stats().pages_scanned(), 1);
    assert_eq!(stream.stats().items_scanned(), 3);
    assert_eq!(stream.stats().bytes_scanned(), 100);
    assert_eq!(stream.dedupe().candidates(), 3);

    // Push a second page and verify accumulation.
    let mut page2 = PageScanOutput::empty();
    page2.set_summary(PageScanSummary::new(2, 0xBB, 5, 200));
    page2.set_stats(ScanStats::new(1, 5, 200));
    page2.set_dedupe(make_counters(5, 3, 2, 0));

    stream.push_page(&page2);

    assert_eq!(stream.page_summaries().len(), 2);
    assert_eq!(stream.stats().pages_scanned(), 2);
    assert_eq!(stream.stats().items_scanned(), 8);
    assert_eq!(stream.stats().bytes_scanned(), 300);
    assert_eq!(stream.dedupe().candidates(), 8);
    assert_eq!(stream.dedupe().emitted(), 5);
}
