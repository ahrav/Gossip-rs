use gossip_contracts::connector::{Cursor, ItemKey, ScanItem, TokenBytes};
use proptest::prelude::*;

use super::*;
use crate::test_support::{make_item, make_weak_item};

// ---------------------------------------------------------------------------
// Existing tests (extracted from core.rs inline module)
// ---------------------------------------------------------------------------

#[test]
fn builder_rejects_zero_max_findings_per_page() {
    let err = ScannerCore::builder()
        .max_findings_per_page(0)
        .build()
        .unwrap_err();
    assert_eq!(err, ScannerCoreBuildError::ZeroMaxFindingsPerPage);
}

#[test]
fn metadata_only_page_emits_findings_and_diagnostic() {
    let core = ScannerCore::default();
    let cursor = Cursor::initial();
    let next_cursor =
        Cursor::with_last_key(ItemKey::try_from_slice(b"charlie").expect("valid key"));
    let items = [make_item(b"alpha", b"ref-a", [0x11; 32], b"v1")];
    let context = PageScanContext::new(b"a", b"z", &cursor, &next_cursor, 1);

    let output = core
        .scan_page(PageScanRequest::metadata_only(context, &items))
        .expect("metadata-only request should scan");

    assert_eq!(output.summary().page_num(), 1);
    assert_eq!(output.summary().item_count(), 1);
    assert_eq!(output.stats().bytes_scanned(), 0);
    assert_eq!(output.findings().len(), 1);
    assert_eq!(output.dedupe().candidates(), 1);
    assert_eq!(output.dedupe().emitted(), 1);
    assert_eq!(
        output.diagnostics(),
        &[ScanDiagnostic::MetadataOnlyInputs {
            page_num: 1,
            item_count: 1
        }]
    );
}

#[test]
fn page_with_mismatched_item_bytes_is_rejected() {
    let core = ScannerCore::default();
    let cursor = Cursor::initial();
    let next_cursor = Cursor::with_token(
        ItemKey::try_from_slice(b"alpha").expect("valid key"),
        TokenBytes::try_from_slice(b"token-a").expect("valid token"),
    );
    let items = [
        make_item(b"alpha", b"ref-a", [0x11; 32], b"v1"),
        make_item(b"bravo", b"ref-b", [0x22; 32], b"v2"),
    ];
    let bytes: [&[u8]; 1] = [b"payload-alpha"];
    let request = PageScanRequest::with_item_bytes(
        PageScanContext::new(b"a", b"z", &cursor, &next_cursor, 1),
        &items,
        &bytes,
    );
    let err = core.scan_page(request).unwrap_err();
    assert_eq!(
        err,
        ScannerCoreError::ItemBytesLenMismatch {
            page_num: 1,
            items: 2,
            item_bytes: 1,
        }
    );
}

#[test]
fn stream_scan_dedupes_across_pages() {
    let core = ScannerCore::default();
    let cursor = Cursor::initial();
    let next_cursor = Cursor::with_last_key(ItemKey::try_from_slice(b"alpha").expect("valid key"));
    let page1_items = [make_item(b"alpha", b"ref-a", [0x11; 32], b"v1")];
    let page2_items = [make_item(b"alpha", b"ref-a", [0x11; 32], b"v1")];
    let page1_bytes: [&[u8]; 1] = [b"payload-alpha"];
    let page2_bytes: [&[u8]; 1] = [b"payload-alpha"];
    let page1 = PageScanRequest::with_item_bytes(
        PageScanContext::new(b"a", b"z", &cursor, &next_cursor, 1),
        &page1_items,
        &page1_bytes,
    );
    let page2 = PageScanRequest::with_item_bytes(
        PageScanContext::new(b"a", b"z", &cursor, &next_cursor, 2),
        &page2_items,
        &page2_bytes,
    );

    let output = core
        .scan_stream([page1, page2])
        .expect("stream scan should succeed");

    assert_eq!(output.stats().pages_scanned(), 2);
    assert_eq!(output.stats().items_scanned(), 2);
    assert_eq!(output.dedupe().candidates(), 2);
    assert_eq!(output.dedupe().emitted(), 1);
    assert_eq!(output.dedupe().duplicate_suppressed(), 1);
    assert_eq!(output.findings().len(), 1);
}

#[test]
fn stream_scan_requires_strictly_increasing_page_numbers() {
    let core = ScannerCore::default();
    let cursor = Cursor::initial();
    let next_cursor = Cursor::with_last_key(ItemKey::try_from_slice(b"alpha").expect("valid key"));
    let items = [make_item(b"alpha", b"ref-a", [0x11; 32], b"v1")];
    let page1 = PageScanRequest::metadata_only(
        PageScanContext::new(b"a", b"z", &cursor, &next_cursor, 2),
        &items,
    );
    let page2 = PageScanRequest::metadata_only(
        PageScanContext::new(b"a", b"z", &cursor, &next_cursor, 1),
        &items,
    );

    let err = core.scan_stream([page1, page2]).unwrap_err();
    assert_eq!(
        err,
        ScannerCoreError::NonMonotonicPageNum {
            previous_page_num: 2,
            page_num: 1
        }
    );
}

// ---------------------------------------------------------------------------
// New unit tests — each exercises a distinct behavior not covered by proptest
// ---------------------------------------------------------------------------

#[test]
fn default_config_values() {
    let config = ScannerCoreConfig::default();
    assert_eq!(config.max_findings_per_page(), 8_192);
    assert!(config.emit_metadata_only_diagnostics());
}

#[test]
fn builder_with_config_preserves_values() {
    let config = ScannerCoreConfig::new(42, false);
    let core = ScannerCoreBuilder::with_config(config).build().unwrap();
    assert_eq!(core.config().max_findings_per_page(), 42);
    assert!(!core.config().emit_metadata_only_diagnostics());
}

#[test]
fn findings_cap_emits_truncation_diagnostic() {
    let core = ScannerCore::builder()
        .max_findings_per_page(2)
        .build()
        .unwrap();
    let cursor = Cursor::initial();
    let next_cursor = Cursor::initial();
    // Three unique items; cap is 2 → one limit_suppressed + truncation diagnostic.
    let items = [
        make_item(b"a", b"ra", [0x01; 32], b"v1"),
        make_item(b"b", b"rb", [0x02; 32], b"v2"),
        make_item(b"c", b"rc", [0x03; 32], b"v3"),
    ];
    let context = PageScanContext::new(b"", b"", &cursor, &next_cursor, 1);
    let output = core
        .scan_page(PageScanRequest::metadata_only(context, &items))
        .unwrap();

    assert_eq!(output.findings().len(), 2);
    assert_eq!(output.dedupe().candidates(), 3);
    assert_eq!(output.dedupe().emitted(), 2);
    assert_eq!(output.dedupe().limit_suppressed(), 1);
    assert_eq!(
        output.diagnostics(),
        &[
            ScanDiagnostic::MetadataOnlyInputs {
                page_num: 1,
                item_count: 3,
            },
            ScanDiagnostic::FindingsTruncated {
                page_num: 1,
                max_findings_per_page: 2,
                suppressed: 1,
            },
        ]
    );
}

#[test]
fn metadata_diag_suppressed_when_disabled() {
    let core = ScannerCore::builder()
        .emit_metadata_only_diagnostics(false)
        .build()
        .unwrap();
    let cursor = Cursor::initial();
    let next_cursor = Cursor::initial();
    let items = [make_item(b"a", b"ra", [0x01; 32], b"v1")];
    let context = PageScanContext::new(b"", b"", &cursor, &next_cursor, 1);
    let output = core
        .scan_page(PageScanRequest::metadata_only(context, &items))
        .unwrap();

    assert!(
        output.diagnostics().is_empty(),
        "metadata-only diagnostic should not be emitted when disabled"
    );
}

#[test]
fn empty_page_produces_zero_findings() {
    let core = ScannerCore::default();
    let cursor = Cursor::initial();
    let next_cursor = Cursor::initial();
    let items: [ScanItem; 0] = [];
    let context = PageScanContext::new(b"", b"", &cursor, &next_cursor, 1);
    let output = core
        .scan_page(PageScanRequest::metadata_only(context, &items))
        .unwrap();

    assert!(output.findings().is_empty());
    assert_eq!(output.summary().item_count(), 0);
    assert_eq!(output.stats().bytes_scanned(), 0);
    assert_eq!(output.dedupe().candidates(), 0);
    assert!(output.diagnostics().is_empty());
}

#[test]
fn scan_page_into_reuses_output() {
    let core = ScannerCore::default();
    let cursor = Cursor::initial();
    let next_cursor = Cursor::initial();
    let items = [make_item(b"a", b"ra", [0x01; 32], b"v1")];
    let context1 = PageScanContext::new(b"", b"", &cursor, &next_cursor, 1);
    let context2 = PageScanContext::new(b"", b"", &cursor, &next_cursor, 2);

    let mut dedupe = ScanDedupState::default();
    let mut output = PageScanOutput::empty();

    // First scan: output gets populated.
    core.scan_page_into(
        PageScanRequest::metadata_only(context1, &items),
        &mut dedupe,
        &mut output,
    )
    .unwrap();
    assert_eq!(output.findings().len(), 1);

    // Second scan into same output: previous results are cleared.
    let items2 = [make_item(b"b", b"rb", [0x02; 32], b"v2")];
    core.scan_page_into(
        PageScanRequest::metadata_only(context2, &items2),
        &mut dedupe,
        &mut output,
    )
    .unwrap();
    assert_eq!(output.findings().len(), 1, "old findings should be cleared");
    assert_eq!(
        output.summary().page_num(),
        2,
        "summary should reflect the second scan"
    );
}

#[test]
fn page_with_payload_counts_bytes() {
    let core = ScannerCore::default();
    let cursor = Cursor::initial();
    let next_cursor = Cursor::initial();
    let items = [
        make_item(b"a", b"ra", [0x01; 32], b"v1"),
        make_item(b"b", b"rb", [0x02; 32], b"v2"),
    ];
    let bytes: [&[u8]; 2] = [b"hello", b"world!"];
    let context = PageScanContext::new(b"", b"", &cursor, &next_cursor, 1);
    let request = PageScanRequest::with_item_bytes(context, &items, &bytes);
    let output = core.scan_page(request).unwrap();

    assert_eq!(output.stats().bytes_scanned(), 11); // 5 + 6
    assert!(
        output.diagnostics().is_empty(),
        "payload-present page should have no metadata-only diagnostic"
    );
}

#[test]
fn fnv_opt_domain_separation() {
    // None and Some(b"") must hash differently so empty tokens are
    // distinguishable from absent tokens in page signatures.
    let mut sig_none = FNV_OFFSET;
    fnv_mix_opt_bytes(&mut sig_none, None);

    let mut sig_empty = FNV_OFFSET;
    fnv_mix_opt_bytes(&mut sig_empty, Some(b""));

    assert_ne!(
        sig_none, sig_empty,
        "None and Some(empty) must produce different hashes"
    );
}

#[test]
fn version_strong_vs_weak_fingerprint() {
    // Strong and Weak version tags use distinct domain-separation bytes (1 vs 2)
    // so the same version payload under different claim strengths produces a
    // different fingerprint.
    let strong = make_item(b"k", b"r", [0xAA; 32], b"ver1");
    let weak = make_weak_item(b"k", b"r", [0xAA; 32], b"ver1");

    let fp_strong = finding_fingerprint(&strong, b"payload");
    let fp_weak = finding_fingerprint(&weak, b"payload");

    assert_ne!(
        fp_strong, fp_weak,
        "Strong and Weak version tags must produce distinct fingerprints"
    );
}

// ---------------------------------------------------------------------------
// Property tests — each subsumes multiple potential unit tests
// ---------------------------------------------------------------------------

/// Proptest strategy: byte vec of 1..64 bytes, well within ItemKey/ItemRef limits.
fn arb_key() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 1..64)
}

/// Proptest strategy: non-empty version bytes (from_version_bytes panics on empty).
fn arb_version_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 1..32)
}

proptest! {
    /// The finding fingerprint covers (stable_item_id, version, payload) but
    /// explicitly excludes item_key and item_ref. This property verifies the
    /// design decision: changing only key/ref must NOT change the fingerprint.
    ///
    /// Subsumes individual unit tests for key-only, ref-only, and both-changed
    /// scenarios.
    #[test]
    fn fingerprint_independent_of_key_and_ref(
        key_a in arb_key(),
        key_b in arb_key(),
        ref_a in arb_key(),
        ref_b in arb_key(),
        stable_id in prop::array::uniform32(any::<u8>()),
        version in arb_version_bytes(),
        payload in prop::collection::vec(any::<u8>(), 0..100),
    ) {
        let item_a = make_item(&key_a, &ref_a, stable_id, &version);
        let item_b = make_item(&key_b, &ref_b, stable_id, &version);
        prop_assert_eq!(
            finding_fingerprint(&item_a, &payload),
            finding_fingerprint(&item_b, &payload),
        );
    }

    /// The dedupe funnel invariant must hold after every page scan:
    ///   candidates == emitted + duplicate_suppressed + limit_suppressed
    ///
    /// This property is exercised over random item counts and findings caps,
    /// with intentional duplicate items (modular identity) to exercise all
    /// three counter paths (emit, duplicate, limit).
    ///
    /// Subsumes any hand-crafted unit test that manually checks the funnel
    /// equation for a specific scenario.
    #[test]
    fn dedupe_funnel_invariant(
        num_items in 0..15_usize,
        max_findings in 1..20_usize,
    ) {
        let items: Vec<ScanItem> = (0..num_items)
            .map(|i| {
                // Modular identity creates duplicates when num_items > 5.
                let idx = (i % 5) as u8;
                make_item(&[idx], &[idx], [idx; 32], &[idx, 1])
            })
            .collect();
        let core = ScannerCore::builder()
            .max_findings_per_page(max_findings)
            .build()
            .unwrap();
        let cursor = Cursor::initial();
        let next_cursor = Cursor::initial();
        let context = PageScanContext::new(b"", b"", &cursor, &next_cursor, 1);
        let request = PageScanRequest::metadata_only(context, &items);
        let output = core.scan_page(request).unwrap();
        let d = output.dedupe();
        prop_assert_eq!(
            d.candidates(),
            d.emitted() + d.duplicate_suppressed() + d.limit_suppressed(),
            "funnel invariant violated: candidates={}, emitted={}, dup={}, limit={}",
            d.candidates(), d.emitted(), d.duplicate_suppressed(), d.limit_suppressed(),
        );
    }

    /// Scanning the same page twice with a fresh `ScannerCore` must produce
    /// the same page signature both times.  The FNV-1a hash is pure: it
    /// depends only on the key range, cursor pair, and item fields — no
    /// hidden mutable state.
    #[test]
    fn page_signature_is_deterministic(
        key in arb_key(),
        version in arb_version_bytes(),
        stable_id in prop::array::uniform32(any::<u8>()),
    ) {
        let items = [make_item(&key, &key, stable_id, &version)];
        let cursor = Cursor::initial();
        let next_cursor = Cursor::initial();

        let context1 = PageScanContext::new(b"a", b"z", &cursor, &next_cursor, 1);
        let output1 = ScannerCore::default()
            .scan_page(PageScanRequest::metadata_only(context1, &items))
            .expect("first scan should succeed");

        let context2 = PageScanContext::new(b"a", b"z", &cursor, &next_cursor, 1);
        let output2 = ScannerCore::default()
            .scan_page(PageScanRequest::metadata_only(context2, &items))
            .expect("second scan should succeed");

        prop_assert_eq!(
            output1.summary().signature(),
            output2.summary().signature(),
            "identical inputs must yield identical page signatures"
        );
    }
}

#[test]
fn different_items_produce_different_signatures() {
    let cursor = Cursor::initial();
    let next_cursor = Cursor::initial();

    let items_a = [make_item(b"alpha", b"ref-a", [0x11; 32], b"v1")];
    let context_a = PageScanContext::new(b"a", b"z", &cursor, &next_cursor, 1);
    let output_a = ScannerCore::default()
        .scan_page(PageScanRequest::metadata_only(context_a, &items_a))
        .expect("scan A should succeed");

    let items_b = [make_item(b"bravo", b"ref-b", [0x22; 32], b"v2")];
    let context_b = PageScanContext::new(b"a", b"z", &cursor, &next_cursor, 1);
    let output_b = ScannerCore::default()
        .scan_page(PageScanRequest::metadata_only(context_b, &items_b))
        .expect("scan B should succeed");

    assert_ne!(
        output_a.summary().signature(),
        output_b.summary().signature(),
        "pages with different items must produce different signatures"
    );
}

#[test]
fn explicitly_empty_payload_not_classified_as_metadata_only() {
    let core = ScannerCore::default();
    let cursor = Cursor::initial();
    let next_cursor = Cursor::with_last_key(ItemKey::try_from_slice(b"zulu").expect("valid key"));
    let items = [make_item(b"alpha", b"ref-a", [0x11; 32], b"v1")];
    // Bytes are explicitly provided but happen to be empty (e.g. empty file).
    let payloads: &[&[u8]] = &[b""];
    let context = PageScanContext::new(b"a", b"z", &cursor, &next_cursor, 1);

    let output = core
        .scan_page(PageScanRequest::with_item_bytes(context, &items, payloads))
        .expect("scan with empty payload bytes should succeed");

    // Bytes were supplied — the page is NOT metadata-only, even though
    // the payload happens to be zero-length.
    assert!(
        !output
            .diagnostics()
            .iter()
            .any(|d| matches!(d, ScanDiagnostic::MetadataOnlyInputs { .. })),
        "MetadataOnlyInputs should not fire when item_bytes is Some (even if payloads are empty)"
    );
}

// ---------------------------------------------------------------------------
// F8: Empty and single-page stream tests
// ---------------------------------------------------------------------------

#[test]
fn scan_stream_handles_empty_iterator() {
    let core = ScannerCore::default();
    let pages: Vec<PageScanRequest<'_>> = vec![];
    let output = core
        .scan_stream(pages)
        .expect("empty stream should succeed");
    assert!(output.findings().is_empty());
    assert!(output.page_summaries().is_empty());
    assert_eq!(output.stats().pages_scanned(), 0);
    assert_eq!(output.stats().items_scanned(), 0);
    assert_eq!(output.stats().bytes_scanned(), 0);
    assert_eq!(output.dedupe().candidates(), 0);
}

#[test]
fn scan_stream_handles_single_page() {
    let core = ScannerCore::default();
    let cursor = Cursor::initial();
    let next_cursor = Cursor::initial();
    let items = [make_item(b"alpha", b"ref-a", [0x11; 32], b"v1")];
    let bytes: [&[u8]; 1] = [b"payload-alpha"];
    let page = PageScanRequest::with_item_bytes(
        PageScanContext::new(b"a", b"z", &cursor, &next_cursor, 1),
        &items,
        &bytes,
    );
    let output = core
        .scan_stream([page])
        .expect("single-page stream should succeed");
    assert_eq!(output.page_summaries().len(), 1);
    assert_eq!(output.findings().len(), 1);
    assert_eq!(output.stats().pages_scanned(), 1);
    assert_eq!(output.stats().items_scanned(), 1);
    assert_eq!(output.dedupe().emitted(), 1);
}

// ---------------------------------------------------------------------------
// F9: Direct scan_page_with_dedupe test
// ---------------------------------------------------------------------------

#[test]
fn scan_page_with_dedupe_preserves_state_across_calls() {
    let core = ScannerCore::default();
    let cursor = Cursor::initial();
    let next_cursor = Cursor::initial();
    let mut dedupe = ScanDedupState::default();

    // First call: item A is new.
    let items1 = [make_item(b"a", b"ra", [0x01; 32], b"v1")];
    let ctx1 = PageScanContext::new(b"", b"", &cursor, &next_cursor, 1);
    let out1 = core
        .scan_page_with_dedupe(PageScanRequest::metadata_only(ctx1, &items1), &mut dedupe)
        .unwrap();
    assert_eq!(out1.findings().len(), 1);
    assert_eq!(out1.dedupe().emitted(), 1);

    // Second call: same item A is duplicate, item B is new.
    let items2 = [
        make_item(b"a", b"ra", [0x01; 32], b"v1"),
        make_item(b"b", b"rb", [0x02; 32], b"v2"),
    ];
    let ctx2 = PageScanContext::new(b"", b"", &cursor, &next_cursor, 2);
    let out2 = core
        .scan_page_with_dedupe(PageScanRequest::metadata_only(ctx2, &items2), &mut dedupe)
        .unwrap();
    assert_eq!(out2.findings().len(), 1, "only item B should be emitted");
    assert_eq!(out2.dedupe().candidates(), 2);
    assert_eq!(out2.dedupe().emitted(), 1);
    assert_eq!(out2.dedupe().duplicate_suppressed(), 1);
}
