use std::fs;
use std::path::PathBuf;

use gossip_contracts::{
    connector::{Cursor, ItemKey, ItemRef, ScanItem, TokenBytes, VersionId},
    identity::{ObjectVersionId, StableItemId},
};
use gossip_engine::{
    CanonicalRun, PageScanContext, PageScanRequest, ScannerCore, canonicalize_stream_output,
    enforce_throughput_thresholds,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct FixtureRun {
    page_summaries: Vec<FixturePageSummary>,
    findings: Vec<FixtureFinding>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct FixturePageSummary {
    page_num: u64,
    signature: u64,
    item_count: usize,
    bytes_scanned: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct FixtureFinding {
    stable_item_id_hex: String,
    version_strength: String,
    version_hex: String,
    page_num: u64,
    item_index: usize,
    fingerprint: u64,
    payload_bytes: u64,
}

impl From<CanonicalRun> for FixtureRun {
    fn from(run: CanonicalRun) -> Self {
        Self {
            page_summaries: run
                .page_summaries
                .into_iter()
                .map(|summary| FixturePageSummary {
                    page_num: summary.page_num,
                    signature: summary.signature,
                    item_count: summary.item_count,
                    bytes_scanned: summary.bytes_scanned,
                })
                .collect(),
            findings: run
                .findings
                .into_iter()
                .map(|finding| FixtureFinding {
                    stable_item_id_hex: finding.stable_item_id_hex,
                    version_strength: finding.version_strength.as_str().to_owned(),
                    version_hex: finding.version_hex,
                    page_num: finding.page_num,
                    item_index: finding.item_index,
                    fingerprint: finding.fingerprint,
                    payload_bytes: finding.payload_bytes,
                })
                .collect(),
        }
    }
}

fn make_item(key: &[u8], item_ref: &[u8], stable: [u8; 32], version: &[u8]) -> ScanItem {
    ScanItem::new(
        ItemKey::try_from_slice(key).expect("valid key"),
        ItemRef::try_from_slice(item_ref).expect("valid ref"),
        StableItemId::from_bytes(stable),
        VersionId::Strong(ObjectVersionId::from_version_bytes(version)),
    )
}

fn build_case_output() -> FixtureRun {
    let core = ScannerCore::builder()
        .max_findings_per_page(16)
        .emit_metadata_only_diagnostics(false)
        .build()
        .expect("valid core config");

    let cursor0 = Cursor::initial();
    let cursor1 = Cursor::with_last_key(ItemKey::try_from_slice(b"k-1").expect("key"));
    let cursor2 = Cursor::with_token(
        ItemKey::try_from_slice(b"k-3").expect("key"),
        TokenBytes::try_from_slice(b"token-2").expect("token"),
    );

    let page1_items = [
        make_item(b"k-1", b"ref-1", [0x11; 32], b"version-a"),
        make_item(b"k-2", b"ref-2", [0x22; 32], b"version-b"),
    ];
    let page1_bytes: [&[u8]; 2] = [b"alpha-secret", b"bravo-secret"];

    let page2_items = [
        make_item(b"k-1", b"ref-1", [0x11; 32], b"version-a"), // duplicate fingerprint
        make_item(b"k-3", b"ref-3", [0x33; 32], b"version-c"),
    ];
    let page2_bytes: [&[u8]; 2] = [b"alpha-secret", b"charlie-secret"];

    let run = core
        .scan_stream([
            PageScanRequest::with_item_bytes(
                PageScanContext::new(b"a", b"z", &cursor0, &cursor1, 1),
                &page1_items,
                &page1_bytes,
            ),
            PageScanRequest::with_item_bytes(
                PageScanContext::new(b"a", b"z", &cursor1, &cursor2, 2),
                &page2_items,
                &page2_bytes,
            ),
        ])
        .expect("fixture scan should succeed");

    FixtureRun::from(canonicalize_stream_output(&run))
}

fn load_fixture(name: &str) -> FixtureRun {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name);
    let bytes = fs::read(&path).unwrap_or_else(|err| {
        panic!("failed to read fixture {}: {}", path.display(), err);
    });
    serde_json::from_slice(&bytes).unwrap_or_else(|err| {
        panic!("failed to parse fixture {}: {}", path.display(), err);
    })
}

#[test]
fn migrated_core_matches_known_good_fixture() {
    let actual = build_case_output();
    if std::env::var_os("GOSSIP_ENGINE_PRINT_PARITY_FIXTURE").is_some() {
        eprintln!(
            "candidate fixture:\n{}",
            serde_json::to_string_pretty(&actual).expect("serialize fixture")
        );
    }
    let expected = load_fixture("phase1b_core_parity.json");

    assert_eq!(
        actual, expected,
        "fixture parity drift detected; run with GOSSIP_ENGINE_PRINT_PARITY_FIXTURE=1 to inspect candidate output"
    );
}

#[test]
fn throughput_policy_matches_phase_threshold_defaults() {
    // Baseline policy gate for phase cutover:
    // - median absolute delta <= 2%
    // - per-case absolute delta <= 5%
    let passing = [1.8, -1.1, 2.0, -0.8, 4.9];
    let median_abs = enforce_throughput_thresholds(&passing, 2.0, 5.0).expect("must pass");
    assert!(
        median_abs <= 2.0,
        "median absolute delta should respect 2% policy"
    );

    let failing = [1.0, -5.2];
    let err = enforce_throughput_thresholds(&failing, 2.0, 5.0).expect_err("must fail");
    assert!(
        format!("{err}").contains("per-case"),
        "per-case gate should explain failure reason"
    );
}
