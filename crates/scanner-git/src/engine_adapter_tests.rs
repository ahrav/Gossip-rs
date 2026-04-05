use super::*;
use crate::alloc_guard;
use crate::pack_candidates::LooseCandidate;
use crate::tree_candidate::{CandidateContext, ChangeKind};
use crate::ByteRef;
use crate::{demo_engine_with_anchor_mode, AnchorMode};

/// Verify that the scan hot path allocates nothing after warmup.
///
/// The alloc guard uses **global** counters, so allocations from any
/// thread are visible. Run with:
///
/// ```sh
/// SCANNER_RS_ALLOC_GUARD=1 cargo test --lib scan_alloc_guard_no_alloc_after_warmup \
///     -- --test-threads=1
/// ```
#[test]
fn scan_alloc_guard_no_alloc_after_warmup() {
    if std::env::var("SCANNER_RS_ALLOC_GUARD").ok().as_deref() != Some("1") {
        eprintln!(
            "alloc guard test skipped; set SCANNER_RS_ALLOC_GUARD=1 and \
             run with --test-threads=1 to enable"
        );
        return;
    }

    let engine = demo_engine_with_anchor_mode(AnchorMode::Manual);
    let mut adapter = EngineAdapter::new(&engine, EngineAdapterConfig::default());

    let ctx = CandidateContext {
        commit_id: 0,
        parent_idx: 0,
        change_kind: ChangeKind::Add,
        ctx_flags: 0,
        cand_flags: 0,
        path_ref: ByteRef::new(0, 0),
    };
    let candidate = LooseCandidate {
        oid: OidBytes::from_slice(&[0u8; 20]),
        ctx,
    };
    let path = b"test.txt";
    let blob = b"no findings here";

    alloc_guard::set_enabled(false);
    adapter
        .emit_loose(&candidate, path, blob)
        .expect("warmup scan");

    alloc_guard::set_enabled(true);
    adapter
        .emit_loose(&candidate, path, blob)
        .expect("guarded scan");
    alloc_guard::set_enabled(false);
}

fn make_candidate() -> LooseCandidate {
    make_candidate_with_ctx(0, ChangeKind::Add)
}

/// Blob of exactly chunk_bytes takes the bypass path (single chunk).
#[test]
fn chunker_bypass_exact_chunk_size() {
    let engine = demo_engine_with_anchor_mode(AnchorMode::Manual);
    let config = EngineAdapterConfig::default();
    let mut adapter = EngineAdapter::new(&engine, config);
    let candidate = make_candidate();

    // Blob exactly chunk_bytes long — should take bypass (one chunk).
    let blob = vec![b'a'; config.chunk_bytes];
    adapter
        .emit_loose(&candidate, b"test.txt", &blob)
        .expect("exact chunk_bytes scan");
    assert_eq!(adapter.results().len(), 1);
}

/// Blob of chunk_bytes + 1 takes the slow path (two chunks).
#[test]
fn chunker_slow_path_chunk_size_plus_one() {
    let engine = demo_engine_with_anchor_mode(AnchorMode::Manual);
    let config = EngineAdapterConfig::default();
    let mut adapter = EngineAdapter::new(&engine, config);
    let candidate = make_candidate();

    // Blob one byte over chunk_bytes — must use the ring chunker.
    let blob = vec![b'a'; config.chunk_bytes + 1];
    adapter
        .emit_loose(&candidate, b"test.txt", &blob)
        .expect("chunk_bytes+1 scan");
    assert_eq!(adapter.results().len(), 1);
}

/// Binary blob (contains NUL byte) is skipped entirely.
#[test]
fn binary_blob_skipped() {
    let engine = demo_engine_with_anchor_mode(AnchorMode::Manual);
    let mut adapter = EngineAdapter::new(&engine, EngineAdapterConfig::default());
    let candidate = make_candidate();

    let mut blob = vec![b'a'; 1024];
    blob[512] = 0; // NUL byte at offset 512
    adapter
        .emit_loose(&candidate, b"image.png", &blob)
        .expect("binary scan");
    // Should have a result entry with zero findings.
    assert_eq!(adapter.results().len(), 1);
    assert_eq!(adapter.results()[0].findings.len, 0);
}

/// Pure-text blob is not skipped.
#[test]
fn text_blob_not_skipped() {
    let engine = demo_engine_with_anchor_mode(AnchorMode::Manual);
    let mut adapter = EngineAdapter::new(&engine, EngineAdapterConfig::default());
    let candidate = make_candidate();

    let blob = b"this is plain text with no NUL bytes";
    adapter
        .emit_loose(&candidate, b"readme.txt", blob)
        .expect("text scan");
    assert_eq!(adapter.results().len(), 1);
}

/// is_likely_binary edge cases (delegated to content_policy).
#[test]
fn is_likely_binary_edge_cases() {
    use scanner_engine::content_policy::is_likely_binary;
    // Empty blob is not binary.
    assert!(!is_likely_binary(b"", 8192));
    // All-text is not binary.
    assert!(!is_likely_binary(b"hello world", 8192));
    // NUL at first byte.
    assert!(is_likely_binary(b"\0hello", 8192));
    // NUL beyond check_len is not detected.
    let mut data = vec![b'a'; 100];
    data.push(0);
    assert!(!is_likely_binary(&data, 100));
    // NUL at exact boundary.
    let mut data2 = vec![b'a'; 99];
    data2.push(0);
    assert!(is_likely_binary(&data2, 100));
}

// -- Attribution event tests ------------------------------------------------

use crate::commit_graph::CommitGraphIndex;
use crate::events::{EventSink, ScanEvent, VecEventSink};
use gossip_stdx::AtomicBitSet;
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

/// Build a test adapter with event sink and dummy commit-graph / bitset.
///
/// The dummy graph is empty and the bitset has a single bit; this means
/// `stream_findings` will skip commit-meta emission (commit_id out of
/// range), which is fine for tests that only verify finding events.
fn test_adapter_with_sink<'a>(engine: &'a Engine, sink: Arc<VecEventSink>) -> EngineAdapter<'a> {
    EngineAdapter::new_with_event_sink(
        engine,
        EngineAdapterConfig::default(),
        CommitMetaContext {
            event_sink: sink,
            commit_graph_index: Arc::new(CommitGraphIndex::empty()),
            commit_meta_seen: Arc::new(AtomicBitSet::empty(1)),
            identity_interner: None,
        },
    )
}

#[derive(Default)]
struct CapturingFindingSink {
    findings: Mutex<Vec<CapturedFindingEvent>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CapturedFindingEvent {
    start: u64,
    end: u64,
    match_start: u64,
    match_end: u64,
    norm_hash: [u8; 32],
}

impl CapturingFindingSink {
    fn take_findings(&self) -> Vec<CapturedFindingEvent> {
        std::mem::take(&mut *self.findings.lock().expect("capturing sink mutex poisoned"))
    }
}

impl EventSink for CapturingFindingSink {
    fn emit(&self, event: ScanEvent<'_>) {
        if let ScanEvent::Finding(finding) = event {
            self.findings
                .lock()
                .expect("capturing sink mutex poisoned")
                .push(CapturedFindingEvent {
                    start: finding.start,
                    end: finding.end,
                    match_start: finding.match_start,
                    match_end: finding.match_end,
                    norm_hash: finding.norm_hash,
                });
        }
    }

    fn flush(&self) {}
}

fn test_adapter_with_capturing_sink<'a>(
    engine: &'a Engine,
    sink: Arc<CapturingFindingSink>,
) -> EngineAdapter<'a> {
    EngineAdapter::new_with_event_sink(
        engine,
        EngineAdapterConfig::default(),
        CommitMetaContext {
            event_sink: sink,
            commit_graph_index: Arc::new(CommitGraphIndex::empty()),
            commit_meta_seen: Arc::new(AtomicBitSet::empty(1)),
            identity_interner: None,
        },
    )
}
use crate::{
    demo_tuning, AnchorPolicy, Gate, RuleSpec, TransformConfig, TransformId, TransformMode,
    ValidatorKind,
};
use regex::bytes::Regex;

fn test_engine_with_tok_rule() -> Engine {
    let rule = RuleSpec {
        name: "tok",
        anchors: &[b"TOK_"],
        radius: 16,
        validator: ValidatorKind::None,
        two_phase: None,
        must_contain: None,
        keywords_any: None,
        value_suppressors_any: None,
        entropy: None,
        char_class: None,
        local_context: None,
        secret_group: Some(1),
        min_confidence: None,
        offline_validation: None,
        uuid_format_secret: false,
        re: Regex::new(r"TOK_([A-Z0-9]{8})").unwrap(),
    };

    let transforms = vec![TransformConfig {
        id: TransformId::Base64,
        mode: TransformMode::Always,
        gate: Gate::AnchorsInDecoded,
        min_len: 16,
        max_spans_per_buffer: 4,
        max_encoded_len: 1024,
        max_decoded_bytes: 1024,
        plus_to_space: false,
        base64_allow_space_ws: false,
    }];

    Engine::new_with_anchor_policy(
        vec![rule],
        transforms,
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    )
}

fn test_engine_with_tok_rule_and_keyword_confidence() -> Engine {
    let rule = RuleSpec {
        name: "tok-keyword-confidence",
        anchors: &[b"TOK_"],
        radius: 16,
        validator: ValidatorKind::None,
        two_phase: None,
        must_contain: None,
        keywords_any: Some(&[b"TOK_"]),
        value_suppressors_any: None,
        entropy: None,
        char_class: None,
        local_context: None,
        secret_group: Some(1),
        min_confidence: None,
        offline_validation: None,
        uuid_format_secret: false,
        re: Regex::new(r"TOK_([A-Z0-9]{8})").unwrap(),
    };

    let transforms = vec![TransformConfig {
        id: TransformId::Base64,
        mode: TransformMode::Always,
        gate: Gate::AnchorsInDecoded,
        min_len: 16,
        max_spans_per_buffer: 4,
        max_encoded_len: 1024,
        max_decoded_bytes: 1024,
        plus_to_space: false,
        base64_allow_space_ws: false,
    }];

    Engine::new_with_anchor_policy(
        vec![rule],
        transforms,
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    )
}

fn make_candidate_with_ctx(commit_id: u32, change_kind: ChangeKind) -> LooseCandidate {
    let ctx = CandidateContext {
        commit_id,
        parent_idx: 0,
        change_kind,
        ctx_flags: 0,
        cand_flags: 0,
        path_ref: ByteRef::new(0, 0),
    };
    LooseCandidate {
        oid: OidBytes::from_slice(&[0u8; 20]),
        ctx,
    }
}

#[test]
fn git_finding_event_carries_add_attribution() {
    let engine = test_engine_with_tok_rule();
    let sink = Arc::new(VecEventSink::new());
    let mut adapter = test_adapter_with_sink(&engine, sink.clone());

    let candidate = make_candidate_with_ctx(42, ChangeKind::Add);
    let blob = b"prefix TOK_ABCDEFGH suffix";
    adapter
        .emit_loose(&candidate, b"secret.txt", blob)
        .expect("scan with Add attribution");

    let output = String::from_utf8(sink.take()).expect("valid UTF-8");
    assert!(
        output.contains("\"commit_id\":42"),
        "expected commit_id:42 in: {output}"
    );
    assert!(
        output.contains("\"change_kind\":\"add\""),
        "expected change_kind:add in: {output}"
    );
}

#[test]
fn git_finding_event_carries_modify_attribution() {
    let engine = test_engine_with_tok_rule();
    let sink = Arc::new(VecEventSink::new());
    let mut adapter = test_adapter_with_sink(&engine, sink.clone());

    let candidate = make_candidate_with_ctx(99, ChangeKind::Modify);
    let blob = b"prefix TOK_ABCDEFGH suffix";
    adapter
        .emit_loose(&candidate, b"secret.txt", blob)
        .expect("scan with Modify attribution");

    let output = String::from_utf8(sink.take()).expect("valid UTF-8");
    assert!(
        output.contains("\"commit_id\":99"),
        "expected commit_id:99 in: {output}"
    );
    assert!(
        output.contains("\"change_kind\":\"modify\""),
        "expected change_kind:modify in: {output}"
    );
}

#[test]
fn no_finding_blob_emits_no_events() {
    let engine = test_engine_with_tok_rule();
    let sink = Arc::new(VecEventSink::new());
    let mut adapter = test_adapter_with_sink(&engine, sink.clone());

    let candidate = make_candidate_with_ctx(1, ChangeKind::Add);
    let blob = b"nothing suspicious here";
    adapter
        .emit_loose(&candidate, b"clean.txt", blob)
        .expect("scan clean blob");

    let output = sink.take();
    assert!(output.is_empty(), "expected no events for clean blob");
}

#[test]
fn pack_object_sink_carries_attribution() {
    let engine = test_engine_with_tok_rule();
    let sink = Arc::new(VecEventSink::new());
    let mut adapter = test_adapter_with_sink(&engine, sink.clone());

    let ctx = CandidateContext {
        commit_id: 77,
        parent_idx: 0,
        change_kind: ChangeKind::Modify,
        ctx_flags: 0,
        cand_flags: 0,
        path_ref: ByteRef::new(0, 0),
    };
    let candidate = PackCandidate {
        oid: OidBytes::from_slice(&[0u8; 20]),
        ctx,
        pack_id: 0,
        offset: 0,
    };
    let blob = b"prefix TOK_ABCDEFGH suffix";

    PackObjectSink::emit(&mut adapter, &candidate, b"packed.txt", blob).expect("pack path scan");

    let output = String::from_utf8(sink.take()).expect("valid UTF-8");
    assert!(
        output.contains("\"commit_id\":77"),
        "pack path must carry commit_id: {output}"
    );
    assert!(
        output.contains("\"change_kind\":\"modify\""),
        "pack path must carry change_kind: {output}"
    );
}

#[test]
fn git_finding_events_carry_source_git() {
    let engine = test_engine_with_tok_rule();
    let sink = Arc::new(VecEventSink::new());
    let mut adapter = test_adapter_with_sink(&engine, sink.clone());

    let candidate = make_candidate_with_ctx(1, ChangeKind::Add);
    let blob = b"prefix TOK_ABCDEFGH suffix";
    adapter
        .emit_loose(&candidate, b"secret.txt", blob)
        .expect("scan");

    let output = String::from_utf8(sink.take()).expect("valid UTF-8");
    assert!(
        output.contains("\"source\":\"git\""),
        "git findings must have source:git: {output}"
    );
}

#[test]
fn git_finding_events_propagate_confidence_score() {
    let engine = test_engine_with_tok_rule_and_keyword_confidence();
    let sink = Arc::new(VecEventSink::new());
    let mut adapter = test_adapter_with_sink(&engine, sink.clone());

    let candidate = make_candidate_with_ctx(1, ChangeKind::Add);
    let blob = b"prefix TOK_ABCDEFGH suffix";
    adapter
        .emit_loose(&candidate, b"secret.txt", blob)
        .expect("scan");

    let output = String::from_utf8(sink.take()).expect("valid UTF-8");
    assert!(
        output.contains("\"confidence_score\":2"),
        "git findings must carry non-zero confidence score from engine: {output}"
    );
}

#[test]
fn git_finding_events_propagate_norm_hash() {
    let engine = test_engine_with_tok_rule();
    let sink = Arc::new(CapturingFindingSink::default());
    let mut adapter = test_adapter_with_capturing_sink(&engine, Arc::clone(&sink));

    let candidate = make_candidate_with_ctx(1, ChangeKind::Add);
    let blob = b"prefix TOK_ABCDEFGH suffix";
    adapter
        .emit_loose(&candidate, b"secret.txt", blob)
        .expect("scan");

    let captured = sink.take_findings();
    assert_eq!(captured.len(), 1, "expected exactly one captured finding");
    assert_eq!(
        captured[0].norm_hash,
        adapter.findings_arena()[0].key.norm_hash,
        "git finding events must forward the finding norm_hash"
    );
}

#[test]
fn git_finding_events_preserve_exact_match_spans_when_root_hints_diverge() {
    let engine = test_engine_with_tok_rule();
    let sink = Arc::new(CapturingFindingSink::default());
    let mut adapter = test_adapter_with_capturing_sink(&engine, Arc::clone(&sink));

    let candidate = make_candidate_with_ctx(1, ChangeKind::Add);
    let blob = b"prefix VE9LX0FCQ0RFRkdI suffix";
    adapter
        .emit_loose(&candidate, b"secret.txt", blob)
        .expect("scan transformed finding");

    let captured = sink.take_findings();
    assert_eq!(captured.len(), 1, "expected exactly one captured finding");

    let finding = captured[0];
    assert_ne!(
        (finding.start, finding.end),
        (finding.match_start, finding.match_end),
        "transform-derived finding should preserve a distinct exact match span",
    );
    assert_eq!(
        (finding.start as u32, finding.end as u32),
        (
            adapter.findings_arena()[0].key.start,
            adapter.findings_arena()[0].key.end,
        ),
        "event root hints must still match the dedupe key",
    );
    assert_eq!(
        (finding.match_start as u32, finding.match_end as u32),
        (
            adapter.findings_arena()[0].match_start,
            adapter.findings_arena()[0].match_end,
        ),
        "event exact spans must match the adapter's stored match coordinates",
    );
}

#[test]
fn sort_and_dedupe_findings_prefers_higher_confidence() {
    let mut findings = vec![
        ScoredFinding {
            key: FindingKey {
                start: 10,
                end: 20,
                rule_id: 7,
                norm_hash: [0x11; 32],
            },
            match_start: 10,
            match_end: 20,
            confidence_score: 1,
        },
        ScoredFinding {
            key: FindingKey {
                start: 10,
                end: 20,
                rule_id: 7,
                norm_hash: [0x11; 32],
            },
            match_start: 10,
            match_end: 20,
            confidence_score: 5,
        },
        ScoredFinding {
            key: FindingKey {
                start: 30,
                end: 40,
                rule_id: 7,
                norm_hash: [0x22; 32],
            },
            match_start: 30,
            match_end: 40,
            confidence_score: 0,
        },
    ];

    sort_and_dedupe_findings(&mut findings);

    assert_eq!(
        findings.len(),
        2,
        "identity-equivalent findings must dedupe"
    );
    assert_eq!(
        findings[0].confidence_score, 5,
        "dedupe winner should retain highest confidence"
    );
}

#[test]
fn sort_and_dedupe_findings_prefers_higher_confidence_reverse_input() {
    let mut findings = vec![
        ScoredFinding {
            key: FindingKey {
                start: 10,
                end: 20,
                rule_id: 7,
                norm_hash: [0x11; 32],
            },
            match_start: 10,
            match_end: 20,
            confidence_score: 5,
        },
        ScoredFinding {
            key: FindingKey {
                start: 10,
                end: 20,
                rule_id: 7,
                norm_hash: [0x11; 32],
            },
            match_start: 10,
            match_end: 20,
            confidence_score: 1,
        },
    ];
    sort_and_dedupe_findings(&mut findings);
    assert_eq!(findings.len(), 1, "duplicates must be removed");
    assert_eq!(
        findings[0].confidence_score, 5,
        "highest confidence must survive regardless of input order"
    );
}

/// `FindingKey` is pure identity — `Eq`, `Hash`, and `Ord` are derived
/// and cover all fields. `ScoredFinding` carries confidence as metadata
/// outside the identity key.
#[test]
fn finding_key_derived_eq_and_hash_cover_all_fields() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let a = FindingKey {
        start: 10,
        end: 20,
        rule_id: 7,
        norm_hash: [0x11; 32],
    };
    let b = FindingKey {
        start: 10,
        end: 20,
        rule_id: 7,
        norm_hash: [0x11; 32],
    };

    assert_eq!(a, b, "identical FindingKey values must be equal");

    let hash = |k: &FindingKey| {
        let mut h = DefaultHasher::new();
        k.hash(&mut h);
        h.finish()
    };
    assert_eq!(
        hash(&a),
        hash(&b),
        "identical FindingKey values must hash identically"
    );
}

/// Derived `Ord` on `FindingKey` orders by field declaration order:
/// `(start, end, rule_id, norm_hash)`. This test documents that expectation
/// so field reordering doesn't silently change dedup semantics.
#[test]
fn finding_key_ord_follows_field_declaration_order() {
    let base = FindingKey {
        start: 0,
        end: 10,
        rule_id: 1,
        norm_hash: [0x00; 32],
    };

    // Differs only in `start`.
    let higher_start = FindingKey { start: 1, ..base };
    assert!(base < higher_start, "start is the primary sort key");

    // Same start, differs in `end`.
    let higher_end = FindingKey { end: 11, ..base };
    assert!(base < higher_end, "end breaks ties after start");

    // Same start+end, differs in `rule_id`.
    let higher_rule = FindingKey { rule_id: 2, ..base };
    assert!(base < higher_rule, "rule_id breaks ties after end");

    // Same start+end+rule_id, differs in `norm_hash`.
    let higher_hash = FindingKey {
        norm_hash: [0x01; 32],
        ..base
    };
    assert!(base < higher_hash, "norm_hash breaks ties after rule_id");
}

// -- sort_and_dedupe_findings edge cases ------------------------------------

#[test]
fn sort_and_dedupe_empty_vec() {
    let mut findings: Vec<ScoredFinding> = vec![];
    sort_and_dedupe_findings(&mut findings);
    assert!(findings.is_empty());
}

#[test]
fn sort_and_dedupe_single_element() {
    let original = ScoredFinding {
        key: FindingKey {
            start: 5,
            end: 15,
            rule_id: 1,
            norm_hash: [0xaa; 32],
        },
        match_start: 5,
        match_end: 15,
        confidence_score: 3,
    };
    let mut findings = vec![original];
    sort_and_dedupe_findings(&mut findings);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].confidence_score, 3);
}

#[test]
fn sort_and_dedupe_negative_confidence_keeps_higher() {
    let mut findings = vec![
        ScoredFinding {
            key: FindingKey {
                start: 0,
                end: 10,
                rule_id: 2,
                norm_hash: [0xbb; 32],
            },
            match_start: 0,
            match_end: 10,
            confidence_score: -10,
        },
        ScoredFinding {
            key: FindingKey {
                start: 0,
                end: 10,
                rule_id: 2,
                norm_hash: [0xbb; 32],
            },
            match_start: 0,
            match_end: 10,
            confidence_score: -5,
        },
    ];
    sort_and_dedupe_findings(&mut findings);
    assert_eq!(
        findings.len(),
        1,
        "negative-confidence duplicates must dedup"
    );
    assert_eq!(
        findings[0].confidence_score, -5,
        "higher (less-negative) confidence wins"
    );
}

#[test]
fn sort_and_dedupe_three_duplicates_keeps_highest() {
    let mut findings = vec![
        ScoredFinding {
            key: FindingKey {
                start: 0,
                end: 8,
                rule_id: 4,
                norm_hash: [0xcc; 32],
            },
            match_start: 0,
            match_end: 8,
            confidence_score: 2,
        },
        ScoredFinding {
            key: FindingKey {
                start: 0,
                end: 8,
                rule_id: 4,
                norm_hash: [0xcc; 32],
            },
            match_start: 0,
            match_end: 8,
            confidence_score: 7,
        },
        ScoredFinding {
            key: FindingKey {
                start: 0,
                end: 8,
                rule_id: 4,
                norm_hash: [0xcc; 32],
            },
            match_start: 0,
            match_end: 8,
            confidence_score: 3,
        },
    ];
    sort_and_dedupe_findings(&mut findings);
    assert_eq!(
        findings.len(),
        1,
        "three identical-identity must dedup to 1"
    );
    assert_eq!(findings[0].confidence_score, 7, "highest confidence wins");
}

#[test]
fn sort_and_dedupe_all_identical_including_confidence() {
    let f = ScoredFinding {
        key: FindingKey {
            start: 1,
            end: 2,
            rule_id: 9,
            norm_hash: [0xdd; 32],
        },
        match_start: 1,
        match_end: 2,
        confidence_score: 4,
    };
    let mut findings = vec![f, f, f];
    sort_and_dedupe_findings(&mut findings);
    assert_eq!(
        findings.len(),
        1,
        "fully identical findings must dedup to 1"
    );
    assert_eq!(findings[0].confidence_score, 4);
}

#[test]
fn sort_and_dedupe_mixed_duplicates_and_unique() {
    let mut findings = vec![
        // Group A: two duplicates with different confidence.
        ScoredFinding {
            key: FindingKey {
                start: 10,
                end: 20,
                rule_id: 1,
                norm_hash: [0x11; 32],
            },
            match_start: 10,
            match_end: 20,
            confidence_score: 2,
        },
        ScoredFinding {
            key: FindingKey {
                start: 10,
                end: 20,
                rule_id: 1,
                norm_hash: [0x11; 32],
            },
            match_start: 10,
            match_end: 20,
            confidence_score: 8,
        },
        // Group B: unique finding.
        ScoredFinding {
            key: FindingKey {
                start: 30,
                end: 40,
                rule_id: 2,
                norm_hash: [0x22; 32],
            },
            match_start: 30,
            match_end: 40,
            confidence_score: 0,
        },
        // Group C: three duplicates.
        ScoredFinding {
            key: FindingKey {
                start: 50,
                end: 60,
                rule_id: 3,
                norm_hash: [0x33; 32],
            },
            match_start: 50,
            match_end: 60,
            confidence_score: 1,
        },
        ScoredFinding {
            key: FindingKey {
                start: 50,
                end: 60,
                rule_id: 3,
                norm_hash: [0x33; 32],
            },
            match_start: 50,
            match_end: 60,
            confidence_score: 6,
        },
        ScoredFinding {
            key: FindingKey {
                start: 50,
                end: 60,
                rule_id: 3,
                norm_hash: [0x33; 32],
            },
            match_start: 50,
            match_end: 60,
            confidence_score: 3,
        },
    ];
    sort_and_dedupe_findings(&mut findings);
    assert_eq!(findings.len(), 3, "expected 3 unique identity groups");
    // Results are sorted by identity, so group A < B < C by start offset.
    assert_eq!(findings[0].key.start, 10);
    assert_eq!(findings[0].confidence_score, 8, "group A winner");
    assert_eq!(findings[1].key.start, 30);
    assert_eq!(findings[1].confidence_score, 0, "group B sole entry");
    assert_eq!(findings[2].key.start, 50);
    assert_eq!(findings[2].confidence_score, 6, "group C winner");
}

#[test]
fn commit_id_zero_roundtrips_as_some() {
    let engine = test_engine_with_tok_rule();
    let sink = Arc::new(VecEventSink::new());
    let mut adapter = test_adapter_with_sink(&engine, sink.clone());

    // commit_id 0 is a valid graph position (root commit).
    let candidate = make_candidate_with_ctx(0, ChangeKind::Add);
    let blob = b"prefix TOK_ABCDEFGH suffix";
    adapter
        .emit_loose(&candidate, b"root.txt", blob)
        .expect("scan with commit_id 0");

    let output = String::from_utf8(sink.take()).expect("valid UTF-8");
    assert!(
        output.contains("\"commit_id\":0"),
        "commit_id:0 must appear in JSONL (not be treated as None): {output}"
    );
    assert!(
        output.contains("\"change_kind\":\"add\""),
        "change_kind must still appear with commit_id 0: {output}"
    );
}

// -- CommitMeta emission tests ----------------------------------------------

use crate::commit_walk::{CommitGraph, ParentScratch};
use crate::errors::CommitPlanError;
use gix_commitgraph::Position;

/// Tiny commit-graph stub with known OIDs and timestamps.
struct SmallTestGraph {
    oids: Vec<OidBytes>,
    timestamps: Vec<u64>,
}

impl SmallTestGraph {
    fn new(entries: &[(OidBytes, u64)]) -> Self {
        let (oids, timestamps) = entries.iter().cloned().unzip();
        Self { oids, timestamps }
    }
}

impl CommitGraph for SmallTestGraph {
    fn num_commits(&self) -> u32 {
        self.oids.len() as u32
    }
    fn lookup(&self, _oid: &OidBytes) -> Result<Option<Position>, CommitPlanError> {
        Ok(None)
    }
    fn generation(&self, _pos: Position) -> u32 {
        0
    }
    fn collect_parents(
        &self,
        _pos: Position,
        _max: u32,
        scratch: &mut ParentScratch,
    ) -> Result<(), CommitPlanError> {
        scratch.clear();
        Ok(())
    }
    fn root_tree_oid(&self, pos: Position) -> Result<OidBytes, CommitPlanError> {
        Ok(self.oids[pos.0 as usize])
    }
    fn commit_oid(&self, pos: Position) -> Result<OidBytes, CommitPlanError> {
        Ok(self.oids[pos.0 as usize])
    }
    fn committer_timestamp(&self, pos: Position) -> u64 {
        self.timestamps[pos.0 as usize]
    }
}

/// Build an adapter wired to a real `CommitGraphIndex` + fresh `AtomicBitSet`.
fn test_adapter_with_graph<'a>(
    engine: &'a Engine,
    sink: Arc<VecEventSink>,
    entries: &[(OidBytes, u64)],
) -> EngineAdapter<'a> {
    let graph = SmallTestGraph::new(entries);
    let cg = Arc::new(CommitGraphIndex::build(&graph).expect("build test graph"));
    let seen = Arc::new(AtomicBitSet::empty(cg.len().max(1)));
    EngineAdapter::new_with_event_sink(
        engine,
        EngineAdapterConfig::default(),
        CommitMetaContext {
            event_sink: sink,
            commit_graph_index: cg,
            commit_meta_seen: seen,
            identity_interner: None,
        },
    )
}

fn test_oid(n: u8) -> OidBytes {
    let mut bytes = [0u8; 20];
    bytes[0] = n;
    OidBytes::sha1(bytes)
}

fn parse_jsonl_types(output: &str) -> Vec<(&str, Option<u64>)> {
    output
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| {
            let ty = if l.contains("\"type\":\"commit_meta\"") {
                "commit_meta"
            } else if l.contains("\"type\":\"finding\"") {
                "finding"
            } else {
                "other"
            };
            // Extract commit_id value.
            let cid = l.find("\"commit_id\":").map(|start| {
                let rest = &l[start + "\"commit_id\":".len()..];
                let end = rest
                    .find(|c: char| !c.is_ascii_digit())
                    .unwrap_or(rest.len());
                rest[..end].parse::<u64>().unwrap()
            });
            (ty, cid)
        })
        .collect()
}

#[test]
fn single_adapter_commit_meta_precedes_its_findings() {
    let entries = vec![(test_oid(0xab), 1_700_000_000)];
    let engine = test_engine_with_tok_rule();
    let sink = Arc::new(VecEventSink::new());
    let mut adapter = test_adapter_with_graph(&engine, sink.clone(), &entries);

    let candidate = make_candidate_with_ctx(0, ChangeKind::Add);
    let blob = b"prefix TOK_ABCDEFGH suffix";
    adapter
        .emit_loose(&candidate, b"secret.txt", blob)
        .expect("scan");

    let output = String::from_utf8(sink.take()).expect("valid UTF-8");
    let events = parse_jsonl_types(&output);

    assert!(
        events.len() >= 2,
        "expected commit_meta + finding, got: {output}"
    );
    assert_eq!(
        events[0].0, "commit_meta",
        "first event must be commit_meta: {output}"
    );
    assert_eq!(events[0].1, Some(0));
    assert_eq!(
        events[1].0, "finding",
        "second event must be finding: {output}"
    );
    // Verify OID hex and timestamp are present.
    assert!(
        output.contains("\"oid\":\"ab"),
        "commit_meta must contain OID hex: {output}"
    );
    assert!(
        output.contains("\"timestamp\":1700000000"),
        "commit_meta must contain timestamp: {output}"
    );
}

#[derive(Default)]
struct ReorderGateState {
    meta_waiting: bool,
    allow_meta_emit: bool,
}

/// Event sink that blocks the first `CommitMeta` until another worker emits
/// a `Finding`. This makes cross-worker ordering inversions deterministic.
struct BlockingCommitMetaSink {
    events: Mutex<Vec<&'static str>>,
    state: Mutex<ReorderGateState>,
    cv: Condvar,
}

impl BlockingCommitMetaSink {
    fn new() -> Self {
        Self {
            events: Mutex::new(Vec::new()),
            state: Mutex::new(ReorderGateState::default()),
            cv: Condvar::new(),
        }
    }

    fn wait_until_meta_waiting(&self, timeout: Duration) -> bool {
        let start = Instant::now();
        let mut state = self
            .state
            .lock()
            .expect("blocking sink state mutex poisoned");
        while !state.meta_waiting {
            let elapsed = start.elapsed();
            if elapsed >= timeout {
                return false;
            }
            let wait_for = timeout.saturating_sub(elapsed);
            let (next_state, timed_out) = self
                .cv
                .wait_timeout(state, wait_for)
                .expect("blocking sink condvar wait poisoned");
            state = next_state;
            if timed_out.timed_out() && !state.meta_waiting {
                return false;
            }
        }
        true
    }

    fn events(&self) -> Vec<&'static str> {
        self.events
            .lock()
            .expect("blocking sink events mutex poisoned")
            .clone()
    }
}

impl EventSink for BlockingCommitMetaSink {
    fn emit(&self, event: ScanEvent<'_>) {
        match event {
            ScanEvent::CommitMeta(_) => {
                let mut state = self
                    .state
                    .lock()
                    .expect("blocking sink state mutex poisoned");
                state.meta_waiting = true;
                self.cv.notify_all();
                while !state.allow_meta_emit {
                    state = self
                        .cv
                        .wait(state)
                        .expect("blocking sink condvar wait poisoned");
                }
                drop(state);

                self.events
                    .lock()
                    .expect("blocking sink events mutex poisoned")
                    .push("commit_meta");
            }
            ScanEvent::Finding(_) => {
                self.events
                    .lock()
                    .expect("blocking sink events mutex poisoned")
                    .push("finding");
                let mut state = self
                    .state
                    .lock()
                    .expect("blocking sink state mutex poisoned");
                if state.meta_waiting {
                    state.allow_meta_emit = true;
                    self.cv.notify_all();
                }
            }
            _ => {}
        }
    }

    fn flush(&self) {}
}

#[test]
fn parallel_adapters_can_emit_finding_before_commit_meta_for_same_commit() {
    let entries = vec![(test_oid(0xdd), 4_000)];
    let engine = Arc::new(test_engine_with_tok_rule());
    let sink = Arc::new(BlockingCommitMetaSink::new());

    let graph = SmallTestGraph::new(&entries);
    let commit_graph_index = Arc::new(CommitGraphIndex::build(&graph).expect("build graph"));
    let commit_meta_seen = Arc::new(AtomicBitSet::empty(commit_graph_index.len().max(1)));
    let blob = b"prefix TOK_ABCDEFGH suffix";

    let worker_a = {
        let engine = Arc::clone(&engine);
        let sink = Arc::clone(&sink);
        let commit_graph_index = Arc::clone(&commit_graph_index);
        let commit_meta_seen = Arc::clone(&commit_meta_seen);
        std::thread::spawn(move || {
            let event_sink: Arc<dyn EventSink> = sink;
            let mut adapter = EngineAdapter::new_with_event_sink(
                engine.as_ref(),
                EngineAdapterConfig::default(),
                CommitMetaContext {
                    event_sink,
                    commit_graph_index,
                    commit_meta_seen,
                    identity_interner: None,
                },
            );
            let candidate = make_candidate_with_ctx(0, ChangeKind::Add);
            adapter
                .emit_loose(&candidate, b"a.txt", blob)
                .expect("worker A scan");
        })
    };

    assert!(
        sink.wait_until_meta_waiting(Duration::from_secs(2)),
        "timed out waiting for worker A to block in commit_meta emit"
    );

    let worker_b = {
        let engine = Arc::clone(&engine);
        let sink = Arc::clone(&sink);
        let commit_graph_index = Arc::clone(&commit_graph_index);
        let commit_meta_seen = Arc::clone(&commit_meta_seen);
        std::thread::spawn(move || {
            let event_sink: Arc<dyn EventSink> = sink;
            let mut adapter = EngineAdapter::new_with_event_sink(
                engine.as_ref(),
                EngineAdapterConfig::default(),
                CommitMetaContext {
                    event_sink,
                    commit_graph_index,
                    commit_meta_seen,
                    identity_interner: None,
                },
            );
            let candidate = make_candidate_with_ctx(0, ChangeKind::Add);
            adapter
                .emit_loose(&candidate, b"b.txt", blob)
                .expect("worker B scan");
        })
    };

    worker_b.join().expect("worker B join");
    worker_a.join().expect("worker A join");

    let events = sink.events();
    let first_finding = events
        .iter()
        .position(|ty| *ty == "finding")
        .expect("expected at least one finding event");
    let first_meta = events
        .iter()
        .position(|ty| *ty == "commit_meta")
        .expect("expected commit_meta event");
    assert!(
        first_finding < first_meta,
        "expected a finding before commit_meta for the same commit: {events:?}"
    );
}

#[test]
fn commit_meta_emitted_once_per_commit() {
    let entries = vec![(test_oid(0xaa), 1000), (test_oid(0xbb), 2000)];
    let engine = test_engine_with_tok_rule();
    let sink = Arc::new(VecEventSink::new());
    let mut adapter = test_adapter_with_graph(&engine, sink.clone(), &entries);

    let blob = b"prefix TOK_ABCDEFGH suffix";

    // Two scans with the same commit_id=0.
    let c0 = make_candidate_with_ctx(0, ChangeKind::Add);
    adapter.emit_loose(&c0, b"a.txt", blob).expect("scan 1");
    adapter.emit_loose(&c0, b"b.txt", blob).expect("scan 2");

    // One scan with commit_id=1.
    let c1 = make_candidate_with_ctx(1, ChangeKind::Add);
    adapter.emit_loose(&c1, b"c.txt", blob).expect("scan 3");

    let output = String::from_utf8(sink.take()).expect("valid UTF-8");
    let events = parse_jsonl_types(&output);

    let meta_count = events.iter().filter(|(t, _)| *t == "commit_meta").count();
    assert_eq!(
        meta_count, 2,
        "expected exactly 2 commit_meta events (one per unique commit_id), got {meta_count}: {output}"
    );

    // Verify each commit_id has exactly one commit_meta.
    let meta_ids: Vec<u64> = events
        .iter()
        .filter(|(t, _)| *t == "commit_meta")
        .map(|(_, id)| id.unwrap())
        .collect();
    assert!(meta_ids.contains(&0), "missing commit_meta for id=0");
    assert!(meta_ids.contains(&1), "missing commit_meta for id=1");
}

#[test]
fn no_commit_meta_without_findings() {
    let entries = vec![(test_oid(0xcc), 3000)];
    let engine = test_engine_with_tok_rule();
    let sink = Arc::new(VecEventSink::new());
    let mut adapter = test_adapter_with_graph(&engine, sink.clone(), &entries);

    let candidate = make_candidate_with_ctx(0, ChangeKind::Add);
    let blob = b"nothing suspicious here";
    adapter
        .emit_loose(&candidate, b"clean.txt", blob)
        .expect("scan clean blob");

    let output = sink.take();
    assert!(
        output.is_empty(),
        "no events should be emitted for blobs without findings"
    );
}

#[test]
fn out_of_range_commit_id_emits_diagnostic() {
    // Graph has 1 entry (positions 0..1); commit_id=5 is out of range.
    let entries = vec![(test_oid(0xaa), 1000)];
    let engine = test_engine_with_tok_rule();
    let sink = Arc::new(VecEventSink::new());
    let mut adapter = test_adapter_with_graph(&engine, sink.clone(), &entries);

    let candidate = make_candidate_with_ctx(5, ChangeKind::Add);
    let blob = b"prefix TOK_ABCDEFGH suffix";
    adapter
        .emit_loose(&candidate, b"secret.txt", blob)
        .expect("scan with out-of-range commit_id");

    let output = String::from_utf8(sink.take()).expect("valid UTF-8");
    // Findings should still be emitted.
    assert!(
        output.contains("\"type\":\"finding\""),
        "findings must still be emitted for out-of-range commit_id: {output}"
    );
    // No commit_meta should be emitted (commit_id is out of range).
    assert!(
        !output.contains("\"type\":\"commit_meta\""),
        "commit_meta must not be emitted for out-of-range commit_id: {output}"
    );
    // A diagnostic warning should be emitted so the skip is visible.
    assert!(
        output.contains("\"type\":\"diagnostic\""),
        "expected a diagnostic event for out-of-range commit_id, got: {output}"
    );
}

#[test]
fn commit_meta_carries_correct_oid_and_timestamp() {
    let oid = OidBytes::sha1([
        0xde, 0xad, 0xbe, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba,
        0x98, 0x76, 0x54, 0x32, 0x10,
    ]);
    let entries = vec![(oid, 1_234_567_890)];
    let engine = test_engine_with_tok_rule();
    let sink = Arc::new(VecEventSink::new());
    let mut adapter = test_adapter_with_graph(&engine, sink.clone(), &entries);

    let candidate = make_candidate_with_ctx(0, ChangeKind::Add);
    let blob = b"prefix TOK_ABCDEFGH suffix";
    adapter
        .emit_loose(&candidate, b"s.txt", blob)
        .expect("scan");

    let output = String::from_utf8(sink.take()).expect("valid UTF-8");
    assert!(
        output.contains("\"oid\":\"deadbeef0123456789abcdeffedcba9876543210\""),
        "OID hex must match: {output}"
    );
    assert!(
        output.contains("\"timestamp\":1234567890"),
        "timestamp must match: {output}"
    );
}

#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "AtomicBitSet bit_length")]
fn mismatched_bitset_and_graph_panics_in_debug() {
    // Graph has 3 entries but bitset only has 1 bit — mismatch.
    let entries = vec![
        (test_oid(0xaa), 1000),
        (test_oid(0xbb), 2000),
        (test_oid(0xcc), 3000),
    ];
    let engine = test_engine_with_tok_rule();
    let sink = Arc::new(VecEventSink::new());
    let graph = SmallTestGraph::new(&entries);
    let cg = Arc::new(CommitGraphIndex::build(&graph).expect("build test graph"));
    // Deliberately create a bitset smaller than the graph.
    let seen = Arc::new(AtomicBitSet::empty(1));
    let _adapter = EngineAdapter::new_with_event_sink(
        &engine,
        EngineAdapterConfig::default(),
        CommitMetaContext {
            event_sink: sink,
            commit_graph_index: cg,
            commit_meta_seen: seen,
            identity_interner: None,
        },
    );
}

/// Debug output must redact `norm_hash` to prevent leaking secret-derived bytes.
#[test]
fn finding_key_debug_redacts_norm_hash() {
    let key = FindingKey {
        start: 0,
        end: 10,
        rule_id: 1,
        norm_hash: [0xFF; 32],
    };
    let debug = format!("{key:?}");
    assert!(
        debug.contains("[redacted]"),
        "Debug must redact norm_hash, got: {debug}"
    );
    assert!(
        !debug.contains("255"),
        "Debug must not leak raw hash bytes, got: {debug}"
    );
}
