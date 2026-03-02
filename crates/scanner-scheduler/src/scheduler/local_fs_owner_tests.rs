use super::*;
use crate::Engine;
use crate::api::{FileId, RuleSpec, TransformConfig, Tuning, ValidatorKind};
use crate::archive::PartialReason;
use crate::events::VecEventOutput;
use crate::scheduler::engine_stub::{FindingRec, MockEngine, MockRule, RuleId};
use crate::scheduler::engine_trait::{
    EngineScratch, FindingRecord, FindingWithHash, FindingWithHashRecord, ScanEngine,
};
use crate::scheduler::local_fs_archive_ctx::{ArchiveEnd, apply_entry_budget_clamp};
use crate::store::{EmitOnlyStoreProducer, FailingStoreProducer, InMemoryStoreProducer};
use regex::bytes::Regex;
use std::fs;
use std::io::Write;
use tempfile::{NamedTempFile, TempDir};

fn test_engine() -> MockEngine {
    MockEngine::new(
        vec![
            MockRule {
                name: "secret".into(),
                pattern: b"SECRET".to_vec(),
            },
            MockRule {
                name: "password".into(),
                pattern: b"PASSWORD".to_vec(),
            },
        ],
        16, // 16 byte overlap
    )
}

fn small_config_with_sink(sink: Arc<VecEventOutput>) -> LocalConfig {
    LocalConfig {
        workers: 2,
        chunk_size: 64, // Tiny for testing
        pool_buffers: 8,
        local_queue_cap: 2,
        max_in_flight_objects: 8,
        max_file_size: u64::MAX,
        seed: 12345,
        pin_threads: false,
        dedupe_within_chunk: true,
        archive: ArchiveConfig::default(),
        skip_binary: true,
        event_sink: sink,
        store_producer: None,
    }
}

fn small_config() -> LocalConfig {
    small_config_with_sink(Arc::new(VecEventOutput::new()))
}

fn real_test_tuning(max_findings_per_chunk: usize) -> Tuning {
    Tuning {
        merge_gap: 64,
        max_windows_per_rule_variant: 64,
        pressure_gap_start: 128,
        max_anchor_hits_per_rule_variant: 256,
        max_utf16_decoded_bytes_per_window: 4096,
        max_transform_depth: 2,
        max_total_decode_output_bytes: 1024 * 1024,
        max_work_items: 64,
        max_findings_per_chunk,
        scan_utf16_variants: true,
    }
}

fn real_simple_rule() -> RuleSpec {
    RuleSpec {
        name: "secret",
        anchors: &[b"SECRET"],
        radius: 32,
        validator: ValidatorKind::None,
        two_phase: None,
        must_contain: None,
        keywords_any: None,
        value_suppressors_any: None,
        entropy: None,
        char_class: None,
        local_context: None,
        secret_group: None,
        min_confidence: None,
        offline_validation: None,
        uuid_format_secret: false,
        re: Regex::new(r"SECRET[A-Z0-9]{8}").unwrap(),
    }
}

struct DuplicateDropEngine;

struct DuplicateDropScratch {
    findings: Vec<FindingWithHash<FindingRec>>,
    dropped_findings: u64,
}

impl EngineScratch for DuplicateDropScratch {
    type Finding = FindingWithHash<FindingRec>;

    fn clear(&mut self) {
        self.findings.clear();
        self.dropped_findings = 0;
    }

    fn drop_prefix_findings(&mut self, new_bytes_start: u64) {
        self.findings
            .retain(|f| f.finding.root_hint_end >= new_bytes_start);
    }

    fn drain_findings_into(&mut self, out: &mut Vec<Self::Finding>) {
        out.append(&mut self.findings);
    }

    fn pending_findings_len(&self) -> usize {
        self.findings.len()
    }

    fn dropped_findings(&self) -> u64 {
        self.dropped_findings
    }
}

impl ScanEngine for DuplicateDropEngine {
    type Scratch = DuplicateDropScratch;

    fn required_overlap(&self) -> usize {
        0
    }

    fn new_scratch(&self) -> Self::Scratch {
        DuplicateDropScratch {
            findings: Vec::with_capacity(4),
            dropped_findings: 0,
        }
    }

    fn scan_chunk_into(
        &self,
        _data: &[u8],
        _file_id: FileId,
        _base_offset: u64,
        scratch: &mut Self::Scratch,
    ) {
        scratch.clear();
        let finding = FindingWithHash::new(
            FindingRec {
                rule_id: RuleId(0),
                root_hint_start: 0,
                root_hint_end: 6,
                span_start: 0,
                span_end: 6,
                confidence_score: 0,
            },
            [0xAB; 32],
        );
        // Scheduler dedupe will collapse these to one.
        // Scheduler dedupe will collapse these to one.  The engine
        // emitted both copies so `dropped_findings` stays 0 — the
        // "drop" is purely scheduler-side dedup, not an engine cap.
        scratch.findings.push(finding);
        scratch.findings.push(finding);
    }

    fn rule_name(&self, _rule_id: u32) -> &str {
        "duplicate-drop"
    }

    fn max_findings_per_chunk(&self) -> usize {
        4
    }
}

fn assert_perf_u64(actual: u64, expected: u64) {
    if cfg!(all(feature = "perf-stats", debug_assertions)) {
        assert_eq!(actual, expected);
    } else {
        assert_eq!(actual, 0);
    }
}

#[test]
fn zip_budget_clamp_charges_discarded_bytes() {
    let cfg = ArchiveConfig {
        max_uncompressed_bytes_per_entry: 4,
        max_total_uncompressed_bytes_per_archive: 5,
        max_total_uncompressed_bytes_per_root: 5,
        ..ArchiveConfig::default()
    };

    let mut budgets = ArchiveBudgets::new(&cfg);
    assert!(budgets.enter_archive().is_ok());
    budgets.begin_entry_scan();

    let mut entry_partial_reason = None;
    let mut outcome = ArchiveEnd::Scanned;
    let mut stop_archive = false;

    let (allowed, clamped) = apply_entry_budget_clamp(
        &mut budgets,
        6,
        &mut entry_partial_reason,
        &mut outcome,
        &mut stop_archive,
    );

    assert_eq!(allowed, 4);
    assert!(clamped);
    assert!(stop_archive);
    assert_eq!(budgets.root_decompressed_out(), 5);
    assert_eq!(
        outcome,
        ArchiveEnd::Partial(PartialReason::ArchiveOutputBudgetExceeded)
    );
}

#[test]
fn scans_single_file_with_findings() {
    let engine = Arc::new(test_engine());
    let sink = Arc::new(VecEventOutput::new());

    // Create temp file with secret
    let mut tmp = NamedTempFile::new().unwrap();
    writeln!(tmp, "hello SECRET world").unwrap();
    tmp.flush().unwrap();

    let path = tmp.path().to_path_buf();
    let size = tmp.as_file().metadata().unwrap().len();

    let source = VecFileSource::new(vec![LocalFile { path, size }]);

    let report = scan_local(engine, source, small_config_with_sink(sink.clone()));

    assert_eq!(report.stats.files_enqueued, 1);
    assert!(report.metrics.chunks_scanned >= 1);

    let output = sink.take();
    let output_str = String::from_utf8_lossy(&output);
    assert!(output_str.contains("secret"), "output: {}", output_str);
}

#[test]
fn handles_empty_file() {
    let engine = Arc::new(test_engine());
    let sink = Arc::new(VecEventOutput::new());

    let tmp = NamedTempFile::new().unwrap();
    let path = tmp.path().to_path_buf();

    let source = VecFileSource::new(vec![LocalFile { path, size: 0 }]);

    let report = scan_local(engine, source, small_config_with_sink(sink.clone()));

    assert_eq!(report.stats.files_enqueued, 1);
    assert!(sink.take().is_empty());
}

#[test]
fn enforces_max_file_size_at_open_time() {
    let engine = Arc::new(test_engine());
    let sink = Arc::new(VecEventOutput::new());

    let mut tmp = NamedTempFile::new().unwrap();
    writeln!(tmp, "SECRETABCD1234").unwrap();
    tmp.flush().unwrap();

    let path = tmp.path().to_path_buf();
    let source = VecFileSource::new(vec![LocalFile { path, size: 4 }]);

    let mut cfg = small_config_with_sink(sink.clone());
    cfg.max_file_size = 4; // Smaller than actual file size at open time.

    let report = scan_local(engine, source, cfg);

    assert_eq!(report.stats.files_enqueued, 1);
    assert_eq!(report.metrics.bytes_scanned, 0);
    assert!(sink.take().is_empty());
}

#[test]
fn handles_no_files() {
    let engine = Arc::new(test_engine());

    let source = VecFileSource::new(vec![]);

    let report = scan_local(engine, source, small_config());

    assert_eq!(report.stats.files_enqueued, 0);
    assert_eq!(report.metrics.chunks_scanned, 0);
}

#[test]
fn finds_boundary_spanning_secret() {
    let engine = Arc::new(test_engine());
    let sink = Arc::new(VecEventOutput::new());

    // Create file where SECRET spans chunk boundary
    // With chunk_size=64 and overlap=16, secret at position ~60 will span
    let mut tmp = NamedTempFile::new().unwrap();
    let padding = vec![b'x'; 60];
    tmp.write_all(&padding).unwrap();
    tmp.write_all(b"SECRET").unwrap();
    tmp.write_all(&[b'y'; 100]).unwrap();
    tmp.flush().unwrap();

    let path = tmp.path().to_path_buf();
    let size = tmp.as_file().metadata().unwrap().len();

    let source = VecFileSource::new(vec![LocalFile { path, size }]);

    let report = scan_local(engine, source, small_config_with_sink(sink.clone()));

    assert!(report.metrics.chunks_scanned >= 2);

    let output = sink.take();
    let output_str = String::from_utf8_lossy(&output);

    // Should find exactly one SECRET (not duplicated due to overlap)
    let count = output_str.matches("secret").count();
    assert_eq!(
        count, 1,
        "expected 1 finding, got {}: {}",
        count, output_str
    );
}

#[test]
fn processes_multiple_files() {
    let engine = Arc::new(test_engine());
    let sink = Arc::new(VecEventOutput::new());

    let mut files = Vec::new();
    let mut temps = Vec::new();

    for i in 0..5 {
        let mut tmp = NamedTempFile::new().unwrap();
        writeln!(tmp, "file {} contains SECRET", i).unwrap();
        tmp.flush().unwrap();

        let path = tmp.path().to_path_buf();
        let size = tmp.as_file().metadata().unwrap().len();
        files.push(LocalFile { path, size });
        temps.push(tmp); // Keep alive
    }

    let source = VecFileSource::new(files);

    let report = scan_local(engine, source, small_config_with_sink(sink.clone()));

    assert_eq!(report.stats.files_enqueued, 5);

    let output = sink.take();
    let output_str = String::from_utf8_lossy(&output);
    let count = output_str.matches("secret").count();
    assert_eq!(
        count, 5,
        "expected 5 findings, got {}: {}",
        count, output_str
    );
}

#[test]
fn config_validation() {
    let engine = test_engine();

    // Valid config
    let cfg = LocalConfig::default();
    cfg.validate(&engine);
}

#[test]
#[should_panic(expected = "exceeds BUFFER_LEN_MAX")]
fn config_validation_rejects_oversized_chunk() {
    let engine = test_engine();

    // Invalid: chunk_size + overlap > BUFFER_LEN_MAX
    let bad_cfg = LocalConfig {
        chunk_size: BUFFER_LEN_MAX, // Will exceed with overlap
        ..Default::default()
    };
    bad_cfg.validate(&engine); // Should panic
}

#[test]
fn metrics_track_bytes() {
    let engine = Arc::new(test_engine());

    let mut tmp = NamedTempFile::new().unwrap();
    let data = vec![b'a'; 1000];
    tmp.write_all(&data).unwrap();
    tmp.flush().unwrap();

    let path = tmp.path().to_path_buf();
    let size = tmp.as_file().metadata().unwrap().len();

    let source = VecFileSource::new(vec![LocalFile { path, size }]);

    let report = scan_local(engine, source, small_config());

    // bytes_scanned should be ~1000 (the actual payload scanned)
    assert!(report.metrics.bytes_scanned >= 1000);
}

#[test]
fn archive_detection_skips_when_enabled() {
    let engine = Arc::new(test_engine());

    let dir = TempDir::new().unwrap();
    let path = dir.path().join("sample.zip");
    fs::write(&path, b"SECRET").unwrap();
    let size = fs::metadata(&path).unwrap().len();

    let source = VecFileSource::new(vec![LocalFile { path, size }]);
    let mut cfg = small_config();
    cfg.archive.enabled = true;

    let report = scan_local(engine, source, cfg);

    if cfg!(all(feature = "perf-stats", debug_assertions)) {
        assert_eq!(report.metrics.archive.archives_seen, 1);
        assert_eq!(report.metrics.archive.archives_partial, 1);
        assert_eq!(
            report.metrics.archive.partial_reasons[PartialReason::MalformedZip.as_usize()],
            1
        );
    } else {
        assert_eq!(report.metrics.archive.archives_seen, 0);
        assert_eq!(report.metrics.archive.archives_partial, 0);
        assert_eq!(
            report.metrics.archive.partial_reasons[PartialReason::MalformedZip.as_usize()],
            0
        );
    }
}

#[test]
fn archive_extension_scans_when_disabled() {
    let engine = Arc::new(test_engine());
    let sink = Arc::new(VecEventOutput::new());

    let dir = TempDir::new().unwrap();
    let path = dir.path().join("sample.zip");
    fs::write(&path, b"hello SECRET world").unwrap();
    let size = fs::metadata(&path).unwrap().len();

    let source = VecFileSource::new(vec![LocalFile { path, size }]);
    let mut cfg = small_config_with_sink(sink.clone());
    cfg.archive.enabled = false;
    cfg.skip_binary = false;

    let report = scan_local(engine, source, cfg);

    assert_perf_u64(report.metrics.archive.archives_seen, 0);

    let output = sink.take();
    let output_str = String::from_utf8_lossy(&output);
    assert!(
        output_str.contains("secret"),
        "expected finding for archive extension when disabled; output: {output_str}"
    );
}

// ---------------------------------------------------------------
// dedupe_findings_cross_rule unit tests
// ---------------------------------------------------------------

fn finding(rule: u16, start: u64, end: u64) -> FindingRec {
    FindingRec {
        rule_id: RuleId(rule),
        root_hint_start: start,
        root_hint_end: end,
        span_start: start,
        span_end: end,
        confidence_score: 0,
    }
}

/// Wrap a `FindingRec` with a default norm_hash for dedupe tests.
fn hashed(f: FindingRec) -> FindingWithHash<FindingRec> {
    FindingWithHash::new(f, [0; 32])
}

#[test]
fn dedupe_empty_vec() {
    let mut v: Vec<FindingWithHash<FindingRec>> = Vec::new();
    dedupe_findings_cross_rule(&mut v, |_, _| std::cmp::Ordering::Equal);
    assert!(v.is_empty());
}

#[test]
fn dedupe_single_element() {
    let mut v = vec![hashed(finding(0, 10, 16))];
    dedupe_findings_cross_rule(&mut v, |_, _| std::cmp::Ordering::Equal);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].finding.root_hint_start, 10);
}

#[test]
fn dedupe_removes_exact_duplicates() {
    let mut v = vec![
        hashed(finding(0, 10, 16)),
        hashed(finding(0, 10, 16)), // dup
        hashed(finding(1, 20, 28)),
        hashed(finding(1, 20, 28)), // dup
        hashed(finding(2, 50, 56)),
    ];
    dedupe_findings_cross_rule(&mut v, |_, _| std::cmp::Ordering::Equal);
    assert_eq!(v.len(), 3);
}

#[test]
fn dedupe_preserves_different_rules_same_offsets() {
    let mut v = vec![
        hashed(finding(0, 10, 16)),
        hashed(finding(1, 10, 16)),
        hashed(finding(2, 10, 16)),
    ];
    dedupe_findings_cross_rule(&mut v, |_, _| std::cmp::Ordering::Equal);
    assert_eq!(
        v.len(),
        1,
        "cross-rule dedupe selects winner among different rules at same location+hash"
    );
}

#[test]
fn dedupe_preserves_same_rule_different_offsets() {
    let mut v = vec![
        hashed(finding(0, 10, 16)),
        hashed(finding(0, 20, 26)),
        hashed(finding(0, 30, 36)),
    ];
    dedupe_findings_cross_rule(&mut v, |_, _| std::cmp::Ordering::Equal);
    assert_eq!(v.len(), 3, "distinct offsets should all be kept");
}

#[test]
fn dedupe_works_for_finding_with_hash_carrier() {
    let mut v = vec![
        FindingWithHash::new(finding(0, 10, 16), [1; 32]),
        FindingWithHash::new(finding(0, 10, 16), [1; 32]), // dup
        FindingWithHash::new(finding(1, 20, 26), [2; 32]),
    ];
    dedupe_findings_cross_rule(&mut v, |_, _| std::cmp::Ordering::Equal);
    assert_eq!(v.len(), 2);
    assert_eq!(v[0].finding.rule_id, RuleId(0));
    assert_eq!(v[1].finding.rule_id, RuleId(1));
}

#[test]
fn persistence_batches_emitted_for_regular_fs_loop() {
    let engine = Arc::new(test_engine());
    let sink = Arc::new(VecEventOutput::new());
    let producer = Arc::new(InMemoryStoreProducer::default());

    let mut tmp = NamedTempFile::new().unwrap();
    tmp.write_all(b"SECRET one SECRET two").unwrap();
    tmp.flush().unwrap();
    let path = tmp.path().to_path_buf();
    let size = tmp.as_file().metadata().unwrap().len();

    let source = VecFileSource::new(vec![LocalFile { path, size }]);
    let mut cfg = small_config_with_sink(sink);
    cfg.store_producer = Some(producer.clone());

    let report = scan_local(engine, source, cfg);
    let batches = producer.batches();
    let persisted: usize = batches.iter().map(|b| b.findings.len()).sum();

    assert!(!batches.is_empty(), "expected persisted fs finding batches");
    assert_eq!(persisted as u64, report.metrics.findings_emitted);
}

#[test]
fn dropped_findings_roll_up_into_persistence_run_loss() {
    let engine = Arc::new(Engine::new(
        vec![real_simple_rule()],
        Vec::<TransformConfig>::new(),
        real_test_tuning(1), // force max-findings drops
    ));
    let producer = Arc::new(InMemoryStoreProducer::default());
    let sink = Arc::new(VecEventOutput::new());

    let mut tmp = NamedTempFile::new().unwrap();
    tmp.write_all(b"SECRET12345678 and SECRETABCDEFGH").unwrap();
    tmp.flush().unwrap();
    let path = tmp.path().to_path_buf();
    let size = tmp.as_file().metadata().unwrap().len();

    let source = VecFileSource::new(vec![LocalFile { path, size }]);
    let mut cfg = small_config_with_sink(sink);
    cfg.chunk_size = 1024;
    cfg.store_producer = Some(producer.clone());
    let report = scan_local(engine, source, cfg);

    assert!(report.stats.dropped_findings > 0);
    assert!(report.stats.persistence_incomplete);

    let losses = producer.losses();
    assert_eq!(losses.len(), 1);
    assert_eq!(losses[0].dropped_findings, report.stats.dropped_findings);
    assert_eq!(
        losses[0].persistence_emit_failures,
        report.stats.persistence_emit_failures
    );
    assert!(losses[0].incomplete());
}

#[test]
fn duplicate_only_drop_does_not_mark_persistence_incomplete() {
    let engine = Arc::new(DuplicateDropEngine);
    let sink = Arc::new(VecEventOutput::new());
    let producer = Arc::new(InMemoryStoreProducer::default());

    let mut tmp = NamedTempFile::new().unwrap();
    tmp.write_all(b"data").unwrap();
    tmp.flush().unwrap();
    let path = tmp.path().to_path_buf();
    let size = tmp.as_file().metadata().unwrap().len();

    let source = VecFileSource::new(vec![LocalFile { path, size }]);
    let mut cfg = small_config_with_sink(sink);
    cfg.workers = 1;
    cfg.store_producer = Some(producer.clone());

    let report = scan_local(engine, source, cfg);

    assert_eq!(report.metrics.findings_emitted, 1);
    assert_eq!(
        report.stats.dropped_findings, 0,
        "drops that correspond only to scheduler-pruned duplicates should not mark run loss"
    );
    assert!(!report.stats.persistence_incomplete);

    let losses = producer.losses();
    assert_eq!(losses.len(), 1);
    assert_eq!(losses[0].dropped_findings, 0);
    assert!(!losses[0].incomplete());
}

/// Regression: persistence emit failures must NOT inflate io_errors.
///
/// `io_errors` is documented as "file open, read, metadata failures" and
/// operators / automation rely on that definition. Persistence backend
/// errors are a different failure domain — they have their own counter
/// (`persistence_emit_failures`).
#[test]
fn persistence_failure_does_not_inflate_io_errors() {
    let engine = Arc::new(test_engine());
    let sink = Arc::new(VecEventOutput::new());
    let producer = Arc::new(FailingStoreProducer);

    let mut tmp = NamedTempFile::new().unwrap();
    tmp.write_all(b"SECRET one SECRET two").unwrap();
    tmp.flush().unwrap();
    let path = tmp.path().to_path_buf();
    let size = tmp.as_file().metadata().unwrap().len();

    let source = VecFileSource::new(vec![LocalFile { path, size }]);
    let mut cfg = small_config_with_sink(sink);
    cfg.store_producer = Some(producer);

    let report = scan_local(engine, source, cfg);

    // Persistence failures should be tracked separately.
    assert!(
        report.stats.persistence_emit_failures > 0,
        "expected persistence failures from FailingStoreProducer"
    );
    // io_errors must reflect only real file I/O problems — the file
    // above was read successfully, so io_errors should be zero.
    assert_eq!(
        report.stats.io_errors, 0,
        "persistence failures must not be counted as io_errors"
    );
}

/// Regression: record_fs_run_loss failure must NOT inflate io_errors.
///
/// Same principle as above: a persistence backend call failing at run
/// end is not a file-system I/O error.
#[test]
fn run_loss_failure_does_not_inflate_io_errors() {
    let engine = Arc::new(test_engine());
    let sink = Arc::new(VecEventOutput::new());
    let producer = Arc::new(EmitOnlyStoreProducer::new());

    let mut tmp = NamedTempFile::new().unwrap();
    tmp.write_all(b"SECRET one").unwrap();
    tmp.flush().unwrap();
    let path = tmp.path().to_path_buf();
    let size = tmp.as_file().metadata().unwrap().len();

    let source = VecFileSource::new(vec![LocalFile { path, size }]);
    let mut cfg = small_config_with_sink(sink);
    cfg.store_producer = Some(producer.clone());

    let report = scan_local(engine, source, cfg);

    // Batches emitted fine (EmitOnlyStoreProducer succeeds on emit).
    assert!(!producer.batches().is_empty());

    // record_fs_run_loss fails — that must NOT bump io_errors.
    assert_eq!(
        report.stats.io_errors, 0,
        "run_loss failure must not be counted as io_errors"
    );

    // But persistence_incomplete should be true (run_loss failure
    // increments persistence_emit_failures).
    assert!(report.stats.persistence_incomplete);
    assert!(report.stats.persistence_emit_failures > 0);
}

#[test]
fn dedupe_same_span_different_hash_preserves_both() {
    let mut v = vec![
        FindingWithHash::new(finding(0, 10, 16), [0xAA; 32]),
        FindingWithHash::new(finding(0, 10, 16), [0xBB; 32]),
    ];
    dedupe_findings_cross_rule(&mut v, |_, _| std::cmp::Ordering::Equal);
    assert_eq!(
        v.len(),
        2,
        "same span but different norm_hash must be preserved"
    );
}

#[test]
fn dedupe_same_span_same_hash_collapses() {
    let mut v = vec![
        FindingWithHash::new(finding(0, 10, 16), [0xCC; 32]),
        FindingWithHash::new(finding(0, 10, 16), [0xCC; 32]),
    ];
    dedupe_findings_cross_rule(&mut v, |_, _| std::cmp::Ordering::Equal);
    assert_eq!(
        v.len(),
        1,
        "identical span and norm_hash should collapse to one"
    );
}

#[test]
fn cross_rule_dedupe_prefers_higher_confidence() {
    let mut v = vec![
        FindingWithHash::new(
            FindingRec {
                rule_id: RuleId(0),
                root_hint_start: 10,
                root_hint_end: 16,
                span_start: 10,
                span_end: 16,
                confidence_score: 2,
            },
            [0xDD; 32],
        ),
        FindingWithHash::new(
            FindingRec {
                rule_id: RuleId(1),
                root_hint_start: 10,
                root_hint_end: 16,
                span_start: 10,
                span_end: 16,
                confidence_score: 7,
            },
            [0xDD; 32],
        ),
    ];

    dedupe_findings_cross_rule(&mut v, |_lhs, _rhs| std::cmp::Ordering::Equal);
    assert_eq!(v.len(), 1);
    assert_eq!(v[0].rule_id(), 1);
}

#[test]
fn cross_rule_dedupe_tie_breaks_by_rule_name_then_rule_id() {
    let names = ["zeta", "alpha", "alpha"];
    let mut v = vec![
        FindingWithHash::new(
            FindingRec {
                rule_id: RuleId(0),
                root_hint_start: 20,
                root_hint_end: 26,
                span_start: 20,
                span_end: 26,
                confidence_score: 5,
            },
            [0xEF; 32],
        ),
        FindingWithHash::new(
            FindingRec {
                rule_id: RuleId(2),
                root_hint_start: 20,
                root_hint_end: 26,
                span_start: 20,
                span_end: 26,
                confidence_score: 5,
            },
            [0xEF; 32],
        ),
        FindingWithHash::new(
            FindingRec {
                rule_id: RuleId(1),
                root_hint_start: 20,
                root_hint_end: 26,
                span_start: 20,
                span_end: 26,
                confidence_score: 5,
            },
            [0xEF; 32],
        ),
    ];

    dedupe_findings_cross_rule(&mut v, |lhs, rhs| {
        names[lhs as usize].cmp(names[rhs as usize])
    });
    assert_eq!(v.len(), 1);
    assert_eq!(
        v[0].rule_id(),
        1,
        "same-confidence ties should prefer lexical rule_name, then lower rule_id"
    );
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SpanModeFinding {
    rule_id: u32,
    root_hint_start: u64,
    root_hint_end: u64,
    span_start: u64,
    span_end: u64,
    dedupe_with_span: bool,
    confidence_score: i8,
    norm_hash: [u8; 32],
}

impl FindingRecord for SpanModeFinding {
    fn rule_id(&self) -> u32 {
        self.rule_id
    }

    fn root_hint_start(&self) -> u64 {
        self.root_hint_start
    }

    fn root_hint_end(&self) -> u64 {
        self.root_hint_end
    }

    fn span_start(&self) -> u64 {
        self.span_start
    }

    fn span_end(&self) -> u64 {
        self.span_end
    }

    fn dedupe_with_span(&self) -> bool {
        self.dedupe_with_span
    }

    fn confidence_score(&self) -> i8 {
        self.confidence_score
    }
}

impl FindingWithHashRecord for SpanModeFinding {
    fn norm_hash(&self) -> &[u8; 32] {
        &self.norm_hash
    }
}

#[test]
fn cross_rule_dedupe_zeros_span_when_dedupe_with_span_is_false() {
    let mut v = vec![
        SpanModeFinding {
            rule_id: 0,
            root_hint_start: 100,
            root_hint_end: 120,
            span_start: 100,
            span_end: 110,
            dedupe_with_span: false,
            confidence_score: 1,
            norm_hash: [0x11; 32],
        },
        SpanModeFinding {
            rule_id: 1,
            root_hint_start: 100,
            root_hint_end: 120,
            span_start: 111,
            span_end: 120,
            dedupe_with_span: false,
            confidence_score: 2,
            norm_hash: [0x11; 32],
        },
    ];

    dedupe_findings_cross_rule(&mut v, |_lhs, _rhs| std::cmp::Ordering::Equal);
    assert_eq!(
        v.len(),
        1,
        "span should be ignored when dedupe_with_span=false"
    );
}

#[test]
fn cross_rule_dedupe_preserves_distinct_spans_when_dedupe_with_span_is_true() {
    let mut v = vec![
        SpanModeFinding {
            rule_id: 0,
            root_hint_start: 100,
            root_hint_end: 120,
            span_start: 100,
            span_end: 110,
            dedupe_with_span: true,
            confidence_score: 1,
            norm_hash: [0x22; 32],
        },
        SpanModeFinding {
            rule_id: 1,
            root_hint_start: 100,
            root_hint_end: 120,
            span_start: 111,
            span_end: 120,
            dedupe_with_span: true,
            confidence_score: 2,
            norm_hash: [0x22; 32],
        },
    ];

    dedupe_findings_cross_rule(&mut v, |_lhs, _rhs| std::cmp::Ordering::Equal);
    assert_eq!(
        v.len(),
        2,
        "span should remain part of key when dedupe_with_span=true"
    );
}

#[test]
fn cross_rule_dedupe_mixed_span_modes_form_separate_groups() {
    let mut v = vec![
        SpanModeFinding {
            rule_id: 0,
            root_hint_start: 100,
            root_hint_end: 120,
            span_start: 100,
            span_end: 110,
            dedupe_with_span: false,
            confidence_score: 5,
            norm_hash: [0x33; 32],
        },
        SpanModeFinding {
            rule_id: 1,
            root_hint_start: 100,
            root_hint_end: 120,
            span_start: 105,
            span_end: 115,
            dedupe_with_span: true,
            confidence_score: 8,
            norm_hash: [0x33; 32],
        },
    ];

    dedupe_findings_cross_rule(&mut v, |_lhs, _rhs| std::cmp::Ordering::Equal);
    assert_eq!(
        v.len(),
        2,
        "mixed dedupe_with_span values should form separate groups"
    );
}

// ---------------------------------------------------------------
// scan_local: overlap dedup, exact-size, multi-secret, reuse
// ---------------------------------------------------------------

#[test]
fn overlap_dedup_no_double_report() {
    // Place SECRET so it falls entirely within the overlap region between
    // chunk 1 and chunk 2. With chunk_size=64 and overlap=16, SECRET at
    // offset 50 spans [50..56]. In chunk 2 (overlap carry from [48..64]),
    // drop_prefix_findings(64) drops it since root_hint_end=56 < 64.
    let engine = Arc::new(test_engine());
    let sink = Arc::new(VecEventOutput::new());

    let mut tmp = NamedTempFile::new().unwrap();
    let mut data = vec![b'x'; 50];
    data.extend_from_slice(b"SECRET");
    data.extend_from_slice(&[b'y'; 100]); // ensure >1 chunk
    tmp.write_all(&data).unwrap();
    tmp.flush().unwrap();

    let path = tmp.path().to_path_buf();
    let size = tmp.as_file().metadata().unwrap().len();

    let source = VecFileSource::new(vec![LocalFile { path, size }]);
    let report = scan_local(engine, source, small_config_with_sink(sink.clone()));

    assert!(report.metrics.chunks_scanned >= 2);
    let output = sink.take();
    let output_str = String::from_utf8_lossy(&output);
    let count = output_str.matches("secret").count();
    assert_eq!(
        count, 1,
        "SECRET in overlap region must be reported exactly once, got {count}: {output_str}"
    );
}

#[test]
fn file_exactly_chunk_size() {
    // File of exactly chunk_size bytes should be scanned in one chunk.
    let engine = Arc::new(test_engine());
    let sink = Arc::new(VecEventOutput::new());

    let mut tmp = NamedTempFile::new().unwrap();
    // chunk_size=64 in small_config; place SECRET in the middle.
    let mut data = vec![b'x'; 20];
    data.extend_from_slice(b"SECRET");
    data.resize(64, b'z');
    tmp.write_all(&data).unwrap();
    tmp.flush().unwrap();

    let path = tmp.path().to_path_buf();
    let size = tmp.as_file().metadata().unwrap().len();

    let source = VecFileSource::new(vec![LocalFile { path, size }]);
    let report = scan_local(engine, source, small_config_with_sink(sink.clone()));

    assert_eq!(report.metrics.chunks_scanned, 1);
    let output = sink.take();
    let output_str = String::from_utf8_lossy(&output);
    assert_eq!(
        output_str.matches("secret").count(),
        1,
        "single chunk should find SECRET"
    );
}

#[test]
fn multiple_secrets_across_chunks_in_one_file() {
    // One file spanning 3+ chunks, each containing a SECRET well away
    // from overlap boundaries.
    let engine = Arc::new(test_engine());
    let sink = Arc::new(VecEventOutput::new());

    // chunk_size=64, overlap=16.
    // Place SECRETs at offsets 4, 100, and 196 — each solidly within
    // the "new bytes" region of their respective chunks.
    let mut tmp = NamedTempFile::new().unwrap();
    let mut data = vec![b'A'; 4];
    data.extend_from_slice(b"SECRET"); // offset 4..10
    data.resize(100, b'B');
    data.extend_from_slice(b"SECRET"); // offset 100..106
    data.resize(196, b'C');
    data.extend_from_slice(b"SECRET"); // offset 196..202
    data.resize(256, b'D'); // ensure 3+ chunks
    tmp.write_all(&data).unwrap();
    tmp.flush().unwrap();

    let path = tmp.path().to_path_buf();
    let size = tmp.as_file().metadata().unwrap().len();

    let source = VecFileSource::new(vec![LocalFile { path, size }]);
    let report = scan_local(engine, source, small_config_with_sink(sink.clone()));

    assert!(
        report.metrics.chunks_scanned >= 3,
        "need at least 3 chunks, got {}",
        report.metrics.chunks_scanned
    );
    let output = sink.take();
    let output_str = String::from_utf8_lossy(&output);
    let count = output_str.matches("secret").count();
    assert_eq!(
        count, 3,
        "each SECRET in its own chunk region should be found; got {count}: {output_str}"
    );
}

#[test]
fn two_files_no_cross_contamination() {
    // Scan two files back-to-back and verify findings are correct for each.
    // Tests that per-worker scratch is properly cleared between files.
    let engine = Arc::new(test_engine());
    let sink = Arc::new(VecEventOutput::new());

    let dir = TempDir::new().unwrap();
    let p1 = dir.path().join("first.txt");
    let p2 = dir.path().join("second.txt");
    fs::write(&p1, b"first SECRET here").unwrap();
    fs::write(&p2, b"second PASSWORD there").unwrap();

    let s1 = fs::metadata(&p1).unwrap().len();
    let s2 = fs::metadata(&p2).unwrap().len();
    let files = vec![
        LocalFile { path: p1, size: s1 },
        LocalFile { path: p2, size: s2 },
    ];

    let source = VecFileSource::new(files);
    let cfg = LocalConfig {
        workers: 1,
        ..small_config_with_sink(sink.clone())
    };
    let report = scan_local(engine, source, cfg);

    assert_eq!(report.stats.files_enqueued, 2);
    let output = sink.take();
    let output_str = String::from_utf8_lossy(&output);
    assert_eq!(
        output_str.matches("secret").count(),
        1,
        "first file's SECRET"
    );
    assert_eq!(
        output_str.matches("password").count(),
        1,
        "second file's PASSWORD"
    );
}

// ---------------------------------------------------------------
// Error-path tests for persistence plumbing
// ---------------------------------------------------------------

#[test]
fn persistence_emit_failure_increments_counters() {
    let engine = Arc::new(test_engine());
    let sink = Arc::new(VecEventOutput::new());
    let producer = Arc::new(FailingStoreProducer);

    let mut tmp = NamedTempFile::new().unwrap();
    tmp.write_all(b"SECRET one SECRET two").unwrap();
    tmp.flush().unwrap();
    let path = tmp.path().to_path_buf();
    let size = tmp.as_file().metadata().unwrap().len();

    let source = VecFileSource::new(vec![LocalFile { path, size }]);
    let mut cfg = small_config_with_sink(sink.clone());
    cfg.store_producer = Some(producer);

    let report = scan_local(engine, source, cfg);

    assert!(
        report.stats.persistence_emit_failures > 0,
        "expected persistence_emit_failures > 0, got {}",
        report.stats.persistence_emit_failures
    );
    assert!(
        report.stats.persistence_incomplete,
        "expected persistence_incomplete to be true"
    );

    // Verify a diagnostic event was emitted for the failure.
    let output = sink.take();
    let output_str = String::from_utf8_lossy(&output);
    assert!(
        output_str.contains("persistence batch emit failed") || output_str.contains("injected"),
        "expected diagnostic event about emit failure; output: {output_str}"
    );
}

#[test]
fn run_loss_record_failure_increments_counters_and_emits_diagnostic() {
    let engine = Arc::new(test_engine());
    let sink = Arc::new(VecEventOutput::new());
    let producer = Arc::new(EmitOnlyStoreProducer::new());

    let mut tmp = NamedTempFile::new().unwrap();
    tmp.write_all(b"SECRET one SECRET two").unwrap();
    tmp.flush().unwrap();
    let path = tmp.path().to_path_buf();
    let size = tmp.as_file().metadata().unwrap().len();

    let source = VecFileSource::new(vec![LocalFile { path, size }]);
    let mut cfg = small_config_with_sink(sink.clone());
    cfg.store_producer = Some(producer.clone());

    let report = scan_local(engine, source, cfg);

    // Emit should have succeeded — batches were collected.
    assert!(
        !producer.batches().is_empty(),
        "emit should have succeeded and collected batches"
    );

    // run_loss failure bumps persistence_emit_failures and sets incomplete.
    assert!(
        report.stats.persistence_incomplete,
        "expected persistence_incomplete after run-loss record failure"
    );
    // The persistence_emit_failures counter should include the run-loss failure.
    assert!(
        report.stats.persistence_emit_failures >= 1,
        "expected persistence_emit_failures >= 1 from run-loss failure, got {}",
        report.stats.persistence_emit_failures
    );

    // Verify a diagnostic event was emitted for the run-loss failure.
    let output = sink.take();
    let output_str = String::from_utf8_lossy(&output);
    assert!(
        output_str.contains("run-loss recording failed") || output_str.contains("injected"),
        "expected diagnostic event about run-loss failure; output: {output_str}"
    );
}

// ---------------------------------------------------------------
// build_persistence_batch field mapping
// ---------------------------------------------------------------

#[test]
fn build_persistence_batch_maps_all_fields() {
    let finding = FindingRec {
        rule_id: RuleId(42),
        root_hint_start: 100,
        root_hint_end: 200,
        span_start: 110,
        span_end: 190,
        confidence_score: 0,
    };
    let hash = [0xDE; 32];
    let wrapped = FindingWithHash::new(finding, hash);
    let findings = vec![wrapped];
    let mut out = Vec::with_capacity(findings.len());

    build_persistence_batch(&findings, &mut out);

    assert_eq!(out.len(), 1);
    let rec = &out[0];
    assert_eq!(rec.rule_id, 42);
    assert_eq!(rec.root_hint_start, 100);
    assert_eq!(rec.root_hint_end, 200);
    assert_eq!(rec.span_start, 110);
    assert_eq!(rec.span_end, 190);
    assert_eq!(rec.norm_hash, [0xDE; 32]);
}

// ------------------------------------------------------------------
// StackMsg UTF-8 boundary truncation
// ------------------------------------------------------------------

#[test]
fn stack_msg_truncates_at_utf8_boundary_3byte() {
    use std::fmt::Write;
    // ☃ is U+2603, encoded as 3 bytes (E2 98 83).
    // A StackMsg<5> has room for 5 bytes. "ab" = 2 bytes, then 3 bytes
    // remaining — exactly enough for ☃. Verify it fits.
    let mut msg = StackMsg::<5>::new();
    write!(msg, "ab☃").unwrap();
    assert_eq!(msg.as_str(), "ab☃");

    // A StackMsg<4> has room for 4 bytes. "ab" = 2 bytes, then only 2
    // bytes remaining — not enough for a 3-byte character. The snowman
    // must be dropped entirely to preserve UTF-8 validity.
    let mut msg = StackMsg::<4>::new();
    write!(msg, "ab☃").unwrap();
    assert_eq!(msg.as_str(), "ab");
}

#[test]
fn stack_msg_truncates_at_utf8_boundary_2byte() {
    use std::fmt::Write;
    // é is U+00E9, encoded as 2 bytes (C3 A9).
    // StackMsg<4>: "abc" = 3 bytes, 1 remaining — can't fit 2-byte char.
    let mut msg = StackMsg::<4>::new();
    write!(msg, "abcé").unwrap();
    assert_eq!(msg.as_str(), "abc");
}

#[test]
fn stack_msg_truncates_at_utf8_boundary_4byte() {
    use std::fmt::Write;
    // 𝄞 is U+1D11E (musical symbol), encoded as 4 bytes (F0 9D 84 9E).
    // StackMsg<5>: "a" = 1 byte, 4 remaining — exactly fits.
    let mut msg = StackMsg::<5>::new();
    write!(msg, "a𝄞").unwrap();
    assert_eq!(msg.as_str(), "a𝄞");

    // StackMsg<4>: "a" = 1 byte, 3 remaining — can't fit 4-byte char.
    let mut msg = StackMsg::<4>::new();
    write!(msg, "a𝄞").unwrap();
    assert_eq!(msg.as_str(), "a");
}

#[test]
fn stack_msg_exact_fill_multibyte() {
    use std::fmt::Write;
    // Two 3-byte chars = 6 bytes, exactly fills StackMsg<6>.
    let mut msg = StackMsg::<6>::new();
    write!(msg, "☃☃").unwrap();
    assert_eq!(msg.as_str(), "☃☃");
}

#[test]
fn stack_msg_sequential_writes_respect_boundary() {
    use std::fmt::Write;
    // First write fills 3 bytes, second write has only 1 byte remaining
    // and must drop the 2-byte é.
    let mut msg = StackMsg::<4>::new();
    write!(msg, "abc").unwrap();
    write!(msg, "é").unwrap();
    assert_eq!(msg.as_str(), "abc");
}

// ---------------------------------------------------------------
// First-read dual-use: preloaded + overlap carry interaction
// ---------------------------------------------------------------

/// The preloaded first chunk must interact correctly with the overlap
/// carry loop. A secret straddling the boundary between the preloaded
/// chunk and the second read must be found exactly once.
#[test]
fn preloaded_first_chunk_overlap_carry_finds_boundary_secret() {
    let engine = Arc::new(test_engine());
    let sink = Arc::new(VecEventOutput::new());

    // chunk_size=100, overlap=16.  Place SECRET at position 97 so it
    // spans the boundary between the preloaded first chunk ([0..100))
    // and the second chunk.  The preloaded path sets carry=16 from
    // bytes [84..100) of the first read.  The overlap must correctly
    // deliver bytes [84..100)+[100..200) so SECRET at [97..103) is
    // found.
    let mut data = vec![b'A'; 97];
    data.extend_from_slice(b"SECRET");
    data.extend_from_slice(&[b'B'; 100]); // ensure second chunk read

    let mut tmp = NamedTempFile::new().unwrap();
    tmp.write_all(&data).unwrap();
    tmp.flush().unwrap();

    let path = tmp.path().to_path_buf();
    let size = tmp.as_file().metadata().unwrap().len();

    let source = VecFileSource::new(vec![LocalFile { path, size }]);
    let mut cfg = small_config_with_sink(sink.clone());
    cfg.workers = 1;
    cfg.chunk_size = 100;
    // overlap remains 16 (from test_engine)

    let report = scan_local(engine, source, cfg);

    assert!(
        report.metrics.chunks_scanned >= 2,
        "expected >= 2 chunks, got {}",
        report.metrics.chunks_scanned
    );
    let output = sink.take();
    let output_str = String::from_utf8_lossy(&output);
    let count = output_str.matches("secret").count();
    assert_eq!(
        count, 1,
        "SECRET spanning preloaded boundary should be found exactly once, got {count}: {output_str}"
    );
}

/// A file smaller than TAR_BLOCK_LEN (512 bytes) must scan normally
/// and not be misidentified as an archive when archive sniffing is
/// enabled.
#[test]
fn small_file_below_tar_block_len_scans_normally() {
    let engine = Arc::new(test_engine());
    let sink = Arc::new(VecEventOutput::new());

    let dir = TempDir::new().unwrap();
    let path = dir.path().join("tiny.txt");
    // 100-byte text file containing SECRET (well below 512 TAR_BLOCK_LEN)
    let mut data = vec![b'A'; 50];
    data.extend_from_slice(b"SECRET");
    data.resize(100, b'z');
    fs::write(&path, &data).unwrap();
    let size = fs::metadata(&path).unwrap().len();

    let source = VecFileSource::new(vec![LocalFile { path, size }]);
    let mut cfg = small_config_with_sink(sink.clone());
    cfg.archive.enabled = true;

    let report = scan_local(engine, source, cfg);

    // File should be scanned as text, not routed as archive.
    let output = sink.take();
    let output_str = String::from_utf8_lossy(&output);
    assert!(
        output_str.contains("secret"),
        "small file should be scanned and find SECRET; output: {output_str}"
    );
    assert_perf_u64(report.metrics.archive.archives_seen, 0);
}

// ---------------------------------------------------------------------------
// account_effective_dropped_findings regression tests
// ---------------------------------------------------------------------------

#[test]
fn account_effective_dropped_subtracts_pruned() {
    let mut m = WorkerMetricsLocal::new();

    // Normal: 10 engine drops - 3 scheduler pruned = 7 effective.
    account_effective_dropped_findings(&mut m, 10, 3);
    assert_eq!(m.findings_dropped, 7);

    // Accumulates: 7 + (5 - 2) = 10.
    account_effective_dropped_findings(&mut m, 5, 2);
    assert_eq!(m.findings_dropped, 10);
}

#[test]
fn account_effective_dropped_saturates_when_pruned_exceeds_dropped() {
    let mut m = WorkerMetricsLocal::new();

    // Pruned > dropped: saturating_sub gives 0 (this was the bug).
    account_effective_dropped_findings(&mut m, 2, 5);
    assert_eq!(m.findings_dropped, 0);

    // Equal: also 0.
    account_effective_dropped_findings(&mut m, 3, 3);
    assert_eq!(m.findings_dropped, 0);
}
