use super::{CollectedFindings, normalize_findings_for_diff};
use crate::api::{FileId, FindingRec, STEP_ROOT, StepId, TransformId};
use crate::archive::ArchiveConfig;
use crate::sim_scanner::generator::build_engine_from_suite;
use crate::sim_scanner::scenario::{RuleSuiteSpec, RunConfig, SyntheticRuleSpec};

fn test_engine() -> crate::Engine {
    let suite = RuleSuiteSpec {
        schema_version: 1,
        rules: vec![SyntheticRuleSpec {
            rule_id: 0,
            name: "test_rule".to_string(),
            anchors: vec![b"TEST".to_vec()],
            radius: 16,
            regex: "TEST[0-9]{4}".to_string(),
        }],
    };
    let run_cfg = RunConfig {
        workers: 1,
        chunk_size: 64,
        overlap: 64,
        max_in_flight_objects: 1,
        buffer_pool_cap: 1,
        max_file_size: u64::MAX,
        max_steps: 0,
        max_transform_depth: 2,
        scan_utf16_variants: false,
        archive: ArchiveConfig::default(),
        stability_runs: 1,
        archive_deadline_countdown: None,
    };
    build_engine_from_suite(&suite, &run_cfg).expect("engine build")
}

fn non_root_rec(
    span_len: u32,
    root_hint_start: u64,
    root_hint_end: u64,
    step_id: StepId,
) -> FindingRec {
    FindingRec {
        file_id: FileId(0),
        rule_id: 0,
        span_start: 0,
        span_end: span_len,
        root_hint_start,
        root_hint_end,
        dedupe_with_span: false,
        step_id,
        confidence_score: 0,
    }
}

fn root_rec(span_start: u32, span_end: u32) -> FindingRec {
    FindingRec {
        file_id: FileId(0),
        rule_id: 0,
        span_start,
        span_end,
        root_hint_start: span_start as u64,
        root_hint_end: span_end as u64,
        dedupe_with_span: true,
        step_id: STEP_ROOT,
        confidence_score: 0,
    }
}

#[test]
fn normalize_findings_for_diff_base64_within_overlap_passes_filter() {
    let engine = test_engine();
    let overlap = engine.required_overlap() as u64;

    // The engine pre-normalizes Base64 root_hint_end to the padding-free
    // minimum before emission. A finding whose hint_len fits within the
    // overlap window passes the filter.
    let decoded_len = 1u64;
    let min_encoded = (decoded_len * 4).div_ceil(3);
    assert!(min_encoded <= overlap);

    let root_hint_start: u64 = 100;
    let root_hint_end = root_hint_start + min_encoded;

    let rec = non_root_rec(
        decoded_len as u32,
        root_hint_start,
        root_hint_end,
        StepId::from_raw(0),
    );
    let findings = CollectedFindings {
        recs: vec![rec],
        leaf_transforms: vec![Some(TransformId::Base64)],
    };

    let normalized = normalize_findings_for_diff(&engine, &findings);
    assert_eq!(normalized.len(), 1);
    let key = normalized.iter().next().unwrap();
    assert_eq!(key.root_hint_end, root_hint_end);
}

#[test]
fn normalize_findings_for_diff_base64_not_subsumed_by_wider_root_span() {
    let engine = test_engine();
    let overlap = engine.required_overlap() as u64;

    // The engine pre-normalizes Base64 root_hint_end to the padding-free
    // minimum before emission. A non-root finding whose hint window does
    // NOT contain a root span should survive the subsumption filter.
    let decoded_len = 1u64;
    let min_encoded = (decoded_len * 4).div_ceil(3);
    assert!(overlap >= min_encoded);

    let root_hint_start: u64 = 0;
    let root_hint_end = root_hint_start + min_encoded;

    // Root span extends beyond the non-root's pre-normalized hint end.
    let root_span_end = (min_encoded + 1) as u32;
    assert!(root_span_end as u64 > min_encoded);

    let root = root_rec(0, root_span_end);
    let non_root = non_root_rec(
        decoded_len as u32,
        root_hint_start,
        root_hint_end,
        StepId::from_raw(1),
    );
    let findings = CollectedFindings {
        recs: vec![root, non_root],
        leaf_transforms: vec![None, Some(TransformId::Base64)],
    };

    let normalized = normalize_findings_for_diff(&engine, &findings);
    assert_eq!(normalized.len(), 2);
    assert!(
        normalized
            .iter()
            .any(|key| key.span_start == 0 && key.span_end == 0)
    );
    assert!(
        normalized
            .iter()
            .any(|key| key.span_start != 0 || key.span_end != 0)
    );
}

#[test]
fn normalize_findings_for_diff_skips_base64_padding_for_non_base64() {
    let engine = test_engine();
    let overlap = engine.required_overlap() as u64;
    assert!(overlap >= 3);

    let root_hint_start = 50;
    let root_hint_end = root_hint_start + 3;
    let rec = non_root_rec(1, root_hint_start, root_hint_end, StepId::from_raw(2));
    let findings = CollectedFindings {
        recs: vec![rec],
        leaf_transforms: vec![Some(TransformId::UrlPercent)],
    };

    let normalized = normalize_findings_for_diff(&engine, &findings);
    assert_eq!(normalized.len(), 1);
    let key = normalized.iter().next().unwrap();
    assert_eq!(key.root_hint_end, root_hint_end);
}
