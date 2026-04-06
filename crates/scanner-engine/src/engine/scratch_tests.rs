use super::{CachelineBoundary, RootSpanMapCtx, ScanScratch, normalize_root_hint_end_for_dedup};
use crate::api::{
    DecodeStep, FileId, FindingRec, Gate, RuleSpec, STEP_ROOT, StepId, TransformConfig,
    TransformId, TransformMode, Tuning,
};
use crate::engine::Engine;
use regex::bytes::Regex;
use rstest::rstest;

#[test]
fn scanscratch_cold_region_is_cacheline_aligned() {
    assert_eq!(std::mem::align_of::<CachelineBoundary>(), 64);
    assert_eq!(std::mem::align_of::<ScanScratch>() % 64, 0);

    let cold_boundary_offset = std::mem::offset_of!(ScanScratch, _cold_boundary);
    let slab_offset = std::mem::offset_of!(ScanScratch, slab);

    assert_eq!(cold_boundary_offset % 64, 0);
    assert_eq!(slab_offset % 64, 0);
    assert!(slab_offset >= cold_boundary_offset);

    // Key hot fields must live before the cold boundary.
    let out_offset = std::mem::offset_of!(ScanScratch, out);
    let work_q_offset = std::mem::offset_of!(ScanScratch, work_q);
    let steps_buf_offset = std::mem::offset_of!(ScanScratch, steps_buf);

    assert!(
        out_offset < cold_boundary_offset,
        "out (findings) must be in the hot region"
    );
    assert!(
        work_q_offset < cold_boundary_offset,
        "work_q must be in the hot region"
    );
    assert!(
        steps_buf_offset < cold_boundary_offset,
        "steps_buf must be in the hot region"
    );
}

fn make_rec(
    step_id: StepId,
    span_start: u32,
    span_end: u32,
    root_hint_start: u64,
    root_hint_end: u64,
) -> FindingRec {
    FindingRec {
        file_id: FileId(0),
        rule_id: 0,
        span_start,
        span_end,
        root_hint_start,
        root_hint_end,
        dedupe_with_span: false,
        step_id,
        confidence_score: 0,
    }
}

fn test_tuning() -> Tuning {
    Tuning {
        merge_gap: 64,
        max_windows_per_rule_variant: 64,
        pressure_gap_start: 128,
        max_anchor_hits_per_rule_variant: 256,
        max_utf16_decoded_bytes_per_window: 4096,
        max_transform_depth: 2,
        max_total_decode_output_bytes: 1024 * 1024,
        max_work_items: 64,
        max_findings_per_chunk: 4096,
        scan_utf16_variants: true,
    }
}

fn simple_rule() -> RuleSpec {
    RuleSpec {
        name: "test-secret",
        anchors: &[b"SECRET"],
        radius: 32,
        validator: crate::api::ValidatorKind::None,
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

fn base64_test_transform_config() -> TransformConfig {
    TransformConfig {
        id: TransformId::Base64,
        mode: TransformMode::Always,
        gate: Gate::None,
        min_len: 4,
        max_spans_per_buffer: 16,
        max_encoded_len: 64 * 1024,
        max_decoded_bytes: 64 * 1024,
        plus_to_space: false,
        base64_allow_space_ws: false,
    }
}

fn new_test_scratch() -> ScanScratch {
    let engine = Engine::new(
        vec![simple_rule()],
        Vec::<TransformConfig>::new(),
        test_tuning(),
    );
    engine.new_scratch()
}

#[test]
fn engine_normalize_url_percent_not_snapped() {
    // decoded_len=13, min_encoded(base64)=18
    // root_hint_end = root_hint_start + 19 (min+1, in padding window)
    let rec = make_rec(StepId(1), 200, 213, 1000, 1019);
    let result = normalize_root_hint_end_for_dedup(&rec, Some(TransformId::UrlPercent));
    // UrlPercent must NOT snap — returns original root_hint_end
    assert_eq!(result, 1019);
}

#[test]
fn engine_normalize_base64_snaps() {
    let rec = make_rec(StepId(1), 200, 213, 1000, 1019);
    let result = normalize_root_hint_end_for_dedup(&rec, Some(TransformId::Base64));
    // Base64: decoded_len=13, min_encoded=18, actual=19, snap to 1018
    assert_eq!(result, 1018);
}

#[test]
fn engine_normalize_root_unchanged() {
    let rec = make_rec(STEP_ROOT, 200, 213, 1000, 1019);
    let result = normalize_root_hint_end_for_dedup(&rec, Some(TransformId::Base64));
    assert_eq!(result, 1019);
}

#[test]
fn engine_normalize_none_transform_not_snapped() {
    let rec = make_rec(StepId(1), 200, 213, 1000, 1019);
    let result = normalize_root_hint_end_for_dedup(&rec, None);
    assert_eq!(result, 1019);
}

/// Boundary-value coverage for the Base64 snap window.
///
/// The snap condition is:
///   `actual_encoded > min_encoded && actual_encoded <= min_encoded + 3`
///
/// For decoded_len=13 (span 200..213): min_encoded = ceil(13*4/3) = 18.
/// Parameterize over actual_encoded offsets relative to min to hit every
/// branch boundary.
#[rstest]
#[case::exact_no_snap(1000, 1018, false, "actual == min: no snap (strict >)")]
#[case::plus_one_snap(1000, 1019, true, "actual == min+1: snap")]
#[case::plus_three_snap(1000, 1021, true, "actual == min+3: far boundary snap")]
#[case::plus_four_no_snap(1000, 1022, false, "actual == min+4: beyond window")]
fn normalize_base64_snap_window_boundaries(
    #[case] root_hint_start: u64,
    #[case] root_hint_end: u64,
    #[case] expect_snap: bool,
    #[case] label: &str,
) {
    let rec = make_rec(StepId(1), 200, 213, root_hint_start, root_hint_end);
    let result = normalize_root_hint_end_for_dedup(&rec, Some(TransformId::Base64));
    let expected = if expect_snap {
        root_hint_start + 18 // snapped to min_encoded
    } else {
        root_hint_end // unchanged
    };
    assert_eq!(result, expected, "{label}");
}

#[test]
fn drain_findings_with_hashes_preserves_alignment_and_order() {
    let mut scratch = new_test_scratch();
    let rec_a = make_rec(STEP_ROOT, 10, 16, 100, 106);
    let rec_b = make_rec(STEP_ROOT, 20, 26, 200, 206);
    let hash_a = [0xA1; 32];
    let hash_b = [0xB2; 32];

    scratch.push_finding(rec_a, hash_a);
    scratch.push_finding(rec_b, hash_b);

    let mut findings_out = Vec::with_capacity(2);
    let mut hash_out = Vec::with_capacity(2);
    scratch.drain_findings_with_hashes(&mut findings_out, &mut hash_out);

    assert_eq!(findings_out, vec![rec_a, rec_b]);
    assert_eq!(hash_out, vec![hash_a, hash_b]);
    assert_eq!(scratch.pending_findings_len(), 0);
    assert!(scratch.norm_hashes().is_empty());
    assert!(scratch.drop_hint_end().is_empty());
}

#[test]
#[should_panic(expected = "findings output capacity too small")]
fn drain_findings_with_hashes_panics_when_findings_capacity_too_small() {
    let mut scratch = new_test_scratch();
    scratch.push_finding(make_rec(STEP_ROOT, 10, 16, 100, 106), [0x11; 32]);
    scratch.push_finding(make_rec(STEP_ROOT, 20, 26, 200, 206), [0x22; 32]);

    let mut findings_out = Vec::with_capacity(1);
    let mut hash_out = Vec::with_capacity(2);
    scratch.drain_findings_with_hashes(&mut findings_out, &mut hash_out);
}

#[test]
#[should_panic(expected = "norm-hash output capacity too small")]
fn drain_findings_with_hashes_panics_when_hash_capacity_too_small() {
    let mut scratch = new_test_scratch();
    scratch.push_finding(make_rec(STEP_ROOT, 10, 16, 100, 106), [0x11; 32]);
    scratch.push_finding(make_rec(STEP_ROOT, 20, 26, 200, 206), [0x22; 32]);

    let mut findings_out = Vec::with_capacity(2);
    let mut hash_out = Vec::with_capacity(1);
    scratch.drain_findings_with_hashes(&mut findings_out, &mut hash_out);
}

#[test]
fn cross_chunk_dedupe_tracks_candidates_beyond_emit_cap() {
    let mut tuning = test_tuning();
    tuning.max_findings_per_chunk = 8;
    let engine = Engine::new(vec![simple_rule()], Vec::<TransformConfig>::new(), tuning);
    let mut scratch = engine.new_scratch();

    let make_candidate = |idx: u32| {
        make_rec(
            STEP_ROOT,
            idx.saturating_mul(2),
            idx.saturating_mul(2).saturating_add(1),
            1_000u64.saturating_add(u64::from(idx).saturating_mul(10)),
            1_004u64.saturating_add(u64::from(idx).saturating_mul(10)),
        )
    };

    scratch.update_chunk_overlap(FileId(0), 0, 1024);
    for idx in 0..80u32 {
        let rec = make_candidate(idx);
        let mut norm_hash = [0u8; 32];
        norm_hash[0] = idx as u8;
        scratch.push_finding_with_drop_hint(
            rec,
            norm_hash,
            rec.root_hint_end,
            rec.dedupe_with_span,
        );
    }
    assert_eq!(
        scratch.pending_findings_len(),
        8,
        "emit cap should keep only the first eight pending findings"
    );

    scratch.reset_for_scan_after_prefilter(&engine);
    scratch.update_chunk_overlap(FileId(0), 768, 1024);

    let duplicate = make_candidate(79);
    scratch.push_finding_with_drop_hint(
        duplicate,
        [79u8; 32],
        duplicate.root_hint_end,
        duplicate.dedupe_with_span,
    );

    assert_eq!(
        scratch.pending_findings_len(),
        0,
        "cross-chunk duplicate should be suppressed even when first sighting exceeded emit cap"
    );
}

#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "overflows the 24-bit field")]
fn dedup_rejects_rule_ids_that_overlap_variant_bits() {
    let engine = Engine::new(
        vec![simple_rule()],
        Vec::<TransformConfig>::new(),
        test_tuning(),
    );
    let mut scratch = engine.new_scratch();
    scratch.update_chunk_overlap(FileId(0), 0, 1024);

    // rule_id 0x01_00_00_01 exceeds 24 bits, so the packed dedup key
    // construction must panic rather than silently overlapping the
    // UTF-16 variant discriminator byte.
    let overflow = FindingRec {
        file_id: FileId(0),
        rule_id: 0x01_00_00_01,
        span_start: 10,
        span_end: 20,
        root_hint_start: 100,
        root_hint_end: 120,
        dedupe_with_span: true,
        step_id: STEP_ROOT,
        confidence_score: 0,
    };

    scratch.push_finding_with_drop_hint(
        overflow,
        [0xA1; 32],
        overflow.root_hint_end,
        overflow.dedupe_with_span,
    );
}

#[test]
fn same_scan_raw_duplicate_is_not_replaced_by_equal() {
    // Two identical RAW findings in the same scan: the second is recognized as
    // a same-scan duplicate. Because root_hint_end is equal, no replacement
    // occurs — the original stays.
    let engine = Engine::new(
        vec![simple_rule()],
        Vec::<TransformConfig>::new(),
        test_tuning(),
    );
    let mut scratch = engine.new_scratch();
    scratch.update_chunk_overlap(FileId(0), 0, 1024);

    let rec = FindingRec {
        file_id: FileId(0),
        rule_id: 0,
        span_start: 10,
        span_end: 20,
        root_hint_start: 100,
        root_hint_end: 120,
        dedupe_with_span: true,
        step_id: STEP_ROOT,
        confidence_score: 0,
    };
    let hash_a = [0xA1; 32];
    let hash_b = [0xB2; 32];

    scratch.push_finding_with_drop_hint(rec, hash_a, rec.root_hint_end, rec.dedupe_with_span);
    scratch.push_finding_with_drop_hint(rec, hash_b, rec.root_hint_end, rec.dedupe_with_span);

    assert_eq!(
        scratch.pending_findings_len(),
        1,
        "duplicate should not create a second finding"
    );

    let mut findings = Vec::with_capacity(1);
    let mut hashes = Vec::with_capacity(1);
    scratch.drain_findings_with_hashes(&mut findings, &mut hashes);
    assert_eq!(
        hashes[0], hash_a,
        "original norm_hash should be preserved (no replacement)"
    );
}

#[test]
fn same_scan_transform_replaces_raw_finding() {
    // A transform finding (step_id != STEP_ROOT) should replace a RAW finding
    // (step_id == STEP_ROOT) when both produce the same DedupKey hash.
    //
    // DedupKey composition: (file_id, rule_id|variant_disc<<24, span_start,
    // span_end, root_hint_start, root_hint_end).
    //
    // For STEP_ROOT findings, span is always included in the key (the
    // `include_span || step_id == STEP_ROOT` guard). For non-root transform
    // findings with include_span=false, span is zeroed to (0, 0). To make
    // both keys hash identically, the RAW finding uses span=(0, 0) as well.
    let engine = Engine::new(
        vec![simple_rule()],
        Vec::<TransformConfig>::new(),
        test_tuning(),
    );
    let mut scratch = engine.new_scratch();
    scratch.update_chunk_overlap(FileId(0), 0, 4096);

    let raw_rec = FindingRec {
        file_id: FileId(0),
        rule_id: 0,
        span_start: 0,
        span_end: 0,
        root_hint_start: 100,
        root_hint_end: 120,
        dedupe_with_span: false,
        step_id: STEP_ROOT,
        confidence_score: 0,
    };
    let raw_hash = [0xAA; 32];
    scratch.push_finding_with_drop_hint(raw_rec, raw_hash, raw_rec.root_hint_end, false);

    // Non-UTF16 transform: variant_disc=0, so rule_id_with_variant matches the
    // RAW finding. include_span=false zeroes the span to (0, 0).
    let transform_step = scratch.step_arena.push(
        STEP_ROOT,
        DecodeStep::Transform {
            transform_idx: 0,
            parent_span: 0..100,
        },
    );
    let transform_rec = FindingRec {
        file_id: FileId(0),
        rule_id: 0,
        span_start: 5,
        span_end: 15,
        root_hint_start: 100,
        root_hint_end: 120,
        dedupe_with_span: false,
        step_id: transform_step,
        confidence_score: 0,
    };
    let transform_hash = [0xBB; 32];
    scratch.push_finding_with_drop_hint(
        transform_rec,
        transform_hash,
        transform_rec.root_hint_end,
        false,
    );

    assert_eq!(scratch.pending_findings_len(), 1);
    let mut findings = Vec::with_capacity(1);
    let mut hashes = Vec::with_capacity(1);
    scratch.drain_findings_with_hashes(&mut findings, &mut hashes);
    assert_ne!(
        findings[0].step_id, STEP_ROOT,
        "transform finding should have replaced the RAW finding"
    );
    assert_eq!(
        hashes[0], transform_hash,
        "norm_hash should be updated to the transform's hash"
    );
}

#[test]
fn same_scan_raw_does_not_replace_transform_finding() {
    // The reverse: a RAW finding should NOT replace an existing transform finding.
    // Same DedupKey alignment constraints as the test above — RAW span must be
    // (0, 0) to match the transform's zeroed span in the dedup key.
    let engine = Engine::new(
        vec![simple_rule()],
        Vec::<TransformConfig>::new(),
        test_tuning(),
    );
    let mut scratch = engine.new_scratch();
    scratch.update_chunk_overlap(FileId(0), 0, 4096);

    // Push a transform finding first.
    let transform_step = scratch.step_arena.push(
        STEP_ROOT,
        DecodeStep::Transform {
            transform_idx: 0,
            parent_span: 0..100,
        },
    );
    let transform_rec = FindingRec {
        file_id: FileId(0),
        rule_id: 0,
        span_start: 5,
        span_end: 15,
        root_hint_start: 100,
        root_hint_end: 120,
        dedupe_with_span: false,
        step_id: transform_step,
        confidence_score: 0,
    };
    let transform_hash = [0xBB; 32];
    scratch.push_finding_with_drop_hint(
        transform_rec,
        transform_hash,
        transform_rec.root_hint_end,
        false,
    );

    // Now push a RAW finding that hashes the same (span=0,0 to match zeroed
    // transform span in DedupKey).
    let raw_rec = FindingRec {
        file_id: FileId(0),
        rule_id: 0,
        span_start: 0,
        span_end: 0,
        root_hint_start: 100,
        root_hint_end: 120,
        dedupe_with_span: false,
        step_id: STEP_ROOT,
        confidence_score: 0,
    };
    let raw_hash = [0xAA; 32];
    scratch.push_finding_with_drop_hint(raw_rec, raw_hash, raw_rec.root_hint_end, false);

    assert_eq!(scratch.pending_findings_len(), 1);
    let mut findings = Vec::with_capacity(1);
    let mut hashes = Vec::with_capacity(1);
    scratch.drain_findings_with_hashes(&mut findings, &mut hashes);
    assert_ne!(
        findings[0].step_id, STEP_ROOT,
        "transform finding should NOT be replaced by RAW"
    );
    assert_eq!(
        hashes[0], transform_hash,
        "original transform hash should be preserved"
    );
}

// ── DedupKey packing boundary tests ─────────────────────────────────────

#[test]
fn pack_rule_id_at_max_boundary() {
    use super::{DEDUP_RULE_ID_BITS, DEDUP_RULE_ID_MAX, pack_rule_id_with_variant};

    // Exactly at DEDUP_RULE_ID_MAX should succeed.
    let packed = pack_rule_id_with_variant(DEDUP_RULE_ID_MAX, 0);
    assert_eq!(packed, DEDUP_RULE_ID_MAX);

    // With variant discriminator.
    let packed = pack_rule_id_with_variant(DEDUP_RULE_ID_MAX, 2);
    assert_eq!(packed & DEDUP_RULE_ID_MAX, DEDUP_RULE_ID_MAX);
    assert_eq!(packed >> DEDUP_RULE_ID_BITS, 2);
}

#[test]
#[should_panic(expected = "rule_id exceeds 24-bit dedup budget")]
fn pack_rule_id_overflow_panics() {
    use super::{DEDUP_RULE_ID_MAX, pack_rule_id_with_variant};

    pack_rule_id_with_variant(DEDUP_RULE_ID_MAX + 1, 0);
}

#[test]
fn higher_confidence_wins_dedup() {
    // Two RAW findings at the same position (identical DedupKey) but with
    // different confidence_score values.  The second push triggers
    // `replace_same_scan_duplicate`; because root_hint_end is equal the
    // tie-breaker is confidence_score — the higher value should win.
    let engine = Engine::new(
        vec![simple_rule()],
        Vec::<TransformConfig>::new(),
        test_tuning(),
    );
    let mut scratch = engine.new_scratch();
    scratch.update_chunk_overlap(FileId(0), 0, 1024);

    let low = FindingRec {
        file_id: FileId(0),
        rule_id: 0,
        span_start: 10,
        span_end: 20,
        root_hint_start: 100,
        root_hint_end: 120,
        dedupe_with_span: true,
        step_id: STEP_ROOT,
        confidence_score: 3,
    };
    let high = FindingRec {
        confidence_score: 7,
        ..low
    };

    let hash_low = [0xAA; 32];
    let hash_high = [0xBB; 32];

    // Insert low-confidence first, then high-confidence.
    scratch.push_finding_with_drop_hint(low, hash_low, low.root_hint_end, low.dedupe_with_span);
    scratch.push_finding_with_drop_hint(high, hash_high, high.root_hint_end, high.dedupe_with_span);

    assert_eq!(
        scratch.pending_findings_len(),
        1,
        "duplicate should not create a second finding"
    );

    // The arena should contain the high-confidence finding.
    let mut findings = Vec::with_capacity(1);
    let mut hashes = Vec::with_capacity(1);
    scratch.drain_findings_with_hashes(&mut findings, &mut hashes);
    assert_eq!(
        findings[0].confidence_score, 7,
        "higher confidence should replace lower"
    );
    assert_eq!(
        hashes[0], hash_high,
        "norm_hash should be updated to the higher-confidence finding's hash"
    );
}

#[test]
fn higher_confidence_retained_on_reverse_insert() {
    // Insert the HIGH-confidence finding first, then the low-confidence one.
    // The dedup logic must keep the higher score even when it arrives first.
    let engine = Engine::new(
        vec![simple_rule()],
        Vec::<TransformConfig>::new(),
        test_tuning(),
    );
    let mut scratch = engine.new_scratch();
    scratch.update_chunk_overlap(FileId(0), 0, 1024);

    let high = FindingRec {
        file_id: FileId(0),
        rule_id: 0,
        span_start: 10,
        span_end: 20,
        root_hint_start: 100,
        root_hint_end: 120,
        dedupe_with_span: true,
        step_id: STEP_ROOT,
        confidence_score: 7,
    };
    let low = FindingRec {
        confidence_score: 3,
        ..high
    };

    let hash_high = [0xBB; 32];
    let hash_low = [0xAA; 32];

    // High first, then low.
    scratch.push_finding_with_drop_hint(high, hash_high, high.root_hint_end, high.dedupe_with_span);
    scratch.push_finding_with_drop_hint(low, hash_low, low.root_hint_end, low.dedupe_with_span);

    assert_eq!(
        scratch.pending_findings_len(),
        1,
        "duplicate should not create a second finding"
    );

    let mut findings = Vec::with_capacity(1);
    let mut hashes = Vec::with_capacity(1);
    scratch.drain_findings_with_hashes(&mut findings, &mut hashes);
    assert_eq!(
        findings[0].confidence_score, 7,
        "higher confidence must be retained when inserted first"
    );
    assert_eq!(
        hashes[0], hash_high,
        "norm_hash must remain the high-confidence finding's hash"
    );
}

#[test]
fn transform_finding_storage_normalizes_base64_root_hint_end() {
    let mut scratch = new_test_scratch();
    scratch.update_chunk_overlap(FileId(0), 0, 4096);

    let transform = base64_test_transform_config();
    let encoded = b"U0VDUkVUQUJDREVGR0g=".to_vec();
    scratch.root_span_map_ctx = Some(RootSpanMapCtx::new(&transform, &encoded, 1000, 0));

    let transform_step = scratch.step_arena.push(
        STEP_ROOT,
        DecodeStep::Transform {
            transform_idx: 0,
            parent_span: 0..encoded.len(),
        },
    );
    let rec = make_rec(transform_step, 200, 213, 1000, 1019);

    scratch.push_finding_with_drop_hint(rec, [0xCC; 32], 1024, false);

    assert_eq!(scratch.pending_findings_len(), 1);
    assert_eq!(
        scratch.findings()[0].root_hint_end,
        1018,
        "emitted finding should store the normalized base64 root hint end"
    );
    assert_eq!(
        scratch.drop_hint_end()[0],
        1024,
        "drop hint sidecar must remain unchanged by root hint normalization"
    );
}

#[test]
fn same_scan_base64_transform_replacement_keeps_normalized_root_hint_end() {
    let mut scratch = new_test_scratch();
    scratch.update_chunk_overlap(FileId(0), 0, 4096);

    let raw_rec = FindingRec {
        file_id: FileId(0),
        rule_id: 0,
        span_start: 0,
        span_end: 0,
        root_hint_start: 1000,
        root_hint_end: 1018,
        dedupe_with_span: false,
        step_id: STEP_ROOT,
        confidence_score: 0,
    };
    scratch.push_finding_with_drop_hint(raw_rec, [0x11; 32], raw_rec.root_hint_end, false);

    let transform = base64_test_transform_config();
    let encoded = b"U0VDUkVUQUJDREVGR0g=".to_vec();
    scratch.root_span_map_ctx = Some(RootSpanMapCtx::new(&transform, &encoded, 1000, 0));

    let transform_step = scratch.step_arena.push(
        STEP_ROOT,
        DecodeStep::Transform {
            transform_idx: 0,
            parent_span: 0..encoded.len(),
        },
    );
    let transform_rec = FindingRec {
        file_id: FileId(0),
        rule_id: 0,
        span_start: 5,
        span_end: 18,
        root_hint_start: 1000,
        root_hint_end: 1019,
        dedupe_with_span: false,
        step_id: transform_step,
        confidence_score: 0,
    };

    scratch.push_finding_with_drop_hint(
        transform_rec,
        [0x22; 32],
        transform_rec.root_hint_end,
        false,
    );

    assert_eq!(scratch.pending_findings_len(), 1);
    assert_ne!(
        scratch.findings()[0].step_id,
        STEP_ROOT,
        "transform finding should replace the RAW duplicate"
    );
    assert_eq!(
        scratch.findings()[0].root_hint_end,
        1018,
        "replacement path must keep the normalized base64 root hint end"
    );

    let mut findings = Vec::with_capacity(1);
    let mut hashes = Vec::with_capacity(1);
    scratch.drain_findings_with_hashes(&mut findings, &mut hashes);
    assert_eq!(
        hashes[0], [0x22; 32],
        "norm_hash must be updated to the transform finding's hash"
    );
}

#[test]
fn normalization_skipped_without_root_span_map_ctx() {
    let mut scratch = new_test_scratch();
    scratch.update_chunk_overlap(FileId(0), 0, 4096);
    // No root_span_map_ctx — leaf_transform resolves to None, so the
    // normalize function returns root_hint_end unchanged even for a
    // non-root step.
    let step = scratch.step_arena.push(
        STEP_ROOT,
        DecodeStep::Transform {
            transform_idx: 0,
            parent_span: 0..20,
        },
    );
    let rec = make_rec(step, 200, 213, 1000, 1019);
    scratch.push_finding_with_drop_hint(rec, [0xAA; 32], 1024, false);
    assert_eq!(
        scratch.findings()[0].root_hint_end,
        1019,
        "without root_span_map_ctx, root_hint_end must remain un-normalized"
    );
}
