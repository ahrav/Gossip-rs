//! Engine tests and property checks.
//!
//! These tests exercise anchor selection, transform gating, and provenance
//! tracking. A slow reference scanner is included to validate correctness
//! across transforms and UTF-16 variants.

use super::core::Engine;
#[cfg(feature = "stdx-proptest")]
use super::helpers::entropy_gate_outcome;
use super::helpers::{decode_utf16be_to_vec, decode_utf16le_to_vec, extract_secret_span, hash128};
#[cfg(all(test, feature = "stdx-proptest"))]
use super::hit_pool::{HitAccPool, SpanU32};
#[cfg(feature = "stdx-proptest")]
use super::rule_repr::EntropyCompiled;
use super::rule_repr::{PackedPatterns, Variant, utf16be_bytes, utf16le_bytes};
#[cfg(feature = "stdx-proptest")]
use super::scratch::EntropyScratch;
#[cfg(feature = "stdx-proptest")]
use super::simd_classify::classify_window;
#[cfg(all(test, feature = "stdx-proptest"))]
use super::transform::find_url_spans_into;
#[cfg(feature = "stdx-proptest")]
use super::transform::{
    base64_char_count, base64_skip_chars, find_spans_into, transform_quick_trigger,
};
use super::transform::{decode_to_vec, find_base64_spans_into};
#[cfg(feature = "stdx-proptest")]
use super::vectorscan_prefilter::{
    VsStreamMatchCtx, VsStreamWindow, build_stream_match_ctx, gate_match_callback,
    stream_match_callback,
};
#[cfg(all(test, feature = "stdx-proptest"))]
use crate::api::OfflineVerdict;
use crate::api::Tuning;
use crate::api::confidence;
use crate::api::{
    AnchorPolicy, CharClassSpec, DecodeStep, EntropySpec, FileId, Finding, FindingRec, Gate,
    LocalContextSpec, OfflineValidationSpec, RuleSpec, STEP_ROOT, TransformConfig, TransformId,
    TransformMode, Utf16Endianness, ValidatorKind,
};
use crate::demo::{demo_engine, demo_rules, demo_tuning};
use crate::regex2anchor::{AnchorDeriveConfig, TriggerPlan, compile_trigger_plan};
#[cfg(all(test, feature = "stdx-proptest"))]
use crate::scratch_memory::ScratchVec;
#[cfg(all(test, feature = "stdx-proptest"))]
use crate::tiger_harness::{ChunkPattern, maybe_write_regression};
use crate::tiger_harness::{
    ChunkPlan, check_oracle_covered, correctness_engine, load_regressions_from_dir,
    scan_chunked_records, scan_one_chunk_records,
};
#[cfg(feature = "stdx-proptest")]
use memchr::memmem;
#[cfg(feature = "stdx-proptest")]
use proptest::prelude::*;
use regex::bytes::Regex;
use rstest::rstest;
use std::collections::HashSet;
#[cfg(feature = "stdx-proptest")]
use std::ops::Range;
use std::path::Path;
use std::sync::OnceLock;

// ---------------------------------------------------------------------------
// Cached engine singletons — Vectorscan DB compilation is extremely expensive
// (~40-60s per build). These let all tests share a single compiled engine
// rather than each test building its own.
// ---------------------------------------------------------------------------

/// Returns a shared reference to a [`demo_engine()`] instance, building it
/// on first access. All subsequent calls return the same engine.
fn cached_demo_engine() -> &'static Engine {
    static INSTANCE: OnceLock<Engine> = OnceLock::new();
    INSTANCE.get_or_init(demo_engine)
}

/// Returns a shared reference to a [`correctness_engine()`] instance, building
/// it on first access. All subsequent calls return the same engine.
fn cached_correctness_engine() -> &'static Engine {
    static INSTANCE: OnceLock<Engine> = OnceLock::new();
    INSTANCE.get_or_init(correctness_engine)
}

#[cfg(feature = "stdx-proptest")]
fn decoded_prefilter_hit(engine: &Engine, decoded: &[u8]) -> bool {
    if let Some(vs_gate) = engine.vs_gate.as_ref() {
        let mut scratch = match vs_gate.alloc_scratch() {
            Ok(s) => s,
            Err(_) => return false,
        };
        let mut stream = match vs_gate.open_stream() {
            Ok(s) => s,
            Err(_) => return false,
        };

        let mut hit: u8 = 0;
        let cb = gate_match_callback();
        if vs_gate
            .scan_stream(
                &mut stream,
                decoded,
                &mut scratch,
                cb,
                (&mut hit as *mut u8).cast(),
            )
            .is_err()
        {
            let _ = vs_gate.close_stream(stream, &mut scratch, cb, (&mut hit as *mut u8).cast());
            return false;
        }
        if vs_gate
            .close_stream(stream, &mut scratch, cb, (&mut hit as *mut u8).cast())
            .is_err()
        {
            return false;
        }
        return hit != 0;
    }

    let Some(vs_stream) = engine.vs_stream.as_ref() else {
        return true;
    };

    let mut scratch = match vs_stream.alloc_scratch() {
        Ok(s) => s,
        Err(_) => return false,
    };
    let mut stream = match vs_stream.open_stream() {
        Ok(s) => s,
        Err(_) => return false,
    };

    let mut pending: Vec<VsStreamWindow> = Vec::with_capacity(32);
    let pending_cap = u32::try_from(pending.capacity()).unwrap_or(u32::MAX);
    let mut pending_len: u32 = 0;
    let mut overflowed: u8 = 0;
    let mut ctx = build_stream_match_ctx(
        &mut pending,
        &mut pending_len,
        vs_stream.meta(),
        pending_cap,
        &mut overflowed,
    );
    let cb = stream_match_callback();

    if vs_stream
        .scan_stream(
            &mut stream,
            decoded,
            &mut scratch,
            cb,
            (&mut ctx as *mut VsStreamMatchCtx).cast(),
        )
        .is_err()
    {
        let _ = vs_stream.close_stream(
            stream,
            &mut scratch,
            cb,
            (&mut ctx as *mut VsStreamMatchCtx).cast(),
        );
        return false;
    }
    // SAFETY: The FFI callback writes at most `pending_cap` elements into the vec's spare
    // capacity, and `pending_len` is set by the callback to the number actually written,
    // so `pending_len <= pending.capacity()` and all elements are initialized.
    unsafe { pending.set_len(pending_len as usize) };
    let mut hit = !pending.is_empty();
    pending.clear();
    pending_len = 0;

    if vs_stream
        .close_stream(
            stream,
            &mut scratch,
            cb,
            (&mut ctx as *mut VsStreamMatchCtx).cast(),
        )
        .is_err()
    {
        return false;
    }
    // SAFETY: Same as above -- the callback initialized `pending_len` elements within the
    // vec's spare capacity after `clear()` reset the length to zero.
    unsafe { pending.set_len(pending_len as usize) };
    if !pending.is_empty() {
        hit = true;
    }

    hit
}

#[test]
fn norm_hash_deterministic_for_raw_matches() {
    let rule = RuleSpec {
        radius: 16,
        secret_group: Some(1),
        ..base_rule("tok", &[b"TOK_"], Regex::new(r"TOK_([A-Z0-9]{4})").unwrap())
    };

    let engine = Engine::new_with_anchor_policy(
        vec![rule],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );
    let mut scratch = engine.new_scratch();
    let hay = b"xx TOK_ABCD yy TOK_ABCD zz TOK_WXYZ";
    engine.scan_chunk_into(hay, FileId(0), 0, &mut scratch);
    scratch.drop_prefix_findings(0);

    let recs = scratch.findings();
    let hashes = scratch.norm_hashes();
    assert_eq!(recs.len(), hashes.len());
    assert!(recs.len() >= 3);

    let mut seen = std::collections::HashMap::new();
    for (rec, hash) in recs.iter().zip(hashes.iter()) {
        let secret = &hay[rec.span_start as usize..rec.span_end as usize];
        let expected = *blake3::hash(secret).as_bytes();
        assert_eq!(*hash, expected);
        *seen.entry(*hash).or_insert(0usize) += 1;
    }

    let abcd = *blake3::hash(b"ABCD").as_bytes();
    let wxyz = *blake3::hash(b"WXYZ").as_bytes();
    assert_eq!(seen.get(&abcd), Some(&2));
    assert_eq!(seen.get(&wxyz), Some(&1));
}

#[test]
fn norm_hash_uses_decoded_bytes_for_base64_transform() {
    let rule = RuleSpec {
        radius: 24,
        secret_group: Some(1),
        ..base_rule(
            "b64",
            &[b"SECRET_"],
            Regex::new(r"SECRET_([A-Z]{4})").unwrap(),
        )
    };
    let transforms = vec![TransformConfig {
        id: TransformId::Base64,
        mode: TransformMode::Always,
        gate: Gate::AnchorsInDecoded,
        min_len: 8,
        max_spans_per_buffer: 8,
        max_encoded_len: 1024,
        max_decoded_bytes: 1024,
        plus_to_space: false,
        base64_allow_space_ws: false,
    }];

    let engine = Engine::new_with_anchor_policy(
        vec![rule],
        transforms,
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );
    let mut scratch = engine.new_scratch();
    let hay = b"prefix U0VDUkVUX0FCQ0Q= suffix";
    engine.scan_chunk_into(hay, FileId(0), 0, &mut scratch);
    scratch.drop_prefix_findings(0);

    let hashes = scratch.norm_hashes();
    assert_eq!(hashes.len(), 1);
    let expected = *blake3::hash(b"ABCD").as_bytes();
    assert_eq!(hashes[0], expected);
}

#[test]
fn local_context_gate_applies_in_base64_stream_decode() {
    let rule = RuleSpec {
        radius: 24,
        local_context: Some(LocalContextSpec {
            lookbehind: 64,
            lookahead: 64,
            require_same_line_assignment: false,
            require_quoted: true,
            key_names_any: None,
        }),
        secret_group: Some(0),
        ..base_rule(
            "b64-local-context",
            &[b"SECRET_"],
            Regex::new(r"SECRET_[A-Z]{4}").unwrap(),
        )
    };
    let transforms = vec![TransformConfig {
        id: TransformId::Base64,
        mode: TransformMode::Always,
        gate: Gate::AnchorsInDecoded,
        min_len: 8,
        max_spans_per_buffer: 8,
        max_encoded_len: 1024,
        max_decoded_bytes: 1024,
        plus_to_space: false,
        base64_allow_space_ws: false,
    }];

    let engine = Engine::new_with_anchor_policy(
        vec![rule],
        transforms,
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );

    let good_plain = b"key=\"SECRET_ABCD\" ";
    let good_b64 = b64_encode(good_plain);
    let hay = format!("prefix {good_b64} suffix");
    let hits = scan_chunk_findings(&engine, hay.as_bytes());
    assert!(
        hits.iter().any(|h| h.rule == "b64-local-context"),
        "expected finding with quoted secret in decoded stream"
    );

    let bad_plain = b"key=SECRET_ABCD ";
    let bad_b64 = b64_encode(bad_plain);
    let hay = format!("prefix {bad_b64} suffix");
    let hits = scan_chunk_findings(&engine, hay.as_bytes());
    assert!(
        !hits.iter().any(|h| h.rule == "b64-local-context"),
        "expected local context gate to filter unquoted decoded secret"
    );
}

#[test]
fn local_context_gate_filters_without_assignment_when_bounds_present() {
    let rule = RuleSpec {
        local_context: Some(LocalContextSpec {
            lookbehind: 64,
            lookahead: 64,
            require_same_line_assignment: true,
            require_quoted: false,
            key_names_any: None,
        }),
        ..base_rule(
            "lc-assign",
            &[b"TOK_"],
            Regex::new(r"TOK_[A-Z]{4}").unwrap(),
        )
    };

    let engine = Engine::new_with_anchor_policy(
        vec![rule],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );

    let hay = b"prefix\nTOK_ABCD\nsuffix";
    let hits = scan_chunk_findings(&engine, hay);
    assert!(
        !hits.iter().any(|h| h.rule == "lc-assign"),
        "expected local context gate to filter when assignment is missing"
    );

    let hay = b"prefix\nkey = TOK_ABCD\nsuffix";
    let hits = scan_chunk_findings(&engine, hay);
    assert!(
        hits.iter().any(|h| h.rule == "lc-assign"),
        "expected local context gate to pass when assignment is present"
    );
}

#[test]
fn local_context_key_names_required_and_fail_open_when_out_of_range() {
    let rule = RuleSpec {
        local_context: Some(LocalContextSpec {
            lookbehind: 64,
            lookahead: 64,
            require_same_line_assignment: false,
            require_quoted: false,
            key_names_any: Some(&[b"key"]),
        }),
        ..base_rule(
            "lc-keyname",
            &[b"TOK_"],
            Regex::new(r"TOK_[A-Z]{4}").unwrap(),
        )
    };

    let engine = Engine::new_with_anchor_policy(
        vec![rule],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );

    let hay = b"prefix\nkey = TOK_ABCD\nsuffix";
    let hits = scan_chunk_findings(&engine, hay);
    assert!(
        hits.iter().any(|h| h.rule == "lc-keyname"),
        "expected local context gate to pass with required key name"
    );

    let hay = b"prefix\nvalue = TOK_ABCD\nsuffix";
    let hits = scan_chunk_findings(&engine, hay);
    assert!(
        !hits.iter().any(|h| h.rule == "lc-keyname"),
        "expected local context gate to filter without key name"
    );

    let hay = b"prefix key = TOK_ABCD suffix";
    let hits = scan_chunk_findings(&engine, hay);
    assert!(
        hits.iter().any(|h| h.rule == "lc-keyname"),
        "expected local context gate to fail open when line bounds are missing"
    );
}

// Helper that uses the allocation-free scan API and materializes findings.
fn scan_chunk_findings(engine: &Engine, hay: &[u8]) -> Vec<Finding> {
    let mut scratch = engine.new_scratch();
    let mut out = Vec::with_capacity(engine.tuning.max_findings_per_chunk);
    engine.scan_chunk_materialized(hay, &mut scratch, &mut out);
    out
}

fn unpack_patterns(pats: &PackedPatterns) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let count = pats.offsets.len().saturating_sub(1);
    for i in 0..count {
        let start = pats.offsets[i] as usize;
        let end = pats.offsets[i + 1] as usize;
        out.push(pats.bytes[start..end].to_vec());
    }
    out
}

/// Shared base `RuleSpec` with default field values. Tests override only the
/// fields that matter via struct-update syntax (`..base_rule(…)`).
fn base_rule(name: &'static str, anchors: &'static [&'static [u8]], re: Regex) -> RuleSpec {
    RuleSpec {
        name,
        anchors,
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
        re,
    }
}

// Tiny base64 encoder for tests (standard alphabet, with '=' padding).
fn b64_encode(input: &[u8]) -> String {
    const ALPH: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    let mut i = 0usize;

    while i < input.len() {
        let b0 = input[i];
        let b1 = if i + 1 < input.len() { input[i + 1] } else { 0 };
        let b2 = if i + 2 < input.len() { input[i + 2] } else { 0 };

        let n = ((b0 as u32) << 16) | ((b1 as u32) << 8) | (b2 as u32);

        let c0 = ((n >> 18) & 63) as usize;
        let c1 = ((n >> 12) & 63) as usize;
        let c2 = ((n >> 6) & 63) as usize;
        let c3 = (n & 63) as usize;

        out.push(ALPH[c0] as char);
        out.push(ALPH[c1] as char);

        if i + 1 < input.len() {
            out.push(ALPH[c2] as char);
        } else {
            out.push('=');
        }

        if i + 2 < input.len() {
            out.push(ALPH[c3] as char);
        } else {
            out.push('=');
        }

        i += 3;
    }

    out
}

#[cfg(feature = "stdx-proptest")]
fn is_b64_char_ref(b: u8) -> bool {
    matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/' | b'=' | b'-' | b'_')
}

#[cfg(feature = "stdx-proptest")]
fn is_b64_ws_ref(b: u8, allow_space_ws: bool) -> bool {
    matches!(b, b'\n' | b'\r' | b'\t') || (allow_space_ws && b == b' ')
}

#[cfg(feature = "stdx-proptest")]
fn is_b64_or_ws_ref(b: u8, allow_space_ws: bool) -> bool {
    is_b64_char_ref(b) || is_b64_ws_ref(b, allow_space_ws)
}

#[cfg(feature = "stdx-proptest")]
fn find_base64_spans_reference(
    hay: &[u8],
    min_chars: usize,
    max_len: usize,
    max_spans: usize,
    allow_space_ws: bool,
) -> Vec<Range<usize>> {
    assert!(max_len >= min_chars);
    let mut spans: Vec<Range<usize>> = Vec::new();
    if max_spans == 0 {
        return spans;
    }

    // Mirror the production span finder semantics, including padding handling.
    let mut i = 0usize;
    let mut in_run = false;
    let mut start = 0usize;
    let mut run_len = 0usize;
    let mut b64_chars = 0usize;
    let mut have_b64 = false;
    let mut last_b64 = 0usize;

    while i < hay.len() && spans.len() < max_spans {
        let b = hay[i];
        let allowed = is_b64_or_ws_ref(b, allow_space_ws);

        if !in_run {
            if !allowed {
                i += 1;
                continue;
            }
            in_run = true;
            start = i;
            run_len = 0;
            b64_chars = 0;
            have_b64 = false;
        }

        if allowed {
            run_len += 1;
            if is_b64_char_ref(b) {
                if b == b'=' {
                    if have_b64 {
                        let mut pad_end = i;
                        if i + 1 < hay.len() && hay[i + 1] == b'=' {
                            pad_end = i + 1;
                            i += 1;
                        }
                        last_b64 = pad_end;
                        if b64_chars >= min_chars {
                            spans.push(start..(last_b64 + 1));
                            if spans.len() >= max_spans {
                                return spans;
                            }
                        }
                    }
                    in_run = false;
                    i += 1;
                    continue;
                }
                b64_chars += 1;
                last_b64 = i;
                have_b64 = true;
            }
            i += 1;

            if run_len >= max_len {
                if have_b64 && b64_chars >= min_chars {
                    spans.push(start..(last_b64 + 1));
                    if spans.len() >= max_spans {
                        return spans;
                    }
                }
                in_run = false;
            }
        } else {
            if have_b64 && b64_chars >= min_chars {
                spans.push(start..(last_b64 + 1));
                if spans.len() >= max_spans {
                    return spans;
                }
            }
            in_run = false;
            i += 1;
        }
    }

    if in_run && have_b64 && b64_chars >= min_chars && spans.len() < max_spans {
        spans.push(start..(last_b64 + 1));
    }

    spans
}

#[test]
fn hash128_deterministic() {
    let data = b"hello world";
    let h1 = hash128(data);
    let h2 = hash128(data);
    assert_eq!(h1, h2);

    // Different inputs produce different hashes.
    let h3 = hash128(b"hello worlD");
    assert_ne!(h1, h3);
}

#[test]
fn hash128_collision_resistant() {
    // Verify that small changes produce different hashes.
    let base = b"AKIAIOSFODNN7EXAMPLE";
    let h_base = hash128(base);

    // Single byte change.
    let mut modified = *base;
    modified[0] ^= 1;
    assert_ne!(h_base, hash128(&modified));

    // Append a byte.
    let mut appended = base.to_vec();
    appended.push(0);
    assert_ne!(h_base, hash128(&appended));

    // Empty input has distinct hash.
    let h_empty = hash128(b"");
    assert_ne!(h_base, h_empty);
}

#[test]
fn url_span_includes_prefix_and_finds_ghp() {
    let eng = cached_demo_engine();
    // ghp_ + 36 chars
    let token = "ghp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8";
    let url = token.replace("_", "%5F"); // ghp%5F...
    let hay = format!("token={}", url).into_bytes();

    let hits = scan_chunk_findings(&eng, &hay);
    assert!(hits.iter().any(|h| h.rule == "github-pat"));
}

#[test]
fn rules_hot_and_cold_have_equal_length() {
    let eng = cached_demo_engine();
    assert_eq!(
        eng.rules_hot.len(),
        eng.rules_cold.len(),
        "rules_hot and rules_cold must be parallel arrays of equal length"
    );
}

#[test]
fn zero_hit_url_plus_to_space_still_scans_transforms() {
    let rule = RuleSpec {
        ..base_rule(
            "url-plus-space",
            &[b"TOK "],
            Regex::new(r"TOK [A-Z]{4}").unwrap(),
        )
    };
    let transforms = vec![TransformConfig {
        id: TransformId::UrlPercent,
        mode: TransformMode::Always,
        gate: Gate::AnchorsInDecoded,
        min_len: 4,
        max_spans_per_buffer: 16,
        max_encoded_len: 1024,
        max_decoded_bytes: 1024,
        plus_to_space: true,
        base64_allow_space_ws: false,
    }];

    let engine = Engine::new_with_anchor_policy(
        vec![rule],
        transforms,
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );

    // Raw bytes contain "TOK+ABCD" (no "%XX"), so only URL plus-to-space decode
    // can produce the anchored token "TOK ABCD".
    let hay = b"prefix TOK+ABCD suffix";
    let hits = scan_chunk_findings(&engine, hay);
    assert!(
        hits.iter().any(|h| h.rule == "url-plus-space"),
        "expected plus-to-space URL transform to decode and match"
    );
}

#[test]
fn base64_utf16_aws_key_is_detected() {
    let eng = cached_demo_engine();

    // Use a realistic (non-example) AWS key. The previous value
    // "AKIAIOSFODNN7EXAMPLE" is now correctly suppressed by the secret-bytes
    // safelist as an AWS example key.
    let aws = b"AKIAIOSFODNN7ABCDEFG"; // 20 bytes, not an EXAMPLE key
    let utf16le = utf16le_bytes(aws);
    let b64 = b64_encode(&utf16le);

    let hay = format!("prefix {} suffix", b64).into_bytes();
    let hits = scan_chunk_findings(&eng, &hay);

    assert!(hits.iter().any(|h| h.rule == "aws-access-token"));
}

#[test]
fn base64_padding_in_root_hint() {
    let rule = RuleSpec {
        radius: 25,
        ..base_rule(
            "b64-padding",
            &[b"SIM0_"],
            Regex::new(r"SIM0_[A-Z0-9]{12}").unwrap(),
        )
    };
    let transforms = vec![TransformConfig {
        id: TransformId::Base64,
        mode: TransformMode::Always,
        gate: Gate::AnchorsInDecoded,
        min_len: 4,
        max_spans_per_buffer: 16,
        max_encoded_len: 64 * 1024,
        max_decoded_bytes: 64 * 1024,
        plus_to_space: false,
        base64_allow_space_ws: false,
    }];
    let engine = Engine::new_with_anchor_policy(
        vec![rule],
        transforms,
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );

    let token = b"SIM0_ABCDEFGH1234";
    let b64 = b64_encode(token);
    let hay = format!("xx{}yy", b64).into_bytes();
    let start = 2usize;
    let end = start + b64.len();

    // After Base64 normalization, `root_hint_end` is snapped to the
    // padding-free minimum encoded length: ceil(decoded_len * 4/3).
    // For a 17-byte token, min_encoded = 23, so the normalized end is
    // start + 23 = 25, one byte less than the full 24-char Base64 span.
    let decoded_len = token.len() as u64;
    let min_encoded = (decoded_len * 4).div_ceil(3);
    let normalized_end = start as u64 + min_encoded;

    let hits = scan_chunk_findings(&engine, &hay);
    assert!(
        hits.iter().any(|h| {
            h.rule == "b64-padding"
                && h.root_span_hint.start <= start
                && h.root_span_hint.end as u64 >= normalized_end
                && h.root_span_hint.end <= end
        }),
        "expected base64 root_hint to cover at least the padding-normalized \
         span {}..{} (raw encoded end {})",
        start,
        normalized_end,
        end,
    );
}

#[rstest]
#[case::trims_trailing_space(b"AAAA   " as &[u8], 2, 32, 8, true, vec![0..4])]
#[case::includes_leading_space(b"  AAAA" as &[u8], 2, 32, 8, true, vec![0..6])]
#[case::disallows_space(b"AA AA" as &[u8], 1, 32, 8, false, vec![0..2, 3..5])]
#[case::respects_min_chars(b"A \tA" as &[u8], 3, 32, 8, true, vec![])]
#[case::respects_max_len(b"AAAAAAAAAA" as &[u8], 1, 4, 8, false, vec![0..4, 4..8, 8..10])]
fn base64_span_behavior(
    #[case] hay: &[u8],
    #[case] min_chars: usize,
    #[case] max_len: usize,
    #[case] max_spans: usize,
    #[case] allow_space: bool,
    #[case] expected: Vec<std::ops::Range<usize>>,
) {
    let mut spans = Vec::new();
    find_base64_spans_into(hay, min_chars, max_len, max_spans, allow_space, &mut spans);
    assert_eq!(spans, expected);
}

#[test]
fn keyword_gate_filters_without_keyword() {
    const ANCHORS: &[&[u8]] = &[b"ANCH"];
    const KEYWORDS: &[&[u8]] = &[b"kw"];
    let rule = RuleSpec {
        radius: 16,
        keywords_any: Some(KEYWORDS),
        ..base_rule("keyword-gate", ANCHORS, Regex::new("secret").unwrap())
    };
    let eng = Engine::new_with_anchor_policy(
        vec![rule],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );

    let hay = b"ANCHsecret";
    let hits = scan_chunk_findings(&eng, hay);
    assert!(!hits.iter().any(|h| h.rule == "keyword-gate"));

    let hay = b"ANCHkwsecret";
    let hits = scan_chunk_findings(&eng, hay);
    assert!(hits.iter().any(|h| h.rule == "keyword-gate"));
}

#[test]
fn derived_confirm_all_is_compiled() {
    let rule = RuleSpec {
        radius: 16,
        ..base_rule("confirm-all", &[], Regex::new(r"foo\d+bar").unwrap())
    };

    let eng = Engine::new_with_anchor_policy(
        vec![rule],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::DerivedOnly,
    );

    let derive_cfg = AnchorDeriveConfig {
        utf8: false,
        ..AnchorDeriveConfig::default()
    };
    let expected = match compile_trigger_plan(r"foo\d+bar", &derive_cfg).unwrap() {
        TriggerPlan::Anchored { confirm_all, .. } => confirm_all,
        other => panic!("expected anchored plan, got {other:?}"),
    };

    let compiled = &eng.rules_hot[0];
    let compiled_confirm_idx = compiled.confirm_all;
    if expected.is_empty() {
        assert_eq!(
            compiled_confirm_idx,
            super::rule_repr::NO_GATE,
            "confirm_all should be omitted when no extra literals are required"
        );
    } else {
        assert_ne!(
            compiled_confirm_idx,
            super::rule_repr::NO_GATE,
            "confirm_all should be compiled"
        );
        let idx = compiled_confirm_idx;
        let confirm = &eng.confirm_all_gates[idx as usize];
        let primary = confirm.primary[Variant::Raw.idx()]
            .as_ref()
            .expect("confirm_all primary must be set");
        let mut literals = vec![primary.to_vec()];
        literals.extend(unpack_patterns(&confirm.rest[Variant::Raw.idx()]));

        let expected_set: HashSet<Vec<u8>> = expected.into_iter().collect();
        let actual_set: HashSet<Vec<u8>> = literals.into_iter().collect();
        assert_eq!(
            actual_set, expected_set,
            "confirm_all literals should match"
        );
    }

    let hay = b"zzzfoo123barzzz";
    let hits = scan_chunk_findings(&eng, hay);
    assert!(hits.iter().any(|h| h.rule == "confirm-all"));
}

#[test]
fn value_suppressor_gate_is_compiled_and_indexed() {
    const ANCHORS: &[&[u8]] = &[b"TOK_"];
    const SUPPRESSORS: &[&[u8]] = &[b"EXAMPLE", b"DUMMY_TOKEN"];
    let rule = RuleSpec {
        radius: 16,
        value_suppressors_any: Some(SUPPRESSORS),
        ..base_rule(
            "value-suppressor-gate",
            ANCHORS,
            Regex::new(r"TOK_[A-Za-z0-9]{8}").unwrap(),
        )
    };

    let eng = Engine::new_with_anchor_policy(
        vec![rule],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );

    let compiled = &eng.rules_hot[0];
    let idx = compiled.value_suppressors;
    assert_ne!(
        idx,
        super::rule_repr::NO_GATE,
        "value suppressor gate index should be populated"
    );
    let suppressor_gate = eng
        .value_suppressor_gate(idx)
        .expect("value suppressor gate should be accessible");
    assert!(
        std::ptr::eq(suppressor_gate, &eng.value_suppressor_gates[idx as usize]),
        "rule gate index should point to the pooled value suppressor gate"
    );
    assert_eq!(
        unpack_patterns(suppressor_gate),
        vec![b"EXAMPLE".to_vec(), b"DUMMY_TOKEN".to_vec()]
    );
    assert!(
        eng.value_suppressor_gate(super::rule_repr::NO_GATE)
            .is_none()
    );
}

#[test]
fn value_suppressor_filters_matching_secret_in_raw_path() {
    let rule = RuleSpec {
        value_suppressors_any: Some(&[b"EXAMPLE"]),
        secret_group: Some(1),
        ..base_rule(
            "value-suppressor-raw-filter",
            &[b"TOK_"],
            Regex::new(r"TOK_([A-Za-z0-9]{8,16})").unwrap(),
        )
    };

    let engine = Engine::new_with_anchor_policy(
        vec![rule],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );

    let hay = b"prefix TOK_AEXAMPLE9 suffix";
    let hits = scan_chunk_findings(&engine, hay);
    assert!(
        !hits.iter().any(|h| h.rule == "value-suppressor-raw-filter"),
        "expected matching suppressor to prevent emission"
    );
}

#[test]
fn value_suppressor_passes_non_matching_secret_in_raw_path() {
    let rule = RuleSpec {
        value_suppressors_any: Some(&[b"EXAMPLE"]),
        secret_group: Some(1),
        ..base_rule(
            "value-suppressor-raw-pass",
            &[b"TOK_"],
            Regex::new(r"TOK_([A-Za-z0-9]{8,16})").unwrap(),
        )
    };

    let engine = Engine::new_with_anchor_policy(
        vec![rule],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );

    let hay = b"prefix TOK_LIVEKEY12 suffix";
    let hits = scan_chunk_findings(&engine, hay);
    assert!(
        hits.iter().any(|h| h.rule == "value-suppressor-raw-pass"),
        "expected non-matching suppressor to allow emission"
    );
}

#[test]
fn value_suppressor_any_match_filters_with_multiple_patterns() {
    let rule = RuleSpec {
        value_suppressors_any: Some(&[b"DUMMY", b"EXAMPLE"]),
        secret_group: Some(1),
        ..base_rule(
            "value-suppressor-raw-multi",
            &[b"TOK_"],
            Regex::new(r"TOK_([A-Za-z0-9]{8,16})").unwrap(),
        )
    };

    let engine = Engine::new_with_anchor_policy(
        vec![rule],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );

    let hay = b"TOK_LIVEKEY12 TOK_ZDUMMY99";
    let hits = scan_chunk_findings(&engine, hay);
    let kept = hits
        .iter()
        .filter(|h| h.rule == "value-suppressor-raw-multi")
        .count();
    assert_eq!(
        kept, 1,
        "expected exactly one finding: non-suppressed secret should pass, suppressed secret should be filtered"
    );
}

#[test]
fn value_suppressor_absent_does_not_change_behavior() {
    let rule = RuleSpec {
        secret_group: Some(1),
        ..base_rule(
            "value-suppressor-none",
            &[b"TOK_"],
            Regex::new(r"TOK_([A-Za-z0-9]{8,16})").unwrap(),
        )
    };

    let engine = Engine::new_with_anchor_policy(
        vec![rule],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );

    let hay = b"prefix TOK_AEXAMPLE9 suffix";
    let hits = scan_chunk_findings(&engine, hay);
    assert!(
        hits.iter().any(|h| h.rule == "value-suppressor-none"),
        "expected finding when no suppressors are configured"
    );
}

#[test]
fn safelist_emit_time_filter_suppresses_root_finding() {
    let rule = RuleSpec {
        ..base_rule(
            "safelist-root-filter",
            &[b"token"],
            Regex::new(r"(?:placeholder_token|prod_token_[A-Z0-9]{6})").unwrap(),
        )
    };

    let engine = Engine::new_with_anchor_policy(
        vec![rule],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );

    let mut scratch = engine.new_scratch();
    let hay = b"placeholder_token prod_token_A1B2C3";
    engine.scan_chunk_into(hay, FileId(0), 0, &mut scratch);

    let recs = scratch.findings();
    assert_eq!(
        recs.len(),
        1,
        "expected emit-time safelist to suppress placeholder root finding"
    );
    assert_eq!(
        recs.len(),
        scratch.norm_hashes().len(),
        "norm_hash sidecar must stay aligned after emit-time suppression"
    );
    assert_eq!(
        recs.len(),
        scratch.drop_hint_end().len(),
        "drop_hint_end sidecar must stay aligned after emit-time suppression"
    );

    let rec = recs[0];
    assert_eq!(rec.step_id, STEP_ROOT, "remaining finding should be root");
    let span = rec.span_start as usize..rec.span_end as usize;
    assert_eq!(&hay[span], b"prod_token_A1B2C3");
    #[cfg(all(feature = "perf-stats", debug_assertions))]
    assert_eq!(
        scratch.safelist_suppressed(),
        1,
        "safelist_suppressed counter should track suppressed root findings"
    );
}

#[test]
fn safelist_emit_time_filter_keeps_non_root_findings() {
    // Use a value that matches the context safelist (pattern 0: placeholder+noun)
    // for the root finding, but whose decoded value does NOT match the
    // secret-bytes safelist (a realistic-looking token).
    let rule = RuleSpec {
        radius: 64,
        ..base_rule(
            "safelist-mixed-root-non-root",
            &[b"token"],
            Regex::new(r"(?:placeholder_token|prod_token_A1B2C3)").unwrap(),
        )
    };
    let transforms = vec![TransformConfig {
        id: TransformId::Base64,
        mode: TransformMode::Always,
        gate: Gate::AnchorsInDecoded,
        min_len: 8,
        max_spans_per_buffer: 8,
        max_encoded_len: 1024,
        max_decoded_bytes: 1024,
        plus_to_space: false,
        base64_allow_space_ws: false,
    }];

    let engine = Engine::new_with_anchor_policy(
        vec![rule],
        transforms,
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );

    let mut scratch = engine.new_scratch();
    // Root: "placeholder_token" matches context safelist → suppressed.
    // Base64: "cHJvZF90b2tlbl9BMUI..." decodes to "prod_token_A1B2C3" → NOT a
    //         placeholder, so the secret-bytes safelist does not suppress it.
    let hay = b"placeholder_token cHJvZF90b2tlbl9BMUIyQzM=";
    engine.scan_chunk_into(hay, FileId(0), 0, &mut scratch);

    let recs = scratch.findings();
    assert_eq!(
        recs.len(),
        1,
        "expected root finding suppression while preserving decoded non-root finding"
    );
    assert_ne!(
        recs[0].step_id, STEP_ROOT,
        "non-root findings must bypass context safelist suppression"
    );
    assert_eq!(
        recs.len(),
        scratch.norm_hashes().len(),
        "norm_hash sidecar must stay aligned after mixed compaction"
    );
    assert_eq!(
        recs.len(),
        scratch.drop_hint_end().len(),
        "drop_hint_end sidecar must stay aligned after mixed compaction"
    );
}

#[test]
fn safelist_emit_time_filter_does_not_suppress_utf16_root_emission() {
    // Use a non-placeholder value that matches neither the context safelist
    // nor the secret-bytes safelist, to verify UTF-16 root emissions bypass
    // the root-only context safelist path (they carry a Utf16Window step_id).
    let rule = RuleSpec {
        radius: 64,
        ..base_rule(
            "safelist-utf16-root-emission",
            &[b"prod_token_A1B2C3"],
            Regex::new(r"prod_token_A1B2C3").unwrap(),
        )
    };

    let mut tuning = demo_tuning();
    tuning.scan_utf16_variants = true;
    let engine =
        Engine::new_with_anchor_policy(vec![rule], Vec::new(), tuning, AnchorPolicy::ManualOnly);

    let mut scratch = engine.new_scratch();
    let hay = utf16le_bytes(b"prod_token_A1B2C3");
    engine.scan_chunk_into(&hay, FileId(0), 0, &mut scratch);

    let recs = scratch.findings();
    assert_eq!(
        recs.len(),
        1,
        "utf16 root emissions are tagged with decode steps and must bypass root-only safelist suppression"
    );
    assert_ne!(
        recs[0].step_id, STEP_ROOT,
        "utf16 finding from root input should have a utf16 decode step id"
    );
    #[cfg(all(feature = "perf-stats", debug_assertions))]
    assert_eq!(
        scratch.safelist_suppressed(),
        0,
        "root-only safelist suppression must not drop utf16 root emissions"
    );
}

#[test]
fn safelist_suppression_does_not_consume_findings_cap() {
    let rule = RuleSpec {
        radius: 128,
        ..base_rule(
            "safelist-cap-ordering",
            &[b"token"],
            Regex::new(r"(?:placeholder_token|prod_token_[A-Z0-9]{6})").unwrap(),
        )
    };

    let mut tuning = demo_tuning();
    tuning.max_findings_per_chunk = 2;

    let engine =
        Engine::new_with_anchor_policy(vec![rule], Vec::new(), tuning, AnchorPolicy::ManualOnly);

    let mut scratch = engine.new_scratch();
    let hay = b"placeholder_token placeholder_token placeholder_token prod_token_A1B2C3";
    engine.scan_chunk_into(hay, FileId(0), 0, &mut scratch);

    let recs = scratch.findings();
    assert_eq!(
        recs.len(),
        1,
        "safelisted roots should not consume finding capacity ahead of real findings"
    );
    let span = recs[0].span_start as usize..recs[0].span_end as usize;
    assert_eq!(&hay[span], b"prod_token_A1B2C3");
    assert_eq!(
        scratch.dropped_findings(),
        0,
        "suppressed safelist findings should not be counted as dropped findings"
    );
}

#[test]
fn max_findings_cap_applies_after_safelist_suppression() {
    let rule = RuleSpec {
        radius: 128,
        ..base_rule(
            "safelist-cap-emit-time-suppression",
            &[b"token"],
            Regex::new(r"(?:placeholder_token|prod_token_[A-Z0-9]{6})").unwrap(),
        )
    };

    let mut tuning = demo_tuning();
    tuning.max_findings_per_chunk = 2;

    let engine =
        Engine::new_with_anchor_policy(vec![rule], Vec::new(), tuning, AnchorPolicy::ManualOnly);

    let mut scratch = engine.new_scratch();
    let hay = b"placeholder_token prod_token_A1B2C3 prod_token_D4E5F6 prod_token_G7H8I9";
    engine.scan_chunk_into(hay, FileId(0), 0, &mut scratch);

    let recs = scratch.findings();
    assert_eq!(
        recs.len(),
        2,
        "cap should be enforced after emit-time safelist suppression"
    );
    let spans: Vec<&[u8]> = recs
        .iter()
        .map(|rec| &hay[rec.span_start as usize..rec.span_end as usize])
        .collect();
    assert_eq!(
        spans,
        vec![
            b"prod_token_A1B2C3".as_slice(),
            b"prod_token_D4E5F6".as_slice()
        ],
        "cap should trim only after placeholder suppression"
    );
    #[cfg(all(feature = "perf-stats", debug_assertions))]
    assert_eq!(
        scratch.safelist_suppressed(),
        1,
        "placeholder should be suppressed by safelist before cap truncation"
    );
    assert_eq!(
        scratch.dropped_findings(),
        1,
        "only findings above the cap should count as dropped"
    );
}

#[test]
fn safelist_emit_time_filter_noop_keeps_all_non_safelisted_roots() {
    let rule = RuleSpec {
        ..base_rule(
            "safelist-noop-root",
            &[b"prod_token_"],
            Regex::new(r"prod_token_[A-Z0-9]{6}").unwrap(),
        )
    };

    let engine = Engine::new_with_anchor_policy(
        vec![rule],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );

    let mut scratch = engine.new_scratch();
    let hay = b"prod_token_A1B2C3 prod_token_D4E5F6";
    engine.scan_chunk_into(hay, FileId(0), 0, &mut scratch);

    let recs = scratch.findings();
    assert_eq!(
        recs.len(),
        2,
        "non-safelisted roots should not be suppressed"
    );
    assert_eq!(
        recs.len(),
        scratch.norm_hashes().len(),
        "norm_hash sidecar must stay aligned on no-op emit-time path"
    );
    assert_eq!(
        recs.len(),
        scratch.drop_hint_end().len(),
        "drop_hint_end sidecar must stay aligned on no-op emit-time path"
    );
    for rec in recs {
        assert_eq!(rec.step_id, STEP_ROOT);
    }
    #[cfg(all(feature = "perf-stats", debug_assertions))]
    assert_eq!(
        scratch.safelist_suppressed(),
        0,
        "no-op path should not increment safelist_suppressed counter"
    );
}

#[test]
fn safelist_emit_time_filter_drops_tail_root_finding() {
    let rule = RuleSpec {
        radius: 64,
        ..base_rule(
            "safelist-tail-drop",
            &[b"token"],
            Regex::new(r"(?:prod_token_[A-Z0-9]{6}|placeholder_token)").unwrap(),
        )
    };

    let engine = Engine::new_with_anchor_policy(
        vec![rule],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );

    let mut scratch = engine.new_scratch();
    let hay = b"prod_token_A1B2C3 placeholder_token";
    engine.scan_chunk_into(hay, FileId(0), 0, &mut scratch);

    let recs = scratch.findings();
    assert_eq!(
        recs.len(),
        1,
        "tail safelisted finding should be removed while preserving earlier root finding"
    );
    let span = recs[0].span_start as usize..recs[0].span_end as usize;
    assert_eq!(&hay[span], b"prod_token_A1B2C3");
    assert_eq!(recs.len(), scratch.norm_hashes().len());
    assert_eq!(recs.len(), scratch.drop_hint_end().len());
    #[cfg(all(feature = "perf-stats", debug_assertions))]
    assert_eq!(
        scratch.safelist_suppressed(),
        1,
        "tail drop should increment safelist_suppressed counter"
    );
}

#[test]
fn safelist_emit_time_filter_suppresses_duplicate_root_spans_across_rules() {
    let rules = vec![
        RuleSpec {
            ..base_rule(
                "safelist-dup-a",
                &[b"placeholder_token"],
                Regex::new(r"placeholder_token").unwrap(),
            )
        },
        RuleSpec {
            ..base_rule(
                "safelist-dup-b",
                &[b"placeholder_token"],
                Regex::new(r"placeholder_token").unwrap(),
            )
        },
        RuleSpec {
            ..base_rule(
                "safelist-dup-keep",
                &[b"prod_token_"],
                Regex::new(r"prod_token_[A-Z0-9]{6}").unwrap(),
            )
        },
    ];

    let engine =
        Engine::new_with_anchor_policy(rules, Vec::new(), demo_tuning(), AnchorPolicy::ManualOnly);

    let mut scratch = engine.new_scratch();
    let hay = b"placeholder_token prod_token_A1B2C3";
    engine.scan_chunk_into(hay, FileId(0), 0, &mut scratch);

    let recs = scratch.findings();
    assert_eq!(
        recs.len(),
        1,
        "duplicate safelisted root spans across rules should all be suppressed"
    );
    let span = recs[0].span_start as usize..recs[0].span_end as usize;
    assert_eq!(&hay[span], b"prod_token_A1B2C3");
}

#[test]
fn safelist_emit_time_filter_all_findings_suppressed() {
    let rule = RuleSpec {
        ..base_rule(
            "safelist-all-suppressed",
            &[b"placeholder_token"],
            Regex::new(r"placeholder_token").unwrap(),
        )
    };

    let engine = Engine::new_with_anchor_policy(
        vec![rule],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );

    let mut scratch = engine.new_scratch();
    let hay = b"placeholder_token";
    engine.scan_chunk_into(hay, FileId(0), 0, &mut scratch);

    let recs = scratch.findings();
    assert_eq!(
        recs.len(),
        0,
        "all root findings matching safelist should be suppressed"
    );
    assert_eq!(recs.len(), scratch.norm_hashes().len());
    assert_eq!(recs.len(), scratch.drop_hint_end().len());
    #[cfg(all(feature = "perf-stats", debug_assertions))]
    assert!(
        scratch.safelist_suppressed() > 0,
        "safelist_suppressed counter must be non-zero when findings are suppressed"
    );
}

#[cfg(all(feature = "perf-stats", debug_assertions))]
#[test]
fn safelist_suppressed_counter_resets_between_scans() {
    let rule = RuleSpec {
        ..base_rule(
            "safelist-counter-reset",
            &[b"token"],
            Regex::new(r"(?:placeholder_token|prod_token_[A-Z0-9]{6})").unwrap(),
        )
    };

    let engine = Engine::new_with_anchor_policy(
        vec![rule],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );

    let mut scratch = engine.new_scratch();

    // First scan: one finding suppressed.
    let hay1 = b"placeholder_token prod_token_A1B2C3";
    engine.scan_chunk_into(hay1, FileId(0), 0, &mut scratch);
    assert_eq!(scratch.safelist_suppressed(), 1);

    // Second scan: no findings suppressed.
    let hay2 = b"prod_token_D4E5F6";
    engine.scan_chunk_into(hay2, FileId(1), 0, &mut scratch);
    assert_eq!(
        scratch.safelist_suppressed(),
        0,
        "safelist_suppressed counter should reset between scans"
    );
}

// ── Secret-bytes safelist integration tests ──────────────────────────────

#[test]
fn secret_bytes_safelist_suppresses_placeholder_when_context_is_clean() {
    // The secret value is "changeme" — a known metadata placeholder. The
    // context "header changeme trailer" has no `[:=]` prefix, so context-tier
    // pattern 5 (`[:=]\s*(?:changeme|...)`) does NOT fire. Only the
    // secret-bytes safelist pattern `(?i)\b(?:changeme|...)\b` suppresses this.
    let rule = RuleSpec {
        radius: 64,
        secret_group: Some(1),
        ..base_rule(
            "secret-bytes-clean-context",
            &[b"header"],
            Regex::new(r"header\s+(\S+)").unwrap(),
        )
    };

    let engine = Engine::new_with_anchor_policy(
        vec![rule],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );

    let mut scratch = engine.new_scratch();
    let hay = b"header changeme trailer";
    engine.scan_chunk_into(hay, FileId(0), 0, &mut scratch);

    assert_eq!(
        scratch.findings().len(),
        0,
        "secret-bytes safelist should suppress placeholder 'changeme' when context is clean"
    );
}

#[test]
fn secret_bytes_safelist_does_not_suppress_high_entropy_secret() {
    let rule = RuleSpec {
        secret_group: Some(1),
        ..base_rule(
            "secret-bytes-high-entropy",
            &[b"token"],
            Regex::new(r"token[:=]\s*(\S+)").unwrap(),
        )
    };

    let engine = Engine::new_with_anchor_policy(
        vec![rule],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );

    let mut scratch = engine.new_scratch();
    let hay = b"token=9f7A2kL8mN4qR1tV6xZ0cB3dF5gH7jK";
    engine.scan_chunk_into(hay, FileId(0), 0, &mut scratch);

    assert_eq!(
        scratch.findings().len(),
        1,
        "secret-bytes safelist must not suppress high-entropy secrets"
    );
}

#[test]
fn secret_bytes_safelist_suppresses_decoded_placeholder() {
    // Base64-encoded "hunter2" in a decoded buffer should still be suppressed
    // by the secret-bytes safelist.
    let rule = RuleSpec {
        ..base_rule(
            "secret-bytes-decoded",
            &[b"hunter2"],
            Regex::new(r"hunter2").unwrap(),
        )
    };
    let transforms = vec![TransformConfig {
        id: TransformId::Base64,
        mode: TransformMode::Always,
        gate: Gate::AnchorsInDecoded,
        min_len: 4,
        max_spans_per_buffer: 8,
        max_encoded_len: 1024,
        max_decoded_bytes: 1024,
        plus_to_space: false,
        base64_allow_space_ws: false,
    }];

    let engine = Engine::new_with_anchor_policy(
        vec![rule],
        transforms,
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );

    let mut scratch = engine.new_scratch();
    // "hunter2" base64-encoded = "aHVudGVyMg=="
    let hay = b"data aHVudGVyMg==";
    engine.scan_chunk_into(hay, FileId(0), 0, &mut scratch);

    assert_eq!(
        scratch.findings().len(),
        0,
        "decoded placeholder 'hunter2' should be suppressed by secret-bytes safelist"
    );
}

#[cfg(all(feature = "perf-stats", debug_assertions))]
#[test]
fn secret_bytes_safelist_counter_resets_between_scans() {
    // Use a context that does NOT trigger the context-window safelist (Tier 1)
    // so the finding reaches the secret-bytes safelist (Tier 2).
    // "changeme" matches secret-bytes pattern `(?i)\b(?:null|changeme|todo|fixme)\b`
    // but the context "header changeme trailer" has no `[:=]\s*` prefix, so
    // context pattern 5 `(?i)[:=]\s*(?:null|changeme|todo|fixme)\b` does not fire.
    let rule = RuleSpec {
        radius: 64,
        secret_group: Some(1),
        ..base_rule(
            "secret-bytes-counter-reset",
            &[b"header"],
            Regex::new(r"header\s+(\S+)").unwrap(),
        )
    };

    let engine = Engine::new_with_anchor_policy(
        vec![rule],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );

    let mut scratch = engine.new_scratch();

    // First scan: "changeme" suppressed by secret-bytes tier.
    let hay1 = b"header changeme trailer";
    engine.scan_chunk_into(hay1, FileId(0), 0, &mut scratch);
    assert!(
        scratch.secret_bytes_safelist_suppressed() > 0,
        "secret-bytes counter should be non-zero after suppression"
    );

    // Second scan: real secret, no suppression.
    let hay2 = b"header 9f7A2kL8mN4qR1tV6xZ0cB3dF5gH7jK trailer";
    engine.scan_chunk_into(hay2, FileId(1), 0, &mut scratch);
    assert_eq!(
        scratch.secret_bytes_safelist_suppressed(),
        0,
        "secret_bytes_safelist_suppressed counter should reset between scans"
    );
}

#[test]
fn secret_bytes_safelist_suppressed_findings_dont_consume_cap() {
    let mut tuning = demo_tuning();
    tuning.max_findings_per_chunk = 2;

    // Use "header <value>" format so the context has no `[:=]` prefix and
    // the context-tier safelist does NOT fire. Only the secret-bytes tier
    // suppresses "changeme".
    let rule = RuleSpec {
        radius: 128,
        secret_group: Some(1),
        ..base_rule(
            "secret-bytes-cap-ordering",
            &[b"header"],
            Regex::new(r"header\s+(\S+)").unwrap(),
        )
    };

    let engine =
        Engine::new_with_anchor_policy(vec![rule], Vec::new(), tuning, AnchorPolicy::ManualOnly);

    let mut scratch = engine.new_scratch();
    // Three values: placeholder, real1, real2. Cap is 2.
    // Placeholder should be suppressed by secret-bytes tier without consuming cap
    // → both real findings emitted.
    let hay = b"header changeme end header 9f7A2kL8mN end header 4qR1tV6xZ0 end";
    engine.scan_chunk_into(hay, FileId(0), 0, &mut scratch);

    assert_eq!(
        scratch.findings().len(),
        2,
        "suppressed placeholder must not consume findings cap"
    );
    assert_eq!(
        scratch.dropped_findings(),
        0,
        "no findings should be dropped since cap was not exhausted"
    );
}

#[test]
fn secret_bytes_suppression_does_not_block_child_transforms() {
    // Regression: when a finding in a decoded buffer is suppressed by the
    // secret-bytes safelist, `found_any` must NOT prevent child transforms
    // with `IfNoFindingsInThisBuffer` mode from running. The suppressed
    // finding was never emitted, so the buffer effectively has no findings
    // and child transforms should proceed.
    //
    // Setup: base64-encoded content containing:
    //   - A rule match with "hunter2" as the secret (safelist-suppressed)
    //   - A URL-percent-encoded real secret
    // The UrlPercent transform (IfNoFindingsInThisBuffer) should still run
    // and discover the real secret.
    let rule = RuleSpec {
        radius: 64,
        secret_group: Some(1),
        ..base_rule(
            "found-any-suppression",
            &[b"SECRET_"],
            Regex::new(r"SECRET_([A-Za-z0-9]+)").unwrap(),
        )
    };
    let transforms = vec![
        TransformConfig {
            id: TransformId::UrlPercent,
            mode: TransformMode::IfNoFindingsInThisBuffer,
            gate: Gate::AnchorsInDecoded,
            min_len: 16,
            max_spans_per_buffer: 8,
            max_encoded_len: 4096,
            max_decoded_bytes: 4096,
            plus_to_space: false,
            base64_allow_space_ws: false,
        },
        TransformConfig {
            id: TransformId::Base64,
            mode: TransformMode::Always,
            gate: Gate::AnchorsInDecoded,
            min_len: 8,
            max_spans_per_buffer: 8,
            max_encoded_len: 4096,
            max_decoded_bytes: 4096,
            plus_to_space: false,
            base64_allow_space_ws: false,
        },
    ];

    let mut tuning = demo_tuning();
    tuning.max_transform_depth = 3;

    let engine =
        Engine::new_with_anchor_policy(vec![rule], transforms, tuning, AnchorPolicy::ManualOnly);

    // Base64-encode content that has a safelist-suppressed match AND a URL-encoded real secret.
    // Decoded base64: "key SECRET_hunter2 urldata %53%45%43%52%45%54%5F%58%6B%39%70%51%6D end"
    // URL-decoded portion: "SECRET_Xk9pQm"
    let inner_plain = b"key SECRET_hunter2 urldata %53%45%43%52%45%54%5F%58%6B%39%70%51%6D end";
    let b64 = b64_encode(inner_plain);
    let hay = format!("noise {b64}");
    let hits = scan_chunk_findings(&engine, hay.as_bytes());

    // The "hunter2" finding should be suppressed.
    // The "Xk9pQm" finding from the URL-decoded layer should be emitted.
    assert!(
        hits.iter().any(|h| {
            h.rule == "found-any-suppression"
                && h.decode_steps
                    .iter()
                    .any(|s| matches!(s, DecodeStep::Transform { transform_idx, .. } if *transform_idx == 0))
        }),
        "URL-decoded real secret should be found — IfNoFindingsInThisBuffer \
         must not be blocked by safelist-suppressed findings.\n\
         Found {} findings: {:?}",
        hits.len(),
        hits.iter()
            .map(|h| (&h.rule, &h.decode_steps))
            .collect::<Vec<_>>()
    );
}

#[test]
fn confidence_suppression_does_not_block_child_transforms() {
    // Mirrors `secret_bytes_suppression_does_not_block_child_transforms` but
    // uses confidence-threshold suppression instead of safelist suppression.
    //
    // Two rules, both match in base64-decoded content:
    //   Rule A ("conf-suppressed"): matches SECRET_*, min_confidence=5, no keyword gate
    //     → scores 0 → suppressed. Must NOT set found_any.
    //   Rule B ("conf-passthrough"): matches TOKEN_*, no min_confidence
    //     → discovered in the URL-percent-decoded child buffer.
    //
    // The UrlPercent transform (IfNoFindingsInThisBuffer) should run because
    // Rule A's suppressed finding never set found_any.
    let rule_a = RuleSpec {
        radius: 64,
        secret_group: Some(1),
        min_confidence: Some(5),
        ..base_rule(
            "conf-suppressed",
            &[b"SECRET_"],
            Regex::new(r"SECRET_([A-Za-z0-9]+)").unwrap(),
        )
    };
    let rule_b = RuleSpec {
        radius: 64,
        secret_group: Some(1),
        ..base_rule(
            "conf-passthrough",
            &[b"TOKEN_"],
            Regex::new(r"TOKEN_([A-Za-z0-9]+)").unwrap(),
        )
    };
    let transforms = vec![
        TransformConfig {
            id: TransformId::UrlPercent,
            mode: TransformMode::IfNoFindingsInThisBuffer,
            gate: Gate::AnchorsInDecoded,
            min_len: 16,
            max_spans_per_buffer: 8,
            max_encoded_len: 4096,
            max_decoded_bytes: 4096,
            plus_to_space: false,
            base64_allow_space_ws: false,
        },
        TransformConfig {
            id: TransformId::Base64,
            mode: TransformMode::Always,
            gate: Gate::AnchorsInDecoded,
            min_len: 8,
            max_spans_per_buffer: 8,
            max_encoded_len: 4096,
            max_decoded_bytes: 4096,
            plus_to_space: false,
            base64_allow_space_ws: false,
        },
    ];

    let mut tuning = demo_tuning();
    tuning.max_transform_depth = 3;

    let engine = Engine::new_with_anchor_policy(
        vec![rule_a, rule_b],
        transforms,
        tuning,
        AnchorPolicy::ManualOnly,
    );

    // Base64-encode content with a confidence-suppressed match (Rule A) and a
    // URL-encoded real secret for Rule B.
    // Decoded base64: "key SECRET_PlainLow urldata %54%4F%4B%45%4E%5F%58%6B%39%70%51%6D end"
    //   - "SECRET_PlainLow" → Rule A, scores 0, suppressed by min_confidence=5
    //   - URL-decoded: "TOKEN_Xk9pQm" → Rule B, no threshold, emitted
    let inner_plain = b"key SECRET_PlainLow urldata %54%4F%4B%45%4E%5F%58%6B%39%70%51%6D end";
    let b64 = b64_encode(inner_plain);
    let hay = format!("noise {b64}");
    let hits = scan_chunk_findings(&engine, hay.as_bytes());

    // Rule A's finding is suppressed by confidence threshold.
    // Rule B's finding from the URL-decoded layer should be emitted via the
    // IfNoFindingsInThisBuffer transform (transform_idx 0).
    assert!(
        hits.iter().any(|h| {
            h.rule == "conf-passthrough"
                && h.decode_steps
                    .iter()
                    .any(|s| matches!(s, DecodeStep::Transform { transform_idx, .. } if *transform_idx == 0))
        }),
        "URL-decoded real secret should be found — IfNoFindingsInThisBuffer \
         must not be blocked by confidence-suppressed findings.\n\
         Found {} findings: {:?}",
        hits.len(),
        hits.iter()
            .map(|h| (&h.rule, &h.decode_steps))
            .collect::<Vec<_>>()
    );
}

#[test]
fn secret_bytes_safelist_does_not_suppress_composite_secret_with_placeholder_segment() {
    // Regression: composite secrets like "key-null-safety-9xK2mB" must not be
    // suppressed. Before the \b → ^...$ anchoring fix, the `\b(?:null|...)\b`
    // pattern would match "null" at the hyphen-delimited segment boundary.
    let rule = RuleSpec {
        radius: 64,
        secret_group: Some(1),
        ..base_rule(
            "secret-bytes-composite",
            &[b"SECRET_"],
            Regex::new(r"SECRET_([A-Za-z0-9._-]+)").unwrap(),
        )
    };

    let engine = Engine::new_with_anchor_policy(
        vec![rule],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );

    let mut scratch = engine.new_scratch();
    let hay = b"config SECRET_key-null-safety-9xK2mB end";
    engine.scan_chunk_into(hay, FileId(0), 0, &mut scratch);

    assert_eq!(
        scratch.findings().len(),
        1,
        "composite secret with 'null' segment must NOT be suppressed by secret-bytes safelist"
    );
}

#[test]
fn value_suppressor_applies_in_base64_stream_decode_raw_path() {
    let rule = RuleSpec {
        value_suppressors_any: Some(&[b"ABCD"]),
        secret_group: Some(1),
        ..base_rule(
            "value-suppressor-b64-raw",
            &[b"SECRET_"],
            Regex::new(r"SECRET_([A-Z]{4})").unwrap(),
        )
    };
    let transforms = vec![TransformConfig {
        id: TransformId::Base64,
        mode: TransformMode::Always,
        gate: Gate::AnchorsInDecoded,
        min_len: 8,
        max_spans_per_buffer: 8,
        max_encoded_len: 1024,
        max_decoded_bytes: 1024,
        plus_to_space: false,
        base64_allow_space_ws: false,
    }];

    let engine = Engine::new_with_anchor_policy(
        vec![rule],
        transforms,
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );

    let suppressed_hay = b64_encode(b"prefix SECRET_ABCD suffix");
    let suppressed_hits = scan_chunk_findings(&engine, suppressed_hay.as_bytes());
    assert!(
        !suppressed_hits
            .iter()
            .any(|h| h.rule == "value-suppressor-b64-raw"),
        "expected suppressor to filter match in decoded base64 stream"
    );

    let kept_hay = b64_encode(b"prefix SECRET_WXYZ suffix");
    let kept_hits = scan_chunk_findings(&engine, kept_hay.as_bytes());
    assert!(
        kept_hits
            .iter()
            .any(|h| h.rule == "value-suppressor-b64-raw"),
        "expected non-suppressed secret to emit in decoded base64 stream"
    );
}

#[test]
fn value_suppressor_applies_in_base64_stream_decode_utf16_path() {
    let with_suppressor = RuleSpec {
        radius: 0,
        value_suppressors_any: Some(&[b"TOK"]),
        secret_group: Some(0),
        ..base_rule(
            "value-suppressor-b64-utf16",
            &[b"TOK"],
            Regex::new("TOK").unwrap(),
        )
    };
    let without_suppressor = RuleSpec {
        value_suppressors_any: None,
        ..with_suppressor.clone()
    };
    let tc = TransformConfig {
        id: TransformId::Base64,
        mode: TransformMode::Always,
        gate: Gate::AnchorsInDecoded,
        min_len: 8,
        max_spans_per_buffer: 8,
        max_encoded_len: 8 * 1024,
        max_decoded_bytes: 8 * 1024,
        plus_to_space: false,
        base64_allow_space_ws: false,
    };

    let mut tuning = demo_tuning();
    tuning.scan_utf16_variants = true;
    tuning.max_total_decode_output_bytes = tuning.max_total_decode_output_bytes.max(8 * 1024);

    let engine_with_suppressor = Engine::new_with_anchor_policy(
        vec![with_suppressor],
        vec![tc.clone()],
        tuning.clone(),
        AnchorPolicy::ManualOnly,
    );
    let engine_without_suppressor = Engine::new_with_anchor_policy(
        vec![without_suppressor],
        vec![tc],
        tuning,
        AnchorPolicy::ManualOnly,
    );

    let encoded_utf16 = b64_encode(&utf16be_bytes(b"TOK"));
    let suppressed_hits = scan_chunk_findings(&engine_with_suppressor, encoded_utf16.as_bytes());
    assert!(
        !suppressed_hits
            .iter()
            .any(|h| h.rule == "value-suppressor-b64-utf16"),
        "expected suppressor to filter UTF-16 decoded match"
    );

    let unsuppressed_hits =
        scan_chunk_findings(&engine_without_suppressor, encoded_utf16.as_bytes());
    assert!(
        unsuppressed_hits
            .iter()
            .any(|h| h.rule == "value-suppressor-b64-utf16"),
        "expected UTF-16 decoded match when suppressors are not configured"
    );
}

#[test]
fn value_suppressor_filters_in_chunked_scan_path() {
    let rule = RuleSpec {
        value_suppressors_any: Some(&[b"EXAMPLE"]),
        secret_group: Some(1),
        ..base_rule(
            "value-suppressor-chunked",
            &[b"TOK_"],
            Regex::new(r"TOK_([A-Za-z0-9]{8,16})").unwrap(),
        )
    };

    let engine = Engine::new_with_anchor_policy(
        vec![rule],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );

    // Two secrets: one suppressed, one not.
    let hay = b"prefix TOK_AEXAMPLE9 middle TOK_LIVEKEY12 suffix";
    let hits = scan_in_chunks(&engine, hay, 32);
    let names: Vec<&str> = hits
        .iter()
        .filter(|r| r.rule_id == 0)
        .map(|_| "value-suppressor-chunked")
        .collect();
    assert_eq!(
        names.len(),
        1,
        "chunked scan: expected exactly one finding (suppressed secret filtered, live secret kept)"
    );
}

#[test]
fn value_suppressor_is_case_sensitive() {
    let rule = RuleSpec {
        value_suppressors_any: Some(&[b"example"]),
        secret_group: Some(1),
        ..base_rule(
            "value-suppressor-case",
            &[b"TOK_"],
            Regex::new(r"TOK_([A-Za-z0-9]{8,16})").unwrap(),
        )
    };

    let engine = Engine::new_with_anchor_policy(
        vec![rule],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );

    // Secret contains "EXAMPLE" (uppercase) but suppressor is "example" (lowercase).
    // Case-sensitive matching means the finding should NOT be suppressed.
    let hay = b"prefix TOK_AEXAMPLE9 suffix";
    let hits = scan_chunk_findings(&engine, hay);
    assert!(
        hits.iter().any(|h| h.rule == "value-suppressor-case"),
        "case-sensitive suppressor should not match different-case secret"
    );
}

#[test]
fn value_suppressor_works_with_full_match_fallback() {
    // No capture groups → secret_group: None falls back to the full match.
    let rule = RuleSpec {
        value_suppressors_any: Some(&[b"TOK_AAAABBBB"]),
        ..base_rule(
            "value-suppressor-full-match",
            &[b"TOK_"],
            Regex::new(r"TOK_[A-Z]{8}").unwrap(),
        )
    };

    let engine = Engine::new_with_anchor_policy(
        vec![rule],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );

    // This secret matches the suppressor exactly.
    let hay_suppressed = b"prefix TOK_AAAABBBB suffix";
    let hits = scan_chunk_findings(&engine, hay_suppressed);
    assert!(
        !hits.iter().any(|h| h.rule == "value-suppressor-full-match"),
        "suppressor should filter full-match secret"
    );

    // This secret does NOT match the suppressor.
    let hay_pass = b"prefix TOK_CCCCDDDD suffix";
    let hits = scan_chunk_findings(&engine, hay_pass);
    assert!(
        hits.iter().any(|h| h.rule == "value-suppressor-full-match"),
        "non-matching full-match secret should pass"
    );
}

#[test]
fn value_suppressor_single_byte_pattern() {
    let rule = RuleSpec {
        value_suppressors_any: Some(&[b"X"]),
        secret_group: Some(1),
        ..base_rule(
            "value-suppressor-single-byte",
            &[b"TOK_"],
            Regex::new(r"TOK_([A-Za-z0-9]{8,16})").unwrap(),
        )
    };

    let engine = Engine::new_with_anchor_policy(
        vec![rule],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );

    // Secret contains 'X' → should be suppressed.
    let hay_with_x = b"prefix TOK_ABCDXFGH suffix";
    let hits = scan_chunk_findings(&engine, hay_with_x);
    assert!(
        !hits
            .iter()
            .any(|h| h.rule == "value-suppressor-single-byte"),
        "single-byte suppressor should match and filter"
    );

    // Secret has no 'X' → should pass.
    let hay_no_x = b"prefix TOK_ABCDEFGH suffix";
    let hits = scan_chunk_findings(&engine, hay_no_x);
    assert!(
        hits.iter()
            .any(|h| h.rule == "value-suppressor-single-byte"),
        "single-byte suppressor should not match when absent"
    );
}

#[test]
fn value_suppressor_targets_secret_group_not_full_match() {
    // The suppressor must be checked against the *secret group* span, not the full regex
    // match. Here group 1 = the part after "KEY_", so suppressor "KEY_" should only match
    // if the captured group itself contains "KEY_".
    let rule = RuleSpec {
        value_suppressors_any: Some(&[b"KEY_"]),
        secret_group: Some(1),
        ..base_rule(
            "vs-group-target",
            &[b"KEY_"],
            Regex::new(r"KEY_([A-Za-z0-9]{8,16})").unwrap(),
        )
    };

    let engine = Engine::new_with_anchor_policy(
        vec![rule],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );

    // Group 1 = "LIVEABCDEF" — does NOT contain "KEY_", so finding should be emitted.
    let hay_pass = b"prefix KEY_LIVEABCDEF suffix";
    let hits = scan_chunk_findings(&engine, hay_pass);
    assert!(
        hits.iter().any(|h| h.rule == "vs-group-target"),
        "suppressor 'KEY_' should not match group 1 'LIVEABCDEF'"
    );

    // Group 1 = "AKEY_BCDEFG" — DOES contain "KEY_", so finding should be suppressed.
    let hay_suppress = b"prefix KEY_AKEY_BCDEFG suffix";
    let hits = scan_chunk_findings(&engine, hay_suppress);
    assert!(
        !hits.iter().any(|h| h.rule == "vs-group-target"),
        "suppressor 'KEY_' should match group 1 'AKEY_BCDEFG' and suppress"
    );
}

#[test]
fn value_suppressor_is_substring_match_not_exact() {
    // Verify that suppressor matching is substring-based: the suppressor pattern must be
    // found anywhere in the secret span, not requiring an exact match.
    let rule = RuleSpec {
        value_suppressors_any: Some(&[b"ABC"]),
        secret_group: Some(1),
        ..base_rule(
            "vs-substring",
            &[b"TOK_"],
            Regex::new(r"TOK_([A-Za-z0-9]{8})").unwrap(),
        )
    };

    let engine = Engine::new_with_anchor_policy(
        vec![rule],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );

    // Prefix match: "ABCDEFGH" — suppressed.
    let hits = scan_chunk_findings(&engine, b"TOK_ABCDEFGH");
    assert!(
        !hits.iter().any(|h| h.rule == "vs-substring"),
        "suppressor 'ABC' at prefix should suppress"
    );

    // Interior match: "XABCYZ12" — suppressed.
    let hits = scan_chunk_findings(&engine, b"TOK_XABCYZ12");
    assert!(
        !hits.iter().any(|h| h.rule == "vs-substring"),
        "suppressor 'ABC' in interior should suppress"
    );

    // Suffix match: "12345ABC" — suppressed.
    let hits = scan_chunk_findings(&engine, b"TOK_12345ABC");
    assert!(
        !hits.iter().any(|h| h.rule == "vs-substring"),
        "suppressor 'ABC' at suffix should suppress"
    );

    // No match: "XYZWVUQP" — emitted.
    let hits = scan_chunk_findings(&engine, b"TOK_XYZWVUQP");
    assert!(
        hits.iter().any(|h| h.rule == "vs-substring"),
        "suppressor 'ABC' absent from secret should not suppress"
    );
}

#[test]
fn value_suppressor_with_entropy_and_local_context_combined() {
    // Rule with all three post-regex gates active: entropy, suppressor, and local context.
    // Each vector tests a different gate filtering independently.
    let rule = RuleSpec {
        radius: 64,
        value_suppressors_any: Some(&[b"EXAMPLE"]),
        entropy: Some(EntropySpec {
            min_bits_per_byte: 3.0,
            min_len: 8,
            max_len: 32,
            min_entropy_bits_per_byte: None,
            digit_penalty: false,
        }),
        local_context: Some(LocalContextSpec {
            lookbehind: 64,
            lookahead: 64,
            require_same_line_assignment: true,
            require_quoted: false,
            key_names_any: None,
        }),
        secret_group: Some(1),
        ..base_rule(
            "vs-triple-gate",
            &[b"KEY="],
            Regex::new(r"KEY=([A-Za-z0-9]{8,16})").unwrap(),
        )
    };

    let engine = Engine::new_with_anchor_policy(
        vec![rule],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );

    // (1) All gates pass: high-entropy secret, assignment present, no suppressor match → emitted.
    let hits = scan_chunk_findings(&engine, b"api KEY=a8f2k9x7m4 tail");
    assert!(
        hits.iter().any(|h| h.rule == "vs-triple-gate"),
        "all gates pass → finding should be emitted"
    );

    // (2) Entropy gate rejects: low-entropy secret.
    let hits = scan_chunk_findings(&engine, b"api KEY=AAAAAAAA tail");
    assert!(
        !hits.iter().any(|h| h.rule == "vs-triple-gate"),
        "low entropy should filter the finding"
    );

    // (3) Suppressor gate rejects: secret contains "EXAMPLE".
    let hits = scan_chunk_findings(&engine, b"api KEY=aEXAMPLEz9 tail");
    assert!(
        !hits.iter().any(|h| h.rule == "vs-triple-gate"),
        "suppressor match should filter the finding"
    );

    // (4) Local-context gate rejects: no assignment on same line (secret on a new line).
    let hits = scan_chunk_findings(&engine, b"something\nKEY=a8f2k9x7m4 tail");
    assert!(
        hits.iter().any(|h| h.rule == "vs-triple-gate"),
        "assignment is present on the same line after newline prefix"
    );
}

#[test]
fn value_suppressor_direct_utf16_window() {
    // Encode a secret directly as UTF-16BE bytes (not via base64) and verify
    // suppression works through the `run_rule_on_utf16_window_aligned` path.
    let rule = RuleSpec {
        radius: 0,
        value_suppressors_any: Some(&[b"TOK"]),
        secret_group: Some(0),
        ..base_rule("vs-direct-utf16", &[b"TOK"], Regex::new("TOK").unwrap())
    };

    let mut tuning = demo_tuning();
    tuning.scan_utf16_variants = true;

    let engine_suppress = Engine::new_with_anchor_policy(
        vec![rule.clone()],
        Vec::new(),
        tuning.clone(),
        AnchorPolicy::ManualOnly,
    );
    let engine_pass = Engine::new_with_anchor_policy(
        vec![RuleSpec {
            value_suppressors_any: None,
            ..rule
        }],
        Vec::new(),
        tuning,
        AnchorPolicy::ManualOnly,
    );

    // Raw UTF-16BE encoding of "TOK" (each ASCII char zero-extended to 2 bytes).
    let utf16_hay = utf16be_bytes(b"TOK");

    let hits_suppress = scan_chunk_findings(&engine_suppress, &utf16_hay);
    assert!(
        !hits_suppress.iter().any(|h| h.rule == "vs-direct-utf16"),
        "suppressor should filter match in direct UTF-16 path"
    );

    let hits_pass = scan_chunk_findings(&engine_pass, &utf16_hay);
    assert!(
        hits_pass.iter().any(|h| h.rule == "vs-direct-utf16"),
        "without suppressor, direct UTF-16 match should be emitted"
    );
}

#[test]
fn multiple_rules_different_suppressors_are_independent() {
    // Two rules with different suppressors: verify no cross-contamination.
    let rule_a = RuleSpec {
        value_suppressors_any: Some(&[b"FOO"]),
        secret_group: Some(1),
        ..base_rule(
            "rule-a",
            &[b"AA_"],
            Regex::new(r"AA_([A-Za-z0-9]{8})").unwrap(),
        )
    };
    let rule_b = RuleSpec {
        value_suppressors_any: Some(&[b"BAR"]),
        secret_group: Some(1),
        ..base_rule(
            "rule-b",
            &[b"BB_"],
            Regex::new(r"BB_([A-Za-z0-9]{8})").unwrap(),
        )
    };

    let engine = Engine::new_with_anchor_policy(
        vec![rule_a, rule_b],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );

    // Rule A's secret contains "BAR" (Rule B's suppressor) — Rule A should NOT be suppressed.
    // Rule B's secret contains "FOO" (Rule A's suppressor) — Rule B should NOT be suppressed.
    let hay = b"AA_xBARyz12 BB_aFOObcd3";
    let hits = scan_chunk_findings(&engine, hay);
    assert!(
        hits.iter().any(|h| h.rule == "rule-a"),
        "Rule B's suppressor 'BAR' must not suppress Rule A"
    );
    assert!(
        hits.iter().any(|h| h.rule == "rule-b"),
        "Rule A's suppressor 'FOO' must not suppress Rule B"
    );

    // Now test that each rule's own suppressor DOES work.
    let hay2 = b"AA_xFOOyz12 BB_aBAR1cd3";
    let hits2 = scan_chunk_findings(&engine, hay2);
    assert!(
        !hits2.iter().any(|h| h.rule == "rule-a"),
        "Rule A's own suppressor 'FOO' should suppress Rule A"
    );
    assert!(
        !hits2.iter().any(|h| h.rule == "rule-b"),
        "Rule B's own suppressor 'BAR' should suppress Rule B"
    );
}

#[test]
fn value_suppressor_with_explicit_secret_group_0() {
    // Same pattern as `value_suppressor_works_with_full_match_fallback` but with
    // `secret_group: Some(0)` explicitly set. Verifies that the explicit group 0
    // path in `extract_secret_span_locs` behaves identically to the None fallback.
    let rule = RuleSpec {
        value_suppressors_any: Some(&[b"TOK_AAAABBBB"]),
        secret_group: Some(0),
        ..base_rule(
            "vs-explicit-group0",
            &[b"TOK_"],
            Regex::new(r"TOK_[A-Z]{8}").unwrap(),
        )
    };

    let engine = Engine::new_with_anchor_policy(
        vec![rule],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );

    // Suppressor matches the full match → should be suppressed.
    let hay_suppress = b"prefix TOK_AAAABBBB suffix";
    let hits = scan_chunk_findings(&engine, hay_suppress);
    assert!(
        !hits.iter().any(|h| h.rule == "vs-explicit-group0"),
        "explicit group 0: suppressor should filter full-match secret"
    );

    // Secret doesn't match suppressor → should pass.
    let hay_pass = b"prefix TOK_CCCCDDDD suffix";
    let hits = scan_chunk_findings(&engine, hay_pass);
    assert!(
        hits.iter().any(|h| h.rule == "vs-explicit-group0"),
        "explicit group 0: non-matching secret should pass"
    );
}

#[test]
fn entropy_gate_filters_low_entropy_matches() {
    const ANCHORS: &[&[u8]] = &[b"TOK_"];
    let rule = RuleSpec {
        radius: 8,
        entropy: Some(EntropySpec {
            min_bits_per_byte: 3.0,
            min_len: 8,
            max_len: 32,
            min_entropy_bits_per_byte: None,
            digit_penalty: false,
        }),
        ..base_rule(
            "entropy-gate",
            ANCHORS,
            Regex::new(r"TOK_[A-Za-z0-9]{8}").unwrap(),
        )
    };
    let eng = Engine::new_with_anchor_policy(
        vec![rule],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );

    let low = b"TOK_AAAAAAAA";
    let hits = scan_chunk_findings(&eng, low);
    assert!(!hits.iter().any(|h| h.rule == "entropy-gate"));

    let high = b"TOK_A1b2C3d4";
    let hits = scan_chunk_findings(&eng, high);
    assert!(hits.iter().any(|h| h.rule == "entropy-gate"));
}

/// Verify that the entropy gate is evaluated on the *extracted secret*
/// (via `secret_group`) rather than on the full regex match.
///
/// Two sub-cases exercise both sides of the distinction:
///   (a) Full match has high entropy but the captured secret is all-X → reject.
///   (b) Full match has low entropy (dominated by repeated A) but the captured
///       secret is high-entropy alphanumeric → accept.
///
/// Both cases would produce wrong results if entropy were evaluated on the
/// full match instead of the extracted secret.
#[test]
fn entropy_gate_evaluated_on_extracted_secret() {
    let entropy = Some(EntropySpec {
        min_bits_per_byte: 2.5,
        min_len: 4,
        max_len: 64,
        min_entropy_bits_per_byte: None,
        digit_penalty: false,
    });

    // --- (a) Reject: full match high entropy, secret zero entropy ----------
    const ANCHORS_A: &[&[u8]] = &[b"pfx_"];
    let rule_reject = RuleSpec {
        radius: 40,
        entropy: entropy.clone(),
        secret_group: Some(1),
        ..base_rule(
            "ent-on-secret-reject",
            ANCHORS_A,
            Regex::new(r"pfx_[a-z0-9]{8}:([X]{8})").unwrap(),
        )
    };

    // --- (b) Accept: full match low entropy, secret high entropy -----------
    const ANCHORS_B: &[&[u8]] = &[b"REP_"];
    let rule_accept = RuleSpec {
        radius: 40,
        entropy: entropy.clone(),
        secret_group: Some(1),
        ..base_rule(
            "ent-on-secret-accept",
            ANCHORS_B,
            Regex::new(r"REP_[A]{20}_([a-z0-9]{8})").unwrap(),
        )
    };

    let eng = Engine::new_with_anchor_policy(
        vec![rule_reject, rule_accept],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );

    // (a) Full match "pfx_a1b2c3d4:XXXXXXXX" (~3.2 bits/byte) passes 2.5,
    //     but secret "XXXXXXXX" (0 bits/byte) fails → no finding.
    let hay_reject = b"pfx_a1b2c3d4:XXXXXXXX";
    let hits = scan_chunk_findings(&eng, hay_reject);
    assert!(
        !hits.iter().any(|h| h.rule == "ent-on-secret-reject"),
        "entropy evaluated on extracted secret should reject zero-entropy secret \
         even when full match has high entropy"
    );

    // (b) Full match "REP_AAAA…_x7k9m2p4" (below 2.5 bits/byte) fails 2.5,
    //     but secret "x7k9m2p4" (3.0 bits/byte) passes → finding emitted.
    let hay_accept = b"REP_AAAAAAAAAAAAAAAAAAAA_x7k9m2p4";
    let hits = scan_chunk_findings(&eng, hay_accept);
    assert!(
        hits.iter().any(|h| h.rule == "ent-on-secret-accept"),
        "entropy evaluated on extracted secret should accept high-entropy secret \
         even when full match has low entropy"
    );
}

#[test]
fn offline_validation_gate_pooled_round_trip() {
    const ANCHORS: &[&[u8]] = &[b"TOK_"];
    let rule_with = RuleSpec {
        offline_validation: Some(OfflineValidationSpec::GithubFinegrainedPat),
        ..base_rule("with-ov", ANCHORS, Regex::new(r"TOK_[A-Z0-9]{4}").unwrap())
    };
    let rule_without = RuleSpec {
        ..base_rule(
            "without-ov",
            ANCHORS,
            Regex::new(r"TOK_[A-Z0-9]{4}").unwrap(),
        )
    };

    let engine = Engine::new_with_anchor_policy(
        vec![rule_with, rule_without],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );

    // Rule 0 should have offline_validation index 0.
    assert_eq!(engine.rules_hot[0].offline_validation, 0);
    assert_eq!(
        engine.offline_validation_gates[0],
        OfflineValidationSpec::GithubFinegrainedPat,
    );

    // Rule 1 should have no offline_validation gate.
    assert_eq!(
        engine.rules_hot[1].offline_validation,
        super::rule_repr::NO_GATE
    );
}

// --------------------------
// Offline validation end-to-end tests
// --------------------------
//
// These tests verify emit-time offline validation ordering:
// engine scan → safelist (step-root only) → offline validation (root-semantic)
// → finding suppression / retention.

/// Build a `pfx_<payload><base62(crc32(payload))>` token.
fn build_crc32_base62_token(payload: &[u8]) -> Vec<u8> {
    let crc = crc32fast::hash(payload);
    let mut checksum = [0u8; 6];
    // Inline base62 encode matching offline_validate's format.
    {
        let chars: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        let mut v = crc;
        for slot in checksum.iter_mut().rev() {
            *slot = chars[(v % 62) as usize];
            v /= 62;
        }
    }
    let mut tok = Vec::with_capacity(4 + payload.len() + 6);
    tok.extend_from_slice(b"pfx_");
    tok.extend_from_slice(payload);
    tok.extend_from_slice(&checksum);
    tok
}

/// Helper: build a `RuleSpec` that matches `pfx_<alnum>{16}` with optional offline
/// validation using `Crc32Base62 { prefix_skip: 4, payload_len: 10, checksum_len: 6 }`.
fn crc32_rule(name: &'static str, with_ov: bool) -> RuleSpec {
    const ANCHORS: &[&[u8]] = &[b"pfx_"];
    RuleSpec {
        name,
        anchors: ANCHORS,
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
        offline_validation: if with_ov {
            Some(OfflineValidationSpec::Crc32Base62 {
                prefix_skip: 4,
                payload_len: 10,
                checksum_len: 6,
            })
        } else {
            None
        },
        uuid_format_secret: false,
        re: Regex::new(r"pfx_[A-Za-z0-9]{16}").unwrap(),
    }
}

#[test]
fn offline_validation_suppresses_invalid_crc_token() {
    let rule = crc32_rule("ov-crc", true);
    let engine = Engine::new_with_anchor_policy(
        vec![rule],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );

    // Token with a WRONG checksum — should be suppressed.
    let bad_token = b"pfx_ABCDEFGHIJ000000";
    let hay = [b"prefix " as &[u8], bad_token, b" suffix"].concat();
    let hits = scan_chunk_findings(&engine, &hay);
    assert!(
        !hits.iter().any(|h| h.rule == "ov-crc"),
        "finding with invalid CRC should be suppressed by offline validation"
    );
}

#[test]
fn offline_validation_keeps_valid_crc_token() {
    let rule = crc32_rule("ov-crc", true);
    let engine = Engine::new_with_anchor_policy(
        vec![rule],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );

    // Token with a CORRECT checksum — should survive.
    let good_token = build_crc32_base62_token(b"ABCDEFGHIJ");
    let hay = [b"prefix " as &[u8], &good_token, b" suffix"].concat();
    let hits = scan_chunk_findings(&engine, &hay);
    assert!(
        hits.iter().any(|h| h.rule == "ov-crc"),
        "finding with valid CRC should pass offline validation"
    );
}

#[test]
fn offline_validation_does_not_affect_rules_without_gate() {
    let rule = crc32_rule("no-ov", false);
    let engine = Engine::new_with_anchor_policy(
        vec![rule],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );

    // Bad checksum, but the rule has no offline_validation — finding kept.
    let bad_token = b"pfx_ABCDEFGHIJ000000";
    let hay = [b"prefix " as &[u8], bad_token, b" suffix"].concat();
    let hits = scan_chunk_findings(&engine, &hay);
    assert!(
        hits.iter().any(|h| h.rule == "no-ov"),
        "rule without offline_validation should emit finding regardless of CRC"
    );
}

#[test]
fn offline_validation_indeterminate_keeps_finding() {
    let rule = crc32_rule("ov-short", true);
    let engine = Engine::new_with_anchor_policy(
        vec![rule],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );

    // Token where the 6-char base-62 checksum decodes to a value > u32::MAX.
    // "zzzzzz" in base-62 = 56_800_235_583 which overflows u32, so
    // base62_decode_u32 returns None → validate_crc32_base62 returns
    // Indeterminate → finding is kept.
    let overflow_token = b"pfx_ABCDEFGHIJzzzzzz";
    let hay = [b"prefix " as &[u8], overflow_token as &[u8], b" suffix"].concat();
    let hits = scan_chunk_findings(&engine, &hay);
    assert!(
        hits.iter().any(|h| h.rule == "ov-short"),
        "Indeterminate verdict should keep the finding"
    );
}

#[test]
fn offline_validation_mixed_rules_selective_suppression() {
    let rule_with = crc32_rule("with-ov", true);
    let rule_without = crc32_rule("without-ov", false);
    let engine = Engine::new_with_anchor_policy(
        vec![rule_with, rule_without],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );

    // Bad CRC token — should be suppressed by with-ov, kept by without-ov.
    let bad_token = b"pfx_ABCDEFGHIJ000000";
    let hay = [b"prefix " as &[u8], bad_token, b" suffix"].concat();
    let hits = scan_chunk_findings(&engine, &hay);
    assert!(
        !hits.iter().any(|h| h.rule == "with-ov"),
        "rule with offline_validation should suppress invalid CRC"
    );
    assert!(
        hits.iter().any(|h| h.rule == "without-ov"),
        "rule without offline_validation should keep finding"
    );
}

// --------------------------
// Secret extraction tests
// --------------------------
//
// These tests verify the capture-group-based secret extraction logic implemented
// in `extract_secret_span`. The feature allows rules to specify which capture group
// contains the actual secret (vs. surrounding context like prefixes/delimiters).

/// Parametrized secret extraction tests covering default group-1 convention,
/// explicit `secret_group` override, no-group fallback, empty-group fallback,
/// explicit group-0 override, and empty-configured-group fallback.
#[rstest]
#[case::prefers_group1(0, None, r"KEY_([A-Za-z0-9]{8,16})", b"prefix KEY_SecretValue1 suffix" as &[u8], b"SecretValue1" as &[u8])]
#[case::uses_configured_secret_group(
    1,
    Some(2),
    r"TOK([A-Z]+):([a-z0-9]{8,16})",
    b"prefix TOKTYPE:secretval12 suffix",
    b"secretval12"
)]
#[case::falls_back_to_full_match_without_groups(
    2,
    None,
    r"AKIA[A-Z0-9]{16}",
    b"prefix AKIAIOSFODNN7REAL123 suffix",
    b"AKIAIOSFODNN7REAL123"
)]
#[case::skips_empty_group1(
    3,
    None,
    r"OPT([A-Z]*)_[a-z0-9]{8}",
    b"prefix OPT_abcd1234 suffix",
    b"OPT_abcd1234"
)]
#[case::explicit_group0_overrides_group1(
    4,
    Some(0),
    r"TOK_([A-Za-z0-9]{8})_END",
    b"prefix TOK_Secret12_END suffix",
    b"TOK_Secret12_END"
)]
#[case::empty_configured_group_falls_back(
    5,
    Some(2),
    r"CFG_([a-z0-9]{8})([A-Z]*)",
    b"prefix CFG_secret12 suffix",
    b"secret12"
)]
fn secret_extraction_span(
    #[case] anchor_idx: usize,
    #[case] secret_group: Option<u16>,
    #[case] pattern: &str,
    #[case] hay: &[u8],
    #[case] expected_secret: &[u8],
) {
    const ANCHOR_SETS: &[&[&[u8]]] = &[
        &[b"KEY_"], // 0: prefers_group1
        &[b"TOK"],  // 1: uses_configured_secret_group
        &[b"AKIA"], // 2: falls_back_to_full_match_without_groups
        &[b"OPT"],  // 3: skips_empty_group1
        &[b"TOK_"], // 4: explicit_group0_overrides_group1
        &[b"CFG_"], // 5: empty_configured_group_falls_back
    ];
    let rule = RuleSpec {
        radius: 16,
        secret_group,
        ..base_rule(
            "se-test",
            ANCHOR_SETS[anchor_idx],
            Regex::new(pattern).unwrap(),
        )
    };
    let eng = Engine::new_with_anchor_policy(
        vec![rule],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );
    let hits = scan_chunk_findings(&eng, hay);
    assert!(
        hits.iter().any(|h| h.rule == "se-test"),
        "expected finding for secret extraction rule"
    );
    let hit = hits.iter().find(|h| h.rule == "se-test").unwrap();
    assert_eq!(
        &hay[hit.span.clone()],
        expected_secret,
        "extracted secret mismatch"
    );
}

#[test]
fn secret_extraction_hash_consistency() {
    // Same secret value should produce the same hash regardless of how it's found.
    const ANCHORS: &[&[u8]] = &[b"SEC_"];
    let rule = RuleSpec {
        radius: 16,
        ..base_rule(
            "hash-consistency",
            ANCHORS,
            Regex::new(r"SEC_([A-Za-z0-9]{12})").unwrap(),
        )
    };
    let eng = Engine::new_with_anchor_policy(
        vec![rule],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );

    // Two different contexts with the same secret value
    let hay1 = b"first SEC_AbCdEfGh1234 context";
    let hay2 = b"different SEC_AbCdEfGh1234 other";

    let hits1 = scan_chunk_findings(&eng, hay1);
    let hits2 = scan_chunk_findings(&eng, hay2);

    let hit1 = hits1
        .iter()
        .find(|h| h.rule == "hash-consistency")
        .expect("expected hit in hay1");
    let hit2 = hits2
        .iter()
        .find(|h| h.rule == "hash-consistency")
        .expect("expected hit in hay2");

    // Verify both findings extracted the same secret (from capture group 1)
    let secret1 = &hay1[hit1.span.clone()];
    let secret2 = &hay2[hit2.span.clone()];
    assert_eq!(secret1, secret2, "secrets should match");
    assert_eq!(secret1, b"AbCdEfGh1234");

    // Hash the secrets using the same function the engine uses
    let hash1 = hash128(secret1);
    let hash2 = hash128(secret2);
    assert_eq!(hash1, hash2, "hashes should be identical for same secret");
}

#[test]
fn secret_extraction_utf16le_path() {
    // Secret extraction should work correctly through UTF-16LE decode path.
    const ANCHORS: &[&[u8]] = &[b"UTF_"];
    let rule = RuleSpec {
        ..base_rule(
            "utf16-extraction",
            ANCHORS,
            Regex::new(r"UTF_([A-Za-z0-9]{8})").unwrap(),
        )
    };

    let mut tuning = demo_tuning();
    tuning.scan_utf16_variants = true;

    let eng =
        Engine::new_with_anchor_policy(vec![rule], Vec::new(), tuning, AnchorPolicy::ManualOnly);

    // Create a UTF-16LE encoded input
    let plain = b"UTF_Secret12";
    let utf16 = utf16le_bytes(plain);
    let mut hay = vec![b'!'; 8];
    hay.extend_from_slice(&utf16);
    hay.extend(vec![b'!'; 8]);

    let hits = scan_chunk_findings(&eng, &hay);
    assert!(
        hits.iter().any(|h| h.rule == "utf16-extraction"),
        "expected finding through UTF-16LE path"
    );

    // Verify the finding has correct decode steps
    let hit = hits.iter().find(|h| h.rule == "utf16-extraction").unwrap();
    assert!(
        !hit.decode_steps.is_empty(),
        "UTF-16 finding should have decode steps"
    );
    assert!(
        matches!(
            hit.decode_steps
                .as_slice()
                .first()
                .expect("UTF-16 finding should include a decode step"),
            DecodeStep::Utf16Window { endianness, .. } if matches!(endianness, Utf16Endianness::Le)
        ),
        "first decode step should be UTF-16LE"
    );

    // The span should be the extracted secret (capture group 1), not the full match
    // Note: The span is in the decoded UTF-8 buffer, not the original UTF-16LE
    // We verify length matches "Secret12" (8 chars)
    assert_eq!(
        hit.span.len(),
        8,
        "span should be capture group 1 length (Secret12)"
    );
}

#[test]
fn local_context_gate_applies_in_utf16_path() {
    const ANCHORS: &[&[u8]] = &[b"UTF_"];
    let rule = RuleSpec {
        local_context: Some(LocalContextSpec {
            lookbehind: 64,
            lookahead: 64,
            require_same_line_assignment: false,
            require_quoted: true,
            key_names_any: None,
        }),
        secret_group: Some(0),
        ..base_rule(
            "utf16-local-context",
            ANCHORS,
            Regex::new(r"UTF_[A-Za-z0-9]{8}").unwrap(),
        )
    };

    let mut tuning = demo_tuning();
    tuning.scan_utf16_variants = true;

    let eng =
        Engine::new_with_anchor_policy(vec![rule], Vec::new(), tuning, AnchorPolicy::ManualOnly);

    let good_plain = b"UTF_Secret12";
    let mut good = Vec::with_capacity(good_plain.len() + 2);
    good.push(b'"');
    good.extend_from_slice(good_plain);
    good.push(b'"');
    // Prefix with two zero bytes so the BE-aligned decode includes a leading
    // character before the match; otherwise the quote gate can fail open at offset 0.
    let mut utf16 = Vec::with_capacity(2 + good.len() * 2);
    utf16.extend_from_slice(&[0u8, 0u8]);
    utf16.extend_from_slice(&utf16le_bytes(&good));
    let hits = scan_chunk_findings(&eng, &utf16);
    assert!(
        hits.iter().any(|h| h.rule == "utf16-local-context"),
        "expected quoted UTF-16 match to pass local context gate"
    );

    let bad_plain = b"xUTF_Secret12 ";
    // Same prefix ensures both UTF-16 alignments see a non-quote before the secret.
    let mut utf16 = Vec::with_capacity(2 + bad_plain.len() * 2);
    utf16.extend_from_slice(&[0u8, 0u8]);
    utf16.extend_from_slice(&utf16le_bytes(bad_plain));
    let hits = scan_chunk_findings(&eng, &utf16);
    assert!(
        !hits.iter().any(|h| h.rule == "utf16-local-context"),
        "expected unquoted UTF-16 match to be filtered by local context gate"
    );
}

#[test]
fn secret_extraction_sonar_extracts_token_not_keyword() {
    // Regression test: sonar-api-token was extracting "login"|"token" (group 1)
    // instead of the actual secret (group 2). Verify we extract the token.
    let rules = crate::rules::builtin_rules();
    let sonar_rule = rules
        .iter()
        .find(|r| r.name == "sonar-api-token")
        .expect("sonar-api-token rule should exist");

    // Build an engine with just this rule.
    let eng = Engine::new_with_anchor_policy(
        vec![sonar_rule.clone()],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );

    // Test input matching the rule pattern.
    let token = b"squ_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8";
    let hay = format!("SONAR_TOKEN='{}'", std::str::from_utf8(token).unwrap()).into_bytes();

    let hits = scan_chunk_findings(&eng, &hay);
    assert!(
        hits.iter().any(|h| h.rule == "sonar-api-token"),
        "expected finding for sonar-api-token rule"
    );

    let hit = hits.iter().find(|h| h.rule == "sonar-api-token").unwrap();
    let secret = &hay[hit.span.clone()];

    // Should extract the actual token, not "TOKEN" (keyword from group 1).
    assert_eq!(
        secret, token,
        "sonar rule should extract the token (group 2), not the keyword"
    );
}

#[test]
fn secret_extraction_teams_webhook_extracts_full_url() {
    // Regression test: microsoft-teams-webhook was extracting GUID fragment
    // (from capture groups used for repetition) instead of the full URL.
    let rules = crate::rules::builtin_rules();
    let teams_rule = rules
        .iter()
        .find(|r| r.name == "microsoft-teams-webhook")
        .expect("microsoft-teams-webhook rule should exist");

    let eng = Engine::new_with_anchor_policy(
        vec![teams_rule.clone()],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );

    // Construct a valid Teams webhook URL matching the rule regex.
    let webhook_url = b"https://contoso.webhook.office.com/webhookb2/12345678-abcd-1234-abcd-123456789012@12345678-abcd-1234-abcd-123456789012/IncomingWebhook/abcdef01234567890123456789abcdef/12345678-abcd-1234-abcd-123456789012";
    let hay = format!(
        "webhook_url='{}'",
        std::str::from_utf8(webhook_url).unwrap()
    )
    .into_bytes();

    let hits = scan_chunk_findings(&eng, &hay);
    assert!(
        hits.iter().any(|h| h.rule == "microsoft-teams-webhook"),
        "expected finding for microsoft-teams-webhook rule"
    );

    let hit = hits
        .iter()
        .find(|h| h.rule == "microsoft-teams-webhook")
        .unwrap();
    let secret = &hay[hit.span.clone()];

    // Should extract the full URL, not just a GUID fragment like "abcd-".
    assert!(
        secret.starts_with(b"https://"),
        "teams webhook should extract full URL, got: {:?}",
        std::str::from_utf8(secret)
    );
    assert!(
        secret.len() > 100,
        "extracted secret should be the full URL (>100 chars), got {} chars",
        secret.len()
    );
}

#[test]
fn root_span_hint_uses_full_window_for_partial_secret() {
    // Regression test: root_span_hint was using secret-only span in Raw variant,
    // causing chunk boundary drops when delimiter falls in new bytes region.
    // Now root_span_hint uses full window span (aligned with UTF-16 path).

    // Create a rule where the secret is a substring of the full match.
    const ANCHORS: &[&[u8]] = &[b"PREFIX_"];
    let rule = RuleSpec {
        ..base_rule(
            "partial-secret-window",
            ANCHORS,
            Regex::new(r"PREFIX_([A-Za-z0-9]{8})_SUFFIX").unwrap(),
        )
    };

    let eng = Engine::new_with_anchor_policy(
        vec![rule],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );

    // Construct input where the secret ends near the chunk boundary but SUFFIX
    // extends past it. This exercises root_span_hint calculation.
    let hay = b"data PREFIX_Secret12_SUFFIX more data";
    let hits = scan_chunk_findings(&eng, hay);

    assert!(
        hits.iter().any(|h| h.rule == "partial-secret-window"),
        "expected finding for partial-secret-window rule"
    );

    let hit = hits
        .iter()
        .find(|h| h.rule == "partial-secret-window")
        .unwrap();

    // The span should be just the captured secret (group 1).
    let secret = &hay[hit.span.clone()];
    assert_eq!(
        secret, b"Secret12",
        "span should be capture group 1 (secret only)"
    );

    // The root_span_hint should cover the full window (PREFIX_Secret12_SUFFIX).
    // We verify indirectly by checking the finding was not dropped.
    // The fix ensures root_span_hint uses w.clone() instead of span_in_buf.clone().
}

#[test]
fn anchor_policy_prefers_derived_over_manual() {
    const MANUAL: &[&[u8]] = &[b"bar"];
    let rule = RuleSpec {
        radius: 0,
        ..base_rule("derived-prefers", MANUAL, Regex::new("foo").unwrap())
    };

    let eng = Engine::new(vec![rule], Vec::new(), demo_tuning());
    #[cfg(feature = "stats")]
    {
        let stats = eng.anchor_plan_stats();
        assert_eq!(stats.derived_rules, 1);
        assert_eq!(stats.manual_rules, 0);
    }

    let hits = scan_chunk_findings(&eng, b"barfoo");
    assert!(hits.iter().any(|h| h.rule == "derived-prefers"));
}

#[test]
fn regression_slack_webhook_raw_match_not_suppressed() {
    // Byte layout:
    //   [0..39)   random non-ASCII prefix
    //   [39..116) "https://hooks.slack.com/services/AAVDQBWQAbaiDCz9ngsUzHq0m0NRqTZt02ESGr8Kk9Fx"
    //   [116]     0x25 ('%') — adjacent percent that triggers duplicate VS prefilter windows
    //   [117..156) random non-ASCII suffix
    let buf: Vec<u8> = vec![
        57, 221, 123, 82, 133, 169, 165, 91, 183, 11, 248, 153, 63, 172, 98, 240, 220, 91, 10, 75,
        10, 135, 150, 106, 232, 156, 76, 162, 159, 190, 148, 46, 221, 19, 120, 19, 13, 5, 133, 104,
        116, 116, 112, 115, 58, 47, 47, 104, 111, 111, 107, 115, 46, 115, 108, 97, 99, 107, 46, 99,
        111, 109, 47, 115, 101, 114, 118, 105, 99, 101, 115, 47, 65, 65, 86, 68, 81, 66, 87, 81,
        65, 98, 97, 105, 68, 67, 122, 57, 110, 103, 115, 85, 122, 72, 113, 48, 109, 48, 78, 82,
        113, 84, 90, 116, 48, 50, 69, 83, 71, 114, 56, 75, 107, 57, 70, 120, 37, 192, 134, 34, 52,
        202, 133, 250, 48, 156, 25, 0, 23, 244, 138, 247, 112, 101, 3, 36, 32, 205, 201, 250, 108,
        185, 208, 176, 133, 248, 42, 88, 101, 99, 109, 225, 208, 74, 34, 251, 14,
    ];
    let engine = cached_demo_engine();
    let findings = scan_chunk_findings(&engine, &buf);
    let has_raw = findings
        .iter()
        .any(|f| f.rule == "slack-webhook-url" && f.span == (39..116) && f.decode_steps.is_empty());
    assert!(has_raw, "raw slack-webhook-url match missing at 39..116");
}

#[test]
fn anchor_policy_falls_back_to_manual_on_unfilterable() {
    const MANUAL: &[&[u8]] = &[b"Z"];
    // `[A-Za-z]{1,}` now derives a residue run-length gate, so it is no
    // longer classified as unfilterable.  Manual anchors are still emitted
    // because the residue path calls `add_manual` for Vectorscan matching.
    let rule = RuleSpec {
        radius: 0,
        ..base_rule(
            "manual-fallback",
            MANUAL,
            Regex::new("[A-Za-z]{1,}").unwrap(),
        )
    };

    let eng = Engine::new(vec![rule], Vec::new(), demo_tuning());
    #[cfg(feature = "stats")]
    {
        let stats = eng.anchor_plan_stats();
        assert_eq!(stats.manual_rules, 1);
        assert_eq!(stats.derived_rules, 0);
        assert_eq!(stats.residue_rules, 1);
        assert_eq!(stats.unfilterable_rules, 0);
    }

    let hits = scan_chunk_findings(&eng, b"Z");
    assert!(hits.iter().any(|h| h.rule == "manual-fallback"));
}

#[test]
fn nested_encoding_is_skipped_in_gated_mode() {
    let eng = cached_demo_engine();

    // URL-encoded underscore inside base64.
    let token = "ghp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8";
    let url = token.replace("_", "%5F"); // ghp%5F...
    let b64 = b64_encode(url.as_bytes());

    let hay = format!("X{}Y", b64).into_bytes();

    let hits = scan_chunk_findings(&eng, &hay);
    assert!(!hits.iter().any(|h| h.rule == "github-pat"));
}

#[cfg(feature = "stdx-proptest")]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum StepKind {
    Transform { idx: usize },
    Utf16 { le: bool },
}

#[cfg(feature = "stdx-proptest")]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct FindingKey {
    rule: &'static str,
    span: Range<usize>,
    steps: Vec<StepKind>,
}

// Normalize findings into a hashable form for equivalence checks.
#[cfg(feature = "stdx-proptest")]
fn findings_to_keys(findings: &[Finding]) -> HashSet<FindingKey> {
    findings
        .iter()
        .map(|f| {
            let steps = f
                .decode_steps
                .iter()
                .map(|step| match step {
                    DecodeStep::Transform { transform_idx, .. } => StepKind::Transform {
                        idx: *transform_idx,
                    },
                    DecodeStep::Utf16Window { endianness, .. } => StepKind::Utf16 {
                        le: matches!(endianness, Utf16Endianness::Le),
                    },
                })
                .collect();
            FindingKey {
                rule: f.rule,
                span: f.span.clone(),
                steps,
            }
        })
        .collect()
}

#[cfg(feature = "stdx-proptest")]
#[derive(Clone)]
struct RefWorkItem {
    buf: Vec<u8>,
    steps: Vec<StepKind>,
    depth: usize,
}

// Slow, allocation-heavy reference scan that mirrors the engine's semantics.
#[cfg(feature = "stdx-proptest")]
fn reference_scan_keys(engine: &Engine, rules: &[RuleSpec], buf: &[u8]) -> HashSet<FindingKey> {
    let mut out = HashSet::new();
    let mut entropy_scratch = EntropyScratch::new();
    let mut work_q = Vec::new();
    work_q.push(RefWorkItem {
        buf: buf.to_vec(),
        steps: Vec::new(),
        depth: 0,
    });

    let mut work_head = 0usize;
    let mut total_decode_output_bytes = 0usize;
    let mut work_items_enqueued = 0usize;
    let mut seen = HashSet::<u128>::new();

    while work_head < work_q.len() {
        let item = work_q[work_head].clone();
        work_head += 1;

        let found_any = scan_rules_reference(
            engine,
            rules,
            &item.buf,
            &item.steps,
            &mut out,
            &mut total_decode_output_bytes,
            &mut entropy_scratch,
        );

        if item.depth >= engine.tuning.max_transform_depth {
            continue;
        }
        if work_items_enqueued >= engine.tuning.max_work_items {
            continue;
        }

        for (tidx, tc) in engine.transforms.iter().enumerate() {
            if tc.mode == TransformMode::Disabled {
                continue;
            }
            if tc.mode == TransformMode::IfNoFindingsInThisBuffer && found_any {
                continue;
            }
            if item.buf.len() < tc.min_len {
                continue;
            }
            if !transform_quick_trigger(tc, &item.buf) {
                continue;
            }
            if !engine.base64_buffer_gate(tc, &item.buf) {
                continue;
            }

            let mut spans = Vec::new();
            find_spans_into(tc, &item.buf, &mut spans);
            if spans.is_empty() {
                continue;
            }

            let span_len = spans.len().min(tc.max_spans_per_buffer);
            for enc_span in spans.iter().take(span_len) {
                if work_items_enqueued >= engine.tuning.max_work_items {
                    break;
                }
                if total_decode_output_bytes >= engine.tuning.max_total_decode_output_bytes {
                    break;
                }

                let enc_span = enc_span.clone();
                let enc = &item.buf[enc_span.clone()];

                if tc.id == TransformId::Base64 && tc.gate == Gate::AnchorsInDecoded {
                    if let Some(gate) = &engine.b64_gate {
                        if !gate.hits(enc) {
                            continue;
                        }
                    }
                }

                let mut span_starts = [0usize; 4];
                let mut span_ends = [0usize; 4];
                let mut span_count = 0usize;

                if tc.id == TransformId::Base64 {
                    let allow_space_ws = tc.base64_allow_space_ws;
                    for shift in 0..4usize {
                        let Some(rel) = base64_skip_chars(enc, shift, allow_space_ws) else {
                            break;
                        };
                        let start = enc_span.start.saturating_add(rel);
                        if start >= enc_span.end {
                            continue;
                        }
                        if span_starts[..span_count].contains(&start) {
                            continue;
                        }
                        let enc_aligned = &item.buf[start..enc_span.end];
                        let remaining_chars = base64_char_count(enc_aligned, allow_space_ws);
                        if remaining_chars < tc.min_len {
                            continue;
                        }
                        span_starts[span_count] = start;
                        span_ends[span_count] = enc_span.end;
                        span_count += 1;
                        if span_count >= span_starts.len() {
                            break;
                        }
                    }
                } else {
                    span_starts[0] = enc_span.start;
                    span_ends[0] = enc_span.end;
                    span_count = 1;
                }

                for idx in 0..span_count {
                    if work_items_enqueued >= engine.tuning.max_work_items {
                        break;
                    }
                    if total_decode_output_bytes >= engine.tuning.max_total_decode_output_bytes {
                        break;
                    }

                    let enc_span = span_starts[idx]..span_ends[idx];
                    let enc = &item.buf[enc_span.clone()];

                    let remaining = engine
                        .tuning
                        .max_total_decode_output_bytes
                        .saturating_sub(total_decode_output_bytes);
                    if remaining == 0 {
                        break;
                    }
                    let max_out = tc.max_decoded_bytes.min(remaining);

                    let decoded = match decode_to_vec(tc, enc, max_out) {
                        Ok(bytes) => bytes,
                        Err(_) => continue,
                    };
                    if decoded.is_empty() {
                        continue;
                    }

                    total_decode_output_bytes =
                        total_decode_output_bytes.saturating_add(decoded.len());
                    if total_decode_output_bytes > engine.tuning.max_total_decode_output_bytes {
                        break;
                    }

                    if tc.gate == Gate::AnchorsInDecoded {
                        let gate_satisfied = decoded_prefilter_hit(engine, &decoded);
                        let enforce_gate = if engine.vs_gate.is_some() {
                            true
                        } else {
                            !engine.tuning.scan_utf16_variants || !engine.has_utf16_anchors
                        };
                        if enforce_gate && !gate_satisfied {
                            continue;
                        }
                    }

                    let h = hash128(&decoded);
                    if !seen.insert(h) {
                        continue;
                    }

                    let mut steps = item.steps.clone();
                    steps.push(StepKind::Transform { idx: tidx });

                    work_q.push(RefWorkItem {
                        buf: decoded,
                        steps,
                        depth: item.depth + 1,
                    });
                    work_items_enqueued += 1;
                }
            }
        }
    }

    out
}

// Reference rule scan over raw + UTF-16 variants for a single buffer.
#[cfg(feature = "stdx-proptest")]
fn scan_rules_reference(
    engine: &Engine,
    rules: &[RuleSpec],
    buf: &[u8],
    steps: &[StepKind],
    out: &mut HashSet<FindingKey>,
    total_decode_output_bytes: &mut usize,
    entropy_scratch: &mut EntropyScratch,
) -> bool {
    let mut found_any = false;

    for rule in rules {
        for variant in [Variant::Raw, Variant::Utf16Le, Variant::Utf16Be] {
            let windows = collect_windows_for_variant(buf, rule, variant, &engine.tuning);
            if windows.is_empty() {
                continue;
            }

            match variant {
                Variant::Raw => {
                    for w in windows {
                        let window = &buf[w.clone()];
                        // char_class gate: reject windows dominated by lowercase ASCII.
                        if let Some(ref cc) = rule.char_class {
                            if window.len() >= cc.min_window_len as usize {
                                let profile = classify_window(window);
                                if (profile.lower as u64) * 100
                                    > (window.len() as u64) * (cc.max_lower_pct as u64)
                                {
                                    continue;
                                }
                            }
                        }
                        for caps in rule.re.captures_iter(window) {
                            // Extract secret span first so entropy is evaluated
                            // on the secret itself, not the full match (matches
                            // production ordering in window_validate.rs).
                            let (secret_start, secret_end) =
                                extract_secret_span(&caps, rule.secret_group);
                            if let Some(spec) = rule.entropy.as_ref() {
                                let ent = EntropyCompiled {
                                    min_bits_per_byte: spec.min_bits_per_byte,
                                    digit_penalty: spec.digit_penalty,
                                    min_len: spec.min_len,
                                    max_len: spec.max_len,
                                    min_entropy_bits_per_byte: spec.min_entropy_bits_per_byte,
                                };
                                let secret_bytes = &window[secret_start..secret_end];
                                if !entropy_gate_outcome(
                                    &ent,
                                    secret_bytes,
                                    entropy_scratch,
                                    &engine.entropy_log2,
                                )
                                .allows_candidate()
                                {
                                    continue;
                                }
                            }
                            // Offline validation: suppress structurally invalid
                            // tokens (bad CRC32, etc.) for root-level findings,
                            // matching engine emit-time policy.
                            if steps.is_empty() {
                                if let Some(spec) = &rule.offline_validation {
                                    let secret_bytes = &window[secret_start..secret_end];
                                    let verdict =
                                        super::offline_validate::validate(*spec, secret_bytes);
                                    if matches!(verdict, OfflineVerdict::Invalid)
                                        && spec.suppresses_on_invalid()
                                    {
                                        continue;
                                    }
                                }
                            }
                            let span = (w.start + secret_start)..(w.start + secret_end);
                            out.insert(FindingKey {
                                rule: rule.name,
                                span,
                                steps: steps.to_vec(),
                            });
                            found_any = true;
                        }
                    }
                }
                Variant::Utf16Le | Variant::Utf16Be => {
                    for w in windows {
                        // Match engine parity handling: UTF-16 anchors can land on either byte
                        // alignment, so decode both offsets within the window.
                        for offset in 0..=1 {
                            let decode_start = w.start.saturating_add(offset);
                            if decode_start >= w.end {
                                continue;
                            }
                            if *total_decode_output_bytes
                                >= engine.tuning.max_total_decode_output_bytes
                            {
                                return found_any;
                            }

                            let remaining = engine
                                .tuning
                                .max_total_decode_output_bytes
                                .saturating_sub(*total_decode_output_bytes);
                            if remaining == 0 {
                                return found_any;
                            }
                            let max_out = engine
                                .tuning
                                .max_utf16_decoded_bytes_per_window
                                .min(remaining);

                            let decoded = match variant {
                                Variant::Utf16Le => {
                                    decode_utf16le_to_vec(&buf[decode_start..w.end], max_out)
                                }
                                Variant::Utf16Be => {
                                    decode_utf16be_to_vec(&buf[decode_start..w.end], max_out)
                                }
                                _ => unreachable!(),
                            };

                            let decoded = match decoded {
                                Ok(bytes) => bytes,
                                Err(_) => continue,
                            };

                            if decoded.is_empty() {
                                continue;
                            }

                            *total_decode_output_bytes =
                                total_decode_output_bytes.saturating_add(decoded.len());
                            if *total_decode_output_bytes
                                > engine.tuning.max_total_decode_output_bytes
                            {
                                return found_any;
                            }

                            // char_class gate on decoded bytes.
                            if let Some(ref cc) = rule.char_class {
                                if decoded.len() >= cc.min_window_len as usize {
                                    let profile = classify_window(&decoded);
                                    if (profile.lower as u64) * 100
                                        > (decoded.len() as u64) * (cc.max_lower_pct as u64)
                                    {
                                        continue;
                                    }
                                }
                            }

                            let parent_is_root = steps.is_empty();
                            let mut steps = steps.to_vec();
                            steps.push(StepKind::Utf16 {
                                le: matches!(variant, Variant::Utf16Le),
                            });

                            for caps in rule.re.captures_iter(&decoded) {
                                // Extract secret span first so entropy is evaluated
                                // on the secret itself, not the full match (matches
                                // production ordering in window_validate.rs).
                                let (secret_start, secret_end) =
                                    extract_secret_span(&caps, rule.secret_group);
                                if let Some(spec) = rule.entropy.as_ref() {
                                    let ent = EntropyCompiled {
                                        min_bits_per_byte: spec.min_bits_per_byte,
                                        digit_penalty: spec.digit_penalty,
                                        min_len: spec.min_len,
                                        max_len: spec.max_len,
                                        min_entropy_bits_per_byte: spec.min_entropy_bits_per_byte,
                                    };
                                    let secret_bytes = &decoded[secret_start..secret_end];
                                    if !entropy_gate_outcome(
                                        &ent,
                                        secret_bytes,
                                        entropy_scratch,
                                        &engine.entropy_log2,
                                    )
                                    .allows_candidate()
                                    {
                                        continue;
                                    }
                                }
                                // Offline validation: suppress structurally invalid
                                // tokens for root-level findings (parent steps empty),
                                // matching engine emit-time policy.
                                if parent_is_root {
                                    if let Some(spec) = &rule.offline_validation {
                                        let secret_bytes = &decoded[secret_start..secret_end];
                                        let verdict =
                                            super::offline_validate::validate(*spec, secret_bytes);
                                        if matches!(verdict, OfflineVerdict::Invalid)
                                            && spec.suppresses_on_invalid()
                                        {
                                            continue;
                                        }
                                    }
                                }
                                let span = secret_start..secret_end;
                                out.insert(FindingKey {
                                    rule: rule.name,
                                    span,
                                    steps: steps.clone(),
                                });
                                found_any = true;
                            }
                        }
                    }
                }
            }
        }
    }

    found_any
}

// Build windows using the same merge/pressure logic as the engine.
#[cfg(feature = "stdx-proptest")]
fn collect_windows_for_variant(
    buf: &[u8],
    rule: &RuleSpec,
    variant: Variant,
    tuning: &Tuning,
) -> Vec<Range<usize>> {
    let anchors = rule
        .anchors
        .iter()
        .map(|a| match variant {
            Variant::Raw => a.to_vec(),
            Variant::Utf16Le => utf16le_bytes(a),
            Variant::Utf16Be => utf16be_bytes(a),
        })
        .collect::<Vec<_>>();

    let seed_radius = match rule.two_phase.as_ref() {
        Some(tp) => tp.seed_radius,
        None => rule.radius,
    };
    let seed_radius_bytes = seed_radius.saturating_mul(variant.scale());

    let mut windows = Vec::new();
    push_anchor_windows(buf, &anchors, seed_radius_bytes, &mut windows);
    if windows.is_empty() {
        return windows;
    }

    merge_ranges_with_gap(&mut windows, tuning.merge_gap);
    coalesce_under_pressure(
        &mut windows,
        buf.len(),
        tuning.pressure_gap_start,
        tuning.max_windows_per_rule_variant,
    );

    let Some(tp) = rule.two_phase.as_ref() else {
        return windows;
    };

    let confirm = tp
        .confirm_any
        .iter()
        .map(|c| match variant {
            Variant::Raw => c.to_vec(),
            Variant::Utf16Le => utf16le_bytes(c),
            Variant::Utf16Be => utf16be_bytes(c),
        })
        .collect::<Vec<_>>();

    let full_radius_bytes = tp.full_radius.saturating_mul(variant.scale());
    let extra = full_radius_bytes.saturating_sub(seed_radius_bytes);

    let mut expanded = Vec::new();
    for seed in windows {
        let win = &buf[seed.clone()];
        if !confirm.iter().any(|c| memmem::find(win, c).is_some()) {
            continue;
        }

        let lo = seed.start.saturating_sub(extra);
        let hi = (seed.end + extra).min(buf.len());
        expanded.push(lo..hi);
    }

    if expanded.is_empty() {
        return expanded;
    }

    merge_ranges_with_gap(&mut expanded, tuning.merge_gap);
    coalesce_under_pressure(
        &mut expanded,
        buf.len(),
        tuning.pressure_gap_start,
        tuning.max_windows_per_rule_variant,
    );

    expanded
}

#[cfg(feature = "stdx-proptest")]
fn push_anchor_windows(
    buf: &[u8],
    anchors: &[Vec<u8>],
    radius: usize,
    out: &mut Vec<Range<usize>>,
) {
    for anchor in anchors {
        if anchor.is_empty() {
            continue;
        }

        let mut start = 0usize;
        while start < buf.len() {
            let hay = &buf[start..];
            let Some(pos) = memmem::find(hay, anchor) else {
                break;
            };
            let idx = start + pos;
            let lo = idx.saturating_sub(radius);
            let hi = (idx + anchor.len() + radius).min(buf.len());
            out.push(lo..hi);
            start = idx + 1;
        }
    }
}

#[cfg(feature = "stdx-proptest")]
fn merge_ranges_with_gap(ranges: &mut Vec<Range<usize>>, gap: usize) {
    if ranges.len() <= 1 {
        return;
    }

    ranges.sort_by_key(|r| r.start);
    let mut merged = Vec::with_capacity(ranges.len());
    let mut cur = ranges[0].clone();

    for r in ranges.iter().skip(1) {
        if r.start <= cur.end.saturating_add(gap) {
            cur.end = cur.end.max(r.end);
        } else {
            merged.push(cur);
            cur = r.clone();
        }
    }

    merged.push(cur);
    *ranges = merged;
}

#[cfg(feature = "stdx-proptest")]
fn coalesce_under_pressure(
    ranges: &mut Vec<Range<usize>>,
    hay_len: usize,
    mut gap: usize,
    max_windows: usize,
) {
    if ranges.len() <= max_windows {
        return;
    }

    while ranges.len() > max_windows && gap < hay_len {
        merge_ranges_with_gap(ranges, gap);
        gap = gap.saturating_mul(2);
    }

    if ranges.len() > max_windows && !ranges.is_empty() {
        let start = ranges.first().unwrap().start;
        let end = ranges.last().unwrap().end;
        ranges.clear();
        ranges.push(start.min(hay_len)..end.min(hay_len));
    }
}

#[cfg(feature = "stdx-proptest")]
#[derive(Clone, Debug)]
struct TokenCase {
    rule_name: &'static str,
    token: Vec<u8>,
}

#[cfg(feature = "stdx-proptest")]
#[derive(Clone, Debug)]
struct InputCase {
    rule_name: &'static str,
    buf: Vec<u8>,
}

#[cfg(feature = "stdx-proptest")]
#[derive(Clone, Copy, Debug)]
enum BaseEncoding {
    Raw,
    Utf16Le,
    Utf16Be,
}

#[cfg(feature = "stdx-proptest")]
#[derive(Clone, Copy, Debug)]
enum TransformChain {
    None,
    Url,
    Base64,
    UrlThenBase64,
    Base64ThenUrl,
}

const TOKEN_RULE_NAMES: &[&str] = &[
    "aws-access-token",
    "github-pat",
    "github-oauth",
    "github-app-token",
    "gitlab-pat",
    "slack-legacy-workspace-token",
    "slack-webhook-url",
    "stripe-access-token",
    "sendgrid-api-token",
    "npm-access-token",
    "databricks-api-token",
    "private-key",
];

#[cfg(feature = "stdx-proptest")]
fn token_strategy() -> BoxedStrategy<TokenCase> {
    const ALNUM_UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const ALNUM_LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    const ALNUM_MIXED: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const GITLAB_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";
    const BASE64_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const SENDGRID_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789=_-.";
    const DATABRICKS_CHARS: &[u8] = b"abcdefgh0123456789";

    let aws = prop::collection::vec(any::<u8>(), 16).prop_map(|bytes| {
        let mut token = b"AKIA".to_vec();
        token.extend(map_bytes(&bytes, ALNUM_UPPER));
        TokenCase {
            rule_name: "aws-access-token",
            token,
        }
    });

    let github_pat = prop::collection::vec(any::<u8>(), 36).prop_map(|bytes| TokenCase {
        rule_name: "github-pat",
        token: [b"ghp_".as_slice(), &map_bytes(&bytes, ALNUM_MIXED)].concat(),
    });

    let github_oauth = prop::collection::vec(any::<u8>(), 36).prop_map(|bytes| TokenCase {
        rule_name: "github-oauth",
        token: [b"gho_".as_slice(), &map_bytes(&bytes, ALNUM_MIXED)].concat(),
    });

    let github_app = prop::collection::vec(any::<u8>(), 37).prop_map(|bytes| {
        let prefixes = [b"ghu_".as_slice(), b"ghs_".as_slice()];
        let prefix = prefixes[(bytes[0] as usize) % prefixes.len()];
        let mut token = prefix.to_vec();
        token.extend(map_bytes(&bytes[1..], ALNUM_MIXED));
        TokenCase {
            rule_name: "github-app-token",
            token,
        }
    });

    let gitlab_pat = prop::collection::vec(any::<u8>(), 20).prop_map(|bytes| TokenCase {
        rule_name: "gitlab-pat",
        token: [b"glpat-".as_slice(), &map_bytes(&bytes, GITLAB_CHARS)].concat(),
    });

    let slack_workspace = prop::collection::vec(any::<u8>(), 21).prop_map(|bytes| {
        let prefixes = [b"xoxa-".as_slice(), b"xoxr-".as_slice()];
        let prefix = prefixes[(bytes[0] as usize) % prefixes.len()];
        let mut token = prefix.to_vec();
        token.extend(map_bytes(&bytes[1..], ALNUM_MIXED));
        TokenCase {
            rule_name: "slack-legacy-workspace-token",
            token,
        }
    });

    let slack_webhook = prop::collection::vec(any::<u8>(), 44).prop_map(|bytes| TokenCase {
        rule_name: "slack-webhook-url",
        token: [
            b"https://hooks.slack.com/services/".as_slice(),
            &map_bytes(&bytes, BASE64_CHARS),
        ]
        .concat(),
    });

    let stripe = prop::collection::vec(any::<u8>(), 17).prop_map(|bytes| {
        let prefixes = [
            b"sk_test_".as_slice(),
            b"sk_live_".as_slice(),
            b"pk_test_".as_slice(),
            b"pk_live_".as_slice(),
        ];
        let prefix = prefixes[(bytes[0] as usize) % prefixes.len()];
        let mut token = prefix.to_vec();
        token.extend(map_bytes(&bytes[1..], ALNUM_LOWER));
        TokenCase {
            rule_name: "stripe-access-token",
            token,
        }
    });

    let sendgrid = prop::collection::vec(any::<u8>(), 67).prop_map(|bytes| {
        let prefixes = [b"SG.".as_slice(), b"sg.".as_slice()];
        let prefix = prefixes[(bytes[0] as usize) % prefixes.len()];
        let mut token = prefix.to_vec();
        token.extend(map_bytes(&bytes[1..], SENDGRID_CHARS));
        TokenCase {
            rule_name: "sendgrid-api-token",
            token,
        }
    });

    let npm = prop::collection::vec(any::<u8>(), 36).prop_map(|bytes| TokenCase {
        rule_name: "npm-access-token",
        token: [b"npm_".as_slice(), &map_bytes(&bytes, ALNUM_LOWER)].concat(),
    });

    let databricks = prop::collection::vec(any::<u8>(), 33).prop_map(|bytes| {
        let prefixes = [b"dapi".as_slice(), b"DAPI".as_slice()];
        let prefix = prefixes[(bytes[0] as usize) % prefixes.len()];
        let mut token = prefix.to_vec();
        token.extend(map_bytes(&bytes[1..], DATABRICKS_CHARS));
        TokenCase {
            rule_name: "databricks-api-token",
            token,
        }
    });

    let private_key = prop::collection::vec(any::<u8>(), 64).prop_map(|bytes| {
        let mut token = b"-----BEGIN PRIVATE KEY-----\n".to_vec();
        token.extend(map_bytes(&bytes, BASE64_CHARS));
        token.extend(b"\n-----END PRIVATE KEY-----");
        TokenCase {
            rule_name: "private-key",
            token,
        }
    });

    prop_oneof![
        aws,
        github_pat,
        github_oauth,
        github_app,
        gitlab_pat,
        slack_workspace,
        slack_webhook,
        stripe,
        sendgrid,
        npm,
        databricks,
        private_key,
    ]
    .boxed()
}

#[cfg(feature = "stdx-proptest")]
fn base_encoding_strategy() -> BoxedStrategy<BaseEncoding> {
    prop_oneof![
        Just(BaseEncoding::Raw),
        Just(BaseEncoding::Utf16Le),
        Just(BaseEncoding::Utf16Be),
    ]
    .boxed()
}

#[cfg(feature = "stdx-proptest")]
fn transform_chain_strategy() -> BoxedStrategy<TransformChain> {
    prop_oneof![
        Just(TransformChain::None),
        Just(TransformChain::Url),
        Just(TransformChain::Base64),
        Just(TransformChain::UrlThenBase64),
        Just(TransformChain::Base64ThenUrl),
    ]
    .boxed()
}

#[cfg(feature = "stdx-proptest")]
fn input_case_strategy() -> BoxedStrategy<InputCase> {
    (
        token_strategy(),
        base_encoding_strategy(),
        transform_chain_strategy(),
        prop::collection::vec(any::<u8>(), 0..64),
        prop::collection::vec(any::<u8>(), 0..64),
    )
        .prop_map(|(token_case, base, chain, prefix, suffix)| {
            let mut token = token_case.token;
            if requires_trailing_delimiter(token_case.rule_name) {
                token.push(b' ');
            }
            let encoded = apply_encoding(&token, base, chain);
            let mut buf = Vec::new();
            buf.extend(prefix);
            buf.extend(encoded);
            buf.extend(suffix);
            InputCase {
                rule_name: token_case.rule_name,
                buf,
            }
        })
        .boxed()
}

#[cfg(feature = "stdx-proptest")]
fn map_bytes(bytes: &[u8], charset: &[u8]) -> Vec<u8> {
    bytes
        .iter()
        .map(|b| charset[*b as usize % charset.len()])
        .collect()
}

#[cfg(feature = "stdx-proptest")]
fn apply_encoding(token: &[u8], base: BaseEncoding, chain: TransformChain) -> Vec<u8> {
    let bytes = match base {
        BaseEncoding::Raw => token.to_vec(),
        BaseEncoding::Utf16Le => utf16le_bytes(token),
        BaseEncoding::Utf16Be => utf16be_bytes(token),
    };

    match chain {
        TransformChain::None => bytes,
        TransformChain::Url => percent_encode_all(&bytes),
        TransformChain::Base64 => b64_encode(&bytes).into_bytes(),
        TransformChain::UrlThenBase64 => {
            let url = percent_encode_all(&bytes);
            b64_encode(&url).into_bytes()
        }
        TransformChain::Base64ThenUrl => {
            let b64 = b64_encode(&bytes);
            percent_encode_all(b64.as_bytes())
        }
    }
}

/// Percent-encode every byte as `%XX` with uppercase hex — equivalent to
/// [`crate::sim::mutation::percent_encode_all`] but kept local so that tests
/// compile without the `sim-harness` feature.
fn percent_encode_all(input: &[u8]) -> Vec<u8> {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = Vec::with_capacity(input.len().saturating_mul(3));
    for &b in input {
        out.push(b'%');
        out.push(HEX[(b >> 4) as usize]);
        out.push(HEX[(b & 0x0F) as usize]);
    }
    out
}

#[cfg(feature = "stdx-proptest")]
fn requires_trailing_delimiter(rule_name: &str) -> bool {
    matches!(
        rule_name,
        "sendgrid-api-token" | "npm-access-token" | "databricks-api-token"
    )
}

#[cfg(feature = "stdx-proptest")]
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct RecKey {
    rule_id: u32,
    span_start: u32,
    span_end: u32,
}

fn scan_in_chunks_with_overlap(
    engine: &Engine,
    buf: &[u8],
    chunk_size: usize,
    overlap: usize,
) -> Vec<FindingRec> {
    let mut scratch = engine.new_scratch();
    let mut out = Vec::new();
    let mut batch = Vec::with_capacity(engine.tuning.max_findings_per_chunk);

    let mut tail = Vec::new();
    let mut tail_len = 0usize;
    let mut offset = 0usize;

    while offset < buf.len() {
        let read = (buf.len() - offset).min(chunk_size);
        let mut chunk = vec![0u8; tail_len + read];
        if tail_len > 0 {
            chunk[..tail_len].copy_from_slice(&tail[..tail_len]);
        }
        chunk[tail_len..tail_len + read].copy_from_slice(&buf[offset..offset + read]);

        let base_offset = offset.saturating_sub(tail_len) as u64;
        engine.scan_chunk_into(&chunk, FileId(0), base_offset, &mut scratch);
        scratch.drop_prefix_findings(offset as u64);
        scratch.drain_findings_into(&mut batch);
        out.append(&mut batch);

        let total_len = tail_len + read;
        let next_tail_len = overlap.min(total_len);
        if tail.len() < next_tail_len {
            tail.resize(next_tail_len, 0);
        }
        if next_tail_len > 0 {
            tail[..next_tail_len].copy_from_slice(&chunk[total_len - next_tail_len..total_len]);
        }
        tail_len = next_tail_len;
        offset += read;
    }

    out
}

fn scan_in_chunks(engine: &Engine, buf: &[u8], chunk_size: usize) -> Vec<FindingRec> {
    scan_in_chunks_with_overlap(engine, buf, chunk_size, engine.required_overlap())
}

#[cfg(feature = "stdx-proptest")]
fn recs_to_keys(recs: &[FindingRec]) -> HashSet<RecKey> {
    recs.iter()
        .map(|rec| RecKey {
            rule_id: rec.rule_id,
            span_start: rec.span_start,
            span_end: rec.span_end,
        })
        .collect()
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct FullRecKey {
    rule_id: u32,
    span_start: u32,
    span_end: u32,
    root_hint_start: u64,
    root_hint_end: u64,
}

fn recs_to_full_keys(recs: &[FindingRec]) -> HashSet<FullRecKey> {
    recs.iter()
        .map(|rec| FullRecKey {
            rule_id: rec.rule_id,
            span_start: rec.span_start,
            span_end: rec.span_end,
            root_hint_start: rec.root_hint_start,
            root_hint_end: rec.root_hint_end,
        })
        .collect()
}

fn replay_steps(engine: &Engine, root: &[u8], steps: &[DecodeStep]) -> Option<Vec<u8>> {
    let mut cur = root.to_vec();

    for step in steps {
        match step {
            DecodeStep::Transform {
                transform_idx,
                parent_span,
            } => {
                if parent_span.end > cur.len() || parent_span.start > parent_span.end {
                    return None;
                }
                let tc = engine.transforms.get(*transform_idx)?;
                let decoded =
                    decode_to_vec(tc, &cur[parent_span.clone()], tc.max_decoded_bytes).ok()?;
                cur = decoded;
            }
            DecodeStep::Utf16Window {
                endianness,
                parent_span,
            } => {
                if parent_span.end > cur.len() || parent_span.start > parent_span.end {
                    return None;
                }
                let max_out = engine.tuning.max_utf16_decoded_bytes_per_window;
                let decoded = match endianness {
                    Utf16Endianness::Le => {
                        decode_utf16le_to_vec(&cur[parent_span.clone()], max_out).ok()?
                    }
                    Utf16Endianness::Be => {
                        decode_utf16be_to_vec(&cur[parent_span.clone()], max_out).ok()?
                    }
                };
                cur = decoded;
            }
        }
    }

    Some(cur)
}

fn validate_findings(engine: &Engine, root: &[u8], findings: &[Finding]) -> Result<(), String> {
    for finding in findings {
        let buf = replay_steps(engine, root, finding.decode_steps.as_slice())
            .ok_or_else(|| format!("decode steps failed for {}", finding.rule))?;

        if finding.span.end > buf.len() {
            return Err(format!(
                "span out of bounds for {} ({} > {})",
                finding.rule,
                finding.span.end,
                buf.len()
            ));
        }

        let rule_idx = engine
            .rules_cold
            .iter()
            .position(|r| r.name == finding.rule)
            .ok_or_else(|| format!("rule not found: {}", finding.rule))?;
        let rule = &engine.rules_hot[rule_idx];

        let mut matched = false;
        for caps in rule.re.captures_iter(&buf) {
            // Extract secret span to match production behavior.
            let (secret_start, secret_end) = extract_secret_span(&caps, rule.secret_group());
            if secret_start == finding.span.start && secret_end == finding.span.end {
                matched = true;
                break;
            }
        }

        if !matched {
            return Err(format!(
                "span not aligned with regex for {} at {:?}",
                finding.rule, finding.span
            ));
        }
    }

    Ok(())
}

#[test]
fn token_strategy_covers_demo_rules() {
    let expected: HashSet<&str> = demo_rules().iter().map(|r| r.name).collect();
    let provided: HashSet<&str> = TOKEN_RULE_NAMES.iter().copied().collect();
    let missing: Vec<&str> = provided.difference(&expected).copied().collect();
    assert!(
        missing.is_empty(),
        "token strategy rules missing from demo rules: {missing:?}"
    );
}

#[test]
fn utf16_overlap_accounts_for_scaled_radius() {
    let rule = RuleSpec {
        radius: 12,
        ..base_rule(
            "utf16-boundary",
            &[b"tok_"],
            Regex::new(r"aaatok_[0-9]{8}bbbb").unwrap(),
        )
    };
    let engine = Engine::new_with_anchor_policy(
        vec![rule],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );

    let anchor_len_utf16 = b"tok_".len() * 2;
    let radius = 12usize;
    let old_overlap = radius
        .saturating_mul(2)
        .saturating_add(anchor_len_utf16)
        .saturating_sub(1);
    let expected_overlap = engine
        .max_prefilter_width
        .saturating_add(radius.saturating_mul(4))
        .saturating_sub(1);

    assert_eq!(engine.required_overlap(), expected_overlap);
    assert!(old_overlap < engine.required_overlap());

    let token = b"aaatok_12345678bbbb";
    let utf16 = utf16le_bytes(token);

    let mut buf = vec![b'!'; 30];
    buf.extend_from_slice(&utf16);
    buf.extend(vec![b'!'; 12]);

    let chunk_size = 67;

    let bad = scan_in_chunks_with_overlap(&engine, &buf, chunk_size, old_overlap);
    assert!(
        !bad.iter()
            .any(|rec| engine.rule_name(rec.rule_id) == "utf16-boundary"),
        "expected miss with undersized overlap"
    );

    let good = scan_in_chunks(&engine, &buf, chunk_size);
    assert!(
        good.iter()
            .any(|rec| engine.rule_name(rec.rule_id) == "utf16-boundary"),
        "expected match with required_overlap"
    );
}

#[test]
fn utf16le_anchor_odd_offset_near_start_is_detected() {
    let rule = RuleSpec {
        radius: 25,
        ..base_rule(
            "utf16-odd-start",
            &[b"SIM2_"],
            Regex::new(r"SIM2_[A-Z0-9]{12}").unwrap(),
        )
    };
    let engine = Engine::new_with_anchor_policy(
        vec![rule],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );

    let token = b"SIM2_ABCDEFGH1234";
    let utf16 = utf16le_bytes(token);

    let mut buf = vec![b'x'; 15]; // odd offset, forces window clamp at 0
    let start = buf.len();
    buf.extend_from_slice(&utf16);
    let end = buf.len();
    buf.extend_from_slice(b"zzz");

    let mut scratch = engine.new_scratch();
    engine.scan_chunk_into(&buf, FileId(0), 0, &mut scratch);
    let hits = scratch.findings();
    assert!(
        hits.iter().any(|rec| {
            engine.rule_name(rec.rule_id) == "utf16-odd-start"
                && rec.root_hint_start <= start as u64
                && rec.root_hint_end >= end as u64
        }),
        "expected utf16 match at odd offset near start (span {}..{})",
        start,
        end
    );
}

#[test]
fn utf16be_mixed_parity_anchors_find_both() {
    let rule = RuleSpec {
        radius: 25,
        ..base_rule(
            "utf16be-mixed-parity",
            &[b"SIM2_"],
            Regex::new(r"SIM2_[A-Z0-9]{12}").unwrap(),
        )
    };
    let mut tuning = demo_tuning();
    tuning.scan_utf16_variants = true;
    let engine =
        Engine::new_with_anchor_policy(vec![rule], Vec::new(), tuning, AnchorPolicy::ManualOnly);

    let token_a = b"SIM2_9E8N0D075LOG";
    let token_b = b"SIM2_7M0VSS01PXYO";
    let utf16_a = utf16be_bytes(token_a);
    let utf16_b = utf16be_bytes(token_b);

    let mut buf = vec![b'x'; 9]; // odd offset for first token
    let start_a = buf.len();
    buf.extend_from_slice(&utf16_a);
    let end_a = buf.len();
    buf.extend_from_slice(&[b'x'; 9]);
    let start_b = buf.len();
    buf.extend_from_slice(&utf16_b);
    let end_b = buf.len();

    let mut scratch = engine.new_scratch();
    engine.scan_chunk_into(&buf, FileId(0), 0, &mut scratch);
    let hits = scratch.findings();
    let mut saw_a = false;
    let mut saw_b = false;
    for rec in hits {
        if engine.rule_name(rec.rule_id) != "utf16be-mixed-parity" {
            continue;
        }
        if rec.root_hint_start <= start_a as u64 && rec.root_hint_end >= end_a as u64 {
            saw_a = true;
        }
        if rec.root_hint_start <= start_b as u64 && rec.root_hint_end >= end_b as u64 {
            saw_b = true;
        }
    }
    assert!(
        saw_a,
        "expected utf16be match at odd offset (span {}..{})",
        start_a, end_a
    );
    assert!(
        saw_b,
        "expected utf16be match at even offset (span {}..{})",
        start_b, end_b
    );
}

/// Regression test: Verify deduplication works when a secret is entirely
/// within the overlap prefix but the window extends past the chunk boundary.
///
/// Bug: Commit f415259 changed root_span_hint fallback from match span to
/// window span, causing drop_prefix_findings() to keep findings it should drop.
#[test]
fn test_chunked_scan_dedup_secret_in_overlap_with_wide_window() {
    const ANCHORS: &[&[u8]] = &[b"KEY_"];

    let rule = RuleSpec {
        radius: 128,
        ..base_rule(
            "dedup-regression",
            ANCHORS,
            Regex::new(r"KEY_([A-Za-z0-9]{16})").unwrap(),
        )
    };

    let eng = Engine::new_with_anchor_policy(
        vec![rule],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );

    // Buffer layout:
    //   [padding][KEY_0123456789ABCDEF][more_padding........]
    //   ^0       ^64                  ^84                   ^256
    //
    // Chunk boundary at offset 128:
    //   Chunk 0: bytes [0, 192), base_offset=0
    //   Chunk 1: bytes [64, 256), base_offset=64, new_bytes_start=128
    //
    // Secret at [64, 84) is entirely in overlap [64, 128)
    // Window with radius=128 will extend to ~196, past boundary 128
    //
    // Expected: 1 finding (deduped correctly)
    // Bug: 2 findings (window span causes false keep)

    let mut buf = vec![b'x'; 256];
    buf[64..84].copy_from_slice(b"KEY_0123456789ABCDEF");

    let chunk_size = 128;
    let overlap = 64;
    let findings = scan_in_chunks_with_overlap(&eng, &buf, chunk_size, overlap);

    // Count findings for this specific secret
    let dedup_keys: HashSet<_> = findings
        .iter()
        .map(|f| (f.rule_id, f.span_start, f.span_end))
        .collect();

    assert_eq!(
        dedup_keys.len(),
        1,
        "Expected 1 unique finding, got {} (duplicate emitted due to window-based root_hint)",
        dedup_keys.len()
    );
}

/// Test that trailing context doesn't cause missed findings.
///
/// When a pattern has trailing context after the capture group (e.g., `secret([a-z]+)(?:;|$)`),
/// the full match may extend into new bytes even when the secret ends in the overlap prefix.
/// Using the secret span for root_hint would incorrectly drop these findings.
///
/// Buffer layout:
///   [padding][KEY_ABCD1234;][padding...]
///   ^0       ^60          ^72         ^128
///             ^^^^^^^^^^^ secret (60..71)
///             ^^^^^^^^^^^^ full match including delimiter (60..72)
///
/// Chunk boundary at 64, overlap starts at 32:
///   - Secret ends at 71 (in overlap region but past new_bytes_start)
///   - Full match ends at 72 (delimiter `;` past secret end)
///
/// With secret-only root_hint: finding might be dropped if logic changes
/// With full match root_hint: finding is correctly kept
#[test]
fn test_chunked_scan_trailing_context_not_dropped() {
    const ANCHORS: &[&[u8]] = &[b"KEY_"];

    // Pattern with trailing delimiter context after the capture group.
    // The `;` is NOT part of the captured secret but IS part of the full match.
    let rule = RuleSpec {
        radius: 64,
        secret_group: Some(1),
        ..base_rule(
            "trailing-context-test",
            ANCHORS,
            Regex::new(r"KEY_([A-Z0-9]{8})(?:;|$)").unwrap(),
        )
    };

    let eng = Engine::new_with_anchor_policy(
        vec![rule],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );

    // Position the secret so it ends before chunk boundary but the delimiter is right at/after it.
    // Chunk boundary at 64, secret at [52, 64), delimiter at 64.
    let mut buf = vec![b'x'; 128];
    // KEY_ABCD1234; starting at offset 48
    // KEY_ at [48, 52), secret at [52, 60), ; at 60
    buf[48..61].copy_from_slice(b"KEY_ABCD1234;");

    let chunk_size = 64;
    let overlap = 32;
    let findings = scan_in_chunks_with_overlap(&eng, &buf, chunk_size, overlap);

    // Should find exactly 1 match (not 0 due to incorrect dropping)
    assert_eq!(
        findings.len(),
        1,
        "Expected 1 finding for trailing context pattern, got {}. Finding may have been incorrectly dropped.",
        findings.len()
    );

    // Verify the span covers just the secret (capture group 1), not the delimiter
    let f = &findings[0];
    assert_eq!(f.span_start, 52, "Secret should start at offset 52");
    assert_eq!(
        f.span_end, 60,
        "Secret should end at offset 60 (excluding delimiter)"
    );
}

/// Regression test: base64-encoded slack webhook URL with tiny chunk size.
///
/// Bug: For base64 transform findings, `drop_hint_end` was set to
/// `root_span_hint.end` (the mapped match end in root-buffer coordinates),
/// which can fall *inside* the encoded region. A base64 region is only
/// decodable when the full span (including `=` padding) is visible, so a
/// finding may first appear in a chunk whose overlap boundary exceeds the
/// mapped match end. `drop_prefix_findings` would then discard it as a
/// "prior-chunk duplicate" that was never actually emitted.
///
/// Fix: `drop_hint_end_for_match` now extends to the end of the encoded
/// base64 region, ensuring the finding survives until the overlap fully
/// covers the encoded span.
#[test]
fn test_chunked_base64_drop_hint_covers_encoded_region() {
    let buf: Vec<u8> = vec![
        98, 31, 202, 153, 57, 129, 44, 220, 242, 146, 212, 47, 218, 232, 250, 28, 221, 188, 19,
        176, 82, 223, 61, 36, 182, 134, 39, 74, 181, 210, 55, 63, 124, 51, 114, 8, 155, 155, 247,
        198, 15, 87, 57, 202, 89, 8, 95, 136, 117, 113, 126, 135, 65, 79, 237, 70, 118, 65, 71,
        103, 65, 100, 65, 66, 48, 65, 72, 65, 65, 99, 119, 65, 54, 65, 67, 56, 65, 76, 119, 66,
        111, 65, 71, 56, 65, 98, 119, 66, 114, 65, 72, 77, 65, 76, 103, 66, 122, 65, 71, 119, 65,
        89, 81, 66, 106, 65, 71, 115, 65, 76, 103, 66, 106, 65, 71, 56, 65, 98, 81, 65, 118, 65,
        72, 77, 65, 90, 81, 66, 121, 65, 72, 89, 65, 97, 81, 66, 106, 65, 71, 85, 65, 99, 119, 65,
        118, 65, 69, 69, 65, 81, 81, 66, 85, 65, 69, 107, 65, 79, 65, 66, 82, 65, 69, 119, 65, 83,
        103, 66, 54, 65, 69, 77, 65, 83, 103, 66, 53, 65, 69, 56, 65, 85, 119, 66, 122, 65, 69,
        107, 65, 98, 81, 66, 79, 65, 70, 77, 65, 89, 119, 66, 106, 65, 71, 85, 65, 82, 103, 66, 87,
        65, 72, 73, 65, 90, 103, 66, 71, 65, 68, 81, 65, 83, 103, 66, 71, 65, 71, 103, 65, 99, 103,
        66, 54, 65, 71, 119, 65, 87, 65, 66, 66, 65, 72, 73, 65, 97, 65, 65, 121, 65, 69, 69, 65,
        101, 103, 66, 82, 65, 72, 103, 65, 75, 119, 61, 61, 49, 247, 144, 167, 153, 202, 213, 40,
        125, 92, 5, 234, 167, 35, 124, 169, 105, 208, 92, 140, 88, 134, 246, 67, 154, 213, 42, 162,
    ];

    let engine = cached_demo_engine();
    let mut scratch = engine.new_scratch();

    let full = engine.scan_chunk_records(&buf, FileId(0), 0, &mut scratch);
    let full_keys: std::collections::HashSet<_> = full
        .iter()
        .map(|r| (r.rule_id, r.span_start, r.span_end))
        .collect();

    let chunked = scan_in_chunks(&engine, &buf, 11);
    let chunked_keys: std::collections::HashSet<_> = chunked
        .iter()
        .map(|r| (r.rule_id, r.span_start, r.span_end))
        .collect();

    assert!(
        chunked_keys.is_superset(&full_keys),
        "Chunked scan (chunk_size=11) missed findings present in full scan.\n\
         Full: {full_keys:?}\nChunked: {chunked_keys:?}"
    );
}

// --------------------------
// Property tests for engine correctness and chunking.
// Gated behind `stdx-proptest` to keep `cargo test` fast.
// Run with: cargo test --features stdx-proptest
// --------------------------

#[cfg(all(test, feature = "stdx-proptest"))]
mod engine_proptests {
    use super::*;

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 128,
            .. ProptestConfig::default()
        })]

        #[test]
        fn prop_engine_matches_reference(case in input_case_strategy()) {
            let engine = cached_demo_engine();
            let _ = case.rule_name;
            let rules = demo_rules();

            let findings = scan_chunk_findings(&engine, &case.buf);
            let engine_keys = findings_to_keys(&findings);
            let ref_keys = reference_scan_keys(&engine, &rules, &case.buf);

            prop_assert_eq!(engine_keys, ref_keys);

            if let Err(msg) = validate_findings(&engine, &case.buf, &findings) {
                prop_assert!(false, "{}", msg);
            }
        }

        #[test]
        fn prop_chunked_matches_full(case in input_case_strategy(), chunk_size in 1usize..256) {
            let engine = cached_demo_engine();
            let _ = case.rule_name;
            let mut scratch = engine.new_scratch();
            let full = engine.scan_chunk_records(&case.buf, FileId(0), 0, &mut scratch);
            let chunked = scan_in_chunks(&engine, &case.buf, chunk_size);

            let full_keys = recs_to_keys(full);
            let chunked_keys = recs_to_keys(&chunked);

            prop_assert!(chunked_keys.is_superset(&full_keys));
        }
    }

    // --------------------------
    // Tiger-style chunking nondeterminism harness
    // --------------------------

    proptest! {
        // Keep this relatively small: each case runs multiple chunking plans.
        #![proptest_config(ProptestConfig {
            cases: 32,
            .. ProptestConfig::default()
        })]

        #[test]
        fn prop_tiger_chunk_plans_cover_oracle(
            case in input_case_strategy(),
            seed in any::<u64>(),
        ) {
            let engine = cached_correctness_engine();
            let _ = case.rule_name;
            let oracle = scan_one_chunk_records(&engine, &case.buf);

            // A small set of "interesting" sizes that tends to shake out edge cases.
            const SIZES: &[usize] = &[
                1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128, 255, 256,
            ];

            let pick = |shift: u32| -> usize { SIZES[((seed >> shift) as usize) % SIZES.len()] };

            let s0 = pick(0);
            let s1 = pick(8);
            let s2 = pick(16);
            let s3 = pick(24);

            // Force at least one plan where the chunk size exceeds required overlap.
            // Otherwise very small chunks can overlap the whole previous chunk, which
            // is correct but less stressful.
            let overlap = engine.required_overlap();
            let big = overlap.saturating_add(1).saturating_add(seed as usize % 512);

            // Shift boundaries by making the first chunk a different size.
            let first_shift = 1 + ((seed >> 32) as usize % 64);

            let plans: Vec<ChunkPlan> = vec![
                ChunkPlan::fixed(s0),
                ChunkPlan::fixed_shifted(s0, first_shift),
                ChunkPlan::alternating(s1, s2),
                ChunkPlan::random_range(seed, 1, s3.max(1)).with_first_chunk(first_shift),
                ChunkPlan {
                    pattern: ChunkPattern::Sequence(vec![1, s0, 2, s1, 3, s2, 5, s3]),
                    seed: 0,
                    first_chunk_len: None,
                },
                ChunkPlan::fixed(big).with_first_chunk(first_shift),
            ];

            for plan in plans {
                let plan_dbg = format!("{plan:?}");
                // Preserve the exact plan for regression capture before it is consumed.
                let plan_for_regression = plan.clone();
                let chunked = scan_chunked_records(&engine, &case.buf, plan);
                if let Err(msg) = check_oracle_covered(&engine, &oracle, &chunked) {
                    maybe_write_regression(
                        "tiger_chunk_plans_cover_oracle",
                        seed,
                        &plan_for_regression,
                        &case.buf,
                    );
                    prop_assert!(false, "plan={}: {}", plan_dbg, msg);
                }
            }
        }
    }

    proptest! {
        // Focused boundary-alignment property: ensure a secret instance that
        // straddles a chunk boundary is still reported.
        #![proptest_config(ProptestConfig {
            cases: 32,
            .. ProptestConfig::default()
        })]

        #[test]
        fn prop_tiger_boundary_crossing_not_dropped(
            token_case in token_strategy(),
            base in base_encoding_strategy(),
            chain in transform_chain_strategy(),
            seed in any::<u64>(),
        ) {
            let engine = cached_correctness_engine();
            let overlap = engine.required_overlap();

            // Build an encoded secret instance with safe surrounding bytes so
            // word-boundary + delimiter validators are more likely to pass.
            let mut token = token_case.token;
            if requires_trailing_delimiter(token_case.rule_name) {
                token.push(b' ');
            }

            let encoded = apply_encoding(&token, base, chain);
            prop_assume!(encoded.len() >= 2);

            // Choose a chunk size > overlap so we are testing the contract
            // "overlap is sufficient", not the degenerate case where overlap equals
            // the whole previous chunk.
            let chunk_size = overlap.saturating_add(1).saturating_add(seed as usize % 256);

            let k_max = overlap.min(encoded.len() - 1);
            prop_assume!(k_max >= 1);

            // Try a handful of k alignments that hit:
            // - base64 quanta boundaries (mod 4)
            // - url-percent triplets (mod 3)
            // - utf16 odd/even boundaries (mod 2)
            let ks = [1usize, 2, 3, 4, 7, 8, 15];

            for &k in ks.iter() {
                if k > k_max {
                    continue;
                }

                // Place the token so that it starts `k` bytes before the boundary at
                // `chunk_size`. That makes the token start within the overlap prefix
                // of chunk 2, and finish in its payload.
                let start = chunk_size - k;

                let mut buf = vec![b'A'; start];
                // Force a non-word byte right before the secret; this satisfies rules with
                // require_word_boundary_before=true more often than random bytes.
                if start > 0 {
                    buf[start - 1] = b' ';
                }

                buf.extend_from_slice(&encoded);
                buf.push(b' ');
                buf.extend_from_slice(b"ZZZ");

                let oracle = scan_one_chunk_records(&engine, &buf);
                prop_assume!(!oracle.is_empty());

                let chunked = scan_chunked_records(&engine, &buf, ChunkPlan::fixed(chunk_size));
                if let Err(msg) = check_oracle_covered(&engine, &oracle, &chunked) {
                    let plan = ChunkPlan::fixed(chunk_size);
                    maybe_write_regression(
                        "tiger_boundary_crossing_not_dropped",
                        seed,
                        &plan,
                        &buf,
                    );
                    prop_assert!(false, "chunk_size={} k={}: {}", chunk_size, k, msg);
                }
            }
        }
    }
}

#[test]
fn tiger_regressions_replay() {
    // Replays any captured regressions to keep failures sticky and reproducible.
    // The directory is optional so CI can run even when no regressions exist.
    let dir = Path::new("tests/regressions/tiger_chunking");
    let cases = match load_regressions_from_dir(dir) {
        Ok(cases) => cases,
        Err(err) => panic!("failed to load tiger regressions: {}", err),
    };

    if cases.is_empty() {
        return;
    }

    let engine = cached_correctness_engine();
    for case in cases {
        let oracle = scan_one_chunk_records(&engine, &case.input);
        let chunked = scan_chunked_records(&engine, &case.input, case.plan.clone());
        if let Err(msg) = check_oracle_covered(&engine, &oracle, &chunked) {
            panic!(
                "regression {:?} ({:?}) failed: {}",
                case.path, case.label, msg
            );
        }
    }
}

#[test]
fn tiger_boundary_url_percent_adjacent_secret() {
    // Regression guard for the oracle itself: the VS prefilter fires at two
    // adjacent match-end offsets for a slack-webhook-url embedded next to a
    // trailing `%` byte. Both windows (after clamping) cover the same decoded
    // region and yield identical regex matches, staging two FindingRecs that
    // cause `replace_same_scan_duplicate` to overwrite the raw finding.
    //
    // The single-chunk oracle must include the raw finding (not just the
    // decoded one), and no chunking plan may regress it.
    let engine = cached_correctness_engine();

    // Byte layout (same buffer as regression_slack_webhook_raw_match_not_suppressed):
    //   [0..39)   random non-ASCII prefix
    //   [39..116) "https://hooks.slack.com/services/AAVDQBWQAbaiDCz9ngsUzHq0m0NRqTZt02ESGr8Kk9Fx"
    //   [116]     0x25 ('%') — adjacent percent that triggers duplicate VS prefilter windows
    //   [117..156) random non-ASCII suffix
    let buf: Vec<u8> = vec![
        57, 221, 123, 82, 133, 169, 165, 91, 183, 11, 248, 153, 63, 172, 98, 240, 220, 91, 10, 75,
        10, 135, 150, 106, 232, 156, 76, 162, 159, 190, 148, 46, 221, 19, 120, 19, 13, 5, 133, 104,
        116, 116, 112, 115, 58, 47, 47, 104, 111, 111, 107, 115, 46, 115, 108, 97, 99, 107, 46, 99,
        111, 109, 47, 115, 101, 114, 118, 105, 99, 101, 115, 47, 65, 65, 86, 68, 81, 66, 87, 81,
        65, 98, 97, 105, 68, 67, 122, 57, 110, 103, 115, 85, 122, 72, 113, 48, 109, 48, 78, 82,
        113, 84, 90, 116, 48, 50, 69, 83, 71, 114, 56, 75, 107, 57, 70, 120, 37, 192, 134, 34, 52,
        202, 133, 250, 48, 156, 25, 0, 23, 244, 138, 247, 112, 101, 3, 36, 32, 205, 201, 250, 108,
        185, 208, 176, 133, 248, 42, 88, 101, 99, 109, 225, 208, 74, 34, 251, 14,
    ];

    // The oracle itself must contain the raw finding.
    let oracle = scan_one_chunk_records(&engine, &buf);
    let has_raw_oracle = oracle
        .iter()
        .any(|f| engine.rule_name(f.rule_id) == "slack-webhook-url" && f.step_id == STEP_ROOT);
    assert!(
        has_raw_oracle,
        "oracle must contain raw slack-webhook-url finding; got: {:?}",
        oracle
    );

    // Exercise multiple chunk plans to ensure every plan preserves the raw finding.
    let plans = [
        ("fixed-32", ChunkPlan::fixed(32)),
        ("fixed-48", ChunkPlan::fixed(48)),
        ("alternating-24-64", ChunkPlan::alternating(24, 64)),
    ];
    for (label, plan) in &plans {
        let chunked = scan_chunked_records(&engine, &buf, plan.clone());
        if let Err(msg) = check_oracle_covered(&engine, &oracle, &chunked) {
            panic!(
                "tiger_boundary_url_percent_adjacent_secret [{}] failed: {}",
                label, msg
            );
        }
        // Chunked output must also preserve the raw finding.
        let has_raw_chunked = chunked
            .iter()
            .any(|f| engine.rule_name(f.rule_id) == "slack-webhook-url" && f.step_id == STEP_ROOT);
        assert!(
            has_raw_chunked,
            "[{}] chunked scan lost raw slack-webhook-url finding; got: {:?}",
            label, chunked
        );
    }
}

#[test]
fn tiger_boundary_percent_triplet_split() {
    // Explicitly split a `%AB` percent triplet so '%' ends a chunk and the
    // two hex digits begin the next chunk. This exercises URL-percent decoding
    // across chunk boundaries.
    let engine = cached_correctness_engine();
    let overlap = engine.required_overlap();

    let token = b"ghp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8";
    let encoded = percent_encode_all(token);
    assert_eq!(encoded.first(), Some(&b'%'));

    let chunk_size = overlap.saturating_add(1);
    let start = chunk_size.saturating_sub(1);

    let mut buf = vec![b'A'; start];
    if start > 0 {
        buf[start - 1] = b' ';
    }
    buf.extend_from_slice(&encoded);
    buf.push(b' ');
    buf.extend_from_slice(b"ZZZ");

    assert_eq!(buf[chunk_size - 1], b'%');

    let oracle = scan_one_chunk_records(&engine, &buf);
    assert!(!oracle.is_empty(), "oracle empty for percent triplet split");

    let chunked = scan_chunked_records(&engine, &buf, ChunkPlan::fixed(chunk_size));
    if let Err(msg) = check_oracle_covered(&engine, &oracle, &chunked) {
        panic!("percent triplet split failed: {}", msg);
    }
}

#[test]
fn chunked_transform_root_hint_matches_reference() {
    let rule = RuleSpec {
        radius: 64,
        ..base_rule("tok0", &[b"TOK0_"], Regex::new("TOK0_[A-Z0-9]{8}").unwrap())
    };

    let transforms = vec![
        TransformConfig {
            id: TransformId::UrlPercent,
            mode: TransformMode::Always,
            gate: Gate::AnchorsInDecoded,
            min_len: 4,
            max_spans_per_buffer: 16,
            max_encoded_len: 64 * 1024,
            max_decoded_bytes: 64 * 1024,
            plus_to_space: false,
            base64_allow_space_ws: false,
        },
        TransformConfig {
            id: TransformId::Base64,
            mode: TransformMode::Always,
            gate: Gate::AnchorsInDecoded,
            min_len: 4,
            max_spans_per_buffer: 16,
            max_encoded_len: 64 * 1024,
            max_decoded_bytes: 64 * 1024,
            plus_to_space: false,
            base64_allow_space_ws: false,
        },
    ];

    let mut tuning = demo_tuning();
    tuning.scan_utf16_variants = false;
    let engine =
        Engine::new_with_anchor_policy(vec![rule], transforms, tuning, AnchorPolicy::ManualOnly);

    let token = b"TOK0_ABCDEFGH";
    let encoded_b64 = b64_encode(token).into_bytes();
    let encoded_url = percent_encode_all(token);

    let mut buf = Vec::new();
    buf.extend_from_slice(b"start ");
    buf.extend_from_slice(&encoded_b64);
    buf.extend_from_slice(b" mid ");
    buf.extend_from_slice(&encoded_url);
    buf.extend_from_slice(b" end");

    let reference = scan_one_chunk_records(&engine, &buf);
    let chunked = scan_in_chunks_with_overlap(&engine, &buf, 24, 512);

    // Base64 root_hint_end is normalized before emission, so chunked and
    // single-chunk scans should now agree on the full finding identity.
    assert_eq!(
        reference.len(),
        chunked.len(),
        "finding count mismatch: reference {} vs chunked {}",
        reference.len(),
        chunked.len()
    );

    // Compare findings by the emitted identity-bearing coordinates.
    #[derive(Debug, PartialEq, Eq, Hash)]
    struct FullKey {
        rule_id: u32,
        span_start: u32,
        span_end: u32,
        root_hint_start: u64,
        root_hint_end: u64,
    }

    let reference_full: std::collections::HashSet<_> = reference
        .iter()
        .map(|r| FullKey {
            rule_id: r.rule_id,
            span_start: r.span_start,
            span_end: r.span_end,
            root_hint_start: r.root_hint_start,
            root_hint_end: r.root_hint_end,
        })
        .collect();

    let chunked_full: std::collections::HashSet<_> = chunked
        .iter()
        .map(|r| FullKey {
            rule_id: r.rule_id,
            span_start: r.span_start,
            span_end: r.span_end,
            root_hint_start: r.root_hint_start,
            root_hint_end: r.root_hint_end,
        })
        .collect();

    assert_eq!(
        reference_full, chunked_full,
        "full finding identity mismatch:\nreference: {:?}\nchunked: {:?}",
        reference_full, chunked_full
    );
}

#[test]
fn base64_root_hint_end_stable_across_chunk_sizes() {
    let rule = RuleSpec {
        radius: 64,
        ..base_rule("tok0", &[b"TOK0_"], Regex::new("TOK0_[A-Z0-9]{8}").unwrap())
    };
    let transforms = vec![TransformConfig {
        id: TransformId::Base64,
        mode: TransformMode::Always,
        gate: Gate::AnchorsInDecoded,
        min_len: 4,
        max_spans_per_buffer: 16,
        max_encoded_len: 64 * 1024,
        max_decoded_bytes: 64 * 1024,
        plus_to_space: false,
        base64_allow_space_ws: false,
    }];

    let mut tuning = demo_tuning();
    tuning.scan_utf16_variants = false;
    let engine =
        Engine::new_with_anchor_policy(vec![rule], transforms, tuning, AnchorPolicy::ManualOnly);

    let token = b"TOK0_ABCDEFGH";
    let encoded = b64_encode(token).into_bytes();
    let mut buf = vec![b'A'; 511];
    buf[510] = b' ';
    buf.extend_from_slice(&encoded);
    buf.push(b' ');
    buf.extend(std::iter::repeat_n(b'B', 600));

    let mut reference_keys: Vec<_> = scan_one_chunk_records(&engine, &buf)
        .into_iter()
        .filter(|rec| rec.step_id != STEP_ROOT)
        .map(|rec| {
            (
                rec.rule_id,
                rec.span_start,
                rec.span_end,
                rec.root_hint_start,
                rec.root_hint_end,
            )
        })
        .collect();
    reference_keys.sort_unstable();
    assert!(
        !reference_keys.is_empty(),
        "reference scan must find at least one base64-derived finding"
    );

    for chunk_size in [64usize, 128, 256, 512] {
        let mut chunked_keys: Vec<_> = scan_in_chunks(&engine, &buf, chunk_size)
            .into_iter()
            .filter(|rec| rec.step_id != STEP_ROOT)
            .map(|rec| {
                (
                    rec.rule_id,
                    rec.span_start,
                    rec.span_end,
                    rec.root_hint_start,
                    rec.root_hint_end,
                )
            })
            .collect();
        chunked_keys.sort_unstable();

        assert_eq!(
            chunked_keys, reference_keys,
            "base64 finding identity changed for chunk size {chunk_size}"
        );
    }
}

#[test]
fn chunked_url_percent_prefix_trigger_kept() {
    let rule = RuleSpec {
        radius: 64,
        ..base_rule("tok0", &[b"TOK0_"], Regex::new("TOK0_[A-Z0-9]{8}").unwrap())
    };

    let transforms = vec![TransformConfig {
        id: TransformId::UrlPercent,
        mode: TransformMode::Always,
        gate: Gate::AnchorsInDecoded,
        min_len: 4,
        max_spans_per_buffer: 16,
        max_encoded_len: 64 * 1024,
        max_decoded_bytes: 64 * 1024,
        plus_to_space: false,
        base64_allow_space_ws: false,
    }];

    let mut tuning = demo_tuning();
    tuning.scan_utf16_variants = false;
    let engine =
        Engine::new_with_anchor_policy(vec![rule], transforms, tuning, AnchorPolicy::ManualOnly);
    if engine.vs_stream.is_none() {
        return;
    }

    let token = b"TOK0_ABCDEFGH";
    let mut buf = Vec::new();
    buf.extend_from_slice(token);
    buf.extend(std::iter::repeat_n(b'x', 24));
    buf.extend_from_slice(&percent_encode_all(b"WXYZ"));

    let reference = scan_one_chunk_records(&engine, &buf);
    let chunked = scan_in_chunks_with_overlap(&engine, &buf, 32, engine.required_overlap());

    let reference_keys = recs_to_full_keys(&reference);
    let chunked_keys = recs_to_full_keys(&chunked);

    assert_eq!(
        reference_keys, chunked_keys,
        "reference keys: {:?}\nchunked keys: {:?}",
        reference_keys, chunked_keys
    );
}

#[test]
fn chunked_url_percent_no_duplicate_when_trigger_before_and_after() {
    let rule = RuleSpec {
        radius: 64,
        ..base_rule("tok0", &[b"TOK0_"], Regex::new("TOK0_[A-Z0-9]{8}").unwrap())
    };

    let transforms = vec![TransformConfig {
        id: TransformId::UrlPercent,
        mode: TransformMode::Always,
        gate: Gate::AnchorsInDecoded,
        min_len: 4,
        max_spans_per_buffer: 16,
        max_encoded_len: 64 * 1024,
        max_decoded_bytes: 64 * 1024,
        plus_to_space: false,
        base64_allow_space_ws: false,
    }];

    let mut tuning = demo_tuning();
    tuning.scan_utf16_variants = false;
    let engine =
        Engine::new_with_anchor_policy(vec![rule], transforms, tuning, AnchorPolicy::ManualOnly);
    if engine.vs_stream.is_none() {
        return;
    }

    let overlap = engine.required_overlap();
    let chunk_size = overlap.saturating_add(32);

    let token = b"TOK0_ABCDEFGH";
    let before_trigger = b"%41";
    let after_trigger = b"%42";

    let chunk2_start = chunk_size.saturating_sub(overlap);
    let token_start = chunk2_start + 8;
    let prefix_len = token_start.saturating_sub(before_trigger.len());
    let after_trigger_offset = chunk_size.saturating_add(4);
    let after_fill = after_trigger_offset.saturating_sub(token_start + token.len());

    let mut buf = Vec::new();
    buf.extend(std::iter::repeat_n(b'a', prefix_len));
    buf.extend_from_slice(before_trigger);
    buf.extend_from_slice(token);
    buf.extend(std::iter::repeat_n(b'b', after_fill));
    buf.extend_from_slice(after_trigger);
    buf.extend(std::iter::repeat_n(b'c', 16));

    assert!(token_start < overlap, "token not in overlap prefix");
    assert!(
        after_trigger_offset >= chunk_size,
        "after-trigger not in new bytes"
    );
    assert!(buf.len() > chunk_size, "buffer should span multiple chunks");

    let reference = scan_one_chunk_records(&engine, &buf);
    let chunked = scan_in_chunks_with_overlap(&engine, &buf, chunk_size, overlap);

    let reference_keys = recs_to_full_keys(&reference);
    let chunked_keys = recs_to_full_keys(&chunked);

    assert_eq!(
        reference_keys, chunked_keys,
        "reference keys: {:?}\nchunked keys: {:?}",
        reference_keys, chunked_keys
    );
    assert_eq!(
        chunked.len(),
        chunked_keys.len(),
        "expected no duplicate findings: {:?}",
        chunked
    );
}

// -- Tests for streaming-decode duplicate-finding bug (raw overwrite) ----------

/// Build an engine with a single `TOK0_[A-Z0-9]{8}` rule, a URL-percent
/// transform, and UTF-16 scanning disabled. The `customize` closure receives
/// a mutable `Tuning` for per-test tweaks. Returns `None` when the
/// vectorscan prefilter is unavailable (the tests are only meaningful with
/// the VS streaming path).
fn percent_dedup_test_engine(customize: impl FnOnce(&mut Tuning)) -> Option<Engine> {
    let rule = RuleSpec {
        radius: 64,
        ..base_rule("tok0", &[b"TOK0_"], Regex::new("TOK0_[A-Z0-9]{8}").unwrap())
    };

    let transforms = vec![TransformConfig {
        id: TransformId::UrlPercent,
        mode: TransformMode::Always,
        gate: Gate::AnchorsInDecoded,
        min_len: 4,
        max_spans_per_buffer: 16,
        max_encoded_len: 64 * 1024,
        max_decoded_bytes: 64 * 1024,
        plus_to_space: false,
        base64_allow_space_ws: false,
    }];

    let mut tuning = demo_tuning();
    tuning.scan_utf16_variants = false;
    customize(&mut tuning);
    let engine =
        Engine::new_with_anchor_policy(vec![rule], transforms, tuning, AnchorPolicy::ManualOnly);
    engine.vs_stream.is_some().then_some(engine)
}

#[test]
fn raw_and_url_percent_transform_findings_coexist() {
    // When a plaintext secret sits adjacent to `%XX` bytes, the URL span
    // finder merges them into one URLISH run.  After decoding, the secret
    // is still present (it passes through URL decoding unchanged), so BOTH
    // a raw finding and a transform finding should be produced.
    //
    // Before the dedup fix in `run_rule_on_raw_window_into`, the VS
    // prefilter could fire at adjacent offsets, staging two identical
    // transform findings.  `replace_same_scan_duplicate` then overwrote the
    // raw finding with the duplicate, losing it.
    let Some(engine) = percent_dedup_test_engine(|_| {}) else {
        return;
    };

    let token = b"TOK0_ABCDEFGH";
    // Space breaks the URLISH run, isolating the span.
    let mut buf = Vec::new();
    buf.extend(std::iter::repeat_n(b' ', 32));
    buf.extend_from_slice(token);
    buf.extend_from_slice(&percent_encode_all(b"ABCD"));
    buf.extend(std::iter::repeat_n(b' ', 32));

    let recs = scan_one_chunk_records(&engine, &buf);

    let has_raw = recs.iter().any(|r| r.step_id == STEP_ROOT);
    let has_transform = recs.iter().any(|r| r.step_id != STEP_ROOT);

    assert!(has_raw, "raw finding missing; got: {:?}", recs);
    assert!(has_transform, "transform finding missing; got: {:?}", recs);

    // No duplicate findings: every (rule_id, span, root_hint) tuple is unique.
    let keys = recs_to_full_keys(&recs);
    assert_eq!(
        recs.len(),
        keys.len(),
        "duplicate findings detected: {:?}",
        recs
    );
}

#[test]
fn chunked_scan_preserves_raw_and_transform_for_percent_adjacent_secret() {
    // Same setup as `raw_and_url_percent_transform_findings_coexist`, but
    // compares oracle (single-chunk) vs chunked output. Both must contain
    // raw + transform findings AND oracle == chunked.
    let Some(engine) = percent_dedup_test_engine(|t| {
        t.max_findings_per_chunk = t.max_findings_per_chunk.max(65_535);
    }) else {
        return;
    };

    let token = b"TOK0_ABCDEFGH";
    let mut buf = Vec::new();
    buf.extend(std::iter::repeat_n(b' ', 32));
    buf.extend_from_slice(token);
    buf.extend_from_slice(&percent_encode_all(b"ABCD"));
    buf.extend(std::iter::repeat_n(b' ', 32));

    let reference = scan_one_chunk_records(&engine, &buf);
    let chunked = scan_in_chunks_with_overlap(&engine, &buf, 32, engine.required_overlap());

    let reference_keys = recs_to_full_keys(&reference);
    let chunked_keys = recs_to_full_keys(&chunked);

    assert_eq!(
        reference_keys, chunked_keys,
        "oracle vs chunked mismatch:\n  oracle: {:?}\n  chunked: {:?}",
        reference_keys, chunked_keys
    );

    // Both must have raw + transform.
    let has_raw = reference.iter().any(|r| r.step_id == STEP_ROOT);
    let has_transform = reference.iter().any(|r| r.step_id != STEP_ROOT);
    assert!(has_raw, "oracle missing raw finding");
    assert!(has_transform, "oracle missing transform finding");
}

#[test]
fn percent_spans_both_sides_of_secret_no_extra_findings() {
    // `%XX` bytes on BOTH sides of the secret create a wider URLISH span
    // and more VS match offsets, increasing the likelihood of adjacent
    // prefilter fires that trigger the duplicate staging bug.
    let Some(engine) = percent_dedup_test_engine(|_| {}) else {
        return;
    };

    let token = b"TOK0_ABCDEFGH";
    let mut buf = Vec::new();
    buf.extend(std::iter::repeat_n(b' ', 32));
    buf.extend_from_slice(&percent_encode_all(b"AB"));
    buf.extend_from_slice(token);
    buf.extend_from_slice(&percent_encode_all(b"CDE"));
    buf.extend(std::iter::repeat_n(b' ', 32));

    let recs = scan_one_chunk_records(&engine, &buf);

    // No duplicate findings.
    let keys = recs_to_full_keys(&recs);
    assert_eq!(
        recs.len(),
        keys.len(),
        "duplicate findings detected: {:?}",
        recs
    );

    // At most 1 raw + at most 1 transform.
    let raw_count = recs.iter().filter(|r| r.step_id == STEP_ROOT).count();
    let transform_count = recs.iter().filter(|r| r.step_id != STEP_ROOT).count();
    assert!(
        raw_count <= 1,
        "expected at most 1 raw finding, got {}: {:?}",
        raw_count,
        recs
    );
    assert!(
        transform_count <= 1,
        "expected at most 1 transform finding, got {}: {:?}",
        transform_count,
        recs
    );
}

#[test]
fn utf16_staging_path_no_duplicate_findings() {
    // Regression test for the UTF-16 staging path: the same VS prefilter
    // overlap that caused duplicate findings on the raw path can also occur
    // when a secret is encoded as UTF-16LE and then base64-wrapped.
    let rule = RuleSpec {
        radius: 64,
        ..base_rule("tok0", &[b"TOK0_"], Regex::new("TOK0_[A-Z0-9]{8}").unwrap())
    };

    let transforms = vec![TransformConfig {
        id: TransformId::Base64,
        mode: TransformMode::Always,
        gate: Gate::AnchorsInDecoded,
        min_len: 4,
        max_spans_per_buffer: 16,
        max_encoded_len: 64 * 1024,
        max_decoded_bytes: 64 * 1024,
        plus_to_space: false,
        base64_allow_space_ws: false,
    }];

    let mut tuning = demo_tuning();
    tuning.scan_utf16_variants = true;
    let engine =
        Engine::new_with_anchor_policy(vec![rule], transforms, tuning, AnchorPolicy::ManualOnly);
    if engine.vs_stream.is_none() {
        return;
    }

    let secret = b"TOK0_ABCDEFGH";
    let utf16le = utf16le_bytes(secret);
    let b64 = b64_encode(&utf16le);

    let mut buf = Vec::new();
    buf.extend(std::iter::repeat_n(b' ', 32));
    buf.extend_from_slice(b64.as_bytes());
    buf.extend(std::iter::repeat_n(b' ', 32));

    let recs = scan_one_chunk_records(&engine, &buf);

    // No duplicate (rule_id, span, root_hint) tuples.
    let keys = recs_to_full_keys(&recs);
    assert_eq!(
        recs.len(),
        keys.len(),
        "duplicate findings in UTF-16 staging path: {:?}",
        recs
    );
}

// -- End streaming-decode duplicate-finding tests -----------------------------

#[test]
fn chunked_overlap_gt_chunk_dedupes_transform_findings() {
    let rule = RuleSpec {
        radius: 64,
        ..base_rule("tok0", &[b"TOK0_"], Regex::new("TOK0_[A-Z0-9]{8}").unwrap())
    };

    let transforms = vec![TransformConfig {
        id: TransformId::UrlPercent,
        mode: TransformMode::Always,
        gate: Gate::AnchorsInDecoded,
        min_len: 4,
        max_spans_per_buffer: 16,
        max_encoded_len: 64 * 1024,
        max_decoded_bytes: 64 * 1024,
        plus_to_space: false,
        base64_allow_space_ws: false,
    }];

    let mut tuning = demo_tuning();
    tuning.scan_utf16_variants = false;
    let engine =
        Engine::new_with_anchor_policy(vec![rule], transforms, tuning, AnchorPolicy::ManualOnly);
    if engine.vs_stream.is_none() {
        return;
    }

    let token = b"TOK0_ABCDEFGH";
    let encoded = percent_encode_all(token);

    let mut buf = Vec::new();
    buf.extend(std::iter::repeat_n(b'x', 64));
    buf.extend_from_slice(&encoded);
    buf.extend(std::iter::repeat_n(b'y', 64));
    buf.extend_from_slice(token);
    buf.extend(std::iter::repeat_n(b'z', 64));

    let findings = scan_in_chunks_with_overlap(&engine, &buf, 8, 32);

    #[derive(Debug, Hash, PartialEq, Eq)]
    struct Key {
        rule_id: u32,
        span_start: u32,
        span_end: u32,
        root_hint_start: u64,
        root_hint_end: u64,
    }

    let mut seen = HashSet::new();
    for rec in &findings {
        let (span_start, span_end) = if rec.step_id == STEP_ROOT {
            (rec.span_start, rec.span_end)
        } else {
            (0, 0)
        };
        let key = Key {
            rule_id: rec.rule_id,
            span_start,
            span_end,
            root_hint_start: rec.root_hint_start,
            root_hint_end: rec.root_hint_end,
        };
        assert!(
            seen.insert(key),
            "duplicate finding emitted in overlap>chunk scenario: {:?}",
            rec
        );
    }
}

#[test]
fn nested_transform_dedupe_keeps_multiple_matches() {
    let rule = RuleSpec {
        radius: 64,
        ..base_rule("tok0", &[b"TOK0_"], Regex::new("TOK0_[A-Z0-9]{8}").unwrap())
    };

    let transforms = vec![
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
        },
        TransformConfig {
            id: TransformId::UrlPercent,
            mode: TransformMode::Always,
            gate: Gate::None,
            min_len: 4,
            max_spans_per_buffer: 16,
            max_encoded_len: 64 * 1024,
            max_decoded_bytes: 64 * 1024,
            plus_to_space: false,
            base64_allow_space_ws: false,
        },
    ];

    let mut tuning = demo_tuning();
    tuning.scan_utf16_variants = false;
    let engine =
        Engine::new_with_anchor_policy(vec![rule], transforms, tuning, AnchorPolicy::ManualOnly);

    let tok_a = b"TOK0_ABCDEFGH";
    let tok_b = b"TOK0_IJKLMNOP";
    let mut decoded = Vec::new();
    decoded.extend_from_slice(tok_a);
    decoded.extend_from_slice(b"--");
    decoded.extend_from_slice(tok_b);

    let url_encoded = percent_encode_all(&decoded);
    let b64_encoded = b64_encode(&url_encoded).into_bytes();

    let mut buf = Vec::new();
    buf.extend_from_slice(b"prefix ");
    buf.extend_from_slice(&b64_encoded);
    buf.extend_from_slice(b" suffix");

    let findings = scan_one_chunk_records(&engine, &buf);
    let spans: HashSet<_> = findings
        .iter()
        .map(|rec| (rec.span_start, rec.span_end))
        .collect();

    assert_eq!(
        findings.len(),
        2,
        "expected two distinct findings from nested transform chain"
    );
    assert_eq!(
        spans.len(),
        2,
        "expected distinct spans for nested transform matches"
    );
}

#[test]
fn tiger_boundary_base64_padding_split() {
    // Ensure base64 '=' padding is split across the chunk boundary so the
    // decoder must carry padding state across chunks.
    let engine = cached_correctness_engine();
    let overlap = engine.required_overlap();

    let token = b"ghp_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8";
    let encoded = b64_encode(token).into_bytes();
    assert!(encoded.len() >= 2);
    assert_eq!(&encoded[encoded.len() - 2..], b"==");

    let mut chunk_size = overlap.saturating_add(1);
    if chunk_size < encoded.len() {
        chunk_size = encoded.len();
    }
    let start = chunk_size.saturating_sub(encoded.len().saturating_sub(1));

    let mut buf = vec![b'A'; start];
    if start > 0 {
        buf[start - 1] = b' ';
    }
    buf.extend_from_slice(&encoded);
    buf.push(b' ');
    buf.extend_from_slice(b"ZZZ");

    assert!(buf.len() > chunk_size);
    assert_eq!(buf[chunk_size - 1], b'=');
    assert_eq!(buf[chunk_size], b'=');

    let oracle = scan_one_chunk_records(&engine, &buf);
    assert!(!oracle.is_empty(), "oracle empty for base64 padding split");

    let chunked = scan_chunked_records(&engine, &buf, ChunkPlan::fixed(chunk_size));
    if let Err(msg) = check_oracle_covered(&engine, &oracle, &chunked) {
        panic!("base64 padding split failed: {}", msg);
    }
}

#[test]
fn base64_gate_utf16be_anchor_straddles_stream_boundary() {
    // The base64 stream decoder flushes output in bounded chunks,
    // so we place a UTF-16BE anchor so its final byte lands in a 1-byte tail
    // chunk. The gate must inspect tail+chunk to see the NULs and match.
    let rule = RuleSpec {
        radius: 0,
        ..base_rule(
            "utf16be-gate-boundary",
            &[b"TOK"],
            Regex::new("TOK").unwrap(),
        )
    };

    let tc = TransformConfig {
        id: TransformId::Base64,
        mode: TransformMode::Always,
        gate: Gate::AnchorsInDecoded,
        min_len: 8,
        max_spans_per_buffer: 8,
        max_encoded_len: 8 * 1024,
        max_decoded_bytes: 8 * 1024,
        plus_to_space: false,
        base64_allow_space_ws: false,
    };

    let mut tuning = demo_tuning();
    tuning.max_total_decode_output_bytes = tuning.max_total_decode_output_bytes.max(8 * 1024);
    tuning.scan_utf16_variants = true;

    let engine =
        Engine::new_with_anchor_policy(vec![rule], vec![tc], tuning, AnchorPolicy::ManualOnly);

    let utf16 = utf16be_bytes(b"TOK");
    let flush_len = super::transform::STREAM_DECODE_CHUNK_BYTES.saturating_sub(4);
    let prefix_len = flush_len - (utf16.len().saturating_sub(1));

    let mut decoded = vec![b'A'; prefix_len];
    decoded.extend_from_slice(&utf16);
    assert_eq!(decoded.len(), flush_len + 1);

    let encoded = b64_encode(&decoded).into_bytes();
    let hits = scan_chunk_findings(&engine, &encoded);

    assert!(
        hits.iter().any(|h| h.rule == "utf16be-gate-boundary"),
        "expected utf16be match to survive base64 gate boundary"
    );
}

#[test]
fn stream_window_recovers_after_ring_eviction() {
    let rule = RuleSpec {
        radius: 128,
        ..base_rule("ring-evict-window", &[b"TOK"], Regex::new("TOK").unwrap())
    };

    let tc = TransformConfig {
        id: TransformId::Base64,
        mode: TransformMode::Always,
        gate: Gate::None,
        min_len: 8,
        max_spans_per_buffer: 4,
        max_encoded_len: 64 * 1024,
        max_decoded_bytes: 64 * 1024,
        plus_to_space: false,
        base64_allow_space_ws: false,
    };

    let mut tuning = demo_tuning();
    tuning.max_total_decode_output_bytes = tuning.max_total_decode_output_bytes.max(8 * 1024);

    let mut engine =
        Engine::new_with_anchor_policy(vec![rule], vec![tc], tuning, AnchorPolicy::ManualOnly);
    if engine.vs_stream.is_none() {
        return;
    }
    engine.stream_ring_bytes = 32;

    let mut decoded = vec![b'A'; 256];
    decoded.extend_from_slice(b"TOK");
    decoded.extend(std::iter::repeat_n(b'B', 256));
    let encoded = b64_encode(&decoded).into_bytes();

    let hits = scan_chunk_findings(&engine, &encoded);
    assert!(
        hits.iter().any(|h| h.rule == "ring-evict-window"),
        "expected match to survive ring eviction"
    );
}

#[test]
fn stream_hit_cap_forces_full_fallback() {
    let rule = RuleSpec {
        radius: 0,
        ..base_rule(
            "stream-hit-cap-fallback",
            &[b"TOK"],
            Regex::new("TOK").unwrap(),
        )
    };

    let tc = TransformConfig {
        id: TransformId::Base64,
        mode: TransformMode::Always,
        gate: Gate::None,
        min_len: 8,
        max_spans_per_buffer: 4,
        max_encoded_len: 64 * 1024,
        max_decoded_bytes: 64 * 1024,
        plus_to_space: false,
        base64_allow_space_ws: false,
    };

    let mut tuning = demo_tuning();
    tuning.max_windows_per_rule_variant = 1;
    tuning.max_total_decode_output_bytes = tuning.max_total_decode_output_bytes.max(8 * 1024);

    let engine =
        Engine::new_with_anchor_policy(vec![rule], vec![tc], tuning, AnchorPolicy::ManualOnly);
    if engine.vs_stream.is_none() {
        return;
    }

    let mut decoded = Vec::new();
    decoded.extend_from_slice(b"TOK");
    decoded.extend(std::iter::repeat_n(b'A', 512));
    decoded.extend_from_slice(b"TOK");
    let encoded = b64_encode(&decoded).into_bytes();

    let hits = scan_chunk_findings(&engine, &encoded);
    let count = hits
        .iter()
        .filter(|h| h.rule == "stream-hit-cap-fallback")
        .count();
    assert!(count >= 2, "expected >=2 matches, got {count}");
}

#[test]
fn stream_nested_span_fallback_recovers() {
    let rule = RuleSpec {
        radius: 0,
        ..base_rule(
            "nested-span-fallback",
            &[b"TOK"],
            Regex::new("TOK").unwrap(),
        )
    };

    let tc = TransformConfig {
        id: TransformId::Base64,
        mode: TransformMode::Always,
        gate: Gate::None,
        min_len: 4,
        max_spans_per_buffer: 8,
        max_encoded_len: 64 * 1024,
        max_decoded_bytes: 64 * 1024,
        plus_to_space: false,
        base64_allow_space_ws: false,
    };

    let mut tuning = demo_tuning();
    tuning.max_total_decode_output_bytes = tuning.max_total_decode_output_bytes.max(16 * 1024);

    let mut engine =
        Engine::new_with_anchor_policy(vec![rule], vec![tc], tuning, AnchorPolicy::ManualOnly);
    if engine.vs_stream.is_none() {
        return;
    }
    engine.stream_ring_bytes = 32;

    let inner = b64_encode(b"TOK");
    let mut outer_decoded = Vec::new();
    outer_decoded.extend(std::iter::repeat_n(b'A', 128));
    outer_decoded.extend_from_slice(inner.as_bytes());
    outer_decoded.extend(std::iter::repeat_n(b'B', 128));

    let outer_encoded = b64_encode(&outer_decoded).into_bytes();
    let hits = scan_chunk_findings(&engine, &outer_encoded);
    assert!(
        hits.iter().any(|h| h.rule == "nested-span-fallback"),
        "expected nested span to be recovered via fallback"
    );
}

#[test]
fn tiger_boundary_utf16_odd_byte_split() {
    // Split a UTF-16LE encoded anchor on an odd byte boundary so the decoder
    // must reconstruct code units across chunks.
    let engine = cached_correctness_engine();
    let overlap = engine.required_overlap();

    let token = b"AKIAIOSFODNN7ABCDEFG";
    let encoded = utf16le_bytes(token);
    assert!(encoded.len() >= 2);

    let chunk_size = overlap.saturating_add(1);
    let start = chunk_size.saturating_sub(1);

    let mut buf = vec![0u8; start];
    if start > 0 {
        buf[start - 1] = b' ';
    }
    buf.extend_from_slice(&encoded);
    buf.extend_from_slice(&[b' ', 0]);
    buf.extend_from_slice(b"ZZZ");

    assert_eq!(buf[chunk_size - 1], encoded[0]);
    assert_eq!(buf[chunk_size], encoded[1]);

    let oracle = scan_one_chunk_records(&engine, &buf);
    assert!(!oracle.is_empty(), "oracle empty for utf16 odd-byte split");

    let chunked = scan_chunked_records(&engine, &buf, ChunkPlan::fixed(chunk_size));
    if let Err(msg) = check_oracle_covered(&engine, &oracle, &chunked) {
        panic!("utf16 odd-byte split failed: {}", msg);
    }
}

#[cfg(all(test, feature = "stdx-proptest"))]
mod proptests {
    use super::*;

    const PROPTEST_CASES: u32 = 32;
    const PROPTEST_FUZZ_MULTIPLIER: u32 = 1;

    fn proptest_config() -> ProptestConfig {
        let cases = crate::test_utils::proptest_cases(PROPTEST_CASES);
        let mult = crate::test_utils::proptest_fuzz_multiplier(PROPTEST_FUZZ_MULTIPLIER);
        ProptestConfig::with_cases(cases.saturating_mul(mult))
    }

    proptest! {
        #![proptest_config(proptest_config())]

        #[test]
        fn prop_scan_chunk_reuse_scratch_matches_fresh(
            case_a in input_case_strategy(),
            case_b in input_case_strategy(),
        ) {
            let engine = cached_demo_engine();
            let mut scratch = engine.new_scratch();
            let mut out = Vec::new();
            let _ = case_a.rule_name;
            let _ = case_b.rule_name;

            engine.scan_chunk_into(&case_a.buf, FileId(0), 0, &mut scratch);
            engine.drain_findings_materialized(&mut scratch, &mut out);
            let keys_a = findings_to_keys(&out);
            let fresh_a = findings_to_keys(&scan_chunk_findings(&engine, &case_a.buf));
            prop_assert_eq!(keys_a, fresh_a);

            out.clear();
            engine.scan_chunk_into(&case_b.buf, FileId(0), 0, &mut scratch);
            engine.drain_findings_materialized(&mut scratch, &mut out);
            let keys_b = findings_to_keys(&out);
            let fresh_b = findings_to_keys(&scan_chunk_findings(&engine, &case_b.buf));
            prop_assert_eq!(keys_b, fresh_b);
        }

        #[test]
        fn prop_hit_acc_pool_coalesces(
            ranges in prop::collection::vec((0u32..512, 0u32..512), 0..128),
            max_hits in 1usize..32
        ) {
            let mut acc =
                HitAccPool::new(1, max_hits).expect("hit accumulator pool allocation failed");
            let mut touched_pairs: ScratchVec<u32> =
                ScratchVec::with_capacity(1).expect("scratch touched_pairs allocation failed");
            let pair = 0usize;
            let mut ref_windows: Vec<SpanU32> = Vec::new();
            let mut ref_coalesced: Option<SpanU32> = None;

            for (a, b) in ranges {
                let (start, end) = if a <= b { (a, b) } else { (b, a) };
                let start = start as usize;
                let end = end as usize;
                acc.push_span(pair, SpanU32::new_no_hint(start, end), &mut touched_pairs);

                let r = SpanU32::new_no_hint(start, end);
                if let Some(c) = ref_coalesced.as_mut() {
                    c.start = c.start.min(r.start);
                    c.end = c.end.max(r.end);
                    // Preserve the earliest anchor_hint when coalescing.
                    c.anchor_hint = c.anchor_hint.min(r.anchor_hint);
                } else if ref_windows.len() < max_hits {
                    ref_windows.push(r);
                } else {
                    let mut c = ref_windows[0];
                    for w in &ref_windows[1..] {
                        c.start = c.start.min(w.start);
                        c.end = c.end.max(w.end);
                        c.anchor_hint = c.anchor_hint.min(w.anchor_hint);
                    }
                    c.start = c.start.min(r.start);
                    c.end = c.end.max(r.end);
                    c.anchor_hint = c.anchor_hint.min(r.anchor_hint);
                    ref_windows.clear();
                    ref_coalesced = Some(c);
                }
            }

            let acc_coalesced = if acc.is_coalesced(pair) {
                Some(acc.coalesced_span(pair))
            } else {
                None
            };

            match (acc_coalesced, ref_coalesced) {
                (Some(actual), Some(expected)) => {
                    prop_assert_eq!(actual, expected);
                    prop_assert_eq!(acc.pair_len(pair), 0);
                }
                (None, None) => {
                    let len = acc.pair_len(pair) as usize;
                    prop_assert_eq!(len, ref_windows.len());
                    for (i, expected) in ref_windows.iter().enumerate() {
                        prop_assert_eq!(acc.window_at(pair, i), *expected);
                    }
                }
                _ => {
                    prop_assert!(false, "coalesced state mismatch");
                }
            }
        }

        /// Multi-pair variant: exercises stride arithmetic and the per-word
        /// touched bitset across multiple pairs, catching off-by-one errors
        /// that the single-pair test above cannot reach.
        #[test]
        fn prop_hit_acc_pool_coalesces_multi_pair(
            pair_count in 2usize..=128,
            ranges in prop::collection::vec(
                (0u32..512, 0u32..512),
                0..128,
            ),
            max_hits in 1usize..32
        ) {
            let mut acc = HitAccPool::new(pair_count, max_hits)
                .expect("hit accumulator pool allocation failed");
            let mut touched: ScratchVec<u32> =
                ScratchVec::with_capacity(pair_count).expect("scratch alloc failed");

            // Push every span to every pair.
            for (a, b) in &ranges {
                let (start, end) = if a <= b { (*a, *b) } else { (*b, *a) };
                for p in 0..pair_count {
                    acc.push_span(
                        p,
                        SpanU32::new_no_hint(start as usize, end as usize),
                        &mut touched,
                    );
                }
            }

            // All pairs must show the same state.
            for p in 1..pair_count {
                prop_assert_eq!(
                    acc.pair_len(0),
                    acc.pair_len(p),
                    "pair_len diverged between pair 0 and pair {}",
                    p,
                );
                prop_assert_eq!(
                    acc.is_coalesced(0),
                    acc.is_coalesced(p),
                    "coalesced state diverged between pair 0 and pair {}",
                    p,
                );
                if acc.is_coalesced(p) {
                    prop_assert_eq!(
                        acc.coalesced_span(0),
                        acc.coalesced_span(p),
                        "coalesced span diverged between pair 0 and pair {}",
                        p,
                    );
                } else {
                    let len = acc.pair_len(p) as usize;
                    for i in 0..len {
                        prop_assert_eq!(
                            acc.window_at(0, i),
                            acc.window_at(p, i),
                            "window {} diverged between pair 0 and pair {}",
                            i,
                            p,
                        );
                    }
                }
            }

            // Reset and verify all pairs are clean.
            for &p in touched.as_slice() {
                acc.reset_pair(p as usize);
            }
            acc.reset_touched(touched.as_slice());
            for p in 0..pair_count {
                prop_assert_eq!(acc.pair_len(p), 0);
                prop_assert!(!acc.is_coalesced(p));
            }
        }

        #[test]
        fn prop_span_finders_match_vec_vs_scratch(
            buf in prop::collection::vec(any::<u8>(), 0..256),
            min_len in 1usize..32,
            max_len in 1usize..96,
            max_spans in 0usize..32,
            plus_to_space in any::<bool>(),
            allow_space_ws in any::<bool>(),
        ) {
            let max_len = max_len.max(min_len);
            let mut vec_out: Vec<Range<usize>> = Vec::new();
            let mut scratch_out: ScratchVec<Range<usize>> =
                ScratchVec::with_capacity(max_spans).unwrap();

            find_url_spans_into(
                &buf,
                min_len,
                max_len,
                max_spans,
                plus_to_space,
                &mut vec_out,
            );
            find_url_spans_into(
                &buf,
                min_len,
                max_len,
                max_spans,
                plus_to_space,
                &mut scratch_out,
            );
            prop_assert_eq!(vec_out.as_slice(), scratch_out.as_slice());

            vec_out.clear();
            scratch_out.clear();
            find_base64_spans_into(
                &buf,
                min_len,
                max_len,
                max_spans,
                allow_space_ws,
                &mut vec_out,
            );
            find_base64_spans_into(
                &buf,
                min_len,
                max_len,
                max_spans,
                allow_space_ws,
                &mut scratch_out,
            );
            prop_assert_eq!(vec_out.as_slice(), scratch_out.as_slice());
        }

        #[test]
        fn prop_base64_spans_match_reference(
            buf in prop::collection::vec(any::<u8>(), 0..256),
            min_len in 1usize..32,
            max_len in 1usize..96,
            max_spans in 0usize..32,
            allow_space_ws in any::<bool>(),
        ) {
            let max_len = max_len.max(min_len);
            let mut actual = Vec::new();
            find_base64_spans_into(
                &buf,
                min_len,
                max_len,
                max_spans,
                allow_space_ws,
                &mut actual,
            );

            let expected = find_base64_spans_reference(
                &buf,
                min_len,
                max_len,
                max_spans,
                allow_space_ws,
            );

            prop_assert_eq!(actual.as_slice(), expected.as_slice());
        }
    }
}

// ---------------------------------------------------------------------------
// `url_percent_gate_check` unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod url_percent_gate_check_tests {
    use super::super::core::url_percent_gate_check;

    /// Build a 256-bit anchor byte set containing exactly the given bytes.
    fn make_anchor_set(bytes: &[u8]) -> [u64; 4] {
        let mut set = [0u64; 4];
        for &b in bytes {
            set[(b >> 6) as usize] |= 1u64 << (b & 63);
        }
        set
    }

    #[test]
    fn no_percent_returns_false() {
        let set = make_anchor_set(b"A");
        assert!(!url_percent_gate_check(
            &set,
            false,
            b"plain text no percent"
        ));
    }

    #[test]
    fn matching_triplet_returns_true() {
        let set = make_anchor_set(b"A");
        assert!(url_percent_gate_check(&set, false, b"data%41more"));
    }

    #[test]
    fn multiple_triplets_later_match() {
        let set = make_anchor_set(b"B");
        // %41='A' (not in set), %42='B' (in set)
        assert!(url_percent_gate_check(&set, false, b"%41%42"));
    }
}

// ---------------------------------------------------------------------------
// Offline validation emission-time gate tests
// ---------------------------------------------------------------------------

/// Encode a `u32` into a 6-char base-62 string, matching the production encoder.
fn base62_encode_u32_test(mut val: u32, buf: &mut [u8; 6]) {
    const CHARS: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    for slot in buf.iter_mut().rev() {
        *slot = CHARS[(val % 62) as usize];
        val /= 62;
    }
}

/// Build a `tok_<8-char payload><6-char CRC>` token with a correct CRC.
fn build_valid_crc_token() -> Vec<u8> {
    let prefix = b"tok_";
    let payload = b"ABcd1234"; // 8 bytes
    let crc = crc32fast::hash(payload);
    let mut checksum = [0u8; 6];
    base62_encode_u32_test(crc, &mut checksum);
    let mut token = Vec::with_capacity(18);
    token.extend_from_slice(prefix);
    token.extend_from_slice(payload);
    token.extend_from_slice(&checksum);
    token
}

/// Build a `tok_<8-char payload><6-char CRC>` token with an INVALID CRC.
fn build_invalid_crc_token() -> Vec<u8> {
    let prefix = b"tok_";
    let payload = b"XYzw5678"; // 8 bytes
    // Use a deliberately wrong CRC (correct CRC + 1).
    let wrong_crc = crc32fast::hash(payload).wrapping_add(1);
    let mut checksum = [0u8; 6];
    base62_encode_u32_test(wrong_crc, &mut checksum);
    let mut token = Vec::with_capacity(18);
    token.extend_from_slice(prefix);
    token.extend_from_slice(payload);
    token.extend_from_slice(&checksum);
    token
}

/// Create a rule spec with offline CRC-32 base-62 validation.
///
/// The regex captures `tok_` + 14 alphanumeric chars (8 payload + 6 checksum).
/// `secret_group` is `None` so the full match is the secret span.
fn offline_crc_rule() -> RuleSpec {
    RuleSpec {
        radius: 64,
        offline_validation: Some(OfflineValidationSpec::Crc32Base62 {
            prefix_skip: 4,
            payload_len: 8,
            checksum_len: 6,
        }),
        ..base_rule(
            "offline-crc-test",
            &[b"tok_"],
            Regex::new(r"tok_[A-Za-z0-9]{14}").unwrap(),
        )
    }
}

#[test]
fn offline_validation_suppresses_invalid_root_finding() {
    let rule = offline_crc_rule();
    let engine = Engine::new_with_anchor_policy(
        vec![rule],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );

    let invalid_tok = build_invalid_crc_token();
    let mut hay = Vec::new();
    hay.extend_from_slice(b"prefix ");
    hay.extend_from_slice(&invalid_tok);
    hay.extend_from_slice(b" suffix");

    let mut scratch = engine.new_scratch();
    engine.scan_chunk_into(&hay, FileId(0), 0, &mut scratch);

    let recs = scratch.findings();
    assert_eq!(
        recs.len(),
        0,
        "offline validation should suppress root finding with invalid CRC"
    );
    #[cfg(all(feature = "perf-stats", debug_assertions))]
    assert_eq!(
        scratch.offline_suppressed(),
        1,
        "offline_suppressed counter should track suppressed findings"
    );
    // Sidecar alignment must hold even after compaction.
    assert_eq!(recs.len(), scratch.norm_hashes().len());
    assert_eq!(recs.len(), scratch.drop_hint_end().len());
}

#[test]
fn offline_validation_keeps_valid_root_finding() {
    let rule = offline_crc_rule();
    let engine = Engine::new_with_anchor_policy(
        vec![rule],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );

    let valid_tok = build_valid_crc_token();
    let mut hay = Vec::new();
    hay.extend_from_slice(b"prefix ");
    hay.extend_from_slice(&valid_tok);
    hay.extend_from_slice(b" suffix");

    let mut scratch = engine.new_scratch();
    engine.scan_chunk_into(&hay, FileId(0), 0, &mut scratch);

    let recs = scratch.findings();
    assert_eq!(
        recs.len(),
        1,
        "offline validation should keep root finding with valid CRC"
    );
    assert_eq!(recs[0].step_id, STEP_ROOT);
    #[cfg(all(feature = "perf-stats", debug_assertions))]
    assert_eq!(scratch.offline_suppressed(), 0);
    assert_eq!(recs.len(), scratch.norm_hashes().len());
    assert_eq!(recs.len(), scratch.drop_hint_end().len());
}

#[test]
fn offline_validation_mixed_valid_invalid_and_no_gate() {
    // Three rules: one with valid CRC, one with invalid CRC, one without offline gate.
    let crc_rule = offline_crc_rule();

    // A rule without offline validation.
    let plain_rule = RuleSpec {
        radius: 64,
        ..base_rule(
            "plain-no-gate",
            &[b"api_"],
            Regex::new(r"api_[A-Za-z0-9]{8}").unwrap(),
        )
    };

    let engine = Engine::new_with_anchor_policy(
        vec![crc_rule, plain_rule],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );

    let valid_tok = build_valid_crc_token();
    let invalid_tok = build_invalid_crc_token();

    let mut hay = Vec::new();
    hay.extend_from_slice(b"prefix ");
    hay.extend_from_slice(&valid_tok);
    hay.extend_from_slice(b" middle ");
    hay.extend_from_slice(&invalid_tok);
    hay.extend_from_slice(b" api_Zz9aQq1R end");

    let mut scratch = engine.new_scratch();
    engine.scan_chunk_into(&hay, FileId(0), 0, &mut scratch);

    let recs = scratch.findings();
    // Expected: valid CRC token + plain rule token survive; invalid CRC token is removed.
    assert_eq!(
        recs.len(),
        2,
        "expected 2 findings: valid CRC kept + plain rule kept, invalid CRC suppressed"
    );
    #[cfg(all(feature = "perf-stats", debug_assertions))]
    assert_eq!(scratch.offline_suppressed(), 1);
    assert_eq!(recs.len(), scratch.norm_hashes().len());
    assert_eq!(recs.len(), scratch.drop_hint_end().len());

    let rule_names: Vec<&str> = recs.iter().map(|r| engine.rule_name(r.rule_id)).collect();
    assert!(
        rule_names.contains(&"offline-crc-test"),
        "valid CRC finding should survive"
    );
    assert!(
        rule_names.contains(&"plain-no-gate"),
        "finding without offline gate should survive"
    );
}

#[test]
fn offline_validation_does_not_suppress_non_root_findings() {
    // A rule with offline validation that also matches via base64 transform.
    // The base64-decoded finding (non-root step) should bypass offline validation.
    let rule = offline_crc_rule();

    let transforms = vec![TransformConfig {
        id: TransformId::Base64,
        mode: TransformMode::Always,
        gate: Gate::AnchorsInDecoded,
        min_len: 8,
        max_spans_per_buffer: 8,
        max_encoded_len: 1024,
        max_decoded_bytes: 1024,
        plus_to_space: false,
        base64_allow_space_ws: false,
    }];

    let engine = Engine::new_with_anchor_policy(
        vec![rule],
        transforms,
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );

    // Build an invalid-CRC token and base64-encode it so the transform
    // decodes it into the scan buffer. The decoded finding is non-root
    // (step_id != STEP_ROOT) and should survive offline validation.
    let invalid_tok = build_invalid_crc_token();
    let b64_encoded = base64_encode_bytes(&invalid_tok);

    let mut hay = Vec::new();
    hay.extend_from_slice(b"data ");
    hay.extend_from_slice(&b64_encoded);
    hay.extend_from_slice(b" end");

    let mut scratch = engine.new_scratch();
    engine.scan_chunk_into(&hay, FileId(0), 0, &mut scratch);

    let recs = scratch.findings();
    // The base64-decoded finding is non-root and should survive.
    assert!(
        recs.iter().any(|r| r.step_id != STEP_ROOT),
        "non-root (transform-derived) finding should bypass offline validation"
    );
}

#[test]
fn offline_validation_suppresses_invalid_utf16_root_finding() {
    // Root UTF-16 findings carry a Utf16Window step id, but offline validation
    // now uses the parent step_id (STEP_ROOT) to correctly identify them.
    let rule = offline_crc_rule();
    let mut tuning = demo_tuning();
    tuning.scan_utf16_variants = true;
    let engine =
        Engine::new_with_anchor_policy(vec![rule], Vec::new(), tuning, AnchorPolicy::ManualOnly);

    let invalid_tok = build_invalid_crc_token();
    let hay = utf16le_bytes(&invalid_tok);

    let mut scratch = engine.new_scratch();
    engine.scan_chunk_into(&hay, FileId(0), 0, &mut scratch);

    let recs = scratch.findings();
    assert_eq!(
        recs.len(),
        0,
        "invalid token should be suppressed for UTF-16 root input, same as ASCII root input"
    );
}

#[test]
fn offline_validation_keeps_valid_utf16_root_finding() {
    let rule = offline_crc_rule();
    let mut tuning = demo_tuning();
    tuning.scan_utf16_variants = true;
    let engine =
        Engine::new_with_anchor_policy(vec![rule], Vec::new(), tuning, AnchorPolicy::ManualOnly);

    let valid_tok = build_valid_crc_token();
    let hay = utf16le_bytes(&valid_tok);

    let mut scratch = engine.new_scratch();
    engine.scan_chunk_into(&hay, FileId(0), 0, &mut scratch);

    let recs = scratch.findings();
    assert_eq!(
        recs.len(),
        1,
        "valid CRC token in UTF-16 LE should produce a finding"
    );
}

#[test]
#[cfg(all(feature = "perf-stats", debug_assertions))]
fn offline_validation_utf16_root_counts_suppressed() {
    let rule = offline_crc_rule();
    let mut tuning = demo_tuning();
    tuning.scan_utf16_variants = true;
    let engine =
        Engine::new_with_anchor_policy(vec![rule], Vec::new(), tuning, AnchorPolicy::ManualOnly);

    let invalid_tok = build_invalid_crc_token();
    let hay = utf16le_bytes(&invalid_tok);

    let mut scratch = engine.new_scratch();
    engine.scan_chunk_into(&hay, FileId(0), 0, &mut scratch);

    assert_eq!(
        scratch.offline_suppressed(),
        1,
        "offline_suppressed counter should increment for UTF-16 root suppression"
    );
}

#[test]
fn offline_validation_suppresses_invalid_utf16be_root_finding() {
    let rule = offline_crc_rule();
    let mut tuning = demo_tuning();
    tuning.scan_utf16_variants = true;
    let engine =
        Engine::new_with_anchor_policy(vec![rule], Vec::new(), tuning, AnchorPolicy::ManualOnly);

    let invalid_tok = build_invalid_crc_token();
    let hay = utf16be_bytes(&invalid_tok);

    let mut scratch = engine.new_scratch();
    engine.scan_chunk_into(&hay, FileId(0), 0, &mut scratch);

    let recs = scratch.findings();
    assert_eq!(
        recs.len(),
        0,
        "invalid token should be suppressed for UTF-16 BE root input"
    );
}

#[test]
fn offline_invalid_does_not_consume_finding_cap_slot() {
    // With the old post-scan filter, invalid findings consumed cap slots during
    // emission and were only removed afterwards — crowding out valid findings in
    // pathological inputs. Inline suppression must prevent this: an invalid
    // token followed by a valid token should still allow the valid token to
    // occupy the single cap slot when cap = 1.
    let rule = offline_crc_rule();
    let mut tuning = demo_tuning();
    tuning.max_findings_per_chunk = 1;
    let engine =
        Engine::new_with_anchor_policy(vec![rule], Vec::new(), tuning, AnchorPolicy::ManualOnly);

    let invalid_tok = build_invalid_crc_token();
    let valid_tok = build_valid_crc_token();
    let mut hay = Vec::new();
    hay.extend_from_slice(b"prefix ");
    hay.extend_from_slice(&invalid_tok);
    hay.extend_from_slice(b" middle ");
    hay.extend_from_slice(&valid_tok);
    hay.extend_from_slice(b" suffix");

    let mut scratch = engine.new_scratch();
    engine.scan_chunk_into(&hay, FileId(0), 0, &mut scratch);

    let recs = scratch.findings();
    assert_eq!(
        recs.len(),
        1,
        "valid token should survive even with cap=1 because invalid token is suppressed inline"
    );
    assert_eq!(
        &hay[recs[0].span_start as usize..recs[0].span_end as usize],
        valid_tok.as_slice(),
        "the surviving finding should be the valid token, not the invalid one"
    );
}

#[test]
fn char_class_gate_rejects_all_lowercase() {
    let rule = RuleSpec {
        radius: 64,
        char_class: Some(CharClassSpec {
            max_lower_pct: 50,
            min_window_len: 16,
        }),
        ..base_rule(
            "cc-reject",
            &[b"tok_"],
            Regex::new(r"tok_([a-z]{20})").unwrap(),
        )
    };
    let engine = Engine::new_with_anchor_policy(
        vec![rule],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );
    let mut scratch = engine.new_scratch();
    // All-lowercase secret: "tok_" + 20 lowercase chars. Window will be >50% lowercase.
    let hay = b"prefix tok_abcdefghijklmnopqrst suffix";
    engine.scan_chunk_into(hay, FileId(0), 0, &mut scratch);
    scratch.drop_prefix_findings(0);
    assert_eq!(
        scratch.findings().len(),
        0,
        "char_class gate should reject all-lowercase window"
    );
}

#[test]
fn char_class_gate_passes_mixed_case() {
    let rule = RuleSpec {
        radius: 64,
        char_class: Some(CharClassSpec {
            max_lower_pct: 50,
            min_window_len: 16,
        }),
        ..base_rule(
            "cc-pass",
            &[b"TOK_"],
            Regex::new(r"TOK_([A-Za-z0-9]{8})").unwrap(),
        )
    };
    let engine = Engine::new_with_anchor_policy(
        vec![rule],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );
    let mut scratch = engine.new_scratch();
    // Mixed-case secret: upper+lower+digit. Window should pass the 50% lowercase gate.
    let hay = b"PREFIX TOK_A1b2C3d4 SUFFIX";
    engine.scan_chunk_into(hay, FileId(0), 0, &mut scratch);
    scratch.drop_prefix_findings(0);
    assert!(
        !scratch.findings().is_empty(),
        "char_class gate should pass for mixed-case window"
    );
}

#[test]
fn char_class_gate_fail_open_short_window() {
    let rule = RuleSpec {
        radius: 16,
        char_class: Some(CharClassSpec {
            max_lower_pct: 50,
            min_window_len: 128, // Very high min_window_len
        }),
        ..base_rule(
            "cc-failopen",
            &[b"tok_"],
            Regex::new(r"tok_([a-z]{8})").unwrap(),
        )
    };
    let engine = Engine::new_with_anchor_policy(
        vec![rule],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );
    let mut scratch = engine.new_scratch();
    // Short all-lowercase input — gate should fail-open because window < min_window_len.
    let hay = b"tok_abcdefgh";
    engine.scan_chunk_into(hay, FileId(0), 0, &mut scratch);
    scratch.drop_prefix_findings(0);
    assert!(
        !scratch.findings().is_empty(),
        "char_class gate should fail-open on short window"
    );
}

/// Minimal base64 encoder for test helpers.
fn base64_encode_bytes(input: &[u8]) -> Vec<u8> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let mut i = 0;
    while i + 2 < input.len() {
        let n = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8) | (input[i + 2] as u32);
        out.push(ALPHABET[((n >> 18) & 63) as usize]);
        out.push(ALPHABET[((n >> 12) & 63) as usize]);
        out.push(ALPHABET[((n >> 6) & 63) as usize]);
        out.push(ALPHABET[(n & 63) as usize]);
        i += 3;
    }
    let remaining = input.len() - i;
    if remaining == 2 {
        let n = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8);
        out.push(ALPHABET[((n >> 18) & 63) as usize]);
        out.push(ALPHABET[((n >> 12) & 63) as usize]);
        out.push(ALPHABET[((n >> 6) & 63) as usize]);
        out.push(b'=');
    } else if remaining == 1 {
        let n = (input[i] as u32) << 16;
        out.push(ALPHABET[((n >> 18) & 63) as usize]);
        out.push(ALPHABET[((n >> 12) & 63) as usize]);
        out.push(b'=');
        out.push(b'=');
    }
    out
}

// ---------------------------------------------------------------------------
// Confidence-score integration tests
// ---------------------------------------------------------------------------

#[test]
fn confidence_score_zero_when_no_gates() {
    let rule = RuleSpec {
        radius: 64,
        ..base_rule(
            "test-secret",
            &[b"SECRET"],
            Regex::new(r"SECRET[A-Z]{8}").unwrap(),
        )
    };
    let engine = Engine::new_with_anchor_policy(
        vec![rule],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );
    let hay = b"prefix SECRETABCDEFGH suffix";
    let mut scratch = engine.new_scratch();
    engine.scan_chunk_into(hay, FileId(0), 0, &mut scratch);
    let recs = scratch.findings();
    assert_eq!(recs.len(), 1, "should find one match");
    assert_eq!(recs[0].confidence_score, 0, "no gates → score 0");
}

#[test]
fn confidence_score_entropy_gate() {
    let rule = RuleSpec {
        radius: 64,
        entropy: Some(EntropySpec {
            min_bits_per_byte: 3.0,
            min_len: 4,
            max_len: 32,
            min_entropy_bits_per_byte: None,
            digit_penalty: false,
        }),
        secret_group: Some(1),
        ..base_rule(
            "entropy-test",
            &[b"TOK_"],
            Regex::new(r"TOK_([A-Za-z0-9]{8})").unwrap(),
        )
    };
    let engine = Engine::new_with_anchor_policy(
        vec![rule],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );
    // "xK9mQ2pR" has high entropy — mixed case + digits.
    let hay = b"prefix TOK_xK9mQ2pR suffix";
    let mut scratch = engine.new_scratch();
    engine.scan_chunk_into(hay, FileId(0), 0, &mut scratch);
    let recs = scratch.findings();
    assert_eq!(recs.len(), 1, "high-entropy token should survive gate");
    assert_eq!(
        recs[0].confidence_score,
        confidence::ENTROPY_PASS,
        "measured entropy pass should add ENTROPY_PASS ({}) to score",
        confidence::ENTROPY_PASS,
    );
}

#[test]
fn confidence_score_keyword_gate() {
    let rule = RuleSpec {
        radius: 64,
        keywords_any: Some(&[b"password"]),
        ..base_rule(
            "keyword-test",
            &[b"TOK_"],
            Regex::new(r"TOK_[A-Z]{8}").unwrap(),
        )
    };
    let engine = Engine::new_with_anchor_policy(
        vec![rule],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );
    let hay = b"password TOK_ABCDEFGH suffix";
    let mut scratch = engine.new_scratch();
    engine.scan_chunk_into(hay, FileId(0), 0, &mut scratch);
    let recs = scratch.findings();
    assert_eq!(recs.len(), 1, "keyword-gated finding should be emitted");
    assert_eq!(
        recs[0].confidence_score,
        confidence::KEYWORD_PRESENT,
        "local keyword evidence should add KEYWORD_PRESENT ({}) to score",
        confidence::KEYWORD_PRESENT,
    );
}

#[test]
fn confidence_score_keyword_presence_without_local_evidence_is_zero() {
    let rule = RuleSpec {
        radius: 256,
        keywords_any: Some(&[b"password"]),
        ..base_rule(
            "keyword-presence-not-evidence",
            &[b"TOK_"],
            Regex::new(r"TOK_[A-Z]{8}").unwrap(),
        )
    };
    let engine = Engine::new_with_anchor_policy(
        vec![rule],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );

    let mut hay = Vec::new();
    hay.extend_from_slice(b"password ");
    hay.extend(std::iter::repeat_n(b'x', 96));
    hay.extend_from_slice(b"TOK_ABCDEFGH suffix");

    let mut scratch = engine.new_scratch();
    engine.scan_chunk_into(&hay, FileId(0), 0, &mut scratch);
    let recs = scratch.findings();
    assert_eq!(
        recs.len(),
        1,
        "presence-only keyword window should still emit"
    );
    assert_eq!(
        recs[0].confidence_score, 0,
        "keyword presence outside the local evidence window must not earn score"
    );
}

#[test]
fn confidence_score_offline_valid() {
    let rule = offline_crc_rule();
    let engine = Engine::new_with_anchor_policy(
        vec![rule],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );
    let valid_tok = build_valid_crc_token();
    let mut hay = Vec::new();
    hay.extend_from_slice(b"prefix ");
    hay.extend_from_slice(&valid_tok);
    hay.extend_from_slice(b" suffix");

    let mut scratch = engine.new_scratch();
    engine.scan_chunk_into(&hay, FileId(0), 0, &mut scratch);
    let recs = scratch.findings();
    assert_eq!(recs.len(), 1, "valid CRC finding should be kept");
    assert_eq!(
        recs[0].confidence_score,
        confidence::OFFLINE_VALID,
        "offline-valid gate should add OFFLINE_VALID ({}) to score",
        confidence::OFFLINE_VALID,
    );
}

#[test]
fn confidence_score_multiple_gates_accumulate() {
    // Rule with entropy + keywords + offline CRC validation.
    let rule = RuleSpec {
        radius: 64,
        keywords_any: Some(&[b"secret"]),
        entropy: Some(EntropySpec {
            min_bits_per_byte: 2.5,
            min_len: 4,
            max_len: 32,
            min_entropy_bits_per_byte: None,
            digit_penalty: false,
        }),
        offline_validation: Some(OfflineValidationSpec::Crc32Base62 {
            prefix_skip: 4,
            payload_len: 8,
            checksum_len: 6,
        }),
        ..base_rule(
            "multi-gate-test",
            &[b"tok_"],
            Regex::new(r"tok_[A-Za-z0-9]{14}").unwrap(),
        )
    };
    let engine = Engine::new_with_anchor_policy(
        vec![rule],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );
    let valid_tok = build_valid_crc_token();
    let mut hay = Vec::new();
    hay.extend_from_slice(b"secret ");
    hay.extend_from_slice(&valid_tok);
    hay.extend_from_slice(b" end");

    let mut scratch = engine.new_scratch();
    engine.scan_chunk_into(&hay, FileId(0), 0, &mut scratch);
    let recs = scratch.findings();
    assert_eq!(recs.len(), 1, "multi-gate finding should be emitted");
    let expected =
        confidence::ENTROPY_PASS + confidence::KEYWORD_PRESENT + confidence::OFFLINE_VALID;
    assert_eq!(
        recs[0].confidence_score,
        expected,
        "all three gates should accumulate: ENTROPY({}) + KEYWORD({}) + OFFLINE({}) = {}",
        confidence::ENTROPY_PASS,
        confidence::KEYWORD_PRESENT,
        confidence::OFFLINE_VALID,
        expected,
    );
}

#[test]
fn confidence_score_assignment_shape_gate() {
    // name = "generic-api-key" enables the assignment-shape check.
    let rule = RuleSpec {
        radius: 64,
        ..base_rule(
            "generic-api-key",
            &[b"gak_"],
            Regex::new(r"gak_[A-Z]{8}").unwrap(),
        )
    };
    let engine = Engine::new_with_anchor_policy(
        vec![rule],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );
    // Assignment pattern "api_key=" triggers the shape check.
    let hay = b"api_key=gak_ABCDEFGH end";
    let mut scratch = engine.new_scratch();
    engine.scan_chunk_into(hay, FileId(0), 0, &mut scratch);
    let recs = scratch.findings();
    assert_eq!(recs.len(), 1, "assignment-shape finding should be emitted");
    assert_eq!(
        recs[0].confidence_score,
        confidence::ASSIGNMENT_SHAPE,
        "assignment-shape gate should add ASSIGNMENT_SHAPE ({}) to score",
        confidence::ASSIGNMENT_SHAPE,
    );
}

fn stage1_generic_api_key_rule() -> RuleSpec {
    // Stage 1 requires entropy-backed confidence: assignment shape (2) + keyword (2)
    // tops out at 4, so min_confidence=5 forces an entropy contribution.
    RuleSpec {
        radius: 128,
        keywords_any: Some(&[b"api_key", b"token"]),
        entropy: Some(EntropySpec {
            min_bits_per_byte: 3.5,
            min_len: 16,
            max_len: 64,
            min_entropy_bits_per_byte: None,
            digit_penalty: false,
        }),
        min_confidence: Some(5),
        secret_group: None,
        ..base_rule(
            "generic-api-key",
            &[b"api_key", b"token"],
            Regex::new(r"(?i)(?:api_key|token)\s*=\s*([A-Za-z0-9_]{10,40})").unwrap(),
        )
    }
}

#[test]
fn generic_api_key_stage1_requires_measured_entropy_to_emit() {
    let engine = Engine::new_with_anchor_policy(
        vec![stage1_generic_api_key_rule()],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );
    assert_eq!(
        engine.rule_min_confidence(0),
        5,
        "stage1 generic-api-key rule should require confidence >= 5"
    );

    let mut scratch = engine.new_scratch();

    // Assignment + keyword + assignment-shape can only reach 4 when
    // entropy is not measured (len < 16), so this should be filtered.
    engine.scan_chunk_into(b"api_key=driver_probe suffix", FileId(0), 0, &mut scratch);
    assert!(
        scratch.findings().is_empty(),
        "generic-api-key should reject assignment/keyword evidence without measured entropy"
    );

    engine.scan_chunk_into(
        b"api_key=A1b2C3d4E5f6G7h8 suffix",
        FileId(1),
        0,
        &mut scratch,
    );
    let recs = scratch.findings();
    assert_eq!(recs.len(), 1, "measured-entropy token should emit");
    assert_eq!(
        recs[0].confidence_score,
        confidence::ASSIGNMENT_SHAPE + confidence::KEYWORD_PRESENT + confidence::ENTROPY_PASS,
        "stage1 generic-api-key score should include assignment+keyword+entropy signals"
    );
}

#[test]
fn generic_api_key_stage1_rejects_identifier_like_constant() {
    let engine = Engine::new_with_anchor_policy(
        vec![stage1_generic_api_key_rule()],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );
    let mut scratch = engine.new_scratch();
    engine.scan_chunk_into(
        b"token=CONFIG_CONFIG_CONFIG suffix",
        FileId(0),
        0,
        &mut scratch,
    );
    assert!(
        scratch.findings().is_empty(),
        "identifier-like constant should not survive stage1 generic-api-key thresholds"
    );
}

#[test]
fn keyword_entropy_auto_tier_requires_measured_entropy_evidence() {
    let rule = RuleSpec {
        radius: 128,
        keywords_any: Some(&[b"password"]),
        entropy: Some(EntropySpec {
            min_bits_per_byte: 2.0,
            min_len: 16,
            max_len: 64,
            min_entropy_bits_per_byte: None,
            digit_penalty: false,
        }),
        secret_group: Some(1),
        ..base_rule(
            "kw-ent-evidence",
            &[b"TOK_"],
            Regex::new(r"TOK_([A-Za-z0-9]{8,24})").unwrap(),
        )
    };
    let engine = Engine::new_with_anchor_policy(
        vec![rule],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );

    // Entropy bypass (len < 16): contributes 0, so score stays at keyword-only (2)
    // and fails the auto-derived keyword+entropy threshold (3).
    let mut scratch = engine.new_scratch();
    engine.scan_chunk_into(b"password TOK_A1b2C3d4 suffix", FileId(0), 0, &mut scratch);
    assert!(
        scratch.findings().is_empty(),
        "short-len entropy bypass should not satisfy kw+entropy auto-threshold"
    );

    // Measured entropy pass (len >= 16) + local keyword evidence => score 3 and emit.
    engine.scan_chunk_into(
        b"password TOK_A1b2C3d4E5f6G7h8 suffix",
        FileId(1),
        0,
        &mut scratch,
    );
    let recs = scratch.findings();
    assert_eq!(
        recs.len(),
        1,
        "measured entropy + keyword evidence should emit"
    );
    assert_eq!(
        recs[0].confidence_score,
        confidence::KEYWORD_PRESENT + confidence::ENTROPY_PASS,
        "auto-tier score should reflect measured entropy + local keyword evidence"
    );
    assert_eq!(
        engine.rule_min_confidence(0),
        confidence::KEYWORD_PRESENT + confidence::ENTROPY_PASS
    );
}

fn min_conf_rule(name: &'static str) -> RuleSpec {
    RuleSpec {
        radius: 64,
        secret_group: Some(1),
        ..base_rule(
            name,
            &[b"TOK_"],
            Regex::new(r"TOK_([A-Za-z0-9]{8})").unwrap(),
        )
    }
}

#[test]
fn rule_min_confidence_explicit_override_wins() {
    let mut rule = offline_crc_rule();
    rule.min_confidence = Some(7);
    let engine = Engine::new_with_anchor_policy(
        vec![rule],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );
    assert_eq!(engine.rule_min_confidence(0), 7);
}

#[test]
fn rule_min_confidence_offline_only_defaults_to_zero() {
    // Offline validation is excluded from auto-derivation because the
    // signal is only available on root-semantic findings. A rule with
    // only offline validation (no keyword/entropy gates) gets threshold 0.
    let engine = Engine::new_with_anchor_policy(
        vec![offline_crc_rule()],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );
    assert_eq!(engine.rule_min_confidence(0), 0);
}

#[test]
fn rule_min_confidence_keywords_plus_entropy_default_is_three() {
    let mut rule = min_conf_rule("kw-ent");
    rule.keywords_any = Some(&[b"password"]);
    rule.entropy = Some(EntropySpec {
        min_bits_per_byte: 2.0,
        min_len: 4,
        max_len: 32,
        min_entropy_bits_per_byte: None,
        digit_penalty: false,
    });
    let engine = Engine::new_with_anchor_policy(
        vec![rule],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );
    assert_eq!(
        engine.rule_min_confidence(0),
        confidence::KEYWORD_PRESENT + confidence::ENTROPY_PASS
    );
}

#[test]
fn rule_min_confidence_assignment_shape_default_is_two() {
    let rule = min_conf_rule("generic-api-key");
    let engine = Engine::new_with_anchor_policy(
        vec![rule],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );
    assert_eq!(engine.rule_min_confidence(0), confidence::ASSIGNMENT_SHAPE);
}

#[test]
fn rule_min_confidence_plain_rule_default_is_zero() {
    let engine = Engine::new_with_anchor_policy(
        vec![min_conf_rule("plain-rule")],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );
    assert_eq!(engine.rule_min_confidence(0), 0);
}

#[test]
fn rule_min_confidence_returns_zero_for_out_of_bounds_rule_id() {
    let engine = Engine::new_with_anchor_policy(
        vec![min_conf_rule("plain-rule")],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );
    assert_eq!(engine.rule_min_confidence(999), 0);
}

#[test]
fn rule_min_confidence_offline_plus_keywords_entropy_uses_keyword_tier() {
    // Offline validation is excluded from auto-derivation, so a rule with
    // offline + keywords + entropy falls through to the keyword+entropy
    // tier (3), not the offline tier (5).
    let mut rule = offline_crc_rule();
    rule.keywords_any = Some(&[b"password"]);
    rule.entropy = Some(EntropySpec {
        min_bits_per_byte: 2.0,
        min_len: 4,
        max_len: 32,
        min_entropy_bits_per_byte: None,
        digit_penalty: false,
    });
    let engine = Engine::new_with_anchor_policy(
        vec![rule],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );
    assert_eq!(
        engine.rule_min_confidence(0),
        confidence::KEYWORD_PRESENT + confidence::ENTROPY_PASS
    );
}

#[test]
fn transform_finding_confidence_meets_offline_rule_threshold() {
    // Offline validation is intentionally excluded from auto-derived min_confidence.
    // Transform-derived findings (non-root step) bypass offline validation, so
    // they cannot earn OFFLINE_VALID (+5). This regression test ensures the
    // effective threshold remains compatible with valid transform findings.
    let rule = offline_crc_rule();

    let transforms = vec![TransformConfig {
        id: TransformId::Base64,
        mode: TransformMode::Always,
        gate: Gate::AnchorsInDecoded,
        min_len: 8,
        max_spans_per_buffer: 8,
        max_encoded_len: 1024,
        max_decoded_bytes: 1024,
        plus_to_space: false,
        base64_allow_space_ws: false,
    }];

    let engine = Engine::new_with_anchor_policy(
        vec![rule],
        transforms,
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );

    // Build an invalid-CRC token and base64-encode it so the transform
    // decodes it. The decoded finding is non-root and gets no offline signal.
    let invalid_tok = build_invalid_crc_token();
    let b64_encoded = base64_encode_bytes(&invalid_tok);

    let mut hay = Vec::new();
    hay.extend_from_slice(b"data ");
    hay.extend_from_slice(&b64_encoded);
    hay.extend_from_slice(b" end");

    let mut scratch = engine.new_scratch();
    engine.scan_chunk_into(&hay, FileId(0), 0, &mut scratch);

    let threshold = engine.rule_min_confidence(0);
    let transform_findings: Vec<_> = scratch
        .findings()
        .iter()
        .filter(|r| r.step_id != STEP_ROOT)
        .collect();

    assert!(
        !transform_findings.is_empty(),
        "expected at least one transform-derived finding"
    );

    for f in &transform_findings {
        assert!(
            f.confidence_score >= threshold,
            "transform finding confidence {} is below rule threshold {} — \
             downstream policy would incorrectly drop this valid finding",
            f.confidence_score,
            threshold,
        );
    }
}

// ── UUID quick-reject integration tests ─────────────────────────────────

#[test]
fn uuid_quick_reject_suppresses_bare_uuid() {
    // Rule with uuid_format_secret=false, regex captures UUID-shaped value.
    // Extracted secret is a bare UUID → should be suppressed.
    let rule = RuleSpec {
        radius: 64,
        secret_group: Some(1),
        ..base_rule(
            "uuid-suppress-test",
            &[b"header"],
            Regex::new(r"header\s+(\S+)").unwrap(),
        )
    };

    let engine = Engine::new_with_anchor_policy(
        vec![rule],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );

    let mut scratch = engine.new_scratch();
    let hay = b"header 67e55044-10b1-426f-9247-bb680e5fe0c8 trailer";
    engine.scan_chunk_into(hay, FileId(0), 0, &mut scratch);

    assert_eq!(
        scratch.findings().len(),
        0,
        "UUID-format secret should be suppressed when uuid_format_secret=false"
    );
}

#[test]
fn uuid_quick_reject_bypassed_when_rule_captures_uuid_secrets() {
    // Same setup but uuid_format_secret=true → finding should be preserved.
    let rule = RuleSpec {
        radius: 64,
        secret_group: Some(1),
        uuid_format_secret: true,
        ..base_rule(
            "uuid-bypass-test",
            &[b"header"],
            Regex::new(r"header\s+(\S+)").unwrap(),
        )
    };

    let engine = Engine::new_with_anchor_policy(
        vec![rule],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );

    let mut scratch = engine.new_scratch();
    let hay = b"header 67e55044-10b1-426f-9247-bb680e5fe0c8 trailer";
    engine.scan_chunk_into(hay, FileId(0), 0, &mut scratch);

    assert_eq!(
        scratch.findings().len(),
        1,
        "UUID-format secret should be kept when uuid_format_secret=true"
    );
}

#[test]
fn digit_penalty_rejects_all_digit_secret() {
    // An all-digit string like "1234567890123456" has Shannon ~3.32 bpb,
    // which clears a 3.0 bpb threshold without penalty.  With
    // digit_penalty enabled the effective Shannon drops below 3.0 and the
    // finding should be rejected.
    let rule_penalty = RuleSpec {
        radius: 64,
        entropy: Some(EntropySpec {
            min_bits_per_byte: 3.0,
            min_len: 8,
            max_len: 64,
            min_entropy_bits_per_byte: None,
            digit_penalty: true,
        }),
        secret_group: Some(1),
        ..base_rule(
            "digit-penalty-on",
            &[b"NUM_"],
            Regex::new(r"NUM_([0-9]{16})").unwrap(),
        )
    };

    let rule_no_penalty = RuleSpec {
        entropy: Some(EntropySpec {
            digit_penalty: false,
            ..rule_penalty.entropy.clone().unwrap()
        }),
        ..base_rule(
            "digit-penalty-off",
            &[b"NUM_"],
            Regex::new(r"NUM_([0-9]{16})").unwrap(),
        )
    };

    let engine = Engine::new_with_anchor_policy(
        vec![rule_penalty, rule_no_penalty],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );

    let hits = scan_chunk_findings(&engine, b"prefix NUM_1234567890123456 suffix");

    assert!(
        !hits.iter().any(|h| h.rule == "digit-penalty-on"),
        "digit_penalty should reject all-digit secret that barely clears Shannon"
    );
    assert!(
        hits.iter().any(|h| h.rule == "digit-penalty-off"),
        "without digit_penalty the same all-digit secret should pass Shannon"
    );
}

/// Integration test: full `Engine::scan_chunk → window_validate → entropy_gate_outcome`
/// pipeline with `digit_penalty: true`.
///
/// An all-digit secret clears 3.0 bpb Shannon on its own but the penalty
/// pushes effective entropy below the threshold → rejected.  A mixed hex
/// secret of the same length is unaffected by the penalty → accepted.
#[test]
fn digit_penalty_integration_mixed_vs_all_digit() {
    let rule = RuleSpec {
        radius: 64,
        entropy: Some(EntropySpec {
            min_bits_per_byte: 3.0,
            min_len: 8,
            max_len: 32,
            min_entropy_bits_per_byte: None,
            digit_penalty: true,
        }),
        secret_group: Some(1),
        ..base_rule(
            "dp-hex",
            &[b"TOK_"],
            Regex::new(r"TOK_([A-Fa-f0-9]{10})").unwrap(),
        )
    };

    let engine = Engine::new_with_anchor_policy(
        vec![rule],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );

    // All-digit secret: Shannon ~3.32 bpb clears 3.0 without penalty, but
    // the digit-only penalty pushes it below → should be rejected.
    let all_digit = scan_chunk_findings(&engine, b"prefix TOK_0123456789 suffix");
    assert!(
        all_digit.is_empty(),
        "digit_penalty should reject all-digit secret in full pipeline"
    );

    // Mixed hex secret: penalty does not apply → should pass entropy gate.
    let mixed_hex = scan_chunk_findings(&engine, b"prefix TOK_0a1b2c3d4e suffix");
    assert!(
        !mixed_hex.is_empty(),
        "mixed hex secret should pass entropy gate despite digit_penalty being enabled"
    );
}
