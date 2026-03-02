//! Window-level validation against compiled rules.
//!
//! Purpose: run a compiled rule against a fixed-size window of bytes and record
//! findings while enforcing cheap gates and decode budgets.
//!
//! # Invariants
//! - Window ranges must be valid for the provided buffer.
//! - For `Variant::Raw`, match spans are in raw byte space; for UTF-16 variants,
//!   match spans are in decoded UTF-8 byte space.
//! - `root_hint` (when present) is expressed in the same coordinate space as
//!   `base_offset` and anchors findings back to the parent stream.
//!
//! # Algorithm
//! 1. Apply cheap byte gates (must-contain, confirm-all, keyword gate).
//!    For UTF-16 variants, confirm-all and keywords run on raw bytes *before*
//!    decode; must-contain runs on decoded UTF-8 *after* decode.
//! 2. Apply assignment-shape precheck (when configured).
//! 3. Apply character-class distribution gate (when configured) — SIMD-accelerated
//!    rejection of windows dominated by lowercase ASCII.
//! 4. For UTF-16 variants, decode with per-window and total-output budgets.
//!    Steps 2–3 run on the raw window for `Variant::Raw` but on the decoded
//!    UTF-8 buffer for UTF-16 variants (i.e., after this step).
//! 5. Run regex with reusable capture locations to access capture groups.
//! 6. Extract the secret span using capture group priority (see [`extract_secret_span_locs_raw`]).
//! 7. Apply entropy gate on the *extracted secret*. `Failed` vetoes the finding;
//!    the outcome is captured in [`GateEvidence`] for confidence scoring.
//! 8. Probe for keyword evidence in local context (±`KEYWORD_EVIDENCE_RADIUS` bytes
//!    around the full match). Result stored in [`GateEvidence`].
//! 9. Apply value suppressors (when configured) on the extracted secret bytes.
//! 10. Apply local context checks (when configured) on the secret span.
//! 11. Apply root-context safelist suppression for root emit paths.
//! 12. Apply secret-bytes safelist suppression (all findings, including decoded).
//! 13. Apply UUID-format quick-reject: suppress findings whose extracted value is
//!     a bare UUID (8-4-4-4-12 hex), unless the rule opts out via
//!     `uuid_format_secret()`.
//! 14. Apply offline structural validation (CRC, charset, etc.) for root-semantic findings.
//! 15. Compute additive confidence score from [`GateEvidence`], rule flags, and
//!     emit-policy outcome (see `compute_confidence_score`).
//! 16. Apply per-rule `min_confidence` threshold — suppress findings below floor.
//! 17. Record the finding with the extracted secret span.
//!
//! # Secret Extraction
//! The finding's `span_start`/`span_end` reflect the *secret* portion of the match,
//! not necessarily the full regex match. The `root_hint_*` fields use the *full match*
//! span (not secret span or window span) to ensure correct deduplication in chunked
//! scans: `drop_prefix_findings()` uses `root_hint_end` to decide whether to keep a
//! finding. Using the full match span handles trailing context correctly (e.g., when
//! a pattern like `secret([a-z]+)(?:;|$)` has a delimiter that extends into new bytes).
//!
//! The extraction priority is:
//! 1. Configured `secret_group` if present and non-empty.
//! 2. First non-empty capture group (1..N). Gitleaks convention places
//!    secrets in group 1, but rules with alternation (e.g., `curl-auth-header`)
//!    may fire a higher group.
//! 3. Full match (group 0) as fallback.
//!
//! # Design Choices
//! - Keyword/confirm gates run on raw UTF-16 bytes to avoid wasting decode budget.
//! - UTF-16 findings attach a `DecodeStep::Utf16Window` so callers can map
//!   decoded spans back to parent byte offsets.
//! - Capture locations are reused per rule to avoid per-match allocations in hot paths.
//! - Evidence collection (steps 7–8) is separated from scoring (step 15) so that
//!   suppress-only gates (steps 9–14) can veto a finding without computing a
//!   score, and all four emission sites share a single scoring function via
//!   [`GateEvidence`].
//!
//! # Entry Points
//! - `run_rule_on_window`: engine hot path that writes findings directly into
//!   `ScanScratch`, applying safelist suppression + dedupe/drop-hint bookkeeping.
//! - `run_rule_on_raw_window_into` / `run_rule_on_utf16_window_into`: scheduler
//!   adapters that accumulate findings in `scratch.tmp_findings` for the caller
//!   to batch-commit.
//!
//! [`extract_secret_span_locs_raw`]: super::helpers::extract_secret_span_locs_raw

use crate::api::{
    DecodeStep, FileId, FindingRec, LocalContextSpec, STEP_ROOT, StepId, Utf16Endianness,
    confidence,
};
use memchr::memmem;
use regex::bytes::CaptureLocations;
use std::ops::Range;

use super::core::Engine;
use super::helpers::{
    EntropyGateOutcome, contains_all_memmem, contains_any_memmem, decode_utf16be_to_buf,
    decode_utf16le_to_buf, entropy_gate_outcome, extract_secret_span_locs_raw,
    map_utf16_decoded_offset,
};
use super::rule_repr::{
    CharClassCompiled, ConfirmAllCompiled, EntropyCompiled, KeywordsCompiled, PackedPatterns,
    RuleCompiled, Variant,
};
use super::scratch::ScanScratch;

/// Gate references resolved once per (rule, variant) pair, then passed into
/// every `run_rule_on_window` / `run_rule_on_utf16_window_aligned` call for
/// the same rule.
///
/// Without this struct, LLVM may conservatively re-load gate pool references
/// after `&mut ScanScratch` mutations, even though Rust's aliasing rules
/// guarantee `&self` and `&mut ScanScratch` do not overlap. In practice,
/// the optimizer does not always exploit `noalias` through complex call
/// chains. Hoisting the lookups here keeps them in local variables that
/// LLVM can hold in registers across the per-window inner loop. This also
/// eliminates redundant `NO_GATE` sentinel checks and repeated pool indexing.
#[derive(Clone, Copy)]
pub(super) struct ResolvedGates<'e> {
    pub(super) confirm_all: Option<&'e ConfirmAllCompiled>,
    pub(super) keywords: Option<&'e KeywordsCompiled>,
    pub(super) entropy: Option<EntropyCompiled>,
    pub(super) char_class: Option<CharClassCompiled>,
    pub(super) value_suppressors: Option<&'e PackedPatterns>,
    pub(super) local_context: Option<LocalContextSpec>,
    pub(super) min_confidence: i8,
}

impl ResolvedGates<'_> {
    /// Returns `true` when the confidence score meets the rule's threshold.
    #[inline(always)]
    fn passes_threshold(&self, score: i8) -> bool {
        score >= self.min_confidence
    }
}

impl Engine {
    /// Resolves all per-window gates for a rule into stack-local references.
    ///
    /// Called once per (rule, variant) pair in `scan_rules_on_buffer` and the
    /// `*_into` staging paths, then the result is passed into every
    /// `run_rule_on_window` call for that pair. The resolved gates are
    /// rule-specific and do not vary by variant; the per-pair call frequency
    /// is an artifact of the loop structure, not a semantic requirement.
    /// See [`ResolvedGates`] for the optimization rationale.
    ///
    /// `rule_id` is required separately because `min_confidence` is stored in
    /// `rules_cold` (not in `RuleCompiled`) and resolved via
    /// [`rule_min_confidence`](Engine::rule_min_confidence).
    #[inline(always)]
    pub(super) fn resolve_gates(&self, rule_id: u32, rule: &RuleCompiled) -> ResolvedGates<'_> {
        let min_confidence = self.rule_min_confidence(rule_id);
        debug_assert!(
            (0..=10).contains(&min_confidence),
            "min_confidence {min_confidence} out of Phase 1 range for rule {rule_id}"
        );
        ResolvedGates {
            confirm_all: self.confirm_all_gate(rule.confirm_all),
            keywords: self.keyword_gate(rule.keywords),
            entropy: self.entropy_gate(rule.entropy),
            char_class: self.char_class_gate(rule.char_class),
            value_suppressors: self.value_suppressor_gate(rule.value_suppressors),
            local_context: self.local_context_gate(rule.local_context),
            min_confidence,
        }
    }
}

/// Bytes scanned backward from the anchor hint to find the regex match start.
///
/// Vectorscan's anchor hint points to the *anchor literal*, which may sit in
/// the middle or tail of the full regex match. For example, the pattern
/// `password\s*=\s*([A-Za-z0-9]+)` anchors on `password`, but the regex
/// can start earlier if preceded by context (line-start, key prefix, etc.).
///
/// 64 bytes exceeds the longest prefix observed in production rule sets while
/// adding negligible cost relative to typical 4–16 KiB window sizes. Doubling
/// this showed no additional matches in benchmarks.
const BACK_SCAN_MARGIN: usize = 64;
/// Bytes of context on each side of the full regex match scanned for keyword
/// evidence in confidence scoring.
///
/// The search window is `match_start - RADIUS .. match_end + RADIUS` (clamped
/// to buffer bounds). A hit within this radius awards `confidence::KEYWORD_PRESENT`
/// (+2). The value 32 is a pragmatic trade-off: large enough to catch
/// `key = <secret>` patterns where the key name sits before the match, but small
/// enough to avoid awarding score for unrelated keywords elsewhere in the buffer.
const KEYWORD_EVIDENCE_RADIUS: usize = 32;

/// Sidecar data computed by [`Engine::apply_emit_time_policy`] when a finding
/// survives safelist suppression and offline validation.
///
/// Callers pass these values to `push_finding_with_drop_hint` alongside the
/// `FindingRec` so that dedup and drop-prefix bookkeeping stay consistent.
#[derive(Clone, Copy)]
struct EmitPolicyOutcome {
    /// Absolute byte offset (in root-buffer coordinates) past which
    /// `drop_prefix_findings` should keep this finding. May be extended
    /// beyond the match span for URL-percent transforms with late triggers.
    drop_hint_end: u64,
    /// Whether the decoded span should participate in the dedup key.
    /// `true` for root findings (`emitted_step_id == STEP_ROOT`) and when
    /// no root-span mapping context is available;
    /// `false` for transform-derived findings when a root-span mapping
    /// exists, since mapping can shift decoded offsets across chunk boundaries.
    dedupe_with_span: bool,
    /// BLAKE3 digest of the raw secret bytes, used for cross-chunk and
    /// cross-run deduplication.
    norm_hash: [u8; 32],
    /// Whether offline structural validation returned [`OfflineVerdict::Valid`].
    /// Used by confidence scoring — `true` contributes [`confidence::OFFLINE_VALID`]
    /// to the finding's additive score.
    offline_verdict_valid: bool,
}

/// Per-finding evidence bundle consumed by [`compute_confidence_score`].
///
/// Constructed after entropy gating and keyword probing at each emission site,
/// then passed — together with [`RuleCompiled`] flags and [`EmitPolicyOutcome`]
/// — into confidence scoring. Only signals that require per-finding evaluation
/// are stored here; rule-level signals (e.g., assignment-shape) and emit-time
/// signals (e.g., offline validation) live in their respective structs.
///
/// # Design rationale
///
/// Separating evidence collection from scoring keeps the four structurally
/// identical emission sites (raw, UTF-16 direct, raw-into, UTF-16-into) in
/// sync: each builds a `GateEvidence`, and all share a single scoring function.
#[derive(Clone, Copy, Debug)]
struct GateEvidence {
    /// Entropy-gate decision for this finding's extracted secret bytes.
    ///
    /// `None` when no entropy gate is configured for the rule. `Some(Failed)`
    /// causes an early return before this struct is ever constructed, so in
    /// practice only `Some(PassedMeasured)` and `Some(BypassedShortLen)` appear.
    entropy_outcome: Option<EntropyGateOutcome>,
    /// Whether any rule keyword appears within [`KEYWORD_EVIDENCE_RADIUS`] bytes
    /// of the full regex match in the current buffer.
    keyword_local_hit: bool,
}

/// Iterate capture matches without allocating by reusing `CaptureLocations`.
///
/// This is the allocation-free alternative to `Regex::captures_iter`, which
/// allocates a fresh `Captures` per match. By reusing a single
/// `CaptureLocations`, the hot path stays in the per-rule scratch buffer
/// with zero heap traffic.
///
/// # Termination
/// - Returns when the regex finds no further match.
/// - Advances by one byte on empty-width matches to avoid infinite loops,
///   mirroring `captures_iter` semantics.
///
/// # Callback
/// `on_match(locs, start, end)` receives the full match span (`start..end`)
/// relative to `hay[0]`. Capture groups are accessible through `locs`.
///
/// # Preconditions
/// `locs` must have been created by `Regex::capture_locations()` for the same
/// `re`, ensuring it has enough slots for all capture groups. Callers borrow
/// `locs` out of `scratch.capture_locs[rule_id]` and must restore it after
/// the loop to keep the slot populated for the next invocation.
///
/// # Performance
/// O(hay.len() x regex_complexity) per call.
#[inline]
fn for_each_capture_match(
    re: &regex::bytes::Regex,
    locs: &mut CaptureLocations,
    hay: &[u8],
    mut on_match: impl FnMut(&CaptureLocations, usize, usize),
) {
    let mut at = 0usize;
    while at <= hay.len() {
        let Some(m) = re.captures_read_at(locs, hay, at) else {
            break;
        };
        on_match(locs, m.start(), m.end());
        if m.end() == at {
            at = at.saturating_add(1);
        } else {
            at = m.end();
        }
    }
}

/// Cheap precheck for rules with assignment-value patterns.
///
/// Returns `false` if the regex cannot possibly match because the window lacks
/// the necessary structure: a separator (`=`, `:`, `>`) followed by a plausible
/// token (10+ alphanumeric/underscore/hyphen/dot characters).
///
/// This is a conservative filter with **no false negatives**: a `false` return
/// guarantees the regex will not match. This guarantee holds because the check
/// is only enabled for rules whose patterns structurally require an assignment
/// separator and token run (see `needs_assignment_shape_check()`). False
/// positives are acceptable because the regex will reject them; the goal is to
/// skip the regex entirely on clearly irrelevant windows.
///
/// # Performance
/// O(window.len()) single-pass byte scan vs O(regex_complexity × window.len())
/// for the full regex. On production workloads, this rejects ~70–80% of
/// candidate windows for assignment-pattern rules.
#[inline]
fn has_assignment_value_shape(window: &[u8]) -> bool {
    // Find any assignment separator. We check for `=`, `:`, and `>` (for `=>`).
    // The position we find may be part of `=>`, but that's fine for our purpose.
    // Uses vectorized memchr3 (SIMD on x86/ARM) instead of byte-at-a-time scan.
    let sep_pos = match memchr::memchr3(b'=', b':', b'>', window) {
        Some(pos) => pos,
        None => return false,
    };

    // Check for plausible token run after separator (10+ alnum/underscore/hyphen/dot).
    let after_sep = &window[sep_pos + 1..];

    // Skip whitespace/quotes/extra separators after the separator.
    let token_start = after_sep
        .iter()
        .position(|&b| !matches!(b, b' ' | b'\t' | b'"' | b'\'' | b'`' | b'=' | b'>'))
        .unwrap_or(after_sep.len());

    if token_start >= after_sep.len() {
        return false;
    }

    // Count consecutive token chars.
    let token_bytes = &after_sep[token_start..];
    let token_len = token_bytes
        .iter()
        .take_while(|&&b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.')
        .count();

    // 10 is the minimum plausible secret length: shorter tokens are overwhelmingly
    // variable names or config values, not secrets. This threshold was chosen to
    // reject noise without risking false negatives on real API keys/tokens.
    token_len >= 10
}

/// Character-class distribution pre-filter: rejects windows dominated by
/// lowercase ASCII (e.g. prose, English variable names) that cannot be
/// high-entropy secrets.
///
/// Fails open for windows shorter than `spec.min_window_len` to avoid false
/// negatives on short matches. Uses integer cross-multiply to avoid float
/// division on the hot path.
///
/// # Design trade-off
///
/// This gate runs on the **full window**, not the extracted secret bytes.
/// The entropy gate, by contrast, runs post-extraction on secret bytes only.
/// Running char_class pre-regex avoids the regex cost entirely for prose
/// windows, but surrounding context (e.g., `password=`) contributes to the
/// classification. The generous default (`max_lower_pct: 95`) accommodates
/// this dilution.
#[inline]
fn char_class_gate_passes(window: &[u8], spec: CharClassCompiled) -> bool {
    if window.len() < spec.min_window_len as usize {
        return true; // fail-open for short windows
    }
    let profile = super::simd_classify::classify_window(window);
    // Integer cross-multiply avoids f32 division:
    // lower / total <= max_lower_pct / 100  ⟺  lower * 100 <= total * max_lower_pct
    // Use u64 throughout to avoid u32 truncation on the (theoretical) >4 GiB path.
    (profile.lower as u64) * 100 <= (window.len() as u64) * (spec.max_lower_pct as u64)
}

/// Returns the `(line_start, line_end)` byte offsets of the line containing
/// `secret_start`, searching within bounded lookaround windows.
///
/// - `line_start` — byte *after* the preceding `\n`, within `lookbehind` bytes.
/// - `line_end` — the `\n` byte itself (not past it).
///
/// Returns `None` when **either** boundary is not found within the lookaround.
/// This is intentional fail-open: at chunk/window edges where a newline might
/// exist just outside the scan window, the caller must allow the match to
/// avoid false negatives. The tradeoff is a rare false positive, which is
/// preferable to silently dropping a real finding.
#[inline]
fn find_line_bounds(
    hay: &[u8],
    secret_start: usize,
    lookbehind: usize,
    lookahead: usize,
) -> Option<(usize, usize)> {
    let back = secret_start.min(lookbehind);
    let scan_start = secret_start - back;
    let mut line_start = None;
    for i in (scan_start..secret_start).rev() {
        if hay[i] == b'\n' {
            line_start = Some(i + 1);
            break;
        }
    }

    let fwd_end = secret_start.saturating_add(lookahead).min(hay.len());
    let mut line_end = None;
    for (i, &b) in hay.iter().enumerate().take(fwd_end).skip(secret_start) {
        if b == b'\n' {
            line_end = Some(i);
            break;
        }
    }

    match (line_start, line_end) {
        (Some(start), Some(end)) => Some((start, end)),
        _ => None,
    }
}

/// Checks whether `line` contains any assignment separator (`=`, `:`, `>`).
///
/// Used by [`local_context_passes`] to enforce `require_same_line_assignment`.
/// Kept separate from `has_assignment_value_shape` because context checks
/// operate on the line *before* the secret, not on the full window.
#[inline]
fn has_assignment_sep(line: &[u8]) -> bool {
    line.iter().any(|&b| b == b'=' || b == b':' || b == b'>')
}

/// Returns `true` if `hay` contains any of the `needles` (short-circuit OR).
///
/// Used by [`local_context_passes`] for `key_names_any` matching. Each needle
/// is a key name literal; a single hit is sufficient to pass the gate.
#[inline]
fn contains_any_literal(hay: &[u8], needles: &[&[u8]]) -> bool {
    for &needle in needles {
        if memmem::find(hay, needle).is_some() {
            return true;
        }
    }
    false
}

/// Checks whether the secret at `hay[secret_start..secret_end]` is wrapped
/// in matching quote characters (`'`, `"`, or `` ` ``).
///
/// Returns `Some(true)` when the byte immediately before and after the secret
/// are the same quote character, `Some(false)` when they differ or aren't
/// quotes, and `None` when either boundary is out of bounds (fail-open).
#[inline]
fn is_quoted_at(hay: &[u8], secret_start: usize, secret_end: usize) -> Option<bool> {
    let left = secret_start.checked_sub(1)?;
    let ql = *hay.get(left)?;
    let qr = *hay.get(secret_end)?;
    let is_quote = ql == b'\'' || ql == b'"' || ql == b'`';
    Some(is_quote && ql == qr)
}

/// Bounded, fail-open local context gate.
///
/// Evaluates up to three orthogonal sub-gates in short-circuit order:
///
/// 1. **`require_quoted`** — secret must be wrapped in matching quote chars
///    (`'`, `"`, `` ` ``). Fail-open when boundary bytes are out of bounds.
/// 2. **`require_same_line_assignment`** — the line *before* the secret
///    (up to `lookbehind` bytes) must contain `=`, `:`, or `>`.
/// 3. **`key_names_any`** — the line before the secret must contain at
///    least one configured key-name literal (memmem).
///
/// Sub-gates 2 and 3 share a single `find_line_bounds` call.
///
/// Returns `false` only when a sub-gate **definitively** fails within the
/// bounded lookaround. When line boundaries are ambiguous (e.g., at window
/// edges), the function returns `true` — fail-open — because a false positive
/// is cheaper than a missed finding.
#[inline]
fn local_context_passes(
    window: &[u8],
    secret_start: usize,
    secret_end: usize,
    spec: LocalContextSpec,
) -> bool {
    if spec.require_quoted {
        match is_quoted_at(window, secret_start, secret_end) {
            Some(true) => {}
            Some(false) => return false,
            None => {}
        }
    }

    if spec.require_same_line_assignment || spec.key_names_any.is_some() {
        let bounds = find_line_bounds(window, secret_start, spec.lookbehind, spec.lookahead);
        let (line_start, line_end) = match bounds {
            Some(bounds) => bounds,
            None => return true,
        };

        let line_before_secret = &window[line_start..line_end.min(secret_start)];

        if spec.require_same_line_assignment && !has_assignment_sep(line_before_secret) {
            return false;
        }

        if let Some(keys) = spec.key_names_any {
            if !contains_any_literal(line_before_secret, keys) {
                return false;
            }
        }
    }

    true
}

/// Evaluates entropy-family gates on extracted secret bytes.
///
/// Returns `None` when no entropy gate is configured for this rule; otherwise
/// delegates to [`entropy_gate_outcome`] and returns the canonical decision.
///
/// Callers use the returned outcome in two ways:
/// 1. Hard-gate: `Some(Failed)` causes immediate discard of the finding.
/// 2. Evidence: the outcome is stored in [`GateEvidence::entropy_outcome`]
///    for confidence scoring.
#[inline]
fn post_match_entropy_outcome(
    entropy: Option<EntropyCompiled>,
    secret_bytes: &[u8],
    scratch: &mut ScanScratch,
    entropy_log2: &[f32],
) -> Option<EntropyGateOutcome> {
    let ent = entropy?;
    Some(entropy_gate_outcome(
        &ent,
        secret_bytes,
        scratch.ensure_entropy_scratch(),
        entropy_log2,
    ))
}

/// Returns true when any rule keyword appears in local context around the match.
///
/// Scans ±[`KEYWORD_EVIDENCE_RADIUS`] bytes around the full regex match
/// (`match_start..match_end`) using the rule's compiled keyword patterns.
/// Locality matters: a keyword on the same line as the secret is strong
/// evidence, but a keyword 500 bytes away is not. The bounded window avoids
/// false confidence boosts from unrelated context.
///
/// Returns `false` when no keywords are configured (`keywords` is `None`),
/// which means the rule does not participate in keyword evidence.
#[inline]
fn keyword_local_hit(
    hay: &[u8],
    match_start: usize,
    match_end: usize,
    keywords: Option<&PackedPatterns>,
) -> bool {
    let Some(keywords) = keywords else {
        return false;
    };
    let local_start = match_start.saturating_sub(KEYWORD_EVIDENCE_RADIUS);
    let local_end = match_end
        .saturating_add(KEYWORD_EVIDENCE_RADIUS)
        .min(hay.len());
    contains_any_memmem(&hay[local_start..local_end], keywords)
}

/// Computes an additive confidence score for a finding based on which
/// per-finding evidence signals were observed at emission time.
///
/// Each signal contributes a fixed weight defined in [`confidence`]:
/// - Measured entropy passed → `ENTROPY_PASS` (+1)
/// - Local keyword evidence hit → `KEYWORD_PRESENT` (+2)
/// - Assignment-shape check enabled → `ASSIGNMENT_SHAPE` (+2)
/// - Offline structural validation passed → `OFFLINE_VALID` (+5)
///
/// Suppress-only gates (must-contain, value-suppressors, safelists) contribute
/// zero because they only filter — they never add positive signal.
///
/// # Inputs
/// - `evidence`: per-finding entropy and keyword signals (see [`GateEvidence`]).
/// - `rule`: consulted for rule-level flags (`needs_assignment_shape_check`).
/// - `outcome`: consulted for the offline validation verdict.
///
/// # Output range
/// Phase 1 scores are clamped to `0..=10`. The theoretical maximum is 10
/// (entropy + keyword + assignment + offline). No current rule earns all
/// four signals simultaneously. Callers compare the result against
/// `ResolvedGates::min_confidence` for threshold filtering.
///
/// `#[inline(always)]` because the function is called on every finding
/// emission and the body is a short chain of branch-and-add operations
/// that benefits from inlining into each call-site.
#[inline(always)]
fn compute_confidence_score(
    evidence: &GateEvidence,
    rule: &RuleCompiled,
    outcome: &EmitPolicyOutcome,
) -> i8 {
    debug_assert!(
        !matches!(evidence.entropy_outcome, Some(EntropyGateOutcome::Failed)),
        "Failed entropy outcome should never reach confidence scoring"
    );
    let mut s: i8 = 0;
    if matches!(
        evidence.entropy_outcome,
        Some(EntropyGateOutcome::PassedMeasured)
    ) {
        s = s.saturating_add(confidence::ENTROPY_PASS);
    }
    if evidence.keyword_local_hit {
        s = s.saturating_add(confidence::KEYWORD_PRESENT);
    }
    if rule.needs_assignment_shape_check() {
        s = s.saturating_add(confidence::ASSIGNMENT_SHAPE);
    }
    if outcome.offline_verdict_valid {
        s = s.saturating_add(confidence::OFFLINE_VALID);
    }
    debug_assert!(s >= 0, "confidence score must be non-negative: {s}");
    debug_assert!(s <= 10, "confidence score exceeds max: {s}");
    s.clamp(0, 10)
}

/// Returns `true` when `staged` already contains a finding with the same
/// rule, span, and root-hint coordinates — i.e. the candidate is a duplicate
/// produced by overlapping VS prefilter windows that decode to the same region.
///
/// `step_id` is intentionally excluded from the comparison: raw and transform
/// findings at identical coordinates must both be staged because downstream
/// `replace_same_scan_duplicate` resolves raw-vs-transform priority.
///
/// This is staging-local dedup only. Global cross-window dedup happens in
/// `push_finding_with_drop_hint` → `replace_same_scan_duplicate`.
///
/// O(n) scan over `staged`, bounded by `max_findings_per_chunk`.
fn is_staging_duplicate(
    staged: &[FindingRec],
    rule_id: u32,
    span_start: u32,
    span_end: u32,
    root_hint_start: u64,
    root_hint_end: u64,
) -> bool {
    staged.iter().any(|f| {
        f.rule_id == rule_id
            && f.span_start == span_start
            && f.span_end == span_end
            && f.root_hint_start == root_hint_start
            && f.root_hint_end == root_hint_end
    })
}

impl Engine {
    /// Runs a compiled rule against one window and appends findings into `scratch`.
    ///
    /// This is the engine hot-path entry point. It dispatches on `variant`:
    /// - `Variant::Raw` — gates and regex run directly on the window bytes.
    /// - `Variant::Utf16Le` / `Utf16Be` — tries both byte parities (hinted
    ///   parity first), decoding each alignment to UTF-8 before regex matching.
    ///
    /// Findings are committed directly into `scratch` (dedup state, output
    /// vectors, drop-hint bookkeeping). Use the `*_into` methods instead when
    /// the caller needs staging semantics (commit/rollback).
    ///
    /// # Guarantees
    /// - `w` must be a valid range into `buf`.
    /// - For `Variant::Raw`, spans are expressed in raw `buf` byte space.
    /// - For UTF-16 variants, spans are in decoded UTF-8 byte space and the
    ///   parent raw span is recorded via `DecodeStep::Utf16Window`.
    /// - `root_hint`, when provided, is expected to be in the same coordinate
    ///   space as `buf`/`w` and is used as a fallback root span when no
    ///   root-span mapping context is active.
    /// - `anchor_hint` is the byte offset (in `buf` coordinates) where Vectorscan
    ///   reported the match start. Regex search starts near this position with
    ///   a back-scan margin for correctness.
    ///
    /// # Early returns
    /// - Returns without findings when gates fail, decode budgets are exhausted,
    ///   or decoding fails.
    /// - Findings may be suppressed at emit-time by safelist policy, UUID-format
    ///   quick-reject, or offline structural validation.
    /// - Surviving findings are still dropped when the computed additive
    ///   confidence score is below the rule's `min_confidence` threshold.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn run_rule_on_window(
        &self,
        rule_id: u32,
        rule: &RuleCompiled,
        variant: Variant,
        buf: &[u8],
        w: Range<usize>,
        step_id: StepId,
        root_hint: Option<Range<usize>>,
        base_offset: u64,
        file_id: FileId,
        scratch: &mut ScanScratch,
        anchor_hint: usize,
        gates: &ResolvedGates<'_>,
    ) {
        match variant {
            Variant::Raw => {
                let window = &buf[w.clone()];

                if let Some(needle) = rule.must_contain {
                    if memmem::find(window, needle).is_none() {
                        return;
                    }
                }

                if let Some(confirm) = gates.confirm_all {
                    let vidx = Variant::Raw.idx();
                    if let Some(primary) = &confirm.primary[vidx] {
                        if memmem::find(window, primary).is_none() {
                            return;
                        }
                    }
                    if !contains_all_memmem(window, &confirm.rest[vidx]) {
                        return;
                    }
                }

                if let Some(kws) = gates.keywords {
                    // Keyword gate is a cheap pre-regex filter: if none of the
                    // keywords appear in this window, the regex cannot be relevant.
                    if !contains_any_memmem(window, &kws.any[Variant::Raw.idx()]) {
                        return;
                    }
                }

                // Assignment-shape precheck: skip regex if window lacks required structure.
                if rule.needs_assignment_shape_check() && !has_assignment_value_shape(window) {
                    return;
                }

                // Character-class distribution gate: reject windows dominated by
                // lowercase ASCII (prose, variable names) that cannot be secrets.
                if let Some(cc) = gates.char_class {
                    if !char_class_gate_passes(window, cc) {
                        return;
                    }
                }

                // Compute search start based on anchor hint with back-scan margin.
                // Gates still run on full window for correctness, but regex starts near anchor.
                let hint_in_window = anchor_hint.saturating_sub(w.start);
                let search_start = hint_in_window.saturating_sub(BACK_SCAN_MARGIN);
                let search_window = &window[search_start..];

                let entropy = gates.entropy;
                let keyword_evidence_patterns =
                    gates.keywords.map(|kws| &kws.any[Variant::Raw.idx()]);
                let value_suppressors = gates.value_suppressors;
                let secret_group_raw = rule.secret_group_raw();
                let has_secret_group_override = rule.has_secret_group_override();
                let mut last_safelist_decision: Option<(u64, u64, bool)> = None;
                // Take the pre-allocated CaptureLocations out of scratch so the
                // closure can borrow `locs` mutably without also borrowing `scratch`.
                // Restored after the loop to keep the slot populated for the next call.
                let mut locs = scratch.capture_locs[rule_id as usize]
                    .take()
                    .expect("capture locations missing for rule");
                for_each_capture_match(&rule.re, &mut locs, search_window, |locs, start, end| {
                    // Get full match span for anchor hint.
                    let match_start = search_start + start;
                    let match_end = search_start + end;

                    // Extract secret span first so entropy is evaluated on the
                    // secret itself, not the full match which includes non-secret
                    // context (key names, assignment operators, quotes).
                    let (secret_start, secret_end) = extract_secret_span_locs_raw(
                        locs,
                        secret_group_raw,
                        has_secret_group_override,
                    );
                    let secret_start = search_start + secret_start;
                    let secret_end = search_start + secret_end;
                    let secret_bytes = &window[secret_start..secret_end];

                    let entropy_outcome = post_match_entropy_outcome(
                        entropy,
                        secret_bytes,
                        scratch,
                        &self.entropy_log2,
                    );
                    if matches!(entropy_outcome, Some(EntropyGateOutcome::Failed)) {
                        return;
                    }
                    let evidence = GateEvidence {
                        entropy_outcome,
                        keyword_local_hit: keyword_local_hit(
                            window,
                            match_start,
                            match_end,
                            keyword_evidence_patterns,
                        ),
                    };

                    // Value suppressor gate: discard findings whose extracted
                    // secret contains a known placeholder/example pattern.
                    if let Some(vs) = value_suppressors {
                        if contains_any_memmem(secret_bytes, vs) {
                            return;
                        }
                    }

                    let context_ok = if let Some(ctx) = gates.local_context {
                        local_context_passes(window, secret_start, secret_end, ctx)
                    } else {
                        true
                    };

                    if context_ok {
                        let span_in_buf = (w.start + secret_start)..(w.start + secret_end);
                        let match_span_in_buf = (w.start + match_start)..(w.start + match_end);
                        // Root hint uses the FULL MATCH span (group 0), not the secret or
                        // window span. `drop_prefix_findings()` compares `root_hint_end`
                        // against the chunk overlap boundary:
                        // - Prefilter window span → too wide → false duplicates.
                        // - Secret span → too narrow → misses findings whose trailing
                        //   context (e.g., `;` delimiter) extends into the next chunk.
                        // - Full match span → correct extent of the regex match.
                        let root_span_hint = if let Some(ctx) = scratch.root_span_map_ctx.as_ref() {
                            ctx.map_span(match_span_in_buf.clone())
                        } else {
                            root_hint.clone().unwrap_or(match_span_in_buf)
                        };
                        let root_hint_start = base_offset + root_span_hint.start as u64;
                        let root_hint_end = base_offset + root_span_hint.end as u64;
                        let Some(outcome) = self.apply_emit_time_policy(
                            rule,
                            secret_bytes,
                            step_id,
                            step_id,
                            buf,
                            base_offset,
                            base_offset,
                            &root_span_hint,
                            root_hint_start,
                            root_hint_end,
                            &mut last_safelist_decision,
                            scratch,
                        ) else {
                            return;
                        };
                        let confidence_score = compute_confidence_score(&evidence, rule, &outcome);
                        if !gates.passes_threshold(confidence_score) {
                            crate::perf_stats::sat_add_usize(&mut scratch.confidence_suppressed, 1);
                            return;
                        }
                        scratch.push_finding_with_drop_hint(
                            FindingRec {
                                file_id,
                                rule_id,
                                span_start: span_in_buf.start as u32,
                                span_end: span_in_buf.end as u32,
                                root_hint_start,
                                root_hint_end,
                                dedupe_with_span: outcome.dedupe_with_span,
                                step_id,
                                confidence_score,
                            },
                            outcome.norm_hash,
                            outcome.drop_hint_end,
                            outcome.dedupe_with_span,
                        );
                    }
                });
                scratch.capture_locs[rule_id as usize] = Some(locs);
            }

            Variant::Utf16Le | Variant::Utf16Be => {
                // UTF-16 code units are 2-byte aligned, so decoding must start on the
                // correct byte parity (even vs odd offset within the window). The anchor
                // hint gives one parity. Merged windows may contain anchors at both
                // parities, so we decode both: hinted parity first (most likely to
                // produce findings), then the opposite. Each parity gets its own decode
                // budget check to avoid wasting resources.
                let parity = anchor_hint.saturating_sub(w.start) & 1;
                let offsets = [parity, parity ^ 1];
                for offset in offsets {
                    let decode_start = w.start.saturating_add(offset);
                    if decode_start >= w.end {
                        continue;
                    }
                    let decode_range = decode_start..w.end;
                    self.run_rule_on_utf16_window_aligned(
                        rule_id,
                        rule,
                        variant,
                        buf,
                        decode_range,
                        step_id,
                        root_hint.clone(),
                        base_offset,
                        file_id,
                        scratch,
                        gates,
                    );
                    if scratch.total_decode_output_bytes
                        >= self.tuning.max_total_decode_output_bytes
                    {
                        break;
                    }
                }
            }
        }
    }

    /// Validates one UTF-16-aligned decode range and writes findings directly.
    ///
    /// Called by [`run_rule_on_window`] for each byte parity. The caller is
    /// responsible for trying both even/odd alignments; this method assumes
    /// `decode_range` already starts on a code-unit boundary.
    ///
    /// # Guarantees
    /// - `decode_range` must start on a UTF-16 code-unit boundary (even byte
    ///   offset for LE, the correct parity for BE).
    /// - Findings are emitted in decoded UTF-8 byte space and annotated with
    ///   `DecodeStep::Utf16Window` so callers can recover parent raw spans.
    /// - Root span hints are derived from full-match extents after mapping
    ///   decoded offsets back into raw UTF-16 bytes via
    ///   [`map_utf16_decoded_offset`].
    ///
    /// # Gate ordering for UTF-16
    /// Confirm-all and keyword gates run on **raw** UTF-16 bytes (pre-decode)
    /// to avoid wasting decode budget. Must-contain, assignment-shape, and
    /// char_class gates run on **decoded** UTF-8 bytes (post-decode). The
    /// remaining gates (regex, entropy, value suppressor, local context,
    /// safelist, UUID reject, offline validation) operate on the decoded
    /// representation. After emit-time policy passes, confidence is scored and
    /// compared against `min_confidence` before emission.
    ///
    /// # Step ID distinction
    /// Context-window safelist suppression uses the emitted `utf16_step_id`
    /// (which is never `STEP_ROOT`, so root-only context checks are skipped).
    /// Offline validation uses the **parent** `step_id` so root-level UTF-16
    /// findings (`parent == STEP_ROOT`) are correctly validated.
    #[allow(clippy::too_many_arguments)]
    fn run_rule_on_utf16_window_aligned(
        &self,
        rule_id: u32,
        rule: &RuleCompiled,
        variant: Variant,
        buf: &[u8],
        decode_range: Range<usize>,
        step_id: StepId,
        root_hint: Option<Range<usize>>,
        base_offset: u64,
        file_id: FileId,
        scratch: &mut ScanScratch,
        gates: &ResolvedGates<'_>,
    ) {
        let remaining = self
            .tuning
            .max_total_decode_output_bytes
            .saturating_sub(scratch.total_decode_output_bytes);
        if remaining == 0 {
            return;
        }

        let raw_win = &buf[decode_range.clone()];

        if let Some(confirm) = gates.confirm_all {
            // Confirm-all literals are encoded like anchors/keywords so we can
            // cheaply reject UTF-16 windows before decoding.
            let vidx = variant.idx();
            if let Some(primary) = &confirm.primary[vidx] {
                if memmem::find(raw_win, primary).is_none() {
                    return;
                }
            }
            if !contains_all_memmem(raw_win, &confirm.rest[vidx]) {
                return;
            }
        }

        if let Some(kws) = gates.keywords {
            // For UTF-16 variants, apply the keyword gate on the raw UTF-16 bytes
            // *before* decoding to avoid spending decode budget on windows that
            // could never pass the keyword check.
            let vidx = variant.idx();
            if !contains_any_memmem(raw_win, &kws.any[vidx]) {
                return;
            }
        }

        let max_out = self
            .tuning
            .max_utf16_decoded_bytes_per_window
            .min(remaining);

        let decoded = match variant {
            Variant::Utf16Le => decode_utf16le_to_buf(raw_win, max_out, &mut scratch.utf16_buf),
            Variant::Utf16Be => decode_utf16be_to_buf(raw_win, max_out, &mut scratch.utf16_buf),
            _ => unreachable!(),
        };

        if decoded.is_err() {
            return;
        }

        // Reborrow `utf16_buf` through a raw pointer so that `decoded` does not
        // hold an immutable borrow on all of `scratch`, which would prevent the
        // mutable borrows needed by `push_finding_with_drop_hint` and friends.
        //
        // SAFETY:
        // 1. `utf16_buf` was just populated; its length and backing allocation
        //    are stable for the remainder of this function.
        // 2. No code path between here and the last use of `decoded` writes to,
        //    resizes, or reallocates `utf16_buf`. Mutations below touch other
        //    scratch fields (`out`, `drop_hint_end`, `seen_findings`,
        //    `safelist_suppressed`, `offline_suppressed`,
        //    `total_decode_output_bytes`, `capture_locs`) but never `utf16_buf`.
        // 3. Pointer and length are captured before any subsequent mutation.
        let decoded_len = scratch.utf16_buf.len();
        let decoded_ptr = scratch.utf16_buf.as_slice().as_ptr();
        // SAFETY: See the 3-point justification above — `utf16_buf` is not
        // mutated while this slice reference is live.
        let decoded = unsafe { std::slice::from_raw_parts(decoded_ptr, decoded_len) };
        if decoded.is_empty() {
            return;
        }

        scratch.total_decode_output_bytes = scratch
            .total_decode_output_bytes
            .saturating_add(decoded.len());
        if scratch.total_decode_output_bytes > self.tuning.max_total_decode_output_bytes {
            return;
        }

        if let Some(needle) = rule.must_contain {
            if memmem::find(decoded, needle).is_none() {
                return;
            }
        }

        // Assignment-shape precheck on decoded UTF-8 bytes.
        if rule.needs_assignment_shape_check() && !has_assignment_value_shape(decoded) {
            return;
        }

        // Character-class distribution gate on decoded bytes.
        if let Some(cc) = gates.char_class {
            if !char_class_gate_passes(decoded, cc) {
                return;
            }
        }

        let endianness = match variant {
            Variant::Utf16Le => Utf16Endianness::Le,
            Variant::Utf16Be => Utf16Endianness::Be,
            Variant::Raw => unreachable!("raw variant in UTF-16 branch"),
        };
        let utf16_step_id = scratch.step_arena.push(
            step_id,
            DecodeStep::Utf16Window {
                endianness,
                parent_span: decode_range.clone(),
            },
        );

        let entropy = gates.entropy;
        let keyword_evidence_patterns = gates.keywords.map(|kws| &kws.any[Variant::Raw.idx()]);
        let value_suppressors = gates.value_suppressors;
        let secret_group_raw = rule.secret_group_raw();
        let has_secret_group_override = rule.has_secret_group_override();
        let mut last_safelist_decision: Option<(u64, u64, bool)> = None;
        let mut locs = scratch.capture_locs[rule_id as usize]
            .take()
            .expect("capture locations missing for rule");
        for_each_capture_match(&rule.re, &mut locs, decoded, |locs, start, end| {
            let span = start..end;

            // Extract secret span first so entropy is evaluated on the
            // secret itself, not the full match (see raw-path comment).
            let (secret_start, secret_end) =
                extract_secret_span_locs_raw(locs, secret_group_raw, has_secret_group_override);
            let secret_bytes = &decoded[secret_start..secret_end];

            let entropy_outcome =
                post_match_entropy_outcome(entropy, secret_bytes, scratch, &self.entropy_log2);
            if matches!(entropy_outcome, Some(EntropyGateOutcome::Failed)) {
                return;
            }
            let evidence = GateEvidence {
                entropy_outcome,
                keyword_local_hit: keyword_local_hit(
                    decoded,
                    span.start,
                    span.end,
                    keyword_evidence_patterns,
                ),
            };

            // Value suppressor gate (see raw-path comment for rationale).
            if let Some(vs) = value_suppressors {
                if contains_any_memmem(secret_bytes, vs) {
                    return;
                }
            }

            let context_ok = if let Some(ctx) = gates.local_context {
                local_context_passes(decoded, secret_start, secret_end, ctx)
            } else {
                true
            };

            if context_ok {
                // Map decoded UTF-8 match span back to raw UTF-16 byte offsets.
                let match_raw_start = map_utf16_decoded_offset(
                    raw_win,
                    span.start,
                    matches!(variant, Variant::Utf16Le),
                );
                let match_raw_end = map_utf16_decoded_offset(
                    raw_win,
                    span.end,
                    matches!(variant, Variant::Utf16Le),
                );
                let mapped_span =
                    (decode_range.start + match_raw_start)..(decode_range.start + match_raw_end);
                // Apply root_span_map_ctx for transform-derived findings (same as Raw variant)
                // to ensure each UTF-16 match gets a distinct root hint for deduplication.
                let root_span_hint = if let Some(ctx) = scratch.root_span_map_ctx.as_ref() {
                    ctx.map_span(mapped_span.clone())
                } else {
                    root_hint.clone().unwrap_or(mapped_span)
                };
                let root_hint_start = base_offset + root_span_hint.start as u64;
                let root_hint_end = base_offset + root_span_hint.end as u64;
                // Use the parent step_id (not utf16_step_id) for offline validation:
                // root UTF-16 findings have parent == STEP_ROOT.
                let Some(outcome) = self.apply_emit_time_policy(
                    rule,
                    secret_bytes,
                    utf16_step_id,
                    step_id,
                    buf,
                    base_offset,
                    base_offset,
                    &root_span_hint,
                    root_hint_start,
                    root_hint_end,
                    &mut last_safelist_decision,
                    scratch,
                ) else {
                    return;
                };
                let confidence_score = compute_confidence_score(&evidence, rule, &outcome);
                if !gates.passes_threshold(confidence_score) {
                    crate::perf_stats::sat_add_usize(&mut scratch.confidence_suppressed, 1);
                    return;
                }
                scratch.push_finding_with_drop_hint(
                    FindingRec {
                        file_id,
                        rule_id,
                        span_start: secret_start as u32,
                        span_end: secret_end as u32,
                        root_hint_start,
                        root_hint_end,
                        dedupe_with_span: outcome.dedupe_with_span,
                        step_id: utf16_step_id,
                        confidence_score,
                    },
                    outcome.norm_hash,
                    outcome.drop_hint_end,
                    outcome.dedupe_with_span,
                );
            }
        });
        scratch.capture_locs[rule_id as usize] = Some(locs);
    }

    /// Validates a raw decoded-space window and stages findings in `scratch.tmp_*`.
    ///
    /// Staging variant of the raw path in [`run_rule_on_window`]. Findings are
    /// appended to `tmp_findings`, `tmp_drop_hint_end`, and `tmp_norm_hash`
    /// instead of being committed directly into dedup state. The caller
    /// (scheduler stream driver) decides whether to commit or roll back the
    /// batch after all rules for the current buffer have run.
    ///
    /// # Guarantees
    /// - `window_start` is the decoded-stream offset for `window[0]`.
    /// - Span offsets in findings are expressed in decoded-stream byte space.
    /// - `root_hint`, when present, is in the same coordinate space as
    ///   `base_offset` and is used as a fallback root span when no root-span
    ///   mapping context is active.
    /// - `anchor_hint` is the decoded-stream offset where Vectorscan reported the
    ///   match start. Regex search starts near this position with a back-scan margin.
    ///
    /// # Effects
    /// - Sets `found_any` when any match passes gates, emit-time policy,
    ///   and the `min_confidence` threshold.
    ///   Suppressed findings do not set `found_any`, ensuring
    ///   `IfNoFindingsInThisBuffer` transforms can still run.
    /// - Findings may be suppressed by the context-window safelist when emitted
    ///   `step_id == STEP_ROOT`, by the secret-bytes safelist (all findings),
    ///   UUID-format quick-reject, and by offline structural validation for
    ///   root-semantic findings (`parent_step_id == STEP_ROOT`).
    #[allow(clippy::too_many_arguments)]
    pub(super) fn run_rule_on_raw_window_into(
        &self,
        rule_id: u32,
        rule: &RuleCompiled,
        window: &[u8],
        window_start: u64,
        step_id: StepId,
        root_hint: &Option<Range<usize>>,
        base_offset: u64,
        file_id: FileId,
        scratch: &mut ScanScratch,
        found_any: &mut bool,
        anchor_hint: u64,
        gates: &ResolvedGates<'_>,
    ) {
        if let Some(needle) = rule.must_contain {
            if memmem::find(window, needle).is_none() {
                return;
            }
        }

        if let Some(confirm) = gates.confirm_all {
            let vidx = Variant::Raw.idx();
            if let Some(primary) = &confirm.primary[vidx] {
                if memmem::find(window, primary).is_none() {
                    return;
                }
            }
            if !contains_all_memmem(window, &confirm.rest[vidx]) {
                return;
            }
        }

        if let Some(kws) = gates.keywords {
            if !contains_any_memmem(window, &kws.any[Variant::Raw.idx()]) {
                return;
            }
        }

        // Assignment-shape precheck: skip regex if window lacks required structure.
        if rule.needs_assignment_shape_check() && !has_assignment_value_shape(window) {
            return;
        }

        // Character-class distribution gate.
        if let Some(cc) = gates.char_class {
            if !char_class_gate_passes(window, cc) {
                return;
            }
        }

        // Compute search start based on anchor hint with back-scan margin.
        // Gates still run on full window for correctness, but regex starts near anchor.
        let hint_in_window = anchor_hint.saturating_sub(window_start) as usize;
        let search_start = hint_in_window.saturating_sub(BACK_SCAN_MARGIN);
        let search_window = &window[search_start..];

        let entropy = gates.entropy;
        let keyword_evidence_patterns = gates.keywords.map(|kws| &kws.any[Variant::Raw.idx()]);
        let value_suppressors = gates.value_suppressors;
        let secret_group_raw = rule.secret_group_raw();
        let has_secret_group_override = rule.has_secret_group_override();
        let mut last_safelist_decision: Option<(u64, u64, bool)> = None;
        let mut locs = scratch.capture_locs[rule_id as usize]
            .take()
            .expect("capture locations missing for rule");
        for_each_capture_match(&rule.re, &mut locs, search_window, |locs, start, end| {
            // Adjust match offsets back to window coordinates.
            let match_start = search_start + start;
            let match_end = search_start + end;

            // Extract secret span first so entropy is evaluated on the
            // secret itself, not the full match (see raw-path comment in
            // run_rule_on_window for rationale).
            let (secret_start, secret_end) =
                extract_secret_span_locs_raw(locs, secret_group_raw, has_secret_group_override);
            let secret_start = search_start + secret_start;
            let secret_end = search_start + secret_end;
            let secret_bytes = &window[secret_start..secret_end];

            let entropy_outcome =
                post_match_entropy_outcome(entropy, secret_bytes, scratch, &self.entropy_log2);
            if matches!(entropy_outcome, Some(EntropyGateOutcome::Failed)) {
                return;
            }
            let evidence = GateEvidence {
                entropy_outcome,
                keyword_local_hit: keyword_local_hit(
                    window,
                    match_start,
                    match_end,
                    keyword_evidence_patterns,
                ),
            };

            // Value suppressor gate (see raw-path comment for rationale).
            if let Some(vs) = value_suppressors {
                if contains_any_memmem(secret_bytes, vs) {
                    return;
                }
            }

            let context_ok = if let Some(ctx) = gates.local_context {
                local_context_passes(window, secret_start, secret_end, ctx)
            } else {
                true
            };

            if context_ok {
                let span_start = window_start.saturating_add(secret_start as u64) as usize;
                let span_end = window_start.saturating_add(secret_end as u64) as usize;
                let span_in_buf = span_start..span_end;
                // Use FULL MATCH span for root_span_hint (see Raw variant comment for rationale).
                let match_hint_start = window_start.saturating_add(match_start as u64) as usize;
                let match_hint_end = window_start.saturating_add(match_end as u64) as usize;
                let match_span_in_buf = match_hint_start..match_hint_end;
                let root_span_hint = if let Some(ctx) = scratch.root_span_map_ctx.as_ref() {
                    ctx.map_span(match_span_in_buf.clone())
                } else {
                    root_hint.clone().unwrap_or(match_span_in_buf)
                };
                let root_hint_start = base_offset + root_span_hint.start as u64;
                let root_hint_end = base_offset + root_span_hint.end as u64;
                let Some(outcome) = self.apply_emit_time_policy(
                    rule,
                    secret_bytes,
                    step_id,
                    step_id,
                    window,
                    base_offset,
                    base_offset.saturating_add(window_start),
                    &root_span_hint,
                    root_hint_start,
                    root_hint_end,
                    &mut last_safelist_decision,
                    scratch,
                ) else {
                    return;
                };
                let confidence_score = compute_confidence_score(&evidence, rule, &outcome);
                if !gates.passes_threshold(confidence_score) {
                    crate::perf_stats::sat_add_usize(&mut scratch.confidence_suppressed, 1);
                    return;
                }
                // Streaming decode can produce overlapping windows for the
                // same (rule, variant) when the VS prefilter fires at adjacent
                // match-end offsets. After clamping, these windows cover the
                // same decoded region and yield identical regex matches. Skip
                // the duplicate to avoid pushing two findings with the same
                // coordinates into the staging buffer.
                if is_staging_duplicate(
                    scratch.tmp_findings.as_slice(),
                    rule_id,
                    span_in_buf.start as u32,
                    span_in_buf.end as u32,
                    root_hint_start,
                    root_hint_end,
                ) {
                    return;
                }

                // Set found_any only for findings that are actually staged.
                // Suppressed findings (emit-time policy or confidence threshold)
                // must not prevent IfNoFindingsInThisBuffer transforms from running.
                *found_any = true;
                scratch.tmp_findings.push(FindingRec {
                    file_id,
                    rule_id,
                    span_start: span_in_buf.start as u32,
                    span_end: span_in_buf.end as u32,
                    root_hint_start,
                    root_hint_end,
                    dedupe_with_span: outcome.dedupe_with_span,
                    step_id,
                    confidence_score,
                });
                scratch.tmp_drop_hint_end.push(outcome.drop_hint_end);
                scratch.tmp_norm_hash.push(outcome.norm_hash);
            }
        });
        scratch.capture_locs[rule_id as usize] = Some(locs);
    }

    /// Validates a UTF-16 window by decoding to UTF-8 and staging findings.
    ///
    /// Staging variant of [`run_rule_on_utf16_window_aligned`]. Applies the
    /// same gate sequence (pre-decode raw gates, decode, post-decode gates,
    /// regex, emit-time policy, confidence threshold) but writes to `tmp_*` staging buffers instead
    /// of committing directly. See that method for the full gate ordering and
    /// safety justification for the `utf16_buf` raw-pointer reborrow.
    ///
    /// # Guarantees
    /// - `window_start` is the decoded-stream offset for `raw_win[0]`.
    /// - Spans recorded in findings are in decoded UTF-8 byte space.
    /// - An attached [`DecodeStep::Utf16Window`] records the raw UTF-16 parent
    ///   span in decoded-stream byte offsets.
    /// - `root_hint`, when present, is in the same coordinate space as
    ///   `base_offset` and is used as a fallback root span when no root-span
    ///   mapping context is active.
    ///
    /// # Effects
    /// - Sets `found_any` when any match passes gates, emit-time policy,
    ///   and the `min_confidence` threshold.
    ///   Suppressed findings do not set `found_any`, preserving
    ///   `IfNoFindingsInThisBuffer` transform semantics.
    /// - Context-window safelist suppression checks the emitted step
    ///   (`utf16_step_id`), so UTF-16 emissions bypass root-only context checks.
    ///   The secret-bytes safelist and UUID reject still apply to all findings
    ///   regardless of step, catching placeholder values in decoded buffers.
    /// - Findings may be suppressed by offline structural validation using the
    ///   parent `step_id` (not `utf16_step_id`) for root-semantic detection.
    /// - Appends into staging buffers only; commit vs rollback is handled by
    ///   the stream driver.
    ///
    /// # Early returns
    /// Returns without findings when decode budgets are exhausted or decoding
    /// produces no output.
    #[allow(clippy::too_many_arguments)]
    fn run_rule_on_utf16_window_aligned_into(
        &self,
        rule_id: u32,
        rule: &RuleCompiled,
        variant: Variant,
        raw_win: &[u8],
        window_start: u64,
        step_id: StepId,
        root_hint: &Option<Range<usize>>,
        base_offset: u64,
        file_id: FileId,
        scratch: &mut ScanScratch,
        found_any: &mut bool,
        gates: &ResolvedGates<'_>,
    ) {
        // Contract mirrors `run_rule_on_utf16_window_aligned` but writes into
        // staging vectors (`tmp_findings` and friends) instead of committing
        // directly into dedupe state.
        // Decode this window as UTF-16 and run the same validators on UTF-8 output.
        let remaining = self
            .tuning
            .max_total_decode_output_bytes
            .saturating_sub(scratch.total_decode_output_bytes);
        if remaining == 0 {
            return;
        }

        if let Some(confirm) = gates.confirm_all {
            let vidx = variant.idx();
            if let Some(primary) = &confirm.primary[vidx] {
                if memmem::find(raw_win, primary).is_none() {
                    return;
                }
            }
            if !contains_all_memmem(raw_win, &confirm.rest[vidx]) {
                return;
            }
        }

        if let Some(kws) = gates.keywords {
            let vidx = variant.idx();
            if !contains_any_memmem(raw_win, &kws.any[vidx]) {
                return;
            }
        }

        let max_out = self
            .tuning
            .max_utf16_decoded_bytes_per_window
            .min(remaining);

        let decoded = match variant {
            Variant::Utf16Le => decode_utf16le_to_buf(raw_win, max_out, &mut scratch.utf16_buf),
            Variant::Utf16Be => decode_utf16be_to_buf(raw_win, max_out, &mut scratch.utf16_buf),
            Variant::Raw => unreachable!("raw variant in utf16 path"),
        };
        if decoded.is_err() {
            return;
        }

        // Reborrow `utf16_buf` through a raw pointer — same technique and safety
        // argument as `run_rule_on_utf16_window_aligned`. See that method for the
        // full SAFETY justification.
        let decoded_len = scratch.utf16_buf.len();
        let decoded_ptr = scratch.utf16_buf.as_slice().as_ptr();
        // SAFETY: Same raw-pointer reborrow as `run_rule_on_utf16_window_aligned`;
        // `utf16_buf` is not mutated while this slice reference is live.
        let decoded = unsafe { std::slice::from_raw_parts(decoded_ptr, decoded_len) };
        if decoded.is_empty() {
            return;
        }

        scratch.total_decode_output_bytes = scratch
            .total_decode_output_bytes
            .saturating_add(decoded.len());
        if scratch.total_decode_output_bytes > self.tuning.max_total_decode_output_bytes {
            return;
        }

        if let Some(needle) = rule.must_contain {
            if memmem::find(decoded, needle).is_none() {
                return;
            }
        }

        // Assignment-shape precheck on decoded UTF-8 bytes.
        if rule.needs_assignment_shape_check() && !has_assignment_value_shape(decoded) {
            return;
        }

        // Character-class distribution gate on decoded bytes.
        if let Some(cc) = gates.char_class {
            if !char_class_gate_passes(decoded, cc) {
                return;
            }
        }

        let endianness = match variant {
            Variant::Utf16Le => Utf16Endianness::Le,
            Variant::Utf16Be => Utf16Endianness::Be,
            Variant::Raw => unreachable!("raw variant in utf16 path"),
        };
        let parent_span =
            window_start as usize..window_start.saturating_add(raw_win.len() as u64) as usize;
        let utf16_step_id = scratch.step_arena.push(
            step_id,
            DecodeStep::Utf16Window {
                endianness,
                parent_span: parent_span.clone(),
            },
        );

        let entropy = gates.entropy;
        let keyword_evidence_patterns = gates.keywords.map(|kws| &kws.any[Variant::Raw.idx()]);
        let value_suppressors = gates.value_suppressors;
        let secret_group_raw = rule.secret_group_raw();
        let has_secret_group_override = rule.has_secret_group_override();
        let mut last_safelist_decision: Option<(u64, u64, bool)> = None;
        let mut locs = scratch.capture_locs[rule_id as usize]
            .take()
            .expect("capture locations missing for rule");
        for_each_capture_match(&rule.re, &mut locs, decoded, |locs, start, end| {
            let span = start..end;

            // Extract secret span first so entropy is evaluated on the
            // secret itself, not the full match (see raw-path comment).
            let (secret_start, secret_end) =
                extract_secret_span_locs_raw(locs, secret_group_raw, has_secret_group_override);
            let secret_bytes = &decoded[secret_start..secret_end];

            let entropy_outcome =
                post_match_entropy_outcome(entropy, secret_bytes, scratch, &self.entropy_log2);
            if matches!(entropy_outcome, Some(EntropyGateOutcome::Failed)) {
                return;
            }
            let evidence = GateEvidence {
                entropy_outcome,
                keyword_local_hit: keyword_local_hit(
                    decoded,
                    span.start,
                    span.end,
                    keyword_evidence_patterns,
                ),
            };

            // Value suppressor gate (see raw-path comment for rationale).
            if let Some(vs) = value_suppressors {
                if contains_any_memmem(secret_bytes, vs) {
                    return;
                }
            }

            let context_ok = if let Some(ctx) = gates.local_context {
                local_context_passes(decoded, secret_start, secret_end, ctx)
            } else {
                true
            };

            if context_ok {
                // Map decoded UTF-8 match span back to raw UTF-16 offsets, then
                // lift into decoded-stream coordinates and (when available) map
                // through the transform root-span context.
                let match_raw_start = map_utf16_decoded_offset(
                    raw_win,
                    span.start,
                    matches!(variant, Variant::Utf16Le),
                );
                let match_raw_end = map_utf16_decoded_offset(
                    raw_win,
                    span.end,
                    matches!(variant, Variant::Utf16Le),
                );
                let match_stream_start = window_start as usize + match_raw_start;
                let match_stream_end = window_start as usize + match_raw_end;
                let mapped_span = match_stream_start..match_stream_end;
                let root_span_hint = if let Some(ctx) = scratch.root_span_map_ctx.as_ref() {
                    ctx.map_span(mapped_span.clone())
                } else {
                    root_hint.clone().unwrap_or(mapped_span)
                };
                let root_hint_start = base_offset + root_span_hint.start as u64;
                let root_hint_end = base_offset + root_span_hint.end as u64;
                // Use the parent step_id (not utf16_step_id) for offline validation:
                // root UTF-16 findings have parent == STEP_ROOT.
                let Some(outcome) = self.apply_emit_time_policy(
                    rule,
                    secret_bytes,
                    utf16_step_id,
                    step_id,
                    raw_win,
                    base_offset,
                    base_offset.saturating_add(window_start),
                    &root_span_hint,
                    root_hint_start,
                    root_hint_end,
                    &mut last_safelist_decision,
                    scratch,
                ) else {
                    return;
                };
                let confidence_score = compute_confidence_score(&evidence, rule, &outcome);
                if !gates.passes_threshold(confidence_score) {
                    crate::perf_stats::sat_add_usize(&mut scratch.confidence_suppressed, 1);
                    return;
                }
                // Same dedup guard as the raw staging path: overlapping VS
                // prefilter windows can decode to the same UTF-16 region and
                // yield identical regex matches.
                if is_staging_duplicate(
                    scratch.tmp_findings.as_slice(),
                    rule_id,
                    secret_start as u32,
                    secret_end as u32,
                    root_hint_start,
                    root_hint_end,
                ) {
                    return;
                }
                // Set found_any only for findings that are actually staged
                // (emit-time policy and confidence threshold both passed).
                *found_any = true;
                scratch.tmp_findings.push(FindingRec {
                    file_id,
                    rule_id,
                    span_start: secret_start as u32,
                    span_end: secret_end as u32,
                    root_hint_start,
                    root_hint_end,
                    dedupe_with_span: outcome.dedupe_with_span,
                    step_id: utf16_step_id,
                    confidence_score,
                });
                scratch.tmp_drop_hint_end.push(outcome.drop_hint_end);
                scratch.tmp_norm_hash.push(outcome.norm_hash);
            }
        });
        scratch.capture_locs[rule_id as usize] = Some(locs);
    }

    /// UTF-16 scheduler adapter: scans both byte parities and stages findings.
    ///
    /// Staging counterpart of the UTF-16 branch in [`run_rule_on_window`].
    /// Delegates to [`run_rule_on_utf16_window_aligned_into`] for each parity.
    ///
    /// Hinted parity is attempted first because the anchor hint byte offset
    /// tells us which alignment most likely contains the match. The opposite
    /// parity is tried second only if decode budget remains. This ordering
    /// minimizes wasted decode work when the total-output budget is tight.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn run_rule_on_utf16_window_into(
        &self,
        rule_id: u32,
        rule: &RuleCompiled,
        variant: Variant,
        raw_win: &[u8],
        window_start: u64,
        step_id: StepId,
        root_hint: &Option<Range<usize>>,
        base_offset: u64,
        file_id: FileId,
        scratch: &mut ScanScratch,
        found_any: &mut bool,
        anchor_hint: u64,
        gates: &ResolvedGates<'_>,
    ) {
        let parity = (anchor_hint.saturating_sub(window_start) & 1) as usize;
        let offsets = [parity, parity ^ 1];

        for offset in offsets {
            if offset >= raw_win.len() {
                continue;
            }
            self.run_rule_on_utf16_window_aligned_into(
                rule_id,
                rule,
                variant,
                &raw_win[offset..],
                window_start.saturating_add(offset as u64),
                step_id,
                root_hint,
                base_offset,
                file_id,
                scratch,
                found_any,
                gates,
            );
            if scratch.total_decode_output_bytes >= self.tuning.max_total_decode_output_bytes {
                break;
            }
        }
    }

    /// Applies emit-time safelist/offline gates and computes finding sidecars.
    ///
    /// `emitted_step_id` controls root-step context-window safelist suppression
    /// and dedupe-key span inclusion; the secret-bytes safelist runs
    /// unconditionally on all surviving findings. `parent_step_id` controls
    /// root-semantic offline validation.
    /// These differ for UTF-16 findings (`emitted_step_id` is `Utf16Window`,
    /// `parent_step_id` may still be `STEP_ROOT`).
    ///
    /// Gate sequence (in order):
    /// 1. Context-window safelist (root findings only).
    /// 2. Secret-bytes safelist (all findings — placeholders in decoded buffers
    ///    are equally fake).
    /// 3. UUID-format quick-reject (skipped when the rule's `uuid_format_secret()`
    ///    flag is set, e.g. Heroku/Snyk API keys that legitimately look like UUIDs).
    /// 4. Offline structural validation (root-semantic findings only).
    ///
    /// Returns `None` when the finding is suppressed. In that case suppression
    /// counters are incremented here (when `perf-stats` + `debug_assertions`
    /// are enabled) so callers do not duplicate bookkeeping. Confidence
    /// thresholding is intentionally handled by callers after
    /// [`compute_confidence_score`].
    #[allow(clippy::too_many_arguments)]
    #[inline(always)]
    fn apply_emit_time_policy(
        &self,
        rule: &RuleCompiled,
        secret_bytes: &[u8],
        emitted_step_id: StepId,
        parent_step_id: StepId,
        context_buf: &[u8],
        base_offset: u64,
        context_base_offset: u64,
        root_span_hint: &Range<usize>,
        root_hint_start: u64,
        root_hint_end: u64,
        last_safelist_decision: &mut Option<(u64, u64, bool)>,
        scratch: &mut ScanScratch,
    ) -> Option<EmitPolicyOutcome> {
        if self.suppress_root_finding_by_safelist(
            context_buf,
            context_base_offset,
            emitted_step_id,
            root_hint_start,
            root_hint_end,
            last_safelist_decision,
        ) {
            crate::perf_stats::sat_add_usize(&mut scratch.safelist_suppressed, 1);
            return None;
        }

        // Secret-bytes safelist: checks all findings (not just root) because
        // placeholder values in decoded buffers are equally fake.
        if self.safelist.secret_bytes_matcher().is_match(secret_bytes) {
            crate::perf_stats::sat_add_usize(&mut scratch.secret_bytes_safelist_suppressed, 1);
            return None;
        }

        // UUID-format quick-reject: suppress findings whose extracted value is a
        // bare UUID (8-4-4-4-12 hex) unless the originating rule captures
        // UUID-format secrets (e.g., Heroku, Snyk API keys).
        if !rule.uuid_format_secret() && super::safelist::is_uuid_format(secret_bytes) {
            crate::perf_stats::sat_add_usize(&mut scratch.uuid_format_suppressed, 1);
            return None;
        }

        let mut drop_hint_end = root_span_hint.end;
        if let Some(ctx) = scratch.root_span_map_ctx.as_ref() {
            if let Some(end) = ctx.drop_hint_end_for_match(root_span_hint.clone()) {
                drop_hint_end = drop_hint_end.max(end);
            }
        }
        let drop_hint_end = base_offset + drop_hint_end as u64;

        // Dedupe key includes the decoded span only when offsets are stable
        // across chunks:
        // - Root findings (`STEP_ROOT`): offsets are absolute file positions.
        // - No root-span mapping: nested transforms with length-changing parents
        //   produce different decoded offsets per chunk alignment, but without
        //   mapping we have no better key.
        // When mapping IS available, decoded spans can shift with chunk
        // boundaries, so dedupe relies solely on the root hint window.
        let dedupe_with_span = emitted_step_id == STEP_ROOT || scratch.root_span_map_ctx.is_none();

        // Offline validation: compute the verdict once and use for both
        // suppression (Invalid + spec opts in) and confidence scoring (Valid).
        let offline_verdict = self.compute_offline_verdict(rule, secret_bytes, parent_step_id);
        // Not all Invalid verdicts suppress — `suppresses_on_invalid()` is a
        // per-spec policy flag.  Specs may detect structural failure but keep
        // the finding for manual review.
        if matches!(offline_verdict, Some(crate::api::OfflineVerdict::Invalid))
            && self
                .offline_validation_gate(rule.offline_validation)
                .is_some_and(|spec| spec.suppresses_on_invalid())
        {
            crate::perf_stats::sat_add_usize(&mut scratch.offline_suppressed, 1);
            return None;
        }

        let norm_hash = *blake3::hash(secret_bytes).as_bytes();
        Some(EmitPolicyOutcome {
            drop_hint_end,
            dedupe_with_span,
            norm_hash,
            offline_verdict_valid: matches!(
                offline_verdict,
                Some(crate::api::OfflineVerdict::Valid)
            ),
        })
    }

    /// Computes the offline structural validation verdict for a finding.
    ///
    /// Returns `None` when offline validation does not apply (non-root findings
    /// or rules without an offline validation spec). Otherwise returns the
    /// verdict from [`offline_validate::validate`].
    ///
    /// Only root-semantic findings (`parent_step_id == STEP_ROOT`) are checked;
    /// transform-derived findings reference decoded buffers, not original input.
    ///
    /// For UTF-16 paths, callers must pass the **parent** `step_id` (not
    /// `utf16_step_id`), because root-level UTF-16 findings carry a
    /// `Utf16Window` decode step as their own `step_id` while their parent
    /// is `STEP_ROOT`.
    #[inline(always)]
    fn compute_offline_verdict(
        &self,
        rule: &RuleCompiled,
        secret_bytes: &[u8],
        parent_step_id: StepId,
    ) -> Option<crate::api::OfflineVerdict> {
        if parent_step_id != STEP_ROOT {
            return None;
        }
        let spec = self.offline_validation_gate(rule.offline_validation)?;
        Some(super::offline_validate::validate(spec, secret_bytes))
    }
}

#[cfg(test)]
#[path = "window_validate_tests.rs"]
mod tests;
