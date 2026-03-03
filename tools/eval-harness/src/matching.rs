//! Finding-to-truth matching for PRC-AUC evaluation.
//!
//! Classifies each [`NormalizedFinding`] against [`TruthItem`] annotations to
//! produce [`FindingClass`] labels (TP, FP, or Unlabeled) that feed into
//! precision/recall computation.
//!
//! # Algorithm
//!
//! Uses confidence-sorted greedy matching, the same strategy as COCO and
//! PASCAL VOC evaluation protocols:
//!
//! 1. Sort findings by confidence descending (deterministic tiebreak via
//!    [`NormalizedFinding::Ord`]).
//! 2. Group truth items by file path, sort each group by `line_start`.
//! 3. For each finding (highest confidence first):
//!    - Convert byte range to line range via [`LineIndex`].
//!    - Binary search for overlapping truth items.
//!    - Apply label priority: Positive > Negative > Placeholder.
//!    - Consume matched Positive truths (one-to-one TP counting).
//!
//! Greedy matching is **required** for valid PRC-AUC: it produces nested TP
//! sets across confidence thresholds, ensuring recall is monotonically
//! non-decreasing as the threshold decreases. Optimal (Hungarian) matching
//! violates this property.
//!
//! # Consumption rules
//!
//! - **Positive** truth items are consumed on match (one-to-one), preventing
//!   metric inflation where multiple findings inflate the TP count.
//! - **Negative** truth items are **not** consumed — they describe regions, not
//!   tokens. Multiple findings at a negative region should all be classified FP.
//! - **Placeholder** truth items are **not** consumed — multiple findings at an
//!   ignore region should all be excluded from scoring (Unlabeled).

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::line_index::LineIndex;
use crate::pipeline::DedupMode;
use crate::types::{ClassifiedFinding, FindingClass, NormalizedFinding, TruthItem, TruthLabel};
use gossip_stdx::DynamicBitSet;

/// Per-file index combining truth items and byte-to-line mapping.
///
/// Collocates the two pieces of information needed per finding path — the
/// truth items to match against and the [`LineIndex`] for byte-to-line
/// conversion — behind a single `HashMap` key lookup. This halves per-finding
/// hash computations compared to separate `truth_by_file` and `line_indices`
/// maps, and improves cache locality when processing many findings against the
/// same file.
struct FileInfo<'a> {
    /// Byte-to-line mapping for this file. `None` when truth items reference
    /// the path but no file contents were provided — findings on such paths
    /// are classified as Unlabeled.
    line_index: Option<LineIndex>,
    /// Truth items for this file, sorted by `line_start` for binary search.
    /// The `usize` is the index into the original truth slice, used to mark
    /// consumed Positive items in the global bitset.
    truths: Vec<(usize, &'a TruthItem)>,
}

/// Configuration for the matching algorithm.
///
/// Callers set fields explicitly. For location-only matching use
/// `require_rule_match = false` with `dedup_mode = DedupMode::ByRule`.
/// The `require_rule_match` toggle adds an additional constraint when ground
/// truth uses rule-specific annotations (e.g., CredData categories).
#[derive(Clone, Copy, Debug)]
pub struct MatchConfig {
    /// When true, a finding only matches truth items where the finding's
    /// rule name exactly equals one colon-delimited segment of the truth
    /// item's `rule` field (see [`rule_matches`]). When false, matching
    /// is purely location-based — any finding overlapping a truth item's
    /// line range is considered a match regardless of rule name.
    pub require_rule_match: bool,
    /// Dedup mode applied to findings before matching.
    ///
    /// `AcrossRules` means per-span rule alternatives were collapsed before
    /// matching, so rule-sensitive matching (`require_rule_match = true`) is
    /// invalid and rejected by a hard precondition.
    pub dedup_mode: DedupMode,
}

/// Result of matching findings against ground truth.
///
/// Carries both the per-finding classification and the unmatched positive
/// truths (false negatives). Together these provide everything needed for
/// precision/recall computation and PRC-AUC curve generation.
///
/// # Counting invariants
///
/// These hold for every valid result and are enforced by hard assertions
/// inside [`match_findings`]:
///
/// Every input finding is classified into exactly one bucket:
/// ```text
/// classified.len() == input_findings.len()
/// tp_count() + fp_count() + unlabeled_count() == classified.len() as u64
/// ```
///
/// Every positive truth item is either matched or a false negative:
/// ```text
/// tp_count() + fn_count() == total positive truth items
/// ```
///
/// # Diagnostic counters
///
/// The four `u64` counters (`unmatched_finding_paths`, `unmatchable_truth_paths`,
/// `out_of_bounds_findings`, `unmatchable_findings`) are diagnostic signals, not error codes. Non-zero
/// values indicate data quality issues (stale scanner output, missing corpus
/// files, incomplete annotations) rather than matching bugs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchResult {
    /// Every input finding, classified as TP, FP, or Unlabeled.
    /// Order: confidence descending, then by [`NormalizedFinding::Ord`]
    /// tiebreak. This ordering is required by downstream PRC-AUC
    /// computation, which sweeps a threshold from high to low confidence.
    pub classified: Vec<ClassifiedFinding>,

    /// Positive truth items that no finding matched. These represent
    /// secrets the scanner failed to detect. Negative and Placeholder
    /// truths are never included here — only Positive labels contribute
    /// to recall.
    pub false_negatives: Vec<TruthItem>,

    /// Pre-computed TP count, accumulated during the classification loop.
    tp: u64,
    /// Pre-computed FP count, accumulated during the classification loop.
    fp: u64,
    /// Pre-computed Unlabeled count, accumulated during the classification loop.
    unlabeled: u64,

    /// Findings on paths with no corresponding truth entries at all.
    /// These findings are classified as Unlabeled because there is no
    /// annotation to compare against — they are neither penalized nor
    /// rewarded.
    pub unmatched_finding_paths: u64,

    /// Truth paths for which no file contents were provided. Without file
    /// bytes, [`LineIndex`] cannot be built, so truth items on these paths
    /// cannot participate in matching. Affected truth items with Positive
    /// labels will appear in `false_negatives`.
    pub unmatchable_truth_paths: u64,

    /// Findings whose `byte_end` exceeds the file size reported by
    /// [`LineIndex`]. Typically caused by stale scanner output run against
    /// a file that was subsequently truncated. Classified as Unlabeled.
    pub out_of_bounds_findings: u64,

    /// Findings on paths where truth items exist but file contents were
    /// not provided. Without a [`LineIndex`], byte-to-line conversion is
    /// impossible, so these findings are classified as Unlabeled.
    pub unmatchable_findings: u64,
}

impl MatchResult {
    /// Number of findings classified as True Positive (matched a Positive
    /// truth annotation). Bounded above by the total positive truth count.
    pub fn tp_count(&self) -> u64 {
        self.tp
    }

    /// Number of findings classified as False Positive (matched a Negative
    /// truth annotation). Non-zero only when Negative truth items exist in
    /// the corpus.
    pub fn fp_count(&self) -> u64 {
        self.fp
    }

    /// Number of Positive truth items not matched by any finding (false
    /// negatives). Equivalent to `false_negatives.len()`.
    pub fn fn_count(&self) -> u64 {
        self.false_negatives.len() as u64
    }

    /// Findings excluded from scoring: either no annotation at their
    /// location, or matched a Placeholder. These do not affect precision
    /// or recall.
    pub fn unlabeled_count(&self) -> u64 {
        self.unlabeled
    }

    /// Total ground-truth positive count: `tp_count() + fn_count()`.
    /// This is the denominator for recall computation.
    pub fn total_positives(&self) -> u64 {
        self.tp + self.fn_count()
    }
}

/// Classify findings against truth items using position-based matching.
///
/// Pure function — no I/O. Caller provides file contents for [`LineIndex`]
/// construction. Findings and truth items must have paths already
/// normalized via [`crate::types::normalize_path`].
///
/// Takes ownership of `findings` and `truth` to avoid cloning when building
/// the output — findings are moved into [`ClassifiedFinding`] and unmatched
/// truth items are moved into [`MatchResult::false_negatives`].
///
/// The output `classified` list is ordered by confidence descending (then by
/// [`NormalizedFinding::Ord`] for ties). Pass it to
/// [`crate::metrics::compute_metrics`] to obtain PRC-AUC and F1.
///
/// # Panics
///
/// Panics (hard `assert!`, not debug-only) if:
///
/// - `config.dedup_mode == ByRule` and `findings` contains duplicate identities
///   by [`NormalizedFinding`] equality (`path`, `byte_start`, `byte_end`, `rule`;
///   confidence is ignored): `findings must be deduplicated by rule before matching`.
/// - `config.dedup_mode == AcrossRules` and `findings` contains duplicate spans
///   (`path`, `byte_start`, `byte_end`): `findings must be deduplicated by span
///   before cross-rule matching`.
/// - `config.dedup_mode == AcrossRules` with `require_rule_match = true`:
///   `require_rule_match cannot be combined with cross-rule dedup mode`.
/// - the conservation invariants are violated after classification:
///
/// - `tp + fp + unlabeled != findings.len()`
/// - `tp + fn != total positive truth items`
///
/// These indicate a logic bug in the matching algorithm, not bad input.
///
/// # Complexity
///
/// `O(F log F + T log T + B + sum_f(F_f * C_f) + T)` where F = findings,
/// T = truth items, B = total file bytes, F_f = findings in file f,
/// C_f = candidate truths scanned per finding (bounded by T_f, the truth
/// count in file f). Adequate for F up to 100K and T up to 200K spread
/// across thousands of files.
pub fn match_findings(
    mut findings: Vec<NormalizedFinding>,
    truth: Vec<TruthItem>,
    file_contents: &HashMap<String, Vec<u8>>,
    config: MatchConfig,
) -> MatchResult {
    // ── Precondition: findings are deduplicated using the configured mode ─
    match config.dedup_mode {
        DedupMode::ByRule => {
            // Identity-level duplicates inflate TP counts. Identity here
            // matches NormalizedFinding Eq/Hash (path/start/end/rule),
            // ignoring confidence.
            let mut seen = HashSet::with_capacity(findings.len());
            assert!(
                findings.iter().all(|finding| seen.insert(finding)),
                "findings must be deduplicated by rule before matching"
            );
        }
        DedupMode::AcrossRules => {
            assert!(
                !config.require_rule_match,
                "require_rule_match cannot be combined with cross-rule dedup mode"
            );
            let mut seen = HashSet::with_capacity(findings.len());
            assert!(
                findings.iter().all(|finding| seen.insert((
                    finding.path.as_str(),
                    finding.byte_start,
                    finding.byte_end,
                ))),
                "findings must be deduplicated by span before cross-rule matching"
            );
        }
    }

    let findings_len = findings.len();

    // ── Sort findings in-place by (-confidence, identity) ──────────
    findings.sort_unstable_by(|a, b| {
        // Descending confidence via reverse comparison — never negate i8
        // (i8::MIN overflow wraps silently in release mode).
        b.confidence.cmp(&a.confidence).then_with(|| a.cmp(b))
    });

    // Sort postcondition.
    debug_assert!(
        findings
            .windows(2)
            .all(|w| w[0].confidence >= w[1].confidence),
        "sort must produce confidence-descending order"
    );

    // ── Build per-file index: group truth by path, attach LineIndex ─
    // Counting total_positives inline avoids a separate scan of truth.
    let mut file_info: HashMap<&str, FileInfo<'_>> = HashMap::new();
    let mut unmatchable_truth_paths: u64 = 0;
    let mut total_positives: u64 = 0;

    for (idx, item) in truth.iter().enumerate() {
        if item.label == TruthLabel::Positive {
            total_positives += 1;
        }
        file_info
            .entry(item.path.as_str())
            .or_insert_with(|| FileInfo {
                line_index: None,
                truths: Vec::new(),
            })
            .truths
            .push((idx, item));
    }

    for (path, info) in file_info.iter_mut() {
        if let Some(bytes) = file_contents.get(*path) {
            info.line_index = Some(LineIndex::new(bytes));
        } else {
            unmatchable_truth_paths += 1;
        }
        info.truths.sort_unstable_by_key(|(_, t)| t.line_start);
    }

    // ── Global consumed-truth bitset (Positive truths only) ───────
    let mut consumed = DynamicBitSet::empty(truth.len());

    // ── Per-finding classification with inline counting ──────────
    let mut classified = Vec::with_capacity(findings_len);
    let mut tp: u64 = 0;
    let mut fp: u64 = 0;
    let mut unlabeled: u64 = 0;
    let mut unmatched_finding_paths: u64 = 0;
    let mut out_of_bounds_findings: u64 = 0;
    let mut unmatchable_findings: u64 = 0;

    for finding in findings {
        let class = classify_one_finding(
            &finding,
            &file_info,
            &mut consumed,
            &config,
            &mut unmatched_finding_paths,
            &mut out_of_bounds_findings,
            &mut unmatchable_findings,
        );

        match class {
            FindingClass::TruePositive => tp += 1,
            FindingClass::FalsePositive => fp += 1,
            FindingClass::Unlabeled => unlabeled += 1,
        }

        classified.push(ClassifiedFinding { finding, class });
    }

    // Drop file_info to release borrows on truth before consuming it.
    drop(file_info);

    // ── Collect false negatives ───────────────────────────────────
    // Move unmatched Positive truth items into the result without cloning.
    let false_negatives: Vec<TruthItem> = truth
        .into_iter()
        .enumerate()
        .filter(|(idx, item)| item.label == TruthLabel::Positive && !consumed.is_set(*idx))
        .map(|(_, item)| item)
        .collect();

    // ── Conservation assertions ───────────────────────────────────
    // Use pre-computed counts — zero extra iterations over classified or truth.
    assert_eq!(
        tp + fp + unlabeled,
        findings_len as u64,
        "finding count conservation"
    );
    assert_eq!(
        tp + false_negatives.len() as u64,
        total_positives,
        "truth count conservation"
    );

    // Cross-check: consumed bits must agree with TP count. Only Positive
    // truths have their bits set, so `consumed.count()` == consumed Positives.
    debug_assert_eq!(
        consumed.count() as u64,
        tp,
        "consumed positive count must equal TP"
    );

    MatchResult {
        classified,
        false_negatives,
        tp,
        fp,
        unlabeled,
        unmatched_finding_paths,
        unmatchable_truth_paths,
        out_of_bounds_findings,
        unmatchable_findings,
    }
}

/// Classify a single finding against the truth index.
///
/// This is the per-finding core of the matching algorithm. For each finding,
/// it resolves byte offsets to line numbers, searches for overlapping truth
/// items via binary search, and selects the highest-priority match using
/// the label precedence Positive > Negative > Placeholder.
///
/// # Side effects
///
/// - **`consumed`**: Sets the bit for any matched Positive truth item
///   (one-to-one consumption). Negative and Placeholder bits are never set.
/// - **`unmatched_finding_paths`**: Incremented when the finding's path
///   has no corresponding truth entries.
/// - **`out_of_bounds_findings`**: Incremented when `byte_end` exceeds
///   the file size, indicating stale scanner output.
/// - **`unmatchable_findings`**: Incremented when the finding's path has
///   truth entries but no [`LineIndex`] (file contents not provided).
///
/// # Early-return paths
///
/// Returns [`FindingClass::Unlabeled`] early (without scanning truths) in
/// three cases:
///
/// 1. No entry in `file_info` for this path — no truth items reference it.
/// 2. Entry exists but no [`LineIndex`] — file contents were not provided.
/// 3. Byte offsets exceed file size (out-of-bounds).
///
/// In all early-return cases, the finding cannot affect TP or FP counts.
fn classify_one_finding(
    finding: &NormalizedFinding,
    file_info: &HashMap<&str, FileInfo<'_>>,
    consumed: &mut DynamicBitSet,
    config: &MatchConfig,
    unmatched_finding_paths: &mut u64,
    out_of_bounds_findings: &mut u64,
    unmatchable_findings: &mut u64,
) -> FindingClass {
    // 1. Look up combined per-file info (truths + LineIndex).
    let Some(info) = file_info.get(finding.path.as_str()) else {
        *unmatched_finding_paths += 1;
        return FindingClass::Unlabeled;
    };

    // 2. Get LineIndex. None means truth items exist for this path but
    //    file contents were not provided — already counted as
    //    unmatchable_truth_paths by the caller.
    let Some(line_index) = &info.line_index else {
        *unmatchable_findings += 1;
        return FindingClass::Unlabeled;
    };

    // 3. Validate byte offsets against file size. Out-of-bounds findings
    //    indicate stale scanner output or a truncated file read — diagnosable
    //    via the out_of_bounds_findings counter, but not a programming error.
    if finding.byte_end > line_index.data_len() as u64 {
        *out_of_bounds_findings += 1;
        return FindingClass::Unlabeled;
    }

    // 4. Convert byte range to line range.
    let (f_start, f_end) = line_index.line_range(finding.byte_start, finding.byte_end);

    let file_truths = &info.truths;

    // Upper bound: first truth with line_start > f_end.
    // This predicate is SOUND on line_start-sorted data because line_start
    // is monotonically non-decreasing. The naive alternative —
    // `partition_point(|t| t.line_end < f_start)` — is UNSOUND because
    // line_end is NOT monotonic when truths are sorted by line_start
    // (e.g., [(1,10), (2,3)] has line_end = [10,3]).
    let upper = file_truths.partition_point(|(_, t)| t.line_start <= f_end);

    // Binary search postcondition.
    debug_assert!(
        file_truths[..upper]
            .iter()
            .all(|(_, t)| t.line_start <= f_end)
    );
    debug_assert!(
        file_truths[upper..]
            .iter()
            .all(|(_, t)| t.line_start > f_end)
    );

    // 5. Scan candidates for the first overlapping truth of each label.
    //    Linear scan over `file_truths[..upper]` — bounded by T_f (truth
    //    count in this file), which is small in practice. We track the first
    //    match per label rather than breaking early so that label priority
    //    (Positive > Negative > Placeholder) is resolved after scanning, not
    //    during. This avoids order-dependent bugs where a Negative encountered
    //    before a Positive would shadow it.
    let mut best_positive: Option<usize> = None;
    let mut best_negative: Option<usize> = None;
    let mut best_placeholder: Option<usize> = None;

    for &(truth_idx, truth_item) in &file_truths[..upper] {
        // No overlap: truth ends before finding starts.
        if truth_item.line_end < f_start {
            continue;
        }

        // Only check consumed for Positive truths — Negative/Placeholder
        // describe regions and are reusable across multiple findings.
        if truth_item.label == TruthLabel::Positive && consumed.is_set(truth_idx) {
            continue;
        }

        // Rule matching (optional).
        if config.require_rule_match && !rule_matches(&finding.rule, &truth_item.rule) {
            continue;
        }

        match truth_item.label {
            TruthLabel::Positive => {
                if best_positive.is_none() {
                    best_positive = Some(truth_idx);
                }
            }
            TruthLabel::Negative => {
                if best_negative.is_none() {
                    best_negative = Some(truth_idx);
                }
            }
            TruthLabel::Placeholder => {
                if best_placeholder.is_none() {
                    best_placeholder = Some(truth_idx);
                }
            }
        }
    }

    // 6. Classify with label priority — only consume Positive.
    if let Some(idx) = best_positive {
        debug_assert!(!consumed.is_set(idx), "truth item {} already consumed", idx);
        consumed.set(idx);
        debug_assert!(consumed.is_set(idx));
        FindingClass::TruePositive
    } else if best_negative.is_some() {
        FindingClass::FalsePositive
    } else {
        // Both Placeholder match and no match produce Unlabeled.
        // Placeholder = "exclude from scoring"; no match = "no annotation".
        FindingClass::Unlabeled
    }
}

/// Check if a finding's rule matches a truth item's rule field.
///
/// Truth rules from CredData use colon-separated category hierarchies
/// (e.g., `"Secret:Token"` → segments `["Secret", "Token"]`). Finding
/// rules are flat scanner-rs names (e.g., `"slack-bot-token"`). This
/// function returns true if `finding_rule` exactly equals any segment
/// after splitting `truth_rule` on `':'`.
///
/// Matching is case-sensitive and requires an exact segment match —
/// substring matches within a segment do not count (e.g., `"Tok"` does
/// not match the `"Token"` segment).
///
/// If `truth_rule` contains no colons, it is treated as a single segment
/// and the comparison reduces to `finding_rule == truth_rule`.
fn rule_matches(finding_rule: &str, truth_rule: &str) -> bool {
    truth_rule.split(':').any(|segment| segment == finding_rule)
}

// ── Tests ────────────────────────────────────────────────────────────────
//
// Two layers of coverage:
//
// 1. **Unit tests** — deterministic scenarios targeting one behavior each
//    (single-label classification, consumption, priority, out-of-bounds,
//    rule matching, confidence ordering, etc.). Use a fixed 3-line file
//    (`SIMPLE_FILE`) to keep byte/line reasoning tractable.
//
// 2. **Property tests** (proptest) — randomized scenarios verifying global
//    invariants that must hold for *all* inputs:
//    - Conservation: tp + fp + unlabeled == findings count, tp + fn == positives.
//    - Determinism: identical inputs always produce identical output.
//    - One-to-one: TP count never exceeds positive truth count.
//    - Path isolation: findings on path A never match truths on path B.
//    - Label consistency: no TP without Positive truths, no FP without Negatives.
//    - Placeholder neutrality: adding/removing Placeholders cannot change TP/FP.
//    - Recall monotonicity: recall never decreases as the confidence threshold
//      drops (required for valid PRC-AUC).

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helpers ──────────────────────────────────────────────────────

    fn make_finding(
        path: &str,
        byte_start: u64,
        byte_end: u64,
        rule: &str,
        conf: i8,
    ) -> NormalizedFinding {
        NormalizedFinding::new(path.into(), byte_start, byte_end, rule.into(), conf)
    }

    fn make_truth(
        path: &str,
        line_start: u32,
        line_end: u32,
        label: TruthLabel,
        rule: &str,
    ) -> TruthItem {
        TruthItem::new(path.into(), line_start, line_end, label, rule.into())
    }

    fn default_config() -> MatchConfig {
        MatchConfig {
            require_rule_match: false,
            dedup_mode: DedupMode::ByRule,
        }
    }

    /// Create file_contents map from (path, content) pairs.
    fn contents(entries: &[(&str, &[u8])]) -> HashMap<String, Vec<u8>> {
        entries
            .iter()
            .map(|(p, c)| (p.to_string(), c.to_vec()))
            .collect()
    }

    // ── Unit tests ──────────────────────────────────────────────────

    // Simple file: "aaaa\nbbbb\ncccc\n" => 3 lines, 15 bytes
    // Line 1: bytes 0-4 ("aaaa\n"), Line 2: bytes 5-9 ("bbbb\n"), Line 3: bytes 10-14 ("cccc\n")
    const SIMPLE_FILE: &[u8] = b"aaaa\nbbbb\ncccc\n";
    const SIMPLE_PATH: &str = "f.txt";

    #[rstest::rstest]
    #[case::positive(TruthLabel::Positive, FindingClass::TruePositive)]
    #[case::negative(TruthLabel::Negative, FindingClass::FalsePositive)]
    #[case::placeholder(TruthLabel::Placeholder, FindingClass::Unlabeled)]
    fn single_finding_classification(
        #[case] label: TruthLabel,
        #[case] expected_class: FindingClass,
    ) {
        let findings = vec![make_finding(SIMPLE_PATH, 0, 4, "r", 5)];
        let truth = vec![make_truth(SIMPLE_PATH, 1, 1, label, "r")];
        let fc = contents(&[(SIMPLE_PATH, SIMPLE_FILE)]);

        let result = match_findings(findings, truth, &fc, default_config());
        assert_eq!(result.classified.len(), 1);
        assert_eq!(
            result.classified[0].class, expected_class,
            "label={label:?} should produce {expected_class:?}"
        );
    }

    #[test]
    fn no_overlap() {
        let findings = vec![make_finding(SIMPLE_PATH, 0, 4, "r", 5)];
        let truth = vec![make_truth(SIMPLE_PATH, 3, 3, TruthLabel::Positive, "r")];
        let fc = contents(&[(SIMPLE_PATH, SIMPLE_FILE)]);

        let result = match_findings(findings, truth, &fc, default_config());
        assert_eq!(result.classified[0].class, FindingClass::Unlabeled);
        assert_eq!(result.false_negatives.len(), 1);
    }

    #[test]
    fn no_truth_file() {
        let findings = vec![make_finding("other.txt", 0, 3, "r", 5)];
        let truth = vec![make_truth(SIMPLE_PATH, 1, 1, TruthLabel::Positive, "r")];
        let fc = contents(&[(SIMPLE_PATH, SIMPLE_FILE), ("other.txt", b"abc")]);

        let result = match_findings(findings, truth, &fc, default_config());
        assert_eq!(result.classified[0].class, FindingClass::Unlabeled);
        assert_eq!(result.unmatched_finding_paths, 1);
    }

    #[test]
    fn no_file_contents() {
        let findings = vec![make_finding("missing.txt", 0, 3, "r", 5)];
        let truth: Vec<TruthItem> = vec![];
        let fc: HashMap<String, Vec<u8>> = HashMap::new();

        let result = match_findings(findings, truth, &fc, default_config());
        assert_eq!(result.classified[0].class, FindingClass::Unlabeled);
    }

    #[test]
    fn label_priority_positive_wins() {
        let findings = vec![make_finding(SIMPLE_PATH, 0, 4, "r", 5)];
        let truth = vec![
            make_truth(SIMPLE_PATH, 1, 1, TruthLabel::Positive, "r"),
            make_truth(SIMPLE_PATH, 1, 1, TruthLabel::Negative, "r"),
        ];
        let fc = contents(&[(SIMPLE_PATH, SIMPLE_FILE)]);

        let result = match_findings(findings, truth, &fc, default_config());
        assert_eq!(result.classified[0].class, FindingClass::TruePositive);
        assert_eq!(result.false_negatives.len(), 0);
    }

    #[test]
    fn label_priority_placeholder_last() {
        let findings = vec![make_finding(SIMPLE_PATH, 0, 4, "r", 5)];
        let truth = vec![
            make_truth(SIMPLE_PATH, 1, 1, TruthLabel::Positive, "r"),
            make_truth(SIMPLE_PATH, 1, 1, TruthLabel::Placeholder, "r"),
        ];
        let fc = contents(&[(SIMPLE_PATH, SIMPLE_FILE)]);

        let result = match_findings(findings, truth, &fc, default_config());
        assert_eq!(result.classified[0].class, FindingClass::TruePositive);
    }

    #[test]
    fn label_priority_negative_over_placeholder() {
        let findings = vec![make_finding(SIMPLE_PATH, 0, 4, "r", 5)];
        let truth = vec![
            make_truth(SIMPLE_PATH, 1, 1, TruthLabel::Negative, "r"),
            make_truth(SIMPLE_PATH, 1, 1, TruthLabel::Placeholder, "r"),
        ];
        let fc = contents(&[(SIMPLE_PATH, SIMPLE_FILE)]);

        let result = match_findings(findings, truth, &fc, default_config());
        assert_eq!(result.classified[0].class, FindingClass::FalsePositive);
        assert!(result.false_negatives.is_empty());
    }

    #[test]
    fn greedy_consumption_respects_confidence_order() {
        // Each finding needs a distinct rule so dedup does not collapse them.
        // require_rule_match is false, so rule names do not affect matching.
        let findings = vec![
            make_finding(SIMPLE_PATH, 0, 9, "r1", 10),
            make_finding(SIMPLE_PATH, 0, 9, "r2", 5),
            make_finding(SIMPLE_PATH, 0, 9, "r3", 1),
        ];
        let truth = vec![
            make_truth(SIMPLE_PATH, 1, 1, TruthLabel::Positive, "r"),
            make_truth(SIMPLE_PATH, 2, 2, TruthLabel::Positive, "r"),
        ];
        let fc = contents(&[(SIMPLE_PATH, SIMPLE_FILE)]);

        let result = match_findings(findings, truth, &fc, default_config());
        assert_eq!(result.tp_count(), 2);
        assert_eq!(result.fp_count(), 0);
        assert_eq!(result.classified[0].class, FindingClass::TruePositive);
        assert_eq!(result.classified[1].class, FindingClass::TruePositive);
        assert_eq!(result.classified[2].class, FindingClass::Unlabeled);
    }

    #[test]
    fn one_to_one_consumption() {
        let findings = vec![
            make_finding(SIMPLE_PATH, 0, 4, "r", 10),
            make_finding(SIMPLE_PATH, 1, 4, "r", 5),
        ];
        let truth = vec![make_truth(SIMPLE_PATH, 1, 1, TruthLabel::Positive, "r")];
        let fc = contents(&[(SIMPLE_PATH, SIMPLE_FILE)]);

        let result = match_findings(findings, truth, &fc, default_config());
        assert_eq!(result.classified[0].class, FindingClass::TruePositive);
        assert_eq!(result.classified[1].class, FindingClass::Unlabeled);
    }

    #[test]
    fn confidence_ordering() {
        let findings = vec![
            make_finding(SIMPLE_PATH, 0, 4, "r1", 3),
            make_finding(SIMPLE_PATH, 0, 4, "r2", 8),
        ];
        let truth = vec![make_truth(SIMPLE_PATH, 1, 1, TruthLabel::Positive, "r")];
        let fc = contents(&[(SIMPLE_PATH, SIMPLE_FILE)]);

        let result = match_findings(findings, truth, &fc, default_config());
        let tp_finding = result
            .classified
            .iter()
            .find(|c| c.class == FindingClass::TruePositive)
            .unwrap();
        assert_eq!(tp_finding.finding.confidence, 8);
    }

    #[test]
    fn byte_offset_out_of_bounds() {
        let findings = vec![make_finding(SIMPLE_PATH, 0, 9999, "r", 5)];
        let truth = vec![make_truth(SIMPLE_PATH, 1, 1, TruthLabel::Positive, "r")];
        let fc = contents(&[(SIMPLE_PATH, SIMPLE_FILE)]);

        let result = match_findings(findings, truth, &fc, default_config());
        assert_eq!(result.classified[0].class, FindingClass::Unlabeled);
        assert_eq!(result.out_of_bounds_findings, 1);
        assert_eq!(result.false_negatives.len(), 1);
    }

    #[test]
    fn zero_width_finding() {
        let findings = vec![make_finding(SIMPLE_PATH, 0, 0, "r", 5)];
        let truth = vec![make_truth(SIMPLE_PATH, 1, 1, TruthLabel::Positive, "r")];
        let fc = contents(&[(SIMPLE_PATH, SIMPLE_FILE)]);

        let result = match_findings(findings, truth, &fc, default_config());
        assert_eq!(result.classified[0].class, FindingClass::TruePositive);
    }

    #[test]
    fn rule_match_colon_split() {
        let findings = vec![make_finding(SIMPLE_PATH, 0, 4, "Token", 5)];
        let truth = vec![make_truth(
            SIMPLE_PATH,
            1,
            1,
            TruthLabel::Positive,
            "Secret:Token",
        )];
        let fc = contents(&[(SIMPLE_PATH, SIMPLE_FILE)]);
        let config = MatchConfig {
            require_rule_match: true,
            dedup_mode: DedupMode::ByRule,
        };

        let result = match_findings(findings, truth, &fc, config);
        assert_eq!(result.classified[0].class, FindingClass::TruePositive);
    }

    #[test]
    fn rule_match_disabled() {
        let findings = vec![make_finding(SIMPLE_PATH, 0, 4, "scanner-rule", 5)];
        let truth = vec![make_truth(
            SIMPLE_PATH,
            1,
            1,
            TruthLabel::Positive,
            "CredDataCategory",
        )];
        let fc = contents(&[(SIMPLE_PATH, SIMPLE_FILE)]);

        let result = match_findings(findings, truth, &fc, default_config());
        assert_eq!(result.classified[0].class, FindingClass::TruePositive);
    }

    #[test]
    fn rule_match_required_but_no_match() {
        let findings = vec![make_finding(SIMPLE_PATH, 0, 4, "slack-bot-token", 5)];
        let truth = vec![make_truth(
            SIMPLE_PATH,
            1,
            1,
            TruthLabel::Positive,
            "Secret:Token",
        )];
        let fc = contents(&[(SIMPLE_PATH, SIMPLE_FILE)]);
        let config = MatchConfig {
            require_rule_match: true,
            dedup_mode: DedupMode::ByRule,
        };

        let result = match_findings(findings, truth, &fc, config);
        assert_eq!(result.classified[0].class, FindingClass::Unlabeled);
        assert_eq!(result.false_negatives.len(), 1);
    }

    #[test]
    fn unmatchable_truth_path_missing_file_contents() {
        let findings = vec![make_finding("missing.txt", 0, 4, "r", 5)];
        let truth = vec![make_truth("missing.txt", 1, 1, TruthLabel::Positive, "r")];
        let fc = contents(&[(SIMPLE_PATH, SIMPLE_FILE)]);

        let result = match_findings(findings, truth, &fc, default_config());
        assert_eq!(result.unmatchable_truth_paths, 1);
        assert_eq!(result.unmatchable_findings, 1);
        assert_eq!(result.classified[0].class, FindingClass::Unlabeled);
        assert_eq!(result.false_negatives.len(), 1);
    }

    #[test]
    fn fn_collection() {
        let findings: Vec<NormalizedFinding> = vec![];
        let truth = vec![
            make_truth(SIMPLE_PATH, 1, 1, TruthLabel::Positive, "r"),
            make_truth(SIMPLE_PATH, 2, 2, TruthLabel::Positive, "r"),
            make_truth(SIMPLE_PATH, 3, 3, TruthLabel::Negative, "r"),
        ];
        let fc = contents(&[(SIMPLE_PATH, SIMPLE_FILE)]);

        let result = match_findings(findings, truth, &fc, default_config());
        assert_eq!(result.false_negatives.len(), 2);
        assert!(
            result
                .false_negatives
                .iter()
                .all(|t| t.label == TruthLabel::Positive)
        );
    }

    #[test]
    fn empty_inputs() {
        let result = match_findings(vec![], vec![], &HashMap::new(), default_config());
        assert!(result.classified.is_empty());
        assert!(result.false_negatives.is_empty());
        assert_eq!(result.unmatched_finding_paths, 0);
        assert_eq!(result.unmatchable_truth_paths, 0);
        assert_eq!(result.out_of_bounds_findings, 0);
        assert_eq!(result.unmatchable_findings, 0);
    }

    #[test]
    fn multi_line_partial_overlap() {
        let findings = vec![make_finding(SIMPLE_PATH, 0, 10, "r", 5)];
        let truth = vec![make_truth(SIMPLE_PATH, 2, 3, TruthLabel::Positive, "r")];
        let fc = contents(&[(SIMPLE_PATH, SIMPLE_FILE)]);

        let result = match_findings(findings, truth, &fc, default_config());
        assert_eq!(result.classified[0].class, FindingClass::TruePositive);
    }

    #[test]
    fn negative_truth_not_consumed() {
        let findings = vec![
            make_finding(SIMPLE_PATH, 0, 4, "r1", 10),
            make_finding(SIMPLE_PATH, 1, 4, "r2", 5),
        ];
        let truth = vec![make_truth(SIMPLE_PATH, 1, 1, TruthLabel::Negative, "r")];
        let fc = contents(&[(SIMPLE_PATH, SIMPLE_FILE)]);

        let result = match_findings(findings, truth, &fc, default_config());
        assert_eq!(result.classified[0].class, FindingClass::FalsePositive);
        assert_eq!(result.classified[1].class, FindingClass::FalsePositive);
    }

    #[test]
    fn placeholder_truth_not_consumed() {
        let findings = vec![
            make_finding(SIMPLE_PATH, 0, 4, "r1", 10),
            make_finding(SIMPLE_PATH, 1, 4, "r2", 5),
        ];
        let truth = vec![make_truth(SIMPLE_PATH, 1, 1, TruthLabel::Placeholder, "r")];
        let fc = contents(&[(SIMPLE_PATH, SIMPLE_FILE)]);

        let result = match_findings(findings, truth, &fc, default_config());
        assert_eq!(result.classified[0].class, FindingClass::Unlabeled);
        assert_eq!(result.classified[1].class, FindingClass::Unlabeled);
    }

    #[test]
    fn confidence_tie_determinism() {
        let findings = vec![
            make_finding(SIMPLE_PATH, 0, 4, "r1", 5),
            make_finding(SIMPLE_PATH, 0, 4, "r2", 5),
        ];
        let truth = vec![make_truth(SIMPLE_PATH, 1, 1, TruthLabel::Positive, "r")];
        let fc = contents(&[(SIMPLE_PATH, SIMPLE_FILE)]);

        let result1 = match_findings(findings.clone(), truth.clone(), &fc, default_config());
        let result2 = match_findings(findings, truth, &fc, default_config());

        assert_eq!(result1.classified[0].class, result2.classified[0].class);
        assert_eq!(result1.classified[1].class, result2.classified[1].class);

        // "r1" < "r2" in Ord, so r1 is processed first and gets TP.
        assert_eq!(result1.classified[0].class, FindingClass::TruePositive);
        assert_eq!(result1.classified[0].finding.rule, "r1");
    }

    #[test]
    #[should_panic(expected = "findings must be deduplicated by rule before matching")]
    fn duplicate_findings_precondition_panics() {
        let findings = vec![
            make_finding(SIMPLE_PATH, 0, 4, "dup", 10),
            make_finding(SIMPLE_PATH, 5, 9, "other", 9),
            // Duplicate identity (path/start/end/rule) with different confidence.
            make_finding(SIMPLE_PATH, 0, 4, "dup", 1),
        ];
        let truth = vec![make_truth(SIMPLE_PATH, 1, 2, TruthLabel::Positive, "r")];
        let fc = contents(&[(SIMPLE_PATH, SIMPLE_FILE)]);

        let _ = match_findings(findings, truth, &fc, default_config());
    }

    #[test]
    #[should_panic(expected = "findings must be deduplicated by span before cross-rule matching")]
    fn cross_rule_duplicate_span_precondition_panics() {
        let findings = vec![
            make_finding(SIMPLE_PATH, 0, 4, "r1", 10),
            make_finding(SIMPLE_PATH, 0, 4, "r2", 9),
        ];
        let truth = vec![make_truth(SIMPLE_PATH, 1, 1, TruthLabel::Positive, "r1")];
        let fc = contents(&[(SIMPLE_PATH, SIMPLE_FILE)]);
        let config = MatchConfig {
            require_rule_match: false,
            dedup_mode: DedupMode::AcrossRules,
        };

        let _ = match_findings(findings, truth, &fc, config);
    }

    #[test]
    #[should_panic(expected = "require_rule_match cannot be combined with cross-rule dedup mode")]
    fn cross_rule_mode_rejects_rule_match_requirement() {
        let findings = vec![make_finding(SIMPLE_PATH, 0, 4, "r1", 10)];
        let truth = vec![make_truth(SIMPLE_PATH, 1, 1, TruthLabel::Positive, "r1")];
        let fc = contents(&[(SIMPLE_PATH, SIMPLE_FILE)]);
        let config = MatchConfig {
            require_rule_match: true,
            dedup_mode: DedupMode::AcrossRules,
        };

        let _ = match_findings(findings, truth, &fc, config);
    }

    #[test]
    fn finding_spans_entire_file() {
        let findings = vec![make_finding(
            SIMPLE_PATH,
            0,
            SIMPLE_FILE.len() as u64,
            "r",
            5,
        )];
        let truth = vec![make_truth(SIMPLE_PATH, 2, 2, TruthLabel::Positive, "r")];
        let fc = contents(&[(SIMPLE_PATH, SIMPLE_FILE)]);

        let result = match_findings(findings, truth, &fc, default_config());
        assert_eq!(result.classified[0].class, FindingClass::TruePositive);
    }

    // ── rule_matches helper tests ───────────────────────────────────

    #[test]
    fn rule_matches_exact() {
        assert!(rule_matches("Token", "Token"));
    }

    #[test]
    fn rule_matches_colon_split() {
        assert!(rule_matches("Token", "Secret:Token"));
        assert!(rule_matches("Secret", "Secret:Token"));
    }

    #[test]
    fn rule_matches_no_match() {
        assert!(!rule_matches("Other", "Secret:Token"));
        assert!(!rule_matches("Tok", "Secret:Token"));
    }

    // ── Property tests ──────────────────────────────────────────────

    mod prop {
        use super::*;
        use proptest::prelude::*;

        fn file_bytes() -> impl Strategy<Value = Vec<u8>> {
            prop_oneof![
                proptest::collection::vec(prop_oneof![Just(b'\n'), Just(b'x')], 1..200),
                proptest::collection::vec(Just(b'x'), 1..200),
            ]
        }

        fn truth_item_for(path: String, line_count: u32) -> impl Strategy<Value = TruthItem> {
            (
                1..=line_count,
                prop_oneof![
                    Just(TruthLabel::Positive),
                    Just(TruthLabel::Negative),
                    Just(TruthLabel::Placeholder),
                ],
                prop_oneof![Just("r1".to_string()), Just("r2".to_string())],
            )
                .prop_flat_map(move |(start, label, rule)| {
                    let p = path.clone();
                    (start..=line_count).prop_map(move |end| {
                        TruthItem::new(p.clone(), start, end, label, rule.clone())
                    })
                })
        }

        fn finding_for(path: String, data_len: u64) -> impl Strategy<Value = NormalizedFinding> {
            (
                0..data_len.max(1),
                -128i8..=127i8,
                prop_oneof![Just("r1".to_string()), Just("r2".to_string())],
            )
                .prop_flat_map(move |(start, conf, rule)| {
                    let p = path.clone();
                    (start..=data_len).prop_map(move |end| {
                        NormalizedFinding::new(p.clone(), start, end, rule.clone(), conf)
                    })
                })
        }

        #[derive(Debug, Clone)]
        struct Scenario {
            file_contents: HashMap<String, Vec<u8>>,
            truth: Vec<TruthItem>,
            findings: Vec<NormalizedFinding>,
        }

        fn scenario() -> impl Strategy<Value = Scenario> {
            proptest::collection::vec(file_bytes(), 1..=3).prop_flat_map(|files| {
                let paths: Vec<String> = (0..files.len()).map(|i| format!("f{i}.txt")).collect();
                let file_contents: HashMap<String, Vec<u8>> =
                    paths.iter().cloned().zip(files.iter().cloned()).collect();

                let line_counts: Vec<u32> = files
                    .iter()
                    .map(|f| LineIndex::new(f).line_count())
                    .collect();
                let data_lens: Vec<u64> = files.iter().map(|f| f.len() as u64).collect();

                let truth_strats: Vec<_> = paths
                    .iter()
                    .zip(line_counts.iter())
                    .map(|(p, &lc)| {
                        proptest::collection::vec(truth_item_for(p.clone(), lc), 0..=10)
                    })
                    .collect();

                let finding_strats: Vec<_> = paths
                    .iter()
                    .zip(data_lens.iter())
                    .map(|(p, &dl)| proptest::collection::vec(finding_for(p.clone(), dl), 0..=10))
                    .collect();

                (truth_strats, finding_strats).prop_map(move |(truth_groups, finding_groups)| {
                    let mut truth: Vec<TruthItem> = truth_groups.into_iter().flatten().collect();
                    let mut findings: Vec<NormalizedFinding> =
                        finding_groups.into_iter().flatten().collect();

                    findings.sort();
                    findings.dedup_by(|a, b| {
                        if a == b {
                            b.confidence = b.confidence.max(a.confidence);
                            true
                        } else {
                            false
                        }
                    });

                    truth.sort_by(|a, b| {
                        a.path
                            .cmp(&b.path)
                            .then(a.line_start.cmp(&b.line_start))
                            .then(a.line_end.cmp(&b.line_end))
                            .then(a.rule.cmp(&b.rule))
                    });
                    truth.dedup_by(|a, b| {
                        a.path == b.path
                            && a.line_start == b.line_start
                            && a.line_end == b.line_end
                            && a.rule == b.rule
                            && a.label == b.label
                    });

                    Scenario {
                        file_contents: file_contents.clone(),
                        truth,
                        findings,
                    }
                })
            })
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(256))]

            #[test]
            fn conservation_finding_count(s in scenario()) {
                let result = match_findings(
                    s.findings, s.truth, &s.file_contents, default_config(),
                );
                prop_assert_eq!(
                    result.tp_count() + result.fp_count() + result.unlabeled_count(),
                    result.classified.len() as u64,
                    "tp+fp+unlabeled != findings.len()"
                );
            }

            #[test]
            fn conservation_truth_count(s in scenario()) {
                let total_positives = s.truth.iter()
                    .filter(|t| t.label == TruthLabel::Positive)
                    .count() as u64;
                let result = match_findings(
                    s.findings, s.truth, &s.file_contents, default_config(),
                );
                prop_assert_eq!(
                    result.tp_count() + result.fn_count(),
                    total_positives,
                    "tp+fn != total_positives"
                );
            }

            #[test]
            fn determinism(s in scenario()) {
                let r1 = match_findings(
                    s.findings.clone(), s.truth.clone(), &s.file_contents, default_config(),
                );
                let r2 = match_findings(
                    s.findings, s.truth, &s.file_contents, default_config(),
                );
                prop_assert_eq!(r1.classified.len(), r2.classified.len());
                for (a, b) in r1.classified.iter().zip(r2.classified.iter()) {
                    prop_assert_eq!(a.class, b.class);
                    prop_assert_eq!(&a.finding, &b.finding);
                }
                prop_assert_eq!(r1.false_negatives.len(), r2.false_negatives.len());
            }

            #[test]
            fn one_to_one(s in scenario()) {
                let total_positives = s.truth.iter()
                    .filter(|t| t.label == TruthLabel::Positive)
                    .count() as u64;
                let result = match_findings(
                    s.findings, s.truth, &s.file_contents, default_config(),
                );
                prop_assert!(
                    result.tp_count() <= total_positives,
                    "more TPs ({}) than positive truths ({})",
                    result.tp_count(), total_positives
                );
            }

            #[test]
            fn path_isolation(
                file_a in file_bytes(),
                file_b in file_bytes(),
                conf in -128i8..=127i8,
            ) {
                prop_assume!(!file_a.is_empty() && !file_b.is_empty());
                let idx_b = LineIndex::new(&file_b);

                let findings = vec![NormalizedFinding::new(
                    "a.txt".into(), 0, file_a.len() as u64, "r".into(), conf,
                )];
                let truth = vec![TruthItem::new(
                    "b.txt".into(), 1, idx_b.line_count(), TruthLabel::Positive, "r".into(),
                )];
                let fc = contents(&[
                    ("a.txt", &file_a),
                    ("b.txt", &file_b),
                ]);

                let result = match_findings(findings, truth, &fc, default_config());
                prop_assert_eq!(result.classified[0].class, FindingClass::Unlabeled);
                prop_assert_eq!(result.false_negatives.len(), 1);
            }

            #[test]
            fn label_consistency_no_tp_from_negative(s in scenario()) {
                let has_positive = s.truth.iter().any(|t| t.label == TruthLabel::Positive);
                let result = match_findings(
                    s.findings, s.truth, &s.file_contents, default_config(),
                );
                if !has_positive {
                    prop_assert_eq!(
                        result.tp_count(), 0,
                        "TP found with no positive truths"
                    );
                }
            }

            #[test]
            fn negative_never_tp(s in scenario()) {
                let all_negative = s.truth.iter().all(|t| t.label == TruthLabel::Negative);
                let result = match_findings(
                    s.findings, s.truth, &s.file_contents, default_config(),
                );
                if all_negative {
                    prop_assert_eq!(result.tp_count(), 0, "TP from Negative-only truths");
                }
            }

            #[test]
            fn placeholder_neutrality(s in scenario()) {
                let truth_no_placeholder: Vec<TruthItem> = s.truth.iter()
                    .filter(|t| t.label != TruthLabel::Placeholder)
                    .cloned()
                    .collect();
                let result_with = match_findings(
                    s.findings.clone(), s.truth, &s.file_contents, default_config(),
                );
                let result_without = match_findings(
                    s.findings, truth_no_placeholder, &s.file_contents, default_config(),
                );
                prop_assert_eq!(
                    result_with.tp_count(), result_without.tp_count(),
                    "placeholder removal changed TP count"
                );
                prop_assert_eq!(
                    result_with.fp_count(), result_without.fp_count(),
                    "placeholder removal changed FP count"
                );
            }

            #[test]
            fn fp_bounded_by_negatives(s in scenario()) {
                let has_negative = s.truth.iter().any(|t| t.label == TruthLabel::Negative);
                let result = match_findings(
                    s.findings, s.truth, &s.file_contents, default_config(),
                );
                if !has_negative {
                    prop_assert_eq!(
                        result.fp_count(), 0,
                        "FP without any Negative truths"
                    );
                }
            }

            #[test]
            fn recall_monotonicity(s in scenario()) {
                let total_positives = s.truth.iter()
                    .filter(|t| t.label == TruthLabel::Positive)
                    .count() as u64;
                let result = match_findings(
                    s.findings, s.truth, &s.file_contents, default_config(),
                );

                if total_positives == 0 {
                    return Ok(());
                }

                let mut cumulative_tp: u64 = 0;
                let mut prev_recall: f64 = 0.0;

                for cf in &result.classified {
                    if cf.class == FindingClass::TruePositive {
                        cumulative_tp += 1;
                    }
                    let recall = cumulative_tp as f64 / total_positives as f64;
                    prop_assert!(
                        recall >= prev_recall,
                        "recall decreased from {} to {} at confidence {}",
                        prev_recall, recall, cf.finding.confidence
                    );
                    prev_recall = recall;
                }
            }
        }
    }
}
