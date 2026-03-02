//! Regex-to-Anchors: Extract literal anchors from regex patterns for prefiltering.
//!
//! This module derives a *sound* set of literal substrings ("anchors") from a regex
//! pattern. The intended use is **fast prefiltering** in a secret scanner: scan a
//! haystack for any anchor first, then run the full regex only if an anchor is
//! present. Anchors are byte substrings (not necessarily valid UTF-8); all length
//! limits in this module are measured in bytes.
//!
//! # Soundness invariant (the only non-negotiable rule)
//!
//! ```text
//! For any pattern and haystack:
//! if regex_matches(pattern, haystack),
//! then haystack must contain at least one derived anchor.
//! ```
//!
//! If this invariant is violated, a scanner will have **false negatives** (missed
//! secrets). The algorithm is therefore conservative: it returns errors when it
//! cannot safely produce anchors.
//!
//! # Invariants
//! - Returned anchors are sufficient for a sound OR prefilter.
//! - Patterns that can match the empty string are never anchored.
//! - `AnchorDeriveConfig::utf8` must match the regex engine semantics.
//! - Length limits are in bytes, not Unicode scalar values.
//!
//! # Algorithm
//!
//! 1. Parse the pattern into the regex-syntax HIR (high-level intermediate
//!    representation) so we can reason about structure safely.
//! 2. Walk the HIR and compute `Info` for each node:
//!    - `exact`: an explicit, *finite* set of strings the node can match.
//!    - `pf`: a prefilter summary (substring or set of substrings) that **must**
//!      appear in any match.
//! 3. Combine child `Info` values using rules that preserve the soundness
//!    invariant (concatenation, alternation, repetition, etc).
//! 4. Convert the final `Info` into anchors, enforcing minimum length and
//!    rejecting patterns that can match the empty string.
//!
//! # Design notes and limitations
//!
//! - This module never guesses: if it cannot *prove* a required substring, it
//!   returns an error or an unfilterable plan rather than risk false negatives.
//! - Look-around assertions are treated as zero-width for anchor derivation.
//!   Only ASCII word boundaries are used by residue gates.
//! - Character classes are expanded only when small and ASCII/byte-only.
//!   Large or non-ASCII classes are treated as "match anything" for anchors.
//! - Repetitions that can match empty drop required substrings entirely.
//!
//! # Why HIR (and what it gives us)
//!
//! The HIR produced by `regex-syntax` already accounts for flags, case folding,
//! and many syntactic details. For example, `(?i:ab)` is translated into a
//! character class like `[aA][bB]`, which we can analyze without having to
//! implement case folding ourselves.
//!
//! References:
//! - `regex-syntax` crate docs: <https://docs.rs/regex-syntax/>
//! - HIR overview: <https://docs.rs/regex-syntax/latest/regex_syntax/hir/index.html>

use regex_syntax::hir::{Class, Hir, HirKind, Literal, Look, Repetition};
use std::cmp::Ordering;

/// Configuration for anchor derivation.
///
/// # Guarantees
/// - Enumeration caps bound exact-set growth; exceeding them degrades to broader
///   summaries or errors instead of returning unsound anchors.
/// - `min_anchor_len` is enforced at selection time; shorter required strings
///   yield `AnchorDeriveError::OnlyWeakAnchors`.
///
/// # Invariants
/// - All lengths are in bytes.
/// - `utf8` must match the regex engine used for the final match.
/// - k-gram fields only apply when the `kgram-gate` feature is enabled.
///
/// # Performance
/// - Larger caps increase enumeration cost; smaller caps increase the chance of
///   falling back to broader prefilters or `Unfilterable` results.
#[derive(Debug, Clone)]
pub struct AnchorDeriveConfig {
    /// Minimum length for an anchor to be useful.
    /// Anchors shorter than this are considered too weak.
    pub min_anchor_len: usize,
    /// Maximum number of elements in an exact set before degrading to broader prefilters.
    pub max_exact_set: usize,
    /// Maximum length of any single string in an exact set.
    pub max_exact_string_len: usize,
    /// Maximum size for character class expansion.
    pub max_class_expansion: usize,
    /// Whether to require UTF-8 matching semantics when parsing the pattern.
    /// When false, byte-oriented patterns (e.g. `(?-u)` or `\xFF`) are allowed.
    ///
    /// This flag should match the semantics of the regex engine you will use
    /// for the final match:
    /// - Use `utf8 = true` for `regex::Regex` (Unicode-aware).
    /// - Use `utf8 = false` for `regex::bytes::Regex` or byte-oriented patterns.
    ///
    /// If you parse with UTF-8 semantics but later match as bytes (or vice versa),
    /// you can miss valid anchors or derive anchors for strings that never match.
    pub utf8: bool,
    /// Optional k-gram gate size (prefix window length).
    /// Only used when the `kgram-gate` feature is enabled.
    pub kgram_k: usize,
    /// Maximum number of k-grams to enumerate for the gate.
    /// Only used when the `kgram-gate` feature is enabled.
    pub max_kgram_set: usize,
    /// Maximum alphabet size per position when enumerating k-grams.
    /// Only used when the `kgram-gate` feature is enabled.
    pub max_kgram_alphabet: usize,
}

impl Default for AnchorDeriveConfig {
    fn default() -> Self {
        Self {
            min_anchor_len: 3,
            max_exact_set: 64,
            max_exact_string_len: 256,
            max_class_expansion: 16,
            utf8: true,
            kgram_k: 4,
            max_kgram_set: 4096,
            max_kgram_alphabet: 32,
        }
    }
}

/// Errors that can occur during anchor derivation.
///
/// # Notes
/// - These errors are conservative: they indicate no sound anchor set exists
///   under the current configuration.
/// - `compile_trigger_plan` may map `Unanchorable`/`OnlyWeakAnchors` into
///   `UnfilterableReason` after attempting residue gates. `InvalidPattern`
///   is returned directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnchorDeriveError {
    /// The regex pattern is invalid.
    InvalidPattern(String),
    /// The pattern cannot be anchored (e.g., `.*`).
    Unanchorable,
    /// Only weak anchors were found (shorter than min_anchor_len).
    OnlyWeakAnchors,
}

/// A prefilter represents the extracted anchor information.
///
/// # Invariants
/// - `Substring`/`AnyOf` describe byte substrings that must appear in any match.
/// - `All` means no required substring can be proven.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Prefilter {
    /// No useful anchors - pattern matches too broadly.
    All,
    /// A set of literal strings, any of which must be present.
    /// For alternation like `(foo|bar)`, this contains `["foo", "bar"]`.
    AnyOf(Vec<Vec<u8>>),
    /// A single substring that must be present.
    Substring(Vec<u8>),
}

/// Output of regex prefilter compilation for a single rule.
///
/// # Semantics
/// - `Anchored`: OR over `anchors`, optional AND over `confirm_all`.
/// - `Residue`: conservative ASCII-only gates used when anchors are unavailable.
/// - `Unfilterable`: no safe gate; caller must run the full regex or skip.
///
/// # Soundness
/// - `Anchored` guarantees at least one anchor is present in any match.
/// - `Residue` provides a conservative gate when anchors are unavailable.
#[derive(Debug, Clone)]
pub enum TriggerPlan {
    Anchored {
        /// Any match must contain at least one of these anchors (sound OR set).
        anchors: Vec<Vec<u8>>,
        /// Optional AND filter of mandatory literal islands.
        /// Each entry must appear in any match; used to reduce false positives
        /// after an anchor hit. Safe to leave empty.
        confirm_all: Vec<Vec<u8>>,
    },
    Residue {
        gate: ResidueGatePlan,
    },
    Unfilterable {
        reason: UnfilterableReason,
    },
}

/// Reasons an anchor or gate could not be produced safely.
///
/// # Notes
/// - `UnsupportedRegexFeatures` is set by higher-level validation when the
///   regex engine accepts constructs this module does not model.
#[derive(Debug, Clone)]
pub enum UnfilterableReason {
    /// Pattern can match the empty string.
    MatchesEmptyString,
    /// All required anchors are shorter than `min_anchor_len`.
    OnlyWeakAnchors,
    /// Uses features this module does not model safely.
    UnsupportedRegexFeatures,
    /// No sound gate could be derived under the configured limits.
    NoSoundGate,
}

/// Secondary gating plan when anchors are unavailable.
///
/// These gates are conservative, ASCII-only summaries. They should be treated
/// as prefilters and may still require a full regex match.
#[derive(Debug, Clone)]
pub enum ResidueGatePlan {
    /// Fast linear scan for a run of a byteclass of length [min,max].
    /// Only sound for patterns that reduce to a single consuming atom.
    RunLength(RunLengthGate),
    /// Enumerated, bounded k-grams. Derived when the `kgram-gate` feature is enabled.
    KGrams(KGramGate),
    /// Logical OR of gate plans (used for alternations).
    Or(Vec<ResidueGatePlan>),
}

/// Boundary semantics applied by the gate (ASCII-only).
#[derive(Debug, Clone, Copy)]
pub enum Boundary {
    None,
    /// \b under ASCII definition [A-Za-z0-9_].
    ///
    /// This is only used when both leading and trailing word boundaries are
    /// present. A single-sided boundary is ignored to avoid false negatives.
    AsciiWord,
}

/// Run-length gate spec (ASCII byte-oriented).
///
/// # Guarantees
/// - When produced by this module, any match contains a run that satisfies
///   this gate.
///
/// # Invariants
/// - The gate scans for runs of bytes contained in `byte_mask` (ASCII only).
/// - `min_len`/`max_len` are measured in bytes.
/// - `boundary = AsciiWord` means require word boundaries on both sides.
#[derive(Debug, Clone)]
pub struct RunLengthGate {
    /// 256-bit membership mask for bytes allowed in the run.
    pub byte_mask: [u64; 4],
    /// Min number of units in the run (bytes).
    pub min_len: u32,
    /// Optional max. `None` means unbounded.
    pub max_len: Option<u32>,
    /// ASCII boundary handling applied around the run.
    pub boundary: Boundary,
    /// If you want entropy gating, make it explicit rule semantics.
    /// Do NOT infer it automatically and call it “sound”.
    pub min_entropy: Option<f32>,
    /// Whether to also scan UTF-16LE/BE ASCII forms:
    /// - LE: [byte, 0] repeated
    /// - BE: [0, byte] repeated
    pub scan_utf16_variants: bool,
}

/// K-gram gate spec for prefix scanning.
///
/// `gram_hashes` is sorted and deduplicated. For `k <= 8`, grams are packed
/// little-endian into a `u64`; longer grams use FNV-1a hashing.
#[derive(Debug, Clone)]
pub struct KGramGate {
    /// Prefix length (k) used for the gate.
    pub k: u8,
    /// Use hashed grams for AMQ scanning. Keep raw grams if count is tiny.
    pub gram_hashes: Vec<u64>,
    /// Where the k-gram is guaranteed to appear.
    pub position: PositionHint,
}

/// Hint for where a k-gram must appear within the match.
///
/// `Prefix` means the k-gram is guaranteed at the start of the match, `Suffix`
/// at the end, and `Anywhere` indicates only presence somewhere in the match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PositionHint {
    Prefix,
    Suffix,
    Anywhere,
}

/// Internal representation tracking both exact matches and prefilter info.
///
/// # Invariants
/// - If `exact = Some(S)`, the node matches **exactly** the byte strings in `S`.
/// - If `exact = None`, `pf` summarizes a *necessary* substring condition.
/// - Combining nodes only ever weakens information, never strengthens it.
#[derive(Debug, Clone)]
struct Info {
    /// If Some, the exact set of strings this node can match.
    /// None means the set is too large or unbounded.
    exact: Option<Vec<Vec<u8>>>,
    /// The prefilter derived from this node.
    pf: Prefilter,
}

impl Info {
    /// Create an Info representing "matches anything" (e.g., `.*`).
    fn all() -> Self {
        Self {
            exact: None,
            pf: Prefilter::All,
        }
    }

    /// Create an Info from an exact set of strings.
    /// Does NOT check min_anchor_len - that's done at the final step.
    fn exact(mut set: Vec<Vec<u8>>, cfg: &AnchorDeriveConfig) -> Option<Self> {
        set.sort_unstable();
        set.dedup();
        if set.len() > cfg.max_exact_set {
            return None;
        }
        if set.iter().any(|s| s.len() > cfg.max_exact_string_len) {
            return None;
        }
        Some(Self {
            exact: Some(set),
            pf: Prefilter::All,
        })
    }

    /// Create an Info with a prefilter but no exact set.
    fn with_prefilter(pf: Prefilter) -> Self {
        Self { exact: None, pf }
    }
}

/// Expand a character class to a set of bytes if small enough.
///
/// We only expand ASCII or byte ranges when they remain small. Large or Unicode
/// ranges would explode the search space and are therefore treated as "match
/// anything" for anchor purposes.
///
/// # Returns
/// - `Some(bytes)` for small ASCII/byte ranges.
/// - `None` when the expansion is large or non-ASCII.
fn class_to_small_byte_set(class: &Class, cfg: &AnchorDeriveConfig) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    match class {
        Class::Unicode(ranges) => {
            for range in ranges.iter() {
                for c in range.start()..=range.end() {
                    if c as u32 > 127 {
                        // Non-ASCII expansion is large and not byte-stable here.
                        return None;
                    }
                    bytes.push(c as u8);
                    if bytes.len() > cfg.max_class_expansion {
                        return None;
                    }
                }
            }
        }
        Class::Bytes(ranges) => {
            for range in ranges.iter() {
                for b in range.start()..=range.end() {
                    bytes.push(b);
                    if bytes.len() > cfg.max_class_expansion {
                        return None;
                    }
                }
            }
        }
    }
    Some(bytes)
}

/// Convert a character class to a 256-bit ASCII-only byte mask.
///
/// # Returns
/// - `Some(mask)` for classes entirely within ASCII.
/// - `None` if the class contains any non-ASCII byte.
fn class_to_ascii_mask(class: &Class) -> Option<[u64; 4]> {
    let mut mask = [0u64; 4];
    let mut set_bit = |b: u8| {
        let idx = (b >> 6) as usize;
        let bit = b & 63;
        mask[idx] |= 1u64 << bit;
    };

    match class {
        Class::Unicode(ranges) => {
            for range in ranges.iter() {
                for c in range.start()..=range.end() {
                    if c as u32 > 0x7F {
                        return None;
                    }
                    set_bit(c as u8);
                }
            }
        }
        Class::Bytes(ranges) => {
            for range in ranges.iter() {
                for b in range.start()..=range.end() {
                    if b > 0x7F {
                        return None;
                    }
                    set_bit(b);
                }
            }
        }
    }

    Some(mask)
}

/// Convert a character class to a sorted ASCII byte vector.
///
/// # Returns
/// - `Some(bytes)` when the class is ASCII-only.
/// - `None` when the class contains non-ASCII bytes.
#[cfg(feature = "kgram-gate")]
fn class_to_ascii_vec(class: &Class) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    match class {
        Class::Unicode(ranges) => {
            for range in ranges.iter() {
                for c in range.start()..=range.end() {
                    if c as u32 > 0x7F {
                        return None;
                    }
                    bytes.push(c as u8);
                }
            }
        }
        Class::Bytes(ranges) => {
            for range in ranges.iter() {
                for b in range.start()..=range.end() {
                    if b > 0x7F {
                        return None;
                    }
                    bytes.push(b);
                }
            }
        }
    }
    bytes.sort_unstable();
    bytes.dedup();
    if bytes.is_empty() { None } else { Some(bytes) }
}

/// Convert a single-byte literal to an ASCII-only mask.
///
/// # Returns
/// - `Some(mask)` for single-byte ASCII literals.
/// - `None` for multi-byte or non-ASCII literals.
fn literal_byte_to_mask(bytes: &[u8]) -> Option<[u64; 4]> {
    if bytes.len() != 1 {
        return None;
    }
    let b = bytes[0];
    if b > 0x7F {
        return None;
    }
    let mut mask = [0u64; 4];
    let idx = (b >> 6) as usize;
    let bit = b & 63;
    mask[idx] |= 1u64 << bit;
    Some(mask)
}

/// Compute cross product of two exact sets (concatenation).
///
/// This is the core operation for concatenation and repetition. We cap both
/// the total number of strings and the length of each string to avoid
/// combinatorial blowups.
///
/// Complexity is O(|A| * |B|) strings plus concatenation cost.
///
/// # Returns
/// - `Some(product)` when within size/length limits.
/// - `None` when caps or size overflows are hit.
fn cross_product(a: &[Vec<u8>], b: &[Vec<u8>], cfg: &AnchorDeriveConfig) -> Option<Vec<Vec<u8>>> {
    let prod = a.len().checked_mul(b.len())?;
    if prod > cfg.max_exact_set {
        return None;
    }

    let mut result = Vec::with_capacity(prod);
    for x in a {
        for y in b {
            let len = x.len().checked_add(y.len())?;
            if len > cfg.max_exact_string_len {
                return None;
            }
            let mut combined = Vec::with_capacity(len);
            combined.extend_from_slice(x);
            combined.extend_from_slice(y);
            result.push(combined);
        }
    }
    Some(result)
}

/// Analyze a HIR node and extract anchor information.
///
/// This function is the heart of the algorithm: it performs structural
/// induction on the HIR and returns an `Info` summary for each node.
///
/// # Soundness
/// - Information is only ever weakened, never strengthened.
///
/// # Returns
/// - An `Info` with an exact set when finite and within caps.
/// - Otherwise a conservative prefilter that preserves the invariant.
fn analyze(hir: &Hir, cfg: &AnchorDeriveConfig) -> Info {
    match hir.kind() {
        HirKind::Empty => {
            // Empty consumes no bytes; exact {""} keeps concat/alt reasoning sound.
            Info::exact(vec![vec![]], cfg).unwrap_or_else(Info::all)
        }

        HirKind::Literal(Literal(bytes)) => {
            // Literal contributes a fixed byte sequence; exact singleton is precise.
            Info::exact(vec![bytes.to_vec()], cfg).unwrap_or_else(Info::all)
        }

        HirKind::Class(class) => {
            // Expand small ASCII/byte classes; large or Unicode classes explode.
            if let Some(bytes) = class_to_small_byte_set(class, cfg) {
                let set: Vec<Vec<u8>> = bytes.into_iter().map(|b| vec![b]).collect();
                Info::exact(set, cfg).unwrap_or_else(Info::all)
            } else {
                Info::all()
            }
        }

        HirKind::Look(_) => {
            // Lookarounds consume nothing, so they behave like empty for anchors.
            Info::exact(vec![vec![]], cfg).unwrap_or_else(Info::all)
        }

        HirKind::Repetition(rep) => analyze_repetition(rep, cfg),

        HirKind::Capture(cap) => {
            // Captures do not change matched bytes; unwrap for anchor analysis.
            analyze(&cap.sub, cfg)
        }

        HirKind::Concat(subs) => analyze_concat(subs, cfg),

        HirKind::Alternation(alts) => analyze_alternation(alts, cfg),
    }
}

/// Analyze repetition (*, +, ?, {n,m}).
///
/// Key rule: if the repetition can match empty (min == 0), then it cannot
/// *require* any anchor from its subexpression. We therefore degrade to `All`,
/// except for the `?` case where the exact set is still finite.
///
/// # Soundness
/// - When `min == 0`, required substrings may disappear, so anchors are dropped.
fn analyze_repetition(rep: &Repetition, cfg: &AnchorDeriveConfig) -> Info {
    let min = rep.min;
    let max = rep.max;
    let sub_info = analyze(&rep.sub, cfg);

    // Zero repeats allow empty; required substrings may disappear.
    if min == 0 {
        // Exact {""} preserves soundness for a forced-empty repetition.
        if max == Some(0) {
            return Info::exact(vec![vec![]], cfg).unwrap_or_else(Info::all);
        }

        // If the sub is finite and max==1, the exact set is still enumerable.
        if let Some(exact) = &sub_info.exact {
            // The `?` case yields {""} ∪ sub, which is finite and exact.
            if max == Some(1) {
                let mut set = vec![vec![]];
                set.extend(exact.iter().cloned());
                return Info::exact(set, cfg).unwrap_or_else(Info::all);
            }
        }

        // Unbounded or large finite repetitions yield too many combinations.
        return Info::all();
    }

    // At least n copies are mandatory, so a required prefix can be derived.
    if let Some(exact) = sub_info.exact {
        // Enumerate the exact set for the minimum repetition count.
        let mut result = exact.clone();
        for _ in 1..min {
            if let Some(product) = cross_product(&result, &exact, cfg) {
                result = product;
            } else {
                // Size/length caps exceeded; fall back to All.
                return Info::all();
            }
        }

        // Exact repetition count stays finite.
        if max == Some(min) {
            return Info::exact(result, cfg).unwrap_or_else(Info::all);
        }

        // For larger max, the minimum concatenations are still mandatory
        // substrings, but the full exact set is unbounded.
        if result.len() == 1 {
            return Info {
                exact: None,
                pf: Prefilter::Substring(result.into_iter().next().unwrap()),
            };
        } else {
            return Info {
                exact: None,
                pf: Prefilter::AnyOf(result),
            };
        }
    }

    // No exact set; propagate whatever mandatory substring the sub provided.
    sub_info
}

/// Weight used to treat 1 byte ~= 8 bits of "selectivity" in scoring heuristics.
///
/// Example: a 3-byte required substring scores as 24 "bits".
/// This is not a probability model; it only puts length and log2(set size)
/// on comparable units.
const SCORE_BITS_PER_BYTE: i64 = 8;

/// Returns ceil(log2(n)) for n >= 1, or 0 for n <= 1.
///
/// Examples: n=1 -> 0, n=2 -> 1, n=3..4 -> 2, n=5..8 -> 3.
/// Used as a small penalty for large AnyOf sets: choosing one element from a
/// set of size N costs about log2(N) bits of information.
fn ceil_log2(n: usize) -> usize {
    if n <= 1 {
        0
    } else {
        let x = n - 1;
        (usize::BITS - x.leading_zeros()) as usize
    }
}

/// Heuristic score for an anchor set.
///
/// Rationale:
/// - Longer required substrings are generally more selective.
/// - Large AnyOf sets can be cheap to match but are less selective; we apply a
///   log2 penalty to avoid preferring giant sets with short members.
///
/// Example: min_len=4, set_size=16 -> score = 4*8 - ceil_log2(16) = 32 - 4 = 28.
/// This keeps the scoring monotonic with length while gently discouraging
/// large sets. It is a heuristic, not a correctness requirement.
fn anchor_set_score(min_len: usize, set_size: usize) -> i64 {
    let penalty = ceil_log2(set_size.max(1)) as i64;
    (min_len as i64) * SCORE_BITS_PER_BYTE - penalty
}

/// Find the best contiguous exact "window" within a concat.
///
/// Example (case-folded literal):
/// - Pattern: `(?i:abcdef)`
/// - HIR: `[aA][bB][cC][dD][eE][fF]`
/// - Full exact set size: 2^6 = 64 (often too large to keep)
/// - A 3-atom window yields 2^3 = 8 exact substrings (e.g., "abc", "Abc", ...)
///
/// We consider every contiguous run of exact children, compute the exact set
/// for that window (bounded by config caps), and pick the best window by the
/// same scoring heuristic used for other prefilters. This is sound: any match
/// of the concat must include every contiguous exact window, so choosing one
/// is still a necessary substring condition.
///
/// Concrete example (min_anchor_len = 3):
/// ```text
/// +----------------------------------------------------------------------------+
/// |              EXAMPLE: "api" [_-] "key" "=" [0-9]+                           |
/// +----------------------------------------------------------------------------+
/// |                                                                            |
/// |   Children after analysis:                                                 |
/// |       [0] exact: ["api"]                                                   |
/// |       [1] exact: ["_", "-"]                                                |
/// |       [2] exact: ["key"]                                                   |
/// |       [3] exact: ["="]                                                     |
/// |       [4] exact: None (pf: All)                                            |
/// |                                                                            |
/// |   Window search:                                                           |
/// |   --------------                                                           |
/// |                                                                            |
/// |   START=0:                                                                 |
/// |     acc = [""]                                                             |
/// |     x ["api"] -> ["api"]                  score(3,1) = 24                  |
/// |     x ["_","-"] -> ["api_","api-"]        score(4,2) = 31   * new best     |
/// |     x ["key"] -> ["api_key","api-key"]    score(7,2) = 55   * new best     |
/// |     x ["="] -> ["api_key=","api-key="]    score(8,2) = 63   * new best     |
/// |     child[4] has no exact -> STOP                                           |
/// |                                                                            |
/// |   START=1:                                                                 |
/// |     acc = [""]                                                             |
/// |     x ["_","-"] -> ["_","-"]              min_len=1 < 3, skip              |
/// |     x ["key"] -> ["_key","-key"]          score(4,2) = 31                  |
/// |     x ["="] -> ["_key=","-key="]          score(5,2) = 39                  |
/// |     ... (no improvement over 63)                                           |
/// |                                                                            |
/// |   START=2:                                                                 |
/// |     x ["key"] -> ["key"]                  score(3,1) = 24                  |
/// |     x ["="] -> ["key="]                   score(4,1) = 32                  |
/// |     ... (no improvement over 63)                                           |
/// |                                                                            |
/// |   BEST: ["api_key=", "api-key="]  with score 63                            |
/// |                                                                            |
/// |   Single-child fallback would pick "api" or "key" (score 24).              |
/// +----------------------------------------------------------------------------+
/// ```
fn best_exact_window_prefilter(children: &[Info], cfg: &AnchorDeriveConfig) -> Option<Prefilter> {
    fn stats(set: &[Vec<u8>]) -> (usize, usize, usize) {
        let min_len = set.iter().map(|s| s.len()).min().unwrap_or(0);
        let max_len = set.iter().map(|s| s.len()).max().unwrap_or(0);
        (min_len, set.len(), max_len)
    }

    let mut best: Option<Vec<Vec<u8>>> = None;

    for start in 0..children.len() {
        if children[start].exact.is_none() {
            continue;
        }

        // Build the exact set for a growing contiguous window [start..end].
        let mut acc: Vec<Vec<u8>> = vec![vec![]];

        for child in children.iter().skip(start) {
            let Some(exact) = child.exact.as_ref() else {
                break;
            };

            let Some(mut prod) = cross_product(&acc, exact, cfg) else {
                break;
            };

            // Deterministic ordering helps dedup and avoids set-size blowups
            // from optional/epsilon-heavy cases.
            prod.sort_unstable();
            prod.dedup();

            if prod.len() > cfg.max_exact_set {
                break;
            }
            acc = prod;

            // Skip windows that can be empty; they are not safe anchors.
            if acc.iter().any(|s| s.is_empty()) {
                continue;
            }

            let (min_len, size, max_len) = stats(&acc);
            if min_len < cfg.min_anchor_len {
                continue;
            }

            let score = anchor_set_score(min_len, size);
            let better = match &best {
                None => true,
                Some(prev) => {
                    let (pmin, psize, pmax) = stats(prev);
                    let pscore = anchor_set_score(pmin, psize);

                    score > pscore
                        || (score == pscore
                            && (min_len, usize::MAX - size, max_len)
                                > (pmin, usize::MAX - psize, pmax))
                }
            };

            if better {
                best = Some(acc.clone());
            }
        }
    }

    best.map(|set| {
        if set.len() == 1 {
            Prefilter::Substring(set.into_iter().next().unwrap())
        } else {
            Prefilter::AnyOf(set)
        }
    })
}

/// Analyze concatenation.
///
/// Soundness intuition: if `A` and `B` both match within a concatenation, then
/// any anchor required by `A` or `B` must appear in the whole match. When we
/// cannot keep an exact set for the whole concatenation, we prefer the best
/// contiguous exact window (more selective than any single atom), and finally
/// fall back to the most selective single child prefilter.
///
/// # Strategy
/// - Prefer full exact concatenation when finite and within caps.
/// - Otherwise, pick the most selective exact window.
/// - Finally, fall back to the best child prefilter.
fn analyze_concat(subs: &[Hir], cfg: &AnchorDeriveConfig) -> Info {
    if subs.is_empty() {
        return Info::exact(vec![vec![]], cfg).unwrap_or_else(Info::all);
    }

    let children: Vec<Info> = subs.iter().map(|s| analyze(s, cfg)).collect();

    let mut accumulated: Option<Vec<Vec<u8>>> = Some(vec![vec![]]);

    for child in &children {
        if let (Some(acc), Some(child_exact)) = (accumulated.as_ref(), child.exact.as_ref()) {
            accumulated = cross_product(acc, child_exact, cfg);
        } else {
            accumulated = None;
            break;
        }
    }

    if let Some(exact) = accumulated {
        if let Some(info) = Info::exact(exact, cfg) {
            return info;
        }
    }

    // Prefer a contiguous exact window over a single child.
    // Example: `[aA][bB][cC][dD]` should yield a multi-byte anchor window,
    // not just a single byte from one child.
    if let Some(pf) = best_exact_window_prefilter(&children, cfg) {
        return Info::with_prefilter(pf);
    }

    let best = children
        .iter()
        .filter_map(|c| {
            if let Some(exact) = &c.exact {
                if exact.is_empty() {
                    None
                } else if exact.len() == 1 {
                    Some(Prefilter::Substring(exact[0].clone()))
                } else {
                    Some(Prefilter::AnyOf(exact.clone()))
                }
            } else {
                match &c.pf {
                    Prefilter::All => None,
                    pf => Some(pf.clone()),
                }
            }
        })
        .max_by(compare_prefilters);

    match best {
        Some(pf) => Info::with_prefilter(pf),
        None => Info::all(),
    }
}

/// Analyze alternation (|).
///
/// Soundness intuition: if any branch can match, then **some** anchor from
/// that branch must be present. Therefore, we union anchors across branches.
/// If any branch is unanchorable (matches empty or has no anchors), then the
/// alternation as a whole is unanchorable.
///
/// # Soundness
/// - A single empty-string branch makes the whole alternation unanchorable.
fn analyze_alternation(alts: &[Hir], cfg: &AnchorDeriveConfig) -> Info {
    if alts.is_empty() {
        return Info::all();
    }

    let children: Vec<Info> = alts.iter().map(|a| analyze(a, cfg)).collect();

    // For alternation to have exact set, ALL branches must have exact sets
    let all_exact: Option<Vec<Vec<u8>>> = children
        .iter()
        .map(|c| c.exact.clone())
        .collect::<Option<Vec<_>>>()
        .map(|sets| sets.into_iter().flatten().collect());

    if let Some(exact) = all_exact {
        if let Some(info) = Info::exact(exact, cfg) {
            return info;
        }
    }

    // Can't build exact set - alternation means we need ANY of the branches' anchors
    // This is tricky: we need the UNION of all branch anchors
    // If any branch is All, the whole alternation is All

    let mut all_anchors: Vec<Vec<u8>> = Vec::new();

    for child in &children {
        if let Some(exact) = &child.exact {
            // CRITICAL: If ANY branch can match empty string, the whole
            // alternation can match empty, making it unanchorable.
            // We must check this BEFORE collecting anchors.
            if exact.iter().any(|s| s.is_empty()) {
                return Info::all();
            }
            // Now safe to add all anchors from this branch
            all_anchors.extend(exact.iter().cloned());
        } else {
            match &child.pf {
                Prefilter::All => return Info::all(), // One branch has no anchor
                Prefilter::Substring(s) => all_anchors.push(s.clone()),
                Prefilter::AnyOf(set) => all_anchors.extend(set.iter().cloned()),
            }
        }
    }

    all_anchors.sort_unstable();
    all_anchors.dedup();

    if all_anchors.is_empty() {
        Info::all()
    } else if all_anchors.len() == 1 {
        Info::with_prefilter(Prefilter::Substring(
            all_anchors.into_iter().next().unwrap(),
        ))
    } else if all_anchors.len() <= cfg.max_exact_set {
        Info::with_prefilter(Prefilter::AnyOf(all_anchors))
    } else {
        Info::all()
    }
}

/// Return true if the look-around is a positive ASCII word boundary.
fn is_ascii_word_boundary(look: Look) -> bool {
    matches!(
        look,
        Look::WordAscii
            | Look::WordStartAscii
            | Look::WordEndAscii
            | Look::WordStartHalfAscii
            | Look::WordEndHalfAscii
    )
}

/// Extract a residue gate plan when anchors are unavailable.
///
/// - Alternation becomes OR of per-branch gates.
/// - Otherwise attempt a run-length gate.
///
/// This is intentionally narrow: residue gates only cover a small subset of
/// patterns, and always remain conservative.
///
/// # Returns
/// - `Some(gate)` when a conservative gate can be derived.
/// - `None` when no sound residue gate exists.
fn derive_residue_gate_plan(hir: &Hir) -> Option<ResidueGatePlan> {
    match hir.kind() {
        HirKind::Capture(cap) => derive_residue_gate_plan(&cap.sub),
        HirKind::Alternation(alts) => {
            if alts.is_empty() {
                return None;
            }
            // Any branch match is sufficient, so OR their gates.
            let mut gates = Vec::with_capacity(alts.len());
            for alt in alts {
                let gate = derive_residue_gate_plan(alt)?;
                gates.push(gate);
            }
            Some(ResidueGatePlan::Or(gates))
        }
        _ => derive_run_length_gate(hir).map(ResidueGatePlan::RunLength),
    }
}

/// Attempt to derive a run-length gate from a HIR.
///
/// Only matches a single consuming atom (literal/class or repetition with min > 0),
/// optionally wrapped by ASCII word boundaries and captures.
/// Any single-sided boundary is ignored to avoid false negatives.
///
/// # Returns
/// - `Some(gate)` for ASCII-only, fixed-shape patterns.
/// - `None` for variable-length or multi-atom patterns.
fn derive_run_length_gate(hir: &Hir) -> Option<RunLengthGate> {
    let (boundary, mut core) = extract_core_with_boundary(hir)?;

    // Peel capture groups inside the core if present.
    while let HirKind::Capture(cap) = core.kind() {
        core = &cap.sub;
    }

    let (mask, min_len, max_len) = match core.kind() {
        HirKind::Class(class) => (class_to_ascii_mask(class)?, 1, Some(1)),
        HirKind::Literal(Literal(bytes)) => (literal_byte_to_mask(bytes)?, 1, Some(1)),
        HirKind::Repetition(rep) => {
            if rep.min == 0 {
                // Zero-min repetitions can be skipped entirely.
                return None;
            }
            let (mask, min_len, max_len) = match rep.sub.kind() {
                HirKind::Class(class) => (class_to_ascii_mask(class)?, rep.min, rep.max),
                HirKind::Literal(Literal(bytes)) => {
                    (literal_byte_to_mask(bytes)?, rep.min, rep.max)
                }
                HirKind::Capture(cap) => match cap.sub.kind() {
                    HirKind::Class(class) => (class_to_ascii_mask(class)?, rep.min, rep.max),
                    HirKind::Literal(Literal(bytes)) => {
                        (literal_byte_to_mask(bytes)?, rep.min, rep.max)
                    }
                    _ => return None,
                },
                _ => return None,
            };
            (mask, min_len, max_len)
        }
        _ => return None,
    };

    Some(RunLengthGate {
        byte_mask: mask,
        min_len,
        max_len,
        boundary,
        min_entropy: None,
        scan_utf16_variants: true,
    })
}

/// Extract a single consuming core with optional ASCII word boundaries.
///
/// Leading/trailing lookarounds and empties are ignored; if more than one
/// consuming element remains, the run-length gate cannot represent it.
/// A single boundary is intentionally dropped (only both sides are honored).
///
/// # Returns
/// - `(boundary, core)` when exactly one consuming element remains.
/// - `None` when the core has multiple consuming elements.
fn extract_core_with_boundary(hir: &Hir) -> Option<(Boundary, &Hir)> {
    match hir.kind() {
        HirKind::Concat(subs) => {
            let mut start = 0usize;
            let mut end = subs.len();
            let mut prefix_word = false;
            let mut suffix_word = false;

            while start < end {
                match subs[start].kind() {
                    HirKind::Look(look) => {
                        if is_ascii_word_boundary(*look) {
                            prefix_word = true;
                        }
                        start += 1;
                    }
                    HirKind::Empty => start += 1,
                    _ => break,
                }
            }

            while end > start {
                match subs[end - 1].kind() {
                    HirKind::Look(look) => {
                        if is_ascii_word_boundary(*look) {
                            suffix_word = true;
                        }
                        end -= 1;
                    }
                    HirKind::Empty => end -= 1,
                    _ => break,
                }
            }

            let core = &subs[start..end];
            if core.len() != 1 {
                return None;
            }

            let boundary = if prefix_word && suffix_word {
                Boundary::AsciiWord
            } else {
                Boundary::None
            };
            Some((boundary, &core[0]))
        }
        _ => Some((Boundary::None, hir)),
    }
}

#[cfg(feature = "kgram-gate")]
/// Derive a prefix k-gram gate.
///
/// This enumerates all possible k-length prefixes using a small ASCII alphabet
/// per position, then stores them as u64s for fast membership checks.
///
/// # Returns
/// - `Some(gate)` when the prefix is fixed and enumerable.
/// - `None` when the prefix is ambiguous or too large.
fn derive_kgram_gate(hir: &Hir, cfg: &AnchorDeriveConfig) -> Option<KGramGate> {
    let k = cfg.kgram_k;
    if k == 0 || k > u8::MAX as usize {
        return None;
    }
    let min_len = hir.properties().minimum_len()?;
    if min_len < k {
        // Pattern too short to guarantee a k-gram prefix.
        return None;
    }

    let atoms = collect_prefix_atoms(hir, k, cfg)?;
    if atoms.len() < k {
        // Prefix is not fully determined.
        return None;
    }

    let mut grams: Vec<Vec<u8>> = vec![Vec::new()];
    for atom in atoms.into_iter().take(k) {
        if atom.len() > cfg.max_kgram_alphabet {
            return None;
        }
        let mut next = Vec::new();
        for prefix in &grams {
            for &b in &atom {
                let mut combined = prefix.clone();
                combined.push(b);
                next.push(combined);
                if next.len() > cfg.max_kgram_set {
                    return None;
                }
            }
        }
        grams = next;
    }

    fn pack_kgram_le(bytes: &[u8]) -> u64 {
        let mut v = 0u64;
        for (i, &b) in bytes.iter().enumerate() {
            v |= (b as u64) << (i * 8);
        }
        v
    }

    fn fnv1a64(bytes: &[u8]) -> u64 {
        let mut h: u64 = 0xcbf29ce484222325;
        for &b in bytes {
            h ^= b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        h
    }

    // Use a stable, cheap encoding for grams to avoid pulling in hash crates.
    let mut hashes = Vec::with_capacity(grams.len());
    for gram in grams {
        let v = if k <= 8 {
            pack_kgram_le(&gram)
        } else {
            fnv1a64(&gram)
        };
        hashes.push(v);
    }
    hashes.sort_unstable();
    hashes.dedup();

    Some(KGramGate {
        k: k as u8,
        gram_hashes: hashes,
        position: PositionHint::Prefix,
    })
}

#[cfg(feature = "kgram-gate")]
/// Collect per-position prefix atoms for the first k bytes of the pattern.
///
/// Returns None when the prefix is ambiguous or unbounded (e.g., alternation,
/// optional/variable repetition, or non-ASCII bytes).
///
/// # Returns
/// - `Some(atoms)` where each entry is the byte alphabet for that position.
/// - `None` when the prefix cannot be enumerated soundly.
fn collect_prefix_atoms(hir: &Hir, k: usize, cfg: &AnchorDeriveConfig) -> Option<Vec<Vec<u8>>> {
    fn append_atoms(
        hir: &Hir,
        atoms: &mut Vec<Vec<u8>>,
        k: usize,
        cfg: &AnchorDeriveConfig,
    ) -> Option<bool> {
        if atoms.len() >= k {
            return Some(true);
        }

        match hir.kind() {
            HirKind::Capture(cap) => append_atoms(&cap.sub, atoms, k, cfg),
            HirKind::Concat(subs) => {
                for sub in subs {
                    if append_atoms(sub, atoms, k, cfg)? {
                        return Some(true);
                    }
                }
                Some(false)
            }
            HirKind::Look(_) | HirKind::Empty => Some(false),
            HirKind::Literal(Literal(bytes)) => {
                for &b in bytes {
                    if b > 0x7F {
                        return None;
                    }
                    atoms.push(vec![b]);
                    if atoms.len() >= k {
                        return Some(true);
                    }
                }
                Some(false)
            }
            HirKind::Class(class) => {
                let bytes = class_to_ascii_vec(class)?;
                atoms.push(bytes);
                Some(atoms.len() >= k)
            }
            HirKind::Repetition(rep) => {
                if rep.min == 0 || rep.max != Some(rep.min) {
                    // Variable-length repetition makes prefix enumeration unsound.
                    return None;
                }
                let count = rep.min as usize;
                let bytes = match rep.sub.kind() {
                    HirKind::Class(class) => class_to_ascii_vec(class)?,
                    HirKind::Literal(Literal(bytes)) => {
                        if bytes.len() != 1 || bytes[0] > 0x7F {
                            return None;
                        }
                        vec![bytes[0]]
                    }
                    HirKind::Capture(cap) => match cap.sub.kind() {
                        HirKind::Class(class) => class_to_ascii_vec(class)?,
                        HirKind::Literal(Literal(bytes)) => {
                            if bytes.len() != 1 || bytes[0] > 0x7F {
                                return None;
                            }
                            vec![bytes[0]]
                        }
                        _ => return None,
                    },
                    _ => return None,
                };

                if bytes.len() > cfg.max_kgram_alphabet {
                    return None;
                }

                for _ in 0..count {
                    atoms.push(bytes.clone());
                    if atoms.len() >= k {
                        return Some(true);
                    }
                }
                Some(false)
            }
            HirKind::Alternation(_) => None,
        }
    }

    let mut atoms = Vec::new();
    append_atoms(hir, &mut atoms, k, cfg)?;
    Some(atoms)
}

/// Compare two prefilters to determine which is "better" (more selective).
///
/// Scoring heuristic:
/// - Longer anchors are better (scaled by SCORE_BITS_PER_BYTE).
/// - Larger AnyOf sets are penalized by log2(set size).
///
/// This favors a small set of longer anchors over a huge set of short ones.
fn compare_prefilters(a: &Prefilter, b: &Prefilter) -> Ordering {
    let score_a = prefilter_score(a);
    let score_b = prefilter_score(b);
    score_a.cmp(&score_b)
}

/// Score a prefilter by its selectivity.
/// Higher is better (more selective).
fn prefilter_score(pf: &Prefilter) -> i64 {
    match pf {
        Prefilter::All => 0,
        Prefilter::Substring(s) => (s.len() as i64) * SCORE_BITS_PER_BYTE,
        Prefilter::AnyOf(set) => {
            let min_len = set.iter().map(|s| s.len()).min().unwrap_or(0);
            anchor_set_score(min_len, set.len())
        }
    }
}

/// Choose the best anchor set from an Info.
///
/// This is where we enforce global constraints:
/// - Empty matches are forbidden (anchors would miss them).
/// - Anchors shorter than `min_anchor_len` are rejected.
/// - We never "filter out" short alternatives, because that would be unsound.
///
/// # Errors
/// - `Unanchorable` when the pattern can match empty or no anchors exist.
/// - `OnlyWeakAnchors` when any required anchor is shorter than the minimum.
fn choose_anchors(
    info: &Info,
    cfg: &AnchorDeriveConfig,
) -> Result<Vec<Vec<u8>>, AnchorDeriveError> {
    if let Some(exact) = &info.exact {
        // If exact set contains empty string, pattern can match empty - unanchorable
        // (any anchor we return would miss empty inputs)
        if exact.iter().any(|s| s.is_empty()) {
            return Err(AnchorDeriveError::Unanchorable);
        }

        // Check if ANY string is too short - if so, that's a soundness issue
        // because we can't just filter them out (the pattern still matches short strings)
        if exact.iter().any(|s| s.len() < cfg.min_anchor_len) {
            return Err(AnchorDeriveError::OnlyWeakAnchors);
        }

        // All strings meet minimum length
        return Ok(exact.clone());
    }

    match &info.pf {
        Prefilter::All => Err(AnchorDeriveError::Unanchorable),
        Prefilter::Substring(s) => {
            if s.len() >= cfg.min_anchor_len {
                Ok(vec![s.clone()])
            } else {
                Err(AnchorDeriveError::OnlyWeakAnchors)
            }
        }
        Prefilter::AnyOf(set) => {
            // Check if any anchor is too short or empty
            if set.iter().any(|s| s.is_empty()) {
                return Err(AnchorDeriveError::Unanchorable);
            }
            if set.iter().any(|s| s.len() < cfg.min_anchor_len) {
                return Err(AnchorDeriveError::OnlyWeakAnchors);
            }

            if set.is_empty() {
                Err(AnchorDeriveError::Unanchorable)
            } else {
                Ok(set.clone())
            }
        }
    }
}

/// Return true if the HIR can match the empty string.
fn hir_matches_empty(hir: &Hir) -> bool {
    matches!(hir.properties().minimum_len(), Some(0))
}

/// Collect required fixed literal "islands" from a top-level concat.
///
/// Example: `foo\\d+bar` (concat of literal, repetition, literal)
/// - "foo" and "bar" are mandatory islands, so they are safe for confirm_all.
///
/// confirm_all is a cheap AND filter used after the OR anchor hit; it reduces
/// false candidates without changing soundness. The engine checks the longest
/// literal first, then requires all remaining literals inside the same window.
/// This stays out of derive_anchors_from_pattern to preserve the existing
/// anchor contract.
///
/// # Semantics
/// - Only considers mandatory subexpressions from the top-level concatenation.
/// - Optional/empty-matching segments are excluded.
fn collect_confirm_all_literals(hir: &Hir, cfg: &AnchorDeriveConfig) -> Vec<Vec<u8>> {
    fn peel_capture(mut h: &Hir) -> &Hir {
        loop {
            match h.kind() {
                HirKind::Capture(cap) => h = &cap.sub,
                _ => return h,
            }
        }
    }

    let mut out = Vec::new();
    let root = peel_capture(hir);

    let HirKind::Concat(subs) = root.kind() else {
        return out;
    };

    for sub in subs {
        let sub = peel_capture(sub);

        // Optional segments cannot be used for confirm_all.
        if matches!(sub.properties().minimum_len(), Some(0)) {
            continue;
        }

        match sub.kind() {
            HirKind::Literal(Literal(bytes)) => {
                // Direct literal: a required island.
                if !bytes.is_empty() && bytes.len() >= cfg.min_anchor_len {
                    out.push(bytes.to_vec());
                }
            }
            _ => {
                let info = analyze(sub, cfg);

                // Single-element exact sets and Substring prefilters are
                // mandatory for this subexpression, so they are safe here.
                if let Some(ex) = info.exact.as_ref() {
                    if ex.len() == 1 && !ex[0].is_empty() && ex[0].len() >= cfg.min_anchor_len {
                        out.push(ex[0].clone());
                        continue;
                    }
                }

                if let Prefilter::Substring(s) = &info.pf {
                    if !s.is_empty() && s.len() >= cfg.min_anchor_len {
                        out.push(s.clone());
                    }
                }
            }
        }
    }

    out.sort_unstable();
    out.dedup();
    out
}

/// Compile a regex pattern into a trigger plan for the two-pass pipeline.
///
/// # Strategy
/// - Prefer anchors (fastest, most selective gate).
/// - Fall back to residue gates when anchors are unavailable.
/// - Optionally fall back to a k-gram gate when enabled.
/// - Otherwise mark the pattern as unfilterable.
///
/// # Soundness
/// - Patterns that can match the empty string are always unfilterable.
///
/// # Errors
/// - `InvalidPattern` when the regex fails to parse.
pub fn compile_trigger_plan(
    pattern: &str,
    cfg: &AnchorDeriveConfig,
) -> Result<TriggerPlan, AnchorDeriveError> {
    let mut builder = regex_syntax::ParserBuilder::new();
    builder.utf8(cfg.utf8);
    let hir = builder
        .build()
        .parse(pattern)
        .map_err(|e| AnchorDeriveError::InvalidPattern(e.to_string()))?;

    // Rules that can match the empty string are not gateable without risking
    // false negatives. They must be treated as unfilterable.
    if hir_matches_empty(&hir) {
        return Ok(TriggerPlan::Unfilterable {
            reason: UnfilterableReason::MatchesEmptyString,
        });
    }

    // First, attempt anchors (fastest gate).
    let info = analyze(&hir, cfg);
    match choose_anchors(&info, cfg) {
        Ok(anchors) => {
            // confirm_all adds a cheap AND filter to reduce false candidates.
            let mut confirm_all = collect_confirm_all_literals(&hir, cfg);
            confirm_all.retain(|c| !anchors.contains(c));

            return Ok(TriggerPlan::Anchored {
                anchors,
                confirm_all,
            });
        }
        Err(_anchor_err) => {}
    }

    if let Some(gate) = derive_residue_gate_plan(&hir) {
        return Ok(TriggerPlan::Residue { gate });
    }

    // Optional: attempt bounded k-gram gate (feature-flagged).
    #[cfg(feature = "kgram-gate")]
    {
        if let Some(kgram) = derive_kgram_gate(&hir, cfg) {
            return Ok(TriggerPlan::Residue {
                gate: ResidueGatePlan::KGrams(kgram),
            });
        }
    }

    let info = analyze(&hir, cfg);
    let reason = match choose_anchors(&info, cfg) {
        Err(AnchorDeriveError::OnlyWeakAnchors) => UnfilterableReason::OnlyWeakAnchors,
        _ => UnfilterableReason::NoSoundGate,
    };

    Ok(TriggerPlan::Unfilterable { reason })
}

/// Derive anchors from a regex pattern.
///
/// # Returns
/// - A vector of anchor byte strings; any match must contain at least one.
///
/// # Examples
/// ```rust
/// # use scanner_engine::regex2anchor::{AnchorDeriveConfig, derive_anchors_from_pattern};
/// let cfg = AnchorDeriveConfig::default();
/// let anchors = derive_anchors_from_pattern("foo[0-9]+bar", &cfg).unwrap();
/// assert!(anchors.contains(&b"foo".to_vec()) || anchors.contains(&b"bar".to_vec()));
/// ```
///
/// # Soundness
/// - Returns an error rather than guessing when a sound anchor set is impossible.
///
/// # Errors
/// - `InvalidPattern` when the regex fails to parse.
/// - `Unanchorable` when the pattern matches too broadly (including empty).
/// - `OnlyWeakAnchors` when any required anchor is shorter than `min_anchor_len`.
pub fn derive_anchors_from_pattern(
    pattern: &str,
    cfg: &AnchorDeriveConfig,
) -> Result<Vec<Vec<u8>>, AnchorDeriveError> {
    // Important: parsing semantics (UTF-8 vs bytes) must match the regex engine
    // that will ultimately be used for matching.
    let mut builder = regex_syntax::ParserBuilder::new();
    builder.utf8(cfg.utf8);
    let hir = builder
        .build()
        .parse(pattern)
        .map_err(|e| AnchorDeriveError::InvalidPattern(e.to_string()))?;

    let info = analyze(&hir, cfg);
    choose_anchors(&info, cfg)
}

/// Convenience function to derive anchors as strings (for ASCII patterns).
///
/// This uses `from_utf8_lossy` and is therefore **not** a safe representation
/// for arbitrary byte patterns. Use `derive_anchors_from_pattern` if you care
/// about raw bytes.
///
/// # Examples
/// ```rust
/// # use scanner_engine::regex2anchor::{AnchorDeriveConfig, derive_anchors_as_strings};
/// let cfg = AnchorDeriveConfig::default();
/// let anchors = derive_anchors_as_strings("api[_-]?key", &cfg).unwrap();
/// assert!(anchors.iter().any(|s| s.contains("api")));
/// ```
pub fn derive_anchors_as_strings(
    pattern: &str,
    cfg: &AnchorDeriveConfig,
) -> Result<Vec<String>, AnchorDeriveError> {
    let anchors = derive_anchors_from_pattern(pattern, cfg)?;
    Ok(anchors
        .into_iter()
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .collect())
}

#[cfg(test)]
#[path = "regex2anchor_tests.rs"]
mod tests;
