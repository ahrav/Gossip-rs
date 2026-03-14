//! Internal compiled rule representation.
//!
//! This module defines the data layout the scan loop consumes: anchor variants,
//! packed literal tables, and precompiled gates derived from a validated
//! [`RuleSpec`]. The emphasis is on cache-friendly layouts and variant-indexed
//! tables so the hot path avoids allocation and encoding conversion.
//!
//! ## Data flow
//!
//! ```text
//! RuleSpec (api.rs)
//!   │
//!   ├─ compile_rule() ──► (RuleCompiled, CompiledGates)
//!   │                          │               │
//!   │                          │   Engine::new() pools each gate object into
//!   │                          │   a type-specific Vec on Engine and patches
//!   │                          │   the u32 index back onto RuleCompiled.
//!   │                          │
//!   │                          ▼
//!   │                     RuleCompiled   ── hot array iterated per buffer
//!   │                     RuleCold       ── parallel cold array (name, min confidence, etc.)
//!   │
//!   ├─ add_pat_raw/owned() ──► anchor map (AHashMap<Vec<u8>, Vec<Target>>)
//!   │                              │
//!   │                              ▼
//!   │                         map_to_patterns() ──► (patterns, targets, offsets)
//!   │                              │
//!   │                              ▼
//!   │                         Vectorscan prefilter DB
//!   │                         (pattern ids are positional → deterministic sort)
//!   │
//!   └─ compile_confirm_all() ──► ConfirmAllCompiled (pooled in second pass)
//! ```
//!
//! ## Two-tier compilation
//!
//! Compilation is split into two tiers to keep `RuleCompiled` compact:
//!
//! 1. [`compile_rule`] produces a `RuleCompiled` with all gate indices set to
//!    [`NO_GATE`] (sentinel for "absent"), plus a [`CompiledGates`] bag holding
//!    the heavyweight gate objects.
//! 2. The caller (`Engine::new`) pools each gate into a type-specific `Vec` on
//!    `Engine` and patches the corresponding `u32` index back onto the rule.
//!    This indirection means `RuleCompiled` stays small enough for
//!    cache-friendly iteration while the (rarely accessed) gate data lives in
//!    separate, densely packed pools.
//!
//! `confirm_all` is a special case: its literals are derived from regex analysis
//! *after* `compile_rule` returns, so the caller must build it separately via
//! [`compile_confirm_all`] and pool it in a second pass.
//!
//! ## Variant-indexed arrays
//!
//! Several compiled gate types (`TwoPhaseCompiled`, `KeywordsCompiled`,
//! `ConfirmAllCompiled`) store pattern data in per-variant `[_; 3]` arrays
//! indexed by [`Variant::idx()`]: slot 0 = Raw, 1 = Utf16Le, 2 = Utf16Be.
//! Most use `[PackedPatterns; 3]`; `ConfirmAllCompiled::primary` uses
//! `[Option<Box<[u8]>>; 3]` for the single longest literal.
//! This avoids runtime dispatch and lets the scan loop select the correct
//! encoding with a single array index.
//!
//! ## Notes
//!
//! - UTF-16 helpers in this module are ASCII-only expansions (1 byte → 1 code
//!   unit) used for literal gating. They are not general-purpose UTF-16 encoders.
//! - Variant ordering is stable and reused for packed arrays and bit layouts.

use crate::api::{LocalContextSpec, OfflineValidationSpec, RuleSpec};
use ahash::AHashMap;
use regex::bytes::Regex;

// --------------------------
// Anchor variants
// --------------------------

/// Encoding variant that determines byte layout for anchors, keywords, and gate patterns.
///
/// Anchors, keywords, and most gate literals are compiled into three encoding
/// variants (Raw, UTF-16LE, UTF-16BE) so the scan loop can gate on raw bytes
/// without runtime encoding conversion. Value suppressors are the exception:
/// they run on extracted secret bytes (always decoded) and are compiled raw-only.
/// The variant also controls window
/// scaling: UTF-16 encodes each ASCII character as two bytes, so window radii
/// must double to cover the same number of logical characters.
///
/// The three variants form a closed set and are used as array indices throughout
/// the compiled rule representation (e.g., `[PackedPatterns; 3]` arrays in
/// [`TwoPhaseCompiled`], [`KeywordsCompiled`], and [`ConfirmAllCompiled`]).
///
/// # Invariants
/// - `idx()` ordering is stable: Raw=0, Utf16Le=1, Utf16Be=2.
/// - This ordering is used for packed tables, array slots, and the low bits
///   of [`Target`].
/// - `scale()` returns 1 for raw and 2 for UTF-16 variants.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) enum Variant {
    Raw,
    Utf16Le,
    Utf16Be,
}

impl Variant {
    /// Stable index into per-variant `[_; 3]` arrays: Raw=0, Utf16Le=1, Utf16Be=2.
    ///
    /// Used to select the correct encoding slot in compiled gate structures
    /// (e.g., `TwoPhaseCompiled::confirm[v.idx()]`).
    pub(super) fn idx(self) -> usize {
        match self {
            Variant::Raw => 0,
            Variant::Utf16Le => 1,
            Variant::Utf16Be => 2,
        }
    }

    /// Convert a packed table index back to a variant, returning `None` for
    /// out-of-range values.
    ///
    /// Inverse of [`idx`](Self::idx). Used when decoding variant tags from
    /// packed representations like [`Target`].
    pub(super) fn from_idx(idx: u8) -> Option<Self> {
        match idx {
            0 => Some(Variant::Raw),
            1 => Some(Variant::Utf16Le),
            2 => Some(Variant::Utf16Be),
            _ => None,
        }
    }

    /// Scale a character radius into a byte radius for this variant.
    ///
    /// Returns 1 for `Raw` (1 byte per character) and 2 for UTF-16 variants
    /// (2 bytes per code unit for ASCII). Multiply a character-count radius by
    /// this factor to get the equivalent byte-count radius.
    pub(super) fn scale(self) -> usize {
        match self {
            Variant::Raw => 1,
            Variant::Utf16Le | Variant::Utf16Be => 2,
        }
    }
}

// --------------------------
// Target mapping
// --------------------------

/// Mapping entry from an anchor pattern id to a rule/variant accumulator.
///
/// Anchor patterns are deduped in a shared pattern table. Each pattern id can
/// fan out to multiple rules and variants; `pat_offsets` slices into the flat
/// `pat_targets` array. A `Target` is a compact (rule_id, variant) pair packed
/// into `u32` to keep the fanout table cache-friendly and avoid extra pointer
/// chasing.
///
/// Layout (low bits): `[variant (2 bits)] [rule_id (30 bits)]`
///
/// # Invariants
/// - `rule_id` fits in 30 bits (max ~1 billion rules).
/// - The low-bit layout is stable and must match `variant()`.
///
/// # Ordering
/// `Ord` is derived on the raw `u32`, which sorts by (rule_id, variant).
/// [`map_to_patterns`] sorts each pattern's target list by this order to
/// ensure deterministic output across compilations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Target(u32);

impl Target {
    const VARIANT_MASK: u32 = 0b11;
    const VARIANT_SHIFT: u32 = 2;

    /// Pack a (rule_id, variant) into a single `u32`.
    ///
    /// # Panics
    /// Panics if `rule_id` exceeds 30 bits (~1 billion rules).
    pub(super) fn new(rule_id: u32, variant: Variant) -> Self {
        assert!(rule_id <= (u32::MAX >> Self::VARIANT_SHIFT));
        Self((rule_id << Self::VARIANT_SHIFT) | variant.idx() as u32)
    }

    /// Extract the rule index from the packed representation.
    pub(super) fn rule_id(self) -> usize {
        (self.0 >> Self::VARIANT_SHIFT) as usize
    }

    /// Extract the variant tag from the packed representation.
    pub(super) fn variant(self) -> Variant {
        match self.0 & Self::VARIANT_MASK {
            0 => Variant::Raw,
            1 => Variant::Utf16Le,
            2 => Variant::Utf16Be,
            _ => unreachable!("invalid variant tag"),
        }
    }
}

// --------------------------
// Pattern storage
// --------------------------

/// Packed byte patterns with an offset table (immutable after construction).
///
/// `bytes` stores all patterns back-to-back, and `offsets` is a prefix-sum
/// table with length `patterns + 1`. This avoids a `Vec<Vec<u8>>` and keeps
/// confirm patterns contiguous for cache-friendly memmem checks (both ANY and
/// ALL gates).
///
/// # Accessing patterns
///
/// Pattern `i` is `bytes[offsets[i] as usize .. offsets[i+1] as usize]`.
/// The number of patterns is `offsets.len() - 1`. The `contains_any_memmem`
/// and `contains_all_memmem` helpers in `helpers.rs` iterate patterns this
/// way, inlining the slice indexing directly for the memmem inner loops.
///
/// # Invariants
/// - `offsets[0] == 0` and the last offset equals `bytes.len()`.
/// - `offsets` is monotonically non-decreasing.
/// - `bytes.len() <= u32::MAX`.
/// - Empty pattern sets are valid: `offsets == [0]`, `bytes == []`.
///
/// # Performance
/// - Contiguous storage enables cache-friendly `memmem` gates without
///   per-window allocations.
/// - Uses `Box<[T]>` instead of `Vec<T>` since data is immutable after
///   engine compilation, saving 8 bytes per field (no capacity word).
#[derive(Clone, Debug)]
pub(super) struct PackedPatterns {
    pub(super) bytes: Box<[u8]>,
    pub(super) offsets: Box<[u32]>,
}

// Compile-time size guard: 2 × Box<[T]> = 2 × 16 = 32 bytes.
const _: () = assert!(std::mem::size_of::<PackedPatterns>() == 32);

/// Mutable builder for [`PackedPatterns`].
///
/// Accumulates patterns into growable `Vec` storage, then freezes into
/// immutable boxed slices via [`build`](Self::build). The typical lifecycle is:
///
/// 1. Create with [`with_capacity`](Self::with_capacity) sized from the rule spec.
/// 2. Append patterns via `push_raw`, `push_utf16le`, or `push_utf16be`.
/// 3. Freeze via `build()` -- consumes the builder and returns a `PackedPatterns`.
///
/// After `build()`, the resulting `PackedPatterns` is immutable and uses
/// `Box<[T]>` storage (no excess capacity).
///
/// # Invariants maintained during building
/// - `offsets[0] == 0` (established at construction).
/// - Each `push_*` call appends bytes and records a new offset.
/// - `bytes.len() <= u32::MAX` (asserted on each push).
pub(super) struct PackedPatternsBuilder {
    bytes: Vec<u8>,
    offsets: Vec<u32>,
}

impl PackedPatternsBuilder {
    /// Create a builder pre-allocated for the expected number of patterns
    /// and total byte count.
    ///
    /// `patterns` is the number of patterns to be added (determines offset
    /// vector capacity). `bytes` is the total byte count across all patterns.
    pub(super) fn with_capacity(patterns: usize, bytes: usize) -> Self {
        let mut offsets = Vec::with_capacity(patterns.saturating_add(1));
        offsets.push(0);
        Self {
            bytes: Vec::with_capacity(bytes),
            offsets,
        }
    }

    /// Append a raw pattern (byte-for-byte).
    pub(super) fn push_raw(&mut self, pat: &[u8]) {
        self.bytes.extend_from_slice(pat);
        assert!(self.bytes.len() <= u32::MAX as usize);
        self.offsets.push(self.bytes.len() as u32);
    }

    /// Append an ASCII pattern expanded to UTF-16LE code units (each byte
    /// becomes `[byte, 0x00]`).
    pub(super) fn push_utf16le(&mut self, pat: &[u8]) {
        for &b in pat {
            self.bytes.push(b);
            self.bytes.push(0);
        }
        assert!(self.bytes.len() <= u32::MAX as usize);
        self.offsets.push(self.bytes.len() as u32);
    }

    /// Append an ASCII pattern expanded to UTF-16BE code units (each byte
    /// becomes `[0x00, byte]`).
    pub(super) fn push_utf16be(&mut self, pat: &[u8]) {
        for &b in pat {
            self.bytes.push(0);
            self.bytes.push(b);
        }
        assert!(self.bytes.len() <= u32::MAX as usize);
        self.offsets.push(self.bytes.len() as u32);
    }

    /// Consume the builder and freeze into an immutable [`PackedPatterns`].
    ///
    /// After this call, the returned `PackedPatterns` uses `Box<[T]>` storage
    /// with no excess capacity. The builder cannot be reused.
    pub(super) fn build(self) -> PackedPatterns {
        debug_assert_eq!(
            *self.offsets.last().unwrap() as usize,
            self.bytes.len(),
            "PackedPatternsBuilder: last offset must equal bytes length"
        );
        PackedPatterns {
            bytes: self.bytes.into_boxed_slice(),
            offsets: self.offsets.into_boxed_slice(),
        }
    }
}

// --------------------------
// Compiled rule gates
// --------------------------

/// Two-phase rule data compiled per variant for fast confirm checks.
///
/// Two-phase gating is applied in `buffer_scan` *before* windows are sent to
/// `window_validate`, making it the earliest per-window filter after the
/// Vectorscan prefilter.
///
/// The two-phase algorithm reduces regex work by narrowing candidate windows:
///
/// 1. **Seed phase**: Vectorscan emits a seed window of
///    `seed_radius * variant.scale()` bytes around each anchor hit (for raw
///    anchors `scale()` is 1, so the byte radius equals `seed_radius`; for
///    UTF-16 anchors it doubles).
/// 2. **Confirm phase**: the seed window is checked for at least one `confirm`
///    pattern via memmem (ANY semantics). Windows that lack a confirm pattern
///    are discarded without running the regex.
/// 3. **Expand phase**: confirmed seeds are widened to
///    `full_radius * variant.scale()` bytes to give the regex enough context
///    for a full match.
///
/// # Guarantees
/// - `confirm` entries are encoded per variant and indexed by `Variant::idx()`.
///
/// # Invariants
/// - `seed_radius <= full_radius`.
/// - Radii and pattern lengths are validated by `RuleSpec::assert_valid`.
#[derive(Clone, Debug)]
pub(super) struct TwoPhaseCompiled {
    pub(super) seed_radius: usize,
    pub(super) full_radius: usize,

    /// Confirm patterns per variant, indexed by [`Variant::idx()`].
    ///
    /// Raw byte patterns for `Variant::Raw`, UTF-16-expanded patterns for
    /// `Variant::Utf16Le` and `Variant::Utf16Be`.
    pub(super) confirm: [PackedPatterns; 3],
}

/// Keyword gate compiled per variant for fast "any keyword" checks.
///
/// Evaluated inside the validation window *before* the regex runs (after
/// must-contain and confirm-all, but before assignment-shape and char-class
/// gates). At least one keyword must appear in the window for the rule to
/// proceed to regex evaluation. This is a cheap `memmem` scan that eliminates
/// windows lacking the expected context words (e.g., `password`, `api_key`).
///
/// # Guarantees
/// - `any` is encoded per variant and indexed by `Variant::idx()`.
#[derive(Clone, Debug)]
pub(super) struct KeywordsCompiled {
    /// Keyword patterns per variant, indexed by [`Variant::idx()`].
    ///
    /// Mirrors anchor variant handling so keyword gating behaves consistently
    /// across encodings and avoids per-window UTF-16 conversions.
    pub(super) any: [PackedPatterns; 3],
}

/// Derived "confirm all" gate from mandatory literal islands extracted from
/// regex analysis.
///
/// Unlike `TwoPhaseCompiled` and `KeywordsCompiled` whose patterns come from
/// the rule spec, confirm-all literals are derived automatically from the
/// regex's mandatory literal islands by the anchor derivation pass. This is
/// why the gate is compiled separately via [`compile_confirm_all`] rather
/// than inside [`compile_rule`].
///
/// ## Check strategy
///
/// 1. **Primary literal** (longest): checked first via a single `memmem`
///    search. Because it is the longest mandatory literal, it provides the
///    highest rejection rate and makes the common negative case fast.
/// 2. **Rest literals**: checked with AND semantics (all must match) using
///    [`PackedPatterns`] iteration.
///
/// UTF-16 variants are encoded the same way as anchors/keywords so the gate
/// can reject windows on raw bytes without decoding.
///
/// # Guarantees
/// - `primary[v]` is always `Some` when the gate exists (the longest literal
///   is always promoted to primary). When only one literal is derived, it
///   becomes the primary and `rest` contains zero patterns.
/// - `rest` is encoded per variant and indexed by `Variant::idx()`.
#[derive(Clone, Debug)]
pub(super) struct ConfirmAllCompiled {
    pub(super) primary: [Option<Box<[u8]>>; 3],
    pub(super) rest: [PackedPatterns; 3],
}

/// Entropy gate parameters compiled into a rule.
///
/// Copied from the validated [`crate::api::EntropySpec`] at compile time to
/// avoid repeated lookups through the rule spec during scanning. Evaluated
/// *after* the regex matches, on the extracted secret bytes (not the full
/// match or the window). This is the primary false-positive filter for
/// token-like rules: low-entropy matches (repeated characters, sequential
/// digits) are rejected before emission.
///
/// The gate computes Shannon entropy and optionally min-entropy (NIST
/// SP 800-90B) over the extracted secret, capped to `max_len` bytes.
/// See [`EntropySpec`](crate::api::EntropySpec) for the full algorithm.
///
/// # Invariants
/// - Values are validated by `RuleSpec::assert_valid`.
/// - `min_len <= max_len`.
#[derive(Clone, Copy, Debug)]
pub(super) struct EntropyCompiled {
    /// Minimum Shannon entropy threshold in bits per byte.
    ///
    /// Candidates below this threshold are rejected as low-entropy
    /// (e.g., repeated characters, sequential digits).
    pub(super) min_bits_per_byte: f32,
    /// Applies a detect-secrets style penalty to all-digit candidates.
    ///
    /// When enabled, `DIGIT_ONLY_PENALTY_NUMERATOR / log2(len)` is subtracted
    /// from Shannon entropy for entropy slices composed entirely of ASCII
    /// digits, using the capped entropy window length (`len == 1` is skipped).
    /// See [`super::helpers::entropy::DIGIT_ONLY_PENALTY_NUMERATOR`].
    pub(super) digit_penalty: bool,
    /// Minimum candidate length in bytes for the entropy check to apply.
    pub(super) min_len: usize,
    /// Maximum number of bytes used for the entropy computation.
    ///
    /// Candidates longer than this are not skipped; instead the entropy
    /// calculation is capped to the first `max_len` bytes.
    ///
    /// Also determines the size of the pre-computed `ln(i)/ln(2)` table
    /// in [`Engine::entropy_log2`](super::core::Engine).
    pub(super) max_len: usize,
    /// Lower bound on min-entropy in bits/byte (NIST SP 800-90B).
    ///
    /// `None` skips the min-entropy gate. When set, candidates whose
    /// `H_inf = log2(n) - log2(max_bin_count)` falls below this threshold
    /// are rejected even if Shannon entropy passes.
    pub(super) min_entropy_bits_per_byte: Option<f32>,
}

// Keep this hot-path gate compact: `ResolvedGates` copies it by value.
const _: () = assert!(core::mem::size_of::<EntropyCompiled>() <= 32);

/// Compiled character-class distribution gate.
///
/// Copied from the validated [`crate::api::CharClassSpec`] at compile time.
/// Evaluated in [`window_validate`](super::window_validate) *before* the regex
/// runs (after confirm-all and keyword gates). Windows whose lowercase ASCII
/// percentage exceeds `max_lower_pct` are rejected without regex evaluation,
/// cheaply eliminating prose-dominated windows that cannot be secrets.
///
/// The gate is skipped for windows shorter than `min_window_len` to avoid
/// noisy statistics on small samples.
///
/// # Invariants
/// - Values are validated by `RuleSpec::assert_valid`.
/// - `max_lower_pct` is in `0..=100`.
#[derive(Clone, Copy, Debug)]
pub(super) struct CharClassCompiled {
    /// Maximum percentage of lowercase ASCII bytes (`a`..`z`) allowed (0--100).
    ///
    /// Windows exceeding this threshold are rejected. A typical value for
    /// high-entropy secret rules is 95, which allows mixed-case tokens but
    /// rejects natural-language prose.
    pub(super) max_lower_pct: u8,
    /// Minimum window length (in bytes) for the gate to apply.
    ///
    /// Windows shorter than this skip the character-class check entirely,
    /// avoiding unreliable percentage calculations on small byte counts.
    pub(super) min_window_len: u16,
}

/// Sentinel value indicating no gate is assigned for a given slot.
///
/// Using `u32::MAX` as a sentinel instead of `Option<u32>` saves 4 bytes per
/// gate field (no discriminant padding), shrinking `RuleCompiled` by ~32 bytes
/// total across its eight gate fields. Valid pool indices never reach
/// `u32::MAX` because each pool has at most one entry per rule, and the rule
/// count is bounded well below `u32::MAX` by practical memory limits.
pub(super) const NO_GATE: u32 = u32::MAX;

// -- Packed rule metadata bit layout --
//
// `RuleCompiled::rule_meta` packs several per-rule flags into a single `u32`
// to avoid padding and keep the hot struct compact. Bit-packing rather than
// separate `bool` + `Option<u16>` fields saves 6+ bytes of padding per rule,
// which matters when the hot array is iterated for every merged window.
//
// Layout:
//   bits  0..=15  secret_group value (meaningful only when bit 17 is set)
//   bit   16      needs_assignment_shape_check
//   bit   17      has_secret_group_override (distinguishes None from Some(u16::MAX))
//   bit   18      uuid_format_secret
//   bits 19..=31  reserved (must be zero)

const RULE_META_SECRET_GROUP_MASK: u32 = 0xFFFF;
const RULE_META_NEEDS_ASSIGNMENT_SHAPE: u32 = 1 << 16;
const RULE_META_HAS_SECRET_GROUP: u32 = 1 << 17;
const RULE_META_UUID_FORMAT_SECRET: u32 = 1 << 18;

/// Pack per-rule boolean flags and the optional secret-group index into a
/// single `u32` for storage in [`RuleCompiled::rule_meta`].
///
/// A dedicated "has" bit (`RULE_META_HAS_SECRET_GROUP`) disambiguates
/// `secret_group: None` from `secret_group: Some(u16::MAX)`, since the
/// value `0xFFFF` would otherwise collide with the all-ones mask when the
/// group is absent.
#[inline(always)]
fn pack_rule_meta(
    secret_group: Option<u16>,
    needs_assignment_shape_check: bool,
    uuid_format_secret: bool,
) -> u32 {
    let mut meta = 0;
    if let Some(secret_group) = secret_group {
        meta |= RULE_META_HAS_SECRET_GROUP | secret_group as u32;
    }
    if needs_assignment_shape_check {
        meta |= RULE_META_NEEDS_ASSIGNMENT_SHAPE;
    }
    if uuid_format_secret {
        meta |= RULE_META_UUID_FORMAT_SECRET;
    }
    meta
}

/// Hot compiled rule representation used during scanning.
///
/// This keeps precompiled regexes and optional gate pool indices to minimize
/// work in the hot path. Large gate structures are stored in pool vectors on
/// `Engine` and accessed via `u32` indices here (with [`NO_GATE`] as the
/// "absent" sentinel), keeping this struct compact for cache-friendly iteration.
///
/// Cold per-rule metadata (e.g., rule name) is stored in the parallel
/// [`RuleCold`] array at `Engine::rules_cold`, indexed identically so that
/// `rules_hot[i]` and `rules_cold[i]` always describe the same rule.
///
/// # Field layout rationale
///
/// Fields are ordered by access frequency in the scan loop:
///
/// 1. **Every candidate**: `re`, `must_contain`, `rule_meta`
///    — touched for every merged window to decide if the regex runs.
/// 2. **Post-match only**: secret-group bits in `rule_meta` — read only when the
///    regex matches.
/// 3. **Gate indices**: `confirm_all`, `keywords`, `value_suppressors`,
///    `entropy`, `char_class`, `local_context`, `two_phase`,
///    `offline_validation` — dereferenced through `Engine` pool accessors
///    only when the corresponding gate is present (`!= NO_GATE`). Most
///    rules have 0–2 gates, so these are cold for the majority of
///    candidates.
///
/// # Gate pool access
///
/// Gate indices dereference through the corresponding pool on `Engine`:
///
/// | Field          | Pool on `Engine`          |
/// |----------------|---------------------------|
/// | `confirm_all`  | `confirm_all_gates`       |
/// | `keywords`     | `keyword_gates`           |
/// | `value_suppressors` | `value_suppressor_gates` |
/// | `entropy`      | `entropy_gates`           |
/// | `char_class`   | `char_class_gates`        |
/// | `local_context`| `local_context_gates`     |
/// | `two_phase`    | `two_phase_gates`         |
/// | `offline_validation` | `offline_validation_gates` |
///
/// # Invariants
/// - All fields are derived from a validated `RuleSpec`.
/// - Gate indices, when `!= NO_GATE`, are valid into the corresponding pool
///   vectors.
#[derive(Clone, Debug)]
pub(super) struct RuleCompiled {
    pub(super) re: Regex,
    pub(super) must_contain: Option<&'static [u8]>,
    // Packed per-rule metadata:
    // - bits 0..=15: secret_group (when bit 17 is set)
    // - bit 16: needs_assignment_shape_check
    // - bit 17: has_secret_group_override
    // - bit 18: uuid_format_secret
    pub(super) rule_meta: u32,
    // Gate pool indices — dereference through Engine pool vectors.
    // NO_GATE (u32::MAX) means the gate is absent for this rule.
    pub(super) confirm_all: u32,
    pub(super) keywords: u32,
    pub(super) value_suppressors: u32,
    pub(super) entropy: u32,
    pub(super) char_class: u32,
    pub(super) local_context: u32,
    pub(super) two_phase: u32,
    pub(super) offline_validation: u32,
}

impl RuleCompiled {
    /// Whether the window validator should run the assignment-shape precheck
    /// (e.g., looking for `key = value` patterns) before executing the regex.
    ///
    /// Currently only enabled for `generic-api-key`, whose regex is expensive
    /// and whose false-positive rate drops significantly with this gate.
    #[inline(always)]
    pub(super) fn needs_assignment_shape_check(&self) -> bool {
        (self.rule_meta & RULE_META_NEEDS_ASSIGNMENT_SHAPE) != 0
    }

    /// Raw `u16` value of the secret-group capture index.
    ///
    /// Only meaningful when [`has_secret_group_override`](Self::has_secret_group_override)
    /// is `true`; otherwise the low 16 bits are zero but carry no semantic meaning.
    #[inline(always)]
    pub(super) fn secret_group_raw(&self) -> u16 {
        (self.rule_meta & RULE_META_SECRET_GROUP_MASK) as u16
    }

    /// Whether this rule specifies an explicit capture-group override for
    /// secret extraction (i.e., `secret_group` was `Some(_)` in the spec).
    #[inline(always)]
    pub(super) fn has_secret_group_override(&self) -> bool {
        (self.rule_meta & RULE_META_HAS_SECRET_GROUP) != 0
    }

    /// Reconstruct the `Option<u16>` secret-group value from the packed bits.
    ///
    /// Test-only because the hot path uses the decomposed accessors above
    /// to avoid the branch.
    #[cfg(test)]
    #[inline(always)]
    pub(super) fn secret_group(&self) -> Option<u16> {
        self.has_secret_group_override()
            .then_some(self.secret_group_raw())
    }

    /// Returns `true` if this rule intentionally captures UUID-format secrets.
    ///
    /// When set, the UUID-format quick-reject in the safelist is bypassed.
    #[inline(always)]
    pub(super) fn uuid_format_secret(&self) -> bool {
        (self.rule_meta & RULE_META_UUID_FORMAT_SECRET) != 0
    }
}

/// Cold rule metadata consulted only at finding-emission time.
///
/// Stored in `Engine::rules_cold`, a parallel array indexed identically with
/// `Engine::rules_hot` (i.e., `rules_hot[i]` and `rules_cold[i]` always
/// describe the same rule). Separating cold metadata from [`RuleCompiled`]
/// keeps the hot array compact: the scan loop iterates `rules_hot` for every
/// merged window, but only reads `rules_cold` when a finding survives all
/// gates and is about to be emitted.
///
/// # Why separate from `RuleCompiled`?
///
/// `RuleCompiled` is sized for cache-line-friendly iteration (<=88 bytes).
/// Adding reporting fields like `name` (a pointer + length) and
/// `min_confidence` (policy metadata) would inflate the hot struct and waste
/// cache capacity on data that is only read once per emitted finding, not
/// once per candidate window.
#[derive(Clone, Copy, Debug)]
pub(super) struct RuleCold {
    /// Human-readable rule name used in finding reports.
    pub(super) name: &'static str,
    /// Effective minimum confidence threshold for this rule.
    ///
    /// Precomputed by [`derive_min_confidence`] during engine construction.
    /// At emission time, findings whose `confidence_score` is below this
    /// value are suppressed. Stored here (not in `RuleCompiled`) because it
    /// is only consulted at emit time, not in the hot per-window gate loop.
    pub(super) min_confidence: i8,
}

/// Returns whether this rule should use the assignment-shape precheck gate.
///
/// The assignment-shape gate is a cheap textual filter that runs *before*
/// the regex, rejecting windows that lack a `key = value`-like structure.
/// Currently hard-coded to `generic-api-key`, which matches token patterns
/// in arbitrary contexts and benefits most from structural filtering. The
/// gate both (a) reduces false positives by discarding prose windows and
/// (b) enables `confidence::ASSIGNMENT_SHAPE` (+2) as a positive confidence
/// signal when the shape is found.
fn needs_assignment_shape_check(spec: &RuleSpec) -> bool {
    spec.name == "generic-api-key"
}

/// Computes the effective minimum confidence threshold for a rule.
///
/// # Priority cascade
///
/// The first matching tier wins; later tiers are not consulted:
/// 1. Explicit `RuleSpec::min_confidence` override (author intent).
/// 2. Both keyword + entropy gates configured => `KEYWORD_PRESENT + ENTROPY_PASS` (3).
/// 3. Assignment-shape check enabled => `ASSIGNMENT_SHAPE` (2).
/// 4. Default => 0 (no threshold filtering).
///
/// This chooses a single default floor (not an additive score). The
/// keyword+entropy tier requires both signals because that is the evidence
/// combination the auto-derived threshold expects at emission time: a local
/// keyword hit (+2) plus a measured entropy pass (+1) on the same finding.
///
/// # Why offline validation is excluded
///
/// Offline validation (`OFFLINE_VALID`, +5) is only scored on root-semantic
/// findings (`parent_step_id == STEP_ROOT`), so transform-derived findings
/// can never earn it. A per-rule threshold of `OFFLINE_VALID` would silently
/// block all valid transform-derived findings. Rules that want an offline-tier
/// threshold should set `min_confidence` explicitly.
///
/// # Returns
///
/// A value in `0..=10` (Phase 1 ceiling), stored in [`RuleCold::min_confidence`].
pub(super) fn derive_min_confidence(spec: &RuleSpec) -> i8 {
    use crate::api::confidence;

    if let Some(v) = spec.min_confidence {
        return v;
    }
    if spec.keywords_any.is_some() && spec.entropy.is_some() {
        return confidence::KEYWORD_PRESENT + confidence::ENTROPY_PASS;
    }
    if needs_assignment_shape_check(spec) {
        return confidence::ASSIGNMENT_SHAPE;
    }
    0
}

// Compile-time size guards: RuleCompiled is iterated for every merged window
// in the scan loop, so its size directly affects cache pressure. The u32
// sentinel approach (NO_GATE = u32::MAX) saves 4 bytes per gate field vs.
// Option<u32> (which gets no niche optimization for u32::MAX), keeping the
// struct within a single cache line pair.
const _: () = assert!(std::mem::size_of::<u32>() == 4);
const _: () = assert!(std::mem::size_of::<RuleCompiled>() <= 88);
const _: () = assert!(std::mem::size_of::<RuleCold>() <= 24);

// --------------------------
// Compile helpers
// --------------------------

/// Compiled gates returned alongside [`RuleCompiled`] by [`compile_rule`].
///
/// This is a transient bag: the caller (`Engine::new`) pools each `Some`
/// variant into the corresponding type-specific `Vec` on `Engine`, obtains
/// a `u32` pool index, and patches that index onto `RuleCompiled`. `None`
/// fields leave the [`NO_GATE`] sentinel in place (no pool entry allocated).
///
/// After pooling, this struct is dropped -- it exists only to transfer
/// ownership of gate objects from the per-rule compilation step to the
/// engine-wide gate pools.
///
/// # Absent field: `confirm_all`
///
/// `confirm_all` is intentionally absent here. Its literals are derived from
/// regex analysis *after* `compile_rule` returns (via the anchor derivation
/// pass), so the caller builds it separately with [`compile_confirm_all`]
/// and pools it in a second pass.
pub(super) struct CompiledGates {
    pub(super) two_phase: Option<TwoPhaseCompiled>,
    pub(super) keywords: Option<KeywordsCompiled>,
    pub(super) value_suppressors: Option<PackedPatterns>,
    pub(super) entropy: Option<EntropyCompiled>,
    pub(super) char_class: Option<CharClassCompiled>,
    pub(super) local_context: Option<LocalContextSpec>,
    pub(super) offline_validation: Option<OfflineValidationSpec>,
}

/// Compile a validated [`RuleSpec`] into the runtime representation.
///
/// Returns a compact [`RuleCompiled`] with all gate indices set to
/// [`NO_GATE`], plus a [`CompiledGates`] bag holding the heavyweight gate
/// objects. The caller (`Engine::new`) is responsible for:
///
/// 1. Pooling each `Some` gate from `CompiledGates` into the corresponding
///    type-specific `Vec` on `Engine`.
/// 2. Patching the resulting `u32` pool index back onto `RuleCompiled`.
/// 3. Building `confirm_all` separately via [`compile_confirm_all`] (its
///    literals are derived from regex analysis, which happens after this
///    function returns).
///
/// # Gate encoding rules
///
/// - **Two-phase, keywords, confirm-all**: compiled into per-variant
///   `[PackedPatterns; 3]` arrays (Raw + UTF-16LE + UTF-16BE) so the scan
///   loop can gate on raw bytes without decoding.
/// - **Value suppressors**: compiled as raw-only `PackedPatterns` because
///   they run on decoded/extracted secret bytes, never on raw UTF-16 window
///   bytes.
/// - **Entropy, char-class, local-context, offline-validation**: copied
///   verbatim from the spec (small `Copy` types or enums).
///
/// # Panics
/// Panics if `spec.re` cannot be cloned (regex compilation failure upstream).
pub(super) fn compile_rule(spec: &RuleSpec) -> (RuleCompiled, CompiledGates) {
    let two_phase = spec.two_phase.as_ref().map(|tp| {
        let count = tp.confirm_any.len();
        let raw_bytes = tp.confirm_any.iter().map(|p| p.len()).sum::<usize>();
        let utf16_bytes = raw_bytes.saturating_mul(2);
        let mut raw = PackedPatternsBuilder::with_capacity(count, raw_bytes);
        let mut le = PackedPatternsBuilder::with_capacity(count, utf16_bytes);
        let mut be = PackedPatternsBuilder::with_capacity(count, utf16_bytes);

        for &p in tp.confirm_any {
            raw.push_raw(p);
            le.push_utf16le(p);
            be.push_utf16be(p);
        }

        TwoPhaseCompiled {
            seed_radius: tp.seed_radius,
            full_radius: tp.full_radius,
            confirm: [raw.build(), le.build(), be.build()],
        }
    });

    let keywords = spec.keywords_any.map(|kws| {
        let count = kws.len();
        let raw_bytes = kws.iter().map(|p| p.len()).sum::<usize>();
        let utf16_bytes = raw_bytes.saturating_mul(2);

        let mut raw = PackedPatternsBuilder::with_capacity(count, raw_bytes);
        let mut le = PackedPatternsBuilder::with_capacity(count, utf16_bytes);
        let mut be = PackedPatternsBuilder::with_capacity(count, utf16_bytes);

        for &p in kws {
            raw.push_raw(p);
            le.push_utf16le(p);
            be.push_utf16be(p);
        }

        KeywordsCompiled {
            any: [raw.build(), le.build(), be.build()],
        }
    });

    // Value suppressors only need raw patterns: they are checked against
    // extracted secret bytes (post-regex), which are always in decoded byte
    // space, never raw UTF-16 window bytes.
    let value_suppressors = spec.value_suppressors_any.map(|suppressors| {
        let count = suppressors.len();
        let raw_bytes = suppressors.iter().map(|p| p.len()).sum::<usize>();
        let mut raw = PackedPatternsBuilder::with_capacity(count, raw_bytes);
        for &p in suppressors {
            raw.push_raw(p);
        }
        raw.build()
    });

    let entropy = spec.entropy.as_ref().map(|e| EntropyCompiled {
        min_bits_per_byte: e.min_bits_per_byte,
        digit_penalty: e.digit_penalty,
        min_len: e.min_len,
        max_len: e.max_len,
        min_entropy_bits_per_byte: e.min_entropy_bits_per_byte,
    });

    // The assignment-shape precheck (looking for `key = value` structure) is a
    // cheap textual gate that substantially reduces false positives for rules with
    // broad regexes. Currently hard-coded to `generic-api-key` because that rule's
    // regex is intentionally loose and benefits most from this structural filter.
    let needs_assignment_shape_check = needs_assignment_shape_check(spec);

    let rule = RuleCompiled {
        re: spec.re.clone(),
        must_contain: spec.must_contain,
        rule_meta: pack_rule_meta(
            spec.secret_group,
            needs_assignment_shape_check,
            spec.uuid_format_secret,
        ),
        confirm_all: NO_GATE,
        keywords: NO_GATE,
        value_suppressors: NO_GATE,
        entropy: NO_GATE,
        char_class: NO_GATE,
        local_context: NO_GATE,
        two_phase: NO_GATE,
        offline_validation: NO_GATE,
    };

    let char_class = spec.char_class.map(|cc| CharClassCompiled {
        max_lower_pct: cc.max_lower_pct,
        min_window_len: cc.min_window_len,
    });

    let gates = CompiledGates {
        two_phase,
        keywords,
        value_suppressors,
        entropy,
        char_class,
        local_context: spec.local_context,
        offline_validation: spec.offline_validation,
    };

    (rule, gates)
}

/// Compile derived mandatory literal islands into a [`ConfirmAllCompiled`] gate.
///
/// Called by `Engine::new` *after* [`compile_rule`], because the mandatory
/// literals are produced by the regex analysis / anchor derivation pass that
/// runs between the two stages.
///
/// Returns `None` if `confirm_all` is empty (no mandatory literals derived).
///
/// The longest literal becomes the `primary` selector -- checked first via a
/// single `memmem` search for early rejection (longest needles are least
/// likely to appear by chance in non-matching windows). The remaining literals
/// are packed into AND-gated tables (all must match) for the secondary pass.
///
/// Sorting is longest-first with ties broken lexicographically. The tiebreaker
/// ensures deterministic primary selection across compilations when multiple
/// literals share the same length.
pub(super) fn compile_confirm_all(mut confirm_all: Vec<Vec<u8>>) -> Option<ConfirmAllCompiled> {
    if confirm_all.is_empty() {
        return None;
    }

    // Sort longest-first so the primary literal is maximally selective.
    confirm_all.sort_unstable_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
    let primary = confirm_all.remove(0);
    let primary_raw: Option<Box<[u8]>> = Some(primary.clone().into_boxed_slice());
    let primary_le: Option<Box<[u8]>> = Some(utf16le_bytes(&primary).into_boxed_slice());
    let primary_be: Option<Box<[u8]>> = Some(utf16be_bytes(&primary).into_boxed_slice());

    let count = confirm_all.len();
    let raw_bytes = confirm_all.iter().map(|p| p.len()).sum::<usize>();
    let utf16_bytes = raw_bytes.saturating_mul(2);
    let mut raw = PackedPatternsBuilder::with_capacity(count, raw_bytes);
    let mut le = PackedPatternsBuilder::with_capacity(count, utf16_bytes);
    let mut be = PackedPatternsBuilder::with_capacity(count, utf16_bytes);

    for p in confirm_all {
        raw.push_raw(&p);
        le.push_utf16le(&p);
        be.push_utf16be(&p);
    }

    Some(ConfirmAllCompiled {
        primary: [primary_raw, primary_le, primary_be],
        rest: [raw.build(), le.build(), be.build()],
    })
}

/// Register a `(pattern, target)` pair in the anchor dedup map, borrowing the pattern.
///
/// Multiple rules (and variants) may share the same anchor byte pattern. This
/// map deduplicates patterns so each unique byte sequence appears only once in
/// the Vectorscan prefilter DB, with a fanout list of [`Target`] entries that
/// records every (rule, variant) combination that needs to be notified on a hit.
///
/// If the pattern already exists in the map, the target is appended to its
/// fanout list. Otherwise, the pattern is cloned into the map as a new entry.
///
/// Use [`add_pat_owned`] when the caller already has an owned `Vec<u8>` (e.g.,
/// UTF-16-expanded patterns produced by [`utf16le_bytes`] / [`utf16be_bytes`])
/// to avoid the clone.
pub(super) fn add_pat_raw(map: &mut AHashMap<Vec<u8>, Vec<Target>>, pat: &[u8], target: Target) {
    if let Some(existing) = map.get_mut(pat) {
        existing.push(target);
    } else {
        map.insert(pat.to_vec(), vec![target]);
    }
}

/// Register a `(pattern, target)` pair in the anchor dedup map, taking ownership.
///
/// Same semantics as [`add_pat_raw`] but avoids cloning when the pattern bytes
/// are already owned (common for UTF-16-expanded anchors produced by
/// [`utf16le_bytes`] / [`utf16be_bytes`]).
pub(super) fn add_pat_owned(
    map: &mut AHashMap<Vec<u8>, Vec<Target>>,
    pat: Vec<u8>,
    target: Target,
) {
    if let Some(existing) = map.get_mut(pat.as_slice()) {
        existing.push(target);
    } else {
        map.insert(pat, vec![target]);
    }
}

/// Flatten the anchor dedup map into packed arrays consumed by the prefilter pipeline.
///
/// Consumes the dedup map built by [`add_pat_raw`] / [`add_pat_owned`] and
/// produces three parallel arrays:
///
/// - `patterns[i]`: the `i`-th unique anchor pattern (sorted lexicographically).
/// - `flat_targets[offsets[i]..offsets[i+1]]`: the [`Target`] entries for
///   pattern `i`, recording every (rule, variant) pair that needs notification.
/// - `offsets`: prefix-sum index with length `patterns.len() + 1`.
///
/// The patterns vector is fed to Vectorscan's multi-pattern compiler. Because
/// Vectorscan assigns pattern ids positionally (pattern 0 gets id 0, etc.),
/// the lexicographic sort is essential: it guarantees the same anchor bytes
/// always receive the same id, regardless of `AHashMap` iteration order.
/// Each pattern's target list is also sorted by packed [`Target`] value to
/// ensure deterministic fanout across compilations.
///
/// # Why deterministic ordering matters
///
/// Without stable pattern-id assignment, a Vectorscan hit callback would route
/// to a wrong (rule, variant) accumulator whenever `AHashMap` reorders entries
/// between compilations. The sort-by-bytes guarantee closes this gap.
pub(super) fn map_to_patterns(
    map: AHashMap<Vec<u8>, Vec<Target>>,
) -> (Vec<Vec<u8>>, Vec<Target>, Vec<u32>) {
    let mut entries: Vec<(Vec<u8>, Vec<Target>)> = map.into_iter().collect();
    entries.sort_unstable_by(|(a, _), (b, _)| a.cmp(b));

    let mut patterns: Vec<Vec<u8>> = Vec::with_capacity(entries.len());
    let mut flat: Vec<Target> = Vec::new();
    let mut offsets: Vec<u32> = Vec::with_capacity(entries.len().saturating_add(1));
    offsets.push(0);

    let mut total_targets = 0usize;
    for (_, ts) in entries.iter() {
        total_targets = total_targets.saturating_add(ts.len());
    }
    flat.reserve(total_targets);

    for (p, mut ts) in entries {
        ts.sort_unstable();
        patterns.push(p);
        flat.extend(ts);
        assert!(flat.len() <= u32::MAX as usize);
        // Prefix-sum offsets: each pattern id maps to flat[start..end].
        offsets.push(flat.len() as u32);
    }

    (patterns, flat, offsets)
}

/// Convert ASCII bytes to UTF-16LE encoding (each byte `b` becomes `[b, 0x00]`).
///
/// This is an ASCII-only expansion used for literal gating, not a
/// general-purpose UTF-16 encoder. Input is assumed to be ASCII (0x00--0x7F);
/// non-ASCII input produces technically invalid UTF-16 but is still useful
/// for byte-level literal matching in the prefilter and gate pipelines.
///
/// The output length is always `2 * ascii.len()`.
pub(super) fn utf16le_bytes(ascii: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(ascii.len() * 2);
    for &b in ascii {
        out.push(b);
        out.push(0);
    }
    out
}

/// Convert ASCII bytes to UTF-16BE encoding (each byte `b` becomes `[0x00, b]`).
///
/// This is an ASCII-only expansion used for literal gating, not a
/// general-purpose UTF-16 encoder. Input is assumed to be ASCII (0x00--0x7F);
/// non-ASCII input produces technically invalid UTF-16 but is still useful
/// for byte-level literal matching in the prefilter and gate pipelines.
///
/// The output length is always `2 * ascii.len()`.
pub(super) fn utf16be_bytes(ascii: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(ascii.len() * 2);
    for &b in ascii {
        out.push(0);
        out.push(b);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{EntropySpec, OfflineValidationSpec, RuleSpec, ValidatorKind, confidence};
    use regex::bytes::Regex;
    use rstest::rstest;

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

    fn test_rule_spec(value_suppressors_any: Option<&'static [&'static [u8]]>) -> RuleSpec {
        RuleSpec {
            name: "compile-rule-test",
            anchors: &[b"TOK_"],
            radius: 32,
            validator: ValidatorKind::None,
            two_phase: None,
            must_contain: None,
            keywords_any: None,
            value_suppressors_any,
            entropy: None,
            char_class: None,
            local_context: None,
            secret_group: Some(1),
            min_confidence: None,
            offline_validation: None,
            uuid_format_secret: false,
            re: Regex::new(r"TOK_([A-Z0-9]{4})").unwrap(),
        }
    }

    #[test]
    fn map_to_patterns_sorts_patterns_and_targets() {
        let mut map: AHashMap<Vec<u8>, Vec<Target>> = AHashMap::new();
        map.insert(
            b"b".to_vec(),
            vec![Target::new(2, Variant::Raw), Target::new(1, Variant::Raw)],
        );
        map.insert(b"a".to_vec(), vec![Target::new(3, Variant::Utf16Le)]);
        map.insert(b"aa".to_vec(), vec![Target::new(1, Variant::Raw)]);

        let (patterns, flat, offsets) = map_to_patterns(map);

        assert_eq!(patterns, vec![b"a".to_vec(), b"aa".to_vec(), b"b".to_vec()]);
        assert_eq!(offsets, vec![0, 1, 2, 4]);
        assert_eq!(
            flat,
            vec![
                Target::new(3, Variant::Utf16Le),
                Target::new(1, Variant::Raw),
                Target::new(1, Variant::Raw),
                Target::new(2, Variant::Raw),
            ]
        );
    }

    #[test]
    fn compile_rule_builds_value_suppressor_patterns() {
        static SUPPRESSORS: &[&[u8]] = &[b"EXAMPLE", b"DUMMY_TOKEN"];
        let spec = test_rule_spec(Some(SUPPRESSORS));

        let (rule, gates) = compile_rule(&spec);
        assert_eq!(rule.value_suppressors, NO_GATE);
        let packed = gates
            .value_suppressors
            .as_ref()
            .expect("value suppressors should be compiled");
        assert_eq!(
            unpack_patterns(packed),
            vec![b"EXAMPLE".to_vec(), b"DUMMY_TOKEN".to_vec()]
        );
    }

    #[test]
    fn compile_rule_without_value_suppressors_has_no_gate() {
        let spec = test_rule_spec(None);
        let (rule, gates) = compile_rule(&spec);

        assert_eq!(rule.value_suppressors, NO_GATE);
        assert!(gates.value_suppressors.is_none());
    }

    #[rstest]
    #[case::no_signals(None, false, false, false, false, 0)]
    #[case::explicit_override(Some(7), false, false, false, false, 7)]
    #[case::offline_alone_no_threshold(None, true, false, false, false, 0)]
    #[case::override_beats_offline(Some(3), true, false, false, false, 3)]
    #[case::keywords_plus_entropy(None, false, true, true, false,
        confidence::KEYWORD_PRESENT + confidence::ENTROPY_PASS)]
    #[case::keywords_only(None, false, true, false, false, 0)]
    #[case::entropy_only(None, false, false, true, false, 0)]
    #[case::offline_ignored_keywords_plus_entropy(
        None,
        true,
        true,
        true,
        false,
        confidence::KEYWORD_PRESENT + confidence::ENTROPY_PASS
    )]
    #[case::assignment_shape(None, false, false, false, true, confidence::ASSIGNMENT_SHAPE)]
    fn derive_min_confidence_priority_cascade(
        #[case] min_confidence: Option<i8>,
        #[case] has_offline: bool,
        #[case] has_keywords: bool,
        #[case] has_entropy: bool,
        #[case] is_generic_api_key: bool,
        #[case] expected: i8,
    ) {
        let mut spec = test_rule_spec(None);
        spec.min_confidence = min_confidence;
        if has_offline {
            spec.offline_validation = Some(OfflineValidationSpec::Crc32Base62 {
                prefix_skip: 4,
                payload_len: 8,
                checksum_len: 6,
            });
        }
        if has_keywords {
            spec.keywords_any = Some(&[b"key"]);
        }
        if has_entropy {
            spec.entropy = Some(EntropySpec {
                min_bits_per_byte: 2.0,
                min_len: 4,
                max_len: 32,
                min_entropy_bits_per_byte: None,
                digit_penalty: false,
            });
        }
        if is_generic_api_key {
            spec.name = "generic-api-key";
        }
        assert_eq!(derive_min_confidence(&spec), expected);
    }

    #[test]
    fn pack_rule_meta_distinguishes_none_from_explicit_max_secret_group() {
        let none_meta = pack_rule_meta(None, false, false);
        let explicit_max_meta = pack_rule_meta(Some(u16::MAX), false, false);

        assert_ne!(
            none_meta, explicit_max_meta,
            "explicit secret_group=u16::MAX must not be conflated with None"
        );
    }

    #[test]
    fn pack_rule_meta_uuid_format_secret_round_trips() {
        let meta_without_uuid = pack_rule_meta(Some(42), true, false);
        let meta_with_uuid = pack_rule_meta(Some(42), true, true);

        let dummy_re = Regex::new(r"x").unwrap();

        let rule_without = RuleCompiled {
            re: dummy_re.clone(),
            must_contain: None,
            rule_meta: meta_without_uuid,
            confirm_all: NO_GATE,
            keywords: NO_GATE,
            value_suppressors: NO_GATE,
            entropy: NO_GATE,
            char_class: NO_GATE,
            local_context: NO_GATE,
            two_phase: NO_GATE,
            offline_validation: NO_GATE,
        };

        let rule_with = RuleCompiled {
            re: dummy_re,
            must_contain: None,
            rule_meta: meta_with_uuid,
            confirm_all: NO_GATE,
            keywords: NO_GATE,
            value_suppressors: NO_GATE,
            entropy: NO_GATE,
            char_class: NO_GATE,
            local_context: NO_GATE,
            two_phase: NO_GATE,
            offline_validation: NO_GATE,
        };

        // Bit 18 round-trips correctly.
        assert!(
            !rule_without.uuid_format_secret(),
            "uuid_format_secret should be false when packed as false"
        );
        assert!(
            rule_with.uuid_format_secret(),
            "uuid_format_secret should be true when packed as true"
        );

        // Other fields are unaffected by bit 18.
        assert_eq!(
            rule_without.secret_group(),
            rule_with.secret_group(),
            "secret_group must be identical regardless of uuid_format_secret"
        );
        assert_eq!(rule_without.secret_group(), Some(42));

        assert_eq!(
            rule_without.needs_assignment_shape_check(),
            rule_with.needs_assignment_shape_check(),
            "needs_assignment_shape_check must be identical regardless of uuid_format_secret"
        );
        assert!(rule_without.needs_assignment_shape_check());
    }
}
