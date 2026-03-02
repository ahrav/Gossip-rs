//! YARA-style base64 gate.
//!
//! # Problem
//! Base64 encoding groups bytes into 3-byte blocks. A raw anchor can therefore
//! start at offsets 0, 1, or 2 within a block, yielding three base64
//! permutations. YARA documents this for "This program cannot" and notes that
//! leading/trailing base64 characters can be unstable because they depend on
//! adjacent bytes. See: https://yara.readthedocs.io/en/stable/writingrules.html
//!
//! Sigma's `base64offset` modifier describes the same phenomenon: there are
//! three variants for shifts by 0..2 bytes and a stable middle segment.
//!
//! # Scope
//! This is a *gate* only. It does not validate base64 or decode; it only checks
//! whether any stable base64 substrings derived from anchors appear in the input.
//!
//! # Build-time algorithm
//! For each anchor `A` and each offset `o` in 0..=2:
//! - Prefix `A` with `o` zero bytes to model unknown preceding bytes.
//! - Encode with the standard base64 alphabet.
//! - Drop the unstable prefix: `o=0 -> 0`, `o=1 -> 2`, `o=2 -> 3`.
//! - Drop the unstable suffix based on `(len(prefix+A) % 3)`:
//!   `rem=0 -> 0`, `rem=1 -> 3`, `rem=2 -> 2`.
//! - Keep the remaining substring if it is at least `min_pattern_len`.
//!
//! # Runtime canonicalization
//! - Ignore whitespace per policy.
//! - Map urlsafe `'-'` to `'+'` and `'_'` to `'/'`.
//! - Handle `'='` per policy (stop-and-halt or reset-and-continue).
//! - Any other byte breaks the current run; matches never cross boundaries.
//!
//! # Semantics
//! - False positives are expected; this is a gate.
//! - False negatives are possible if short patterns are dropped via `min_pattern_len`.
//! - Matches are confined to canonicalized runs and never span invalid bytes or padding.
//!
//! # Performance
//! - Scan time is O(1) per byte via a dense 64-symbol Aho-Corasick automaton.
//! - Memory is O(states * 64), trading space for predictable latency.

use std::collections::{BTreeSet, VecDeque};
use std::sync::Arc;

/// How to treat base64 padding during scanning.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PaddingPolicy {
    /// Stop scanning at the first '=' and keep this "halted" state across
    /// subsequent chunks until the caller resets the `GateState`.
    StopAndHalt,
    /// Treat '=' as a boundary: reset to the root state and continue scanning.
    ResetAndContinue,
}

/// Which whitespace characters are ignored while scanning.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WhitespacePolicy {
    /// Ignore only SP, TAB, CR, LF (common decoder behavior).
    Rfc4648,
    /// Ignore all ASCII whitespace (includes VT and FF).
    AsciiWhitespace,
}

/// Configuration for building a base64 gate.
///
/// This controls how aggressively patterns are dropped and how input is
/// canonicalized at scan time.
#[derive(Clone, Debug)]
pub struct Base64YaraGateConfig {
    /// Drop generated base64-permutation patterns shorter than this.
    /// - Larger => fewer false positives, faster downstream, but higher miss risk for short anchors.
    /// - Smaller => more coverage for short anchors, but gate becomes noisy.
    ///
    /// This length check happens after unstable prefix/suffix trimming.
    pub min_pattern_len: usize,
    /// How to treat '=' (padding) in input.
    /// Default: `PaddingPolicy::ResetAndContinue`.
    pub padding_policy: PaddingPolicy,
    /// Which whitespace characters to ignore in input.
    /// Default: `WhitespacePolicy::Rfc4648`.
    pub whitespace_policy: WhitespacePolicy,
}

impl Default for Base64YaraGateConfig {
    fn default() -> Self {
        Self {
            min_pattern_len: 0,
            padding_policy: PaddingPolicy::ResetAndContinue,
            whitespace_policy: WhitespacePolicy::Rfc4648,
        }
    }
}

/// Streaming state for incremental scans across chunks.
///
/// Semantics:
/// - Tracks the automaton state across chunks.
/// - When `PaddingPolicy::StopAndHalt` is used, once '=' (padding) is observed,
///   scanning is halted for the remainder of the span (sticky across subsequent
///   `scan_with_state()` calls) until `reset()` is invoked.
/// - The state is only valid for the gate that produced it. If it is reused
///   across gates, scanning falls back to the root state instead of panicking.
#[derive(Clone, Copy, Debug, Default)]
pub struct GateState {
    // Index into the AC node array. Stored as u32 to keep GateState small and copyable.
    state: u32,
    // Once padding is observed, later bytes are outside the base64 span and must be ignored.
    halted: bool,
}

impl GateState {
    /// Reset to the root state and clear any padding halt.
    #[inline]
    pub fn reset(&mut self) {
        self.state = 0;
        self.halted = false;
    }
}

/// Immutable base64 gate backed by a dense automaton.
///
/// Cloning this struct is cheap; the automaton is reference-counted.
#[derive(Clone, Debug)]
pub struct Base64YaraGate {
    ac: Arc<Ac64>,
    pattern_count: usize,
    padding_policy: PaddingPolicy,
    whitespace_policy: WhitespacePolicy,
}

impl Base64YaraGate {
    /// Build the gate from raw anchor byte patterns.
    ///
    /// Anchors are treated as raw bytes (include UTF-16 variants upstream if you
    /// want them gated too). Each anchor can produce up to three patterns
    /// (offsets 0..=2) after trimming unstable prefix/suffix, and patterns
    /// shorter than `cfg.min_pattern_len` are dropped. Generated patterns are
    /// deduplicated to keep the automaton compact and deterministic.
    ///
    /// The patterns are built using the standard base64 alphabet; urlsafe input
    /// is handled at scan time via canonicalization.
    pub fn build<'a, I>(anchors: I, cfg: Base64YaraGateConfig) -> Self
    where
        I: IntoIterator<Item = &'a [u8]>,
    {
        // Deduplicate patterns to keep the AC compact and deterministic.
        // BTreeSet preserves a stable order across runs, which helps tests and fuzzers.
        let mut set: BTreeSet<Vec<u8>> = BTreeSet::new();

        for a in anchors {
            if a.is_empty() {
                continue;
            }
            for offset in 0..3 {
                if let Some(p) = yara_base64_perm(a, offset, cfg.min_pattern_len) {
                    set.insert(p);
                }
            }
        }

        let patterns: Vec<Vec<u8>> = set.into_iter().collect();
        let ac = Ac64::build_from_base64_patterns(&patterns);

        Self {
            ac: Arc::new(ac),
            pattern_count: patterns.len(),
            padding_policy: cfg.padding_policy,
            whitespace_policy: cfg.whitespace_policy,
        }
    }

    /// Number of unique base64 patterns compiled into the gate.
    ///
    /// The count reflects deduplication across anchors and offsets.
    pub fn pattern_count(&self) -> usize {
        self.pattern_count
    }

    /// One-shot scan of an encoded base64-ish span.
    ///
    /// Returns true if any compiled pattern is observed after canonicalization.
    /// This is a gate only: it can return false positives and may miss patterns
    /// that were dropped by `min_pattern_len`.
    #[inline]
    pub fn hits(&self, encoded: &[u8]) -> bool {
        // Allocate a fresh streaming state so callers do not need to manage it.
        let mut st = GateState::default();
        self.scan_with_state(encoded, &mut st)
    }

    /// One-shot scan over a whole buffer, treating '=' as a boundary.
    ///
    /// This is a conservative buffer-level prefilter: it resets state at
    /// padding boundaries rather than halting, so a single call can cover the
    /// entire buffer. It may return more false positives than `hits`, but it
    /// will not introduce false negatives for valid base64 runs.
    ///
    /// # Difference from `hits`
    /// - `hits_anywhere`: Treats '=' as a boundary (resets state) but continues
    ///   scanning the rest of the buffer. Suitable for whole-buffer prefiltering.
    /// - `hits`: Respects `PaddingPolicy` and may halt entirely on '=' (with
    ///   `StopAndHalt`). Suitable for per-span scanning with precise boundaries.
    #[inline]
    pub fn hits_anywhere(&self, encoded: &[u8]) -> bool {
        let mut state = 0usize;
        let lut = input_lut(self.whitespace_policy);

        for &b in encoded {
            let v = lut[b as usize];
            if v < 64 {
                let sym = v as usize;
                state = self.ac.next_state(state, sym);
                if self.ac.is_match(state) {
                    return true;
                }
                continue;
            }

            if v == TAG_WS {
                continue;
            }

            if v == TAG_PAD {
                // Treat padding as a boundary and continue scanning.
                state = 0;
                continue;
            }

            // Any other byte breaks the run; restart from the root state.
            state = 0;
        }

        false
    }

    /// Incremental scan. Useful if your base64 span crosses chunk boundaries.
    ///
    /// Caller must reset state between independent spans/runs.
    ///
    /// Canonicalization and boundaries:
    /// - Whitespace is ignored per policy.
    /// - '-' and '_' are mapped to '+' and '/'.
    /// - '=' is handled per `PaddingPolicy`.
    /// - Any other byte resets the automaton to the root state, so matches never
    ///   span invalid bytes or padding boundaries.
    ///
    /// With `PaddingPolicy::StopAndHalt`, stopping at '=' is sticky across
    /// chunks. Once '=' is seen, this returns false for subsequent calls until
    /// `GateState::reset()` is invoked.
    #[inline]
    pub fn scan_with_state(&self, encoded: &[u8], st: &mut GateState) -> bool {
        // Sticky stop across calls for the same span.
        if self.padding_policy == PaddingPolicy::StopAndHalt && st.halted {
            return false;
        }
        if self.padding_policy == PaddingPolicy::ResetAndContinue {
            // Clear any stale halt bit if a state is reused across gates/policies.
            st.halted = false;
        }

        // Defensive: if a state from another gate is reused, avoid panicking.
        // This trades perfect streaming semantics for resilience against misuse.
        // An invalid state (>= state_count) silently restarts from the root,
        // which may miss a match that spans the boundary but prevents crashes.
        let mut state = st.state as usize;
        if state >= self.ac.state_count() {
            state = 0;
        }

        let lut = input_lut(self.whitespace_policy);

        for &b in encoded {
            let v = lut[b as usize];
            if v < 64 {
                let sym = v as usize;
                state = self.ac.next_state(state, sym);
                if self.ac.is_match(state) {
                    // Any match is enough to gate-in decoding. We do not report
                    // which pattern matched, only that at least one did.
                    st.state = state as u32;
                    return true;
                }
                continue;
            }

            if v == TAG_WS {
                continue;
            }

            if v == TAG_PAD {
                match self.padding_policy {
                    PaddingPolicy::StopAndHalt => {
                        // '=' marks the end of a base64 span. We stop early to avoid
                        // false matches across unrelated data and to keep streaming fast.
                        st.state = state as u32;
                        st.halted = true;
                        return false;
                    }
                    PaddingPolicy::ResetAndContinue => {
                        // Treat padding as a boundary and keep scanning.
                        state = 0;
                        continue;
                    }
                }
            }

            // Not base64-ish: reset to root so matches cannot span
            // across invalid bytes. This mirrors the naive oracle that
            // only matches within canonicalized runs.
            state = 0;
        }

        st.state = state as u32;
        false
    }
}

// -----------------------------
// Pattern generation (YARA-style)
// -----------------------------

/// Compute the YARA-style base64 permutation for a given anchor and offset.
///
/// This models the anchor starting at byte offset 0..=2 within a 3-byte
/// base64 block. Unstable base64 characters that depend on unknown adjacent
/// bytes are trimmed from both ends. Returns None if the resulting pattern
/// is empty or shorter than `min_pat_len`.
fn yara_base64_perm(anchor: &[u8], offset: usize, min_pat_len: usize) -> Option<Vec<u8>> {
    assert!(offset < 3);
    if anchor.is_empty() {
        return None;
    }

    // Build [0; offset] + anchor to simulate the anchor being shifted by offset bytes
    // in the decoded stream. The leading zeros stand in for the unknown preceding bytes.
    let mut prefixed = Vec::with_capacity(offset + anchor.len());
    prefixed.resize(offset, 0u8);
    prefixed.extend_from_slice(anchor);

    let enc = base64_encode_std(&prefixed);

    // YARA's documented permutations match stripping:
    // offset 0 => strip 0 left chars
    // offset 1 => strip 2 left chars
    // offset 2 => strip 3 left chars
    //
    // Rationale: when the anchor is not aligned to 3-byte blocks, the first 2 or 3
    // base64 characters depend on the preceding (unknown) bytes. Those characters
    // are unstable across real input, so they are dropped from the gate pattern.
    let left = match offset {
        0 => 0usize,
        1 => 2usize,
        2 => 3usize,
        _ => unreachable!(),
    };

    // Strip right chars based on remainder.
    // For total_len % 3:
    //   0 => no dependency on following bytes, strip 0
    //   1 => last 3 chars depend on following bytes, strip 3
    //   2 => last 2 chars depend on following bytes, strip 2
    //
    // Rationale mirrors the left-strip: trailing base64 characters can encode bits
    // from bytes after the anchor, so they are not stable if we only know the anchor.
    let rem = prefixed.len() % 3;
    let right = match rem {
        0 => 0usize,
        1 => 3usize,
        2 => 2usize,
        _ => unreachable!(),
    };

    if enc.len() <= left + right {
        return None;
    }

    let pat = enc[left..(enc.len() - right)].to_vec();
    if pat.len() < min_pat_len {
        return None;
    }
    Some(pat)
}

const BASE64_STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Minimal standard-alphabet base64 encoder.
///
/// Used only for gate pattern generation and tests; it does not handle line
/// wrapping or alternative alphabets.
fn base64_encode_std(input: &[u8]) -> Vec<u8> {
    // This encoder is intentionally minimal and used only for gate pattern generation
    // and tests, not for general-purpose use. Capacity uses div_ceil to avoid reallocation.
    let mut out = Vec::with_capacity(input.len().div_ceil(3) * 4);

    let mut i = 0usize;
    while i + 3 <= input.len() {
        let b0 = input[i] as u32;
        let b1 = input[i + 1] as u32;
        let b2 = input[i + 2] as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;

        out.push(BASE64_STD[((n >> 18) & 63) as usize]);
        out.push(BASE64_STD[((n >> 12) & 63) as usize]);
        out.push(BASE64_STD[((n >> 6) & 63) as usize]);
        out.push(BASE64_STD[(n & 63) as usize]);

        i += 3;
    }

    let rem = input.len() - i;
    if rem == 1 {
        // One leftover byte maps to two base64 chars plus "==" padding.
        let b0 = input[i] as u32;
        let n = b0 << 16;
        out.push(BASE64_STD[((n >> 18) & 63) as usize]);
        out.push(BASE64_STD[((n >> 12) & 63) as usize]);
        out.push(b'=');
        out.push(b'=');
    } else if rem == 2 {
        // Two leftover bytes map to three base64 chars plus "=" padding.
        let b0 = input[i] as u32;
        let b1 = input[i + 1] as u32;
        let n = (b0 << 16) | (b1 << 8);
        out.push(BASE64_STD[((n >> 18) & 63) as usize]);
        out.push(BASE64_STD[((n >> 12) & 63) as usize]);
        out.push(BASE64_STD[((n >> 6) & 63) as usize]);
        out.push(b'=');
    }

    out
}

// -----------------------------
// Runtime normalization
// -----------------------------

/// Marker for bytes that are not valid base64 alphabet characters.
const TAG_INVALID: u8 = 0xFF;
/// Marker for whitespace bytes (space, newline, tab, etc.) to be skipped.
const TAG_WS: u8 = 0xFE;
/// Marker for padding character '=' which may reset or halt the automaton.
const TAG_PAD: u8 = 0xFD;

#[inline]
const fn is_ws_rfc4648(b: u8) -> bool {
    matches!(b, b' ' | b'\n' | b'\r' | b'\t')
}

#[inline]
const fn is_ws_ascii(b: u8) -> bool {
    matches!(b, b' ' | b'\n' | b'\r' | b'\t' | 0x0b | 0x0c)
}

#[inline]
const fn base64_sym(b: u8) -> u8 {
    if b >= b'A' && b <= b'Z' {
        b - b'A'
    } else if b >= b'a' && b <= b'z' {
        b - b'a' + 26
    } else if b >= b'0' && b <= b'9' {
        b - b'0' + 52
    } else if b == b'+' || b == b'-' {
        62
    } else if b == b'/' || b == b'_' {
        63
    } else {
        TAG_INVALID
    }
}

const fn build_lut(allow_ascii_ws: bool) -> [u8; 256] {
    let mut lut = [TAG_INVALID; 256];
    let mut i = 0usize;
    while i < 256 {
        let b = i as u8;
        if b == b'=' {
            lut[i] = TAG_PAD;
        } else if if allow_ascii_ws {
            is_ws_ascii(b)
        } else {
            is_ws_rfc4648(b)
        } {
            lut[i] = TAG_WS;
        } else {
            let sym = base64_sym(b);
            if sym != TAG_INVALID {
                lut[i] = sym;
            }
        }
        i += 1;
    }
    lut
}

const LUT_RFC4648: [u8; 256] = build_lut(false);
const LUT_ASCII_WS: [u8; 256] = build_lut(true);

#[inline]
fn input_lut(policy: WhitespacePolicy) -> &'static [u8; 256] {
    match policy {
        WhitespacePolicy::Rfc4648 => &LUT_RFC4648,
        WhitespacePolicy::AsciiWhitespace => &LUT_ASCII_WS,
    }
}

/// Map pattern bytes (standard base64 alphabet) to symbol 0..63.
#[inline]
fn sym_from_pattern_byte(b: u8) -> Option<u8> {
    let sym = base64_sym(b);
    if sym == TAG_INVALID { None } else { Some(sym) }
}

// -----------------------------
// Dense automaton over 64-symbol alphabet
// -----------------------------

const NONE: u32 = u32::MAX;

#[derive(Clone, Debug)]
struct Node {
    // Dense next-state table for the 64-symbol base64 alphabet.
    // This is memory-heavy but keeps scan time strictly O(1) per byte.
    next: [u32; 64],
    fail: u32,
    // True if any pattern ends at this state (including via fail links).
    out: bool,
}

impl Node {
    fn new() -> Self {
        Self {
            next: [NONE; 64],
            fail: 0,
            out: false,
        }
    }
}

#[derive(Debug)]
struct Ac64 {
    // Dense next-state table: state * 64 + sym -> next state
    next: Box<[u32]>,
    // Output marker per state (0/1).
    out: Box<[u8]>,
}

impl Ac64 {
    /// Build a dense Aho-Corasick automaton over the standard base64 alphabet.
    ///
    /// Patterns must contain only standard base64 characters; otherwise this
    /// will panic (internal invariant).
    fn build_from_base64_patterns(patterns: &[Vec<u8>]) -> Self {
        let mut nodes: Vec<Node> = Vec::new();
        nodes.push(Node::new()); // root

        // Insert patterns
        for pat in patterns {
            if pat.is_empty() {
                continue;
            }
            let mut s = 0usize;
            for &ch in pat {
                let sym = sym_from_pattern_byte(ch).expect("pattern contains non-base64 character")
                    as usize;
                let nxt = nodes[s].next[sym];
                if nxt == NONE {
                    let new_idx = u32::try_from(nodes.len()).expect("AC too large for u32 state");
                    nodes.push(Node::new());
                    nodes[s].next[sym] = new_idx;
                    s = new_idx as usize;
                } else {
                    s = nxt as usize;
                }
            }
            nodes[s].out = true;
        }

        // Build failure links and densify transitions.
        //
        // After this pass, every node has a defined transition for every symbol.
        // That makes next_state a single table lookup with no branches, which is
        // the main performance goal of this gate.
        let mut q: VecDeque<usize> = VecDeque::new();

        // Root: missing transitions point to root. Existing children fail to root.
        for sym in 0..64 {
            let nxt = nodes[0].next[sym];
            if nxt == NONE {
                nodes[0].next[sym] = 0;
            } else {
                nodes[nxt as usize].fail = 0;
                q.push_back(nxt as usize);
            }
        }

        while let Some(v) = q.pop_front() {
            let fail_v = nodes[v].fail as usize;

            // Propagate output through fail links so any suffix match is reported.
            if nodes[fail_v].out {
                nodes[v].out = true;
            }

            for sym in 0..64 {
                let nxt = nodes[v].next[sym];
                if nxt == NONE {
                    // Inherit transition from fail state (dense goto function).
                    nodes[v].next[sym] = nodes[fail_v].next[sym];
                } else {
                    // Compute fail transition for child based on the parent's fail.
                    let f = nodes[fail_v].next[sym];
                    nodes[nxt as usize].fail = f;
                    q.push_back(nxt as usize);
                }
            }
        }

        let states = nodes.len();
        let mut next = vec![0u32; states * 64];
        let mut out = vec![0u8; states];

        for (i, node) in nodes.iter().enumerate() {
            out[i] = node.out as u8;
            let base = i * 64;
            next[base..(base + 64)].copy_from_slice(&node.next);
        }

        Self {
            next: next.into_boxed_slice(),
            out: out.into_boxed_slice(),
        }
    }

    #[inline]
    fn next_state(&self, state: usize, sym: usize) -> usize {
        self.next[state * 64 + sym] as usize
    }

    #[inline]
    fn is_match(&self, state: usize) -> bool {
        self.out[state] != 0
    }

    #[inline]
    fn state_count(&self) -> usize {
        self.out.len()
    }
}

// -----------------------------
// Tests
// -----------------------------
#[cfg(test)]
mod tests {
    use super::*;

    // --- Dev-deps used by this test module ---
    // base64: differential oracle for encoding + trimming rules
    // proptest: structured randomized property tests

    use std::collections::BTreeSet;

    // Differential reference: standard base64 encoding
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;

    use proptest::prelude::*;

    // -----------------------------
    // Helpers for corpus + oracles
    // -----------------------------

    /// Canonicalize input bytes the same way the gate does, but *materialize* valid runs
    /// as bytes ('+'/'/' etc), breaking on invalid bytes and handling '=' per policy.
    fn split_into_canonical_segments(
        encoded: &[u8],
        padding_policy: PaddingPolicy,
        whitespace_policy: WhitespacePolicy,
    ) -> Vec<Vec<u8>> {
        let mut segs: Vec<Vec<u8>> = Vec::new();
        let mut cur: Vec<u8> = Vec::new();
        let lut = super::input_lut(whitespace_policy);

        for &b in encoded {
            let v = lut[b as usize];
            if v == super::TAG_WS {
                continue;
            }
            if v == super::TAG_PAD {
                match padding_policy {
                    PaddingPolicy::StopAndHalt => break,
                    PaddingPolicy::ResetAndContinue => {
                        if !cur.is_empty() {
                            segs.push(std::mem::take(&mut cur));
                        }
                    }
                }
                continue;
            }

            if v < 64 {
                cur.push(super::BASE64_STD[v as usize]);
            } else if !cur.is_empty() {
                segs.push(std::mem::take(&mut cur));
            }
        }
        if !cur.is_empty() {
            segs.push(cur);
        }
        segs
    }

    fn segment_contains(seg: &[u8], pat: &[u8]) -> bool {
        if pat.is_empty() {
            return true;
        }
        if pat.len() > seg.len() {
            return false;
        }
        seg.windows(pat.len()).any(|w| w == pat)
    }

    /// Naive/oracle matcher that must be equivalent to the AC gate:
    /// - ignores whitespace per policy
    /// - maps '-'->'+', '_'->'/'
    /// - handles '=' per policy
    /// - does not match across invalid bytes (resets)
    fn oracle_hits(
        patterns: &[Vec<u8>],
        encoded: &[u8],
        padding_policy: PaddingPolicy,
        whitespace_policy: WhitespacePolicy,
    ) -> bool {
        let segs = split_into_canonical_segments(encoded, padding_policy, whitespace_policy);
        for seg in &segs {
            for pat in patterns {
                if segment_contains(seg, pat) {
                    return true;
                }
            }
        }
        false
    }

    fn build_patterns_from_anchors(anchors: &[&[u8]], min_pat_len: usize) -> Vec<Vec<u8>> {
        let mut set: BTreeSet<Vec<u8>> = BTreeSet::new();
        for a in anchors {
            if a.is_empty() {
                continue;
            }
            for offset in 0..3 {
                if let Some(p) = super::yara_base64_perm(a, offset, min_pat_len) {
                    set.insert(p);
                }
            }
        }
        set.into_iter().collect()
    }

    /// Reference implementation of the same YARA trimming rule, but using the `base64` crate
    /// as the encoding oracle (differential test).
    fn ref_yara_base64_perm_using_base64_crate(
        anchor: &[u8],
        offset: usize,
        min_pat_len: usize,
    ) -> Option<Vec<u8>> {
        if anchor.is_empty() || offset >= 3 {
            return None;
        }

        let mut prefixed = vec![0u8; offset];
        prefixed.extend_from_slice(anchor);

        let enc = STANDARD.encode(&prefixed).into_bytes();

        let left = match offset {
            0 => 0usize,
            1 => 2usize,
            2 => 3usize,
            _ => unreachable!(),
        };

        let rem = prefixed.len() % 3;
        let right = match rem {
            0 => 0usize,
            1 => 3usize,
            2 => 2usize,
            _ => unreachable!(),
        };

        if enc.len() <= left + right {
            return None;
        }

        let pat = enc[left..(enc.len() - right)].to_vec();
        if pat.len() < min_pat_len {
            return None;
        }
        Some(pat)
    }

    fn insert_newlines_every(s: &[u8], every: usize) -> Vec<u8> {
        if every == 0 {
            return s.to_vec();
        }
        let mut out = Vec::with_capacity(s.len() + (s.len() / every) + 4);
        for (i, &b) in s.iter().enumerate() {
            if i != 0 && i % every == 0 {
                out.push(b'\n');
            }
            out.push(b);
        }
        out
    }

    fn to_urlsafe(s: &[u8]) -> Vec<u8> {
        s.iter()
            .map(|&b| match b {
                b'+' => b'-',
                b'/' => b'_',
                other => other,
            })
            .collect()
    }

    fn stream_scan_two_chunks(gate: &Base64YaraGate, bytes: &[u8], split: usize) -> bool {
        let split = split.min(bytes.len());
        let mut st = GateState::default();
        let a = gate.scan_with_state(&bytes[..split], &mut st);
        let b = gate.scan_with_state(&bytes[split..], &mut st);
        a || b
    }

    // -----------------------------
    // 1) Curated corpus tests
    // -----------------------------

    #[test]
    fn corpus_yara_doc_example_permutations_match() {
        // YARA docs show these three permutations for "This program cannot".
        let a = b"This program cannot";

        let p0 = yara_base64_perm(a, 0, 0).unwrap();
        let p1 = yara_base64_perm(a, 1, 0).unwrap();
        let p2 = yara_base64_perm(a, 2, 0).unwrap();

        assert_eq!(
            std::str::from_utf8(&p0).unwrap(),
            "VGhpcyBwcm9ncmFtIGNhbm5vd"
        );
        assert_eq!(
            std::str::from_utf8(&p1).unwrap(),
            "RoaXMgcHJvZ3JhbSBjYW5ub3"
        );
        assert_eq!(
            std::str::from_utf8(&p2).unwrap(),
            "UaGlzIHByb2dyYW0gY2Fubm90"
        );
    }

    #[test]
    fn corpus_rfc_whitespace_policy_does_not_ignore_vt_ff() {
        let gate = Base64YaraGate::build(
            [b"abc".as_slice()],
            Base64YaraGateConfig {
                min_pattern_len: 4,
                whitespace_policy: WhitespacePolicy::Rfc4648,
                ..Default::default()
            },
        );

        let encoded = b"YW\x0bJj\x0c";
        assert!(!gate.hits(encoded));
    }

    #[test]
    fn corpus_ascii_whitespace_policy_ignores_vt_ff() {
        let gate = Base64YaraGate::build(
            [b"abc".as_slice()],
            Base64YaraGateConfig {
                min_pattern_len: 4,
                whitespace_policy: WhitespacePolicy::AsciiWhitespace,
                ..Default::default()
            },
        );

        let encoded = b"YW\x0bJj\x0c";
        assert!(gate.hits(encoded));
    }

    #[test]
    fn corpus_stop_at_padding_prevents_matches_after_equals() {
        let gate = Base64YaraGate::build(
            [b"test".as_slice()],
            Base64YaraGateConfig {
                min_pattern_len: 0,
                padding_policy: PaddingPolicy::StopAndHalt,
                ..Default::default()
            },
        );

        // Ensure the "test" pattern is after '='.
        // If scanning continues after '=', this would match.
        let encoded = b"AAAA=dGVzdA";
        assert!(!gate.hits(encoded));
    }

    #[test]
    fn hits_anywhere_continues_after_padding() {
        let gate = Base64YaraGate::build(
            [b"abc".as_slice()],
            Base64YaraGateConfig {
                min_pattern_len: 4,
                padding_policy: PaddingPolicy::StopAndHalt,
                ..Default::default()
            },
        );

        let encoded = b"foo=YWJj";
        assert!(!gate.hits(encoded));
        assert!(gate.hits_anywhere(encoded));
    }

    #[test]
    fn corpus_padding_reset_allows_matches_after_equals() {
        // Anchor "abc" -> "YWJj"
        let gate = Base64YaraGate::build(
            [b"abc".as_slice()],
            Base64YaraGateConfig {
                min_pattern_len: 4,
                padding_policy: PaddingPolicy::ResetAndContinue,
                ..Default::default()
            },
        );

        let encoded = b"foo=YWJj";
        assert!(gate.hits(encoded));
    }

    #[test]
    fn corpus_true_negative_no_slashes_no_match_for_slash_heavy_anchor() {
        // Anchor -> pattern contains '/', but input has no '/' and no '_' (which maps to '/').
        let anchor = &[0xffu8, 0xffu8, 0xffu8]; // "////"
        let gate = Base64YaraGate::build(
            [anchor.as_slice()],
            Base64YaraGateConfig {
                min_pattern_len: 4,
                ..Default::default()
            },
        );

        let input = b"plain ascii text without any slash characters or underscores";
        assert!(!gate.hits(input));
    }

    #[test]
    fn corpus_invalid_bytes_reset_state_no_match_across_nul() {
        // "abc" -> "YWJj"
        let gate = Base64YaraGate::build(
            [b"abc".as_slice()],
            Base64YaraGateConfig {
                min_pattern_len: 4,
                ..Default::default()
            },
        );
        let broken = b"YW\0Jj"; // NUL resets; cannot match across it
        assert!(!gate.hits(broken));
    }

    // -----------------------------
    // 2) Determinism + streaming equivalence
    // -----------------------------

    #[test]
    fn streaming_stop_at_first_padding_is_sticky_across_chunks() {
        // Anchor "abc" has base64 "YWJj".
        // With min_pattern_len=4, only the offset=0 pattern ("YWJj") is kept.
        let gate = Base64YaraGate::build(
            [b"abc".as_slice()],
            Base64YaraGateConfig {
                min_pattern_len: 4,
                padding_policy: PaddingPolicy::StopAndHalt,
                ..Default::default()
            },
        );

        // "Ma" -> "TWE=" then "abc" -> "YWJj"
        let encoded = b"TWE=YWJj";

        assert!(!gate.hits(encoded));

        let mut st = GateState::default();
        let first = gate.scan_with_state(&encoded[..4], &mut st); // "TWE="
        let second = gate.scan_with_state(&encoded[4..], &mut st); // "YWJj"
        assert!(!(first || second));
    }

    #[test]
    fn streaming_padding_reset_continues_after_equals() {
        let gate = Base64YaraGate::build(
            [b"abc".as_slice()],
            Base64YaraGateConfig {
                min_pattern_len: 4,
                padding_policy: PaddingPolicy::ResetAndContinue,
                ..Default::default()
            },
        );

        let encoded = b"TWE=YWJj";
        let mut st = GateState::default();
        let first = gate.scan_with_state(&encoded[..4], &mut st);
        let second = gate.scan_with_state(&encoded[4..], &mut st);
        assert!(!first);
        assert!(second);
    }

    #[test]
    fn gate_state_reset_clears_padding_halt() {
        let gate = Base64YaraGate::build(
            [b"abc".as_slice()],
            Base64YaraGateConfig {
                min_pattern_len: 4,
                padding_policy: PaddingPolicy::StopAndHalt,
                ..Default::default()
            },
        );

        let mut st = GateState::default();
        assert!(!gate.scan_with_state(b"TWE=", &mut st));
        assert!(!gate.scan_with_state(b"YWJj", &mut st));

        st.reset();
        assert!(gate.scan_with_state(b"YWJj", &mut st));
    }

    #[test]
    fn reusing_gate_state_across_different_gates_does_not_panic() {
        // This is defensive; correct usage is "reset between spans and don't reuse across gates".
        let g1 = Base64YaraGate::build(
            [b"abc".as_slice()],
            Base64YaraGateConfig {
                min_pattern_len: 0,
                ..Default::default()
            },
        );
        let g2 = Base64YaraGate::build(
            [b"This program cannot".as_slice()],
            Base64YaraGateConfig {
                min_pattern_len: 0,
                ..Default::default()
            },
        );

        let mut st = GateState::default();
        let _ = g1.scan_with_state(b"YWJj", &mut st);
        let _ = g2.scan_with_state(b"VGhpcyBwcm9ncmFtIGNhbm5vd", &mut st);
    }

    // -----------------------------
    // 3) Robustness / hostile inputs
    // -----------------------------

    #[test]
    fn robustness_long_input_does_not_panic_and_is_deterministic() {
        let gate = Base64YaraGate::build(
            [
                b"This program cannot".as_slice(),
                b"abc".as_slice(),
                b"\xff\xff\xff".as_slice(),
            ],
            Base64YaraGateConfig {
                min_pattern_len: 0,
                ..Default::default()
            },
        );

        // 256 KiB of mostly-non-base64 bytes + islands.
        let mut data = vec![0u8; 256 * 1024];
        for (i, b) in data.iter_mut().enumerate() {
            // Deterministic pseudo-noise (no RNG dep here)
            let v = (i as u32)
                .wrapping_mul(1103515245u32)
                .wrapping_add(12345u32);
            *b = v as u8;
        }
        // Add a base64-ish island with whitespace + urlsafe.
        data.extend_from_slice(b"\n____\n");
        data.extend_from_slice(b"VGhpcyBwcm9ncmFtIGNhbm5vd");

        let a = gate.hits(&data);
        let b = gate.hits(&data);
        assert_eq!(a, b);
    }

    // -----------------------------
    // 4) Proptest properties (deterministic, high leverage)
    // -----------------------------

    proptest! {
        // Keep this fast enough for PRs.
        // In CI/nightly, bump with: PROPTEST_CASES=... and/or run proptest with more cases.
        #![proptest_config(ProptestConfig {
            cases: 128,
            max_shrink_iters: 256,
            .. ProptestConfig::default()
        })]

        // 2.1 Encoder correctness vs reference oracle.
        #[test]
        fn prop_base64_encode_std_matches_base64_crate(bytes in proptest::collection::vec(any::<u8>(), 0..=4096)) {
            let ours = super::base64_encode_std(&bytes);
            let theirs = STANDARD.encode(&bytes).into_bytes();
            prop_assert_eq!(ours, theirs);
        }

        // 2.2 YARA trimming rules correctness vs reference oracle.
        #[test]
        fn prop_yara_perm_matches_reference(
            anchor in proptest::collection::vec(any::<u8>(), 1..=256),
            offset in 0usize..3,
            min_len in 0usize..=16,
        ) {
            let ours = super::yara_base64_perm(&anchor, offset, min_len);
            let theirs = ref_yara_base64_perm_using_base64_crate(&anchor, offset, min_len);
            prop_assert_eq!(ours, theirs);
        }

        // 2.3 Gate algorithm correctness: AC gate must match naive oracle for arbitrary inputs.
        #[test]
        fn prop_gate_equals_oracle_for_random_inputs(
            anchors in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 1..=32), 1..=6),
            min_len in 0usize..=8,
            input in proptest::collection::vec(any::<u8>(), 0..=4096),
        ) {
            let anchor_slices: Vec<&[u8]> = anchors.iter().map(|a| a.as_slice()).collect();
            let cfg = Base64YaraGateConfig {
                min_pattern_len: min_len,
                ..Default::default()
            };
            let gate = Base64YaraGate::build(anchor_slices.iter().copied(), cfg.clone());
            let patterns = build_patterns_from_anchors(&anchor_slices, min_len);

            let g = gate.hits(&input);
            let o = oracle_hits(&patterns, &input, cfg.padding_policy, cfg.whitespace_policy);

            prop_assert_eq!(g, o);
        }

        // 2.4 Canonicalization invariants (whitespace + urlsafe mapping) should not change result.
        #[test]
        fn prop_canonicalization_invariance(
            anchors in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 3..=32), 1..=4),
            min_len in 0usize..=8,
            raw in proptest::collection::vec(any::<u8>(), 0..=512),
        ) {
            let anchor_slices: Vec<&[u8]> = anchors.iter().map(|a| a.as_slice()).collect();
            let gate = Base64YaraGate::build(
                anchor_slices.iter().copied(),
                Base64YaraGateConfig {
                    min_pattern_len: min_len,
                    ..Default::default()
                },
            );

            // Make a base64-ish candidate by encoding raw.
            let enc = super::base64_encode_std(&raw);

            // Variants: line-wrapped, urlsafe, both.
            let v1 = insert_newlines_every(&enc, 76);
            let v2 = to_urlsafe(&enc);
            let v3 = insert_newlines_every(&v2, 64);

            let a = gate.hits(&enc);
            let b = gate.hits(&v1);
            let c = gate.hits(&v2);
            let d = gate.hits(&v3);

            prop_assert_eq!(a, b);
            prop_assert_eq!(a, c);
            prop_assert_eq!(a, d);
        }

        // 2.5 Streaming vs one-shot must be equivalent (two-chunk split derived from data).
        #[test]
        fn prop_streaming_equivalence_two_chunks(
            anchors in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 1..=32), 1..=4),
            min_len in 0usize..=8,
            input in proptest::collection::vec(any::<u8>(), 0..=4096),
            split_seed in any::<u16>(),
        ) {
            let anchor_slices: Vec<&[u8]> = anchors.iter().map(|a| a.as_slice()).collect();
            let gate = Base64YaraGate::build(
                anchor_slices.iter().copied(),
                Base64YaraGateConfig {
                    min_pattern_len: min_len,
                    ..Default::default()
                },
            );

            let split = if input.is_empty() {
                0
            } else {
                (split_seed as usize) % (input.len() + 1)
            };

            let one = gate.hits(&input);
            let streaming = stream_scan_two_chunks(&gate, &input, split);

            prop_assert_eq!(one, streaming);
        }

        // 2.6 YARA-style "anchor present in decoded bytes implies gate hits on the base64 encoding"
        // Conditioned on "pattern for the actual offset exists under min_len".
        #[test]
        fn prop_anchor_present_implies_gate_hits_when_pattern_exists(
            anchor in proptest::collection::vec(any::<u8>(), 3..=64),
            prefix in proptest::collection::vec(any::<u8>(), 0..=24),
            suffix in proptest::collection::vec(any::<u8>(), 0..=24),
            min_len in 0usize..=8,
        ) {
            let offset = prefix.len() % 3;
            let expected_pat = super::yara_base64_perm(&anchor, offset, min_len);

            // Only assert the implication when a non-dropped pattern exists for the actual alignment.
            prop_assume!(expected_pat.is_some());

            let gate = Base64YaraGate::build(
                [anchor.as_slice()],
                Base64YaraGateConfig {
                    min_pattern_len: min_len,
                    ..Default::default()
                },
            );

            let mut decoded = prefix.clone();
            decoded.extend_from_slice(&anchor);
            decoded.extend_from_slice(&suffix);

            let enc = super::base64_encode_std(&decoded);

            // Make it more realistic: add whitespace and urlsafe mapping.
            let enc = insert_newlines_every(&to_urlsafe(&enc), 76);

            prop_assert!(gate.hits(&enc));
        }
    }

    // -----------------------------
    // 5) Pattern count boundary checks (sanity)
    // -----------------------------

    #[test]
    fn pattern_count_dedups_duplicates_for_short_anchors() {
        // For very short anchors, different offsets can yield identical patterns.
        let gate = Base64YaraGate::build(
            [b"\x00".as_slice()],
            Base64YaraGateConfig {
                min_pattern_len: 0,
                ..Default::default()
            },
        );
        assert!(gate.pattern_count() >= 1);
        assert!(gate.pattern_count() <= 3);
    }
}
