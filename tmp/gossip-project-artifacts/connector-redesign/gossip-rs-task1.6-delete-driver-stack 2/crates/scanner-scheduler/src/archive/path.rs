//! Deterministic virtual path construction for archive entries.
//!
//! Converts raw archive entry names (which may contain arbitrary bytes, `..`
//! traversals, or Windows separators) into bounded, printable-ASCII display
//! identifiers. These identifiers are used in logging and scan results -- they
//! are **not** filesystem paths and are never used to open files.
//!
//! Two public types compose the full pipeline:
//!
//! - [`EntryPathCanonicalizer`] -- sanitizes a single entry name (resolve `.`/`..`,
//!   escape non-printable bytes, enforce length + component caps).
//! - [`VirtualPathBuilder`] -- joins `parent::entry` display bytes, optionally
//!   with a suffix (e.g. a transaction-id tag), applying the same truncation scheme.
//!
//! # Invariants
//! - Output bytes are printable ASCII (`0x20..=0x7E`); everything else is
//!   percent-escaped as `%HH` (uppercase hex).
//! - `..` traversal never escapes above the virtual root.
//! - Output length is bounded by `max_len`. When truncated, a deterministic
//!   `~#<16-hex-digit>` suffix (FNV-1a of the *full* untruncated output) replaces
//!   the tail, so two different long paths never silently collide.
//! - Component count is capped to avoid zip-bomb-style path explosion.
//!
//! # Algorithm
//! 1. Normalize separators (`\` → `/`) and split into components.
//! 2. Drop `.`; resolve `..` via a stack, clamping at root.
//! 3. Emit escaped display bytes, streaming the FNV-1a hash over the full
//!    (unbounded) output while storing only up to `max_len` bytes.
//! 4. If the full output exceeded `max_len`, replace the stored tail with the
//!    hash suffix, taking care not to split a `%HH` escape at the boundary.
//!
//! # Design Notes
//! - Output is a **display identifier**, not a filesystem path.
//! - ASCII output avoids terminal / control-byte issues in logs.
//! - FNV-1a is chosen for speed and simplicity -- collision resistance is not
//!   a security goal here; the hash exists only to distinguish truncated paths.
//! - `EntryPathCanonicalizer` uses two internal buffers (component ranges + output bytes);
//!   `VirtualPathBuilder` uses a single `Vec<u8>` output buffer. Both are intended to
//!   be allocated once per worker thread for steady-state zero allocation.

use crate::archive::util;

/// Default maximum number of path components allowed during canonicalization.
pub const DEFAULT_MAX_COMPONENTS: usize = 256;

/// Suffix inserted on truncation: `~#` + 16 hex digits (64-bit hash).
const TRUNC_SUFFIX_LEN: usize = 2 + 16;

/// Placeholder used when canonicalization produces an empty path.
const EMPTY_PLACEHOLDER: &[u8] = b"<empty>";

/// Placeholder used when component cap is exceeded (caller should usually skip).
const COMPONENT_CAP_PLACEHOLDER: &[u8] = b"<component-cap-exceeded>";

/// Result of entry-path canonicalization.
///
/// Borrows the canonicalizer's internal buffer -- the slice is valid until
/// the next call to [`EntryPathCanonicalizer::canonicalize`].
///
/// Callers typically inspect the flags to decide whether to log a warning
/// (`had_traversal`, `component_cap_exceeded`) and use `bytes` as the
/// display path in scan results.
pub struct CanonicalPath<'a> {
    /// Sanitized display bytes (printable ASCII, percent-escaped).
    pub bytes: &'a [u8],
    /// True if input attempted to traverse above root (`..` with empty stack).
    pub had_traversal: bool,
    /// True if output was length-truncated and a hash suffix was appended.
    pub truncated: bool,
    /// True if component cap was exceeded. Output will be a placeholder.
    pub component_cap_exceeded: bool,
    /// 64-bit deterministic hash. For normal paths, hashes the canonical display bytes.
    /// When `component_cap_exceeded` is true, hashes the raw input bytes with
    /// separator normalization instead.
    pub hash64: u64,
}

/// Result of virtual path construction (`parent::entry`).
///
/// Borrows the builder's internal buffer -- the slice is valid until the
/// next call to [`VirtualPathBuilder::build`] or [`VirtualPathBuilder::build_with_suffix`].
pub struct VirtualPath<'a> {
    /// The assembled display bytes (e.g. `/tmp/a.zip::dir/file.txt`).
    pub bytes: &'a [u8],
    pub truncated: bool,
    /// 64-bit deterministic hash of the full (untruncated) display bytes.
    /// Returns 0 when the suffix alone exceeds `max_len` (no base bytes to hash).
    pub hash64: u64,
}

/// Canonicalizes archive entry names into bounded, printable-ASCII display bytes.
///
/// # Guarantees
/// - Returned slices are valid until the next call to [`Self::canonicalize`].
/// - Output length never exceeds `max_len`; component count never exceeds `max_components`.
/// - Internal buffers never grow beyond the capacity set by [`Self::with_capacity`].
///
/// # Performance
/// Intended to be allocated once per worker thread and reused across entries.
/// After the first call, all operations are zero-allocation (the internal
/// `Vec`s are cleared and refilled within their existing capacity).  Use
/// [`Self::debug_assert_no_growth`] in tests to verify this invariant.
#[derive(Default)]
pub struct EntryPathCanonicalizer {
    // Resolved component ranges `(start, end)` into the *raw input* slice.
    // Stored as ranges rather than owned copies to avoid copying bytes during
    // the resolve phase; the emit phase reads back from the raw slice.
    comps: Vec<(usize, usize)>,
    // Output buffer for escaped display bytes (printable ASCII).
    out: Vec<u8>,

    // Debug-only capacity guards.
    #[cfg(debug_assertions)]
    comps_cap: usize,
    #[cfg(debug_assertions)]
    out_cap: usize,
}

impl EntryPathCanonicalizer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Pre-size internal buffers for steady-state zero growth.
    pub fn with_capacity(max_components: usize, max_len: usize) -> Self {
        let comps_cap = max_components.min(DEFAULT_MAX_COMPONENTS);
        let out_cap = max_len;
        Self {
            comps: Vec::with_capacity(comps_cap),
            out: Vec::with_capacity(out_cap),
            #[cfg(debug_assertions)]
            comps_cap,
            #[cfg(debug_assertions)]
            out_cap,
        }
    }

    /// Debug-only guard: ensure internal buffers never grow after startup.
    #[inline]
    pub fn debug_assert_no_growth(&self) {
        #[cfg(debug_assertions)]
        {
            if self.comps_cap != 0 {
                debug_assert_eq!(
                    self.comps.capacity(),
                    self.comps_cap,
                    "canonicalizer comps grew after startup"
                );
            }
            if self.out_cap != 0 {
                debug_assert_eq!(
                    self.out.capacity(),
                    self.out_cap,
                    "canonicalizer output grew after startup"
                );
            }
        }
    }

    /// Canonicalize a raw archive entry path into bounded display bytes.
    ///
    /// The method works in two phases:
    ///
    /// **Phase 1 -- Resolve:** Split the raw bytes on `/` and `\`, drop `.`,
    /// resolve `..` via a stack (clamping at root), and enforce the component cap.
    /// This phase stores `(start, end)` ranges into `raw` -- no bytes are copied.
    ///
    /// **Phase 2 -- Emit:** Walk the resolved ranges, percent-escape non-printable
    /// bytes, and stream-hash the full (unbounded) output via FNV-1a.  Only the
    /// first `max_len` bytes are stored; if the full output exceeded that limit,
    /// the stored tail is replaced with `~#<16hex>` (the hash suffix).
    ///
    /// # Truncation boundary
    /// The suffix replacement avoids splitting a `%HH` escape: if the cut falls
    /// inside one, the prefix is shortened by 1-2 bytes so the escape stays intact.
    ///
    /// # Clamping
    /// `max_len` and `max_components` are silently clamped to internal buffer
    /// capacity to prevent growth. Use [`Self::with_capacity`] to size for
    /// larger limits.
    pub fn canonicalize<'a>(
        &'a mut self,
        raw: &[u8],
        max_components: usize,
        max_len: usize,
    ) -> CanonicalPath<'a> {
        let max_len = max_len.min(self.out.capacity());
        let max_components = max_components
            .min(DEFAULT_MAX_COMPONENTS)
            .min(self.comps.capacity());
        debug_assert!(
            self.out.capacity() >= max_len,
            "canonicalizer output buffer too small for max_len"
        );
        debug_assert!(
            self.comps.capacity() >= max_components,
            "canonicalizer component stack too small for max_components"
        );
        self.comps.clear();

        let mut had_traversal = false;
        let mut component_cap_exceeded = false;

        // Split and resolve '.' / '..' using a bounded stack of ranges into `raw`.
        let mut i = 0usize;
        while i < raw.len() {
            // Skip separators (treat '\\' as '/').
            while i < raw.len() && is_sep(raw[i]) {
                i += 1;
            }
            if i >= raw.len() {
                break;
            }
            let start = i;
            while i < raw.len() && !is_sep(raw[i]) {
                i += 1;
            }
            let end = i;
            if end <= start {
                continue;
            }

            let comp = &raw[start..end];
            if comp == b"." {
                continue;
            }
            if comp == b".." {
                if self.comps.pop().is_none() {
                    had_traversal = true;
                }
                continue;
            }

            if self.comps.len() >= max_components {
                component_cap_exceeded = true;
                break;
            }

            self.comps.push((start, end));
        }

        // Emit escaped display bytes and hash them deterministically.
        self.out.clear();

        // If component cap exceeded, output a deterministic placeholder and hash raw bytes.
        if component_cap_exceeded {
            let h = fnv1a64_raw_with_sep_norm(raw);
            emit_truncated_with_hash_suffix(&mut self.out, COMPONENT_CAP_PLACEHOLDER, h, max_len);
            return CanonicalPath {
                bytes: &self.out,
                had_traversal,
                truncated: self.out.len() < COMPONENT_CAP_PLACEHOLDER.len(),
                component_cap_exceeded: true,
                hash64: h,
            };
        }

        // If empty after canonicalization, emit placeholder.
        if self.comps.is_empty() {
            let h = util::fnv1a64(EMPTY_PLACEHOLDER);
            emit_truncated_with_hash_suffix(&mut self.out, EMPTY_PLACEHOLDER, h, max_len);
            return CanonicalPath {
                bytes: &self.out,
                had_traversal,
                truncated: self.out.len() < EMPTY_PLACEHOLDER.len(),
                component_cap_exceeded: false,
                hash64: h,
            };
        }

        // Emit full display bytes up to max_len, but compute hash over full (unbounded) display bytes.
        let mut hash = util::fnv1a64_init();
        let mut full_len = 0usize;

        for (idx, (s, e)) in self.comps.iter().copied().enumerate() {
            if idx != 0 {
                emit_one(&mut self.out, &mut hash, &mut full_len, b'/', max_len);
            }
            for &b in &raw[s..e] {
                emit_escaped_byte(&mut self.out, &mut hash, &mut full_len, b, max_len);
            }
        }

        // If truncation happened (full_len > max_len), rewrite to prefix + suffix.
        let truncated = full_len > max_len;
        if truncated {
            apply_hash_suffix_truncation(&mut self.out, hash, max_len);
        } else {
            // Ensure out length matches full_len (it should, since full_len <= max_len).
            debug_assert_eq!(self.out.len(), full_len);
        }

        CanonicalPath {
            bytes: &self.out,
            had_traversal,
            truncated,
            component_cap_exceeded: false,
            hash64: hash,
        }
    }
}

/// Joins a parent display path and an entry name with a `::` separator,
/// producing bounded display bytes with the same truncation scheme as
/// [`EntryPathCanonicalizer`].
///
/// The `::` separator is chosen to be visually distinct from filesystem
/// separators (`/`, `\`) so nested archive paths read unambiguously in logs:
/// `/tmp/outer.tar::inner.zip::dir/file.txt`.
///
/// Like `EntryPathCanonicalizer`, allocate once per worker thread and reuse.
#[derive(Default)]
pub struct VirtualPathBuilder {
    out: Vec<u8>,

    // Debug-only capacity guard.
    #[cfg(debug_assertions)]
    cap: usize,
}

impl VirtualPathBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Pre-size the internal buffer for steady-state zero growth.
    ///
    /// `max_len` should match the largest `max_len` argument you will pass
    /// to [`Self::build`] or [`Self::build_with_suffix`].
    pub fn with_capacity(max_len: usize) -> Self {
        Self {
            out: Vec::with_capacity(max_len),
            #[cfg(debug_assertions)]
            cap: max_len,
        }
    }

    /// Debug-only guard: ensure internal buffer never grows after startup.
    #[inline]
    pub fn debug_assert_no_growth(&self) {
        #[cfg(debug_assertions)]
        {
            debug_assert_eq!(
                self.out.capacity(),
                self.cap,
                "virtual path builder grew after startup"
            );
        }
    }

    /// Builds `parent_display_bytes + "::" + entry_display_bytes`.
    ///
    /// If result exceeds `max_len`, it truncates and appends `~#<16hex>` where
    /// the hash is computed over the full untruncated bytes.
    pub fn build<'a>(&'a mut self, parent: &[u8], entry: &[u8], max_len: usize) -> VirtualPath<'a> {
        let max_len = max_len.min(self.out.capacity());
        debug_assert!(
            self.out.capacity() >= max_len,
            "virtual path buffer too small for max_len"
        );
        self.out.clear();

        let mut hash = util::fnv1a64_init();
        let mut full_len = 0usize;

        for &b in parent {
            emit_one(&mut self.out, &mut hash, &mut full_len, b, max_len);
        }
        emit_one(&mut self.out, &mut hash, &mut full_len, b':', max_len);
        emit_one(&mut self.out, &mut hash, &mut full_len, b':', max_len);
        for &b in entry {
            emit_one(&mut self.out, &mut hash, &mut full_len, b, max_len);
        }

        let truncated = full_len > max_len;
        if truncated {
            apply_hash_suffix_truncation(&mut self.out, hash, max_len);
        } else {
            debug_assert_eq!(self.out.len(), full_len);
        }

        VirtualPath {
            bytes: &self.out,
            truncated,
            hash64: hash,
        }
    }

    /// Builds `parent::entry` and appends `suffix` after the entry segment.
    ///
    /// If the full output exceeds `max_len`, it truncates the base
    /// `parent::entry` portion (with `~#<16hex>` hash suffix) and then appends
    /// `suffix`, so the suffix always appears at the end.
    ///
    /// If `suffix` alone exceeds `max_len`, the output is the truncated suffix
    /// and `hash64` is returned as 0.
    pub fn build_with_suffix<'a>(
        &'a mut self,
        parent: &[u8],
        entry: &[u8],
        suffix: &[u8],
        max_len: usize,
    ) -> VirtualPath<'a> {
        let max_len = max_len.min(self.out.capacity());
        debug_assert!(
            self.out.capacity() >= max_len,
            "virtual path buffer too small for max_len"
        );
        self.out.clear();

        if max_len == 0 {
            return VirtualPath {
                bytes: &self.out,
                truncated: parent
                    .len()
                    .saturating_add(entry.len())
                    .saturating_add(suffix.len())
                    > 0,
                hash64: 0,
            };
        }

        let suffix_len = suffix.len();
        if suffix_len > max_len {
            self.out.extend_from_slice(&suffix[..max_len]);
            return VirtualPath {
                bytes: &self.out,
                truncated: true,
                hash64: 0,
            };
        }

        let base_limit = max_len - suffix_len;
        let mut hash = util::fnv1a64_init();
        let mut full_len = 0usize;

        for &b in parent {
            emit_one(&mut self.out, &mut hash, &mut full_len, b, base_limit);
        }
        emit_one(&mut self.out, &mut hash, &mut full_len, b':', base_limit);
        emit_one(&mut self.out, &mut hash, &mut full_len, b':', base_limit);
        for &b in entry {
            emit_one(&mut self.out, &mut hash, &mut full_len, b, base_limit);
        }

        let truncated = full_len > base_limit;
        if truncated {
            apply_hash_suffix_truncation(&mut self.out, hash, base_limit);
        } else {
            debug_assert_eq!(self.out.len(), full_len);
        }

        if suffix_len > 0 {
            self.out.extend_from_slice(suffix);
        }

        VirtualPath {
            bytes: &self.out,
            truncated,
            hash64: hash,
        }
    }
}

// -------------------------
// Internals
// -------------------------

#[inline(always)]
fn is_sep(b: u8) -> bool {
    b == b'/' || b == b'\\'
}

// FNV-1a helpers are in `crate::archive::util`. The separator-normalizing
// variant below is path-specific (normalizes `\` → `/` before hashing).

// Hash raw bytes with `\` normalized to `/`.  Used for the component-cap-exceeded
// placeholder so that `a\b\c` and `a/b/c` hash identically.
fn fnv1a64_raw_with_sep_norm(raw: &[u8]) -> u64 {
    let mut h = util::fnv1a64_init();
    for &b in raw {
        let bb = if b == b'\\' { b'/' } else { b };
        h = util::fnv1a64_update(h, bb);
    }
    h
}

// Core emit primitive: unconditionally hashes `b` and increments `full_len`,
// but only stores the byte in `out` while `out.len() < max_len`.  This lets
// the caller compute the hash over the full (unbounded) output while keeping
// the stored prefix bounded -- the key trick behind the truncation scheme.
#[inline(always)]
fn emit_one(out: &mut Vec<u8>, hash: &mut u64, full_len: &mut usize, b: u8, max_len: usize) {
    *hash = util::fnv1a64_update(*hash, b);
    *full_len = full_len.saturating_add(1);
    if out.len() < max_len {
        out.push(b);
    }
}

// Escape non-printable bytes and '%' as `%HH` (uppercase).
#[inline(always)]
fn emit_escaped_byte(
    out: &mut Vec<u8>,
    hash: &mut u64,
    full_len: &mut usize,
    b: u8,
    max_len: usize,
) {
    if is_printable_ascii(b) && b != b'%' {
        emit_one(out, hash, full_len, b, max_len);
    } else {
        emit_one(out, hash, full_len, b'%', max_len);
        let hi = (b >> 4) & 0xF;
        let lo = b & 0xF;
        emit_one(out, hash, full_len, hex_upper(hi), max_len);
        emit_one(out, hash, full_len, hex_upper(lo), max_len);
    }
}

#[inline(always)]
fn is_printable_ascii(b: u8) -> bool {
    (0x20..=0x7e).contains(&b)
}

const HEX_UPPER: [u8; 16] = *b"0123456789ABCDEF";

#[inline(always)]
fn hex_upper(n: u8) -> u8 {
    debug_assert!(n < 16);
    HEX_UPPER[n as usize]
}

/// Replace the tail of `out` with the deterministic hash suffix `~#<16hex>`.
///
/// `out` is assumed to already contain a prefix of the display bytes (up to
/// `max_len` long). This function:
///
/// 1. Truncates `out` to `max_len - 18` bytes (room for `~#` + 16 hex digits).
/// 2. Backs up 1-2 bytes if the cut would split a `%HH` percent-escape.
/// 3. Appends the suffix.
///
/// Edge cases:
/// - `max_len == 0` => `out` is cleared (no room for anything).
/// - `max_len <= 18` => `out` is the suffix prefix alone (no display prefix).
pub(crate) fn apply_hash_suffix_truncation(out: &mut Vec<u8>, hash: u64, max_len: usize) {
    if max_len == 0 {
        out.clear();
        return;
    }

    // Build suffix.
    let mut suffix = [0u8; TRUNC_SUFFIX_LEN];
    suffix[0] = b'~';
    suffix[1] = b'#';
    util::write_u64_hex_lower(hash, &mut suffix[2..18]);

    if max_len <= TRUNC_SUFFIX_LEN {
        out.clear();
        out.extend_from_slice(&suffix[..max_len]);
        return;
    }

    let prefix_len = max_len - TRUNC_SUFFIX_LEN;
    if out.len() > prefix_len {
        out.truncate(prefix_len);
    }

    // Avoid splitting a percent-escape sequence at the truncation boundary.
    if out.ends_with(b"%") {
        out.truncate(out.len().saturating_sub(1));
    } else if out.len() >= 2 && out[out.len() - 2] == b'%' {
        out.truncate(out.len().saturating_sub(2));
    }

    out.extend_from_slice(&suffix);
    debug_assert!(out.len() <= max_len);
}

// Emit a literal `base` slice (no escaping) into `out`, applying hash-suffix
// truncation only when `base` exceeds `max_len`.  When `base` fits, the output
// is the full `base` unchanged -- the hash suffix is not appended because there
// is no information loss to compensate for.
fn emit_truncated_with_hash_suffix(out: &mut Vec<u8>, base: &[u8], hash: u64, max_len: usize) {
    out.clear();
    if max_len == 0 {
        return;
    }
    let take = base.len().min(max_len);
    out.extend_from_slice(&base[..take]);

    if base.len() <= max_len {
        return; // Base fits -- no truncation needed.
    }
    apply_hash_suffix_truncation(out, hash, max_len);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalize_escapes_non_printable_and_percent() {
        let mut c = EntryPathCanonicalizer::with_capacity(DEFAULT_MAX_COMPONENTS, 1024);
        // component: "ab%\x01"
        let r = c.canonicalize(b"ab%\x01", 256, 1024);
        assert_eq!(r.bytes, b"ab%25%01");
    }

    #[test]
    fn canonicalize_empty_becomes_placeholder() {
        let mut c = EntryPathCanonicalizer::with_capacity(DEFAULT_MAX_COMPONENTS, 1024);
        let r = c.canonicalize(b"/./", 256, 1024);
        assert_eq!(r.bytes, b"<empty>");
    }

    #[test]
    fn canonicalize_truncates_with_hash_suffix() {
        let mut c = EntryPathCanonicalizer::with_capacity(DEFAULT_MAX_COMPONENTS, 20);
        let raw = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let r = c.canonicalize(raw, 256, 20);
        assert_eq!(r.bytes.len(), 20);
        assert_eq!(&r.bytes[2..4], b"~#"); // prefix "aa" then "~#"
        assert!(r.truncated);
    }

    #[test]
    fn component_cap_exceeded_sets_flag_and_placeholder() {
        let mut c = EntryPathCanonicalizer::with_capacity(DEFAULT_MAX_COMPONENTS, 64);
        // 300 components "a/a/a/..."
        let mut raw = Vec::new();
        for i in 0..300 {
            if i != 0 {
                raw.push(b'/');
            }
            raw.push(b'a');
        }
        let r = c.canonicalize(&raw, 16, 64);
        assert!(r.component_cap_exceeded);
        assert!(r.bytes.starts_with(b"<component-cap-exceeded>") || r.bytes.starts_with(b"~#"));
    }

    #[test]
    fn virtual_path_builds_parent_entry() {
        let mut b = VirtualPathBuilder::with_capacity(1024);
        let v = b.build(b"/tmp/a.zip", b"a/b.txt", 1024);
        assert_eq!(v.bytes, b"/tmp/a.zip::a/b.txt");
        assert!(!v.truncated);
    }

    #[test]
    fn virtual_path_truncates() {
        let mut b = VirtualPathBuilder::with_capacity(16);
        let parent = b"/this/is/a/very/very/very/very/very/long/path";
        let entry = b"entry";
        let v = b.build(parent, entry, 16);
        assert_eq!(v.bytes.len(), 16);
        assert!(v.truncated);
    }

    #[test]
    fn virtual_path_appends_suffix_after_truncation() {
        let mut b = VirtualPathBuilder::with_capacity(20);
        let parent = b"/tmp/archive.tar";
        let entry = b"very-long-entry-name";
        let suffix = b"@t0000000000000001";
        let v = b.build_with_suffix(parent, entry, suffix, 20);
        assert!(v.bytes.ends_with(suffix));
        assert!(v.bytes.windows(2).any(|w| w == b"~#"));
    }

    #[test]
    fn canonicalize_clamps_to_output_capacity() {
        let mut c = EntryPathCanonicalizer::with_capacity(DEFAULT_MAX_COMPONENTS, 8);
        let raw = b"this/is/a/very/long/path";
        let r = c.canonicalize(raw, DEFAULT_MAX_COMPONENTS, 128);
        assert!(r.bytes.len() <= 8);
        assert!(r.truncated);
    }

    // ── Percent-escape boundary truncation ──────────────────────────────

    #[test]
    fn hash_suffix_trunc_cut_on_percent_removes_lone_percent() {
        // Build output where cut falls exactly on '%'.
        // TRUNC_SUFFIX_LEN = 18. With max_len=20, prefix_len=2.
        // If prefix is "X%", the '%' at the boundary should be removed.
        let mut out = b"X%".to_vec();
        let hash = 0x1234_5678_ABCD_EF00u64;
        apply_hash_suffix_truncation(&mut out, hash, 20);
        // The '%' should be removed: output = "X" + suffix (18 bytes) = 19 bytes.
        assert!(out.len() <= 20);
        assert!(!out[..out.len().saturating_sub(18)].ends_with(b"%"));
        assert!(out.windows(2).any(|w| w == b"~#"));
    }

    #[test]
    fn hash_suffix_trunc_cut_on_first_hex_removes_partial_escape() {
        // Prefix is "X%2" → "%2" should be removed (split escape).
        let mut out = b"X%2".to_vec();
        let hash = 0x1234_5678_ABCD_EF01u64;
        // max_len = 21 → prefix_len = 3. Out has 3 bytes, cut is at 3.
        // But out ends with "%2" (2-byte partial), which the backup should remove.
        apply_hash_suffix_truncation(&mut out, hash, 21);
        assert!(out.len() <= 21);
        // The "%2" should be removed from the prefix.
        let prefix_end = out.len().saturating_sub(18);
        let prefix = &out[..prefix_end];
        assert!(
            !prefix.ends_with(b"%2"),
            "partial escape '%2' should have been removed"
        );
    }

    #[test]
    fn hash_suffix_trunc_complete_escape_preserved() {
        // Prefix is "X%25" → complete escape, no backup needed.
        let mut out = b"X%25".to_vec();
        let hash = 0x1234_5678_ABCD_EF02u64;
        // max_len = 22 → prefix_len = 4. Out has 4 bytes, all good.
        apply_hash_suffix_truncation(&mut out, hash, 22);
        assert!(out.len() <= 22);
        let prefix_end = out.len().saturating_sub(18);
        let prefix = &out[..prefix_end];
        // Complete escape "%25" should be preserved (not backed up).
        assert_eq!(prefix, b"X%25");
    }

    #[test]
    fn hash_suffix_trunc_max_len_equals_suffix_len() {
        // max_len == TRUNC_SUFFIX_LEN (18) → output is just the suffix.
        let mut out = b"some long prefix data".to_vec();
        let hash = 0xAAAA_BBBB_CCCC_DDDDu64;
        apply_hash_suffix_truncation(&mut out, hash, TRUNC_SUFFIX_LEN);
        assert_eq!(out.len(), TRUNC_SUFFIX_LEN);
        assert!(out.starts_with(b"~#"));
    }

    #[test]
    fn hash_suffix_trunc_max_len_zero() {
        let mut out = b"some data".to_vec();
        apply_hash_suffix_truncation(&mut out, 0, 0);
        assert!(out.is_empty());
    }

    #[test]
    fn hash_suffix_trunc_max_len_less_than_suffix() {
        // max_len < TRUNC_SUFFIX_LEN → output is truncated suffix.
        let mut out = b"data".to_vec();
        let hash = 0x1111_2222_3333_4444u64;
        apply_hash_suffix_truncation(&mut out, hash, 5);
        assert_eq!(out.len(), 5);
        assert!(out.starts_with(b"~#"));
    }
}
