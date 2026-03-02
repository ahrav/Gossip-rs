//! Shared low-level utilities for archive format parsers.
//!
//! Five categories of helpers shared across format-specific scanners:
//!
//! - **FNV-1a hashing** — non-cryptographic 64-bit hash for path-truncation
//!   suffixes and zip entry deduplication.
//! - **Hex formatting** — allocation-free u64 → 16-hex-digit conversion.
//! - **I/O** — `read_exact_n`, a labeled variant of `Read::read_exact`.
//! - **Counted I/O** — `CountedRead`, a byte-counting `Read` wrapper for
//!   inflation ratio enforcement.
//! - **Budget mapping** — `BudgetHit` → `PartialReason` translation shared by
//!   every format-specific scanner.
//!
//! All functions here sit on hot paths (called per archive entry or per byte
//! chunk).  Centralizing them avoids silent divergence between copies and
//! ensures bug fixes propagate automatically.

use std::io::{self, Read};

// ── Counted I/O ─────────────────────────────────────────────────────────────

/// Read wrapper that counts bytes consumed from the underlying reader.
///
/// Used to drive best-effort inflation ratio enforcement via budgets.
///
/// # Guarantees
/// - `bytes()` is monotonic and saturating.
pub struct CountedRead<R> {
    inner: R,
    bytes: u64,
}

impl<R> CountedRead<R> {
    #[inline]
    pub fn new(inner: R) -> Self {
        Self { inner, bytes: 0 }
    }

    #[inline]
    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    #[inline]
    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read> Read for CountedRead<R> {
    #[inline]
    fn read(&mut self, dst: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(dst)?;
        self.bytes = self.bytes.saturating_add(n as u64);
        Ok(n)
    }
}

// ── FNV-1a (64-bit) ──────────────────────────────────────────────────────────
//
// Non-cryptographic hash used to distinguish truncated display paths and to
// fingerprint zip entry names for deduplication.  Collision resistance is
// **not** a security requirement — see `path.rs` module docs.
//
// Reference: <https://www.isthe.com/chongo/tech/comp/fnv/index.html>

/// Return the FNV-1a 64-bit offset basis (`0xcbf29ce484222325`).
///
/// Start a streaming hash by passing this value to [`fnv1a64_update`].
#[inline(always)]
pub(crate) fn fnv1a64_init() -> u64 {
    14_695_981_039_346_656_037u64
}

/// Fold one byte into an FNV-1a 64-bit hash state.
///
/// The algorithm is XOR-then-multiply: `h ^= byte; h *= FNV_PRIME`.
/// `wrapping_mul` is required because the 64-bit FNV prime
/// (`0x00000100000001B3`) overflows on most intermediate states.
#[inline(always)]
pub(crate) fn fnv1a64_update(mut h: u64, b: u8) -> u64 {
    h ^= b as u64;
    h = h.wrapping_mul(1_099_511_628_211u64);
    h
}

/// Hash a complete byte slice with FNV-1a 64.
///
/// Convenience wrapper over [`fnv1a64_init`] + [`fnv1a64_update`] for callers
/// that have the full input available up-front.  For streaming use (e.g.
/// building a hash byte-by-byte during path canonicalization), use the
/// init/update pair directly.
#[inline]
pub(crate) fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut h = fnv1a64_init();
    for &b in bytes {
        h = fnv1a64_update(h, b);
    }
    h
}

// ── Hex formatting ───────────────────────────────────────────────────────────

const HEX_LOWER: [u8; 16] = *b"0123456789abcdef";

/// Write `x` as exactly 16 lowercase hex digits into `out16`.
///
/// Produces the same output as `format!("{x:016x}")` but without allocating
/// or routing through `std::fmt`.  Used on hot paths (path truncation
/// suffixes, entry-tag generation) where a `String` allocation per entry is
/// unacceptable.
///
/// # Panics
///
/// Debug-asserts that `out16.len() == 16`.  In release builds the
/// debug-assert is elided, but a length shorter than 16 still panics
/// via Rust's bounds-checked indexing.
#[inline(always)]
pub(crate) fn write_u64_hex_lower(x: u64, out16: &mut [u8]) {
    debug_assert_eq!(out16.len(), 16);
    for i in 0..16 {
        out16[i] = HEX_LOWER[((x >> ((15 - i) * 4)) & 0xF) as usize];
    }
}

// ── I/O helpers ──────────────────────────────────────────────────────────────

/// Single `read()` call that retries on `EINTR`.  Returns 0 only at true EOF.
#[inline(always)]
fn read_some<R: Read + ?Sized>(r: &mut R, dst: &mut [u8]) -> io::Result<usize> {
    loop {
        match r.read(dst) {
            Ok(n) => return Ok(n),
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
}

/// Fill `dst` completely or return `Err(UnexpectedEof)`.
///
/// Behaves like [`Read::read_exact`] but produces a labeled error message
/// (e.g. `"tar truncated"`, `"zip truncated"`) so callers can distinguish
/// which format hit a short read without wrapping `read_exact` at every
/// call site.
///
/// # Errors
///
/// - [`io::ErrorKind::UnexpectedEof`] with message `"{label} truncated"`
///   if the stream ends before `dst` is filled.
/// - Any other [`io::Error`] propagated from the underlying reader.
pub(crate) fn read_exact_n<R: Read + ?Sized>(
    r: &mut R,
    dst: &mut [u8],
    label: &str,
) -> io::Result<()> {
    let mut off = 0;
    while off < dst.len() {
        let n = read_some(r, &mut dst[off..])?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("{label} truncated"),
            ));
        }
        off += n;
    }
    Ok(())
}

// ── Budget-hit mapping ───────────────────────────────────────────────────────

use crate::archive::budget::BudgetHit;
use crate::archive::outcome::{ArchiveSkipReason, PartialReason};

/// Map a [`BudgetHit`] to the [`PartialReason`] that should be recorded on
/// the current entry.
///
/// The mapping is **lossy**: `SkipArchive` variants that have no 1:1
/// `PartialReason` counterpart collapse to `format_fallback`, which the
/// caller sets to the format-specific malformed reason (e.g.
/// `PartialReason::MalformedTar`, `PartialReason::MalformedZip`).
///
/// `SkipEntry` is always promoted into an entry-level partial reason.
#[inline(always)]
pub(crate) fn budget_hit_to_partial(
    hit: BudgetHit,
    format_fallback: PartialReason,
) -> PartialReason {
    match hit {
        BudgetHit::PartialArchive(r) => r,
        BudgetHit::StopRoot(r) => r,
        BudgetHit::SkipArchive(r) => match r {
            ArchiveSkipReason::MetadataBudgetExceeded => PartialReason::MetadataBudgetExceeded,
            ArchiveSkipReason::PathBudgetExceeded => PartialReason::PathBudgetExceeded,
            ArchiveSkipReason::EntryCountExceeded => PartialReason::EntryCountExceeded,
            ArchiveSkipReason::ArchiveOutputBudgetExceeded => {
                PartialReason::ArchiveOutputBudgetExceeded
            }
            ArchiveSkipReason::RootOutputBudgetExceeded => PartialReason::RootOutputBudgetExceeded,
            ArchiveSkipReason::InflationRatioExceeded => PartialReason::InflationRatioExceeded,
            ArchiveSkipReason::UnsupportedFeature => PartialReason::UnsupportedFeature,
            ArchiveSkipReason::Disabled
            | ArchiveSkipReason::UnsupportedFormat
            | ArchiveSkipReason::EncryptedArchive
            | ArchiveSkipReason::DepthExceeded
            | ArchiveSkipReason::NeedsRandomAccessNoSpill
            | ArchiveSkipReason::IoError
            | ArchiveSkipReason::Corrupt => format_fallback,
        },
        BudgetHit::SkipEntry(r) => r.to_partial(),
    }
}
