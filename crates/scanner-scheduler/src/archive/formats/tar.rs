//! Streaming tar parser for bounded archive scanning.
//!
//! Provides [`TarCursor`], a zero-allocation (after startup) state machine that
//! walks a tar byte stream one 512-byte header block at a time. The cursor
//! handles GNU longname and PAX extended-header records internally, yielding
//! resolved [`TarEntryMeta`] for every non-metadata entry. Callers decide which
//! entries to scan (typically regular files via [`TarEntryMeta::is_regular`])
//! and are responsible for consuming or skipping payload bytes.
//!
//! # Invariants
//! - Parsing is sequential; no seeks are performed.
//! - Size fields are untrusted; overflow or short reads are treated as malformed.
//! - Metadata bytes are charged to [`ArchiveBudgets::charge_metadata`].
//! - Internal buffers are allocated once at construction and never grow;
//!   `debug_assert_no_growth()` enforces this in debug builds.
//!
//! # Algorithm
//! 1. Read a 512-byte header block (charge metadata budget first).
//! 2. Detect end-of-archive via two consecutive zero blocks.
//! 3. For GNU longname (`L`) or PAX (`x`/`g`) records, consume their payloads
//!    into bounded internal buffers and loop back to step 1.
//! 4. For all other typeflags, apply any pending name overrides (PAX > GNU >
//!    header) and yield the entry. Overrides are consumed on use.
//!
//! # Design Notes
//! - This is a scanner-oriented parser, not a general extraction library.
//! - Global PAX `path` is parsed but intentionally not applied; doing so would
//!   misattribute entries in multi-file archives.
//! - All I/O goes through [`TarRead`] so callers can supply plain files,
//!   gzip-decoded streams, or in-memory cursors uniformly.

use crate::archive::formats::{Bzip2Stream, GzipStream};
use crate::archive::util;
use crate::archive::{ArchiveBudgets, ArchiveConfig, ChargeResult, PartialReason};

use std::fs::File;
use std::io::{self, Read};
use std::sync::Arc;

/// Size of a single tar header/data block in bytes (per POSIX.1-2001).
pub const TAR_BLOCK_LEN: usize = 512;

/// Byte offset of the `"ustar"` magic within a tar header block.
pub const USTAR_MAGIC_OFFSET: usize = 257;

/// Returns `true` if `header` is at least [`TAR_BLOCK_LEN`] bytes and
/// contains the `"ustar"` magic at [`USTAR_MAGIC_OFFSET`].
///
/// This is a quick probe used by format detection to decide whether a buffer
/// looks like a tar header before committing to a full parse.
#[inline(always)]
pub fn is_ustar_header(header: &[u8]) -> bool {
    header.len() >= TAR_BLOCK_LEN && &header[USTAR_MAGIC_OFFSET..USTAR_MAGIC_OFFSET + 5] == b"ustar"
}

/// Input source for tar scanning: plain tar file, gzip-decoded tar stream,
/// or bzip2-decoded tar stream.
///
/// # Design Notes
/// - Used by the scheduler to distinguish compressed input for ratio accounting.
#[allow(clippy::large_enum_variant)]
pub enum TarInput {
    Plain(File),
    Gzip(GzipStream<File>),
    Bzip2(Bzip2Stream<std::io::BufReader<File>>),
}

impl TarInput {
    /// Compressed-byte delta since the previous call.
    ///
    /// Returns `0` for plain tar so callers can charge budgets through one
    /// uniform interface regardless of wrapping codec.
    #[inline(always)]
    pub fn take_compressed_delta(&mut self) -> u64 {
        match self {
            TarInput::Plain(_) => 0,
            TarInput::Gzip(gz) => gz.take_compressed_delta(),
            TarInput::Bzip2(bz2) => bz2.take_compressed_delta(),
        }
    }
}

impl Read for TarInput {
    #[inline]
    fn read(&mut self, dst: &mut [u8]) -> io::Result<usize> {
        match self {
            TarInput::Plain(f) => read_some(f, dst),
            TarInput::Gzip(gz) => gz.read(dst),
            TarInput::Bzip2(bz2) => bz2.read(dst),
        }
    }
}

/// Reader trait for tar parsing that can optionally report compressed input deltas.
///
/// # Guarantees
/// - `take_compressed_delta()` returns the number of compressed bytes consumed
///   since the last call (or 0 for uncompressed sources).
pub trait TarRead: Read {
    #[inline(always)]
    fn take_compressed_delta(&mut self) -> u64 {
        0
    }
}

impl TarRead for TarInput {
    #[inline(always)]
    fn take_compressed_delta(&mut self) -> u64 {
        TarInput::take_compressed_delta(self)
    }
}

impl TarRead for File {}

impl<R: Read> TarRead for GzipStream<R> {
    #[inline(always)]
    fn take_compressed_delta(&mut self) -> u64 {
        self.take_compressed_delta()
    }
}

impl<R: Read> TarRead for Bzip2Stream<R> {
    #[inline(always)]
    fn take_compressed_delta(&mut self) -> u64 {
        self.take_compressed_delta()
    }
}

impl<T: TarRead + ?Sized> TarRead for &mut T {
    #[inline(always)]
    fn take_compressed_delta(&mut self) -> u64 {
        (**self).take_compressed_delta()
    }
}

impl TarRead for std::io::Cursor<Vec<u8>> {}

impl TarRead for std::io::Cursor<Arc<[u8]>> {}

/// A parsed tar entry header with GNU/PAX name overrides already applied.
///
/// Returned by [`TarCursor::next_entry`]. The caller must consume (or skip)
/// `size` payload bytes plus `pad` alignment bytes before calling
/// `next_entry` again; failing to do so breaks block alignment.
pub struct TarEntryMeta<'a> {
    /// Entry name after applying PAX `path=` or GNU longname overrides.
    /// Raw bytes, not canonicalized or validated as UTF-8.
    pub name: &'a [u8],
    /// Payload size in bytes (from the octal size field).
    pub size: u64,
    /// Padding bytes after the payload to reach the next block boundary.
    /// Always `0` when `size` is block-aligned.
    pub pad: u64,
    /// POSIX typeflag byte: `b'0'` or `0` for regular files, `b'5'` for dirs, etc.
    pub typeflag: u8,
    /// Zero-based index of this entry's header block in the stream.
    /// Useful for diagnostics and offset computation (`index * 512`).
    pub header_block_index: u64,
}

impl<'a> TarEntryMeta<'a> {
    #[inline(always)]
    pub fn is_regular(&self) -> bool {
        self.typeflag == 0 || self.typeflag == b'0'
    }
}

/// Result of a single [`TarCursor::next_entry`] call.
pub enum TarNext<'a> {
    /// End-of-archive: two consecutive zero blocks or clean EOF at a header boundary.
    End,
    /// A non-metadata entry was found. The caller must consume or skip its
    /// payload (`size` + `pad` bytes) before the next call.
    Entry(TarEntryMeta<'a>),
    /// A budget limit was hit; scanning should stop. The contained
    /// [`PartialReason`] describes which budget was exhausted.
    Stop(PartialReason),
}

/// Stateful tar header/metadata parser.
///
/// # Invariants
/// - Callers must consume or skip payload bytes to keep alignment.
/// - GNU/PAX overrides apply to the next non-metadata entry only.
///
/// This does not scan payloads; it only yields entry metadata and consumes
/// metadata-only records (GNU longname, PAX headers), charging metadata budgets.
pub struct TarCursor {
    hdr: [u8; TAR_BLOCK_LEN],
    zero_blocks: u8,
    block_index: u64,

    // Per-file overrides (apply to next real entry only).
    gnu_longname: Vec<u8>,
    pax_path: Vec<u8>,

    // Global pax data (we parse but do NOT apply `path=` globally; doing so can
    // misattribute multi-entry archives. Kept only to consume safely).
    pax_global_saw_path: bool,

    // Current computed name for yielded entry.
    name_buf: Vec<u8>,

    // Scratch for skipping/reading.
    discard: [u8; 8192],
    pax_carry: Vec<u8>,
    /// Read cursor into `pax_carry` to avoid `drain()` (O(n^2)) when parsing
    /// many small PAX records. We compact the buffer in-place when the cursor
    /// grows large or the buffer is full.
    pax_carry_pos: usize,

    // Debug-only capacity guards.
    #[cfg(debug_assertions)]
    gnu_cap: usize,
    #[cfg(debug_assertions)]
    pax_cap: usize,
    #[cfg(debug_assertions)]
    name_cap: usize,
    #[cfg(debug_assertions)]
    carry_cap: usize,
}

impl TarCursor {
    /// Construct a cursor with preallocated buffers sized from `ArchiveConfig`.
    ///
    /// All buffers are allocated once here and reused via `reset()` to avoid
    /// runtime allocations while scanning.
    pub fn with_capacity(cfg: &ArchiveConfig) -> Self {
        let path_cap = cfg
            .max_virtual_path_len_per_entry
            .saturating_add(1)
            .min(16 * 1024);
        let carry_cap = 4096;
        Self {
            hdr: [0; TAR_BLOCK_LEN],
            zero_blocks: 0,
            block_index: 0,
            gnu_longname: Vec::with_capacity(path_cap),
            pax_path: Vec::with_capacity(path_cap),
            pax_global_saw_path: false,
            name_buf: Vec::with_capacity(path_cap),
            discard: [0; 8192],
            pax_carry: Vec::with_capacity(carry_cap),
            pax_carry_pos: 0,

            #[cfg(debug_assertions)]
            gnu_cap: path_cap,
            #[cfg(debug_assertions)]
            pax_cap: path_cap,
            #[cfg(debug_assertions)]
            name_cap: path_cap,
            #[cfg(debug_assertions)]
            carry_cap,
        }
    }

    /// Reset cursor state for reuse without allocating.
    #[inline]
    pub fn reset(&mut self) {
        self.zero_blocks = 0;
        self.block_index = 0;
        self.gnu_longname.clear();
        self.pax_path.clear();
        self.pax_global_saw_path = false;
        self.name_buf.clear();
        self.pax_carry.clear();
        self.pax_carry_pos = 0;
        self.debug_assert_no_growth();
    }

    /// Debug-only guard: ensure internal buffers never grow after startup.
    #[inline]
    pub fn debug_assert_no_growth(&self) {
        #[cfg(debug_assertions)]
        {
            debug_assert_eq!(
                self.gnu_longname.capacity(),
                self.gnu_cap,
                "gnu_longname grew after startup"
            );
            debug_assert_eq!(
                self.pax_path.capacity(),
                self.pax_cap,
                "pax_path grew after startup"
            );
            debug_assert_eq!(
                self.name_buf.capacity(),
                self.name_cap,
                "name_buf grew after startup"
            );
            debug_assert_eq!(
                self.pax_carry.capacity(),
                self.carry_cap,
                "pax_carry grew after startup"
            );
        }
    }

    /// Read and parse until a non-meta entry is found, or end, or deterministic stop.
    ///
    /// This consumes only header/metadata records. For regular entries, the
    /// caller must read (or skip) the payload and then advance alignment via
    /// `advance_entry_blocks` or the helper skip methods.
    pub fn next_entry<'a, R: TarRead + ?Sized>(
        &'a mut self,
        input: &mut R,
        budgets: &mut ArchiveBudgets,
        cfg: &ArchiveConfig,
    ) -> io::Result<TarNext<'a>> {
        self.debug_assert_no_growth();
        loop {
            // Charge 1 header block before we read it (prevents overshoot).
            if let ChargeResult::Clamp { hit, .. } = budgets.charge_metadata(TAR_BLOCK_LEN as u64) {
                return Ok(TarNext::Stop(util::budget_hit_to_partial(
                    hit,
                    PartialReason::MalformedTar,
                )));
            }

            // Read header block.
            if !read_exact_or_eof(input, &mut self.hdr)? {
                // Clean EOF at header boundary.
                return Ok(TarNext::End);
            }
            budgets.charge_compressed_in(input.take_compressed_delta());

            let header_block_index = self.block_index;
            self.block_index = self.block_index.saturating_add(1);

            if is_zero_block(&self.hdr) {
                self.zero_blocks = self.zero_blocks.saturating_add(1);
                if self.zero_blocks >= 2 {
                    return Ok(TarNext::End);
                }
                continue;
            }
            self.zero_blocks = 0;

            // Count this record.
            if let Err(hit) = budgets.note_entry() {
                return Ok(TarNext::Stop(util::budget_hit_to_partial(
                    hit,
                    PartialReason::MalformedTar,
                )));
            }

            let typeflag = self.hdr[156];
            let size = match parse_tar_size_octal(&self.hdr[124..136]) {
                Some(s) => s,
                None => return Ok(TarNext::Stop(PartialReason::MalformedTar)),
            };
            let pad = tar_pad(size);

            // GNU longname record.
            if typeflag == b'L' {
                self.gnu_longname.clear();
                if let Err(stop) = self.read_gnu_longname(input, budgets, cfg, size, pad)? {
                    return Ok(TarNext::Stop(stop));
                }
                self.advance_entry_blocks(size, pad);
                continue;
            }

            // PAX headers.
            if typeflag == b'x' {
                self.pax_path.clear();
                if let Err(stop) =
                    self.read_pax_path(input, budgets, cfg, size, pad, PaxTarget::PerFile)?
                {
                    return Ok(TarNext::Stop(stop));
                }
                self.advance_entry_blocks(size, pad);
                continue;
            }
            if typeflag == b'g' {
                self.pax_global_saw_path = false;
                if let Err(stop) =
                    self.read_pax_path(input, budgets, cfg, size, pad, PaxTarget::Global)?
                {
                    return Ok(TarNext::Stop(stop));
                }
                self.advance_entry_blocks(size, pad);
                continue;
            }

            // Compute base name from header, then apply overrides (per-file only).
            self.name_buf.clear();
            let max_name = cfg
                .max_virtual_path_len_per_entry
                .min(self.name_buf.capacity());
            build_ustar_name(&self.hdr, &mut self.name_buf, max_name);

            if !self.pax_path.is_empty() {
                self.name_buf.clear();
                self.name_buf.extend_from_slice(&self.pax_path);
            } else if !self.gnu_longname.is_empty() {
                self.name_buf.clear();
                self.name_buf.extend_from_slice(&self.gnu_longname);
            }

            // Overrides apply to exactly one real entry.
            self.pax_path.clear();
            self.gnu_longname.clear();

            return Ok(TarNext::Entry(TarEntryMeta {
                name: &self.name_buf,
                size,
                pad,
                typeflag,
                header_block_index,
            }));
        }
    }

    /// Skip non-regular entry payload and padding as metadata-bounded work.
    pub fn skip_payload_and_pad<R: TarRead + ?Sized>(
        &mut self,
        input: &mut R,
        budgets: &mut ArchiveBudgets,
        size: u64,
        pad: u64,
    ) -> io::Result<Result<(), PartialReason>> {
        // Treat skipped payload as metadata work to keep bounded.
        if let Err(stop) = self.skip_bytes_as_metadata(input, budgets, size)? {
            return Ok(Err(stop));
        }
        if let Err(stop) = self.skip_bytes_as_metadata(input, budgets, pad)? {
            return Ok(Err(stop));
        }
        self.advance_entry_blocks(size, pad);
        Ok(Ok(()))
    }

    /// Advance the internal block counter after the caller has consumed an
    /// entry's payload (`size`) and alignment padding (`pad`).
    ///
    /// `size + pad` must be block-aligned (debug-asserted).
    #[inline]
    pub fn advance_entry_blocks(&mut self, size: u64, pad: u64) {
        let total = size.saturating_add(pad);
        debug_assert_eq!(total % TAR_BLOCK_LEN as u64, 0);
        self.block_index = self
            .block_index
            .saturating_add(total / TAR_BLOCK_LEN as u64);
    }

    /// Skip padding bytes after a payload read, charging metadata budget.
    pub fn skip_padding_only<R: TarRead + ?Sized>(
        &mut self,
        input: &mut R,
        budgets: &mut ArchiveBudgets,
        pad: u64,
    ) -> io::Result<Result<(), PartialReason>> {
        if let Err(stop) = self.skip_bytes_as_metadata(input, budgets, pad)? {
            return Ok(Err(stop));
        }
        Ok(Ok(()))
    }

    fn skip_bytes_as_metadata<R: TarRead + ?Sized>(
        &mut self,
        input: &mut R,
        budgets: &mut ArchiveBudgets,
        mut n: u64,
    ) -> io::Result<Result<(), PartialReason>> {
        while n > 0 {
            let step = (self.discard.len() as u64).min(n) as usize;

            if let ChargeResult::Clamp { allowed, hit } = budgets.charge_metadata(step as u64) {
                let allowed_usize = allowed as usize;
                if allowed_usize == 0 {
                    return Ok(Err(util::budget_hit_to_partial(
                        hit,
                        PartialReason::MalformedTar,
                    )));
                }
                util::read_exact_n(input, &mut self.discard[..allowed_usize], "tar")?;
                budgets.charge_compressed_in(input.take_compressed_delta());
                return Ok(Err(util::budget_hit_to_partial(
                    hit,
                    PartialReason::MalformedTar,
                )));
            }

            util::read_exact_n(input, &mut self.discard[..step], "tar")?;
            budgets.charge_compressed_in(input.take_compressed_delta());
            n -= step as u64;
        }
        Ok(Ok(()))
    }

    fn read_gnu_longname<R: TarRead + ?Sized>(
        &mut self,
        input: &mut R,
        budgets: &mut ArchiveBudgets,
        cfg: &ArchiveConfig,
        size: u64,
        pad: u64,
    ) -> io::Result<Result<(), PartialReason>> {
        // Read payload as metadata, store up to a bounded prefix.
        let cap = cfg
            .max_virtual_path_len_per_entry
            .saturating_add(1)
            .min(16 * 1024)
            .min(self.gnu_longname.capacity());
        let mut remaining = size;
        while remaining > 0 {
            let step = (self.discard.len() as u64).min(remaining) as usize;

            if let ChargeResult::Clamp { allowed, hit } = budgets.charge_metadata(step as u64) {
                let a = allowed as usize;
                if a == 0 {
                    return Ok(Err(util::budget_hit_to_partial(
                        hit,
                        PartialReason::MalformedTar,
                    )));
                }
                util::read_exact_n(input, &mut self.discard[..a], "tar")?;
                budgets.charge_compressed_in(input.take_compressed_delta());
                append_longname_bytes(&mut self.gnu_longname, &self.discard[..a], cap);
                return Ok(Err(util::budget_hit_to_partial(
                    hit,
                    PartialReason::MalformedTar,
                )));
            }

            util::read_exact_n(input, &mut self.discard[..step], "tar")?;
            budgets.charge_compressed_in(input.take_compressed_delta());
            append_longname_bytes(&mut self.gnu_longname, &self.discard[..step], cap);
            remaining -= step as u64;
        }

        // Trim trailing NUL/newlines.
        while let Some(&b) = self.gnu_longname.last() {
            if b == 0 || b == b'\n' {
                self.gnu_longname.pop();
            } else {
                break;
            }
        }

        // Skip pad.
        match self.skip_bytes_as_metadata(input, budgets, pad)? {
            Ok(()) => Ok(Ok(())),
            Err(stop) => Ok(Err(stop)),
        }
    }

    fn read_pax_path<R: TarRead + ?Sized>(
        &mut self,
        input: &mut R,
        budgets: &mut ArchiveBudgets,
        cfg: &ArchiveConfig,
        size: u64,
        pad: u64,
        target: PaxTarget,
    ) -> io::Result<Result<(), PartialReason>> {
        // Parse records with a bounded carry buffer; store only `path=` value prefix.
        self.pax_carry.clear();
        self.pax_carry_pos = 0;
        let mut remaining = size;

        // Value storage cap.
        let cap = cfg
            .max_virtual_path_len_per_entry
            .saturating_add(1)
            .min(32 * 1024)
            .min(self.pax_path.capacity());

        while remaining > 0 {
            let step = (self.discard.len() as u64).min(remaining) as usize;

            if let ChargeResult::Clamp { allowed, hit } = budgets.charge_metadata(step as u64) {
                let a = allowed as usize;
                if a == 0 {
                    return Ok(Err(util::budget_hit_to_partial(
                        hit,
                        PartialReason::MalformedTar,
                    )));
                }
                util::read_exact_n(input, &mut self.discard[..a], "tar")?;
                budgets.charge_compressed_in(input.take_compressed_delta());
                consume_pax_bytes(
                    &mut self.pax_carry,
                    &mut self.pax_carry_pos,
                    &mut self.pax_path,
                    &mut self.pax_global_saw_path,
                    &self.discard[..a],
                    target,
                    cap,
                );
                return Ok(Err(util::budget_hit_to_partial(
                    hit,
                    PartialReason::MalformedTar,
                )));
            }

            util::read_exact_n(input, &mut self.discard[..step], "tar")?;
            budgets.charge_compressed_in(input.take_compressed_delta());
            consume_pax_bytes(
                &mut self.pax_carry,
                &mut self.pax_carry_pos,
                &mut self.pax_path,
                &mut self.pax_global_saw_path,
                &self.discard[..step],
                target,
                cap,
            );

            remaining -= step as u64;
        }

        // Skip pad.
        match self.skip_bytes_as_metadata(input, budgets, pad)? {
            Ok(()) => Ok(Ok(())),
            Err(stop) => Ok(Err(stop)),
        }
    }
}

/// Discriminates per-file PAX headers (`x`) from global ones (`g`).
///
/// Per-file headers populate `pax_path`; global headers only set a flag
/// (the global `path` is intentionally not applied to entries).
#[derive(Clone, Copy)]
enum PaxTarget {
    PerFile,
    Global,
}

/// Padding bytes needed after `size` payload bytes to reach the next 512-byte
/// block boundary. Returns 0 when `size` is already block-aligned.
#[inline(always)]
fn tar_pad(size: u64) -> u64 {
    let rem = size % TAR_BLOCK_LEN as u64;
    if rem == 0 {
        0
    } else {
        TAR_BLOCK_LEN as u64 - rem
    }
}

/// Check whether a 512-byte tar block is entirely zeroed.
///
/// Uses word-wide (`u64`) unaligned reads with early exit on the first
/// non-zero 64-byte group. This is faster than `iter().all(|&b| b == 0)`
/// because it processes 8 bytes per load and can bail out early.
///
/// # Safety invariant
///
/// All pointer offsets stay within the `[u8; TAR_BLOCK_LEN]` array:
/// `TAR_BLOCK_LEN` (512) is divisible by 64 (outer stride) and by 8
/// (`size_of::<u64>()`), so `i + j ≤ 504 < 512` for all iterations.
/// This is formally verified by the Kani proof `verify_is_zero_block_bounds`.
#[inline(always)]
fn is_zero_block(b: &[u8; TAR_BLOCK_LEN]) -> bool {
    let ptr = b.as_ptr();
    let mut i = 0usize;
    while i < TAR_BLOCK_LEN {
        let mut acc: u64 = 0;
        let mut j = 0;
        while j < 64 && i + j < TAR_BLOCK_LEN {
            // SAFETY: `i + j` is always in `[0, 504]` (outer stride 64, inner stride 8,
            // total 512), so `ptr.add(i + j)` plus an 8-byte read stays within the
            // 512-byte array. Formally verified by `kani_proofs::verify_is_zero_block_bounds`.
            acc |= unsafe { ptr.add(i + j).cast::<u64>().read_unaligned() };
            j += 8;
        }
        if acc != 0 {
            return false;
        }
        i += 64;
    }
    true
}

/// Reconstruct the entry name from a ustar header's `prefix` (bytes 345–500)
/// and `name` (bytes 0–100) fields, joining with `/` when both are present.
///
/// Output is truncated to `max_len` bytes. Non-ustar headers use `name` only.
fn build_ustar_name(hdr: &[u8; TAR_BLOCK_LEN], out: &mut Vec<u8>, max_len: usize) {
    out.clear();
    if max_len == 0 {
        return;
    }

    let name = cstr_bytes(&hdr[0..100]);
    let prefix = cstr_bytes(&hdr[345..500]);

    let is_ustar = &hdr[USTAR_MAGIC_OFFSET..USTAR_MAGIC_OFFSET + 5] == b"ustar";
    let mut remaining = max_len;

    if is_ustar && !prefix.is_empty() {
        append_clamped(out, prefix, &mut remaining);
        if remaining > 0 && !out.ends_with(b"/") {
            out.push(b'/');
            remaining = remaining.saturating_sub(1);
        }
    }
    append_clamped(out, name, &mut remaining);
}

#[inline]
fn append_clamped(out: &mut Vec<u8>, bytes: &[u8], remaining: &mut usize) {
    if *remaining == 0 {
        return;
    }
    let take = bytes.len().min(*remaining);
    out.extend_from_slice(&bytes[..take]);
    *remaining = remaining.saturating_sub(take);
}

/// Return the slice up to (but not including) the first NUL, or the entire
/// slice if no NUL is present. Mimics C `strlen` semantics on a fixed field.
fn cstr_bytes(field: &[u8]) -> &[u8] {
    match memchr_byte(0, field) {
        Some(i) => &field[..i],
        None => field,
    }
}

/// Parse a tar size field as NUL/space-padded ASCII octal.
///
/// Returns `Some(0)` for an empty or all-whitespace field. Returns `None`
/// when the accumulated value overflows `u64`, rejecting malformed entries
/// rather than silently wrapping.
fn parse_tar_size_octal(field: &[u8]) -> Option<u64> {
    // tar size field is NUL/space padded octal.
    let mut i = 0;
    while i < field.len() && (field[i] == 0 || field[i] == b' ') {
        i += 1;
    }
    let mut end = i;
    while end < field.len() && (b'0'..=b'7').contains(&field[end]) {
        end += 1;
    }
    if end == i {
        return Some(0);
    }
    // 21 octal digits ≤ 63 bits (8^21 − 1 = 2^63 − 1), which fits in u64.
    // Reject anything longer up-front so the loop can use wrapping arithmetic
    // without overflow risk.  Standard tar fields are 12 bytes, so this guard
    // only fires on pathologically crafted inputs.
    if end - i > 21 {
        return None;
    }
    let mut v: u64 = 0;
    for &d in &field[i..end] {
        v = v.wrapping_mul(8).wrapping_add((d - b'0') as u64);
    }
    Some(v)
}

fn memchr_byte(needle: u8, hay: &[u8]) -> Option<usize> {
    // small, dependency-free
    for (i, &b) in hay.iter().enumerate() {
        if b == needle {
            return Some(i);
        }
    }
    None
}

/// Append bytes to `longname` without exceeding `cap`, silently truncating.
fn append_longname_bytes(longname: &mut Vec<u8>, bytes: &[u8], cap: usize) {
    if longname.len() >= cap {
        return;
    }
    let take = (cap - longname.len()).min(bytes.len());
    longname.extend_from_slice(&bytes[..take]);
}

/// Incrementally parse PAX extended-header records from a chunked byte stream,
/// extracting only the `path=` value.
///
/// # Algorithm
/// PAX records are self-framing: `"<len> <key>=<value>\n"` where `<len>`
/// includes the length digits, space, and trailing newline. Because input
/// arrives in arbitrary chunks, we maintain a carry buffer (`pax_carry`) with
/// a read cursor (`pax_carry_pos`) to reassemble records that straddle chunk
/// boundaries.
///
/// On each call we append new bytes (up to the fixed carry capacity), then
/// drain complete records from the cursor position. If a record length field
/// is malformed or exceeds the carry buffer, we mark the remainder as
/// consumed to avoid re-parsing the same corrupt bytes.
///
/// The carry buffer is compacted (shifted left) when the cursor passes the
/// halfway mark or the buffer is full, keeping steady-state memory O(1).
///
/// # Bounds
/// - `pax_carry` never grows beyond its startup capacity.
/// - `pax_path` is capped at `cap` bytes.
fn consume_pax_bytes(
    pax_carry: &mut Vec<u8>,
    pax_carry_pos: &mut usize,
    pax_path: &mut Vec<u8>,
    pax_global_saw_path: &mut bool,
    bytes: &[u8],
    target: PaxTarget,
    cap: usize,
) {
    // Append at most the fixed carry capacity; never grow after startup.
    let cap_bytes = pax_carry.capacity();
    if pax_carry.len() < cap_bytes {
        let take = (cap_bytes - pax_carry.len()).min(bytes.len());
        pax_carry.extend_from_slice(&bytes[..take]);
    }

    let mut malformed = false;

    loop {
        let start = *pax_carry_pos;
        if start >= pax_carry.len() {
            break;
        }

        let space = match memchr_byte_from(b' ', pax_carry, start) {
            Some(i) => i,
            None => break,
        };
        if space == start {
            malformed = true;
            break;
        }

        let mut rec_len: usize = 0;
        for &d in &pax_carry[start..space] {
            if !d.is_ascii_digit() {
                malformed = true;
                break;
            }
            rec_len = rec_len
                .saturating_mul(10)
                .saturating_add((d - b'0') as usize);
        }
        if malformed {
            break;
        }
        if rec_len == 0 {
            malformed = true;
            break;
        }
        if rec_len > cap_bytes {
            // Record is larger than our bounded carry buffer; drop parsing.
            malformed = true;
            break;
        }

        let rec_end = start.saturating_add(rec_len);
        if rec_end <= space || rec_end > pax_carry.len() {
            // Need more bytes, or malformed length that doesn't cover its own prefix.
            if rec_end <= space {
                malformed = true;
            }
            break;
        }

        let rec = &pax_carry[space + 1..rec_end];
        if let Some(eq) = memchr_byte(b'=', rec) {
            let key = &rec[..eq];
            let mut val = &rec[eq + 1..];
            if val.last() == Some(&b'\n') {
                val = &val[..val.len() - 1];
            }
            if key == b"path" {
                match target {
                    PaxTarget::PerFile => {
                        if pax_path.len() < cap {
                            let take = (cap - pax_path.len()).min(val.len());
                            pax_path.extend_from_slice(&val[..take]);
                        }
                    }
                    PaxTarget::Global => {
                        *pax_global_saw_path = true;
                    }
                }
            }
        }

        *pax_carry_pos = rec_end;
    }

    // On malformed input, drop carry to avoid spinning on the same bytes.
    if malformed {
        *pax_carry_pos = pax_carry.len();
    }

    // Compact buffer when the cursor advances enough or the buffer is full.
    if *pax_carry_pos > 0 {
        if *pax_carry_pos >= pax_carry.len() {
            pax_carry.clear();
            *pax_carry_pos = 0;
        } else if *pax_carry_pos >= (cap_bytes / 2) || pax_carry.len() == cap_bytes {
            let len = pax_carry.len();
            pax_carry.copy_within(*pax_carry_pos..len, 0);
            pax_carry.truncate(len - *pax_carry_pos);
            *pax_carry_pos = 0;
        }
    }
}

fn memchr_byte_from(needle: u8, hay: &[u8], start: usize) -> Option<usize> {
    if start >= hay.len() {
        return None;
    }
    for (i, &b) in hay[start..].iter().enumerate() {
        if b == needle {
            return Some(start + i);
        }
    }
    None
}

/// Single `read()` call that retries on `EINTR`. Returns 0 only at true EOF.
fn read_some<R: Read + ?Sized>(r: &mut R, dst: &mut [u8]) -> io::Result<usize> {
    loop {
        match r.read(dst) {
            Ok(n) => return Ok(n),
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
}

/// Fill `dst` completely, returning `Ok(true)`, or detect clean EOF.
///
/// Returns `Ok(false)` if EOF is reached before any bytes are read (clean
/// boundary). Returns `Err(UnexpectedEof)` if EOF occurs mid-read —
/// indicating a truncated header or payload.
fn read_exact_or_eof<R: Read + ?Sized>(r: &mut R, dst: &mut [u8]) -> io::Result<bool> {
    let mut off = 0;
    while off < dst.len() {
        let n = read_some(r, &mut dst[off..])?;
        if n == 0 {
            // EOF before full block: clean EOF only if nothing was read.
            if off == 0 {
                return Ok(false);
            }
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "tar truncated header",
            ));
        }
        off += n;
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::{ArchiveBudgets, ArchiveConfig};
    use std::io;

    fn tar_write_header(buf: &mut [u8; TAR_BLOCK_LEN], name: &str, size: u64, typeflag: u8) {
        buf.fill(0);
        let name_bytes = name.as_bytes();
        let name_len = name_bytes.len().min(100);
        buf[0..name_len].copy_from_slice(&name_bytes[..name_len]);
        buf[100..108].copy_from_slice(b"0000777\0");
        buf[108..116].copy_from_slice(b"0000000\0");
        buf[116..124].copy_from_slice(b"0000000\0");
        let mut size_field = [b'0'; 11];
        let mut v = size;
        for i in (0..11).rev() {
            size_field[i] = b'0' + ((v & 7) as u8);
            v >>= 3;
        }
        buf[124..135].copy_from_slice(&size_field);
        buf[135] = 0;
        buf[136..148].copy_from_slice(b"00000000000\0");
        for b in &mut buf[148..156] {
            *b = b' ';
        }
        buf[156] = typeflag;
        buf[257..263].copy_from_slice(b"ustar\0");
        buf[263..265].copy_from_slice(b"00");
        let sum: u32 = buf.iter().map(|&b| b as u32).sum();
        let chk = format!("{:06o}\0 ", sum);
        buf[148..156].copy_from_slice(chk.as_bytes());
    }

    #[test]
    fn parse_octal_size() {
        assert_eq!(parse_tar_size_octal(b"0000000010\0"), Some(8));
        assert_eq!(parse_tar_size_octal(b"        \0"), Some(0));
    }

    #[test]
    fn parse_octal_rejects_overflow() {
        // 21 octal sevens = 8^21 − 1 = 2^63 − 1: max safe digit count.
        let max_safe = b"777777777777777777777";
        assert_eq!(
            parse_tar_size_octal(max_safe),
            Some((1u64 << 63) - 1),
            "21 octal digits must be accepted",
        );

        // 22 octal digits can overflow u64 → must be rejected.
        let overflow_input = b"7777777777777777777777";
        assert_eq!(
            parse_tar_size_octal(overflow_input),
            None,
            "22+ octal digits must be rejected",
        );
    }

    #[test]
    fn pad_math() {
        assert_eq!(tar_pad(0), 0);
        assert_eq!(tar_pad(1), 511);
        assert_eq!(tar_pad(512), 0);
        assert_eq!(tar_pad(513), 511);
    }

    #[test]
    fn truncated_header_returns_error() {
        let cfg = ArchiveConfig::default();
        let mut budgets = ArchiveBudgets::new(&cfg);
        budgets.enter_archive().unwrap();

        let mut cursor = TarCursor::with_capacity(&cfg);
        let mut input = io::Cursor::new(vec![0u8; 10]); // shorter than a header block

        match cursor.next_entry(&mut input, &mut budgets, &cfg) {
            Err(err) => assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof),
            Ok(_) => panic!("expected truncated header error"),
        }
    }

    #[test]
    fn pax_parser_handles_invalid_length_without_panicking() {
        let mut carry = Vec::with_capacity(64);
        let mut pos = 0usize;
        let mut path = Vec::new();
        let mut saw_global = false;

        // Length says 1 byte, but record is longer (malformed).
        consume_pax_bytes(
            &mut carry,
            &mut pos,
            &mut path,
            &mut saw_global,
            b"1 path=evil\n",
            PaxTarget::PerFile,
            64,
        );

        assert!(pos <= carry.len());
        assert!(carry.len() <= carry.capacity());
        assert!(path.is_empty());
        assert!(!saw_global);
    }

    #[test]
    fn pax_parser_extracts_path_across_chunks() {
        fn build_record(key: &str, val: &str) -> Vec<u8> {
            let body = format!("{key}={val}\n");
            // length includes digits + space + body
            let mut len = body.len() + 1;
            loop {
                let len_str = len.to_string();
                let new_len = len_str.len() + 1 + body.len();
                if new_len == len {
                    let mut v = Vec::new();
                    v.extend_from_slice(len_str.as_bytes());
                    v.push(b' ');
                    v.extend_from_slice(body.as_bytes());
                    return v;
                }
                len = new_len;
            }
        }

        let mut carry = Vec::with_capacity(64);
        let mut pos = 0usize;
        let mut path = Vec::new();
        let mut saw_global = false;

        let rec = build_record("path", "a/b/c.txt");
        let split = rec.len() / 2;

        consume_pax_bytes(
            &mut carry,
            &mut pos,
            &mut path,
            &mut saw_global,
            &rec[..split],
            PaxTarget::PerFile,
            128,
        );
        consume_pax_bytes(
            &mut carry,
            &mut pos,
            &mut path,
            &mut saw_global,
            &rec[split..],
            PaxTarget::PerFile,
            128,
        );

        assert_eq!(path, b"a/b/c.txt");
        assert!(!saw_global);
    }

    #[test]
    fn pax_path_is_capped_to_buffer_capacity() {
        fn build_record(key: &str, val: &str) -> Vec<u8> {
            let body = format!("{key}={val}\n");
            let mut len = body.len() + 1;
            loop {
                let len_str = len.to_string();
                let new_len = len_str.len() + 1 + body.len();
                if new_len == len {
                    let mut v = Vec::new();
                    v.extend_from_slice(len_str.as_bytes());
                    v.push(b' ');
                    v.extend_from_slice(body.as_bytes());
                    return v;
                }
                len = new_len;
            }
        }

        let cfg = ArchiveConfig {
            max_virtual_path_len_per_entry: 8,
            ..ArchiveConfig::default()
        };
        let mut budgets = ArchiveBudgets::new(&cfg);
        budgets.enter_archive().unwrap();

        let mut cursor = TarCursor::with_capacity(&cfg);
        let cap = cursor.pax_path.capacity();

        let pax_path = "a/".repeat(64) + "file.txt";
        let record = build_record("path", &pax_path);

        let mut tar = Vec::new();
        let mut hdr = [0u8; TAR_BLOCK_LEN];
        tar_write_header(&mut hdr, "PaxHeader", record.len() as u64, b'x');
        tar.extend_from_slice(&hdr);
        tar.extend_from_slice(&record);
        tar.extend_from_slice(&vec![0u8; tar_pad(record.len() as u64) as usize]);

        let payload = b"hello";
        tar_write_header(&mut hdr, "ignored.txt", payload.len() as u64, b'0');
        tar.extend_from_slice(&hdr);
        tar.extend_from_slice(payload);
        tar.extend_from_slice(&vec![0u8; tar_pad(payload.len() as u64) as usize]);

        tar.extend_from_slice(&[0u8; TAR_BLOCK_LEN]);
        tar.extend_from_slice(&[0u8; TAR_BLOCK_LEN]);

        let mut input = io::Cursor::new(tar);
        let entry = match cursor.next_entry(&mut input, &mut budgets, &cfg).unwrap() {
            TarNext::Entry(m) => m,
            _ => panic!("expected entry after PAX header"),
        };
        assert!(entry.name.len() <= cap);
        assert_eq!(cursor.pax_path.capacity(), cap);
        cursor.debug_assert_no_growth();
    }

    // ── is_zero_block Miri-targeted tests ─────────────────────────────
    //
    // These exercise the `read_unaligned` pointer arithmetic in
    // `is_zero_block` without any FFI, so they run cleanly under Miri
    // with strict-provenance checking.

    #[test]
    fn zero_block_all_zeros() {
        let block = [0u8; TAR_BLOCK_LEN];
        assert!(is_zero_block(&block));
    }

    #[test]
    fn zero_block_first_byte_nonzero() {
        let mut block = [0u8; TAR_BLOCK_LEN];
        block[0] = 1;
        assert!(!is_zero_block(&block));
    }

    #[test]
    fn zero_block_last_byte_nonzero() {
        let mut block = [0u8; TAR_BLOCK_LEN];
        block[TAR_BLOCK_LEN - 1] = 0xFF;
        assert!(!is_zero_block(&block));
    }

    #[test]
    fn zero_block_boundary_byte_nonzero() {
        // Offset 504 is the start of the last u64 read (bytes [504..512)).
        let mut block = [0u8; TAR_BLOCK_LEN];
        block[504] = 1;
        assert!(!is_zero_block(&block));
    }

    #[test]
    fn zero_block_mid_chunk_nonzero() {
        // Offset 63 is the last byte of the first 64-byte chunk.
        let mut block = [0u8; TAR_BLOCK_LEN];
        block[63] = 1;
        assert!(!is_zero_block(&block));
    }

    #[test]
    fn zero_block_every_byte_exercised() {
        // Setting each byte individually ensures every u64 read path detects
        // a nonzero byte regardless of alignment or chunk position.
        for i in 0..TAR_BLOCK_LEN {
            let mut block = [0u8; TAR_BLOCK_LEN];
            block[i] = 1;
            assert!(
                !is_zero_block(&block),
                "is_zero_block should detect nonzero at offset {i}"
            );
        }
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// Prove that every `ptr.add(i + j)` in `is_zero_block` stays within
    /// the `[0, 512)` bounds of the input array.
    ///
    /// The loop bounds are all compile-time constants (`TAR_BLOCK_LEN = 512`,
    /// outer stride 64, inner stride 8), so this is statically verifiable.
    /// The proof also checks that each 8-byte `read_unaligned` at the
    /// computed offset stays within `[0, 512)`.
    #[kani::proof]
    fn verify_is_zero_block_bounds() {
        let block = [0u8; TAR_BLOCK_LEN];

        // Walk the same loop structure as is_zero_block and verify every
        // access offset.
        let mut i = 0usize;
        while i < TAR_BLOCK_LEN {
            let mut j = 0usize;
            while j < 64 && i + j < TAR_BLOCK_LEN {
                let offset = i + j;
                // The pointer offset must be within [0, 504] (last valid
                // start for an 8-byte read in a 512-byte buffer).
                kani::assert(
                    offset <= TAR_BLOCK_LEN - 8,
                    "offset must allow 8-byte read within bounds",
                );
                // The 8-byte read spans [offset, offset+8), which must be
                // fully within [0, 512).
                kani::assert(
                    offset + 8 <= TAR_BLOCK_LEN,
                    "8-byte read must not exceed buffer",
                );
                j += 8;
            }
            i += 64;
        }

        // Also verify the function itself doesn't panic or UB on valid input.
        let result = is_zero_block(&block);
        kani::assert(result, "all-zero block must return true");
    }
}
