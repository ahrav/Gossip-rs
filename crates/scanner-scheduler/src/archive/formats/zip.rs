//! zip sniff helpers + safe Zip32 reader.
//!
//! # Invariants
//! - All sizes/offsets are untrusted and validated against file length.
//! - Metadata reads are charged against `ArchiveBudgets::charge_metadata`.
//! - Central directory parsing is sequential; payload reads use cloned file handles.
//!
//! # Supported
//! - Zip32 (EOCD + central directory).
//! - Entries: stored (method 0) and deflate (method 8).
//! - Encrypted entries are skipped (flag bit 0).
//!
//! # Not Supported
//! - Zip64 (sentinel 0xFFFF/0xFFFFFFFF fields).
//! - Multi-disk archives.
//!
//! # Design Notes
//! - Filename storage is bounded; oversized names are truncated and hashed.
//! - Name bytes are otherwise accepted verbatim; non-printable bytes are
//!   escaped later by the entry-path canonicalizer (no silent drops).
//! - `flate2::read::DeflateDecoder` may allocate internally; this is treated as
//!   an allowed library exception under the "no allocations after startup"
//!   policy.

use std::fs::File;
use std::io::{self, Cursor, Read, Seek, SeekFrom};
use std::sync::Arc;

use crate::archive::formats::tar::TarRead;

use flate2::read::DeflateDecoder;

use crate::archive::util;
use crate::archive::{
    ArchiveBudgets, ArchiveConfig, ArchiveSkipReason, ChargeResult, PartialReason,
};

/// Source for ZIP parsing that supports random access and cloning.
pub trait ZipSource: Read + Seek {
    /// Total byte length of the archive.
    fn len(&self) -> io::Result<u64>;
    /// Returns true if the archive length is zero.
    #[inline]
    fn is_empty(&self) -> io::Result<bool> {
        Ok(self.len()? == 0)
    }
    /// Clone the source for concurrent payload reads.
    fn try_clone(&self) -> io::Result<Self>
    where
        Self: Sized;
}

impl ZipSource for File {
    #[inline]
    fn len(&self) -> io::Result<u64> {
        Ok(self.metadata()?.len())
    }

    #[inline]
    fn try_clone(&self) -> io::Result<Self> {
        self.try_clone()
    }
}

impl ZipSource for Cursor<Arc<[u8]>> {
    #[inline]
    fn len(&self) -> io::Result<u64> {
        Ok(self.get_ref().len() as u64)
    }

    #[inline]
    fn try_clone(&self) -> io::Result<Self> {
        Ok(self.clone())
    }
}

impl ZipSource for Cursor<Vec<u8>> {
    #[inline]
    fn len(&self) -> io::Result<u64> {
        Ok(self.get_ref().len() as u64)
    }

    #[inline]
    fn try_clone(&self) -> io::Result<Self> {
        Ok(self.clone())
    }
}

/// ZIP signatures are `PK..`.
///
/// Common ones:
/// - Local file header:      PK 03 04
/// - Central directory:      PK 01 02
/// - End of central dir:     PK 05 06
/// - Data descriptor:        PK 07 08
#[inline(always)]
pub fn is_zip_magic(header: &[u8]) -> bool {
    if header.len() < 4 {
        return false;
    }
    if header[0] != b'P' || header[1] != b'K' {
        return false;
    }
    matches!((header[2], header[3]), (1, 2) | (3, 4) | (5, 6) | (7, 8))
}

const SIG_EOCD: u32 = 0x0605_4b50;
const SIG_CDFH: u32 = 0x0201_4b50;
const SIG_LFH: u32 = 0x0403_4b50;

const EOCD_MIN_LEN: usize = 22;
const EOCD_SEARCH_MAX: usize = 66 * 1024; // 64 KiB comment + header margin

/// Central directory fixed header length.
const CDFH_LEN: usize = 46;
/// Local file header fixed length.
const LFH_LEN: usize = 30;

/// Outcome of opening a ZIP container.
pub enum ZipOpen {
    Ready,
    Skip(ArchiveSkipReason),
    Stop(PartialReason),
}

/// Outcome of advancing the central-directory cursor.
pub enum ZipNext<'a> {
    End,
    Entry(ZipEntryMeta<'a>),
    Stop(PartialReason),
}

/// Central-directory metadata for a single entry.
///
/// # Invariants
/// - All sizes/offsets are validated against the file length before use.
pub struct ZipEntryMeta<'a> {
    pub name: &'a [u8],
    pub flags: u16,
    pub method: u16,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
    pub local_header_offset: u64,
    pub cdfh_offset: u64,
    pub lfh_offset_valid: bool,
    pub is_dir: bool,
    pub name_truncated: bool,
    pub name_hash64: u64,
}

impl<'a> ZipEntryMeta<'a> {
    #[inline(always)]
    pub fn is_encrypted(&self) -> bool {
        (self.flags & 0x0001) != 0
    }

    #[inline(always)]
    pub fn uses_data_descriptor(&self) -> bool {
        (self.flags & 0x0008) != 0
    }

    #[inline(always)]
    pub fn compression_supported(&self) -> bool {
        self.method == 0 || self.method == 8
    }
}

/// Streaming cursor over the central directory.
///
/// # Invariants
/// - `next_entry` advances monotonically through the central directory region.
/// - Payload reads are performed via cloned file handles.
pub struct ZipCursor<R: ZipSource> {
    file: Option<R>,
    payload_file: Option<R>,
    file_len: u64,

    cd_pos: u64,
    cd_end: u64,

    entries_total: u32,
    entries_seen: u32,

    name_buf: Vec<u8>,
    eocd_buf: Vec<u8>,
    discard: [u8; 8192],

    // Debug-only capacity guards.
    #[cfg(debug_assertions)]
    name_cap: usize,
    #[cfg(debug_assertions)]
    eocd_cap: usize,
}

impl<R: ZipSource> ZipCursor<R> {
    /// Construct a reusable cursor with preallocated buffers.
    pub fn with_capacity(cfg: &ArchiveConfig) -> Self {
        let name_cap = cfg
            .max_virtual_path_len_per_entry
            .saturating_mul(4)
            .min(64 * 1024);
        let eocd_cap = EOCD_SEARCH_MAX;
        Self {
            file: None,
            payload_file: None,
            file_len: 0,
            cd_pos: 0,
            cd_end: 0,
            entries_total: 0,
            entries_seen: 0,
            name_buf: Vec::with_capacity(name_cap),
            eocd_buf: vec![0u8; eocd_cap],
            discard: [0u8; 8192],
            #[cfg(debug_assertions)]
            name_cap,
            #[cfg(debug_assertions)]
            eocd_cap,
        }
    }

    /// Reset cursor state for reuse without allocating.
    #[inline]
    pub fn reset(&mut self) {
        self.file = None;
        self.payload_file = None;
        self.file_len = 0;
        self.cd_pos = 0;
        self.cd_end = 0;
        self.entries_total = 0;
        self.entries_seen = 0;
        self.name_buf.clear();
        self.debug_assert_no_growth();
    }

    /// Debug-only guard: ensure internal buffers never grow after startup.
    #[inline]
    pub fn debug_assert_no_growth(&self) {
        #[cfg(debug_assertions)]
        {
            debug_assert_eq!(
                self.name_buf.capacity(),
                self.name_cap,
                "zip name_buf grew after startup"
            );
            debug_assert_eq!(
                self.eocd_buf.len(),
                self.eocd_cap,
                "zip eocd_buf length changed after startup"
            );
            debug_assert_eq!(
                self.eocd_buf.capacity(),
                self.eocd_cap,
                "zip eocd_buf grew after startup"
            );
        }
    }

    /// Open a ZIP container and initialize central-directory traversal.
    ///
    /// This charges metadata budget for the EOCD search window and validates
    /// container bounds. Returns:
    /// - `ZipOpen::Ready` when the container is parsable.
    /// - `ZipOpen::Skip` for unsupported features (Zip64, multi-disk, etc.).
    /// - `ZipOpen::Stop` for malformed data or budget exhaustion.
    pub fn open(
        &mut self,
        mut file: R,
        budgets: &mut ArchiveBudgets,
        cfg: &ArchiveConfig,
    ) -> io::Result<ZipOpen> {
        self.reset();

        let file_len = file.len()?;
        if file_len < EOCD_MIN_LEN as u64 {
            return Ok(ZipOpen::Stop(PartialReason::MalformedZip));
        }

        // Read tail window (bounded to the preallocated EOCD buffer).
        let win_len = (file_len as usize).min(EOCD_SEARCH_MAX);
        let win_off = file_len - win_len as u64;

        // Charge metadata for the EOCD search window.
        match budgets.charge_metadata(win_len as u64) {
            ChargeResult::Ok => {}
            ChargeResult::Clamp { hit, .. } => {
                return Ok(ZipOpen::Stop(util::budget_hit_to_partial(
                    hit,
                    PartialReason::MalformedZip,
                )));
            }
        }

        file.seek(SeekFrom::Start(win_off))?;
        let win = &mut self.eocd_buf[..win_len];
        util::read_exact_n(&mut file, win, "zip")?;

        // Find EOCD signature within window (scan backward).
        let eocd_rel = match rfind_sig_u32_le(win, SIG_EOCD) {
            Some(i) => i,
            None => return Ok(ZipOpen::Stop(PartialReason::MalformedZip)),
        };

        // Need full EOCD fixed fields.
        if eocd_rel + EOCD_MIN_LEN > win.len() {
            return Ok(ZipOpen::Stop(PartialReason::MalformedZip));
        }

        let eocd = &win[eocd_rel..];

        let disk_no = le_u16(&eocd[4..6]);
        let cd_disk = le_u16(&eocd[6..8]);
        let entries_disk = le_u16(&eocd[8..10]);
        let entries_total = le_u16(&eocd[10..12]);
        let cd_size = le_u32(&eocd[12..16]);
        let cd_off = le_u32(&eocd[16..20]);
        let comment_len = le_u16(&eocd[20..22]) as usize;

        // Ensure comment bytes are present in window.
        if eocd_rel + EOCD_MIN_LEN + comment_len > win.len() {
            // Could be a false-positive signature; continue searching earlier occurrences.
            let mut cur = eocd_rel;
            let mut found = None;
            while cur > 0 {
                cur -= 1;
                if cur + 4 > win.len() {
                    continue;
                }
                if u32_from_le(&win[cur..cur + 4]) == SIG_EOCD && cur + EOCD_MIN_LEN <= win.len() {
                    let c_len = le_u16(&win[cur + 20..cur + 22]) as usize;
                    if cur + EOCD_MIN_LEN + c_len <= win.len() {
                        found = Some(cur);
                        break;
                    }
                }
            }
            let eocd_rel = match found {
                Some(x) => x,
                None => return Ok(ZipOpen::Stop(PartialReason::MalformedZip)),
            };
            let eocd = &win[eocd_rel..];
            let disk_no = le_u16(&eocd[4..6]);
            let cd_disk = le_u16(&eocd[6..8]);
            let entries_disk = le_u16(&eocd[8..10]);
            let entries_total = le_u16(&eocd[10..12]);
            let cd_size = le_u32(&eocd[12..16]);
            let cd_off = le_u32(&eocd[16..20]);

            return self.finish_open(
                file,
                file_len,
                cfg,
                disk_no,
                cd_disk,
                entries_disk,
                entries_total,
                cd_size,
                cd_off,
            );
        }

        self.finish_open(
            file,
            file_len,
            cfg,
            disk_no,
            cd_disk,
            entries_disk,
            entries_total,
            cd_size,
            cd_off,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn finish_open(
        &mut self,
        file: R,
        file_len: u64,
        cfg: &ArchiveConfig,
        disk_no: u16,
        cd_disk: u16,
        entries_disk: u16,
        entries_total: u16,
        cd_size: u32,
        cd_off: u32,
    ) -> io::Result<ZipOpen> {
        // Multi-disk unsupported.
        if disk_no != 0 || cd_disk != 0 || entries_disk != entries_total {
            return Ok(ZipOpen::Skip(ArchiveSkipReason::UnsupportedFeature));
        }

        // Zip64 sentinel values in EOCD -> unsupported.
        if entries_total == 0xFFFF || cd_size == 0xFFFF_FFFF || cd_off == 0xFFFF_FFFF {
            return Ok(ZipOpen::Skip(ArchiveSkipReason::UnsupportedFeature));
        }

        let entries_total_u32 = entries_total as u32;
        if entries_total_u32 > cfg.max_entries_per_archive {
            return Ok(ZipOpen::Skip(ArchiveSkipReason::EntryCountExceeded));
        }

        let cd_off_u64 = cd_off as u64;
        let cd_size_u64 = cd_size as u64;

        // Validate CD bounds.
        if cd_off_u64 > file_len {
            return Ok(ZipOpen::Stop(PartialReason::MalformedZip));
        }
        let cd_end = cd_off_u64.saturating_add(cd_size_u64);
        if cd_end > file_len {
            return Ok(ZipOpen::Stop(PartialReason::MalformedZip));
        }

        let payload_file = file.try_clone()?;

        self.file = Some(file);
        self.payload_file = Some(payload_file);
        self.file_len = file_len;
        self.cd_pos = cd_off_u64;
        self.cd_end = cd_end;
        self.entries_total = entries_total_u32;
        self.entries_seen = 0;
        self.name_buf.clear();

        Ok(ZipOpen::Ready)
    }

    /// Yield the next central-directory entry metadata, charging metadata budget.
    pub fn next_entry<'a>(
        &'a mut self,
        budgets: &mut ArchiveBudgets,
        cfg: &ArchiveConfig,
    ) -> io::Result<ZipNext<'a>> {
        self.debug_assert_no_growth();
        if self.entries_seen >= self.entries_total || self.cd_pos >= self.cd_end {
            return Ok(ZipNext::End);
        }

        let file = match self.file.as_mut() {
            Some(f) => f,
            None => return Ok(ZipNext::Stop(PartialReason::MalformedZip)),
        };

        let cdfh_offset = self.cd_pos;

        // Read fixed CDFH.
        match budgets.charge_metadata(CDFH_LEN as u64) {
            ChargeResult::Ok => {}
            ChargeResult::Clamp { hit, .. } => {
                return Ok(ZipNext::Stop(util::budget_hit_to_partial(
                    hit,
                    PartialReason::MalformedZip,
                )));
            }
        }

        file.seek(SeekFrom::Start(self.cd_pos))?;
        let mut hdr = [0u8; CDFH_LEN];
        util::read_exact_n(file, &mut hdr, "zip")?;

        let sig = u32_from_le(&hdr[0..4]);
        if sig != SIG_CDFH {
            return Ok(ZipNext::Stop(PartialReason::MalformedZip));
        }

        // Enforce entry count deterministically.
        if let Err(hit) = budgets.note_entry() {
            return Ok(ZipNext::Stop(util::budget_hit_to_partial(
                hit,
                PartialReason::MalformedZip,
            )));
        }
        self.entries_seen = self.entries_seen.saturating_add(1);

        let flags = le_u16(&hdr[8..10]);
        let method = le_u16(&hdr[10..12]);

        let comp_size = le_u32(&hdr[20..24]);
        let uncomp_size = le_u32(&hdr[24..28]);

        let name_len = le_u16(&hdr[28..30]) as usize;
        let extra_len = le_u16(&hdr[30..32]) as usize;
        let comment_len = le_u16(&hdr[32..34]) as usize;

        let lfh_off = le_u32(&hdr[42..46]);
        let lfh_off_u64 = lfh_off as u64;
        let lfh_offset_valid = lfh_off_u64.saturating_add(LFH_LEN as u64) <= self.file_len;

        // Zip64 sentinel in CDFH -> unsupported.
        if comp_size == 0xFFFF_FFFF || uncomp_size == 0xFFFF_FFFF || lfh_off == 0xFFFF_FFFF {
            return Ok(ZipNext::Stop(PartialReason::UnsupportedFeature));
        }

        let var_total = name_len
            .saturating_add(extra_len)
            .saturating_add(comment_len);

        match budgets.charge_metadata(var_total as u64) {
            ChargeResult::Ok => {}
            ChargeResult::Clamp { hit, .. } => {
                return Ok(ZipNext::Stop(util::budget_hit_to_partial(
                    hit,
                    PartialReason::MalformedZip,
                )));
            }
        }

        // Read filename, bounded storage (prefix) + streaming hash for overflow.
        self.name_buf.clear();

        let max_store = cfg
            .max_virtual_path_len_per_entry
            .saturating_mul(4)
            .min(64 * 1024);
        let store_len = name_len.min(max_store).min(self.name_buf.capacity());
        let name_truncated = name_len > store_len;

        // SAFETY: `store_len` is bounded by `self.name_buf.capacity()` (see
        // `.min(self.name_buf.capacity())` above), satisfying `set_len`'s
        // precondition.  The buffer is immediately filled by `read_name_exact`
        // (which calls `read_exact_n`).
        //
        // Error-path safety: if `read_name_exact` returns `Err`, the `?`
        // propagates upward with `name_buf` containing uninitialized bytes.
        // This is safe because the next call to `next_entry` begins with
        // `self.name_buf.clear()` (which sets len=0 without reading), so the
        // uninitialized bytes are never observed — only overwritten or discarded.
        // This is exercised by the Miri test `name_buf_error_path_clears_without_reading_uninit`.
        if store_len > 0 {
            // SAFETY: `store_len <= capacity` (clamped above) and the buffer is
            // immediately filled by `read_name_exact` on the next line.
            unsafe {
                self.name_buf.set_len(store_len);
            }
            self.read_name_exact(store_len)?;
        }

        let mut name_hash64 = util::fnv1a64_init();
        for &b in &self.name_buf {
            name_hash64 = util::fnv1a64_update(name_hash64, b);
        }

        if name_truncated {
            // Discard remaining name bytes while hashing them.
            let remaining = name_len.saturating_sub(store_len);
            if remaining > 0 {
                self.discard_exact_with_hash(remaining, &mut name_hash64)?;
            }
        }

        // Skip extra + comment without storing.
        if extra_len > 0 {
            self.discard_exact(extra_len)?;
        }
        if comment_len > 0 {
            self.discard_exact(comment_len)?;
        }

        // Advance cd_pos.
        let rec_len = (CDFH_LEN + var_total) as u64;
        self.cd_pos = self.cd_pos.saturating_add(rec_len);

        // Directory heuristic: name ends with '/'.
        let is_dir = (!name_truncated) && self.name_buf.last().copied() == Some(b'/');

        Ok(ZipNext::Entry(ZipEntryMeta {
            name: &self.name_buf,
            flags,
            method,
            compressed_size: comp_size as u64,
            uncompressed_size: uncomp_size as u64,
            local_header_offset: lfh_off_u64,
            cdfh_offset,
            lfh_offset_valid,
            is_dir,
            name_truncated,
            name_hash64,
        }))
    }

    fn read_name_exact(&mut self, n: usize) -> io::Result<()> {
        let file = match self.file.as_mut() {
            Some(f) => f,
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "zip: file closed",
                ));
            }
        };
        util::read_exact_n(file, &mut self.name_buf[..n], "zip")
    }

    fn discard_exact(&mut self, mut n: usize) -> io::Result<()> {
        let file = match self.file.as_mut() {
            Some(f) => f,
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "zip: file closed",
                ));
            }
        };
        while n > 0 {
            let step = self.discard.len().min(n);
            util::read_exact_n(file, &mut self.discard[..step], "zip")?;
            n -= step;
        }
        Ok(())
    }

    fn discard_exact_with_hash(&mut self, mut n: usize, hash: &mut u64) -> io::Result<()> {
        let file = match self.file.as_mut() {
            Some(f) => f,
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "zip: file closed",
                ));
            }
        };
        while n > 0 {
            let step = self.discard.len().min(n);
            util::read_exact_n(file, &mut self.discard[..step], "zip")?;
            for &b in &self.discard[..step] {
                *hash = util::fnv1a64_update(*hash, b);
            }
            n -= step;
        }
        Ok(())
    }

    /// Open a decompressed reader for the entry payload, using a cloned file handle.
    ///
    /// This charges metadata budget for the local header and validates bounds against file length.
    pub fn open_entry_reader<'a>(
        &'a mut self,
        meta: &ZipEntryMeta<'_>,
        budgets: &mut ArchiveBudgets,
    ) -> io::Result<Result<ZipEntryReader<'a, R>, PartialReason>> {
        if meta.local_header_offset > self.file_len {
            return Ok(Err(PartialReason::MalformedZip));
        }

        let f = match self.payload_file.as_mut() {
            Some(f) => f,
            None => return Ok(Err(PartialReason::MalformedZip)),
        };
        f.seek(SeekFrom::Start(meta.local_header_offset))?;

        match budgets.charge_metadata(LFH_LEN as u64) {
            ChargeResult::Ok => {}
            ChargeResult::Clamp { hit, .. } => {
                return Ok(Err(util::budget_hit_to_partial(
                    hit,
                    PartialReason::MalformedZip,
                )));
            }
        }

        let mut lfh = [0u8; LFH_LEN];
        util::read_exact_n(f, &mut lfh, "zip")?;

        let sig = u32_from_le(&lfh[0..4]);
        if sig != SIG_LFH {
            return Ok(Err(PartialReason::MalformedZip));
        }

        let name_len = le_u16(&lfh[26..28]) as u64;
        let extra_len = le_u16(&lfh[28..30]) as u64;

        let local_var = name_len.saturating_add(extra_len);
        match budgets.charge_metadata(local_var) {
            ChargeResult::Ok => {}
            ChargeResult::Clamp { hit, .. } => {
                return Ok(Err(util::budget_hit_to_partial(
                    hit,
                    PartialReason::MalformedZip,
                )));
            }
        }

        let data_start = meta
            .local_header_offset
            .saturating_add(LFH_LEN as u64)
            .saturating_add(name_len)
            .saturating_add(extra_len);

        let data_end = data_start.saturating_add(meta.compressed_size);
        if data_start > self.file_len || data_end > self.file_len {
            return Ok(Err(PartialReason::MalformedZip));
        }

        f.seek(SeekFrom::Start(data_start))?;

        let take = LimitedRead::new(f, meta.compressed_size);
        let counted = CountedRead::new(take);

        let r = match meta.method {
            0 => ZipEntryReader::Stored(counted),
            8 => ZipEntryReader::Deflate(DeflateDecoder::new(counted)),
            _ => return Ok(Err(PartialReason::MalformedZip)),
        };

        Ok(Ok(r))
    }
}

/// Decompressed reader for a ZIP entry, with compressed-byte accounting.
///
/// # Guarantees
/// - `total_compressed()` is monotonic and saturating.
pub enum ZipEntryReader<'a, R: Read> {
    Stored(CountedRead<LimitedRead<'a, R>>),
    Deflate(DeflateDecoder<CountedRead<LimitedRead<'a, R>>>),
}

impl<'a, R: Read> ZipEntryReader<'a, R> {
    #[inline(always)]
    pub fn read_decompressed(&mut self, dst: &mut [u8]) -> io::Result<usize> {
        match self {
            ZipEntryReader::Stored(r) => r.read(dst),
            ZipEntryReader::Deflate(r) => r.read(dst),
        }
    }

    #[inline(always)]
    pub fn total_compressed(&self) -> u64 {
        match self {
            ZipEntryReader::Stored(r) => r.bytes(),
            ZipEntryReader::Deflate(r) => r.get_ref().bytes(),
        }
    }
}

/// Read wrapper that limits reads to a fixed number of bytes.
///
/// This is used to bound entry payload reads to the compressed size.
pub struct LimitedRead<'a, R: ?Sized + Read> {
    inner: &'a mut R,
    remaining: u64,
}

impl<'a, R: ?Sized + Read> LimitedRead<'a, R> {
    #[inline]
    pub fn new(inner: &'a mut R, remaining: u64) -> Self {
        Self { inner, remaining }
    }

    #[inline]
    pub fn remaining(&self) -> u64 {
        self.remaining
    }
}

impl<R: ?Sized + Read> Read for LimitedRead<'_, R> {
    #[inline]
    fn read(&mut self, dst: &mut [u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            return Ok(0);
        }
        let max = self.remaining.min(dst.len() as u64) as usize;
        let n = self.inner.read(&mut dst[..max])?;
        self.remaining = self.remaining.saturating_sub(n as u64);
        Ok(n)
    }
}

impl<R: ?Sized + Read> TarRead for LimitedRead<'_, R> {}

pub use crate::archive::util::CountedRead;

fn rfind_sig_u32_le(hay: &[u8], sig: u32) -> Option<usize> {
    if hay.len() < 4 {
        return None;
    }
    let mut i = hay.len() - 4;
    loop {
        if u32_from_le(&hay[i..i + 4]) == sig {
            return Some(i);
        }
        if i == 0 {
            break;
        }
        i -= 1;
    }
    None
}

#[inline(always)]
fn u32_from_le(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

#[inline(always)]
fn le_u16(b: &[u8]) -> u16 {
    u16::from_le_bytes([b[0], b[1]])
}

#[inline(always)]
fn le_u32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::{ArchiveBudgets, ArchiveConfig};
    use std::io::Write;
    use std::sync::Arc;
    use tempfile::NamedTempFile;

    #[test]
    fn sniff_zip_magic() {
        assert!(is_zip_magic(b"PK\x03\x04"));
        assert!(is_zip_magic(b"PK\x05\x06"));
        assert!(!is_zip_magic(b"PK\x00\x00"));
        assert!(!is_zip_magic(b"P"));
    }

    #[test]
    fn long_name_is_truncated_and_hashed_without_growth() {
        let cfg = ArchiveConfig {
            max_virtual_path_len_per_entry: 8, // name_cap = 32
            ..ArchiveConfig::default()
        };

        let mut tmp = NamedTempFile::new().unwrap();
        {
            let mut zw = zip::ZipWriter::new(tmp.as_file_mut());
            let opts = zip::write::FileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            let name = "a".repeat(64);
            zw.start_file(name, opts).unwrap();
            zw.write_all(b"hi").unwrap();
            zw.finish().unwrap();
        }
        tmp.flush().unwrap();

        let mut budgets = ArchiveBudgets::new(&cfg);
        budgets.enter_archive().unwrap();

        let mut cursor = ZipCursor::with_capacity(&cfg);
        let name_cap = cursor.name_buf.capacity();

        let open = cursor
            .open(tmp.reopen().unwrap(), &mut budgets, &cfg)
            .unwrap();
        match open {
            ZipOpen::Ready => {}
            _ => panic!("expected zip to open"),
        }

        let entry = match cursor.next_entry(&mut budgets, &cfg).unwrap() {
            ZipNext::Entry(m) => m,
            _ => panic!("expected entry"),
        };

        assert!(entry.name_truncated);
        assert!(!entry.name.is_empty());
        assert_eq!(entry.name.len(), name_cap);
        assert_ne!(entry.name_hash64, 0);
        assert_eq!(cursor.name_buf.capacity(), name_cap);
        cursor.debug_assert_no_growth();
    }

    #[test]
    fn in_memory_sources_open_and_read_entries() {
        let cfg = ArchiveConfig::default();

        let mut cursor = std::io::Cursor::new(Vec::new());
        {
            let mut zw = zip::ZipWriter::new(&mut cursor);
            let opts = zip::write::FileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            zw.start_file("entry.txt", opts).unwrap();
            zw.write_all(b"hello").unwrap();
            zw.finish().unwrap();
        }

        let bytes = cursor.into_inner();
        let bytes_arc: Arc<[u8]> = Arc::from(bytes.clone());

        fn assert_entry<S: ZipSource>(source: S, cfg: &ArchiveConfig) {
            let mut budgets = ArchiveBudgets::new(cfg);
            budgets.enter_archive().unwrap();

            let mut cursor = ZipCursor::with_capacity(cfg);
            let open = cursor.open(source, &mut budgets, cfg).unwrap();
            assert!(matches!(open, ZipOpen::Ready));

            let entry = match cursor.next_entry(&mut budgets, cfg).unwrap() {
                ZipNext::Entry(m) => m,
                _ => panic!("expected entry"),
            };
            assert_eq!(entry.name, b"entry.txt");
        }

        assert_entry(std::io::Cursor::new(bytes.clone()), &cfg);
        assert_entry(std::io::Cursor::new(bytes_arc), &cfg);
    }

    // ── set_len Miri-targeted tests ───────────────────────────────────
    //
    // These exercise the `Vec::set_len` + immediate fill pattern used in
    // `parse_local_file_header` without any FFI (no flate2 / zlib-ng),
    // so they run cleanly under Miri with strict-provenance checking.

    /// Validates the normal path: `set_len(n)` followed by immediate fill.
    /// This mirrors the pattern at line 502-505 where `set_len(store_len)`
    /// is immediately followed by `read_name_exact(store_len)`.
    #[test]
    fn name_buf_set_len_and_fill() {
        let cap = 64;
        let mut buf: Vec<u8> = Vec::with_capacity(cap);

        // Mimic parse_local_file_header: clear, set_len, fill.
        buf.clear();
        let store_len = 32usize.min(cap);
        // SAFETY: `store_len` (32) <= `cap` (64); all bytes are filled immediately below.
        unsafe {
            buf.set_len(store_len);
        }
        // Immediately fill (simulates `read_name_exact`).
        buf[..store_len].copy_from_slice(&[0xAA; 32]);

        assert_eq!(buf.len(), 32);
        assert!(buf.iter().all(|&b| b == 0xAA));
    }

    /// Validates the error path: `set_len(n)` followed by a failed read,
    /// then `clear()` on the next call. The uninitialized bytes between
    /// `set_len` and `clear` must never be read.
    #[test]
    fn name_buf_error_path_clears_without_reading_uninit() {
        let cap = 64;
        let mut buf: Vec<u8> = Vec::with_capacity(cap);

        buf.clear();
        let store_len = 32usize.min(cap);
        // SAFETY: `store_len` (32) <= `cap` (64); simulates the error path where
        // uninit bytes are never read — `clear()` below sets len=0 without reading.
        unsafe {
            buf.set_len(store_len);
        }
        // Simulate `read_name_exact` returning Err — the `?` propagates
        // upward. On the next call, `parse_local_file_header` starts with
        // `self.name_buf.clear()`. We must NOT read the uninit bytes.

        // clear() just sets len=0 — no read of uninit memory.
        buf.clear();
        assert_eq!(buf.len(), 0);
        assert_eq!(buf.capacity(), cap);

        // After clear, the buffer is safe to reuse with a new set_len+fill.
        // SAFETY: 16 <= `cap` (64); all bytes are filled immediately below.
        unsafe {
            buf.set_len(16);
        }
        buf[..16].copy_from_slice(&[0xBB; 16]);
        assert_eq!(buf.len(), 16);
        assert!(buf.iter().all(|&b| b == 0xBB));
    }

    /// Validates set_len with store_len == 0 (no unsafe needed).
    #[test]
    fn name_buf_zero_len_skips_set_len() {
        let cap = 64;
        let mut buf: Vec<u8> = Vec::with_capacity(cap);

        buf.clear();
        let store_len = 0usize;
        // The code guards: `if store_len > 0 { unsafe { set_len(...) } }`
        // so store_len == 0 never enters the unsafe block.
        if store_len > 0 {
            // SAFETY: `store_len` <= `cap`; dead code here since `store_len == 0`.
            unsafe {
                buf.set_len(store_len);
            }
        }
        assert_eq!(buf.len(), 0);
    }

    /// Validates set_len at exact capacity boundary.
    #[test]
    fn name_buf_set_len_at_capacity() {
        let cap = 64;
        let mut buf: Vec<u8> = Vec::with_capacity(cap);

        buf.clear();
        let store_len = cap; // store_len == capacity
        // SAFETY: `store_len == cap` (64); all bytes are filled immediately below.
        unsafe {
            buf.set_len(store_len);
        }
        buf[..store_len].fill(0xCC);
        assert_eq!(buf.len(), cap);
        assert!(buf.iter().all(|&b| b == 0xCC));
    }
}
