//! Vectorscan/Hyperscan prefilter integration for raw-byte and decoded-stream scanning.
//!
//! # Scope
//! This module builds and runs Vectorscan databases for three prefilter paths:
//! - Raw bytes (block mode) via `VsPrefilterDb`.
//! - Decoded streams (stream mode) via `VsStreamDb`.
//! - UTF-16 anchors and decoded-space gating via `VsAnchorDb`, `VsUtf16StreamDb`,
//!   and `VsGateDb`.
//!
//! # Pattern id layout
//! - Raw rule expressions are compiled first; their ids are `0..raw_rule_count`.
//! - Optional anchor literal patterns are appended; their ids start at `anchor_id_base`.
//! - `raw_meta` maps raw pattern index -> (`rule_id`, `max_width`, `seed_radius`);
//!   anchor patterns map via the `anchor_*` tables.
//!
//! # Coordinate systems
//! - Raw/UTF-16 anchor scans operate on raw-byte offsets in the scanned buffer.
//! - Stream prefilters emit decoded-byte offsets in the post-transform stream.
//!
//! # Match offsets
//! Vectorscan reports `from`/`to` offsets in the coordinate system of the scan
//! input. We treat `to` as the match end offset for window seeding and derive
//! the start from the bounded `max_width` estimate when available.
//!
//! # Correctness contract
//! Prefiltering is conservative: it may add extra windows but must never drop
//! true matches. Window math is saturating and clamped to the available
//! haystack length when known to avoid under-seeding on overflow.
//!
//! # Invariants and safety
//! - Compiled databases are immutable and may be shared across threads.
//! - Each scanning thread must use its own `hs_scratch_t` (`VsScratch`).
//! - Match callbacks must never panic or unwind across the FFI boundary.
//! - Callback `ctx` pointers are valid only for the duration of a scan.
//! - Scan buffers must fit in `u32`; some entrypoints return errors when lengths
//!   exceed that bound, others assume callers pre-chunk input accordingly.
//!
//! # Window seeding
//! 1. Compile each rule regex in block mode with `HS_FLAG_PREFILTER` to get
//!    conservative hits.
//! 2. Use `hs_expression_info` to estimate `max_width` for overlap sizing.
//! 3. On a match, seed a window around the match end (conservative).
//! 4. Optionally include UTF-16 anchor patterns in the same database to avoid
//!    a second scan pass.
//!
//! # Design choices
//! - If window math saturates `u32`, we fall back to whole-buffer windows rather
//!   than risking under-seeding.
//! - UTF-16 scanning always uses anchor databases; Vectorscan only gates
//!   raw-byte and decoded-stream variants.
//!
//! # Startup DB cache
//! - `VsPrefilterDb` and `VsStreamDb` optionally use an on-disk cache of
//!   serialized Vectorscan databases to reduce repeated process startup time.
//! - Cache keys include compile mode, platform fingerprint, Vectorscan version,
//!   and exact pattern/flag/id lists.
//! - Cache misses or deserialize failures always fall back to normal compile;
//!   cache I/O is best-effort and never a correctness dependency.
//! - Environment controls:
//!   - `SCANNER_VS_DB_CACHE=0|false|off|no` disables cache use.
//!   - `SCANNER_VS_DB_CACHE_DIR=/path` overrides cache location.
//!
//! # Limits and fallback behavior
//! - Scan APIs accept `u32` lengths; we return errors when a haystack exceeds
//!   that bound.
//! - If multi-compile fails for raw rules, we fall back to per-rule compilation
//!   to pinpoint rejects; any rejected pattern returns an error.
//! - Empty UTF-16/gate pattern sets return an error early.
use crate::api::RuleSpec;
use libc::{c_char, c_int, c_uint, c_void};
use std::ffi::CString;
use std::mem::MaybeUninit;
use std::ptr;

use vectorscan_rs_sys as vs;

use super::hit_pool::SpanU32;
use super::rule_repr::{Target, Variant};
use super::scratch::ScanScratch;

/// Per-pattern metadata for the raw-byte match callback (AoS layout).
///
/// Indexed by Vectorscan expression id in the compiled database. The match
/// callback loads one `RawPatternMeta` per hit to determine the originating
/// rule, the estimated match width (for window start derivation), and the
/// seed radius (for window expansion). The `#[repr(C)]` layout guarantees
/// 12 bytes with no internal padding, verified by the compile-time assertion
/// below.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct RawPatternMeta {
    rule_id: u32,
    match_width: u32,
    seed_radius: u32,
}

// Compile-time size guard: 3 × u32 = 12 bytes, no padding under #[repr(C)].
// Exact size matters because the match callback indexes this via raw pointer
// arithmetic (`raw_meta.add(id)`) in the hot path.
const _: () = assert!(std::mem::size_of::<RawPatternMeta>() == 12);

/// Compiled Vectorscan database plus per-rule window metadata for raw-byte scanning.
///
/// The database is immutable after compilation and can be shared across
/// threads, but each thread must allocate its own `VsScratch`.
///
/// Raw pattern ids follow compile order; `raw_meta` maps expression index to
/// scan metadata (`rule_id`, `max_width`, `seed_radius`) in one AoS load. If
/// we fall back to per-rule compilation, `raw_missing_rules` records rejected
/// rules (and the build fails). Optional UTF-16 anchor patterns are appended
/// after raw patterns and resolved via the `anchor_*` mapping tables.
pub(crate) struct VsPrefilterDb {
    /// Compiled Vectorscan block-mode database.
    db: *mut vs::hs_database_t,
    /// Number of raw rule patterns in the database.
    raw_rule_count: u32,
    /// Per-raw-pattern metadata (rule id + width + seed radius).
    raw_meta: Vec<RawPatternMeta>,
    /// Rule ids that failed individual compilation (fallback path).
    raw_missing_rules: Vec<u32>,
    /// Pattern id where anchor literals begin (equals `raw_rule_count`).
    anchor_id_base: u32,
    /// Number of anchor literal patterns.
    anchor_pat_count: u32,
    /// Rule/variant targets for anchor patterns.
    anchor_targets: Vec<VsAnchorTarget>,
    /// Prefix-sum offsets into `anchor_targets`.
    anchor_pat_offsets: Vec<u32>,
    /// Byte length of each anchor pattern.
    anchor_pat_lens: Vec<u32>,
    /// Max bounded width across all rules.
    max_width: u32,
    /// True if any rule reports an unbounded width.
    unbounded: bool,
}

/// Per-rule metadata for stream-mode window seeding.
///
/// `max_width` is derived from `hs_expression_info`; Vectorscan reports
/// `UINT_MAX` for unbounded patterns and `0` for zero-width matches — both
/// are mapped to `u32::MAX` for window seeding. When unbounded,
/// `whole_buffer_on_hit` is set and the callback asks the caller to scan the
/// full decoded stream instead of emitting offsets. `radius` comes from rule
/// tuning and expands windows around the match end.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct VsStreamMeta {
    pub(crate) max_width: u32,
    pub(crate) radius: u32,
    pub(crate) whole_buffer_on_hit: u32,
}

/// Compiled Vectorscan database for stream-mode scanning.
///
/// This is used for decoded-stream prefiltering; matches are converted into
/// candidate windows in the caller using `VsStreamMeta` indexed by rule id.
/// The `meta` vector is aligned to rule ids assigned at compile time.
pub(crate) struct VsStreamDb {
    /// Compiled Vectorscan stream-mode database.
    db: *mut vs::hs_database_t,
    /// Per-rule window metadata indexed by rule id.
    meta: Vec<VsStreamMeta>,
}

/// Vectorscan stream database for decoded-space anchor gating.
///
/// Uses literal byte patterns to detect whether any anchor variant appears in
/// a decoded stream. Patterns are compiled with `HS_FLAG_SINGLEMATCH` to avoid
/// repeated callbacks once a hit is detected.
/// A hit serves as a decoded-space gate signal; callers may skip downstream
/// scanning when no anchors are observed.
pub(crate) struct VsGateDb {
    /// Compiled Vectorscan stream-mode database for gate detection.
    db: *mut vs::hs_database_t,
}

use super::vs_cache::{CacheKeyInput, VsDbCache};

// SAFETY: hs_database_t is immutable after compilation, and we require per-thread scratch.
unsafe impl Send for VsStreamDb {}
// SAFETY: hs_database_t is immutable after compilation, and we require per-thread scratch.
unsafe impl Sync for VsStreamDb {}

// SAFETY: hs_database_t is immutable after compilation, and we require per-thread scratch.
unsafe impl Send for VsGateDb {}
// SAFETY: hs_database_t is immutable after compilation, and we require per-thread scratch.
unsafe impl Sync for VsGateDb {}

impl Drop for VsStreamDb {
    fn drop(&mut self) {
        // SAFETY: `self.db` was allocated by `hs_compile_multi` (or deserialized)
        // and is only freed once here; the null check guards against double-free.
        unsafe {
            if !self.db.is_null() {
                vs::hs_free_database(self.db);
            }
        }
    }
}

impl Drop for VsGateDb {
    fn drop(&mut self) {
        // SAFETY: `self.db` was allocated by `hs_compile_multi` (or deserialized)
        // and is only freed once here; the null check guards against double-free.
        unsafe {
            if !self.db.is_null() {
                vs::hs_free_database(self.db);
            }
        }
    }
}

// SAFETY: hs_database_t is immutable after compilation, and we require per-thread scratch.
unsafe impl Send for VsPrefilterDb {}
// SAFETY: hs_database_t is immutable after compilation, and we require per-thread scratch.
unsafe impl Sync for VsPrefilterDb {}

impl Drop for VsPrefilterDb {
    fn drop(&mut self) {
        // SAFETY: `self.db` was allocated by `hs_compile_multi` (or deserialized)
        // and is only freed once here; the null check guards against double-free.
        unsafe {
            if !self.db.is_null() {
                vs::hs_free_database(self.db);
            }
        }
    }
}

/// Per-thread Vectorscan scratch space bound to a specific database.
///
/// This must only be used with the database it was allocated for and must not
/// be used concurrently from multiple threads. Dropping it releases the
/// underlying `hs_scratch_t`.
pub(crate) struct VsScratch {
    /// Opaque Vectorscan scratch handle (must not be shared across threads).
    scratch: *mut vs::hs_scratch_t,
    /// Database this scratch was allocated for (used for binding validation).
    db: *mut vs::hs_database_t,
}

impl VsScratch {
    /// Returns the database pointer this scratch was allocated for.
    #[inline]
    pub(crate) fn bound_db_ptr(&self) -> *mut vs::hs_database_t {
        self.db
    }
}

// SAFETY: VsScratch exclusively owns its hs_scratch_t allocation.
// Transfer to another thread is safe; concurrent use is not (we don't impl Sync).
// Same ownership model as VsPrefilterDb/VsStreamDb Send impls above.
unsafe impl Send for VsScratch {}

/// Opaque stream handle for stream-mode scanning.
///
/// Must be closed via one of the `close_stream` methods on [`VsStreamDb`],
/// [`VsUtf16StreamDb`], or [`VsGateDb`] to flush end-of-stream matches and
/// free the underlying `hs_stream_t`.
///
/// **There is intentionally no `Drop` impl**: `hs_close_stream` requires a
/// scratch handle and a match callback, so cleanup cannot be done
/// automatically. Callers must ensure `close_stream` is called on every
/// opened stream, even on error paths, to avoid leaking the Vectorscan
/// stream allocation.
pub(crate) struct VsStream {
    /// Opaque Vectorscan stream handle.
    stream: *mut vs::hs_stream_t,
}

impl VsStreamDb {
    /// Build a stream-mode database for decoded-byte scanning.
    ///
    /// Uses `hs_expression_info` to estimate match width; a zero width is
    /// treated as unbounded and capped by `max_decoded_cap` when nonzero.
    /// Patterns are compiled with `HS_FLAG_PREFILTER`; hits are conservative
    /// and used only for window seeding.
    ///
    /// # Errors
    /// Returns an error if any rule pattern contains NUL bytes,
    /// `hs_expression_info` rejects a pattern, or `hs_compile_multi` fails.
    pub(crate) fn try_new_stream(
        rules: &[RuleSpec],
        max_decoded_cap: usize,
    ) -> Result<Self, String> {
        let mut c_patterns: Vec<CString> = Vec::with_capacity(rules.len());
        let mut expr_ptrs: Vec<*const c_char> = Vec::with_capacity(rules.len());
        let mut flags: Vec<c_uint> = Vec::with_capacity(rules.len());
        let mut ids: Vec<c_uint> = Vec::with_capacity(rules.len());
        let mut meta: Vec<VsStreamMeta> = Vec::with_capacity(rules.len());

        for (rid, r) in rules.iter().enumerate() {
            let radius = if let Some(tp) = &r.two_phase {
                tp.full_radius
            } else {
                r.radius
            };

            let radius_u32 = usize_to_u32_saturating(radius);
            let (mut max_width_u32, c_pat) = expression_info_prefilter_max_width(r.re.as_str())?;
            let mut whole_buffer_on_hit = 0u32;
            if max_width_u32 == 0 {
                whole_buffer_on_hit = 1;
                max_width_u32 = u32::MAX;
            }
            if max_width_u32 == u32::MAX {
                let cap = usize_to_u32_saturating(max_decoded_cap);
                if cap > 0 {
                    max_width_u32 = cap;
                }
            }

            meta.push(VsStreamMeta {
                max_width: max_width_u32,
                radius: radius_u32,
                whole_buffer_on_hit,
            });

            c_patterns.push(c_pat);
            expr_ptrs.push(c_patterns.last().unwrap().as_ptr());
            flags.push(vs::HS_FLAG_PREFILTER as c_uint);
            ids.push(rid as c_uint);
        }

        // SAFETY: `hs_platform_info_t` is a plain-data struct (all integer fields)
        // and `MaybeUninit::zeroed()` produces a valid all-zeros representation.
        // `hs_populate_platform` fills it on success; on failure the zeroed value
        // is still a valid `hs_platform_info_t` (Vectorscan treats zero fields as
        // "use defaults"), so `assume_init` is sound in both cases.
        let mut platform = MaybeUninit::<vs::hs_platform_info_t>::zeroed();
        // SAFETY: `platform` is a valid `MaybeUninit` pointer; `hs_populate_platform`
        // writes through it and does not retain the pointer after returning.
        unsafe {
            let _ = vs::hs_populate_platform(platform.as_mut_ptr());
        }
        // SAFETY: `hs_platform_info_t` is a plain-data struct; zeroed memory is a valid
        // representation, and `hs_populate_platform` (or the zeroed fallback) initializes it.
        let platform = unsafe { platform.assume_init() };

        let cache = VsDbCache::new();
        let cache_key = cache.cache_key(&CacheKeyInput {
            kind: b"vs-stream-db:stream",
            mode: vs::HS_MODE_STREAM as c_uint,
            platform: &platform,
            patterns: &c_patterns,
            flags: Some(&flags),
            ids: &ids,
        });
        if let Some(cached_db) = cache.try_load(&cache_key) {
            return Ok(Self {
                db: cached_db,
                meta,
            });
        }

        let mut db: *mut vs::hs_database_t = ptr::null_mut();
        let mut compile_err: *mut vs::hs_compile_error_t = ptr::null_mut();
        // SAFETY: all pointer arrays (`expr_ptrs`, `flags`, `ids`) are valid for
        // `expr_ptrs.len()` elements and live for the duration of the call; `db`
        // and `compile_err` are valid out-pointers written by the FFI function.
        let rc = unsafe {
            vs::hs_compile_multi(
                expr_ptrs.as_ptr(),
                flags.as_ptr(),
                ids.as_ptr(),
                expr_ptrs.len() as c_uint,
                vs::HS_MODE_STREAM as c_uint,
                &platform as *const vs::hs_platform_info_t,
                &mut db as *mut *mut vs::hs_database_t,
                &mut compile_err as *mut *mut vs::hs_compile_error_t,
            )
        };

        if rc != vs::HS_SUCCESS as c_int {
            // SAFETY: `compile_err` was written by `hs_compile_multi` on failure;
            // the pointer and its `message` field are valid until `hs_free_compile_error`.
            let msg = unsafe {
                if compile_err.is_null() {
                    "hs_compile_multi failed (no error message)".to_string()
                } else {
                    let s = if (*compile_err).message.is_null() {
                        "hs_compile_multi failed (null error message)".to_string()
                    } else {
                        let cstr = std::ffi::CStr::from_ptr((*compile_err).message);
                        format!(
                            "hs_compile_multi failed at expression {}: {}",
                            (*compile_err).expression,
                            cstr.to_string_lossy()
                        )
                    };
                    vs::hs_free_compile_error(compile_err);
                    s
                }
            };
            return Err(msg);
        }

        cache.try_store(&cache_key, db as *const vs::hs_database_t);
        Ok(Self { db, meta })
    }

    /// Allocates a new scratch space bound to this database.
    pub(crate) fn alloc_scratch(&self) -> Result<VsScratch, String> {
        let mut scratch: *mut vs::hs_scratch_t = ptr::null_mut();
        // SAFETY: `self.db` is a valid compiled database; `scratch` is a valid
        // out-pointer. `hs_alloc_scratch` allocates or grows the scratch space.
        let rc =
            unsafe { vs::hs_alloc_scratch(self.db, &mut scratch as *mut *mut vs::hs_scratch_t) };
        if rc != vs::HS_SUCCESS as c_int {
            return Err(format!("hs_alloc_scratch failed: rc={rc}"));
        }
        Ok(VsScratch {
            scratch,
            db: self.db,
        })
    }

    /// Returns per-rule window metadata for stream match processing.
    #[inline]
    pub(crate) fn meta(&self) -> &[VsStreamMeta] {
        &self.meta
    }

    /// Returns the raw database pointer for scratch binding checks.
    #[inline]
    pub(crate) fn db_ptr(&self) -> *mut vs::hs_database_t {
        self.db
    }

    /// Opens a new stream handle bound to this database.
    ///
    /// The caller **must** call [`Self::close_stream`] on the returned handle
    /// to flush end-of-stream matches and free the underlying allocation.
    /// See [`VsStream`] for lifecycle details.
    pub(crate) fn open_stream(&self) -> Result<VsStream, String> {
        let mut stream: *mut vs::hs_stream_t = ptr::null_mut();
        // SAFETY: `self.db` is a valid compiled stream-mode database; `stream`
        // is a valid out-pointer written by the FFI function.
        let rc = unsafe { vs::hs_open_stream(self.db, 0, &mut stream) };
        if rc != vs::HS_SUCCESS as c_int {
            return Err(format!("hs_open_stream failed: rc={rc}"));
        }
        Ok(VsStream { stream })
    }

    /// Scans a stream chunk and delivers matches to `on_event`.
    ///
    /// `scratch` must be allocated for this database; `ctx` must remain valid
    /// for the duration of the call. `HS_SCAN_TERMINATED` is treated as success to
    /// allow early termination in callbacks.
    pub(crate) fn scan_stream(
        &self,
        stream: &mut VsStream,
        data: &[u8],
        scratch: &mut VsScratch,
        on_event: vs::match_event_handler,
        ctx: *mut c_void,
    ) -> Result<(), String> {
        let len_u32: c_uint = data
            .len()
            .try_into()
            .map_err(|_| format!("buffer too large for hs_scan_stream: {} bytes", data.len()))?;
        // SAFETY: `stream.stream` is a valid open stream; `data` is a valid byte
        // slice with length fitting in `u32`; `scratch` is allocated for this db;
        // `ctx` is caller-guaranteed valid for the callback duration.
        let rc = unsafe {
            vs::hs_scan_stream(
                stream.stream,
                data.as_ptr().cast::<c_char>(),
                len_u32,
                0,
                scratch.scratch,
                on_event,
                ctx,
            )
        };
        if rc == vs::HS_SUCCESS as c_int || rc == vs::HS_SCAN_TERMINATED as c_int {
            Ok(())
        } else {
            Err(format!("hs_scan_stream failed: rc={rc}"))
        }
    }

    /// Closes a stream, flushing end-of-stream matches via `on_event`.
    ///
    /// `scratch` must be allocated for this database; `ctx` must remain valid
    /// for the duration of the call.
    pub(crate) fn close_stream(
        &self,
        stream: VsStream,
        scratch: &mut VsScratch,
        on_event: vs::match_event_handler,
        ctx: *mut c_void,
    ) -> Result<(), String> {
        // SAFETY: `stream.stream` is a valid open stream being consumed (moved in);
        // `scratch` is allocated for this db; `ctx` is valid for the callback duration.
        let rc = unsafe { vs::hs_close_stream(stream.stream, scratch.scratch, on_event, ctx) };
        if rc == vs::HS_SUCCESS as c_int {
            Ok(())
        } else {
            Err(format!("hs_close_stream failed: rc={rc}"))
        }
    }
}

/// Stream match event used by decoded-byte scanning (32 bytes, `#[repr(C)]`).
///
/// Produced by Vectorscan stream callbacks and consumed by `decode_stream_and_scan`
/// to drive windowed rule validation on decoded byte streams.
///
/// `lo`/`hi` bound the candidate window (decoded-byte offsets, half-open
/// `[lo, hi)`) to verify.
/// `variant_idx` matches `Variant::idx()`. `force_full` asks the caller to
/// fall back to a full decode scan and ignore `lo`/`hi`.
/// `lo`/`hi` are not clamped to the current stream length; callers must clamp
/// when materializing decode work.
///
/// `anchor_hint` is Vectorscan's `from` match offset, preserved to start regex
/// searches near the anchor instead of at window start.
///
/// # Layout
/// Fields are ordered largest-first (`u64` before `u32` before `u8`) under
/// `#[repr(C)]` to eliminate internal alignment padding (32B vs 40B naive).
#[repr(C)]
pub(crate) struct VsStreamWindow {
    /// Decoded-byte offset of the window start (inclusive).
    pub(crate) lo: u64,
    /// Decoded-byte offset of the window end (exclusive, not clamped).
    pub(crate) hi: u64,
    /// Anchor hint from Vectorscan's `from` offset, clamped to `[lo, to]`.
    pub(crate) anchor_hint: u64,
    /// Rule id that produced this match.
    pub(crate) rule_id: u32,
    /// Variant index matching `Variant::idx()` (0=raw, 1=utf16-le, 2=utf16-be).
    pub(crate) variant_idx: u8,
    /// When `true`, caller should scan the full decoded stream instead of `[lo, hi)`.
    pub(crate) force_full: bool,
    // 2B tail padding
}

const _: () = assert!(std::mem::size_of::<VsStreamWindow>() == 32);

/// Callback context for stream-mode scans on decoded byte streams.
///
/// Unlike `VsUtf16StreamMatchCtx`, this does not include a `base_offset` field
/// because standard stream scanning processes the entire decoded buffer in a
/// single stream, so match offsets are already absolute within that buffer.
///
/// Safety invariants:
/// - `pending_ptr` points to a writable buffer of `pending_cap` windows.
/// - `pending_len` points to the current initialized length in `pending_ptr`.
/// - `meta` points to an array of `meta_len` entries indexed by rule id.
/// - `meta_len` matches the number of compiled rules; ids are expected `< meta_len`.
/// - `max_pending <= pending_cap`.
/// - `overflowed` points to a live byte flag for the duration of the scan (`0`/`1`).
#[repr(C)]
pub(crate) struct VsStreamMatchCtx {
    pub(crate) pending_ptr: *mut VsStreamWindow,
    pub(crate) pending_len: *mut u32,
    pub(crate) pending_cap: u32,
    pub(crate) meta: *const VsStreamMeta,
    pub(crate) meta_len: u32,
    pub(crate) max_pending: u32,
    pub(crate) overflowed: *mut u8,
}

/// Callback context for UTF-16 anchor stream scans.
///
/// Unlike `VsStreamMatchCtx`, this includes a `base_offset` field because UTF-16
/// decoded streams may be processed across multiple chunks, and each scan_stream
/// call reports offsets relative to that chunk. `base_offset` translates those
/// stream-local offsets into absolute positions within the full decoded output.
///
/// Safety invariants:
/// - `targets`/`pat_offsets`/`pat_lens` describe the UTF-16 anchor mapping tables.
/// - `pat_offsets` has length `pat_count + 1` and is monotonically increasing.
/// - `pat_offsets[pat_count]` equals the number of `targets` entries.
/// - `pat_lens` has length `pat_count`.
/// - `base_offset` converts stream-local match offsets into absolute decoded offsets.
/// - `pending_ptr` points to a writable buffer of `pending_cap` windows.
/// - `pending_len` points to the current initialized length in `pending_ptr`.
/// - `max_pending <= pending_cap`.
/// - `overflowed` points to a live byte flag for the duration of the scan (`0`/`1`).
#[repr(C)]
pub(crate) struct VsUtf16StreamMatchCtx {
    pub(crate) pending_ptr: *mut VsStreamWindow,
    pub(crate) pending_len: *mut u32,
    pub(crate) pending_cap: u32,
    pub(crate) targets: *const VsAnchorTarget,
    pub(crate) pat_offsets: *const u32,
    pub(crate) pat_lens: *const u32,
    pub(crate) pat_count: u32,
    pub(crate) base_offset: u64,
    pub(crate) max_pending: u32,
    pub(crate) overflowed: *mut u8,
}

/// Borrowed UTF-16 anchor mapping tables used by stream callbacks.
pub(crate) struct VsUtf16MatchTables<'a> {
    pub(crate) targets: &'a [VsAnchorTarget],
    pub(crate) pat_offsets: &'a [u32],
    pub(crate) pat_lens: &'a [u32],
}

/// Constructs the stream callback context from a pending-window staging buffer.
///
/// `pending` is treated as fixed-capacity storage during callbacks: appends write
/// directly into its allocation via `pending_ptr` and increment `pending_len`.
#[inline(always)]
pub(crate) fn build_stream_match_ctx(
    pending: &mut Vec<VsStreamWindow>,
    pending_len: &mut u32,
    meta: &[VsStreamMeta],
    max_pending: u32,
    overflowed: &mut u8,
) -> VsStreamMatchCtx {
    let pending_cap = u32::try_from(pending.capacity()).unwrap_or(u32::MAX);
    debug_assert!(max_pending <= pending_cap);
    VsStreamMatchCtx {
        pending_ptr: pending.as_mut_ptr(),
        pending_len: (pending_len as *mut u32),
        pending_cap,
        meta: meta.as_ptr(),
        meta_len: meta.len() as u32,
        max_pending,
        overflowed: (overflowed as *mut u8),
    }
}

/// Constructs the UTF-16 stream callback context from the shared pending-window
/// staging buffer and UTF-16 mapping tables.
///
/// Like [`build_stream_match_ctx`], `pending` is treated as fixed-capacity
/// storage during callbacks: appends write directly into its allocation via
/// `pending_ptr` and increment `pending_len`. The caller must not reallocate
/// `pending` while the returned context is in use.
#[inline(always)]
pub(crate) fn build_utf16_stream_match_ctx(
    pending: &mut Vec<VsStreamWindow>,
    pending_len: &mut u32,
    tables: VsUtf16MatchTables<'_>,
    base_offset: u64,
    max_pending: u32,
    overflowed: &mut u8,
) -> VsUtf16StreamMatchCtx {
    let pending_cap = u32::try_from(pending.capacity()).unwrap_or(u32::MAX);
    debug_assert!(max_pending <= pending_cap);
    VsUtf16StreamMatchCtx {
        pending_ptr: pending.as_mut_ptr(),
        pending_len: (pending_len as *mut u32),
        pending_cap,
        targets: tables.targets.as_ptr(),
        pat_offsets: tables.pat_offsets.as_ptr(),
        pat_lens: tables.pat_lens.as_ptr(),
        pat_count: tables.pat_lens.len() as u32,
        base_offset,
        max_pending,
        overflowed: (overflowed as *mut u8),
    }
}

/// Appends a callback-produced window without triggering `Vec` growth.
///
/// Returns `true` if the window was appended, `false` if the buffer is full
/// (at `max_pending` or `pending_cap`). On `false`, sets `*overflowed = 1`
/// when the pointer is non-null, signalling callers to fall back to a
/// whole-buffer scan.
///
/// # Safety
/// - `pending_ptr` must point to a writable allocation of `pending_cap` windows.
/// - `pending_len` must be a valid pointer to the initialized count for `pending_ptr`.
/// - `overflowed` must be null or point to a writable `u8` flag.
/// - No concurrent access to `pending_ptr`/`pending_len` may occur.
#[inline(always)]
unsafe fn push_stream_window_bounded(
    pending_ptr: *mut VsStreamWindow,
    pending_len: *mut u32,
    pending_cap: u32,
    max_pending: u32,
    overflowed: *mut u8,
    win: VsStreamWindow,
) -> bool {
    debug_assert!(!pending_ptr.is_null());
    debug_assert!(!pending_len.is_null());
    // SAFETY: Caller guarantees `pending_len` is a valid, aligned, dereferenceable pointer.
    let len = unsafe { *pending_len };
    if len >= max_pending || len >= pending_cap {
        if !overflowed.is_null() {
            // SAFETY: Caller guarantees `overflowed` is valid when non-null.
            unsafe { *overflowed = 1 };
        }
        return false;
    }
    // `len < max_pending` and `len < pending_cap` from the guard above,
    // so `len + 1 <= pending_cap <= u32::MAX` — no overflow.
    debug_assert!(len < u32::MAX, "pending_len would overflow u32");
    // SAFETY: `len < pending_cap`, so `pending_ptr.add(len)` is within the
    // allocation. `pending_len` is valid and writable (caller invariant).
    unsafe {
        pending_ptr.add(len as usize).write(win);
        *pending_len = len + 1;
    }
    true
}

/// Stream-mode match callback. Pushes window seeds into `pending`.
///
/// # Safety
/// - `ctx` must be non-null and point to a valid `VsStreamMatchCtx`.
/// - `pending_ptr`/`pending_len`/`meta` must outlive the call and not be
///   accessed concurrently.
/// - This callback must never panic or unwind across the FFI boundary.
unsafe extern "C" fn vs_on_stream_match(
    id: c_uint,
    from: u64,
    to: u64,
    _flags: c_uint,
    ctx: *mut c_void,
) -> c_int {
    if ctx.is_null() {
        return 0;
    }
    let c = &mut *(ctx as *mut VsStreamMatchCtx);
    // SAFETY: `c.overflowed` is a valid pointer when non-null (caller invariant).
    if !c.overflowed.is_null() && unsafe { *c.overflowed } != 0 {
        return 1;
    }
    if id >= c.meta_len {
        return 0;
    }
    let meta = *c.meta.add(id as usize);
    if meta.whole_buffer_on_hit != 0 {
        if !push_stream_window_bounded(
            c.pending_ptr,
            c.pending_len,
            c.pending_cap,
            c.max_pending,
            c.overflowed,
            VsStreamWindow {
                rule_id: id,
                lo: 0,
                hi: 0,
                variant_idx: 0,
                force_full: true,
                anchor_hint: from,
            },
        ) {
            return 1;
        }
        return 0;
    }
    let max_width = meta.max_width as u64;
    let radius = meta.radius as u64;
    let lo = to.saturating_sub(max_width.saturating_add(radius));
    let hi = to.saturating_add(radius);

    // Clamp anchor hint to window bounds.
    let anchor_hint = clamp_u64_ordered(from, lo, to);

    if !push_stream_window_bounded(
        c.pending_ptr,
        c.pending_len,
        c.pending_cap,
        c.max_pending,
        c.overflowed,
        VsStreamWindow {
            rule_id: id,
            lo,
            hi,
            variant_idx: 0,
            force_full: false,
            anchor_hint,
        },
    ) {
        return 1;
    }
    0
}

/// Returns the stream-mode match callback for decoded-byte scanning.
///
/// The callback expects a `*mut VsStreamMatchCtx` as the `ctx` parameter.
pub(crate) fn stream_match_callback() -> vs::match_event_handler {
    Some(vs_on_stream_match)
}

/// Decoded-space gate callback. Marks a hit and continues scanning.
///
/// # Safety
/// - `ctx` must point to a valid `u8` flag for the duration of the call.
/// - This callback must never panic or unwind across the FFI boundary.
unsafe extern "C" fn vs_gate_on_match(
    _id: c_uint,
    _from: u64,
    _to: u64,
    _flags: c_uint,
    ctx: *mut c_void,
) -> c_int {
    if ctx.is_null() {
        return 0;
    }
    let hit = &mut *(ctx as *mut u8);
    *hit = 1;
    0
}

/// Returns the decoded-space gate callback.
///
/// The callback expects a `*mut u8` flag as the `ctx` parameter; it sets the
/// flag to `1` on any match.
pub(crate) fn gate_match_callback() -> vs::match_event_handler {
    Some(vs_gate_on_match)
}

/// UTF-16 stream match callback. Seeds UTF-16 variant windows into `pending`.
///
/// Converts stream-local match offsets into absolute decoded offsets using
/// `base_offset`.
///
/// # Safety
/// - `ctx` must point to a valid `VsUtf16StreamMatchCtx`.
/// - `pending_ptr`/`pending_len` and UTF-16 mapping tables must outlive the call
///   and not be accessed concurrently.
/// - This callback must never panic or unwind across the FFI boundary.
unsafe extern "C" fn vs_utf16_stream_on_match(
    id: c_uint,
    from: u64,
    to: u64,
    _flags: c_uint,
    ctx: *mut c_void,
) -> c_int {
    if ctx.is_null() {
        return 0;
    }
    let c = &mut *(ctx as *mut VsUtf16StreamMatchCtx);
    // SAFETY: `c.overflowed` is a valid pointer when non-null (caller invariant).
    if !c.overflowed.is_null() && unsafe { *c.overflowed } != 0 {
        return 1;
    }
    if id >= c.pat_count {
        return 0;
    }

    let pid = id as usize;
    let len = *c.pat_lens.add(pid) as u64;
    let end = c.base_offset.saturating_add(to);
    let start = end.saturating_sub(len);

    // Compute absolute anchor hint from base_offset + from.
    let abs_from = c.base_offset.saturating_add(from);

    let off_start = *c.pat_offsets.add(pid) as usize;
    let off_end = *c.pat_offsets.add(pid + 1) as usize;

    for i in off_start..off_end {
        let target = *c.targets.add(i);
        let seed = target.seed_radius_bytes as u64;
        let lo = start.saturating_sub(seed);
        let hi = end.saturating_add(seed);
        // Clamp anchor hint to window bounds.
        let anchor_hint = clamp_u64_ordered(abs_from, lo, end);
        if !push_stream_window_bounded(
            c.pending_ptr,
            c.pending_len,
            c.pending_cap,
            c.max_pending,
            c.overflowed,
            VsStreamWindow {
                rule_id: target.rule_id,
                lo,
                hi,
                variant_idx: target.variant_idx,
                force_full: false,
                anchor_hint,
            },
        ) {
            return 1;
        }
    }
    0
}

/// Clamps `v` into `[lo, hi]`. Requires `lo <= hi` (debug-asserted).
///
/// Used in FFI callbacks where panicking is undefined behavior. Unlike
/// `Ord::clamp()`, which uses `assert!(min <= max)` and can unwind across
/// the FFI boundary, this uses `debug_assert!` — the panic path is elided
/// in release builds, making the function safe for `extern "C"` callbacks.
#[inline(always)]
fn clamp_u32_ordered(v: u32, lo: u32, hi: u32) -> u32 {
    debug_assert!(lo <= hi);
    if v < lo {
        lo
    } else if v > hi {
        hi
    } else {
        v
    }
}

/// Clamps `v` into `[lo, hi]`. Requires `lo <= hi` (debug-asserted).
///
/// 64-bit variant for stream-mode callbacks where offsets are `u64`.
/// See [`clamp_u32_ordered`] for the FFI safety rationale.
#[inline(always)]
fn clamp_u64_ordered(v: u64, lo: u64, hi: u64) -> u64 {
    debug_assert!(lo <= hi);
    if v < lo {
        lo
    } else if v > hi {
        hi
    } else {
        v
    }
}

/// Returns the UTF-16 stream-mode match callback for anchor scanning.
///
/// The callback expects a `*mut VsUtf16StreamMatchCtx` as the `ctx` parameter.
pub(crate) fn utf16_stream_match_callback() -> vs::match_event_handler {
    Some(vs_utf16_stream_on_match)
}

/// Mapping from UTF-16 anchor patterns to rule/variant targets.
///
/// `seed_radius_bytes` is the extra padding (raw bytes, in the UTF-16 byte
/// stream) applied around the matched anchor when seeding windows.
/// `variant_idx` matches `Variant::idx()` (0=raw, 1=utf16-le, 2=utf16-be).
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct VsAnchorTarget {
    rule_id: u32,
    variant_idx: u8,
    seed_radius_bytes: u32,
}

/// Inputs describing anchor literal patterns and their target rules.
///
/// `patterns` holds raw byte patterns (raw and/or UTF-16-encoded). `pat_targets`
/// is a flat list of rule/variant targets, and `pat_offsets` is a prefix-sum
/// table mapping each pattern to its target slice.
///
/// `seed_radius_raw` and `seed_radius_utf16` are indexed by rule id and used
/// based on each target's variant.
///
/// Expected shape (defensively validated):
/// - `pat_offsets.len()` should be `patterns.len() + 1`, with the last offset
///   equal to `pat_targets.len()`.
/// - Out-of-range offsets are treated as empty ranges.
/// - Missing `seed_radius_*` entries default to zero padding.
pub(crate) struct AnchorInput<'a> {
    pub(crate) patterns: &'a [Vec<u8>],
    pub(crate) pat_targets: &'a [Target],
    pub(crate) pat_offsets: &'a [u32],
    pub(crate) seed_radius_raw: &'a [u32],
    pub(crate) seed_radius_utf16: &'a [u32],
}

/// Intermediate anchor pattern data for database compilation.
///
/// Produced by `build_anchor_data` after filtering empty patterns and
/// compacting offset tables. Consumed by `VsAnchorDb` and `VsUtf16StreamDb`
/// constructors.
struct AnchorData {
    /// Compiled literal patterns as `\xNN` regex strings.
    patterns: Vec<CString>,
    /// Per-target rule/variant mapping with seed radius.
    targets: Vec<VsAnchorTarget>,
    /// Prefix-sum offsets into `targets` for each pattern.
    pat_offsets: Vec<u32>,
    /// Length in bytes of each pattern.
    pat_lens: Vec<u32>,
}

/// Builds the filtered pattern table and target mappings for anchor literals.
///
/// Empty patterns are dropped, offsets are compacted, and out-of-range target
/// ranges are ignored. Each surviving pattern is encoded as a `\xNN` literal
/// byte regex so Vectorscan treats it as a raw-byte match. When `debug` is
/// true, basic pattern stats are logged.
///
/// # Errors
/// Returns an error if no non-empty patterns remain or if pattern encoding fails.
fn build_anchor_data(
    patterns: &[Vec<u8>],
    pat_targets: &[Target],
    pat_offsets: &[u32],
    seed_radius_raw: &[u32],
    seed_radius_utf16: &[u32],
    debug: bool,
) -> Result<AnchorData, String> {
    if patterns.is_empty() {
        return Err("no anchor patterns".to_string());
    }
    let mut filtered_patterns: Vec<&[u8]> = Vec::with_capacity(patterns.len());
    let mut filtered_offsets: Vec<u32> = Vec::with_capacity(pat_offsets.len());
    let mut filtered_targets: Vec<Target> = Vec::with_capacity(pat_targets.len());

    filtered_offsets.push(0);
    for (pid, pat) in patterns.iter().enumerate() {
        if pat.is_empty() {
            continue;
        }
        let off_start = *pat_offsets.get(pid).unwrap_or(&0) as usize;
        let off_end = *pat_offsets.get(pid + 1).unwrap_or(&0) as usize;
        if off_start < off_end && off_end <= pat_targets.len() {
            filtered_targets.extend_from_slice(&pat_targets[off_start..off_end]);
        }
        filtered_patterns.push(pat.as_slice());
        filtered_offsets.push(filtered_targets.len() as u32);
    }

    if filtered_patterns.is_empty() {
        return Err("no non-empty anchor patterns".to_string());
    }

    if debug {
        let mut zero_len = 0usize;
        let mut leading_nul = 0usize;
        let mut min_len = usize::MAX;
        let mut max_len = 0usize;
        for pat in &filtered_patterns {
            let len = pat.len();
            if len == 0 {
                zero_len = zero_len.saturating_add(1);
            }
            if matches!(pat.first(), Some(0)) {
                leading_nul = leading_nul.saturating_add(1);
            }
            min_len = min_len.min(len);
            max_len = max_len.max(len);
        }
        if min_len == usize::MAX {
            min_len = 0;
        }
        let first = filtered_patterns.first().unwrap();
        eprintln!(
            "vectorscan anchor db build: patterns={} zero_len={} leading_nul={} min_len={} max_len={} first_len={} first_byte={}",
            filtered_patterns.len(),
            zero_len,
            leading_nul,
            min_len,
            max_len,
            first.len(),
            first.first().copied().unwrap_or(0),
        );
    }

    let mut c_patterns: Vec<CString> = Vec::with_capacity(filtered_patterns.len());
    for pat in &filtered_patterns {
        let mut expr = String::with_capacity(pat.len().saturating_mul(4));
        for b in *pat {
            use std::fmt::Write;
            let _ = write!(expr, "\\x{b:02X}");
        }
        let c_pat =
            CString::new(expr).map_err(|_| "anchor pattern contains unexpected NUL".to_string())?;
        c_patterns.push(c_pat);
    }

    let mut targets = Vec::with_capacity(filtered_targets.len());
    for t in &filtered_targets {
        let rule_id = t.rule_id() as u32;
        let variant = t.variant();
        let variant_idx = variant.idx() as u8;
        let seed_radius_bytes = match variant {
            Variant::Raw => *seed_radius_raw.get(rule_id as usize).unwrap_or(&0),
            Variant::Utf16Le | Variant::Utf16Be => {
                *seed_radius_utf16.get(rule_id as usize).unwrap_or(&0)
            }
        };
        targets.push(VsAnchorTarget {
            rule_id,
            variant_idx,
            seed_radius_bytes,
        });
    }

    let mut pat_lens = Vec::with_capacity(filtered_patterns.len());
    for pat in &filtered_patterns {
        pat_lens.push(usize_to_u32_saturating(pat.len()));
    }

    Ok(AnchorData {
        patterns: c_patterns,
        targets,
        pat_offsets: filtered_offsets,
        pat_lens,
    })
}

/// Vectorscan database for UTF-16 anchor prefiltering.
///
/// Patterns are literal bytes (encoded as `\xNN` regexes); matches are expanded
/// into rule/variant windows using the `targets` mapping.
/// `pat_offsets` is a prefix-sum table: pattern `i` maps to
/// `targets[pat_offsets[i]..pat_offsets[i + 1]]`.
/// Window offsets are in raw-byte coordinates of the scanned buffer.
pub(crate) struct VsAnchorDb {
    /// Compiled Vectorscan block-mode database.
    db: *mut vs::hs_database_t,
    /// Rule/variant targets for each anchor pattern.
    targets: Vec<VsAnchorTarget>,
    /// Prefix-sum offsets into `targets` for each pattern.
    pat_offsets: Vec<u32>,
    /// Byte length of each anchor pattern.
    pat_lens: Vec<u32>,
}

/// Vectorscan stream database for UTF-16 anchor scanning.
///
/// Uses the same mapping tables as `VsAnchorDb`, but runs in stream mode and
/// emits `VsStreamWindow` entries via the UTF-16 stream callback.
/// Window offsets are in decoded-byte coordinates of the stream output.
pub(crate) struct VsUtf16StreamDb {
    /// Compiled Vectorscan stream-mode database.
    db: *mut vs::hs_database_t,
    /// Rule/variant targets for each anchor pattern.
    targets: Vec<VsAnchorTarget>,
    /// Prefix-sum offsets into `targets` for each pattern.
    pat_offsets: Vec<u32>,
    /// Byte length of each anchor pattern.
    pat_lens: Vec<u32>,
}

// SAFETY: hs_database_t is immutable after compilation, and we require per-thread scratch.
unsafe impl Send for VsUtf16StreamDb {}
// SAFETY: hs_database_t is immutable after compilation, and we require per-thread scratch.
unsafe impl Sync for VsUtf16StreamDb {}

impl Drop for VsUtf16StreamDb {
    fn drop(&mut self) {
        // SAFETY: `self.db` was allocated by `hs_compile_multi` (or deserialized)
        // and is only freed once here; the null check guards against double-free.
        unsafe {
            if !self.db.is_null() {
                vs::hs_free_database(self.db);
            }
        }
    }
}

// SAFETY: hs_database_t is immutable after compilation, and we require per-thread scratch.
unsafe impl Send for VsAnchorDb {}
// SAFETY: hs_database_t is immutable after compilation, and we require per-thread scratch.
unsafe impl Sync for VsAnchorDb {}

impl Drop for VsAnchorDb {
    fn drop(&mut self) {
        // SAFETY: `self.db` was allocated by `hs_compile_multi` (or deserialized)
        // and is only freed once here; the null check guards against double-free.
        unsafe {
            if !self.db.is_null() {
                vs::hs_free_database(self.db);
            }
        }
    }
}

impl VsAnchorDb {
    /// Builds the UTF-16 anchor database and mapping tables.
    ///
    /// Empty patterns are filtered out; offsets are compacted accordingly.
    /// Each remaining pattern is compiled as a literal byte regex.
    /// Out-of-range offsets are ignored, yielding zero targets for that pattern.
    /// If `SCANNER_VS_UTF16_DEBUG` is set, basic pattern stats are logged.
    ///
    /// # Errors
    /// Returns an error if there are no non-empty patterns or if compilation fails.
    pub(crate) fn try_new_utf16(
        patterns: &[Vec<u8>],
        pat_targets: &[Target],
        pat_offsets: &[u32],
        seed_radius_raw: &[u32],
        seed_radius_utf16: &[u32],
    ) -> Result<Self, String> {
        let debug = std::env::var("SCANNER_VS_UTF16_DEBUG").is_ok();
        let data = build_anchor_data(
            patterns,
            pat_targets,
            pat_offsets,
            seed_radius_raw,
            seed_radius_utf16,
            debug,
        )?;

        let mut expr_ptrs: Vec<*const c_char> = Vec::with_capacity(data.patterns.len());
        let mut ids: Vec<c_uint> = Vec::with_capacity(data.patterns.len());

        for (id, pat) in data.patterns.iter().enumerate() {
            expr_ptrs.push(pat.as_ptr());
            ids.push(id as c_uint);
        }

        // SAFETY: see `VsStreamDb::try_new_stream` for the zeroed-platform rationale.
        let mut platform = MaybeUninit::<vs::hs_platform_info_t>::zeroed();
        // SAFETY: `platform` is a valid `MaybeUninit` pointer; `hs_populate_platform`
        // writes through it and does not retain the pointer after returning.
        unsafe {
            let _ = vs::hs_populate_platform(platform.as_mut_ptr());
        }
        // SAFETY: zeroed `hs_platform_info_t` is valid, and `hs_populate_platform`
        // (or the zeroed fallback) fully initializes it.
        let platform = unsafe { platform.assume_init() };

        let cache = VsDbCache::new();
        let cache_key = cache.cache_key(&CacheKeyInput {
            kind: b"vs-anchor-db:block",
            mode: vs::HS_MODE_BLOCK as c_uint,
            platform: &platform,
            patterns: &data.patterns,
            flags: None,
            ids: &ids,
        });
        if let Some(cached_db) = cache.try_load(&cache_key) {
            return Ok(Self {
                db: cached_db,
                targets: data.targets,
                pat_offsets: data.pat_offsets,
                pat_lens: data.pat_lens,
            });
        }

        let mut db: *mut vs::hs_database_t = ptr::null_mut();
        let mut compile_err: *mut vs::hs_compile_error_t = ptr::null_mut();

        if debug {
            eprintln!(
                "vectorscan utf16 db build: using regex compiler for {} patterns",
                expr_ptrs.len()
            );
        }

        // SAFETY: all pointer arrays (`expr_ptrs`, `ids`) are valid for
        // `expr_ptrs.len()` elements and live for the duration of the call; `db`
        // and `compile_err` are valid out-pointers written by the FFI function.
        let rc = unsafe {
            vs::hs_compile_multi(
                expr_ptrs.as_ptr(),
                ptr::null(),
                ids.as_ptr(),
                expr_ptrs.len() as c_uint,
                vs::HS_MODE_BLOCK as c_uint,
                &platform as *const vs::hs_platform_info_t,
                &mut db as *mut *mut vs::hs_database_t,
                &mut compile_err as *mut *mut vs::hs_compile_error_t,
            )
        };

        if rc != vs::HS_SUCCESS as c_int {
            // SAFETY: `compile_err` was populated by `hs_compile_multi`; if non-null it
            // points to a valid `hs_compile_error_t` that we read and then free.
            let msg = unsafe {
                if compile_err.is_null() {
                    "hs_compile_multi failed (no error message)".to_string()
                } else {
                    let s = if (*compile_err).message.is_null() {
                        "hs_compile_multi failed (null error message)".to_string()
                    } else {
                        let cstr = std::ffi::CStr::from_ptr((*compile_err).message);
                        format!(
                            "hs_compile_multi failed at expression {}: {}",
                            (*compile_err).expression,
                            cstr.to_string_lossy()
                        )
                    };
                    vs::hs_free_compile_error(compile_err);
                    s
                }
            };
            return Err(msg);
        }

        cache.try_store(&cache_key, db as *const vs::hs_database_t);
        Ok(Self {
            db,
            targets: data.targets,
            pat_offsets: data.pat_offsets,
            pat_lens: data.pat_lens,
        })
    }

    /// Allocates a new scratch space bound to this anchor database.
    pub(crate) fn alloc_scratch(&self) -> Result<VsScratch, String> {
        let mut scratch: *mut vs::hs_scratch_t = ptr::null_mut();
        // SAFETY: `self.db` is a valid compiled Vectorscan database; `scratch` is
        // a valid out-pointer. Vectorscan allocates scratch internally.
        let rc =
            unsafe { vs::hs_alloc_scratch(self.db, &mut scratch as *mut *mut vs::hs_scratch_t) };
        if rc != vs::HS_SUCCESS as c_int {
            return Err(format!("hs_alloc_scratch failed: rc={rc}"));
        }
        Ok(VsScratch {
            scratch,
            db: self.db,
        })
    }

    /// Returns the raw database pointer for scratch binding checks.
    #[inline]
    pub(crate) fn db_ptr(&self) -> *mut vs::hs_database_t {
        self.db
    }

    /// Scans raw bytes for UTF-16 anchor hits and seeds per-variant windows.
    ///
    /// The callback performs window math using the precomputed target mapping.
    /// `vs_scratch` must be allocated for this database and not shared across
    /// threads; `scratch` must not be accessed concurrently. Window ends are
    /// clamped to the haystack length, and per-(rule, variant) hits are capped to
    /// `max_hits_per_rule_variant`.
    pub(crate) fn scan_utf16(
        &self,
        hay: &[u8],
        scratch: &mut ScanScratch,
        vs_scratch: &mut VsScratch,
    ) -> Result<bool, String> {
        let len_u32: c_uint = hay
            .len()
            .try_into()
            .map_err(|_| format!("buffer too large for hs_scan: {} bytes", hay.len()))?;

        let mut ctx = VsAnchorMatchCtx {
            scratch: scratch as *mut ScanScratch,
            targets: self.targets.as_ptr(),
            pat_offsets: self.pat_offsets.as_ptr(),
            pat_lens: self.pat_lens.as_ptr(),
            pat_count: self.pat_lens.len() as u32,
            hay_len: len_u32,
            saw_utf16: false,
        };

        // SAFETY: `self.db` is a valid compiled database; `hay` is a live slice with
        // length `len_u32`; `vs_scratch` is allocated for this database; `ctx` is a
        // valid `VsAnchorMatchCtx` that outlives the scan. The callback
        // `vs_anchor_on_match` upholds the FFI contract (no panics, no unwind).
        let rc = unsafe {
            vs::hs_scan(
                self.db,
                hay.as_ptr().cast::<c_char>(),
                len_u32,
                0,
                vs_scratch.scratch,
                Some(vs_anchor_on_match),
                (&mut ctx as *mut VsAnchorMatchCtx).cast::<c_void>(),
            )
        };

        if rc == vs::HS_SUCCESS as c_int || rc == vs::HS_SCAN_TERMINATED as c_int {
            Ok(ctx.saw_utf16)
        } else {
            Err(format!("hs_scan failed: rc={rc}"))
        }
    }
}

impl VsUtf16StreamDb {
    /// Builds the UTF-16 anchor stream database and mapping tables.
    ///
    /// Empty patterns are filtered out; offsets are compacted accordingly.
    /// Each remaining pattern is compiled as a literal byte regex.
    /// Out-of-range offsets are ignored, yielding zero targets for that pattern.
    /// If `SCANNER_VS_UTF16_DEBUG` is set, basic pattern stats are logged.
    ///
    /// # Errors
    /// Returns an error if there are no non-empty patterns or if compilation fails.
    pub(crate) fn try_new_utf16_stream(
        patterns: &[Vec<u8>],
        pat_targets: &[Target],
        pat_offsets: &[u32],
        seed_radius_raw: &[u32],
        seed_radius_utf16: &[u32],
    ) -> Result<Self, String> {
        let debug = std::env::var("SCANNER_VS_UTF16_DEBUG").is_ok();
        let data = build_anchor_data(
            patterns,
            pat_targets,
            pat_offsets,
            seed_radius_raw,
            seed_radius_utf16,
            debug,
        )?;

        let mut expr_ptrs: Vec<*const c_char> = Vec::with_capacity(data.patterns.len());
        let mut ids: Vec<c_uint> = Vec::with_capacity(data.patterns.len());

        for (id, pat) in data.patterns.iter().enumerate() {
            expr_ptrs.push(pat.as_ptr());
            ids.push(id as c_uint);
        }

        let mut platform = MaybeUninit::<vs::hs_platform_info_t>::zeroed();
        // SAFETY: `hs_populate_platform` writes CPU feature fields into the
        // provided pointer. The `MaybeUninit` allocation is valid and
        // properly aligned; see `VsStreamDb::try_new_stream` for rationale.
        unsafe {
            let _ = vs::hs_populate_platform(platform.as_mut_ptr());
        }
        // SAFETY: `hs_populate_platform` wrote all fields; the zeroed base
        // ensures any untouched padding is deterministic.
        let platform = unsafe { platform.assume_init() };

        let cache = VsDbCache::new();
        let cache_key = cache.cache_key(&CacheKeyInput {
            kind: b"vs-utf16-stream-db:stream",
            mode: vs::HS_MODE_STREAM as c_uint,
            platform: &platform,
            patterns: &data.patterns,
            flags: None,
            ids: &ids,
        });
        if let Some(cached_db) = cache.try_load(&cache_key) {
            return Ok(Self {
                db: cached_db,
                targets: data.targets,
                pat_offsets: data.pat_offsets,
                pat_lens: data.pat_lens,
            });
        }

        let mut db: *mut vs::hs_database_t = ptr::null_mut();
        let mut compile_err: *mut vs::hs_compile_error_t = ptr::null_mut();

        // SAFETY: All pointer arrays (`expr_ptrs`, `ids`) are valid, non-null,
        // and contain `expr_ptrs.len()` elements. `db` and `compile_err` are valid
        // out-pointers. The platform struct is fully initialized.
        let rc = unsafe {
            vs::hs_compile_multi(
                expr_ptrs.as_ptr(),
                ptr::null(),
                ids.as_ptr(),
                expr_ptrs.len() as c_uint,
                vs::HS_MODE_STREAM as c_uint,
                &platform as *const vs::hs_platform_info_t,
                &mut db as *mut *mut vs::hs_database_t,
                &mut compile_err as *mut *mut vs::hs_compile_error_t,
            )
        };

        if rc != vs::HS_SUCCESS as c_int {
            // SAFETY: `compile_err` was populated by `hs_compile_multi`; if non-null it
            // points to a valid `hs_compile_error_t` that we read and then free.
            let msg = unsafe {
                if compile_err.is_null() {
                    "hs_compile_multi failed (no error message)".to_string()
                } else {
                    let s = if (*compile_err).message.is_null() {
                        "hs_compile_multi failed (null error message)".to_string()
                    } else {
                        let cstr = std::ffi::CStr::from_ptr((*compile_err).message);
                        format!(
                            "hs_compile_multi failed at expression {}: {}",
                            (*compile_err).expression,
                            cstr.to_string_lossy()
                        )
                    };
                    vs::hs_free_compile_error(compile_err);
                    s
                }
            };
            return Err(msg);
        }

        cache.try_store(&cache_key, db as *const vs::hs_database_t);
        Ok(Self {
            db,
            targets: data.targets,
            pat_offsets: data.pat_offsets,
            pat_lens: data.pat_lens,
        })
    }

    /// Allocates a new scratch space bound to this UTF-16 stream database.
    pub(crate) fn alloc_scratch(&self) -> Result<VsScratch, String> {
        let mut scratch: *mut vs::hs_scratch_t = ptr::null_mut();
        // SAFETY: `self.db` is a valid compiled Vectorscan database; `scratch` is
        // a valid out-pointer. Vectorscan allocates scratch internally.
        let rc =
            unsafe { vs::hs_alloc_scratch(self.db, &mut scratch as *mut *mut vs::hs_scratch_t) };
        if rc != vs::HS_SUCCESS as c_int {
            return Err(format!("hs_alloc_scratch failed: rc={rc}"));
        }
        Ok(VsScratch {
            scratch,
            db: self.db,
        })
    }

    /// Returns the rule/variant target mapping for anchor patterns.
    #[inline]
    pub(crate) fn targets(&self) -> &[VsAnchorTarget] {
        &self.targets
    }

    /// Returns the raw database pointer for scratch binding checks.
    #[inline]
    pub(crate) fn db_ptr(&self) -> *mut vs::hs_database_t {
        self.db
    }

    /// Returns the prefix-sum offset table for pattern-to-target mapping.
    #[inline]
    pub(crate) fn pat_offsets(&self) -> &[u32] {
        &self.pat_offsets
    }

    /// Returns the byte length of each anchor pattern.
    #[inline]
    pub(crate) fn pat_lens(&self) -> &[u32] {
        &self.pat_lens
    }

    /// Opens a new stream handle bound to this database.
    ///
    /// The caller **must** call [`Self::close_stream`] on the returned handle
    /// to flush end-of-stream matches and free the underlying allocation.
    /// See [`VsStream`] for lifecycle details.
    pub(crate) fn open_stream(&self) -> Result<VsStream, String> {
        let mut stream: *mut vs::hs_stream_t = ptr::null_mut();
        // SAFETY: `self.db` is a valid compiled stream-mode database; `stream` is a
        // valid out-pointer. Vectorscan allocates the stream state internally.
        let rc = unsafe { vs::hs_open_stream(self.db, 0, &mut stream) };
        if rc != vs::HS_SUCCESS as c_int {
            return Err(format!("hs_open_stream failed: rc={rc}"));
        }
        Ok(VsStream { stream })
    }

    /// Scans a decoded stream chunk for UTF-16 anchor hits.
    ///
    /// Returns an error if `chunk` exceeds `u32::MAX` bytes (Vectorscan API
    /// constraint). `scratch` must be allocated for this database; `ctx` must
    /// remain valid for the duration of the call. `HS_SCAN_TERMINATED` is
    /// treated as success to allow early termination in callbacks.
    pub(crate) fn scan_stream(
        &self,
        stream: &mut VsStream,
        chunk: &[u8],
        scratch: &mut VsScratch,
        on_event: vs::match_event_handler,
        ctx: *mut c_void,
    ) -> Result<(), String> {
        let len_u32: c_uint = chunk
            .len()
            .try_into()
            .map_err(|_| format!("buffer too large for hs_scan_stream: {} bytes", chunk.len()))?;
        // SAFETY: `stream` is a valid open stream for this database; `chunk` is a
        // live slice with length `len_u32`; `scratch` is allocated for this database.
        // The caller guarantees `ctx` remains valid for the duration of the call.
        let rc = unsafe {
            vs::hs_scan_stream(
                stream.stream,
                chunk.as_ptr().cast::<c_char>(),
                len_u32,
                0,
                scratch.scratch,
                on_event,
                ctx,
            )
        };
        if rc == vs::HS_SUCCESS as c_int || rc == vs::HS_SCAN_TERMINATED as c_int {
            Ok(())
        } else {
            Err(format!("hs_scan_stream failed: rc={rc}"))
        }
    }

    /// Closes a stream, flushing end-of-stream matches via `on_event`.
    ///
    /// Unlike [`VsGateDb::close_stream`], this does **not** treat
    /// `HS_SCAN_TERMINATED` as success — early termination during close is
    /// considered an error for UTF-16 anchor streams because partial flush
    /// can drop match events.
    pub(crate) fn close_stream(
        &self,
        stream: VsStream,
        scratch: &mut VsScratch,
        on_event: vs::match_event_handler,
        ctx: *mut c_void,
    ) -> Result<(), String> {
        // SAFETY: `stream` is a valid open stream; `scratch` is allocated for
        // this database. The caller guarantees `ctx` remains valid for the call.
        // Ownership of `stream` is consumed (freed by Vectorscan).
        let rc = unsafe { vs::hs_close_stream(stream.stream, scratch.scratch, on_event, ctx) };
        if rc == vs::HS_SUCCESS as c_int {
            Ok(())
        } else {
            Err(format!("hs_close_stream failed: rc={rc}"))
        }
    }
}

impl VsGateDb {
    /// Builds a decoded-space gate DB from literal anchor patterns.
    ///
    /// Empty patterns are filtered out. Each remaining pattern is compiled as
    /// a literal byte regex in stream mode.
    ///
    /// # Errors
    /// Returns an error if there are no non-empty patterns or if compilation fails.
    pub(crate) fn try_new_gate(patterns: &[Vec<u8>]) -> Result<Self, String> {
        if patterns.is_empty() {
            return Err("no gate anchor patterns".to_string());
        }

        let mut filtered: Vec<&[u8]> = Vec::with_capacity(patterns.len());
        for pat in patterns {
            if !pat.is_empty() {
                filtered.push(pat.as_slice());
            }
        }
        if filtered.is_empty() {
            return Err("no non-empty gate anchor patterns".to_string());
        }

        let mut c_patterns: Vec<CString> = Vec::with_capacity(filtered.len());
        let mut expr_ptrs: Vec<*const c_char> = Vec::with_capacity(filtered.len());
        let mut flags: Vec<c_uint> = Vec::with_capacity(filtered.len());
        let mut ids: Vec<c_uint> = Vec::with_capacity(filtered.len());

        for (id, pat) in filtered.iter().enumerate() {
            let mut expr = String::with_capacity(pat.len().saturating_mul(4));
            for b in *pat {
                use std::fmt::Write;
                let _ = write!(expr, "\\x{b:02X}");
            }
            let c_pat =
                CString::new(expr).map_err(|_| "gate anchor pattern contains NUL".to_string())?;
            c_patterns.push(c_pat);
            expr_ptrs.push(c_patterns.last().unwrap().as_ptr());
            flags.push(vs::HS_FLAG_SINGLEMATCH as c_uint);
            ids.push(id as c_uint);
        }

        let mut platform = MaybeUninit::<vs::hs_platform_info_t>::zeroed();
        // SAFETY: `hs_populate_platform` writes CPU feature fields into the
        // provided pointer. The `MaybeUninit` allocation is valid and
        // properly aligned; see `VsStreamDb::try_new_stream` for rationale.
        unsafe {
            let _ = vs::hs_populate_platform(platform.as_mut_ptr());
        }
        // SAFETY: `hs_populate_platform` wrote all fields; the zeroed base
        // ensures any untouched padding is deterministic.
        let platform = unsafe { platform.assume_init() };

        let cache = VsDbCache::new();
        let cache_key = cache.cache_key(&CacheKeyInput {
            kind: b"vs-gate-db:stream",
            mode: vs::HS_MODE_STREAM as c_uint,
            platform: &platform,
            patterns: &c_patterns,
            flags: Some(&flags),
            ids: &ids,
        });
        if let Some(cached_db) = cache.try_load(&cache_key) {
            return Ok(Self { db: cached_db });
        }

        let mut db: *mut vs::hs_database_t = ptr::null_mut();
        let mut compile_err: *mut vs::hs_compile_error_t = ptr::null_mut();
        // SAFETY: All pointer arrays (`expr_ptrs`, `flags`, `ids`) are valid,
        // non-null, and contain `expr_ptrs.len()` elements. `db` and `compile_err`
        // are valid out-pointers. The platform struct is fully initialized.
        let rc = unsafe {
            vs::hs_compile_multi(
                expr_ptrs.as_ptr(),
                flags.as_ptr(),
                ids.as_ptr(),
                expr_ptrs.len() as c_uint,
                vs::HS_MODE_STREAM as c_uint,
                &platform as *const vs::hs_platform_info_t,
                &mut db as *mut *mut vs::hs_database_t,
                &mut compile_err as *mut *mut vs::hs_compile_error_t,
            )
        };

        if rc != vs::HS_SUCCESS as c_int {
            // SAFETY: `compile_err` was populated by `hs_compile_multi`; if non-null it
            // points to a valid `hs_compile_error_t` that we read and then free.
            let msg = unsafe {
                if compile_err.is_null() {
                    "hs_compile_multi failed (no error message)".to_string()
                } else {
                    let s = if (*compile_err).message.is_null() {
                        "hs_compile_multi failed (null error message)".to_string()
                    } else {
                        let cstr = std::ffi::CStr::from_ptr((*compile_err).message);
                        format!(
                            "hs_compile_multi failed at expression {}: {}",
                            (*compile_err).expression,
                            cstr.to_string_lossy()
                        )
                    };
                    vs::hs_free_compile_error(compile_err);
                    s
                }
            };
            return Err(msg);
        }

        cache.try_store(&cache_key, db as *const vs::hs_database_t);
        Ok(Self { db })
    }

    /// Allocates a new scratch space bound to this database.
    pub(crate) fn alloc_scratch(&self) -> Result<VsScratch, String> {
        let mut scratch: *mut vs::hs_scratch_t = ptr::null_mut();
        // SAFETY: `self.db` is a valid compiled Vectorscan database; `scratch` is
        // a valid out-pointer. Vectorscan allocates scratch internally.
        let rc =
            unsafe { vs::hs_alloc_scratch(self.db, &mut scratch as *mut *mut vs::hs_scratch_t) };
        if rc != vs::HS_SUCCESS as c_int {
            return Err(format!("hs_alloc_scratch failed: rc={rc}"));
        }
        Ok(VsScratch {
            scratch,
            db: self.db,
        })
    }

    /// Returns the raw database pointer for scratch binding checks.
    #[inline]
    pub(crate) fn db_ptr(&self) -> *mut vs::hs_database_t {
        self.db
    }

    /// Opens a new stream handle bound to this database.
    ///
    /// The caller **must** call [`Self::close_stream`] on the returned handle
    /// to flush end-of-stream matches and free the underlying allocation.
    /// See [`VsStream`] for lifecycle details.
    pub(crate) fn open_stream(&self) -> Result<VsStream, String> {
        let mut stream: *mut vs::hs_stream_t = ptr::null_mut();
        // SAFETY: `self.db` is a valid compiled stream-mode database; `stream` is a
        // valid out-pointer. Vectorscan allocates the stream state internally.
        let rc = unsafe { vs::hs_open_stream(self.db, 0, &mut stream) };
        if rc != vs::HS_SUCCESS as c_int {
            return Err(format!("hs_open_stream failed: rc={rc}"));
        }
        Ok(VsStream { stream })
    }

    /// Scans a stream chunk and delivers matches to `on_event`.
    ///
    /// `scratch` must be allocated for this database; `ctx` must remain valid
    /// for the duration of the call. `HS_SCAN_TERMINATED` is treated as success to
    /// allow early termination in callbacks.
    pub(crate) fn scan_stream(
        &self,
        stream: &mut VsStream,
        data: &[u8],
        scratch: &mut VsScratch,
        on_event: vs::match_event_handler,
        ctx: *mut c_void,
    ) -> Result<(), String> {
        let len_u32: c_uint = data
            .len()
            .try_into()
            .map_err(|_| format!("buffer too large for hs_scan_stream: {} bytes", data.len()))?;
        // SAFETY: `stream` is a valid open stream for this database; `data` is a
        // live slice with length `len_u32`; `scratch` is allocated for this database.
        // The caller guarantees `ctx` remains valid for the duration of the call.
        let rc = unsafe {
            vs::hs_scan_stream(
                stream.stream,
                data.as_ptr().cast::<c_char>(),
                len_u32,
                0,
                scratch.scratch,
                on_event,
                ctx,
            )
        };
        if rc == vs::HS_SUCCESS as c_int || rc == vs::HS_SCAN_TERMINATED as c_int {
            Ok(())
        } else {
            Err(format!("hs_scan_stream failed: rc={rc}"))
        }
    }

    /// Closes a stream, flushing end-of-stream matches via `on_event`.
    pub(crate) fn close_stream(
        &self,
        stream: VsStream,
        scratch: &mut VsScratch,
        on_event: vs::match_event_handler,
        ctx: *mut c_void,
    ) -> Result<(), String> {
        // SAFETY: `stream` is a valid open stream; `scratch` is allocated for
        // this database. The caller guarantees `ctx` remains valid for the call.
        // Ownership of `stream` is consumed (freed by Vectorscan).
        let rc = unsafe { vs::hs_close_stream(stream.stream, scratch.scratch, on_event, ctx) };
        if rc == vs::HS_SUCCESS as c_int || rc == vs::HS_SCAN_TERMINATED as c_int {
            Ok(())
        } else {
            Err(format!("hs_close_stream failed: rc={rc}"))
        }
    }
}

impl Drop for VsScratch {
    fn drop(&mut self) {
        // SAFETY: `self.scratch` was allocated by `hs_alloc_scratch` and is
        // non-null (checked below). We have exclusive ownership via `&mut self`.
        unsafe {
            if !self.scratch.is_null() {
                vs::hs_free_scratch(self.scratch);
            }
        }
    }
}

impl VsPrefilterDb {
    /// Builds a Vectorscan DB for raw regex prefilter matches and optional anchor hits.
    ///
    /// # Arguments
    /// * `rules` - Rule specifications to compile
    /// * `anchor` - Optional anchor patterns to include as exact literals
    /// * `use_raw_prefilter` - Per-rule flags indicating whether to include raw regex.
    ///   When `None`, all rules use raw regex prefiltering. When `Some`, only rules
    ///   with `use_raw_prefilter[rid] == true` have their regex compiled. Rules with
    ///   `false` rely on anchor patterns for window seeding.
    ///
    /// # Errors
    /// Returns an error if:
    /// - Any rule pattern contains NUL bytes or is rejected by
    ///   `hs_expression_info`.
    /// - `hs_compile_multi` fails for the combined database. In this case
    ///   patterns are recompiled individually; the error lists every rejected
    ///   rule with its name, pattern, and compiler message.
    /// - All raw patterns are rejected and no anchor data is available.
    pub(crate) fn try_new(
        rules: &[RuleSpec],
        anchor: Option<AnchorInput<'_>>,
        use_raw_prefilter: Option<&[bool]>,
    ) -> Result<Self, String> {
        const RAW_FLAGS: c_uint = vs::HS_FLAG_PREFILTER as c_uint;

        #[derive(Clone)]
        struct RawPattern<'a> {
            rule_id: u32,
            seed_radius: u32,
            c_pat: CString,
            name: &'a str,
            pattern: &'a str,
            max_width: u32,
        }

        let mut raw_patterns: Vec<RawPattern<'_>> = Vec::with_capacity(rules.len());
        let mut max_width = 0u32;
        let mut unbounded = false;

        for (rid, r) in rules.iter().enumerate() {
            let seed_radius = if let Some(tp) = &r.two_phase {
                tp.seed_radius
            } else {
                r.radius
            };

            let (mut max_width_u32, c_pat) = expression_info_max_width(r.re.as_str(), RAW_FLAGS)?;
            if max_width_u32 == 0 {
                max_width_u32 = u32::MAX;
            }
            if max_width_u32 == u32::MAX {
                unbounded = true;
            }
            // Always track max_width for all rules (needed for window expansion).
            max_width = max_width.max(max_width_u32);

            // Skip adding raw regex pattern for rules where use_raw_prefilter[rid] is false.
            // These rules rely on anchor patterns (in the anchor input) for window seeding.
            if let Some(flags) = use_raw_prefilter {
                if rid < flags.len() && !flags[rid] {
                    continue;
                }
            }

            raw_patterns.push(RawPattern {
                rule_id: rid as u32,
                seed_radius: usize_to_u32_saturating(seed_radius),
                c_pat,
                name: r.name,
                pattern: r.re.as_str(),
                max_width: max_width_u32,
            });
        }

        let anchor_data = if let Some(anchor) = anchor {
            let debug = std::env::var("SCANNER_VS_UTF16_DEBUG").is_ok();
            Some(build_anchor_data(
                anchor.patterns,
                anchor.pat_targets,
                anchor.pat_offsets,
                anchor.seed_radius_raw,
                anchor.seed_radius_utf16,
                debug,
            )?)
        } else {
            None
        };

        let mut platform = MaybeUninit::<vs::hs_platform_info_t>::zeroed();
        // SAFETY: `hs_populate_platform` writes CPU feature fields into the
        // provided pointer. The `MaybeUninit` allocation is valid and
        // properly aligned; see `VsStreamDb::try_new_stream` for rationale.
        unsafe {
            let _ = vs::hs_populate_platform(platform.as_mut_ptr());
        }
        // SAFETY: `hs_populate_platform` wrote all fields; the zeroed base
        // ensures any untouched padding is deterministic.
        let platform = unsafe { platform.assume_init() };

        let cache = VsDbCache::new();

        let compile_db = |raw: &[RawPattern<'_>]| -> Result<*mut vs::hs_database_t, String> {
            let anchor_len = anchor_data.as_ref().map_or(0, |d| d.pat_lens.len());
            let mut c_patterns: Vec<CString> =
                Vec::with_capacity(raw.len().saturating_add(anchor_len));
            let mut expr_ptrs: Vec<*const c_char> =
                Vec::with_capacity(raw.len().saturating_add(anchor_len));
            let mut flags: Vec<c_uint> = Vec::with_capacity(raw.len().saturating_add(anchor_len));
            let mut ids: Vec<c_uint> = Vec::with_capacity(raw.len().saturating_add(anchor_len));

            for (idx, pat) in raw.iter().enumerate() {
                c_patterns.push(pat.c_pat.clone());
                expr_ptrs.push(c_patterns.last().unwrap().as_ptr());
                flags.push(RAW_FLAGS);
                ids.push(idx as c_uint);
            }

            if let Some(data) = &anchor_data {
                let base = raw.len() as u32;
                for (idx, pat) in data.patterns.iter().enumerate() {
                    c_patterns.push(pat.clone());
                    expr_ptrs.push(c_patterns.last().unwrap().as_ptr());
                    flags.push(0);
                    ids.push(base + idx as u32);
                }
            }

            if expr_ptrs.is_empty() {
                return Err("no patterns to compile".to_string());
            }

            let cache_key = cache.cache_key(&CacheKeyInput {
                kind: b"vs-prefilter-db:block",
                mode: vs::HS_MODE_BLOCK as c_uint,
                platform: &platform,
                patterns: &c_patterns,
                flags: Some(&flags),
                ids: &ids,
            });
            if let Some(cached_db) = cache.try_load(&cache_key) {
                return Ok(cached_db);
            }

            let mut db: *mut vs::hs_database_t = ptr::null_mut();
            let mut compile_err: *mut vs::hs_compile_error_t = ptr::null_mut();
            // SAFETY: All pointer arrays (`expr_ptrs`, `flags`, `ids`) are valid,
            // non-null, and contain `expr_ptrs.len()` elements. `db` and `compile_err`
            // are valid out-pointers. The platform struct is fully initialized.
            let rc = unsafe {
                vs::hs_compile_multi(
                    expr_ptrs.as_ptr(),
                    flags.as_ptr(),
                    ids.as_ptr(),
                    expr_ptrs.len() as c_uint,
                    vs::HS_MODE_BLOCK as c_uint,
                    &platform as *const vs::hs_platform_info_t,
                    &mut db as *mut *mut vs::hs_database_t,
                    &mut compile_err as *mut *mut vs::hs_compile_error_t,
                )
            };

            if rc != vs::HS_SUCCESS as c_int {
                // SAFETY: `compile_err` was populated by `hs_compile_multi`; if non-null
                // it points to a valid `hs_compile_error_t` that we read and then free.
                let msg = unsafe {
                    if compile_err.is_null() {
                        "hs_compile_multi failed (no error message)".to_string()
                    } else {
                        let s = if (*compile_err).message.is_null() {
                            "hs_compile_multi failed (null error message)".to_string()
                        } else {
                            let cstr = std::ffi::CStr::from_ptr((*compile_err).message);
                            format!(
                                "hs_compile_multi failed at expression {}: {}",
                                (*compile_err).expression,
                                cstr.to_string_lossy()
                            )
                        };
                        vs::hs_free_compile_error(compile_err);
                        s
                    }
                };
                return Err(msg);
            }

            cache.try_store(&cache_key, db as *const vs::hs_database_t);
            Ok(db)
        };

        // Compiles a single pattern in isolation to test whether Vectorscan
        // accepts it. The compiled database is immediately freed — the only
        // purpose is to identify which patterns caused the multi-compile failure
        // so we can exclude them and retry with the valid subset.
        let compile_single = |pat: &RawPattern<'_>| -> Result<(), String> {
            let expr_ptrs = [pat.c_pat.as_ptr()];
            let flags = [RAW_FLAGS];
            let ids = [0u32];
            let mut db: *mut vs::hs_database_t = ptr::null_mut();
            let mut compile_err: *mut vs::hs_compile_error_t = ptr::null_mut();
            // SAFETY: Single-element arrays are valid pointers with count 1.
            // `db` and `compile_err` are valid out-pointers. Platform is initialized.
            let rc = unsafe {
                vs::hs_compile_multi(
                    expr_ptrs.as_ptr(),
                    flags.as_ptr(),
                    ids.as_ptr(),
                    1,
                    vs::HS_MODE_BLOCK as c_uint,
                    &platform as *const vs::hs_platform_info_t,
                    &mut db as *mut *mut vs::hs_database_t,
                    &mut compile_err as *mut *mut vs::hs_compile_error_t,
                )
            };
            if rc != vs::HS_SUCCESS as c_int {
                // SAFETY: `compile_err` was populated by `hs_compile_multi`; if non-null
                // it points to a valid `hs_compile_error_t` that we read and then free.
                let msg = unsafe {
                    if compile_err.is_null() {
                        "hs_compile_multi failed (no error message)".to_string()
                    } else {
                        let s = if (*compile_err).message.is_null() {
                            "hs_compile_multi failed (null error message)".to_string()
                        } else {
                            let cstr = std::ffi::CStr::from_ptr((*compile_err).message);
                            format!(
                                "hs_compile_multi failed at expression {}: {}",
                                (*compile_err).expression,
                                cstr.to_string_lossy()
                            )
                        };
                        vs::hs_free_compile_error(compile_err);
                        s
                    }
                };
                return Err(msg);
            }
            // SAFETY: `db` was successfully allocated by `hs_compile_multi` above
            // (rc == HS_SUCCESS). We free it immediately since we only needed to
            // validate the pattern.
            unsafe {
                if !db.is_null() {
                    vs::hs_free_database(db);
                }
            }
            Ok(())
        };

        let mut raw_kept = raw_patterns.clone();
        let mut raw_missing_rules = Vec::new();
        let db = match compile_db(&raw_kept) {
            Ok(db) => db,
            Err(_err) => {
                raw_kept.clear();
                let mut errors = Vec::new();
                for pat in &raw_patterns {
                    match compile_single(pat) {
                        Ok(()) => raw_kept.push(pat.clone()),
                        Err(err) => {
                            raw_missing_rules.push(pat.rule_id);
                            errors.push(format!(
                                "rule='{}' pattern='{}' error={}",
                                pat.name, pat.pattern, err
                            ));
                        }
                    }
                }

                if !errors.is_empty() {
                    return Err(format!(
                        "vectorscan raw db compile failed for {} rules:\n{}",
                        errors.len(),
                        errors.join("\n")
                    ));
                }

                if raw_kept.is_empty() && anchor_data.as_ref().is_none_or(|d| d.pat_lens.is_empty())
                {
                    return Err("vectorscan raw db compile failed for all patterns".to_string());
                }
                compile_db(&raw_kept)?
            }
        };

        let raw_meta: Vec<RawPatternMeta> = raw_kept
            .iter()
            .map(|p| RawPatternMeta {
                rule_id: p.rule_id,
                match_width: p.max_width,
                seed_radius: p.seed_radius,
            })
            .collect();
        // Construction invariant: every rule_id must be a valid index into the
        // engine's rules array. This is guaranteed by the enumerate() loop above
        // but checked here defensively since the FFI callbacks rely on it for
        // safe push_span_unchecked_hot indexing (pair = rule_id * 3 + variant).
        debug_assert!(
            raw_meta.iter().all(|m| (m.rule_id as usize) < rules.len()),
            "raw_meta rule_id out of bounds: max rule_id={}, rules.len()={}",
            raw_meta.iter().map(|m| m.rule_id).max().unwrap_or(0),
            rules.len(),
        );
        let raw_rule_count = raw_kept.len() as u32;

        let (anchor_id_base, anchor_pat_count, anchor_targets, anchor_pat_offsets, anchor_pat_lens) =
            if let Some(data) = anchor_data {
                let pat_count = data.pat_lens.len() as u32;
                if pat_count == 0 {
                    (raw_rule_count, 0, Vec::new(), Vec::new(), Vec::new())
                } else {
                    (
                        raw_rule_count,
                        pat_count,
                        data.targets,
                        data.pat_offsets,
                        data.pat_lens,
                    )
                }
            } else {
                (raw_rule_count, 0, Vec::new(), Vec::new(), Vec::new())
            };

        // Same invariant for anchor targets: rule_id must be in-bounds and
        // variant_idx must be 0..3 so pair = rule_id * 3 + variant_idx < rules.len() * 3.
        debug_assert!(
            anchor_targets
                .iter()
                .all(|t| (t.rule_id as usize) < rules.len() && t.variant_idx < 3),
            "anchor target rule_id or variant_idx out of bounds",
        );

        Ok(Self {
            db,
            raw_rule_count,
            raw_meta,
            raw_missing_rules,
            anchor_id_base,
            anchor_pat_count,
            anchor_targets,
            anchor_pat_offsets,
            anchor_pat_lens,
            max_width,
            unbounded,
        })
    }

    /// Returns the maximum bounded match width across all rules.
    pub(crate) fn max_match_width_bounded(&self) -> Option<u32> {
        if self.unbounded {
            None
        } else {
            Some(self.max_width)
        }
    }

    /// Allocates a new scratch space bound to this database.
    ///
    /// Callers should reuse the returned scratch across scans on the same
    /// thread to avoid allocation overhead.
    pub(crate) fn alloc_scratch(&self) -> Result<VsScratch, String> {
        let mut scratch: *mut vs::hs_scratch_t = ptr::null_mut();
        // SAFETY: `self.db` is a valid compiled Vectorscan database; `scratch` is
        // a valid out-pointer. Vectorscan allocates scratch internally.
        let rc =
            unsafe { vs::hs_alloc_scratch(self.db, &mut scratch as *mut *mut vs::hs_scratch_t) };
        if rc != vs::HS_SUCCESS as c_int {
            return Err(format!("hs_alloc_scratch failed: rc={rc}"));
        }
        Ok(VsScratch {
            scratch,
            db: self.db,
        })
    }

    /// Returns the raw database pointer for scratch binding checks.
    #[inline]
    pub(crate) fn db_ptr(&self) -> *mut vs::hs_database_t {
        self.db
    }

    #[inline]
    pub(crate) fn raw_missing_rules(&self) -> &[u32] {
        &self.raw_missing_rules
    }

    /// Scan raw bytes and seed per-rule candidate windows.
    ///
    /// Prefilter matches seed raw windows; anchor patterns (when
    /// present in the database) seed raw/UTF-16 windows.
    ///
    /// `vs_scratch` must be allocated for this database and not shared across
    /// threads; `scratch` must not be accessed concurrently. Per-(rule, variant)
    /// hits are capped to `max_hits_per_rule_variant` and may coalesce when the cap
    /// is exceeded.
    ///
    /// Returns `Ok(true)` if any UTF-16 anchor hit was observed.
    pub(crate) fn scan_raw(
        &self,
        hay: &[u8],
        scratch: &mut ScanScratch,
        vs_scratch: &mut VsScratch,
    ) -> Result<bool, String> {
        let len_u32: c_uint = hay
            .len()
            .try_into()
            .map_err(|_| format!("buffer too large for hs_scan: {} bytes", hay.len()))?;

        let mut ctx = VsMatchCtx {
            scratch: scratch as *mut ScanScratch,
            hay_len: len_u32,
            raw_rule_count: self.raw_rule_count,
            raw_meta: self.raw_meta.as_ptr(),
            anchor_id_base: self.anchor_id_base,
            anchor_pat_count: self.anchor_pat_count,
            anchor_targets: self.anchor_targets.as_ptr(),
            anchor_pat_offsets: self.anchor_pat_offsets.as_ptr(),
            anchor_pat_lens: self.anchor_pat_lens.as_ptr(),
            saw_utf16: false,
        };

        // SAFETY: `self.db` is a valid compiled database; `hay` is a live slice with
        // length `len_u32`; `vs_scratch` is allocated for this database; `ctx` is a
        // valid `VsMatchCtx` that outlives the scan. The callback `vs_on_match`
        // upholds the FFI contract (no panics, no unwind).
        let rc = unsafe {
            vs::hs_scan(
                self.db,
                hay.as_ptr().cast::<c_char>(),
                len_u32,
                0,
                vs_scratch.scratch,
                Some(vs_on_match),
                (&mut ctx as *mut VsMatchCtx).cast::<c_void>(),
            )
        };

        if rc == vs::HS_SUCCESS as c_int || rc == vs::HS_SCAN_TERMINATED as c_int {
            Ok(ctx.saw_utf16)
        } else {
            Err(format!("hs_scan failed: rc={rc}"))
        }
    }
}

#[repr(C)]
/// Callback context for `hs_scan`.
///
/// Safety invariants:
/// - `scratch` points to a live `ScanScratch` for the duration of the scan.
/// - `hay_len` matches the length passed to `hs_scan`.
/// - If `anchor_pat_count > 0`, the anchor mapping tables are valid and
///   `anchor_pat_offsets` has length `anchor_pat_count + 1`.
/// - `raw_meta` has length `raw_rule_count`.
struct VsMatchCtx {
    scratch: *mut ScanScratch,
    hay_len: u32,
    raw_rule_count: u32,
    raw_meta: *const RawPatternMeta,
    anchor_id_base: u32,
    anchor_pat_count: u32,
    anchor_targets: *const VsAnchorTarget,
    anchor_pat_offsets: *const u32,
    anchor_pat_lens: *const u32,
    saw_utf16: bool,
}

#[repr(C)]
/// Callback context for anchor literal scans.
///
/// Safety invariants:
/// - `scratch` points to a live `ScanScratch` for the duration of the scan.
/// - `targets` points to `pat_offsets[pat_count]` entries indexed by pattern id.
/// - `pat_offsets` has length `pat_count + 1` and is monotonically increasing.
/// - `pat_lens` has length `pat_count`.
/// - `hay_len` matches the length passed to `hs_scan`.
struct VsAnchorMatchCtx {
    scratch: *mut ScanScratch,
    targets: *const VsAnchorTarget,
    pat_offsets: *const u32,
    pat_lens: *const u32,
    pat_count: u32,
    hay_len: u32,
    saw_utf16: bool,
}

/// Expands one matched anchor pattern into per-target hit spans.
///
/// # Safety
/// - `targets` must point to at least `off_end` entries.
/// - `off_start <= off_end`.
/// - `scratch` must be valid and exclusively borrowed for the call.
#[inline(always)]
unsafe fn enqueue_anchor_target_spans(
    scratch: &mut ScanScratch,
    targets: *const VsAnchorTarget,
    offsets: std::ops::Range<usize>,
    start: u32,
    end: u32,
    hay_len: u32,
    saw_utf16: &mut bool,
) {
    for i in offsets {
        // SAFETY: caller guarantees `targets` covers `[off_start, off_end)`.
        let target = unsafe { *targets.add(i) };
        let seed = target.seed_radius_bytes;
        let lo = start.saturating_sub(seed);
        let hi = end.saturating_add(seed).min(hay_len);

        // Anchor patterns are fixed-width; use the computed start as the hint to
        // avoid relying on `from` for prefilter-style callbacks.
        let anchor_hint = clamp_u32_ordered(start, lo, end);

        let rid = target.rule_id as usize;
        let vidx = target.variant_idx as usize;
        let pair = rid * 3 + vidx;
        debug_assert!(
            pair < scratch.hit_acc_pool.pair_count(),
            "pair {pair} exceeds pool pair_count {}",
            scratch.hit_acc_pool.pair_count()
        );
        // SAFETY: `pair` is in bounds (debug-asserted above); `scratch` has
        // exclusive access for the duration of the scan.
        unsafe {
            scratch.hit_acc_pool.push_span_unchecked_hot(
                pair,
                SpanU32 {
                    start: lo,
                    end: hi,
                    anchor_hint,
                },
                &mut scratch.touched_pairs,
            );
        }
        if matches!(target.variant_idx, 1 | 2) {
            *saw_utf16 = true;
        }
    }
}

/// Prefilter match callback for raw-byte scanning.
///
/// Seeds per-rule raw windows in `ScanScratch` based on the match end offset.
/// `id` values below `raw_rule_count` denote raw rules; ids at or above
/// `anchor_id_base` denote anchor literal patterns. Out-of-range ids or
/// match ends beyond `hay_len` are silently dropped (defensive against
/// Vectorscan reporting spurious matches under `HS_FLAG_PREFILTER`).
///
/// # Id dispatch
/// - `id < raw_rule_count`: raw regex hit — seeds one window using
///   `raw_meta[id]` for width and radius.
/// - `anchor_id_base <= id < anchor_id_base + anchor_pat_count`: anchor
///   literal hit — fans out to all `(rule, variant)` targets for that
///   pattern.
/// - Everything else: ignored.
///
/// # Safety
/// - `ctx` must be non-null and point to a valid `VsMatchCtx`.
/// - `scratch` and mapping tables referenced by `ctx` must remain valid and
///   not be accessed concurrently for the duration of the scan.
/// - This callback must never panic or unwind across the FFI boundary.
unsafe extern "C" fn vs_on_match(
    id: c_uint,
    from: u64,
    to: u64,
    _flags: c_uint,
    ctx: *mut c_void,
) -> c_int {
    // Absolutely no panics across FFI.
    // SAFETY: `ctx` is a valid, non-null pointer to `VsMatchCtx` passed by the
    // caller of `hs_scan`. It is exclusively borrowed for the scan duration.
    let c = unsafe { &mut *(ctx as *mut VsMatchCtx) };
    if id < c.raw_rule_count {
        let raw_idx = id as usize;
        // SAFETY: `raw_idx < raw_rule_count`, and `raw_meta` has `raw_rule_count`
        // entries (ctx invariant).
        let meta = unsafe { *c.raw_meta.add(raw_idx) };
        let rid = meta.rule_id as usize;

        // SAFETY: `scratch` is valid for the duration of the scan and is not used concurrently.
        let scratch = unsafe { &mut *c.scratch };

        const RAW_IDX: usize = 0;

        let end = to as u32;
        if end > c.hay_len {
            return 0;
        }
        let max_width = meta.match_width;
        let start = if max_width == u32::MAX {
            0
        } else {
            end.saturating_sub(max_width)
        };
        let seed = meta.seed_radius;
        let lo = start.saturating_sub(seed);
        let hi = end.saturating_add(seed).min(c.hay_len);

        // Clamp anchor hint to window bounds.
        let anchor_hint = clamp_u32_ordered(from as u32, lo, end);

        // Pair encoding: `rid * 3 + variant_idx` maps (rule, variant) to a
        // unique hit-accumulator slot. Variant indices: 0=Raw, 1=UTF-16LE, 2=UTF-16BE.
        let pair = rid * 3 + RAW_IDX;
        debug_assert!(
            pair < scratch.hit_acc_pool.pair_count(),
            "pair {pair} exceeds pool pair_count {}",
            scratch.hit_acc_pool.pair_count()
        );
        // SAFETY: `pair` is in bounds (debug-asserted above); `scratch` has
        // exclusive access for the duration of the scan.
        unsafe {
            scratch.hit_acc_pool.push_span_unchecked_hot(
                pair,
                SpanU32 {
                    start: lo,
                    end: hi,
                    anchor_hint,
                },
                &mut scratch.touched_pairs,
            );
        }
        return 0;
    }

    if c.anchor_pat_count == 0 || id < c.anchor_id_base {
        return 0;
    }

    let pid = (id - c.anchor_id_base) as usize;
    if pid >= c.anchor_pat_count as usize {
        return 0;
    }

    // SAFETY: pid < anchor_pat_count (checked at line above).
    let len = unsafe { *c.anchor_pat_lens.add(pid) };
    let end = to as u32;
    if end > c.hay_len {
        return 0;
    }
    let start = end.saturating_sub(len);

    // SAFETY: pat_offsets has length anchor_pat_count + 1 (ctx invariant),
    // and pid < anchor_pat_count, so pid and pid + 1 are in bounds.
    let off_start = unsafe { *c.anchor_pat_offsets.add(pid) } as usize;
    // SAFETY: pid + 1 <= anchor_pat_count, so this offset is in bounds.
    let off_end = unsafe { *c.anchor_pat_offsets.add(pid + 1) } as usize;

    // SAFETY: `scratch` is valid for the duration of the scan and not used concurrently.
    let scratch = unsafe { &mut *c.scratch };

    // SAFETY: offsets are derived from `anchor_pat_offsets` bounds checked above.
    unsafe {
        enqueue_anchor_target_spans(
            scratch,
            c.anchor_targets,
            off_start..off_end,
            start,
            end,
            c.hay_len,
            &mut c.saw_utf16,
        );
    }

    0
}

/// Anchor literal match callback.
///
/// Expands each anchor match into windows for all rule/variant targets tied to
/// the matched pattern. Window ends are clamped to `hay_len`.
///
/// # Safety
/// - `ctx` must be non-null and point to a valid `VsAnchorMatchCtx`.
/// - `scratch` and mapping tables referenced by `ctx` must remain valid and
///   not be accessed concurrently for the duration of the scan.
/// - This callback must never panic or unwind across the FFI boundary.
unsafe extern "C" fn vs_anchor_on_match(
    id: c_uint,
    _from: u64,
    to: u64,
    _flags: c_uint,
    ctx: *mut c_void,
) -> c_int {
    // Absolutely no panics across FFI.
    // SAFETY: `ctx` is a valid, non-null pointer to `VsAnchorMatchCtx` passed by
    // the caller of `hs_scan`. It is exclusively borrowed for the scan duration.
    let c = unsafe { &mut *(ctx as *mut VsAnchorMatchCtx) };

    let pid = id as usize;
    debug_assert!(pid < c.pat_count as usize);

    // SAFETY: pid < pat_count (debug-asserted above).
    let len = unsafe { *c.pat_lens.add(pid) };
    let end = to as u32;
    debug_assert!(end <= c.hay_len);
    let start = end.saturating_sub(len);

    // SAFETY: pat_offsets has length pat_count + 1 (ctx invariant),
    // and pid < pat_count, so pid and pid + 1 are in bounds.
    let off_start = unsafe { *c.pat_offsets.add(pid) } as usize;
    // SAFETY: pid + 1 <= pat_count, so this offset is in bounds.
    let off_end = unsafe { *c.pat_offsets.add(pid + 1) } as usize;

    // SAFETY: scratch is valid for the duration of the scan and not used concurrently.
    let scratch = unsafe { &mut *c.scratch };

    // SAFETY: offsets are derived from `pat_offsets` bounds checked above.
    unsafe {
        enqueue_anchor_target_spans(
            scratch,
            c.targets,
            off_start..off_end,
            start,
            end,
            c.hay_len,
            &mut c.saw_utf16,
        );
    }

    0
}

/// Returns `(max_width, c_pattern)` for use in compilation.
///
/// Vectorscan reports `max_width = UINT_MAX` for truly unbounded patterns
/// (e.g. `.*`) and `0` for zero-width matches (e.g. `^`, `\b`). Callers
/// treat both as effectively unbounded for window seeding.
///
/// # Errors
/// Returns an error if the pattern contains NUL bytes or if
/// `hs_expression_info` fails (e.g. unsupported regex syntax).
fn expression_info_max_width(pattern: &str, flags: c_uint) -> Result<(u32, CString), String> {
    let c_pat = CString::new(pattern).map_err(|_| "pattern contains NUL byte".to_string())?;

    let mut info_ptr: *mut vs::hs_expr_info_t = ptr::null_mut();
    let mut compile_err: *mut vs::hs_compile_error_t = ptr::null_mut();
    // SAFETY: `c_pat` is a valid NUL-terminated C string; `info_ptr` and
    // `compile_err` are valid out-pointers.
    let rc =
        unsafe { vs::hs_expression_info(c_pat.as_ptr(), flags, &mut info_ptr, &mut compile_err) };
    if rc != vs::HS_SUCCESS as c_int {
        // SAFETY: `compile_err` was populated by `hs_expression_info`; if non-null
        // it points to a valid `hs_compile_error_t` that we read and then free.
        let msg = unsafe {
            if compile_err.is_null() {
                format!("hs_expression_info failed: rc={rc}")
            } else {
                let s = if (*compile_err).message.is_null() {
                    format!("hs_expression_info failed: rc={rc}")
                } else {
                    let cstr = std::ffi::CStr::from_ptr((*compile_err).message);
                    format!(
                        "hs_expression_info failed at expression {}: {}",
                        (*compile_err).expression,
                        cstr.to_string_lossy()
                    )
                };
                vs::hs_free_compile_error(compile_err);
                s
            }
        };
        return Err(msg);
    }
    if info_ptr.is_null() {
        return Err("hs_expression_info returned null info".to_string());
    }

    // SAFETY: `info_ptr` is non-null (checked above) and was allocated by
    // `hs_expression_info` with a valid `hs_expr_info_t` layout.
    let maxw = unsafe { (*info_ptr).max_width };
    // SAFETY: `info_ptr` was allocated by Vectorscan's misc allocator (which
    // uses the default malloc); freeing it with `libc::free` is correct.
    unsafe {
        libc::free(info_ptr.cast());
    }

    Ok((maxw, c_pat))
}

/// Convenience wrapper for `expression_info_max_width` with `HS_FLAG_PREFILTER`.
fn expression_info_prefilter_max_width(pattern: &str) -> Result<(u32, CString), String> {
    expression_info_max_width(pattern, vs::HS_FLAG_PREFILTER as c_uint)
}

/// Saturating conversion from `usize` to `u32`.
///
/// Returns `u32::MAX` if the value exceeds `u32::MAX`.
#[inline]
fn usize_to_u32_saturating(v: usize) -> u32 {
    if v > u32::MAX as usize {
        u32::MAX
    } else {
        v as u32
    }
}

// ---------------------------------------------------------------------------
// Miri-compatible unit tests (no FFI dependencies)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_window(rule_id: u32, lo: u64, hi: u64) -> VsStreamWindow {
        VsStreamWindow {
            lo,
            hi,
            anchor_hint: lo,
            rule_id,
            variant_idx: 0,
            force_full: false,
        }
    }

    #[test]
    fn miri_push_stream_window_bounded_within_cap() {
        let mut buf =
            std::array::from_fn::<_, 4, _>(|_| std::mem::MaybeUninit::<VsStreamWindow>::uninit());
        let ptr = buf.as_mut_ptr() as *mut VsStreamWindow;
        let mut len: u32 = 0;
        let mut overflow: u8 = 0;

        let win = make_window(0, 0, 100);

        // SAFETY: `ptr` points to a 4-element MaybeUninit buffer; `len` and
        // `overflow` are valid mutable references. cap=4, max_pending=4.
        let ok = unsafe { push_stream_window_bounded(ptr, &mut len, 4, 4, &mut overflow, win) };
        assert!(ok);
        assert_eq!(len, 1);
        assert_eq!(overflow, 0);

        // Verify the written value.
        // SAFETY: One element was successfully written above (len == 1), so
        // `ptr` points to an initialized `VsStreamWindow`.
        let stored = unsafe { ptr.read() };
        assert_eq!(stored.lo, 0);
        assert_eq!(stored.hi, 100);
    }

    #[test]
    fn miri_push_stream_window_bounded_fills_to_cap() {
        let mut buf =
            std::array::from_fn::<_, 3, _>(|_| std::mem::MaybeUninit::<VsStreamWindow>::uninit());
        let ptr = buf.as_mut_ptr() as *mut VsStreamWindow;
        let mut len: u32 = 0;
        let mut overflow: u8 = 0;

        for i in 0..3u32 {
            // SAFETY: `ptr` points to a 3-element buffer; `len < cap` on each
            // iteration. All mutable references are valid.
            let ok = unsafe {
                push_stream_window_bounded(
                    ptr,
                    &mut len,
                    3,
                    3,
                    &mut overflow,
                    make_window(i, i as u64 * 10, i as u64 * 10 + 5),
                )
            };
            assert!(ok, "push {i} should succeed");
        }
        assert_eq!(len, 3);
        assert_eq!(overflow, 0);

        // Next push should fail — buffer is full.
        // SAFETY: `ptr` points to a 3-element buffer; `len == cap` so no write
        // occurs. All mutable references are valid.
        let ok = unsafe {
            push_stream_window_bounded(ptr, &mut len, 3, 3, &mut overflow, make_window(99, 0, 1))
        };
        assert!(!ok);
        assert_eq!(overflow, 1);
        assert_eq!(len, 3); // Unchanged.
    }

    #[test]
    fn miri_push_stream_window_bounded_max_pending_lower_than_cap() {
        let mut buf =
            std::array::from_fn::<_, 8, _>(|_| std::mem::MaybeUninit::<VsStreamWindow>::uninit());
        let ptr = buf.as_mut_ptr() as *mut VsStreamWindow;
        let mut len: u32 = 0;
        let mut overflow: u8 = 0;

        // Cap is 8 but max_pending is 2.
        for i in 0..2u32 {
            // SAFETY: `ptr` points to an 8-element buffer; `len < max_pending`
            // on each iteration. All mutable references are valid.
            let ok = unsafe {
                push_stream_window_bounded(
                    ptr,
                    &mut len,
                    8,
                    2,
                    &mut overflow,
                    make_window(i, 0, 10),
                )
            };
            assert!(ok);
        }
        assert_eq!(len, 2);

        // Third push hits max_pending.
        // SAFETY: `ptr` points to an 8-element buffer; `len == max_pending` so
        // no write occurs. All mutable references are valid.
        let ok = unsafe {
            push_stream_window_bounded(ptr, &mut len, 8, 2, &mut overflow, make_window(3, 0, 10))
        };
        assert!(!ok);
        assert_eq!(overflow, 1);
        assert_eq!(len, 2);
    }

    #[test]
    fn miri_push_stream_window_bounded_null_overflow_ptr() {
        let mut buf =
            std::array::from_fn::<_, 1, _>(|_| std::mem::MaybeUninit::<VsStreamWindow>::uninit());
        let ptr = buf.as_mut_ptr() as *mut VsStreamWindow;
        let mut len: u32 = 1; // Already full.

        // Null overflow pointer — should not crash.
        // SAFETY: `ptr` points to a 1-element buffer; `len == cap` so no write
        // occurs. The null overflow pointer is handled internally by the function.
        let ok = unsafe {
            push_stream_window_bounded(
                ptr,
                &mut len,
                1,
                1,
                std::ptr::null_mut(),
                make_window(0, 0, 10),
            )
        };
        assert!(!ok);
        assert_eq!(len, 1);
    }

    #[test]
    fn miri_push_stream_window_bounded_preserves_field_values() {
        let mut buf =
            std::array::from_fn::<_, 2, _>(|_| std::mem::MaybeUninit::<VsStreamWindow>::uninit());
        let ptr = buf.as_mut_ptr() as *mut VsStreamWindow;
        let mut len: u32 = 0;
        let mut overflow: u8 = 0;

        let win = VsStreamWindow {
            lo: 42,
            hi: 999,
            anchor_hint: 50,
            rule_id: 7,
            variant_idx: 2,
            force_full: true,
        };

        // SAFETY: `ptr` points to a 2-element buffer; `len == 0 < cap`. All
        // mutable references are valid.
        let ok = unsafe { push_stream_window_bounded(ptr, &mut len, 2, 2, &mut overflow, win) };
        assert!(ok);

        // SAFETY: One element was successfully written above (len == 1), so
        // `ptr` points to an initialized `VsStreamWindow`.
        let stored = unsafe { ptr.read() };
        assert_eq!(stored.lo, 42);
        assert_eq!(stored.hi, 999);
        assert_eq!(stored.anchor_hint, 50);
        assert_eq!(stored.rule_id, 7);
        assert_eq!(stored.variant_idx, 2);
        assert!(stored.force_full);
    }

    #[test]
    fn stream_match_callback_terminates_on_overflow() {
        let mut pending: Vec<VsStreamWindow> = Vec::new();
        let mut pending_len = 0u32;
        let mut overflowed = 0u8;
        let meta = [VsStreamMeta {
            max_width: 8,
            radius: 4,
            whole_buffer_on_hit: 0,
        }];
        let mut ctx =
            build_stream_match_ctx(&mut pending, &mut pending_len, &meta, 0, &mut overflowed);

        // SAFETY: `ctx` is a valid, stack-allocated `VsStreamMatchCtx` with all
        // fields pointing to live locals. The cast to `*mut c_void` matches the
        // FFI callback signature.
        let rc =
            unsafe { vs_on_stream_match(0, 10, 20, 0, (&mut ctx as *mut VsStreamMatchCtx).cast()) };
        assert_eq!(rc, 1);
        assert_eq!(overflowed, 1);
        assert_eq!(pending_len, 0);
    }

    #[test]
    fn utf16_stream_callback_terminates_on_overflow() {
        let mut pending: Vec<VsStreamWindow> = Vec::new();
        let mut pending_len = 0u32;
        let mut overflowed = 0u8;
        let targets = [VsAnchorTarget {
            rule_id: 7,
            variant_idx: 1,
            seed_radius_bytes: 3,
        }];
        let pat_offsets = [0u32, 1u32];
        let pat_lens = [2u32];
        let mut ctx = build_utf16_stream_match_ctx(
            &mut pending,
            &mut pending_len,
            VsUtf16MatchTables {
                targets: &targets,
                pat_offsets: &pat_offsets,
                pat_lens: &pat_lens,
            },
            0,
            0,
            &mut overflowed,
        );

        // SAFETY: `ctx` is a valid, stack-allocated `VsUtf16StreamMatchCtx` with
        // all fields pointing to live locals. The cast to `*mut c_void` matches
        // the FFI callback signature.
        let rc = unsafe {
            vs_utf16_stream_on_match(0, 0, 2, 0, (&mut ctx as *mut VsUtf16StreamMatchCtx).cast())
        };
        assert_eq!(rc, 1);
        assert_eq!(overflowed, 1);
        assert_eq!(pending_len, 0);
    }

    #[test]
    fn clamp_u32_ordered_within_range() {
        assert_eq!(clamp_u32_ordered(5, 0, 10), 5);
    }

    #[test]
    fn clamp_u32_ordered_below_range() {
        assert_eq!(clamp_u32_ordered(0, 5, 10), 5);
    }

    #[test]
    fn clamp_u32_ordered_above_range() {
        assert_eq!(clamp_u32_ordered(15, 5, 10), 10);
    }

    #[test]
    fn clamp_u32_ordered_equal_bounds() {
        assert_eq!(clamp_u32_ordered(3, 5, 5), 5);
        assert_eq!(clamp_u32_ordered(5, 5, 5), 5);
        assert_eq!(clamp_u32_ordered(7, 5, 5), 5);
    }
}
