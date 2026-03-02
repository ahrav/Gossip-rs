//! Budget tracking for archive expansion/scanning.
//!
//! Prevents resource exhaustion from zip bombs and deeply nested archives by
//! enforcing hard caps on entry counts, decompressed output, metadata, nesting
//! depth, and inflation ratio.  An optional wall-clock deadline can be configured
//! via [`ArchiveConfig::max_wall_clock_secs_per_root`] for CPU-exhaustion
//! defense; when `None`, the struct remains purely deterministic and
//! `is_deadline_expired()` is a no-op.
//!
//! # Budget Hierarchy
//!
//! Three nested scopes, each with independent caps:
//!
//! ```text
//! Root (per-source-file)
//!  └─ Archive (per-container: zip, tar, tar.gz, …)
//!      └─ Entry (per-file inside the container)
//! ```
//!
//! When charging decompressed output the tightest remaining allowance across
//! all three scopes wins, and the corresponding [`BudgetHit`] variant is
//! returned so callers can decide whether to skip just the entry, mark the
//! archive partial, or stop the entire root.
//!
//! Inflation-ratio enforcement runs at both archive and entry scopes:
//! `archive_out <= archive_in * R` and, while an entry scope is open,
//! `entry_out <= entry_in * R`.  Per-entry ratio tracking is independent of
//! archive-level ratio credit, preventing a credit-accumulation attack where
//! many small well-compressed entries build up archive-level headroom that a
//! single malicious entry later exploits.
//!
//! # Caller Protocol
//!
//! ```text
//! new(cfg) / reset()
//!   enter_archive()          ← push a frame, enforce depth cap
//!     note_entry() / begin_entry()   ← count + optionally open entry scope
//!       charge_metadata(n)
//!       charge_compressed_in(n)
//!       charge_decompressed_out(n) / charge_discarded_out(n)
//!     end_entry(scanned)     ← close entry scope
//!   exit_archive()           ← pop frame
//! ```
//!
//! `enter_archive`/`exit_archive` and `begin_entry`/`end_entry` must be
//! balanced.  Calling charge methods without an active frame is safe (returns
//! a clamp-to-zero result).
//!
//! # Invariants
//!
//! - All byte/count accounting is deterministic and reproducible. The
//!   wall-clock deadline is a separate, opt-in layer: only the
//!   `is_deadline_expired()` predicate introduces non-determinism (it reads
//!   `Instant::now()`). It does not affect byte or count accounting — callers
//!   poll it at natural loop boundaries as an early-exit check.
//! - All accounting is saturating; overflows are treated as budget hits.
//! - If no archive frame is active, charge methods clamp to 0 and remaining
//!   allowance is 0.
//! - The frame stack index (`depth - 1`) is always valid when `depth > 0`.
//!   This is the safety invariant for `cur()`/`cur_mut()` and is formally
//!   verified by the Kani proof `verify_budget_cur_bounds`.
//!
//! # Design Notes
//!
//! - This module does **not** perform I/O or decompression.
//! - Per-entry vs per-archive limits are separated to avoid ambiguity.
//! - The frame stack is preallocated to `max_archive_depth` and never grows
//!   after startup (no `Vec` push/pop on hot paths).

use std::time::{Duration, Instant};

use super::{ArchiveConfig, ArchiveSkipReason, EntrySkipReason, PartialReason};

/// Classification of a budget limit hit.
///
/// Variants are ordered by increasing blast radius:
///
/// | Variant          | Scope affected                                  |
/// |------------------|-------------------------------------------------|
/// | `SkipEntry`      | Current entry only; archive continues.          |
/// | `SkipArchive`    | Entire archive discarded (no progress yet).     |
/// | `PartialArchive` | Archive stops; bytes already scanned are kept.  |
/// | `StopRoot`       | All remaining archives under this root stop.    |
///
/// The charge methods inside [`ArchiveBudgets`] select the variant by
/// checking which budget was the binding constraint and whether any
/// scanning progress had already been made (see `progressed` heuristic
/// in [`ArchiveBudgets::charge_decompressed_out`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BudgetHit {
    /// Skip the current entry and continue the archive.
    SkipEntry(EntrySkipReason),
    /// Skip the entire archive (no payload bytes were scanned yet).
    SkipArchive(ArchiveSkipReason),
    /// Stop scanning this archive; bytes already produced were scanned.
    PartialArchive(PartialReason),
    /// Stop scanning further archive output for this root (cross-archive cap hit).
    StopRoot(PartialReason),
}

/// Result of charging a quantity where partial progress is meaningful (bytes).
///
/// When a charge exceeds the remaining budget, `Clamp` tells the caller exactly
/// how many bytes it may still process.  The charged amount has already been
/// debited from the internal counters, so the caller must not re-charge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChargeResult {
    /// Full requested amount is within budget and was charged.
    Ok,
    /// Only `allowed` bytes (possibly zero) were charged.
    ///
    /// The caller must stop after scanning/emitting that prefix and use `hit`
    /// to decide the appropriate outcome (skip entry, mark partial, etc.).
    /// `allowed == 0` means the budget was already exhausted before this charge.
    Clamp { allowed: u64, hit: BudgetHit },
}

/// Deterministic budget tracker for nested archive scanning.
///
/// Holds immutable caps (copied from [`ArchiveConfig`] at construction) and
/// mutable counters that advance as bytes flow through the scanner.  A
/// fixed-size frame stack tracks per-archive state for nested containers
/// without any runtime allocation.
///
/// # Reuse
///
/// A single instance is reused across root files via [`reset`](Self::reset),
/// which zeroes counters and (if configured) arms a new wall-clock deadline.
/// The frame stack allocation is preserved across resets.
///
/// # Invariants
///
/// - `enter_archive` / `exit_archive` must be balanced.
/// - `begin_entry` / `end_entry` must be balanced within the current frame.
/// - All methods are panic-free for hostile inputs.
/// - Frame storage is a fixed-size stack preallocated to `max_archive_depth`.
/// - `max_uncompressed_bytes_per_entry` is clamped to `ENTRY_NOT_OPEN - 1`
///   at construction to prevent the sentinel collision (see [`ENTRY_NOT_OPEN`]).
#[derive(Clone, Debug)]
pub struct ArchiveBudgets {
    // -- Immutable caps (set once at construction from ArchiveConfig) ----------
    max_depth: u8,
    max_entries_per_archive: u32,
    max_uncompressed_bytes_per_entry: u64,
    max_total_uncompressed_bytes_per_archive: u64,
    max_total_uncompressed_bytes_per_root: u64,
    max_archive_metadata_bytes: u64,
    max_inflation_ratio: u32,

    // -- Optional wall-clock deadline (CPU-exhaustion defense) -----------------
    // `max_wall_clock_secs` is the configured limit; `deadline` is the armed
    // `Instant` computed by `reset()`.  When `max_wall_clock_secs` is `None`,
    // `deadline` stays `None` and `is_deadline_expired()` is a no-op — no
    // `Instant::now()` call occurs, preserving full determinism in tests.
    max_wall_clock_secs: Option<u64>,
    deadline: Option<Instant>,

    // -- Test-only countdown for deterministic deadline testing ----------------
    // When set to Some(n), `is_deadline_expired()` decrements n on each call
    // and returns `true` when it reaches 0 — without any `Instant::now()`.
    // This allows tests to trigger a timeout after exactly N checks,
    // exercising the mid-scan timeout path deterministically.
    #[cfg(any(test, feature = "sim-harness"))]
    deadline_check_countdown: std::cell::Cell<Option<u32>>,

    // -- Mutable root-level counter -------------------------------------------
    root_decompressed_out: u64,

    // -- Frame stack (one slot per nesting level, preallocated) ----------------
    frames: Box<[ArchiveFrame]>,
    depth: usize,
}

/// Sentinel value indicating no entry is currently open.
/// Using a sentinel instead of a separate `bool` eliminates 7 bytes of padding
/// and keeps the struct compact with `#[repr(C)]`.
///
/// `u64::MAX` is safe as a sentinel because:
///   - `max_uncompressed_bytes_per_entry` is clamped to at most `ENTRY_NOT_OPEN - 1`
///     in [`ArchiveBudgets::new`].
///   - The charge paths (`charge_decompressed_out`, `charge_discarded_out`) apply a
///     runtime cap that clamps `entry_decompressed_out` to `ENTRY_NOT_OPEN - 1`
///     after every saturating addition.
///
/// Note: `entry_compressed_in` tracks input bytes for the current entry and is
/// only meaningful while an entry is open (`entry_decompressed_out != ENTRY_NOT_OPEN`).
/// It is reset to 0 by `end_entry()`.
const ENTRY_NOT_OPEN: u64 = u64::MAX;

/// Returns `true` when an entry is currently open (being scanned).
#[inline(always)]
fn entry_is_open(frame: &ArchiveFrame) -> bool {
    frame.entry_decompressed_out != ENTRY_NOT_OPEN
}

/// Per-archive accounting frame pushed/popped by `enter_archive`/`exit_archive`.
///
/// Tracks entry counts, cumulative byte counters, and per-entry state for one
/// level of archive nesting.  Using `#[repr(C)]` with a compile-time size
/// assertion (48 bytes) ensures the layout is predictable and padding-free,
/// which matters because frames are `Copy`-initialized on every `enter_archive`.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
struct ArchiveFrame {
    /// Total entry records observed (headers, metadata records, regular files).
    entries_seen: u32,
    /// Entries for which at least one payload byte was scanned/emitted.
    entries_scanned: u32,
    /// Cumulative metadata bytes charged (central directory, tar headers, etc.).
    metadata_bytes: u64,
    /// Cumulative compressed input bytes consumed (for inflation ratio tracking).
    compressed_in: u64,
    /// Cumulative decompressed output bytes produced across all entries.
    decompressed_out: u64,
    /// Compressed input bytes consumed for the *current* entry.
    /// Reset at each `begin_entry_scan`.
    entry_compressed_in: u64,
    /// Decompressed bytes produced for the *current* entry.
    /// [`ENTRY_NOT_OPEN`] (`u64::MAX`) means no entry scope is active.
    entry_decompressed_out: u64,
}

impl Default for ArchiveFrame {
    #[inline]
    fn default() -> Self {
        Self {
            entries_seen: 0,
            entries_scanned: 0,
            metadata_bytes: 0,
            compressed_in: 0,
            decompressed_out: 0,
            entry_compressed_in: 0,
            entry_decompressed_out: ENTRY_NOT_OPEN,
        }
    }
}

impl ArchiveBudgets {
    /// True when at least one `enter_archive` is in effect.
    #[inline(always)]
    fn has_active_frame(&self) -> bool {
        self.depth > 0
    }

    /// Fallback hit used when a charge is attempted with no active frame.
    ///
    /// This should only happen if caller code is out of sequence; the
    /// conservative choice is `PartialArchive` rather than a panic.
    #[inline(always)]
    fn no_frame_hit(&self) -> BudgetHit {
        BudgetHit::PartialArchive(PartialReason::ArchiveOutputBudgetExceeded)
    }

    /// Construct a budget tracker from config, preallocating `max_archive_depth` frames.
    ///
    /// The per-entry byte cap is clamped to `ENTRY_NOT_OPEN - 1` so that
    /// saturating-add on `entry_decompressed_out` can never collide with the
    /// sentinel value (`u64::MAX`).
    ///
    /// The deadline is **not** armed here — call [`reset`](Self::reset) before
    /// the first root file to arm it.
    pub fn new(cfg: &ArchiveConfig) -> Self {
        let frames_cap = cfg.max_archive_depth as usize;
        Self {
            max_depth: cfg.max_archive_depth,
            max_entries_per_archive: cfg.max_entries_per_archive,
            max_uncompressed_bytes_per_entry: cfg
                .max_uncompressed_bytes_per_entry
                .min(ENTRY_NOT_OPEN - 1),
            max_total_uncompressed_bytes_per_archive: cfg.max_total_uncompressed_bytes_per_archive,
            max_total_uncompressed_bytes_per_root: cfg.max_total_uncompressed_bytes_per_root,
            max_archive_metadata_bytes: cfg.max_archive_metadata_bytes,
            max_inflation_ratio: cfg.max_inflation_ratio,

            max_wall_clock_secs: cfg.max_wall_clock_secs_per_root,
            deadline: None,

            #[cfg(any(test, feature = "sim-harness"))]
            deadline_check_countdown: std::cell::Cell::new(None),

            root_decompressed_out: 0,
            frames: vec![ArchiveFrame::default(); frames_cap].into_boxed_slice(),
            depth: 0,
        }
    }

    /// Reset all counters for a new root file, reusing the frame allocation.
    ///
    /// When `max_wall_clock_secs` is configured, this is the **only** place
    /// that calls `Instant::now()` to arm the deadline.  Nested archives share
    /// the root's deadline (they call `enter_archive`, not `reset`).
    ///
    /// If the configured duration is too large to represent as an `Instant`,
    /// `checked_add` returns `None` and the deadline is effectively disabled
    /// (equivalent to no wall-clock limit).
    #[inline]
    pub fn reset(&mut self) {
        debug_assert_eq!(
            self.depth, 0,
            "reset() must only be called at root level (depth 0)"
        );
        self.root_decompressed_out = 0;
        self.depth = 0;
        self.deadline = self
            .max_wall_clock_secs
            .and_then(|s| Instant::now().checked_add(Duration::from_secs(s)));
        debug_assert!(
            self.deadline.is_none() || self.max_wall_clock_secs.is_some(),
            "deadline armed without max_wall_clock_secs configured"
        );
        self.debug_assert_no_growth();
    }

    /// Debug-only guard: ensure the frame stack never grows beyond its
    /// preallocated capacity.
    #[inline]
    pub fn debug_assert_no_growth(&self) {
        #[cfg(debug_assertions)]
        {
            debug_assert_eq!(
                self.frames.len(),
                self.max_depth as usize,
                "archive budget frame stack length changed after startup"
            );
        }
    }

    /// Returns `true` if the wall-clock deadline has expired.
    ///
    /// When `max_wall_clock_secs` is `None`, this always returns `false`
    /// without calling `Instant::now()`.
    ///
    /// In test builds, if a countdown has been armed via
    /// [`set_deadline_check_countdown`](Self::set_deadline_check_countdown),
    /// each call decrements the counter instead of reading the clock.
    /// The method returns `true` when the counter reaches zero, giving
    /// tests deterministic control over when the timeout fires.
    #[inline(always)]
    pub fn is_deadline_expired(&self) -> bool {
        #[cfg(any(test, feature = "sim-harness"))]
        if let Some(n) = self.deadline_check_countdown.get() {
            if n == 0 {
                return true;
            }
            self.deadline_check_countdown.set(Some(n - 1));
            return false;
        }
        self.deadline.is_some_and(|d| Instant::now() >= d)
    }

    /// Arm a deterministic countdown that overrides `is_deadline_expired()`.
    ///
    /// After `n` calls to `is_deadline_expired()`, the method returns `true`
    /// regardless of the real clock. This allows tests to trigger a timeout
    /// at an exact point in the scan loop (e.g., after the first entry is
    /// fully processed but before the second entry begins).
    ///
    /// Pass `None` to disable the countdown and fall back to the real
    /// deadline.
    #[cfg(any(test, feature = "sim-harness"))]
    pub(crate) fn set_deadline_check_countdown(&self, n: Option<u32>) {
        self.deadline_check_countdown.set(n);
    }

    /// Current archive nesting depth (0 = no archive open).
    #[inline(always)]
    pub fn depth(&self) -> u8 {
        self.depth as u8
    }

    /// Cumulative decompressed bytes charged across all archives under this root.
    #[inline(always)]
    pub fn root_decompressed_out(&self) -> u64 {
        self.root_decompressed_out
    }

    /// Return a mutable reference to the topmost archive frame.
    ///
    /// # Safety
    ///
    /// `self.depth` is always in `0..=self.max_depth`, and `self.frames` is
    /// preallocated to exactly `self.max_depth` elements.  Every caller checks
    /// `has_active_frame()` (i.e. `depth > 0`) before reaching this method, so
    /// `depth - 1` is always a valid index.  The `debug_assert` catches
    /// violations in test builds.
    #[inline(always)]
    fn cur_mut(&mut self) -> &mut ArchiveFrame {
        debug_assert!(self.depth > 0, "enter_archive must be called first");
        // SAFETY: depth ∈ 1..=max_depth and frames.len() == max_depth.
        unsafe { self.frames.get_unchecked_mut(self.depth - 1) }
    }

    /// Return a shared reference to the topmost archive frame.
    ///
    /// See [`Self::cur_mut`] for the safety argument.
    #[inline(always)]
    fn cur(&self) -> &ArchiveFrame {
        debug_assert!(self.depth > 0, "enter_archive must be called first");
        // SAFETY: same as cur_mut.
        unsafe { self.frames.get_unchecked(self.depth - 1) }
    }

    /// Push a new archive frame onto the stack, enforcing the depth cap.
    ///
    /// The new frame is zero-initialized with `entry_decompressed_out` set to
    /// [`ENTRY_NOT_OPEN`] (no entry scope active).  Returns
    /// `Err(SkipArchive(DepthExceeded))` if the caller has already reached
    /// `max_archive_depth` levels of nesting.
    pub fn enter_archive(&mut self) -> Result<(), BudgetHit> {
        let next_depth = self.depth.saturating_add(1);
        if next_depth > self.max_depth as usize {
            return Err(BudgetHit::SkipArchive(ArchiveSkipReason::DepthExceeded));
        }
        self.frames[self.depth] = ArchiveFrame::default();
        self.depth = next_depth;
        Ok(())
    }

    /// Exit current archive scope (pops a frame).
    ///
    /// No-ops at depth 0 so that error-recovery paths can call this
    /// unconditionally without tracking whether `enter_archive` succeeded.
    pub fn exit_archive(&mut self) {
        if self.depth > 0 {
            self.depth -= 1;
        }
    }

    /// Count an archive entry record without opening an output-accounted payload stream.
    ///
    /// Used by tar for header records and metadata-only records (PAX, GNU longname),
    /// and for non-regular entries the scanner skips.  Does not reset per-entry
    /// byte counters (that requires [`begin_entry_scan`](Self::begin_entry_scan)).
    pub fn note_entry(&mut self) -> Result<(), BudgetHit> {
        if !self.has_active_frame() {
            return Err(self.no_frame_hit());
        }
        let max_entries = self.max_entries_per_archive;
        let f = self.cur_mut();
        if f.entries_seen == max_entries {
            // If we already scanned payload bytes or completed entries, the
            // archive has partial results worth keeping.  Otherwise it can
            // be treated as if it was never opened.
            if f.decompressed_out > 0 || f.entries_scanned > 0 {
                return Err(BudgetHit::PartialArchive(PartialReason::EntryCountExceeded));
            }
            return Err(BudgetHit::SkipArchive(
                ArchiveSkipReason::EntryCountExceeded,
            ));
        }
        f.entries_seen = f.entries_seen.saturating_add(1);
        Ok(())
    }

    /// Open an entry-level accounting scope (zeroes per-entry byte counters).
    ///
    /// Must be preceded by [`note_entry`](Self::note_entry).  While this scope
    /// is active, per-entry output and inflation-ratio caps apply to
    /// [`charge_decompressed_out`](Self::charge_decompressed_out).
    #[inline]
    pub fn begin_entry_scan(&mut self) {
        if !self.has_active_frame() {
            return;
        }
        let f = self.cur_mut();
        f.entry_compressed_in = 0;
        f.entry_decompressed_out = 0;
    }

    /// Convenience: [`note_entry`](Self::note_entry) + [`begin_entry_scan`](Self::begin_entry_scan).
    ///
    /// Use this for regular file entries where you intend to read payload bytes.
    /// Callers must call [`end_entry`](Self::end_entry) once done.
    pub fn begin_entry(&mut self) -> Result<(), BudgetHit> {
        self.note_entry()?;
        self.begin_entry_scan();
        Ok(())
    }

    /// Close the current entry accounting scope.
    ///
    /// `scanned=true` means at least one payload byte was scanned/emitted and
    /// counts toward `entries_scanned`. Call with `false` for metadata-only or
    /// skipped entries to keep progress accounting consistent.
    #[inline]
    pub fn end_entry(&mut self, scanned: bool) {
        if !self.has_active_frame() {
            return;
        }
        let f = self.cur_mut();
        if scanned {
            f.entries_scanned = f.entries_scanned.saturating_add(1);
        }
        f.entry_compressed_in = 0;
        f.entry_decompressed_out = ENTRY_NOT_OPEN;
    }

    /// Charge archive metadata bytes (central directory, tar headers, PAX, etc.).
    ///
    /// Metadata is tracked separately from decompressed output because it
    /// limits the parser's exposure to malicious headers (e.g., zip central
    /// directories with millions of entries) without consuming the archive's
    /// payload byte budget.
    #[inline]
    pub fn charge_metadata(&mut self, bytes: u64) -> ChargeResult {
        if bytes == 0 {
            return ChargeResult::Ok;
        }
        if !self.has_active_frame() {
            return ChargeResult::Clamp {
                allowed: 0,
                hit: self.no_frame_hit(),
            };
        }
        let hit = self.metadata_budget_hit_kind();
        let cap = self.max_archive_metadata_bytes;
        let f = self.cur_mut();
        charge_u64_with_cap(&mut f.metadata_bytes, bytes, cap, hit)
    }

    /// Charge compressed input bytes consumed for ratio tracking.
    ///
    /// This never triggers a budget directly; ratio enforcement happens when charging decompressed output.
    #[inline]
    pub fn charge_compressed_in(&mut self, bytes: u64) {
        if !self.has_active_frame() {
            return;
        }
        let f = self.cur_mut();
        f.compressed_in = f.compressed_in.saturating_add(bytes);
        if entry_is_open(f) {
            f.entry_compressed_in = f.entry_compressed_in.saturating_add(bytes);
        }
    }

    /// Charge decompressed output bytes across all three scopes (entry/archive/root).
    ///
    /// Computes the tightest remaining allowance among five independent caps:
    ///
    /// 1. **Entry output** — per-entry byte limit (only when an entry scope is open).
    /// 2. **Entry ratio** — `entry_in * R` (only when entry compressed bytes > 0).
    /// 3. **Archive output** — per-archive byte limit.
    /// 4. **Root output** — cross-archive byte limit for this source file.
    /// 5. **Archive ratio** — `archive_in * R` (only when archive compressed bytes > 0).
    ///
    /// Returns `Ok` if the full charge fits; otherwise returns `Clamp` with the
    /// allowed prefix and a [`BudgetHit`] identifying the binding constraint.
    /// When multiple caps are tied, the first in the priority list above wins,
    /// which ensures entry-scoped hits (cheaper to handle) take precedence over
    /// archive-scoped ones.
    #[inline]
    pub fn charge_decompressed_out(&mut self, bytes: u64) -> ChargeResult {
        if bytes == 0 {
            return ChargeResult::Ok;
        }
        if !self.has_active_frame() {
            return ChargeResult::Clamp {
                allowed: 0,
                hit: self.no_frame_hit(),
            };
        }

        // Snapshot all counters before mutation so the headroom calculations
        // see a consistent state.
        let max_entry = self.max_uncompressed_bytes_per_entry;
        let max_archive = self.max_total_uncompressed_bytes_per_archive;
        let max_root = self.max_total_uncompressed_bytes_per_root;
        let max_ratio = self.max_inflation_ratio;
        let root_out = self.root_decompressed_out;

        let (entry_out, entry_comp_in, arch_out, comp_in, entries_scanned) = {
            let f = self.cur();
            (
                f.entry_decompressed_out,
                f.entry_compressed_in,
                f.decompressed_out,
                f.compressed_in,
                f.entries_scanned,
            )
        };
        let entry_open = entry_out != ENTRY_NOT_OPEN;

        // Remaining headroom under each independent cap; the tightest wins.
        let rem_entry = if entry_open {
            remaining(max_entry, entry_out)
        } else {
            u64::MAX // no entry scope → entry cap does not apply
        };
        let rem_entry_ratio = if entry_open && max_ratio > 0 && entry_comp_in > 0 {
            remaining(entry_comp_in.saturating_mul(max_ratio as u64), entry_out)
        } else {
            u64::MAX // ratio disabled, no entry scope, or no entry compressed bytes yet
        };
        let rem_arch = remaining(max_archive, arch_out);
        let rem_root = remaining(max_root, root_out);
        let rem_ratio = if max_ratio > 0 && comp_in > 0 {
            remaining(comp_in.saturating_mul(max_ratio as u64), arch_out)
        } else {
            u64::MAX // ratio disabled or no compressed input observed yet
        };

        let min_rem = rem_entry
            .min(rem_entry_ratio)
            .min(rem_arch)
            .min(rem_root)
            .min(rem_ratio);
        let allowed = bytes.min(min_rem);

        if allowed > 0 {
            let f = self.cur_mut();
            if entry_is_open(f) {
                f.entry_decompressed_out = f.entry_decompressed_out.saturating_add(allowed);
                // Prevent counter from reaching the ENTRY_NOT_OPEN sentinel.
                if f.entry_decompressed_out == ENTRY_NOT_OPEN {
                    f.entry_decompressed_out = ENTRY_NOT_OPEN - 1;
                }
            }
            f.decompressed_out = f.decompressed_out.saturating_add(allowed);
            self.root_decompressed_out = self.root_decompressed_out.saturating_add(allowed);
        }

        if allowed == bytes {
            return ChargeResult::Ok;
        }

        // Identify which cap was the binding constraint.
        //
        // Priority order (first match wins):
        //   1. entry       — per-entry output cap
        //   2. entry ratio — per-entry inflation ratio cap
        //   3. archive     — per-archive output cap
        //   4. root        — root-level (cross-archive) output cap
        //   5. ratio       — archive-level inflation ratio cap
        //   6. fallback    — defensive (should be unreachable when caps are finite)
        //
        // `progressed` distinguishes "we scanned nothing from this archive"
        // (→ SkipArchive, the archive is treated as if it was never opened)
        // from "we scanned some entries/bytes" (→ PartialArchive, results so
        // far are still reported to the caller).
        let progressed = arch_out > 0 || entries_scanned > 0;
        let hit = if allowed == rem_entry {
            BudgetHit::SkipEntry(EntrySkipReason::EntryOutputBudgetExceeded)
        } else if allowed == rem_entry_ratio {
            BudgetHit::SkipEntry(EntrySkipReason::EntryInflationRatioExceeded)
        } else if allowed == rem_arch {
            if progressed {
                BudgetHit::PartialArchive(PartialReason::ArchiveOutputBudgetExceeded)
            } else {
                BudgetHit::SkipArchive(ArchiveSkipReason::ArchiveOutputBudgetExceeded)
            }
        } else if allowed == rem_root {
            BudgetHit::StopRoot(PartialReason::RootOutputBudgetExceeded)
        } else if allowed == rem_ratio {
            if progressed {
                BudgetHit::PartialArchive(PartialReason::InflationRatioExceeded)
            } else {
                BudgetHit::SkipArchive(ArchiveSkipReason::InflationRatioExceeded)
            }
        } else {
            // Defensive fallback — should not be reachable when caps are finite.
            debug_assert!(
                false,
                "unreachable: allowed={allowed} must equal one of \
                 rem_entry={rem_entry}, rem_entry_ratio={rem_entry_ratio}, \
                 rem_arch={rem_arch}, rem_root={rem_root}, rem_ratio={rem_ratio}"
            );
            BudgetHit::PartialArchive(PartialReason::ArchiveOutputBudgetExceeded)
        };

        ChargeResult::Clamp { allowed, hit }
    }

    /// Charge decompressed bytes that were produced but **not** scanned.
    ///
    /// Decoders sometimes produce trailing bytes after the scan limit is hit
    /// (e.g., a gzip stream that inflates past the per-entry cap).  Those bytes
    /// were already produced so they must count toward archive/root totals and
    /// inflation ratio, but they intentionally bypass the per-entry *output*
    /// cap — that cap governs how much the scanner *looks at*, not how much
    /// the decoder produced.
    ///
    /// Per-entry inflation ratio is still enforced: discarded bytes advance
    /// `entry_decompressed_out`, so a `SkipEntry(EntryInflationRatioExceeded)`
    /// can still fire here.
    #[inline]
    pub fn charge_discarded_out(&mut self, bytes: u64) -> ChargeResult {
        if bytes == 0 {
            return ChargeResult::Ok;
        }
        if !self.has_active_frame() {
            return ChargeResult::Clamp {
                allowed: 0,
                hit: self.no_frame_hit(),
            };
        }

        let max_archive = self.max_total_uncompressed_bytes_per_archive;
        let max_root = self.max_total_uncompressed_bytes_per_root;
        let max_ratio = self.max_inflation_ratio;
        let root_out = self.root_decompressed_out;

        let (entry_open, entry_out, entry_comp_in, arch_out, comp_in, entries_scanned) = {
            let f = self.cur();
            (
                entry_is_open(f),
                f.entry_decompressed_out,
                f.entry_compressed_in,
                f.decompressed_out,
                f.compressed_in,
                f.entries_scanned,
            )
        };

        let rem_entry_ratio = if entry_open && max_ratio > 0 && entry_comp_in > 0 {
            remaining(entry_comp_in.saturating_mul(max_ratio as u64), entry_out)
        } else {
            u64::MAX
        };
        let rem_arch = remaining(max_archive, arch_out);
        let rem_root = remaining(max_root, root_out);
        let rem_ratio = if max_ratio > 0 && comp_in > 0 {
            remaining(comp_in.saturating_mul(max_ratio as u64), arch_out)
        } else {
            u64::MAX
        };

        let min_rem = rem_entry_ratio.min(rem_arch).min(rem_root).min(rem_ratio);
        let allowed = bytes.min(min_rem);

        if allowed > 0 {
            let f = self.cur_mut();
            if entry_is_open(f) {
                f.entry_decompressed_out = f.entry_decompressed_out.saturating_add(allowed);
                // Prevent counter from reaching the ENTRY_NOT_OPEN sentinel.
                if f.entry_decompressed_out == ENTRY_NOT_OPEN {
                    f.entry_decompressed_out = ENTRY_NOT_OPEN - 1;
                }
            }
            f.decompressed_out = f.decompressed_out.saturating_add(allowed);
            self.root_decompressed_out = self.root_decompressed_out.saturating_add(allowed);
        }

        if allowed == bytes {
            return ChargeResult::Ok;
        }

        let progressed = arch_out > 0 || entries_scanned > 0;
        let hit = if allowed == rem_entry_ratio {
            BudgetHit::SkipEntry(EntrySkipReason::EntryInflationRatioExceeded)
        } else if allowed == rem_arch {
            if progressed {
                BudgetHit::PartialArchive(PartialReason::ArchiveOutputBudgetExceeded)
            } else {
                BudgetHit::SkipArchive(ArchiveSkipReason::ArchiveOutputBudgetExceeded)
            }
        } else if allowed == rem_root {
            BudgetHit::StopRoot(PartialReason::RootOutputBudgetExceeded)
        } else if allowed == rem_ratio {
            if progressed {
                BudgetHit::PartialArchive(PartialReason::InflationRatioExceeded)
            } else {
                BudgetHit::SkipArchive(ArchiveSkipReason::InflationRatioExceeded)
            }
        } else {
            debug_assert!(
                false,
                "unreachable: allowed={allowed} must equal one of \
                 rem_entry_ratio={rem_entry_ratio}, rem_arch={rem_arch}, \
                 rem_root={rem_root}, rem_ratio={rem_ratio}"
            );
            BudgetHit::PartialArchive(PartialReason::ArchiveOutputBudgetExceeded)
        };

        ChargeResult::Clamp { allowed, hit }
    }

    /// Best-effort remaining decompressed bytes that may be produced right now.
    ///
    /// Scanners use this to size their read buffers so a single decoder call
    /// does not overshoot the budget by a large margin.  The value is
    /// advisory — the authoritative check is [`charge_decompressed_out`](Self::charge_decompressed_out).
    #[inline]
    pub fn remaining_decompressed_allowance(&self) -> u64 {
        self.remaining_decompressed_allowance_with_ratio_probe(false)
    }

    /// Remaining decompressed bytes, with an optional conservative ratio probe.
    ///
    /// When `ratio_active` is `true`, the archive-level ratio cap is applied
    /// even if no compressed bytes have been observed yet — it assumes 1 byte
    /// of compressed input, limiting the first read to `max_inflation_ratio`
    /// bytes.  This prevents a large first-read overshoot in compressed
    /// formats (gzip, deflate).  For uncompressed containers (plain tar,
    /// stored zip entries) pass `false`.
    ///
    /// Per-entry ratio is only applied once `entry_compressed_in > 0`; before
    /// that, the entry-ratio dimension is unconstrained.
    #[inline]
    pub fn remaining_decompressed_allowance_with_ratio_probe(&self, ratio_active: bool) -> u64 {
        if !self.has_active_frame() {
            return 0;
        }
        let f = self.cur();

        let mut rem = remaining(
            self.max_total_uncompressed_bytes_per_root,
            self.root_decompressed_out,
        );

        let rem_arch = remaining(
            self.max_total_uncompressed_bytes_per_archive,
            f.decompressed_out,
        );
        rem = rem.min(rem_arch);

        if entry_is_open(f) {
            let rem_entry = remaining(
                self.max_uncompressed_bytes_per_entry,
                f.entry_decompressed_out,
            );
            rem = rem.min(rem_entry);
        }

        // Ratio enforcement (optional): out <= in * ratio.
        if ratio_active && self.max_inflation_ratio > 0 {
            let ratio = self.max_inflation_ratio as u64;
            let comp_in = if f.compressed_in > 0 {
                f.compressed_in
            } else {
                // Conservative probe: assume at least 1 compressed byte to cap
                // the first read and avoid large overshoot.
                1
            };
            let max_out = comp_in.saturating_mul(ratio);
            let rem_ratio = remaining(max_out, f.decompressed_out);
            rem = rem.min(rem_ratio);

            if entry_is_open(f) && f.entry_compressed_in > 0 {
                let entry_max_out = f.entry_compressed_in.saturating_mul(ratio);
                let rem_entry_ratio = remaining(entry_max_out, f.entry_decompressed_out);
                rem = rem.min(rem_entry_ratio);
            }
        }

        rem
    }

    /// Choose `SkipArchive` vs `PartialArchive` for a metadata budget overrun.
    ///
    /// Uses the same "progressed" heuristic as `charge_decompressed_out`:
    /// if no payload bytes were produced and no entries were scanned, the
    /// archive is treated as never opened.
    fn metadata_budget_hit_kind(&self) -> BudgetHit {
        let f = self.cur();
        if f.decompressed_out == 0 && f.entries_scanned == 0 {
            BudgetHit::SkipArchive(ArchiveSkipReason::MetadataBudgetExceeded)
        } else {
            BudgetHit::PartialArchive(PartialReason::MetadataBudgetExceeded)
        }
    }
}

/// Headroom remaining under a budget cap, floored at zero.
#[inline(always)]
fn remaining(cap: u64, used: u64) -> u64 {
    cap.saturating_sub(used)
}

/// Charge `bytes` against `counter` up to `cap`, returning [`ChargeResult::Ok`]
/// when the full amount fits or [`ChargeResult::Clamp`] with the allowed prefix.
///
/// This is the shared primitive behind [`ArchiveBudgets::charge_metadata`] and
/// similar single-counter charge paths.
#[inline]
fn charge_u64_with_cap(counter: &mut u64, bytes: u64, cap: u64, hit: BudgetHit) -> ChargeResult {
    if bytes == 0 {
        return ChargeResult::Ok;
    }
    let rem = remaining(cap, *counter);
    let allowed = bytes.min(rem);
    if allowed > 0 {
        *counter = counter.saturating_add(allowed);
    }
    if allowed == bytes {
        ChargeResult::Ok
    } else {
        ChargeResult::Clamp { allowed, hit }
    }
}

// Guard against accidental padding: 2 * u32 + 5 * u64 = 48 bytes exactly.
// Adding a field without adjusting the layout will break this assertion.
const _: () = assert!(std::mem::size_of::<ArchiveFrame>() == 48);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::ArchiveConfig;
    use rstest::rstest;

    fn cfg() -> ArchiveConfig {
        ArchiveConfig {
            enabled: true,
            max_archive_depth: 2,
            max_entries_per_archive: 2,
            max_uncompressed_bytes_per_entry: 10,
            max_total_uncompressed_bytes_per_archive: 20,
            max_total_uncompressed_bytes_per_root: 30,
            max_archive_metadata_bytes: 8,
            max_inflation_ratio: 2,
            ..ArchiveConfig::default()
        }
    }

    #[test]
    fn depth_zero_calls_are_safe() {
        let mut b = ArchiveBudgets::new(&cfg());
        let hit = BudgetHit::PartialArchive(PartialReason::ArchiveOutputBudgetExceeded);

        assert_eq!(b.remaining_decompressed_allowance(), 0);
        assert_eq!(b.remaining_decompressed_allowance_with_ratio_probe(true), 0);
        assert_eq!(
            b.charge_metadata(1),
            ChargeResult::Clamp { allowed: 0, hit }
        );
        b.charge_compressed_in(5);
        assert_eq!(
            b.charge_decompressed_out(1),
            ChargeResult::Clamp { allowed: 0, hit }
        );
        assert_eq!(b.note_entry().unwrap_err(), hit);
        assert_eq!(b.begin_entry().unwrap_err(), hit);
        b.begin_entry_scan();
        b.end_entry(false);
        b.exit_archive();
        assert_eq!(b.root_decompressed_out(), 0);
    }

    #[test]
    fn depth_is_enforced() {
        let mut b = ArchiveBudgets::new(&cfg());
        assert!(b.enter_archive().is_ok());
        assert!(b.enter_archive().is_ok());
        assert_eq!(
            b.enter_archive().unwrap_err(),
            BudgetHit::SkipArchive(ArchiveSkipReason::DepthExceeded)
        );
    }

    #[test]
    fn metadata_budget_clamps_and_reports_skip_before_progress() {
        let mut b = ArchiveBudgets::new(&cfg());
        b.enter_archive().unwrap();

        let r = b.charge_metadata(100);
        assert_eq!(
            r,
            ChargeResult::Clamp {
                allowed: 8,
                hit: BudgetHit::SkipArchive(ArchiveSkipReason::MetadataBudgetExceeded)
            }
        );
    }

    #[test]
    fn entry_count_reports_partial_after_progress() {
        let mut b = ArchiveBudgets::new(&cfg());
        b.enter_archive().unwrap();

        // Scan one entry with 1 byte to create progress.
        b.begin_entry().unwrap();
        assert_eq!(b.charge_decompressed_out(1), ChargeResult::Ok);
        b.end_entry(true);

        // Second entry ok.
        b.begin_entry().unwrap();
        b.end_entry(false);

        // Third entry exceeds cap -> partial.
        assert_eq!(
            b.begin_entry().unwrap_err(),
            BudgetHit::PartialArchive(PartialReason::EntryCountExceeded)
        );
    }

    #[test]
    fn entry_output_cap_clamps_and_skips_entry() {
        let mut b = ArchiveBudgets::new(&cfg());
        b.enter_archive().unwrap();
        b.begin_entry().unwrap();

        // Request 15 bytes; entry cap is 10.
        let r = b.charge_decompressed_out(15);
        assert_eq!(
            r,
            ChargeResult::Clamp {
                allowed: 10,
                hit: BudgetHit::SkipEntry(EntrySkipReason::EntryOutputBudgetExceeded)
            }
        );
    }

    #[test]
    fn archive_output_cap_clamps_and_reports_partial_after_progress() {
        let mut c = cfg();
        c.max_uncompressed_bytes_per_entry = 100;

        let mut b = ArchiveBudgets::new(&c);
        b.enter_archive().unwrap();
        b.begin_entry().unwrap();

        // Fill archive to cap (20) across requests.
        assert_eq!(b.charge_decompressed_out(20), ChargeResult::Ok);

        // Next byte clamps to 0 and reports partial.
        let r = b.charge_decompressed_out(1);
        assert_eq!(
            r,
            ChargeResult::Clamp {
                allowed: 0,
                hit: BudgetHit::PartialArchive(PartialReason::ArchiveOutputBudgetExceeded)
            }
        );
    }

    #[test]
    fn root_output_cap_stops_root() {
        let mut c = cfg();
        c.max_total_uncompressed_bytes_per_root = 5;

        let mut b = ArchiveBudgets::new(&c);
        b.enter_archive().unwrap();
        b.begin_entry().unwrap();

        assert_eq!(b.charge_decompressed_out(5), ChargeResult::Ok);
        let r = b.charge_decompressed_out(1);
        assert_eq!(
            r,
            ChargeResult::Clamp {
                allowed: 0,
                hit: BudgetHit::StopRoot(PartialReason::RootOutputBudgetExceeded)
            }
        );
    }

    #[test]
    fn entry_inflation_ratio_is_enforced() {
        let mut b = ArchiveBudgets::new(&cfg());
        b.enter_archive().unwrap();
        b.begin_entry().unwrap();

        // compressed_in=2, ratio=2 => max_out=4
        b.charge_compressed_in(2);
        assert_eq!(b.charge_decompressed_out(4), ChargeResult::Ok);

        let r = b.charge_decompressed_out(1);
        assert_eq!(
            r,
            ChargeResult::Clamp {
                allowed: 0,
                hit: BudgetHit::SkipEntry(EntrySkipReason::EntryInflationRatioExceeded)
            }
        );
    }

    #[test]
    fn entry_ratio_resets_across_entries() {
        let mut c = cfg();
        c.max_entries_per_archive = 8;
        c.max_uncompressed_bytes_per_entry = 100;
        c.max_total_uncompressed_bytes_per_archive = 1000;
        c.max_total_uncompressed_bytes_per_root = 1000;

        let mut b = ArchiveBudgets::new(&c);
        b.enter_archive().unwrap();

        b.begin_entry().unwrap();
        b.charge_compressed_in(2);
        assert_eq!(b.charge_decompressed_out(4), ChargeResult::Ok);
        assert_eq!(
            b.charge_decompressed_out(1),
            ChargeResult::Clamp {
                allowed: 0,
                hit: BudgetHit::SkipEntry(EntrySkipReason::EntryInflationRatioExceeded)
            }
        );
        b.end_entry(true);

        b.begin_entry().unwrap();
        b.charge_compressed_in(2);
        assert_eq!(b.charge_decompressed_out(4), ChargeResult::Ok);
        assert_eq!(
            b.charge_decompressed_out(1),
            ChargeResult::Clamp {
                allowed: 0,
                hit: BudgetHit::SkipEntry(EntrySkipReason::EntryInflationRatioExceeded)
            }
        );
    }

    #[test]
    fn entry_ratio_independent_of_archive_ratio() {
        let mut c = cfg();
        c.max_entries_per_archive = 8;
        c.max_uncompressed_bytes_per_entry = 256;
        c.max_total_uncompressed_bytes_per_archive = 4096;
        c.max_total_uncompressed_bytes_per_root = 4096;

        let mut b = ArchiveBudgets::new(&c);
        b.enter_archive().unwrap();

        // Entry 1 contributes large archive-level compressed credit.
        b.begin_entry().unwrap();
        b.charge_compressed_in(64);
        assert_eq!(b.charge_decompressed_out(64), ChargeResult::Ok);
        b.end_entry(true);

        // Entry 2 still enforces its own ratio regardless of archive credit.
        b.begin_entry().unwrap();
        b.charge_compressed_in(1);
        assert_eq!(b.charge_decompressed_out(2), ChargeResult::Ok);
        assert_eq!(
            b.charge_decompressed_out(1),
            ChargeResult::Clamp {
                allowed: 0,
                hit: BudgetHit::SkipEntry(EntrySkipReason::EntryInflationRatioExceeded)
            }
        );
    }

    #[test]
    fn credit_accumulation_attack_prevented() {
        let mut c = cfg();
        c.max_entries_per_archive = 128;
        c.max_uncompressed_bytes_per_entry = 1024;
        c.max_total_uncompressed_bytes_per_archive = 16 * 1024;
        c.max_total_uncompressed_bytes_per_root = 16 * 1024;

        let mut b = ArchiveBudgets::new(&c);
        b.enter_archive().unwrap();

        for _ in 0..99 {
            b.begin_entry().unwrap();
            b.charge_compressed_in(8);
            assert_eq!(b.charge_decompressed_out(8), ChargeResult::Ok);
            b.end_entry(true);
        }

        b.begin_entry().unwrap();
        b.charge_compressed_in(1);
        assert_eq!(b.charge_decompressed_out(2), ChargeResult::Ok);
        assert_eq!(
            b.charge_decompressed_out(1),
            ChargeResult::Clamp {
                allowed: 0,
                hit: BudgetHit::SkipEntry(EntrySkipReason::EntryInflationRatioExceeded)
            }
        );
    }

    #[test]
    fn entry_ratio_zero_compressed_in_returns_max() {
        let mut c = cfg();
        c.max_uncompressed_bytes_per_entry = 1024;
        c.max_total_uncompressed_bytes_per_archive = 1024;
        c.max_total_uncompressed_bytes_per_root = 1024;

        let mut b = ArchiveBudgets::new(&c);
        b.enter_archive().unwrap();
        b.begin_entry().unwrap();

        // No compressed bytes observed yet; entry ratio does not clamp.
        assert_eq!(b.charge_decompressed_out(32), ChargeResult::Ok);
    }

    #[test]
    fn ratio_probe_caps_initial_allowance() {
        let mut b = ArchiveBudgets::new(&cfg());
        b.enter_archive().unwrap();
        b.begin_entry().unwrap();

        // No compressed bytes observed yet; probe should cap to ratio (2).
        let rem = b.remaining_decompressed_allowance_with_ratio_probe(true);
        assert_eq!(rem, 2);
    }

    /// When entry and archive caps are tied, the entry cap wins (SkipEntry,
    /// not PartialArchive).  This locks in the priority ordering of the
    /// branchless hit-identification chain.
    #[test]
    fn tied_entry_and_archive_caps_prefer_skip_entry() {
        let mut c = cfg();
        // Set entry cap == archive cap so they exhaust simultaneously.
        c.max_uncompressed_bytes_per_entry = 10;
        c.max_total_uncompressed_bytes_per_archive = 10;
        c.max_total_uncompressed_bytes_per_root = 1000;

        let mut b = ArchiveBudgets::new(&c);
        b.enter_archive().unwrap();
        b.begin_entry().unwrap();

        // Charge exactly up to the shared cap.
        assert_eq!(b.charge_decompressed_out(10), ChargeResult::Ok);

        // Next byte hits both caps; entry should win.
        let r = b.charge_decompressed_out(1);
        assert_eq!(
            r,
            ChargeResult::Clamp {
                allowed: 0,
                hit: BudgetHit::SkipEntry(EntrySkipReason::EntryOutputBudgetExceeded)
            }
        );
    }

    /// `charge_discarded_out` intentionally bypasses the per-entry cap.
    /// After the entry cap is exhausted via `charge_decompressed_out`, discarded
    /// bytes should still be accepted up to the archive/root caps.
    #[test]
    fn discarded_out_bypasses_entry_cap() {
        let mut c = cfg();
        c.max_uncompressed_bytes_per_entry = 5;
        c.max_total_uncompressed_bytes_per_archive = 100;
        c.max_total_uncompressed_bytes_per_root = 1000;

        let mut b = ArchiveBudgets::new(&c);
        b.enter_archive().unwrap();
        b.begin_entry().unwrap();

        // Exhaust the per-entry cap.
        assert_eq!(b.charge_decompressed_out(5), ChargeResult::Ok);
        assert_eq!(
            b.charge_decompressed_out(1),
            ChargeResult::Clamp {
                allowed: 0,
                hit: BudgetHit::SkipEntry(EntrySkipReason::EntryOutputBudgetExceeded)
            }
        );

        // Discarded bytes should still succeed (entry cap does not apply).
        assert_eq!(b.charge_discarded_out(10), ChargeResult::Ok);
    }

    #[test]
    fn discarded_out_enforces_entry_ratio_when_entry_open() {
        let mut c = cfg();
        c.max_uncompressed_bytes_per_entry = 100;
        c.max_total_uncompressed_bytes_per_archive = 1000;
        c.max_total_uncompressed_bytes_per_root = 1000;

        let mut b = ArchiveBudgets::new(&c);
        b.enter_archive().unwrap();
        b.begin_entry().unwrap();
        b.charge_compressed_in(2);

        assert_eq!(b.charge_discarded_out(4), ChargeResult::Ok);
        assert_eq!(
            b.charge_discarded_out(1),
            ChargeResult::Clamp {
                allowed: 0,
                hit: BudgetHit::SkipEntry(EntrySkipReason::EntryInflationRatioExceeded)
            }
        );
    }

    /// Entry counters reset correctly across open/close/reopen cycles.
    /// The second entry gets its full per-entry budget regardless of what
    /// the first entry consumed.
    #[test]
    fn entry_lifecycle_reopen_resets_counter() {
        let mut c = cfg();
        c.max_uncompressed_bytes_per_entry = 10;
        c.max_total_uncompressed_bytes_per_archive = 100;
        c.max_total_uncompressed_bytes_per_root = 1000;
        c.max_entries_per_archive = 10;

        let mut b = ArchiveBudgets::new(&c);
        b.enter_archive().unwrap();

        // First entry: consume full per-entry budget.
        b.begin_entry().unwrap();
        assert_eq!(b.charge_decompressed_out(10), ChargeResult::Ok);
        assert_eq!(
            b.charge_decompressed_out(1),
            ChargeResult::Clamp {
                allowed: 0,
                hit: BudgetHit::SkipEntry(EntrySkipReason::EntryOutputBudgetExceeded)
            }
        );
        b.end_entry(true);

        // Second entry: should get a fresh per-entry budget of 10.
        b.begin_entry().unwrap();
        assert_eq!(b.charge_decompressed_out(10), ChargeResult::Ok);
        assert_eq!(
            b.charge_decompressed_out(1),
            ChargeResult::Clamp {
                allowed: 0,
                hit: BudgetHit::SkipEntry(EntrySkipReason::EntryOutputBudgetExceeded)
            }
        );
        b.end_entry(true);
    }

    #[test]
    fn ratio_zero_disables_all_ratio_enforcement() {
        let mut c = cfg();
        c.max_inflation_ratio = 0;
        c.max_uncompressed_bytes_per_entry = u64::MAX;
        c.max_total_uncompressed_bytes_per_archive = u64::MAX;
        c.max_total_uncompressed_bytes_per_root = u64::MAX;

        let mut b = ArchiveBudgets::new(&c);
        b.enter_archive().unwrap();
        b.begin_entry().unwrap();
        b.charge_compressed_in(1);
        // ratio=0 disables enforcement; unlimited output allowed.
        assert_eq!(b.charge_decompressed_out(1_000_000), ChargeResult::Ok);
    }

    /// The constructor clamps `max_uncompressed_bytes_per_entry` to
    /// `ENTRY_NOT_OPEN - 1`, preventing the sentinel collision where
    /// `saturating_add` could reach `u64::MAX`.
    #[test]
    fn sentinel_collision_prevented_by_constructor_clamp() {
        let mut c = cfg();
        c.max_uncompressed_bytes_per_entry = u64::MAX;
        c.max_total_uncompressed_bytes_per_archive = u64::MAX;
        c.max_total_uncompressed_bytes_per_root = u64::MAX;

        let b = ArchiveBudgets::new(&c);
        assert_eq!(b.max_uncompressed_bytes_per_entry, ENTRY_NOT_OPEN - 1);
    }

    /// Deadline configuration behaves correctly across all edge cases:
    /// - `None` → never expires (no wall-clock limit configured)
    /// - `Some(0)` after reset → expires immediately (safe degradation)
    /// - `Some(60)` after reset → not expired yet (normal operation)
    /// - `Some(u64::MAX)` after reset → saturates without panic
    /// - `Some(0)` without reset → not expired (deadline only armed by reset)
    #[rstest]
    #[case::none_never_expires(None, true, false)]
    #[case::zero_expires_immediately(Some(0), true, true)]
    #[case::large_not_expired_immediately(Some(60), true, false)]
    #[case::huge_secs_saturates(Some(u64::MAX), true, false)]
    #[case::not_armed_before_reset(Some(0), false, false)]
    fn deadline_config(
        #[case] wall_clock: Option<u64>,
        #[case] do_reset: bool,
        #[case] expected_expired: bool,
    ) {
        let mut c = cfg();
        c.max_wall_clock_secs_per_root = wall_clock;
        let mut b = ArchiveBudgets::new(&c);
        if do_reset {
            b.reset();
        }
        assert_eq!(b.is_deadline_expired(), expected_expired);
    }

    /// `enter_archive()` must not clear or re-arm the deadline — nested
    /// archives share the root's deadline set by `reset()`.
    #[test]
    fn enter_archive_preserves_deadline() {
        let mut c = cfg();
        c.max_wall_clock_secs_per_root = Some(3600);
        let mut b = ArchiveBudgets::new(&c);
        b.reset();
        assert!(!b.is_deadline_expired());

        b.enter_archive().unwrap();
        // Deadline must still be set and not expired after entering a nested frame.
        assert!(!b.is_deadline_expired());

        b.enter_archive().unwrap();
        assert!(!b.is_deadline_expired());
    }

    /// Successive `reset()` calls must each re-arm the deadline so that every
    /// root-level scan gets a fresh timeout budget.
    #[test]
    fn reset_rearms_deadline_on_second_call() {
        let mut c = cfg();
        c.max_wall_clock_secs_per_root = Some(60);
        let mut b = ArchiveBudgets::new(&c);

        b.reset();
        assert!(
            !b.is_deadline_expired(),
            "first reset should arm a valid deadline"
        );

        b.reset();
        assert!(
            !b.is_deadline_expired(),
            "second reset should re-arm a fresh, non-expired deadline"
        );
    }
}

#[cfg(all(test, feature = "stdx-proptest"))]
mod proptests {
    use super::*;
    use crate::archive::ArchiveConfig;
    use proptest::prelude::*;

    /// Operations that exercise the full budget protocol surface.
    /// Byte amounts are kept small (u16) to make cap interactions frequent
    /// without needing astronomically large configs.
    #[derive(Debug, Clone)]
    enum Op {
        EnterArchive,
        ExitArchive,
        BeginEntry,
        EndEntry(bool),
        ChargeCompressedIn(u16),
        ChargeDecompressedOut(u16),
        ChargeDiscardedOut(u16),
        ChargeMetadata(u16),
    }

    fn op_strategy() -> impl Strategy<Value = Op> {
        prop_oneof![
            2 => Just(Op::EnterArchive),
            1 => Just(Op::ExitArchive),
            3 => Just(Op::BeginEntry),
            2 => any::<bool>().prop_map(Op::EndEntry),
            3 => (1u16..=512).prop_map(Op::ChargeCompressedIn),
            4 => (1u16..=512).prop_map(Op::ChargeDecompressedOut),
            2 => (1u16..=512).prop_map(Op::ChargeDiscardedOut),
            1 => (1u16..=128).prop_map(Op::ChargeMetadata),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        /// Verify budget charging invariants hold for arbitrary operation sequences.
        ///
        /// Invariants checked after every charge:
        /// 1. Monotonicity: `root_decompressed_out` never decreases.
        /// 2. Conservation: after `charge_decompressed_out(n)`, the root counter
        ///    increased by exactly `n` (Ok) or `allowed` (Clamp), and `allowed <= n`.
        /// 3. Bound: `root_decompressed_out` never exceeds the configured root cap.
        /// 4. Sentinel safety: `entry_decompressed_out` never reaches `ENTRY_NOT_OPEN`.
        #[test]
        fn budget_charging_invariants(ops in prop::collection::vec(op_strategy(), 1..80)) {
            let c = ArchiveConfig {
                enabled: true,
                max_archive_depth: 3,
                max_entries_per_archive: 16,
                max_uncompressed_bytes_per_entry: 1024,
                max_total_uncompressed_bytes_per_archive: 4096,
                max_total_uncompressed_bytes_per_root: 8192,
                max_archive_metadata_bytes: 256,
                max_inflation_ratio: 4,
                ..ArchiveConfig::default()
            };
            let mut b = ArchiveBudgets::new(&c);
            let mut prev_root = 0u64;

            for op in &ops {
                match op {
                    Op::EnterArchive => { let _ = b.enter_archive(); }
                    Op::ExitArchive => b.exit_archive(),
                    Op::BeginEntry => { let _ = b.begin_entry(); }
                    Op::EndEntry(scanned) => b.end_entry(*scanned),
                    Op::ChargeCompressedIn(n) => b.charge_compressed_in(*n as u64),
                    Op::ChargeDecompressedOut(n) => {
                        let n = *n as u64;
                        let before = b.root_decompressed_out();
                        let result = b.charge_decompressed_out(n);

                        let after = b.root_decompressed_out();

                        // Invariant 1: monotonicity.
                        prop_assert!(after >= before, "root_decompressed_out decreased");

                        // Invariant 2: conservation + clamp bound.
                        match result {
                            ChargeResult::Ok => {
                                prop_assert_eq!(after, before + n,
                                    "Ok must advance root counter by exactly n");
                            }
                            ChargeResult::Clamp { allowed, .. } => {
                                prop_assert!(allowed <= n,
                                    "allowed ({}) > requested ({})", allowed, n);
                                prop_assert_eq!(after, before + allowed,
                                    "Clamp must advance root counter by exactly allowed");
                            }
                        }

                        // Invariant 3: root bound.
                        prop_assert!(after <= c.max_total_uncompressed_bytes_per_root,
                            "root_decompressed_out ({}) exceeds root cap ({})",
                            after, c.max_total_uncompressed_bytes_per_root);

                        prev_root = after;
                    }
                    Op::ChargeDiscardedOut(n) => {
                        let n = *n as u64;
                        let before = b.root_decompressed_out();
                        let result = b.charge_discarded_out(n);

                        let after = b.root_decompressed_out();

                        // Monotonicity.
                        prop_assert!(after >= before, "root_decompressed_out decreased");

                        // Conservation + clamp bound.
                        match result {
                            ChargeResult::Ok => {
                                prop_assert_eq!(after, before + n,
                                    "Ok must advance root counter by exactly n");
                            }
                            ChargeResult::Clamp { allowed, .. } => {
                                prop_assert!(allowed <= n,
                                    "allowed ({}) > requested ({})", allowed, n);
                                prop_assert_eq!(after, before + allowed,
                                    "Clamp must advance root counter by exactly allowed");
                            }
                        }

                        // Root bound.
                        prop_assert!(after <= c.max_total_uncompressed_bytes_per_root,
                            "root_decompressed_out ({}) exceeds root cap ({})",
                            after, c.max_total_uncompressed_bytes_per_root);

                        prev_root = after;
                    }
                    Op::ChargeMetadata(n) => {
                        let _ = b.charge_metadata(*n as u64);
                    }
                }

                // Invariant 4: sentinel safety — if an entry is open, its
                // decompressed counter must not have reached the sentinel value.
                if b.has_active_frame() {
                    let f = b.cur();
                    if entry_is_open(f) {
                        prop_assert_ne!(f.entry_decompressed_out, ENTRY_NOT_OPEN,
                            "entry_decompressed_out reached ENTRY_NOT_OPEN sentinel");
                    }
                }

                // Re-check monotonicity across all operations (not just charges).
                let current = b.root_decompressed_out();
                prop_assert!(current >= prev_root,
                    "root_decompressed_out decreased across operations");
                prev_root = current;
            }
        }

        /// Allowance consistency: `charge_decompressed_out(n)` returns `Ok` when
        /// `n <= remaining_decompressed_allowance()`.
        #[test]
        fn allowance_predicts_charge_result(
            ops in prop::collection::vec(op_strategy(), 1..40),
            probe in 1u16..=256,
        ) {
            let c = ArchiveConfig {
                enabled: true,
                max_archive_depth: 3,
                max_entries_per_archive: 16,
                max_uncompressed_bytes_per_entry: 1024,
                max_total_uncompressed_bytes_per_archive: 4096,
                max_total_uncompressed_bytes_per_root: 8192,
                max_archive_metadata_bytes: 256,
                max_inflation_ratio: 0, // disable ratio to isolate byte-cap behavior
                ..ArchiveConfig::default()
            };
            let mut b = ArchiveBudgets::new(&c);

            // Run the prefix sequence to reach an arbitrary state.
            for op in &ops {
                match op {
                    Op::EnterArchive => { let _ = b.enter_archive(); }
                    Op::ExitArchive => b.exit_archive(),
                    Op::BeginEntry => { let _ = b.begin_entry(); }
                    Op::EndEntry(scanned) => b.end_entry(*scanned),
                    Op::ChargeCompressedIn(n) => b.charge_compressed_in(*n as u64),
                    Op::ChargeDecompressedOut(n) => { b.charge_decompressed_out(*n as u64); }
                    Op::ChargeDiscardedOut(n) => { b.charge_discarded_out(*n as u64); }
                    Op::ChargeMetadata(n) => { b.charge_metadata(*n as u64); }
                }
            }

            let allowance = b.remaining_decompressed_allowance();
            let n = probe as u64;
            if n <= allowance {
                let result = b.charge_decompressed_out(n);
                prop_assert_eq!(result, ChargeResult::Ok,
                    "charge of {} should succeed with allowance {}", n, allowance);
            }
        }
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;
    use crate::archive::ArchiveConfig;

    /// Prove that `depth - 1` is always a valid index into `frames` whenever
    /// `has_active_frame()` returns true, for any sequence of enter/exit ops.
    ///
    /// This is the safety invariant relied on by `cur()` and `cur_mut()`.
    /// The proof bounds `max_archive_depth` to 3 (the production default)
    /// and explores 6 symbolic operations to keep the state space tractable.
    #[kani::proof]
    #[kani::unwind(8)]
    fn verify_budget_cur_bounds() {
        let depth: u8 = kani::any();
        kani::assume(depth >= 1 && depth <= 4);

        let cfg = ArchiveConfig {
            max_archive_depth: depth,
            ..ArchiveConfig::default()
        };
        let mut b = ArchiveBudgets::new(&cfg);

        kani::assert(
            b.frames.len() == depth as usize,
            "frames must be preallocated to max_depth",
        );

        // Perform a symbolic sequence of enter/exit operations.
        // 6 ops with max_depth ≤ 4 exercises all reachable depth transitions.
        let mut i = 0u32;
        while i < 6 {
            let enter: bool = kani::any();
            if enter {
                let _ = b.enter_archive();
            } else {
                b.exit_archive();
            }

            // Core invariant: whenever depth > 0, depth - 1 is in bounds.
            if b.has_active_frame() {
                kani::assert(b.depth >= 1, "has_active_frame implies depth >= 1");
                kani::assert(
                    b.depth - 1 < b.frames.len(),
                    "depth - 1 must be a valid frame index",
                );
            }

            // Secondary invariant: depth never exceeds max_depth.
            kani::assert(
                b.depth <= depth as usize,
                "depth must never exceed max_depth",
            );

            i += 1;
        }
    }
}
