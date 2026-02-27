- New file: `crates/gossip-contracts/src/connector/conformance.rs`
- Updated file: `crates/gossip-contracts/src/connector/mod.rs`

Below is the full code for both files.

---

## `crates/gossip-contracts/src/connector/mod.rs`

```rust
//! Connector boundary types + traits + conformance tooling.
//!
//! The intent is that *every* connector crate only needs to depend on this module.
//! The runtime (later) should also only depend on this module, not on connector-specific types.

mod api;
mod page_validator;
mod types;

pub mod conformance;

pub use api::{
    ConnectorCapabilities, EnumerationConnector, EnumerateError, ErrorClass, ReadConnector, ReadError,
};
pub use page_validator::{
    validate_page_range, PageValidationError, PageValidationViolation, ToxicDigest,
};
pub use types::{
    Budgets, ConnectorInputError, ContentHints, Cursor, EnumerationPage, ItemKey, ItemRef, Location,
    ScanItem, TokenBytes,
};
```

---

## `crates/gossip-contracts/src/connector/conformance.rs`

````rust
//! Connector conformance harness (Chunk 4).
//!
//! This is intentionally "spec-as-tests":
//! - It validates every enumerate_page() output using validate_page_range() (Chunk 3).
//! - It enforces additional hard requirements that are awkward to express page-locally.
//! - It runs multi-call checks: token loss / token corruption restartability, determinism.
//!
//! Safety requirement: never print raw ItemKey/ItemRef/token bytes in errors.
//! All diagnostics are digests + indices.

use std::collections::{HashMap, HashSet};
use std::fmt;

use blake3;

use super::{
    validate_page_range, Budgets, Cursor, EnumerationPage, ItemKey, ItemRef, ScanItem, TokenBytes,
};

use super::api::{ConnectorCapabilities, EnumerateError};
use super::page_validator::PageValidationError;

/// Default best-effort patterns that should never appear inside an ItemRef.
///
/// Notes:
/// - This is a heuristic. False positives are extremely unlikely.
/// - For higher confidence, also pass `secret_canaries` via [`SecretScanConfig`].
const DEFAULT_FORBIDDEN_ITEMREF_PATTERNS: &[&[u8]] = &[
    b"Authorization:",
    b"Bearer ",
    b"AKIA",                 // AWS Access Key ID prefix (common)
    b"ASIA",                 // AWS temporary Access Key ID prefix (common)
    b"x-amz-security-token", // AWS session token header/query key
    b"X-Amz-Signature=",
    b"X-Amz-Credential=",
    b"GoogleAccessId=",
    b"-----BEGIN ", // PEM blocks (private keys/certs)
];

/// Whether the harness should enforce determinism.
///
/// Determinism is only meaningful relative to a declared EnumerationView.
/// For connectors whose view is inherently mutable (Continuous), set this to BestEffort.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeterminismExpectation {
    Deterministic,
    BestEffort,
}

/// Resume-by-key multi-call checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResumeChecks {
    /// Simulate losing pagination tokens and require resumption using last_key alone.
    pub drop_token: bool,
    /// Simulate corrupting pagination tokens and require resumption using last_key alone.
    pub corrupt_token: bool,
}

impl Default for ResumeChecks {
    fn default() -> Self {
        Self {
            drop_token: true,
            corrupt_token: true,
        }
    }
}

/// Best-effort secret scanning configuration for ItemRef bytes.
#[derive(Clone, Debug)]
pub struct SecretScanConfig {
    pub enabled: bool,
    pub forbidden_substrings: Vec<&'static [u8]>,
    /// Caller-provided sentinels to ensure credentials/config secrets never leak into ItemRef.
    ///
    /// Treat these as sensitive: harness errors will not print them.
    pub secret_canaries: Vec<Vec<u8>>,
}

impl Default for SecretScanConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            forbidden_substrings: DEFAULT_FORBIDDEN_ITEMREF_PATTERNS.to_vec(),
            secret_canaries: Vec::new(),
        }
    }
}

/// Conformance harness knobs.
///
/// Defaults are intentionally strict for Stage 3.
#[derive(Clone, Debug)]
pub struct ConformanceConfig {
    /// Maximum number of enumerate_page calls per run (prevents infinite loops).
    pub max_pages: usize,
    /// Maximum number of items collected per run (prevents accidental OOM in tests).
    pub max_total_items: usize,
    /// Budgets passed to enumerate_page calls from the harness.
    ///
    /// Recommendation: keep `max_items` small to force pagination.
    pub page_budgets: Budgets,

    /// Require keys to be strictly increasing (no duplicates).
    ///
    /// With a Cursor that only stores last_key and "resume after last_key" semantics,
    /// allowing duplicate keys can create permanent gaps.
    pub require_strict_key_order: bool,

    /// Require that if a page returns items, next_cursor.last_key == last_item_key.
    ///
    /// This disallows "jumping" the last_key forward past returned keys (which can skip).
    pub require_cursor_eq_last_item: bool,

    pub determinism: DeterminismExpectation,
    pub resume_checks: ResumeChecks,
    pub secret_scan: SecretScanConfig,

    /// Restart point selection for resume-by-key tests.
    ///
    /// `Auto(n)` chooses up to `n` cursor checkpoints spread across the run.
    pub restart_points: RestartPoints,
}

impl Default for ConformanceConfig {
    fn default() -> Self {
        Self {
            max_pages: 10_000,
            max_total_items: 1_000_000,
            // Force pagination by default.
            page_budgets: Budgets::new(32, u64::MAX, None),
            require_strict_key_order: true,
            require_cursor_eq_last_item: true,
            determinism: DeterminismExpectation::Deterministic,
            resume_checks: ResumeChecks::default(),
            secret_scan: SecretScanConfig::default(),
            restart_points: RestartPoints::Auto(4),
        }
    }
}

/// How restart points are selected for resume-by-key checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestartPoints {
    /// Choose up to N restart points spread across the run.
    Auto(usize),
    /// Explicit cursor indices into the trace's `cursors` array.
    ///
    /// Index 0 is the initial cursor. Index i is the cursor after page i-1.
    Explicit(&'static [usize]),
}

/// A safe digest type for toxic bytes, usable in HashMap/HashSet and error messages.
///
/// We intentionally do not reuse `ToxicDigest` here because `ToxicDigest`'s fields are private,
/// and we need `Hash` + easy accessors for mapping.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Digest32 {
    len: u32,
    hash: [u8; 32],
}

impl Digest32 {
    pub fn of_bytes(bytes: &[u8]) -> Self {
        let h = blake3::hash(bytes);
        Self {
            len: u32::try_from(bytes.len()).unwrap_or(u32::MAX),
            hash: *h.as_bytes(),
        }
    }

    pub fn prefix8_hex(&self) -> String {
        // 8 bytes -> 16 hex chars
        let mut s = String::with_capacity(16);
        for b in &self.hash[..8] {
            s.push_str(&format!("{:02x}", b));
        }
        s
    }
}

impl fmt::Debug for Digest32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Digest32")
            .field("len", &self.len)
            .field("hash_prefix8", &self.prefix8_hex())
            .finish()
    }
}

impl fmt::Display for Digest32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Keep this compact and safe.
        write!(f, "len={} hash_prefix8={}", self.len, self.prefix8_hex())
    }
}

/// What we compare across runs.
/// This is intentionally a hash, so we never store/print raw toxic bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ItemObservation {
    pub key: Digest32,
    pub fingerprint: [u8; 32],
}

impl ItemObservation {
    fn fingerprint_prefix8_hex(&self) -> String {
        let mut s = String::with_capacity(16);
        for b in &self.fingerprint[..8] {
            s.push_str(&format!("{:02x}", b));
        }
        s
    }
}

impl fmt::Display for ItemObservation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // No raw anything. Just digests.
        write!(
            f,
            "key=({}) item_fp_prefix8={}",
            self.key,
            self.fingerprint_prefix8_hex()
        )
    }
}

/// Collected trace from a single enumeration run.
#[derive(Clone, Debug)]
pub struct EnumerationTrace {
    /// Items in the order they were produced (post-validation).
    pub items: Vec<ItemObservation>,
    /// Cursor checkpoints:
    /// - cursors[0] is the initial cursor used
    /// - cursors[i+1] is the cursor returned by page i
    pub cursors: Vec<Cursor>,
    pub pages: usize,
}

#[derive(Debug)]
pub enum ConformanceError {
    CapabilityMissingSeekByKey {
        caps: ConnectorCapabilities,
    },

    EnumerateFailed {
        at_page: usize,
        class: super::api::ErrorClass,
    },

    ReturnedTooManyItems {
        at_page: usize,
        got: usize,
        max: usize,
    },

    PageValidationFailed {
        at_page: usize,
        err: PageValidationError,
    },

    NotStrictlyIncreasingWithinPage {
        at_page: usize,
        at_index: usize,
        prev_key: Digest32,
        next_key: Digest32,
    },

    CursorDoesNotMatchLastItem {
        at_page: usize,
        cursor_key: Option<Digest32>,
        last_item_key: Digest32,
    },

    DuplicateKeyInRun {
        key: Digest32,
    },

    TooManyPages {
        max_pages: usize,
    },

    TooManyItems {
        max_total_items: usize,
    },

    DeterminismMismatch {
        at_index: usize,
        run1: ItemObservation,
        run2: ItemObservation,
    },

    ResumeMismatch {
        /// Which cursor checkpoint we restarted from (index into trace.cursors).
        restart_cursor_index: usize,
        mode: ResumeMode,
        at_index: usize,
        expected: ItemObservation,
        got: ItemObservation,
    },

    ResumeLengthMismatch {
        restart_cursor_index: usize,
        mode: ResumeMode,
        expected_len: usize,
        got_len: usize,
    },

    ItemRefAppearsToContainSecret {
        /// Digest of the suspicious pattern (never print raw).
        pattern: Digest32,
        /// Digest of the full item_ref.
        item_ref: Digest32,
    },
}

impl fmt::Display for ConformanceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use ConformanceError::*;
        match self {
            CapabilityMissingSeekByKey { caps } => {
                write!(f, "connector caps missing seek_by_key: {:?}", caps)
            }
            EnumerateFailed { at_page, class } => {
                write!(f, "enumerate_page failed at page {} with {:?}", at_page, class)
            }
            ReturnedTooManyItems { at_page, got, max } => {
                write!(
                    f,
                    "enumerate_page returned too many items at page {} (got {}, max {})",
                    at_page, got, max
                )
            }
            PageValidationFailed { at_page, err } => {
                write!(f, "page validation failed at page {}: {}", at_page, err)
            }
            NotStrictlyIncreasingWithinPage {
                at_page,
                at_index,
                prev_key,
                next_key,
            } => {
                write!(
                    f,
                    "keys not strictly increasing within page {} at index {}: prev=({}) next=({})",
                    at_page, at_index, prev_key, next_key
                )
            }
            CursorDoesNotMatchLastItem {
                at_page,
                cursor_key,
                last_item_key,
            } => {
                write!(
                    f,
                    "next_cursor.last_key mismatch at page {}: cursor={:?}, last_item=({})",
                    at_page, cursor_key, last_item_key
                )
            }
            DuplicateKeyInRun { key } => {
                write!(f, "duplicate key observed in run: ({})", key)
            }
            TooManyPages { max_pages } => write!(f, "too many pages (max {})", max_pages),
            TooManyItems { max_total_items } => {
                write!(f, "too many items collected (max {})", max_total_items)
            }
            DeterminismMismatch { at_index, run1, run2 } => {
                write!(
                    f,
                    "determinism mismatch at item index {}: run1={} run2={}",
                    at_index, run1, run2
                )
            }
            ResumeMismatch {
                restart_cursor_index,
                mode,
                at_index,
                expected,
                got,
            } => {
                write!(
                    f,
                    "resume mismatch (restart_cursor_index={}, mode={:?}) at suffix index {}: expected={} got={}",
                    restart_cursor_index, mode, at_index, expected, got
                )
            }
            ResumeLengthMismatch {
                restart_cursor_index,
                mode,
                expected_len,
                got_len,
            } => {
                write!(
                    f,
                    "resume length mismatch (restart_cursor_index={}, mode={:?}): expected_len={} got_len={}",
                    restart_cursor_index, mode, expected_len, got_len
                )
            }
            ItemRefAppearsToContainSecret { pattern, item_ref } => {
                write!(
                    f,
                    "item_ref appears to contain secret substring: pattern=({}) item_ref=({})",
                    pattern, item_ref
                )
            }
        }
    }
}

impl std::error::Error for ConformanceError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResumeMode {
    DropToken,
    CorruptToken,
}

/// Main entry point for connector conformance.
///
/// The harness is generic over connector type `C` and uses caller-provided closures
/// to avoid coupling to a specific shard/spec type.
///
/// Expected usage in a connector crate:
///
/// ```ignore
/// let cfg = ConformanceConfig::default();
/// assert_connector_conforms(
///     || MyConnector::new(...),
///     |c| c.caps(),
///     |c, cursor, budgets| c.enumerate_page(&spec, cursor, budgets),
///     &spec.start,
///     &spec.end,
///     cfg,
/// )?;
/// ```
pub fn assert_connector_conforms<C, Make, Caps, Enum>(
    make: Make,
    caps: Caps,
    enumerate_page: Enum,
    start: &ItemKey,
    end: &ItemKey,
    cfg: ConformanceConfig,
) -> Result<(), ConformanceError>
where
    Make: Fn() -> C,
    Caps: Fn(&C) -> ConnectorCapabilities,
    Enum: Fn(&mut C, &Cursor, Budgets) -> Result<EnumerationPage, EnumerateError>,
{
    // Capability gate: Stage 3 / B1 requires seek-by-key resumability (or manifest-native).
    // For now: require seek_by_key in caps, because manifest-native is not modeled here yet.
    {
        let c = make();
        let c_caps = caps(&c);
        if !c_caps.seek_by_key {
            return Err(ConformanceError::CapabilityMissingSeekByKey { caps: c_caps });
        }
    }

    // Baseline run.
    let baseline = collect_trace(&make, &enumerate_page, start, end, &cfg, Cursor::initial())?;

    // Determinism (full-run) check.
    if cfg.determinism == DeterminismExpectation::Deterministic {
        let run2 = collect_trace(&make, &enumerate_page, start, end, &cfg, Cursor::initial())?;
        assert_same_items(&baseline.items, &run2.items)?;
    }

    // Resume-by-key checks.
    if cfg.resume_checks.drop_token || cfg.resume_checks.corrupt_token {
        run_resume_checks(&make, &enumerate_page, start, end, &cfg, &baseline)?;
    }

    Ok(())
}

fn collect_trace<C, Make, Enum>(
    make: &Make,
    enumerate_page: &Enum,
    start: &ItemKey,
    end: &ItemKey,
    cfg: &ConformanceConfig,
    initial_cursor: Cursor,
) -> Result<EnumerationTrace, ConformanceError>
where
    Make: Fn() -> C,
    Enum: Fn(&mut C, &Cursor, Budgets) -> Result<EnumerationPage, EnumerateError>,
{
    let mut connector = make();

    let mut pages = 0usize;
    let mut items: Vec<ItemObservation> = Vec::new();
    let mut cursors: Vec<Cursor> = Vec::new();

    // Cursor checkpoints include the starting cursor.
    let mut cursor = initial_cursor;
    cursors.push(cursor.clone());

    // Track key uniqueness across the whole run (when strict order is required).
    let mut seen_keys: HashSet<Digest32> = HashSet::new();

    loop {
        if pages >= cfg.max_pages {
            return Err(ConformanceError::TooManyPages {
                max_pages: cfg.max_pages,
            });
        }

        let page = enumerate_page(&mut connector, &cursor, cfg.page_budgets).map_err(|e| {
            ConformanceError::EnumerateFailed {
                at_page: pages,
                class: e.class,
            }
        })?;

        if page.items.len() > cfg.page_budgets.max_items {
            return Err(ConformanceError::ReturnedTooManyItems {
                at_page: pages,
                got: page.items.len(),
                max: cfg.page_budgets.max_items,
            });
        }

        // Page validator hard gate (Chunk 3).
        validate_page_range(
            start.as_bytes(),
            end.as_bytes(),
            cursor.last_key().map(|k| k.as_bytes()),
            &page.items,
            page.next_cursor.last_key().map(|k| k.as_bytes()),
        )
        .map_err(|e| ConformanceError::PageValidationFailed { at_page: pages, err: e })?;

        // Additional strictness: key uniqueness and strict ordering within page.
        if cfg.require_strict_key_order {
            assert_strict_increasing_within_page(pages, &page.items)?;
        }

        // Additional strictness: next_cursor.last_key must match the last returned item key.
        if cfg.require_cursor_eq_last_item && !page.items.is_empty() {
            let last_item_key = Digest32::of_bytes(page.items.last().unwrap().item_key.as_bytes());
            let cursor_key = page.next_cursor.last_key().map(|k| Digest32::of_bytes(k.as_bytes()));
            if cursor_key != Some(last_item_key) {
                return Err(ConformanceError::CursorDoesNotMatchLastItem {
                    at_page: pages,
                    cursor_key,
                    last_item_key,
                });
            }
        }

        // Secret scan for ItemRef (best-effort).
        if cfg.secret_scan.enabled {
            for it in &page.items {
                assert_item_ref_secret_free(&it.item_ref, &cfg.secret_scan)?;
            }
        }

        // Record items.
        for it in &page.items {
            if items.len() >= cfg.max_total_items {
                return Err(ConformanceError::TooManyItems {
                    max_total_items: cfg.max_total_items,
                });
            }

            let obs = observe_item(it);
            if cfg.require_strict_key_order {
                if !seen_keys.insert(obs.key) {
                    return Err(ConformanceError::DuplicateKeyInRun { key: obs.key });
                }
            }
            items.push(obs);
        }

        // Advance cursor and record checkpoint.
        let next = page.next_cursor.clone();
        cursors.push(next.clone());

        // Termination condition: empty page + cursor doesn't advance (validator enforces last_key not advancing).
        if page.items.is_empty() {
            pages += 1;
            break;
        }

        cursor = next;
        pages += 1;
    }

    Ok(EnumerationTrace {
        items,
        cursors,
        pages,
    })
}

fn assert_same_items(a: &[ItemObservation], b: &[ItemObservation]) -> Result<(), ConformanceError> {
    let min_len = a.len().min(b.len());
    for i in 0..min_len {
        if a[i] != b[i] {
            return Err(ConformanceError::DeterminismMismatch {
                at_index: i,
                run1: a[i],
                run2: b[i],
            });
        }
    }
    if a.len() != b.len() {
        // Represent length mismatch as a mismatch at the first out-of-range index.
        // The caller can infer the issue from the lengths printed in surrounding test output.
        let idx = min_len;
        let run1 = a.get(idx).copied().unwrap_or(ItemObservation {
            key: Digest32::of_bytes(b""),
            fingerprint: [0u8; 32],
        });
        let run2 = b.get(idx).copied().unwrap_or(ItemObservation {
            key: Digest32::of_bytes(b""),
            fingerprint: [0u8; 32],
        });
        return Err(ConformanceError::DeterminismMismatch {
            at_index: idx,
            run1,
            run2,
        });
    }
    Ok(())
}

fn run_resume_checks<C, Make, Enum>(
    make: &Make,
    enumerate_page: &Enum,
    start: &ItemKey,
    end: &ItemKey,
    cfg: &ConformanceConfig,
    baseline: &EnumerationTrace,
) -> Result<(), ConformanceError>
where
    Make: Fn() -> C,
    Enum: Fn(&mut C, &Cursor, Budgets) -> Result<EnumerationPage, EnumerateError>,
{
    // Map from key digest to baseline index (keys are required unique under strict config).
    let mut key_to_index: HashMap<Digest32, usize> = HashMap::new();
    for (idx, obs) in baseline.items.iter().enumerate() {
        key_to_index.insert(obs.key, idx);
    }

    // Decide restart cursor checkpoints.
    let restart_indices = select_restart_points(cfg.restart_points, baseline.cursors.len());

    for &cursor_idx in &restart_indices {
        let restart_cursor = baseline
            .cursors
            .get(cursor_idx)
            .expect("restart index must be in bounds")
            .clone();

        let expected_suffix = expected_suffix_from_cursor(&restart_cursor, &baseline.items, &key_to_index);

        if cfg.resume_checks.drop_token {
            let dropped = drop_token(&restart_cursor);
            let got = collect_suffix(make, enumerate_page, start, end, cfg, dropped)?;
            assert_same_suffix(cursor_idx, ResumeMode::DropToken, &expected_suffix, &got)?;
        }

        if cfg.resume_checks.corrupt_token {
            let corrupted = corrupt_token(&restart_cursor, cursor_idx as u64);
            let got = collect_suffix(make, enumerate_page, start, end, cfg, corrupted)?;
            assert_same_suffix(cursor_idx, ResumeMode::CorruptToken, &expected_suffix, &got)?;
        }
    }

    Ok(())
}

fn collect_suffix<C, Make, Enum>(
    make: &Make,
    enumerate_page: &Enum,
    start: &ItemKey,
    end: &ItemKey,
    cfg: &ConformanceConfig,
    cursor: Cursor,
) -> Result<Vec<ItemObservation>, ConformanceError>
where
    Make: Fn() -> C,
    Enum: Fn(&mut C, &Cursor, Budgets) -> Result<EnumerationPage, EnumerateError>,
{
    // We reuse collect_trace but discard its cursor checkpoints and just return items.
    let trace = collect_trace(make, enumerate_page, start, end, cfg, cursor)?;
    Ok(trace.items)
}

fn assert_same_suffix(
    restart_cursor_index: usize,
    mode: ResumeMode,
    expected: &[ItemObservation],
    got: &[ItemObservation],
) -> Result<(), ConformanceError> {
    if expected.len() != got.len() {
        return Err(ConformanceError::ResumeLengthMismatch {
            restart_cursor_index,
            mode,
            expected_len: expected.len(),
            got_len: got.len(),
        });
    }

    for i in 0..expected.len() {
        if expected[i] != got[i] {
            return Err(ConformanceError::ResumeMismatch {
                restart_cursor_index,
                mode,
                at_index: i,
                expected: expected[i],
                got: got[i],
            });
        }
    }

    Ok(())
}

fn expected_suffix_from_cursor(
    cursor: &Cursor,
    baseline_items: &[ItemObservation],
    key_to_index: &HashMap<Digest32, usize>,
) -> Vec<ItemObservation> {
    match cursor.last_key() {
        None => baseline_items.to_vec(),
        Some(k) => {
            let d = Digest32::of_bytes(k.as_bytes());
            match key_to_index.get(&d) {
                None => {
                    // If the cursor last_key isn't in the baseline items (e.g., initial or end sentinel),
                    // then the safest expectation is "baseline suffix is empty or full depending on ordering".
                    // For our contract (resume AFTER last_key), we treat it as "start after unknown key",
                    // which should yield the same as starting from that cursor anyway.
                    //
                    // Returning empty avoids false failures. Connectors should not generate such cursors in practice.
                    Vec::new()
                }
                Some(&idx) => baseline_items[(idx + 1)..].to_vec(),
            }
        }
    }
}

fn select_restart_points(mode: RestartPoints, cursor_len: usize) -> Vec<usize> {
    if cursor_len == 0 {
        return vec![];
    }

    match mode {
        RestartPoints::Explicit(idxs) => idxs
            .iter()
            .copied()
            .filter(|&i| i < cursor_len)
            .collect(),

        RestartPoints::Auto(n) => {
            if n == 0 {
                return vec![];
            }
            // Always include 0, and then spread up to n-1 additional indices.
            // We choose indices in [0, cursor_len-1].
            let mut out = Vec::new();
            out.push(0);

            if cursor_len == 1 {
                return out;
            }

            let targets = n.saturating_sub(1);
            if targets == 0 {
                return out;
            }

            // Spread indices roughly evenly, including the last cursor checkpoint.
            // Example for cursor_len=10, targets=3 -> indices: 3, 6, 9 (plus 0)
            for t in 1..=targets {
                let idx = (t * (cursor_len - 1)) / targets;
                out.push(idx);
            }

            out.sort_unstable();
            out.dedup();
            out
        }
    }
}

fn assert_strict_increasing_within_page(
    at_page: usize,
    items: &[ScanItem],
) -> Result<(), ConformanceError> {
    for i in 0..items.len().saturating_sub(1) {
        let a = items[i].item_key.as_bytes();
        let b = items[i + 1].item_key.as_bytes();
        if a >= b {
            return Err(ConformanceError::NotStrictlyIncreasingWithinPage {
                at_page,
                at_index: i,
                prev_key: Digest32::of_bytes(a),
                next_key: Digest32::of_bytes(b),
            });
        }
    }
    Ok(())
}

fn observe_item(item: &ScanItem) -> ItemObservation {
    let key = Digest32::of_bytes(item.item_key.as_bytes());
    let fingerprint = fingerprint_item(item);
    ItemObservation { key, fingerprint }
}

fn fingerprint_item(item: &ScanItem) -> [u8; 32] {
    // The fingerprint is intentionally a hash of stable-ish fields.
    // It lets us compare runs without ever keeping/printing raw toxic bytes.
    //
    // We include:
    // - item_key bytes
    // - item_ref bytes
    // - stable_item_id + version via Debug bytes (safe: should not be secret)
    //
    // If you later want stronger typing, swap this to use stable_id/version byte accessors directly.
    let mut hasher = blake3::Hasher::new();
    hasher.update(item.item_key.as_bytes());
    hasher.update(item.item_ref.as_bytes());

    // Avoid depending on private fields of identity types.
    // Assumption: Debug output for stable ids / version ids is deterministic and non-secret.
    hasher.update(format!("{:?}", item.stable_item_id).as_bytes());
    hasher.update(format!("{:?}", item.version).as_bytes());

    *hasher.finalize().as_bytes()
}

fn drop_token(cursor: &Cursor) -> Cursor {
    match cursor.last_key().cloned() {
        None => Cursor::initial(),
        Some(k) => Cursor::with_last_key(k),
    }
}

fn corrupt_token(cursor: &Cursor, seed: u64) -> Cursor {
    // Only valid if we have a last_key.
    let Some(k) = cursor.last_key().cloned() else {
        return Cursor::initial();
    };

    let mut buf = [0u8; 8];
    buf.copy_from_slice(&seed.to_le_bytes());
    let h = blake3::hash(&buf);

    // 16 bytes is enough for "garbage token" without blowing caps.
    let token = TokenBytes::try_from_slice(&h.as_bytes()[..16])
        .expect("16 bytes should always be a valid TokenBytes");

    Cursor::with_token(k, token)
}

fn assert_item_ref_secret_free(
    item_ref: &ItemRef,
    cfg: &SecretScanConfig,
) -> Result<(), ConformanceError> {
    let bytes = item_ref.as_bytes();

    for pat in &cfg.forbidden_substrings {
        if contains_subslice(bytes, pat) {
            return Err(ConformanceError::ItemRefAppearsToContainSecret {
                pattern: Digest32::of_bytes(pat),
                item_ref: Digest32::of_bytes(bytes),
            });
        }
    }

    for canary in &cfg.secret_canaries {
        if !canary.is_empty() && contains_subslice(bytes, canary) {
            return Err(ConformanceError::ItemRefAppearsToContainSecret {
                pattern: Digest32::of_bytes(canary),
                item_ref: Digest32::of_bytes(bytes),
            });
        }
    }

    Ok(())
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if needle.len() > haystack.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

// ---------------------------
// Tests (stubs are allowed)
// ---------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn select_restart_points_auto_is_bounded_and_sorted() {
        let pts = select_restart_points(RestartPoints::Auto(4), 10);
        assert!(!pts.is_empty());
        assert!(pts.windows(2).all(|w| w[0] <= w[1]));
        assert!(pts.iter().all(|&i| i < 10));
    }

    #[test]
    fn contains_subslice_basic() {
        assert!(contains_subslice(b"hello bearer world", b"bearer"));
        assert!(!contains_subslice(b"hello world", b"bearer"));
    }

    // NOTE: Full harness property tests will come once we add reference connectors (Chunk 5).
    // At that point we can:
    // - run assert_connector_conforms() against InMemoryDeterministicConnector
    // - generate random key streams and validate resumability/determinism end-to-end
    #[test]
    fn harness_end_to_end_todo() {
        // TODO (Chunk 5): wire in an in-memory deterministic connector and call assert_connector_conforms().
    }
}
````

---

### What this harness enforces right now

- Page-level invariants via `validate_page_range(...)` (membership, monotonic cursor, ordered output, empty-page semantics, etc)
- Budget boundedness: `items.len() <= budgets.max_items`
- Strict key uniqueness (optional, default on) and strict ordering within page (default on)
- Cursor safety: `next_cursor.last_key == last_item_key` if the page returned items (default on)
- Resume-by-key: restart from arbitrary checkpoint cursors with token dropped or corrupted and require identical suffix stream
- Determinism: two full runs must produce identical item stream (configurable)
- Best-effort ItemRef secret scanning (default on) including injected canaries

This is the “hard gate” for connectors going forward.
