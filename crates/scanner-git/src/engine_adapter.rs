//! Engine adapter for Git blob scanning.
//!
//! Bridges decoded blob bytes into the core `Engine` using overlap-safe chunking
//! and a fixed-size ring buffer, then aggregates findings per blob with
//! deterministic ordering.
//!
//! # Per-blob pipeline
//!
//! Each blob flows through four stages:
//!
//! 1. **Classify** (`scan_blob_into_buf`) — text blobs are scanned directly,
//!    extractable binary formats (`.class`, `.pyc`, etc.) have their text
//!    extracted first, and opaque binaries are skipped.
//! 2. **Scan** — blob bytes are fed through overlap-safe chunk windows.
//!    Blobs that fit in a single chunk skip the ring buffer entirely
//!    (fast path); larger blobs stream through `RingChunker` (slow path).
//! 3. **Stream** (`stream_findings`) — findings are emitted to the
//!    structured `EventSink` for real-time consumption. A `CommitMeta`
//!    event is emitted at most once per commit via `AtomicBitSet`.
//! 4. **Record** (`record_findings`) — findings are appended to the shared
//!    arena and the resulting `FindingSpan` is attached to the `ScannedBlob`.
//!
//! # Chunking algorithm
//!
//! 1. Stream blob bytes into fixed windows using `RingChunker`.
//! 2. Scan each window with `Engine::scan_chunk_into` at the correct base offset.
//! 3. Drop findings that fall entirely inside the overlap prefix so each match
//!    is recorded exactly once.
//! 4. Convert findings into `FindingKey` values (no raw secret bytes).
//! 5. Sort + dedup per blob to guarantee deterministic ordering.
//!
//! # Design
//!
//! - Chunk overlap uses `Engine::required_overlap()` and
//!   `ScanScratch::drop_prefix_findings`.
//! - A fixed-size ring buffer streams blob bytes into the scanner, avoiding
//!   per-blob allocations beyond the chunk window.
//! - Findings are stored in a shared arena with per-blob spans, so individual
//!   blobs reference contiguous slices rather than owning separate `Vec`s.
//! - `CommitMeta` events are emitted at most once per commit using an
//!   `AtomicBitSet` shared across all adapter instances. See
//!   [`EngineAdapter::stream_findings`] for the exactly-once protocol.
//!
//! # Invariants
//!
//! - Results are returned in candidate order.
//! - `ScannedBlob.findings` indexes into the adapter's findings arena.
//! - Path refs in results point into the mapping arena supplied by the caller.
//! - When the debug allocation guard is enabled, scanning must not allocate.

use std::fmt;
use std::sync::Arc;

use gix_commitgraph::Position;

use crate::events::{CommitMetaEvent, DiagnosticEvent, EventSink, FindingEvent, ScanEvent};
use gossip_stdx::AtomicBitSet;
use scanner_engine::content_policy::{self, ContentVerdict};
use scanner_engine::{Engine, FileId, NormHash, ScanScratch};
use scanner_scheduler::source_kind::SourceKind;
use scanner_scheduler::AllocGuard;

use super::commit_graph::CommitGraphIndex;
use super::identity_intern::IdentityInterner;

use super::alloc_guard;
use super::object_id::OidBytes;
use super::pack_candidates::{LooseCandidate, PackCandidate};
use super::pack_exec::{PackExecError, PackObjectSink};
use super::tree_candidate::CandidateContext;
use scanner_engine::perf_counters as perf;

/// Bundles the event sink and commit-graph state needed for exactly-once
/// `CommitMeta` emission during scanning.
///
/// This exists as a single argument bundle so that runner entry-points can
/// thread all commit-attribution state into per-worker
/// [`EngineAdapter::new_with_event_sink`] calls without growing the
/// argument list every time a new shared resource is added.
pub struct CommitMetaContext {
    /// Structured event sink for streaming scan progress and diagnostics.
    pub event_sink: Arc<dyn EventSink>,
    /// Maps commit-graph positions to OIDs, timestamps, and (optionally)
    /// identity data.
    pub commit_graph_index: Arc<CommitGraphIndex>,
    /// Emit-once bitset — one bit per commit-graph position.
    pub commit_meta_seen: Arc<AtomicBitSet>,
    /// Identity interner for resolving intern IDs to raw name/email bytes.
    ///
    /// Present when identity enrichment is enabled (`enrich_identities`).
    /// The runner reads this for upfront `IdentityDictionary` emission;
    /// it is carried here to avoid a separate plumbing path through the
    /// scheduler into per-worker adapter construction.
    pub identity_interner: Option<Arc<IdentityInterner>>,
}

/// Default chunk window size for adapter scanning (1 MiB).
pub const DEFAULT_CHUNK_BYTES: usize = 1 << 20;

/// Engine adapter configuration.
///
/// Controls the chunking strategy and content-policy behavior for scanning.
/// Larger `chunk_bytes` reduce per-blob overhead but increase peak memory;
/// the default (1 MiB) balances throughput and resident memory.
#[derive(Clone, Copy, Debug)]
pub struct EngineAdapterConfig {
    /// Total chunk window size in bytes (overlap prefix + new payload).
    ///
    /// The adapter clamps this to at least `required_overlap + 1` so every
    /// chunk makes forward progress, and caps at `u32::MAX` so finding
    /// offsets can safely downcast. Use `0` to select [`DEFAULT_CHUNK_BYTES`].
    pub chunk_bytes: usize,
    /// When `true`, skip the binary content check and scan every blob
    /// regardless of content classification.
    pub scan_binary: bool,
}

impl Default for EngineAdapterConfig {
    fn default() -> Self {
        Self {
            chunk_bytes: DEFAULT_CHUNK_BYTES,
            scan_binary: false,
        }
    }
}

/// Normalized finding key for Git persistence.
///
/// Stores the minimal information needed to identify and deduplicate a
/// finding without retaining the raw secret bytes — the secret is
/// represented only by its `NormHash`, avoiding sensitive data in
/// long-lived persistence structures.
///
/// Identity key is `(start, end, rule_id, norm_hash)`.
/// All identity traits (`PartialEq`, `Eq`, `Hash`, `Ord`, `PartialOrd`)
/// are derived over the full field tuple.
///
/// `start` and `end` are **blob-absolute root-hint offsets** sourced from
/// `FindingRec.root_hint_start/root_hint_end`. The engine populates
/// `root_hint_*` via `base_offset + match_span.start` (root findings) or
/// `base_offset + RootSpanMapCtx::map_span(decoded_span).start` (transform
/// findings). These coordinates are stable across chunker alignment changes
/// and are the identity inputs forwarded into Git persistence via
/// `GitFindingForPersistence`.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct FindingKey {
    /// Inclusive blob-absolute start offset of the full match.
    pub start: u32,
    /// Exclusive blob-absolute end offset of the full match.
    pub end: u32,
    /// Stable rule identifier.
    pub rule_id: u32,
    /// Normalized secret hash — the sole representation of the matched
    /// secret, so raw secret bytes never appear in scan output structures.
    pub norm_hash: NormHash,
}

impl fmt::Debug for FindingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FindingKey")
            .field("start", &self.start)
            .field("end", &self.end)
            .field("rule_id", &self.rule_id)
            .field("norm_hash", &"[redacted]")
            .finish()
    }
}

/// A finding paired with its confidence score from gate evaluation.
///
/// The arena stores `ScoredFinding` so that dedup can prefer the highest
/// confidence when multiple scans produce the same identity key.
/// `confidence_score` does not participate in persistence keying (see
/// `build_finding_key` in `finalize.rs`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScoredFinding {
    pub key: FindingKey,
    pub confidence_score: i8,
}

impl Ord for ScoredFinding {
    /// Primary: identity key ascending. Secondary: confidence descending.
    /// Matches dedup contract: sort_unstable() + dedup_by key keeps highest confidence.
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.key
            .cmp(&other.key)
            .then_with(|| other.confidence_score.cmp(&self.confidence_score))
    }
}

impl PartialOrd for ScoredFinding {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Sort findings by identity and dedupe equal identities in place.
///
/// Tie-breaker inside an identity group is descending confidence, so dedupe
/// keeps the most informative score. The first (highest-confidence) entry
/// in each identity group survives.
#[inline]
pub(crate) fn sort_and_dedupe_findings(findings: &mut Vec<ScoredFinding>) {
    findings.sort_unstable();
    findings.dedup_by(|a, b| {
        let same = a.key == b.key;
        debug_assert!(
            !same || b.confidence_score >= a.confidence_score,
            "sort must place highest confidence first within identity group"
        );
        same
    });
}

/// Range into the adapter findings arena for a single blob.
///
/// The span indexes into `ScannedBlobs.finding_arena` (or the adapter's
/// internal arena prior to `take_results`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FindingSpan {
    /// Start index in the findings arena.
    pub start: u32,
    /// Number of findings for the blob.
    pub len: u32,
}

/// Blob scanned by the engine adapter.
///
/// The `ctx.path_ref` points into the mapping arena owned by the caller.
#[derive(Clone, Debug)]
pub struct ScannedBlob {
    /// Blob object ID.
    pub oid: OidBytes,
    /// Canonical context with path reference (mapping arena).
    pub ctx: CandidateContext,
    /// Sorted + deduped findings span in the adapter findings arena.
    pub findings: FindingSpan,
}

/// Collected scan results with a shared findings arena.
///
/// The findings arena is shared across blobs; individual blobs reference it
/// via `FindingSpan`.
#[derive(Clone, Debug)]
pub struct ScannedBlobs {
    /// Blobs scanned in candidate order.
    pub blobs: Vec<ScannedBlob>,
    /// Shared findings arena referenced by `ScannedBlob.findings`.
    pub finding_arena: Vec<ScoredFinding>,
}

/// Always-on Git scan counters for user-facing summaries.
///
/// Unlike `git-perf` counters (debug/profile only), these values are
/// recorded in all builds and track the same core dimensions as the FS
/// scan summary — enabling unified reporting across scan modes.
///
/// All counters use `saturating_add` so overflow silently caps at `u64::MAX`
/// rather than panicking.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GitScanCommonMetrics {
    /// Number of blob payloads sent through the scanner.
    pub objects_scanned: u64,
    /// Number of chunk windows scanned across all objects.
    pub chunks_scanned: u64,
    /// Total payload bytes scanned.
    pub bytes_scanned: u64,
    /// Findings emitted to the event stream.
    pub findings_emitted: u64,
    /// Blobs skipped because they were classified as binary.
    pub binary_skipped: u64,
    /// Blobs skipped pre-scan because extension matched the binary skip set.
    pub ext_skipped: u64,
    /// Blobs skipped pre-scan because filename matched the lock-file table.
    pub lock_skipped: u64,
    /// Blobs scanned via extracted text from binary formats.
    pub binary_extracted: u64,
    /// Pack-exec error-category skips (all skip reasons except `NotBlob`).
    pub errors: u64,
}

impl GitScanCommonMetrics {
    /// Accumulates counters from `other` into `self` using saturating
    /// arithmetic. Used to merge per-worker metrics into a global summary.
    #[inline(always)]
    pub fn merge_from(&mut self, other: &Self) {
        self.objects_scanned = self.objects_scanned.saturating_add(other.objects_scanned);
        self.chunks_scanned = self.chunks_scanned.saturating_add(other.chunks_scanned);
        self.bytes_scanned = self.bytes_scanned.saturating_add(other.bytes_scanned);
        self.findings_emitted = self.findings_emitted.saturating_add(other.findings_emitted);
        self.binary_skipped = self.binary_skipped.saturating_add(other.binary_skipped);
        self.ext_skipped = self.ext_skipped.saturating_add(other.ext_skipped);
        self.lock_skipped = self.lock_skipped.saturating_add(other.lock_skipped);
        self.binary_extracted = self.binary_extracted.saturating_add(other.binary_extracted);
        self.errors = self.errors.saturating_add(other.errors);
    }
}

/// Engine adapter error taxonomy.
///
/// These are non-recoverable errors from a single blob's scan.
/// Both variants arise from `u32` bounds checking — a deliberate
/// constraint that keeps `FindingKey` and `FindingSpan` compact
/// (4 bytes per offset field vs 8 for `u64`).
#[derive(Debug, thiserror::Error)]
pub enum EngineAdapterError {
    /// A finding's byte offsets within the blob exceeded `u32::MAX`.
    ///
    /// This can only happen for blobs larger than 4 GiB, which are
    /// exotic in Git repositories.
    #[error("finding offsets exceed u32: {start}..{end}")]
    FindingOffsetOverflow { start: u64, end: u64 },
    /// The cumulative findings arena grew past `u32::MAX` entries.
    ///
    /// This would require billions of findings across all blobs in
    /// a single adapter lifetime — practically unreachable.
    #[error("findings arena index {end} exceeds max {max}")]
    FindingArenaOverflow { end: usize, max: u32 },
}

impl From<EngineAdapterError> for PackExecError {
    fn from(err: EngineAdapterError) -> Self {
        PackExecError::Sink(err.to_string())
    }
}

/// Git engine adapter that implements [`PackObjectSink`].
///
/// This is the primary entry point for scanning decoded Git blobs. It
/// reuses a ring chunker and scratch space across blobs to minimize
/// allocations on hot paths. Results accumulate until `take_results`
/// or `clear_results` is called.
///
/// Findings flow through two parallel channels:
///
/// - **Event stream** — structured [`ScanEvent::Finding`] events emitted
///   to the configured `EventSink` for real-time consumption (dashboards,
///   progress reporting, CI integrations).
/// - **Arena accumulation** — `ScoredFinding` values appended to a shared
///   arena for batch persistence after the scan completes.
///
/// The adapter is `Send` so it can be pooled across scoped-thread
/// boundaries alongside `PackCache` and `PackExecScratch`.
pub struct EngineAdapter<'a> {
    engine: &'a Engine,
    scratch: ScanScratch,
    overlap: usize,
    results: Vec<ScannedBlob>,
    /// Accumulated findings across all blobs; each `ScannedBlob.findings`
    /// indexes a contiguous span here.
    findings_arena: Vec<ScoredFinding>,
    /// Per-blob scratch: populated by `scan_blob_into_buf`, read by
    /// `stream_findings`, drained into the arena by `record_findings`,
    /// then cleared at the start of the next `scan_blob_into_buf` call.
    findings_buf: Vec<ScoredFinding>,
    chunker: RingChunker,
    // Monotone ID for this adapter instance; wraps on overflow.
    next_file_id: u32,
    /// Structured event sink for streaming findings.
    event_sink: Arc<dyn EventSink>,
    /// When `true`, skip the binary content check and scan everything.
    scan_binary: bool,
    /// Reusable buffer for binary format text extraction.
    extract_buf: Vec<u8>,
    /// Temporary workspace for extractors (e.g. per-entry reads in JARs).
    extract_scratch: Vec<u8>,
    /// Commit-graph index for resolving `commit_id` → OID + timestamp.
    commit_graph: Arc<CommitGraphIndex>,
    /// Emit-once gating for `CommitMeta` events.
    ///
    /// Each bit corresponds to a commit-graph position.
    /// `test_and_set(pos)` returns `true` exactly once per position across
    /// all adapter instances sharing the same `Arc`, ensuring at most one
    /// `CommitMeta` event per commit even under concurrent pack-exec workers.
    commit_meta_seen: Arc<AtomicBitSet>,
    /// Always-on counters for machine-readable scan summaries.
    metrics: GitScanCommonMetrics,
}

impl<'a> EngineAdapter<'a> {
    /// Creates a new adapter with a structured event sink.
    ///
    /// Findings are streamed as structured events during scanning (in addition
    /// to being accumulated in `ScannedBlobs` for persistence).
    ///
    /// # Panics (debug only)
    ///
    /// Debug-asserts that `ctx.commit_meta_seen.bit_length()` is at least
    /// `ctx.commit_graph_index.len()`. A mismatched bitset would silently
    /// skip `CommitMeta` emission for high-position commits.
    #[must_use]
    pub fn new_with_event_sink(
        engine: &'a Engine,
        config: EngineAdapterConfig,
        ctx: CommitMetaContext,
    ) -> Self {
        debug_assert!(
            ctx.commit_meta_seen.bit_length() >= ctx.commit_graph_index.len(),
            "AtomicBitSet bit_length ({}) must be >= CommitGraphIndex len ({})",
            ctx.commit_meta_seen.bit_length(),
            ctx.commit_graph_index.len(),
        );
        let overlap = engine.required_overlap();
        let chunk_bytes = effective_chunk_bytes(config.chunk_bytes, overlap);
        Self {
            engine,
            scratch: engine.new_scratch(),
            overlap,
            results: Vec::new(),
            findings_arena: Vec::new(),
            findings_buf: Vec::with_capacity(64),
            chunker: RingChunker::new(chunk_bytes, overlap),
            next_file_id: 0,
            event_sink: ctx.event_sink,
            scan_binary: config.scan_binary,
            extract_buf: Vec::with_capacity(
                scanner_engine::content_policy::extract::EXTRACT_OUTPUT_CAP,
            ),
            extract_scratch: Vec::with_capacity(
                scanner_engine::content_policy::extract::JAR_ENTRY_CAP,
            ),
            commit_graph: ctx.commit_graph_index,
            commit_meta_seen: ctx.commit_meta_seen,
            metrics: GitScanCommonMetrics::default(),
        }
    }

    /// Returns adapter results in the order candidates were emitted.
    #[must_use]
    pub fn results(&self) -> &[ScannedBlob] {
        &self.results
    }

    /// Returns the shared findings arena.
    ///
    /// Each `ScannedBlob.findings` references a span in this arena.
    #[must_use]
    pub fn findings_arena(&self) -> &[ScoredFinding] {
        &self.findings_arena
    }

    /// Takes ownership of the accumulated results and findings arena.
    pub fn take_results(&mut self) -> ScannedBlobs {
        ScannedBlobs {
            blobs: std::mem::take(&mut self.results),
            finding_arena: std::mem::take(&mut self.findings_arena),
        }
    }

    /// Clears accumulated results and resets scan counters to zero while
    /// preserving allocated capacity.
    ///
    /// This does not reset the file-id counter; file ids continue to
    /// monotonically wrap.
    pub fn clear_results(&mut self) {
        self.results.clear();
        self.findings_arena.clear();
        self.findings_buf.clear();
        self.metrics = GitScanCommonMetrics::default();
    }

    /// Reserves capacity for upcoming blob results.
    pub fn reserve_results(&mut self, additional: usize) {
        self.results.reserve(additional);
    }

    /// Reserves capacity in the shared findings arena.
    pub fn reserve_findings(&mut self, additional: usize) {
        self.findings_arena.reserve(additional);
    }

    /// Reserves capacity for the per-blob findings buffer.
    ///
    /// The per-blob buffer is drained into the shared arena after each blob,
    /// so this only needs to cover the expected peak per-blob finding count
    /// (not the cumulative total).
    pub fn reserve_findings_buf(&mut self, additional: usize) {
        self.findings_buf.reserve(additional);
    }

    /// Returns the always-on scan summary counters accumulated by this adapter.
    #[must_use]
    pub const fn metrics(&self) -> GitScanCommonMetrics {
        self.metrics
    }

    /// Takes the current metrics snapshot and resets counters to zero.
    pub fn take_metrics(&mut self) -> GitScanCommonMetrics {
        std::mem::take(&mut self.metrics)
    }

    /// Emits a loose candidate blob for scanning.
    ///
    /// This follows the same path/arena and finding aggregation logic as
    /// packed candidates.
    ///
    /// # Errors
    /// - `FindingOffsetOverflow` or `FindingArenaOverflow` for oversized blobs.
    pub fn emit_loose(
        &mut self,
        candidate: &LooseCandidate,
        path: &[u8],
        bytes: &[u8],
    ) -> Result<(), PackExecError> {
        let file_id = FileId(self.next_file_id);
        self.next_file_id = self.next_file_id.wrapping_add(1);

        self.scan_blob_into_buf(file_id, path, bytes)?;
        self.stream_findings(
            path,
            candidate.ctx.commit_id,
            candidate.ctx.change_kind.as_str(),
        );
        let span = self.record_findings()?;
        self.results.push(ScannedBlob {
            oid: candidate.oid,
            ctx: candidate.ctx,
            findings: span,
        });
        Ok(())
    }

    /// Stream findings from `findings_buf` to the event sink.
    ///
    /// Called after `scan_blob_into_buf` and before `record_findings`.
    ///
    /// # Exactly-once `CommitMeta` gating
    ///
    /// When `findings_buf` is non-empty and `commit_id` falls within the
    /// commit-graph range, `commit_meta_seen.test_and_set(commit_id)` is
    /// called. The atomic bitset returns `true` exactly once per position
    /// (across all adapter instances sharing the same `Arc<AtomicBitSet>`),
    /// so the resulting `CommitMeta` event is emitted at most once per
    /// `commit_id` — even when multiple workers or blobs reference the
    /// same commit.
    ///
    /// Within the adapter call that wins `test_and_set`, `CommitMeta` is
    /// emitted before that adapter's finding events. Across parallel adapters,
    /// global stream order is intentionally non-deterministic: a `Finding`
    /// for a commit may appear before that commit's `CommitMeta`.
    ///
    /// Commits with zero findings never trigger `CommitMeta` emission.
    ///
    /// When `commit_id` is out of range (>= `commit_graph.len()`), a
    /// `Diagnostic` event at warn level is emitted instead of `CommitMeta`.
    /// Findings are still emitted regardless.
    fn stream_findings(&self, path: &[u8], commit_id: u32, change_kind: &str) {
        if !self.findings_buf.is_empty() {
            if (commit_id as usize) < self.commit_graph.len() {
                if self.commit_meta_seen.test_and_set(commit_id as usize) {
                    let oid = self.commit_graph.commit_oid(Position(commit_id));
                    let ts = self.commit_graph.committer_timestamp(Position(commit_id));
                    let identity = self.commit_graph.identity_ids(Position(commit_id));
                    self.event_sink.emit(ScanEvent::CommitMeta(CommitMetaEvent {
                        commit_id,
                        commit_oid: oid,
                        timestamp: ts,
                        identity,
                    }));
                }
            } else {
                self.event_sink.emit(ScanEvent::Diagnostic(DiagnosticEvent {
                    level: "warn",
                    message: "commit_id out of commit-graph range; CommitMeta skipped",
                }));
            }
        }
        for f in &self.findings_buf {
            self.event_sink.emit(ScanEvent::Finding(FindingEvent {
                source: SourceKind::Git,
                object_path: path,
                start: u64::from(f.key.start),
                end: u64::from(f.key.end),
                rule_id: f.key.rule_id,
                rule_name: self.engine.rule_name(f.key.rule_id),
                norm_hash: f.key.norm_hash,
                commit_id: Some(commit_id),
                change_kind: Some(change_kind),
                confidence_score: f.confidence_score,
            }));
        }
    }

    /// Classify, optionally extract, and scan a single blob into `findings_buf`.
    ///
    /// When `scan_binary` is false the blob is classified via
    /// [`content_policy::classify_content`]. Text blobs are scanned directly;
    /// extractable binary formats (`.class`, `.pyc`, etc.) have their text
    /// extracted first; opaque binaries are skipped entirely.
    ///
    /// On return, `self.findings_buf` contains the sorted+deduped findings
    /// for this blob. The caller is responsible for streaming them to the
    /// event sink and recording them in the findings arena.
    fn scan_blob_into_buf(
        &mut self,
        file_id: FileId,
        path: &[u8],
        bytes: &[u8],
    ) -> Result<(), EngineAdapterError> {
        self.findings_buf.clear();
        if !self.scan_binary {
            match content_policy::classify_content(bytes, path, content_policy::CHECK_LEN) {
                ContentVerdict::Binary => {
                    perf::record_scan_binary_skip();
                    self.metrics.binary_skipped = self.metrics.binary_skipped.saturating_add(1);
                    return Ok(());
                }
                ContentVerdict::BinaryExtractable(fmt) => {
                    use scanner_engine::content_policy::extract::{extract_content, ExtractResult};
                    if extract_content(fmt, bytes, &mut self.extract_buf, &mut self.extract_scratch)
                        == ExtractResult::Ok
                    {
                        perf::record_scan_binary_extract();
                        self.metrics.binary_extracted =
                            self.metrics.binary_extracted.saturating_add(1);
                        scan_blob_chunked_with_chunker(
                            self.engine,
                            &mut self.scratch,
                            file_id,
                            &self.extract_buf,
                            self.overlap,
                            &mut self.chunker,
                            &mut self.findings_buf,
                        )?;
                        self.record_scanned_payload(self.extract_buf.len());
                        return Ok(());
                    }
                    perf::record_scan_binary_skip();
                    self.metrics.binary_skipped = self.metrics.binary_skipped.saturating_add(1);
                    return Ok(());
                }
                ContentVerdict::Text => {}
            }
        }
        self.scan_blob_payload(file_id, bytes)
    }

    /// Scans raw blob bytes through the chunking pipeline and updates
    /// metrics. Called by `scan_blob_into_buf` after content classification
    /// has already determined the bytes are scannable (either the original
    /// text bytes, or extracted text from a binary format).
    fn scan_blob_payload(
        &mut self,
        file_id: FileId,
        bytes: &[u8],
    ) -> Result<(), EngineAdapterError> {
        scan_blob_chunked_with_chunker(
            self.engine,
            &mut self.scratch,
            file_id,
            bytes,
            self.overlap,
            &mut self.chunker,
            &mut self.findings_buf,
        )?;
        self.record_scanned_payload(bytes.len());
        Ok(())
    }

    /// Increments scan metrics for a successfully scanned payload.
    #[inline(always)]
    fn record_scanned_payload(&mut self, scanned_len: usize) {
        self.metrics.objects_scanned = self.metrics.objects_scanned.saturating_add(1);
        self.metrics.bytes_scanned = self
            .metrics
            .bytes_scanned
            .saturating_add(scanned_len as u64);
        self.metrics.chunks_scanned =
            self.metrics
                .chunks_scanned
                .saturating_add(chunk_count_for_blob_len(
                    scanned_len,
                    self.chunker.chunk_bytes(),
                    self.overlap,
                ));
    }

    /// Transfer `findings_buf` into the shared arena and return the span.
    ///
    /// Must be called after `scan_blob_into_buf` (which populates
    /// `findings_buf`) and `stream_findings` (which reads it). The span
    /// indexes into `findings_arena` for the just-scanned blob.
    fn record_findings(&mut self) -> Result<FindingSpan, EngineAdapterError> {
        let start = self.findings_arena.len();
        let len = self.findings_buf.len();
        let end = start.saturating_add(len);
        if end > u32::MAX as usize {
            return Err(EngineAdapterError::FindingArenaOverflow { end, max: u32::MAX });
        }

        // Extend the shared arena; the returned span is used by `ScannedBlob`.
        self.findings_arena.extend_from_slice(&self.findings_buf);
        self.metrics.findings_emitted = self.metrics.findings_emitted.saturating_add(len as u64);
        Ok(FindingSpan {
            start: start as u32,
            len: len as u32,
        })
    }
}

impl PackObjectSink for EngineAdapter<'_> {
    /// Scans a pack-sourced blob, streams findings to the event sink, and
    /// records results in the adapter arena.
    ///
    /// Follows the same scan → stream → record pipeline as
    /// [`emit_loose`](Self::emit_loose); the only difference is the candidate
    /// type (`PackCandidate` carries a pack offset).
    fn emit(
        &mut self,
        candidate: &PackCandidate,
        path: &[u8],
        bytes: &[u8],
    ) -> Result<(), PackExecError> {
        let file_id = FileId(self.next_file_id);
        self.next_file_id = self.next_file_id.wrapping_add(1);

        self.scan_blob_into_buf(file_id, path, bytes)?;
        self.stream_findings(
            path,
            candidate.ctx.commit_id,
            candidate.ctx.change_kind.as_str(),
        );
        let span = self.record_findings()?;
        self.results.push(ScannedBlob {
            oid: candidate.oid,
            ctx: candidate.ctx,
            findings: span,
        });
        Ok(())
    }
}

#[cfg(test)]
impl<'a> EngineAdapter<'a> {
    /// Creates a new adapter with dummy commit-graph state (test-only).
    ///
    /// Production callers must use [`new_with_event_sink`](Self::new_with_event_sink)
    /// with a real `CommitMetaContext`.
    #[must_use]
    pub fn new(engine: &'a Engine, config: EngineAdapterConfig) -> Self {
        use crate::events::NullEventSink;

        Self::new_with_event_sink(
            engine,
            config,
            CommitMetaContext {
                event_sink: Arc::new(NullEventSink),
                commit_graph_index: Arc::new(CommitGraphIndex::empty()),
                commit_meta_seen: Arc::new(AtomicBitSet::empty(1)),
                identity_interner: None,
            },
        )
    }
}

/// Scan a blob with overlap-safe chunking and return sorted + deduped findings.
///
/// This is the standalone entry point for callers that do not need a
/// long-lived [`EngineAdapter`]. A fresh `ScanScratch` and `RingChunker`
/// are allocated per call, so prefer the adapter API for batch scanning.
///
/// Findings are normalized into `FindingKey` values and ordered deterministically.
///
/// # Errors
/// - `FindingOffsetOverflow` if any finding span exceeds `u32` bounds.
pub fn scan_blob_chunked(
    engine: &Engine,
    blob: &[u8],
    chunk_bytes: usize,
) -> Result<Vec<ScoredFinding>, EngineAdapterError> {
    let overlap = engine.required_overlap();
    let chunk_bytes = effective_chunk_bytes(chunk_bytes, overlap);
    let mut scratch = engine.new_scratch();
    let mut out = Vec::new();
    scan_blob_chunked_into(
        engine,
        &mut scratch,
        FileId(0),
        blob,
        chunk_bytes,
        overlap,
        &mut out,
    )?;
    Ok(out)
}

/// Clamp requested chunk sizes for overlap and offset safety.
///
/// Ensures `chunk_bytes > overlap` (so each chunk makes forward progress)
/// and caps the result at `u32::MAX` so finding offsets can safely downcast
/// to `u32`. A `requested` value of `0` selects [`DEFAULT_CHUNK_BYTES`].
fn effective_chunk_bytes(requested: usize, overlap: usize) -> usize {
    // Enforce progress and clamp to u32::MAX for offset conversion safety.
    // Finding offsets are stored as `u32`, so chunking must preserve bounds.
    let min = overlap.saturating_add(1).max(1);
    let base = if requested == 0 {
        DEFAULT_CHUNK_BYTES
    } else {
        requested
    };
    base.max(min).min(u32::MAX as usize)
}

/// Computes the number of chunk windows emitted for a blob of the given length,
/// accounting for overlap between adjacent windows.
///
/// Returns at least 1 (single-chunk fast path), matching `RingChunker` behavior.
#[inline(always)]
fn chunk_count_for_blob_len(blob_len: usize, chunk_bytes: usize, overlap: usize) -> u64 {
    if blob_len <= chunk_bytes {
        return 1;
    }
    // RingChunker emits one full chunk, then advances by (chunk-overlap) bytes
    // per subsequent window, with a final partial chunk when remainder exists.
    let step = chunk_bytes.saturating_sub(overlap).max(1);
    let remaining = blob_len.saturating_sub(chunk_bytes);
    let extra = remaining.saturating_add(step - 1) / step;
    1u64.saturating_add(extra as u64)
}

/// Internal scan entry point that creates a fresh `RingChunker` and delegates
/// to [`scan_blob_chunked_with_chunker`]. Used by the public
/// [`scan_blob_chunked`] API when no reusable chunker is available.
fn scan_blob_chunked_into(
    engine: &Engine,
    scratch: &mut ScanScratch,
    file_id: FileId,
    blob: &[u8],
    chunk_bytes: usize,
    overlap: usize,
    out: &mut Vec<ScoredFinding>,
) -> Result<(), EngineAdapterError> {
    let mut chunker = RingChunker::new(chunk_bytes, overlap);
    scan_blob_chunked_with_chunker(engine, scratch, file_id, blob, overlap, &mut chunker, out)
}

/// Scan a blob using a reusable chunker and optional allocation guard.
///
/// This is the inner workhorse shared by both the standalone
/// `scan_blob_chunked` API and the `EngineAdapter` per-blob pipeline.
///
/// Two code paths exist:
///
/// - **Fast path** — blob fits in a single chunk (`len <= chunk_bytes`).
///   Constructs a `ChunkView` directly on the blob slice, skipping the
///   ring buffer memcpy entirely.
/// - **Slow path** — blob spans multiple chunks. Streams bytes through
///   `RingChunker::feed` + `flush`, which emits overlapping windows.
///
/// Both paths sort+dedup findings after scanning and optionally assert
/// zero allocations when the debug allocation guard is enabled.
///
/// The chunker is reset before use and must have the same overlap as the
/// caller-provided `overlap`. `out` is cleared and populated with sorted,
/// deduped findings.
fn scan_blob_chunked_with_chunker(
    engine: &Engine,
    scratch: &mut ScanScratch,
    file_id: FileId,
    blob: &[u8],
    overlap: usize,
    chunker: &mut RingChunker,
    out: &mut Vec<ScoredFinding>,
) -> Result<(), EngineAdapterError> {
    perf::record_scan_blob();

    // Fast path: blob fits in a single chunk — skip the ring buffer memcpy.
    // When blob.len() <= chunk_bytes, feed() emits at most one full chunk and
    // flush() emits the remainder. Either way it's exactly one chunk, so we
    // can construct the ChunkView directly on the blob bytes.
    if blob.len() <= chunker.chunk_bytes() {
        perf::record_scan_chunker_bypass();
        let (res, nanos) = perf::time(|| {
            let guard = if alloc_guard::enabled() {
                Some(AllocGuard::new())
            } else {
                None
            };

            out.clear();
            let mut err: Option<EngineAdapterError> = None;

            let view = ChunkView {
                base: 0,
                is_first: true,
                window: blob,
            };
            scan_chunk(engine, scratch, file_id, overlap, view, out, &mut err);

            if let Some(err) = err {
                return Err(err);
            }

            let ((), _sd_nanos) = perf::time(|| {
                if !out.is_empty() {
                    sort_and_dedupe_findings(out);
                }
            });
            perf::record_scan_sort_dedup(_sd_nanos);

            if let Some(guard) = guard {
                guard.assert_no_alloc();
            }

            Ok(())
        });

        if res.is_ok() {
            perf::record_scan(blob.len(), nanos);
        }

        return res;
    }

    // Slow path: blob spans multiple chunks — stream through the ring buffer.
    let (res, nanos) = perf::time(|| {
        let guard = if alloc_guard::enabled() {
            Some(AllocGuard::new())
        } else {
            None
        };

        out.clear();
        chunker.reset();
        debug_assert_eq!(chunker.overlap(), overlap, "overlap mismatch");
        let mut err: Option<EngineAdapterError> = None;

        chunker.feed(blob, |view| {
            if err.is_some() {
                return;
            }
            scan_chunk(engine, scratch, file_id, overlap, view, out, &mut err);
        });
        chunker.flush(|view| {
            if err.is_some() {
                return;
            }
            scan_chunk(engine, scratch, file_id, overlap, view, out, &mut err);
        });

        if let Some(err) = err {
            return Err(err);
        }

        let ((), _sd_nanos) = perf::time(|| {
            if !out.is_empty() {
                sort_and_dedupe_findings(out);
            }
        });
        perf::record_scan_sort_dedup(_sd_nanos);

        if let Some(guard) = guard {
            guard.assert_no_alloc();
        }

        Ok(())
    });

    if res.is_ok() {
        perf::record_scan(blob.len(), nanos);
    }

    res
}

/// Scan a single chunk window and collect findings into `out`.
///
/// After scanning, findings wholly within the overlap prefix are dropped
/// to avoid cross-chunk duplication. Remaining findings are converted to
/// `FindingKey` values and appended to `out`. If any finding offset
/// exceeds `u32` bounds, `err` is set and the function returns early.
///
/// The `err` out-parameter (instead of a `Result` return) allows this
/// function to be called inside the `RingChunker::feed` / `flush`
/// closures, which use `FnMut(ChunkView)` with no `Result` return.
fn scan_chunk(
    engine: &Engine,
    scratch: &mut ScanScratch,
    file_id: FileId,
    overlap: usize,
    view: ChunkView<'_>,
    out: &mut Vec<ScoredFinding>,
    err: &mut Option<EngineAdapterError>,
) {
    perf::record_scan_chunk();
    engine.scan_chunk_into(view.window, file_id, view.base, scratch);
    // Skip findings that are fully contained in the overlap prefix.
    // This keeps each match while avoiding duplicate reporting.
    let new_bytes_start = if view.is_first {
        view.base
    } else {
        view.base.saturating_add(overlap as u64)
    };
    scratch.drop_prefix_findings(new_bytes_start);

    let recs = scratch.findings();
    let hashes = scratch.norm_hashes();
    debug_assert_eq!(recs.len(), hashes.len(), "finding/hash mismatch");

    for (rec, hash) in recs.iter().zip(hashes.iter()) {
        let start = rec.root_hint_start;
        let end = rec.root_hint_end;
        if start > u32::MAX as u64 || end > u32::MAX as u64 {
            *err = Some(EngineAdapterError::FindingOffsetOverflow { start, end });
            return;
        }
        out.push(ScoredFinding {
            key: FindingKey {
                start: start as u32,
                end: end as u32,
                rule_id: rec.rule_id,
                norm_hash: *hash,
            },
            confidence_score: rec.confidence_score,
        });
    }
}

/// A single chunk window produced by the ring chunker.
///
/// Each view represents a contiguous slice of a blob, potentially including
/// an overlap prefix from the previous window. The overlap region exists so
/// the scan engine can detect secrets that straddle chunk boundaries.
///
/// After scanning, findings whose offsets fall entirely within the overlap
/// prefix are dropped to prevent double-reporting — except for the first
/// window (`is_first`), where no prior window exists to own those bytes.
struct ChunkView<'a> {
    /// Absolute byte offset of `window[0]` within the original blob.
    base: u64,
    /// `true` for the first window in a blob, which suppresses overlap
    /// deduplication (there is no prior window whose "new bytes" region
    /// could own findings in the prefix).
    is_first: bool,
    /// Window bytes: `[overlap prefix | new bytes]`.
    /// Length is exactly `chunk_bytes` for full windows, or less for the
    /// final partial window emitted by `flush`.
    window: &'a [u8],
}

/// Fixed-size ring chunker for streaming blob bytes into scan windows.
///
/// Accepts arbitrary-length input via `feed`, emitting full chunk windows
/// as they fill. The ring retains `overlap` trailing bytes between windows
/// so the scan engine can detect secrets that straddle chunk boundaries.
/// A final partial window is emitted by `flush`.
///
/// The buffer is allocated once at construction and reused across blobs
/// (via `reset`), so per-blob overhead is bounded to overlap-prefix copies
/// at chunk boundaries — no heap allocation on the hot path.
///
/// # Usage protocol
///
/// 1. Construct once with `new(chunk_bytes, overlap)`.
/// 2. Call `feed(data, callback)` — may invoke the callback zero or more
///    times, once per full `chunk_bytes` window.
/// 3. Call `flush(callback)` — emits the final partial window (if any)
///    and resets internal state for reuse.
/// 4. To reuse across blobs, call `reset()` before the next `feed` cycle.
///
/// The first emitted window has `is_first = true`, which tells the scan
/// layer not to drop findings in the overlap prefix (there is no prior
/// window whose "new bytes" region owns them).
///
/// # Invariant
/// `chunk_bytes > overlap`, enforced at construction. This guarantees
/// each window advances by at least one byte, preventing infinite loops.
struct RingChunker {
    chunk_bytes: usize,
    overlap: usize,
    buf: Vec<u8>,
    filled: usize,
    base: u64,
    is_first: bool,
}

impl RingChunker {
    /// Creates a chunker with the given window size and overlap.
    ///
    /// # Panics
    /// If `chunk_bytes == 0` or `chunk_bytes <= overlap`.
    fn new(chunk_bytes: usize, overlap: usize) -> Self {
        assert!(chunk_bytes > 0, "chunk_bytes must be > 0");
        assert!(chunk_bytes > overlap, "chunk_bytes must exceed overlap");
        Self {
            chunk_bytes,
            overlap,
            buf: vec![0u8; chunk_bytes],
            filled: 0,
            base: 0,
            is_first: true,
        }
    }

    /// Returns the total window size (overlap + new bytes).
    fn chunk_bytes(&self) -> usize {
        self.chunk_bytes
    }

    /// Returns the overlap prefix size retained between consecutive windows.
    fn overlap(&self) -> usize {
        self.overlap
    }

    /// Resets the chunker for reuse with a new blob.
    ///
    /// Clears the fill cursor and base offset; the next `feed` call will
    /// treat the first emitted window as `is_first = true`.
    fn reset(&mut self) {
        self.filled = 0;
        self.base = 0;
        self.is_first = true;
    }

    /// Stream data into fixed windows and invoke the callback per full chunk.
    ///
    /// Each window is `chunk_bytes` long and includes the overlap prefix
    /// from the tail of the previous window. Input data may be larger than
    /// a single chunk; the loop consumes it in passes, emitting one
    /// `ChunkView` each time the internal buffer fills.
    fn feed(&mut self, mut data: &[u8], mut on_chunk: impl FnMut(ChunkView<'_>)) {
        while !data.is_empty() {
            let space = self.chunk_bytes - self.filled;
            let n = space.min(data.len());
            self.buf[self.filled..self.filled + n].copy_from_slice(&data[..n]);
            self.filled += n;
            data = &data[n..];

            if self.filled == self.chunk_bytes {
                on_chunk(ChunkView {
                    base: self.base,
                    is_first: self.is_first,
                    window: &self.buf[..self.filled],
                });
                self.is_first = false;
                let step = self.chunk_bytes - self.overlap;
                // Retain the overlap prefix so the next window includes it.
                if self.overlap > 0 {
                    self.buf
                        .copy_within(self.chunk_bytes - self.overlap..self.chunk_bytes, 0);
                    self.base = self.base.saturating_add(step as u64);
                    self.filled = self.overlap;
                } else {
                    self.base = self.base.saturating_add(step as u64);
                    self.filled = 0;
                }
            }
        }
    }

    /// Emit the final partial chunk (if any), then reset internal state.
    ///
    /// A partial chunk that contains *only* the overlap prefix (no new bytes)
    /// is suppressed — those bytes were already scanned as part of the
    /// previous full window.
    fn flush(&mut self, mut on_chunk: impl FnMut(ChunkView<'_>)) {
        if self.filled == 0 {
            return;
        }
        // Suppress a trailing window that has no new bytes beyond the overlap.
        if !self.is_first && self.filled <= self.overlap {
            self.reset();
            return;
        }
        on_chunk(ChunkView {
            base: self.base,
            is_first: self.is_first,
            window: &self.buf[..self.filled],
        });
        self.reset();
    }
}

// Compile-time assertion: `EngineAdapter` must be `Send` so it can live in
// a per-worker pool and be moved across scoped-thread boundaries during
// parallel pack execution (same pattern as `PackCache` / `PackExecScratch`).
const _: () = {
    fn _assert_send<T: Send>() {}
    fn _check() {
        _assert_send::<super::EngineAdapter<'_>>();
    }
};

#[cfg(test)]
#[path = "engine_adapter_tests.rs"]
mod tests;
