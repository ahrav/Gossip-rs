//! Shared scan-post-processing helpers used by all scheduler I/O paths.
//!
//! These functions handle cross-rule finding deduplication, effective-drop
//! accounting, and structured finding emission. They are factored out of
//! [`local_fs_owner`](super::local_fs_owner) so that the connector pipeline,
//! io_uring path, remote scanner, and archive processors can reuse them
//! without coupling to the local-filesystem scheduler.

use super::engine_trait::{FindingRecord, FindingWithHashRecord, ScanEngine};
use super::metrics::WorkerMetricsLocal;

use std::cmp::Ordering as CmpOrdering;

/// Sort-then-dedup pass that collapses findings sharing the same
/// (root_hint_start, root_hint_end, span, norm_hash) tuple across rules.
///
/// Tie-breaking order within a dedupe group:
/// 1. Higher `confidence_score` wins
/// 2. Lexical rule-name order (caller-provided comparator)
/// 3. Lower `rule_id`
///
/// Span participation is conditional per finding:
/// - `dedupe_with_span == true`: include `span_start/span_end`
/// - `dedupe_with_span == false`: zero span components in the key
#[inline]
pub(super) fn dedupe_findings_cross_rule<F, C>(findings: &mut Vec<F>, mut rule_cmp: C)
where
    F: FindingWithHashRecord,
    C: FnMut(u32, u32) -> CmpOrdering,
{
    if findings.len() <= 1 {
        return;
    }

    findings.sort_unstable_by(|a, b| {
        a.root_hint_start()
            .cmp(&b.root_hint_start())
            .then_with(|| a.root_hint_end().cmp(&b.root_hint_end()))
            .then_with(|| {
                let a_span = if a.dedupe_with_span() {
                    (a.span_start(), a.span_end())
                } else {
                    (0, 0)
                };
                let b_span = if b.dedupe_with_span() {
                    (b.span_start(), b.span_end())
                } else {
                    (0, 0)
                };
                a_span.cmp(&b_span)
            })
            .then_with(|| a.norm_hash().cmp(b.norm_hash()))
            .then_with(|| b.confidence_score().cmp(&a.confidence_score()))
            .then_with(|| rule_cmp(a.rule_id(), b.rule_id()))
            .then_with(|| a.rule_id().cmp(&b.rule_id()))
    });

    findings.dedup_by(|a, b| {
        let a_span = if a.dedupe_with_span() {
            (a.span_start(), a.span_end())
        } else {
            (0, 0)
        };
        let b_span = if b.dedupe_with_span() {
            (b.span_start(), b.span_end())
        } else {
            (0, 0)
        };

        a.root_hint_start() == b.root_hint_start()
            && a.root_hint_end() == b.root_hint_end()
            && a_span == b_span
            && a.norm_hash() == b.norm_hash()
    });
}

/// Apply cross-rule winner dedupe and return the number of removed findings.
///
/// Convenience wrapper around [`dedupe_findings_cross_rule`] that skips
/// trivially-small vectors and returns a count suitable for scheduler
/// pruning arithmetic.
#[inline]
pub(super) fn apply_cross_rule_dedupe<F, E>(findings: &mut Vec<F>, engine: &E) -> usize
where
    F: FindingWithHashRecord,
    E: ScanEngine,
{
    let before = findings.len();
    if before <= 1 {
        return 0;
    }
    dedupe_findings_cross_rule(findings, |lhs, rhs| {
        engine.rule_name(lhs).cmp(engine.rule_name(rhs))
    });
    before - findings.len()
}

/// Account for effective drop loss after scheduler-side pruning.
///
/// The engine reports dropped findings (due to max-findings caps) *before*
/// overlap-prefix pruning and within-chunk dedupe. Findings removed by those
/// scheduler passes would have been discarded anyway and are not lossful for
/// persistence, so we subtract them from the engine-reported drops.
///
/// ```text
///   effective_drops = engine_reported_drops − scheduler_pruned
/// ```
///
/// Without this adjustment a chunk where the engine dropped 2 findings and the
/// scheduler pruned 2 duplicates would falsely report 2 drops, triggering the
/// `persistence_incomplete` signal even though every unique finding was emitted.
#[inline]
pub(super) fn account_effective_dropped_findings(
    metrics: &mut WorkerMetricsLocal,
    engine_dropped: u64,
    scheduler_pruned: usize,
) {
    let effective = engine_dropped.saturating_sub(scheduler_pruned as u64);
    metrics.findings_dropped = metrics.findings_dropped.saturating_add(effective);
}

/// Emit structured finding events via the [`EventSink`].
///
/// Emits one [`ScanEvent::Finding`] per finding record.
///
/// [`EventSink`]: crate::unified::events::EventSink
#[inline]
pub(super) fn emit_findings<E: ScanEngine, F: FindingRecord>(
    engine: &E,
    event_sink: &dyn crate::unified::events::EventSink,
    path: &[u8],
    findings: &[F],
) {
    if findings.is_empty() {
        return;
    }

    for rec in findings {
        event_sink.emit(crate::unified::events::ScanEvent::Finding(
            crate::unified::events::FindingEvent {
                source: crate::unified::SourceKind::Fs,
                object_path: path,
                start: rec.root_hint_start(),
                end: rec.root_hint_end(),
                rule_id: rec.rule_id(),
                rule_name: engine.rule_name(rec.rule_id()),
                commit_id: None,
                change_kind: None,
                confidence_score: rec.confidence_score(),
            },
        ));
    }
}
