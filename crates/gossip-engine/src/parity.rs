//! Deterministic parity helpers for scanner-core migration gates.
//!
//! When migrating scanner implementations (e.g. v1 -> v2), we need to verify
//! that the new scanner produces *functionally identical* output on the same
//! input corpus.  This module provides the two building blocks for that gate:
//!
//! 1. **Canonicalization** — [`canonicalize_stream_output`] projects a
//!    [`StreamScanOutput`] into a stable, serialization-friendly form
//!    ([`CanonicalRun`]) that strips runtime-specific metadata while
//!    preserving the fields that define correctness: finding identity, page
//!    signatures, and emission order.  Fixture tests compare the canonical
//!    form, so a migration is correct iff `canonical(old) == canonical(new)`.
//!
//! 2. **Throughput thresholds** — [`enforce_throughput_thresholds`] implements
//!    a two-tier policy on per-case and median throughput deltas so that a
//!    candidate engine must be *not meaningfully slower* before cutover is
//!    allowed.  Recommended limits are documented on the function itself.
//!
//! All logic here is runtime-agnostic (no async, no I/O).

use std::fmt;

use gossip_contracts::connector::VersionId;

use crate::StreamScanOutput;

/// Strength of a connector's version claim in canonical form.
///
/// Maps 1:1 from [`VersionId`] variants.  The distinction matters because
/// strong versions are treated as authoritative during dedup while weak
/// versions may be superseded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CanonicalVersionStrength {
    /// The connector provided an authoritative version identifier.
    Strong,
    /// The connector provided a best-effort version identifier that may be
    /// superseded by a later strong claim.
    Weak,
}

impl CanonicalVersionStrength {
    /// Lowercase stable text form for fixture encoding.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Strong => "strong",
            Self::Weak => "weak",
        }
    }
}

/// Canonical representation of a single scanner finding.
///
/// Every field that participates in correctness comparison is included here
/// in a stable, text-safe encoding (lowercase hex for byte fields).  Fields
/// that are runtime-specific (e.g. wall-clock timestamps, internal refs) are
/// intentionally excluded so that fixture snapshots survive refactors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalFinding {
    /// 32-byte stable item identity, encoded as 64-char lowercase hex.
    pub stable_item_id_hex: String,
    /// Whether this version claim is authoritative or best-effort.
    pub version_strength: CanonicalVersionStrength,
    /// Version identity bytes, encoded as lowercase hex.
    pub version_hex: String,
    /// 1-based page number where the finding was emitted.
    pub page_num: u64,
    /// 0-based item index within the page (position in the connector's
    /// response, not a global sequence number).
    pub item_index: usize,
    /// FNV-1a fingerprint used for cross-page deduplication.
    pub fingerprint: u64,
    /// Number of payload bytes that contributed to the fingerprint.
    pub payload_bytes: u64,
}

/// Canonical representation of a single page's scan summary.
///
/// Captures the deterministic digest of a page so that fixture tests can
/// verify both per-page integrity and stream-level ordering stability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CanonicalPageSummary {
    /// 1-based page sequence number within the stream.
    pub page_num: u64,
    /// Deterministic content signature (FNV-1a over all page items).
    pub signature: u64,
    /// Number of connector items the page contained.
    pub item_count: usize,
    /// Total payload bytes consumed while scanning this page.
    pub bytes_scanned: u64,
}

/// Full canonical snapshot of a scanner stream execution.
///
/// Two `CanonicalRun` values are equal iff the underlying scanner produced
/// the same findings in the same order with the same page structure.  This
/// is the unit of comparison in migration parity tests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalRun {
    /// Page summaries in stream order (first page at index 0).
    pub page_summaries: Vec<CanonicalPageSummary>,
    /// Findings in emission order across all pages.
    ///
    /// Order is intentionally preserved so that fixture comparisons detect
    /// ordering drift in addition to identity drift — a reordered but
    /// otherwise identical run is treated as a parity failure.
    pub findings: Vec<CanonicalFinding>,
}

/// Project a [`StreamScanOutput`] into its canonical form for fixture comparison.
///
/// The projection is deterministic and order-preserving: page summaries keep
/// their stream order and findings keep their emission order.  Byte-valued
/// fields (stable item IDs, version bytes) are encoded as lowercase hex so
/// the result is safe for JSON/YAML serialization without base64.
///
/// Runtime-only metadata (stats, dedupe counters, diagnostics) is stripped —
/// only the fields that define *correctness* survive.
#[must_use]
pub fn canonicalize_stream_output(output: &StreamScanOutput) -> CanonicalRun {
    let page_summaries = output
        .page_summaries()
        .iter()
        .map(|summary| CanonicalPageSummary {
            page_num: summary.page_num(),
            signature: summary.signature(),
            item_count: summary.item_count(),
            bytes_scanned: summary.bytes_scanned(),
        })
        .collect();

    let findings = output
        .findings()
        .iter()
        .map(|finding| {
            let (version_strength, version_hex) = match finding.version() {
                VersionId::Strong(version) => (
                    CanonicalVersionStrength::Strong,
                    encode_hex(version.as_bytes()),
                ),
                VersionId::Weak(version) => (
                    CanonicalVersionStrength::Weak,
                    encode_hex(version.as_bytes()),
                ),
            };
            CanonicalFinding {
                stable_item_id_hex: encode_hex(finding.stable_item_id().as_bytes()),
                version_strength,
                version_hex,
                page_num: finding.page_num(),
                item_index: finding.item_index(),
                fingerprint: finding.fingerprint(),
                payload_bytes: finding.payload_bytes(),
            }
        })
        .collect();

    CanonicalRun {
        page_summaries,
        findings,
    }
}

/// Errors from throughput delta computation and threshold enforcement.
///
/// Variants are designed for actionable diagnostics: each carries enough
/// context (labels, values, indices) to produce a human-readable message
/// without re-inspecting the input data.
#[derive(Debug, Clone, PartialEq)]
pub enum ThroughputError {
    /// The input sample slice was empty (at least one value is required).
    EmptyInput,
    /// A numeric input was NaN or infinite.
    NonFinite {
        /// Which parameter was non-finite (e.g. `"baseline"`, `"sample"`).
        label: &'static str,
        /// The offending value.
        value: f64,
    },
    /// Baseline throughput was zero (with non-zero candidate) or negative.
    ///
    /// A zero-vs-zero comparison is *not* an error — it returns 0% delta.
    NonPositiveBaseline {
        /// The invalid baseline value.
        baseline: f64,
    },
    /// A threshold limit parameter was zero or negative.
    NonPositiveLimit {
        /// Which limit was invalid.
        label: &'static str,
        /// The offending value.
        value: f64,
    },
    /// A computed delta exceeded the configured threshold.
    ThresholdExceeded {
        /// `"per-case"` or `"median"`.
        scope: &'static str,
        /// Absolute delta that was observed.
        observed_abs_pct: f64,
        /// The limit it exceeded.
        limit_abs_pct: f64,
        /// For per-case violations, the 0-based index into `deltas_pct`.
        /// `None` for median violations.
        index: Option<usize>,
    },
}

impl fmt::Display for ThroughputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyInput => write!(f, "at least one throughput sample is required"),
            Self::NonFinite { label, value } => {
                write!(f, "throughput value '{}' is non-finite: {}", label, value)
            }
            Self::NonPositiveBaseline { baseline } => {
                write!(f, "baseline throughput must be > 0, got {}", baseline)
            }
            Self::NonPositiveLimit { label, value } => {
                write!(f, "threshold limit '{}' must be > 0, got {}", label, value)
            }
            Self::ThresholdExceeded {
                scope,
                observed_abs_pct,
                limit_abs_pct,
                index,
            } => {
                if let Some(i) = index {
                    write!(
                        f,
                        "{} delta at index {} exceeded limit: {:.4}% > {:.4}%",
                        scope, i, observed_abs_pct, limit_abs_pct
                    )
                } else {
                    write!(
                        f,
                        "{} delta exceeded limit: {:.4}% > {:.4}%",
                        scope, observed_abs_pct, limit_abs_pct
                    )
                }
            }
        }
    }
}

impl std::error::Error for ThroughputError {}

/// Compute signed throughput delta as a percentage.
///
/// Formula: `((candidate - baseline) / baseline) * 100`.
///
/// A positive result means the candidate is faster; negative means slower.
///
/// # Special cases
///
/// - `baseline == 0.0 && candidate == 0.0` returns `Ok(0.0)` (no change).
/// - `baseline == 0.0 && candidate != 0.0` is an error (division by zero).
/// - Negative baselines are rejected because throughput is non-negative by
///   definition.  Negative *candidates* are allowed so that callers can
///   detect regressions through the sign of the result.
///
/// # Errors
///
/// - [`ThroughputError::NonFinite`] — either input is NaN or infinite.
/// - [`ThroughputError::NonPositiveBaseline`] — baseline is negative, or
///   zero with a non-zero candidate.
pub fn throughput_delta_pct(baseline: f64, candidate: f64) -> Result<f64, ThroughputError> {
    if !baseline.is_finite() {
        return Err(ThroughputError::NonFinite {
            label: "baseline",
            value: baseline,
        });
    }
    if !candidate.is_finite() {
        return Err(ThroughputError::NonFinite {
            label: "candidate",
            value: candidate,
        });
    }
    if baseline == 0.0 {
        if candidate == 0.0 {
            return Ok(0.0);
        }
        return Err(ThroughputError::NonPositiveBaseline { baseline });
    }
    if baseline < 0.0 {
        return Err(ThroughputError::NonPositiveBaseline { baseline });
    }
    Ok(((candidate - baseline) / baseline) * 100.0)
}

/// Compute the median of a finite-valued sample.
///
/// For odd-length input, returns the middle element after sorting.
/// For even-length input, returns the mean of the two middle elements.
///
/// Sorting uses [`f64::total_cmp`] for a deterministic order, though NaN
/// values are rejected before the sort is reached.
///
/// # Allocation
///
/// Clones the input into a temporary `Vec` for sorting (cold-path only).
///
/// # Errors
///
/// - [`ThroughputError::EmptyInput`] — the slice was empty.
/// - [`ThroughputError::NonFinite`] — at least one sample is NaN or infinite.
pub fn median(values: &[f64]) -> Result<f64, ThroughputError> {
    if values.is_empty() {
        return Err(ThroughputError::EmptyInput);
    }
    let mut sorted = values.to_vec();
    for v in &sorted {
        if !v.is_finite() {
            return Err(ThroughputError::NonFinite {
                label: "sample",
                value: *v,
            });
        }
    }
    sorted.sort_by(f64::total_cmp);
    let mid = sorted.len() / 2;
    if sorted.len() % 2 == 1 {
        Ok(sorted[mid])
    } else {
        Ok((sorted[mid - 1] + sorted[mid]) / 2.0)
    }
}

/// Enforce a two-tier absolute throughput delta policy.
///
/// The gate checks **per-case** limits first (no single test case may
/// regress beyond `per_case_limit_abs_pct`), then the **median** limit
/// (the overall tendency must stay within `median_limit_abs_pct`).
/// Evaluation short-circuits: the first per-case violation is reported
/// immediately without inspecting remaining deltas.
///
/// Recommended migration-gate values:
/// - `median_limit_abs_pct = 2.0` — median absolute delta <= 2 %.
/// - `per_case_limit_abs_pct = 5.0` — every case absolute delta <= 5 %.
///
/// Returns the computed **median absolute delta** on success, which
/// callers can log or record for trend tracking.
///
/// # Errors
///
/// - [`ThroughputError::EmptyInput`] — no deltas provided.
/// - [`ThroughputError::NonFinite`] / [`ThroughputError::NonPositiveLimit`]
///   — invalid limit or delta value.
/// - [`ThroughputError::ThresholdExceeded`] — a per-case or median limit
///   was breached.
pub fn enforce_throughput_thresholds(
    deltas_pct: &[f64],
    median_limit_abs_pct: f64,
    per_case_limit_abs_pct: f64,
) -> Result<f64, ThroughputError> {
    if deltas_pct.is_empty() {
        return Err(ThroughputError::EmptyInput);
    }
    if !median_limit_abs_pct.is_finite() {
        return Err(ThroughputError::NonFinite {
            label: "median_limit_abs_pct",
            value: median_limit_abs_pct,
        });
    }
    if median_limit_abs_pct <= 0.0 {
        return Err(ThroughputError::NonPositiveLimit {
            label: "median_limit_abs_pct",
            value: median_limit_abs_pct,
        });
    }
    if !per_case_limit_abs_pct.is_finite() {
        return Err(ThroughputError::NonFinite {
            label: "per_case_limit_abs_pct",
            value: per_case_limit_abs_pct,
        });
    }
    if per_case_limit_abs_pct <= 0.0 {
        return Err(ThroughputError::NonPositiveLimit {
            label: "per_case_limit_abs_pct",
            value: per_case_limit_abs_pct,
        });
    }

    let mut abs_deltas = Vec::with_capacity(deltas_pct.len());
    for (idx, delta) in deltas_pct.iter().copied().enumerate() {
        if !delta.is_finite() {
            return Err(ThroughputError::NonFinite {
                label: "delta_pct",
                value: delta,
            });
        }
        let abs = delta.abs();
        if abs > per_case_limit_abs_pct {
            return Err(ThroughputError::ThresholdExceeded {
                scope: "per-case",
                observed_abs_pct: abs,
                limit_abs_pct: per_case_limit_abs_pct,
                index: Some(idx),
            });
        }
        abs_deltas.push(abs);
    }

    let median_abs = median(&abs_deltas)?;
    if median_abs > median_limit_abs_pct {
        return Err(ThroughputError::ThresholdExceeded {
            scope: "median",
            observed_abs_pct: median_abs,
            limit_abs_pct: median_limit_abs_pct,
            index: None,
        });
    }

    Ok(median_abs)
}

/// Encode `bytes` as a lowercase hex string (2 chars per byte, no prefix).
///
/// Uses a table lookup rather than `format!` to avoid repeated formatting
/// overhead when encoding many small byte slices during canonicalization.
fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        out.push(char::from(HEX[(byte >> 4) as usize]));
        out.push(char::from(HEX[(byte & 0x0f) as usize]));
    }
    out
}

#[cfg(test)]
#[path = "parity_tests.rs"]
mod tests;
