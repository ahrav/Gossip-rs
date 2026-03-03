//! Regression detection and CI gating.
//!
//! Compares current eval metrics against a stored baseline to produce a
//! [`Verdict`] (Pass / Warn / Block) suitable for CI gate decisions. This
//! module is pure computation — it does not load or persist baselines, nor
//! does it interact with the filesystem or network. Callers are responsible
//! for supplying the current and baseline [`EvalMetrics`] and interpreting
//! the returned [`RegressionResult`] (e.g., mapping [`Verdict::exit_code`]
//! to a process exit).
//!
//! # Algorithm
//!
//! 1. **Threshold validation**: ensure warn/block values are finite,
//!    non-negative, and ordered (`warn <= block`) via
//!    [`RegressionThresholds::validate`].
//! 2. **AP check**: compute `current - baseline`, optionally apply the CI
//!    overlap gate (see below), classify as Pass/Warn/Block based on the
//!    absolute drop against [`RegressionThresholds`].
//! 3. **Precision check**: same threshold logic, no CI gate.
//! 4. **Overall verdict** = `max(ap_verdict, precision_verdict)`. Because
//!    [`Verdict`] derives `Ord` with Pass < Warn < Block, `max` yields the
//!    worst verdict with no branching.
//! 5. **Per-rule diff**: merge the per-rule `BTreeMap` keys via a
//!    `BTreeSet` union to identify new, removed, and retained rules in
//!    O(n log n). These deltas are informational — they do not influence
//!    the verdict and are computed after the verdict is finalized.
//!
//! # CI overlap gate
//!
//! When `use_ci` is true and the current run carries a bootstrap CI for AP
//! (see [`crate::metrics::EvalMetrics::ap_ci`]), the gate checks whether
//! the baseline AP falls at or below the CI upper bound. If it does, the
//! observed drop is attributable to sampling noise rather than a real
//! regression, and the metric check returns Pass regardless of the raw
//! delta.
//!
//! This is a **one-sided** test: only the upper bound matters because we
//! are asking "could the baseline plausibly come from the same distribution
//! as the current run?" The baseline is treated as a fixed point estimate
//! (no CI of its own), so overlap is checked in one direction only.
//!
//! # Threshold semantics
//!
//! All thresholds are **absolute** deltas in the same scale as the metric
//! (0.0–1.0 for precision and AP). A `block` threshold of 0.02 means a 2
//! percentage-point drop triggers Block. Relative (percentage) thresholds
//! are intentionally not supported: a 2pp drop from 0.98 to 0.96 is
//! operationally different from a 2pp drop from 0.52 to 0.50, but both
//! should block equally because the eval harness treats the absolute
//! quality floor as the gating criterion. Invalid ordering (`warn > block`)
//! is rejected by [`RegressionThresholds::validate`] (called by
//! [`check_regression`]) so the Warn band stays reachable.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::metrics::{ConfidenceInterval, EvalMetrics, RuleMetrics};

#[cfg(test)]
use crate::metrics::safe_div;

// ── Public types ────────────────────────────────────────────────────────

/// Thresholds for regression gating (absolute deltas, not relative).
///
/// A drop exceeding the `block` threshold produces [`Verdict::Block`]; a drop
/// exceeding `warn` but not `block` produces [`Verdict::Warn`]; otherwise
/// [`Verdict::Pass`].
///
/// Thresholds are compared against the **absolute drop** (`baseline - current`),
/// so a value of 0.02 means "2 percentage points." The `warn` threshold should
/// be less than or equal to `block` for the three-tier classification
/// (Pass / Warn / Block) to work as intended. When inverted (`warn > block`),
/// the Warn verdict becomes unreachable: any drop large enough for Warn has
/// already triggered Block, so regressions jump directly from Pass to Block.
/// Construction does not enforce this; call [`RegressionThresholds::validate`]
/// directly or use [`check_regression`], which validates before computing
/// verdicts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegressionThresholds {
    /// AP drop (absolute) that triggers Block. Default: 0.02 (2 percentage points).
    pub ap_block: f64,
    /// AP drop (absolute) that triggers Warn. Default: 0.005 (0.5 percentage points).
    pub ap_warn: f64,
    /// Precision drop (absolute) that triggers Block. Default: 0.02 (2 percentage points).
    pub precision_block: f64,
    /// Precision drop (absolute) that triggers Warn. Default: 0.005 (0.5 percentage points).
    pub precision_warn: f64,
    /// Whether to apply the one-sided CI gate for AP. When true and the current
    /// run has a bootstrap CI, a drop is treated as noise (Pass) when
    /// `baseline_ap <= current_ap_ci.upper`. Default: true.
    pub use_ci: bool,
}

/// Configuration error returned when regression thresholds are invalid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegressionConfigError {
    /// One or more threshold values are NaN or Infinity.
    NonFiniteThreshold,
    /// One or more threshold values are negative.
    NegativeThreshold,
    /// Warn threshold is greater than block threshold, making Warn unreachable.
    WarnExceedsBlock,
}

impl std::fmt::Display for RegressionConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::NonFiniteThreshold => "threshold values must be finite",
            Self::NegativeThreshold => "threshold values must be non-negative",
            Self::WarnExceedsBlock => {
                "warn threshold exceeds block threshold (Warn band unreachable)"
            }
        })
    }
}

impl std::error::Error for RegressionConfigError {}

impl RegressionThresholds {
    /// Validate that all threshold values are sensible.
    ///
    /// Returns `Err` with a description when:
    /// - Any threshold is non-finite (NaN or Inf).
    /// - Any threshold is negative.
    /// - `warn > block` for either metric pair (Warn band is unreachable).
    pub fn validate(&self) -> Result<(), RegressionConfigError> {
        let pairs = [
            (self.ap_warn, self.ap_block, "ap"),
            (self.precision_warn, self.precision_block, "precision"),
        ];
        for (warn, block, _name) in pairs {
            if !warn.is_finite() || !block.is_finite() {
                return Err(RegressionConfigError::NonFiniteThreshold);
            }
            if warn < 0.0 || block < 0.0 {
                return Err(RegressionConfigError::NegativeThreshold);
            }
            if warn > block {
                return Err(RegressionConfigError::WarnExceedsBlock);
            }
        }
        Ok(())
    }
}

impl Default for RegressionThresholds {
    fn default() -> Self {
        Self {
            ap_block: 0.02,
            ap_warn: 0.005,
            precision_block: 0.02,
            precision_warn: 0.005,
            use_ci: true,
        }
    }
}

/// Regression verdict for a CI gate decision.
///
/// **Variant order is load-bearing**: the derived `Ord` gives
/// Pass < Warn < Block, so `a.max(b)` yields the worst verdict. This
/// enables composing multiple metric checks into a single overall verdict
/// via `max` without any conditional logic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Verdict {
    /// No regression detected.
    Pass,
    /// Minor regression, within tolerance but notable.
    Warn,
    /// Significant regression, should block CI.
    Block,
}

impl Verdict {
    /// Map to a process exit code suitable for CI scripts.
    ///
    /// Pass and Warn both map to 0 (success) because warnings are
    /// informational; only Block produces a non-zero exit (1) that fails
    /// the CI step.
    pub fn exit_code(self) -> i32 {
        match self {
            Self::Pass | Self::Warn => 0,
            Self::Block => 1,
        }
    }
}

impl std::fmt::Display for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Pass => "PASS",
            Self::Warn => "WARN",
            Self::Block => "BLOCK",
        })
    }
}

/// Which metric is being checked for regression.
///
/// Only two metrics are currently evaluated: average precision (AP) and
/// precision. Using an enum instead of a raw string prevents typos and
/// enables exhaustive matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetricName {
    /// Area under the precision-recall curve (average precision).
    AveragePrecision,
    /// Precision = TP / (TP + FP).
    Precision,
}

impl std::fmt::Display for MetricName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::AveragePrecision => "average_precision",
            Self::Precision => "precision",
        })
    }
}

/// Result of checking a single metric (AP or precision) against thresholds.
///
/// Each [`RegressionResult`] contains one `MetricCheck` per evaluated metric.
/// The `verdict` field reflects only this metric's contribution; the overall
/// verdict in [`RegressionResult`] is the `max` across all checks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricCheck {
    /// Which metric this check evaluates.
    pub metric: MetricName,
    /// Current run's value (0.0–1.0 as produced by [`EvalMetrics`]).
    pub current: f64,
    /// Baseline value (0.0–1.0 as produced by [`EvalMetrics`]).
    pub baseline: f64,
    /// `current - baseline`. Negative means regression (current is worse).
    pub delta: f64,
    /// Verdict for this metric alone.
    pub verdict: Verdict,
    /// Whether the CI overlap gate fired, overriding the raw threshold
    /// comparison and forcing the verdict to Pass. Only possible for AP
    /// when [`RegressionThresholds::use_ci`] is true and a bootstrap CI
    /// is available.
    pub ci_gate_applied: bool,
}

/// Per-rule TP/FP/precision delta between current and baseline runs.
///
/// These deltas are **informational only** — they do not influence the
/// overall [`Verdict`]. They exist so that CI reporters can surface
/// which specific rules improved or regressed, helping developers
/// pinpoint the cause of an aggregate metric shift.
///
/// For [`RuleDeltaStatus::New`] rules, the baseline fields are zero.
/// For [`RuleDeltaStatus::Removed`] rules, the current fields are zero.
/// For [`RuleDeltaStatus::Retained`] rules, both sides are populated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleDelta {
    /// Rule name (matches the key in [`EvalMetrics::per_rule`]).
    pub rule: String,
    /// Current TP count (0 for removed rules).
    pub current_tp: u64,
    /// Baseline TP count (0 for new rules).
    pub baseline_tp: u64,
    /// Current FP count (0 for removed rules).
    pub current_fp: u64,
    /// Baseline FP count (0 for new rules).
    pub baseline_fp: u64,
    /// Precision delta (`current_precision - baseline_precision`). Negative
    /// means the rule's precision regressed. For New rules this equals the
    /// current precision (baseline is implicitly 0.0); for Removed rules
    /// this equals the negated baseline precision.
    pub precision_delta: f64,
    /// Whether this rule is new, removed, or present in both runs.
    pub status: RuleDeltaStatus,
}

/// Classification of a rule's lifecycle between two eval runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleDeltaStatus {
    /// Rule exists in both runs. Counts may differ or be identical.
    Retained,
    /// Rule appears only in the current run (absent from baseline).
    New,
    /// Rule appears only in the baseline (absent from current).
    Removed,
}

/// Complete regression check result, suitable for serialization to JSON
/// and consumption by CI reporters.
///
/// Typical consumer flow:
/// 1. Check [`verdict`](Self::verdict) to decide pass/fail.
/// 2. If Warn or Block, iterate [`checks`](Self::checks) to identify which
///    metric(s) triggered the verdict.
/// 3. Optionally display [`per_rule_deltas`](Self::per_rule_deltas) to help
///    developers pinpoint which rules contributed to the regression.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegressionResult {
    /// Overall verdict — the worst (maximum) of all per-metric verdicts.
    pub verdict: Verdict,
    /// Per-metric checks: `[average_precision, precision]`, in that order.
    pub checks: [MetricCheck; 2],
    /// Per-rule deltas between current and baseline. Informational only;
    /// these do not affect the verdict.
    pub per_rule_deltas: Vec<RuleDelta>,
    /// The thresholds that were applied, echoed back for auditability.
    pub thresholds: RegressionThresholds,
    /// Whether the current run and baseline used comparable pipeline semantics.
    ///
    /// Defaults to `true` for backward compatibility and is set to `false` by
    /// the caller when out-of-band config checks detect mismatches (for
    /// example cross-rule dedup enabled in only one run).
    #[serde(default = "default_true")]
    pub baseline_comparable: bool,
    /// Human-readable warnings about baseline comparability.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub comparison_warnings: Vec<String>,
}

const fn default_true() -> bool {
    true
}

// ── Public API ──────────────────────────────────────────────────────────

/// Run regression checks comparing current metrics against a baseline.
///
/// This is the sole entry point for regression detection. It is a pure
/// function: no IO, no side effects, deterministic output for the same
/// inputs.
///
/// The returned [`RegressionResult`] contains:
/// - An overall [`Verdict`] (the worst across all metrics).
/// - Two [`MetricCheck`] entries: one for AP, one for precision.
/// - A Vec of [`RuleDelta`] entries showing per-rule TP/FP/precision
///   changes (informational, does not affect the verdict).
/// - Baseline comparability metadata initialized to compatible with no
///   warnings; callers may override these fields if external checks find
///   semantic mismatches.
///
/// # Errors
///
/// Returns [`RegressionConfigError`] when `thresholds` are invalid
/// (non-finite, negative, or `warn > block`).
///
/// # Non-finite metrics
///
/// Non-finite metric inputs (`NaN`, `+/-Inf`) are treated as hard failures:
/// the affected metric check returns [`Verdict::Block`]. This avoids accidental
/// Pass/Warn outcomes from IEEE-754 comparison behavior.
///
/// # Verdict composition
///
/// `verdict = max(ap_check.verdict, precision_check.verdict)`.
/// Because [`Verdict`] orders Pass < Warn < Block, any single Block
/// metric is sufficient to block the overall result.
pub fn check_regression(
    current: &EvalMetrics,
    baseline: &EvalMetrics,
    thresholds: &RegressionThresholds,
) -> Result<RegressionResult, RegressionConfigError> {
    thresholds.validate()?;

    let ap_check = check_metric(
        MetricName::AveragePrecision,
        current.average_precision,
        baseline.average_precision,
        current.ap_ci.as_ref(),
        thresholds.ap_block,
        thresholds.ap_warn,
        thresholds.use_ci,
    );

    let precision_check = check_metric(
        MetricName::Precision,
        current.precision,
        baseline.precision,
        None, // No CI gate for precision.
        thresholds.precision_block,
        thresholds.precision_warn,
        false,
    );

    let verdict = ap_check.verdict.max(precision_check.verdict);
    let per_rule_deltas = compute_per_rule_deltas(&current.per_rule, &baseline.per_rule);

    Ok(RegressionResult {
        verdict,
        checks: [ap_check, precision_check],
        per_rule_deltas,
        thresholds: thresholds.clone(),
        baseline_comparable: true,
        comparison_warnings: Vec::new(),
    })
}

// ── Internal helpers ────────────────────────────────────────────────────

/// Check a single metric against thresholds, optionally applying the CI gate.
///
/// The CI gate is a **short-circuit**: when `use_ci` is true, a CI is
/// available, and the baseline falls at or below the CI upper bound, the
/// function returns Pass immediately without evaluating threshold logic.
/// The gate only checks the upper bound (one-sided) because we are asking
/// whether the baseline could plausibly be drawn from the same distribution
/// as the current run; a baseline above the CI upper bound is evidence of
/// a real regression.
///
/// When the CI gate does not fire, the raw absolute drop
/// (`baseline - current`) is compared against the warn and block thresholds.
/// Improvements (current > baseline) always produce Pass because the drop
/// is non-positive.
///
/// # Threshold evaluation order
///
/// Block is checked before Warn: `if drop >= block { Block } else if drop >= warn { Warn }`.
/// When `warn <= block` (the expected configuration), this produces a three-tier
/// classification: `[0, warn)` = Pass, `[warn, block)` = Warn, `[block, inf)` = Block.
/// When inverted (`warn > block`), the Warn branch becomes unreachable because
/// any drop exceeding `warn` has already exceeded the smaller `block` threshold.
/// Invalid threshold ordering is rejected by [`check_regression`] validation.
fn check_metric(
    metric_name: MetricName,
    current_val: f64,
    baseline_val: f64,
    ci: Option<&ConfidenceInterval>,
    block_threshold: f64,
    warn_threshold: f64,
    use_ci: bool,
) -> MetricCheck {
    // Non-finite values (NaN, Inf) cannot be meaningfully compared against
    // thresholds. IEEE 754 NaN comparisons always return false, which would
    // silently produce Pass for arbitrarily bad data. Block immediately.
    if !current_val.is_finite() || !baseline_val.is_finite() {
        return MetricCheck {
            metric: metric_name,
            current: current_val,
            baseline: baseline_val,
            delta: current_val - baseline_val,
            verdict: Verdict::Block,
            ci_gate_applied: false,
        };
    }

    let delta = current_val - baseline_val;

    // CI overlap gate: if baseline falls within the current CI, the observed
    // drop is noise, not a real regression. Only the upper bound matters —
    // see module-level "CI overlap gate" section for rationale.
    if use_ci
        && let Some(ci) = ci
        && baseline_val <= ci.upper
    {
        return MetricCheck {
            metric: metric_name,
            current: current_val,
            baseline: baseline_val,
            delta,
            verdict: Verdict::Pass,
            ci_gate_applied: true,
        };
    }

    // Negate the delta so that a regression (current < baseline) yields a
    // positive `drop`, making the threshold comparison read naturally.
    let drop = -delta;
    let verdict = if drop >= block_threshold {
        Verdict::Block
    } else if drop >= warn_threshold {
        Verdict::Warn
    } else {
        Verdict::Pass
    };

    MetricCheck {
        metric: metric_name,
        current: current_val,
        baseline: baseline_val,
        delta,
        verdict,
        ci_gate_applied: false,
    }
}

/// Compute per-rule deltas by merging the current and baseline `BTreeMap` keys.
///
/// Collects all rule names from both maps into a `BTreeSet` (automatic
/// deduplication and sorted order), then classifies each rule as
/// New/Removed/Retained based on map membership.
///
/// # Complexity
///
/// O(n log n) where n = r_curr + r_base (dominated by BTreeSet insertion).
/// Output is sorted by rule name, inheriting the BTreeSet iteration order.
fn compute_per_rule_deltas(
    current: &BTreeMap<String, RuleMetrics>,
    baseline: &BTreeMap<String, RuleMetrics>,
) -> Vec<RuleDelta> {
    let all_rules: std::collections::BTreeSet<&str> = current
        .keys()
        .chain(baseline.keys())
        .map(String::as_str)
        .collect();

    all_rules
        .into_iter()
        .map(|rule| match (current.get(rule), baseline.get(rule)) {
            (Some(cm), Some(bm)) => RuleDelta {
                rule: rule.to_string(),
                current_tp: cm.tp,
                baseline_tp: bm.tp,
                current_fp: cm.fp,
                baseline_fp: bm.fp,
                precision_delta: cm.precision - bm.precision,
                status: RuleDeltaStatus::Retained,
            },
            (Some(cm), None) => RuleDelta {
                rule: rule.to_string(),
                current_tp: cm.tp,
                baseline_tp: 0,
                current_fp: cm.fp,
                baseline_fp: 0,
                precision_delta: cm.precision,
                status: RuleDeltaStatus::New,
            },
            (None, Some(bm)) => RuleDelta {
                rule: rule.to_string(),
                current_tp: 0,
                baseline_tp: bm.tp,
                current_fp: 0,
                baseline_fp: bm.fp,
                precision_delta: -bm.precision,
                status: RuleDeltaStatus::Removed,
            },
            (None, None) => unreachable!("rule came from one of the maps"),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const EPS: f64 = 1e-9;

    /// Build minimal EvalMetrics with the given AP and precision.
    fn metrics(ap: f64, precision: f64) -> EvalMetrics {
        EvalMetrics {
            average_precision: ap,
            precision,
            recall: 0.0,
            f1: 0.0,
            f2: 0.0,
            tp: 0,
            fp: 0,
            false_neg: 0,
            unlabeled: 0,
            baseline_ap: 0.0,
            precision_at_recall: vec![],
            recall_at_precision: vec![],
            ap_ci: None,
            per_rule: BTreeMap::new(),
        }
    }

    fn metrics_with_ci(ap: f64, precision: f64, ci_lower: f64, ci_upper: f64) -> EvalMetrics {
        let mut m = metrics(ap, precision);
        m.ap_ci = Some(ConfidenceInterval {
            lower: ci_lower,
            upper: ci_upper,
        });
        m
    }

    fn metrics_with_rules(ap: f64, precision: f64, rules: &[(&str, u64, u64)]) -> EvalMetrics {
        let mut m = metrics(ap, precision);
        for &(name, tp, fp) in rules {
            m.per_rule.insert(
                name.to_string(),
                RuleMetrics {
                    tp,
                    fp,
                    precision: safe_div(tp as f64, (tp + fp) as f64),
                },
            );
        }
        m
    }

    fn check_regression(
        current: &EvalMetrics,
        baseline: &EvalMetrics,
        thresholds: &RegressionThresholds,
    ) -> RegressionResult {
        super::check_regression(current, baseline, thresholds)
            .expect("test thresholds should be valid unless explicitly testing errors")
    }

    // ── Verdict properties ─────────────────────────────────────────────

    #[test]
    fn verdict_properties() {
        // Ordering: Pass < Warn < Block, max yields worst.
        assert!(Verdict::Pass < Verdict::Warn);
        assert!(Verdict::Warn < Verdict::Block);
        assert_eq!(Verdict::Pass.max(Verdict::Block), Verdict::Block);

        // Exit codes: only Block is non-zero.
        for (v, code) in [(Verdict::Pass, 0), (Verdict::Warn, 0), (Verdict::Block, 1)] {
            assert_eq!(v.exit_code(), code, "{v:?}.exit_code()");
        }

        // Display strings.
        for (v, label) in [
            (Verdict::Pass, "PASS"),
            (Verdict::Warn, "WARN"),
            (Verdict::Block, "BLOCK"),
        ] {
            assert_eq!(v.to_string(), label, "{v:?}.to_string()");
        }
    }

    // ── Metric threshold verdicts ───────────────────────────────────

    #[rstest::rstest]
    #[case::identical(0.92, 0.88, 0.92, 0.88, 0, Verdict::Pass)]
    #[case::ap_3pp_drop(0.90, 0.88, 0.93, 0.88, 0, Verdict::Block)]
    #[case::ap_1pp_drop(0.91, 0.88, 0.92, 0.88, 0, Verdict::Warn)]
    #[case::ap_03pp_drop(0.917, 0.88, 0.92, 0.88, 0, Verdict::Pass)]
    #[case::prec_3pp_drop(0.92, 0.85, 0.92, 0.88, 1, Verdict::Block)]
    #[case::prec_1pp_drop(0.92, 0.87, 0.92, 0.88, 1, Verdict::Warn)]
    fn metric_threshold_verdicts(
        #[case] curr_ap: f64,
        #[case] curr_prec: f64,
        #[case] base_ap: f64,
        #[case] base_prec: f64,
        #[case] idx: usize,
        #[case] expected: Verdict,
    ) {
        let result = check_regression(
            &metrics(curr_ap, curr_prec),
            &metrics(base_ap, base_prec),
            &RegressionThresholds::default(),
        );
        assert_eq!(
            result.checks[idx].verdict, expected,
            "curr=({curr_ap},{curr_prec}) base=({base_ap},{base_prec}) check[{idx}]"
        );
    }

    // ── CI gate ──────────────────────────────────────────────────────

    #[rstest::rstest]
    #[case::ci_includes_baseline(0.91, 0.89, 0.93, 0.92, Verdict::Pass, true)]
    #[case::ci_below_baseline(0.89, 0.87, 0.91, 0.92, Verdict::Block, false)]
    fn ci_gate_behavior(
        #[case] curr_ap: f64,
        #[case] ci_lo: f64,
        #[case] ci_hi: f64,
        #[case] base_ap: f64,
        #[case] expected: Verdict,
        #[case] ci_applied: bool,
    ) {
        let current = metrics_with_ci(curr_ap, 0.88, ci_lo, ci_hi);
        let baseline = metrics(base_ap, 0.88);
        let result = check_regression(&current, &baseline, &RegressionThresholds::default());
        assert_eq!(
            result.checks[0].verdict, expected,
            "ap={curr_ap} ci=[{ci_lo},{ci_hi}] base={base_ap}"
        );
        assert_eq!(
            result.checks[0].ci_gate_applied, ci_applied,
            "ci_gate_applied mismatch for ap={curr_ap}"
        );
    }

    // ── Per-rule deltas ──────────────────────────────────────────────

    /// Per-rule deltas correctly classify rules as New, Removed, or Retained
    /// based on their presence in the current vs. baseline maps.
    #[test]
    fn per_rule_delta_statuses() {
        fn assert_rule_status(
            curr_rules: &[(&str, u64, u64)],
            base_rules: &[(&str, u64, u64)],
            target: &str,
            expected: RuleDeltaStatus,
        ) {
            let result = check_regression(
                &metrics_with_rules(0.92, 0.88, curr_rules),
                &metrics_with_rules(0.92, 0.88, base_rules),
                &RegressionThresholds::default(),
            );
            let delta = result
                .per_rule_deltas
                .iter()
                .find(|d| d.rule == target)
                .unwrap_or_else(|| panic!("missing delta for {target}"));
            assert_eq!(delta.status, expected, "status for {target}");
        }

        // Rule only in baseline → Removed.
        assert_rule_status(
            &[("rule_a", 10, 2)],
            &[("rule_a", 10, 2), ("rule_b", 5, 1)],
            "rule_b",
            RuleDeltaStatus::Removed,
        );
        // Rule only in current → New.
        assert_rule_status(
            &[("rule_a", 10, 2), ("rule_c", 3, 0)],
            &[("rule_a", 10, 2)],
            "rule_c",
            RuleDeltaStatus::New,
        );
        // Rule in both → Retained.
        assert_rule_status(
            &[("rule_a", 12, 3)],
            &[("rule_a", 10, 2)],
            "rule_a",
            RuleDeltaStatus::Retained,
        );
    }

    /// Edge case: the per-rule merge handles empty maps gracefully.
    ///
    /// Three sub-cases: both empty (no output), only current non-empty (all
    /// New), only baseline non-empty (all Removed).
    #[test]
    fn empty_per_rule_maps() {
        // Both maps empty → no deltas emitted.
        let result = check_regression(
            &metrics(0.92, 0.88),
            &metrics(0.92, 0.88),
            &RegressionThresholds::default(),
        );
        assert!(result.per_rule_deltas.is_empty());

        // One empty, other non-empty → all entries are New or Removed.
        let result = check_regression(
            &metrics_with_rules(0.92, 0.88, &[("rule_a", 5, 1)]),
            &metrics(0.92, 0.88),
            &RegressionThresholds::default(),
        );
        assert_eq!(result.per_rule_deltas.len(), 1);
        assert_eq!(result.per_rule_deltas[0].status, RuleDeltaStatus::New);

        let result = check_regression(
            &metrics(0.92, 0.88),
            &metrics_with_rules(0.92, 0.88, &[("rule_b", 3, 0)]),
            &RegressionThresholds::default(),
        );
        assert_eq!(result.per_rule_deltas.len(), 1);
        assert_eq!(result.per_rule_deltas[0].status, RuleDeltaStatus::Removed);
    }

    /// Inverted thresholds (warn > block) are rejected as invalid config.
    #[test]
    fn inverted_thresholds_are_rejected() {
        let thresh = RegressionThresholds {
            ap_block: 0.005, // lower than warn
            ap_warn: 0.02,   // higher than block
            precision_block: 0.02,
            precision_warn: 0.005,
            use_ci: false,
        };
        let err = super::check_regression(&metrics(0.91, 0.88), &metrics(0.92, 0.88), &thresh)
            .unwrap_err();
        assert_eq!(err, RegressionConfigError::WarnExceedsBlock);
    }

    #[test]
    fn worst_verdict_wins() {
        // AP blocks, precision passes → overall Block.
        let current = metrics(0.88, 0.88);
        let baseline = metrics(0.92, 0.88);
        let result = check_regression(&current, &baseline, &RegressionThresholds::default());
        assert_eq!(result.verdict, Verdict::Block);
        assert_eq!(result.checks[0].verdict, Verdict::Block);
        assert_eq!(result.checks[1].verdict, Verdict::Pass);
    }

    // ── Exact boundary tests ──────────────────────────────────────────

    #[test]
    fn exact_threshold_boundary() {
        let thresh = RegressionThresholds::default();
        // Default: ap_block = 0.02, ap_warn = 0.005.

        // Drop exactly at block threshold (0.02) → Block.
        let result = check_regression(&metrics(0.90, 0.88), &metrics(0.92, 0.88), &thresh);
        assert_eq!(
            result.checks[0].verdict,
            Verdict::Block,
            "drop == block threshold"
        );

        // Drop exactly at warn threshold (0.005) → Warn.
        let result = check_regression(&metrics(0.915, 0.88), &metrics(0.92, 0.88), &thresh);
        assert_eq!(
            result.checks[0].verdict,
            Verdict::Warn,
            "drop == warn threshold"
        );
    }

    #[test]
    fn ci_gate_with_no_ci_data() {
        // use_ci=true but ap_ci=None: CI gate should be skipped, fall
        // through to threshold comparison.
        let current = metrics(0.89, 0.88); // 3pp AP drop from baseline
        let baseline = metrics(0.92, 0.88);
        let thresh = RegressionThresholds {
            use_ci: true,
            ..Default::default()
        };

        let result = check_regression(&current, &baseline, &thresh);
        // No CI data → gate cannot fire → threshold applies → Block.
        assert_eq!(result.checks[0].verdict, Verdict::Block);
        assert!(
            !result.checks[0].ci_gate_applied,
            "CI gate must not fire without CI data"
        );
    }

    #[test]
    fn nan_metric_produces_block() {
        // NaN in current AP → Block, not a silent Pass from IEEE 754 semantics.
        let current = metrics(f64::NAN, 0.88);
        let baseline = metrics(0.92, 0.88);
        let result = check_regression(&current, &baseline, &RegressionThresholds::default());
        assert_eq!(
            result.checks[0].verdict,
            Verdict::Block,
            "NaN current AP must Block"
        );
        assert!(!result.checks[0].ci_gate_applied);

        // NaN in baseline precision → Block.
        let current = metrics(0.92, 0.88);
        let baseline = metrics(0.92, f64::NAN);
        let result = check_regression(&current, &baseline, &RegressionThresholds::default());
        assert_eq!(
            result.checks[1].verdict,
            Verdict::Block,
            "NaN baseline precision must Block"
        );

        // Inf in current → Block.
        let current = metrics(f64::INFINITY, 0.88);
        let baseline = metrics(0.92, 0.88);
        let result = check_regression(&current, &baseline, &RegressionThresholds::default());
        assert_eq!(
            result.checks[0].verdict,
            Verdict::Block,
            "Inf current AP must Block"
        );
    }

    /// When `use_ci: false`, the CI gate must not fire even when CI data is
    /// present. The raw threshold comparison should apply instead.
    #[test]
    fn use_ci_false_ignores_ci_data() {
        // CI that would normally absorb the 1pp drop (baseline within CI).
        let current = metrics_with_ci(0.91, 0.88, 0.89, 0.93);
        let baseline = metrics(0.92, 0.88);
        let thresh = RegressionThresholds {
            use_ci: false,
            ..Default::default()
        };

        let result = check_regression(&current, &baseline, &thresh);
        // With use_ci=true this would be Pass (CI absorbs), but with
        // use_ci=false the 1pp drop hits the warn threshold (0.005).
        assert!(
            !result.checks[0].ci_gate_applied,
            "CI gate must not fire when use_ci=false"
        );
        assert_eq!(
            result.checks[0].verdict,
            Verdict::Warn,
            "1pp AP drop with use_ci=false should Warn, not be absorbed by CI"
        );
    }

    // ── Threshold validation ───────────────────────────────────────

    #[test]
    fn threshold_validate_valid() {
        assert!(RegressionThresholds::default().validate().is_ok());
    }

    #[test]
    fn threshold_validate_nan() {
        let t = RegressionThresholds {
            ap_block: f64::NAN,
            ..Default::default()
        };
        assert_eq!(t.validate(), Err(RegressionConfigError::NonFiniteThreshold));
    }

    #[test]
    fn threshold_validate_negative() {
        let t = RegressionThresholds {
            precision_warn: -0.01,
            ..Default::default()
        };
        assert_eq!(t.validate(), Err(RegressionConfigError::NegativeThreshold));
    }

    #[test]
    fn threshold_validate_inverted() {
        let t = RegressionThresholds {
            ap_warn: 0.05,
            ap_block: 0.02,
            ..Default::default()
        };
        assert_eq!(t.validate(), Err(RegressionConfigError::WarnExceedsBlock));
    }

    #[test]
    fn check_regression_rejects_invalid_thresholds() {
        let current = metrics(0.9, 0.9);
        let baseline = metrics(0.9, 0.9);
        let invalid = RegressionThresholds {
            ap_warn: 0.05,
            ap_block: 0.02,
            ..Default::default()
        };

        let err = super::check_regression(&current, &baseline, &invalid).unwrap_err();
        assert_eq!(err, RegressionConfigError::WarnExceedsBlock);
    }

    // ── Proptest ─────────────────────────────────────────────────────

    mod prop {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(256))]

            /// Larger drops never produce weaker verdicts.
            #[test]
            fn verdict_monotonicity(
                baseline_ap in 0.5f64..1.0,
                drop_small in 0.0f64..0.05,
                drop_extra in 0.001f64..0.05,
            ) {
                let small_current = metrics(baseline_ap - drop_small, 0.88);
                let large_current = metrics(baseline_ap - drop_small - drop_extra, 0.88);
                let baseline = metrics(baseline_ap, 0.88);
                let thresh = RegressionThresholds { use_ci: false, ..Default::default() };

                let r_small = check_regression(&small_current, &baseline, &thresh);
                let r_large = check_regression(&large_current, &baseline, &thresh);
                prop_assert!(
                    r_large.verdict >= r_small.verdict,
                    "larger drop ({}) has weaker verdict ({:?}) than smaller drop ({}) verdict ({:?})",
                    drop_small + drop_extra, r_large.verdict, drop_small, r_small.verdict,
                );
            }

            /// Same inputs always produce the same result.
            #[test]
            fn determinism(
                ap in 0.0f64..1.0,
                prec in 0.0f64..1.0,
                base_ap in 0.0f64..1.0,
                base_prec in 0.0f64..1.0,
            ) {
                let current = metrics(ap, prec);
                let baseline = metrics(base_ap, base_prec);
                let thresh = RegressionThresholds::default();
                let r1 = check_regression(&current, &baseline, &thresh);
                let r2 = check_regression(&current, &baseline, &thresh);
                prop_assert_eq!(r1.verdict, r2.verdict);
                for (a, b) in r1.checks.iter().zip(r2.checks.iter()) {
                    prop_assert_eq!(a.verdict, b.verdict);
                    prop_assert!((a.delta - b.delta).abs() < EPS);
                }
            }

            /// NaN guard: safe_div guarantees no NaN in metrics, so AP and
            /// precision are always finite. This test verifies the assumption
            /// holds under arbitrary inputs.
            #[test]
            fn no_nan_in_result(
                ap in 0.0f64..1.0,
                prec in 0.0f64..1.0,
            ) {
                let current = metrics(ap, prec);
                let baseline = metrics(0.9, 0.9);
                let result = check_regression(&current, &baseline, &RegressionThresholds::default());
                for check in &result.checks {
                    prop_assert!(check.delta.is_finite(), "delta is not finite: {}", check.delta);
                    prop_assert!(check.current.is_finite());
                    prop_assert!(check.baseline.is_finite());
                }
            }
        }
    }
}
