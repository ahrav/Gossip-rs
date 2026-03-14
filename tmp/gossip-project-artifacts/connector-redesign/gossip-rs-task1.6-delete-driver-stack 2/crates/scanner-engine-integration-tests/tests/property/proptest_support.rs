//! Proptest strategies and custom shrinker for `MutationPlan`.
//!
//! # Why a custom `ValueTree`?
//!
//! Proptest's built-in combinators shrink each field independently, which would
//! generate plans where ops violate the family's `allowed_ops` constraint (e.g.
//! shrinking an `AwsAccessKey` plan's op into `ChecksumCorrupt`, which that
//! family does not allow). A custom [`MutationPlanValueTree`] keeps `family`
//! and `base_seed` immutable throughout shrinking and validates every candidate
//! against [`is_valid_plan`] before emitting it, guaranteeing that proptest
//! never reports an invalid plan as a minimal counterexample.
//!
//! # Shrink phases
//!
//! The shrinker proceeds through four phases in strict priority order, spending
//! the shrinking budget on the highest-impact reductions first:
//!
//! 0. **Truncate ops suffix** — binary search on the included-ops prefix
//!    length, rapidly halving the op count.
//! 1. **Remove individual ops** — bitset soft-deletion with a backward cursor,
//!    trying to eliminate each remaining op one at a time.
//! 2. **Shrink op parameters** — per-field binary search toward 0 on each
//!    surviving op's numeric parameters (lengths, byte values, ordinals).
//! 3. **Shrink context** — decrement the `ContextWrap` ordinal toward `Raw`.
//!
//! Phase transitions are monotonic — once a phase exhausts its search space,
//! the shrinker advances to the next phase and never returns. This ordering
//! ensures that structural simplifications (fewer ops) are preferred over
//! parametric ones (smaller values within an op), producing more readable
//! minimal counterexamples.

use proptest::prelude::*;
use proptest::strategy::{NewTree, ValueTree};
use proptest::test_runner::TestRunner;

use scanner_scheduler::sim::mutation::{
    ContextWrap, MutOp, MutOpKind, MutationPlan, SecretRepr, TokenFamily,
};

// Compile-time guards: if a variant is added to these enums, the assertion
// fires and the ordinal mappings / strategy lists below must be updated.
const _: () = assert!(ContextWrap::ALL.len() == 6);
const _: () = assert!(TokenFamily::ALL.len() == 6);

// ---------------------------------------------------------------------------
// Conservative upper bounds per family (token length)
// ---------------------------------------------------------------------------

/// Delegate to [`TokenFamily::param_bound`] so both proptest and plan_gen
/// share a single source of truth.
fn family_bound(family: TokenFamily) -> usize {
    family.param_bound()
}

// ---------------------------------------------------------------------------
// Ordinal conversions
// ---------------------------------------------------------------------------

// The ordinal mappings below impose a total order on `ContextWrap` and
// `SecretRepr` so that the shrinker can binary-search toward 0 (the "simplest"
// variant: `Raw` for both types). `ContextWrap` ordinals are derived from
// `ContextWrap::ALL` to auto-sync with production code. `SecretRepr` ordinals
// use explicit match arms because the parametric `Nested` variant cannot be
// enumerated in a const array.

/// Map a `ContextWrap` to a numeric ordinal for shrinking (0 = `Raw` = simplest).
///
/// Derived from [`ContextWrap::ALL`] so the mapping auto-syncs when variants
/// are added. The compile-time guard at the top of this file catches count
/// changes.
fn context_to_ordinal(ctx: ContextWrap) -> usize {
    ContextWrap::ALL.iter().position(|&c| c == ctx).unwrap()
}

/// Inverse of [`context_to_ordinal`]. Out-of-range ordinals saturate to the
/// last variant in [`ContextWrap::ALL`].
fn context_from_ordinal(ord: usize) -> ContextWrap {
    ContextWrap::ALL
        .get(ord)
        .copied()
        .unwrap_or(*ContextWrap::ALL.last().unwrap())
}

/// Map a `SecretRepr` to a numeric ordinal for shrinking (0 = `Raw` = simplest).
///
/// `Nested { depth: d }` maps to `5 + (d - 1)`, so `Nested { depth: 1 }` = 5.
/// The `saturating_sub` means `Nested { depth: 0 }` maps to ordinal 5,
/// colliding with `Nested { depth: 1 }`. This is harmless because the
/// generation strategy never produces `depth: 0` (it generates `1..=4`).
fn repr_to_ordinal(repr: &SecretRepr) -> usize {
    match repr {
        SecretRepr::Raw => 0,
        SecretRepr::Base64 => 1,
        SecretRepr::UrlPercent => 2,
        SecretRepr::Utf16Le => 3,
        SecretRepr::Utf16Be => 4,
        SecretRepr::Nested { depth } => 5 + (*depth as usize).saturating_sub(1),
    }
}

/// Inverse of [`repr_to_ordinal`]. Ordinals >= 5 produce `Nested { depth }`
/// with depth = `ord - 4`.
fn repr_from_ordinal(ord: usize) -> SecretRepr {
    match ord {
        0 => SecretRepr::Raw,
        1 => SecretRepr::Base64,
        2 => SecretRepr::UrlPercent,
        3 => SecretRepr::Utf16Le,
        4 => SecretRepr::Utf16Be,
        n => SecretRepr::Nested {
            depth: (n - 4) as u8,
        },
    }
}

// ---------------------------------------------------------------------------
// Unified field layout
// ---------------------------------------------------------------------------

// `field_layout` is the single source of truth for the shrinkable fields of
// each `MutOp` variant. Both `extract_fields` (which builds `ParamSearch`
// entries) and `apply_param_shrinks` (which reconstructs ops from shrunk
// values) delegate here, so adding or reordering a field in one automatically
// updates the other.

/// Return the canonical field layout for an op: one current value per
/// shrinkable numeric field, in a fixed order per variant.
///
/// The shrinker binary-searches each value toward 0. Callers do not need to
/// know the semantic type of each field — `rebuild_op_from_values` handles
/// reconstruction from the flat value array.
fn field_layout(op: &MutOp) -> Vec<usize> {
    match op {
        MutOp::Truncate { len } => vec![*len],
        MutOp::CharsetViolate {
            positions,
            replacement,
        } => {
            let mut fields = Vec::new();
            if !positions.is_empty() {
                fields.push(positions.len());
            }
            fields.push(*replacement as usize);
            fields
        }
        MutOp::PrefixMangle { replacement } => {
            if replacement.is_empty() {
                vec![]
            } else {
                vec![replacement.len()]
            }
        }
        MutOp::ChecksumCorrupt => vec![],
        MutOp::EntropyReduce {
            repeat_byte, count, ..
        } => vec![*repeat_byte as usize, *count],
        MutOp::Encode { repr } => {
            let ord = repr_to_ordinal(repr);
            if ord == 0 { vec![] } else { vec![ord] }
        }
        MutOp::Extend { suffix } => {
            if suffix.is_empty() {
                vec![]
            } else {
                vec![suffix.len()]
            }
        }
    }
}

/// Reconstruct an op from a flat array of shrunk field values.
///
/// The `vals` slice has the same length and ordering as `field_layout(op)`.
/// Collection fields use `vals[i]` as the prefix length (clamped to the
/// original collection size); scalar fields use `vals[i]` directly.
fn rebuild_op_from_values(op: &MutOp, vals: &[usize]) -> MutOp {
    match op {
        MutOp::Truncate { .. } => MutOp::Truncate { len: vals[0] },
        MutOp::CharsetViolate { positions, .. } => {
            if positions.is_empty() {
                MutOp::CharsetViolate {
                    positions: vec![],
                    replacement: vals[0] as u8,
                }
            } else {
                MutOp::CharsetViolate {
                    positions: positions[..vals[0].min(positions.len())].to_vec(),
                    replacement: vals[1] as u8,
                }
            }
        }
        MutOp::PrefixMangle { replacement } => {
            if vals.is_empty() {
                MutOp::PrefixMangle {
                    replacement: replacement.clone(),
                }
            } else {
                MutOp::PrefixMangle {
                    replacement: replacement[..vals[0].min(replacement.len())].to_vec(),
                }
            }
        }
        MutOp::ChecksumCorrupt => MutOp::ChecksumCorrupt,
        MutOp::EntropyReduce { .. } => MutOp::EntropyReduce {
            repeat_byte: vals[0] as u8,
            count: vals[1],
        },
        MutOp::Encode { repr } => {
            if vals.is_empty() {
                MutOp::Encode { repr: repr.clone() }
            } else {
                MutOp::Encode {
                    repr: repr_from_ordinal(vals[0]),
                }
            }
        }
        MutOp::Extend { suffix } => {
            if vals.is_empty() {
                MutOp::Extend {
                    suffix: suffix.clone(),
                }
            } else {
                MutOp::Extend {
                    suffix: suffix[..vals[0].min(suffix.len())].to_vec(),
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Validity check
// ---------------------------------------------------------------------------

/// Check that every op in the plan uses an op kind allowed by the family.
///
/// This is the shrinker's validity predicate: every candidate produced by
/// `simplify()` is checked against this function, and invalid candidates are
/// rejected (the shrinker reverts and tries a different reduction). It is also
/// used in property tests to assert that generation never produces invalid plans.
pub fn is_valid_plan(plan: &MutationPlan) -> bool {
    let allowed = plan.family.allowed_ops();
    plan.ops
        .iter()
        .all(|op: &MutOp| allowed.contains(&op.kind()))
}

// ---------------------------------------------------------------------------
// Leaf strategies (generation-only helpers)
// ---------------------------------------------------------------------------

/// Uniform strategy over all 6 `TokenFamily` variants.
pub(super) fn arb_family() -> impl Strategy<Value = TokenFamily> {
    prop_oneof![
        Just(TokenFamily::AwsAccessKey),
        Just(TokenFamily::GithubFinegrainedPat),
        Just(TokenFamily::GithubClassicPat),
        Just(TokenFamily::JwtLike),
        Just(TokenFamily::Base64Blob),
        Just(TokenFamily::UrlEncodedBlob),
    ]
}

/// Uniform strategy over all 6 `ContextWrap` variants.
fn arb_context_wrap() -> impl Strategy<Value = ContextWrap> {
    prop_oneof![
        Just(ContextWrap::Raw),
        Just(ContextWrap::EnvAssignment),
        Just(ContextWrap::JsonField),
        Just(ContextWrap::YamlValue),
        Just(ContextWrap::SingleLineComment),
        Just(ContextWrap::MultiLineString),
    ]
}

/// Uniform strategy over `SecretRepr` unit variants + `Nested{1..=4}`.
fn arb_secret_repr() -> impl Strategy<Value = SecretRepr> {
    prop_oneof![
        Just(SecretRepr::Raw),
        Just(SecretRepr::Base64),
        Just(SecretRepr::UrlPercent),
        Just(SecretRepr::Utf16Le),
        Just(SecretRepr::Utf16Be),
        (1u8..=4).prop_map(|depth| SecretRepr::Nested { depth }),
    ]
}

/// Generate a `MutOp` constrained to the family's allowed ops with bounded
/// parameters.
///
/// Builds a `Union` strategy over one sub-strategy per allowed `MutOpKind`.
/// Numeric parameters (lengths, positions, byte values) are bounded by
/// [`family_bound`] so that generated values stay within the token's realistic
/// size range. The resulting strategy is boxed because the variant set differs
/// per family.
fn arb_op_for_family(family: TokenFamily) -> BoxedStrategy<MutOp> {
    let allowed = family.allowed_ops();
    let bound = family_bound(family);

    let mut variants: Vec<BoxedStrategy<MutOp>> = Vec::new();

    for &kind in allowed {
        match kind {
            MutOpKind::Truncate => {
                variants.push((0..=bound).prop_map(|len| MutOp::Truncate { len }).boxed());
            }
            MutOpKind::CharsetViolate => {
                variants.push(
                    (proptest::collection::vec(0..bound, 1..=3), any::<u8>())
                        .prop_map(|(positions, replacement)| MutOp::CharsetViolate {
                            positions,
                            replacement,
                        })
                        .boxed(),
                );
            }
            MutOpKind::PrefixMangle => {
                variants.push(
                    proptest::collection::vec(any::<u8>(), 1..=8)
                        .prop_map(|replacement| MutOp::PrefixMangle { replacement })
                        .boxed(),
                );
            }
            MutOpKind::ChecksumCorrupt => {
                variants.push(Just(MutOp::ChecksumCorrupt).boxed());
            }
            MutOpKind::EntropyReduce => {
                variants.push(
                    (any::<u8>(), 0..=bound)
                        .prop_map(|(repeat_byte, count)| MutOp::EntropyReduce {
                            repeat_byte,
                            count,
                        })
                        .boxed(),
                );
            }
            MutOpKind::Encode => {
                variants.push(
                    arb_secret_repr()
                        .prop_map(|repr| MutOp::Encode { repr })
                        .boxed(),
                );
            }
            MutOpKind::Extend => {
                variants.push(
                    proptest::collection::vec(any::<u8>(), 0..=16)
                        .prop_map(|suffix| MutOp::Extend { suffix })
                        .boxed(),
                );
            }
        }
    }

    proptest::strategy::Union::new(variants).boxed()
}

// ---------------------------------------------------------------------------
// MutationPlanStrategy — the public entry point
// ---------------------------------------------------------------------------

/// Maximum ops per generated plan. Kept small to make shrinking fast; 8 ops
/// is enough to exercise multi-op interactions (e.g. Extend then Truncate)
/// without blowing up the shrink search space.
const DEFAULT_MAX_OPS: usize = 8;

/// Proptest strategy that generates `MutationPlan` values paired with a custom
/// [`MutationPlanValueTree`] for structured shrinking.
///
/// Use [`arb_plan`] as the ergonomic entry point. The strategy picks a random
/// `TokenFamily` first, then generates ops constrained to that family's
/// `allowed_ops`, so every generated plan is valid by construction.
#[derive(Debug)]
pub struct MutationPlanStrategy;

/// Convenience constructor for use in `proptest!` blocks and manual test code.
pub fn arb_plan() -> MutationPlanStrategy {
    MutationPlanStrategy
}

impl Strategy for MutationPlanStrategy {
    type Tree = MutationPlanValueTree;
    type Value = MutationPlan;

    fn new_tree(&self, runner: &mut TestRunner) -> NewTree<Self> {
        // Family is generated first because ops depend on it — each family has
        // a different set of allowed op kinds. We snapshot `family` immediately
        // and use it to build the ops strategy, so the generated ops are always
        // valid for the chosen family.
        let family_tree = arb_family().new_tree(runner)?;
        let family = family_tree.current();

        let seed_tree = any::<u64>().new_tree(runner)?;
        let context_tree = arb_context_wrap().new_tree(runner)?;

        let ops_strategy =
            proptest::collection::vec(arb_op_for_family(family), 0..=DEFAULT_MAX_OPS);
        let ops_tree = ops_strategy.new_tree(runner)?;

        // We discard the sub-trees (family_tree, seed_tree, etc.) and hand full
        // control to MutationPlanValueTree, which keeps family and base_seed
        // immutable and only shrinks ops + context.
        let initial = MutationPlan {
            family,
            base_seed: seed_tree.current(),
            case_id: 0,
            ops: ops_tree.current(),
            context: context_tree.current(),
        };

        Ok(MutationPlanValueTree::new(initial))
    }
}

// ---------------------------------------------------------------------------
// MutationPlanValueTree — custom shrinking
// ---------------------------------------------------------------------------

/// Shrinking phase — strictly sequential, monotonic transitions.
///
/// The ordering is deliberate: coarse structural reductions (fewer ops) come
/// before fine parametric ones (smaller values), and context shrinking is last
/// because it is independent of the ops. `Done` is a terminal absorbing state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ShrinkPhase {
    /// Binary search on the prefix length of the included-ops list.
    OpsLength,
    /// Try removing individual ops via bitset soft-deletion.
    RemoveOp,
    /// Binary-search each surviving op's numeric parameters toward 0.
    ShrinkParam,
    /// Decrement the `ContextWrap` ordinal toward `Raw`.
    ShrinkContext,
    /// All phases exhausted; `simplify()` returns `false`.
    Done,
}

/// Tracks the last successful `simplify()` action so that `complicate()` can
/// undo it.
///
/// Proptest calls `complicate()` when the simplified candidate *passes* the
/// test (no longer triggers the failure) — meaning the reduction removed
/// something essential and needs to be partially undone. Each variant stores
/// just enough state to undo one simplify step and adjust the binary search
/// bounds so the next `simplify()` tries the other half.
#[derive(Clone, Debug)]
enum PrevShrink {
    /// Phase 0: truncated ops to `len_hi = mid`; `prev_hi` is the bound before
    /// truncation, needed to restore the search range.
    TruncatedTo { prev_hi: usize },
    /// Phase 1: soft-deleted op at backing-vec index `idx`.
    RemovedOp { idx: usize },
    /// Phase 2: halved a parameter field's `hi` bound; `prev_hi` is the
    /// pre-shrink upper bound for restoration.
    ShrankParam {
        target_idx: usize,
        field_idx: usize,
        prev_hi: usize,
    },
    /// Phase 3: decremented the context ordinal from `prev_ordinal`.
    ShrankContext { prev_ordinal: usize },
}

/// Binary search state for one shrinkable field of an op.
///
/// `lo` is the search floor (starts at 0, the shrink target); `hi` is the
/// current candidate value (starts at the field's generated value). On each
/// `simplify()` step, the midpoint `(lo + hi) / 2` is tried as the new `hi`;
/// on `complicate()`, `lo` is set to `mid + 1` and `hi` is restored. When
/// `lo >= hi`, this field is fully shrunk and the cursor advances.
///
/// The reconstructed op uses `hi` as the effective field value (see
/// [`MutationPlanValueTree::apply_param_shrinks`]), matching proptest's
/// standard convention where `simplify()` lowers `hi` and `complicate()`
/// restores it.
#[derive(Clone, Debug)]
struct ParamSearch {
    lo: usize,
    hi: usize,
}

/// Collects the shrinkable fields for one op, built lazily at the
/// phase 1 -> phase 2 transition.
///
/// `op_idx` refers to the backing `ops` vec (not the filtered view), so it
/// remains valid even as the `included` bitset changes during earlier phases.
#[derive(Clone, Debug)]
struct OpParamTargets {
    /// Index into the backing `ops` vec (stable across shrink phases).
    op_idx: usize,
    /// One [`ParamSearch`] per shrinkable numeric field in this op.
    /// `ChecksumCorrupt` has no fields; `CharsetViolate` has one or two
    /// (position count when non-empty, plus replacement byte).
    fields: Vec<ParamSearch>,
}

/// Custom [`ValueTree`] for `MutationPlan` with structured multi-phase shrinking.
///
/// # Invariants
///
/// - `family` and `base_seed` are **immutable** throughout the tree's lifetime.
///   Only `ops` (via `included` bitset + parameter shrinks) and `context` (via
///   ordinal) change during shrinking.
/// - The backing `ops` vec is never mutated. Inclusion/exclusion is tracked by
///   a parallel `included` bitset, and parameter shrinks are applied on the fly
///   during `current_ops()` reconstruction.
/// - Every plan returned by `current()` satisfies [`is_valid_plan`]. Invalid
///   candidates are silently reverted within each phase's `simplify_*` method.
///
/// # Reconstruction
///
/// `current()` rebuilds the plan from scratch each time: it filters `ops` by
/// the `included` bitset, overlays parameter shrinks from `param_targets`, and
/// converts `context_ordinal` back to a `ContextWrap`. This is cheap (the ops
/// vec is at most [`DEFAULT_MAX_OPS`] = 8 elements) and avoids maintaining a
/// synchronized mutable copy.
pub struct MutationPlanValueTree {
    /// Snapshot of the generated plan. `family` and `base_seed` are read from
    /// here on every `current()` call; `ops` and `context` are ignored in
    /// favor of the shrinker's own state.
    initial: MutationPlan,
    /// Immutable backing storage for the generated ops. Never modified; the
    /// `included` bitset and `param_targets` overlay determine what `current()`
    /// returns.
    ops: Vec<MutOp>,
    /// Parallel bitset: `included[i]` is `true` if `ops[i]` is part of the
    /// current candidate. Phases 0 and 1 flip bits to `false` to remove ops.
    included: Vec<bool>,

    // -- Phase 0: prefix-length binary search --
    phase: ShrinkPhase,
    /// Lower bound (inclusive) of the binary search on included-ops count.
    len_lo: usize,
    /// Upper bound (exclusive) of the binary search on included-ops count.
    len_hi: usize,

    // -- Phase 1: individual op removal --
    /// Backing-vec index at or below which the next removal will be attempted.
    /// Scans backward (high to low) so that later ops are removed first.
    remove_cursor: usize,
    /// Set when the cursor reaches 0, signaling that phase 1 is complete.
    remove_exhausted: bool,

    // -- Phase 2: per-field parameter shrinking --
    /// One entry per surviving op that has shrinkable fields, built lazily at
    /// the phase 1 -> 2 transition by [`build_param_targets`].
    param_targets: Vec<OpParamTargets>,
    /// Cursor into `param_targets` (which op we are currently shrinking).
    param_target_idx: usize,
    /// Cursor into `param_targets[param_target_idx].fields` (which field).
    param_field_idx: usize,

    // -- Phase 3: context ordinal --
    /// Current context ordinal; shrinks by decrementing toward 0 (`Raw`).
    context_ordinal: usize,

    // -- Undo tracking --
    /// The most recent successful simplify action, consumed by `complicate()`
    /// to undo it. `None` after `complicate()` is called or if no simplify
    /// has succeeded yet.
    prev_shrink: Option<PrevShrink>,
}

impl MutationPlanValueTree {
    /// Create a new value tree rooted at the given plan.
    ///
    /// The plan's `ops` are cloned into immutable backing storage, and all
    /// shrinker cursors are initialized to their starting positions (phase 0,
    /// full inclusion, context ordinal matching `plan.context`).
    pub fn new(plan: MutationPlan) -> Self {
        let n = plan.ops.len();
        let context_ordinal = context_to_ordinal(plan.context);
        MutationPlanValueTree {
            ops: plan.ops.clone(),
            included: vec![true; n],
            initial: plan,
            phase: ShrinkPhase::OpsLength,
            len_lo: 0,
            len_hi: n,
            remove_cursor: n.saturating_sub(1),
            remove_exhausted: false,
            param_targets: Vec::new(),
            param_target_idx: 0,
            param_field_idx: 0,
            context_ordinal,
            prev_shrink: None,
        }
    }

    /// Reconstruct the current `MutationPlan` from the shrinker state.
    ///
    /// Reads `family` and `base_seed` from the immutable initial plan, builds
    /// the ops list via [`current_ops`](Self::current_ops), and converts the
    /// context ordinal back to a `ContextWrap`.
    fn current_plan(&self) -> MutationPlan {
        MutationPlan {
            family: self.initial.family,
            base_seed: self.initial.base_seed,
            case_id: self.initial.case_id,
            ops: self.current_ops(),
            context: context_from_ordinal(self.context_ordinal),
        }
    }

    /// Collect included ops, applying any parameter shrinks from phase 2.
    ///
    /// Single-pass reconstruction: builds the filtered ops list while recording
    /// a backing-index → filtered-index mapping. Parameter shrinks are then
    /// applied in O(m) using the precomputed mapping instead of re-scanning
    /// the included bitset for every target.
    fn current_ops(&self) -> Vec<MutOp> {
        let mut backing_to_filtered = [usize::MAX; DEFAULT_MAX_OPS];
        let mut ops = Vec::with_capacity(self.included_count());
        for (i, op) in self.ops.iter().enumerate() {
            if self.included[i] {
                backing_to_filtered[i] = ops.len();
                ops.push(op.clone());
            }
        }

        // Apply parameter shrinks from phase 2 targets.
        for target in &self.param_targets {
            let idx = backing_to_filtered[target.op_idx];
            if idx < ops.len() {
                ops[idx] = self.apply_param_shrinks(&self.ops[target.op_idx], target);
            }
        }

        ops
    }

    /// Replace an op's numeric fields with their current shrunk values.
    ///
    /// Delegates to [`field_layout`] for the canonical field ordering, reads
    /// the shrunk `hi` value from each corresponding `target.fields` entry,
    /// and passes the value array to [`rebuild_op_from_values`] for
    /// reconstruction. This keeps the field-ordering coupling in one place.
    fn apply_param_shrinks(&self, op: &MutOp, target: &OpParamTargets) -> MutOp {
        let layout = field_layout(op);
        let vals: Vec<usize> = layout
            .iter()
            .enumerate()
            .map(|(i, &original)| target.fields.get(i).map_or(original, |f| f.hi))
            .collect();
        rebuild_op_from_values(op, &vals)
    }

    /// Check whether the current shrinker state produces a valid plan without
    /// constructing the full `MutationPlan`. Walks the `included` bitset and
    /// verifies every included op's kind is in the family's `allowed_ops`.
    fn is_current_valid(&self) -> bool {
        let allowed = self.initial.family.allowed_ops();
        self.ops
            .iter()
            .enumerate()
            .filter(|(i, _)| self.included[*i])
            .all(|(_, op)| allowed.contains(&op.kind()))
    }

    /// Count currently included ops.
    fn included_count(&self) -> usize {
        self.included.iter().filter(|&&b| b).count()
    }

    /// Advance to the next shrinking phase, performing any one-time setup
    /// needed by the new phase (e.g. resetting the removal cursor for phase 1
    /// or building parameter targets for phase 2).
    fn advance_phase(&mut self) {
        self.phase = match self.phase {
            ShrinkPhase::OpsLength => {
                // Set up phase 1 cursor based on current included ops.
                let count = self.included_count();
                self.remove_cursor = if count == 0 { 0 } else { self.ops.len() - 1 };
                ShrinkPhase::RemoveOp
            }
            ShrinkPhase::RemoveOp => {
                self.build_param_targets();
                self.param_target_idx = 0;
                self.param_field_idx = 0;
                ShrinkPhase::ShrinkParam
            }
            ShrinkPhase::ShrinkParam => ShrinkPhase::ShrinkContext,
            ShrinkPhase::ShrinkContext | ShrinkPhase::Done => ShrinkPhase::Done,
        };
    }

    /// Build phase 2 shrink targets from the surviving (included) ops.
    ///
    /// Called once at the phase 1 -> 2 transition. Ops with no shrinkable
    /// fields (e.g. `ChecksumCorrupt`) are skipped. The targets are built from
    /// the post-removal state so that removed ops are not shrunk.
    fn build_param_targets(&mut self) {
        self.param_targets.clear();
        for (i, op) in self.ops.iter().enumerate() {
            if !self.included[i] {
                continue;
            }
            let fields = Self::extract_fields(op);
            if !fields.is_empty() {
                self.param_targets
                    .push(OpParamTargets { op_idx: i, fields });
            }
        }
    }

    /// Extract shrinkable fields from an op as `[0, current_value)` binary
    /// search ranges.
    ///
    /// Delegates to [`field_layout`] for the canonical field list, then
    /// converts each value into a `ParamSearch` entry.
    fn extract_fields(op: &MutOp) -> Vec<ParamSearch> {
        field_layout(op)
            .into_iter()
            .map(|val| ParamSearch { lo: 0, hi: val })
            .collect()
    }

    /// Phase 0: binary search on the number of included ops.
    ///
    /// Returns `Some(true)` when a valid truncation is found, `None` when the
    /// binary search is exhausted and the caller should advance to the next
    /// phase. Internal recursion retries after an invalid midpoint (bounded by
    /// `log2(DEFAULT_MAX_OPS)` = 3 levels).
    fn try_simplify_ops_length(&mut self) -> Option<bool> {
        if self.len_lo >= self.len_hi {
            return None;
        }

        let mid = self.len_lo + (self.len_hi - self.len_lo) / 2;

        // Exclude ops beyond `mid`.
        let mut count = 0;
        for i in 0..self.ops.len() {
            if self.included[i] {
                if count >= mid {
                    self.included[i] = false;
                }
                count += 1;
            }
        }

        if !self.is_current_valid() {
            // Revert: restore all included, then re-exclude beyond len_hi.
            self.included = vec![true; self.ops.len()];
            for (i, b) in self.included.iter_mut().enumerate() {
                if i >= self.len_hi {
                    *b = false;
                }
            }
            self.len_lo = mid + 1;
            return self.try_simplify_ops_length();
        }

        self.prev_shrink = Some(PrevShrink::TruncatedTo {
            prev_hi: self.len_hi,
        });
        self.len_hi = mid;
        Some(true)
    }

    /// Phase 1: remove individual ops one at a time via bitset soft deletion.
    ///
    /// Returns `Some(true)` when an op is successfully removed, `None` when
    /// all candidates have been tried and the caller should advance phases.
    fn try_simplify_remove_op(&mut self) -> Option<bool> {
        if self.remove_exhausted {
            return None;
        }

        // Find next included index, scanning backward from cursor.
        loop {
            if !self.included.iter().any(|&b| b) {
                return None;
            }

            // Find an included index at or before cursor.
            let candidate = (0..=self.remove_cursor).rev().find(|&i| self.included[i]);

            let idx = candidate?;

            self.included[idx] = false;

            if !self.is_current_valid() {
                // Revert and try next position.
                self.included[idx] = true;
                if idx == 0 {
                    return None;
                }
                self.remove_cursor = idx - 1;
                continue;
            }

            self.prev_shrink = Some(PrevShrink::RemovedOp { idx });
            if idx == 0 {
                // No lower indices left; next simplify should advance phase.
                self.remove_exhausted = true;
            } else {
                self.remove_cursor = idx - 1;
            }
            return Some(true);
        }
    }

    /// Phase 2: shrink op parameters via per-field binary search toward 0.
    ///
    /// Returns `Some(true)` when a field is successfully shrunk, `None` when
    /// all targets and fields are exhausted and the caller should advance.
    fn try_simplify_shrink_param(&mut self) -> Option<bool> {
        loop {
            if self.param_target_idx >= self.param_targets.len() {
                return None;
            }

            let target = &self.param_targets[self.param_target_idx];
            if self.param_field_idx >= target.fields.len() {
                self.param_target_idx += 1;
                self.param_field_idx = 0;
                continue;
            }

            let field = &self.param_targets[self.param_target_idx].fields[self.param_field_idx];
            if field.lo >= field.hi {
                self.param_field_idx += 1;
                continue;
            }

            let mid = field.lo + (field.hi - field.lo) / 2;
            let prev_hi = self.param_targets[self.param_target_idx].fields[self.param_field_idx].hi;

            self.param_targets[self.param_target_idx].fields[self.param_field_idx].hi = mid;

            if !self.is_current_valid() {
                // Revert.
                self.param_targets[self.param_target_idx].fields[self.param_field_idx].hi = prev_hi;
                self.param_targets[self.param_target_idx].fields[self.param_field_idx].lo = mid + 1;
                continue;
            }

            self.prev_shrink = Some(PrevShrink::ShrankParam {
                target_idx: self.param_target_idx,
                field_idx: self.param_field_idx,
                prev_hi,
            });
            return Some(true);
        }
    }

    /// Phase 3: decrement the context ordinal by 1 toward `Raw` (ordinal 0).
    ///
    /// Returns `Some(true)` when the ordinal is decremented, `None` when
    /// already at 0 and the caller should advance to `Done`.
    fn try_simplify_shrink_context(&mut self) -> Option<bool> {
        if self.context_ordinal == 0 {
            return None;
        }

        let prev = self.context_ordinal;
        self.context_ordinal -= 1;
        self.prev_shrink = Some(PrevShrink::ShrankContext { prev_ordinal: prev });
        Some(true)
    }
}

/// Proptest's `ValueTree` contract: `current()` returns the current candidate,
/// `simplify()` tries to make it smaller (returns `true` if it changed),
/// `complicate()` partially undoes the last simplification (returns `true` if
/// it changed). The test runner alternates simplify/complicate to binary-search
/// for the minimal failing input.
impl ValueTree for MutationPlanValueTree {
    type Value = MutationPlan;

    fn current(&self) -> MutationPlan {
        self.current_plan()
    }

    /// Dispatch to the current phase's simplification logic.
    ///
    /// Loops through phases: when a phase returns `None` (exhausted), the
    /// shrinker advances to the next phase and retries. Returns `true` if the
    /// candidate changed (a smaller plan was produced), `false` when all
    /// phases are exhausted.
    fn simplify(&mut self) -> bool {
        loop {
            let result = match self.phase {
                ShrinkPhase::OpsLength => self.try_simplify_ops_length(),
                ShrinkPhase::RemoveOp => self.try_simplify_remove_op(),
                ShrinkPhase::ShrinkParam => self.try_simplify_shrink_param(),
                ShrinkPhase::ShrinkContext => self.try_simplify_shrink_context(),
                ShrinkPhase::Done => return false,
            };
            match result {
                Some(progress) => return progress,
                None => self.advance_phase(),
            }
        }
    }

    /// Undo the last simplification step and adjust search bounds so that
    /// the next `simplify()` explores the complementary half of the range.
    ///
    /// Returns `false` if there is nothing to undo (no prior simplification
    /// succeeded, or `complicate()` was already called).
    fn complicate(&mut self) -> bool {
        let Some(prev) = self.prev_shrink.take() else {
            return false;
        };

        match prev {
            PrevShrink::TruncatedTo { prev_hi } => {
                // The last simplify set len_hi = mid. Undo by restoring
                // len_hi to prev_hi and advancing len_lo past mid so the
                // next binary search step explores the upper half.
                let current_hi = self.len_hi;
                self.len_hi = prev_hi;
                self.len_lo = current_hi + 1;

                // Re-include ops up to prev_hi (full reset because the
                // truncation may have flipped multiple bits).
                self.included = vec![false; self.ops.len()];
                for (i, b) in self.included.iter_mut().enumerate() {
                    if i < prev_hi {
                        *b = true;
                    }
                }
                true
            }
            PrevShrink::RemovedOp { idx } => {
                self.included[idx] = true;
                // The cursor is already below this index, so re-including it
                // won't cause a retry. If idx == 0, there are no lower indices
                // to try, so mark the phase exhausted.
                if idx == 0 {
                    self.remove_exhausted = true;
                }
                true
            }
            PrevShrink::ShrankParam {
                target_idx,
                field_idx,
                prev_hi,
            } => {
                // Restore the upper bound and advance the lower bound past the
                // midpoint that was tried, mirroring standard binary search
                // "complicate" semantics.
                if target_idx < self.param_targets.len()
                    && field_idx < self.param_targets[target_idx].fields.len()
                {
                    let field = &mut self.param_targets[target_idx].fields[field_idx];
                    field.lo = field.hi + 1;
                    field.hi = prev_hi;
                    true
                } else {
                    false
                }
            }
            PrevShrink::ShrankContext { prev_ordinal } => {
                self.context_ordinal = prev_ordinal;
                true
            }
        }
    }
}

impl std::fmt::Debug for MutationPlanValueTree {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MutationPlanValueTree")
            .field("phase", &self.phase)
            .field("included_count", &self.included_count())
            .field("context_ordinal", &self.context_ordinal)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Ordinal roundtrip guards
// ---------------------------------------------------------------------------

/// Verify that `repr_to_ordinal` → `repr_from_ordinal` roundtrips for every
/// `SecretRepr` variant the generation strategy can produce (unit variants +
/// `Nested { depth: 1..=4 }`). Also asserts no two distinct variants share
/// an ordinal, catching silent collisions.
#[test]
fn repr_ordinal_roundtrip_no_collision() {
    use scanner_scheduler::sim::mutation::SecretRepr;
    use std::collections::HashMap;

    let variants: Vec<SecretRepr> = vec![
        SecretRepr::Raw,
        SecretRepr::Base64,
        SecretRepr::UrlPercent,
        SecretRepr::Utf16Le,
        SecretRepr::Utf16Be,
        SecretRepr::Nested { depth: 1 },
        SecretRepr::Nested { depth: 2 },
        SecretRepr::Nested { depth: 3 },
        SecretRepr::Nested { depth: 4 },
    ];

    let mut seen: HashMap<usize, SecretRepr> = HashMap::new();

    for repr in &variants {
        let ord = repr_to_ordinal(repr);
        let back = repr_from_ordinal(ord);
        assert_eq!(
            *repr, back,
            "roundtrip failed: {repr:?} -> ordinal {ord} -> {back:?}",
        );

        if let Some(prev) = seen.insert(ord, repr.clone()) {
            panic!("ordinal collision: {repr:?} and {prev:?} both map to ordinal {ord}",);
        }
    }
}

/// Verify that `rebuild_op_from_values(op, &field_layout(op)) == op` for every
/// `MutOp` variant with fields. This guards the coupling between `field_layout`
/// and `rebuild_op_from_values` — if a field is added or reordered in one
/// function but not the other, this test catches the mismatch.
#[test]
fn field_layout_rebuild_roundtrip() {
    let ops = vec![
        MutOp::Truncate { len: 42 },
        MutOp::CharsetViolate {
            positions: vec![1, 3, 5],
            replacement: 0xAB,
        },
        MutOp::CharsetViolate {
            positions: vec![],
            replacement: 0xFF,
        },
        MutOp::PrefixMangle {
            replacement: b"AAAA".to_vec(),
        },
        MutOp::PrefixMangle {
            replacement: vec![],
        },
        MutOp::ChecksumCorrupt,
        MutOp::EntropyReduce {
            repeat_byte: 0x00,
            count: 10,
        },
        MutOp::Encode {
            repr: SecretRepr::Base64,
        },
        MutOp::Encode {
            repr: SecretRepr::Raw,
        },
        MutOp::Extend {
            suffix: vec![1, 2, 3],
        },
        MutOp::Extend { suffix: vec![] },
    ];

    for op in &ops {
        let layout = field_layout(op);
        let rebuilt = rebuild_op_from_values(op, &layout);
        assert_eq!(
            *op, rebuilt,
            "roundtrip failed for {op:?}: field_layout={layout:?}, rebuilt={rebuilt:?}",
        );
    }
}
