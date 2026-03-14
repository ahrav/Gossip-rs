//! Random [`MutationPlan`] generation for the sim-harness.
//!
//! Produces valid, deterministic plans from a [`SimRng`] seed so that
//! random-seed test modes can exercise mutation-generated tokens through the
//! full scanning pipeline. The same seed always produces the same sequence of
//! plans, which is what makes both random-seed testing (discover new failures)
//! and corpus replay (reproduce old failures) work from a single code path.
//!
//! # Generation strategy
//!
//! When using [`random_mutation_plan`] (single-plan mode), each plan is
//! assembled by drawing from the RNG in a fixed order:
//!
//! 1. **Family** -- uniform random selection from [`TokenFamily::ALL`]
//!    (skipped in batch mode, where the family is determined by the outer
//!    iteration over [`TokenFamily::ALL`]).
//! 2. **Base seed** -- a fresh 64-bit value used by [`execute_plan`] to
//!    generate the canonical token.
//! 3. **Operator count** -- uniform in `0..=4`. Zero operators test the
//!    baseline (unmutated token must be detected). Higher counts test
//!    multi-operator composition.
//! 4. **Operators** -- each drawn from the family's [`allowed_ops`] set with
//!    parameters bounded by [`param_bound`] to avoid degenerate values.
//! 5. **Context wrapper** -- uniform random from [`ContextWrap::ALL`].
//!
//! The strict RNG consumption order is load-bearing: reordering any draw
//! changes all downstream plans for a given seed. Tests assert determinism
//! across runs (`random_plan_determinism`).
//!
//! [`execute_plan`]: super::plan::execute_plan
//! [`allowed_ops`]: TokenFamily::allowed_ops
//! [`param_bound`]: TokenFamily::param_bound

use super::encode::SecretRepr;
use super::family::TokenFamily;
use super::op::{MutOp, MutOpKind};
use super::plan::{ContextWrap, MutationPlan};
use crate::sim::rng::SimRng;

/// Upper bound (exclusive) on the number of mutation operators per plan.
/// Zero operators test the baseline (unmutated token must be detected);
/// higher counts exercise multi-operator composition paths.
const MAX_MUTATION_OPS: u32 = 5;

/// Generate a single random [`MutationPlan`] for a uniformly chosen family.
///
/// Consumes RNG state for family selection plus all draws needed by
/// `random_plan_for_family`. The caller's `rng` is advanced
/// deterministically, so interleaving calls with other RNG consumers
/// changes the plan sequence -- callers should use a dedicated `SimRng`
/// instance for plan generation.
pub fn random_mutation_plan(rng: &mut SimRng, case_id: u64) -> MutationPlan {
    let families = TokenFamily::ALL;
    let family = families[rng.gen_range(0, families.len() as u32) as usize];
    random_plan_for_family(rng, family, case_id)
}

/// Generate `plans_per_family` random plans for *each* token family.
///
/// Returns exactly `TokenFamily::ALL.len() * plans_per_family` plans,
/// grouped by family in [`TokenFamily::ALL`] order. Within each family
/// group, plans are generated sequentially from the same `rng` stream,
/// so earlier families consume RNG state before later ones. Case IDs are
/// assigned as a monotonically increasing counter across all families.
///
/// This is the primary entry point for the random-seed scanner test
/// (`bounded_random_mutation_scanner_sims`). The corpus replay test
/// deserializes previously generated plans from JSON rather than calling
/// this function.
pub fn random_mutation_plans_all_families(
    rng: &mut SimRng,
    plans_per_family: u32,
) -> Vec<MutationPlan> {
    let mut plans = Vec::with_capacity(TokenFamily::ALL.len() * plans_per_family as usize);
    let mut case_id = 0u64;
    for family in TokenFamily::ALL {
        for _ in 0..plans_per_family {
            plans.push(random_plan_for_family(rng, family, case_id));
            case_id += 1;
        }
    }
    plans
}

/// Build a single plan for a specific family.
///
/// Draws from `rng` in the order documented in the module header:
/// base_seed, op_count, then per-operator kind + parameters, then context
/// wrapper. The 0--4 operator count range keeps plans small enough to
/// reason about while still exercising multi-operator composition paths
/// (e.g. `Extend` then `Truncate`).
fn random_plan_for_family(rng: &mut SimRng, family: TokenFamily, case_id: u64) -> MutationPlan {
    let base_seed = rng.next_u64();
    let op_count = rng.gen_range(0, MAX_MUTATION_OPS) as usize;
    let bound = family.param_bound();
    let allowed = family.allowed_ops();

    let mut ops = Vec::with_capacity(op_count);
    for _ in 0..op_count {
        let kind = allowed[rng.gen_range(0, allowed.len() as u32) as usize];
        ops.push(random_op(rng, kind, bound));
    }

    let wraps = ContextWrap::ALL;
    let context = wraps[rng.gen_range(0, wraps.len() as u32) as usize];

    MutationPlan {
        family,
        base_seed,
        case_id,
        ops,
        context,
    }
}

/// Produce one random [`MutOp`] for the given kind, with numeric parameters
/// bounded by `bound` (typically [`TokenFamily::param_bound`]).
///
/// The bounding strategy keeps generated values in a realistic range for the
/// target token format: positions stay within the token length, truncation
/// lengths stay near the canonical size, and suffix/replacement lengths stay
/// short enough to be interpretable in failure messages. Specific bounds:
///
/// - **Truncate**: `len` in `0..=bound` (may exceed canonical length, which
///   is a no-op, or be zero, which is an aggressive break).
/// - **CharsetViolate**: 1--3 positions, each in `0..bound`.
/// - **PrefixMangle**: 1--8 byte replacement (short enough to inspect).
/// - **EntropyReduce**: `count` in `0..=bound`, arbitrary repeat byte.
/// - **Encode**: uniform over Base64, UrlPercent, Utf16Le, and Nested(1--3).
///   `Raw` and `Utf16Be` are excluded to keep every Encode op non-trivial.
/// - **Extend**: 1--16 byte suffix of random bytes.
fn random_op(rng: &mut SimRng, kind: MutOpKind, bound: usize) -> MutOp {
    match kind {
        MutOpKind::Truncate => MutOp::Truncate {
            len: rng.gen_range(0, bound.saturating_add(1) as u32) as usize,
        },
        MutOpKind::CharsetViolate => {
            let count = rng.gen_range(1, 4) as usize;
            let positions: Vec<usize> = (0..count)
                .map(|_| rng.gen_range(0, bound as u32) as usize)
                .collect();
            MutOp::CharsetViolate {
                positions,
                replacement: rng.gen_range(0, 256) as u8,
            }
        }
        MutOpKind::PrefixMangle => {
            let len = rng.gen_range(1, 9) as usize;
            let replacement: Vec<u8> = (0..len).map(|_| rng.gen_range(0, 256) as u8).collect();
            MutOp::PrefixMangle { replacement }
        }
        MutOpKind::ChecksumCorrupt => MutOp::ChecksumCorrupt,
        MutOpKind::EntropyReduce => MutOp::EntropyReduce {
            repeat_byte: rng.gen_range(0, 256) as u8,
            count: rng.gen_range(0, bound.saturating_add(1) as u32) as usize,
        },
        MutOpKind::Encode => {
            // Weighted 25% each: three concrete encodings plus nested.
            let repr = match rng.gen_range(0, 4) {
                0 => SecretRepr::Base64,
                1 => SecretRepr::UrlPercent,
                2 => SecretRepr::Utf16Le,
                _ => SecretRepr::Nested {
                    depth: rng.gen_range(1, 4) as u8,
                },
            };
            MutOp::Encode { repr }
        }
        MutOpKind::Extend => {
            let len = rng.gen_range(1, 17) as usize;
            let suffix: Vec<u8> = (0..len).map(|_| rng.gen_range(0, 256) as u8).collect();
            MutOp::Extend { suffix }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_plan_determinism() {
        let mut rng_a = SimRng::new(42);
        let mut rng_b = SimRng::new(42);
        let a = random_mutation_plan(&mut rng_a, 0);
        let b = random_mutation_plan(&mut rng_b, 0);
        assert_eq!(a, b, "same seed must produce identical plans");
    }
}

#[cfg(all(test, feature = "stdx-proptest"))]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    const PROPTEST_CASES: u32 = 64;

    /// Assert all structural invariants on a single [`MutationPlan`].
    fn assert_plan_invariants(plan: &MutationPlan) {
        // Op count: random_plan_for_family draws 0..MAX_MUTATION_OPS.
        assert!(
            plan.ops.len() < MAX_MUTATION_OPS as usize,
            "ops.len()={} exceeds maximum of {}",
            plan.ops.len(),
            MAX_MUTATION_OPS - 1,
        );

        // Context must be one of the known wrappers.
        assert!(
            ContextWrap::ALL.contains(&plan.context),
            "unknown context wrapper: {:?}",
            plan.context,
        );

        // Every op kind must be in the family's allowed set.
        let allowed = plan.family.allowed_ops();
        for op in &plan.ops {
            assert!(
                allowed.contains(&op.kind()),
                "op {:?} not in allowed set for {:?}",
                op.kind(),
                plan.family,
            );
        }

        // Per-op parameter bounds.
        let bound = plan.family.param_bound();
        for op in &plan.ops {
            match op {
                MutOp::Truncate { len } => {
                    assert!(
                        *len <= bound,
                        "Truncate len={len} exceeds param_bound={bound}",
                    );
                }
                MutOp::CharsetViolate { positions, .. } => {
                    assert!(
                        (1..=3).contains(&positions.len()),
                        "CharsetViolate positions count={} not in 1..=3",
                        positions.len(),
                    );
                    for &p in positions {
                        assert!(
                            p < bound,
                            "CharsetViolate position={p} >= param_bound={bound}",
                        );
                    }
                }
                MutOp::PrefixMangle { replacement } => {
                    assert!(
                        (1..=8).contains(&replacement.len()),
                        "PrefixMangle replacement len={} not in 1..=8",
                        replacement.len(),
                    );
                }
                MutOp::EntropyReduce { count, .. } => {
                    assert!(
                        *count <= bound,
                        "EntropyReduce count={count} exceeds param_bound={bound}",
                    );
                }
                MutOp::Encode { repr } => {
                    use super::super::encode::SecretRepr;
                    match repr {
                        SecretRepr::Base64 | SecretRepr::UrlPercent | SecretRepr::Utf16Le => {}
                        SecretRepr::Nested { depth } => {
                            assert!(
                                (1..=3).contains(depth),
                                "Encode Nested depth={depth} not in 1..=3",
                            );
                        }
                        other => {
                            panic!("unexpected Encode repr: {other:?}");
                        }
                    }
                }
                MutOp::Extend { suffix } => {
                    assert!(
                        (1..=16).contains(&suffix.len()),
                        "Extend suffix len={} not in 1..=16",
                        suffix.len(),
                    );
                }
                MutOp::ChecksumCorrupt => {}
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(
            crate::test_utils::proptest_cases(PROPTEST_CASES)
        ))]

        /// Same seed + case_id must always produce the same plan.
        #[test]
        fn single_plan_determinism(seed: u64, case_id: u64) {
            let a = random_mutation_plan(&mut SimRng::new(seed), case_id);
            let b = random_mutation_plan(&mut SimRng::new(seed), case_id);
            prop_assert_eq!(a, b);
        }

        /// Every randomly generated plan satisfies all structural invariants.
        #[test]
        fn single_plan_structural_invariants(seed: u64, case_id: u64) {
            let plan = random_mutation_plan(&mut SimRng::new(seed), case_id);
            assert_plan_invariants(&plan);
        }

        /// Batch generation covers all families in order with correct counts
        /// and monotonic case IDs, and every plan passes invariant checks.
        #[test]
        fn batch_generation_invariants(seed: u64, plans_per_family in 1u32..=5) {
            let plans = random_mutation_plans_all_families(
                &mut SimRng::new(seed),
                plans_per_family,
            );

            // Total count: families × plans_per_family.
            let expected_len = TokenFamily::ALL.len() * plans_per_family as usize;
            prop_assert_eq!(plans.len(), expected_len);

            // Families appear grouped in TokenFamily::ALL order.
            for (family_idx, family) in TokenFamily::ALL.iter().enumerate() {
                let start = family_idx * plans_per_family as usize;
                for offset in 0..plans_per_family as usize {
                    prop_assert_eq!(
                        plans[start + offset].family,
                        *family,
                        "plan at index {} should be {:?}",
                        start + offset,
                        family,
                    );
                }
            }

            // case_id is a monotonic 0..n sequence.
            for (i, plan) in plans.iter().enumerate() {
                prop_assert_eq!(
                    plan.case_id,
                    i as u64,
                    "case_id at index {} should be {}",
                    i,
                    i,
                );
            }

            // Every plan passes structural invariants.
            for plan in &plans {
                assert_plan_invariants(plan);
            }
        }
    }
}
