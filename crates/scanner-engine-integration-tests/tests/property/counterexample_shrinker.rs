//! Tests for the custom [`MutationPlanValueTree`] shrinker.
//!
//! These tests validate the shrinker's state machine by driving it through
//! `simplify()` / `complicate()` cycles with synthetic predicates — the same
//! contract that proptest's internal test runner uses. Each test targets a
//! specific property of well-behaved shrinking:
//!
//! - **Monotonicity**: shrinking never increases plan complexity.
//! - **Determinism**: identical seeds produce identical shrink sequences.
//! - **Validity**: every intermediate candidate satisfies the family's op
//!   constraints.
//! - **Minimality**: the shrinker converges to a near-minimal plan that still
//!   satisfies the predicate.
//! - **Context convergence**: unrestricted shrinking drives context to `Raw`.
//! - **Parameter convergence**: phase 2 binary search reaches the minimum
//!   satisfying value (or 0) for each field, including edge cases like
//!   empty collection fields.
//! - **Robustness**: edge cases (empty ops, interleaved simplify/complicate)
//!   do not panic.
//!
//! No scanner engine internals are invoked; the tests exercise only the
//! generation and shrinking layers from [`super::proptest_support`].

use proptest::prelude::*;
use proptest::strategy::ValueTree;
use proptest::test_runner::{Config, TestRunner};

use scanner_scheduler::sim::mutation::{ContextWrap, MutOp, MutOpKind, MutationPlan, TokenFamily};

use super::proptest_support::{MutationPlanValueTree, arb_plan, is_valid_plan};

/// Drive `simplify()` / `complicate()` cycles on `tree`, keeping the last
/// candidate that satisfies `predicate`. Returns that candidate after the
/// shrinker is exhausted or 500 steps elapse.
fn shrink_while(
    tree: &mut MutationPlanValueTree,
    predicate: impl Fn(&MutationPlan) -> bool,
) -> MutationPlan {
    let mut last_valid = tree.current();
    for _ in 0..500 {
        if !tree.simplify() {
            break;
        }
        let candidate = tree.current();
        if predicate(&candidate) {
            last_valid = candidate;
        } else {
            tree.complicate();
        }
    }
    last_valid
}

/// Build a deterministic `MutationPlanValueTree` from a single `u64` seed.
///
/// The seed is expanded to a 32-byte ChaCha key by repeating its little-endian
/// bytes 4 times. This makes tests reproducible — the same `seed` always
/// produces the same plan and the same shrink sequence — while still providing
/// enough entropy for proptest's internal generation.
fn generate_plan(seed: u64) -> (MutationPlanValueTree, MutationPlan) {
    let config = Config::default();
    let mut runner = TestRunner::new_with_rng(
        config,
        proptest::test_runner::TestRng::from_seed(
            proptest::test_runner::RngAlgorithm::ChaCha,
            &seed.to_le_bytes().repeat(4)[..32],
        ),
    );
    let tree = arb_plan().new_tree(&mut runner).unwrap();
    let initial = tree.current();
    (tree, initial)
}

/// Shrinking never increases op count when the predicate accepts any non-empty
/// plan.
///
/// Uses the predicate "has at least 1 op" and verifies that the shrunk plan
/// has fewer (or equal) ops than the initial. This tests that phases 0 and 1
/// monotonically reduce the op list.
#[test]
fn shrinker_reduces_ops_while_reproducing() {
    // Try several seeds to find one that generates a plan with ops.
    for seed in 0..50u64 {
        let (mut tree, initial) = generate_plan(seed);
        if initial.ops.is_empty() {
            continue;
        }

        let initial_count = initial.ops.len();
        let last_valid = shrink_while(&mut tree, |p| !p.ops.is_empty());

        // The shrunk plan should have fewer or equal ops.
        assert!(
            last_valid.ops.len() <= initial_count,
            "seed {seed}: shrunk plan has more ops ({}) than initial ({initial_count})",
            last_valid.ops.len(),
        );
        return; // One successful seed is enough.
    }
    panic!("no seed produced a plan with ops");
}

/// Determinism: the same seed produces byte-identical shrink sequences across
/// independent runs.
///
/// This is critical for reproducibility — a failing seed recorded in CI must
/// replay the exact same counterexample months later. The test collects the
/// first 20 `simplify()` outputs from two independently constructed trees and
/// asserts they are equal.
#[test]
fn shrinker_output_stable_across_runs() {
    let seed = 12345u64;
    let collect_sequence = || {
        let (mut tree, _) = generate_plan(seed);
        let mut sequence = vec![tree.current()];
        for _ in 0..20 {
            if !tree.simplify() {
                break;
            }
            sequence.push(tree.current());
        }
        sequence
    };

    let a = collect_sequence();
    let b = collect_sequence();
    assert_eq!(a, b, "shrink sequences differ across runs");
}

// Generation validity: every plan produced by `arb_plan()` must satisfy the
// family's op constraints and survive execution without panicking.
proptest! {
    #![proptest_config(Config::with_cases(200))]

    #[test]
    fn no_invalid_plans_during_generation(plan in arb_plan()) {
        prop_assert!(
            is_valid_plan(&plan),
            "generated plan has ops not in family's allowed_ops: {plan:?}",
        );

        let case = scanner_scheduler::sim::mutation::execute_plan(&plan);
        let w = &case.wrapped;

        // Bounds safety: the offset window must fit within the buffer.
        prop_assert!(
            w.token_offset + w.token_len <= w.bytes.len(),
            "offset ({}) + len ({}) exceeds buffer ({})",
            w.token_offset,
            w.token_len,
            w.bytes.len(),
        );

        // Content identity: the windowed bytes must equal the mutated token.
        prop_assert_eq!(
            &w.bytes[w.token_offset..w.token_offset + w.token_len],
            case.mutated.as_slice(),
            "wrapped token bytes do not match mutated bytes",
        );
    }
}

/// Every candidate produced during an unrestricted `simplify()` walk satisfies
/// [`is_valid_plan`].
///
/// This is the shrinker's central safety property: no matter what phase or
/// binary search path is taken, the emitted plan always respects the family's
/// allowed-ops constraint. Tested across 20 seeds with a 500-step safety bound
/// per seed.
#[test]
fn all_shrink_candidates_valid() {
    for seed in 0..20u64 {
        let (mut tree, initial) = generate_plan(seed);
        assert!(
            is_valid_plan(&initial),
            "seed {seed}: initial plan is invalid",
        );

        let mut steps = 0;
        while tree.simplify() {
            let candidate = tree.current();
            assert!(
                is_valid_plan(&candidate),
                "seed {seed}, step {steps}: shrink candidate is invalid: {candidate:?}",
            );
            steps += 1;
            if steps > 500 {
                break; // Safety bound.
            }
        }
    }
}

/// A multi-op plan shrinks to at most 2 ops while preserving a `Truncate` op.
///
/// Uses the predicate "plan contains a Truncate op" on plans with >= 3 ops.
/// After exhaustive shrinking, the surviving plan should have at most 2 ops
/// (ideally just the single Truncate), demonstrating that phases 0 and 1
/// effectively strip away unrelated ops.
#[test]
fn complex_plan_shrinks_to_minimal() {
    // Predicate: plan contains a Truncate op.
    let has_truncate = |plan: &MutationPlan| {
        plan.ops
            .iter()
            .any(|op: &MutOp| op.kind() == MutOpKind::Truncate)
    };

    for seed in 0..100u64 {
        let (mut tree, initial) = generate_plan(seed);
        if !has_truncate(&initial) || initial.ops.len() < 3 {
            continue;
        }

        let last_valid = shrink_while(&mut tree, |p| has_truncate(p));

        assert!(
            last_valid.ops.len() <= 2,
            "seed {seed}: expected ≤2 ops after shrinking, got {}",
            last_valid.ops.len(),
        );
        assert!(has_truncate(&last_valid));
        return;
    }
    panic!("no seed produced a multi-op plan with Truncate");
}

/// Unrestricted simplification drives context to `Raw` (ordinal 0).
///
/// Phase 3 of the shrinker decrements the context ordinal until it reaches 0.
/// When no predicate rejects the smaller context, the final plan must have
/// `ContextWrap::Raw`. This confirms that phase 3 is reachable and correctly
/// walks the ordinal down.
#[test]
fn context_shrinks_toward_raw() {
    for seed in 0..50u64 {
        let (mut tree, initial) = generate_plan(seed);
        if initial.context == ContextWrap::Raw {
            continue;
        }

        // Exhaust all simplify steps.
        let mut steps = 0;
        while tree.simplify() {
            steps += 1;
            if steps > 500 {
                break;
            }
        }

        let final_plan = tree.current();
        assert_eq!(
            final_plan.context,
            ContextWrap::Raw,
            "seed {seed}: context did not shrink to Raw (got {:?})",
            final_plan.context,
        );
        return;
    }
    panic!("no seed produced a plan with non-Raw context");
}

/// CharsetViolate with empty positions should still shrink the replacement byte
/// toward 0 during unrestricted shrinking.
///
/// When `positions` is empty, `extract_fields` emits only one field (the
/// replacement byte). `apply_param_shrinks` must recognize this and use
/// `fields[0]` for the replacement — not treat it as the positions count.
#[test]
fn charset_violate_empty_positions_shrinks_replacement() {
    let plan = MutationPlan {
        family: TokenFamily::AwsAccessKey,
        base_seed: 42,
        case_id: 0,
        ops: vec![MutOp::CharsetViolate {
            positions: vec![],
            replacement: 200,
        }],
        context: ContextWrap::Raw,
    };

    let mut tree = MutationPlanValueTree::new(plan);
    let result = shrink_while(&mut tree, |p| {
        p.ops
            .iter()
            .any(|op| matches!(op, MutOp::CharsetViolate { .. }))
    });

    let replacement = match &result.ops[0] {
        MutOp::CharsetViolate { replacement, .. } => *replacement,
        other => panic!("expected CharsetViolate, got {other:?}"),
    };
    assert_eq!(
        replacement, 0,
        "replacement byte should shrink to 0 when positions is empty, got {replacement}"
    );
}

/// Parameter binary search should converge to the minimum value satisfying
/// the predicate, not stall at ~half the original.
///
/// With a `Truncate { len: 100 }` op and predicate "len >= 1", the shrinker
/// must converge to exactly len=1 (the minimum satisfying value). If the binary
/// search uses the wrong field reference, it converges to ~51 instead.
#[test]
fn param_shrink_converges_to_minimum_satisfying_value() {
    let plan = MutationPlan {
        family: TokenFamily::AwsAccessKey,
        base_seed: 42,
        case_id: 0,
        ops: vec![MutOp::Truncate { len: 100 }],
        context: ContextWrap::Raw,
    };

    let mut tree = MutationPlanValueTree::new(plan);
    let result = shrink_while(&mut tree, |p| {
        p.ops
            .iter()
            .any(|op| matches!(op, MutOp::Truncate { len } if *len >= 1))
    });

    let len = match &result.ops[0] {
        MutOp::Truncate { len } => *len,
        other => panic!("expected Truncate, got {other:?}"),
    };
    assert_eq!(
        len, 1,
        "Truncate.len should shrink to exactly 1 (minimum satisfying len >= 1), but got {len}"
    );
}

/// Phase 2 parameter shrinking drives `Truncate { len }` to 0 when the
/// predicate requires a Truncate op but places no constraint on `len`.
///
/// The "has Truncate" predicate prevents phases 0 and 1 from removing the
/// op entirely, forcing the shrinker into phase 2 where it binary-searches
/// `len` toward 0. This confirms that phase 2 fully exhausts its search
/// space and doesn't stall at a non-zero midpoint.
#[test]
fn param_shrink_drives_truncate_len_to_zero() {
    let plan = MutationPlan {
        family: TokenFamily::AwsAccessKey,
        base_seed: 42,
        case_id: 0,
        ops: vec![MutOp::Truncate { len: 50 }],
        context: ContextWrap::Raw,
    };

    let mut tree = MutationPlanValueTree::new(plan);
    let result = shrink_while(&mut tree, |p| {
        p.ops.iter().any(|op| op.kind() == MutOpKind::Truncate)
    });

    let len = match &result.ops[0] {
        MutOp::Truncate { len } => *len,
        other => panic!("expected Truncate, got {other:?}"),
    };
    assert_eq!(
        len, 0,
        "Truncate.len should shrink to 0 with unconstrained predicate, got {len}"
    );
}

/// Edge case: an empty-ops plan with non-Raw context does not panic during
/// interleaved `simplify()` / `complicate()` cycles.
///
/// When ops are empty, phases 0--2 have nothing to do and must gracefully
/// skip to phase 3 (context shrinking). The interleaved complicate calls
/// exercise the undo path on the context ordinal. The final plan should have
/// `ContextWrap::Raw` and an empty ops list.
#[test]
fn empty_ops_plan_shrink_does_not_panic() {
    let plan = MutationPlan {
        family: TokenFamily::AwsAccessKey,
        base_seed: 42,
        case_id: 0,
        ops: vec![],
        context: ContextWrap::MultiLineString,
    };

    let mut tree = MutationPlanValueTree::new(plan);

    // Drive through all phases — should not panic.
    let mut steps = 0;
    while tree.simplify() {
        tree.complicate();
        tree.simplify();
        steps += 1;
        if steps > 100 {
            break;
        }
    }

    // Final context should be Raw (the only thing to shrink).
    let final_plan = tree.current();
    assert_eq!(final_plan.context, ContextWrap::Raw);
    assert!(final_plan.ops.is_empty());
}
