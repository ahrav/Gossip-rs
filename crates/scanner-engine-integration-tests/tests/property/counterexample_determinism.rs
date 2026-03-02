//! Determinism and structural invariant property tests for the mutation framework.
//!
//! The mutation testing pipeline (`execute_plan`) turns a serializable
//! [`MutationPlan`] into a fully materialized [`GeneratedCase`] through four
//! stages: generate a canonical token, apply mutation operators left-to-right,
//! predict the detection outcome, and embed the result in surrounding context
//! bytes. For this pipeline to be useful as a test oracle, three structural
//! properties must hold universally:
//!
//! - **Determinism (P3)** — identical plans always produce byte-identical
//!   output. This is the foundation that makes shrink-sequence
//!   reproducibility possible and enables future corpus serialization and
//!   CI replay (the plan derives `Serialize`/`Deserialize` for this
//!   purpose). If `execute_plan` were non-deterministic, a failing seed
//!   recorded today could not be reproduced tomorrow.
//!
//! - **Non-commutativity (P4)** — operator ordering is semantically
//!   significant. `Truncate`-then-`Extend` must differ from
//!   `Extend`-then-`Truncate`. This confirms that `apply_ops` composes
//!   operators as a strict left-to-right pipeline rather than treating them
//!   as a commutative set, which would collapse distinct mutation scenarios
//!   into identical outputs.
//!
//! - **Offset correctness (P6)** — the [`WrappedToken`] offset metadata
//!   correctly locates the mutated token within its surrounding context
//!   bytes. The test harness relies on these offsets to verify that the
//!   mutated token can be recovered from context (JSON field, env
//!   assignment, etc.); if they are wrong, every downstream assertion on
//!   detection behavior is meaningless.
//!
//! Each property is tested with 500 proptest cases using strategies from
//! [`super::proptest_support`] that generate arbitrary families, seeds, ops,
//! and context wrappers. The custom [`MutationPlanValueTree`] shrinker (tested
//! separately in [`super::counterexample_shrinker`]) ensures that any
//! counterexample found here is minimized structurally before being reported.
//!
//! [`MutationPlan`]: scanner_scheduler::sim::mutation::MutationPlan
//! [`GeneratedCase`]: scanner_scheduler::sim::mutation::GeneratedCase
//! [`WrappedToken`]: scanner_scheduler::sim::mutation::WrappedToken
//! [`MutationPlanValueTree`]: super::proptest_support::MutationPlanValueTree

use proptest::prelude::*;

use scanner_scheduler::sim::SimRng;
use scanner_scheduler::sim::mutation::{ContextWrap, MutOp, apply_ops, execute_plan};

use super::proptest_support::{arb_family, arb_plan};

// Determinism: executing the same plan twice must produce byte-identical
// results across all four pipeline outputs (canonical token, mutated bytes,
// wrapped buffer, and predicted outcome). We clone the plan to ensure the
// two calls receive structurally equal but independently owned inputs,
// ruling out aliasing as a source of accidental equality.
//
// This property underpins corpus storage (plans are designed to be serialized
// to JSON and replayed later) and shrink reproducibility (the test runner
// re-executes plans many times during minimization). A violation here would
// make every other property test in this module unreliable.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn same_seed_same_plan_same_bytes(plan in arb_plan()) {
        let a = execute_plan(&plan);
        let b = execute_plan(&plan.clone());

        prop_assert_eq!(&a.canonical, &b.canonical, "canonical bytes differ");
        prop_assert_eq!(&a.mutated, &b.mutated, "mutated bytes differ");
        prop_assert_eq!(&a.wrapped.bytes, &b.wrapped.bytes, "wrapped bytes differ");
        prop_assert_eq!(a.expectation, b.expectation, "expectation differs");
    }
}

// Non-commutativity: reversing the order of two ops must produce different
// output, proving that `apply_ops` is a true left-to-right pipeline.
//
// The test constructs two orderings of the same (Truncate, Extend) pair and
// asserts that they diverge. The arithmetic guarantees divergence for any
// non-empty canonical token of length N:
//
//   Truncate(max(N/2,1)) then Extend(1 byte) => max(N/2,1) + 1 output bytes
//   Extend(1 byte) then Truncate(max(N/2,1)) => max(N/2,1) output bytes
//
// The `.max(1)` guard is defensive: current families always generate tokens
// of at least 20 bytes, but if a future family produced a 1-byte token
// (N=1 => N/2 = 0), a trunc_len of 0 would still produce divergent outputs
// (1 byte vs 0 bytes). The guard keeps both orderings non-empty, making the
// divergence more obvious and robust against edge cases.
//
// The output lengths alone differ, so the byte sequences must differ. We
// generate the canonical token from an arbitrary family + seed rather than
// using a fixed input to exercise the full range of token lengths (20--96
// bytes depending on family).
//
// Why this matters: if the pipeline accidentally treated ops as commutative
// (e.g. by sorting them), distinct mutation scenarios would collapse into
// the same output and the expectation oracle would produce wrong predictions.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn op_order_is_semantically_significant(
        family in arb_family(),
        seed in any::<u64>(),
        suffix_byte in any::<u8>(),
    ) {
        let canonical = family.gen_valid(&mut SimRng::new(seed));
        let trunc_len = (canonical.len() / 2).max(1);

        let ops_ab = vec![
            MutOp::Truncate { len: trunc_len },
            MutOp::Extend { suffix: vec![suffix_byte] },
        ];
        let ops_ba = vec![
            MutOp::Extend { suffix: vec![suffix_byte] },
            MutOp::Truncate { len: trunc_len },
        ];

        let result_ab = apply_ops(&canonical, &ops_ab);
        let result_ba = apply_ops(&canonical, &ops_ba);

        prop_assert_ne!(
            result_ab.bytes,
            result_ba.bytes,
            "family={:?} seed={}: Truncate-then-Extend should differ from Extend-then-Truncate",
            family,
            seed,
        );
    }
}

// Offset correctness: the WrappedToken metadata must accurately locate the
// mutated token within its surrounding context buffer. The test harness uses
// these offsets to extract candidate tokens from lines that contain context
// bytes (e.g. `{"token":"<secret>"}`); if the offset or length is wrong,
// the harness would extract incorrect bytes and every downstream detection
// assertion would be meaningless.
//
// Three sub-invariants are checked independently:
//
// 1. Bounds safety — the (offset, len) window must not exceed the buffer.
//    A violation here would cause an out-of-bounds slice in production.
//
// 2. Content identity — the bytes at the recorded window must be exactly
//    the mutated token bytes from the pipeline. This catches off-by-one
//    errors in ContextWrap::wrap's prefix-length calculation.
//
// 3. Raw passthrough — when context is `Raw`, there is no prefix or suffix,
//    so the token must start at offset 0. This catches bugs where `Raw`
//    accidentally inserts empty wrapper bytes.
proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn wrapped_token_at_correct_offset(plan in arb_plan()) {
        let case = execute_plan(&plan);
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

        // Raw passthrough: no context wrapper means offset must be zero.
        if plan.context == ContextWrap::Raw {
            prop_assert_eq!(
                w.token_offset, 0,
                "Raw context should have token_offset == 0",
            );
        }
    }
}
