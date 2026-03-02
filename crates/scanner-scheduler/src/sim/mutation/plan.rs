//! Mutation plan execution and context wrapping.
//!
//! A [`MutationPlan`] is the fully specified recipe for a single counterexample
//! test case. It names a token family, a deterministic seed, an ordered list of
//! mutation operators, and a surrounding-context wrapper. [`execute_plan`]
//! materializes it through a four-stage pipeline:
//!
//! 1. **Generate** -- produce a valid canonical token from the family + seed.
//! 2. **Mutate** -- apply operators left-to-right to perturb the token.
//! 3. **Predict** -- query the family's oracle for the expected detection
//!    outcome (`MustMatch`, `MustNotMatch`, or `MayMatch`).
//! 4. **Wrap** -- embed the mutated token in surrounding context bytes (JSON
//!    field, env assignment, etc.) and record the token's offset within them.
//!
//! The output [`GeneratedCase`] carries every intermediate artifact so that
//! test harnesses can assert on the canonical token, the mutated form, the
//! final wrapped bytes, and the predicted outcome.

use serde::{Deserialize, Serialize};

use super::family::{Outcome, TokenFamily};
use super::op::{apply_ops, MutOp};
use crate::sim::rng::SimRng;

/// Surrounding context in which a mutated token is embedded.
///
/// Detection engines often behave differently depending on what surrounds a
/// candidate token (e.g. a JSON string value vs. a bare line). These wrappers
/// exercise different context-sensitivity code paths without changing the token
/// bytes themselves.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContextWrap {
    /// No wrapping -- the token bytes are the entire input.
    Raw,
    /// Shell-style environment assignment: `SECRET_KEY=<token>\n`.
    EnvAssignment,
    /// JSON object with a string field: `{"token":"<token>"}`.
    JsonField,
    /// YAML key-value: `token: <token>\n`.
    YamlValue,
    /// C-style single-line comment: `// <token>\n`.
    SingleLineComment,
    /// Python-style triple-quoted string: `"""\n<token>\n"""`.
    MultiLineString,
}

/// A token embedded within surrounding context bytes.
///
/// **Invariant:** `bytes[token_offset .. token_offset + token_len]` always
/// exactly recovers the original (possibly mutated) token bytes that were
/// passed to [`ContextWrap::wrap`].
#[derive(Clone, Debug)]
pub struct WrappedToken {
    /// The full byte buffer including context prefix, token, and suffix.
    pub bytes: Vec<u8>,
    /// Byte offset where the token begins within `bytes`.
    pub token_offset: usize,
    /// Length of the token in bytes.
    pub token_len: usize,
}

impl ContextWrap {
    /// All context wrappers, for exhaustive iteration in tests.
    pub const ALL: [ContextWrap; 6] = [
        ContextWrap::Raw,
        ContextWrap::EnvAssignment,
        ContextWrap::JsonField,
        ContextWrap::YamlValue,
        ContextWrap::SingleLineComment,
        ContextWrap::MultiLineString,
    ];
}

impl WrappedToken {
    /// The embedded token bytes (slice into `bytes` at the recorded offset).
    pub fn token(&self) -> &[u8] {
        &self.bytes[self.token_offset..self.token_offset + self.token_len]
    }

    /// The full buffer including context prefix, token, and suffix.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Byte offset where the token begins within the full buffer.
    pub fn token_offset(&self) -> usize {
        self.token_offset
    }

    /// Length of the embedded token in bytes.
    pub fn token_len(&self) -> usize {
        self.token_len
    }
}

/// A complete mutation test plan -- the serializable recipe for one test case.
///
/// Plans are designed to be generated in bulk (e.g. by a fuzzer or a property
/// test), serialized to JSON for corpus storage, and replayed deterministically
/// via [`execute_plan`]. The `base_seed` and `family` together fully determine
/// the canonical token; `ops` and `context` determine the mutation and wrapping.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MutationPlan {
    /// Which secret format archetype to generate.
    pub family: TokenFamily,
    /// Seed for the deterministic RNG that produces the canonical token.
    pub base_seed: u64,
    /// Unique identifier for this case within a test run (informational only).
    pub case_id: u64,
    /// Ordered list of mutation operators applied left-to-right.
    pub ops: Vec<MutOp>,
    /// Surrounding-context wrapper applied after mutation.
    pub context: ContextWrap,
}

/// A fully materialized test case produced by [`execute_plan`].
///
/// Retains every intermediate artifact so that test assertions can inspect
/// the canonical token, the mutated form, and the final wrapped output
/// independently.
#[derive(Clone, Debug)]
pub struct GeneratedCase {
    /// Raw valid token bytes (pre-mutation).
    pub canonical: Vec<u8>,
    /// Token bytes after mutation (pre-wrap).
    pub mutated: Vec<u8>,
    /// Context-wrapped output with offset metadata.
    pub wrapped: WrappedToken,
    /// Expected detection result.
    pub expectation: Outcome,
    /// The input plan (cloned).
    pub plan: MutationPlan,
}

impl ContextWrap {
    /// Embed `token` in surrounding context bytes.
    ///
    /// Returns a [`WrappedToken`] whose `token_offset` and `token_len` fields
    /// locate the token within the output buffer. The token bytes are copied
    /// verbatim -- no escaping or encoding is applied, even for wrappers like
    /// `JsonField` where real-world usage would require escaping. This is
    /// intentional: the test exercises the engine's raw byte scanning, not
    /// JSON-aware parsing.
    pub fn wrap(self, token: &[u8]) -> WrappedToken {
        match self {
            ContextWrap::Raw => WrappedToken {
                bytes: token.to_vec(),
                token_offset: 0,
                token_len: token.len(),
            },
            ContextWrap::EnvAssignment => wrap_with(b"SECRET_KEY=", token, b"\n"),
            ContextWrap::JsonField => wrap_with(br#"{"token":""#, token, br#""}"#),
            ContextWrap::YamlValue => wrap_with(b"token: ", token, b"\n"),
            ContextWrap::SingleLineComment => wrap_with(b"// ", token, b"\n"),
            ContextWrap::MultiLineString => wrap_with(b"\"\"\"\n", token, b"\n\"\"\""),
        }
    }
}

/// Assemble a [`WrappedToken`] from prefix + token + suffix, recording the
/// token's byte offset within the combined buffer.
fn wrap_with(prefix: &[u8], token: &[u8], suffix: &[u8]) -> WrappedToken {
    let mut bytes = Vec::with_capacity(prefix.len() + token.len() + suffix.len());
    bytes.extend_from_slice(prefix);
    let offset = bytes.len();
    bytes.extend_from_slice(token);
    bytes.extend_from_slice(suffix);
    WrappedToken {
        bytes,
        token_offset: offset,
        token_len: token.len(),
    }
}

/// Execute a mutation plan through the generate-mutate-predict-wrap pipeline.
///
/// The function is **pure and deterministic**: the same `plan` always produces
/// byte-identical output. This property is what makes corpus replay work --
/// a serialized plan can be re-executed months later and still produce the
/// exact same test case.
///
/// When the mutation pipeline halts early due to [`MAX_OUTPUT_BYTES`], only
/// the operators that actually ran are passed to the expectation oracle. This
/// prevents the oracle from predicting based on operators that never executed.
///
/// [`MAX_OUTPUT_BYTES`]: super::op::MAX_OUTPUT_BYTES
pub fn execute_plan(plan: &MutationPlan) -> GeneratedCase {
    let mut rng = SimRng::new(plan.base_seed);
    let canonical = plan.family.gen_valid(&mut rng);
    let result = apply_ops(&canonical, &plan.ops);
    let applied_ops = &plan.ops[..result.ops_applied];
    let expectation = plan.family.expectation(&canonical, applied_ops);
    let wrapped = plan.context.wrap(&result.bytes);
    GeneratedCase {
        canonical,
        mutated: result.bytes,
        wrapped,
        expectation,
        plan: plan.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_wrap_preserves_token_at_offset() {
        let token = b"my_secret_token";
        for ctx in ContextWrap::ALL {
            let wrapped = ctx.wrap(token);
            assert_eq!(
                wrapped.token(),
                token,
                "context {ctx:?} broke offset invariant"
            );
        }
    }

    #[test]
    fn serde_roundtrip_outcome() {
        for outcome in [Outcome::MustMatch, Outcome::MustNotMatch, Outcome::MayMatch] {
            let json = serde_json::to_string(&outcome).unwrap();
            let de: Outcome = serde_json::from_str(&json).unwrap();
            assert_eq!(de, outcome);
        }
    }

    #[test]
    fn serde_roundtrip_context_wrap() {
        for ctx in ContextWrap::ALL {
            let json = serde_json::to_string(&ctx).unwrap();
            let de: ContextWrap = serde_json::from_str(&json).unwrap();
            assert_eq!(de, ctx);
        }
    }

    #[test]
    fn serde_roundtrip_mutation_plan() {
        use super::super::op::MutOp;
        let plan = MutationPlan {
            family: TokenFamily::AwsAccessKey,
            base_seed: 42,
            case_id: 1,
            ops: vec![MutOp::Truncate { len: 10 }],
            context: ContextWrap::JsonField,
        };
        let json = serde_json::to_string(&plan).unwrap();
        let de: MutationPlan = serde_json::from_str(&json).unwrap();
        assert_eq!(de.family, plan.family);
        assert_eq!(de.base_seed, plan.base_seed);
        assert_eq!(de.case_id, plan.case_id);
        assert_eq!(de.ops, plan.ops);
        assert_eq!(de.context, plan.context);
    }

    // -- execute_plan tests --

    #[test]
    fn execute_plan_determinism() {
        let plan = MutationPlan {
            family: TokenFamily::AwsAccessKey,
            base_seed: 42,
            case_id: 1,
            ops: vec![MutOp::Truncate { len: 10 }],
            context: ContextWrap::JsonField,
        };
        let a = execute_plan(&plan);
        let b = execute_plan(&plan);
        assert_eq!(a.canonical, b.canonical);
        assert_eq!(a.mutated, b.mutated);
        assert_eq!(a.wrapped.bytes, b.wrapped.bytes);
        assert_eq!(a.expectation, b.expectation);
    }

    #[test]
    fn execute_plan_no_ops_identity() {
        let plan = MutationPlan {
            family: TokenFamily::AwsAccessKey,
            base_seed: 7,
            case_id: 2,
            ops: vec![],
            context: ContextWrap::Raw,
        };
        let case = execute_plan(&plan);
        assert_eq!(case.canonical, case.mutated);
        assert_eq!(case.expectation, Outcome::MustMatch);
    }

    #[test]
    fn execute_plan_prefix_mangle_wiring() {
        let plan = MutationPlan {
            family: TokenFamily::AwsAccessKey,
            base_seed: 99,
            case_id: 3,
            ops: vec![MutOp::PrefixMangle {
                replacement: b"XXXX".to_vec(),
            }],
            context: ContextWrap::EnvAssignment,
        };
        let case = execute_plan(&plan);
        assert_ne!(case.mutated, case.canonical);
        assert_eq!(case.expectation, Outcome::MustNotMatch);
        // Verify wrapped token offset is correct.
        let extracted = &case.wrapped.bytes
            [case.wrapped.token_offset..case.wrapped.token_offset + case.wrapped.token_len];
        assert_eq!(extracted, &case.mutated);
    }

    #[test]
    fn execute_plan_truncated_pipeline_uses_applied_ops() {
        // Build a plan whose pipeline will hit MAX_OUTPUT_BYTES, then verify
        // the expectation oracle only sees the ops that actually ran.
        let plan = MutationPlan {
            family: TokenFamily::Base64Blob,
            base_seed: 1,
            case_id: 4,
            ops: {
                let mut ops: Vec<MutOp> = (0..30)
                    .map(|_| MutOp::Encode {
                        repr: super::super::encode::SecretRepr::Base64,
                    })
                    .collect();
                // Append a hard-breaker that would produce MustNotMatch if it ran.
                ops.push(MutOp::Truncate { len: 1 });
                ops
            },
            context: ContextWrap::Raw,
        };
        let case = execute_plan(&plan);
        // The pipeline halts on size, so Truncate{1} never runs.
        // The oracle should NOT see MustNotMatch from the truncation.
        assert_ne!(case.expectation, Outcome::MustNotMatch);
    }
}
