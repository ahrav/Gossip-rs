//! Shared deterministic mutation framework for counterexample generation.
//!
//! Provides encoding functions, token family definitions, mutation operators,
//! and plan execution that both property tests and sim-harness tests consume.

pub mod adapter;
pub mod encode;
pub mod family;
pub mod op;
pub mod plan;
pub mod plan_gen;

pub use adapter::{
    build_mutation_engine, build_mutation_scenario, check_mutation_expectations,
    MutationCheckResult, MutationViolation,
};
pub use encode::{
    base62_encode_u32, base64_encode_std, base64url_encode_nopad, encode_nested, encode_secret,
    encode_utf16, hex_nibble, percent_encode_all, SecretRepr, BASE62_CHARS, BASE64_STD,
    TOKEN_ALPHABET,
};
pub use family::{Outcome, TokenFamily};
pub use op::{apply_ops, ApplyResult, MutOp, MutOpKind};
pub use plan::{execute_plan, ContextWrap, GeneratedCase, MutationPlan, WrappedToken};
pub use plan_gen::{random_mutation_plan, random_mutation_plans_all_families};
