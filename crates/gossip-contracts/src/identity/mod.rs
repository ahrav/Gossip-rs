//! Content-addressed identity types, canonical encoding, and domain-separated hashing.
//!
//! **Dependency direction:** This is the leaf of the boundary graph — no other
//! boundary module may be referenced here. All four sibling modules depend on
//! `identity`.
//!
//! For the full architecture design, see `docs/boundary-1-identity-spine.md`.
//!
//! **Key invariants:**
//! - Collision-freedom — distinct values produce distinct canonical byte
//!   sequences (variable-length fields are length-prefixed).
//! - Determinism — encodings are identical across platforms and Rust versions
//!   (fixed-endian, little-endian by convention).
//! - Domain-tag uniqueness — every domain constant in the registry is globally
//!   unique, enforced by a meta-test.

mod canonical;
mod coordination;
pub mod domain;
mod finding;
pub mod hashing;
mod item;
mod macros;
mod policy;
mod types;

#[cfg(test)]
mod golden;

pub use canonical::CanonicalBytes;
pub use coordination::{FenceEpoch, JobId, LogicalTime, OpId, RunId, ShardId, ShardKey, WorkerId};
pub use finding::{
    FindingId, FindingIdInputs, NormHash, OccurrenceId, OccurrenceIdInputs, RuleFingerprint,
    SecretHash, derive_finding_id, derive_occurrence_id, key_secret_hash,
};
pub use hashing::{domain_hasher, finalize_32, finalize_64};
pub use item::{ConnectorTag, IdentityInputError, ItemIdentityKey, ObjectVersionId, StableItemId};
pub use policy::{
    CURRENT_EVIDENCE_VERSION, CURRENT_VERSION, IdHashMode, PolicyHashInputs, compute_policy_hash,
};
pub use types::{PolicyHash, TenantId, TenantSecretKey};
