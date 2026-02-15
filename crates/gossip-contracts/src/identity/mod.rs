//! Content-addressed identity types, canonical encoding, and domain-separated hashing.
//!
//! **Dependency direction:** This is the leaf of the boundary graph — no other
//! boundary module may be referenced here. All four sibling modules depend on
//! `identity`.
//!
//! **Key invariants:**
//! - Collision-freedom — distinct values produce distinct canonical byte
//!   sequences (variable-length fields are length-prefixed).
//! - Determinism — encodings are identical across platforms and Rust versions
//!   (fixed-endian, little-endian by convention).
//! - Domain-tag uniqueness — every domain constant in the registry is globally
//!   unique, enforced by a meta-test.

mod canonical;
pub mod domain;
mod hashing;
mod item;
mod macros;
mod types;

pub use canonical::CanonicalBytes;
pub use hashing::{domain_hasher, finalize_32};
pub use item::{ConnectorTag, ItemKey, ObjectVersionId, StableItemId};
pub use types::{PolicyHash, TenantId, TenantSecretKey};
