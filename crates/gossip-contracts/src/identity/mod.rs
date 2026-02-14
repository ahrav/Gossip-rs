//! Content-addressed identity types, canonical encoding, and domain-separated hashing.
//!
//! This module owns all content-addressed identities used across the scanner
//! (`TenantId`, `SecretHash`, `FindingId`, `OccurrenceId`, …) and the shared
//! encoding infrastructure they depend on: the `CanonicalBytes` trait for
//! deterministic serialisation, `domain_hasher` / `finalize_32` helpers for
//! BLAKE3 domain-separated hashing, the `define_id_32!` / `define_id_32_restricted!`
//! newtype macros, and the authoritative domain-constant registry.
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
