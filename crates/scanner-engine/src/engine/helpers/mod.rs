//! Helper routines for window merging, entropy gating, UTF-16 decode, and hashing.
//!
//! # Invariants
//! - Window merge helpers expect input ranges sorted by `start` and normalized
//!   (`start <= end`).
//! - Prefilter helpers must be conservative: they may allow false positives but
//!   must not drop candidates that could satisfy full rule validation.
//!
//! # Design Notes
//! - Window merging widens spans to trade small extra scanning for fewer passes.
//! - Entropy gating is conservative: short samples always pass.
//! - UTF-16 decoding uses replacement characters and enforces output limits.
//!   (ASCII-only UTF-16 *anchor expansion* lives in [`rule_repr`](super::rule_repr),
//!   not here; this module provides general UTF-16 -> UTF-8 decode.)

mod confirm;
mod encoding;
mod entropy;
mod extraction;
mod hash;
mod window;

pub(super) use confirm::*;
pub(super) use encoding::*;
pub(super) use entropy::*;
pub(super) use extraction::*;
pub(super) use hash::*;
pub(super) use window::*;
