//! Domain-separated hashing helpers for content-addressed ID derivation.
//!
//! Every ID derivation in the system flows through [`domain_hasher`] and
//! [`finalize_32`]. Together they provide a two-step pattern:
//!
//! ```
//! use gossip_contracts::identity::{domain_hasher, finalize_32, CanonicalBytes};
//!
//! let mut h = domain_hasher(b"gossip/example/v1");
//! 42u64.write_canonical(&mut h);
//! let id: [u8; 32] = finalize_32(&h);
//! ```
//!
//! # Domain separation guarantee
//!
//! [`domain_hasher`] uses BLAKE3's derive-key mode ([`blake3::Hasher::new_derive_key`]),
//! which produces a context-dependent key schedule. Two hashers with different
//! domain tags can **never** produce colliding output, regardless of payload —
//! this is a cryptographic guarantee, not merely a statistical one.
//!
//! # Context string requirements
//!
//! Domain context bytes must be valid UTF-8 (required by BLAKE3's derive-key
//! API). All domain constants in this crate are ASCII `b"gossip/…/vN"` literals,
//! so this is always satisfied. Invalid UTF-8 causes a panic at construction
//! time — this is a programmer error, not a runtime condition.

use blake3::Hasher;

/// Create a BLAKE3 hasher initialized with a domain separation context.
///
/// Uses BLAKE3's derive-key mode to guarantee that distinct domain tags
/// produce cryptographically independent hash functions.
///
/// Accepts `&[u8]` rather than `&str` so callers can pass byte-string
/// literals (`b"gossip/…/vN"`) directly — the UTF-8 check is deferred to
/// runtime since all domain constants in practice are ASCII.
///
/// # Panics
///
/// Panics if `context` is not valid UTF-8.
#[inline]
pub fn domain_hasher(context: &[u8]) -> Hasher {
    Hasher::new_derive_key(core::str::from_utf8(context).expect("domain tag must be valid UTF-8"))
}

/// Finalize a hasher into a 32-byte (256-bit) digest.
///
/// This is the common tail of every content-addressed derivation in the
/// system. The `_32` suffix encodes the output width; if a different
/// digest size is ever needed, it will be a separate function.
#[inline]
pub fn finalize_32(hasher: &Hasher) -> [u8; 32] {
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::CanonicalBytes;
    use proptest::prelude::*;

    // ---------------------------------------------------------------
    // Panic on invalid UTF-8
    // ---------------------------------------------------------------

    #[test]
    #[should_panic(expected = "domain tag must be valid UTF-8")]
    fn rejects_invalid_utf8_context() {
        let _ = domain_hasher(&[0xFF, 0xFE]);
    }

    // ---------------------------------------------------------------
    // Property-based: determinism across random payloads
    // ---------------------------------------------------------------

    proptest! {
        #[test]
        fn deterministic_for_random_payload(data in proptest::collection::vec(any::<u8>(), 0..512)) {
            let domain = b"gossip/prop/v1";

            let mut h1 = domain_hasher(domain);
            data.as_slice().write_canonical(&mut h1);
            let d1 = finalize_32(&h1);

            let mut h2 = domain_hasher(domain);
            data.as_slice().write_canonical(&mut h2);
            let d2 = finalize_32(&h2);

            prop_assert_eq!(d1, d2);
        }

        #[test]
        fn domain_separation_for_random_payload(data in proptest::collection::vec(any::<u8>(), 1..256)) {
            let mut h1 = domain_hasher(b"gossip/left/v1");
            data.as_slice().write_canonical(&mut h1);
            let d1 = finalize_32(&h1);

            let mut h2 = domain_hasher(b"gossip/right/v1");
            data.as_slice().write_canonical(&mut h2);
            let d2 = finalize_32(&h2);

            prop_assert_ne!(d1, d2);
        }
    }
}
