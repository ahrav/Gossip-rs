//! Domain-separated hashing helpers for content-addressed ID derivation.
//!
//! Every ID derivation in the system flows through [`domain_hasher`] and
//! [`finalize_32`]. Together they provide a two-step pattern:
//!
//! ```
//! use gossip_contracts::identity::{domain_hasher, finalize_32, CanonicalBytes};
//!
//! let mut h = domain_hasher(b"gossip/example/v1").expect("domain tag must be valid UTF-8");
//! 42u64.write_canonical(&mut h);
//! let id: [u8; 32] = finalize_32(&h);
//! ```
//!
//! # Domain separation guarantee
//!
//! [`domain_hasher`] uses BLAKE3's derive-key mode ([`blake3::Hasher::new_derive_key`]),
//! which produces a context-dependent key schedule. Two hashers with different
//! domain tags are treated as independent hash functions. Cross-domain
//! collisions remain cryptographically negligible, but not mathematically
//! impossible.
//!
//! # Context string requirements
//!
//! Domain context bytes must be valid UTF-8 (required by BLAKE3's derive-key
//! API). All domain constants in this crate are ASCII `b"gossip/…/vN"` literals,
//! so this is always satisfied. Invalid UTF-8 returns an error instead of
//! panicking, so call sites can decide whether to propagate or assert.

use blake3::Hasher;

/// Create a BLAKE3 hasher initialized with a domain separation context.
///
/// Uses BLAKE3's derive-key mode so distinct domain tags map to
/// cryptographically independent hash domains.
///
/// Accepts `&[u8]` rather than `&str` so callers can pass byte-string
/// literals (`b"gossip/…/vN"`) directly — the UTF-8 check is deferred to
/// runtime since all domain constants in practice are ASCII.
///
/// # Errors
///
/// Returns [`core::str::Utf8Error`] if `context` is not valid UTF-8.
#[inline]
pub fn domain_hasher(context: &[u8]) -> Result<Hasher, core::str::Utf8Error> {
    core::str::from_utf8(context).map(Hasher::new_derive_key)
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

    fn hash_payload(domain: &[u8], payload: &[u8]) -> [u8; 32] {
        let mut hasher = domain_hasher(domain).expect("test domain tags must be valid UTF-8");
        payload.write_canonical(&mut hasher);
        finalize_32(&hasher)
    }

    // ---------------------------------------------------------------
    // Invalid UTF-8 handling
    // ---------------------------------------------------------------

    #[test]
    fn rejects_invalid_utf8_context() {
        let err = domain_hasher(&[0xFF, 0xFE]).expect_err("invalid UTF-8 should error");
        assert_eq!(err.valid_up_to(), 0);
    }

    // ---------------------------------------------------------------
    // Property-based: determinism across random payloads
    // ---------------------------------------------------------------

    proptest! {
        #![proptest_config(crate::test_util::miri_proptest_config())]
        #[test]
        fn deterministic_for_random_payload(data in proptest::collection::vec(any::<u8>(), 0..512)) {
            let domain = b"gossip/prop/v1";

            let d1 = hash_payload(domain, data.as_slice());
            let d2 = hash_payload(domain, data.as_slice());

            prop_assert_eq!(d1, d2);
        }

        #[test]
        fn domain_separation_for_random_payload(data in proptest::collection::vec(any::<u8>(), 1..256)) {
            let d1 = hash_payload(b"gossip/left/v1", data.as_slice());
            let d2 = hash_payload(b"gossip/right/v1", data.as_slice());

            prop_assert_ne!(d1, d2);
        }
    }
}
