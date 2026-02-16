//! Domain-separated hashing helpers for content-addressed ID derivation.
//!
//! Every ID derivation in the system flows through [`domain_hasher`] and
//! one of the finalization functions:
//!
//! - [`finalize_32`] — full 256-bit digest for content-addressed IDs.
//! - [`finalize_64`] — truncated 64-bit digest for coordination IDs
//!   (op-log payload hashes, split shard ID derivation).
//!
//! ```
//! use gossip_contracts::identity::{domain_hasher, finalize_32, CanonicalBytes};
//!
//! let mut h = domain_hasher("gossip/example/v1");
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
//! # Crate-internal fast path
//!
//! For the five domain tags used in identity derivation, pre-initialized
//! hashers are cached in `LazyLock<Hasher>` statics (`FINDING_HASHER`, etc.).
//! [`derive_from_cached`] clones one of these statics instead of re-running
//! the key-schedule setup, making repeated same-domain derivations cheaper.
//! All `derive_*` functions in sibling modules use this path.
//!
//! # Context string requirements
//!
//! Domain constants are `&str`, so UTF-8 validity is enforced at compile time.
//! There is no runtime validation or error path — callers cannot pass invalid
//! context strings through the type system.

use std::sync::LazyLock;

use blake3::Hasher;

use super::domain;

// ---------------------------------------------------------------------------
// Cached derive-key hashers
//
// BLAKE3 derive-key mode performs a key-schedule setup from the context
// string.  Caching the post-setup state in a `LazyLock<Hasher>` lets
// every derivation start from a `clone()` of the fully-initialized
// hasher, avoiding redundant key-schedule computation on each call.
// ---------------------------------------------------------------------------

pub(crate) static FINDING_HASHER: LazyLock<Hasher> =
    LazyLock::new(|| Hasher::new_derive_key(domain::FINDING_ID_V1));

pub(crate) static OCCURRENCE_HASHER: LazyLock<Hasher> =
    LazyLock::new(|| Hasher::new_derive_key(domain::OCCURRENCE_ID_V1));

pub(crate) static ITEM_ID_HASHER: LazyLock<Hasher> =
    LazyLock::new(|| Hasher::new_derive_key(domain::ITEM_ID_V1));

pub(crate) static OBJECT_VERSION_HASHER: LazyLock<Hasher> =
    LazyLock::new(|| Hasher::new_derive_key(domain::OBJECT_VERSION_V1));

pub(crate) static POLICY_HASH_HASHER: LazyLock<Hasher> =
    LazyLock::new(|| Hasher::new_derive_key(domain::POLICY_HASH_V2));

pub(crate) static SPLIT_ID_HASHER: LazyLock<Hasher> =
    LazyLock::new(|| Hasher::new_derive_key(domain::SPLIT_ID_V1));

pub(crate) static OP_PAYLOAD_HASHER: LazyLock<Hasher> =
    LazyLock::new(|| Hasher::new_derive_key(domain::OP_PAYLOAD_V1));

/// Clone a cached hasher, feed canonical input, and finalize to 32 bytes.
///
/// This is the hot-path helper used by every `derive_*` function in the
/// identity module. Cloning a pre-initialized [`Hasher`] is cheaper than
/// calling [`Hasher::new_derive_key`] because the BLAKE3 key-schedule setup
/// (derived from the domain string) has already been computed and stored in
/// the source `LazyLock<Hasher>` static. The clone copies only the
/// post-setup internal state.
///
/// `base` is expected to be one of this module's `LazyLock<Hasher>` statics
/// (e.g., [`FINDING_HASHER`]); deref coercion provides `&Hasher` transparently.
#[inline]
pub(crate) fn derive_from_cached<T: super::CanonicalBytes>(base: &Hasher, inputs: &T) -> [u8; 32] {
    let mut h = base.clone();
    inputs.write_canonical(&mut h);
    finalize_32(&h)
}

/// Create a BLAKE3 hasher initialized with a domain separation context.
///
/// Uses BLAKE3's derive-key mode so distinct domain tags map to
/// cryptographically independent hash domains.
///
/// All domain constants in [`super::domain`] are `&str`, so this function
/// takes `&str` directly — UTF-8 validity is enforced by the type system
/// with no runtime check.
#[inline]
pub fn domain_hasher(context: &str) -> Hasher {
    Hasher::new_derive_key(context)
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

/// Finalize a hasher into a 64-bit (8-byte) digest.
///
/// Takes the first 8 bytes of the BLAKE3 output as a little-endian `u64`.
/// Used for op-log payload hashes and split shard ID derivation.
///
/// # Cardinality bounds
///
/// A 64-bit truncated hash has a birthday collision bound of approximately
/// 2^32 (~4.3 billion) values before a 50% collision probability.  This is
/// acceptable for coordination use cases (shard counts per run, op-log
/// entries per epoch) where cardinality is bounded by system design.  For
/// globally-unique content-addressed identifiers with unbounded cardinality,
/// use [`finalize_32`] instead.
#[inline]
pub fn finalize_64(hasher: &Hasher) -> u64 {
    let bytes = hasher.finalize();
    let first8: [u8; 8] = bytes.as_bytes()[..8]
        .try_into()
        .expect("BLAKE3 output is always ≥ 8 bytes");
    u64::from_le_bytes(first8)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::CanonicalBytes;
    use proptest::prelude::*;

    fn hash_payload(domain: &str, payload: &[u8]) -> [u8; 32] {
        let mut hasher = domain_hasher(domain);
        payload.write_canonical(&mut hasher);
        finalize_32(&hasher)
    }

    // ---------------------------------------------------------------
    // Correctness anchor: domain_hasher + finalize_32 == blake3::derive_key
    // ---------------------------------------------------------------

    #[test]
    fn domain_hasher_matches_blake3_derive_key() {
        let context = "gossip/test-anchor/v1";
        let payload = b"deterministic payload for correctness check";

        // Our two-step API.
        let mut h = domain_hasher(context);
        h.update(payload);
        let ours = finalize_32(&h);

        // Direct blake3 derive_key (single-shot, fixed 32-byte output).
        let reference = blake3::derive_key(context, payload);

        assert_eq!(ours, reference);
    }

    // ---------------------------------------------------------------
    // Property-based: determinism across random payloads
    // ---------------------------------------------------------------

    proptest! {
        #![proptest_config(crate::test_util::miri_proptest_config())]
        #[test]
        fn deterministic_for_random_payload(data in proptest::collection::vec(any::<u8>(), 0..512)) {
            let domain = "gossip/prop/v1";

            let d1 = hash_payload(domain, data.as_slice());
            let d2 = hash_payload(domain, data.as_slice());

            prop_assert_eq!(d1, d2);
        }

        #[test]
        fn domain_separation_for_random_payload(data in proptest::collection::vec(any::<u8>(), 1..256)) {
            let d1 = hash_payload("gossip/left/v1", data.as_slice());
            let d2 = hash_payload("gossip/right/v1", data.as_slice());

            prop_assert_ne!(d1, d2);
        }
    }

    // ---------------------------------------------------------------
    // finalize_64: property-based
    // ---------------------------------------------------------------

    fn hash_payload_64(domain: &str, payload: &[u8]) -> u64 {
        let mut hasher = domain_hasher(domain);
        payload.write_canonical(&mut hasher);
        finalize_64(&hasher)
    }

    proptest! {
        #![proptest_config(crate::test_util::miri_proptest_config())]

        #[test]
        fn finalize_64_is_le_prefix_of_finalize_32(
            data in proptest::collection::vec(any::<u8>(), 0..512)
        ) {
            let domain = "gossip/cross-width-anchor/v1";
            let mut h = domain_hasher(domain);
            data.as_slice().write_canonical(&mut h);

            let full = finalize_32(&h);
            let short = finalize_64(&h);

            let expected = u64::from_le_bytes(full[..8].try_into().unwrap());
            prop_assert_eq!(short, expected);
        }

        #[test]
        fn finalize_64_deterministic(data in proptest::collection::vec(any::<u8>(), 0..512)) {
            let domain = "gossip/prop64/v1";
            let d1 = hash_payload_64(domain, data.as_slice());
            let d2 = hash_payload_64(domain, data.as_slice());
            prop_assert_eq!(d1, d2);
        }

        #[test]
        fn finalize_64_domain_separation(data in proptest::collection::vec(any::<u8>(), 1..256)) {
            let d1 = hash_payload_64("gossip/left64/v1", data.as_slice());
            let d2 = hash_payload_64("gossip/right64/v1", data.as_slice());
            prop_assert_ne!(d1, d2);
        }
    }
}
