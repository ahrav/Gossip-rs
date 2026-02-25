//! [`CanonicalBytes`] trait and primitive implementations.
//!
//! This is the encoding foundation for all content-addressed identity
//! derivation. See the trait-level docs on [`CanonicalBytes`] for the full
//! invariant specification (collision-freedom, determinism, no allocation).

use blake3::Hasher;

/// Deterministic byte encoding for content-addressed hashing.
///
/// Every type that participates in a content-addressed derivation (`FindingId`,
/// `OccurrenceId`, `derive_split_shard_id`, payload hashes) must implement this
/// trait.
///
/// # Invariants
///
/// **Collision-freedom**: for any two distinct values `a != b` of the same type,
/// `a.write_canonical(h)` and `b.write_canonical(h)` must produce different byte
/// sequences. Variable-length fields must be length-prefixed; multi-field types
/// must use unambiguous framing.
///
/// **Determinism**: output must be identical across platforms, byte orders, and
/// Rust versions. Use fixed-endian encoding (little-endian by convention).
///
/// **No allocation**: implementations must feed bytes directly into the hasher
/// without intermediate heap allocation. Identity derivation runs on hot paths
/// (per-finding, per-shard, per-checkpoint), so any allocation here would
/// violate the zero-allocation-after-startup invariant.
///
/// # Implementing for composite types
///
/// Multi-field types must write each field so the boundary between them is
/// unambiguous. Fixed-width primitives are self-framing; variable-length
/// fields are length-prefixed by the `[u8]` impl. A typical composite:
///
/// ```
/// use blake3::Hasher;
/// use gossip_contracts::identity::CanonicalBytes;
///
/// struct Pair { tag: u32, data: Vec<u8> }
///
/// impl CanonicalBytes for Pair {
///     fn write_canonical(&self, h: &mut Hasher) {
///         self.tag.write_canonical(h);             // fixed-width: no prefix needed
///         self.data.as_slice().write_canonical(h);  // variable-length: auto-prefixed
///     }
/// }
/// ```
pub trait CanonicalBytes {
    /// Write this value's canonical byte representation into `hasher`.
    fn write_canonical(&self, hasher: &mut Hasher);
}

/// Single-byte encoding: no length prefix needed (fixed 1-byte width).
impl CanonicalBytes for u8 {
    #[inline]
    fn write_canonical(&self, h: &mut Hasher) {
        h.update(&[*self]);
    }
}

/// 4-byte little-endian encoding: no length prefix needed (fixed width).
impl CanonicalBytes for u32 {
    #[inline]
    fn write_canonical(&self, h: &mut Hasher) {
        h.update(&self.to_le_bytes());
    }
}

/// 8-byte little-endian encoding: no length prefix needed (fixed width).
impl CanonicalBytes for u64 {
    #[inline]
    fn write_canonical(&self, h: &mut Hasher) {
        h.update(&self.to_le_bytes());
    }
}

/// Variable-length byte slices use a 4-byte LE length prefix to prevent
/// concatenation ambiguity. For example, `[0x41, 0x42]` encodes as
/// `[2, 0, 0, 0, 0x41, 0x42]`.
///
/// # Panics
///
/// Panics if `self.len() > u32::MAX` (4 GiB). Identity-derivation inputs
/// are always far below this limit.
impl CanonicalBytes for [u8] {
    #[inline]
    fn write_canonical(&self, h: &mut Hasher) {
        let len =
            u32::try_from(self.len()).expect("slice too large for canonical encoding (max 4 GiB)");
        len.write_canonical(h);
        h.update(self);
    }
}

/// Fixed-length 32-byte arrays need no length prefix (fixed width).
impl CanonicalBytes for [u8; 32] {
    #[inline]
    fn write_canonical(&self, h: &mut Hasher) {
        h.update(self);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use blake3::Hasher;
    use proptest::array::uniform32;
    use proptest::prelude::*;

    // ---------------------------------------------------------------
    // Property-based invariant tests — Determinism
    // ---------------------------------------------------------------

    proptest! {
        #![proptest_config(crate::test_util::miri_proptest_config())]
        #[test]
        fn u8_stable(v in any::<u8>()) {
            let mut h1 = Hasher::new();
            let mut h2 = Hasher::new();
            v.write_canonical(&mut h1);
            v.write_canonical(&mut h2);
            prop_assert_eq!(h1.finalize(), h2.finalize());
        }

        #[test]
        fn u32_stable(v in any::<u32>()) {
            let mut h1 = Hasher::new();
            let mut h2 = Hasher::new();
            v.write_canonical(&mut h1);
            v.write_canonical(&mut h2);
            prop_assert_eq!(h1.finalize(), h2.finalize());
        }

        #[test]
        fn u64_stable(v in any::<u64>()) {
            let mut h1 = Hasher::new();
            let mut h2 = Hasher::new();
            v.write_canonical(&mut h1);
            v.write_canonical(&mut h2);
            prop_assert_eq!(h1.finalize(), h2.finalize());
        }

        #[test]
        fn slice_stable(data in proptest::collection::vec(any::<u8>(), 0..256)) {
            let mut h1 = Hasher::new();
            let mut h2 = Hasher::new();
            data.as_slice().write_canonical(&mut h1);
            data.as_slice().write_canonical(&mut h2);
            prop_assert_eq!(h1.finalize(), h2.finalize());
        }

        #[test]
        fn fixed_32_stable(bytes in uniform32(any::<u8>())) {
            let bytes: [u8; 32] = bytes;
            let mut h1 = Hasher::new();
            let mut h2 = Hasher::new();
            bytes.write_canonical(&mut h1);
            bytes.write_canonical(&mut h2);
            prop_assert_eq!(h1.finalize(), h2.finalize());
        }
    }

    // ---------------------------------------------------------------
    // Property-based invariant tests — Collision-freedom
    // ---------------------------------------------------------------

    proptest! {
        #![proptest_config(crate::test_util::miri_proptest_config())]
        #[test]
        fn u8_collision_free(a in any::<u8>(), b in any::<u8>()) {
            prop_assume!(a != b);
            let mut ha = Hasher::new();
            let mut hb = Hasher::new();
            a.write_canonical(&mut ha);
            b.write_canonical(&mut hb);
            prop_assert_ne!(ha.finalize(), hb.finalize());
        }

        #[test]
        fn u32_collision_free(a in any::<u32>(), b in any::<u32>()) {
            prop_assume!(a != b);
            let mut ha = Hasher::new();
            let mut hb = Hasher::new();
            a.write_canonical(&mut ha);
            b.write_canonical(&mut hb);
            prop_assert_ne!(ha.finalize(), hb.finalize());
        }

        #[test]
        fn u64_collision_free(a in any::<u64>(), b in any::<u64>()) {
            prop_assume!(a != b);
            let mut ha = Hasher::new();
            let mut hb = Hasher::new();
            a.write_canonical(&mut ha);
            b.write_canonical(&mut hb);
            prop_assert_ne!(ha.finalize(), hb.finalize());
        }

        #[test]
        fn slice_collision_free(
            a in proptest::collection::vec(any::<u8>(), 0..128),
            b in proptest::collection::vec(any::<u8>(), 0..128),
        ) {
            prop_assume!(a != b);
            let mut ha = Hasher::new();
            let mut hb = Hasher::new();
            a.as_slice().write_canonical(&mut ha);
            b.as_slice().write_canonical(&mut hb);
            prop_assert_ne!(ha.finalize(), hb.finalize());
        }

        #[test]
        fn fixed_32_collision_free(
            a in uniform32(any::<u8>()),
            b in uniform32(any::<u8>()),
        ) {
            let a: [u8; 32] = a;
            let b: [u8; 32] = b;
            prop_assume!(a != b);
            let mut ha = Hasher::new();
            let mut hb = Hasher::new();
            a.write_canonical(&mut ha);
            b.write_canonical(&mut hb);
            prop_assert_ne!(ha.finalize(), hb.finalize());
        }
    }

    // ---------------------------------------------------------------
    // Encoding format verification
    // ---------------------------------------------------------------

    #[test]
    fn u8_writes_single_byte() {
        let mut h1 = Hasher::new();
        0xFFu8.write_canonical(&mut h1);

        let mut h2 = Hasher::new();
        h2.update(&[0xFF]);

        assert_eq!(h1.finalize(), h2.finalize());
    }

    #[test]
    fn u32_is_little_endian() {
        let val: u32 = 0x01020304;
        let mut h1 = Hasher::new();
        val.write_canonical(&mut h1);

        let mut h2 = Hasher::new();
        h2.update(&val.to_le_bytes());

        assert_eq!(h1.finalize(), h2.finalize());
    }

    #[test]
    fn u64_is_little_endian() {
        let val: u64 = 0x0102030405060708;
        let mut h1 = Hasher::new();
        val.write_canonical(&mut h1);

        let mut h2 = Hasher::new();
        h2.update(&val.to_le_bytes());

        assert_eq!(h1.finalize(), h2.finalize());
    }

    #[test]
    fn fixed_32_no_length_prefix() {
        // [u8; 32] should NOT be length-prefixed (fixed width).
        let bytes = [0xABu8; 32];
        let mut h1 = Hasher::new();
        bytes.write_canonical(&mut h1);

        let mut h2 = Hasher::new();
        h2.update(&bytes);

        assert_eq!(h1.finalize(), h2.finalize());
    }

    // ---------------------------------------------------------------
    // Structural anti-pattern tests
    // ---------------------------------------------------------------

    #[test]
    fn slice_length_prefixed() {
        // [0x41] and [0x41, 0x00] must produce different hashes
        // because the 4-byte LE length prefix distinguishes them.
        let a: &[u8] = &[0x41];
        let b: &[u8] = &[0x41, 0x00];

        let mut ha = Hasher::new();
        let mut hb = Hasher::new();
        a.write_canonical(&mut ha);
        b.write_canonical(&mut hb);

        assert_ne!(ha.finalize(), hb.finalize());
    }

    #[test]
    fn concatenation_unambiguous() {
        // ("ab", "c") != ("a", "bc") for variable-length fields.
        let mut h1 = Hasher::new();
        let mut h2 = Hasher::new();

        b"ab".as_slice().write_canonical(&mut h1);
        b"c".as_slice().write_canonical(&mut h1);

        b"a".as_slice().write_canonical(&mut h2);
        b"bc".as_slice().write_canonical(&mut h2);

        assert_ne!(h1.finalize(), h2.finalize());
    }
}
