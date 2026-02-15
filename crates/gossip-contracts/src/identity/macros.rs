//! `define_id_32!` and `define_id_32_restricted!` newtype macros.
//!
//! These macros are the factory for every `[u8; 32]` identity type in the
//! system.  Each invocation generates a complete newtype with standard derives,
//! a [`Debug`] implementation, byte accessors, and a [`CanonicalBytes`] impl.
//!
//! # Why macros instead of a generic struct?
//!
//! A single `Id<Tag>([u8; 32])` generic would share a single type constructor,
//! making it trivial to accidentally convert between ID domains.  Separate
//! concrete structs (one per macro invocation) are nominally distinct — the
//! compiler rejects `TenantId` where `FindingId` is expected, with zero
//! runtime cost.  Macros eliminate the boilerplate that would otherwise make
//! this strategy painful.
//!
//! # Variants
//!
//! Two variants exist to enforce a construction-safety boundary:
//!
//! | Macro | Inner field | Constructor | Use case |
//! |-------|-----------|-------------|----------|
//! | [`define_id_32!`] | `pub` | `from_bytes` (pub) | Freely constructible IDs (`TenantId`, `FindingId`) |
//! | [`define_id_32_restricted!`] | private | `from_bytes_internal` (`pub(crate)`) | Derivation-only IDs (`NormHash`, `SecretHash`) |
//!
//! The restricted variant exists for values that *must* be produced by a
//! specific derivation function (e.g. hashing with a domain separator).
//! Hiding the constructor prevents callers from forging a hash output by
//! supplying arbitrary bytes.
//!
//! Both macros use fully-qualified paths (`$crate::identity::CanonicalBytes`,
//! `$crate::blake3::Hasher`, `::core::fmt`) so they work from any invocation site —
//! inside this crate, in sibling modules, or from downstream crates.
//!
//! [`CanonicalBytes`]: crate::identity::CanonicalBytes

/// Generate a `[u8; 32]` newtype with public inner field.
///
/// Produces:
/// - `#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]`
/// - `Debug` printing `TypeName(aabbccdd..)` (first 4 bytes, hex)
/// - `ZERO` constant, `from_bytes` (pub const), `as_bytes` (pub const)
/// - `CanonicalBytes` impl (fixed-width, no length prefix)
///
/// # Example
///
/// ```
/// use gossip_contracts::define_id_32;
/// use gossip_contracts::identity::CanonicalBytes;
///
/// define_id_32! {
///     /// A test identity type.
///     TestId
/// }
///
/// let id = TestId::from_bytes([0xAB; 32]);
/// assert_eq!(id.as_bytes(), &[0xAB; 32]);
/// assert_eq!(format!("{:?}", id), "TestId(abababab..)");
/// ```
#[macro_export]
macro_rules! define_id_32 {
    (
        $(#[$meta:meta])*
        $name:ident
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(pub [u8; 32]);

        // Show only the first 4 bytes in hex to keep log output compact
        // while still giving enough entropy to distinguish instances.
        impl ::core::fmt::Debug for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                write!(
                    f,
                    concat!(stringify!($name), "({:02x}{:02x}{:02x}{:02x}..)"),
                    self.0[0], self.0[1], self.0[2], self.0[3]
                )
            }
        }

        impl $name {
            /// The all-zeros sentinel value.
            pub const ZERO: Self = Self([0u8; 32]);

            /// Construct from raw bytes.
            #[inline]
            pub const fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            /// Borrow the inner 32-byte array.
            #[inline]
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }

        impl $crate::identity::CanonicalBytes for $name {
            // Fixed-width: 32 bytes are written directly with no length
            // prefix because the size is statically known from the type.
            #[inline]
            fn write_canonical(&self, h: &mut $crate::blake3::Hasher) {
                h.update(&self.0);
            }
        }
    };
}

/// Generate a `[u8; 32]` newtype with private inner field and redacted `Debug`.
///
/// Use this for values that **must only be produced by a derivation function**
/// (e.g. a keyed hash).  The private field + `pub(crate)` constructor prevent
/// external callers from forging values by supplying arbitrary bytes.
///
/// Produces the same API as [`define_id_32!`] except:
/// - Inner field is private (not `pub`)
/// - Constructor is `from_bytes_internal` with `pub(crate)` visibility
/// - No `ZERO` constant (restricted types must come from derivation functions)
/// - `Debug` prints the caller-supplied string (typically `"TypeName([redacted])"`)
///   to avoid leaking security-sensitive material to logs
///
/// # Example
///
/// ```
/// use gossip_contracts::define_id_32_restricted;
/// use gossip_contracts::identity::CanonicalBytes;
///
/// define_id_32_restricted! {
///     /// A restricted test type.
///     TestRestricted,
///     debug_display = "TestRestricted([redacted])"
/// }
///
/// assert_eq!(format!("{:?}", TestRestricted::from_bytes_internal([0xFF; 32])),
///            "TestRestricted([redacted])");
/// ```
#[macro_export]
macro_rules! define_id_32_restricted {
    (
        $(#[$meta:meta])*
        $name:ident,
        debug_display = $debug:expr
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; 32]);

        // Emit the caller-supplied static string to avoid leaking
        // security-sensitive bytes (e.g. hash outputs) to logs.
        impl ::core::fmt::Debug for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                write!(f, $debug)
            }
        }

        impl $name {
            /// Construct from raw bytes.
            ///
            /// `pub(crate)` — only derivation functions within this crate may
            /// construct this type.
            #[inline]
            pub(crate) const fn from_bytes_internal(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            /// Borrow the inner 32-byte array.
            #[inline]
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }

        impl $crate::identity::CanonicalBytes for $name {
            // Fixed-width: 32 bytes written directly, no length prefix.
            #[inline]
            fn write_canonical(&self, h: &mut $crate::blake3::Hasher) {
                h.update(&self.0);
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use crate::identity::CanonicalBytes;
    use blake3::Hasher;
    use proptest::prelude::*;

    // Invoke the macros to create test-only types.
    define_id_32! {
        /// Public test ID for macro verification.
        PubTestId
    }

    define_id_32_restricted! {
        /// Restricted test ID for macro verification.
        RestrictedTestId,
        debug_display = "RestrictedTestId([redacted])"
    }

    // ---------------------------------------------------------------
    // define_id_32! — construction and accessors
    // ---------------------------------------------------------------

    #[test]
    fn pub_from_bytes_roundtrip() {
        let bytes = [0xAB; 32];
        let id = PubTestId::from_bytes(bytes);
        assert_eq!(*id.as_bytes(), bytes);
    }

    #[test]
    fn pub_zero_constant() {
        assert_eq!(*PubTestId::ZERO.as_bytes(), [0u8; 32]);
    }

    #[test]
    fn pub_inner_field_accessible() {
        let id = PubTestId::from_bytes([0x01; 32]);
        // Public inner field is directly accessible.
        assert_eq!(id.0, [0x01; 32]);
    }

    // ---------------------------------------------------------------
    // define_id_32! — Debug
    // ---------------------------------------------------------------

    #[test]
    fn pub_debug_shows_hex_prefix() {
        let id = PubTestId::from_bytes([
            0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ]);
        assert_eq!(format!("{id:?}"), "PubTestId(deadbeef..)");
    }

    #[test]
    fn pub_debug_does_not_leak_full_value() {
        let id = PubTestId::from_bytes([0xFF; 32]);
        let dbg = format!("{id:?}");
        // Should contain type name + 4-byte hex prefix, not all 32 bytes.
        assert!(dbg.len() < 40);
    }

    // ---------------------------------------------------------------
    // Compile-time trait assertions
    //
    // Derives are compiler-checked, so calling `.clone()` at runtime
    // to "test" Clone is redundant. Instead, a trait-bounded function
    // forces the compiler to verify bounds — the body is empty, so
    // there is zero runtime cost.
    // ---------------------------------------------------------------

    fn assert_id_traits<T: Clone + Copy + PartialEq + Eq + PartialOrd + Ord + core::hash::Hash>() {}

    #[test]
    fn macro_types_implement_required_traits() {
        assert_id_traits::<PubTestId>();
        assert_id_traits::<RestrictedTestId>();
    }

    // ---------------------------------------------------------------
    // define_id_32! — derives (behavioral)
    // ---------------------------------------------------------------

    #[test]
    fn pub_equality() {
        let a = PubTestId::from_bytes([1; 32]);
        let b = PubTestId::from_bytes([1; 32]);
        let c = PubTestId::from_bytes([2; 32]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn pub_ordering() {
        let lo = PubTestId::from_bytes([0x00; 32]);
        let hi = PubTestId::from_bytes([0xFF; 32]);
        assert!(lo < hi);
    }

    #[test]
    fn pub_hash_usable_in_set() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(PubTestId::from_bytes([1; 32]));
        set.insert(PubTestId::from_bytes([1; 32]));
        assert_eq!(set.len(), 1);
    }

    // ---------------------------------------------------------------
    // define_id_32_restricted! — construction and accessors
    // ---------------------------------------------------------------

    #[test]
    fn restricted_from_bytes_internal_roundtrip() {
        let bytes = [0xCD; 32];
        let id = RestrictedTestId::from_bytes_internal(bytes);
        assert_eq!(*id.as_bytes(), bytes);
    }

    // ---------------------------------------------------------------
    // define_id_32_restricted! — Debug
    // ---------------------------------------------------------------

    #[test]
    fn restricted_debug_is_redacted() {
        let id = RestrictedTestId::from_bytes_internal([0xFF; 32]);
        let dbg = format!("{id:?}");
        assert_eq!(dbg, "RestrictedTestId([redacted])");
    }

    #[test]
    fn restricted_debug_does_not_leak_bytes() {
        let id = RestrictedTestId::from_bytes_internal([0xFF; 32]);
        let dbg = format!("{id:?}");
        assert!(!dbg.contains("ff"));
    }

    // ---------------------------------------------------------------
    // define_id_32_restricted! — derives
    // ---------------------------------------------------------------

    #[test]
    fn restricted_equality() {
        let a = RestrictedTestId::from_bytes_internal([1; 32]);
        let b = RestrictedTestId::from_bytes_internal([1; 32]);
        let c = RestrictedTestId::from_bytes_internal([2; 32]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn restricted_ordering() {
        let lo = RestrictedTestId::from_bytes_internal([0x00; 32]);
        let hi = RestrictedTestId::from_bytes_internal([0xFF; 32]);
        assert!(lo < hi);
    }

    #[test]
    fn restricted_hash_usable_in_set() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(RestrictedTestId::from_bytes_internal([1; 32]));
        set.insert(RestrictedTestId::from_bytes_internal([1; 32]));
        assert_eq!(set.len(), 1);
    }

    // ---------------------------------------------------------------
    // CanonicalBytes — both variants
    // ---------------------------------------------------------------

    #[test]
    fn pub_canonical_bytes_fixed_width() {
        // CanonicalBytes for 32-byte IDs should write the raw bytes
        // with no length prefix (same as [u8; 32]).
        let bytes = [0x42; 32];
        let id = PubTestId::from_bytes(bytes);

        let mut h_id = Hasher::new();
        id.write_canonical(&mut h_id);

        let mut h_raw = Hasher::new();
        h_raw.update(&bytes);

        assert_eq!(h_id.finalize(), h_raw.finalize());
    }

    #[test]
    fn restricted_canonical_bytes_fixed_width() {
        let bytes = [0x77; 32];
        let id = RestrictedTestId::from_bytes_internal(bytes);

        let mut h_id = Hasher::new();
        id.write_canonical(&mut h_id);

        let mut h_raw = Hasher::new();
        h_raw.update(&bytes);

        assert_eq!(h_id.finalize(), h_raw.finalize());
    }

    // ---------------------------------------------------------------
    // Property-based — CanonicalBytes stability & collision-freedom
    // ---------------------------------------------------------------

    proptest! {
        #![proptest_config(crate::test_util::miri_proptest_config())]
        #[test]
        fn pub_canonical_bytes_stable(bytes in proptest::array::uniform32(any::<u8>())) {
            let id = PubTestId::from_bytes(bytes);
            let mut h1 = Hasher::new();
            let mut h2 = Hasher::new();
            id.write_canonical(&mut h1);
            id.write_canonical(&mut h2);
            prop_assert_eq!(h1.finalize(), h2.finalize());
        }

        #[test]
        fn pub_canonical_bytes_collision_free(
            a in proptest::array::uniform32(any::<u8>()),
            b in proptest::array::uniform32(any::<u8>()),
        ) {
            prop_assume!(a != b);
            let id_a = PubTestId::from_bytes(a);
            let id_b = PubTestId::from_bytes(b);
            let mut ha = Hasher::new();
            let mut hb = Hasher::new();
            id_a.write_canonical(&mut ha);
            id_b.write_canonical(&mut hb);
            prop_assert_ne!(ha.finalize(), hb.finalize());
        }

        #[test]
        fn restricted_canonical_bytes_stable(bytes in proptest::array::uniform32(any::<u8>())) {
            let id = RestrictedTestId::from_bytes_internal(bytes);
            let mut h1 = Hasher::new();
            let mut h2 = Hasher::new();
            id.write_canonical(&mut h1);
            id.write_canonical(&mut h2);
            prop_assert_eq!(h1.finalize(), h2.finalize());
        }

        #[test]
        fn restricted_canonical_bytes_collision_free(
            a in proptest::array::uniform32(any::<u8>()),
            b in proptest::array::uniform32(any::<u8>()),
        ) {
            prop_assume!(a != b);
            let id_a = RestrictedTestId::from_bytes_internal(a);
            let id_b = RestrictedTestId::from_bytes_internal(b);
            let mut ha = Hasher::new();
            let mut hb = Hasher::new();
            id_a.write_canonical(&mut ha);
            id_b.write_canonical(&mut hb);
            prop_assert_ne!(ha.finalize(), hb.finalize());
        }
    }
}
