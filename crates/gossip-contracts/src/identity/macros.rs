//! Identity newtype macros for `[u8; 32]` and `u64` widths.
//!
//! These macros are the factory for every identity type in the system.  Each
//! invocation generates a complete newtype with standard derives, a [`Debug`]
//! implementation, accessors, and a [`CanonicalBytes`] impl.
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
//! | Macro | Width | Inner | Constructor | Use case |
//! |-------|-------|-------|-------------|----------|
//! | [`define_id_32!`] | `[u8; 32]` | private | `from_bytes` (pub) | Content-addressed IDs (`TenantId`, `FindingId`) |
//! | [`define_id_32_restricted!`] | `[u8; 32]` | private | `from_bytes_internal` (`pub(crate)`) | Derivation-only IDs (`NormHash`, `SecretHash`) |
//! | [`define_id_64!`] | `u64` | private | `from_raw` (pub) | Coordination IDs (`RunId`, `ShardId`, `WorkerId`) |
//!
//! The restricted variant exists for values that *must* be produced by a
//! specific derivation function (e.g. hashing with a domain separator).
//! Hiding the constructor prevents callers from forging a hash output by
//! supplying arbitrary bytes.
//!
//! All macros use fully-qualified paths (`$crate::identity::CanonicalBytes`,
//! `$crate::blake3::Hasher`, `::core::fmt`) so they work from any invocation site —
//! inside this crate, in sibling modules, or from downstream crates.
//!
//! # Test-support macros
//!
//! Additional macros exist for **consumer-crate integration tests** (the
//! `tests/identity_smoke.rs` files in engine, connectors, coordination, and
//! pipeline).  Their purpose is to act as *import canaries*: if a type is
//! removed from the public API or its layout changes, the downstream crate's
//! build breaks immediately — even though `gossip-contracts` itself already
//! has comprehensive property-test and golden-vector coverage.
//!
//! | Macro | Checks | Multiple invocations? |
//! |-------|--------|-----------------------|
//! | [`smoke_test_id_32!`] | size == 32 (const) + `ZERO` sentinel (runtime) | **No** — generates named `#[test]` fns |
//! | [`smoke_test_id_64!`] | size == 8 (const) + `ZERO` sentinel (runtime) | **No** — generates named `#[test]` fns |
//! | [`smoke_test_id_size!`] | size == N (const only) | Yes — only emits `const _` blocks |
//!
//! [`CanonicalBytes`]: crate::identity::CanonicalBytes

/// Generate a `[u8; 32]` newtype with private inner field.
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
        pub struct $name([u8; 32]);

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

        // `Display` intentionally produces the same output as `Debug` so
        // that `tracing` span fields using `%` (Display) and `?` (Debug)
        // are interchangeable for identity types.
        impl ::core::fmt::Display for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                ::core::fmt::Debug::fmt(self, f)
            }
        }

        impl $name {
            /// The all-zeros sentinel value, used as a default/placeholder in
            /// contexts where an ID is structurally required but not yet known
            /// (e.g., uninitialized shard records).
            pub const ZERO: Self = Self([0u8; 32]);

            /// Construct from raw bytes.  No validation is performed --
            /// any 32-byte value is a valid ID.
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
            /// `pub(crate)` visibility ensures that only derivation functions
            /// within this crate may construct this type.  External callers
            /// cannot forge values by supplying arbitrary bytes; they must go
            /// through the designated derivation function (e.g., `key_secret_hash`
            /// for `SecretHash`).
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

/// Generate a fixed-field input struct whose
/// [`CanonicalBytes`](crate::identity::CanonicalBytes) encoding follows the
/// declared field order.
///
/// This is an internal helper for identity/policy input structs such as
/// `FindingIdInputs` and `PolicyHashInputs`. It intentionally avoids a
/// proc-macro crate: the identity layer already uses declarative macros for
/// boilerplate, and keeping the struct definition plus `CanonicalBytes` impl in
/// one macro invocation makes the declaration order the single source of truth.
///
/// # Syntax
///
/// All fields must end with a trailing comma, including the last field.
/// Omitting it produces an unhelpful "no rules matched" error.
macro_rules! define_canonical_input {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident {
            $(
                $(#[$field_meta:meta])*
                $field_vis:vis $field:ident : $ty:ty,
            )*
        }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        $vis struct $name {
            $(
                $(#[$field_meta])*
                $field_vis $field: $ty,
            )*
        }

        impl $crate::identity::CanonicalBytes for $name {
            #[inline]
            fn write_canonical(&self, h: &mut $crate::blake3::Hasher) {
                $(
                    self.$field.write_canonical(h);
                )*
            }
        }
    };
}

pub(crate) use define_canonical_input;

/// Import-canary macro for consumer crates: asserts that every listed
/// [`define_id_32!`] type is still 32 bytes and that its `ZERO` sentinel is
/// all-zero.
///
/// Consumer crates (engine, connectors, coordination, pipeline) each invoke
/// this once in their `tests/identity_smoke.rs` so that removing a type from
/// the public API or changing its layout breaks the downstream build
/// immediately.  The invariants themselves are already covered by property
/// tests and golden vectors inside `gossip-contracts`; this macro exists
/// purely for the **cross-crate compile-gate** effect.
///
/// # What it generates
///
/// - A `const _: ()` block with a compile-time `size_of` assertion per type
///   (fires during `cargo check`, not just `cargo test`).
/// - `#[test] fn id_types_are_32_bytes()` — runtime confirmation with
///   per-type error messages.
/// - `#[test] fn zero_sentinels_are_zeroed()` — runtime check that
///   `T::ZERO.as_bytes()` is `[0u8; 32]` for every listed type.
///
/// # Constraints
///
/// - Every type must expose `ZERO` and `as_bytes()` — i.e. it must be
///   produced by [`define_id_32!`], **not** [`define_id_32_restricted!`].
///   For restricted types use `smoke_test_id_size!` instead.
/// - **Invoke at most once per scope.** The generated test function names
///   (`id_types_are_32_bytes`, `zero_sentinels_are_zeroed`) are fixed, so a
///   second invocation in the same module causes a compile error.
///
/// # Usage
///
/// ```ignore
/// gossip_contracts::smoke_test_id_32!(FindingId, OccurrenceId, RuleFingerprint);
/// ```
#[macro_export]
macro_rules! smoke_test_id_32 {
    ($($ty:ty),+ $(,)?) => {
        // Compile-time size guard — fires during `cargo check`, not just `cargo test`.
        const _: () = {
            $(::core::assert!(::core::mem::size_of::<$ty>() == 32);)+
        };

        #[test]
        fn id_types_are_32_bytes() {
            $(
                assert_eq!(
                    ::core::mem::size_of::<$ty>(), 32,
                    "{} is not 32 bytes", stringify!($ty),
                );
            )+
        }

        #[test]
        fn zero_sentinels_are_zeroed() {
            $({
                let z = <$ty>::ZERO;
                assert_eq!(
                    *z.as_bytes(), [0u8; 32],
                    "{}::ZERO is not all-zero", stringify!($ty),
                );
            })+
        }
    };
}

/// Generate a `u64` newtype with private inner field.
///
/// Produces:
/// - `#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]`
/// - `Debug` printing `TypeName(decimal)` — decimal is more useful for u64 IDs than hex
/// - `ZERO` constant, `from_raw` (pub const), `as_raw` (pub const)
/// - `CanonicalBytes` impl (little-endian 8-byte encoding, no length prefix)
///
/// # Example
///
/// ```
/// use gossip_contracts::define_id_64;
/// use gossip_contracts::identity::CanonicalBytes;
///
/// define_id_64! {
///     /// A test 64-bit identity type.
///     TestId64
/// }
///
/// let id = TestId64::from_raw(42);
/// assert_eq!(id.as_raw(), 42);
/// assert_eq!(format!("{:?}", id), "TestId64(42)");
/// ```
#[macro_export]
macro_rules! define_id_64 {
    (
        $(#[$meta:meta])*
        $name:ident
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(u64);

        // Decimal format is more useful than hex for 64-bit counter/ID values
        // that are assigned sequentially or generated from small ranges.
        impl ::core::fmt::Debug for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                write!(f, concat!(stringify!($name), "({})"), self.0)
            }
        }

        // `Display` intentionally produces the same output as `Debug` so
        // that `tracing` span fields using `%` (Display) and `?` (Debug)
        // are interchangeable for identity types.
        impl ::core::fmt::Display for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                ::core::fmt::Debug::fmt(self, f)
            }
        }

        impl $name {
            /// The zero sentinel value, used as a default/placeholder in
            /// contexts where an ID is structurally required but not yet
            /// assigned (e.g., newly created coordination records).
            pub const ZERO: Self = Self(0);

            /// Construct from a raw `u64`.  No validation is performed --
            /// any `u64` value is a valid ID.
            #[inline]
            pub const fn from_raw(raw: u64) -> Self { Self(raw) }

            /// Return the inner `u64`.
            #[inline]
            pub const fn as_raw(&self) -> u64 { self.0 }
        }

        impl $crate::identity::CanonicalBytes for $name {
            // Delegates to the u64 CanonicalBytes impl (8-byte LE, no prefix).
            #[inline]
            fn write_canonical(&self, h: &mut $crate::blake3::Hasher) {
                self.0.write_canonical(h);
            }
        }
    };
}

/// Import-canary macro for consumer crates: asserts that every listed
/// [`define_id_64!`] type is still 8 bytes and that its `ZERO` sentinel is
/// zero.
///
/// This is the 64-bit counterpart of [`smoke_test_id_32!`]. Consumer crates
/// invoke this in their `tests/identity_smoke.rs` to catch layout or API
/// changes in downstream builds.
///
/// # What it generates
///
/// - A `const _: ()` block with a compile-time `size_of` assertion per type
///   (fires during `cargo check`, not just `cargo test`).
/// - `#[test] fn id_64_types_are_8_bytes()` — runtime confirmation with
///   per-type error messages.
/// - `#[test] fn id_64_zero_sentinels_are_zeroed()` — runtime check that
///   `T::ZERO.as_raw() == 0` for every listed type.
///
/// # Constraints
///
/// - Every type must expose `ZERO` and `as_raw()` — i.e. it must be
///   produced by [`define_id_64!`].
/// - **Invoke at most once per scope.** The generated test function names
///   are fixed, so a second invocation in the same module causes a compile error.
///
/// # Usage
///
/// ```ignore
/// gossip_contracts::smoke_test_id_64!(RunId, ShardId, WorkerId, OpId, JobId);
/// ```
#[macro_export]
macro_rules! smoke_test_id_64 {
    ($($ty:ty),+ $(,)?) => {
        // Compile-time size guard — fires during `cargo check`, not just `cargo test`.
        const _: () = {
            $(::core::assert!(::core::mem::size_of::<$ty>() == 8);)+
        };

        #[test]
        fn id_64_types_are_8_bytes() {
            $(
                assert_eq!(
                    ::core::mem::size_of::<$ty>(), 8,
                    "{} is not 8 bytes", stringify!($ty),
                );
            )+
        }

        #[test]
        fn id_64_zero_sentinels_are_zeroed() {
            $({
                let z = <$ty>::ZERO;
                assert_eq!(
                    z.as_raw(), 0u64,
                    "{}::ZERO is not zero", stringify!($ty),
                );
            })+
        }
    };
}

/// Compile-time size assertion for any identity type — the layout counterpart
/// of [`smoke_test_id_32!`] for types that lack a `ZERO` sentinel.
///
/// Use this for:
/// - **Restricted types** ([`define_id_32_restricted!`]) such as `NormHash`,
///   `SecretHash`, and `TenantSecretKey`, which have no `ZERO` constant.
/// - **Non-32-byte types** such as `ConnectorTag` (8 bytes).
///
/// Only a `const` assertion is emitted — no `#[test]` function — because the
/// size is a layout invariant that should fail the build, not just a test run.
/// Multiple invocations in the same scope are safe (each produces an
/// independent `const _: ()` block).
///
/// See the module-level docs on `macros` for the import-canary rationale.
///
/// # Usage
///
/// ```ignore
/// gossip_contracts::smoke_test_id_size!(ConnectorTag, 8);
/// gossip_contracts::smoke_test_id_size!(NormHash, 32);
/// ```
#[macro_export]
macro_rules! smoke_test_id_size {
    ($ty:ty, $size:expr) => {
        const _: () = {
            ::core::assert!(::core::mem::size_of::<$ty>() == $size);
        };
    };
}

#[cfg(test)]
mod tests {
    use crate::identity::CanonicalBytes;
    use blake3::Hasher;
    use proptest::prelude::*;

    define_id_32! {
        /// Public test ID for macro verification.
        PubTestId
    }

    define_id_32_restricted! {
        /// Restricted test ID for macro verification.
        RestrictedTestId,
        debug_display = "RestrictedTestId([redacted])"
    }

    define_canonical_input! {
        /// Test canonical input for macro verification.
        pub struct CanonicalInputTest {
            /// A fixed-width version field.
            pub version: u32,
            /// A single-byte mode tag.
            pub mode: u8,
            /// A fixed-width digest.
            pub digest: [u8; 32],
        }
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
    fn pub_inner_field_is_private() {
        // The inner `[u8; 32]` field is private — callers must use
        // `from_bytes` / `as_bytes`.  This test exists as a compile-gate
        // reminder; the actual privacy check is structural (removing `pub`
        // from the tuple field).
        let id = PubTestId::from_bytes([0x01; 32]);
        assert_eq!(*id.as_bytes(), [0x01; 32]);
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

    fn assert_canonical_input_traits<T: Clone + Copy + core::fmt::Debug + PartialEq + Eq>() {}

    #[test]
    fn canonical_input_macro_types_implement_required_traits() {
        assert_canonical_input_traits::<CanonicalInputTest>();
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

    #[test]
    fn canonical_input_macro_matches_declaration_order() {
        let inputs = CanonicalInputTest {
            version: 7,
            mode: 1,
            digest: [0xAB; 32],
        };

        let mut generated = Hasher::new();
        inputs.write_canonical(&mut generated);

        let mut manual = Hasher::new();
        7u32.write_canonical(&mut manual);
        1u8.write_canonical(&mut manual);
        [0xAB; 32].write_canonical(&mut manual);

        assert_eq!(generated.finalize(), manual.finalize());
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
