//! Connector boundary value types and validation errors.
//!
//! This module defines "toxic-byte" wrappers used by connector enumeration
//! and paging flows. Toxic bytes may contain sensitive or user-controlled data
//! and must never be formatted as raw bytes in logs.
//!
//! ## Types at a glance
//!
//! | Type | Role | Limit | Ordered? |
//! |------|------|-------|----------|
//! | [`ItemKey`] | Enumeration position for sharding and cursor progression | 4 KiB | Yes (lexicographic) |
//! | [`ItemRef`] | Opaque handle a connector returns for read/open | 16 KiB | No |
//! | [`TokenBytes`] | Pagination/resume token the connector round-trips | 16 KiB | No |
//!
//! ## Core contract
//!
//! - Constructors enforce non-empty bytes and hard upper bounds.
//! - Wrappers own bytes (`Box<[u8]>`) so validated values can cross boundaries
//!   without borrowing caller memory.
//! - Formatting is always redacted (`len + short hash prefix`), so logs can be
//!   correlated without leaking payload contents. The hash is a truncated
//!   BLAKE3 digest -- fast, collision-resistant, and deterministic across runs.
//! - `MAX_ITEM_KEY_SIZE` and `MAX_TOKEN_SIZE` intentionally track coordination
//!   cursor limits to keep connector paging contracts aligned.
//!   `MAX_ITEM_REF_SIZE` is independent; it bounds connector-specific handles
//!   that never enter the cursor path.

use std::fmt;

use crate::coordination::{CursorMaxTokenSize, MAX_KEY_SIZE};

/// Maximum size of an [`ItemKey`] in bytes (4 KiB).
///
/// Kept in lock-step with the coordination cursor `last_key` limit
/// ([`MAX_KEY_SIZE`]) so that every valid connector key can be stored
/// directly in a cursor without truncation.
pub const MAX_ITEM_KEY_SIZE: usize = MAX_KEY_SIZE;

/// Maximum size of an [`ItemRef`] in bytes (16 KiB).
///
/// Unlike `MAX_ITEM_KEY_SIZE` and `MAX_TOKEN_SIZE`, this limit is not
/// derived from coordination cursor fields -- `ItemRef` values never enter
/// the cursor path. The bound exists purely as a defense-in-depth cap on
/// connector-supplied handles.
pub const MAX_ITEM_REF_SIZE: usize = 16_384;

/// Maximum size of a [`TokenBytes`] value in bytes (16 KiB).
///
/// Kept in lock-step with the coordination cursor `token` limit
/// ([`CursorMaxTokenSize`]) so that pagination tokens can be persisted in
/// cursor state without size mismatch.
pub const MAX_TOKEN_SIZE: usize = CursorMaxTokenSize;

/// Input validation errors for connector boundary value types and cross-field
/// cursor-shape checks.
///
/// `Empty` and `TooLarge` are emitted by the byte-wrapper constructors in
/// this module (`ItemKey`, `ItemRef`, `TokenBytes`). `TokenWithoutLastKey`
/// is reserved for higher-level request validation that checks cursor field
/// combinations.
///
/// Marked `non_exhaustive` so new boundary validation failures can be added
/// without a breaking change.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConnectorInputError {
    /// A required field was empty (zero-length byte slice).
    Empty { field: &'static str },
    /// A field exceeded its hard size limit.
    TooLarge {
        field: &'static str,
        /// Actual byte length of the rejected input.
        size: usize,
        /// Upper bound for this field (one of the `MAX_*` constants).
        max: usize,
    },
    /// A cursor token was supplied without a last_key.
    ///
    /// This preserves the cursor contract that a token only has meaning when
    /// attached to an explicit ordered position. Without a last_key the
    /// coordinator cannot determine where enumeration should resume.
    ///
    /// Not emitted by the byte-wrapper constructors in this module; reserved
    /// for higher-level cursor/request validators.
    TokenWithoutLastKey,
}

impl fmt::Display for ConnectorInputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty { field } => write!(f, "{field} must not be empty"),
            Self::TooLarge { field, size, max } => {
                write!(f, "{field} too large ({size} bytes, max {max})")
            }
            Self::TokenWithoutLastKey => write!(f, "cursor token requires a last_key"),
        }
    }
}

impl std::error::Error for ConnectorInputError {}

/// Returns the first 4 bytes of the BLAKE3 digest of `bytes`.
///
/// Used exclusively by [`fmt_toxic_bytes`] to produce a short, deterministic
/// fingerprint for log correlation. Four bytes (8 hex chars) provide enough
/// uniqueness for operational debugging while keeping formatted output compact.
#[inline]
fn hash_prefix_4(bytes: &[u8]) -> [u8; 4] {
    let hash = blake3::hash(bytes);
    let b = hash.as_bytes();
    [b[0], b[1], b[2], b[3]]
}

/// Shared `Debug`/`Display` formatter for all toxic-byte wrappers.
///
/// Output format: `TypeName(len=N, hash=XXXXXXXX..)` where the hash is the
/// first 4 bytes of the BLAKE3 digest in lowercase hex. Both `Debug` and
/// `Display` intentionally produce identical output so callers cannot
/// accidentally bypass the toxic-byte redaction policy by switching format
/// traits.
#[inline]
fn fmt_toxic_bytes(
    f: &mut fmt::Formatter<'_>,
    type_name: &'static str,
    bytes: &[u8],
) -> fmt::Result {
    let [a, b, c, d] = hash_prefix_4(bytes);
    write!(
        f,
        "{type_name}(len={}, hash={:02x}{:02x}{:02x}{:02x}..)",
        bytes.len(),
        a,
        b,
        c,
        d
    )
}

/// Validates the two shared constructor invariants for toxic-byte wrappers:
///
/// 1. `bytes` must not be empty (rejects zero-length slices).
/// 2. `bytes.len()` must not exceed `max`.
///
/// All wrapper constructors delegate here so the emptiness and size checks are
/// defined in exactly one place.
#[inline]
fn validate_toxic_bytes(
    field: &'static str,
    bytes: &[u8],
    max: usize,
) -> Result<(), ConnectorInputError> {
    if bytes.is_empty() {
        return Err(ConnectorInputError::Empty { field });
    }
    if bytes.len() > max {
        return Err(ConnectorInputError::TooLarge {
            field,
            size: bytes.len(),
            max,
        });
    }
    Ok(())
}

/// Ordered enumeration key used for sharding, paging, and cursor progression.
///
/// Connectors produce `ItemKey` values to represent ordered positions within a
/// data source. The coordination layer stores these as cursor `last_key` fields,
/// so both sides must agree on the size bound ([`MAX_ITEM_KEY_SIZE`]).
///
/// ## Ordering
///
/// `Ord` is derived, giving bytewise lexicographic comparison. This matches the
/// cursor progression contract: advancing means moving to a strictly greater key.
///
/// ## Toxic-byte policy
///
/// `Debug` and `Display` are redacted (length + hash prefix). Raw bytes are
/// accessible only through [`as_bytes`](Self::as_bytes) /
/// [`AsRef<[u8]>`](AsRef).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ItemKey(Box<[u8]>);

impl ItemKey {
    /// Panicking constructor for trusted, already-validated call sites.
    ///
    /// Prefer [`try_from_vec`](Self::try_from_vec) at input boundaries where
    /// the caller cannot guarantee validity.
    ///
    /// # Panics
    ///
    /// Panics if `bytes` is empty or larger than [`MAX_ITEM_KEY_SIZE`].
    #[must_use]
    pub fn from_vec(bytes: Vec<u8>) -> Self {
        Self::try_from_vec(bytes).expect("ItemKey must be non-empty and within size limits")
    }

    /// Fallible constructor that takes ownership of caller-provided bytes.
    ///
    /// Use this at input boundaries that accept untrusted or external bytes.
    /// Takes ownership of the `Vec` to avoid a copy when validation succeeds.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectorInputError::Empty`] if `bytes` is empty, or
    /// [`ConnectorInputError::TooLarge`] if it exceeds [`MAX_ITEM_KEY_SIZE`].
    pub fn try_from_vec(bytes: Vec<u8>) -> Result<Self, ConnectorInputError> {
        validate_toxic_bytes("ItemKey", &bytes, MAX_ITEM_KEY_SIZE)?;
        Ok(Self(bytes.into_boxed_slice()))
    }

    /// Fallible constructor from a borrowed slice.
    ///
    /// Copies `bytes` into a new allocation on success. When the caller already
    /// owns a `Vec`, prefer [`try_from_vec`](Self::try_from_vec) to avoid the
    /// extra copy.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectorInputError::Empty`] if `bytes` is empty, or
    /// [`ConnectorInputError::TooLarge`] if it exceeds [`MAX_ITEM_KEY_SIZE`].
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, ConnectorInputError> {
        validate_toxic_bytes("ItemKey", bytes, MAX_ITEM_KEY_SIZE)?;
        Ok(Self(bytes.to_vec().into_boxed_slice()))
    }

    /// Returns the validated key bytes.
    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for ItemKey {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl fmt::Debug for ItemKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_toxic_bytes(f, "ItemKey", &self.0)
    }
}

impl fmt::Display for ItemKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_toxic_bytes(f, "ItemKey", &self.0)
    }
}

/// Opaque, credential-free connector handle for read/open operations.
///
/// A connector returns an `ItemRef` alongside each enumerated item so the
/// coordinator can later ask the connector to open or read that item without
/// needing the connector's internal addressing scheme. The bytes are opaque to
/// the coordination layer -- only the originating connector interprets them.
///
/// ## Differences from [`ItemKey`]
///
/// - **Not ordered.** `ItemRef` does not derive `Ord` because the coordination
///   layer never compares or sorts references; they are looked up, not ranged.
/// - **Independent size limit.** [`MAX_ITEM_REF_SIZE`] is not tied to cursor
///   field limits because references never enter cursor state.
///
/// ## Toxic-byte policy
///
/// `Debug` and `Display` are redacted (length + hash prefix). Raw bytes are
/// accessible only through [`as_bytes`](Self::as_bytes) /
/// [`AsRef<[u8]>`](AsRef).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ItemRef(Box<[u8]>);

impl ItemRef {
    /// Panicking constructor for trusted, already-validated call sites.
    ///
    /// Prefer [`try_from_vec`](Self::try_from_vec) at input boundaries where
    /// the caller cannot guarantee validity.
    ///
    /// # Panics
    ///
    /// Panics if `bytes` is empty or larger than [`MAX_ITEM_REF_SIZE`].
    #[must_use]
    pub fn from_vec(bytes: Vec<u8>) -> Self {
        Self::try_from_vec(bytes).expect("ItemRef must be non-empty and within size limits")
    }

    /// Fallible constructor that takes ownership of caller-provided bytes.
    ///
    /// Use this at input boundaries that accept untrusted or external bytes.
    /// Takes ownership of the `Vec` to avoid a copy when validation succeeds.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectorInputError::Empty`] if `bytes` is empty, or
    /// [`ConnectorInputError::TooLarge`] if it exceeds [`MAX_ITEM_REF_SIZE`].
    pub fn try_from_vec(bytes: Vec<u8>) -> Result<Self, ConnectorInputError> {
        validate_toxic_bytes("ItemRef", &bytes, MAX_ITEM_REF_SIZE)?;
        Ok(Self(bytes.into_boxed_slice()))
    }

    /// Fallible constructor from a borrowed slice.
    ///
    /// Copies `bytes` into a new allocation on success. When the caller already
    /// owns a `Vec`, prefer [`try_from_vec`](Self::try_from_vec) to avoid the
    /// extra copy.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectorInputError::Empty`] if `bytes` is empty, or
    /// [`ConnectorInputError::TooLarge`] if it exceeds [`MAX_ITEM_REF_SIZE`].
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, ConnectorInputError> {
        validate_toxic_bytes("ItemRef", bytes, MAX_ITEM_REF_SIZE)?;
        Ok(Self(bytes.to_vec().into_boxed_slice()))
    }

    /// Returns the validated reference bytes.
    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for ItemRef {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl fmt::Debug for ItemRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_toxic_bytes(f, "ItemRef", &self.0)
    }
}

impl fmt::Display for ItemRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_toxic_bytes(f, "ItemRef", &self.0)
    }
}

/// Connector-opaque pagination or resume token.
///
/// Connectors emit a `TokenBytes` value when an enumeration page has more
/// results. The coordinator persists it in the cursor `token` field and hands
/// it back on the next page request. The coordination layer never interprets
/// the contents -- only presence and size are validated at this boundary.
///
/// ## Cursor coupling
///
/// [`MAX_TOKEN_SIZE`] is derived from the coordination cursor `token` limit,
/// so any token that passes validation here is guaranteed to fit in cursor
/// state. A token only has meaning when paired with an [`ItemKey`] (the
/// cursor `last_key`); see [`ConnectorInputError::TokenWithoutLastKey`].
///
/// ## Toxic-byte policy
///
/// `Debug` and `Display` are redacted (length + hash prefix). Raw bytes are
/// accessible only through [`as_bytes`](Self::as_bytes) /
/// [`AsRef<[u8]>`](AsRef).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct TokenBytes(Box<[u8]>);

impl TokenBytes {
    /// Panicking constructor for trusted, already-validated call sites.
    ///
    /// Prefer [`try_from_vec`](Self::try_from_vec) at input boundaries where
    /// the caller cannot guarantee validity.
    ///
    /// # Panics
    ///
    /// Panics if `bytes` is empty or larger than [`MAX_TOKEN_SIZE`].
    #[must_use]
    pub fn from_vec(bytes: Vec<u8>) -> Self {
        Self::try_from_vec(bytes).expect("TokenBytes must be non-empty and within size limits")
    }

    /// Fallible constructor that takes ownership of caller-provided bytes.
    ///
    /// Use this at input boundaries that accept untrusted or external bytes.
    /// Takes ownership of the `Vec` to avoid a copy when validation succeeds.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectorInputError::Empty`] if `bytes` is empty, or
    /// [`ConnectorInputError::TooLarge`] if it exceeds [`MAX_TOKEN_SIZE`].
    pub fn try_from_vec(bytes: Vec<u8>) -> Result<Self, ConnectorInputError> {
        validate_toxic_bytes("TokenBytes", &bytes, MAX_TOKEN_SIZE)?;
        Ok(Self(bytes.into_boxed_slice()))
    }

    /// Fallible constructor from a borrowed slice.
    ///
    /// Copies `bytes` into a new allocation on success. When the caller already
    /// owns a `Vec`, prefer [`try_from_vec`](Self::try_from_vec) to avoid the
    /// extra copy.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectorInputError::Empty`] if `bytes` is empty, or
    /// [`ConnectorInputError::TooLarge`] if it exceeds [`MAX_TOKEN_SIZE`].
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, ConnectorInputError> {
        validate_toxic_bytes("TokenBytes", bytes, MAX_TOKEN_SIZE)?;
        Ok(Self(bytes.to_vec().into_boxed_slice()))
    }

    /// Returns the validated token bytes.
    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for TokenBytes {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl fmt::Debug for TokenBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_toxic_bytes(f, "TokenBytes", &self.0)
    }
}

impl fmt::Display for TokenBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_toxic_bytes(f, "TokenBytes", &self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn constants_align_with_coordination_limits() {
        assert_eq!(MAX_ITEM_KEY_SIZE, MAX_KEY_SIZE);
        assert_eq!(MAX_TOKEN_SIZE, CursorMaxTokenSize);
    }

    #[test]
    fn connector_input_error_display_messages() {
        assert_eq!(
            ConnectorInputError::Empty { field: "ItemKey" }.to_string(),
            "ItemKey must not be empty"
        );
        assert_eq!(
            ConnectorInputError::TooLarge {
                field: "ItemRef",
                size: 9_999,
                max: 10,
            }
            .to_string(),
            "ItemRef too large (9999 bytes, max 10)"
        );
        assert_eq!(
            ConnectorInputError::TokenWithoutLastKey.to_string(),
            "cursor token requires a last_key"
        );
    }

    #[test]
    fn constructors_reject_empty_values() {
        assert_eq!(
            ItemKey::try_from_slice(b""),
            Err(ConnectorInputError::Empty { field: "ItemKey" })
        );
        assert_eq!(
            ItemRef::try_from_slice(b""),
            Err(ConnectorInputError::Empty { field: "ItemRef" })
        );
        assert_eq!(
            TokenBytes::try_from_slice(b""),
            Err(ConnectorInputError::Empty {
                field: "TokenBytes"
            })
        );
    }

    proptest! {
        #![proptest_config(crate::test_util::miri_proptest_config())]

        #[test]
        fn item_key_roundtrips_and_redacts(
            bytes in proptest::collection::vec(any::<u8>(), 1..=MAX_ITEM_KEY_SIZE),
        ) {
            let key = ItemKey::try_from_vec(bytes.clone()).unwrap();
            prop_assert_eq!(key.as_bytes(), &bytes[..]);
            prop_assert_eq!(key.as_ref(), &bytes[..]);

            let dbg = format!("{key:?}");
            let display = format!("{key}");
            let prefix = format!("ItemKey(len={}, hash=", bytes.len());
            prop_assert!(dbg.starts_with(&prefix), "Debug: {}", dbg);
            prop_assert!(display.starts_with(&prefix), "Display: {}", display);

            if bytes.len() >= 8 {
                let raw = String::from_utf8_lossy(&bytes);
                prop_assert!(!dbg.contains(raw.as_ref()), "leaked raw bytes in Debug");
            }

            prop_assert_eq!(dbg, display, "Debug and Display must match");
        }

        #[test]
        fn item_ref_roundtrips_and_redacts(
            bytes in proptest::collection::vec(any::<u8>(), 1..=MAX_ITEM_REF_SIZE),
        ) {
            let item_ref = ItemRef::try_from_vec(bytes.clone()).unwrap();
            prop_assert_eq!(item_ref.as_bytes(), &bytes[..]);
            prop_assert_eq!(item_ref.as_ref(), &bytes[..]);

            let dbg = format!("{item_ref:?}");
            let display = format!("{item_ref}");
            let prefix = format!("ItemRef(len={}, hash=", bytes.len());
            prop_assert!(dbg.starts_with(&prefix), "Debug: {}", dbg);
            prop_assert!(display.starts_with(&prefix), "Display: {}", display);

            if bytes.len() >= 8 {
                let raw = String::from_utf8_lossy(&bytes);
                prop_assert!(!dbg.contains(raw.as_ref()), "leaked raw bytes in Debug");
            }

            prop_assert_eq!(dbg, display);
        }

        #[test]
        fn token_bytes_roundtrips_and_redacts(
            bytes in proptest::collection::vec(any::<u8>(), 1..=MAX_TOKEN_SIZE),
        ) {
            let token = TokenBytes::try_from_vec(bytes.clone()).unwrap();
            prop_assert_eq!(token.as_bytes(), &bytes[..]);
            prop_assert_eq!(token.as_ref(), &bytes[..]);

            let dbg = format!("{token:?}");
            let display = format!("{token}");
            let prefix = format!("TokenBytes(len={}, hash=", bytes.len());
            prop_assert!(dbg.starts_with(&prefix), "Debug: {}", dbg);
            prop_assert!(display.starts_with(&prefix), "Display: {}", display);

            if bytes.len() >= 8 {
                let raw = String::from_utf8_lossy(&bytes);
                prop_assert!(!dbg.contains(raw.as_ref()), "leaked raw bytes in Debug");
            }

            prop_assert_eq!(dbg, display);
        }

        #[test]
        fn item_key_rejects_oversized(
            bytes in proptest::collection::vec(any::<u8>(), (MAX_ITEM_KEY_SIZE + 1)..=(MAX_ITEM_KEY_SIZE + 512)),
        ) {
            prop_assert_eq!(
                ItemKey::try_from_vec(bytes.clone()),
                Err(ConnectorInputError::TooLarge {
                    field: "ItemKey",
                    size: bytes.len(),
                    max: MAX_ITEM_KEY_SIZE,
                })
            );
        }

        #[test]
        fn item_ref_rejects_oversized(
            bytes in proptest::collection::vec(any::<u8>(), (MAX_ITEM_REF_SIZE + 1)..=(MAX_ITEM_REF_SIZE + 512)),
        ) {
            prop_assert_eq!(
                ItemRef::try_from_vec(bytes.clone()),
                Err(ConnectorInputError::TooLarge {
                    field: "ItemRef",
                    size: bytes.len(),
                    max: MAX_ITEM_REF_SIZE,
                })
            );
        }

        #[test]
        fn token_bytes_rejects_oversized(
            bytes in proptest::collection::vec(any::<u8>(), (MAX_TOKEN_SIZE + 1)..=(MAX_TOKEN_SIZE + 512)),
        ) {
            prop_assert_eq!(
                TokenBytes::try_from_vec(bytes.clone()),
                Err(ConnectorInputError::TooLarge {
                    field: "TokenBytes",
                    size: bytes.len(),
                    max: MAX_TOKEN_SIZE,
                })
            );
        }
    }
}
