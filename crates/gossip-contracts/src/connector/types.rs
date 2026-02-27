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
//! ## Additional boundary types
//!
//! - [`Cursor`] owns connector paging state and bridges to borrowed
//!   [`CursorUpdate`] for coordination APIs.
//! - [`VersionId`] records whether a connector's version evidence is strong or
//!   weak while preserving the same [`ObjectVersionId`] representation.
//! - [`ContentHints`] and [`Location`] are bounded metadata carriers for
//!   presentation and downstream routing decisions.
//! - [`ScanItem`] and [`EnumerationPage`] bundle validated boundary fields for
//!   page-oriented connector enumeration handoff.
//! - [`Budgets`] carries scan-level stop conditions (count, bytes, deadline).
//!
//! ## Core contract
//!
//! - Constructors enforce non-empty bytes and hard upper bounds.
//! - Wrappers own bytes (`Box<[u8]>`) so validated values can cross boundaries
//!   without borrowing caller memory.
//! - Formatting is always redacted (`len + short hash prefix`), so logs can be
//!   correlated without leaking payload contents. The hash is a truncated
//!   BLAKE3 digest prefix -- fast and deterministic, but intentionally short for
//!   correlation rather than cryptographic collision guarantees.
//! - `MAX_ITEM_KEY_SIZE` and `MAX_TOKEN_SIZE` intentionally track coordination
//!   cursor limits to keep connector paging contracts aligned.
//!   `MAX_ITEM_REF_SIZE` is independent; it bounds connector-specific handles
//!   that never enter the cursor path.
//! - Cursor states with `token` but no `last_key` are invalid by contract and
//!   rejected when crossing the coordination boundary.

use std::{
    fmt,
    num::{NonZeroU64, NonZeroUsize},
    time::Instant,
};

use crate::coordination::CursorUpdate;
use crate::identity::{ObjectVersionId, StableItemId};

/// Maximum size of an [`ItemKey`] in bytes (4 KiB).
///
/// Kept in lock-step with the coordination cursor `last_key` limit
/// (`coordination::cursor::MAX_KEY_SIZE`) so that every valid connector key
/// can be stored directly in a cursor without truncation. Alignment is
/// verified by the `constants_align_with_coordination_limits` test.
pub const MAX_ITEM_KEY_SIZE: usize = 4_096;

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
/// (`coordination::cursor::MAX_TOKEN_SIZE`, re-exported as
/// `CursorMaxTokenSize`) so that pagination tokens can be persisted in
/// cursor state without size mismatch. Alignment is verified by the
/// `constants_align_with_coordination_limits` test.
pub const MAX_TOKEN_SIZE: usize = 16_384;

/// Maximum size of [`ContentHints::media_type`] in bytes.
const MAX_CONTENT_HINT_MEDIA_TYPE_SIZE: usize = 256;

/// Maximum size of [`ContentHints::encoding`] in bytes.
const MAX_CONTENT_HINT_ENCODING_SIZE: usize = 128;

/// Maximum size of [`Location::display`] in bytes.
pub const MAX_LOCATION_DISPLAY_SIZE: usize = 4_096;

/// Maximum size of [`Location::url`] in bytes.
pub const MAX_LOCATION_URL_SIZE: usize = 4_096;

/// Input validation errors for connector boundary value types.
///
/// This single error surface keeps connector-boundary failures easy to route:
///
/// - [`Empty`](ConnectorInputError::Empty) and
///   [`TooLarge`](ConnectorInputError::TooLarge) capture field validation
///   failures from `ItemKey` / `ItemRef` / `TokenBytes`, and from bounded
///   metadata constructors ([`ContentHints::try_new`], [`Location::try_new`]).
/// - [`TokenWithoutLastKey`](ConnectorInputError::TokenWithoutLastKey)
///   captures a violated paging invariant when converting from coordination's
///   borrowed [`CursorUpdate`] into owned [`Cursor`].
/// - [`ZeroBudget`](ConnectorInputError::ZeroBudget) rejects zero-valued
///   budget fields in [`Budgets::try_new`].
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// Cursor update had `token` without `last_key`.
    TokenWithoutLastKey,
    /// A budget field was zero, which would make the budget vacuous.
    ZeroBudget { field: &'static str },
}

impl fmt::Display for ConnectorInputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty { field } => write!(f, "{field} must not be empty"),
            Self::TooLarge { field, size, max } => {
                write!(f, "{field} too large ({size} bytes, max {max})")
            }
            Self::TokenWithoutLastKey => write!(f, "token must not be present without last_key"),
            Self::ZeroBudget { field } => write!(f, "{field} must be non-zero"),
        }
    }
}

impl std::error::Error for ConnectorInputError {}

/// Returns the first 4 bytes of the BLAKE3 digest of `bytes`.
///
/// Used exclusively by [`fmt_toxic_bytes`], which renders these 4 bytes as
/// 8 lowercase hex characters for log correlation. This provides enough
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

/// Generates a toxic-byte wrapper struct with validated constructors and
/// redacted formatting.
///
/// Two public arms control whether `PartialOrd`/`Ord` are derived:
/// - `ordered $name, max = $max` — includes ordering (for cursor keys).
/// - `$name, max = $max` — unordered (for opaque handles and tokens).
///
/// Both arms produce: struct, `try_from_vec`, `try_from_slice`, `as_bytes`,
/// `len`, `into_bytes`, `AsRef<[u8]>`, and identical `Debug`/`Display`
/// (redacted to `TypeName(len=N, hash=XXXXXXXX..)`).
macro_rules! define_toxic_bytes {
    // Ordered variant (includes PartialOrd, Ord).
    (
        $(#[$meta:meta])*
        ordered $name:ident, max = $max:expr
    ) => {
        define_toxic_bytes!(@internal $(#[$meta])* [Clone, PartialEq, Eq, PartialOrd, Ord, Hash] $name, $max);
    };
    // Unordered variant.
    (
        $(#[$meta:meta])*
        $name:ident, max = $max:expr
    ) => {
        define_toxic_bytes!(@internal $(#[$meta])* [Clone, PartialEq, Eq, Hash] $name, $max);
    };
    // Internal implementation arm — not intended for direct use.
    (@internal $(#[$meta:meta])* [$($derive:ident),+] $name:ident, $max:expr) => {
        $(#[$meta])*
        #[derive($($derive),+)]
        #[allow(clippy::len_without_is_empty)]
        pub struct $name(Box<[u8]>);

        impl $name {
            /// Fallible constructor that takes ownership of caller-provided bytes.
            ///
            /// Use this at input boundaries that accept untrusted or external bytes.
            /// Takes ownership of the `Vec` to avoid a copy when validation succeeds.
            ///
            /// # Errors
            ///
            /// Returns [`ConnectorInputError::Empty`] if `bytes` is empty, or
            /// [`ConnectorInputError::TooLarge`] if it exceeds the type's size limit.
            pub fn try_from_vec(bytes: Vec<u8>) -> Result<Self, ConnectorInputError> {
                validate_toxic_bytes(stringify!($name), &bytes, $max)?;
                Ok(Self(bytes.into_boxed_slice()))
            }

            /// Fallible constructor from a borrowed slice.
            ///
            /// Copies `bytes` into a new allocation on success. When the caller
            /// already owns a `Vec`, prefer [`try_from_vec`](Self::try_from_vec)
            /// to avoid the extra copy.
            ///
            /// # Errors
            ///
            /// Returns [`ConnectorInputError::Empty`] if `bytes` is empty, or
            /// [`ConnectorInputError::TooLarge`] if it exceeds the type's size limit.
            pub fn try_from_slice(bytes: &[u8]) -> Result<Self, ConnectorInputError> {
                validate_toxic_bytes(stringify!($name), bytes, $max)?;
                Ok(Self(bytes.to_vec().into_boxed_slice()))
            }

            /// Returns the validated bytes.
            #[inline]
            #[must_use]
            pub fn as_bytes(&self) -> &[u8] {
                &self.0
            }

            /// Returns the byte length, which is always >= 1 because constructors
            /// reject empty input. `is_empty()` is intentionally absent since it
            /// would unconditionally return `false`.
            #[inline]
            #[must_use]
            pub fn len(&self) -> usize {
                self.0.len()
            }

            /// Consumes the wrapper and returns the owned byte buffer.
            #[inline]
            #[must_use]
            pub fn into_bytes(self) -> Box<[u8]> {
                self.0
            }
        }

        impl AsRef<[u8]> for $name {
            #[inline]
            fn as_ref(&self) -> &[u8] {
                self.as_bytes()
            }
        }

        impl ::core::fmt::Debug for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                fmt_toxic_bytes(f, stringify!($name), &self.0)
            }
        }

        impl ::core::fmt::Display for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                fmt_toxic_bytes(f, stringify!($name), &self.0)
            }
        }
    };
}

define_toxic_bytes! {
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
    /// `Debug` and `Display` are redacted (length + hash prefix). Raw bytes can
    /// be borrowed through [`as_bytes`](Self::as_bytes) / [`AsRef<[u8]>`](AsRef),
    /// or consumed via [`into_bytes`](Self::into_bytes).
    ordered ItemKey, max = MAX_ITEM_KEY_SIZE
}

define_toxic_bytes! {
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
    /// `Debug` and `Display` are redacted (length + hash prefix). Raw bytes can
    /// be borrowed through [`as_bytes`](Self::as_bytes) / [`AsRef<[u8]>`](AsRef),
    /// or consumed via [`into_bytes`](Self::into_bytes).
    ItemRef, max = MAX_ITEM_REF_SIZE
}

define_toxic_bytes! {
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
    /// cursor `last_key`).
    ///
    /// ## Toxic-byte policy
    ///
    /// `Debug` and `Display` are redacted (length + hash prefix). Raw bytes can
    /// be borrowed through [`as_bytes`](Self::as_bytes) / [`AsRef<[u8]>`](AsRef),
    /// or consumed via [`into_bytes`](Self::into_bytes).
    TokenBytes, max = MAX_TOKEN_SIZE
}

/// Owned cursor used across connector boundaries.
///
/// This bridges to/from the coordination layer's borrowed [`CursorUpdate`]
/// without exposing connector internals to coordination callers.
///
/// ## Invariants
///
/// - `token` is only meaningful when paired with a `last_key`.
/// - Constructors make the invalid `(None, Some(token))` state
///   unrepresentable.
/// - [`try_from_update`](Self::try_from_update) validates external cursor
///   updates and rejects token-without-key states via
///   [`ConnectorInputError::TokenWithoutLastKey`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cursor {
    last_key: Option<ItemKey>,
    token: Option<TokenBytes>,
}

impl Cursor {
    /// Initial cursor: no progress key and no resume token.
    ///
    /// This is the neutral state used at scan start and for defensive
    /// normalization when malformed external input is discarded.
    #[inline]
    #[must_use]
    pub fn initial() -> Self {
        Self {
            last_key: None,
            token: None,
        }
    }

    /// Cursor with a `last_key` and no token.
    ///
    /// Use this after processing a page that does not require connector-side
    /// continuation state.
    #[inline]
    #[must_use]
    pub fn with_last_key(last_key: ItemKey) -> Self {
        Self {
            last_key: Some(last_key),
            token: None,
        }
    }

    /// Cursor with both `last_key` and token.
    ///
    /// This represents continuation state for connectors that require an
    /// opaque token in addition to the ordered progress key.
    #[inline]
    #[must_use]
    pub fn with_token(last_key: ItemKey, token: TokenBytes) -> Self {
        Self {
            last_key: Some(last_key),
            token: Some(token),
        }
    }

    /// Returns the last fully processed key, if any.
    #[inline]
    #[must_use]
    pub fn last_key(&self) -> Option<&ItemKey> {
        self.last_key.as_ref()
    }

    /// Returns the connector-opaque resume token, if any.
    ///
    /// `Some` implies [`last_key`](Self::last_key) is also `Some`.
    #[inline]
    #[must_use]
    pub fn token(&self) -> Option<&TokenBytes> {
        self.token.as_ref()
    }

    /// Borrow this owned cursor as a coordination [`CursorUpdate`].
    ///
    /// This projection is allocation-free. The returned update borrows from
    /// `self` and remains valid for the same lifetime.
    ///
    /// The `(None, Some(_))` state is unreachable because all constructors
    /// prevent token-without-key. If reached, this panics to surface the
    /// logic error rather than silently resetting cursor progress.
    #[inline]
    #[must_use]
    pub fn as_update(&self) -> CursorUpdate<'_> {
        match (&self.last_key, &self.token) {
            (None, None) => CursorUpdate::initial(),
            (Some(last_key), None) => CursorUpdate::with_last_key(last_key.as_bytes()),
            (Some(last_key), Some(token)) => {
                CursorUpdate::with_token(last_key.as_bytes(), token.as_bytes())
            }
            (None, Some(_)) => unreachable!(
                "Cursor invariant violated: token present without last_key. \
                 All constructors prevent this state."
            ),
        }
    }

    /// Copy from a borrowed coordination cursor update.
    ///
    /// Empty token values normalize to `None` so caller behavior does not
    /// depend on whether a connector emits "no token" as `None` or `Some([])`.
    ///
    /// # Errors
    ///
    /// - Returns [`ConnectorInputError::TokenWithoutLastKey`] if a non-empty
    ///   `token` is present but `last_key` is not.
    /// - Returns [`ConnectorInputError::Empty`] / [`ConnectorInputError::TooLarge`]
    ///   when `last_key` or `token` fail wrapper validation.
    pub fn try_from_update(update: CursorUpdate<'_>) -> Result<Self, ConnectorInputError> {
        let last_key = match update.last_key() {
            None => None,
            Some(last_key) => Some(ItemKey::try_from_slice(last_key)?),
        };
        let token = match update.token() {
            None => None,
            Some([]) => None,
            Some(token) => Some(TokenBytes::try_from_slice(token)?),
        };
        if last_key.is_none() && token.is_some() {
            return Err(ConnectorInputError::TokenWithoutLastKey);
        }
        Ok(Self { last_key, token })
    }
}

impl Default for Cursor {
    fn default() -> Self {
        Self::initial()
    }
}

/// Version claim strength for an item's content identity.
///
/// Connectors often have both a 32-byte derived content identifier and
/// additional semantics about how trustworthy that identifier is as an
/// immutability signal. `VersionId` keeps both pieces together:
///
/// - variant (`Strong` vs `Weak`) communicates confidence semantics;
/// - payload ([`ObjectVersionId`]) keeps the hashing/derivation surface stable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum VersionId {
    /// Strong version identity that should reliably reference immutable content.
    Strong(ObjectVersionId),
    /// Weak version identity where content may change without version changes.
    Weak(ObjectVersionId),
}

impl VersionId {
    /// Returns the wrapped [`ObjectVersionId`] regardless of claim strength.
    ///
    /// This allows downstream code to derive occurrence identities without
    /// branching on strength semantics.
    #[inline]
    #[must_use]
    pub const fn object_version_id(self) -> ObjectVersionId {
        match self {
            Self::Strong(version_id) | Self::Weak(version_id) => version_id,
        }
    }

    /// Returns whether this is a strong version identity.
    ///
    /// Callers can use this to gate trust-sensitive behavior (for example,
    /// deciding whether to treat unchanged version IDs as a strong no-change
    /// signal).
    #[inline]
    #[must_use]
    pub const fn is_strong(self) -> bool {
        matches!(self, Self::Strong(_))
    }
}

/// Optional hints about how to interpret item content.
///
/// These fields are intentionally advisory. The contracts layer enforces only
/// byte-size bounds, not MIME/encoding grammar, so connector implementations
/// can forward source-native metadata without lossy normalization.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ContentHints {
    media_type: Option<String>,
    encoding: Option<String>,
}

impl ContentHints {
    /// Construct bounded content hints.
    ///
    /// Empty strings are normalized to `None` so callers cannot observe a
    /// semantic difference between "not provided" and "provided but empty".
    ///
    /// # Errors
    ///
    /// Returns [`ConnectorInputError::TooLarge`] when:
    ///
    /// - `media_type` exceeds `MAX_CONTENT_HINT_MEDIA_TYPE_SIZE`
    /// - `encoding` exceeds `MAX_CONTENT_HINT_ENCODING_SIZE`
    pub fn try_new(
        media_type: Option<String>,
        encoding: Option<String>,
    ) -> Result<Self, ConnectorInputError> {
        // Normalize empty strings to None before validation.
        let media_type = media_type.filter(|s| !s.is_empty());
        let encoding = encoding.filter(|s| !s.is_empty());

        if let Some(media_type) = media_type.as_ref()
            && media_type.len() > MAX_CONTENT_HINT_MEDIA_TYPE_SIZE
        {
            return Err(ConnectorInputError::TooLarge {
                field: "ContentHints.media_type",
                size: media_type.len(),
                max: MAX_CONTENT_HINT_MEDIA_TYPE_SIZE,
            });
        }
        if let Some(encoding) = encoding.as_ref()
            && encoding.len() > MAX_CONTENT_HINT_ENCODING_SIZE
        {
            return Err(ConnectorInputError::TooLarge {
                field: "ContentHints.encoding",
                size: encoding.len(),
                max: MAX_CONTENT_HINT_ENCODING_SIZE,
            });
        }
        Ok(Self {
            media_type,
            encoding,
        })
    }

    /// Returns the MIME-like media type, if known.
    ///
    /// `None` means "unknown" — empty strings are normalized away by the
    /// constructor.
    #[inline]
    #[must_use]
    pub fn media_type(&self) -> Option<&str> {
        self.media_type.as_deref()
    }

    /// Returns the transfer/content encoding name, if known.
    ///
    /// `None` means no encoding hint is available.
    #[inline]
    #[must_use]
    pub fn encoding(&self) -> Option<&str> {
        self.encoding.as_deref()
    }
}

/// Display-safe location metadata for UI/debugging.
///
/// `Location` gives consumers a bounded, human-readable reference they can
/// safely surface in logs and UI without requiring raw connector internals.
/// `url` is optional and size-bounded, but intentionally not parsed or
/// canonicalized at this layer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Location {
    display: String,
    url: Option<String>,
}

impl Location {
    /// Construct a bounded display location.
    ///
    /// `display` is required because it is the stable fallback shown when
    /// no `url` is available or safe to render. Empty URL strings are
    /// normalized to `None` so callers cannot observe a semantic difference
    /// between "not provided" and "provided but empty".
    ///
    /// # Errors
    ///
    /// - [`ConnectorInputError::Empty`] when `display` is empty.
    /// - [`ConnectorInputError::TooLarge`] when `display` or `url` exceeds
    ///   the corresponding `MAX_LOCATION_*` limits.
    pub fn try_new(display: String, url: Option<String>) -> Result<Self, ConnectorInputError> {
        let url = url.filter(|u| !u.is_empty());
        if display.is_empty() {
            return Err(ConnectorInputError::Empty {
                field: "Location.display",
            });
        }
        if display.len() > MAX_LOCATION_DISPLAY_SIZE {
            return Err(ConnectorInputError::TooLarge {
                field: "Location.display",
                size: display.len(),
                max: MAX_LOCATION_DISPLAY_SIZE,
            });
        }
        if let Some(url) = url.as_ref()
            && url.len() > MAX_LOCATION_URL_SIZE
        {
            return Err(ConnectorInputError::TooLarge {
                field: "Location.url",
                size: url.len(),
                max: MAX_LOCATION_URL_SIZE,
            });
        }
        Ok(Self { display, url })
    }

    /// Returns the human-readable location string.
    #[inline]
    #[must_use]
    pub fn display(&self) -> &str {
        &self.display
    }

    /// Returns the optional URL-like deep link.
    #[inline]
    #[must_use]
    pub fn url(&self) -> Option<&str> {
        self.url.as_deref()
    }
}

/// Connector-owned item metadata produced by an enumeration pass.
///
/// `ScanItem` keeps core identity fields (`item_key`, `item_ref`,
/// `stable_item_id`, `version`) alongside optional bounded metadata used for
/// presentation and scheduling (`size_hint`, `content_hints`, `location`).
///
/// Optional fields default to `None` and can be set with builder-style methods
/// after constructing the required identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanItem {
    item_key: ItemKey,
    item_ref: ItemRef,
    stable_item_id: StableItemId,
    version: VersionId,
    size_hint: Option<u64>,
    content_hints: Option<ContentHints>,
    location: Option<Location>,
}

impl ScanItem {
    /// Construct a scan item with required identity fields.
    ///
    /// Optional metadata fields initialize to `None`.
    #[must_use]
    pub fn new(
        item_key: ItemKey,
        item_ref: ItemRef,
        stable_item_id: StableItemId,
        version: VersionId,
    ) -> Self {
        Self {
            item_key,
            item_ref,
            stable_item_id,
            version,
            size_hint: None,
            content_hints: None,
            location: None,
        }
    }

    /// Set the optional size hint in bytes.
    #[must_use]
    pub fn with_size_hint(self, size_hint: u64) -> Self {
        Self {
            size_hint: Some(size_hint),
            ..self
        }
    }

    /// Set optional content hints.
    #[must_use]
    pub fn with_content_hints(self, content_hints: ContentHints) -> Self {
        Self {
            content_hints: Some(content_hints),
            ..self
        }
    }

    /// Set optional display-safe location metadata.
    #[must_use]
    pub fn with_location(self, location: Location) -> Self {
        Self {
            location: Some(location),
            ..self
        }
    }

    /// Returns the ordered item key used for paging progression.
    #[inline]
    #[must_use]
    pub fn item_key(&self) -> &ItemKey {
        &self.item_key
    }

    /// Returns the connector-opaque item reference used for later reads.
    #[inline]
    #[must_use]
    pub fn item_ref(&self) -> &ItemRef {
        &self.item_ref
    }

    /// Returns the stable tenant-independent item identity.
    #[inline]
    #[must_use]
    pub fn stable_item_id(&self) -> StableItemId {
        self.stable_item_id
    }

    /// Returns connector-provided version semantics for this item.
    #[inline]
    #[must_use]
    pub fn version(&self) -> VersionId {
        self.version
    }

    /// Returns an optional byte-size estimate for this item.
    #[inline]
    #[must_use]
    pub fn size_hint(&self) -> Option<u64> {
        self.size_hint
    }

    /// Returns optional content interpretation hints.
    #[inline]
    #[must_use]
    pub fn content_hints(&self) -> Option<&ContentHints> {
        self.content_hints.as_ref()
    }

    /// Returns optional display-safe location metadata.
    #[inline]
    #[must_use]
    pub fn location(&self) -> Option<&Location> {
        self.location.as_ref()
    }

    /// Consume this scan item, returning its ordered key for cursor advancement.
    #[inline]
    #[must_use]
    pub fn into_item_key(self) -> ItemKey {
        self.item_key
    }

    /// Consume the scan item, returning all fields as owned values.
    ///
    /// Use this when you need owned access to multiple fields without cloning.
    /// The tuple order matches the struct field declaration:
    /// `(item_key, item_ref, stable_item_id, version, size_hint,
    /// content_hints, location)`.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        ItemKey,
        ItemRef,
        StableItemId,
        VersionId,
        Option<u64>,
        Option<ContentHints>,
        Option<Location>,
    ) {
        (
            self.item_key,
            self.item_ref,
            self.stable_item_id,
            self.version,
            self.size_hint,
            self.content_hints,
            self.location,
        )
    }
}

/// A connector enumeration page and continuation cursor.
///
/// `items` are the scan results for the current page. `next_cursor` encodes
/// where to resume, including connector token state when present.
///
/// ## Empty-page semantics
///
/// An empty `items` slice is valid and its meaning depends on the cursor:
///
/// - Empty items + [`Cursor::initial()`] → scan is complete (no more data).
/// - Empty items + non-initial cursor → no results in the current range,
///   but more data may exist beyond the cursor position.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnumerationPage {
    items: Vec<ScanItem>,
    next_cursor: Cursor,
}

impl EnumerationPage {
    /// Construct a page from scan items and the continuation cursor.
    #[inline]
    #[must_use]
    pub fn new(items: Vec<ScanItem>, next_cursor: Cursor) -> Self {
        Self { items, next_cursor }
    }

    /// Returns the current page items.
    #[inline]
    #[must_use]
    pub fn items(&self) -> &[ScanItem] {
        &self.items
    }

    /// Returns the cursor to use for the next page request.
    #[inline]
    #[must_use]
    pub fn next_cursor(&self) -> &Cursor {
        &self.next_cursor
    }

    /// Consume the page, returning owned items and the continuation cursor.
    ///
    /// Use this when you need to process the items and cursor separately
    /// without borrowing from the page.
    #[must_use]
    pub fn into_parts(self) -> (Vec<ScanItem>, Cursor) {
        (self.items, self.next_cursor)
    }
}

/// Page/scan budget controls used by connector enumeration APIs.
///
/// `Budgets` combines up to three stop conditions:
/// - `max_items`: upper bound on number of returned items.
/// - `max_bytes`: upper bound on cumulative bytes consumed.
/// - `deadline`: optional monotonic deadline (`Instant`).
///
/// `max_items` and `max_bytes` are stored as [`NonZeroUsize`] and
/// [`NonZeroU64`] respectively so that a vacuous zero budget is
/// unrepresentable. Use [`try_new`](Self::try_new) to construct.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Budgets {
    max_items: NonZeroUsize,
    max_bytes: NonZeroU64,
    deadline: Option<Instant>,
}

impl Budgets {
    /// Construct a validated set of scan budgets.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectorInputError::ZeroBudget`] when `max_items` or
    /// `max_bytes` is zero.
    #[inline]
    pub fn try_new(
        max_items: usize,
        max_bytes: u64,
        deadline: Option<Instant>,
    ) -> Result<Self, ConnectorInputError> {
        let max_items = NonZeroUsize::new(max_items).ok_or(ConnectorInputError::ZeroBudget {
            field: "Budgets.max_items",
        })?;
        let max_bytes = NonZeroU64::new(max_bytes).ok_or(ConnectorInputError::ZeroBudget {
            field: "Budgets.max_bytes",
        })?;
        Ok(Self {
            max_items,
            max_bytes,
            deadline,
        })
    }

    /// Returns the maximum number of items allowed for the scan/page.
    #[inline]
    #[must_use]
    pub fn max_items(&self) -> usize {
        self.max_items.get()
    }

    /// Returns the maximum number of bytes allowed for the scan/page.
    #[inline]
    #[must_use]
    pub fn max_bytes(&self) -> u64 {
        self.max_bytes.get()
    }

    /// Returns the optional scan deadline.
    #[inline]
    #[must_use]
    pub fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    /// Returns `true` when the configured deadline has elapsed relative to
    /// `now`. Returns `false` when no deadline is set.
    ///
    /// Accepting the current instant as a parameter keeps this function pure
    /// and deterministic, which is required for simulation testing.
    #[inline]
    #[must_use]
    pub fn is_expired_at(&self, now: Instant) -> bool {
        self.deadline.is_some_and(|deadline| now >= deadline)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn constants_align_with_coordination_limits() {
        use crate::coordination::{CursorMaxTokenSize, MAX_KEY_SIZE};
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
            "token must not be present without last_key"
        );
        assert_eq!(
            ConnectorInputError::ZeroBudget {
                field: "Budgets.max_items"
            }
            .to_string(),
            "Budgets.max_items must be non-zero"
        );
    }

    #[test]
    fn cursor_initial_has_no_key_or_token() {
        let cursor = Cursor::initial();
        assert!(cursor.last_key().is_none());
        assert!(cursor.token().is_none());
        assert_eq!(cursor, Cursor::default());

        let update = cursor.as_update();
        assert!(update.last_key().is_none());
        assert!(update.token().is_none());
    }

    #[test]
    fn cursor_with_token_roundtrips_through_update() {
        let key = ItemKey::try_from_slice(b"k-1").unwrap();
        let token = TokenBytes::try_from_slice(b"tok-1").unwrap();
        let cursor = Cursor::with_token(key, token);

        let update = cursor.as_update();
        assert_eq!(update.last_key(), Some(b"k-1".as_slice()));
        assert_eq!(update.token(), Some(b"tok-1".as_slice()));

        let reparsed = Cursor::try_from_update(update).unwrap();
        assert_eq!(reparsed, cursor);
    }

    #[test]
    fn cursor_with_last_key_roundtrips_through_update() {
        let key = ItemKey::try_from_slice(b"k-1").unwrap();
        let cursor = Cursor::with_last_key(key);

        assert!(cursor.last_key().is_some());
        assert!(cursor.token().is_none());

        let update = cursor.as_update();
        assert_eq!(update.last_key(), Some(b"k-1".as_slice()));
        assert!(update.token().is_none());

        let reparsed = Cursor::try_from_update(update).unwrap();
        assert_eq!(reparsed, cursor);
    }

    #[test]
    fn cursor_try_from_update_rejects_token_without_last_key() {
        let invalid = crate::coordination::cursor::CursorUpdate::from_raw_parts_for_test(
            None,
            Some(b"tok-1"),
        );
        assert_eq!(
            Cursor::try_from_update(invalid),
            Err(ConnectorInputError::TokenWithoutLastKey)
        );
    }

    #[test]
    fn cursor_try_from_update_normalizes_empty_token_to_none() {
        let update = crate::coordination::cursor::CursorUpdate::from_raw_parts_for_test(
            Some(b"k-1"),
            Some(b""),
        );
        let cursor = Cursor::try_from_update(update).unwrap();
        assert_eq!(cursor.last_key().unwrap().as_bytes(), b"k-1");
        assert!(cursor.token().is_none());
    }

    #[test]
    fn version_id_helpers_work() {
        let object_version = ObjectVersionId::from_version_bytes(b"v1");
        let strong = VersionId::Strong(object_version);
        let weak = VersionId::Weak(object_version);
        assert!(strong.is_strong());
        assert!(!weak.is_strong());
        assert_eq!(strong.object_version_id(), object_version);
        assert_eq!(weak.object_version_id(), object_version);
    }

    #[test]
    fn content_hints_normalizes_empty_strings_to_none() {
        let hints = ContentHints::try_new(Some(String::new()), Some(String::new())).unwrap();
        assert_eq!(hints.media_type(), None);
        assert_eq!(hints.encoding(), None);

        let hints =
            ContentHints::try_new(Some("text/plain".to_owned()), Some(String::new())).unwrap();
        assert_eq!(hints.media_type(), Some("text/plain"));
        assert_eq!(hints.encoding(), None);
    }

    #[test]
    fn content_hints_accessors_return_values() {
        let hints =
            ContentHints::try_new(Some("application/json".to_owned()), Some("gzip".to_owned()))
                .unwrap();
        assert_eq!(hints.media_type(), Some("application/json"));
        assert_eq!(hints.encoding(), Some("gzip"));

        let empty = ContentHints::default();
        assert_eq!(empty.media_type(), None);
        assert_eq!(empty.encoding(), None);
    }

    #[test]
    fn content_hints_enforce_size_limits() {
        assert!(ContentHints::try_new(Some("text/plain".to_owned()), None).is_ok());
        assert!(ContentHints::try_new(None, Some("gzip".to_owned())).is_ok());
        assert_eq!(
            ContentHints::try_new(Some("a".repeat(257)), None),
            Err(ConnectorInputError::TooLarge {
                field: "ContentHints.media_type",
                size: 257,
                max: 256,
            })
        );
        assert_eq!(
            ContentHints::try_new(None, Some("a".repeat(129))),
            Err(ConnectorInputError::TooLarge {
                field: "ContentHints.encoding",
                size: 129,
                max: 128,
            })
        );
    }

    #[test]
    fn location_normalizes_empty_url_to_none() {
        let loc = Location::try_new("ok".to_owned(), Some(String::new())).unwrap();
        assert_eq!(loc.display(), "ok");
        assert_eq!(loc.url(), None);
    }

    #[test]
    fn location_validates_required_and_size_limited_fields() {
        assert_eq!(
            Location::try_new(String::new(), None),
            Err(ConnectorInputError::Empty {
                field: "Location.display",
            })
        );
        assert_eq!(
            Location::try_new("x".repeat(MAX_LOCATION_DISPLAY_SIZE + 1), None),
            Err(ConnectorInputError::TooLarge {
                field: "Location.display",
                size: MAX_LOCATION_DISPLAY_SIZE + 1,
                max: MAX_LOCATION_DISPLAY_SIZE,
            })
        );
        assert_eq!(
            Location::try_new("ok".to_owned(), Some("u".repeat(MAX_LOCATION_URL_SIZE + 1))),
            Err(ConnectorInputError::TooLarge {
                field: "Location.url",
                size: MAX_LOCATION_URL_SIZE + 1,
                max: MAX_LOCATION_URL_SIZE,
            })
        );

        let loc = Location::try_new(
            "repo/path".to_owned(),
            Some("https://example.com".to_owned()),
        )
        .unwrap();
        assert_eq!(loc.display(), "repo/path");
        assert_eq!(loc.url(), Some("https://example.com"));
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

    #[test]
    fn item_key_lexicographic_ordering() {
        let a = ItemKey::try_from_vec(vec![0x00]).unwrap();
        let b = ItemKey::try_from_vec(vec![0x00, 0x01]).unwrap();
        let c = ItemKey::try_from_vec(vec![0x01]).unwrap();
        let d = ItemKey::try_from_vec(vec![0xFF]).unwrap();

        assert!(a < b, "prefix sorts before longer extension");
        assert!(b < c, "[0x00,0x01] sorts before [0x01]");
        assert!(c < d);
        assert_eq!(a.cmp(&a), std::cmp::Ordering::Equal);
    }

    #[test]
    fn boundary_exact_sizes() {
        // 1-byte (minimum valid).
        assert!(ItemKey::try_from_slice(&[0xAB]).is_ok());
        assert!(ItemRef::try_from_slice(&[0xAB]).is_ok());
        assert!(TokenBytes::try_from_slice(&[0xAB]).is_ok());

        // Exactly MAX (maximum valid).
        assert!(ItemKey::try_from_vec(vec![0x42; MAX_ITEM_KEY_SIZE]).is_ok());
        assert!(ItemRef::try_from_vec(vec![0x42; MAX_ITEM_REF_SIZE]).is_ok());
        assert!(TokenBytes::try_from_vec(vec![0x42; MAX_TOKEN_SIZE]).is_ok());

        // Exactly MAX+1 (minimum invalid).
        assert!(ItemKey::try_from_vec(vec![0x42; MAX_ITEM_KEY_SIZE + 1]).is_err());
        assert!(ItemRef::try_from_vec(vec![0x42; MAX_ITEM_REF_SIZE + 1]).is_err());
        assert!(TokenBytes::try_from_vec(vec![0x42; MAX_TOKEN_SIZE + 1]).is_err());
    }

    #[test]
    fn try_from_slice_roundtrips() {
        let data = b"hello-world";
        assert_eq!(ItemKey::try_from_slice(data).unwrap().as_bytes(), data);
        assert_eq!(ItemRef::try_from_slice(data).unwrap().as_bytes(), data);
        assert_eq!(TokenBytes::try_from_slice(data).unwrap().as_bytes(), data);
    }

    #[test]
    fn format_output_is_deterministic() {
        let key = ItemKey::try_from_vec(vec![0xDE, 0xAD, 0xBE, 0xEF]).unwrap();
        let output = format!("{key}");
        let hash = blake3::hash(&[0xDE, 0xAD, 0xBE, 0xEF]);
        let b = hash.as_bytes();
        let expected = format!(
            "ItemKey(len=4, hash={:02x}{:02x}{:02x}{:02x}..)",
            b[0], b[1], b[2], b[3]
        );
        assert_eq!(output, expected);
    }

    #[test]
    fn scan_item_new_defaults_optional_fields_to_none() {
        let scan_item = ScanItem::new(
            ItemKey::try_from_slice(b"item-key").unwrap(),
            ItemRef::try_from_slice(b"item-ref").unwrap(),
            StableItemId::from_bytes([0x11; 32]),
            VersionId::Strong(ObjectVersionId::from_version_bytes(b"v1")),
        );

        assert_eq!(scan_item.item_key().as_bytes(), b"item-key");
        assert_eq!(scan_item.item_ref().as_bytes(), b"item-ref");
        assert_eq!(
            scan_item.stable_item_id(),
            StableItemId::from_bytes([0x11; 32])
        );
        assert_eq!(
            scan_item.version(),
            VersionId::Strong(ObjectVersionId::from_version_bytes(b"v1"))
        );
        assert_eq!(scan_item.size_hint(), None);
        assert_eq!(scan_item.content_hints(), None);
        assert_eq!(scan_item.location(), None);
    }

    #[test]
    fn scan_item_builder_methods_chain() {
        let content_hints =
            ContentHints::try_new(Some("text/plain".to_owned()), Some("gzip".to_owned())).unwrap();
        let location = Location::try_new(
            "repo/path.txt".to_owned(),
            Some("https://example.invalid/path.txt".to_owned()),
        )
        .unwrap();
        let scan_item = ScanItem::new(
            ItemKey::try_from_slice(b"item-key-2").unwrap(),
            ItemRef::try_from_slice(b"item-ref-2").unwrap(),
            StableItemId::from_bytes([0x22; 32]),
            VersionId::Weak(ObjectVersionId::from_version_bytes(b"v2")),
        )
        .with_size_hint(4_096)
        .with_content_hints(content_hints.clone())
        .with_location(location.clone());

        assert_eq!(scan_item.size_hint(), Some(4_096));
        assert_eq!(scan_item.content_hints(), Some(&content_hints));
        assert_eq!(scan_item.location(), Some(&location));
    }

    #[test]
    fn enumeration_page_new_stores_items_and_cursor() {
        let scan_item = ScanItem::new(
            ItemKey::try_from_slice(b"item-key-3").unwrap(),
            ItemRef::try_from_slice(b"item-ref-3").unwrap(),
            StableItemId::from_bytes([0x33; 32]),
            VersionId::Strong(ObjectVersionId::from_version_bytes(b"v3")),
        );
        let next_cursor = Cursor::with_token(
            ItemKey::try_from_slice(b"next-key").unwrap(),
            TokenBytes::try_from_slice(b"next-token").unwrap(),
        );

        let page = EnumerationPage::new(vec![scan_item.clone()], next_cursor.clone());
        assert_eq!(page.items(), &[scan_item]);
        assert_eq!(page.next_cursor(), &next_cursor);
    }

    #[test]
    fn budgets_try_new_rejects_zero_items() {
        assert_eq!(
            Budgets::try_new(0, 1_024, None),
            Err(ConnectorInputError::ZeroBudget {
                field: "Budgets.max_items",
            })
        );
    }

    #[test]
    fn budgets_try_new_rejects_zero_bytes() {
        assert_eq!(
            Budgets::try_new(10, 0, None),
            Err(ConnectorInputError::ZeroBudget {
                field: "Budgets.max_bytes",
            })
        );
    }

    #[test]
    fn scan_item_into_parts_returns_owned_fields() {
        let content_hints = ContentHints::try_new(Some("text/plain".to_owned()), None).unwrap();
        let location = Location::try_new("repo/path.txt".to_owned(), None).unwrap();
        let item = ScanItem::new(
            ItemKey::try_from_slice(b"k").unwrap(),
            ItemRef::try_from_slice(b"r").unwrap(),
            StableItemId::from_bytes([0xAA; 32]),
            VersionId::Strong(ObjectVersionId::from_version_bytes(b"v1")),
        )
        .with_size_hint(42)
        .with_content_hints(content_hints.clone())
        .with_location(location.clone());

        let (key, iref, sid, ver, sz, ch, loc) = item.into_parts();
        assert_eq!(key.as_bytes(), b"k");
        assert_eq!(iref.as_bytes(), b"r");
        assert_eq!(sid, StableItemId::from_bytes([0xAA; 32]));
        assert_eq!(
            ver,
            VersionId::Strong(ObjectVersionId::from_version_bytes(b"v1"))
        );
        assert_eq!(sz, Some(42));
        assert_eq!(ch.as_ref(), Some(&content_hints));
        assert_eq!(loc.as_ref(), Some(&location));
    }

    #[test]
    fn enumeration_page_into_parts_returns_owned_fields() {
        let item = ScanItem::new(
            ItemKey::try_from_slice(b"k").unwrap(),
            ItemRef::try_from_slice(b"r").unwrap(),
            StableItemId::from_bytes([0xBB; 32]),
            VersionId::Weak(ObjectVersionId::from_version_bytes(b"v2")),
        );
        let cursor = Cursor::with_last_key(ItemKey::try_from_slice(b"next").unwrap());
        let page = EnumerationPage::new(vec![item.clone()], cursor.clone());

        let (items, next) = page.into_parts();
        assert_eq!(items, vec![item]);
        assert_eq!(next, cursor);
    }

    #[test]
    fn enumeration_page_empty_is_valid() {
        let page = EnumerationPage::new(vec![], Cursor::initial());
        assert!(page.items().is_empty());
        assert_eq!(page.next_cursor(), &Cursor::initial());
    }

    #[test]
    fn budgets_is_expired_at_respects_deadline() {
        use std::time::Duration;

        let anchor = Instant::now();

        let none = Budgets::try_new(10, 1_024, None).unwrap();
        assert_eq!(none.max_items(), 10);
        assert_eq!(none.max_bytes(), 1_024);
        assert_eq!(none.deadline(), None);
        assert!(!none.is_expired_at(anchor));

        let deadline = anchor + Duration::from_secs(30);
        let future = Budgets::try_new(10, 1_024, Some(deadline)).unwrap();
        assert!(!future.is_expired_at(anchor));
        assert!(future.is_expired_at(deadline));
        assert!(future.is_expired_at(deadline + Duration::from_secs(1)));

        let past_deadline = anchor.checked_sub(Duration::from_secs(1)).unwrap_or(anchor);
        let past = Budgets::try_new(10, 1_024, Some(past_deadline)).unwrap();
        assert!(past.is_expired_at(anchor));

        let boundary = Budgets::try_new(10, 1_024, Some(anchor)).unwrap();
        assert!(boundary.is_expired_at(anchor));
    }

    /// Generates roundtrip + redaction and oversized-rejection proptests for
    /// a toxic-byte wrapper type.
    macro_rules! toxic_bytes_tests {
        (
            type = $ty:ident, max = $max:expr,
            roundtrip_test = $rt:ident,
            oversized_test = $ov:ident $(,)?
        ) => {
            proptest! {
                #![proptest_config(crate::test_util::miri_proptest_config())]

                #[test]
                fn $rt(
                    bytes in proptest::collection::vec(any::<u8>(), 1..=$max),
                ) {
                    let val = $ty::try_from_vec(bytes.clone()).unwrap();
                    prop_assert_eq!(val.as_bytes(), &bytes[..]);
                    prop_assert_eq!(val.as_ref(), &bytes[..]);

                    let dbg = format!("{val:?}");
                    let display = format!("{val}");
                    let prefix = format!(
                        concat!(stringify!($ty), "(len={}, hash="),
                        bytes.len(),
                    );
                    prop_assert!(dbg.starts_with(&prefix), "Debug: {}", dbg);
                    prop_assert!(display.starts_with(&prefix), "Display: {}", display);

                    if bytes.len() >= 8 {
                        let raw = String::from_utf8_lossy(&bytes);
                        prop_assert!(
                            !dbg.contains(raw.as_ref()),
                            "leaked raw bytes in Debug",
                        );
                    }

                    prop_assert_eq!(dbg, display, "Debug and Display must match");
                }

                #[test]
                fn $ov(
                    bytes in proptest::collection::vec(
                        any::<u8>(),
                        ($max + 1)..=($max + 512),
                    ),
                ) {
                    prop_assert_eq!(
                        $ty::try_from_vec(bytes.clone()),
                        Err(ConnectorInputError::TooLarge {
                            field: stringify!($ty),
                            size: bytes.len(),
                            max: $max,
                        })
                    );
                }
            }
        };
    }

    /// Generates a valid `Cursor` from one of three variants: initial,
    /// key-only, or key + token.
    fn arb_cursor() -> impl Strategy<Value = Cursor> {
        prop_oneof![
            Just(Cursor::initial()),
            proptest::collection::vec(any::<u8>(), 1..=64)
                .prop_map(|b| Cursor::with_last_key(ItemKey::try_from_vec(b).unwrap())),
            (
                proptest::collection::vec(any::<u8>(), 1..=64),
                proptest::collection::vec(any::<u8>(), 1..=64),
            )
                .prop_map(|(k, t)| Cursor::with_token(
                    ItemKey::try_from_vec(k).unwrap(),
                    TokenBytes::try_from_vec(t).unwrap(),
                )),
        ]
    }

    proptest! {
        #![proptest_config(crate::test_util::miri_proptest_config())]

        #[test]
        fn cursor_roundtrips_through_update(cursor in arb_cursor()) {
            let update = cursor.as_update();
            let reparsed = Cursor::try_from_update(update).unwrap();
            prop_assert_eq!(reparsed, cursor);
        }
    }

    toxic_bytes_tests! {
        type = ItemKey, max = MAX_ITEM_KEY_SIZE,
        roundtrip_test = item_key_roundtrips_and_redacts,
        oversized_test = item_key_rejects_oversized,
    }

    toxic_bytes_tests! {
        type = ItemRef, max = MAX_ITEM_REF_SIZE,
        roundtrip_test = item_ref_roundtrips_and_redacts,
        oversized_test = item_ref_rejects_oversized,
    }

    toxic_bytes_tests! {
        type = TokenBytes, max = MAX_TOKEN_SIZE,
        roundtrip_test = token_bytes_roundtrips_and_redacts,
        oversized_test = token_bytes_rejects_oversized,
    }
}
