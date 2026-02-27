//! Connector operation error taxonomy, capability negotiation, and runtime trait contracts.
//!
//! These types model connector operation outcomes **after** boundary validation
//! has succeeded. Input-shape and size failures use
//! [`ConnectorInputError`](crate::connector::ConnectorInputError) in
//! the sibling [`types`](super::types) module.
//!
//! ## Surface overview
//!
//! | Type | Role |
//! |------|------|
//! | [`ErrorClass`] | Binary retry posture: `Retryable` vs `Permanent` |
//! | [`EnumerateError`] | Failure from enumeration/listing connector operations |
//! | [`ReadError`] | Failure from item read/open connector operations |
//! | [`ConnectorCapabilities`] | Feature-flag struct advertising optional connector abilities |
//! | [`EnumerationConnector`] | Runtime contract for enumeration operations |
//! | [`ReadConnector`] | Runtime contract for read/open operations |
//! | [`ConnectorInstance`] | Convenience supertrait (`EnumerationConnector + ReadConnector`) |
//!
//! ## Trait defaults and capability signaling
//!
//! The connector traits expose optional hooks with conservative defaults:
//!
//! - [`EnumerationConnector::choose_split_point`] defaults to `Ok(None)`.
//!   Keep this default when the connector cannot provide reliable split hints,
//!   and advertise `ConnectorCapabilities { split_hints: false, .. }`.
//! - [`ReadConnector::read_range`] defaults to
//!   `Err(ReadError::unsupported("range_read"))`.
//!   Keep this default unless the connector truly supports random-access reads,
//!   and advertise `ConnectorCapabilities { range_read: true, .. }` only when
//!   the method is implemented.
//!
//! ## Why two structurally identical error types?
//!
//! [`EnumerateError`] and [`ReadError`] carry the same three fields but are
//! distinct types. This is intentional: enumeration and reading are modeled as
//! separate operations with independent scaling characteristics (metadata-bound
//! vs bandwidth-bound). Keeping their error types distinct means:
//!
//! - Public signatures are unambiguous about which operation failed.
//! - Orchestration can apply different retry/circuit-breaker policies per
//!   operation without downcasting or tag-matching.
//! - The compiler prevents accidental cross-assignment between the two paths.
//!
//! ## Boundary notes
//!
//! - `retry_after_ms` is advisory backoff metadata, not a scheduler contract.
//!   The runtime may enforce stricter global policies regardless of connector
//!   hints.
//! - `message` is passthrough connector text. The `Display` impl replaces most
//!   control characters with U+FFFD (preserving HT/LF/CR) to prevent log
//!   injection, but raw field access via [`message()`] returns the original
//!   unsanitized value.
//! - These types are value-level contracts only. Retry scheduling, circuit
//!   breaking, and backoff policy live in the runtime crate.

use std::{fmt, io};

use crate::coordination::ShardSpec;

use super::{Budgets, Cursor, EnumerationPage, ItemKey, ItemRef};

/// Binary retry posture for connector operation failures.
///
/// Orchestration layers use this to decide whether to re-attempt an operation
/// or to escalate (park the shard, trigger a circuit breaker transition, etc.).
/// The classification is set by the connector at error-construction time and is
/// immutable thereafter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorClass {
    /// Transient or capacity-related failure. The same request may succeed on
    /// retry without any change to inputs or configuration. Typical causes:
    /// network timeouts, HTTP 429/503, temporary service unavailability.
    Retryable,
    /// The same request will not succeed until something external changes --
    /// credentials, permissions, resource existence, or connector configuration.
    /// Typical causes: HTTP 401/403/404, malformed resource identifiers.
    Permanent,
}

impl ErrorClass {
    /// Returns `true` when the classification is [`Retryable`](Self::Retryable).
    #[inline]
    #[must_use]
    pub const fn is_retryable(self) -> bool {
        matches!(self, Self::Retryable)
    }
}

impl fmt::Display for ErrorClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Retryable => f.write_str("retryable"),
            Self::Permanent => f.write_str("permanent"),
        }
    }
}

/// Writes `message` to `f`, replacing control characters with U+FFFD
/// (REPLACEMENT CHARACTER) to prevent log injection.
///
/// Replaced ranges: C0 (U+0000..U+001F) except HT/LF/CR, DEL (U+007F),
/// and C1 (U+0080..U+009F). Together with HT/LF/CR (which are preserved),
/// these ranges form the full set for which [`char::is_control()`] returns
/// `true`.
#[inline]
fn fmt_sanitized_message(f: &mut fmt::Formatter<'_>, message: &str) -> fmt::Result {
    for ch in message.chars() {
        if ch.is_control() && !matches!(ch, '\t' | '\n' | '\r') {
            f.write_str("\u{FFFD}")?;
        } else {
            fmt::Write::write_char(f, ch)?;
        }
    }
    Ok(())
}

/// Generates a connector error type with private fields, named constructors,
/// accessors, and trait impls (`Display`, `Error`).
///
/// Each invocation produces a distinct nominal type with identical structure,
/// preserving type safety between different connector operations (see module
/// docs for rationale). The generated struct has three private fields:
///
/// - `class: ErrorClass` — binary retry posture
/// - `message: String` — connector-originated diagnostic text
/// - `retry_after_ms: Option<u64>` — optional advisory backoff hint
///
/// Generated API surface per type:
/// - Accessors: `class()`, `message()`, `retry_after_ms()`, `is_retryable()`, `into_message()`
/// - Constructors: `retryable()`, `rate_limited()`, `permanent()`
/// - Traits: `Clone`, `Debug`, `PartialEq`, `Eq`, `Display`, `Error`
macro_rules! define_connector_error {
    (
        $(#[$meta:meta])*
        $name:ident
    ) => {
        $(#[$meta])*
        #[derive(Clone, Debug, PartialEq, Eq)]
        pub struct $name {
            class: ErrorClass,
            message: String,
            retry_after_ms: Option<u64>,
        }

        impl $name {
            /// Returns the retryability classification for this failure.
            #[inline]
            #[must_use]
            pub fn class(&self) -> ErrorClass {
                self.class
            }

            /// Returns the connector-originated diagnostic text.
            ///
            /// Not sanitized by this type -- callers must treat it as untrusted
            /// when logging or displaying.
            #[inline]
            #[must_use]
            pub fn message(&self) -> &str {
                &self.message
            }

            /// Returns the optional connector-provided retry hint in milliseconds.
            ///
            /// Advisory only: the runtime may impose stricter or global backoff
            /// policies. A value of `0` is passed through without normalization.
            #[inline]
            #[must_use]
            pub fn retry_after_ms(&self) -> Option<u64> {
                self.retry_after_ms
            }

            /// Returns `true` when the error is classified as
            /// [`Retryable`](ErrorClass::Retryable).
            ///
            /// Convenience shorthand for `self.class().is_retryable()`.
            #[inline]
            #[must_use]
            pub fn is_retryable(&self) -> bool {
                self.class.is_retryable()
            }

            /// Consumes the error and returns the owned diagnostic message.
            #[inline]
            #[must_use]
            pub fn into_message(self) -> String {
                self.message
            }

            /// Construct a retryable error without a backoff hint.
            ///
            /// Use for transient failures where the connector has no opinion on
            /// when to retry (e.g., a generic network timeout).
            #[must_use]
            pub fn retryable(message: impl Into<String>) -> Self {
                Self {
                    class: ErrorClass::Retryable,
                    message: message.into(),
                    retry_after_ms: None,
                }
            }

            /// Construct a retryable error with a connector-supplied backoff hint.
            ///
            /// Typical source: an HTTP `Retry-After` header or equivalent API signal.
            /// The `retry_after_ms` value is stored as-is (including `0`) with no
            /// clamping or normalization -- that is the runtime's responsibility.
            #[must_use]
            pub fn rate_limited(message: impl Into<String>, retry_after_ms: u64) -> Self {
                Self {
                    class: ErrorClass::Retryable,
                    message: message.into(),
                    retry_after_ms: Some(retry_after_ms),
                }
            }

            /// Construct a permanent error.
            ///
            /// Use when the failure will persist until something external changes
            /// (credentials, permissions, resource existence). The runtime should
            /// not retry blindly; typical follow-up is to park the shard or skip
            /// the item with a diagnostic reason.
            #[must_use]
            pub fn permanent(message: impl Into<String>) -> Self {
                Self {
                    class: ErrorClass::Permanent,
                    message: message.into(),
                    retry_after_ms: None,
                }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}: ", self.class)?;
                fmt_sanitized_message(f, &self.message)?;
                if let Some(retry_after_ms) = self.retry_after_ms {
                    write!(f, " (retry_after_ms={})", retry_after_ms)?;
                }
                Ok(())
            }
        }

        /// Boundary-terminal: the underlying cause (IO, HTTP, parse errors) is
        /// flattened into `message` at construction time. Connectors should log
        /// the original error before constructing this type.
        impl std::error::Error for $name {}
    };
}

define_connector_error! {
    /// Error returned by connector enumeration/list operations.
    ///
    /// Bundles orchestration-facing policy metadata ([`ErrorClass`] and an
    /// optional backoff hint) with a connector-originated diagnostic message.
    /// Constructed via named constructors ([`retryable`](Self::retryable),
    /// [`rate_limited`](Self::rate_limited), [`permanent`](Self::permanent))
    /// that enforce consistent class/retry combinations. Fields are private
    /// to preserve these invariants; use [`class`](Self::class),
    /// [`message`](Self::message), and [`retry_after_ms`](Self::retry_after_ms)
    /// to inspect.
    ///
    /// See also [`ReadError`], the structurally parallel type for the read/open
    /// path. The two are kept separate intentionally -- see the module docs for
    /// rationale.
    EnumerateError
}

define_connector_error! {
    /// Error returned by connector read/open operations.
    ///
    /// Structurally identical to [`EnumerateError`] (same three fields, same
    /// named-constructor pattern), but kept as a distinct type so the compiler
    /// enforces which operation path produced the error. This also allows
    /// orchestration to apply independent retry and circuit-breaker policies
    /// for reads vs enumerations.
    ///
    /// Fields are private to preserve constructor invariants; use
    /// [`class`](Self::class), [`message`](Self::message), and
    /// [`retry_after_ms`](Self::retry_after_ms) to inspect.
    ///
    /// In addition to the shared constructors, `ReadError` provides
    /// [`unsupported`](Self::unsupported) for capability mismatches discovered
    /// at call time.
    ReadError
}

impl ReadError {
    /// Construct a permanent read error for an unsupported operation.
    ///
    /// Convenience for capability mismatches discovered at call time -- for
    /// example, a range-read attempt against a connector that does not
    /// advertise [`ConnectorCapabilities::range_read`]. The message is
    /// formatted as `"{feature} not supported"`.
    #[must_use]
    pub fn unsupported(feature: &'static str) -> Self {
        Self::permanent(format!("{feature} not supported"))
    }
}

/// Feature flags that a connector advertises at registration time.
///
/// Orchestration and planning layers use these to choose enumeration strategy
/// (key-seek vs token-resume), decide whether range reads are available, and
/// determine if the connector can emit split hints for dynamic re-sharding.
///
/// `Default` produces a conservative "no features" profile (all fields
/// `false`), which is safe for connectors that have not been updated to
/// declare capabilities. Callers should still handle [`ReadError::unsupported`]
/// at call time, because a capability flag is a *static declaration of
/// intent*, not a guarantee that every call will succeed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ConnectorCapabilities {
    /// The connector can resume enumeration from an arbitrary key position.
    ///
    /// When `true`, the runtime may supply a `last_key` cursor field to skip
    /// ahead in sorted enumeration order. Connectors without this must
    /// enumerate from the beginning of each shard range.
    pub seek_by_key: bool,
    /// The connector supports opaque token-based pagination.
    ///
    /// When `true`, the runtime will round-trip an opaque [`TokenBytes`]
    /// continuation token between pages. This is the natural model for APIs
    /// that return a "next page token" (e.g., S3 `ListObjectsV2`).
    ///
    /// [`TokenBytes`]: crate::connector::TokenBytes
    pub token_resume: bool,
    /// The connector can serve byte-range reads of item content.
    ///
    /// When `false`, the runtime must read entire items. Attempted range
    /// reads against a non-capable connector produce
    /// [`ReadError::unsupported`].
    pub range_read: bool,
    /// The connector emits split hints alongside enumeration pages.
    ///
    /// Split hints inform the sharding layer where natural partition
    /// boundaries exist (e.g., Git tree object boundaries, S3 key prefixes).
    /// The runtime may use these to dynamically subdivide large shards.
    pub split_hints: bool,
}

/// Runtime contract for connector enumeration/listing operations.
///
/// This trait is intentionally separate from [`ReadConnector`]: some backends
/// can list metadata efficiently but have different cost/failure behavior for
/// content reads. Keeping the surfaces split lets orchestration compose them
/// independently, while [`ConnectorInstance`] provides a shorthand bound when
/// both are required.
pub trait EnumerationConnector: Send {
    /// Advertise connector capabilities used by orchestration planning.
    ///
    /// This is a declarative, static profile for the configured
    /// connector instance. It should align with method behavior, but callers
    /// must still handle runtime `unsupported`/policy errors.
    fn caps(&self) -> ConnectorCapabilities;

    /// Enumerate one page of items for `shard` from `cursor` under `budgets`.
    ///
    /// Returns scan items plus the continuation cursor for the next request
    /// (see [`EnumerationPage`]). Empty pages are valid and carry meaning
    /// through the returned cursor state.
    ///
    /// # Budget enforcement
    ///
    /// [`Budgets`] values are **advisory at this trait layer**. Connector
    /// implementations **should** honor [`Budgets::max_items`] as an upper
    /// bound on the returned page length, but callers **must not** assume
    /// compliance. The runtime orchestration layer is responsible for
    /// enforcement: it **may** truncate excess items, apply backpressure,
    /// or terminate a misbehaving connector.
    fn enumerate_page(
        &mut self,
        shard: &ShardSpec,
        cursor: &Cursor,
        budgets: Budgets,
    ) -> Result<EnumerationPage, EnumerateError>;

    /// Optional split-point hint for dynamic shard subdivision.
    ///
    /// Default behavior is `Ok(None)`, indicating "no hint available". Keep
    /// this default unless the connector can provide useful, low-risk split
    /// candidates. Returned hints are advisory and may be ignored by callers.
    /// Runtime callers **should** validate that returned keys fall within
    /// the shard's key range before acting on them.
    ///
    /// # Capability consistency
    ///
    /// The default implementation includes a `debug_assert!` that fires when
    /// [`caps().split_hints`](ConnectorCapabilities::split_hints) is `true`
    /// but this method has not been overridden. This catches a misconfiguration
    /// where the connector advertises split-hint support without providing an
    /// implementation. Connectors that override this method **must** also
    /// return `split_hints: true` from [`caps`](EnumerationConnector::caps).
    fn choose_split_point(
        &mut self,
        _shard: &ShardSpec,
        _cursor: &Cursor,
        _budgets: Budgets,
    ) -> Result<Option<ItemKey>, EnumerateError> {
        debug_assert!(
            !self.caps().split_hints,
            "connector advertises split_hints but does not override choose_split_point"
        );
        Ok(None)
    }
}

/// Runtime contract for connector item reads.
///
/// This surface is split from [`EnumerationConnector`] so orchestration can
/// reason separately about metadata traversal and payload IO costs.
pub trait ReadConnector: Send {
    /// Open an item for sequential read access.
    ///
    /// # Return type: `Box<dyn Read + Send>`
    ///
    /// The boxed trait object is intentional: it preserves object safety so
    /// callers can work with `dyn ReadConnector` at runtime (connector
    /// polymorphism). The heap allocation is acceptable because `open` sits
    /// on the **WARM** read path — called once per item, not per byte —
    /// and the IO cost of the subsequent read dominates.
    ///
    /// The returned reader must be self-contained (`'static`): implementations
    /// cannot borrow from `&self` or other local references. Readers must own
    /// their resources (e.g., an open file handle, a cloned HTTP client, or an
    /// `Arc`-backed buffer).
    ///
    /// # Budget enforcement
    ///
    /// [`Budgets`] values are **advisory at this trait layer**. Connector
    /// implementations **should** respect budget hints (e.g., for chunked
    /// fetching or deadline-aware reads), but callers **must not** assume
    /// compliance. The runtime orchestration layer is responsible for
    /// enforcement: it **must** wrap the returned reader in a size-bounded,
    /// deadline-aware adapter before passing it to downstream consumers.
    ///
    /// Callers may drop the reader at any point; implementations must ensure
    /// resource cleanup via [`Drop`], not via read-to-completion.
    ///
    /// # Item reference affinity
    ///
    /// `item_ref` **must** originate from an [`EnumerationPage`] produced by
    /// this connector instance (or a compatible instance backed by the same
    /// data source). Passing an [`ItemRef`] obtained from a different
    /// connector type is a caller error and may produce garbage reads or
    /// opaque failures.
    fn open(
        &mut self,
        item_ref: &ItemRef,
        budgets: Budgets,
    ) -> Result<Box<dyn io::Read + Send>, ReadError>;

    /// Optional range-read fast path.
    ///
    /// Writes up to `dst.len()` bytes from `item_ref` starting at `offset`
    /// into `dst`, returning the number of bytes written. Implementations
    /// **must** return a value `<= dst.len()`. Runtime callers **should**
    /// defensively clamp before using the value as a slice bound.
    ///
    /// # Overflow safety
    ///
    /// Implementors **must** guard against `offset + dst.len()` overflow
    /// before performing arithmetic on the combined value. Use
    /// `offset.checked_add(dst.len() as u64)` and return an appropriate
    /// [`ReadError`] if the addition wraps.
    ///
    /// **EOF behavior:** when `offset` is at or past the end of the item,
    /// implementations must return `Ok(0)` (consistent with
    /// [`std::io::Read`] semantics). A short read (returned count less than
    /// `dst.len()`) does not necessarily indicate EOF -- only `Ok(0)` is
    /// the definitive end-of-item signal.
    ///
    /// Connectors without native range support should keep this default,
    /// which returns a permanent [`ReadError::unsupported`] classification.
    fn read_range(
        &mut self,
        _item_ref: &ItemRef,
        _offset: u64,
        _dst: &mut [u8],
        _budgets: Budgets,
    ) -> Result<usize, ReadError> {
        Err(ReadError::unsupported("range_read"))
    }
}

/// Convenience supertrait for connector types.
///
/// Use this as a bound when a call path requires both enumeration and read
/// capabilities. The blanket implementation means connector types do not
/// need an explicit `impl ConnectorInstance`.
///
/// # Design constraint
///
/// Because there is a blanket `impl<T: EnumerationConnector + ReadConnector
/// + ?Sized> ConnectorInstance for T` (the `?Sized` bound enables `dyn
/// ConnectorInstance`), adding required methods to this trait would break the
/// blanket impl — the empty body cannot supply an implementation for
/// arbitrary `T`. This is intentional: `ConnectorInstance` is a **pure bound
/// alias**, not an extension point. New connector surface area belongs on
/// [`EnumerationConnector`] or [`ReadConnector`] directly.
pub trait ConnectorInstance: EnumerationConnector + ReadConnector {}

impl<T: EnumerationConnector + ReadConnector + ?Sized> ConnectorInstance for T {}

#[cfg(test)]
#[path = "api_tests.rs"]
mod tests;
