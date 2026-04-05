//! Connector operation error taxonomy and capability negotiation.
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
//! - Constructor invariants are enforced by private fields: only the
//!   rate-limited constructor records `retry_after_ms = Some(_)`, while the
//!   generic retryable and permanent constructors always store `None`.
//! - `message` is passthrough connector text. The `Display` impl replaces most
//!   control characters with U+FFFD (preserving HT/LF/CR) to prevent log
//!   injection, but raw field access via [`message()`] returns the original
//!   unsanitized value.
//! - These types are value-level contracts only. Retry scheduling, circuit
//!   breaking, and backoff policy live in the runtime crate.

use std::fmt;

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

/// Writes `message` to `f`, applying a security-focused sanitization policy.
///
/// Specifically, this replaces all control characters (except HT/LF/CR) with U+FFFD
/// (REPLACEMENT CHARACTER) to actively prevent log injection attacks and terminal
/// disruption. Connectors must use this rather than raw display of untrusted error messages.
///
/// Replaced ranges: C0 (U+0000..U+001F) except HT/LF/CR, DEL (U+007F),
/// and C1 (U+0080..U+009F). Together with HT/LF/CR (which are preserved),
/// these ranges form the full set for which [`char::is_control()`] returns
/// `true`.
///
/// This helper streams directly into the formatter and does not allocate an
/// intermediate sanitized string. Hidden visibility keeps the public API
/// surface small while still allowing macro-generated `Display` impls to reuse
/// one canonical sanitization policy.
#[inline]
#[doc(hidden)]
pub fn fmt_sanitized_message(f: &mut fmt::Formatter<'_>, message: &str) -> fmt::Result {
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
/// Invariant preserved by the generated constructors:
/// - `retryable()` => `class = Retryable`, `retry_after_ms = None`
/// - `rate_limited()` => `class = Retryable`, `retry_after_ms = Some(_)`
/// - `permanent()` => `class = Permanent`, `retry_after_ms = None`
///
/// Generated API surface per type:
/// - Accessors: `class()`, `message()`, `retry_after_ms()`, `is_retryable()`, `into_message()`
/// - Constructors: `retryable()`, `rate_limited()`, `permanent()`
/// - Traits: `Clone`, `Debug`, `PartialEq`, `Eq`, `Display`, `Error`
#[macro_export]
#[doc(hidden)]
macro_rules! define_connector_error {
    (
        $(#[$meta:meta])*
        $name:ident
    ) => {
        $(#[$meta])*
        #[derive(Clone, PartialEq, Eq)]
        pub struct $name {
            class: $crate::connector::ErrorClass,
            message: ::std::string::String,
            retry_after_ms: ::core::option::Option<u64>,
        }

        impl $name {
            /// Returns the retryability classification for this failure.
            #[inline]
            #[must_use]
            pub fn class(&self) -> $crate::connector::ErrorClass {
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
            pub fn retry_after_ms(&self) -> ::core::option::Option<u64> {
                self.retry_after_ms
            }

            /// Returns `true` when the error is classified as
            /// [`Retryable`](crate::connector::ErrorClass::Retryable).
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
            pub fn into_message(self) -> ::std::string::String {
                self.message
            }

            /// Constructs a retryable error without a backoff hint.
            ///
            /// Use for transient failures where the connector has no opinion on
            /// when to retry (e.g., a generic network timeout).
            #[must_use]
            pub fn retryable(message: impl ::core::convert::Into<::std::string::String>) -> Self {
                Self {
                    class: $crate::connector::ErrorClass::Retryable,
                    message: message.into(),
                    retry_after_ms: ::core::option::Option::None,
                }
            }

            /// Constructs a retryable error with a connector-supplied backoff hint.
            ///
            /// Typical source: an HTTP `Retry-After` header or equivalent API signal.
            /// The `retry_after_ms` value is stored as-is (including `0`) with no
            /// clamping or normalization -- that is the runtime's responsibility.
            #[must_use]
            pub fn rate_limited(
                message: impl ::core::convert::Into<::std::string::String>,
                retry_after_ms: u64,
            ) -> Self {
                Self {
                    class: $crate::connector::ErrorClass::Retryable,
                    message: message.into(),
                    retry_after_ms: ::core::option::Option::Some(retry_after_ms),
                }
            }

            /// Constructs a permanent error.
            ///
            /// Use when the failure will persist until something external changes
            /// (credentials, permissions, resource existence). The runtime should
            /// not retry blindly; typical follow-up is to park the shard or skip
            /// the item with a diagnostic reason.
            #[must_use]
            pub fn permanent(
                message: impl ::core::convert::Into<::std::string::String>,
            ) -> Self {
                Self {
                    class: $crate::connector::ErrorClass::Permanent,
                    message: message.into(),
                    retry_after_ms: ::core::option::Option::None,
                }
            }
        }

        impl ::core::fmt::Display for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                write!(f, "{}: ", self.class)?;
                $crate::connector::fmt_sanitized_message(f, &self.message)?;
                if let ::core::option::Option::Some(retry_after_ms) = self.retry_after_ms {
                    write!(f, " (retry_after_ms={})", retry_after_ms)?;
                }
                ::core::result::Result::Ok(())
            }
        }

        impl ::core::fmt::Debug for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.debug_struct(stringify!($name))
                    .field("class", &self.class)
                    .field(
                        "message",
                        &$crate::connector::ToxicDigest::of_bytes(self.message.as_bytes()),
                    )
                    .field("retry_after_ms", &self.retry_after_ms)
                    .finish()
            }
        }

        /// Boundary-terminal: the underlying cause (IO, HTTP, parse errors) is
        /// flattened into `message` at construction time. Connectors should log
        /// the original error before constructing this type.
        impl ::std::error::Error for $name {}
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
    /// Constructs a permanent read error for an unsupported operation.
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
/// The flags are orthogonal: a connector may support neither, either, or both
/// of `seek_by_key` and `token_resume`, and planning code should pick the most
/// natural strategy for the connector/runtime combination instead of assuming
/// one excludes the other.
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

#[cfg(test)]
#[path = "api_tests.rs"]
mod tests;
