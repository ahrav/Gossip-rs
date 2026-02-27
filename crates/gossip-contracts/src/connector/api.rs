//! Connector operation error taxonomy and capability negotiation surface.
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
//! - `message` is passthrough connector text. The `Display` impl replaces
//!   control characters with U+FFFD to prevent log injection, but raw field
//!   access via [`message()`] returns the original unsanitized value.
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
    pub fn is_retryable(self) -> bool {
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
/// and C1 (U+0080..U+009F). These are the characters for which
/// [`char::is_control()`] returns `true`.
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
/// - Accessors: `class()`, `message()`, `retry_after_ms()`, `into_message()`
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

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::{ConnectorCapabilities, EnumerateError, ErrorClass, ReadError};

    // -- EnumerateError constructor cases (each runs as an isolated sub-test) --

    #[rstest]
    #[case::retryable(
        EnumerateError::retryable("transient outage"),
        ErrorClass::Retryable,
        "transient outage",
        None
    )]
    #[case::rate_limited(
        EnumerateError::rate_limited("too many requests", 1_250),
        ErrorClass::Retryable,
        "too many requests",
        Some(1_250)
    )]
    #[case::rate_limited_zero_backoff(
        EnumerateError::rate_limited("zero backoff", 0),
        ErrorClass::Retryable,
        "zero backoff",
        Some(0)
    )]
    #[case::permanent(
        EnumerateError::permanent("invalid credentials"),
        ErrorClass::Permanent,
        "invalid credentials",
        None
    )]
    fn enumerate_error_constructors(
        #[case] error: EnumerateError,
        #[case] expected_class: ErrorClass,
        #[case] expected_message: &str,
        #[case] expected_retry: Option<u64>,
    ) {
        assert_eq!(error.class(), expected_class);
        assert_eq!(error.message(), expected_message);
        assert_eq!(error.retry_after_ms(), expected_retry);
    }

    // -- ReadError constructor cases (includes `unsupported` convenience ctor) --

    #[rstest]
    #[case::retryable(
        ReadError::retryable("temporary read failure"),
        ErrorClass::Retryable,
        "temporary read failure",
        None
    )]
    #[case::rate_limited(
        ReadError::rate_limited("rate limited", 5_000),
        ErrorClass::Retryable,
        "rate limited",
        Some(5_000)
    )]
    #[case::permanent(
        ReadError::permanent("document missing"),
        ErrorClass::Permanent,
        "document missing",
        None
    )]
    #[case::unsupported(
        ReadError::unsupported("range_read"),
        ErrorClass::Permanent,
        "range_read not supported",
        None
    )]
    fn read_error_constructors(
        #[case] error: ReadError,
        #[case] expected_class: ErrorClass,
        #[case] expected_message: &str,
        #[case] expected_retry: Option<u64>,
    ) {
        assert_eq!(error.class(), expected_class);
        assert_eq!(error.message(), expected_message);
        assert_eq!(error.retry_after_ms(), expected_retry);
    }

    // -- Display formatting (with / without retry hint) --

    #[rstest]
    #[case::without_retry(
        EnumerateError::permanent("enumeration disabled"),
        "permanent: enumeration disabled"
    )]
    #[case::with_retry(
        EnumerateError::rate_limited("throttled", 250),
        "retryable: throttled (retry_after_ms=250)"
    )]
    #[case::with_zero_retry(
        EnumerateError::rate_limited("zero hint", 0),
        "retryable: zero hint (retry_after_ms=0)"
    )]
    fn enumerate_error_display(#[case] error: EnumerateError, #[case] expected: &str) {
        assert_eq!(error.to_string(), expected);
    }

    #[rstest]
    #[case::without_retry(
        ReadError::retryable("temporary backend error"),
        "retryable: temporary backend error"
    )]
    #[case::with_retry(
        ReadError::rate_limited("slow down", 750),
        "retryable: slow down (retry_after_ms=750)"
    )]
    fn read_error_display(#[case] error: ReadError, #[case] expected: &str) {
        assert_eq!(error.to_string(), expected);
    }

    // -- Standalone tests (unique setup, not worth parameterizing) --

    #[test]
    fn connector_capabilities_default_is_all_false() {
        let capabilities = ConnectorCapabilities::default();
        assert!(!capabilities.seek_by_key);
        assert!(!capabilities.token_resume);
        assert!(!capabilities.range_read);
        assert!(!capabilities.split_hints);
    }

    #[test]
    fn error_trait_impls_compile() {
        fn assert_error_impl<T: std::error::Error>() {}

        assert_error_impl::<EnumerateError>();
        assert_error_impl::<ReadError>();
    }
}
