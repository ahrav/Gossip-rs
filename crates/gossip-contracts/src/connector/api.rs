//! Connector operation error taxonomy and capability negotiation surface.
//!
//! These types model connector operation outcomes **after** boundary validation
//! has succeeded. Input-shape and size failures use
//! [`ConnectorInputError`](crate::connector::ConnectorInputError) in
//! `connector/types.rs`.
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
//! distinct types. This is intentional: enumeration and reading are separate
//! connector traits with independent scaling characteristics (metadata-bound
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
//! - `message` is passthrough connector text and is **not** sanitized here.
//!   Callers must treat it as untrusted when logging or surfacing to users.
//! - These types are value-level contracts only. Retry scheduling, circuit
//!   breaking, and backoff policy live in the runtime crate.

use std::fmt;

/// Retry posture classification for connector operation failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorClass {
    /// Transient/capacity failure; callers may retry with the same semantics.
    Retryable,
    /// Same request is unlikely to succeed until inputs/configuration change.
    Permanent,
}

/// Error returned by connector enumeration/list APIs.
///
/// This carries orchestration-facing policy metadata (`class`,
/// `retry_after_ms`) plus a connector-originated human message.
#[derive(Clone, Debug)]
pub struct EnumerateError {
    /// Retryability classification for this failure.
    pub class: ErrorClass,
    /// Human-readable connector message (not sanitized by this type).
    pub message: String,
    /// Optional connector-provided retry hint in milliseconds.
    ///
    /// This is advisory metadata; callers may apply stricter/global policies.
    pub retry_after_ms: Option<u64>,
}

impl EnumerateError {
    /// Construct a retryable enumeration error without a retry delay hint.
    #[must_use]
    pub fn retryable(message: impl Into<String>) -> Self {
        Self {
            class: ErrorClass::Retryable,
            message: message.into(),
            retry_after_ms: None,
        }
    }

    /// Construct a retryable enumeration error with an explicit backoff hint.
    ///
    /// `retry_after_ms` is stored as-is (including `0`), with no normalization.
    #[must_use]
    pub fn rate_limited(message: impl Into<String>, retry_after_ms: u64) -> Self {
        Self {
            class: ErrorClass::Retryable,
            message: message.into(),
            retry_after_ms: Some(retry_after_ms),
        }
    }

    /// Construct a permanent enumeration error.
    ///
    /// Use this when blind retries are not expected to help (for example,
    /// authorization or unsupported-operation failures).
    #[must_use]
    pub fn permanent(message: impl Into<String>) -> Self {
        Self {
            class: ErrorClass::Permanent,
            message: message.into(),
            retry_after_ms: None,
        }
    }
}

impl fmt::Display for EnumerateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.retry_after_ms {
            Some(retry_after_ms) => write!(
                f,
                "{:?}: {} (retry_after_ms={})",
                self.class, self.message, retry_after_ms
            ),
            None => write!(f, "{:?}: {}", self.class, self.message),
        }
    }
}

impl std::error::Error for EnumerateError {}

/// Error returned by connector read/open APIs.
///
/// Semantics mirror [`EnumerateError`], but this distinct type keeps read and
/// enumerate surfaces separate in public signatures.
#[derive(Clone, Debug)]
pub struct ReadError {
    /// Retryability classification for this failure.
    pub class: ErrorClass,
    /// Human-readable connector message (not sanitized by this type).
    pub message: String,
    /// Optional connector-provided retry hint in milliseconds.
    ///
    /// This is advisory metadata; callers may apply stricter/global policies.
    pub retry_after_ms: Option<u64>,
}

impl ReadError {
    /// Construct a retryable read error without a retry delay hint.
    #[must_use]
    pub fn retryable(message: impl Into<String>) -> Self {
        Self {
            class: ErrorClass::Retryable,
            message: message.into(),
            retry_after_ms: None,
        }
    }

    /// Construct a retryable read error with an explicit backoff hint.
    ///
    /// `retry_after_ms` is stored as-is (including `0`), with no normalization.
    #[must_use]
    pub fn rate_limited(message: impl Into<String>, retry_after_ms: u64) -> Self {
        Self {
            class: ErrorClass::Retryable,
            message: message.into(),
            retry_after_ms: Some(retry_after_ms),
        }
    }

    /// Construct a permanent read error.
    ///
    /// Use this when retries with unchanged request semantics are not expected
    /// to recover.
    #[must_use]
    pub fn permanent(message: impl Into<String>) -> Self {
        Self {
            class: ErrorClass::Permanent,
            message: message.into(),
            retry_after_ms: None,
        }
    }

    /// Construct a permanent read error for unsupported connector functionality.
    ///
    /// This is a convenience helper for capability mismatches discovered at
    /// runtime (for example, an attempted range read without support).
    #[must_use]
    pub fn unsupported(feature: &'static str) -> Self {
        Self::permanent(format!("{feature} not supported"))
    }
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.retry_after_ms {
            Some(retry_after_ms) => write!(
                f,
                "{:?}: {} (retry_after_ms={})",
                self.class, self.message, retry_after_ms
            ),
            None => write!(f, "{:?}: {}", self.class, self.message),
        }
    }
}

impl std::error::Error for ReadError {}

/// Optional connector features consumed by orchestration/planning layers.
///
/// `Default` is a conservative "feature absent" profile (all fields `false`).
/// Callers should still handle runtime unsupported errors even when a feature
/// is advertised as available.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ConnectorCapabilities {
    /// Supports resuming enumeration from a provided key seek position.
    pub seek_by_key: bool,
    /// Supports connector-native opaque token continuation.
    pub token_resume: bool,
    /// Supports direct range reads.
    pub range_read: bool,
    /// Emits split hints for downstream sharding/partitioning.
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
        assert_eq!(error.class, expected_class);
        assert_eq!(error.message, expected_message);
        assert_eq!(error.retry_after_ms, expected_retry);
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
        assert_eq!(error.class, expected_class);
        assert_eq!(error.message, expected_message);
        assert_eq!(error.retry_after_ms, expected_retry);
    }

    // -- Display formatting (with / without retry hint) --

    #[rstest]
    #[case::without_retry(
        EnumerateError::permanent("enumeration disabled"),
        "Permanent: enumeration disabled"
    )]
    #[case::with_retry(
        EnumerateError::rate_limited("throttled", 250),
        "Retryable: throttled (retry_after_ms=250)"
    )]
    fn enumerate_error_display(#[case] error: EnumerateError, #[case] expected: &str) {
        assert_eq!(error.to_string(), expected);
    }

    #[rstest]
    #[case::without_retry(
        ReadError::retryable("temporary backend error"),
        "Retryable: temporary backend error"
    )]
    #[case::with_retry(
        ReadError::rate_limited("slow down", 750),
        "Retryable: slow down (retry_after_ms=750)"
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
