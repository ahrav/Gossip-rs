//! Connector operation error taxonomy and capability negotiation surface.
//!
//! These types model connector operation outcomes **after** boundary validation
//! has succeeded. Input-shape and size failures use
//! [`ConnectorInputError`](crate::connector::ConnectorInputError) in
//! `connector/types.rs`.
//!
//! - [`EnumerateError`] reports enumeration/listing failures.
//! - [`ReadError`] reports item read/open failures.
//! - [`ErrorClass`] classifies retry posture (`Retryable` vs `Permanent`).
//! - [`ConnectorCapabilities`] advertises optional connector features.
//!
//! ## Boundary notes
//!
//! - `retry_after_ms` is advisory backoff metadata, not a scheduler contract.
//! - `message` is passthrough connector text and is not sanitized here.

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
    use super::{ConnectorCapabilities, EnumerateError, ErrorClass, ReadError};

    #[test]
    fn enumerate_error_constructors_set_class_and_retry_after() {
        let retryable = EnumerateError::retryable("transient outage");
        assert_eq!(retryable.class, ErrorClass::Retryable);
        assert_eq!(retryable.message, "transient outage");
        assert_eq!(retryable.retry_after_ms, None);

        let rate_limited = EnumerateError::rate_limited("too many requests", 1_250);
        assert_eq!(rate_limited.class, ErrorClass::Retryable);
        assert_eq!(rate_limited.message, "too many requests");
        assert_eq!(rate_limited.retry_after_ms, Some(1_250));

        let permanent = EnumerateError::permanent("invalid credentials");
        assert_eq!(permanent.class, ErrorClass::Permanent);
        assert_eq!(permanent.message, "invalid credentials");
        assert_eq!(permanent.retry_after_ms, None);
    }

    #[test]
    fn read_error_constructors_set_class_and_retry_after() {
        let retryable = ReadError::retryable("temporary read failure");
        assert_eq!(retryable.class, ErrorClass::Retryable);
        assert_eq!(retryable.message, "temporary read failure");
        assert_eq!(retryable.retry_after_ms, None);

        let rate_limited = ReadError::rate_limited("rate limited", 5_000);
        assert_eq!(rate_limited.class, ErrorClass::Retryable);
        assert_eq!(rate_limited.message, "rate limited");
        assert_eq!(rate_limited.retry_after_ms, Some(5_000));

        let permanent = ReadError::permanent("document missing");
        assert_eq!(permanent.class, ErrorClass::Permanent);
        assert_eq!(permanent.message, "document missing");
        assert_eq!(permanent.retry_after_ms, None);
    }

    #[test]
    fn read_error_unsupported_is_permanent_and_not_supported() {
        let error = ReadError::unsupported("range_read");
        assert_eq!(error.class, ErrorClass::Permanent);
        assert_eq!(error.message, "range_read not supported");
        assert_eq!(error.retry_after_ms, None);
    }

    #[test]
    fn enumerate_error_display_formats_with_and_without_retry_after() {
        let plain = EnumerateError::permanent("enumeration disabled");
        assert_eq!(plain.to_string(), "Permanent: enumeration disabled");

        let hinted = EnumerateError::rate_limited("throttled", 250);
        assert_eq!(
            hinted.to_string(),
            "Retryable: throttled (retry_after_ms=250)"
        );
    }

    #[test]
    fn read_error_display_formats_with_and_without_retry_after() {
        let plain = ReadError::retryable("temporary backend error");
        assert_eq!(plain.to_string(), "Retryable: temporary backend error");

        let hinted = ReadError::rate_limited("slow down", 750);
        assert_eq!(
            hinted.to_string(),
            "Retryable: slow down (retry_after_ms=750)"
        );
    }

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
