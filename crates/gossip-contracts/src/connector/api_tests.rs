//! Regression tests for the connector-facing API contract.
//!
//! These tests pin the observable behavior of the connector capability flags and
//! the public error helpers that adapters use to classify failures.
//! Specifically, they verify that:
//!
//! - constructor helpers preserve the expected [`ErrorClass`] and retry hints,
//! - display output stays stable and sanitizes disallowed control characters,
//! - default [`ConnectorCapabilities`] remain conservative until a connector
//!   opts into a feature, and
//! - property tests cover arbitrary messages so formatting never panics on
//!   unusual input.
//!
//! The assertions focus on externally visible behavior rather than internal
//! representation so the implementation can evolve without breaking downstream
//! connectors or callers that pattern-match on these guarantees.

use rstest::rstest;

use super::{ConnectorCapabilities, EnumerateError, ErrorClass, ReadError};

/// Asserts every `EnumerateError` constructor exposes the expected class, message,
/// and retry hint.
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
#[case::empty_message(EnumerateError::retryable(""), ErrorClass::Retryable, "", None)]
#[case::max_retry(
    EnumerateError::rate_limited("max backoff", u64::MAX),
    ErrorClass::Retryable,
    "max backoff",
    Some(u64::MAX)
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

/// Mirrors the `ReadError` constructors to ensure their diagnostics expose the correct class,
/// message, and optional retry hint.
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
#[case::empty_message(ReadError::retryable(""), ErrorClass::Retryable, "", None)]
#[case::max_retry(
    ReadError::rate_limited("max backoff", u64::MAX),
    ErrorClass::Retryable,
    "max backoff",
    Some(u64::MAX)
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

/// Verifies `EnumerateError::Display` renders the expected prefix and retry hints.
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
#[case::empty_message(EnumerateError::permanent(""), "permanent: ")]
fn enumerate_error_display(#[case] error: EnumerateError, #[case] expected: &str) {
    assert_eq!(error.to_string(), expected);
}

/// Verifies `ReadError::Display` maintains the expected prefix and retry hints.
#[rstest]
#[case::without_retry(
    ReadError::retryable("temporary backend error"),
    "retryable: temporary backend error"
)]
#[case::with_retry(
    ReadError::rate_limited("slow down", 750),
    "retryable: slow down (retry_after_ms=750)"
)]
#[case::with_zero_retry(
    ReadError::rate_limited("zero hint", 0),
    "retryable: zero hint (retry_after_ms=0)"
)]
#[case::empty_message(ReadError::permanent(""), "permanent: ")]
fn read_error_display(#[case] error: ReadError, #[case] expected: &str) {
    assert_eq!(error.to_string(), expected);
}

/// Confirms the default `ConnectorCapabilities` conservatively disable optional features.
#[test]
fn default_caps_are_conservative() {
    let capabilities = ConnectorCapabilities::default();
    assert!(!capabilities.seek_by_key);
    assert!(!capabilities.token_resume);
    assert!(!capabilities.range_read);
    assert!(!capabilities.split_hints);
}

/// Asserts the connector error types implement `std::error::Error` for trait-object use.
#[test]
fn error_trait_impls_compile() {
    fn assert_error_impl<T: std::error::Error>() {}

    assert_error_impl::<EnumerateError>();
    assert_error_impl::<ReadError>();
}

/// Ensures display output replaces disallowed control characters while leaving allowed whitespace untouched.
#[test]
fn display_sanitizes_control_characters() {
    let msg = "hello\x00world\x1b[31m\x7fred";
    let err = EnumerateError::retryable(msg);
    let display = err.to_string();
    assert_eq!(
        display,
        "retryable: hello\u{FFFD}world\u{FFFD}[31m\u{FFFD}red"
    );

    // Allowed whitespace passes through unchanged.
    let err2 = ReadError::permanent("line1\tline2\nline3\rline4");
    assert_eq!(err2.to_string(), "permanent: line1\tline2\nline3\rline4");
}

/// Validates the `ErrorClass::is_retryable` helper remains aligned with each variant.
#[test]
fn error_class_is_retryable() {
    assert!(ErrorClass::Retryable.is_retryable());
    assert!(!ErrorClass::Permanent.is_retryable());
}

/// Guards that `EnumerateError` respects the retryability decision delegated to `ErrorClass`.
#[test]
fn enumerate_error_is_retryable_delegates_to_class() {
    assert!(EnumerateError::retryable("transient").is_retryable());
    assert!(EnumerateError::rate_limited("throttled", 100).is_retryable());
    assert!(!EnumerateError::permanent("gone").is_retryable());
}

/// Guards that `ReadError` mirrors the `ErrorClass` retryability semantics, including `Unsupported`.
#[test]
fn read_error_is_retryable_delegates_to_class() {
    assert!(ReadError::retryable("transient").is_retryable());
    assert!(ReadError::rate_limited("throttled", 100).is_retryable());
    assert!(!ReadError::permanent("gone").is_retryable());
    assert!(!ReadError::unsupported("range_read").is_retryable());
}

mod proptests {
    //! Property tests covering display invariants for every error variant.
    use proptest::prelude::*;

    use super::{EnumerateError, ErrorClass, ReadError};

    /// Samples each `ErrorClass` variant for downstream strategies.
    fn arb_error_class() -> impl Strategy<Value = ErrorClass> {
        prop_oneof![Just(ErrorClass::Retryable), Just(ErrorClass::Permanent),]
    }

    /// Constructs every possible `EnumerateError` along with optional retry hints.
    fn arb_enumerate_error() -> impl Strategy<Value = EnumerateError> {
        (arb_error_class(), ".*", proptest::option::of(any::<u64>())).prop_map(
            |(class, msg, retry)| match class {
                ErrorClass::Retryable => match retry {
                    Some(r) => EnumerateError::rate_limited(msg, r),
                    None => EnumerateError::retryable(msg),
                },
                ErrorClass::Permanent => EnumerateError::permanent(msg),
            },
        )
    }

    /// Constructs every `ReadError` variant together with optional retry hints.
    fn arb_read_error() -> impl Strategy<Value = ReadError> {
        (arb_error_class(), ".*", proptest::option::of(any::<u64>())).prop_map(
            |(class, msg, retry)| match class {
                ErrorClass::Retryable => match retry {
                    Some(r) => ReadError::rate_limited(msg, r),
                    None => ReadError::retryable(msg),
                },
                ErrorClass::Permanent => ReadError::permanent(msg),
            },
        )
    }

    proptest! {
        #![proptest_config(crate::test_util::miri_proptest_config())]

        /// Ensures any `EnumerateError` renders without panicking and keeps the reporting prefix.
        #[test]
        fn enumerate_error_display_never_panics(err in arb_enumerate_error()) {
            let display = err.to_string();
            let prefix = match err.class() {
                ErrorClass::Retryable => "retryable: ",
                ErrorClass::Permanent => "permanent: ",
            };
            prop_assert!(display.starts_with(prefix));
        }

        /// Ensures any `ReadError` renders without panicking and keeps the reporting prefix.
        #[test]
        fn read_error_display_never_panics(err in arb_read_error()) {
            let display = err.to_string();
            let prefix = match err.class() {
                ErrorClass::Retryable => "retryable: ",
                ErrorClass::Permanent => "permanent: ",
            };
            prop_assert!(display.starts_with(prefix));
        }

        /// Verifies every generated error display output only contains allowed control characters.
        #[test]
        fn display_strips_control_characters(err in arb_enumerate_error()) {
            let display = err.to_string();
            for ch in display.chars() {
                if ch.is_control() {
                    prop_assert!(
                        matches!(ch, '\t' | '\n' | '\r'),
                        "unexpected control char U+{:04X} in display output",
                        ch as u32,
                    );
                }
            }
        }
    }
}
