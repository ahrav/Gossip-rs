use std::io;

use rstest::rstest;

use crate::coordination::ShardSpec;

use super::{
    Budgets, ConnectorCapabilities, ConnectorInstance, Cursor, EnumerateError,
    EnumerationConnector, EnumerationPage, ErrorClass, ItemRef, ReadConnector, ReadError,
};

struct Dummy;

impl EnumerationConnector for Dummy {
    fn caps(&self) -> ConnectorCapabilities {
        ConnectorCapabilities::default()
    }

    fn enumerate_page(
        &mut self,
        _shard: &ShardSpec,
        _cursor: &Cursor,
        _budgets: Budgets,
    ) -> Result<EnumerationPage, EnumerateError> {
        Err(EnumerateError::permanent("not implemented"))
    }
}

impl ReadConnector for Dummy {
    fn open(
        &mut self,
        _item_ref: &ItemRef,
        _budgets: Budgets,
    ) -> Result<Box<dyn io::Read + Send>, ReadError> {
        Err(ReadError::permanent("not implemented"))
    }
}

fn budgets() -> Budgets {
    Budgets::try_new(4, 1024, None).unwrap_or_else(|err| panic!("valid test budgets: {err}"))
}

fn item_ref() -> ItemRef {
    ItemRef::try_from_slice(b"dummy-item-ref")
        .unwrap_or_else(|err| panic!("valid test item ref: {err}"))
}

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
#[case::empty_message(EnumerateError::permanent(""), "permanent: ")]
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
#[case::with_zero_retry(
    ReadError::rate_limited("zero hint", 0),
    "retryable: zero hint (retry_after_ms=0)"
)]
#[case::empty_message(ReadError::permanent(""), "permanent: ")]
fn read_error_display(#[case] error: ReadError, #[case] expected: &str) {
    assert_eq!(error.to_string(), expected);
}

// -- Standalone tests (unique setup, not worth parameterizing) --

#[test]
fn default_caps_are_conservative() {
    let capabilities = ConnectorCapabilities::default();
    assert!(!capabilities.seek_by_key);
    assert!(!capabilities.token_resume);
    assert!(!capabilities.range_read);
    assert!(!capabilities.split_hints);
}

#[test]
fn default_read_range_is_unsupported() {
    let mut connector = Dummy;
    let mut dst = [0_u8; 8];
    let err = connector
        .read_range(&item_ref(), 0, &mut dst, budgets())
        .expect_err("default read_range should be unsupported");
    assert_eq!(err.class(), ErrorClass::Permanent);
    assert!(err.message().contains("not supported"));
}

#[test]
fn default_choose_split_point_returns_none() {
    let mut connector = Dummy;
    let split = connector
        .choose_split_point(&ShardSpec::unbounded(), &Cursor::initial(), budgets())
        .expect("default choose_split_point should not fail");
    assert!(split.is_none());
}

#[test]
fn dummy_is_connector_instance() {
    fn assert_connector_instance<T: ConnectorInstance>() {}
    assert_connector_instance::<Dummy>();
}

#[test]
fn error_trait_impls_compile() {
    fn assert_error_impl<T: std::error::Error>() {}

    assert_error_impl::<EnumerateError>();
    assert_error_impl::<ReadError>();
}

#[test]
fn traits_are_object_safe_and_send() {
    fn assert_obj_safe_send<T: Send + ?Sized>() {}
    assert_obj_safe_send::<dyn EnumerationConnector>();
    assert_obj_safe_send::<dyn ReadConnector>();
    assert_obj_safe_send::<dyn ConnectorInstance>();
}

#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "does not override choose_split_point")]
fn misconfigured_split_hints_fires_debug_assert() {
    struct MisconfiguredConnector;
    impl EnumerationConnector for MisconfiguredConnector {
        fn caps(&self) -> ConnectorCapabilities {
            ConnectorCapabilities {
                split_hints: true,
                ..ConnectorCapabilities::default()
            }
        }
        fn enumerate_page(
            &mut self,
            _: &ShardSpec,
            _: &Cursor,
            _: Budgets,
        ) -> Result<EnumerationPage, EnumerateError> {
            Err(EnumerateError::permanent("stub"))
        }
    }
    impl ReadConnector for MisconfiguredConnector {
        fn open(&mut self, _: &ItemRef, _: Budgets) -> Result<Box<dyn io::Read + Send>, ReadError> {
            Err(ReadError::permanent("stub"))
        }
    }
    let mut c = MisconfiguredConnector;
    let _ = c.choose_split_point(&ShardSpec::unbounded(), &Cursor::initial(), budgets());
}

// -- Object-safety coercion (concrete → dyn) --

#[test]
fn concrete_type_coerces_to_dyn_enum_connector() {
    let mut d = Dummy;
    let _: &mut dyn EnumerationConnector = &mut d;
}

#[test]
fn concrete_type_coerces_to_dyn_read_connector() {
    let mut d = Dummy;
    let _: &mut dyn ReadConnector = &mut d;
}

#[test]
fn concrete_type_coerces_to_dyn_connector_instance() {
    let mut d = Dummy;
    let _: &mut dyn ConnectorInstance = &mut d;
}

// -- Successful open() reader --

#[test]
fn open_returns_readable_reader() {
    use std::io::Read;

    struct WorkingConnector;

    impl EnumerationConnector for WorkingConnector {
        fn caps(&self) -> ConnectorCapabilities {
            ConnectorCapabilities::default()
        }
        fn enumerate_page(
            &mut self,
            _: &ShardSpec,
            _: &Cursor,
            _: Budgets,
        ) -> Result<EnumerationPage, EnumerateError> {
            Err(EnumerateError::permanent("stub"))
        }
    }

    impl ReadConnector for WorkingConnector {
        fn open(
            &mut self,
            _item_ref: &ItemRef,
            _budgets: Budgets,
        ) -> Result<Box<dyn io::Read + Send>, ReadError> {
            Ok(Box::new(io::Cursor::new(b"hello world")))
        }
    }

    let mut connector = WorkingConnector;
    let iref = item_ref();
    let mut reader = connector
        .open(&iref, budgets())
        .expect("WorkingConnector::open should succeed");
    let mut buf = Vec::new();
    reader
        .read_to_end(&mut buf)
        .expect("reading from cursor should not fail");
    assert_eq!(buf, b"hello world");
}

// -- Empty-page enumeration semantics --

#[test]
fn empty_page_with_initial_cursor_signals_scan_complete() {
    struct EmptyDoneConnector;

    impl EnumerationConnector for EmptyDoneConnector {
        fn caps(&self) -> ConnectorCapabilities {
            ConnectorCapabilities::default()
        }
        fn enumerate_page(
            &mut self,
            _: &ShardSpec,
            _: &Cursor,
            _: Budgets,
        ) -> Result<EnumerationPage, EnumerateError> {
            Ok(EnumerationPage::new(vec![], Cursor::initial()))
        }
    }

    impl ReadConnector for EmptyDoneConnector {
        fn open(&mut self, _: &ItemRef, _: Budgets) -> Result<Box<dyn io::Read + Send>, ReadError> {
            Err(ReadError::permanent("stub"))
        }
    }

    let mut c = EmptyDoneConnector;
    let page = c
        .enumerate_page(&ShardSpec::unbounded(), &Cursor::initial(), budgets())
        .expect("empty-done page should succeed");
    assert!(page.items().is_empty());
    // Initial cursor returned → no more data.
    assert_eq!(*page.next_cursor(), Cursor::initial());
}

#[test]
fn empty_page_with_advanced_cursor_signals_more_data() {
    use super::super::ItemKey;

    struct EmptyNotDoneConnector;

    impl EnumerationConnector for EmptyNotDoneConnector {
        fn caps(&self) -> ConnectorCapabilities {
            ConnectorCapabilities::default()
        }
        fn enumerate_page(
            &mut self,
            _: &ShardSpec,
            _: &Cursor,
            _: Budgets,
        ) -> Result<EnumerationPage, EnumerateError> {
            let next = Cursor::with_last_key(
                ItemKey::try_from_slice(b"progress-key").expect("valid test key"),
            );
            Ok(EnumerationPage::new(vec![], next))
        }
    }

    impl ReadConnector for EmptyNotDoneConnector {
        fn open(&mut self, _: &ItemRef, _: Budgets) -> Result<Box<dyn io::Read + Send>, ReadError> {
            Err(ReadError::permanent("stub"))
        }
    }

    let mut c = EmptyNotDoneConnector;
    let page = c
        .enumerate_page(&ShardSpec::unbounded(), &Cursor::initial(), budgets())
        .expect("empty-not-done page should succeed");
    assert!(page.items().is_empty());
    // Non-initial cursor returned → more data may exist.
    assert_ne!(*page.next_cursor(), Cursor::initial());
    assert!(page.next_cursor().last_key().is_some());
}

// -- Display sanitization --

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

// -- is_retryable predicate --

#[test]
fn error_class_is_retryable() {
    assert!(ErrorClass::Retryable.is_retryable());
    assert!(!ErrorClass::Permanent.is_retryable());
}

#[test]
fn enumerate_error_is_retryable_delegates_to_class() {
    assert!(EnumerateError::retryable("transient").is_retryable());
    assert!(EnumerateError::rate_limited("throttled", 100).is_retryable());
    assert!(!EnumerateError::permanent("gone").is_retryable());
}

#[test]
fn read_error_is_retryable_delegates_to_class() {
    assert!(ReadError::retryable("transient").is_retryable());
    assert!(ReadError::rate_limited("throttled", 100).is_retryable());
    assert!(!ReadError::permanent("gone").is_retryable());
    assert!(!ReadError::unsupported("range_read").is_retryable());
}

// -- Proptest: property-based coverage for error types --

mod proptests {
    use proptest::prelude::*;

    use super::{EnumerateError, ErrorClass, ReadError};

    fn arb_error_class() -> impl Strategy<Value = ErrorClass> {
        prop_oneof![Just(ErrorClass::Retryable), Just(ErrorClass::Permanent),]
    }

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

        #[test]
        fn enumerate_error_display_never_panics(err in arb_enumerate_error()) {
            let display = err.to_string();
            let prefix = match err.class() {
                ErrorClass::Retryable => "retryable: ",
                ErrorClass::Permanent => "permanent: ",
            };
            prop_assert!(display.starts_with(prefix));
        }

        #[test]
        fn read_error_display_never_panics(err in arb_read_error()) {
            let display = err.to_string();
            let prefix = match err.class() {
                ErrorClass::Retryable => "retryable: ",
                ErrorClass::Permanent => "permanent: ",
            };
            prop_assert!(display.starts_with(prefix));
        }

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
