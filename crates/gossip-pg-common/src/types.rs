//! Rust ↔ PostgreSQL type-mapping helpers.
//!
//! # `u64` ↔ `BIGINT`
//!
//! PostgreSQL `BIGINT` is a signed 64-bit integer, but domain types
//! throughout gossip-rs use `u64` for both opaque identifiers and ordered
//! counters. These two use cases have different SQL requirements:
//!
//! | Mode | Use case | Accepted range | SQL semantics preserved |
//! |------|----------|----------------|-------------------------|
//! | **Bit-pattern** | Opaque identifiers (equality/grouping only) | Full `u64` (`0..=u64::MAX`) | `=`, `GROUP BY` only |
//! | **Ordered non-negative** | Monotonic counters, timestamps, byte offsets | `0..=i64::MAX` | `<`, `>`, `ORDER BY`, `BETWEEN` |
//!
//! Bit-pattern mode reinterprets the 8 bytes without changing them, so a
//! `u64` value above `i64::MAX` becomes a negative `BIGINT` in SQL — this
//! is harmless because the backend never orders or range-scans these
//! columns.
//!
//! Ordered non-negative mode rejects values above `i64::MAX` at the Rust
//! boundary, because a negative `BIGINT` would invert SQL ordering.
//!
//! Each function pair (`u64_to_pg_*` / `pg_*_to_u64`) is a bijection over
//! its accepted domain. Round-trip correctness is verified in unit tests.
//!
//! # `BYTEA` ↔ fixed-length byte arrays
//!
//! [`decode_fixed_32`] converts a borrowed `&[u8]` slice (obtained via
//! `Row::try_get::<_, &[u8]>`) into a `[u8; 32]` array, returning
//! [`PgByteDecodeError::InvalidByteLength`] when the slice length does not
//! match. This avoids the `Vec<u8>` allocation that `try_get::<_, Vec<u8>>`
//! would incur.

use std::{error::Error, fmt};

/// Error produced when a `u64` ↔ `BIGINT` conversion violates domain
/// constraints.
///
/// Both variants carry the `field` name so that error messages identify which
/// column triggered the failure without requiring the caller to wrap the error
/// with additional context.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PgU64ConversionError {
    /// A `u64` value exceeds `i64::MAX` and cannot be stored in ordered
    /// non-negative mode without breaking SQL ordering semantics.
    OrderedOutOfRange {
        /// Schema column name (e.g. `"fence_epoch"`, `"bytes_scanned"`).
        field: &'static str,
        /// The out-of-range Rust-side value.
        value: u64,
    },
    /// A value read from a column that the schema constrains to `>= 0` was
    /// negative. This indicates either data corruption or a schema-constraint
    /// bypass.
    NegativeStoredValue {
        /// Schema column name (e.g. `"started_at"`).
        field: &'static str,
        /// The negative value read from PostgreSQL.
        value: i64,
    },
}

impl fmt::Display for PgU64ConversionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::OrderedOutOfRange { field, value } => write!(
                f,
                "value {value} for field {field} exceeds non-negative PostgreSQL BIGINT range"
            ),
            Self::NegativeStoredValue { field, value } => write!(
                f,
                "stored value {value} for field {field} is negative but the schema requires non-negative BIGINT"
            ),
        }
    }
}

impl Error for PgU64ConversionError {}

/// Encode a `u64` as `BIGINT` by reinterpreting the raw 8-byte representation.
///
/// Infallible: every `u64` value maps to exactly one `i64` bit pattern and
/// vice versa. The resulting `i64` may be negative, so this encoding must
/// only be used for columns where SQL never performs ordering or range
/// comparisons (i.e., equality/grouping-only identifiers).
#[inline]
#[must_use]
pub fn u64_to_pg_bigint_bits(value: u64) -> i64 {
    i64::from_ne_bytes(value.to_ne_bytes())
}

/// Decode a `BIGINT` back to `u64` by reinterpreting the raw 8-byte
/// representation.
///
/// Inverse of [`u64_to_pg_bigint_bits`]. Infallible and lossless.
#[inline]
#[must_use]
pub fn pg_bigint_to_u64_bits(value: i64) -> u64 {
    u64::from_ne_bytes(value.to_ne_bytes())
}

/// Encode a `u64` as a non-negative `BIGINT` for columns that rely on SQL
/// ordering.
///
/// # Errors
///
/// Returns [`PgU64ConversionError::OrderedOutOfRange`] if `value > i64::MAX`,
/// because storing it would produce a negative `BIGINT` that inverts SQL
/// `ORDER BY` and `>=` semantics.
#[inline]
pub fn u64_to_pg_bigint_checked(
    value: u64,
    field: &'static str,
) -> Result<i64, PgU64ConversionError> {
    i64::try_from(value).map_err(|_| PgU64ConversionError::OrderedOutOfRange { field, value })
}

/// Decode a non-negative `BIGINT` back to `u64`.
///
/// # Errors
///
/// Returns [`PgU64ConversionError::NegativeStoredValue`] if the database
/// value is negative, indicating either data corruption or a constraint
/// violation that bypassed the `CHECK (column >= 0)` guard.
#[inline]
pub fn pg_bigint_nonnegative_to_u64(
    value: i64,
    field: &'static str,
) -> Result<u64, PgU64ConversionError> {
    if value < 0 {
        return Err(PgU64ConversionError::NegativeStoredValue { field, value });
    }
    // Non-negative i64 values are in range 0..=i64::MAX, which is a subset of u64,
    // so this cast is lossless.
    Ok(value as u64)
}

/// Error produced when a `BYTEA` column cannot be decoded into a
/// fixed-length byte array.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PgByteDecodeError {
    /// The stored blob length does not match the expected fixed width.
    InvalidByteLength {
        /// Schema column or field name.
        field: &'static str,
        /// The fixed width the caller requires (e.g. 32 for identity hashes).
        expected: usize,
        /// The actual number of bytes returned by PostgreSQL.
        actual: usize,
    },
}

impl fmt::Display for PgByteDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::InvalidByteLength {
                field,
                expected,
                actual,
            } => write!(f, "field {field}: expected {expected} bytes, got {actual}"),
        }
    }
}

impl Error for PgByteDecodeError {}

/// Decode a `BYTEA` column value into a fixed 32-byte identity array.
///
/// Accepts `&[u8]` to avoid forcing a `Vec<u8>` allocation at the call
/// site — `postgres::Row::try_get::<_, &[u8]>` borrows directly from the
/// row buffer.
///
/// # Errors
///
/// Returns [`PgByteDecodeError::InvalidByteLength`] when `bytes.len() != 32`.
pub fn decode_fixed_32(bytes: &[u8], field: &'static str) -> Result<[u8; 32], PgByteDecodeError> {
    bytes
        .try_into()
        .map_err(|_| PgByteDecodeError::InvalidByteLength {
            field,
            expected: 32,
            actual: bytes.len(),
        })
}

#[cfg(test)]
mod tests {
    use super::{
        PgByteDecodeError, PgU64ConversionError, decode_fixed_32, pg_bigint_nonnegative_to_u64,
        pg_bigint_to_u64_bits, u64_to_pg_bigint_bits, u64_to_pg_bigint_checked,
    };

    use gossip_contracts::test_util::miri_proptest_config;
    use proptest::prelude::*;

    // ── Bit-pattern mode ────────────────────────────────────────────

    #[test]
    fn bit_pattern_round_trip_preserves_full_u64_domain() {
        for raw in [0, 1, u64::MAX, i64::MAX as u64, (i64::MAX as u64) + 1] {
            let stored = u64_to_pg_bigint_bits(raw);
            let restored = pg_bigint_to_u64_bits(stored);
            assert_eq!(restored, raw);
        }
    }

    #[test]
    fn bit_pattern_round_trip_i64_min() {
        // i64::MIN as u64 is 2^63, which should round-trip through bit-pattern mode.
        let value = i64::MIN as u64;
        let stored = u64_to_pg_bigint_bits(value);
        assert_eq!(stored, i64::MIN);
        let restored = pg_bigint_to_u64_bits(stored);
        assert_eq!(restored, value);
    }

    // ── Ordered non-negative mode ───────────────────────────────────

    #[test]
    fn ordered_mode_zero() {
        let stored = u64_to_pg_bigint_checked(0, "test_field")
            .expect("zero should be valid in ordered mode");
        assert_eq!(stored, 0i64);
        let restored = pg_bigint_nonnegative_to_u64(stored, "test_field")
            .expect("zero should decode in ordered mode");
        assert_eq!(restored, 0u64);
    }

    #[test]
    fn ordered_mode_one() {
        let stored =
            u64_to_pg_bigint_checked(1, "test_field").expect("one should fit in ordered mode");
        assert_eq!(stored, 1);
        assert_eq!(
            pg_bigint_nonnegative_to_u64(stored, "test_field")
                .expect("one should decode in ordered mode"),
            1
        );
    }

    #[test]
    fn ordered_mode_accepts_i64_max_boundary() {
        let value = i64::MAX as u64;
        let stored = u64_to_pg_bigint_checked(value, "test_field")
            .expect("i64::MAX should fit in ordered BIGINT mode");
        assert_eq!(stored, i64::MAX);

        let restored = pg_bigint_nonnegative_to_u64(stored, "test_field")
            .expect("non-negative BIGINT should decode in ordered mode");
        assert_eq!(restored, value);
    }

    #[test]
    fn ordered_mode_rejects_values_above_i64_max() {
        let overflow = (i64::MAX as u64) + 1;
        let err = u64_to_pg_bigint_checked(overflow, "test_field")
            .expect_err("ordered mode must reject values above i64::MAX");

        assert_eq!(
            err,
            PgU64ConversionError::OrderedOutOfRange {
                field: "test_field",
                value: overflow,
            }
        );
    }

    #[test]
    fn ordered_mode_rejects_negative_stored_values() {
        let err = pg_bigint_nonnegative_to_u64(-1, "test_field")
            .expect_err("negative BIGINT cannot decode in ordered mode");

        assert_eq!(
            err,
            PgU64ConversionError::NegativeStoredValue {
                field: "test_field",
                value: -1,
            }
        );
    }

    #[test]
    fn ordered_mode_rejects_i64_min_as_stored_value() {
        let err = pg_bigint_nonnegative_to_u64(i64::MIN, "test_field")
            .expect_err("i64::MIN is negative and must be rejected");
        assert_eq!(
            err,
            PgU64ConversionError::NegativeStoredValue {
                field: "test_field",
                value: i64::MIN,
            }
        );
    }

    // ── Display ─────────────────────────────────────────────────────

    #[test]
    fn conversion_error_display_includes_field_name() {
        let ordered_err = PgU64ConversionError::OrderedOutOfRange {
            field: "test_field",
            value: u64::MAX,
        };
        let msg = ordered_err.to_string();
        assert!(
            msg.contains("test_field"),
            "Display should include field name: {msg}"
        );
        assert!(
            msg.contains(&u64::MAX.to_string()),
            "Display should include value: {msg}"
        );

        let negative_err = PgU64ConversionError::NegativeStoredValue {
            field: "test_field",
            value: -42,
        };
        let msg = negative_err.to_string();
        assert!(
            msg.contains("test_field"),
            "Display should include field name: {msg}"
        );
        assert!(msg.contains("-42"), "Display should include value: {msg}");
    }

    // ── Proptest: full-domain bijection verification ────────────────

    proptest! {
        #![proptest_config(miri_proptest_config())]

        #[test]
        fn bit_pattern_round_trip_full_domain(value: u64) {
            let stored = u64_to_pg_bigint_bits(value);
            let restored = pg_bigint_to_u64_bits(stored);
            prop_assert_eq!(restored, value);
        }

        #[test]
        fn ordered_round_trip_nonneg_domain(value in 0u64..=(i64::MAX as u64)) {
            let stored = u64_to_pg_bigint_checked(value, "test_field")
                .expect("value within i64::MAX must succeed");
            let restored = pg_bigint_nonnegative_to_u64(stored, "test_field")
                .expect("non-negative stored value must decode");
            prop_assert_eq!(restored, value);
        }

        #[test]
        fn ordered_rejects_above_i64_max(value in ((i64::MAX as u64) + 1)..=u64::MAX) {
            let err = u64_to_pg_bigint_checked(value, "test_field");
            prop_assert!(err.is_err(), "values above i64::MAX must be rejected");
        }
    }

    // ── BYTEA decode ───────────────────────────────────────────────

    #[test]
    fn decode_fixed_32_accepts_exactly_32_bytes() {
        let bytes = [0xAB; 32];
        assert_eq!(
            decode_fixed_32(&bytes, "test_field").expect("32-byte slice should decode"),
            [0xAB; 32]
        );
    }

    #[test]
    fn decode_fixed_32_rejects_31_bytes() {
        let bytes = [0xAB; 31];
        assert_eq!(
            decode_fixed_32(&bytes, "test_field"),
            Err(PgByteDecodeError::InvalidByteLength {
                field: "test_field",
                expected: 32,
                actual: 31,
            })
        );
    }

    #[test]
    fn decode_fixed_32_rejects_33_bytes() {
        let bytes = [0xAB; 33];
        assert_eq!(
            decode_fixed_32(&bytes, "test_field"),
            Err(PgByteDecodeError::InvalidByteLength {
                field: "test_field",
                expected: 32,
                actual: 33,
            })
        );
    }

    #[test]
    fn decode_fixed_32_rejects_empty() {
        assert_eq!(
            decode_fixed_32(&[], "test_field"),
            Err(PgByteDecodeError::InvalidByteLength {
                field: "test_field",
                expected: 32,
                actual: 0,
            })
        );
    }
}
