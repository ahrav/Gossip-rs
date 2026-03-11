//! Rust ↔ PostgreSQL type-mapping helpers for `u64` fields stored as
//! `BIGINT`.
//!
//! PostgreSQL `BIGINT` is signed, but findings persistence needs two distinct
//! storage modes:
//!
//! | Mode | Fields | Accepted range | SQL semantics preserved |
//! |------|--------|----------------|-------------------------|
//! | **Bit-pattern** | `run_id`, `shard_id` | Full `u64` (`0..=u64::MAX`) | `=`, `GROUP BY` only |
//! | **Ordered non-negative** | `fence_epoch`, `seen_at`, `byte_offset`, `byte_length` | `0..=i64::MAX` | `<`, `>`, `ORDER BY`, `BETWEEN` |
//!
//! Bit-pattern mode preserves the exact 64-bit payload for identifiers that
//! only participate in equality or grouping. Ordered mode rejects values above
//! `i64::MAX` so SQL ordering remains consistent with Rust-side numeric
//! ordering.

use std::{error::Error, fmt};

/// Error produced when a `u64` ↔ `BIGINT` conversion violates a storage-mode
/// invariant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PgU64ConversionError {
    /// A value exceeded the ordered non-negative `BIGINT` domain.
    OrderedOutOfRange {
        /// Schema column name.
        field: &'static str,
        /// The Rust-side value that did not fit.
        value: u64,
    },
    /// A supposedly non-negative persisted `BIGINT` value was negative.
    NegativeStoredValue {
        /// Schema column name.
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
/// This preserves the exact 64-bit payload, but it does not preserve SQL
/// numeric ordering once the sign bit is set. Use it only for identifier
/// columns that participate in equality or grouping operations.
#[inline]
#[must_use]
pub fn u64_to_pg_bigint_bits(value: u64) -> i64 {
    i64::from_ne_bytes(value.to_ne_bytes())
}

/// Decode a `BIGINT` back to `u64` by reinterpreting the raw 8-byte
/// representation.
///
/// Inverse of [`u64_to_pg_bigint_bits`]. This preserves the exact 64-bit
/// payload, but the SQL value must still be treated as an equality/grouping
/// identifier rather than an ordered numeric quantity.
#[inline]
#[must_use]
pub fn pg_bigint_to_u64_bits(value: i64) -> u64 {
    u64::from_ne_bytes(value.to_ne_bytes())
}

/// Encode a `u64` as a non-negative `BIGINT`.
///
/// # Errors
///
/// Returns [`PgU64ConversionError::OrderedOutOfRange`] if `value > i64::MAX`.
/// The `field` argument is copied into the error so callers can report which
/// schema column rejected the value.
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
/// Returns [`PgU64ConversionError::NegativeStoredValue`] if `value < 0`. The
/// `field` argument is copied into the error so callers can report which
/// schema column contained the invalid stored value.
#[inline]
pub fn pg_bigint_nonnegative_to_u64(
    value: i64,
    field: &'static str,
) -> Result<u64, PgU64ConversionError> {
    if value < 0 {
        return Err(PgU64ConversionError::NegativeStoredValue { field, value });
    }
    Ok(value as u64)
}

#[cfg(test)]
mod tests {
    use super::{
        PgU64ConversionError, pg_bigint_nonnegative_to_u64, pg_bigint_to_u64_bits,
        u64_to_pg_bigint_bits, u64_to_pg_bigint_checked,
    };

    use gossip_contracts::test_util::miri_proptest_config;
    use proptest::prelude::*;

    #[test]
    fn bit_pattern_round_trip_preserves_boundary_values() {
        for raw in [0, 1, i64::MAX as u64, (i64::MAX as u64) + 1, u64::MAX] {
            let stored = u64_to_pg_bigint_bits(raw);
            let restored = pg_bigint_to_u64_bits(stored);
            assert_eq!(restored, raw);
        }
    }

    #[test]
    fn bit_pattern_round_trip_i64_min_bit_pattern() {
        let value = i64::MIN as u64;
        let stored = u64_to_pg_bigint_bits(value);
        assert_eq!(stored, i64::MIN);
        assert_eq!(pg_bigint_to_u64_bits(stored), value);
    }

    #[test]
    fn ordered_mode_round_trips_zero() {
        let stored =
            u64_to_pg_bigint_checked(0, "byte_offset").expect("zero should fit in ordered mode");
        assert_eq!(stored, 0);
        assert_eq!(
            pg_bigint_nonnegative_to_u64(stored, "byte_offset")
                .expect("zero should decode in ordered mode"),
            0
        );
    }

    #[test]
    fn ordered_mode_round_trips_one() {
        let stored =
            u64_to_pg_bigint_checked(1, "byte_length").expect("one should fit in ordered mode");
        assert_eq!(stored, 1);
        assert_eq!(
            pg_bigint_nonnegative_to_u64(stored, "byte_length")
                .expect("one should decode in ordered mode"),
            1
        );
    }

    #[test]
    fn ordered_mode_accepts_i64_max_boundary() {
        let value = i64::MAX as u64;
        let stored = u64_to_pg_bigint_checked(value, "seen_at")
            .expect("i64::MAX should fit in ordered mode");
        assert_eq!(stored, i64::MAX);
        assert_eq!(
            pg_bigint_nonnegative_to_u64(stored, "seen_at").expect("stored i64::MAX should decode"),
            value
        );
    }

    #[test]
    fn ordered_mode_rejects_values_above_i64_max() {
        let overflow = (i64::MAX as u64) + 1;
        let err = u64_to_pg_bigint_checked(overflow, "fence_epoch")
            .expect_err("ordered mode must reject values above i64::MAX");

        assert_eq!(
            err,
            PgU64ConversionError::OrderedOutOfRange {
                field: "fence_epoch",
                value: overflow,
            }
        );
    }

    #[test]
    fn ordered_mode_rejects_negative_stored_values() {
        let err = pg_bigint_nonnegative_to_u64(-1, "seen_at")
            .expect_err("negative stored values must fail");

        assert_eq!(
            err,
            PgU64ConversionError::NegativeStoredValue {
                field: "seen_at",
                value: -1,
            }
        );
    }

    #[test]
    fn ordered_mode_rejects_i64_min_as_stored_value() {
        let err = pg_bigint_nonnegative_to_u64(i64::MIN, "byte_offset")
            .expect_err("i64::MIN is negative and must be rejected");

        assert_eq!(
            err,
            PgU64ConversionError::NegativeStoredValue {
                field: "byte_offset",
                value: i64::MIN,
            }
        );
    }

    #[test]
    fn conversion_error_display_mentions_field_and_value() {
        let overflow = PgU64ConversionError::OrderedOutOfRange {
            field: "byte_length",
            value: u64::MAX,
        };
        assert!(overflow.to_string().contains("byte_length"));
        assert!(overflow.to_string().contains(&u64::MAX.to_string()));

        let negative = PgU64ConversionError::NegativeStoredValue {
            field: "seen_at",
            value: -42,
        };
        assert!(negative.to_string().contains("seen_at"));
        assert!(negative.to_string().contains("-42"));
    }

    proptest! {
        #![proptest_config(miri_proptest_config())]

        #[test]
        fn bit_pattern_round_trip_full_domain(value: u64) {
            let stored = u64_to_pg_bigint_bits(value);
            let restored = pg_bigint_to_u64_bits(stored);
            prop_assert_eq!(restored, value);
        }

        #[test]
        fn ordered_round_trip_nonnegative_domain(value in 0u64..=(i64::MAX as u64)) {
            let stored = u64_to_pg_bigint_checked(value, "test_field")
                .expect("values in the ordered domain should encode");
            let restored = pg_bigint_nonnegative_to_u64(stored, "test_field")
                .expect("non-negative BIGINT values should decode");
            prop_assert_eq!(restored, value);
        }

        #[test]
        fn ordered_rejects_values_above_i64_max(value in ((i64::MAX as u64) + 1)..=u64::MAX) {
            let err = u64_to_pg_bigint_checked(value, "test_field");
            prop_assert!(err.is_err(), "values above i64::MAX must be rejected");
        }
    }
}
