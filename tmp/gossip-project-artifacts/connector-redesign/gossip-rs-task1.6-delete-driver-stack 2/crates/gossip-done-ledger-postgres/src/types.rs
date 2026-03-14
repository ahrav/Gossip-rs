//! Rust ↔ PostgreSQL type-mapping for `u64` fields stored as `BIGINT`.
//!
//! PostgreSQL `BIGINT` is a signed 64-bit integer. The contracts layer uses
//! `u64` for both opaque identifiers and ordered counters, but these two use
//! cases have different SQL requirements:
//!
//! | Mode | Fields | Accepted range | SQL semantics preserved |
//! |------|--------|----------------|-------------------------|
//! | **Bit-pattern** | `run_id`, `shard_id` | Full `u64` (`0..=u64::MAX`) | `=`, `GROUP BY` only |
//! | **Ordered non-negative** | `fence_epoch`, `started_at`, `finished_at`, `bytes_scanned` | `0..=i64::MAX` | `<`, `>`, `ORDER BY`, `BETWEEN` |
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
/// comparisons (i.e., equality/grouping-only identifiers like `run_id` and
/// `shard_id`).
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

#[cfg(test)]
mod tests {
    use super::{
        PgU64ConversionError, pg_bigint_nonnegative_to_u64, pg_bigint_to_u64_bits,
        u64_to_pg_bigint_bits, u64_to_pg_bigint_checked,
    };

    #[test]
    fn bit_pattern_round_trip_preserves_full_u64_domain() {
        for raw in [0, 1, u64::MAX, i64::MAX as u64, (i64::MAX as u64) + 1] {
            let stored = u64_to_pg_bigint_bits(raw);
            let restored = pg_bigint_to_u64_bits(stored);
            assert_eq!(restored, raw);
        }
    }

    #[test]
    fn ordered_mode_accepts_i64_max_boundary() {
        let value = i64::MAX as u64;
        let stored = u64_to_pg_bigint_checked(value, "finished_at")
            .expect("i64::MAX should fit in ordered BIGINT mode");
        assert_eq!(stored, i64::MAX);

        let restored = pg_bigint_nonnegative_to_u64(stored, "finished_at")
            .expect("non-negative BIGINT should decode in ordered mode");
        assert_eq!(restored, value);
    }

    #[test]
    fn ordered_mode_rejects_values_above_i64_max() {
        let overflow = (i64::MAX as u64) + 1;
        let err = u64_to_pg_bigint_checked(overflow, "bytes_scanned")
            .expect_err("ordered mode must reject values above i64::MAX");

        assert_eq!(
            err,
            PgU64ConversionError::OrderedOutOfRange {
                field: "bytes_scanned",
                value: overflow,
            }
        );
    }

    #[test]
    fn ordered_mode_rejects_negative_stored_values() {
        let err = pg_bigint_nonnegative_to_u64(-1, "started_at")
            .expect_err("negative BIGINT cannot decode in ordered mode");

        assert_eq!(
            err,
            PgU64ConversionError::NegativeStoredValue {
                field: "started_at",
                value: -1,
            }
        );
    }

    // ── Proptest: full-domain bijection verification ────────────────

    use gossip_contracts::test_util::miri_proptest_config;
    use proptest::prelude::*;

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

    // ── Edge cases ──────────────────────────────────────────────────

    #[test]
    fn bit_pattern_round_trip_i64_min() {
        // i64::MIN as u64 is 2^63, which should round-trip through bit-pattern mode.
        let value = i64::MIN as u64;
        let stored = u64_to_pg_bigint_bits(value);
        assert_eq!(stored, i64::MIN);
        let restored = pg_bigint_to_u64_bits(stored);
        assert_eq!(restored, value);
    }

    #[test]
    fn ordered_mode_zero() {
        let stored = u64_to_pg_bigint_checked(0, "fence_epoch")
            .expect("zero should be valid in ordered mode");
        assert_eq!(stored, 0i64);
        let restored = pg_bigint_nonnegative_to_u64(stored, "fence_epoch")
            .expect("zero should decode in ordered mode");
        assert_eq!(restored, 0u64);
    }

    #[test]
    fn ordered_mode_rejects_i64_min_as_stored_value() {
        let err = pg_bigint_nonnegative_to_u64(i64::MIN, "started_at")
            .expect_err("i64::MIN is negative and must be rejected");
        assert_eq!(
            err,
            PgU64ConversionError::NegativeStoredValue {
                field: "started_at",
                value: i64::MIN,
            }
        );
    }

    // ── Display tests ───────────────────────────────────────────────

    #[test]
    fn conversion_error_display_includes_field_name() {
        let ordered_err = PgU64ConversionError::OrderedOutOfRange {
            field: "bytes_scanned",
            value: u64::MAX,
        };
        let msg = ordered_err.to_string();
        assert!(
            msg.contains("bytes_scanned"),
            "Display should include field name: {msg}"
        );

        let negative_err = PgU64ConversionError::NegativeStoredValue {
            field: "started_at",
            value: -42,
        };
        let msg = negative_err.to_string();
        assert!(
            msg.contains("started_at"),
            "Display should include field name: {msg}"
        );
    }
}
