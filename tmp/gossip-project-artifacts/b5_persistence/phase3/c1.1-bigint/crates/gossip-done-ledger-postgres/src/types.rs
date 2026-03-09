//! Rust-side conversions for representing `u64` contract fields in PostgreSQL
//! `BIGINT` columns.
//!
//! There are two storage modes:
//!
//! - **bit-pattern mode** for identifiers used only for equality/grouping
//!   (`run_id`, `shard_id`): this preserves the full `u64` space by storing the
//!   raw two's-complement bit pattern in a signed `BIGINT` column;
//! - **ordered non-negative mode** for counters/timestamps that rely on SQL
//!   ordering (`fence_epoch`, `started_at`, `finished_at`, etc.): this requires
//!   the value to fit into the positive signed `BIGINT` range.

use std::{error::Error, fmt};

/// Conversion failure while mapping between contract `u64` fields and PostgreSQL
/// `BIGINT` storage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PgU64ConversionError {
    /// A `u64` value does not fit in the non-negative range of PostgreSQL
    /// `BIGINT` and therefore cannot be stored in ordered mode.
    OrderedOutOfRange {
        field: &'static str,
        value: u64,
    },
    /// A value read from a non-negative `BIGINT` column was negative, which
    /// violates the schema contract.
    NegativeStoredValue {
        field: &'static str,
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

/// Convert a `u64` to PostgreSQL `BIGINT` by preserving the raw two's-complement
/// bit pattern.
///
/// Use this for identifier/grouping fields where SQL ordering is irrelevant.
#[inline]
#[must_use]
pub fn u64_to_pg_bigint_bits(value: u64) -> i64 {
    i64::from_ne_bytes(value.to_ne_bytes())
}

/// Convert a PostgreSQL `BIGINT` back to `u64` by preserving the raw bit
/// pattern.
///
/// This is the inverse of [`u64_to_pg_bigint_bits`].
#[inline]
#[must_use]
pub fn pg_bigint_to_u64_bits(value: i64) -> u64 {
    u64::from_ne_bytes(value.to_ne_bytes())
}

/// Convert a `u64` to PostgreSQL `BIGINT` in ordered non-negative mode.
///
/// This fails if the value exceeds `i64::MAX`, because ordered SQL semantics
/// require staying inside the positive signed range.
#[inline]
pub fn u64_to_pg_bigint_checked(
    value: u64,
    field: &'static str,
) -> Result<i64, PgU64ConversionError> {
    i64::try_from(value).map_err(|_| PgU64ConversionError::OrderedOutOfRange { field, value })
}

/// Convert a PostgreSQL `BIGINT` from a non-negative ordered column back to
/// `u64`.
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

// Tests intentionally omitted for this task.
// Add unit coverage in C1.3 for:
// - bit-pattern round-trip on edge values (0, 1, u64::MAX)
// - ordered conversion succeeds for i64::MAX and fails for i64::MAX + 1
// - negative stored value rejection for ordered columns
