//! Helpers for mapping contract `u64` values onto PostgreSQL `BIGINT` columns.
//!
//! We intentionally use two strategies:
//!
//! - **Bit reinterpretation** for equality/grouping identifiers (`run_id`,
//!   `shard_id`) where signed ordering is irrelevant.
//! - **Checked non-negative `BIGINT`** for ordered counters/times
//!   (`fence_epoch`, `seen_at`, byte offsets/lengths) where SQL ordering must
//!   preserve semantic ordering.

use std::{error::Error, fmt};

/// Conversion failures between contract `u64` values and PostgreSQL `BIGINT`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PgIntConversionError {
    /// A value exceeded the positive range of PostgreSQL `BIGINT` for a column
    /// that relies on natural SQL ordering.
    OutOfRange { field: &'static str, value: u64 },
    /// A supposedly non-negative stored `BIGINT` contained a negative value.
    NegativeStoredValue { field: &'static str, value: i64 },
}

impl fmt::Display for PgIntConversionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutOfRange { field, value } => {
                write!(f, "{field}={value} does not fit into ordered PostgreSQL BIGINT")
            }
            Self::NegativeStoredValue { field, value } => {
                write!(f, "stored PostgreSQL BIGINT for {field} was negative: {value}")
            }
        }
    }
}

impl Error for PgIntConversionError {}

/// Reinterpret a `u64` as PostgreSQL `BIGINT` bits.
///
/// Use this only for columns that participate in equality, grouping, or joins,
/// not range ordering.
#[inline]
#[must_use]
pub fn u64_to_pg_i64_bits(v: u64) -> i64 {
    i64::from_ne_bytes(v.to_ne_bytes())
}

/// Reverse [`u64_to_pg_i64_bits`].
#[inline]
#[must_use]
pub fn pg_i64_bits_to_u64(v: i64) -> u64 {
    u64::from_ne_bytes(v.to_ne_bytes())
}

/// Convert a `u64` into a non-negative PostgreSQL `BIGINT`, rejecting values
/// above `i64::MAX`.
#[inline]
pub fn u64_to_pg_i64_checked(v: u64, field: &'static str) -> Result<i64, PgIntConversionError> {
    i64::try_from(v).map_err(|_| PgIntConversionError::OutOfRange { field, value: v })
}

/// Convert a stored non-negative PostgreSQL `BIGINT` back into `u64`.
#[inline]
pub fn pg_i64_nonnegative_to_u64(v: i64, field: &'static str) -> Result<u64, PgIntConversionError> {
    if v < 0 {
        return Err(PgIntConversionError::NegativeStoredValue { field, value: v });
    }
    Ok(v as u64)
}
