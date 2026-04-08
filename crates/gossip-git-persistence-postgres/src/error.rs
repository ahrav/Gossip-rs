//! Error types for the PostgreSQL Git persistence backend and migration
//! subsystem.
//!
//! All schema-migration failures are funneled through
//! [`GitPersistencePgMigrationError`], which distinguishes transport/SQL
//! failures from checksum-integrity violations. Backend operation failures
//! are exposed through [`GitPersistencePgError`].

use std::fmt;

pub use gossip_pg_common::migration::{
    MigrationOperation, PgMigrationError as GitPersistencePgMigrationError,
};

/// Unified backend error for the PostgreSQL Git persistence implementation.
///
/// This is the `GitPersistenceBackend::Error` associated type for
/// [`GitPersistencePg`](crate::GitPersistencePg). Variants fall into three
/// categories:
///
/// - **Infrastructure** — connection failures, mutex poisoning, migration
///   errors ([`Postgres`](Self::Postgres), [`Migration`](Self::Migration),
///   [`MutexPoisoned`](Self::MutexPoisoned));
/// - **Driver/runtime** — SQL execution failures reported by `postgres`;
/// - **Migration integrity** — checksum mismatches or corrupted history
///   records surfaced via [`GitPersistencePgMigrationError`].
#[derive(Debug, thiserror::Error)]
pub enum GitPersistencePgError {
    /// PostgreSQL client failure.
    Postgres(#[from] postgres::Error),
    /// Embedded migration application failed.
    Migration(#[from] GitPersistencePgMigrationError),
    /// Internal client mutex was poisoned by a panic.
    MutexPoisoned,
}

impl fmt::Display for GitPersistencePgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Postgres(source) => {
                if let Some(db_err) = source.as_db_error() {
                    write!(
                        f,
                        "postgres git-persistence operation failed: {} ({})",
                        db_err.severity(),
                        db_err.code().code()
                    )
                } else {
                    // IO/connection errors may embed connection strings — redact details.
                    // Full diagnostics remain available via `Error::source()`.
                    write!(f, "postgres git-persistence connection/protocol error")
                }
            }
            Self::Migration(source) => {
                write!(f, "postgres git-persistence migration failed: {source}")
            }
            Self::MutexPoisoned => f.write_str("postgres git-persistence client mutex is poisoned"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_mismatch_display_includes_version_and_hashes() {
        let err = GitPersistencePgMigrationError::ChecksumMismatch {
            version: "0001_git_kv",
            expected_hex: "aa".repeat(32),
            found_hex: "bb".repeat(32),
        };
        let msg = err.to_string();
        assert!(msg.contains("0001_git_kv"), "should contain version: {msg}");
        assert!(
            msg.contains(&"aa".repeat(32)),
            "should contain expected hex: {msg}"
        );
        assert!(
            msg.contains(&"bb".repeat(32)),
            "should contain found hex: {msg}"
        );
    }
}
