//! PostgreSQL-backed implementation of
//! [`GitPersistenceBackend`](gossip_scanner_runtime::git_persistence::GitPersistenceBackend).
//!
//! ## Architecture
//!
//! A single synchronous `postgres::Client` is held behind an `Arc<Mutex<_>>`,
//! making [`GitPersistencePg`] cheaply cloneable and `Send + Sync`. The four
//! backend SQL queries are prepared eagerly at construction and reused for
//! every subsequent call, avoiding repeated Parse+Describe+Sync round-trips.
//! Each `apply_batch` executes inside an explicit transaction, so the backend
//! can advertise
//! [`supports_atomic_batches`](GitPersistencePg::supports_atomic_batches)
//! as `true`.
//!
//! ## Batch normalization
//!
//! One `apply_batch` call may contain repeated keys. The backend normalizes the
//! input in reverse-iteration order before issuing SQL:
//!
//! - the final operation for a given key wins (detected via reverse scan);
//! - surviving `Put` operations are batched into one `INSERT .. ON CONFLICT`;
//! - surviving `Delete` operations are batched into one `DELETE .. ANY()`.
//!
//! A borrowed `HashSet<&[u8]>` tracks seen keys during the reverse pass,
//! avoiding intermediate key clones for duplicates.
//!
//! ## Positional alignment
//!
//! `multi_get` preserves the caller's requested order: the returned
//! `Vec<Option<Vec<u8>>>` is positionally aligned with the input key slice,
//! with `None` for missing keys and duplicated results for duplicated inputs.

use std::{
    collections::{HashMap, HashSet},
    fmt,
    sync::{Arc, Mutex, MutexGuard},
};

#[cfg(feature = "test-utils")]
use postgres::NoTls;
use postgres::{Client, Statement};

use gossip_scanner_runtime::git_persistence::{GitPersistenceBackend, GitPersistenceOp};

use crate::{
    error::GitPersistencePgError,
    migrations::apply_all_migrations,
    schema::{DELETE_SQL, GET_SQL, MAX_KEY_OCTETS, MAX_VALUE_OCTETS, MULTI_GET_SQL, UPSERT_SQL},
};

#[derive(Debug)]
struct NormalizedBatch {
    puts: Vec<(Vec<u8>, Vec<u8>)>,
    delete_keys: Vec<Vec<u8>>,
}

impl NormalizedBatch {
    /// Deduplicate a batch of persistence operations by key, preserving
    /// last-writer-wins semantics.
    ///
    /// Iterates the input in reverse so the first encounter of each key
    /// corresponds to the final operation. A borrowed `HashSet<&[u8]>` tracks
    /// seen keys without cloning; only surviving keys and values are cloned
    /// into the output vectors.
    fn from_ops(ops: &[GitPersistenceOp]) -> Self {
        let mut seen = HashSet::<&[u8]>::with_capacity(ops.len());
        let mut puts = Vec::with_capacity(ops.len());
        let mut delete_keys = Vec::new();

        for op in ops.iter().rev() {
            match op {
                GitPersistenceOp::Put { key, value } => {
                    if seen.insert(key.as_slice()) {
                        puts.push((key.clone(), value.clone()));
                    }
                }
                GitPersistenceOp::Delete { key } => {
                    if seen.insert(key.as_slice()) {
                        delete_keys.push(key.clone());
                    }
                }
            }
        }

        Self { puts, delete_keys }
    }

    fn is_empty(&self) -> bool {
        self.puts.is_empty() && self.delete_keys.is_empty()
    }
}

/// Pre-prepared PostgreSQL statements for the four backend queries.
///
/// Prepared once during [`GitPersistencePg::from_client`] and reused for every
/// subsequent operation, avoiding a Parse+Describe+Sync server round-trip per
/// call. [`Statement`] is `Arc`-backed and cheap to clone.
#[derive(Clone)]
struct PreparedStatements {
    get: Statement,
    multi_get: Statement,
    upsert: Statement,
    delete: Statement,
}

/// Synchronous PostgreSQL implementation of [`GitPersistenceBackend`].
///
/// Internally wraps a `postgres::Client` in `Arc<Mutex<_>>` so that clones
/// share the same connection and callers can use `GitPersistencePg` from
/// multiple threads. Four backend queries are prepared eagerly at construction
/// and reused across every subsequent operation.
///
/// # Concurrency
///
/// The mutex serializes all database access through a single connection.
/// Concurrent `get`, `multi_get`, and `apply_batch` calls block on the mutex,
/// so throughput is limited to one operation at a time. The runtime's
/// single-writer Git adapter model matches that restriction.
///
/// # Construction
///
/// | Constructor | TLS | Migrations | Feature gate | Use case |
/// |---|---|---|---|---|
/// | [`connect`](Self::connect) | `NoTls` | No | `test-utils` | Quick local / test setup |
/// | [`connect_and_migrate`](Self::connect_and_migrate) | `NoTls` | Yes | `test-utils` | Local dev with auto-schema |
/// | [`from_client`](Self::from_client) | Caller-chosen | No | *(always)* | Production (TLS, pooling) |
///
/// After calling [`from_client`](Self::from_client), use
/// [`apply_migrations`](Self::apply_migrations) to run schema migrations if
/// needed.
#[derive(Clone)]
pub struct GitPersistencePg {
    client: Arc<Mutex<Client>>,
    stmts: PreparedStatements,
}

impl GitPersistencePg {
    /// Connect to PostgreSQL without applying migrations.
    ///
    /// Uses `NoTls` — intended for local development and integration tests
    /// only. Production callers should construct a TLS-enabled
    /// [`Client`](postgres::Client) and use [`from_client`](Self::from_client).
    ///
    /// Requires the `test-utils` feature.
    ///
    /// # Errors
    ///
    /// Returns [`GitPersistencePgError::Postgres`] on connection or statement
    /// preparation failure.
    #[cfg(feature = "test-utils")]
    pub fn connect(database_url: &str) -> Result<Self, GitPersistencePgError> {
        let client = Client::connect(database_url, NoTls)?;
        Self::from_client(client)
    }

    /// Connect to PostgreSQL and apply crate-embedded migrations.
    ///
    /// Equivalent to [`connect`](Self::connect) followed by
    /// [`apply_migrations`](Self::apply_migrations). Uses `NoTls` —
    /// intended for local development and integration tests only.
    ///
    /// Requires the `test-utils` feature.
    ///
    /// # Errors
    ///
    /// Returns [`GitPersistencePgError::Postgres`] on connection or statement
    /// preparation failure, or [`GitPersistencePgError::Migration`] if schema
    /// migration fails.
    #[cfg(feature = "test-utils")]
    pub fn connect_and_migrate(database_url: &str) -> Result<Self, GitPersistencePgError> {
        let client = Client::connect(database_url, NoTls)?;
        let backend = Self::from_client(client)?;
        backend.apply_migrations()?;
        Ok(backend)
    }

    /// Wrap an already-connected PostgreSQL client and prepare backend
    /// statements.
    ///
    /// The preferred production constructor: the caller controls TLS
    /// configuration, connection parameters, and pooling. Call
    /// [`apply_migrations`](Self::apply_migrations) afterwards if the schema
    /// has not yet been applied.
    ///
    /// # Errors
    ///
    /// Returns [`GitPersistencePgError::Postgres`] if statement preparation
    /// fails (e.g. the connection is broken).
    pub fn from_client(mut client: Client) -> Result<Self, GitPersistencePgError> {
        let stmts = PreparedStatements {
            get: client.prepare(GET_SQL)?,
            multi_get: client.prepare(MULTI_GET_SQL)?,
            upsert: client.prepare(UPSERT_SQL)?,
            delete: client.prepare(DELETE_SQL)?,
        };
        Ok(Self {
            client: Arc::new(Mutex::new(client)),
            stmts,
        })
    }

    /// Apply all embedded migrations using the held client.
    ///
    /// Idempotent and concurrency-safe — see [`crate::migrations`] for the
    /// advisory-lock and checksum-verification protocol.
    ///
    /// # Errors
    ///
    /// Returns [`GitPersistencePgError::Migration`] on SQL failure or checksum
    /// mismatch, or [`GitPersistencePgError::MutexPoisoned`] if the internal
    /// mutex was poisoned.
    pub fn apply_migrations(&self) -> Result<(), GitPersistencePgError> {
        let mut client = self.lock_client()?;
        apply_all_migrations(&mut client)?;
        Ok(())
    }

    /// Remove all rows from the key/value table.
    ///
    /// This helper is intended for crate-local integration tests.
    #[cfg(test)]
    pub(crate) fn truncate_all_for_tests(&self) -> Result<(), GitPersistencePgError> {
        let mut client = self.lock_client()?;
        client.batch_execute(&format!("DELETE FROM {}", crate::schema::GIT_KV_TABLE))?;
        Ok(())
    }

    /// Acquire the internal mutex, returning `MutexPoisoned` if a prior
    /// holder panicked.
    ///
    /// Poisoning is treated as terminal because the connection's internal
    /// state (prepared statements, transaction nesting) is indeterminate after
    /// a panic during SQL execution. Attempting to reuse a potentially
    /// half-committed connection risks silent data corruption.
    fn lock_client(&self) -> Result<MutexGuard<'_, Client>, GitPersistencePgError> {
        self.client
            .lock()
            .map_err(|_| GitPersistencePgError::MutexPoisoned)
    }
}

impl fmt::Debug for GitPersistencePg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GitPersistencePg").finish_non_exhaustive()
    }
}

impl GitPersistenceBackend for GitPersistencePg {
    type Error = GitPersistencePgError;

    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
        let mut client = self.lock_client()?;
        let row = client.query_opt(&self.stmts.get, &[&key])?;
        match row {
            Some(row) => Ok(Some(row.try_get(0)?)),
            None => Ok(None),
        }
    }

    fn apply_batch(&self, ops: &[GitPersistenceOp]) -> Result<(), Self::Error> {
        let normalized = NormalizedBatch::from_ops(ops);
        if normalized.is_empty() {
            return Ok(());
        }

        for (key, value) in &normalized.puts {
            if key.len() > MAX_KEY_OCTETS || value.len() > MAX_VALUE_OCTETS {
                return Err(GitPersistencePgError::PayloadTooLarge {
                    key_len: key.len(),
                    value_len: value.len(),
                });
            }
        }

        for key in &normalized.delete_keys {
            if key.len() > MAX_KEY_OCTETS {
                return Err(GitPersistencePgError::PayloadTooLarge {
                    key_len: key.len(),
                    value_len: 0,
                });
            }
        }

        let mut client = self.lock_client()?;
        // Pre-prepared statement handles (self.stmts) are valid inside the
        // transaction — the postgres crate shares its statement cache between
        // the connection and any transactions derived from it.
        let mut tx = client.transaction()?;

        if !normalized.puts.is_empty() {
            let put_keys: Vec<&[u8]> = normalized.puts.iter().map(|(k, _)| k.as_slice()).collect();
            let put_values: Vec<&[u8]> =
                normalized.puts.iter().map(|(_, v)| v.as_slice()).collect();
            tx.execute(&self.stmts.upsert, &[&put_keys, &put_values])?;
        }

        if !normalized.delete_keys.is_empty() {
            let delete_keys: Vec<&[u8]> =
                normalized.delete_keys.iter().map(Vec::as_slice).collect();
            tx.execute(&self.stmts.delete, &[&delete_keys])?;
        }

        tx.commit()?;
        Ok(())
    }

    fn supports_atomic_batches(&self) -> bool {
        true
    }

    fn multi_get(&self, keys: &[Vec<u8>]) -> Result<Vec<Option<Vec<u8>>>, Self::Error> {
        if keys.is_empty() {
            return Ok(Vec::new());
        }

        let requested_keys: Vec<&[u8]> = keys.iter().map(Vec::as_slice).collect();

        let mut client = self.lock_client()?;
        let rows = client.query(&self.stmts.multi_get, &[&requested_keys])?;

        // Positional alignment: build a lookup map, then project each input
        // key to its value. Duplicate input keys produce cloned values. Current
        // callers (watermark/checkpoint loads) always pass distinct keys, so
        // the clone cost is limited to one copy per present key.
        let mut by_key = HashMap::<Vec<u8>, Vec<u8>>::with_capacity(rows.len());
        for row in rows {
            let key: Vec<u8> = row.try_get(0)?;
            let value: Vec<u8> = row.try_get(1)?;
            by_key.insert(key, value);
        }

        // Clone values for positional alignment. Duplicate input keys must
        // receive duplicated results, so `get().cloned()` is correct here;
        // `remove()` would lose the value for subsequent occurrences of the
        // same key.
        Ok(keys.iter().map(|key| by_key.get(key).cloned()).collect())
    }
}
