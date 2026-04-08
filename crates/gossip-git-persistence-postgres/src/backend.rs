//! PostgreSQL-backed implementation of
//! [`GitPersistenceBackend`](gossip_scanner_runtime::git_persistence::GitPersistenceBackend).
//!
//! ## Architecture
//!
//! A single synchronous `postgres::Client` is held behind an `Arc<Mutex<_>>`,
//! making [`GitPersistencePg`] cheaply cloneable and `Send + Sync`. Each
//! `apply_batch` executes inside an explicit transaction, so the backend can
//! advertise [`supports_atomic_batches`](GitPersistencePg::supports_atomic_batches)
//! as `true`.
//!
//! ## Batch normalization
//!
//! One `apply_batch` call may contain repeated keys. The backend normalizes the
//! input in submission order before issuing SQL:
//!
//! - the final operation for a given key wins;
//! - surviving `Put` operations are batched into one `INSERT .. ON CONFLICT`;
//! - surviving `Delete` operations are batched into one `DELETE .. ANY()`.
//!
//! This preserves the sequential semantics of the in-memory test backends while
//! still keeping the database round-trip count bounded.
//!
//! ## Positional alignment
//!
//! `multi_get` preserves the caller's requested order: the returned
//! `Vec<Option<Vec<u8>>>` is positionally aligned with the input key slice,
//! with `None` for missing keys and duplicated results for duplicated inputs.

use std::{
    collections::HashMap,
    fmt,
    sync::{Arc, Mutex, MutexGuard},
};

use postgres::Client;
#[cfg(feature = "test-utils")]
use postgres::NoTls;

use gossip_scanner_runtime::git_persistence::{GitPersistenceBackend, GitPersistenceOp};

use crate::{
    error::GitPersistencePgError,
    migrations::apply_all_migrations,
    schema::{DELETE_SQL, GET_SQL, MULTI_GET_SQL, UPSERT_SQL},
};

#[derive(Debug)]
enum FinalBatchOp {
    Put(Vec<u8>),
    Delete,
}

#[derive(Debug, Default)]
struct NormalizedBatch {
    put_keys: Vec<Vec<u8>>,
    put_values: Vec<Vec<u8>>,
    delete_keys: Vec<Vec<u8>>,
}

impl NormalizedBatch {
    fn from_ops(ops: &[GitPersistenceOp]) -> Self {
        let mut final_ops = HashMap::<Vec<u8>, FinalBatchOp>::with_capacity(ops.len());
        for op in ops {
            match op {
                GitPersistenceOp::Put { key, value } => {
                    final_ops.insert(key.clone(), FinalBatchOp::Put(value.clone()));
                }
                GitPersistenceOp::Delete { key } => {
                    final_ops.insert(key.clone(), FinalBatchOp::Delete);
                }
            }
        }

        let mut normalized = Self::default();
        for (key, op) in final_ops {
            match op {
                FinalBatchOp::Put(value) => {
                    normalized.put_keys.push(key);
                    normalized.put_values.push(value);
                }
                FinalBatchOp::Delete => normalized.delete_keys.push(key),
            }
        }
        normalized
    }

    fn is_empty(&self) -> bool {
        self.put_keys.is_empty() && self.delete_keys.is_empty()
    }
}

/// Synchronous PostgreSQL implementation of [`GitPersistenceBackend`].
///
/// Internally wraps a `postgres::Client` in `Arc<Mutex<_>>` so that clones
/// share the same connection and callers can use `GitPersistencePg` from
/// multiple threads.
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
    /// Returns [`GitPersistencePgError::Postgres`] on connection failure.
    #[cfg(feature = "test-utils")]
    pub fn connect(database_url: &str) -> Result<Self, GitPersistencePgError> {
        let client = Client::connect(database_url, NoTls)?;
        Ok(Self::from_client(client))
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
    /// Returns [`GitPersistencePgError::Postgres`] on connection failure or
    /// [`GitPersistencePgError::Migration`] if schema migration fails.
    #[cfg(feature = "test-utils")]
    pub fn connect_and_migrate(database_url: &str) -> Result<Self, GitPersistencePgError> {
        let client = Client::connect(database_url, NoTls)?;
        let backend = Self::from_client(client);
        backend.apply_migrations()?;
        Ok(backend)
    }

    /// Wrap an already-connected PostgreSQL client.
    ///
    /// The preferred production constructor: the caller controls TLS
    /// configuration, connection parameters, and pooling. Call
    /// [`apply_migrations`](Self::apply_migrations) afterwards if the schema
    /// has not yet been applied.
    #[inline]
    #[must_use]
    pub fn from_client(client: Client) -> Self {
        Self {
            client: Arc::new(Mutex::new(client)),
        }
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
        let stmt = client.prepare(GET_SQL)?;
        let row = client.query_opt(&stmt, &[&key])?;
        Ok(row.map(|row| row.get(0)))
    }

    fn apply_batch(&self, ops: &[GitPersistenceOp]) -> Result<(), Self::Error> {
        let normalized = NormalizedBatch::from_ops(ops);
        if normalized.is_empty() {
            return Ok(());
        }

        let mut client = self.lock_client()?;
        let mut tx = client.transaction()?;

        if !normalized.put_keys.is_empty() {
            let put_keys: Vec<&[u8]> = normalized.put_keys.iter().map(Vec::as_slice).collect();
            let put_values: Vec<&[u8]> = normalized.put_values.iter().map(Vec::as_slice).collect();
            let stmt = tx.prepare(UPSERT_SQL)?;
            tx.execute(&stmt, &[&put_keys, &put_values])?;
        }

        if !normalized.delete_keys.is_empty() {
            let delete_keys: Vec<&[u8]> =
                normalized.delete_keys.iter().map(Vec::as_slice).collect();
            let stmt = tx.prepare(DELETE_SQL)?;
            tx.execute(&stmt, &[&delete_keys])?;
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
        let stmt = client.prepare(MULTI_GET_SQL)?;
        let rows = client.query(&stmt, &[&requested_keys])?;

        let mut by_key = HashMap::<Vec<u8>, Vec<u8>>::with_capacity(rows.len());
        for row in rows {
            let key: Vec<u8> = row.get(0);
            let value: Vec<u8> = row.get(1);
            by_key.insert(key, value);
        }

        Ok(keys.iter().map(|key| by_key.get(key).cloned()).collect())
    }
}
