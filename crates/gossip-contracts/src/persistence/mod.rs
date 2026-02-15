//! Done-ledger, findings-sink traits, and the commit protocol typestate machine.
//!
//! Owns the persistence boundary: the `DoneLedger` trait for
//! recording completed work (`DoneLedgerKey`, `OvidHash`), the `FindingsSink`
//! trait for emitting detection results (`FindingRecord`, `OccurrenceRecord`,
//! `FindingsUpsertBatch`), and the `PageCommit<S>` typestate machine that
//! enforces the commit protocol at compile time — ensuring that a page's
//! done-ledger writes, findings upserts, and cursor checkpoint happen in the
//! correct order and exactly once. Behind the `test-support` feature flag it
//! also provides `InMemoryDoneLedger` and `InMemoryFindingsSink` reference
//! implementations for downstream tests.
//!
//! **Dependency direction:** May depend on `identity`, `coordination`, and
//! `connector` (for ID types, shard metadata, and item outcome types). This
//! is the rightmost module in the acyclic boundary graph.
//!
//! **Key invariants:**
//! - Commit protocol typestate — the `PageCommit` state machine enforces
//!   the write→upsert→checkpoint sequence at compile time; skipping or
//!   reordering steps is a type error.
//! - Done-ledger idempotency — recording the same `DoneLedgerKey` twice
//!   is a no-op.
//! - Findings deduplication — `FindingsSink` upsert semantics ensure that
//!   duplicate `(FindingId, OccurrenceId)` pairs are merged, not duplicated.
