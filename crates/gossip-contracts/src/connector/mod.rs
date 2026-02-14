//! Enumeration/read traits, connector registration, and runtime bridge types.
//!
//! This module owns the traits that data-source connectors implement
//! (`EnumerationConnector`, `ReadConnector`), the value types they exchange
//! (`ScanItem`, `ItemRef`, `EnumerationPage`, `VersionId`), page validation
//! and cursor extraction helpers, the circuit-breaker state machine
//! (`CircuitBreakerState`, `CircuitConfig`), connector registration
//! (`ConnectorRegistration`), per-item outcome tracking (`ItemOutcome`),
//! and shard-level scan statistics (`ShardScanStats`). Behind the
//! `test-support` feature flag it also provides `DeterministicConnector`
//! for downstream integration tests.
//!
//! **Dependency direction:** May depend on `identity`, `coordination`, and
//! `shard` (for ID types, shard metadata, and key-range types). Must not
//! reference `persistence`.
//!
//! **Key invariants:**
//! - Page validation — enumeration pages carry monotonically advancing cursors
//!   and must not be empty.
//! - Circuit-breaker state machine — transitions follow `Closed → Open →
//!   HalfOpen → Closed` with configurable thresholds.
//! - Connector registration uniqueness — no two connectors may share the
//!   same scheme identifier.
