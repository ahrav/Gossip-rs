//! State transition events and event collection.
//!
//! Every coordination operation (acquire, checkpoint, complete, park,
//! split, unpark, run lifecycle) can produce one or more
//! [`StateTransitionEvent`] values describing what happened. Events are
//! pure data — the coordination layer never acts on them. Side effects
//! (metrics, notifications, dashboards) are the caller's responsibility.
//!
//! ## Design
//!
//! Events are NOT callbacks or subscriptions. They are inert data
//! returned alongside operation results via [`EventCollector`]:
//!
//! - Keeps the coordination layer deterministic and testable.
//! - Avoids coupling to notification infrastructure.
//! - Works with deterministic simulation (events are captured in traces
//!   and can be asserted against).
//!
//! ## Structure
//!
//! Each event is a [`StateTransitionEvent`] envelope carrying the
//! tenant, run, and an [`EventKind`] discriminant with variant-specific
//! fields. This ensures tenant/run are always accessible without
//! pattern-matching into specific kinds.
//!
//! ## Integration Pattern
//!
//! The core [`CoordinationBackend`](super::traits::CoordinationBackend)
//! trait does **not** take an `EventCollector`. Events are an optional
//! extension: backends that want event emission would implement
//! companion `_with_events` methods that accept `&mut EventCollector`
//! alongside the standard parameters. This keeps the core trait
//! minimal for testing and simulation, while enabling rich
//! observability in production.
//!
//! ## Event / Operation Correspondence
//!
//! | Backend operation   | Event(s) emitted                             |
//! |---------------------|----------------------------------------------|
//! | `acquire_and_restore` | `ShardAcquired`                            |
//! | `checkpoint`        | `ShardCheckpointed`                          |
//! | `complete`          | `ShardCompleted`                             |
//! | `park_shard`        | `ShardParked`                                |
//! | `split_replace`     | `ShardSplit`                                 |
//! | `split_residual`    | `ShardResidualCreated`                       |
//! | admin unpark        | `ShardUnparked`                              |
//! | `renew`             | `ShardLeaseRenewed`                          |
//! | `create_run`        | `RunCreated`                                 |
//! | `register_shards`   | `RunActivated`                               |
//! | `complete_run`      | `RunCompleted`                               |
//! | `fail_run`          | `RunFailed`                                  |
//! | `cancel_run`        | `RunCancelled`                               |
//!
//! Reference: Event Sourcing pattern (Fowler, 2005); FoundationDB's
//! approach of returning mutation results for the caller to act on.

use std::fmt;

use crate::coordination::record::ParkReason;
use crate::identity::{FenceEpoch, LogicalTime, RunId, ShardId, TenantId, WorkerId};

// ============================================================================
// RedactedKey
// ============================================================================

/// Opaque key bytes with redacted `Debug` output.
///
/// Wraps `Option<Box<[u8]>>` to prevent accidental logging of
/// sensitive key material. The `Debug` impl shows byte length
/// instead of contents (e.g., `Some(<15 bytes>)`).
#[derive(PartialEq, Eq)]
pub struct RedactedKey(pub Option<Box<[u8]>>);

impl fmt::Debug for RedactedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Some(k) => write!(f, "Some(<{} bytes>)", k.len()),
            None => write!(f, "None"),
        }
    }
}

// ============================================================================
// EventKind
// ============================================================================

/// Discriminant for a [`StateTransitionEvent`], carrying only
/// variant-specific fields.
///
/// Classification methods ([`is_shard_event`](Self::is_shard_event),
/// [`is_terminal`](Self::is_terminal)) use exhaustive `match` so the
/// compiler forces updates when new variants are added.
#[derive(Debug, PartialEq, Eq)]
pub enum EventKind {
    // —— Shard events ——————————————————————————————————————————
    /// A worker acquired (or re-acquired) a shard.
    ///
    /// Emitted by `acquire_and_restore`. The `fence_epoch` is the
    /// **new** epoch after the ownership transfer — any prior lease
    /// is now invalid.
    ShardAcquired {
        shard: ShardId,
        worker: WorkerId,
        fence_epoch: FenceEpoch,
    },

    /// A shard's cursor was advanced via checkpoint.
    ///
    /// `last_key` is the opaque resume position the worker persisted.
    /// `None` means the cursor had no key (should not happen in
    /// practice; checkpoint requires a non-empty key).
    ///
    /// **Serialization warning:** `RedactedKey` only redacts `Debug`
    /// output. A naive `#[derive(Serialize)]` on `EventKind` would
    /// leak raw key bytes. Any future serialization must use a custom
    /// impl that redacts or omits `last_key`.
    ShardCheckpointed {
        shard: ShardId,
        last_key: RedactedKey,
    },

    /// A shard finished processing its entire key range. **Terminal.**
    ///
    /// After this event the shard's status is `Done` and no further
    /// mutations are accepted.
    ShardCompleted { shard: ShardId },

    /// A shard was halted due to an error condition. **Terminal.**
    ///
    /// The `reason` classifies why the shard was parked, which
    /// informs whether automatic retry is sensible. Resumption
    /// requires an out-of-band admin unpark operation.
    ShardParked { shard: ShardId, reason: ParkReason },

    /// A shard was replaced by child shards via SplitReplace. **Terminal.**
    ///
    /// The parent shard transitions to `Split` and is no longer
    /// processable. The `children` collectively cover the parent's
    /// key range with no gaps or overlaps. Stored as `Box<[ShardId]>`
    /// because children are immutable after creation.
    ShardSplit {
        parent: ShardId,
        children: Box<[ShardId]>,
    },

    /// A residual shard was carved off via SplitResidual. **Not terminal.**
    ///
    /// Unlike `ShardSplit`, the parent stays `Active` with a narrowed
    /// key range. The `residual` covers the upper portion that the
    /// parent relinquished. This is the only split variant where the
    /// parent's session remains usable.
    ShardResidualCreated { parent: ShardId, residual: ShardId },

    /// A previously parked shard was resumed by an admin. **Not terminal.**
    ///
    /// This is an out-of-band operation (not part of the worker's
    /// lease-gated protocol). The fence epoch increments on unpark,
    /// invalidating any zombie leases from before the park.
    ShardUnparked {
        shard: ShardId,
        new_fence_epoch: FenceEpoch,
    },

    /// A shard's lease deadline was extended via renewal.
    ///
    /// The fence epoch does not change — renewal is a deadline
    /// extension, not an ownership transfer.
    ShardLeaseRenewed {
        shard: ShardId,
        new_deadline: LogicalTime,
    },

    // —— Run events ———————————————————————————————————————————
    /// A new run was created (no shards registered yet).
    RunCreated,

    /// A run's initial shards were registered and it is now active.
    ///
    /// `shard_count` is the number of shards in the initial manifest.
    /// After this event workers may begin claiming shards.
    RunActivated { shard_count: usize },

    /// All shards in the run completed successfully. **Terminal.**
    RunCompleted,

    /// The run was marked as failed. **Terminal.**
    RunFailed,

    /// The run was cancelled by an admin. **Terminal.**
    RunCancelled,
}

impl EventKind {
    /// Returns `true` if this is a shard-level event.
    ///
    /// Uses exhaustive `match` — the compiler will error if a new
    /// variant is added without updating this method.
    #[must_use]
    pub fn is_shard_event(&self) -> bool {
        match self {
            Self::ShardAcquired { .. }
            | Self::ShardCheckpointed { .. }
            | Self::ShardCompleted { .. }
            | Self::ShardParked { .. }
            | Self::ShardSplit { .. }
            | Self::ShardResidualCreated { .. }
            | Self::ShardUnparked { .. }
            | Self::ShardLeaseRenewed { .. } => true,

            Self::RunCreated
            | Self::RunActivated { .. }
            | Self::RunCompleted
            | Self::RunFailed
            | Self::RunCancelled => false,
        }
    }

    /// Returns `true` if this is a run-level event.
    ///
    /// Complement of [`is_shard_event`](Self::is_shard_event).
    #[must_use]
    pub fn is_run_event(&self) -> bool {
        !self.is_shard_event()
    }

    /// Returns `true` if this event represents a terminal transition.
    ///
    /// Terminal shard events: `ShardCompleted`, `ShardParked`, `ShardSplit`.
    /// Terminal run events: `RunCompleted`, `RunFailed`, `RunCancelled`.
    ///
    /// Uses exhaustive `match` — the compiler will error if a new
    /// variant is added without updating this method.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        match self {
            Self::ShardCompleted { .. }
            | Self::ShardParked { .. }
            | Self::ShardSplit { .. }
            | Self::RunCompleted
            | Self::RunFailed
            | Self::RunCancelled => true,

            Self::ShardAcquired { .. }
            | Self::ShardCheckpointed { .. }
            | Self::ShardResidualCreated { .. }
            | Self::ShardUnparked { .. }
            | Self::ShardLeaseRenewed { .. }
            | Self::RunCreated
            | Self::RunActivated { .. } => false,
        }
    }
}

// Compile-time guard: EventKind should stay small (currently 32 bytes on 64-bit).
// Bump this limit deliberately if adding a new variant with large inline data.
const _: () = assert!(std::mem::size_of::<EventKind>() <= 40);

// ============================================================================
// StateTransitionEvent
// ============================================================================

/// A state transition event emitted by coordination operations.
///
/// Envelope struct carrying `(tenant, run, at, kind)`. The `kind`
/// field holds variant-specific data via [`EventKind`].
///
/// ## Structural Invariant
///
/// Every event carries `(TenantId, RunId, LogicalTime)`, ensuring
/// events can always be routed by tenant, correlated to a run, and
/// ordered by logical timestamp without pattern-matching into
/// specific fields.
///
/// ## Terminal vs. Non-Terminal
///
/// Some events signal that a shard or run has reached a final state
/// and will accept no further mutations. See
/// [`EventKind::is_terminal()`] for the exhaustive list and the
/// rationale for each classification.
///
/// ## Security
///
/// `ShardCheckpointed` carries `last_key: RedactedKey` which wraps
/// opaque key material. `RedactedKey`'s `Debug` impl redacts raw
/// bytes to byte lengths (e.g., `Some(<15 bytes>)`).
/// Do NOT add `#[derive(Serialize)]` without a custom `Serialize` impl
/// that redacts `EventKind::ShardCheckpointed::last_key`. The
/// `RedactedKey` wrapper only protects `Debug` output — a naive
/// `Serialize` derive would leak raw key bytes.
#[derive(Debug, PartialEq, Eq)]
pub struct StateTransitionEvent {
    pub tenant: TenantId,
    pub run: RunId,
    pub at: LogicalTime,
    pub kind: EventKind,
}

impl StateTransitionEvent {
    /// Returns `true` if this is a shard-level event.
    #[must_use]
    pub fn is_shard_event(&self) -> bool {
        self.kind.is_shard_event()
    }

    /// Returns `true` if this is a run-level event.
    #[must_use]
    pub fn is_run_event(&self) -> bool {
        self.kind.is_run_event()
    }

    /// Returns `true` if this event represents a terminal transition.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        self.kind.is_terminal()
    }
}

// Compile-time guard: StateTransitionEvent should stay ≤ 88 bytes (currently 80).
// Bump deliberately if adding new envelope fields.
const _: () = assert!(std::mem::size_of::<StateTransitionEvent>() <= 88);

// ============================================================================
// EventCollector
// ============================================================================

/// Accumulator for [`StateTransitionEvent`]s during a coordination
/// operation.
///
/// The caller creates a collector, passes it (as `&mut`) to a
/// backend's `_with_events` extension method, and then drains or
/// iterates the collected events after the operation completes.
///
/// ## Usage
///
/// ```rust,ignore
/// // Illustrative — `_with_events` methods are the planned extension pattern.
/// let mut events = EventCollector::new();
/// backend.checkpoint_with_events(now, tenant, lease, cursor, op_id, &mut events)?;
/// for event in events.drain() {
///     metrics.record(&event);
/// }
/// ```
///
/// ## Design Note
///
/// The core [`CoordinationBackend`](super::traits::CoordinationBackend)
/// trait methods do **not** take an `EventCollector` — they define
/// the minimal semantic contract. Backends that want event emission
/// would provide companion `_with_events` methods that accept
/// `&mut EventCollector`. This keeps the trait simple for testing and
/// deterministic simulation.
///
/// ## Reuse
///
/// A single collector can be reused across multiple operations by
/// calling [`drain()`](Self::drain) between them. Draining transfers
/// ownership of the accumulated events to the caller and resets the
/// collector to empty.
#[derive(Debug, Default)]
pub struct EventCollector {
    events: Vec<StateTransitionEvent>,
}

impl EventCollector {
    /// Create an empty event collector with no pre-allocated capacity.
    #[must_use]
    pub fn new() -> Self {
        Self { events: Vec::new() }
    }

    /// Create an event collector pre-allocated for `cap` events.
    ///
    /// Useful when the caller knows the approximate number of events
    /// an operation will produce, avoiding intermediate reallocations.
    #[must_use]
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            events: Vec::with_capacity(cap),
        }
    }

    /// Append an event to the collector. Events are stored in
    /// emission order.
    ///
    /// # Panics (debug builds only)
    ///
    /// Panics if the new event's tenant differs from previously
    /// collected events. A single collector must not mix tenants —
    /// doing so indicates a routing bug in the caller.
    pub fn emit(&mut self, event: StateTransitionEvent) {
        debug_assert!(
            self.events.is_empty() || self.events[0].tenant == event.tenant,
            "EventCollector cross-tenant mixing: first event tenant {:?}, new event tenant {:?}",
            self.events[0].tenant,
            event.tenant,
        );
        self.events.push(event);
    }

    /// Take all collected events, leaving the collector empty.
    ///
    /// Uses [`std::mem::take`] — O(1) pointer swap, no per-element
    /// moves. The returned `Vec` owns the events; the collector can
    /// be reused immediately (but loses its prior allocation).
    ///
    /// Prefer [`drain_with`](Self::drain_with) when the collector
    /// will be reused and allocation preservation matters.
    pub fn drain(&mut self) -> Vec<StateTransitionEvent> {
        std::mem::take(&mut self.events)
    }

    /// Process all collected events via `f`, preserving the
    /// underlying allocation for reuse.
    ///
    /// Unlike [`drain()`](Self::drain) which transfers the `Vec` to
    /// the caller (losing the allocation), this method uses
    /// `Vec::drain(..)` so subsequent `emit` calls reuse the same
    /// buffer without reallocating.
    pub fn drain_with<F: FnMut(StateTransitionEvent)>(&mut self, f: F) {
        self.events.drain(..).for_each(f);
    }

    /// Number of events collected so far.
    #[must_use]
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Returns `true` if no events have been collected.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Borrow the collected events without consuming them.
    ///
    /// Useful for inspection (e.g., counting terminal events) while
    /// keeping the collector intact for a later [`drain()`](Self::drain).
    pub fn iter(&self) -> impl Iterator<Item = &StateTransitionEvent> {
        self.events.iter()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_tenant() -> TenantId {
        TenantId::from_bytes([0x01; 32])
    }

    fn test_run() -> RunId {
        RunId::from_raw(1)
    }

    fn test_time() -> LogicalTime {
        LogicalTime::from_raw(1000)
    }

    fn evt(kind: EventKind) -> StateTransitionEvent {
        StateTransitionEvent {
            tenant: test_tenant(),
            run: test_run(),
            at: test_time(),
            kind,
        }
    }

    /// Exhaustive classification table for all EventKind variants.
    /// Each entry: (kind, expected_is_shard, expected_is_terminal).
    fn classification_table() -> Vec<(EventKind, bool, bool)> {
        let s = ShardId::from_raw(0);
        vec![
            // Shard events — non-terminal
            (
                EventKind::ShardAcquired {
                    shard: s,
                    worker: WorkerId::from_raw(1),
                    fence_epoch: FenceEpoch::from_raw(1),
                },
                true,
                false,
            ),
            (
                EventKind::ShardCheckpointed {
                    shard: s,
                    last_key: RedactedKey(Some(b"k".to_vec().into_boxed_slice())),
                },
                true,
                false,
            ),
            (
                EventKind::ShardResidualCreated {
                    parent: s,
                    residual: ShardId::from_raw(1),
                },
                true,
                false,
            ),
            (
                EventKind::ShardUnparked {
                    shard: s,
                    new_fence_epoch: FenceEpoch::from_raw(2),
                },
                true,
                false,
            ),
            (
                EventKind::ShardLeaseRenewed {
                    shard: s,
                    new_deadline: LogicalTime::from_raw(100),
                },
                true,
                false,
            ),
            // Shard events — terminal
            (EventKind::ShardCompleted { shard: s }, true, true),
            (
                EventKind::ShardParked {
                    shard: s,
                    reason: ParkReason::Other,
                },
                true,
                true,
            ),
            (
                EventKind::ShardSplit {
                    parent: s,
                    children: vec![ShardId::from_raw(1), ShardId::from_raw(2)].into_boxed_slice(),
                },
                true,
                true,
            ),
            // Run events — non-terminal
            (EventKind::RunCreated, false, false),
            (EventKind::RunActivated { shard_count: 3 }, false, false),
            // Run events — terminal
            (EventKind::RunCompleted, false, true),
            (EventKind::RunFailed, false, true),
            (EventKind::RunCancelled, false, true),
        ]
    }

    #[test]
    fn event_classification_exhaustive() {
        for (kind, expect_shard, expect_terminal) in classification_table() {
            // Check EventKind methods directly before moving into envelope.
            assert_eq!(kind.is_shard_event(), expect_shard, "{kind:?}");
            assert_eq!(kind.is_run_event(), !expect_shard, "{kind:?}");
            assert_eq!(kind.is_terminal(), expect_terminal, "{kind:?}");
            // Move kind into envelope and verify delegation agrees.
            let event = evt(kind);
            assert_eq!(event.is_shard_event(), expect_shard, "{event:?}");
            assert_eq!(event.is_run_event(), !expect_shard, "{event:?}");
            assert_eq!(event.is_terminal(), expect_terminal, "{event:?}");
            assert_eq!(event.tenant, test_tenant(), "{event:?}");
            assert_eq!(event.run, test_run(), "{event:?}");
        }
    }

    #[test]
    fn collector_basic() {
        let mut c = EventCollector::new();
        assert!(c.is_empty());
        assert_eq!(c.len(), 0);

        c.emit(evt(EventKind::RunCreated));
        assert!(!c.is_empty());
        assert_eq!(c.len(), 1);

        let events = c.drain();
        assert_eq!(events.len(), 1);
        assert!(c.is_empty());
    }

    #[test]
    fn collector_multi_emit() {
        let mut c = EventCollector::new();
        c.emit(evt(EventKind::ShardAcquired {
            shard: ShardId::from_raw(0),
            worker: WorkerId::from_raw(1),
            fence_epoch: FenceEpoch::from_raw(2),
        }));
        c.emit(evt(EventKind::ShardCheckpointed {
            shard: ShardId::from_raw(0),
            last_key: RedactedKey(Some(b"k".to_vec().into_boxed_slice())),
        }));
        c.emit(evt(EventKind::ShardCompleted {
            shard: ShardId::from_raw(0),
        }));

        assert_eq!(c.len(), 3);
        let events = c.drain();
        assert!(events[0].is_shard_event());
        assert!(!events[1].is_terminal());
        assert!(events[2].is_terminal());
    }

    #[test]
    fn collector_iter_without_drain() {
        let mut c = EventCollector::new();
        c.emit(evt(EventKind::RunCreated));
        c.emit(evt(EventKind::RunCompleted));

        let terminals: Vec<_> = c.iter().filter(|e| e.is_terminal()).collect();
        assert_eq!(terminals.len(), 1);
        // Not drained — still available.
        assert_eq!(c.len(), 2);
    }

    #[test]
    fn collector_drain_clears() {
        let mut c = EventCollector::new();
        c.emit(evt(EventKind::RunCreated));
        let _ = c.drain();
        assert!(c.is_empty());
        let second = c.drain();
        assert!(second.is_empty());
    }

    #[test]
    fn debug_redacts_checkpoint_last_key() {
        let event = evt(EventKind::ShardCheckpointed {
            shard: ShardId::from_raw(0),
            last_key: RedactedKey(Some(b"secret-key-data".to_vec().into_boxed_slice())),
        });
        let debug = format!("{event:?}");
        assert!(
            debug.contains("<15 bytes>"),
            "must redact key to byte length: {debug}"
        );
        assert!(
            !debug.contains("secret"),
            "must not leak raw key bytes: {debug}"
        );
    }

    #[test]
    fn with_capacity_preallocates() {
        let c = EventCollector::with_capacity(16);
        assert!(c.is_empty());
        assert_eq!(c.len(), 0);
    }

    #[test]
    fn drain_with_preserves_capacity() {
        let mut c = EventCollector::with_capacity(8);
        for i in 0..5 {
            c.emit(StateTransitionEvent {
                tenant: test_tenant(),
                run: test_run(),
                at: test_time(),
                kind: EventKind::ShardCompleted {
                    shard: ShardId::from_raw(i),
                },
            });
        }
        let mut count = 0usize;
        c.drain_with(|_| count += 1);
        assert_eq!(count, 5);
        assert!(c.is_empty());

        // Emit again — should reuse the allocation (no observable
        // way to assert capacity from outside, but this verifies
        // the API works after drain_with).
        c.emit(evt(EventKind::RunCreated));
        assert_eq!(c.len(), 1);
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "cross-tenant mixing")]
    fn emit_cross_tenant_panics_in_debug() {
        let other_tenant = TenantId::from_bytes([0x02; 32]);
        let mut c = EventCollector::new();
        c.emit(evt(EventKind::RunCreated));
        c.emit(StateTransitionEvent {
            tenant: other_tenant,
            run: test_run(),
            at: test_time(),
            kind: EventKind::RunCreated,
        });
    }
}
