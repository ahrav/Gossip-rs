//! State transition events and event collection.
//!
//! Events are value types returned alongside operation results. The
//! coordination layer is pure and testable — side effects (metrics,
//! notifications, dashboards) happen in the caller.
//!
//! ## Design
//!
//! Events are NOT callbacks or subscriptions. They are data emitted
//! by coordination operations for the caller to process:
//!
//! - Keeps the coordination layer deterministic and testable
//! - Avoids coupling to notification infrastructure
//! - Works with deterministic simulation (events captured in trace)
//!
//! Reference: Event Sourcing pattern (Fowler, 2005); FoundationDB's
//! approach of returning mutation results for the caller to act on.

use crate::identity::{
    FenceEpoch, LogicalTime, RunId, ShardId, TenantId, WorkerId,
};
use crate::coordination::record::ParkReason;

// ============================================================================
// § StateTransitionEvent
// ============================================================================

/// A state transition event emitted by coordination operations.
///
/// The caller (orchestrator, scheduler) decides how to handle events —
/// logging, metrics, triggering follow-up actions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StateTransitionEvent {
    // —— Shard events ——

    /// A shard was acquired by a worker.
    ShardAcquired {
        tenant: TenantId,
        run: RunId,
        shard: ShardId,
        worker: WorkerId,
        fence_epoch: FenceEpoch,
    },

    /// A shard's cursor was checkpointed.
    ShardCheckpointed {
        tenant: TenantId,
        run: RunId,
        shard: ShardId,
        last_key: Option<Box<[u8]>>,
    },

    /// A shard completed successfully.
    ShardCompleted {
        tenant: TenantId,
        run: RunId,
        shard: ShardId,
    },

    /// A shard was parked due to an error.
    ShardParked {
        tenant: TenantId,
        run: RunId,
        shard: ShardId,
        reason: ParkReason,
    },

    /// A shard was split into children (SplitReplace).
    ShardSplit {
        tenant: TenantId,
        run: RunId,
        parent: ShardId,
        children: Vec<ShardId>,
    },

    /// A residual shard was created (SplitResidual).
    ShardResidualCreated {
        tenant: TenantId,
        run: RunId,
        parent: ShardId,
        residual: ShardId,
    },

    /// A shard was unparked by an admin.
    ShardUnparked {
        tenant: TenantId,
        run: RunId,
        shard: ShardId,
        new_fence_epoch: FenceEpoch,
    },

    /// A shard's lease was renewed.
    ShardLeaseRenewed {
        tenant: TenantId,
        run: RunId,
        shard: ShardId,
        new_deadline: LogicalTime,
    },

    // —— Run events ——

    /// A new run was created.
    RunCreated {
        tenant: TenantId,
        run: RunId,
    },

    /// A run was activated (initial shards registered).
    RunActivated {
        tenant: TenantId,
        run: RunId,
        shard_count: usize,
    },

    /// A run completed successfully.
    RunCompleted {
        tenant: TenantId,
        run: RunId,
    },

    /// A run failed.
    RunFailed {
        tenant: TenantId,
        run: RunId,
    },

    /// A run was cancelled by an admin.
    RunCancelled {
        tenant: TenantId,
        run: RunId,
    },
}

impl StateTransitionEvent {
    /// The tenant this event belongs to.
    pub fn tenant(&self) -> TenantId {
        match self {
            Self::ShardAcquired { tenant, .. }
            | Self::ShardCheckpointed { tenant, .. }
            | Self::ShardCompleted { tenant, .. }
            | Self::ShardParked { tenant, .. }
            | Self::ShardSplit { tenant, .. }
            | Self::ShardResidualCreated { tenant, .. }
            | Self::ShardUnparked { tenant, .. }
            | Self::ShardLeaseRenewed { tenant, .. }
            | Self::RunCreated { tenant, .. }
            | Self::RunActivated { tenant, .. }
            | Self::RunCompleted { tenant, .. }
            | Self::RunFailed { tenant, .. }
            | Self::RunCancelled { tenant, .. } => *tenant,
        }
    }

    /// The run this event belongs to.
    pub fn run(&self) -> RunId {
        match self {
            Self::ShardAcquired { run, .. }
            | Self::ShardCheckpointed { run, .. }
            | Self::ShardCompleted { run, .. }
            | Self::ShardParked { run, .. }
            | Self::ShardSplit { run, .. }
            | Self::ShardResidualCreated { run, .. }
            | Self::ShardUnparked { run, .. }
            | Self::ShardLeaseRenewed { run, .. }
            | Self::RunCreated { run, .. }
            | Self::RunActivated { run, .. }
            | Self::RunCompleted { run, .. }
            | Self::RunFailed { run, .. }
            | Self::RunCancelled { run, .. } => *run,
        }
    }

    /// Returns `true` if this is a shard-level event.
    pub fn is_shard_event(&self) -> bool {
        matches!(
            self,
            Self::ShardAcquired { .. }
                | Self::ShardCheckpointed { .. }
                | Self::ShardCompleted { .. }
                | Self::ShardParked { .. }
                | Self::ShardSplit { .. }
                | Self::ShardResidualCreated { .. }
                | Self::ShardUnparked { .. }
                | Self::ShardLeaseRenewed { .. }
        )
    }

    /// Returns `true` if this is a run-level event.
    pub fn is_run_event(&self) -> bool {
        !self.is_shard_event()
    }

    /// Returns `true` if this event represents a terminal transition.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::ShardCompleted { .. }
                | Self::ShardParked { .. }
                | Self::ShardSplit { .. }
                | Self::RunCompleted { .. }
                | Self::RunFailed { .. }
                | Self::RunCancelled { .. }
        )
    }
}

// ============================================================================
// § EventCollector
// ============================================================================

/// Collects state transition events during a coordination operation.
///
/// Passed to backend operations to accumulate events. The caller
/// drains the events after the operation completes.
///
/// ## Usage
///
/// ```rust,ignore
/// let mut events = EventCollector::new();
/// backend.checkpoint_with_events(now, tenant, lease, cursor, op_id, &mut events)?;
/// for event in events.drain() {
///     metrics.record(&event);
/// }
/// ```
///
/// ## Design Note
///
/// The `_with_events` methods are optional extensions. The core trait
/// methods (traits.rs) do NOT take an EventCollector — they are the
/// minimal contract. Backends that want event emission implement the
/// extension methods. This keeps the core trait simple for testing.
#[derive(Clone, Debug, Default)]
pub struct EventCollector {
    events: Vec<StateTransitionEvent>,
}

impl EventCollector {
    pub fn new() -> Self {
        Self { events: Vec::new() }
    }

    /// Record an event.
    pub fn emit(&mut self, event: StateTransitionEvent) {
        self.events.push(event);
    }

    /// Drain all collected events, returning them and clearing the collector.
    pub fn drain(&mut self) -> Vec<StateTransitionEvent> {
        std::mem::take(&mut self.events)
    }

    /// Number of events collected.
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Whether any events have been collected.
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Iterate over collected events without draining.
    pub fn iter(&self) -> impl Iterator<Item = &StateTransitionEvent> {
        self.events.iter()
    }
}

// ============================================================================
// § Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{JobId, PolicyHash};

    fn test_tenant() -> TenantId { TenantId::from_bytes([0x01; 32]) }
    fn test_run() -> RunId {
        RunId { job: JobId(1), policy: PolicyHash::from_bytes([0xAA; 32]) }
    }

    #[test]
    fn event_tenant_and_run() {
        let event = StateTransitionEvent::ShardCompleted {
            tenant: test_tenant(),
            run: test_run(),
            shard: ShardId(0),
        };
        assert_eq!(event.tenant(), test_tenant());
        assert_eq!(event.run(), test_run());
        assert!(event.is_shard_event());
        assert!(!event.is_run_event());
        assert!(event.is_terminal());
    }

    #[test]
    fn event_classification() {
        let checkpoint = StateTransitionEvent::ShardCheckpointed {
            tenant: test_tenant(),
            run: test_run(),
            shard: ShardId(0),
            last_key: Some(b"progress".to_vec().into_boxed_slice()),
        };
        assert!(checkpoint.is_shard_event());
        assert!(!checkpoint.is_terminal());

        let run_created = StateTransitionEvent::RunCreated {
            tenant: test_tenant(),
            run: test_run(),
        };
        assert!(run_created.is_run_event());
        assert!(!run_created.is_terminal());

        let run_done = StateTransitionEvent::RunCompleted {
            tenant: test_tenant(),
            run: test_run(),
        };
        assert!(run_done.is_run_event());
        assert!(run_done.is_terminal());
    }

    #[test]
    fn event_non_terminal_variants() {
        let acquired = StateTransitionEvent::ShardAcquired {
            tenant: test_tenant(), run: test_run(),
            shard: ShardId(0), worker: WorkerId(1),
            fence_epoch: FenceEpoch(2),
        };
        assert!(!acquired.is_terminal());

        let renewed = StateTransitionEvent::ShardLeaseRenewed {
            tenant: test_tenant(), run: test_run(),
            shard: ShardId(0), new_deadline: LogicalTime(100),
        };
        assert!(!renewed.is_terminal());

        let residual = StateTransitionEvent::ShardResidualCreated {
            tenant: test_tenant(), run: test_run(),
            parent: ShardId(0), residual: ShardId(1),
        };
        assert!(!residual.is_terminal());

        let activated = StateTransitionEvent::RunActivated {
            tenant: test_tenant(), run: test_run(), shard_count: 3,
        };
        assert!(!activated.is_terminal());
    }

    #[test]
    fn event_terminal_variants() {
        let parked = StateTransitionEvent::ShardParked {
            tenant: test_tenant(), run: test_run(),
            shard: ShardId(0), reason: ParkReason::Other,
        };
        assert!(parked.is_terminal());

        let split = StateTransitionEvent::ShardSplit {
            tenant: test_tenant(), run: test_run(),
            parent: ShardId(0), children: vec![ShardId(1), ShardId(2)],
        };
        assert!(split.is_terminal());

        let failed = StateTransitionEvent::RunFailed {
            tenant: test_tenant(), run: test_run(),
        };
        assert!(failed.is_terminal());

        let cancelled = StateTransitionEvent::RunCancelled {
            tenant: test_tenant(), run: test_run(),
        };
        assert!(cancelled.is_terminal());
    }

    #[test]
    fn collector_basic() {
        let mut c = EventCollector::new();
        assert!(c.is_empty());
        assert_eq!(c.len(), 0);

        c.emit(StateTransitionEvent::RunCreated {
            tenant: test_tenant(), run: test_run(),
        });
        assert!(!c.is_empty());
        assert_eq!(c.len(), 1);

        let events = c.drain();
        assert_eq!(events.len(), 1);
        assert!(c.is_empty());
    }

    #[test]
    fn collector_multi_emit() {
        let mut c = EventCollector::new();
        c.emit(StateTransitionEvent::ShardAcquired {
            tenant: test_tenant(), run: test_run(),
            shard: ShardId(0), worker: WorkerId(1),
            fence_epoch: FenceEpoch(2),
        });
        c.emit(StateTransitionEvent::ShardCheckpointed {
            tenant: test_tenant(), run: test_run(),
            shard: ShardId(0),
            last_key: Some(b"k".to_vec().into_boxed_slice()),
        });
        c.emit(StateTransitionEvent::ShardCompleted {
            tenant: test_tenant(), run: test_run(),
            shard: ShardId(0),
        });

        assert_eq!(c.len(), 3);
        let events = c.drain();
        assert!(events[0].is_shard_event());
        assert!(!events[1].is_terminal());
        assert!(events[2].is_terminal());
    }

    #[test]
    fn collector_iter_without_drain() {
        let mut c = EventCollector::new();
        c.emit(StateTransitionEvent::RunCreated {
            tenant: test_tenant(), run: test_run(),
        });
        c.emit(StateTransitionEvent::RunCompleted {
            tenant: test_tenant(), run: test_run(),
        });

        let terminals: Vec<_> = c.iter().filter(|e| e.is_terminal()).collect();
        assert_eq!(terminals.len(), 1);
        // Not drained — still available.
        assert_eq!(c.len(), 2);
    }

    #[test]
    fn collector_drain_clears() {
        let mut c = EventCollector::new();
        c.emit(StateTransitionEvent::RunCreated {
            tenant: test_tenant(), run: test_run(),
        });
        let _ = c.drain();
        assert!(c.is_empty());
        let second = c.drain();
        assert!(second.is_empty());
    }
}
