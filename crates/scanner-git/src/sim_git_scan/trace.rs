//! Trace events and bounded trace ring for Git simulation.
//!
//! The trace captures a minimal, deterministic record of execution so
//! failures can be replayed and minimized. Events are intentionally
//! compact and avoid embedding large payloads. Event and stage identifiers
//! are numeric to keep traces small; their mapping to semantic stages is
//! defined by the simulation harness.

use std::collections::VecDeque;

/// Minimal event set for Git simulation replay.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum GitTraceEvent {
    /// A stage began execution.
    StageEnter { stage_id: u16 },
    /// A stage completed with counters.
    StageExit { stage_id: u16, items: u32 },
    /// A deterministic decision point (policy, strategy, or ordering).
    Decision { code: u32 },
    /// A fault was injected against a logical resource.
    FaultInjected {
        resource_id: u32,
        op: u32,
        kind: u16,
    },
}

/// Fixed-capacity ring buffer of Git trace events.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct GitTraceRing {
    cap: usize,
    buf: VecDeque<GitTraceEvent>,
}

impl GitTraceRing {
    /// Create a trace ring with at least one slot (zero clamps to one).
    pub fn new(cap: usize) -> Self {
        let cap = cap.max(1);
        Self {
            cap,
            buf: VecDeque::with_capacity(cap),
        }
    }

    /// Maximum number of events retained.
    #[inline(always)]
    pub fn cap(&self) -> usize {
        self.cap
    }

    /// Current number of retained events.
    #[inline(always)]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Whether the ring is empty.
    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Push a new event, evicting the oldest if at capacity.
    #[inline(always)]
    pub fn push(&mut self, ev: GitTraceEvent) {
        if self.buf.len() == self.cap {
            self.buf.pop_front();
        }
        self.buf.push_back(ev);
    }

    /// Snapshot the ring contents in chronological order.
    pub fn dump(&self) -> Vec<GitTraceEvent> {
        self.buf.iter().cloned().collect()
    }
}
