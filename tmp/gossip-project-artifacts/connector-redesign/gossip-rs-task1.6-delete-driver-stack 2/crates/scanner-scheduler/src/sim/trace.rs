//! Bounded trace ring for replay and debugging.
//!
//! Trace events are retained in a fixed-capacity ring. When the ring is full,
//! the oldest events are evicted first.

use std::collections::VecDeque;

/// Minimal event set for deterministic replay and failure forensics.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum TraceEvent {
    StepChoose {
        choices: u32,
        chosen: u32,
    },
    TaskSpawn {
        task_id: u32,
        kind: u16,
    },
    TaskPoll {
        task_id: u32,
        outcome: u16,
    },
    IoSubmit {
        file: u32,
        op: u32,
        offset: u64,
        len: u32,
        ready_at: u64,
    },
    IoComplete {
        file: u32,
        op: u32,
        result: u16,
    },
    FaultInjected {
        file: u32,
        op: u32,
        kind: u16,
    },
    FindingEmit {
        file: u32,
        rule: u32,
        span0: u32,
        span1: u32,
        root0: u32,
        root1: u32,
    },
    ArchiveStart {
        root: u32,
        kind: u16,
    },
    ArchiveEntryStart {
        root: u32,
        entry: u32,
    },
    ArchiveEntryEnd {
        root: u32,
        entry: u32,
    },
    ArchiveEnd {
        root: u32,
        outcome: u16,
    },
    InvariantFail {
        code: u32,
    },
}

/// Fixed-capacity ring buffer of trace events.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct TraceRing {
    cap: usize,
    buf: VecDeque<TraceEvent>,
}

impl TraceRing {
    /// Create a trace ring with at least one slot.
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
    pub fn push(&mut self, ev: TraceEvent) {
        if self.buf.len() == self.cap {
            self.buf.pop_front();
        }
        self.buf.push_back(ev);
    }

    /// Snapshot the ring contents in chronological order.
    pub fn dump(&self) -> Vec<TraceEvent> {
        self.buf.iter().cloned().collect()
    }
}
