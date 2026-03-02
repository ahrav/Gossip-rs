//! Fault plan schema for Git simulation.
//!
//! The fault plan is keyed by logical resources (commit-graph, MIDX, pack IDs,
//! persistence) rather than filesystem paths. This keeps fault injection
//! deterministic even when repository layouts vary.
//!
//! Invariants and expectations:
//! - Resource identifiers should be stable across runs and schema versions.
//! - Read faults are consumed in read-index order; missing entries imply no fault.
//! - Corruption applies only to bytes returned by a read (if any).

use serde::{Deserialize, Serialize};

/// Logical resource identifiers for Git fault injection.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GitResourceId {
    /// Commit-graph file (if present).
    CommitGraph,
    /// Multi-pack-index file (if present).
    Midx,
    /// Pack file identified by logical pack id.
    Pack { pack_id: u16 },
    /// Persistence store (watermarks/seen store).
    Persist,
    /// Catch-all for non-core resources (keep names stable for replay).
    Other(String),
}

/// I/O fault variants for Git simulation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum GitIoFault {
    /// Return an I/O error by kind (opaque u8 tag).
    ErrKind { kind: u8 },
    /// Return at most `max_len` bytes (short read).
    PartialRead { max_len: u32 },
    /// Single EINTR-style interruption (subsequent reads proceed normally).
    EIntrOnce,
}

/// Data corruption variants for Git simulation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum GitCorruption {
    /// Truncate the returned data to `new_len` bytes.
    TruncateTo { new_len: u32 },
    /// Flip bits at a specific offset.
    FlipBit { offset: u32, mask: u8 },
    /// Overwrite bytes starting at `offset`.
    Overwrite { offset: u32, bytes: Vec<u8> },
}

/// Fault injection for a single read step.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitReadFault {
    /// Optional I/O fault.
    pub fault: Option<GitIoFault>,
    /// Simulated latency ticks before completion.
    pub latency_ticks: u64,
    /// Optional data corruption.
    pub corruption: Option<GitCorruption>,
}

/// Faults for a specific resource.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitResourceFaults {
    /// Target logical resource.
    pub resource: GitResourceId,
    /// Faults to apply in read index order.
    pub reads: Vec<GitReadFault>,
}

/// Top-level fault plan for Git simulation.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitFaultPlan {
    /// Resource-specific fault sequences.
    pub resources: Vec<GitResourceFaults>,
}

/// Runtime fault injector keyed by logical Git resources.
#[derive(Clone, Debug)]
pub struct GitFaultInjector {
    resources: Vec<ResourceState>,
}

#[derive(Clone, Debug)]
struct ResourceState {
    resource: GitResourceId,
    reads: Vec<GitReadFault>,
    next_idx: u32,
}

impl GitFaultInjector {
    /// Create a new injector from a deterministic fault plan.
    pub fn new(plan: GitFaultPlan) -> Self {
        let mut resources = Vec::with_capacity(plan.resources.len());
        for res in plan.resources {
            resources.push(ResourceState {
                resource: res.resource,
                reads: res.reads,
                next_idx: 0,
            });
        }
        Self { resources }
    }

    /// Retrieves the next read fault for a resource and advances its read index.
    pub fn next_read(&mut self, resource: &GitResourceId) -> (GitReadFault, u32) {
        for state in &mut self.resources {
            if &state.resource == resource {
                let idx = state.next_idx;
                state.next_idx = state.next_idx.saturating_add(1);
                let fault = state.reads.get(idx as usize).cloned().unwrap_or_default();
                return (fault, idx);
            }
        }
        (GitReadFault::default(), 0)
    }
}

impl GitResourceId {
    /// Stable numeric id for trace logging.
    #[must_use]
    pub fn stable_id(&self) -> u32 {
        match self {
            Self::CommitGraph => 1,
            Self::Midx => 2,
            Self::Pack { pack_id } => 1000 + (*pack_id as u32),
            Self::Persist => 2000,
            Self::Other(name) => 3000 + stable_hash_u32(name.as_bytes()),
        }
    }
}

/// Stable numeric id for fault kinds used in trace events.
#[must_use]
pub fn fault_kind_code(fault: &GitIoFault) -> u16 {
    match fault {
        GitIoFault::ErrKind { .. } => 1,
        GitIoFault::PartialRead { .. } => 2,
        GitIoFault::EIntrOnce => 3,
    }
}

/// Stable numeric id for corruption kinds used in trace events.
#[must_use]
pub fn corruption_kind_code(corruption: &GitCorruption) -> u16 {
    match corruption {
        GitCorruption::TruncateTo { .. } => 10,
        GitCorruption::FlipBit { .. } => 11,
        GitCorruption::Overwrite { .. } => 12,
    }
}

fn stable_hash_u32(bytes: &[u8]) -> u32 {
    const FNV_OFFSET: u32 = 0x811c9dc5;
    const FNV_PRIME: u32 = 0x0100_0193;
    let mut hash = FNV_OFFSET;
    for &b in bytes {
        hash ^= b as u32;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fault_plan_round_trip() {
        let plan = GitFaultPlan {
            resources: vec![GitResourceFaults {
                resource: GitResourceId::Pack { pack_id: 2 },
                reads: vec![GitReadFault {
                    fault: Some(GitIoFault::PartialRead { max_len: 16 }),
                    latency_ticks: 1,
                    corruption: Some(GitCorruption::TruncateTo { new_len: 8 }),
                }],
            }],
        };
        let json = serde_json::to_string(&plan).expect("serialize plan");
        let decoded: GitFaultPlan = serde_json::from_str(&json).expect("deserialize plan");
        assert_eq!(decoded.resources.len(), 1);
    }

    #[test]
    fn injector_advances_read_index() {
        let plan = GitFaultPlan {
            resources: vec![GitResourceFaults {
                resource: GitResourceId::Midx,
                reads: vec![
                    GitReadFault {
                        fault: Some(GitIoFault::ErrKind { kind: 1 }),
                        latency_ticks: 0,
                        corruption: None,
                    },
                    GitReadFault {
                        fault: Some(GitIoFault::PartialRead { max_len: 4 }),
                        latency_ticks: 0,
                        corruption: None,
                    },
                ],
            }],
        };

        let mut injector = GitFaultInjector::new(plan);
        let (first, idx0) = injector.next_read(&GitResourceId::Midx);
        let (second, idx1) = injector.next_read(&GitResourceId::Midx);
        let (third, idx2) = injector.next_read(&GitResourceId::Midx);

        assert_eq!(idx0, 0);
        assert_eq!(idx1, 1);
        assert_eq!(idx2, 2);
        assert!(matches!(first.fault, Some(GitIoFault::ErrKind { .. })));
        assert!(matches!(second.fault, Some(GitIoFault::PartialRead { .. })));
        assert!(third.fault.is_none());
    }
}
