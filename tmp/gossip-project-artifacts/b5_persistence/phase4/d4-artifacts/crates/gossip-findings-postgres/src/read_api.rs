//! Minimal read API for validation, harnesses, and early query-plane checks.
//!
//! This is intentionally small. Until triage state exists, the read surface is
//! limited to:
//!
//! - counting observations grouped by `(tenant_id, policy_hash)`
//! - listing the latest observation per finding as a placeholder for
//!   "findings needing triage"
//!
//! The second query does **not** claim to model user triage state yet. It is a
//! safe, deterministic placeholder that returns one row per finding, keyed by
//! the latest observation seen for that finding.

use gossip_contracts::identity::{
    FindingId, ObservationId, OccurrenceId, PolicyHash, StableItemId, TenantId,
};

/// Grouped observation count for one tenant+policy pair.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservationCountByPolicy {
    pub tenant_id: TenantId,
    pub policy_hash: PolicyHash,
    pub observation_count: u64,
}

impl ObservationCountByPolicy {
    #[inline]
    #[must_use]
    pub const fn new(
        tenant_id: TenantId,
        policy_hash: PolicyHash,
        observation_count: u64,
    ) -> Self {
        Self {
            tenant_id,
            policy_hash,
            observation_count,
        }
    }
}

/// Placeholder row returned by [`FindingsSinkPg::list_findings_needing_triage`].
///
/// Until mutable triage state exists, this is simply the latest observation for
/// each finding for the requested tenant, ordered by `seen_at DESC`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingTriageFinding {
    pub tenant_id: TenantId,
    pub finding_id: FindingId,
    pub stable_item_id: StableItemId,
    pub occurrence_id: OccurrenceId,
    pub observation_id: ObservationId,
    pub policy_hash: PolicyHash,
    pub seen_at: u64,
    pub location_display: Option<String>,
    pub location_url: Option<String>,
}

impl PendingTriageFinding {
    #[inline]
    #[must_use]
    pub fn new(
        tenant_id: TenantId,
        finding_id: FindingId,
        stable_item_id: StableItemId,
        occurrence_id: OccurrenceId,
        observation_id: ObservationId,
        policy_hash: PolicyHash,
        seen_at: u64,
        location_display: Option<String>,
        location_url: Option<String>,
    ) -> Self {
        Self {
            tenant_id,
            finding_id,
            stable_item_id,
            occurrence_id,
            observation_id,
            policy_hash,
            seen_at,
            location_display,
            location_url,
        }
    }
}
