//! Minimal typed results for the findings PostgreSQL read surface.
//!
//! These types mirror the query-plane outputs exposed by
//! [`crate::FindingsSinkPg`]. They keep harnesses and operational tooling on a
//! typed Rust surface instead of raw SQL rows.

use gossip_contracts::identity::{
    FindingId, ObservationId, OccurrenceId, PolicyHash, StableItemId, TenantId,
};

/// Grouped observation count for one tenant and policy pair.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservationCountByPolicy {
    tenant_id: TenantId,
    policy_hash: PolicyHash,
    observation_count: u64,
}

impl ObservationCountByPolicy {
    /// Construct a grouped observation-count row.
    #[inline]
    #[must_use]
    pub const fn new(tenant_id: TenantId, policy_hash: PolicyHash, observation_count: u64) -> Self {
        Self {
            tenant_id,
            policy_hash,
            observation_count,
        }
    }

    /// Tenant that owns the grouped observations.
    #[inline]
    #[must_use]
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    /// Policy whose observations were counted.
    #[inline]
    #[must_use]
    pub const fn policy_hash(&self) -> PolicyHash {
        self.policy_hash
    }

    /// Number of durable observation rows for this tenant and policy.
    #[inline]
    #[must_use]
    pub const fn observation_count(&self) -> u64 {
        self.observation_count
    }
}

/// Latest observation row for one finding, used by the triage read surface.
///
/// "Findings needing triage" returns the latest observation per finding for a
/// tenant, ordered by recency.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingTriageFinding {
    tenant_id: TenantId,
    finding_id: FindingId,
    stable_item_id: StableItemId,
    occurrence_id: OccurrenceId,
    observation_id: ObservationId,
    policy_hash: PolicyHash,
    seen_at: u64,
    location_display: Option<String>,
    location_url: Option<String>,
}

impl PendingTriageFinding {
    /// Construct a placeholder triage row from decoded SQL results.
    #[inline]
    #[must_use]
    #[allow(clippy::too_many_arguments)]
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
        debug_assert!(
            location_url.is_none() || location_display.is_some(),
            "location_url without location_display violates the pairing invariant"
        );
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

    /// Tenant that owns the finding.
    #[inline]
    #[must_use]
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    /// Stable finding identifier.
    #[inline]
    #[must_use]
    pub const fn finding_id(&self) -> FindingId {
        self.finding_id
    }

    /// Stable item referenced by the finding.
    #[inline]
    #[must_use]
    pub const fn stable_item_id(&self) -> StableItemId {
        self.stable_item_id
    }

    /// Occurrence that produced the latest observation.
    #[inline]
    #[must_use]
    pub const fn occurrence_id(&self) -> OccurrenceId {
        self.occurrence_id
    }

    /// Observation selected as the latest row for the finding.
    #[inline]
    #[must_use]
    pub const fn observation_id(&self) -> ObservationId {
        self.observation_id
    }

    /// Policy associated with the selected observation.
    #[inline]
    #[must_use]
    pub const fn policy_hash(&self) -> PolicyHash {
        self.policy_hash
    }

    /// Logical time when the selected observation was seen.
    #[inline]
    #[must_use]
    pub const fn seen_at(&self) -> u64 {
        self.seen_at
    }

    /// Human-readable location for the selected observation, if present.
    /// Returned verbatim from storage; callers must apply context-appropriate
    /// output encoding (e.g. HTML escaping) before rendering.
    #[inline]
    #[must_use]
    pub fn location_display(&self) -> Option<&str> {
        self.location_display.as_deref()
    }

    /// URL paired with the selected observation's location, if present.
    /// Returned verbatim from storage; callers must apply context-appropriate
    /// output encoding before embedding in HTML, JSON, or other formats.
    #[inline]
    #[must_use]
    pub fn location_url(&self) -> Option<&str> {
        self.location_url.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::{ObservationCountByPolicy, PendingTriageFinding};
    use gossip_contracts::identity::{
        FindingId, ObservationId, OccurrenceId, PolicyHash, StableItemId, TenantId,
    };

    #[test]
    fn observation_count_by_policy_constructor_and_accessors_round_trip() {
        let tenant_id = TenantId::from_bytes([0x11; 32]);
        let policy_hash = PolicyHash::from_bytes([0x22; 32]);
        let row = ObservationCountByPolicy::new(tenant_id, policy_hash, 17);

        assert_eq!(row.tenant_id(), tenant_id);
        assert_eq!(row.policy_hash(), policy_hash);
        assert_eq!(row.observation_count(), 17);
    }

    #[test]
    fn pending_triage_finding_constructor_and_accessors_round_trip() {
        let tenant_id = TenantId::from_bytes([0x11; 32]);
        let finding_id = FindingId::from_bytes([0x22; 32]);
        let stable_item_id = StableItemId::from_bytes([0x33; 32]);
        let occurrence_id = OccurrenceId::from_bytes([0x44; 32]);
        let observation_id = ObservationId::from_bytes([0x55; 32]);
        let policy_hash = PolicyHash::from_bytes([0x66; 32]);
        let row = PendingTriageFinding::new(
            tenant_id,
            finding_id,
            stable_item_id,
            occurrence_id,
            observation_id,
            policy_hash,
            77,
            Some("safe/path.txt".to_owned()),
            Some("https://example.invalid/path".to_owned()),
        );

        assert_eq!(row.tenant_id(), tenant_id);
        assert_eq!(row.finding_id(), finding_id);
        assert_eq!(row.stable_item_id(), stable_item_id);
        assert_eq!(row.occurrence_id(), occurrence_id);
        assert_eq!(row.observation_id(), observation_id);
        assert_eq!(row.policy_hash(), policy_hash);
        assert_eq!(row.seen_at(), 77);
        assert_eq!(row.location_display(), Some("safe/path.txt"));
        assert_eq!(row.location_url(), Some("https://example.invalid/path"));
    }

    #[test]
    fn pending_triage_finding_none_location_fields_round_trip() {
        let tenant_id = TenantId::from_bytes([0x11; 32]);
        let finding_id = FindingId::from_bytes([0x22; 32]);
        let stable_item_id = StableItemId::from_bytes([0x33; 32]);
        let occurrence_id = OccurrenceId::from_bytes([0x44; 32]);
        let observation_id = ObservationId::from_bytes([0x55; 32]);
        let policy_hash = PolicyHash::from_bytes([0x66; 32]);
        let row = PendingTriageFinding::new(
            tenant_id,
            finding_id,
            stable_item_id,
            occurrence_id,
            observation_id,
            policy_hash,
            99,
            None,
            None,
        );

        assert!(
            row.location_display().is_none(),
            "None location_display should round-trip as None"
        );
        assert!(
            row.location_url().is_none(),
            "None location_url should round-trip as None"
        );
    }
}
