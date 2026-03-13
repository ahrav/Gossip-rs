//! Rust-side batch projection, deduplication, and observation merge helpers.
//!
//! The PostgreSQL backend folds duplicate rows within a single submitted batch
//! before issuing SQL so `INSERT ... ON CONFLICT` sees at most one row per
//! durable primary key. Observation duplicates use the same winner-selection
//! rules as [`crate::schema::OBSERVATIONS_INSERT_OR_MERGE_SQL`] so Rust-side
//! pre-processing and SQL-side replay converge on the same durable row.

#![cfg_attr(not(test), allow(dead_code))]

use std::collections::{HashMap, hash_map::Entry};
use std::hash::Hash;

use gossip_contracts::{
    identity::{FindingId, ObservationId, OccurrenceId, TenantId},
    persistence::{FindingsUpsertBatch, PersistenceInputError},
};

use crate::{
    error::{FindingsPgError, FindingsPgSchemaError},
    schema::{FindingRow, ObservationRow, OccurrenceRow},
};

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct DedupedBatch {
    pub(crate) findings: Vec<FindingRow>,
    pub(crate) occurrences: Vec<OccurrenceRow>,
    pub(crate) observations: Vec<ObservationRow>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MergeIdentityMismatch {
    tenant_id: [u8; 32],
    observation_id: [u8; 32],
}

pub(crate) fn project_and_dedupe(
    batch: FindingsUpsertBatch<'_>,
) -> Result<DedupedBatch, FindingsPgError> {
    batch
        .validate_observation_identity()
        .map_err(FindingsPgSchemaError::Persistence)?;
    ensure_consistent_tenant(batch).map_err(FindingsPgSchemaError::Persistence)?;

    let findings = batch
        .findings()
        .iter()
        .map(FindingRow::from_record)
        .collect::<Vec<_>>();
    let occurrences = batch
        .occurrences()
        .iter()
        .map(OccurrenceRow::from_record)
        .collect::<Result<Vec<_>, _>>()?;
    let observations = batch
        .observations()
        .iter()
        .map(ObservationRow::from_record)
        .collect::<Result<Vec<_>, _>>()?;

    Ok(DedupedBatch {
        findings: dedupe_findings_rows(&findings)?,
        occurrences: dedupe_occurrence_rows(&occurrences)?,
        observations: dedupe_observation_rows(&observations)?,
    })
}

fn ensure_consistent_tenant(batch: FindingsUpsertBatch<'_>) -> Result<(), PersistenceInputError> {
    let expected_tenant = batch
        .findings()
        .first()
        .map(|record| record.tenant_id())
        .or_else(|| batch.occurrences().first().map(|record| record.tenant_id()))
        .or_else(|| {
            batch
                .observations()
                .first()
                .map(|record| record.tenant_id())
        });

    if let Some(expected_tenant) = expected_tenant {
        for finding in batch.findings() {
            if finding.tenant_id() != expected_tenant {
                return Err(PersistenceInputError::InconsistentTenant);
            }
        }
        for occurrence in batch.occurrences() {
            if occurrence.tenant_id() != expected_tenant {
                return Err(PersistenceInputError::InconsistentTenant);
            }
        }
        for observation in batch.observations() {
            if observation.tenant_id() != expected_tenant {
                return Err(PersistenceInputError::InconsistentTenant);
            }
        }
    }

    Ok(())
}

fn dedupe_findings_rows(rows: &[FindingRow]) -> Result<Vec<FindingRow>, FindingsPgError> {
    let mut merged: HashMap<([u8; 32], [u8; 32]), FindingRow> = HashMap::with_capacity(rows.len());
    let mut order: Vec<([u8; 32], [u8; 32])> = Vec::with_capacity(rows.len());

    for row in rows {
        let key = (row.tenant_id, row.finding_id);
        match merged.entry(key) {
            Entry::Vacant(slot) => {
                order.push(key);
                slot.insert(row.clone());
            }
            Entry::Occupied(slot) => {
                if slot.get() != row {
                    return Err(FindingsPgError::FindingConflict {
                        tenant_id: TenantId::from_bytes(row.tenant_id),
                        finding_id: FindingId::from_bytes(row.finding_id),
                    });
                }
            }
        }
    }

    Ok(drain_in_order(merged, order, "findings"))
}

fn dedupe_occurrence_rows(rows: &[OccurrenceRow]) -> Result<Vec<OccurrenceRow>, FindingsPgError> {
    let mut merged: HashMap<([u8; 32], [u8; 32]), OccurrenceRow> =
        HashMap::with_capacity(rows.len());
    let mut order: Vec<([u8; 32], [u8; 32])> = Vec::with_capacity(rows.len());

    for row in rows {
        let key = (row.tenant_id, row.occurrence_id);
        match merged.entry(key) {
            Entry::Vacant(slot) => {
                order.push(key);
                slot.insert(row.clone());
            }
            Entry::Occupied(slot) => {
                if slot.get() != row {
                    return Err(FindingsPgError::OccurrenceConflict {
                        tenant_id: TenantId::from_bytes(row.tenant_id),
                        occurrence_id: OccurrenceId::from_bytes(row.occurrence_id),
                    });
                }
            }
        }
    }

    Ok(drain_in_order(merged, order, "occurrences"))
}

fn dedupe_observation_rows(
    rows: &[ObservationRow],
) -> Result<Vec<ObservationRow>, FindingsPgError> {
    let mut merged: HashMap<([u8; 32], [u8; 32]), ObservationRow> =
        HashMap::with_capacity(rows.len());
    let mut order: Vec<([u8; 32], [u8; 32])> = Vec::with_capacity(rows.len());

    for row in rows {
        let key = (row.tenant_id, row.observation_id);
        match merged.entry(key) {
            Entry::Vacant(slot) => {
                order.push(key);
                slot.insert(row.clone());
            }
            Entry::Occupied(mut slot) => {
                let merged_row = merge_observation_rows(slot.get(), row).map_err(|mismatch| {
                    FindingsPgError::ObservationConflict {
                        tenant_id: TenantId::from_bytes(mismatch.tenant_id),
                        observation_id: ObservationId::from_bytes(mismatch.observation_id),
                    }
                })?;
                slot.insert(merged_row);
            }
        }
    }

    Ok(drain_in_order(merged, order, "observations"))
}

fn merge_observation_rows(
    existing: &ObservationRow,
    incoming: &ObservationRow,
) -> Result<ObservationRow, MergeIdentityMismatch> {
    if existing.tenant_id != incoming.tenant_id
        || existing.observation_id != incoming.observation_id
        || existing.occurrence_id != incoming.occurrence_id
        || existing.policy_hash != incoming.policy_hash
        || existing.ovid_hash != incoming.ovid_hash
    {
        return Err(MergeIdentityMismatch {
            tenant_id: incoming.tenant_id,
            observation_id: incoming.observation_id,
        });
    }

    let use_incoming_provenance = incoming.seen_at > existing.seen_at
        || (incoming.seen_at == existing.seen_at
            && existing.location_display.is_none()
            && incoming.location_display.is_some());

    let location_display = if incoming.seen_at > existing.seen_at {
        incoming
            .location_display
            .clone()
            .or_else(|| existing.location_display.clone())
    } else if incoming.seen_at < existing.seen_at {
        existing
            .location_display
            .clone()
            .or_else(|| incoming.location_display.clone())
    } else if existing.location_display.is_none() && incoming.location_display.is_some() {
        incoming.location_display.clone()
    } else {
        existing
            .location_display
            .clone()
            .or_else(|| incoming.location_display.clone())
    };

    let location_url = if incoming.seen_at > existing.seen_at {
        if incoming.location_display.is_some() {
            incoming.location_url.clone()
        } else {
            existing.location_url.clone()
        }
    } else if incoming.seen_at < existing.seen_at {
        if existing.location_display.is_some() {
            existing.location_url.clone()
        } else {
            incoming.location_url.clone()
        }
    } else if existing.location_display.is_none() && incoming.location_display.is_some() {
        incoming.location_url.clone()
    } else if existing.location_display.is_some() {
        existing.location_url.clone()
    } else {
        incoming.location_url.clone()
    };

    Ok(ObservationRow {
        tenant_id: existing.tenant_id,
        observation_id: existing.observation_id,
        occurrence_id: existing.occurrence_id,
        policy_hash: existing.policy_hash,
        ovid_hash: existing.ovid_hash,
        run_id: if use_incoming_provenance {
            incoming.run_id
        } else {
            existing.run_id
        },
        shard_id: if use_incoming_provenance {
            incoming.shard_id
        } else {
            existing.shard_id
        },
        fence_epoch: if use_incoming_provenance {
            incoming.fence_epoch
        } else {
            existing.fence_epoch
        },
        seen_at: existing.seen_at.max(incoming.seen_at),
        location_display,
        location_url,
    })
}

fn drain_in_order<K, V>(mut map: HashMap<K, V>, order: Vec<K>, layer: &'static str) -> Vec<V>
where
    K: Copy + Eq + Hash,
{
    order
        .into_iter()
        .map(|key| {
            map.remove(&key)
                .unwrap_or_else(|| panic!("{layer} dedupe map and order diverged"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU64;

    use gossip_contracts::{
        connector::Location,
        identity::{
            FenceEpoch, FindingId, LogicalTime, NormHash, ObjectVersionId, ObservationId,
            OccurrenceId, PolicyHash, RuleFingerprint, RunId, ShardId, StableItemId, TenantId,
            TenantSecretKey, key_secret_hash,
        },
        persistence::{
            FindingRecord, FindingsUpsertBatch, ObservationRecord, OccurrenceRecord,
            PersistenceInputError,
        },
        test_util::{observation_record_with_stored_id, ovid},
    };

    use crate::{
        FindingsPgError, FindingsPgSchemaError, PgU64ConversionError,
        schema::{FindingRow, ObservationRow, OccurrenceRow},
    };

    use super::{
        dedupe_findings_rows, dedupe_observation_rows, dedupe_occurrence_rows,
        ensure_consistent_tenant, merge_observation_rows, project_and_dedupe,
    };

    #[test]
    fn dedupe_preserves_insertion_order() {
        let finding_a = finding_record(0x11, 0x31);
        let finding_b = finding_record(0x11, 0x32);
        let occurrence_a = occurrence_record(0x11, finding_a.finding_id(), 0x41, 10, 4);
        let occurrence_b = occurrence_record(0x11, finding_b.finding_id(), 0x42, 20, 5);
        let observation_a =
            observation_record(0x11, occurrence_a.occurrence_id(), 0x51, 0x61, 1, 2, 3, 10);
        let observation_b =
            observation_record(0x11, occurrence_b.occurrence_id(), 0x52, 0x62, 4, 5, 6, 20);

        let findings = [finding_b.clone(), finding_a.clone(), finding_b.clone()];
        let occurrences = [
            occurrence_b.clone(),
            occurrence_a.clone(),
            occurrence_b.clone(),
        ];
        let observations = [
            observation_b.clone(),
            observation_a.clone(),
            observation_b.clone(),
        ];

        let deduped = project_and_dedupe(FindingsUpsertBatch::new(
            &findings,
            &occurrences,
            &observations,
        ))
        .expect("dedupe should succeed");

        assert_eq!(
            deduped
                .findings
                .iter()
                .map(|row| row.finding_id)
                .collect::<Vec<_>>(),
            vec![
                *finding_b.finding_id().as_bytes(),
                *finding_a.finding_id().as_bytes(),
            ]
        );
        assert_eq!(
            deduped
                .occurrences
                .iter()
                .map(|row| row.occurrence_id)
                .collect::<Vec<_>>(),
            vec![
                *occurrence_b.occurrence_id().as_bytes(),
                *occurrence_a.occurrence_id().as_bytes(),
            ]
        );
        assert_eq!(
            deduped
                .observations
                .iter()
                .map(|row| row.observation_id)
                .collect::<Vec<_>>(),
            vec![
                *observation_b.observation_id().as_bytes(),
                *observation_a.observation_id().as_bytes(),
            ]
        );
    }

    #[test]
    fn dedupe_finding_identical_duplicate_succeeds() {
        let row = finding_row(0x21);
        let deduped = dedupe_findings_rows(&[row.clone(), row.clone()])
            .expect("identical rows should dedupe");

        assert_eq!(deduped, vec![row]);
    }

    #[test]
    fn dedupe_finding_conflict_detected() {
        let row = finding_row(0x22);
        let conflicting = FindingRow {
            secret_hash: [0xF2; 32],
            ..row.clone()
        };

        let err = dedupe_findings_rows(&[row.clone(), conflicting]).expect_err("conflict expected");
        assert_finding_conflict(
            err,
            TenantId::from_bytes(row.tenant_id),
            FindingId::from_bytes(row.finding_id),
        );
    }

    #[test]
    fn dedupe_occurrence_identical_duplicate_succeeds() {
        let row = occurrence_row(0x31);
        let deduped = dedupe_occurrence_rows(&[row.clone(), row.clone()])
            .expect("identical rows should dedupe");

        assert_eq!(deduped, vec![row]);
    }

    #[test]
    fn dedupe_occurrence_conflict_detected() {
        let row = occurrence_row(0x32);
        let conflicting = OccurrenceRow {
            byte_offset: row.byte_offset + 1,
            ..row.clone()
        };

        let err =
            dedupe_occurrence_rows(&[row.clone(), conflicting]).expect_err("conflict expected");
        assert_occurrence_conflict(
            err,
            TenantId::from_bytes(row.tenant_id),
            OccurrenceId::from_bytes(row.occurrence_id),
        );
    }

    #[test]
    fn merge_observation_newer_seen_at_wins() {
        let existing = observation_row(
            10,
            Some("existing/path"),
            Some("https://existing.test"),
            1,
            2,
            3,
        );
        let incoming = observation_row(
            11,
            Some("incoming/path"),
            Some("https://incoming.test"),
            4,
            5,
            6,
        );

        let merged = merge_observation_rows(&existing, &incoming).expect("merge should succeed");

        assert_eq!(merged.run_id, incoming.run_id);
        assert_eq!(merged.shard_id, incoming.shard_id);
        assert_eq!(merged.fence_epoch, incoming.fence_epoch);
        assert_eq!(merged.seen_at, incoming.seen_at);
    }

    #[test]
    fn merge_observation_older_seen_at_loses() {
        let existing = observation_row(
            11,
            Some("existing/path"),
            Some("https://existing.test"),
            1,
            2,
            3,
        );
        let incoming = observation_row(
            10,
            Some("incoming/path"),
            Some("https://incoming.test"),
            4,
            5,
            6,
        );

        let merged = merge_observation_rows(&existing, &incoming).expect("merge should succeed");

        assert_eq!(merged.run_id, existing.run_id);
        assert_eq!(merged.shard_id, existing.shard_id);
        assert_eq!(merged.fence_epoch, existing.fence_epoch);
        assert_eq!(merged.seen_at, existing.seen_at);
    }

    #[test]
    fn merge_observation_equal_seen_at_location_tiebreaker() {
        let existing = observation_row(10, None, None, 1, 2, 3);
        let incoming = observation_row(
            10,
            Some("incoming/path"),
            Some("https://incoming.test"),
            4,
            5,
            6,
        );

        let merged = merge_observation_rows(&existing, &incoming).expect("merge should succeed");

        assert_eq!(merged.run_id, incoming.run_id);
        assert_eq!(merged.shard_id, incoming.shard_id);
        assert_eq!(merged.fence_epoch, incoming.fence_epoch);
        assert_eq!(merged.location_display.as_deref(), Some("incoming/path"));
        assert_eq!(
            merged.location_url.as_deref(),
            Some("https://incoming.test")
        );
    }

    #[test]
    fn merge_observation_equal_seen_at_no_tiebreaker() {
        let existing = observation_row(
            10,
            Some("existing/path"),
            Some("https://existing.test"),
            1,
            2,
            3,
        );
        let incoming = observation_row(
            10,
            Some("incoming/path"),
            Some("https://incoming.test"),
            4,
            5,
            6,
        );

        let merged = merge_observation_rows(&existing, &incoming).expect("merge should succeed");

        assert_eq!(merged.run_id, existing.run_id);
        assert_eq!(merged.shard_id, existing.shard_id);
        assert_eq!(merged.fence_epoch, existing.fence_epoch);
        assert_eq!(merged.location_display.as_deref(), Some("existing/path"));
        assert_eq!(
            merged.location_url.as_deref(),
            Some("https://existing.test")
        );
    }

    #[test]
    fn merge_observation_equal_seen_at_neither_has_location() {
        let existing = observation_row(10, None, None, 1, 2, 3);
        let incoming = observation_row(10, None, None, 4, 5, 6);

        let merged = merge_observation_rows(&existing, &incoming).expect("merge should succeed");

        assert_eq!(merged.run_id, existing.run_id);
        assert_eq!(merged.shard_id, existing.shard_id);
        assert_eq!(merged.fence_epoch, existing.fence_epoch);
        assert_eq!(merged.location_display, None);
        assert_eq!(merged.location_url, None);
    }

    #[test]
    fn merge_observation_identity_mismatch_rejected() {
        let existing = observation_row(
            10,
            Some("existing/path"),
            Some("https://existing.test"),
            1,
            2,
            3,
        );
        let incoming = ObservationRow {
            policy_hash: [0x99; 32],
            ..observation_row(
                10,
                Some("incoming/path"),
                Some("https://incoming.test"),
                4,
                5,
                6,
            )
        };

        let err = merge_observation_rows(&existing, &incoming).expect_err("mismatch expected");

        assert_eq!(err.tenant_id, incoming.tenant_id);
        assert_eq!(err.observation_id, incoming.observation_id);
    }

    #[test]
    fn merge_observation_location_coalesce_winner_has_location() {
        let existing = observation_row(10, None, None, 1, 2, 3);
        let incoming = observation_row(
            11,
            Some("incoming/path"),
            Some("https://incoming.test"),
            4,
            5,
            6,
        );

        let merged = merge_observation_rows(&existing, &incoming).expect("merge should succeed");

        assert_eq!(merged.location_display.as_deref(), Some("incoming/path"));
        assert_eq!(
            merged.location_url.as_deref(),
            Some("https://incoming.test")
        );
    }

    #[test]
    fn merge_observation_location_coalesce_winner_lacks_location() {
        let existing = observation_row(
            10,
            Some("existing/path"),
            Some("https://existing.test"),
            1,
            2,
            3,
        );
        let incoming = observation_row(11, None, None, 4, 5, 6);

        let merged = merge_observation_rows(&existing, &incoming).expect("merge should succeed");

        assert_eq!(merged.run_id, incoming.run_id);
        assert_eq!(merged.location_display.as_deref(), Some("existing/path"));
        assert_eq!(
            merged.location_url.as_deref(),
            Some("https://existing.test")
        );
    }

    #[test]
    fn dedupe_observation_conflict_detected() {
        let row = observation_row(
            10,
            Some("existing/path"),
            Some("https://existing.test"),
            1,
            2,
            3,
        );
        let conflicting = ObservationRow {
            policy_hash: [0xEE; 32],
            ..row.clone()
        };

        let err =
            dedupe_observation_rows(&[row.clone(), conflicting]).expect_err("conflict expected");
        assert_observation_conflict(
            err,
            TenantId::from_bytes(row.tenant_id),
            ObservationId::from_bytes(row.observation_id),
        );
    }

    #[test]
    fn ensure_consistent_tenant_rejects_mixed_tenants() {
        let finding_a = finding_record(0x11, 0x31);
        let finding_b = finding_record(0x12, 0x32);
        let findings = [finding_a, finding_b];

        let err = ensure_consistent_tenant(FindingsUpsertBatch::new(&findings, &[], &[]))
            .expect_err("mixed tenants should fail");

        assert_eq!(err, PersistenceInputError::InconsistentTenant);
    }

    #[test]
    fn ensure_consistent_tenant_accepts_empty_batch() {
        ensure_consistent_tenant(FindingsUpsertBatch::default())
            .expect("empty batch should be valid");
    }

    #[test]
    fn project_and_dedupe_rejects_invalid_observation_identity() {
        let finding = finding_record(0x11, 0x31);
        let occurrence = occurrence_record(0x11, finding.finding_id(), 0x41, 10, 4);
        let observation = observation_record_with_stored_id(
            TenantId::from_bytes([0x11; 32]),
            ObservationId::from_bytes([0xFF; 32]),
            occurrence.occurrence_id(),
            PolicyHash::from_bytes([0x51; 32]),
            ovid(0x61),
            RunId::from_raw(1),
            ShardId::from_raw(2),
            FenceEpoch::from_raw(3),
            LogicalTime::from_raw(10),
            None,
        );
        let findings = [finding];
        let occurrences = [occurrence];
        let observations = [observation];

        let err = project_and_dedupe(FindingsUpsertBatch::new(
            &findings,
            &occurrences,
            &observations,
        ))
        .expect_err("invalid observation identity should fail");

        match err {
            FindingsPgError::Schema(FindingsPgSchemaError::Persistence(
                PersistenceInputError::ObservationIdMismatch { .. },
            )) => {}
            other => panic!("expected observation-id mismatch, got {other:?}"),
        }
    }

    #[test]
    fn project_and_dedupe_rejects_projection_failure() {
        let finding = finding_record(0x11, 0x31);
        let occurrence =
            occurrence_record(0x11, finding.finding_id(), 0x41, i64::MAX as u64 + 1, 4);
        let findings = [finding];
        let occurrences = [occurrence];

        let err = project_and_dedupe(FindingsUpsertBatch::new(&findings, &occurrences, &[]))
            .expect_err("projection overflow should fail");

        match err {
            FindingsPgError::Schema(FindingsPgSchemaError::PgU64Conversion(
                PgU64ConversionError::OrderedOutOfRange { field, value },
            )) => {
                assert_eq!(field, "byte_offset");
                assert_eq!(value, i64::MAX as u64 + 1);
            }
            other => panic!("expected ordered bigint overflow, got {other:?}"),
        }
    }

    fn finding_record(tenant_seed: u8, item_seed: u8) -> FindingRecord {
        let tenant_id = TenantId::from_bytes([tenant_seed; 32]);
        let stable_item_id = StableItemId::from_bytes([item_seed; 32]);
        let rule_fingerprint = RuleFingerprint::from_bytes([item_seed.wrapping_add(1); 32]);
        let secret_hash = key_secret_hash(
            &TenantSecretKey::from_bytes([0x42; 32]),
            &NormHash::from_digest([item_seed.wrapping_add(2); 32]),
        );

        FindingRecord::new(tenant_id, stable_item_id, rule_fingerprint, secret_hash)
    }

    fn occurrence_record(
        tenant_seed: u8,
        finding_id: FindingId,
        version_seed: u8,
        byte_offset: u64,
        byte_length: u64,
    ) -> OccurrenceRecord {
        OccurrenceRecord::new(
            TenantId::from_bytes([tenant_seed; 32]),
            finding_id,
            ObjectVersionId::from_bytes([version_seed; 32]),
            byte_offset,
            NonZeroU64::new(byte_length).expect("test span length must be non-zero"),
        )
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "test helper mirrors the observation durable row shape"
    )]
    fn observation_record(
        tenant_seed: u8,
        occurrence_id: OccurrenceId,
        policy_seed: u8,
        ovid_seed: u8,
        run_id: u64,
        shard_id: u64,
        fence_epoch: u64,
        seen_at: u64,
    ) -> ObservationRecord {
        ObservationRecord::new(
            TenantId::from_bytes([tenant_seed; 32]),
            occurrence_id,
            PolicyHash::from_bytes([policy_seed; 32]),
            ovid(ovid_seed),
            RunId::from_raw(run_id),
            ShardId::from_raw(shard_id),
            FenceEpoch::from_raw(fence_epoch),
            LogicalTime::from_raw(seen_at),
        )
    }

    fn finding_row(id_seed: u8) -> FindingRow {
        FindingRow {
            tenant_id: [0x11; 32],
            finding_id: [id_seed; 32],
            stable_item_id: [id_seed.wrapping_add(1); 32],
            rule_fingerprint: [id_seed.wrapping_add(2); 32],
            secret_hash: [id_seed.wrapping_add(3); 32],
        }
    }

    fn occurrence_row(id_seed: u8) -> OccurrenceRow {
        OccurrenceRow {
            tenant_id: [0x11; 32],
            occurrence_id: [id_seed; 32],
            finding_id: [id_seed.wrapping_add(1); 32],
            object_version_id: [id_seed.wrapping_add(2); 32],
            byte_offset: 100,
            byte_length: 50,
        }
    }

    fn observation_row(
        seen_at: i64,
        location_display: Option<&str>,
        location_url: Option<&str>,
        run_id: i64,
        shard_id: i64,
        fence_epoch: i64,
    ) -> ObservationRow {
        ObservationRow {
            tenant_id: [0x11; 32],
            observation_id: [0x21; 32],
            occurrence_id: [0x31; 32],
            policy_hash: [0x41; 32],
            ovid_hash: [0x51; 32],
            run_id,
            shard_id,
            fence_epoch,
            seen_at,
            location_display: location_display.map(str::to_owned),
            location_url: location_url.map(str::to_owned),
        }
    }

    fn assert_finding_conflict(err: FindingsPgError, tenant_id: TenantId, finding_id: FindingId) {
        match err {
            FindingsPgError::FindingConflict {
                tenant_id: actual_tenant,
                finding_id: actual_finding,
            } => {
                assert_eq!(actual_tenant, tenant_id);
                assert_eq!(actual_finding, finding_id);
            }
            other => panic!("expected finding conflict, got {other:?}"),
        }
    }

    fn assert_occurrence_conflict(
        err: FindingsPgError,
        tenant_id: TenantId,
        occurrence_id: OccurrenceId,
    ) {
        match err {
            FindingsPgError::OccurrenceConflict {
                tenant_id: actual_tenant,
                occurrence_id: actual_occurrence,
            } => {
                assert_eq!(actual_tenant, tenant_id);
                assert_eq!(actual_occurrence, occurrence_id);
            }
            other => panic!("expected occurrence conflict, got {other:?}"),
        }
    }

    fn assert_observation_conflict(
        err: FindingsPgError,
        tenant_id: TenantId,
        observation_id: ObservationId,
    ) {
        match err {
            FindingsPgError::ObservationConflict {
                tenant_id: actual_tenant,
                observation_id: actual_observation,
            } => {
                assert_eq!(actual_tenant, tenant_id);
                assert_eq!(actual_observation, observation_id);
            }
            other => panic!("expected observation conflict, got {other:?}"),
        }
    }

    #[test]
    fn merge_observation_location_helpers_build_valid_location() {
        let location = Location::try_new(
            "repo/path".into(),
            Some("https://example.test/repo/path".into()),
        )
        .expect("location fixture should be valid");

        assert_eq!(location.display(), "repo/path");
    }
}
