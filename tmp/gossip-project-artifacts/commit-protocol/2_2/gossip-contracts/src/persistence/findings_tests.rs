use std::num::NonZeroU64;

use crate::{
    connector::Location,
    identity::{
        FenceEpoch, FindingId, LogicalTime, ObjectVersionId, ObservationId, OccurrenceId,
        PolicyHash, RunId, ShardId, TenantId,
    },
    test_util::{ovid, policy, tenant},
};

use super::*;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

fn finding(seed: u8) -> FindingId {
    FindingId::from_bytes([seed; 32])
}

fn occurrence(seed: u8) -> OccurrenceId {
    OccurrenceId::from_bytes([seed; 32])
}

fn object_version(seed: u8) -> ObjectVersionId {
    ObjectVersionId::from_bytes([seed; 32])
}

// ---------------------------------------------------------------------------
// OccurrenceRecord construction
// ---------------------------------------------------------------------------

#[test]
fn occurrence_record_rejects_zero_span_length() {
    let error =
        OccurrenceRecord::try_new(tenant(1), finding(3), object_version(4), 9, 0).unwrap_err();

    assert_eq!(error, PersistenceInputError::ZeroSpanLength);
}

#[test]
fn occurrence_record_accepts_non_zero_span_length() {
    let record = OccurrenceRecord::new(
        tenant(1),
        finding(3),
        object_version(4),
        9,
        NonZeroU64::new(5).unwrap(),
    );

    assert_eq!(record.byte_length().get(), 5);
}

// ---------------------------------------------------------------------------
// FindingsUpsertBatch
// ---------------------------------------------------------------------------

#[test]
fn findings_upsert_batch_reports_empty_only_when_all_slices_are_empty() {
    let empty = FindingsUpsertBatch::default();
    let occurrence = OccurrenceRecord::new(
        tenant(1),
        finding(3),
        object_version(4),
        9,
        NonZeroU64::new(5).unwrap(),
    );
    let occurrences = [occurrence];
    let non_empty = FindingsUpsertBatch::new(&[], &occurrences, &[]);

    assert!(empty.is_empty());
    assert!(!non_empty.is_empty());
}

#[test]
fn total_records_sums_all_layers() {
    let fr = make_finding_record(0x01);
    let occ = make_occurrence_record(0x05);
    let obs = make_observation_record(0x03);
    let findings = [fr];
    let occurrences = [occ];
    let observations = [obs];
    let batch = FindingsUpsertBatch::new(&findings, &occurrences, &observations);

    assert_eq!(batch.total_records(), 3);
    assert_eq!(FindingsUpsertBatch::default().total_records(), 0);
}

#[test]
fn findings_upsert_batch_validate_observation_identity_accepts_canonical() {
    let observations = [make_observation_record(0x03)];

    FindingsUpsertBatch::new(&[], &[], &observations)
        .validate_observation_identity()
        .expect("canonical observations should pass observation-identity validation");
}

#[test]
fn findings_upsert_batch_validate_observation_identity_accepts_empty() {
    FindingsUpsertBatch::default()
        .validate_observation_identity()
        .expect("empty batch should pass observation identity validation");
}

#[test]
fn findings_upsert_batch_validate_observation_identity_rejects_mismatch() {
    let mut observation = make_observation_record(0x03);
    let actual = ObservationId::from_bytes([0xAA; 32]);
    observation.observation_id = actual;
    let expected = observation.derived_observation_id();
    let observations = [observation];

    assert_eq!(
        FindingsUpsertBatch::new(&[], &[], &observations)
            .validate_observation_identity()
            .unwrap_err(),
        PersistenceInputError::ObservationIdMismatch { expected, actual }
    );
}

#[test]
fn findings_upsert_batch_validate_observation_identity_rejects_one_bad_among_valid() {
    let good = make_observation_record(0x01);
    let mut bad = make_observation_record(0x02);
    let actual = ObservationId::from_bytes([0xBB; 32]);
    bad.observation_id = actual;
    let expected = bad.derived_observation_id();
    let observations = [good, bad];

    assert_eq!(
        FindingsUpsertBatch::new(&[], &[], &observations)
            .validate_observation_identity()
            .unwrap_err(),
        PersistenceInputError::ObservationIdMismatch { expected, actual }
    );
}

// ---------------------------------------------------------------------------
// ObservationRecord location metadata
// ---------------------------------------------------------------------------

#[test]
fn observation_record_preserves_optional_location() {
    let observation = ObservationRecord::new(
        tenant(1),
        occurrence(3),
        policy(4),
        ovid(5),
        RunId::from_raw(6),
        ShardId::from_raw(7),
        FenceEpoch::from_raw(8),
        LogicalTime::from_raw(9),
    )
    .with_location(
        Location::try_new("repo/path".into(), Some("https://example.test".into())).unwrap(),
    );

    assert_eq!(observation.location().unwrap().display(), "repo/path");
}

#[test]
fn observation_record_from_write_context_preserves_scope() {
    let write_context = WriteContext::new(
        tenant(1),
        policy(4),
        RunId::from_raw(6),
        ShardId::from_raw(7),
        FenceEpoch::from_raw(8),
    );

    let observation = ObservationRecord::from_write_context(
        write_context,
        occurrence(3),
        ovid(5),
        LogicalTime::from_raw(9),
    );

    assert_eq!(observation.write_context(), write_context);
    assert_eq!(observation.policy_hash(), write_context.policy_hash());
    assert_eq!(observation.run_id(), write_context.run_id());
    assert_eq!(observation.shard_id(), write_context.shard_id());
    assert_eq!(observation.fence_epoch(), write_context.fence_epoch());
}

#[test]
fn observation_record_validation_helpers_match_stored_identity() {
    let record = make_observation_record(0x03);

    assert_eq!(record.derived_observation_id(), record.observation_id());
    record
        .validate_identity()
        .expect("freshly derived observation id should validate");
}

#[test]
fn observation_record_validate_identity_rejects_tampered_id() {
    let mut record = make_observation_record(0x03);
    let actual = ObservationId::from_bytes([0xFF; 32]);
    record.observation_id = actual;
    let expected = record.derived_observation_id();

    assert_eq!(
        record.validate_identity().unwrap_err(),
        PersistenceInputError::ObservationIdMismatch { expected, actual }
    );
}

#[test]
fn observation_record_from_persisted_accepts_matching_id() {
    let record = make_observation_record(0x03);

    let rebuilt = ObservationRecord::from_persisted(
        record.tenant_id(),
        record.observation_id(),
        record.occurrence_id(),
        record.policy_hash(),
        record.ovid_hash(),
        record.run_id(),
        record.shard_id(),
        record.fence_epoch(),
        record.seen_at(),
        None,
    )
    .expect("matching persisted observation id should be accepted");

    assert_eq!(rebuilt, record);
}

#[test]
fn observation_record_from_persisted_rejects_mismatched_id() {
    let record = make_observation_record(0x03);
    let actual = ObservationId::from_bytes([0xEE; 32]);

    assert_eq!(
        ObservationRecord::from_persisted(
            record.tenant_id(),
            actual,
            record.occurrence_id(),
            record.policy_hash(),
            record.ovid_hash(),
            record.run_id(),
            record.shard_id(),
            record.fence_epoch(),
            record.seen_at(),
            None,
        )
        .unwrap_err(),
        PersistenceInputError::ObservationIdMismatch {
            expected: record.derived_observation_id(),
            actual,
        }
    );
}

#[test]
fn from_persisted_preserves_location_metadata() {
    let location =
        Location::try_new("repo/path".into(), Some("https://example.test".into())).unwrap();
    let record = make_observation_record(0x03).with_location(location.clone());

    let rebuilt = ObservationRecord::from_persisted(
        record.tenant_id(),
        record.observation_id(),
        record.occurrence_id(),
        record.policy_hash(),
        record.ovid_hash(),
        record.run_id(),
        record.shard_id(),
        record.fence_epoch(),
        record.seen_at(),
        Some(location),
    )
    .expect("matching id should be accepted");

    assert_eq!(rebuilt, record);
}

#[test]
fn derive_observation_id_is_field_order_sensitive() {
    let canonical = derive_observation_id(&ObservationIdInputs {
        tenant: TenantId::from_bytes([0x11; 32]),
        policy: PolicyHash::from_bytes([0x22; 32]),
        occurrence: OccurrenceId::from_bytes([0x33; 32]),
    });
    let swapped = derive_observation_id(&ObservationIdInputs {
        tenant: TenantId::from_bytes([0x22; 32]),
        policy: PolicyHash::from_bytes([0x11; 32]),
        occurrence: OccurrenceId::from_bytes([0x33; 32]),
    });

    assert_ne!(canonical, swapped);
}

// ---------------------------------------------------------------------------
// verify_id — correctness and tampering detection
// ---------------------------------------------------------------------------

fn make_finding_record(tenant_seed: u8) -> FindingRecord {
    use crate::identity::{
        NormHash, RuleFingerprint, StableItemId, TenantId, TenantSecretKey, key_secret_hash,
    };

    let tenant_id = TenantId::from_bytes([tenant_seed; 32]);
    let stable_item_id = StableItemId::from_bytes([0x02; 32]);
    let rule_fingerprint = RuleFingerprint::from_bytes([0x03; 32]);
    let secret_hash = key_secret_hash(
        &TenantSecretKey::from_bytes([0x42; 32]),
        &NormHash::from_digest([0xAB; 32]),
    );

    FindingRecord::new(tenant_id, stable_item_id, rule_fingerprint, secret_hash)
}

#[test]
fn finding_record_verify_id_with_correct_derivation() {
    let record = make_finding_record(0x01);
    assert!(
        record.verify_id(),
        "correctly derived finding_id should verify"
    );
}

#[test]
fn finding_record_verify_id_with_wrong_id() {
    let mut record = make_finding_record(0x01);
    // Tamper with the finding_id.
    record.finding_id = FindingId::from_bytes([0xFF; 32]);
    assert!(
        !record.verify_id(),
        "mismatched finding_id should not verify"
    );
}

fn make_occurrence_record(finding_seed: u8) -> OccurrenceRecord {
    let finding_id = FindingId::from_bytes([finding_seed; 32]);
    let object_version_id = ObjectVersionId::from_bytes([0x04; 32]);

    OccurrenceRecord::new(
        tenant(1),
        finding_id,
        object_version_id,
        100,
        NonZeroU64::new(50).unwrap(),
    )
}

#[test]
fn occurrence_record_verify_id_with_correct_derivation() {
    let record = make_occurrence_record(0x05);
    assert!(
        record.verify_id(),
        "correctly derived occurrence_id should verify"
    );
}

#[test]
fn occurrence_record_verify_id_with_wrong_id() {
    let mut record = make_occurrence_record(0x05);
    record.occurrence_id = OccurrenceId::from_bytes([0xFF; 32]);
    assert!(
        !record.verify_id(),
        "mismatched occurrence_id should not verify"
    );
}

fn make_observation_record(occurrence_seed: u8) -> ObservationRecord {
    let tenant_id = TenantId::from_bytes([0x01; 32]);
    let policy_hash = PolicyHash::from_bytes([0x04; 32]);
    let occurrence_id = OccurrenceId::from_bytes([occurrence_seed; 32]);

    ObservationRecord::new(
        tenant_id,
        occurrence_id,
        policy_hash,
        ovid(5),
        RunId::from_raw(6),
        ShardId::from_raw(7),
        FenceEpoch::from_raw(8),
        LogicalTime::from_raw(9),
    )
}

#[test]
fn observation_record_verify_id_with_correct_derivation() {
    let record = make_observation_record(0x03);
    assert!(
        record.verify_id(),
        "correctly derived observation_id should verify"
    );
}

#[test]
fn observation_record_verify_id_with_wrong_id() {
    let mut record = make_observation_record(0x03);
    record.observation_id = ObservationId::from_bytes([0xFF; 32]);
    assert!(
        !record.verify_id(),
        "mismatched observation_id should not verify"
    );
}

// ---------------------------------------------------------------------------
// validate_referential_integrity
// ---------------------------------------------------------------------------

#[test]
fn validate_accepts_referentially_consistent_batch() {
    use crate::identity::{
        NormHash, ObjectVersionId, RuleFingerprint, StableItemId, TenantId, TenantSecretKey,
        key_secret_hash,
    };

    let tenant_id = TenantId::from_bytes([0x01; 32]);
    let stable_item_id = StableItemId::from_bytes([0x02; 32]);
    let rule_fp = RuleFingerprint::from_bytes([0x03; 32]);
    let secret = key_secret_hash(
        &TenantSecretKey::from_bytes([0x42; 32]),
        &NormHash::from_digest([0xAB; 32]),
    );
    let fr = FindingRecord::new(tenant_id, stable_item_id, rule_fp, secret);

    let obj = ObjectVersionId::from_bytes([0x04; 32]);
    let occ = OccurrenceRecord::new(
        tenant_id,
        fr.finding_id(),
        obj,
        0,
        NonZeroU64::new(10).unwrap(),
    );

    let policy_h = PolicyHash::from_bytes([0x05; 32]);
    let obs = ObservationRecord::new(
        tenant_id,
        occ.occurrence_id(),
        policy_h,
        ovid(6),
        RunId::from_raw(7),
        ShardId::from_raw(8),
        FenceEpoch::from_raw(9),
        LogicalTime::from_raw(10),
    );

    let findings = [fr];
    let occurrences = [occ];
    let observations = [obs];
    let batch = FindingsUpsertBatch::new(&findings, &occurrences, &observations);
    batch
        .validate_referential_integrity()
        .expect("consistent batch should pass");
}

#[test]
fn validate_rejects_orphaned_occurrence() {
    let occ = make_occurrence_record(0x05);
    let occurrences = [occ];
    // No findings in the batch — occurrence's finding_id is orphaned.
    let batch = FindingsUpsertBatch::new(&[], &occurrences, &[]);
    assert_eq!(
        batch.validate_referential_integrity().unwrap_err(),
        PersistenceInputError::OrphanedReference {
            child_type: "OccurrenceRecord",
            parent_type: "FindingRecord",
        }
    );
}

#[test]
fn validate_rejects_orphaned_observation() {
    let obs = make_observation_record(0x03);
    let observations = [obs];
    // No occurrences in the batch — observation's occurrence_id is orphaned.
    let batch = FindingsUpsertBatch::new(&[], &[], &observations);
    assert_eq!(
        batch.validate_referential_integrity().unwrap_err(),
        PersistenceInputError::OrphanedReference {
            child_type: "ObservationRecord",
            parent_type: "OccurrenceRecord",
        }
    );
}

#[test]
fn validate_accepts_empty_batch() {
    let batch = FindingsUpsertBatch::default();
    batch
        .validate_referential_integrity()
        .expect("empty batch is valid");
}

#[test]
fn validate_rejects_mixed_tenants_in_findings() {
    use crate::identity::{
        NormHash, RuleFingerprint, StableItemId, TenantSecretKey, key_secret_hash,
    };

    let sid = StableItemId::from_bytes([0x02; 32]);
    let rule = RuleFingerprint::from_bytes([0x03; 32]);
    let secret = key_secret_hash(
        &TenantSecretKey::from_bytes([0x42; 32]),
        &NormHash::from_digest([0xAB; 32]),
    );
    let fr_a = FindingRecord::new(tenant(1), sid, rule, secret);
    let fr_b = FindingRecord::new(tenant(2), sid, rule, secret);

    let findings = [fr_a, fr_b];
    let batch = FindingsUpsertBatch::new(&findings, &[], &[]);
    assert_eq!(
        batch.validate_referential_integrity().unwrap_err(),
        PersistenceInputError::InconsistentTenant,
    );
}

#[test]
fn validate_rejects_mixed_tenants_across_layers() {
    use crate::identity::{
        NormHash, ObjectVersionId, RuleFingerprint, StableItemId, TenantSecretKey, key_secret_hash,
    };

    let sid = StableItemId::from_bytes([0x02; 32]);
    let rule = RuleFingerprint::from_bytes([0x03; 32]);
    let secret = key_secret_hash(
        &TenantSecretKey::from_bytes([0x42; 32]),
        &NormHash::from_digest([0xAB; 32]),
    );
    let fr = FindingRecord::new(tenant(1), sid, rule, secret);
    // Occurrence belongs to a different tenant.
    let occ = OccurrenceRecord::new(
        tenant(2),
        fr.finding_id(),
        ObjectVersionId::from_bytes([0x04; 32]),
        0,
        NonZeroU64::new(10).unwrap(),
    );

    let findings = [fr];
    let occurrences = [occ];
    let batch = FindingsUpsertBatch::new(&findings, &occurrences, &[]);
    assert_eq!(
        batch.validate_referential_integrity().unwrap_err(),
        PersistenceInputError::InconsistentTenant,
    );
}

// ---------------------------------------------------------------------------
// Proptest: constructor-derived IDs match manual derivation
// ---------------------------------------------------------------------------

proptest::proptest! {
    #![proptest_config(crate::test_util::miri_proptest_config())]

    #[test]
    fn finding_record_id_matches_manual_derivation(
        t in proptest::array::uniform32(proptest::num::u8::ANY),
        i in proptest::array::uniform32(proptest::num::u8::ANY),
        r in proptest::array::uniform32(proptest::num::u8::ANY),
        s in proptest::array::uniform32(proptest::num::u8::ANY),
    ) {
        use crate::identity::{
            FindingIdInputs, SecretHash, StableItemId, RuleFingerprint,
            derive_finding_id,
        };
        let tid = TenantId::from_bytes(t);
        let item = StableItemId::from_bytes(i);
        let rule = RuleFingerprint::from_bytes(r);
        let secret = SecretHash::from_bytes_internal(s);
        let record = FindingRecord::new(tid, item, rule, secret);
        let expected = derive_finding_id(&FindingIdInputs {
            tenant: tid, item, rule, secret,
        });
        proptest::prop_assert_eq!(record.finding_id(), expected);
    }

    #[test]
    fn occurrence_record_id_matches_manual_derivation(
        f in proptest::array::uniform32(proptest::num::u8::ANY),
        v in proptest::array::uniform32(proptest::num::u8::ANY),
        offset in proptest::num::u64::ANY,
        length in 1u64..=u64::MAX,
    ) {
        use crate::identity::{
            OccurrenceIdInputs, derive_occurrence_id,
        };
        let fid = FindingId::from_bytes(f);
        let vid = ObjectVersionId::from_bytes(v);
        let bl = NonZeroU64::new(length).unwrap();
        let record = OccurrenceRecord::new(tenant(1), fid, vid, offset, bl);
        let expected = derive_occurrence_id(&OccurrenceIdInputs {
            finding: fid, version: vid, byte_offset: offset, byte_length: length,
        });
        proptest::prop_assert_eq!(record.occurrence_id(), expected);
    }

    #[test]
    fn observation_record_id_matches_manual_derivation(
        t in proptest::array::uniform32(proptest::num::u8::ANY),
        p in proptest::array::uniform32(proptest::num::u8::ANY),
        o in proptest::array::uniform32(proptest::num::u8::ANY),
    ) {
        use crate::identity::{
            ObservationIdInputs, derive_observation_id,
        };
        let tid = TenantId::from_bytes(t);
        let ph = PolicyHash::from_bytes(p);
        let oid = OccurrenceId::from_bytes(o);
        let record = ObservationRecord::new(
            tid, oid, ph, ovid(1),
            RunId::from_raw(1), ShardId::from_raw(1),
            FenceEpoch::from_raw(1), LogicalTime::from_raw(1),
        );
        let expected = derive_observation_id(&ObservationIdInputs {
            tenant: tid, policy: ph, occurrence: oid,
        });
        proptest::prop_assert_eq!(record.observation_id(), expected);
        proptest::prop_assert!(record.validate_identity().is_ok());
    }
}
