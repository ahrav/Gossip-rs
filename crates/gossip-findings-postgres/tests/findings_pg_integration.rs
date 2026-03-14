use gossip_contracts::{
    connector::{Location, VersionId},
    identity::key_secret_hash,
    identity::{FenceEpoch, LogicalTime, ObjectVersionId, RunId, ShardId},
    persistence::{
        CommitHandle, DurableFindingsCounts, FindingRecord, FindingsSink, FindingsUpsertBatch,
        ObservationRecord, OccurrenceRecord, OvidHashInputs, conformance::run_findings_conformance,
        derive_ovid_hash,
    },
};

mod common;

use common::{FindingsFixture, LivePgHarness, policy, rule, sample_fixture, stable_item, tenant};

struct AdditionalFindingRecords {
    finding: FindingRecord,
    occurrence: OccurrenceRecord,
    observation: ObservationRecord,
}

fn additional_finding_records(
    base: &FindingsFixture,
    disambiguator: u8,
    policy_fill: u8,
    seen_at: u64,
) -> AdditionalFindingRecords {
    let stable_item_id = stable_item(disambiguator.wrapping_add(1));
    let rule_fingerprint = rule(disambiguator.wrapping_add(2));
    let secret_hash = key_secret_hash(&base.tenant_secret_key, &base.norm_hash);
    let finding = FindingRecord::new(
        base.tenant_id,
        stable_item_id,
        rule_fingerprint,
        secret_hash,
    );
    let object_version_id = ObjectVersionId::from_version_bytes(
        format!("findings-variant-{disambiguator:02X}").as_bytes(),
    );
    let occurrence = OccurrenceRecord::try_new(
        base.tenant_id,
        finding.finding_id(),
        object_version_id,
        2_000 + u64::from(disambiguator),
        32,
    )
    .expect("fixture byte_length is non-zero");
    let ovid_hash = derive_ovid_hash(&OvidHashInputs {
        stable_item_id,
        version: VersionId::Strong(object_version_id),
    });
    let location = Location::try_new(
        format!("safe/path/findings-{disambiguator:02X}.txt"),
        Some(format!(
            "https://example.invalid/findings/{disambiguator:02X}"
        )),
    )
    .expect("fixture location should be valid");
    let observation = ObservationRecord::new(
        base.tenant_id,
        occurrence.occurrence_id(),
        policy(policy_fill),
        ovid_hash,
        RunId::from_raw(50_000 + u64::from(disambiguator)),
        ShardId::from_raw(60_000 + u64::from(disambiguator)),
        FenceEpoch::from_raw(70_000 + u64::from(disambiguator)),
        LogicalTime::from_raw(seen_at),
    )
    .with_location(location);

    AdditionalFindingRecords {
        finding,
        occurrence,
        observation,
    }
}

/// Run these live integration tests with:
///
/// `cargo test -p gossip-findings-postgres --features test-utils --test findings_pg_integration`
///
/// Optionally point them at a different Postgres instance with:
///
/// `GOSSIP_POSTGRES_TEST_URL='host=127.0.0.1 user=postgres password=postgres dbname=postgres'`

#[test]
fn findings_pg_passes_findings_conformance_suite() {
    let mut harness = LivePgHarness::new();

    run_findings_conformance(harness.backend())
        .unwrap_or_else(|err| panic!("postgres findings conformance failed: {err}"));

    let counts = harness.durable_counts();
    assert!(
        counts.findings >= 1,
        "conformance should persist at least one finding"
    );
    assert!(
        counts.occurrences >= 1,
        "conformance should persist at least one occurrence"
    );
    assert!(
        counts.observations >= 1,
        "conformance should persist at least one observation"
    );
}

#[test]
fn same_record_inserted_twice_creates_no_duplicates() {
    let mut harness = LivePgHarness::new();
    let backend = harness.backend();
    let fixture = sample_fixture(0x31);

    let first_receipt = backend
        .upsert_batch(fixture.batch())
        .expect("first submit should succeed")
        .wait()
        .expect("first durable write should succeed");
    let second_receipt = backend
        .upsert_batch(fixture.batch())
        .expect("second submit should succeed")
        .wait()
        .expect("second durable write should succeed");

    assert_eq!(
        first_receipt.finding_count(),
        1,
        "first receipt should report exactly one finding"
    );
    assert_eq!(
        first_receipt.occurrence_count(),
        1,
        "first receipt should report exactly one occurrence"
    );
    assert_eq!(
        first_receipt.observation_count(),
        1,
        "first receipt should report exactly one observation"
    );

    // Receipt counts reflect the deduplicated batch shape (see `build_receipt`),
    // not net-new rows. An idempotent replay still reports (1, 1, 1).
    assert_eq!(
        second_receipt.finding_count(),
        1,
        "deduplicated replay should report same finding count"
    );
    assert_eq!(
        second_receipt.occurrence_count(),
        1,
        "deduplicated replay should report same occurrence count"
    );
    assert_eq!(
        second_receipt.observation_count(),
        1,
        "deduplicated replay should report same observation count"
    );

    assert_eq!(
        harness.durable_counts(),
        DurableFindingsCounts::new(1, 1, 1),
        "replaying the same batch must not create duplicate durable rows"
    );
}

#[test]
fn two_observations_for_same_occurrence_under_different_policies_both_exist() {
    let mut harness = LivePgHarness::new();
    let backend = harness.backend();
    let fixture = sample_fixture(0x41);

    backend
        .upsert_batch(fixture.batch())
        .expect("initial submit should succeed")
        .wait()
        .expect("initial durable write should succeed");

    let second_policy_observation = fixture.observation_for_policy(
        0x77,
        99_001,
        99_002,
        99_003,
        fixture.observation.seen_at().as_raw() + 500,
    );

    // Submit only the new observation — the parent finding and occurrence
    // already exist from the initial batch. This exercises the code path
    // where an observation arrives without its parent in the same batch.
    backend
        .upsert_batch(FindingsUpsertBatch::new(
            &[],
            &[],
            std::slice::from_ref(&second_policy_observation),
        ))
        .expect("second-policy submit should succeed")
        .wait()
        .expect("second-policy durable write should succeed");

    assert_eq!(
        harness.durable_counts(),
        DurableFindingsCounts::new(1, 1, 2),
        "same occurrence under different policies must produce two observations but only one finding and one occurrence"
    );

    let rows = harness
        .observation_rows_for_occurrence(fixture.tenant_id, fixture.occurrence.occurrence_id());
    assert_eq!(rows.len(), 2, "two policy-scoped observations should exist");

    let mut policy_hashes: Vec<Vec<u8>> = rows.iter().map(|row| row.policy_hash.clone()).collect();
    policy_hashes.sort();
    let mut expected_policies = vec![
        fixture.observation.policy_hash().as_bytes().to_vec(),
        second_policy_observation.policy_hash().as_bytes().to_vec(),
    ];
    expected_policies.sort();
    assert_eq!(
        policy_hashes, expected_policies,
        "both policy hashes should be stored for the same occurrence"
    );

    let mut observation_ids: Vec<Vec<u8>> =
        rows.iter().map(|row| row.observation_id.clone()).collect();
    observation_ids.sort();
    let mut expected_observations = vec![
        fixture.observation.observation_id().as_bytes().to_vec(),
        second_policy_observation
            .observation_id()
            .as_bytes()
            .to_vec(),
    ];
    expected_observations.sort();
    assert_eq!(
        observation_ids, expected_observations,
        "both observation IDs should be stored for the same occurrence"
    );
}

#[test]
fn no_raw_secret_bytes_are_persisted_in_any_inserted_columns() {
    let mut harness = LivePgHarness::new();
    let backend = harness.backend();
    let fixture = sample_fixture(0x61);

    backend
        .upsert_batch(fixture.batch())
        .expect("submit should succeed")
        .wait()
        .expect("durable write should succeed");

    let expected_secret_hash = key_secret_hash(&fixture.tenant_secret_key, &fixture.norm_hash);
    let stored_secret_hashes = harness.finding_secret_hashes(fixture.tenant_id);
    assert_eq!(
        stored_secret_hashes,
        vec![expected_secret_hash.as_bytes().to_vec()],
        "the keyed secret hash should be stored exactly once"
    );

    // Only 32-byte values go in forbidden_byte_values — they match the width
    // of binary columns. The variable-length raw_secret passes the
    // sliding-window check vacuously (windows(N) on a shorter column is
    // empty). Raw-secret exposure is caught by the forbidden_text_fragments
    // check below instead.
    harness.assert_no_forbidden_material(
        fixture.tenant_id,
        &[
            fixture.norm_hash.as_bytes().to_vec(),
            fixture.tenant_secret_key.as_bytes().to_vec(),
        ],
        &[
            std::str::from_utf8(&fixture.raw_secret)
                .expect("fixture raw secret must be valid utf-8"),
            fixture.unsafe_context.as_str(),
        ],
    );

    let stored_observations = harness
        .observation_rows_for_occurrence(fixture.tenant_id, fixture.occurrence.occurrence_id());
    assert_eq!(
        stored_observations.len(),
        1,
        "exactly one observation should be stored"
    );
    assert_eq!(
        stored_observations[0].location_display.as_deref(),
        Some(fixture.safe_location_display.as_str()),
        "only the safe display location should be stored"
    );
    assert_eq!(
        stored_observations[0].location_url.as_deref(),
        Some(fixture.safe_location_url.as_str()),
        "only the safe location URL should be stored"
    );
}

#[test]
fn count_observations_by_tenant_policy_groups_rows_by_policy() {
    let harness = LivePgHarness::new();
    let backend = harness.backend();
    let base = sample_fixture(0x71);
    let same_policy = additional_finding_records(
        &base,
        0x81,
        base.observation.policy_hash().as_bytes()[0],
        base.observation.seen_at().as_raw() + 10,
    );
    let different_policy = additional_finding_records(
        &base,
        0x82,
        base.observation.policy_hash().as_bytes()[0].wrapping_add(1),
        base.observation.seen_at().as_raw() + 20,
    );

    backend
        .upsert_batch(base.batch())
        .expect("base batch should succeed")
        .wait()
        .expect("base batch should commit");
    backend
        .upsert_batch(FindingsUpsertBatch::new(
            std::slice::from_ref(&same_policy.finding),
            std::slice::from_ref(&same_policy.occurrence),
            std::slice::from_ref(&same_policy.observation),
        ))
        .expect("same-policy batch should succeed")
        .wait()
        .expect("same-policy batch should commit");
    backend
        .upsert_batch(FindingsUpsertBatch::new(
            std::slice::from_ref(&different_policy.finding),
            std::slice::from_ref(&different_policy.occurrence),
            std::slice::from_ref(&different_policy.observation),
        ))
        .expect("different-policy batch should succeed")
        .wait()
        .expect("different-policy batch should commit");

    let counts = backend
        .count_observations_by_tenant_policy(base.tenant_id)
        .expect("policy count query should succeed");

    assert_eq!(
        counts.len(),
        2,
        "tenant should have exactly two policy groups"
    );
    assert_eq!(
        counts.iter().map(|row| row.tenant_id()).collect::<Vec<_>>(),
        vec![base.tenant_id, base.tenant_id],
        "every grouped row should belong to the requested tenant"
    );
    let mut actual: Vec<_> = counts
        .iter()
        .map(|row| (row.policy_hash(), row.observation_count()))
        .collect();
    actual.sort_by_key(|(ph, _)| *ph.as_bytes());
    let mut expected = vec![
        (base.observation.policy_hash(), 2),
        (different_policy.observation.policy_hash(), 1),
    ];
    expected.sort_by_key(|(ph, _)| *ph.as_bytes());
    assert_eq!(actual, expected, "counts should be grouped by policy hash");
}

#[test]
fn list_findings_needing_triage_returns_latest_rows_ordered_by_seen_at_and_limited() {
    let harness = LivePgHarness::new();
    let backend = harness.backend();
    let oldest = sample_fixture(0x72);
    let middle = additional_finding_records(
        &oldest,
        0x83,
        0x95,
        oldest.observation.seen_at().as_raw() + 100,
    );
    let newest = additional_finding_records(
        &oldest,
        0x84,
        0x96,
        oldest.observation.seen_at().as_raw() + 200,
    );

    backend
        .upsert_batch(oldest.batch())
        .expect("oldest batch should succeed")
        .wait()
        .expect("oldest batch should commit");
    backend
        .upsert_batch(FindingsUpsertBatch::new(
            std::slice::from_ref(&middle.finding),
            std::slice::from_ref(&middle.occurrence),
            std::slice::from_ref(&middle.observation),
        ))
        .expect("middle batch should succeed")
        .wait()
        .expect("middle batch should commit");
    backend
        .upsert_batch(FindingsUpsertBatch::new(
            std::slice::from_ref(&newest.finding),
            std::slice::from_ref(&newest.occurrence),
            std::slice::from_ref(&newest.observation),
        ))
        .expect("newest batch should succeed")
        .wait()
        .expect("newest batch should commit");

    let rows = backend
        .list_findings_needing_triage(oldest.tenant_id, 2)
        .expect("triage query should succeed");

    assert_eq!(rows.len(), 2, "limit should bound the result set");
    assert_eq!(rows[0].tenant_id(), oldest.tenant_id);
    assert_eq!(rows[0].finding_id(), newest.finding.finding_id());
    assert_eq!(rows[0].stable_item_id(), newest.finding.stable_item_id());
    assert_eq!(rows[0].occurrence_id(), newest.occurrence.occurrence_id());
    assert_eq!(
        rows[0].observation_id(),
        newest.observation.observation_id()
    );
    assert_eq!(rows[0].policy_hash(), newest.observation.policy_hash());
    assert_eq!(rows[0].seen_at(), newest.observation.seen_at().as_raw());
    assert_eq!(
        rows[0].location_display(),
        Some("safe/path/findings-84.txt")
    );
    assert_eq!(
        rows[0].location_url(),
        Some("https://example.invalid/findings/84")
    );
    assert_eq!(rows[1].finding_id(), middle.finding.finding_id());
    assert_eq!(rows[1].seen_at(), middle.observation.seen_at().as_raw());
}

#[test]
fn list_findings_needing_triage_returns_latest_observation_when_finding_has_multiple() {
    let harness = LivePgHarness::new();
    let backend = harness.backend();
    let fixture = sample_fixture(0x75);

    // Insert the base fixture (1 finding, 1 occurrence, 1 observation).
    backend
        .upsert_batch(fixture.batch())
        .expect("base batch should succeed")
        .wait()
        .expect("base batch should commit");

    // Insert a second observation for the same occurrence under a different
    // policy and with a later seen_at, so DISTINCT ON must pick this one.
    let later_seen_at = fixture.observation.seen_at().as_raw() + 500;
    let second_observation =
        fixture.observation_for_policy(0xAA, 99_101, 99_102, 99_103, later_seen_at);
    backend
        .upsert_batch(FindingsUpsertBatch::new(
            &[],
            &[],
            std::slice::from_ref(&second_observation),
        ))
        .expect("second-observation submit should succeed")
        .wait()
        .expect("second-observation durable write should succeed");

    let rows = backend
        .list_findings_needing_triage(fixture.tenant_id, 10)
        .expect("triage query should succeed");

    assert_eq!(
        rows.len(),
        1,
        "DISTINCT ON should collapse two observations into one row per finding"
    );
    assert_eq!(
        rows[0].observation_id(),
        second_observation.observation_id(),
        "DISTINCT ON should select the observation with the later seen_at"
    );
    assert_eq!(
        rows[0].policy_hash(),
        second_observation.policy_hash(),
        "returned row should carry the policy hash of the latest observation"
    );
    assert_eq!(
        rows[0].seen_at(),
        later_seen_at,
        "returned row should carry the seen_at of the latest observation"
    );
}

#[test]
fn list_findings_needing_triage_picks_latest_across_multiple_occurrences() {
    let harness = LivePgHarness::new();
    let backend = harness.backend();
    let fixture = sample_fixture(0x78);

    // Insert base fixture: finding + occurrence A + observation A.
    backend
        .upsert_batch(fixture.batch())
        .expect("base batch should succeed")
        .wait()
        .expect("base batch should commit");

    // Create a second occurrence for the SAME finding with a later observation.
    let object_version_id_b =
        ObjectVersionId::from_version_bytes(b"findings-pg-version-second-occurrence");
    let occurrence_b = OccurrenceRecord::try_new(
        fixture.tenant_id,
        fixture.finding.finding_id(),
        object_version_id_b,
        5_000,
        64,
    )
    .expect("fixture byte_length is non-zero");

    let ovid_hash_b = derive_ovid_hash(&OvidHashInputs {
        stable_item_id: fixture.finding.stable_item_id(),
        version: VersionId::Strong(object_version_id_b),
    });

    let later_seen_at = fixture.observation.seen_at().as_raw() + 1_000;
    let observation_b = ObservationRecord::new(
        fixture.tenant_id,
        occurrence_b.occurrence_id(),
        policy(0xCC),
        ovid_hash_b,
        RunId::from_raw(77_001),
        ShardId::from_raw(77_002),
        FenceEpoch::from_raw(77_003),
        LogicalTime::from_raw(later_seen_at),
    )
    .with_location(
        Location::try_new(
            "safe/path/second-occ.txt".to_owned(),
            Some("https://example.invalid/second-occ".to_owned()),
        )
        .expect("fixture location should be valid"),
    );

    backend
        .upsert_batch(FindingsUpsertBatch::new(
            &[],
            std::slice::from_ref(&occurrence_b),
            std::slice::from_ref(&observation_b),
        ))
        .expect("second-occurrence batch should succeed")
        .wait()
        .expect("second-occurrence batch should commit");

    let rows = backend
        .list_findings_needing_triage(fixture.tenant_id, 10)
        .expect("triage query should succeed");

    assert_eq!(
        rows.len(),
        1,
        "DISTINCT ON should collapse both occurrences into one row per finding"
    );
    assert_eq!(
        rows[0].occurrence_id(),
        occurrence_b.occurrence_id(),
        "DISTINCT ON should select the occurrence whose observation has the later seen_at"
    );
    assert_eq!(
        rows[0].observation_id(),
        observation_b.observation_id(),
        "returned observation_id should match the later observation"
    );
    assert_eq!(
        rows[0].seen_at(),
        later_seen_at,
        "returned seen_at should be the later timestamp"
    );
}

#[test]
fn read_methods_return_empty_results_for_unknown_tenant() {
    let harness = LivePgHarness::new();
    let backend = harness.backend();
    let fixture = sample_fixture(0x73);

    backend
        .upsert_batch(fixture.batch())
        .expect("fixture batch should succeed")
        .wait()
        .expect("fixture batch should commit");

    let unknown_tenant = tenant(0xFE);
    assert!(
        backend
            .count_observations_by_tenant_policy(unknown_tenant)
            .expect("empty count query should succeed")
            .is_empty(),
        "count query should return no rows for a tenant without data"
    );
    assert!(
        backend
            .list_findings_needing_triage(unknown_tenant, 10)
            .expect("empty triage query should succeed")
            .is_empty(),
        "triage query should return no rows for a tenant without data"
    );
}

#[test]
fn list_findings_needing_triage_returns_none_for_observation_without_location() {
    let harness = LivePgHarness::new();
    let backend = harness.backend();
    let fixture = sample_fixture(0x76);

    // Build an observation without calling .with_location(), so both
    // location_display and location_url default to None.
    let no_location_observation = ObservationRecord::new(
        fixture.tenant_id,
        fixture.occurrence.occurrence_id(),
        policy(0xBB),
        fixture.ovid_hash,
        RunId::from_raw(88_001),
        ShardId::from_raw(88_002),
        FenceEpoch::from_raw(88_003),
        LogicalTime::from_raw(fixture.observation.seen_at().as_raw() + 1_000),
    );

    // Submit the base finding and occurrence, plus the no-location observation.
    backend
        .upsert_batch(FindingsUpsertBatch::new(
            std::slice::from_ref(&fixture.finding),
            std::slice::from_ref(&fixture.occurrence),
            std::slice::from_ref(&no_location_observation),
        ))
        .expect("no-location batch should succeed")
        .wait()
        .expect("no-location batch should commit");

    let rows = backend
        .list_findings_needing_triage(fixture.tenant_id, 10)
        .expect("triage query should succeed");

    assert_eq!(rows.len(), 1, "should return exactly one finding row");
    assert!(
        rows[0].location_display().is_none(),
        "observation without location should have None location_display"
    );
    assert!(
        rows[0].location_url().is_none(),
        "observation without location should have None location_url"
    );
}

#[test]
fn list_findings_needing_triage_with_zero_limit_returns_empty_vec() {
    let harness = LivePgHarness::new();
    let backend = harness.backend();
    let fixture = sample_fixture(0x74);

    backend
        .upsert_batch(fixture.batch())
        .expect("fixture batch should succeed")
        .wait()
        .expect("fixture batch should commit");

    let rows = backend
        .list_findings_needing_triage(fixture.tenant_id, 0)
        .expect("zero-limit triage query should succeed");

    assert!(rows.is_empty(), "LIMIT 0 should return no rows");
}
