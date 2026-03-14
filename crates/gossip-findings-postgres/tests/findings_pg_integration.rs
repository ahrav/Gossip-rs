use std::collections::HashSet;

use gossip_contracts::{
    identity::key_secret_hash,
    persistence::{
        CommitHandle, DurableFindingsCounts, FindingsSink, FindingsUpsertBatch,
        conformance::run_findings_conformance,
    },
};

mod common;

use common::{LivePgHarness, sample_fixture};

/// Run these live integration tests with:
///
/// `cargo test -p gossip-findings-postgres --features test-utils -- --ignored`
///
/// Optionally point them at a different Postgres instance with:
///
/// `GOSSIP_POSTGRES_TEST_URL='host=127.0.0.1 user=postgres password=postgres dbname=postgres'`

#[test]
#[ignore = "requires a live Postgres instance"]
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
#[ignore = "requires a live Postgres instance"]
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

    assert_eq!(first_receipt.finding_count(), 1);
    assert_eq!(first_receipt.occurrence_count(), 1);
    assert_eq!(first_receipt.observation_count(), 1);

    // Receipt counts acknowledge the deduplicated batch shape, not net-new rows.
    assert_eq!(second_receipt.finding_count(), 1);
    assert_eq!(second_receipt.occurrence_count(), 1);
    assert_eq!(second_receipt.observation_count(), 1);

    assert_eq!(
        harness.durable_counts(),
        DurableFindingsCounts::new(1, 1, 1),
        "replaying the same batch must not create duplicate durable rows"
    );
}

#[test]
#[ignore = "requires a live Postgres instance"]
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
    let findings = [fixture.finding.clone()];
    let occurrences = [fixture.occurrence.clone()];
    let observations = [second_policy_observation.clone()];

    backend
        .upsert_batch(FindingsUpsertBatch::new(
            &findings,
            &occurrences,
            &observations,
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

    let policy_hashes: HashSet<Vec<u8>> = rows.iter().map(|row| row.policy_hash.clone()).collect();
    let expected_policy_a = fixture.observation.policy_hash().as_bytes().to_vec();
    let expected_policy_b = second_policy_observation.policy_hash().as_bytes().to_vec();
    assert_eq!(policy_hashes.len(), 2);
    assert!(policy_hashes.contains(&expected_policy_a));
    assert!(policy_hashes.contains(&expected_policy_b));

    let observation_ids: HashSet<Vec<u8>> =
        rows.iter().map(|row| row.observation_id.clone()).collect();
    let expected_observation_a = fixture.observation.observation_id().as_bytes().to_vec();
    let expected_observation_b = second_policy_observation
        .observation_id()
        .as_bytes()
        .to_vec();
    assert_eq!(observation_ids.len(), 2);
    assert!(observation_ids.contains(&expected_observation_a));
    assert!(observation_ids.contains(&expected_observation_b));
}

#[test]
#[ignore = "requires a live Postgres instance"]
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

    harness.assert_no_forbidden_material(
        fixture.tenant_id,
        &[
            fixture.raw_secret.clone(),
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
    assert_eq!(stored_observations.len(), 1);
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
