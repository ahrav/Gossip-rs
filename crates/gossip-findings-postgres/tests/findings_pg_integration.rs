use gossip_contracts::persistence::{
    CommitHandle, DurableFindingsCounts, FindingsSink, FindingsUpsertBatch,
};

mod common;

use common::{LivePgHarness, sample_fixture};

/// Run these live integration tests with:
///
/// `cargo test -p gossip-findings-postgres --features test-utils --test findings_pg_integration`
///
/// Optionally point them at a different Postgres instance with:
///
/// `GOSSIP_POSTGRES_TEST_URL='host=127.0.0.1 user=postgres password=postgres dbname=postgres'`

#[test]
fn live_pg_harness_round_trips_fixture_and_inspection_helpers() {
    let mut harness = LivePgHarness::new();
    assert_eq!(harness.durable_counts(), DurableFindingsCounts::default());

    let fixture = sample_fixture(0x31);
    assert_eq!(fixture.finding.stable_item_id(), fixture.stable_item_id);
    assert_eq!(fixture.finding.rule_fingerprint(), fixture.rule_fingerprint);
    assert_eq!(
        fixture.occurrence.object_version_id(),
        fixture.object_version_id
    );
    assert_eq!(fixture.observation.ovid_hash(), fixture.ovid_hash);

    let second_policy_observation =
        fixture.observation_for_policy(0x77, 99_001, 99_002, 99_003, 99_004);
    assert_eq!(
        second_policy_observation.occurrence_id(),
        fixture.occurrence.occurrence_id(),
    );
    assert_ne!(
        second_policy_observation.policy_hash(),
        fixture.observation.policy_hash(),
    );
    assert_ne!(
        second_policy_observation.observation_id(),
        fixture.observation.observation_id(),
    );

    harness
        .backend()
        .upsert_batch(fixture.batch())
        .expect("fixture submit should succeed")
        .wait()
        .expect("fixture durable write should succeed");

    assert_eq!(
        harness.durable_counts(),
        DurableFindingsCounts::new(1, 1, 1)
    );

    let rows = harness
        .observation_rows_for_occurrence(fixture.tenant_id, fixture.occurrence.occurrence_id());
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].observation_id,
        fixture.observation.observation_id().as_bytes().to_vec(),
    );
    assert_eq!(
        rows[0].policy_hash,
        fixture.observation.policy_hash().as_bytes().to_vec(),
    );
    assert_eq!(
        rows[0].location_display.as_deref(),
        Some(fixture.safe_location_display.as_str()),
    );
    assert_eq!(
        rows[0].location_url.as_deref(),
        Some(fixture.safe_location_url.as_str()),
    );

    // Persist the second observation (different policy, same occurrence) and
    // verify the multi-row ordering of observation_rows_for_occurrence.
    let second_batch =
        FindingsUpsertBatch::new(&[], &[], std::slice::from_ref(&second_policy_observation));
    harness
        .backend()
        .upsert_batch(second_batch)
        .expect("second observation submit should succeed")
        .wait()
        .expect("second observation durable write should succeed");

    assert_eq!(
        harness.durable_counts(),
        DurableFindingsCounts::new(1, 1, 2),
    );

    let rows = harness
        .observation_rows_for_occurrence(fixture.tenant_id, fixture.occurrence.occurrence_id());
    assert_eq!(rows.len(), 2, "both observations should be stored");
    // policy 0x35 < 0x77 in ascending order.
    assert_eq!(
        rows[0].policy_hash,
        fixture.observation.policy_hash().as_bytes().to_vec(),
    );
    assert_eq!(
        rows[1].policy_hash,
        second_policy_observation.policy_hash().as_bytes().to_vec(),
    );

    assert_eq!(
        harness.finding_secret_hashes(fixture.tenant_id),
        vec![fixture.finding.secret_hash().as_bytes().to_vec()],
    );

    // Only 32-byte values go in forbidden_byte_values — they match the width
    // of binary columns. The 57-byte raw_secret would pass the sliding-window
    // check vacuously (windows(57) on a 32-byte column is empty). Its exposure
    // is caught by the forbidden_text_fragments check below instead.
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
}
