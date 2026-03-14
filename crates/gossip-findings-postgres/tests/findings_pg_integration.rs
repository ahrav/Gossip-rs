use gossip_contracts::persistence::{CommitHandle, DurableFindingsCounts, FindingsSink};

mod common;

use common::{LivePgHarness, sample_fixture};

/// Run these live integration tests with:
///
/// `cargo test -p gossip-findings-postgres --features test-utils --test findings_pg_integration -- --ignored`
///
/// Optionally point them at a different Postgres instance with:
///
/// `GOSSIP_POSTGRES_TEST_URL='host=127.0.0.1 user=postgres password=postgres dbname=postgres'`

#[test]
#[ignore = "requires a live Postgres instance"]
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

    assert_eq!(
        harness.finding_secret_hashes(fixture.tenant_id),
        vec![fixture.finding.secret_hash().as_bytes().to_vec()],
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
}
