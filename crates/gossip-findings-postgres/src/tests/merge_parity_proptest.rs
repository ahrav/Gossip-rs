//! Property tests that compare PostgreSQL `ON CONFLICT` merge behavior with
//! the in-memory `merge_observation_rows` implementation.

use crate::backend::merge_observation_rows;
use crate::schema::{
    FINDINGS_TABLE, OBSERVATIONS_INSERT_OR_MERGE_SQL, OBSERVATIONS_TABLE, OCCURRENCES_TABLE,
    ObservationRow,
};
use crate::test_postgres::test_client;
use gossip_stdx::test_support::proptest_cases;
use postgres::Client;
use proptest::{
    prelude::*,
    test_runner::{Config as ProptestConfig, TestCaseError, TestRunner},
};
use std::cell::{Cell, RefCell};

// ── Fixed identity values ─────────────────────────────────────────────────

/// Fixed `tenant_id` for all proptest observations (matches parent rows).
const FIXED_TENANT: [u8; 32] = [0x10; 32];
/// Fixed `finding_id` for the parent finding row.
const FIXED_FINDING: [u8; 32] = [0x11; 32];
/// Fixed `occurrence_id` for the parent occurrence and all observations.
const FIXED_OCCURRENCE: [u8; 32] = [0x21; 32];
/// Fixed `observation_id` shared by both observations in each case.
const FIXED_OBSERVATION: [u8; 32] = [0x31; 32];
/// Fixed `policy_hash` shared by both observations (identity field).
const FIXED_POLICY: [u8; 32] = [0x32; 32];
/// Fixed `ovid_hash` shared by both observations (identity field).
const FIXED_OVID: [u8; 32] = [0x33; 32];

// ── Scenario enum ─────────────────────────────────────────────────────────

/// Which branch of the observation merge tie-breaking logic a case exercises.
///
/// The four scenarios cover the full decision tree of `merge_observation_rows`:
/// - `General` — unconstrained; both observations independently generated.
/// - `HigherSeenAt` — incoming has a strictly higher `seen_at`.
/// - `LocationTiebreaker` — equal `seen_at`, existing lacks `location_display`,
///   incoming has it.
/// - `ExactTie` — identical `seen_at` and location-display presence; existing
///   row wins (stability).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MergeScenario {
    General,
    HigherSeenAt,
    LocationTiebreaker,
    ExactTie,
}

// ── Raw merge fields ──────────────────────────────────────────────────────

/// Merge-relevant fields that vary between existing and incoming observations.
#[derive(Clone, Debug)]
struct MergeFields {
    run_id: i64,
    shard_id: i64,
    fence_epoch: i64,
    seen_at: i64,
    location_display: Option<String>,
    location_url: Option<String>,
}

/// A single test case for the SQL/Rust merge parity property test.
#[derive(Clone, Debug)]
struct MergeParityCase {
    scenario: MergeScenario,
    existing: ObservationRow,
    incoming: ObservationRow,
}

// ── Strategies ────────────────────────────────────────────────────────────

/// Non-negative `i64` values concentrated at boundaries of the PostgreSQL
/// `BIGINT` domain. Catches off-by-one errors at the Rust ↔ SQL boundary
/// that uniform sampling would almost never hit.
fn arb_nonneg_i64() -> BoxedStrategy<i64> {
    prop_oneof![
        Just(0i64),
        Just(1i64),
        Just(2i64),
        Just(i64::MAX - 1),
        Just(i64::MAX),
        3i64..=4_096i64,
        (i64::MAX / 4)..=(i64::MAX / 2),
        (i64::MAX - 4_096)..=i64::MAX,
    ]
    .boxed()
}

/// Paired `(location_display, location_url)` covering all presence
/// combinations, including the orphan-url edge case that cannot arise
/// through normal `ObservationRecord` projection.
fn arb_location() -> BoxedStrategy<(Option<String>, Option<String>)> {
    prop_oneof![
        3 => Just((None, None)),
        2 => Just((Some("src/alpha.rs:10".to_owned()), None)),
        3 => Just((
            Some("src/beta.rs:20".to_owned()),
            Some("https://example.test/beta".to_owned()),
        )),
        2 => Just((
            Some("lib/gamma.py:30".to_owned()),
            Some("https://example.test/gamma".to_owned()),
        )),
        1 => Just((None, Some("https://example.test/orphan".to_owned()))),
    ]
    .boxed()
}

fn arb_merge_fields() -> BoxedStrategy<MergeFields> {
    (
        any::<i64>(),     // run_id (bit-pattern, any value)
        any::<i64>(),     // shard_id (bit-pattern, any value)
        arb_nonneg_i64(), // fence_epoch
        arb_nonneg_i64(), // seen_at
        arb_location(),
    )
        .prop_map(
            |(run_id, shard_id, fence_epoch, seen_at, (display, url))| MergeFields {
                run_id,
                shard_id,
                fence_epoch,
                seen_at,
                location_display: display,
                location_url: url,
            },
        )
        .boxed()
}

fn build_observation(fields: &MergeFields) -> ObservationRow {
    ObservationRow {
        tenant_id: FIXED_TENANT,
        observation_id: FIXED_OBSERVATION,
        occurrence_id: FIXED_OCCURRENCE,
        policy_hash: FIXED_POLICY,
        ovid_hash: FIXED_OVID,
        run_id: fields.run_id,
        shard_id: fields.shard_id,
        fence_epoch: fields.fence_epoch,
        seen_at: fields.seen_at,
        location_display: fields.location_display.clone(),
        location_url: fields.location_url.clone(),
    }
}

// ── Scenario strategies ───────────────────────────────────────────────────

/// Unconstrained pair: both observations' merge fields are independently
/// generated. Exercises the full merge logic without biasing toward any
/// particular tie-breaking branch.
fn arb_general_case() -> BoxedStrategy<MergeParityCase> {
    (arb_merge_fields(), arb_merge_fields())
        .prop_map(|(existing, incoming)| MergeParityCase {
            scenario: MergeScenario::General,
            existing: build_observation(&existing),
            incoming: build_observation(&incoming),
        })
        .boxed()
}

/// Incoming has a strictly higher `seen_at`, guaranteeing the merge winner
/// is determined by the first tier of the tie-breaking rule.
fn arb_higher_seen_at_case() -> BoxedStrategy<MergeParityCase> {
    (arb_merge_fields(), arb_merge_fields(), 1i64..=1_000i64)
        .prop_map(|(existing_fields, mut incoming_fields, gap)| {
            // Clamp existing.seen_at so the gap doesn't overflow.
            let base = existing_fields.seen_at.min(i64::MAX - gap);
            incoming_fields.seen_at = base + gap;
            let mut existing = build_observation(&existing_fields);
            existing.seen_at = base;
            MergeParityCase {
                scenario: MergeScenario::HigherSeenAt,
                existing,
                incoming: build_observation(&incoming_fields),
            }
        })
        .boxed()
}

/// Equal `seen_at`, existing lacks `location_display`, incoming has it.
/// This isolates the location-based tiebreaker (second tier of the
/// tie-breaking rule).
fn arb_location_tiebreaker_case() -> BoxedStrategy<MergeParityCase> {
    (arb_merge_fields(), arb_merge_fields())
        .prop_map(|(existing_fields, incoming_fields)| {
            let mut existing = build_observation(&existing_fields);
            let mut incoming = build_observation(&incoming_fields);
            incoming.seen_at = existing.seen_at;
            existing.location_display = None;
            existing.location_url = None;
            if incoming.location_display.is_none() {
                incoming.location_display = Some("tiebreaker/path.rs:1".to_owned());
            }
            MergeParityCase {
                scenario: MergeScenario::LocationTiebreaker,
                existing,
                incoming,
            }
        })
        .boxed()
}

/// Equal `seen_at` and the tiebreaker does not fire — existing wins.
/// The tiebreaker requires `existing.location_display IS NULL AND
/// incoming.location_display IS NOT NULL`; this strategy prevents that
/// combination.
fn arb_exact_tie_case() -> BoxedStrategy<MergeParityCase> {
    (arb_merge_fields(), arb_merge_fields())
        .prop_map(|(existing_fields, incoming_fields)| {
            let existing = build_observation(&existing_fields);
            let mut incoming = build_observation(&incoming_fields);
            incoming.seen_at = existing.seen_at;
            // Prevent tiebreaker: if existing lacks display, strip it from
            // incoming too so the tiebreaker condition cannot fire.
            if existing.location_display.is_none() {
                incoming.location_display = None;
                incoming.location_url = None;
            }
            MergeParityCase {
                scenario: MergeScenario::ExactTie,
                existing,
                incoming,
            }
        })
        .boxed()
}

/// Weighted union of all four merge scenarios.
///
/// `General` gets 2x weight because it covers the broadest input space and
/// implicitly exercises all tie-breaking tiers.
fn arb_merge_parity_case() -> BoxedStrategy<MergeParityCase> {
    prop_oneof![
        2 => arb_general_case(),
        1 => arb_higher_seen_at_case(),
        1 => arb_location_tiebreaker_case(),
        1 => arb_exact_tie_case(),
    ]
    .boxed()
}

// ── SQL helpers ───────────────────────────────────────────────────────────

fn prop_failure(context: &str, err: impl std::fmt::Display) -> TestCaseError {
    TestCaseError::fail(format!("{context}: {err}"))
}

/// Insert parent finding and occurrence rows so FK constraints are satisfied.
/// Truncates all tables first.
fn setup_parent_rows(client: &mut Client) {
    client
        .batch_execute(crate::schema::TRUNCATE_ALL_SQL)
        .expect("truncate should succeed");

    client
        .execute(
            &format!(
                "INSERT INTO {FINDINGS_TABLE} \
                 (tenant_id, finding_id, stable_item_id, rule_fingerprint, secret_hash) \
                 VALUES ($1, $2, $3, $4, $5)"
            ),
            &[
                &FIXED_TENANT.as_slice(),
                &FIXED_FINDING.as_slice(),
                &[0xA0u8; 32].as_slice(),
                &[0xA1u8; 32].as_slice(),
                &[0xA2u8; 32].as_slice(),
            ],
        )
        .expect("parent finding should insert");

    client
        .execute(
            &format!(
                "INSERT INTO {OCCURRENCES_TABLE} \
                 (tenant_id, occurrence_id, finding_id, object_version_id, \
                  byte_offset, byte_length) \
                 VALUES ($1, $2, $3, $4, $5, $6)"
            ),
            &[
                &FIXED_TENANT.as_slice(),
                &FIXED_OCCURRENCE.as_slice(),
                &FIXED_FINDING.as_slice(),
                &[0xB0u8; 32].as_slice(),
                &0i64,
                &1i64,
            ],
        )
        .expect("parent occurrence should insert");
}

fn insert_observation_sql(
    client: &mut Client,
    row: &ObservationRow,
) -> Result<(), postgres::Error> {
    let tenant_id = row.tenant_id.as_slice();
    let observation_id = row.observation_id.as_slice();
    let occurrence_id = row.occurrence_id.as_slice();
    let policy_hash = row.policy_hash.as_slice();
    let ovid_hash = row.ovid_hash.as_slice();
    let _ = client.query(
        OBSERVATIONS_INSERT_OR_MERGE_SQL,
        &[
            &tenant_id,
            &observation_id,
            &occurrence_id,
            &policy_hash,
            &ovid_hash,
            &row.run_id,
            &row.shard_id,
            &row.fence_epoch,
            &row.seen_at,
            &row.location_display,
            &row.location_url,
        ],
    )?;
    Ok(())
}

fn read_observation_sql(client: &mut Client) -> Result<ObservationRow, TestCaseError> {
    let row = client
        .query_one(
            &format!(
                "SELECT tenant_id, observation_id, occurrence_id, policy_hash, \
                        ovid_hash, run_id, shard_id, fence_epoch, seen_at, \
                        location_display, location_url \
                 FROM {OBSERVATIONS_TABLE} \
                 WHERE tenant_id = $1 AND observation_id = $2"
            ),
            &[&FIXED_TENANT.as_slice(), &FIXED_OBSERVATION.as_slice()],
        )
        .map_err(|e| prop_failure("read_observation", e))?;

    let to_arr =
        |v: Vec<u8>| -> [u8; 32] { v.try_into().expect("bytea column should be 32 bytes") };

    Ok(ObservationRow {
        tenant_id: to_arr(row.get(0)),
        observation_id: to_arr(row.get(1)),
        occurrence_id: to_arr(row.get(2)),
        policy_hash: to_arr(row.get(3)),
        ovid_hash: to_arr(row.get(4)),
        run_id: row.get(5),
        shard_id: row.get(6),
        fence_epoch: row.get(7),
        seen_at: row.get(8),
        location_display: row.get(9),
        location_url: row.get(10),
    })
}

/// Write `existing` then `incoming` to PostgreSQL and read back the merged row.
///
/// Deletes all observation rows first so the merge is isolated from prior
/// state. The first insert creates the row; the second hits the SQL
/// `ON CONFLICT` path and exercises the merge expression.
fn run_sql_merge_order(
    client: &mut Client,
    existing: &ObservationRow,
    incoming: &ObservationRow,
) -> Result<ObservationRow, TestCaseError> {
    client
        .execute(&format!("DELETE FROM {OBSERVATIONS_TABLE}"), &[])
        .map_err(|e| prop_failure("delete observations", e))?;

    insert_observation_sql(client, existing).map_err(|e| prop_failure("insert existing", e))?;
    insert_observation_sql(client, incoming).map_err(|e| prop_failure("insert incoming", e))?;

    read_observation_sql(client)
}

// ── Parity assertion ──────────────────────────────────────────────────────

/// Assert that every merge-relevant field of two observation rows matches,
/// producing per-field proptest failure messages for diagnostics.
fn assert_observation_fields_match(
    expected: &ObservationRow,
    actual: &ObservationRow,
    context: &str,
) -> Result<(), TestCaseError> {
    prop_assert_eq!(
        actual.run_id,
        expected.run_id,
        "{}: run_id diverged",
        context
    );
    prop_assert_eq!(
        actual.shard_id,
        expected.shard_id,
        "{}: shard_id diverged",
        context
    );
    prop_assert_eq!(
        actual.fence_epoch,
        expected.fence_epoch,
        "{}: fence_epoch diverged",
        context
    );
    prop_assert_eq!(
        actual.seen_at,
        expected.seen_at,
        "{}: seen_at diverged",
        context
    );
    prop_assert_eq!(
        &actual.location_display,
        &expected.location_display,
        "{}: location_display diverged",
        context
    );
    prop_assert_eq!(
        &actual.location_url,
        &expected.location_url,
        "{}: location_url diverged",
        context
    );
    Ok(())
}

/// Compute the expected result via `merge_observation_rows` (Rust), then
/// compare field-by-field against the actual result from [`run_sql_merge_order`]
/// (PostgreSQL). Returns the SQL merge result on success so callers can
/// perform additional assertions without a redundant database round-trip.
fn assert_sql_merge_matches_rust_merge(
    client: &mut Client,
    existing: &ObservationRow,
    incoming: &ObservationRow,
    scenario: MergeScenario,
    order_label: &str,
) -> Result<ObservationRow, TestCaseError> {
    let context = format!("{scenario:?}/{order_label}");
    let expected = merge_observation_rows(existing, incoming).map_err(|e| {
        TestCaseError::fail(format!(
            "{context}: merge_observation_rows failed: tenant={:02x?}.. obs={:02x?}..",
            &e.tenant_id[..4],
            &e.observation_id[..4],
        ))
    })?;
    let actual = run_sql_merge_order(client, existing, incoming)?;
    assert_observation_fields_match(&expected, &actual, &context)?;
    Ok(actual)
}

// ── Main test ─────────────────────────────────────────────────────────────

/// Property test: for randomly generated observation-row pairs, the SQL
/// `ON CONFLICT` merge must produce the same result as the in-memory
/// `merge_observation_rows`. The case count is governed by
/// [`proptest_cases`] (4 locally, 256 in CI, overridable via
/// `PROPTEST_CASES`).
///
/// Each case is tested in *both* write orders (existing→incoming and
/// incoming→existing) because exact ties preserve the first-written row,
/// so commutativity only holds relative to the Rust merge called in the
/// same order.
#[test]
#[ignore = "requires Docker or GOSSIP_POSTGRES_TEST_URL"]
fn sql_on_conflict_merge_matches_rust_merge_proptest() {
    let mut client = test_client();
    setup_parent_rows(&mut client);

    let strategy = arb_merge_parity_case();
    let case_count = proptest_cases(256);
    let mut runner = TestRunner::new(ProptestConfig {
        cases: case_count,
        max_shrink_iters: 256,
        source_file: Some(file!()),
        ..ProptestConfig::default()
    });
    let saw_higher_seen_at = Cell::new(false);
    let saw_location_tiebreaker = Cell::new(false);
    let saw_exact_tie = Cell::new(false);

    let client = RefCell::new(client);

    runner
        .run(&strategy, |case| {
            saw_higher_seen_at
                .set(saw_higher_seen_at.get() || case.scenario == MergeScenario::HigherSeenAt);
            saw_location_tiebreaker.set(
                saw_location_tiebreaker.get() || case.scenario == MergeScenario::LocationTiebreaker,
            );
            saw_exact_tie.set(saw_exact_tie.get() || case.scenario == MergeScenario::ExactTie);

            let mut client = client.borrow_mut();

            // Test existing→incoming write order.
            let sql_existing_first = assert_sql_merge_matches_rust_merge(
                &mut client,
                &case.existing,
                &case.incoming,
                case.scenario,
                "existing_then_incoming",
            )?;

            // Test incoming→existing write order.
            assert_sql_merge_matches_rust_merge(
                &mut client,
                &case.incoming,
                &case.existing,
                case.scenario,
                "incoming_then_existing",
            )?;

            // On exact tie, SQL must preserve the first-written (existing)
            // record's provenance. This checks the contract directly rather
            // than via the Rust merge, catching bugs where both Rust and SQL
            // agree on the *wrong* answer.
            if case.scenario == MergeScenario::ExactTie {
                prop_assert_eq!(
                    sql_existing_first.run_id,
                    case.existing.run_id,
                    "ExactTie: SQL should preserve existing record's run_id"
                );
                prop_assert_eq!(
                    sql_existing_first.shard_id,
                    case.existing.shard_id,
                    "ExactTie: SQL should preserve existing record's shard_id"
                );
                prop_assert_eq!(
                    sql_existing_first.fence_epoch,
                    case.existing.fence_epoch,
                    "ExactTie: SQL should preserve existing record's fence_epoch"
                );
            }

            Ok(())
        })
        .expect("SQL and Rust observation merge parity proptest should pass");

    // Coverage assertions require enough cases to hit every scenario arm.
    if case_count < 100 {
        eprintln!(
            "note: coverage assertions skipped (case_count={case_count} < 100). \
             Set PROPTEST_CASES=256 or run under CI to enable."
        );
    } else {
        assert!(
            saw_higher_seen_at.get(),
            "proptest should cover higher-seen_at provenance winner selection"
        );
        assert!(
            saw_location_tiebreaker.get(),
            "proptest should cover location-display tiebreaker"
        );
        assert!(
            saw_exact_tie.get(),
            "proptest should cover exact-tie stability (existing row wins)"
        );
    }
}
