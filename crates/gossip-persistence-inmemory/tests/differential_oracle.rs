//! Differential oracle: `InMemoryDoneLedger` vs. `DoneLedgerPg`.
//!
//! Both backends receive the same randomized `batch_upsert` sequences. The
//! oracle compares each batch's durable receipt and then compares durable
//! state through `batch_get` for every key written so far — both after each
//! individual batch and once more at the end of the full sequence.

use std::collections::{BTreeMap, HashSet};

use gossip_contracts::identity::{PolicyHash, TenantId};
use gossip_contracts::persistence::{
    CommitHandle, DoneLedger, DoneLedgerKey, DoneLedgerRecord, DoneLedgerStatus, OvidHash,
};
use gossip_contracts::test_util::{done_record, selected_seeds_from_env};
use gossip_done_ledger_postgres::{DoneLedgerPg, schema::DONE_LEDGER_ENTRIES_TABLE};
use gossip_persistence_inmemory::InMemoryDoneLedger;
use postgres::{Client, NoTls};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;

const CASES: usize = if cfg!(miri) { 2 } else { 100 };
const ERROR_CODES: [&str; 3] = ["TEST_RETRY", "TEST_FATAL", "TEST_SKIP"];

fn repro_command(seed: u64) -> String {
    format!(
        "GOSSIP_DONE_DIFF_SEED={seed} cargo test -p gossip-persistence-inmemory \
         done_ledger_pg_matches_in_memory_differential_oracle -- --ignored --exact --nocapture"
    )
}

fn random_status(rng: &mut ChaCha8Rng) -> DoneLedgerStatus {
    let index = rng.random_range(0..DoneLedgerStatus::ALL.len());
    DoneLedgerStatus::ALL[index]
}

fn random_record(rng: &mut ChaCha8Rng) -> DoneLedgerRecord {
    let tenant_seed = rng.random_range(1..=4);
    let policy_seed = rng.random_range(1..=4);
    let ovid_seed = rng.random_range(1..=8);
    let status = random_status(rng);
    let bytes_scanned = rng.random_range(1..=10_000);
    let findings_count = match status {
        DoneLedgerStatus::ScannedWithFindings => rng.random_range(1..=8),
        _ => 0,
    };
    let started_at = rng.random_range(1..=10_000);
    let finished_at = started_at + rng.random_range(0..=250);
    let error_code = match status {
        DoneLedgerStatus::FailedRetryable => Some(ERROR_CODES[0]),
        DoneLedgerStatus::FailedPermanent => Some(ERROR_CODES[1]),
        DoneLedgerStatus::Skipped => Some(ERROR_CODES[2]),
        DoneLedgerStatus::ScannedClean | DoneLedgerStatus::ScannedWithFindings => None,
    };

    done_record(
        tenant_seed,
        policy_seed,
        ovid_seed,
        status,
        bytes_scanned,
        findings_count,
        rng.random_range(1..=4),
        rng.random_range(1..=16),
        rng.random_range(1..=32),
        started_at,
        finished_at,
        error_code,
    )
}

fn generated_batches(seed: u64) -> Vec<Vec<DoneLedgerRecord>> {
    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    let batch_count = rng.random_range(15..=50);

    (0..batch_count)
        .map(|_| {
            let batch_len = rng.random_range(1..=6);
            (0..batch_len).map(|_| random_record(&mut rng)).collect()
        })
        .collect()
}

fn truncate_postgres(admin: &mut Client) {
    admin
        .batch_execute(&format!("TRUNCATE TABLE {DONE_LEDGER_ENTRIES_TABLE}"))
        .expect("done-ledger differential oracle should clear postgres state between seeds");
}

fn group_keys(keys: &HashSet<DoneLedgerKey>) -> BTreeMap<(TenantId, PolicyHash), Vec<OvidHash>> {
    let mut grouped: BTreeMap<(TenantId, PolicyHash), Vec<OvidHash>> = BTreeMap::new();
    for key in keys {
        grouped
            .entry((key.tenant_id(), key.policy_hash()))
            .or_default()
            .push(key.ovid_hash());
    }

    for ovids in grouped.values_mut() {
        ovids.sort_unstable();
    }

    grouped
}

/// Panics with a uniform diagnostic block for any done-ledger oracle failure.
fn panic_done_ledger(seed: u64, step: &str, reason: &str) -> ! {
    panic!(
        "{reason}\n\
         seed={seed}\n\
         step={step}\n\
         reproduce={}",
        repro_command(seed),
    )
}

/// Compares `batch_get` results for every key written so far, asserting that
/// both backends agree on durable state.
fn assert_state_matches(
    seed: u64,
    step: &str,
    written: &HashSet<DoneLedgerKey>,
    in_memory: &InMemoryDoneLedger,
    postgres: &DoneLedgerPg,
) {
    for ((tenant, policy), ovids) in group_keys(written) {
        let in_memory_rows = in_memory
            .batch_get(tenant, policy, &ovids)
            .unwrap_or_else(|err| {
                panic_done_ledger(
                    seed,
                    step,
                    &format!("in-memory batch_get failed for ({tenant:?}, {policy:?}): {err}"),
                )
            });
        let postgres_rows = postgres
            .batch_get(tenant, policy, &ovids)
            .unwrap_or_else(|err| {
                panic_done_ledger(
                    seed,
                    step,
                    &format!("postgres batch_get failed for ({tenant:?}, {policy:?}): {err}"),
                )
            });

        if in_memory_rows != postgres_rows {
            panic_done_ledger(
                seed,
                step,
                &format!(
                    "done-ledger state drift for ({tenant:?}, {policy:?})\n\
                     ovids={ovids:?}\n\
                     in_memory_rows={in_memory_rows:#?}\n\
                     postgres_rows={postgres_rows:#?}"
                ),
            );
        }
    }
}

fn run_sequence(seed: u64, batches: &[Vec<DoneLedgerRecord>], postgres: &DoneLedgerPg) {
    let in_memory = InMemoryDoneLedger::new();
    let mut written = HashSet::new();

    for (step, batch) in batches.iter().enumerate() {
        let step_label = format!("batch {step}");

        let in_memory_receipt = in_memory
            .batch_upsert(batch)
            .unwrap_or_else(|err| {
                panic_done_ledger(
                    seed,
                    &step_label,
                    &format!("in-memory batch_upsert failed: {err}"),
                )
            })
            .wait()
            .unwrap_or_else(|err| {
                panic_done_ledger(seed, &step_label, &format!("in-memory wait failed: {err}"))
            });
        let postgres_receipt = postgres
            .batch_upsert(batch)
            .unwrap_or_else(|err| {
                panic_done_ledger(
                    seed,
                    &step_label,
                    &format!("postgres batch_upsert failed: {err}"),
                )
            })
            .wait()
            .unwrap_or_else(|err| {
                panic_done_ledger(seed, &step_label, &format!("postgres wait failed: {err}"))
            });

        if in_memory_receipt != postgres_receipt {
            panic_done_ledger(
                seed,
                &step_label,
                &format!(
                    "done-ledger receipt drift detected\n\
                     in_memory_receipt={in_memory_receipt:#?}\n\
                     postgres_receipt={postgres_receipt:#?}\n\
                     batch={batch:#?}"
                ),
            );
        }

        written.extend(batch.iter().map(DoneLedgerRecord::key));

        // Verify intermediate durable state after each batch.
        assert_state_matches(seed, &step_label, &written, &in_memory, postgres);
    }

    // Final full-state comparison.
    assert_state_matches(seed, "final", &written, &in_memory, postgres);
}

#[test]
#[ignore]
fn done_ledger_pg_matches_in_memory_differential_oracle() {
    let database_url = gossip_pg_common::test_support::create_test_db();
    let postgres = DoneLedgerPg::connect_and_migrate(&database_url)
        .expect("done-ledger differential oracle should connect and migrate postgres");
    let mut admin = Client::connect(&database_url, NoTls).expect("admin connection should succeed");

    for seed in selected_seeds_from_env("GOSSIP_DONE_DIFF_SEED", "GOSSIP_DONE_DIFF_CASES", CASES) {
        truncate_postgres(&mut admin);
        let batches = generated_batches(seed);
        run_sequence(seed, &batches, &postgres);
    }
}
