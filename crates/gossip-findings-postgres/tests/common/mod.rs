//! Shared live-PostgreSQL integration-test support for findings backend checks.
//!
//! Each test gets an isolated database via `gossip_pg_common::test_support`,
//! backed by either Docker (testcontainers) or an external instance advertised
//! through `GOSSIP_POSTGRES_TEST_URL`.

use std::slice;

use gossip_contracts::{
    connector::{Location, VersionId},
    identity::{
        FenceEpoch, LogicalTime, NormHash, ObjectVersionId, OccurrenceId, PolicyHash,
        RuleFingerprint, RunId, ShardId, StableItemId, TenantId, TenantSecretKey, key_secret_hash,
    },
    persistence::{
        DurableFindingsCounts, FindingRecord, FindingsUpsertBatch, ObservationRecord,
        OccurrenceRecord, OvidHash, OvidHashInputs, derive_ovid_hash,
    },
};
use gossip_findings_postgres::{
    FindingsSinkPg,
    schema::{
        FINDINGS_COUNT_SQL, FINDINGS_TABLE, OBSERVATIONS_COUNT_SQL, OBSERVATIONS_TABLE,
        OCCURRENCES_COUNT_SQL, OCCURRENCES_TABLE,
    },
};
use gossip_pg_common::test_support::create_test_db;
use postgres::{Client, NoTls};

pub struct LivePgHarness {
    backend: FindingsSinkPg,
    inspector: Client,
}

impl LivePgHarness {
    /// Provision a fresh isolated database, apply migrations, and open an
    /// independent inspector connection.
    pub fn new() -> Self {
        let database_url = create_test_db();
        let backend = FindingsSinkPg::connect_and_migrate(&database_url)
            .expect("connect_and_migrate should succeed against test database");
        let inspector = Client::connect(&database_url, NoTls)
            .expect("inspector connection should succeed against test database");

        Self { backend, inspector }
    }

    /// Return the backend under test.
    pub fn backend(&self) -> &FindingsSinkPg {
        &self.backend
    }

    /// Count durable rows through the independent inspector connection.
    pub fn durable_counts(&mut self) -> DurableFindingsCounts {
        DurableFindingsCounts::new(
            self.read_count(FINDINGS_COUNT_SQL, FINDINGS_TABLE),
            self.read_count(OCCURRENCES_COUNT_SQL, OCCURRENCES_TABLE),
            self.read_count(OBSERVATIONS_COUNT_SQL, OBSERVATIONS_TABLE),
        )
    }

    /// Read observation rows for one occurrence in canonical `(policy, id)`
    /// order directly from PostgreSQL.
    pub fn observation_rows_for_occurrence(
        &mut self,
        tenant_id: TenantId,
        occurrence_id: OccurrenceId,
    ) -> Vec<StoredObservationRow> {
        let tenant = tenant_id.as_bytes();
        let occurrence = occurrence_id.as_bytes();
        let rows = self
            .inspector
            .query(
                "SELECT observation_id, policy_hash, location_display, location_url \
                 FROM observations \
                 WHERE tenant_id = $1 AND occurrence_id = $2 \
                 ORDER BY policy_hash ASC, observation_id ASC",
                &[&&tenant[..], &&occurrence[..]],
            )
            .expect("observation lookup should succeed");

        rows.into_iter()
            .map(|row| StoredObservationRow {
                observation_id: row.get::<_, Vec<u8>>(0),
                policy_hash: row.get::<_, Vec<u8>>(1),
                location_display: row.get::<_, Option<String>>(2),
                location_url: row.get::<_, Option<String>>(3),
            })
            .collect()
    }

    /// Return the stored secret-hash bytes for a tenant without going through
    /// the backend implementation.
    pub fn finding_secret_hashes(&mut self, tenant_id: TenantId) -> Vec<Vec<u8>> {
        let tenant = tenant_id.as_bytes();
        self.inspector
            .query(
                "SELECT secret_hash FROM findings WHERE tenant_id = $1 ORDER BY finding_id ASC",
                &[&&tenant[..]],
            )
            .expect("finding secret-hash lookup should succeed")
            .into_iter()
            .map(|row| row.get::<_, Vec<u8>>(0))
            .collect()
    }

    /// Assert that tenant-scoped durable rows contain none of the forbidden
    /// byte sequences or text fragments.
    pub fn assert_no_forbidden_material(
        &mut self,
        tenant_id: TenantId,
        forbidden_byte_values: &[Vec<u8>],
        forbidden_text_fragments: &[&str],
    ) {
        self.assert_findings_rows_clean(tenant_id, forbidden_byte_values);
        self.assert_occurrences_rows_clean(tenant_id, forbidden_byte_values);
        self.assert_observations_rows_clean(
            tenant_id,
            forbidden_byte_values,
            forbidden_text_fragments,
        );
    }

    fn read_count(&mut self, sql: &str, table: &'static str) -> u64 {
        let row = self
            .inspector
            .query_one(sql, &[])
            .unwrap_or_else(|err| panic!("count query for {table} should succeed: {err}"));
        let value: i64 = row.get(0);
        assert!(
            value >= 0,
            "count for {table} must be non-negative, got {value}"
        );
        value as u64
    }

    fn assert_findings_rows_clean(
        &mut self,
        tenant_id: TenantId,
        forbidden_byte_values: &[Vec<u8>],
    ) {
        let tenant = tenant_id.as_bytes();
        let rows = self
            .inspector
            .query(
                "SELECT tenant_id, finding_id, stable_item_id, rule_fingerprint, secret_hash \
                 FROM findings WHERE tenant_id = $1",
                &[&&tenant[..]],
            )
            .expect("findings row scan should succeed");

        for row in rows {
            assert_no_forbidden_bytes(
                "findings",
                "tenant_id",
                &row.get::<_, Vec<u8>>(0),
                forbidden_byte_values,
            );
            assert_no_forbidden_bytes(
                "findings",
                "finding_id",
                &row.get::<_, Vec<u8>>(1),
                forbidden_byte_values,
            );
            assert_no_forbidden_bytes(
                "findings",
                "stable_item_id",
                &row.get::<_, Vec<u8>>(2),
                forbidden_byte_values,
            );
            assert_no_forbidden_bytes(
                "findings",
                "rule_fingerprint",
                &row.get::<_, Vec<u8>>(3),
                forbidden_byte_values,
            );
            assert_no_forbidden_bytes(
                "findings",
                "secret_hash",
                &row.get::<_, Vec<u8>>(4),
                forbidden_byte_values,
            );
        }
    }

    fn assert_occurrences_rows_clean(
        &mut self,
        tenant_id: TenantId,
        forbidden_byte_values: &[Vec<u8>],
    ) {
        let tenant = tenant_id.as_bytes();
        let rows = self
            .inspector
            .query(
                "SELECT tenant_id, occurrence_id, finding_id, object_version_id \
                 FROM occurrences WHERE tenant_id = $1",
                &[&&tenant[..]],
            )
            .expect("occurrences row scan should succeed");

        for row in rows {
            assert_no_forbidden_bytes(
                "occurrences",
                "tenant_id",
                &row.get::<_, Vec<u8>>(0),
                forbidden_byte_values,
            );
            assert_no_forbidden_bytes(
                "occurrences",
                "occurrence_id",
                &row.get::<_, Vec<u8>>(1),
                forbidden_byte_values,
            );
            assert_no_forbidden_bytes(
                "occurrences",
                "finding_id",
                &row.get::<_, Vec<u8>>(2),
                forbidden_byte_values,
            );
            assert_no_forbidden_bytes(
                "occurrences",
                "object_version_id",
                &row.get::<_, Vec<u8>>(3),
                forbidden_byte_values,
            );
        }
    }

    fn assert_observations_rows_clean(
        &mut self,
        tenant_id: TenantId,
        forbidden_byte_values: &[Vec<u8>],
        forbidden_text_fragments: &[&str],
    ) {
        let tenant = tenant_id.as_bytes();
        let rows = self
            .inspector
            .query(
                "SELECT tenant_id, observation_id, occurrence_id, policy_hash, ovid_hash, \
                        location_display, location_url \
                 FROM observations WHERE tenant_id = $1",
                &[&&tenant[..]],
            )
            .expect("observations row scan should succeed");

        for row in rows {
            assert_no_forbidden_bytes(
                "observations",
                "tenant_id",
                &row.get::<_, Vec<u8>>(0),
                forbidden_byte_values,
            );
            assert_no_forbidden_bytes(
                "observations",
                "observation_id",
                &row.get::<_, Vec<u8>>(1),
                forbidden_byte_values,
            );
            assert_no_forbidden_bytes(
                "observations",
                "occurrence_id",
                &row.get::<_, Vec<u8>>(2),
                forbidden_byte_values,
            );
            assert_no_forbidden_bytes(
                "observations",
                "policy_hash",
                &row.get::<_, Vec<u8>>(3),
                forbidden_byte_values,
            );
            assert_no_forbidden_bytes(
                "observations",
                "ovid_hash",
                &row.get::<_, Vec<u8>>(4),
                forbidden_byte_values,
            );

            if let Some(location_display) = row.get::<_, Option<String>>(5).as_deref() {
                assert_no_forbidden_text(
                    "observations.location_display",
                    location_display,
                    forbidden_text_fragments,
                );
            }
            if let Some(location_url) = row.get::<_, Option<String>>(6).as_deref() {
                assert_no_forbidden_text(
                    "observations.location_url",
                    location_url,
                    forbidden_text_fragments,
                );
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// Raw observation projection used by integration tests to inspect stored rows.
pub struct StoredObservationRow {
    pub observation_id: Vec<u8>,
    pub policy_hash: Vec<u8>,
    pub location_display: Option<String>,
    pub location_url: Option<String>,
}

#[derive(Clone, Debug)]
/// Deterministic, referentially-complete findings fixture for live integration
/// tests.
pub struct FindingsFixture {
    pub tenant_id: TenantId,
    pub tenant_secret_key: TenantSecretKey,
    pub norm_hash: NormHash,
    pub raw_secret: Vec<u8>,
    pub unsafe_context: String,
    pub safe_location_display: String,
    pub safe_location_url: String,
    pub ovid_hash: OvidHash,
    pub finding: FindingRecord,
    pub occurrence: OccurrenceRecord,
    pub observation: ObservationRecord,
}

impl FindingsFixture {
    /// Build a single-record findings batch spanning all three persistence
    /// layers.
    pub fn batch(&self) -> FindingsUpsertBatch<'_> {
        FindingsUpsertBatch::new(
            slice::from_ref(&self.finding),
            slice::from_ref(&self.occurrence),
            slice::from_ref(&self.observation),
        )
    }

    /// Build another observation for the same occurrence under a different
    /// policy and provenance tuple.
    pub fn observation_for_policy(
        &self,
        policy_fill: u8,
        run_id: u64,
        shard_id: u64,
        fence_epoch: u64,
        seen_at: u64,
    ) -> ObservationRecord {
        ObservationRecord::new(
            self.tenant_id,
            self.occurrence.occurrence_id(),
            policy(policy_fill),
            self.ovid_hash,
            RunId::from_raw(run_id),
            ShardId::from_raw(shard_id),
            FenceEpoch::from_raw(fence_epoch),
            LogicalTime::from_raw(seen_at),
        )
        .with_location(
            Location::try_new(
                self.safe_location_display.clone(),
                Some(self.safe_location_url.clone()),
            )
            .expect("fixture location should be valid"),
        )
    }
}

/// Derive a deterministic findings fixture from a single-byte seed.
pub fn sample_fixture(seed: u8) -> FindingsFixture {
    debug_assert!(seed <= 0xF0, "seed too high; wrapping offsets may collide");

    let tenant_id = tenant(seed);
    let stable_item_id = stable_item(seed.wrapping_add(1));
    let rule_fingerprint = rule(seed.wrapping_add(2));
    let tenant_secret_key = tenant_secret_key(seed.wrapping_add(3));

    let raw_secret_string =
        format!("SUPER-SECRET-TOKEN-{seed:02X}-DO-NOT-PERSIST-IN-FINDINGS-POSTGRES");
    let raw_secret = raw_secret_string.as_bytes().to_vec();
    let unsafe_context =
        format!("UNSAFE-CONTEXT::tenant={seed:02X}::secret={raw_secret_string}::END");
    let norm_hash = NormHash::from_digest(*blake3::hash(&raw_secret).as_bytes());
    let secret_hash = key_secret_hash(&tenant_secret_key, &norm_hash);

    let finding = FindingRecord::new(tenant_id, stable_item_id, rule_fingerprint, secret_hash);
    let object_version_id =
        ObjectVersionId::from_version_bytes(format!("findings-pg-version-{seed}").as_bytes());
    let occurrence = OccurrenceRecord::try_new(
        tenant_id,
        finding.finding_id(),
        object_version_id,
        1_000 + u64::from(seed),
        32,
    )
    .expect("fixture byte_length is non-zero");

    let ovid_hash = derive_ovid_hash(&OvidHashInputs {
        stable_item_id,
        version: VersionId::Strong(object_version_id),
    });

    let safe_location_display = format!("safe/path/findings-{seed:02X}.txt");
    let safe_location_url = format!("https://example.invalid/findings/{seed:02X}");
    let location = Location::try_new(
        safe_location_display.clone(),
        Some(safe_location_url.clone()),
    )
    .expect("fixture location should be valid");

    let observation = ObservationRecord::new(
        tenant_id,
        occurrence.occurrence_id(),
        policy(seed.wrapping_add(4)),
        ovid_hash,
        RunId::from_raw(10_000 + u64::from(seed)),
        ShardId::from_raw(20_000 + u64::from(seed)),
        FenceEpoch::from_raw(30_000 + u64::from(seed)),
        LogicalTime::from_raw(40_000 + u64::from(seed)),
    )
    .with_location(location);

    FindingsFixture {
        tenant_id,
        tenant_secret_key,
        norm_hash,
        raw_secret,
        unsafe_context,
        safe_location_display,
        safe_location_url,
        ovid_hash,
        finding,
        occurrence,
        observation,
    }
}

pub fn tenant(fill: u8) -> TenantId {
    TenantId::from_bytes([fill; 32])
}

pub fn policy(fill: u8) -> PolicyHash {
    PolicyHash::from_bytes([fill; 32])
}

pub fn stable_item(fill: u8) -> StableItemId {
    StableItemId::from_bytes([fill; 32])
}

pub fn rule(fill: u8) -> RuleFingerprint {
    RuleFingerprint::from_bytes([fill; 32])
}

pub fn tenant_secret_key(fill: u8) -> TenantSecretKey {
    TenantSecretKey::from_bytes([fill; 32])
}

fn assert_no_forbidden_bytes(
    table: &'static str,
    column: &'static str,
    actual: &[u8],
    forbidden_values: &[Vec<u8>],
) {
    for forbidden in forbidden_values {
        if forbidden.is_empty() {
            continue;
        }
        let matched = actual
            .windows(forbidden.len())
            .any(|window| window == forbidden.as_slice());
        assert!(
            !matched,
            "{table}.{column} contains forbidden byte sequence \
             (forbidden[..{}]={:02x?}, actual[..{}]={:02x?})",
            forbidden.len().min(8),
            &forbidden[..forbidden.len().min(8)],
            actual.len().min(16),
            &actual[..actual.len().min(16)],
        );
    }
}

fn assert_no_forbidden_text(column: &'static str, actual: &str, forbidden_fragments: &[&str]) {
    for forbidden in forbidden_fragments {
        if forbidden.is_empty() {
            continue;
        }
        assert!(
            !actual.contains(forbidden),
            "{column} leaked forbidden text fragment: {forbidden:?}"
        );
    }
}
