//! Benchmarks for identity-derivation primitives in `gossip_contracts::identity`.
//!
//! Measures the latency of cryptographic and hashing operations on the hot path
//! for deriving stable identifiers across the gossip data model.
//!
//! # Invariants
//! * Uses deterministic, synthetic inputs to eliminate setup noise (e.g., RNG, I/O).
//! * Measures pure computational overhead of ID derivation paths.
//!
//! # Design
//! Includes isolated microbenchmarks for leaf operations (e.g., `key_secret_hash`)
//! and a `full_derivation_chain` benchmark to reflect realistic composition costs
//! such as allocations and cascaded hashing.

use criterion::{Criterion, black_box, criterion_group, criterion_main};

use gossip_contracts::identity::{
    ConnectorInstanceIdHash, ConnectorTag, FindingId, FindingIdInputs, IdHashMode, ItemIdentityKey,
    NormHash, ObjectVersionId, ObservationIdInputs, OccurrenceId, OccurrenceIdInputs, PolicyHash,
    PolicyHashInputs, RuleFingerprint, StableItemId, TenantId, TenantSecretKey,
    compute_policy_hash, derive_finding_id, derive_observation_id, derive_occurrence_id,
    key_secret_hash,
};

/// Benchmarks keyed normalization hash for tenant-scoped secrets.
fn bench_key_secret_hash(c: &mut Criterion) {
    let key = TenantSecretKey::from_bytes([0xBB; 32]);
    let norm = NormHash::from_digest([0xCC; 32]);

    c.bench_function("key_secret_hash", |b| {
        b.iter(|| key_secret_hash(black_box(&key), black_box(&norm)))
    });
}

/// Benchmarks finding ID derivation with pre-normalized secret inputs.
fn bench_derive_finding_id(c: &mut Criterion) {
    let tenant_key = TenantSecretKey::from_bytes([0xBB; 32]);
    let norm = NormHash::from_digest([0xCC; 32]);
    let secret = key_secret_hash(&tenant_key, &norm);

    let inputs = FindingIdInputs {
        tenant: TenantId::from_bytes([0x11; 32]),
        item: StableItemId::from_bytes([0x22; 32]),
        rule: RuleFingerprint::from_bytes([0x33; 32]),
        secret,
    };

    c.bench_function("derive_finding_id", |b| {
        b.iter(|| derive_finding_id(black_box(&inputs)))
    });
}

/// Benchmarks occurrence ID derivation for a specific byte range in an object.
fn bench_derive_occurrence_id(c: &mut Criterion) {
    let inputs = OccurrenceIdInputs {
        finding: FindingId::from_bytes([0x55; 32]),
        version: ObjectVersionId::from_bytes([0x66; 32]),
        byte_offset: 1024,
        byte_length: 42,
    };

    c.bench_function("derive_occurrence_id", |b| {
        b.iter(|| derive_occurrence_id(black_box(&inputs)))
    });
}

/// Benchmarks observation ID derivation.
fn bench_derive_observation_id(c: &mut Criterion) {
    let inputs = ObservationIdInputs {
        tenant: TenantId::from_bytes([0x77; 32]),
        policy: PolicyHash::from_bytes([0x88; 32]),
        occurrence: OccurrenceId::from_bytes([0x99; 32]),
    };
    c.bench_function("derive_observation_id", |b| {
        b.iter(|| derive_observation_id(black_box(&inputs)))
    });
}

/// Benchmarks policy hash computation for V1 keyed hashing.
fn bench_compute_policy_hash(c: &mut Criterion) {
    let inputs = PolicyHashInputs {
        policy_hash_version: 1,
        id_hash_mode: IdHashMode::KeyedV1,
        evidence_hash_version: 1,
        rules_digest: [0xAA; 32],
    };

    c.bench_function("compute_policy_hash", |b| {
        b.iter(|| compute_policy_hash(black_box(&inputs)))
    });
}

/// Benchmarks stable item ID derivation.
fn bench_item_key_stable_id(c: &mut Criterion) {
    let key = ItemIdentityKey::new(
        ConnectorTag::from_ascii(b"github"),
        ConnectorInstanceIdHash::from_instance_id_bytes(b"github-installation-1"),
        b"org/repo\0src/main.rs",
    );

    c.bench_function("item_key_stable_id", |b| {
        b.iter(|| black_box(&key).stable_id())
    });
}

/// Benchmarks the end-to-end derivation chain from item key to occurrence ID.
fn bench_full_derivation_chain(c: &mut Criterion) {
    let connector = ConnectorTag::from_ascii(b"github");
    let connector_instance =
        ConnectorInstanceIdHash::from_instance_id_bytes(b"github-installation-1");
    let path = b"org/repo\0src/main.rs".to_vec();
    let tenant_key = TenantSecretKey::from_bytes([0xBB; 32]);
    let norm = NormHash::from_digest([0xCC; 32]);
    let tenant = TenantId::from_bytes([0x11; 32]);
    let rule = RuleFingerprint::from_bytes([0x33; 32]);
    let version = ObjectVersionId::from_bytes([0x66; 32]);

    c.bench_function("full_derivation_chain", |b| {
        b.iter(|| {
            // Rebuild the owned path to include the allocation and copy overhead
            // a caller pays when assembling a fresh identity key in the hot path.
            let key = ItemIdentityKey::new(connector, connector_instance, path.clone());
            let stable_id = key.stable_id();
            let secret = key_secret_hash(&tenant_key, &norm);
            let finding = derive_finding_id(&FindingIdInputs {
                tenant,
                item: stable_id,
                rule,
                secret,
            });
            derive_occurrence_id(black_box(&OccurrenceIdInputs {
                finding,
                version,
                byte_offset: 1024,
                byte_length: 42,
            }))
        })
    });
}

criterion_group!(
    benches,
    bench_key_secret_hash,
    bench_derive_finding_id,
    bench_derive_occurrence_id,
    bench_derive_observation_id,
    bench_compute_policy_hash,
    bench_item_key_stable_id,
    bench_full_derivation_chain,
);
criterion_main!(benches);
