//! Identity enrichment benchmarks.
//!
//! Three benchmark groups:
//! 1. **identity_parse** — `parse_author_identity` on synthetic commit objects
//! 2. **identity_intern** — intern N unique strings, measure throughput
//! 3. **build_with_identities_overhead** — `CommitGraphMem::build_with_identities`
//!    vs `CommitGraphMem::build` to measure the marginal identity overhead
//!
//! Usage:
//! `cargo bench --bench identity_enrichment`

use criterion::{
    black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput,
};
use scanner_git::identity_intern::{CommitIdentityIds, IdentityInterner};
use scanner_git::identity_parse::parse_author_identity;
use scanner_git::{CommitGraphMem, LoadedCommit, ObjectFormat, OidBytes};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_commit_bytes(name: &[u8], email: &[u8], ts: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);
    buf.extend_from_slice(b"tree ");
    buf.extend_from_slice(&[b'a'; 40]);
    buf.push(b'\n');
    buf.extend_from_slice(b"parent ");
    buf.extend_from_slice(&[b'b'; 40]);
    buf.push(b'\n');
    buf.extend_from_slice(b"author ");
    buf.extend_from_slice(name);
    buf.extend_from_slice(b" <");
    buf.extend_from_slice(email);
    buf.extend_from_slice(b"> ");
    buf.extend_from_slice(ts.to_string().as_bytes());
    buf.extend_from_slice(b" +0000\n");
    buf.extend_from_slice(b"committer ");
    buf.extend_from_slice(name);
    buf.extend_from_slice(b" <");
    buf.extend_from_slice(email);
    buf.extend_from_slice(b"> ");
    buf.extend_from_slice(ts.to_string().as_bytes());
    buf.extend_from_slice(b" +0000\n");
    buf.push(b'\n');
    buf.extend_from_slice(b"commit message\n");
    buf
}

fn oid_from_u64(value: u64) -> OidBytes {
    let mut bytes = [0u8; 20];
    bytes[..8].copy_from_slice(&value.to_be_bytes());
    OidBytes::sha1(bytes)
}

fn make_loaded_commit(id: u64, parents: &[u64]) -> LoadedCommit {
    LoadedCommit {
        oid: oid_from_u64(id),
        tree_oid: oid_from_u64(id ^ 0xAA55_AA55_AA55_AA55),
        parents: parents.iter().map(|p| oid_from_u64(*p)).collect(),
        timestamp: id,
    }
}

// ---------------------------------------------------------------------------
// Group 1: identity_parse
// ---------------------------------------------------------------------------

fn bench_identity_parse(c: &mut Criterion) {
    let mut group = c.benchmark_group("identity_parse");

    // Typical commit object (short name + email)
    let typical = make_commit_bytes(
        b"Linus Torvalds",
        b"torvalds@linux-foundation.org",
        1700000000,
    );
    group.throughput(Throughput::Bytes(typical.len() as u64));
    group.bench_function("typical_commit", |b| {
        b.iter(|| black_box(parse_author_identity(black_box(&typical))))
    });

    // Long name + email (stress the linear scan)
    let long_name = vec![b'X'; 200];
    let long_email = vec![b'y'; 100];
    let long = make_commit_bytes(&long_name, &long_email, 1700000000);
    group.throughput(Throughput::Bytes(long.len() as u64));
    group.bench_function("long_identity", |b| {
        b.iter(|| black_box(parse_author_identity(black_box(&long))))
    });

    // Empty name + email (edge case)
    let empty = make_commit_bytes(b"", b"", 1700000000);
    group.bench_function("empty_identity", |b| {
        b.iter(|| black_box(parse_author_identity(black_box(&empty))))
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Group 2: identity_intern
// ---------------------------------------------------------------------------

fn bench_identity_intern(c: &mut Criterion) {
    let mut group = c.benchmark_group("identity_intern");

    for &count in &[100, 1_000, 10_000] {
        // Pre-generate unique strings.
        let strings: Vec<Vec<u8>> = (0..count)
            .map(|i| format!("user-{i:06}@example.com").into_bytes())
            .collect();
        let total_bytes: u64 = strings.iter().map(|s| s.len() as u64).sum();

        group.throughput(Throughput::Elements(count));
        group.bench_with_input(
            BenchmarkId::new("intern_unique", count),
            &strings,
            |b, strings| {
                b.iter_batched(
                    || IdentityInterner::with_capacity(total_bytes as u32 + 4096, count as usize),
                    |mut interner| {
                        for s in strings {
                            black_box(interner.intern(s));
                        }
                    },
                    BatchSize::SmallInput,
                );
            },
        );

        // Dedup benchmark: intern same N strings twice (second pass is all hits).
        group.bench_with_input(
            BenchmarkId::new("intern_dedup", count),
            &strings,
            |b, strings| {
                b.iter_batched(
                    || {
                        let mut interner = IdentityInterner::with_capacity(
                            total_bytes as u32 + 4096,
                            count as usize,
                        );
                        for s in strings {
                            interner.intern(s);
                        }
                        interner
                    },
                    |mut interner| {
                        for s in strings {
                            black_box(interner.intern(s));
                        }
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Group 3: build_with_identities overhead
// ---------------------------------------------------------------------------

fn bench_build_with_identities(c: &mut Criterion) {
    let mut group = c.benchmark_group("commit_graph_identity_overhead");

    for &count in &[100, 1_000, 10_000] {
        // Build a linear chain: commit[i] -> commit[i-1].
        let commits: Vec<LoadedCommit> = (0..count)
            .map(|i| {
                if i == 0 {
                    make_loaded_commit(i, &[])
                } else {
                    make_loaded_commit(i, &[i - 1])
                }
            })
            .collect();

        let identity_ids: Vec<CommitIdentityIds> = (0..count)
            .map(|i| CommitIdentityIds {
                author_name: i as u32,
                author_email: i as u32 + 1,
                committer_name: i as u32 + 2,
                committer_email: i as u32 + 3,
            })
            .collect();

        group.throughput(Throughput::Elements(count));

        group.bench_with_input(
            BenchmarkId::new("build_without_identities", count),
            &commits,
            |b, commits| {
                b.iter_batched(
                    || commits.clone(),
                    |commits| {
                        black_box(CommitGraphMem::build(commits, ObjectFormat::Sha1).unwrap());
                    },
                    BatchSize::SmallInput,
                );
            },
        );

        group.bench_with_input(
            BenchmarkId::new("build_with_identities", count),
            &(commits, identity_ids),
            |b, (commits, identity_ids)| {
                b.iter_batched(
                    || (commits.clone(), identity_ids.clone()),
                    |(commits, ids)| {
                        black_box(
                            CommitGraphMem::build_with_identities(commits, ids, ObjectFormat::Sha1)
                                .unwrap(),
                        );
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_identity_parse,
    bench_identity_intern,
    bench_build_with_identities,
);
criterion_main!(benches);
