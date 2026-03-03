use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use gossip_stdx::{DynamicBitSet, FixedSet128};

const SET_CAP_POW2: usize = 1 << 14; // 16384 slots
const FIXED_SET_LOAD: usize = (SET_CAP_POW2 * 3) / 4; // 75% load
const BITSET_BITS: usize = 1 << 16; // 65536 bits
const BITSET_TOGGLES: usize = 1 << 12; // 4096 toggles

// DynamicBitSet benchmark constants
const DEFAULT_BITS: usize = 65536; // 64K bits
const DEFAULT_OPS: usize = 4096; // 4K operations
const DENSITY_SPARSE: f64 = 0.01; // 1%
const DENSITY_MODERATE: f64 = 0.25; // 25%
const DENSITY_DENSE: f64 = 0.75; // 75%
const BOUNDARY_SIZES: [usize; 6] = [63, 64, 65, 127, 128, 129];
const SCALE_SIZES: [usize; 8] = [64, 128, 1024, 4096, 65536, 262144, 1048576, 4194304];

struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    fn next_u128(&mut self) -> u128 {
        let hi = self.next_u64() as u128;
        let lo = self.next_u64() as u128;
        (hi << 64) | lo
    }
}

fn make_u128_keys(count: usize, seed: u64) -> Vec<u128> {
    let mut rng = XorShift64::new(seed);
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(rng.next_u128());
    }
    out
}

fn make_bit_indices(count: usize, bit_len: usize, seed: u64) -> Vec<usize> {
    let mut rng = XorShift64::new(seed);
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push((rng.next_u64() as usize) % bit_len);
    }
    out
}

/// Creates a bitset with a specific density of set bits
fn make_bitset_with_density(bit_len: usize, density: f64, seed: u64) -> DynamicBitSet {
    let mut bits = DynamicBitSet::empty(bit_len);
    let set_count = (bit_len as f64 * density) as usize;
    let indices = make_bit_indices(set_count * 2, bit_len, seed); // over-generate to account for duplicates
    let mut count = 0;
    for &idx in &indices {
        if !bits.is_set(idx) {
            bits.set(idx);
            count += 1;
            if count >= set_count {
                break;
            }
        }
    }
    bits
}

/// Creates sequential indices for access pattern testing
fn make_sequential_indices(count: usize, bit_len: usize) -> Vec<usize> {
    (0..count).map(|i| i % bit_len).collect()
}

fn bench_fixed_set128(c: &mut Criterion) {
    let keys = make_u128_keys(FIXED_SET_LOAD, 0x1234_5678_9abc_def0);
    let mut set = FixedSet128::with_pow2(SET_CAP_POW2);

    let mut group = c.benchmark_group("fixed_set128");
    group.throughput(Throughput::Elements(keys.len() as u64));
    group.bench_function("insert_reset", |b| {
        b.iter(|| {
            set.reset();
            for &k in &keys {
                black_box(set.insert(k));
            }
        })
    });
    group.finish();
}

fn bench_dynamic_bitset(c: &mut Criterion) {
    let indices = make_bit_indices(BITSET_TOGGLES, BITSET_BITS, 0xfeed_face_cafe_beef);
    let mut bits = DynamicBitSet::empty(BITSET_BITS);

    let mut group = c.benchmark_group("dynamic_bitset");
    group.throughput(Throughput::Elements(indices.len() as u64));
    group.bench_function("set_count_clear", |b| {
        b.iter(|| {
            bits.clear();
            for &idx in &indices {
                bits.set(idx);
            }
            let count = bits.count();
            black_box(count);
        })
    });
    group.finish();
}

/// Benchmarks set() operation with different access patterns
fn bench_bitset_set(c: &mut Criterion) {
    let random_indices = make_bit_indices(DEFAULT_OPS, DEFAULT_BITS, 0xdead_beef_1234_5678);
    let sequential_indices = make_sequential_indices(DEFAULT_OPS, DEFAULT_BITS);

    let mut group = c.benchmark_group("bitset_set");
    group.throughput(Throughput::Elements(DEFAULT_OPS as u64));

    group.bench_function("random", |b| {
        let mut bits = DynamicBitSet::empty(DEFAULT_BITS);
        b.iter(|| {
            bits.clear();
            for &idx in &random_indices {
                bits.set(idx);
            }
            black_box(&bits);
        })
    });

    group.bench_function("sequential", |b| {
        let mut bits = DynamicBitSet::empty(DEFAULT_BITS);
        b.iter(|| {
            bits.clear();
            for &idx in &sequential_indices {
                bits.set(idx);
            }
            black_box(&bits);
        })
    });

    group.finish();
}

/// Benchmarks is_set() query performance
fn bench_bitset_is_set(c: &mut Criterion) {
    let bits_moderate =
        make_bitset_with_density(DEFAULT_BITS, DENSITY_MODERATE, 0xaaaa_bbbb_cccc_dddd);
    let random_indices = make_bit_indices(DEFAULT_OPS, DEFAULT_BITS, 0x1111_2222_3333_4444);

    // Create indices that are guaranteed hits (all set bits)
    let all_hits: Vec<usize> = bits_moderate.iter_set().take(DEFAULT_OPS).collect();

    let mut group = c.benchmark_group("bitset_is_set");
    group.throughput(Throughput::Elements(DEFAULT_OPS as u64));

    group.bench_function("random_mixed", |b| {
        b.iter(|| {
            let mut count = 0usize;
            for &idx in &random_indices {
                if bits_moderate.is_set(idx) {
                    count += 1;
                }
            }
            black_box(count)
        })
    });

    group.bench_function("all_hits", |b| {
        b.iter(|| {
            let mut count = 0usize;
            for &idx in &all_hits {
                if bits_moderate.is_set(idx) {
                    count += 1;
                }
            }
            black_box(count)
        })
    });

    group.finish();
}

/// Benchmarks count() across different bit densities
fn bench_bitset_count(c: &mut Criterion) {
    let bits_empty = DynamicBitSet::empty(DEFAULT_BITS);
    let bits_sparse = make_bitset_with_density(DEFAULT_BITS, DENSITY_SPARSE, 0x1234);
    let bits_moderate = make_bitset_with_density(DEFAULT_BITS, DENSITY_MODERATE, 0x5678);
    let bits_dense = make_bitset_with_density(DEFAULT_BITS, DENSITY_DENSE, 0x9abc);

    // Full bitset
    let mut bits_full = DynamicBitSet::empty(DEFAULT_BITS);
    for i in 0..DEFAULT_BITS {
        bits_full.set(i);
    }

    let mut group = c.benchmark_group("bitset_count");
    group.throughput(Throughput::Elements(DEFAULT_BITS as u64));

    group.bench_function("empty", |b| b.iter(|| black_box(bits_empty.count())));

    group.bench_function("sparse_1pct", |b| b.iter(|| black_box(bits_sparse.count())));

    group.bench_function("moderate_25pct", |b| {
        b.iter(|| black_box(bits_moderate.count()))
    });

    group.bench_function("dense_75pct", |b| b.iter(|| black_box(bits_dense.count())));

    group.bench_function("full", |b| b.iter(|| black_box(bits_full.count())));

    group.finish();
}

/// Benchmarks iter_set() iteration across different densities
fn bench_bitset_iter(c: &mut Criterion) {
    let bits_sparse = make_bitset_with_density(DEFAULT_BITS, DENSITY_SPARSE, 0xaaaa);
    let bits_moderate = make_bitset_with_density(DEFAULT_BITS, DENSITY_MODERATE, 0xbbbb);
    let bits_dense = make_bitset_with_density(DEFAULT_BITS, DENSITY_DENSE, 0xcccc);

    let mut bits_full = DynamicBitSet::empty(DEFAULT_BITS);
    for i in 0..DEFAULT_BITS {
        bits_full.set(i);
    }

    let mut group = c.benchmark_group("bitset_iter");

    // Throughput is number of bits yielded, not total bits
    let sparse_count = bits_sparse.count();
    group.throughput(Throughput::Elements(sparse_count as u64));
    group.bench_function("sparse_1pct", |b| {
        b.iter(|| {
            let mut sum = 0usize;
            for idx in bits_sparse.iter_set() {
                sum += idx;
            }
            black_box(sum)
        })
    });

    let moderate_count = bits_moderate.count();
    group.throughput(Throughput::Elements(moderate_count as u64));
    group.bench_function("moderate_25pct", |b| {
        b.iter(|| {
            let mut sum = 0usize;
            for idx in bits_moderate.iter_set() {
                sum += idx;
            }
            black_box(sum)
        })
    });

    let dense_count = bits_dense.count();
    group.throughput(Throughput::Elements(dense_count as u64));
    group.bench_function("dense_75pct", |b| {
        b.iter(|| {
            let mut sum = 0usize;
            for idx in bits_dense.iter_set() {
                sum += idx;
            }
            black_box(sum)
        })
    });

    group.throughput(Throughput::Elements(DEFAULT_BITS as u64));
    group.bench_function("full", |b| {
        b.iter(|| {
            let mut sum = 0usize;
            for idx in bits_full.iter_set() {
                sum += idx;
            }
            black_box(sum)
        })
    });

    group.finish();
}

/// Benchmarks count() scaling with bitset size (should be O(n))
fn bench_bitset_scale_count(c: &mut Criterion) {
    let mut group = c.benchmark_group("bitset_scale_count");

    for &size in &SCALE_SIZES {
        let bits = make_bitset_with_density(size, DENSITY_MODERATE, 0xface_b00c);
        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &bits, |b, bits| {
            b.iter(|| black_box(bits.count()))
        });
    }

    group.finish();
}

/// Benchmarks clear() scaling with bitset size (should be O(n))
fn bench_bitset_scale_clear(c: &mut Criterion) {
    let mut group = c.benchmark_group("bitset_scale_clear");

    for &size in &SCALE_SIZES {
        let mut bits = make_bitset_with_density(size, DENSITY_MODERATE, 0xcafe_d00d);
        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter(|| {
                bits.clear();
                black_box(&bits);
            })
        });
    }

    group.finish();
}

/// Benchmarks operations at word boundaries to test masking overhead
fn bench_bitset_boundaries(c: &mut Criterion) {
    let mut group = c.benchmark_group("bitset_boundaries");

    for &size in &BOUNDARY_SIZES {
        let mut bits = DynamicBitSet::empty(size);
        // Set alternating bits to create work
        for i in (0..size).step_by(2) {
            bits.set(i);
        }

        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(BenchmarkId::new("count", size), &bits, |b, bits| {
            b.iter(|| black_box(bits.count()))
        });

        group.bench_with_input(BenchmarkId::new("iter", size), &bits, |b, bits| {
            b.iter(|| {
                let mut sum = 0usize;
                for idx in bits.iter_set() {
                    sum += idx;
                }
                black_box(sum)
            })
        });
    }

    group.finish();
}

/// Benchmarks common pattern: populate bitset then count
fn bench_bitset_populate_then_count(c: &mut Criterion) {
    let indices = make_bit_indices(DEFAULT_OPS, DEFAULT_BITS, 0x1234_5678_9abc_def0);

    let mut group = c.benchmark_group("bitset_workflow");
    group.throughput(Throughput::Elements(DEFAULT_OPS as u64));

    group.bench_function("populate_then_count", |b| {
        let mut bits = DynamicBitSet::empty(DEFAULT_BITS);
        b.iter(|| {
            bits.clear();
            for &idx in &indices {
                bits.set(idx);
            }
            black_box(bits.count())
        })
    });

    group.finish();
}

/// Benchmarks pattern: populate then iterate all set bits
fn bench_bitset_populate_then_iterate(c: &mut Criterion) {
    let indices = make_bit_indices(DEFAULT_OPS, DEFAULT_BITS, 0xfeed_face_0000_1111);

    let mut group = c.benchmark_group("bitset_workflow");
    group.throughput(Throughput::Elements(DEFAULT_OPS as u64));

    group.bench_function("populate_then_iterate", |b| {
        let mut bits = DynamicBitSet::empty(DEFAULT_BITS);
        b.iter(|| {
            bits.clear();
            for &idx in &indices {
                bits.set(idx);
            }
            let mut sum = 0usize;
            for idx in bits.iter_set() {
                sum += idx;
            }
            black_box(sum)
        })
    });

    group.finish();
}

/// Benchmarks interleaved read/write pattern
fn bench_bitset_mixed_read_write(c: &mut Criterion) {
    let indices = make_bit_indices(DEFAULT_OPS * 2, DEFAULT_BITS, 0xabcd_ef01_2345_6789);

    let mut group = c.benchmark_group("bitset_workflow");
    group.throughput(Throughput::Elements(DEFAULT_OPS as u64));

    group.bench_function("mixed_read_write", |b| {
        let mut bits = DynamicBitSet::empty(DEFAULT_BITS);
        b.iter(|| {
            bits.clear();
            let mut read_count = 0usize;
            // Interleave: set, query, set, query, ...
            for chunk in indices.chunks(2) {
                bits.set(chunk[0]);
                if bits.is_set(chunk[1]) {
                    read_count += 1;
                }
            }
            black_box(read_count)
        })
    });

    group.finish();
}

criterion_group!(benches, bench_fixed_set128, bench_dynamic_bitset,);

criterion_group!(
    bitset_benches,
    // Operation microbenchmarks
    bench_bitset_set,
    bench_bitset_is_set,
    bench_bitset_count,
    bench_bitset_iter,
    // Size scaling benchmarks
    bench_bitset_scale_count,
    bench_bitset_scale_clear,
    // Word boundary edge cases
    bench_bitset_boundaries,
    // Realistic workflows
    bench_bitset_populate_then_count,
    bench_bitset_populate_then_iterate,
    bench_bitset_mixed_read_write,
);

criterion_main!(benches, bitset_benches);
