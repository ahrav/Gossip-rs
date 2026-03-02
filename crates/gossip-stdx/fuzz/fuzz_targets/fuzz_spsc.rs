//! Fuzz target for SPSC ring buffer — model-based differential test.
//!
//! Drives a single-threaded push/pop/batch-pop sequence against a `VecDeque`
//! oracle and asserts FIFO ordering, occupancy counts, and full/empty
//! detection match at every step.
//!
//! Because the fuzzer runs single-threaded, this exercises the index
//! arithmetic, masking, cached-index refresh logic, and `MaybeUninit`
//! slot management — but NOT cross-thread memory ordering (use loom for
//! that). The key value here is that libFuzzer's coverage-guided mutations
//! can reach deep index states that proptest's bounded random walks miss.

#![no_main]

use std::collections::VecDeque;
use std::mem::MaybeUninit;

use arbitrary::Arbitrary;
use gossip_stdx::spsc_channel;
use libfuzzer_sys::fuzz_target;

/// Operations the fuzzer can perform on the ring.
#[derive(Arbitrary, Debug)]
enum Op {
    /// Push a value into the ring.
    Push(u64),
    /// Pop a single value.
    Pop,
    /// Batch-pop up to `min(requested, 8)` values.
    PopBatch(u8),
}

fuzz_target!(|ops: Vec<Op>| {
    // Capacity 4: small enough to hit full/empty transitions frequently,
    // large enough to exercise batch-pop across wrap boundaries.
    let (mut tx, mut rx) = spsc_channel::<u64, 4>();
    let mut model = VecDeque::with_capacity(4);

    for op in &ops {
        match op {
            Op::Push(v) => {
                let result = tx.try_push(*v);
                if model.len() < 4 {
                    assert!(result.is_ok(), "push should succeed when not full");
                    model.push_back(*v);
                } else {
                    assert_eq!(result, Err(*v), "push should return value when full");
                }
            }
            Op::Pop => {
                let actual = rx.try_pop();
                let expected = model.pop_front();
                assert_eq!(actual, expected, "pop mismatch");
            }
            Op::PopBatch(requested) => {
                // Clamp to 8 to keep stack allocation bounded.
                let n = (*requested as usize).min(8).max(1);
                let mut out = [MaybeUninit::uninit(); 8];
                let count = rx.try_pop_batch(&mut out[..n]);

                // Drain the same number from the model and compare.
                let available = model.len().min(n);
                assert_eq!(count, available, "batch count mismatch");

                for i in 0..count {
                    // SAFETY: try_pop_batch guarantees out[0..count] is initialized.
                    let actual = unsafe { out[i].assume_init() };
                    let expected = model.pop_front().unwrap();
                    assert_eq!(actual, expected, "batch element {i} mismatch");
                }
            }
        }
    }
});
