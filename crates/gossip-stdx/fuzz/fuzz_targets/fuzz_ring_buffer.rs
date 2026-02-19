#![no_main]

use std::collections::VecDeque;

use arbitrary::Arbitrary;
use gossip_stdx::RingBuffer;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
enum Op {
    PushBack(u32),
    PushBackOverwrite(u32),
    PopFront,
    Clear,
    Get(u8),
    Clone,
    IterCollect,
    IterRev,
}

fuzz_target!(|ops: Vec<Op>| {
    let mut ring = RingBuffer::<u32, 8>::new();
    let mut model = VecDeque::with_capacity(8);

    for op in &ops {
        match op {
            Op::PushBack(v) => {
                let ring_res = ring.push_back(*v);
                if model.len() < 8 {
                    model.push_back(*v);
                    assert!(ring_res.is_ok());
                } else {
                    assert_eq!(ring_res, Err(*v));
                }
            }
            Op::PushBackOverwrite(v) => {
                let evicted = ring.push_back_overwrite(*v);
                let model_evicted = if model.len() == 8 {
                    model.pop_front()
                } else {
                    None
                };
                model.push_back(*v);
                assert_eq!(evicted, model_evicted);
            }
            Op::PopFront => {
                assert_eq!(ring.pop_front(), model.pop_front());
            }
            Op::Clear => {
                ring.clear();
                model.clear();
            }
            Op::Get(idx) => {
                let idx = (*idx as usize) % 16;
                assert_eq!(ring.get(idx), model.get(idx));
            }
            Op::Clone => {
                let cloned = ring.clone();
                let ring_vals: Vec<_> = cloned.iter().copied().collect();
                let model_vals: Vec<_> = model.iter().copied().collect();
                assert_eq!(ring_vals, model_vals);
            }
            Op::IterCollect => {
                let ring_vals: Vec<_> = ring.iter().copied().collect();
                let model_vals: Vec<_> = model.iter().copied().collect();
                assert_eq!(ring_vals, model_vals);
            }
            Op::IterRev => {
                let ring_vals: Vec<_> = ring.iter().rev().copied().collect();
                let model_vals: Vec<_> = model.iter().rev().copied().collect();
                assert_eq!(ring_vals, model_vals);
            }
        }

        // After every operation: length and contents must match.
        assert_eq!(ring.len(), model.len());
        let ring_vals: Vec<_> = ring.iter().copied().collect();
        let model_vals: Vec<_> = model.iter().copied().collect();
        assert_eq!(ring_vals, model_vals);
    }
});
