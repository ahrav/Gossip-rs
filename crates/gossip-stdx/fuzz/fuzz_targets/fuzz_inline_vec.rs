#![no_main]

use arbitrary::Arbitrary;
use gossip_stdx::InlineVec;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
enum Op {
    Push(u32),
    ExtendFromSlice(Vec<u32>),
    Clone,
    AsSlice,
    FromSlice(Vec<u32>),
    FromVec(Vec<u32>),
}

fuzz_target!(|ops: Vec<Op>| {
    let mut iv = InlineVec::<u32, 4>::new();
    let mut model = Vec::new();

    for op in &ops {
        match op {
            Op::Push(v) => {
                iv.push(*v);
                model.push(*v);
            }
            Op::ExtendFromSlice(vs) => {
                iv.extend_from_slice(vs);
                model.extend_from_slice(vs);
            }
            Op::Clone => {
                let cloned = iv.clone();
                assert_eq!(cloned.as_slice(), model.as_slice());
            }
            Op::AsSlice => {
                assert_eq!(iv.as_slice(), model.as_slice());
            }
            Op::FromSlice(vs) => {
                let fresh = InlineVec::<u32, 4>::from_slice(vs);
                assert_eq!(fresh.as_slice(), vs.as_slice());
            }
            Op::FromVec(vs) => {
                let fresh: InlineVec<u32, 4> = vs.clone().into();
                assert_eq!(fresh.as_slice(), vs.as_slice());
            }
        }

        // After every operation: length and contents must match.
        assert_eq!(iv.len(), model.len());
        assert_eq!(iv.as_slice(), model.as_slice());
    }
});
