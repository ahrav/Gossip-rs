#![no_main]

use arbitrary::Arbitrary;
use gossip_stdx::{ByteSlab, ByteSlot};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
enum Op {
    /// Allocate a region with the given data (capped to 512 bytes).
    Allocate(Vec<u8>),
    /// Deallocate the live slot at `index % live.len()`.
    Deallocate(u8),
    /// Read-back the live slot at `index % live.len()` and verify contents.
    Get(u8),
    /// Clear the entire slab, invalidating all outstanding slots.
    Clear,
}

fuzz_target!(|ops: Vec<Op>| {
    // Small slab: large enough for meaningful free-list states, small enough
    // for fast fuzzing iterations.
    let mut slab = ByteSlab::with_capacity(4096);
    // Shadow model: tracks every live (slot, expected_data) pair.
    let mut live: Vec<(ByteSlot, Vec<u8>)> = Vec::new();

    for op in &ops {
        match op {
            Op::Allocate(data) => {
                // Cap data to 512 bytes to keep allocations within the slab.
                let data = if data.len() > 512 { &data[..512] } else { data.as_slice() };

                match slab.allocate(data) {
                    Ok(slot) => {
                        // Verify immediate read-back.
                        if !data.is_empty() {
                            assert_eq!(slab.get(slot), data);
                        }
                        live.push((slot, data.to_vec()));
                    }
                    Err(_) => {
                        // SlabFull is expected when the slab runs out of space.
                    }
                }
            }
            Op::Deallocate(idx) => {
                if !live.is_empty() {
                    let i = *idx as usize % live.len();
                    let (slot, _) = live.swap_remove(i);
                    slab.deallocate(slot);
                }
            }
            Op::Get(idx) => {
                if !live.is_empty() {
                    let i = *idx as usize % live.len();
                    let (slot, expected) = &live[i];
                    if !expected.is_empty() {
                        assert_eq!(slab.get(*slot), expected.as_slice());
                    }
                }
            }
            Op::Clear => {
                live.clear();
                slab.clear();
            }
        }

        // -- Post-op invariants (checked on every operation) --

        // live_count matches shadow length (excluding EMPTY slots).
        let non_empty_count = live.iter().filter(|(s, _)| !s.is_empty()).count();
        assert_eq!(slab.live_count(), non_empty_count);

        // Conservation: live_bytes + free_list_bytes + virgin == capacity.
        assert_eq!(
            slab.live_bytes() + slab.free_list_bytes() + (slab.capacity() - slab.bump_offset()),
            slab.capacity(),
        );
    }

    // Drain all live slots, verifying data integrity one last time.
    for (slot, expected) in live.drain(..) {
        if !expected.is_empty() {
            assert_eq!(slab.get(slot), expected.as_slice());
        }
        slab.deallocate(slot);
    }

    // Slab must be fully reclaimed after draining everything.
    assert!(slab.is_empty());
    assert_eq!(slab.live_count(), 0);
    assert_eq!(slab.live_bytes(), 0);
});
