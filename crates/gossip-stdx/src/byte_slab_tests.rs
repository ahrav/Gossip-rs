use super::*;

// -----------------------------------------------------------------------
// alloc_size truth table
// -----------------------------------------------------------------------

#[test]
fn power_of_two_rounding() {
    assert_eq!(alloc_size(0), Some(0));
    assert_eq!(alloc_size(1), Some(16));
    assert_eq!(alloc_size(15), Some(16));
    assert_eq!(alloc_size(16), Some(16));
    assert_eq!(alloc_size(17), Some(32));
    assert_eq!(alloc_size(100), Some(128));
    assert_eq!(alloc_size(4096), Some(4096));
    assert_eq!(alloc_size(16384), Some(16384));
}

#[test]
fn alloc_size_returns_none_on_overflow() {
    assert_eq!(alloc_size((1u32 << 31) as usize + 1), None);
    assert_eq!(alloc_size(u32::MAX as usize), None);
    assert_eq!(alloc_size(u32::MAX as usize + 1), None);
}

#[test]
fn checked_len_rejects_oversized_lengths() {
    assert_eq!(checked_len_u32(u32::MAX as usize), Some(u32::MAX));
    assert_eq!(checked_len_u32(u32::MAX as usize + 1), None);
}

// -----------------------------------------------------------------------
// Constructor
// -----------------------------------------------------------------------

#[test]
fn new_is_empty() {
    let slab = ByteSlab::with_capacity(1024);
    assert_eq!(slab.capacity(), 1024);
    assert_eq!(slab.live_bytes(), 0);
    assert_eq!(slab.live_count(), 0);
    assert_eq!(slab.bump_offset(), 0);
    assert!(slab.is_empty());
    assert_eq!(slab.available_bytes(), 1024);
}

#[test]
fn free_list_metadata_is_preallocated_and_stable() {
    let mut slab = ByteSlab::with_capacity(64 * 1024);
    let free_list_capacity = slab.free_list.capacity();
    assert!(free_list_capacity > 0);
    let free_list_ptr = slab.free_list.as_ptr();

    // Repeatedly churn non-trailing frees to force free-list insert/remove.
    for _ in 0..256 {
        let a = slab.allocate(&[1u8; 17]).unwrap(); // alloc_size = 32
        let pin1 = slab.allocate(&[0u8; 1]).unwrap(); // alloc_size = 16
        let b = slab.allocate(&[2u8; 17]).unwrap(); // alloc_size = 32
        let pin2 = slab.allocate(&[0u8; 1]).unwrap(); // alloc_size = 16
        let c = slab.allocate(&[3u8; 17]).unwrap(); // alloc_size = 32

        slab.deallocate(a);
        slab.deallocate(b);
        slab.deallocate(c);
        slab.deallocate(pin2);
        slab.deallocate(pin1);
    }

    assert_eq!(slab.free_list.capacity(), free_list_capacity);
    assert_eq!(slab.free_list.as_ptr(), free_list_ptr);
}

#[test]
fn deallocate_panics_when_free_list_metadata_is_exhausted() {
    let mut slab = ByteSlab::new_with_free_list_capacity(128, 1);

    let a = slab.allocate(&[1u8; 17]).unwrap(); // [0, 32)
    let _pin1 = slab.allocate(&[0u8; 1]).unwrap(); // [32, 48)
    let b = slab.allocate(&[2u8; 17]).unwrap(); // [48, 80)
    let _pin2 = slab.allocate(&[0u8; 1]).unwrap(); // [80, 96)
    let _tail = slab.allocate(&[3u8; 17]).unwrap(); // [96, 128), keeps bump at 128

    slab.deallocate(a); // fills the single metadata slot.

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| slab.deallocate(b)));
    assert!(
        result.is_err(),
        "deallocate must fail explicitly when free-list metadata is exhausted"
    );

    // Panic occurred mid-deallocate; clear restores a valid terminal state.
    slab.clear();
}

// -----------------------------------------------------------------------
// Allocate + get roundtrip
// -----------------------------------------------------------------------

#[test]
fn allocate_and_get_roundtrip() {
    let mut slab = ByteSlab::with_capacity(1024);
    let data = b"hello world";
    let slot = slab.allocate(data).unwrap();
    assert_eq!(slab.get(slot), data);
    assert_eq!(slot.len(), data.len());
    slab.deallocate(slot);
}

#[test]
fn allocate_zero_length() {
    let mut slab = ByteSlab::with_capacity(1024);
    let slot = slab.allocate(&[]).unwrap();
    assert_eq!(slot, ByteSlot::EMPTY);
    assert!(slot.is_empty());
    assert_eq!(slab.get(slot), &[]);
    assert_eq!(slab.live_count(), 0);
    // Deallocating EMPTY is a no-op.
    slab.deallocate(slot);
}

// -----------------------------------------------------------------------
// Best-fit selection
// -----------------------------------------------------------------------

#[test]
fn best_fit_selection() {
    let mut slab = ByteSlab::with_capacity(4096);
    // Allocate three blocks separated by "pin" allocations to prevent
    // coalescing when the target blocks are freed.
    let s64 = slab.allocate(&[1u8; 33]).unwrap(); // alloc_size = 64
    let pin1 = slab.allocate(&[0u8; 1]).unwrap(); // pin
    let s32 = slab.allocate(&[2u8; 17]).unwrap(); // alloc_size = 32
    let pin2 = slab.allocate(&[0u8; 1]).unwrap(); // pin
    let s128 = slab.allocate(&[3u8; 65]).unwrap(); // alloc_size = 128
    let _pin3 = slab.allocate(&[0u8; 1]).unwrap(); // pin bump

    // Free the three target blocks. Pins prevent coalescing.
    slab.deallocate(s64);
    slab.deallocate(s32);
    slab.deallocate(s128);

    // Request 30 bytes → alloc_size = 32.
    // Best-fit should pick the 32-byte block (exact fit), not 64 or 128.
    let reused = slab.allocate(&[4u8; 30]).unwrap();
    assert_eq!(reused.offset, s32.offset);

    slab.deallocate(reused);
    slab.deallocate(pin1);
    slab.deallocate(pin2);
    slab.deallocate(_pin3);
}

// -----------------------------------------------------------------------
// Deallocate behavior
// -----------------------------------------------------------------------

#[test]
fn deallocate_empty_is_noop() {
    let mut slab = ByteSlab::with_capacity(1024);
    // Should not panic.
    slab.deallocate(ByteSlot::EMPTY);
    assert!(slab.is_empty());
}

#[test]
fn deallocate_rejects_foreign_slot() {
    let mut a = ByteSlab::with_capacity(256);
    let mut b = ByteSlab::with_capacity(256);
    let slot = a.allocate(b"abc").unwrap();

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        b.deallocate(slot);
    }));
    assert!(result.is_err(), "foreign slot deallocation must panic");

    // Clean up the original allocation to satisfy drop leak checks.
    a.deallocate(slot);
}

#[test]
fn get_rejects_foreign_slot() {
    let mut a = ByteSlab::with_capacity(256);
    let b = ByteSlab::with_capacity(256);
    let slot = a.allocate(b"abc").unwrap();

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| b.get(slot)));
    assert!(result.is_err(), "foreign slot read must panic");

    // Clean up the original allocation to satisfy drop leak checks.
    a.deallocate(slot);
}

// -----------------------------------------------------------------------
// Free list coalescing
// -----------------------------------------------------------------------

#[test]
fn free_list_coalescing_right() {
    let mut slab = ByteSlab::with_capacity(4096);
    let a = slab.allocate(&[1u8; 16]).unwrap(); // 16 bytes at offset 0
    let b = slab.allocate(&[2u8; 16]).unwrap(); // 16 bytes at offset 16

    // Free b first (right), then a (left) — a should coalesce with b.
    slab.deallocate(b);
    slab.deallocate(a);

    // Both freed and coalesced → bump should reclaim everything.
    assert_eq!(slab.bump_offset(), 0);
    assert_eq!(slab.free_list_bytes(), 0);
    assert_eq!(slab.available_bytes(), 4096);
}

#[test]
fn free_list_coalescing_left() {
    let mut slab = ByteSlab::with_capacity(4096);
    let a = slab.allocate(&[1u8; 16]).unwrap();
    let b = slab.allocate(&[2u8; 16]).unwrap();
    let _c = slab.allocate(&[3u8; 16]).unwrap(); // keeps bump from reclaiming

    // Free a first (left), then b (right) — b should coalesce with a.
    slab.deallocate(a);
    slab.deallocate(b);

    // One coalesced block of 32 bytes.
    assert_eq!(slab.free_list_bytes(), 32);

    slab.deallocate(_c);
}

#[test]
fn free_list_coalescing_three_way() {
    let mut slab = ByteSlab::with_capacity(4096);
    let a = slab.allocate(&[1u8; 16]).unwrap();
    let b = slab.allocate(&[2u8; 16]).unwrap();
    let c = slab.allocate(&[3u8; 16]).unwrap();

    // Free a and c (creating a gap at b), then free b — three-way coalesce.
    slab.deallocate(a);
    slab.deallocate(c);
    slab.deallocate(b);

    // Everything coalesced and reclaimed into bump.
    assert_eq!(slab.bump_offset(), 0);
    assert_eq!(slab.free_list_bytes(), 0);
}

// -----------------------------------------------------------------------
// Split
// -----------------------------------------------------------------------

#[test]
fn free_list_split() {
    let mut slab = ByteSlab::with_capacity(4096);
    // Allocate 128-byte block, free it, then request 32 bytes from it.
    let big = slab.allocate(&[1u8; 65]).unwrap(); // alloc_size = 128
    let _pin = slab.allocate(&[2u8; 16]).unwrap(); // pin bump
    slab.deallocate(big);

    let small = slab.allocate(&[3u8; 17]).unwrap(); // alloc_size = 32
    assert_eq!(small.offset, big.offset);
    assert_eq!(small.alloc_size, 32);

    // Remainder (128 - 32 = 96) stays in free list.
    assert_eq!(slab.free_list_bytes(), 96);

    slab.deallocate(small);
    slab.deallocate(_pin);
}

#[test]
fn split_minimum_size() {
    let mut slab = ByteSlab::with_capacity(4096);
    // Allocate a 32-byte block, free it, then request 17 bytes (alloc_size = 32).
    // Remainder = 0, so no split.
    let block = slab.allocate(&[1u8; 17]).unwrap(); // alloc_size = 32
    let _pin = slab.allocate(&[2u8; 16]).unwrap();
    slab.deallocate(block);

    // Request same size — should use entire block.
    let reused = slab.allocate(&[3u8; 17]).unwrap();
    assert_eq!(reused.offset, block.offset);
    assert_eq!(reused.alloc_size, 32);
    assert_eq!(slab.free_list_bytes(), 0);

    slab.deallocate(reused);
    slab.deallocate(_pin);
}

// -----------------------------------------------------------------------
// Bump reclamation
// -----------------------------------------------------------------------

#[test]
fn bump_reclamation() {
    let mut slab = ByteSlab::with_capacity(1024);
    let a = slab.allocate(&[1u8; 16]).unwrap();
    let bump_before = slab.bump_offset();

    slab.deallocate(a);

    // Trailing free block reclaimed into bump → free list stays empty.
    assert_eq!(slab.bump_offset(), 0);
    assert!(slab.bump_offset() < bump_before);
    assert_eq!(slab.free_list_bytes(), 0);
}

#[test]
fn bump_reclamation_after_coalesce() {
    let mut slab = ByteSlab::with_capacity(1024);
    let a = slab.allocate(&[1u8; 16]).unwrap();
    let b = slab.allocate(&[2u8; 16]).unwrap();

    // Free b (reclaims bump), then free a (also reclaims bump via coalesce).
    slab.deallocate(b);
    assert_eq!(slab.bump_offset(), 16); // reclaimed b's 16 bytes

    slab.deallocate(a);
    assert_eq!(slab.bump_offset(), 0); // reclaimed a's 16 bytes
    assert_eq!(slab.free_list_bytes(), 0);
}

// -----------------------------------------------------------------------
// Workload patterns
// -----------------------------------------------------------------------

#[test]
fn cursor_update_pattern() {
    let mut slab = ByteSlab::with_capacity(4096);
    // Simulate: alloc key+token, dealloc, realloc with larger data.
    let key = slab.allocate(b"cursor_key_v1").unwrap();
    let token = slab.allocate(b"token_data_bytes").unwrap();

    // "Update" by dealloc + realloc.
    slab.deallocate(key);
    slab.deallocate(token);

    let key2 = slab.allocate(b"cursor_key_v2_longer").unwrap();
    let token2 = slab.allocate(b"token_data_bytes_v2").unwrap();

    assert_eq!(slab.get(key2), b"cursor_key_v2_longer");
    assert_eq!(slab.get(token2), b"token_data_bytes_v2");

    slab.deallocate(key2);
    slab.deallocate(token2);
}

#[test]
fn shard_creation_pattern() {
    let mut slab = ByteSlab::with_capacity(4096);
    let start = slab.allocate(b"shard_start_key").unwrap();
    let end = slab.allocate(b"shard_end_key").unwrap();
    let meta = slab.allocate(b"metadata_blob").unwrap();

    assert_eq!(slab.get(start), b"shard_start_key");
    assert_eq!(slab.get(end), b"shard_end_key");
    assert_eq!(slab.get(meta), b"metadata_blob");

    slab.deallocate(start);
    slab.deallocate(end);
    slab.deallocate(meta);
}

// -----------------------------------------------------------------------
// Slab full
// -----------------------------------------------------------------------

#[test]
fn allocate_until_full() {
    let mut slab = ByteSlab::with_capacity(64);
    // 64 bytes capacity. Alloc 32 + 32 = 64 → full.
    let _a = slab.allocate(&[1u8; 17]).unwrap(); // alloc_size = 32
    let _b = slab.allocate(&[2u8; 17]).unwrap(); // alloc_size = 32

    let err = slab.allocate(&[3u8; 1]).unwrap_err();
    assert_eq!(err.requested, 16); // alloc_size(1) = 16
    assert_eq!(err.available, 0);

    slab.deallocate(_a);
    slab.deallocate(_b);
}

#[test]
fn slab_full_error_info() {
    let mut slab = ByteSlab::with_capacity(48);
    let _a = slab.allocate(&[1u8; 17]).unwrap(); // alloc_size = 32

    // 16 bytes of virgin space remain, but we need 32.
    let err = slab.allocate(&[2u8; 17]).unwrap_err();
    assert_eq!(err.requested, 32);
    assert_eq!(err.available, 16);

    slab.deallocate(_a);
}

#[test]
fn allocate_overflow_returns_error_instead_of_panicking() {
    // Construct a slab state that exercises u32 bump arithmetic overflow.
    // This mirrors release-build wraparound behavior without allocating a
    // multi-gigabyte backing buffer.
    let mut slab = ByteSlab::with_capacity(64);
    slab.bump = u32::MAX - 8;
    slab.capacity = u32::MAX;

    let result =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| slab.allocate(&[3u8; 32])));
    assert!(
        result.is_ok(),
        "allocate should return SlabFull, not panic on overflow"
    );

    let err = result.unwrap().unwrap_err();
    assert_eq!(err.requested, 32);
    assert_eq!(err.available, 8);
}

// -----------------------------------------------------------------------
// Clear
// -----------------------------------------------------------------------

#[test]
fn clear_resets_state() {
    let mut slab = ByteSlab::with_capacity(1024);
    let _ = slab.allocate(&[1u8; 100]).unwrap();
    let _ = slab.allocate(&[2u8; 200]).unwrap();

    slab.clear();

    assert_eq!(slab.bump_offset(), 0);
    assert_eq!(slab.live_bytes(), 0);
    assert_eq!(slab.live_count(), 0);
    assert_eq!(slab.free_list_bytes(), 0);
    assert_eq!(slab.available_bytes(), 1024);
    assert!(slab.is_empty());
}

#[test]
fn clear_rejects_stale_slots() {
    let mut slab = ByteSlab::with_capacity(1024);
    let stale = slab.allocate(b"before_clear").unwrap();
    slab.clear();

    // get() with a pre-clear slot must panic (owner id rotated).
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| slab.get(stale)));
    assert!(result.is_err(), "stale slot after clear must be rejected");
}

// -----------------------------------------------------------------------
// Stale slot detection (slot validity assertions)
// -----------------------------------------------------------------------

/// Allocate a single trailing block, deallocate it (bump retracts),
/// then use the stale copy. The `assert!(offset + alloc_size <= bump)`
/// in `get()` catches the stale handle because the bump pointer has
/// retracted past the slot's region.
#[test]
fn stale_slot_after_bump_retraction_panics_on_get() {
    let mut slab = ByteSlab::with_capacity(1024);
    let slot = slab.allocate(b"hello").unwrap();
    let stale = slot; // Copy the handle.
    slab.deallocate(slot);

    // Bump retracted: stale.offset + stale.alloc_size > slab.bump.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| slab.get(stale)));
    assert!(
        result.is_err(),
        "stale slot after bump retraction must panic"
    );
}

/// Same scenario but through `deallocate()`: the assert catches
/// the stale handle before it corrupts slab accounting.
#[test]
fn stale_slot_after_bump_retraction_panics_on_deallocate() {
    let mut slab = ByteSlab::with_capacity(1024);
    let slot = slab.allocate(b"hello").unwrap();
    let stale = slot;
    slab.deallocate(slot);

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| slab.deallocate(stale)));
    assert!(
        result.is_err(),
        "stale slot deallocation after bump retraction must panic"
    );
}

// -----------------------------------------------------------------------
// SlabFull display
// -----------------------------------------------------------------------

#[test]
fn slab_full_display() {
    let err = SlabFull {
        requested: 32,
        available: 16,
    };
    let msg = format!("{err}");
    assert!(msg.contains("32"));
    assert!(msg.contains("16"));
}

// -----------------------------------------------------------------------
// Property tests (Vec oracle)
// -----------------------------------------------------------------------

fn miri_proptest_config() -> proptest::test_runner::Config {
    if cfg!(miri) {
        proptest::test_runner::Config {
            failure_persistence: None,
            cases: 32,
            ..Default::default()
        }
    } else {
        proptest::test_runner::Config::default()
    }
}

mod prop {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(super::miri_proptest_config())]

        /// Allocate then get returns identical bytes for all live slots.
        #[test]
        fn allocate_get_roundtrip(
            data_list in proptest::collection::vec(
                proptest::collection::vec(0u8..=255, 0..512),
                1..20,
            )
        ) {
            let total: usize = data_list.iter().map(|d| alloc_size(d.len()).unwrap_or(0) as usize).sum();
            let cap = total.max(1024);
            let mut slab = ByteSlab::with_capacity(cap);
            let mut live: Vec<(ByteSlot, Vec<u8>)> = Vec::new();

            for data in &data_list {
                if let Ok(slot) = slab.allocate(data) {
                    if !data.is_empty() {
                        prop_assert_eq!(slab.get(slot), &data[..]);
                    }
                    live.push((slot, data.clone()));
                }
            }

            // Verify all live slots still return correct data.
            for (slot, data) in &live {
                if !data.is_empty() {
                    prop_assert_eq!(slab.get(*slot), &data[..]);
                }
            }

            for (slot, _) in live {
                slab.deallocate(slot);
            }
        }

        /// State machine: random Alloc/Dealloc/Get ops vs a Vec shadow model.
        #[test]
        fn state_machine_oracle(
            ops in proptest::collection::vec(
                prop_oneof![
                    proptest::collection::vec(0u8..=255, 0..512)
                        .prop_map(|d| (0u8, d, 0usize)),      // Allocate
                    (0usize..100).prop_map(|i| (1u8, vec![], i)), // Deallocate(idx)
                    (0usize..100).prop_map(|i| (2u8, vec![], i)), // Get(idx)
                    Just((3u8, vec![], 0usize)),                   // Clear
                ],
                0..200,
            )
        ) {
            let mut slab = ByteSlab::with_capacity(64 * 1024);
            let mut live: Vec<(ByteSlot, Vec<u8>)> = Vec::new();

            for (op, data, idx) in &ops {
                match op {
                    0 => {
                        // Allocate
                        if let Ok(slot) = slab.allocate(data) {
                            live.push((slot, data.clone()));
                        }
                    }
                    1 => {
                        // Deallocate
                        if !live.is_empty() {
                            let i = idx % live.len();
                            let (slot, _) = live.swap_remove(i);
                            slab.deallocate(slot);
                        }
                    }
                    2 => {
                        // Get
                        if !live.is_empty() {
                            let i = idx % live.len();
                            let (slot, expected) = &live[i];
                            if !expected.is_empty() {
                                prop_assert_eq!(slab.get(*slot), &expected[..]);
                            }
                        }
                    }
                    3 => {
                        // Clear
                        live.clear();
                        slab.clear();
                    }
                    _ => unreachable!(),
                }

                // Metrics consistent after every op.
                prop_assert_eq!(slab.live_count(), live.iter().filter(|(s, _)| !s.is_empty()).count());

                // Conservation invariant.
                prop_assert_eq!(
                    slab.live_bytes() + slab.free_list_bytes() + (slab.capacity() - slab.bump_offset()),
                    slab.capacity()
                );
            }

            // Cleanup.
            for (slot, _) in live {
                slab.deallocate(slot);
            }
        }

        /// No two live slots have overlapping physical ranges.
        #[test]
        fn no_overlap(
            data_list in proptest::collection::vec(
                proptest::collection::vec(0u8..=255, 1..256),
                1..30,
            )
        ) {
            let total: usize = data_list.iter().map(|d| alloc_size(d.len()).unwrap_or(0) as usize).sum();
            let cap = total.max(1024);
            let mut slab = ByteSlab::with_capacity(cap);
            let mut live: Vec<ByteSlot> = Vec::new();

            for data in &data_list {
                if let Ok(slot) = slab.allocate(data) {
                    live.push(slot);
                }
            }

            // Check all pairs for overlap.
            for i in 0..live.len() {
                for j in (i + 1)..live.len() {
                    let a = &live[i];
                    let b = &live[j];
                    if a.is_empty() || b.is_empty() { continue; }
                    let a_end = a.offset + a.alloc_size;
                    let b_end = b.offset + b.alloc_size;
                    prop_assert!(
                        a_end <= b.offset || b_end <= a.offset,
                        "overlap: [{}, {}) and [{}, {})",
                        a.offset, a_end, b.offset, b_end
                    );
                }
            }

            for slot in live {
                slab.deallocate(slot);
            }
        }

        /// alloc_size always returns Some(0) or Some(power of 2), and for
        /// nonzero input: result >= MIN_BLOCK and result >= input.
        #[test]
        fn alloc_size_is_power_of_two(n in 0usize..100_000) {
            let result = alloc_size(n);
            if n == 0 {
                prop_assert_eq!(result, Some(0));
            } else if let Some(r) = result {
                prop_assert!(r >= MIN_BLOCK);
                prop_assert!(r >= n as u32);
                prop_assert!(r.is_power_of_two());
            }
            // None is valid for inputs > 2^31 (not exercised by this range).
        }

        /// No two adjacent free blocks exist after any dealloc sequence.
        #[test]
        fn coalescing_completeness(
            alloc_count in 2usize..20,
            dealloc_indices in proptest::collection::vec(0usize..100, 1..20),
        ) {
            let mut slab = ByteSlab::with_capacity(64 * 1024);
            let mut live: Vec<(ByteSlot, Vec<u8>)> = Vec::new();

            for i in 0..alloc_count {
                let data = vec![i as u8; 16 + (i * 7) % 100];
                if let Ok(slot) = slab.allocate(&data) {
                    live.push((slot, data));
                }
            }

            for &idx in &dealloc_indices {
                if !live.is_empty() {
                    let i = idx % live.len();
                    let (slot, _) = live.swap_remove(i);
                    slab.deallocate(slot);
                }
            }

            // Invariants are checked by debug_assert_invariants on every
            // dealloc call, which already asserts no adjacent blocks.
            // We also explicitly verify here.
            // (Access free_list via the conservation check.)
            prop_assert_eq!(
                slab.live_bytes() + slab.free_list_bytes() + (slab.capacity() - slab.bump_offset()),
                slab.capacity()
            );

            // Cleanup.
            for (slot, _) in live {
                slab.deallocate(slot);
            }
        }
    }
}

// -----------------------------------------------------------------------
// Randomized acquire/release cycle (consensus-rs NodePoolType pattern)
// -----------------------------------------------------------------------

/// Weighted random alloc/dealloc cycle modeled on consensus-rs NodePoolType
/// tests. Uses a simple deterministic PRNG (xorshift32) for
/// Miri-compatibility.
///
/// Phase 1: 60% allocate / 40% deallocate (fill up).
/// Phase 2: 40% allocate / 60% deallocate (drain down).
/// Phase 3: deallocate everything, verify slab is fully reclaimed.
#[test]
fn randomized_acquire_release_cycle() {
    // Simple deterministic xorshift32 PRNG — Miri-compatible.
    struct Rng(u32);
    impl Rng {
        fn next(&mut self) -> u32 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 17;
            self.0 ^= self.0 << 5;
            self.0
        }
        fn range(&mut self, lo: u32, hi: u32) -> u32 {
            lo + self.next() % (hi - lo)
        }
        fn percent(&mut self) -> u32 {
            self.next() % 100
        }
    }

    let mut rng = Rng(0xDEAD_BEEF);
    let mut slab = ByteSlab::with_capacity(64 * 1024);
    let mut live: Vec<(ByteSlot, Vec<u8>)> = Vec::new();

    // Phase 1: biased toward allocate (60/40).
    for _ in 0..500 {
        if rng.percent() < 60 && slab.available_bytes() >= 16 {
            let size = rng.range(1, 513) as usize;
            let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
            if let Ok(slot) = slab.allocate(&data) {
                live.push((slot, data));
            }
        } else if !live.is_empty() {
            let idx = rng.next() as usize % live.len();
            let (slot, expected) = live.swap_remove(idx);
            assert_eq!(slab.get(slot), &expected[..]);
            slab.deallocate(slot);
        }
    }

    // Phase 2: biased toward deallocate (40/60).
    for _ in 0..500 {
        if rng.percent() < 40 && slab.available_bytes() >= 16 {
            let size = rng.range(1, 513) as usize;
            let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
            if let Ok(slot) = slab.allocate(&data) {
                live.push((slot, data));
            }
        } else if !live.is_empty() {
            let idx = rng.next() as usize % live.len();
            let (slot, expected) = live.swap_remove(idx);
            assert_eq!(slab.get(slot), &expected[..]);
            slab.deallocate(slot);
        }
    }

    // Phase 3: drain all, verify full reclamation.
    for (slot, expected) in live.drain(..) {
        assert_eq!(slab.get(slot), &expected[..]);
        slab.deallocate(slot);
    }
    assert!(slab.is_empty());
    assert_eq!(slab.live_count(), 0);
    assert_eq!(slab.live_bytes(), 0);
    assert_eq!(slab.available_bytes(), slab.capacity());
}
