//! Property-based tests and Kani bounded model checking proofs for TimingWheel.
//!
//! This module provides:
//! - A reference implementation ([`Model`]) for differential testing
//! - Property-based tests using proptest (feature-gated: `stdx-proptest`)
//! - Kani bounded model checking proofs (feature-gated: `kani`)
//!
//! # Running Tests
//!
//! ```sh
//! # Property tests
//! cargo test --features stdx-proptest
//!
//! # Kani proofs
//! cargo kani --features kani
//!
//! # Specific Kani harness
//! cargo kani --features kani --harness verify_never_fires_early
//! ```

use std::collections::{BTreeMap, VecDeque};

// ============================================================================
// Reference Model
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MErr {
    PoolExhausted,
    TooFarInFuture,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MOutcome<T> {
    Scheduled,
    Ready(T),
}

/// Ceiling division without overflow (matches the fixed implementation)
#[inline(always)]
fn ceil_div_u64(x: u64, d: u64) -> u64 {
    debug_assert!(d != 0);
    let q = x / d;
    let r = x % d;
    q + (r != 0) as u64
}

#[inline(always)]
fn wheel_size_for(max_horizon_bytes: u64, g: u64) -> u64 {
    // Same sizing rule as the wheel:
    // W_required = ceil((max_horizon + (G-1))/G) + 1; W = next_pow2(W_required)
    let worst = max_horizon_bytes.saturating_add(g - 1);
    let w_required = ceil_div_u64(worst, g).saturating_add(1).max(2);
    w_required.next_power_of_two()
}

/// Reference model that mirrors TimingWheel semantics using simple data structures.
pub struct Model<T: Copy> {
    g: u64,
    wheel_size: u64,
    cap: usize,

    // Contract-visible state:
    now_bucket: u64,
    base: u64, // "cursor_abs": next bucket key > any processed/eligible bucket

    len: usize,
    map: BTreeMap<u64, VecDeque<T>>, // key -> FIFO
}

impl<T: Copy> Model<T> {
    pub fn new(max_horizon_bytes: u64, cap: usize, g: u64) -> Self {
        Self {
            g,
            wheel_size: wheel_size_for(max_horizon_bytes, g),
            cap,
            now_bucket: 0,
            base: 0,
            len: 0,
            map: BTreeMap::new(),
        }
    }

    #[inline(always)]
    fn key(&self, hi_end: u64) -> u64 {
        ceil_div_u64(hi_end, self.g)
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn push(&mut self, hi_end: u64, val: T) -> Result<MOutcome<T>, MErr> {
        let k = self.key(hi_end);

        // Mirror the wheel's "already due relative to base" behavior.
        if k < self.base {
            return Ok(MOutcome::Ready(val));
        }

        if k >= self.base.saturating_add(self.wheel_size) {
            return Err(MErr::TooFarInFuture);
        }
        if self.len == self.cap {
            return Err(MErr::PoolExhausted);
        }

        self.map.entry(k).or_default().push_back(val);
        self.len += 1;
        Ok(MOutcome::Scheduled)
    }

    pub fn advance_and_drain(&mut self, now_offset: u64, out: &mut Vec<T>) {
        let nb = now_offset / self.g;
        assert!(nb >= self.now_bucket, "time must be monotone");

        // Fix: mirror the corrected early-return logic
        if nb == self.now_bucket && self.base > nb {
            return;
        }
        self.now_bucket = nb;

        // Drain all keys <= now_bucket in key order, FIFO within key.
        let drain_to = self.now_bucket;
        let keys: Vec<u64> = self.map.range(..=drain_to).map(|(&k, _)| k).collect();

        for k in keys {
            if let Some(mut q) = self.map.remove(&k) {
                while let Some(v) = q.pop_front() {
                    out.push(v);
                    self.len -= 1;
                }
            }
        }

        // Mirror wheel behavior: after advancing time, base is at least now_bucket+1.
        let target_base = self.now_bucket.saturating_add(1);
        if self.base < target_base {
            self.base = target_base;
        }
    }
}

// ============================================================================
// Property Tests (requires proptest crate and stdx-proptest feature)
// ============================================================================

#[cfg(feature = "stdx-proptest")]
mod proptests {
    use super::{MErr, MOutcome, Model};
    use crate::{PushError, PushOutcome, TimingWheel};
    use proptest::prelude::*;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct Ev {
        id: u32,
        hi_end: u64,
    }

    #[derive(Clone, Debug)]
    struct OpSpec {
        tag: u8, // 0=adv, 1=push_in_range, 2=push_too_far, 3=push_past
        val: u32,
    }

    fn norm_err(e: &PushError) -> u8 {
        match e {
            PushError::PoolExhausted => 0,
            PushError::TooFarInFuture { .. } => 1,
            #[cfg(debug_assertions)]
            PushError::SlotCollision { .. } => 2,
        }
    }

    fn norm_model_err(e: &MErr) -> u8 {
        match e {
            MErr::PoolExhausted => 0,
            MErr::TooFarInFuture => 1,
        }
    }

    fn ops_strategy() -> impl Strategy<Value = Vec<OpSpec>> {
        let op = (any::<u8>(), any::<u32>()).prop_map(|(t, v)| OpSpec { tag: t % 4, val: v });
        proptest::collection::vec(op, 0..2000)
    }

    fn run_prop<const G: u32>(max_horizon: u64, cap: usize, ops: Vec<OpSpec>) {
        let mut wheel: TimingWheel<Ev, G> = TimingWheel::new(max_horizon, cap);
        let mut model: Model<Ev> = Model::new(max_horizon, cap, G as u64);

        let mut now: u64 = 0;
        let mut next_id: u32 = 0;

        for op in ops {
            match op.tag {
                0 => {
                    // advance
                    let delta = (op.val as u64) % (4 * (G as u64) + 1);
                    now = now.saturating_add(delta);

                    let mut out_w = Vec::new();
                    let drained_w = wheel.advance_and_drain(now, |e| out_w.push(e));
                    let mut out_m = Vec::new();
                    model.advance_and_drain(now, &mut out_m);

                    assert_eq!(drained_w, out_w.len());
                    assert_eq!(out_w, out_m);

                    // Never early (strong safety property)
                    for e in &out_w {
                        assert!(
                            e.hi_end <= now,
                            "fired early: hi_end={} now={}",
                            e.hi_end,
                            now
                        );
                    }

                    // Bounded lateness check:
                    // Item with hi_end fires when ceil(hi_end/G) <= floor(now/G).
                    // The worst case is when hi_end = k*G (exactly on boundary),
                    // key = k, and now = (k+1)*G - 1 (just before next boundary).
                    // This gives lateness of G-1 bytes.
                    // However, this test advances time coarsely, so items may be
                    // drained at now > hi_end + G - 1 if we didn't call advance
                    // between hi_end and now. The important invariant is that
                    // items never fire early and the model matches the wheel.
                    // The model match is already checked above.

                    assert_eq!(wheel.len(), model.len());
                    wheel.debug_validate();
                }
                1..=3 => {
                    // push
                    let raw = op.val as u64;
                    next_id = next_id.wrapping_add(1);

                    let hi_end = match op.tag {
                        // in range: now + [0..max_horizon]
                        1 => now.saturating_add(raw % (max_horizon.saturating_add(1))),
                        // too far: now + (max_horizon+1) + [0..max_horizon]
                        2 => now
                            .saturating_add(max_horizon.saturating_add(1))
                            .saturating_add(raw % (max_horizon.saturating_add(1))),
                        // past: now - [0..max_horizon]
                        _ => now.saturating_sub(raw % (max_horizon.saturating_add(1))),
                    };

                    // Force boundary cases often.
                    let hi_end = if (op.val & 1) == 0 {
                        // snap to multiple of G occasionally
                        hi_end - (hi_end % (G as u64))
                    } else {
                        hi_end
                    };

                    let ev = Ev {
                        id: next_id,
                        hi_end,
                    };

                    let rw = wheel.push(hi_end, ev);
                    let rm = model.push(hi_end, ev);

                    match (&rw, &rm) {
                        (Ok(PushOutcome::Scheduled), Ok(MOutcome::Scheduled)) => {}
                        (Ok(PushOutcome::Ready(a)), Ok(MOutcome::Ready(b))) => {
                            assert_eq!(a, b)
                        }
                        (Err(e), Err(me)) => {
                            #[cfg(debug_assertions)]
                            {
                                // SlotCollision must never occur under correct sizing
                                assert_ne!(
                                    norm_err(e),
                                    2,
                                    "SlotCollision indicates sizing bug: {e:?}"
                                );
                            }
                            assert_eq!(norm_err(e), norm_model_err(me));
                        }
                        (a, b) => panic!("wheel/model mismatch: wheel={a:?} model={b:?}"),
                    }

                    assert_eq!(wheel.len(), model.len());
                    wheel.debug_validate();

                    // Contract check: after pushing something already eligible,
                    // calling advance at same now must drain it.
                    let mut out_w = Vec::new();
                    wheel.advance_and_drain(now, |e| out_w.push(e));
                    let mut out_m = Vec::new();
                    model.advance_and_drain(now, &mut out_m);
                    assert_eq!(out_w, out_m);

                    assert_eq!(wheel.len(), model.len());
                    wheel.debug_validate();
                }
                _ => unreachable!(),
            }
        }
    }

    proptest! {
        #[test]
        fn timing_wheel_prop_g8(
            max_horizon in 0u16..512,
            cap in 0usize..128,
            ops in ops_strategy()
        ) {
            run_prop::<8>(max_horizon as u64, cap, ops);
        }

        #[test]
        fn timing_wheel_prop_g1(
            max_horizon in 0u16..256,
            cap in 0usize..128,
            ops in ops_strategy()
        ) {
            run_prop::<1>(max_horizon as u64, cap, ops);
        }

        #[test]
        fn timing_wheel_prop_g64(
            max_horizon in 0u16..4096,
            cap in 0usize..128,
            ops in ops_strategy()
        ) {
            run_prop::<64>(max_horizon as u64, cap, ops);
        }
    }
}

// ============================================================================
// Bitset Property Tests
// ============================================================================

#[cfg(feature = "stdx-proptest")]
mod bitset_tests {
    use crate::Bitset2;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn bitset2_matches_naive(
            bits in 1usize..1024,
            ops in proptest::collection::vec(
                (any::<usize>(), any::<bool>(), any::<usize>()),
                0..5000
            )
        ) {
            let mut bs = Bitset2::new(bits);
            let mut naive = vec![false; bits];

            for (i, set, from) in ops {
                let idx = i % bits;
                let from = from % bits;

                if set {
                    bs.set(idx);
                    naive[idx] = true;
                } else {
                    bs.clear(idx);
                    naive[idx] = false;
                }

                assert_eq!(bs.any(), naive.iter().any(|&b| b));

                // Next set >= from
                let exp_ge = (from..bits).find(|&j| naive[j]);
                assert_eq!(bs.find_next_set_ge(from), exp_ge);

                // Cyclic
                let exp_cyc = exp_ge.or_else(|| (0..from).find(|&j| naive[j]));
                assert_eq!(bs.find_next_set_cyclic(from), exp_cyc);
            }
        }
    }
}

// ============================================================================
// Kani Bounded Model Checking Proofs
// ============================================================================
//
// These proofs provide bounded verification of TimingWheel invariants using
// Kani's symbolic execution. They complement the property-based tests in
// timing_wheel_tests.rs by exhaustively exploring all states within bounds.
//
// Bounded sizes (wheel_size=8, cap=8) are used because:
// - Kani exhaustively explores state space; exponential blowup with size
// - Small sizes still exercise all code paths
// - Larger sizes are tested by proptest (unbounded, probabilistic)
// - Together: bounded proof + probabilistic coverage = high confidence
//
// Run with: cargo kani --features kani
// Run specific proof: cargo kani --features kani --harness verify_never_fires_early

#[cfg(kani)]
mod kani_proofs {
    use crate::{Bitset2, PushError, PushOutcome, TimingWheel};

    // ========================================================================
    // TimingWheel Proofs
    // ========================================================================

    /// Verifies that items never fire before their hi_end time.
    ///
    /// This is the core correctness property from the invariants (line 9-10):
    /// "Items are guaranteed to never fire early (before hi_end)"
    ///
    /// Bounded: wheel_size=8, cap=8, single push + drain operation.
    #[kani::proof]
    #[kani::unwind(20)]
    fn verify_never_fires_early() {
        // G=8: bucket key = ceil(hi_end / 8)
        // wheel_size will be >= 8 for horizon=56
        let mut tw: TimingWheel<u64, 8> = TimingWheel::new(56, 8);

        let hi_end: u64 = kani::any();
        kani::assume(hi_end <= 56); // Within horizon

        if let Ok(PushOutcome::Scheduled) = tw.push(hi_end, hi_end) {
            let now: u64 = kani::any();
            kani::assume(now <= 64);

            tw.advance_and_drain(now, |val| {
                // Core invariant: item should never fire before its hi_end
                kani::assert(val <= now, "Item fired before its hi_end!");
            });
        }
    }

    /// Verifies pool coherence: every node is free XOR in-use after operations.
    ///
    /// From invariants: the node pool is partitioned between free list and
    /// bucket lists, with no overlap.
    ///
    /// Bounded: 4 pushes, partial drain, then validate.
    #[kani::proof]
    #[kani::unwind(20)]
    fn verify_pool_coherence() {
        let mut tw: TimingWheel<u32, 8> = TimingWheel::new(56, 8);

        // Push some items to different buckets
        for i in 0u32..4 {
            let _ = tw.push((i as u64) * 8 + 1, i);
        }

        // Partial drain to exercise node freeing
        tw.advance_and_drain(20, |_| {});

        // debug_validate checks that every node is either free or in a bucket list,
        // never both, and counts match
        tw.debug_validate();
    }

    /// Verifies TooFarInFuture is returned for items beyond horizon.
    ///
    /// From invariants (line 94): "key < cursor_abs + wheel_size" must hold
    /// for successful insertion.
    #[kani::proof]
    fn verify_horizon_enforcement() {
        let mut tw: TimingWheel<u32, 8> = TimingWheel::new(56, 8);

        // For horizon=56, G=8: wheel_size = ceil((56+7)/8) + 1 = 9, rounded to 16 (pow2)
        // Actually let's compute: w_required = ceil((56+7)/8) + 1 = ceil(63/8) + 1 = 8 + 1 = 9
        // next_pow2(9) = 16
        // So max_key = cursor_abs + 16 = 0 + 16 = 16
        // hi_end = 129 -> key = ceil(129/8) = 17 >= 16, should fail

        let result = tw.push(129, 0);

        kani::assert(
            matches!(result, Err(PushError::TooFarInFuture { .. })),
            "Should reject item beyond horizon",
        );
    }

    /// Verifies slot occupancy consistency: head[slot] == NONE_U32 iff occ bit is clear.
    ///
    /// From invariants (line 95-96): "head[slot] == NONE_U32 iff the slot is empty.
    /// When empty, tail is NONE_U32 and the occupancy bit is clear."
    #[kani::proof]
    #[kani::unwind(20)]
    fn verify_slot_occupancy_consistency() {
        let mut tw: TimingWheel<u32, 8> = TimingWheel::new(56, 8);

        // Push to a slot
        tw.push(8, 1).unwrap(); // key = ceil(8/8) = 1, slot = 1

        // debug_validate checks head/tail/occ consistency
        tw.debug_validate();

        // Drain
        tw.advance_and_drain(16, |_| {});

        // Verify again after drain
        tw.debug_validate();
    }

    /// Verifies items in same bucket drain in insertion order (FIFO).
    ///
    /// From design: "Each slot is a FIFO list of nodes" and
    /// "Drain order: A -> B -> C (FIFO)"
    #[kani::proof]
    #[kani::unwind(20)]
    fn verify_fifo_ordering() {
        let mut tw: TimingWheel<u32, 8> = TimingWheel::new(56, 8);

        // All map to same bucket key=1 (hi_end in (0,8] for G=8)
        // ceil(1/8)=1, ceil(2/8)=1, ceil(7/8)=1
        tw.push(1, 0).unwrap();
        tw.push(2, 1).unwrap();
        tw.push(7, 2).unwrap();

        let mut last_id: i32 = -1;
        tw.advance_and_drain(8, |id| {
            kani::assert((id as i32) > last_id, "FIFO violation!");
            last_id = id as i32;
        });
    }

    /// Verifies monotonicity: time cannot go backwards.
    ///
    /// From invariants (line 99): "now_offset passed to advance_and_drain
    /// must be monotone non-decreasing."
    ///
    /// This proof verifies that going backwards is a no-op (doesn't corrupt state).
    #[kani::proof]
    #[kani::unwind(20)]
    fn verify_monotonicity_no_corruption() {
        let mut tw: TimingWheel<u32, 8> = TimingWheel::new(56, 8);

        tw.push(16, 1).unwrap();
        tw.push(24, 2).unwrap();

        // Advance forward
        tw.advance_and_drain(20, |_| {});

        // Try to go backwards - should return 0 and not corrupt
        let drained = tw.advance_and_drain(10, |_| {
            kani::assert(false, "Should not drain anything when going backwards");
        });

        kani::assert(drained == 0, "Should return 0 when time goes backwards");

        // Structure should still be valid
        tw.debug_validate();
    }

    /// Verifies reset restores the wheel to initial state.
    #[kani::proof]
    #[kani::unwind(20)]
    fn verify_reset() {
        let mut tw: TimingWheel<u32, 8> = TimingWheel::new(56, 8);

        // Push some items
        tw.push(8, 1).unwrap();
        tw.push(16, 2).unwrap();

        // Reset
        tw.reset();

        kani::assert(tw.len() == 0, "len should be 0 after reset");
        kani::assert(tw.is_empty(), "should be empty after reset");

        // Should be able to push again from time 0
        let result = tw.push(8, 3);
        kani::assert(result.is_ok(), "should be able to push after reset");
    }

    // ========================================================================
    // Bitset2 Proofs
    // ========================================================================

    /// Verifies Bitset2 set/clear/find consistency.
    ///
    /// From Bitset2 invariants (line 196-197): "l1 bit i is set iff l0[i] != 0"
    #[kani::proof]
    #[kani::unwind(5)]
    fn verify_bitset_set_find_consistency() {
        let mut bs = Bitset2::new(64);

        let idx: usize = kani::any();
        kani::assume(idx < 64);

        bs.set(idx);
        kani::assert(bs.any(), "any() should be true after set");

        let found = bs.find_next_set_ge(0);
        kani::assert(found.is_some(), "Should find set bit");
        kani::assert(found.unwrap() <= idx, "Found bit should be <= set bit");
    }

    /// Verifies Bitset2 clear removes the bit correctly.
    #[kani::proof]
    fn verify_bitset_clear() {
        let mut bs = Bitset2::new(64);

        let idx: usize = kani::any();
        kani::assume(idx < 64);

        bs.set(idx);
        kani::assert(bs.is_set(idx), "Bit should be set after set()");

        bs.clear(idx);
        kani::assert(!bs.is_set(idx), "Bit should not be set after clear()");
    }

    /// Verifies Bitset2 any() tracks count correctly.
    #[kani::proof]
    fn verify_bitset_any_count() {
        let mut bs = Bitset2::new(64);

        kani::assert(!bs.any(), "Empty bitset should have any() = false");

        let idx: usize = kani::any();
        kani::assume(idx < 64);

        bs.set(idx);
        kani::assert(bs.any(), "Bitset with one bit should have any() = true");

        bs.clear(idx);
        kani::assert(
            !bs.any(),
            "Bitset after clearing only bit should have any() = false",
        );
    }

    /// Verifies Bitset2 clear_all resets everything.
    #[kani::proof]
    #[kani::unwind(5)]
    fn verify_bitset_clear_all() {
        let mut bs = Bitset2::new(64);

        // Set a few bits
        let idx1: usize = kani::any();
        let idx2: usize = kani::any();
        kani::assume(idx1 < 64);
        kani::assume(idx2 < 64);

        bs.set(idx1);
        bs.set(idx2);

        bs.clear_all();

        kani::assert(!bs.any(), "any() should be false after clear_all");
        kani::assert(
            bs.find_next_set_ge(0).is_none(),
            "find_next_set_ge should return None after clear_all",
        );
    }

    /// Verifies Bitset2 find_next_set_ge returns correct ordering.
    #[kani::proof]
    fn verify_bitset_find_ordering() {
        let mut bs = Bitset2::new(64);

        let idx1: usize = kani::any();
        let idx2: usize = kani::any();
        kani::assume(idx1 < 64);
        kani::assume(idx2 < 64);
        kani::assume(idx1 < idx2); // idx1 is strictly less

        bs.set(idx1);
        bs.set(idx2);

        // Finding from 0 should return idx1 (the smaller one)
        let found = bs.find_next_set_ge(0);
        kani::assert(found == Some(idx1), "Should find smaller index first");

        // Finding from idx1+1 should return idx2
        let found2 = bs.find_next_set_ge(idx1 + 1);
        kani::assert(
            found2 == Some(idx2),
            "Should find idx2 when starting after idx1",
        );
    }
}
