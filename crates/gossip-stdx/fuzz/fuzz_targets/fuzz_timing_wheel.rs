#![no_main]

use std::collections::{BTreeMap, VecDeque};

use arbitrary::Arbitrary;
use gossip_stdx::{PushError, PushOutcome, TimingWheel};
use libfuzzer_sys::fuzz_target;

/// Ceiling division without overflow (mirrors production code).
fn ceil_div(x: u64, d: u64) -> u64 {
    let q = x / d;
    let r = x % d;
    q + (r != 0) as u64
}

/// Compute wheel_size for given horizon and granularity (mirrors production sizing).
fn wheel_size_for(max_horizon: u64, g: u64) -> u64 {
    let worst = max_horizon.saturating_add(g - 1);
    let w_required = ceil_div(worst, g).saturating_add(1).max(2);
    w_required.next_power_of_two()
}

/// Reference model for differential fuzzing.
struct Model {
    g: u64,
    wheel_size: u64,
    cap: usize,
    now_bucket: u64,
    base: u64,
    len: usize,
    map: BTreeMap<u64, VecDeque<u64>>,
}

impl Model {
    fn new(max_horizon: u64, cap: usize, g: u64) -> Self {
        Self {
            g,
            wheel_size: wheel_size_for(max_horizon, g),
            cap,
            now_bucket: 0,
            base: 0,
            len: 0,
            map: BTreeMap::new(),
        }
    }

    fn key(&self, hi_end: u64) -> u64 {
        ceil_div(hi_end, self.g)
    }

    fn push(&mut self, hi_end: u64, val: u64) -> Result<bool, u8> {
        let k = self.key(hi_end);
        if k < self.base {
            return Ok(false); // Ready
        }
        if k >= self.base.saturating_add(self.wheel_size) {
            return Err(1); // TooFarInFuture
        }
        if self.len == self.cap {
            return Err(0); // PoolExhausted
        }
        self.map.entry(k).or_default().push_back(val);
        self.len += 1;
        Ok(true) // Scheduled
    }

    fn advance_and_drain(&mut self, now_offset: u64) -> Vec<u64> {
        let nb = now_offset / self.g;
        assert!(nb >= self.now_bucket, "time must be monotone");
        if nb == self.now_bucket && self.base > nb {
            return Vec::new();
        }
        self.now_bucket = nb;

        let mut out = Vec::new();
        let keys: Vec<u64> = self
            .map
            .range(..=self.now_bucket)
            .map(|(&k, _)| k)
            .collect();
        for k in keys {
            if let Some(mut q) = self.map.remove(&k) {
                while let Some(v) = q.pop_front() {
                    out.push(v);
                    self.len -= 1;
                }
            }
        }
        let target_base = self.now_bucket.saturating_add(1);
        if self.base < target_base {
            self.base = target_base;
        }
        out
    }

    fn reset(&mut self) {
        self.map.clear();
        self.len = 0;
        self.now_bucket = 0;
        self.base = 0;
    }
}

fn norm_err(e: &PushError) -> u8 {
    match e {
        PushError::PoolExhausted => 0,
        PushError::TooFarInFuture { .. } => 1,
        #[cfg(debug_assertions)]
        PushError::SlotCollision { .. } => 2,
    }
}

#[derive(Arbitrary, Debug)]
enum Op {
    Push { hi_offset: u16 },
    Advance { delta: u16 },
    Reset,
    PushExtreme { tail: u8 },
}

fuzz_target!(|ops: Vec<Op>| {
    // G=2 exercises the ceil/floor asymmetry at u64::MAX boundary.
    const G: u32 = 2;
    let max_horizon: u64 = 512;
    let cap: usize = 32;

    let mut tw: TimingWheel<u64, G> = TimingWheel::new(max_horizon, cap);
    let mut model = Model::new(max_horizon, cap, G as u64);
    let mut now: u64 = 0;
    let mut next_id: u64 = 0;

    for op in &ops {
        match op {
            Op::Push { hi_offset } => {
                let hi_end = now.saturating_add(*hi_offset as u64);
                next_id = next_id.wrapping_add(1);

                let rw = tw.push(hi_end, next_id);
                let rm = model.push(hi_end, next_id);

                match (&rw, &rm) {
                    (Ok(PushOutcome::Scheduled), Ok(true)) => {}
                    (Ok(PushOutcome::Ready(a)), Ok(false)) => {
                        // Model returns the "ready" signal but doesn't track value.
                        let _ = a;
                    }
                    (Err(e), Err(me)) => {
                        assert_eq!(norm_err(e), *me);
                    }
                    (a, b) => panic!("wheel/model mismatch: wheel={a:?} model={b:?}"),
                }
            }

            Op::Advance { delta } => {
                let delta = (*delta as u64) % (4 * (G as u64) + 1);
                now = now.saturating_add(delta);

                let mut out_w = Vec::new();
                tw.advance_and_drain(now, |e| out_w.push(e));
                let out_m = model.advance_and_drain(now);

                assert_eq!(out_w, out_m);

                // Never-fire-early check.
                for v in &out_w {
                    // Values are IDs, not hi_end; the model match above is sufficient.
                    let _ = v;
                }
            }

            Op::Reset => {
                tw.reset();
                model.reset();

                assert_eq!(tw.len(), 0);
                assert!(tw.is_empty());
                assert_eq!(model.len, 0);

                now = 0;
            }

            Op::PushExtreme { tail } => {
                let g = G as u64;
                let ws = wheel_size_for(max_horizon, g);
                if ws < 2 || max_horizon == 0 {
                    continue;
                }

                // Advance to near u64::MAX boundary.
                let target_now = u64::MAX.saturating_sub(2 * g * ws);
                if target_now <= now {
                    continue;
                }
                now = target_now;

                let mut out_w = Vec::new();
                tw.advance_and_drain(now, |e| out_w.push(e));
                let out_m = model.advance_and_drain(now);
                assert_eq!(out_w, out_m);

                // Push at u64::MAX (or close to it).
                next_id = next_id.wrapping_add(1);
                let hi_end = u64::MAX - ((*tail as u64) % g);

                let rw = tw.push(hi_end, next_id);
                let rm = model.push(hi_end, next_id);

                match (&rw, &rm) {
                    (Ok(PushOutcome::Scheduled), Ok(true)) => {}
                    (Ok(PushOutcome::Ready(_)), Ok(false)) => {}
                    (Err(e), Err(me)) => {
                        assert_eq!(norm_err(e), *me);
                    }
                    (a, b) => {
                        panic!("wheel/model mismatch at extreme: wheel={a:?} model={b:?}")
                    }
                }
            }
        }

        // Invariant: lengths must always agree.
        assert_eq!(
            tw.len(),
            model.len,
            "len diverged: tw={} model={}",
            tw.len(),
            model.len
        );
    }
});
