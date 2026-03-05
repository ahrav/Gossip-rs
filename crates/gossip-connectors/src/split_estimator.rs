//! Streaming byte-weighted split-point estimation utilities.
//!
//! This module provides a bounded-memory estimator that tracks the
//! byte-weighted median over a streaming, globally sorted key sequence.
//! It maintains bounded key checkpoints over both ordinal rank and
//! cumulative byte weight for robust key recovery.

use std::mem;

const MIN_SAMPLE_CAP: usize = 64;
const KEY_SAMPLE_FACTOR: usize = 4;

#[derive(Clone, Debug)]
struct KeySample {
    position: f64,
    key: Vec<u8>,
}

/// Bounded-memory estimator for byte-weighted split keys in streaming walks.
///
/// Callers feed observed `(key, file_size)` pairs in globally sorted key order.
/// `estimate_split_key` returns an observed key near the byte-weighted median.
/// Memory remains bounded by the configured sample cap.
#[derive(Clone, Debug)]
pub(crate) struct StreamingSplitEstimator {
    sample_cap: usize,
    /// Checkpoints over ordinal rank (`0..count`) for zero-byte fallback and
    /// degenerate front-loaded cases.
    rank_samples: Vec<KeySample>,
    /// Checkpoints over cumulative byte weight for median-by-bytes recovery.
    byte_samples: Vec<KeySample>,
    /// Total observed byte weight (saturating on overflow).
    total_bytes: u64,
    /// Total observed item count.
    count: u64,
}

impl StreamingSplitEstimator {
    pub(crate) const DEFAULT_COMPRESSION: usize = 256;

    /// Create a new streaming estimator.
    ///
    /// `compression` controls the sample-cap sizing: higher values retain more
    /// key checkpoints for better accuracy at the cost of more memory.
    pub(crate) fn new(compression: usize) -> Self {
        let compression = compression.max(32);
        let sample_cap = compression
            .saturating_mul(KEY_SAMPLE_FACTOR)
            .max(MIN_SAMPLE_CAP);
        Self {
            sample_cap,
            rank_samples: Vec::new(),
            byte_samples: Vec::new(),
            total_bytes: 0,
            count: 0,
        }
    }

    /// Observe one key/value pair from the streaming walk.
    pub(crate) fn observe(&mut self, key: &[u8], file_size: u64) {
        let rank = self.count as f64;
        self.push_rank_sample(rank, key);
        self.count = self.count.saturating_add(1);

        if file_size == 0 {
            self.total_bytes = self.total_bytes.saturating_add(file_size);
            return;
        }

        // Sample the cumulative position at the *start* of this file's byte
        // range so that `nearest_sample(byte_samples, total/2)` selects the
        // file whose range straddles the weighted median rather than the file
        // whose cumulative end is nearest.
        let cumulative = self.total_bytes as f64;
        self.push_byte_sample(cumulative, key);

        self.total_bytes = self.total_bytes.saturating_add(file_size);
    }

    /// Estimate the split key closest to the byte-weighted median.
    ///
    /// Returns `None` until at least two keys have been observed.
    pub(crate) fn estimate_split_key(&self) -> Option<Vec<u8>> {
        if self.count < 2 {
            return None;
        }

        let max_rank = (self.count - 1) as f64;
        // Clamp the lower bound to rank 1 so the estimator never returns the
        // very first key (rank 0).  A "split at the first item" leaves zero
        // keys on the left side and is degenerate for every downstream
        // consumer.  When count == 2, max_rank == 1 and this collapses to
        // exactly rank 1, which is the only valid split for two items.
        let min_rank = 1.0_f64.min(max_rank);
        let midpoint_rank = (self.count / 2) as f64;

        if self.total_bytes == 0 {
            let rank = midpoint_rank.clamp(min_rank, max_rank);
            return Self::nearest_sample(&self.rank_samples, rank).map(ToOwned::to_owned);
        }

        let target_weight = self.total_bytes as f64 / 2.0;
        let mut candidate = Self::nearest_sample(&self.byte_samples, target_weight)
            .or_else(|| {
                let rank = midpoint_rank.clamp(min_rank, max_rank);
                Self::nearest_sample(&self.rank_samples, rank)
            })?
            .to_vec();

        // Keep split semantics aligned with existing connectors: avoid
        // degenerate "first item" splits when weight is front-loaded.
        if self
            .rank_samples
            .first()
            .is_some_and(|first| candidate.as_slice() == first.key.as_slice())
        {
            let rank = midpoint_rank.clamp(min_rank, max_rank);
            if let Some(fallback) = Self::nearest_sample(&self.rank_samples, rank) {
                candidate = fallback.to_vec();
            }
        }

        Some(candidate)
    }

    /// Merge another estimator into this one.
    ///
    /// Merge ordering assumes `other` represents keys that occur after `self`
    /// in global key order (append-style merge).
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn merge(&mut self, other: &Self) {
        let rank_offset = self.count as f64;
        let byte_offset = self.total_bytes as f64;
        self.count = self.count.saturating_add(other.count);
        self.total_bytes = self.total_bytes.saturating_add(other.total_bytes);

        for sample in &other.rank_samples {
            self.rank_samples.push(KeySample {
                position: sample.position + rank_offset,
                key: sample.key.clone(),
            });
        }
        while self.rank_samples.len() > self.sample_cap {
            self.compact_rank_samples();
        }

        for sample in &other.byte_samples {
            self.byte_samples.push(KeySample {
                position: sample.position + byte_offset,
                key: sample.key.clone(),
            });
        }
        while self.byte_samples.len() > self.sample_cap {
            self.compact_byte_samples();
        }
    }

    fn push_rank_sample(&mut self, position: f64, key: &[u8]) {
        self.rank_samples.push(KeySample {
            position,
            key: key.to_vec(),
        });
        if self.rank_samples.len() > self.sample_cap {
            self.compact_rank_samples();
        }
    }

    fn push_byte_sample(&mut self, position: f64, key: &[u8]) {
        self.byte_samples.push(KeySample {
            position,
            key: key.to_vec(),
        });
        if self.byte_samples.len() > self.sample_cap {
            self.compact_byte_samples();
        }
    }

    fn compact_rank_samples(&mut self) {
        if self.rank_samples.len() <= self.sample_cap {
            return;
        }
        // Rebalance to evenly spaced samples in stream-order index space.
        let old = mem::take(&mut self.rank_samples);
        let len = old.len();
        if self.sample_cap == 1 {
            self.rank_samples.push(
                old.last()
                    .expect("len > sample_cap implies at least one sample")
                    .clone(),
            );
            return;
        }
        self.rank_samples = (0..self.sample_cap)
            .map(|i| {
                let idx = i * (len - 1) / (self.sample_cap - 1);
                old[idx].clone()
            })
            .collect();
    }

    fn compact_byte_samples(&mut self) {
        if self.byte_samples.len() <= self.sample_cap {
            return;
        }
        // Rebalance by cumulative-byte position so 50th-percentile byte
        // lookups remain stable under strongly skewed size distributions.
        let old = mem::take(&mut self.byte_samples);
        let len = old.len();
        if self.sample_cap == 1 {
            self.byte_samples.push(
                old.last()
                    .expect("len > sample_cap implies at least one sample")
                    .clone(),
            );
            return;
        }

        let first = old.first().expect("non-empty samples").position;
        let last = old.last().expect("non-empty samples").position;

        // When all positions are identical, position-based interpolation
        // collapses and the loop below degenerates to sequential index
        // picking via the `pick <= prev` guard.  Short-circuit with
        // index-based even spacing for clarity.
        if first == last {
            self.byte_samples = (0..self.sample_cap)
                .map(|i| {
                    let idx = i * (len - 1) / (self.sample_cap - 1);
                    old[idx].clone()
                })
                .collect();
            return;
        }

        let mut compacted = Vec::with_capacity(self.sample_cap);
        let mut cursor = 0usize;
        let mut last_pick: Option<usize> = None;
        for i in 0..self.sample_cap {
            let target = if i == 0 {
                first
            } else if i + 1 == self.sample_cap {
                last
            } else {
                first + (last - first) * (i as f64) / ((self.sample_cap - 1) as f64)
            };

            while cursor + 1 < len && old[cursor + 1].position < target {
                cursor += 1;
            }

            let mut pick = if cursor + 1 < len {
                let next = cursor + 1;
                let d_curr = (old[cursor].position - target).abs();
                let d_next = (old[next].position - target).abs();
                if d_next < d_curr { next } else { cursor }
            } else {
                cursor
            };

            if let Some(prev) = last_pick
                && pick <= prev
            {
                pick = prev + 1;
            }
            let remaining = self.sample_cap - i - 1;
            let max_pick = len - remaining - 1;
            if pick > max_pick {
                pick = max_pick;
            }

            compacted.push(old[pick].clone());
            last_pick = Some(pick);
            cursor = pick;
        }

        self.byte_samples = compacted;
    }

    fn nearest_sample(samples: &[KeySample], target: f64) -> Option<&[u8]> {
        if samples.is_empty() {
            return None;
        }
        let idx = samples.partition_point(|sample| sample.position < target);
        if idx == 0 {
            return samples.first().map(|sample| sample.key.as_slice());
        }
        if idx >= samples.len() {
            return samples.last().map(|sample| sample.key.as_slice());
        }
        let prev = &samples[idx - 1];
        let next = &samples[idx];
        if target - prev.position <= next.position - target {
            Some(prev.key.as_slice())
        } else {
            Some(next.key.as_slice())
        }
    }

    #[cfg(test)]
    fn rank_sample_len(&self) -> usize {
        self.rank_samples.len()
    }

    #[cfg(test)]
    fn byte_sample_len(&self) -> usize {
        self.byte_samples.len()
    }

    #[cfg(test)]
    fn sample_cap(&self) -> usize {
        self.sample_cap
    }
}

impl Default for StreamingSplitEstimator {
    fn default() -> Self {
        Self::new(Self::DEFAULT_COMPRESSION)
    }
}

#[cfg(test)]
#[path = "split_estimator_tests.rs"]
mod tests;
