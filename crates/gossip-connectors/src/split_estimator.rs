//! Streaming byte-weighted split-point estimation utilities.
//!
//! This module provides a bounded-memory estimator that tracks the
//! byte-weighted median over a streaming, globally sorted key sequence.
//! It uses a T-Digest for weighted rank accumulation plus bounded key
//! checkpoints for robust key recovery.

use std::mem;

use tdigest::{Centroid, TDigest};

const MIN_COMPRESSION: usize = 32;
const MIN_KEY_SAMPLE_CAP: usize = 64;
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
/// Memory remains bounded by the configured compression and sample caps.
#[derive(Clone, Debug)]
pub(crate) struct StreamingSplitEstimator {
    digest: TDigest,
    compression: usize,
    sample_cap: usize,
    pending_flush_limit: usize,
    /// Checkpoints over ordinal rank (`0..count`) for zero-byte fallback and
    /// degenerate front-loaded cases.
    rank_samples: Vec<KeySample>,
    /// Checkpoints over cumulative byte weight for median-by-bytes recovery.
    byte_samples: Vec<KeySample>,
    pending_centroids: Vec<Centroid>,
    pending_sum: f64,
    pending_weight: f64,
    pending_min: f64,
    pending_max: f64,
    /// Total observed byte weight (saturating on overflow).
    total_bytes: u64,
    /// Total observed item count.
    count: u64,
}

impl StreamingSplitEstimator {
    pub(crate) const DEFAULT_COMPRESSION: usize = 256;

    /// Create a new streaming estimator.
    pub(crate) fn new(compression: usize) -> Self {
        let compression = compression.max(MIN_COMPRESSION);
        let sample_cap = compression
            .saturating_mul(KEY_SAMPLE_FACTOR)
            .max(MIN_KEY_SAMPLE_CAP);
        let pending_flush_limit = compression.max(MIN_COMPRESSION);
        Self {
            digest: TDigest::new_with_size(compression),
            compression,
            sample_cap,
            pending_flush_limit,
            rank_samples: Vec::new(),
            byte_samples: Vec::new(),
            pending_centroids: Vec::new(),
            pending_sum: 0.0,
            pending_weight: 0.0,
            pending_min: 0.0,
            pending_max: 0.0,
            total_bytes: 0,
            count: 0,
        }
    }

    /// Observe one key/value pair from the streaming walk.
    pub(crate) fn observe(&mut self, key: &[u8], file_size: u64) {
        let rank = self.count as f64;
        self.push_rank_sample(rank, key);
        self.count = self.count.saturating_add(1);

        self.total_bytes = self.total_bytes.saturating_add(file_size);

        if file_size == 0 {
            return;
        }

        let cumulative = self.total_bytes as f64;
        self.push_byte_sample(cumulative, key);

        let weight = file_size as f64;
        if self.pending_centroids.is_empty() {
            self.pending_min = rank;
            self.pending_max = rank;
        } else {
            self.pending_min = self.pending_min.min(rank);
            self.pending_max = self.pending_max.max(rank);
        }
        self.pending_sum += rank * weight;
        self.pending_weight += weight;
        self.pending_centroids.push(Centroid::new(rank, weight));

        if self.pending_centroids.len() >= self.pending_flush_limit {
            self.flush_pending();
        }
    }

    /// Estimate the split key closest to the byte-weighted median.
    ///
    /// Returns `None` until at least two keys have been observed.
    pub(crate) fn estimate_split_key(&self) -> Option<Vec<u8>> {
        if self.count < 2 {
            return None;
        }

        let max_rank = (self.count - 1) as f64;
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
        self.flush_pending();
        let other_digest = other.merged_digest_with_pending();
        if !other_digest.is_empty() {
            let current = mem::replace(&mut self.digest, TDigest::new_with_size(self.compression));
            self.digest = TDigest::merge_digests(vec![current, other_digest]);
        }

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
        while self.rank_samples.len() > self.sample_cap {
            self.compact_rank_samples();
        }
    }

    fn push_byte_sample(&mut self, position: f64, key: &[u8]) {
        self.byte_samples.push(KeySample {
            position,
            key: key.to_vec(),
        });
        while self.byte_samples.len() > self.sample_cap {
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

    fn flush_pending(&mut self) {
        let Some(pending_digest) = self.take_pending_digest() else {
            return;
        };
        let current = mem::replace(&mut self.digest, TDigest::new_with_size(self.compression));
        self.digest = TDigest::merge_digests(vec![current, pending_digest]);
    }

    fn take_pending_digest(&mut self) -> Option<TDigest> {
        let pending_len = self.pending_centroids.len();
        if pending_len == 0 {
            return None;
        }
        let centroids = mem::take(&mut self.pending_centroids);
        let digest = TDigest::new(
            centroids,
            self.pending_sum,
            self.pending_weight,
            self.pending_max,
            self.pending_min,
            pending_len.max(1),
        );
        self.pending_sum = 0.0;
        self.pending_weight = 0.0;
        self.pending_min = 0.0;
        self.pending_max = 0.0;
        Some(digest)
    }

    fn merged_digest_with_pending(&self) -> TDigest {
        if self.pending_centroids.is_empty() {
            return self.digest.clone();
        }
        let pending = TDigest::new(
            self.pending_centroids.clone(),
            self.pending_sum,
            self.pending_weight,
            self.pending_max,
            self.pending_min,
            self.pending_centroids.len().max(1),
        );
        TDigest::merge_digests(vec![self.digest.clone(), pending])
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

    #[cfg(test)]
    fn pending_len(&self) -> usize {
        self.pending_centroids.len()
    }

    #[cfg(test)]
    fn pending_cap(&self) -> usize {
        self.pending_flush_limit
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
