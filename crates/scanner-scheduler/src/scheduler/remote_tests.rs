use super::*;
use crate::scheduler::engine_stub::MockRule;
use crate::unified::events::VecEventSink;

// ========================================================================
// Mock Backend
// ========================================================================

#[derive(Clone)]
struct MockObj {
    key: Vec<u8>,
    data: Vec<u8>,
}

struct MockBackend {
    objs: Vec<MockObj>,
}

#[derive(Default)]
struct MockCursor {
    i: usize,
}

impl RemoteBackend for MockBackend {
    type Object = MockObj;
    type Cursor = MockCursor;
    type Error = &'static str;

    fn list_page(
        &self,
        cursor: &mut Self::Cursor,
        max: usize,
    ) -> Result<Vec<RemoteObject<Self::Object>>, Self::Error> {
        if cursor.i >= self.objs.len() {
            return Ok(Vec::new());
        }
        let end = (cursor.i + max).min(self.objs.len());
        let mut out = Vec::with_capacity(end - cursor.i);
        for j in cursor.i..end {
            let o = self.objs[j].clone();
            out.push(RemoteObject {
                handle: o.clone(),
                size: o.data.len() as u64,
                display: o.key.clone(),
            });
        }
        cursor.i = end;
        Ok(out)
    }

    fn fetch_range(
        &self,
        obj: &Self::Object,
        start: u64,
        dst: &mut [u8],
    ) -> Result<usize, Self::Error> {
        let s = start as usize;
        if s >= obj.data.len() {
            return Ok(0);
        }
        let end = (s + dst.len()).min(obj.data.len());
        let n = end - s;
        dst[..n].copy_from_slice(&obj.data[s..end]);
        Ok(n)
    }

    fn classify_error(&self, _err: &Self::Error) -> ErrorClass {
        ErrorClass::Permanent
    }
}

// ========================================================================
// Retryable Mock Backend
// ========================================================================

struct RetryBackend {
    obj: MockObj,
    fail_first_n: std::sync::atomic::AtomicU32,
}

impl RemoteBackend for RetryBackend {
    type Object = ();
    type Cursor = bool; // true = done
    type Error = &'static str;

    fn list_page(
        &self,
        cursor: &mut Self::Cursor,
        _max: usize,
    ) -> Result<Vec<RemoteObject<Self::Object>>, Self::Error> {
        if *cursor {
            return Ok(Vec::new());
        }
        *cursor = true;
        Ok(vec![RemoteObject {
            handle: (),
            size: self.obj.data.len() as u64,
            display: self.obj.key.clone(),
        }])
    }

    fn fetch_range(
        &self,
        _obj: &Self::Object,
        start: u64,
        dst: &mut [u8],
    ) -> Result<usize, Self::Error> {
        // Fail first N attempts
        let remaining = self.fail_first_n.load(Ordering::Relaxed);
        if remaining > 0 {
            self.fail_first_n.fetch_sub(1, Ordering::Relaxed);
            return Err("transient failure");
        }

        let s = start as usize;
        if s >= self.obj.data.len() {
            return Ok(0);
        }
        let end = (s + dst.len()).min(self.obj.data.len());
        let n = end - s;
        dst[..n].copy_from_slice(&self.obj.data[s..end]);
        Ok(n)
    }

    fn classify_error(&self, _err: &Self::Error) -> ErrorClass {
        ErrorClass::Retryable
    }
}

// ========================================================================
// Helper
// ========================================================================

fn test_engine(overlap: usize) -> MockEngine {
    MockEngine::new(
        vec![MockRule {
            name: "secret".to_string(),
            pattern: b"SECRET".to_vec(),
        }],
        overlap,
    )
}

fn small_config() -> RemoteConfig {
    RemoteConfig {
        cpu_workers: 2,
        io_threads: 2,
        chunk_size: 64,
        max_in_flight_objects: 16,
        object_queue_cap: 8,
        discover_batch: 8,
        pool_buffers: 8,
        retry: RetryPolicy {
            max_attempts: 3,
            base_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(10),
            jitter_pct: 10,
        },
        max_object_time: Some(Duration::from_secs(5)),
        seed: 42,
        dedupe_within_chunk: true,
        pin_threads: false,
    }
}

fn assert_perf_u64(actual: u64, expected: u64) {
    if cfg!(all(feature = "perf-stats", debug_assertions)) {
        assert_eq!(actual, expected);
    } else {
        assert_eq!(actual, 0);
    }
}

// ========================================================================
// Tests
// ========================================================================

#[test]
fn remote_pipeline_finds_secret() {
    let engine = Arc::new(test_engine(16));
    let backend = Arc::new(MockBackend {
        objs: vec![MockObj {
            key: b"obj-1".to_vec(),
            data: b"hello SECRET world".to_vec(),
        }],
    });
    let sink = Arc::new(VecEventSink::new());

    let (report, _metrics) = scan_remote(engine, backend, small_config(), sink.clone()).unwrap();

    assert_perf_u64(report.remote.objects_discovered, 1);
    assert_perf_u64(report.remote.objects_enqueued, 1);
    assert_perf_u64(report.io.objects_completed, 1);

    let out = sink.take();
    let out_str = String::from_utf8_lossy(&out);
    assert!(out_str.contains("secret"), "output: {}", out_str);
    assert!(out_str.contains("obj-1"), "output: {}", out_str);
}

#[test]
fn remote_pipeline_handles_boundary_spanning_secret() {
    // Force SECRET to span chunk boundary
    // chunk_size=8, overlap=6 means SECRET (6 bytes) can span
    let engine = Arc::new(test_engine(6));

    // Position SECRET so it starts near end of first chunk
    // First chunk: bytes 0-7, second chunk: bytes 2-9 (overlap=6)
    let data = b"xxSECRETyy"; // SECRET at positions 2-7

    let backend = Arc::new(MockBackend {
        objs: vec![MockObj {
            key: b"boundary-test".to_vec(),
            data: data.to_vec(),
        }],
    });
    let sink = Arc::new(VecEventSink::new());

    let cfg = RemoteConfig {
        chunk_size: 8,
        ..small_config()
    };

    let (report, _metrics) = scan_remote(engine, backend, cfg, sink.clone()).unwrap();

    assert_perf_u64(report.io.objects_completed, 1);

    let out = sink.take();
    let out_str = String::from_utf8_lossy(&out);

    // Note: With overlapping chunks, the same secret may be found in multiple
    // chunks. The current implementation only deduplicates within each chunk
    // (dedupe_within_chunk), not across chunks. Cross-chunk deduplication
    // would require a global findings collector which isn't implemented
    // for the remote scanner.
    //
    // For now, we verify the secret is found at least once.
    let count = out_str.matches("secret").count();
    assert!(
        count >= 1,
        "expected at least 1 finding, got {}: {}",
        count,
        out_str
    );
}

#[test]
fn remote_pipeline_handles_empty_backend() {
    let engine = Arc::new(test_engine(16));
    let backend = Arc::new(MockBackend { objs: vec![] });
    let sink = Arc::new(VecEventSink::new());

    let (report, _metrics) = scan_remote(engine, backend, small_config(), sink.clone()).unwrap();

    assert_perf_u64(report.remote.objects_discovered, 0);
    assert_perf_u64(report.io.objects_completed, 0);
}

#[test]
fn remote_pipeline_processes_multiple_objects() {
    let engine = Arc::new(test_engine(16));

    let objs: Vec<MockObj> = (0..10)
        .map(|i| MockObj {
            key: format!("obj-{}", i).into_bytes(),
            data: format!("file {} has SECRET here", i).into_bytes(),
        })
        .collect();

    let backend = Arc::new(MockBackend { objs });
    let sink = Arc::new(VecEventSink::new());

    let (report, _metrics) = scan_remote(engine, backend, small_config(), sink.clone()).unwrap();

    assert_perf_u64(report.remote.objects_discovered, 10);
    assert_perf_u64(report.io.objects_completed, 10);

    let out = sink.take();
    let out_str = String::from_utf8_lossy(&out);

    // Should find 10 secrets
    let count = out_str.matches("secret").count();
    assert_eq!(count, 10, "expected 10 findings, got {}", count);
}

#[test]
fn remote_pipeline_uses_cross_rule_dedupe_winner_selection() {
    let engine = Arc::new(MockEngine::new(
        vec![
            MockRule {
                name: "zeta".to_string(),
                pattern: b"SECRET".to_vec(),
            },
            MockRule {
                name: "alpha".to_string(),
                pattern: b"SECRET".to_vec(),
            },
        ],
        16,
    ));

    let backend = Arc::new(MockBackend {
        objs: vec![MockObj {
            key: b"dedupe-obj".to_vec(),
            data: b"hello SECRET world".to_vec(),
        }],
    });
    let sink = Arc::new(VecEventSink::new());

    let (_report, _metrics) = scan_remote(engine, backend, small_config(), sink.clone()).unwrap();

    let out = sink.take();
    let out_str = String::from_utf8_lossy(&out);

    // Both rules match the same bytes. Cross-rule dedupe should keep exactly
    // one finding and tie-break to the lexicographically smaller rule name.
    assert_eq!(out_str.matches("alpha").count(), 1, "output: {}", out_str);
    assert_eq!(out_str.matches("zeta").count(), 0, "output: {}", out_str);
}

#[test]
fn remote_pipeline_retries_transient_failures() {
    let engine = Arc::new(test_engine(16));

    let backend = Arc::new(RetryBackend {
        obj: MockObj {
            key: b"retry-obj".to_vec(),
            data: b"data with SECRET".to_vec(),
        },
        fail_first_n: std::sync::atomic::AtomicU32::new(2), // Fail twice, succeed on third
    });

    let sink = Arc::new(VecEventSink::new());

    let cfg = RemoteConfig {
        retry: RetryPolicy {
            max_attempts: 5,
            base_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(5),
            jitter_pct: 0,
        },
        ..small_config()
    };

    let (report, _metrics) = scan_remote(engine, backend, cfg, sink.clone()).unwrap();

    assert_perf_u64(report.io.objects_completed, 1);
    assert_perf_u64(report.io.retryable_errors, 2);
    assert_perf_u64(report.io.retries, 2);

    let out = sink.take();
    assert!(
        !out.is_empty(),
        "should have found the secret after retries"
    );
}

#[test]
fn backoff_respects_max_delay() {
    let policy = RetryPolicy {
        max_attempts: 10,
        base_delay: Duration::from_millis(100),
        max_delay: Duration::from_millis(500),
        jitter_pct: 0,
    };
    let mut rng = XorShift64::new(1);

    // After many attempts, delay should be capped at max_delay
    let d = compute_backoff(10, policy, &mut rng);
    assert_eq!(d, Duration::from_millis(500));
}

#[test]
fn backoff_applies_jitter() {
    let policy = RetryPolicy {
        max_attempts: 5,
        base_delay: Duration::from_millis(100),
        max_delay: Duration::from_secs(10),
        jitter_pct: 50,
    };

    let mut rng = XorShift64::new(42);

    // Collect several backoff values and verify they vary
    let values: Vec<Duration> = (0..10)
        .map(|_| compute_backoff(2, policy, &mut rng))
        .collect();

    // Base delay for attempt 2 is 200ms, jitter is Â±50% = Â±100ms
    // So values should be in [100ms, 300ms]
    for d in &values {
        assert!(
            *d >= Duration::from_millis(100) && *d <= Duration::from_millis(300),
            "backoff {} out of expected range",
            d.as_millis()
        );
    }

    // Values should not all be identical (jitter working)
    let unique: std::collections::HashSet<_> = values.iter().map(|d| d.as_nanos()).collect();
    assert!(unique.len() > 1, "jitter should produce varying values");
}

#[test]
fn config_validation_rejects_invalid() {
    let engine = test_engine(16);

    // chunk_size + overlap > BUFFER_LEN_MAX
    let cfg = RemoteConfig {
        chunk_size: BUFFER_LEN_MAX,
        ..Default::default()
    };

    let result = std::panic::catch_unwind(|| cfg.validate(&engine));
    assert!(result.is_err(), "should panic on oversized chunk");
}

// ========================================================================
// Partial Read Backend (contract violation test)
// ========================================================================

struct PartialReadBackend {
    obj: MockObj,
    /// Return only this many bytes per read (to simulate partial reads)
    bytes_per_read: usize,
}

impl RemoteBackend for PartialReadBackend {
    type Object = ();
    type Cursor = bool;
    type Error = &'static str;

    fn list_page(
        &self,
        cursor: &mut Self::Cursor,
        _max: usize,
    ) -> Result<Vec<RemoteObject<Self::Object>>, Self::Error> {
        if *cursor {
            return Ok(Vec::new());
        }
        *cursor = true;
        Ok(vec![RemoteObject {
            handle: (),
            size: self.obj.data.len() as u64,
            display: self.obj.key.clone(),
        }])
    }

    fn fetch_range(
        &self,
        _obj: &Self::Object,
        start: u64,
        dst: &mut [u8],
    ) -> Result<usize, Self::Error> {
        let s = start as usize;
        if s >= self.obj.data.len() {
            return Ok(0);
        }
        // Intentionally return partial read (violates contract)
        let max_read = self.bytes_per_read.min(dst.len());
        let end = (s + max_read).min(self.obj.data.len());
        let n = end - s;
        dst[..n].copy_from_slice(&self.obj.data[s..end]);
        Ok(n)
    }

    fn classify_error(&self, _err: &Self::Error) -> ErrorClass {
        ErrorClass::Permanent
    }
}

#[test]
fn partial_reads_cause_object_failure() {
    // This test verifies that partial reads (contract violations) are detected
    // and cause the object to fail rather than silently skipping bytes.
    let engine = Arc::new(test_engine(16));

    // Backend returns only 17 bytes per read, but we request more
    let backend = Arc::new(PartialReadBackend {
        obj: MockObj {
            key: b"partial-test".to_vec(),
            data: b"lots of data here with SECRET somewhere".to_vec(),
        },
        bytes_per_read: 17,
    });

    let sink = Arc::new(VecEventSink::new());

    let cfg = RemoteConfig {
        chunk_size: 64, // Larger than bytes_per_read
        ..small_config()
    };

    let (report, _metrics) = scan_remote(engine, backend, cfg, sink.clone()).unwrap();

    // Object should fail because partial reads violate the contract
    if cfg!(all(feature = "perf-stats", debug_assertions)) {
        assert_eq!(
            report.io.objects_failed, 1,
            "partial reads should cause object failure"
        );
    } else {
        assert_eq!(
            report.io.objects_failed, 0,
            "partial reads should cause object failure"
        );
    }
    assert_perf_u64(report.io.objects_completed, 0);
}

// ========================================================================
// Permanent Error Backend
// ========================================================================

struct PermanentErrorBackend {
    obj: MockObj,
}

impl RemoteBackend for PermanentErrorBackend {
    type Object = ();
    type Cursor = bool;
    type Error = &'static str;

    fn list_page(
        &self,
        cursor: &mut Self::Cursor,
        _max: usize,
    ) -> Result<Vec<RemoteObject<Self::Object>>, Self::Error> {
        if *cursor {
            return Ok(Vec::new());
        }
        *cursor = true;
        Ok(vec![RemoteObject {
            handle: (),
            size: self.obj.data.len() as u64,
            display: self.obj.key.clone(),
        }])
    }

    fn fetch_range(
        &self,
        _obj: &Self::Object,
        _start: u64,
        _dst: &mut [u8],
    ) -> Result<usize, Self::Error> {
        // Always return permanent error
        Err("permanent failure")
    }

    fn classify_error(&self, _err: &Self::Error) -> ErrorClass {
        ErrorClass::Permanent
    }
}

#[test]
fn permanent_errors_cause_immediate_failure() {
    let engine = Arc::new(test_engine(16));

    let backend = Arc::new(PermanentErrorBackend {
        obj: MockObj {
            key: b"perm-error-test".to_vec(),
            data: b"data with SECRET".to_vec(),
        },
    });

    let sink = Arc::new(VecEventSink::new());

    let (report, _metrics) = scan_remote(engine, backend, small_config(), sink.clone()).unwrap();

    assert_perf_u64(report.io.objects_failed, 1);
    assert_perf_u64(report.io.objects_completed, 0);
    assert_perf_u64(report.io.permanent_errors, 1);
    // No retries for permanent errors
    assert_perf_u64(report.io.retries, 0);
}

#[test]
fn retryable_errors_exhaust_attempts() {
    let engine = Arc::new(test_engine(16));

    // Fail more times than max_attempts to ensure exhaustion
    let backend = Arc::new(RetryBackend {
        obj: MockObj {
            key: b"retry-exhaust".to_vec(),
            data: b"data with SECRET".to_vec(),
        },
        fail_first_n: std::sync::atomic::AtomicU32::new(100), // More than max_attempts
    });

    let sink = Arc::new(VecEventSink::new());

    let cfg = RemoteConfig {
        retry: RetryPolicy {
            max_attempts: 3,
            base_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(5),
            jitter_pct: 0,
        },
        ..small_config()
    };

    let (report, _metrics) = scan_remote(engine, backend, cfg, sink.clone()).unwrap();

    assert_perf_u64(report.io.objects_failed, 1);
    assert_perf_u64(report.io.objects_completed, 0);
    // Should have 3 retryable errors (initial + 2 retries)
    assert_perf_u64(report.io.retryable_errors, 3);
    // Retries = attempts - 1 = 2
    assert_perf_u64(report.io.retries, 2);
}
