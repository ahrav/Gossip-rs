//! Deterministic scanner simulation runner.
//!
//! Scope:
//! - Deterministic, single-threaded simulation of multi-worker discover + scan scheduling.
//! - Chunked scanning with overlap deduplication using the real `Engine`.
//! - Archive roots are expanded via `archive::scan` into virtual entry objects.
//! - Fault injection, IO latency, and cancellations are modeled deterministically
//!   via a simulated clock and an IO event queue.
//!
//! Determinism:
//! - File discovery order is lexicographic by raw path bytes.
//! - Discovery honors type-hint metadata fallbacks for unknown file types.
//! - Schedule decisions are driven by a seedable RNG in `SimExecutor`.
//! - IO faults are keyed by path + read index and are schedule-independent.
//! - Output ordering is emission order; a stability oracle compares sets.
//! - Archive entry paths are stored in a `VirtualPathTable` with a byte cap.
//! - Trace ring records schedule choices and archive lifecycle events.
//!
//! Oracles implemented here:
//! - Termination: enforce a max-steps bound to catch hangs.
//! - Monotonic progress: chunk offsets and prefix boundaries never move backward.
//! - Overlap dedupe: no finding may be entirely contained in the overlap prefix.
//! - Duplicate suppression: emitted findings are unique under a normalized key.
//! - In-flight budget: file-task permits never exceed `max_in_flight_objects`.
//! - Ground-truth: expected secrets are found (for fully observed objects),
//!   and no unexpected findings appear.
//! - Differential: chunked results match a single-chunk scan over the observed
//!   byte stream (post-faults). Non-root findings are compared only when
//!   `SCANNER_SIM_STRICT_NON_ROOT=1` is set.
//! - Stability: repeated runs with different schedule seeds yield the same set.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::api::{DecodeStep, STEP_ROOT, TransformId};
use crate::archive::formats::tar::TAR_BLOCK_LEN;
use crate::archive::scan::{
    ArchiveEnd, ArchiveEntrySink, ArchiveScratch, EntryChunk, EntryMeta, scan_bzip2_stream,
    scan_gzip_stream, scan_tar_stream, scan_tarbz2_stream, scan_targz_stream, scan_zip_source,
};
use crate::archive::{
    ArchiveConfig, ArchiveKind, ArchiveSkipReason, ArchiveStats, detect_kind_from_name_bytes,
    sniff_kind_from_header,
};
use crate::sim::artifact::TraceDump;
use crate::sim::clock::SimClock;
use crate::sim::executor::{SimExecutor, SimTask, SimTaskId, SimTaskState, StepResult};
use crate::sim::fault::{Corruption, FaultInjector, FaultPlan, IoFault, ReadFault};
use crate::sim::fs::{SimFileHandle, SimFs, SimFsSpec, SimNodeSpec, SimPath, SimTypeHint};
use crate::sim::trace::{TraceEvent, TraceRing};
use crate::sim_scanner::scenario::{ExpectedDisposition, RunConfig, Scenario, SecretRepr, SpanU32};
use crate::sim_scanner::vpath_table::VirtualPathTable;
use crate::{Engine, FileId, FindingRec, ScanScratch};

/// Result of a simulation run.
///
/// `Ok` returns raw `FindingRec` entries in emission order (not sorted).
#[derive(Clone, Debug)]
pub enum RunOutcome {
    Ok { findings: Vec<FindingRec> },
    Failed(FailureReport),
}

/// Structured failure report captured in artifacts.
///
/// `step` is the simulation step index where the failure was detected.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FailureReport {
    pub kind: FailureKind,
    pub message: String,
    pub step: u64,
}

/// Failure classification for deterministic triage.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum FailureKind {
    /// A panic escaped from engine or harness logic.
    Panic,
    /// The simulation failed to reach a terminal state within the step budget.
    Hang,
    /// An invariant about ordering, offsets, or dedupe was violated.
    InvariantViolation { code: u32 },
    /// A correctness oracle failed (ground-truth, differential, or archive).
    OracleMismatch,
    /// The same scenario produced different final findings across schedules.
    StabilityMismatch,
    /// Placeholder for unimplemented phases.
    Unimplemented,
}

const TRACE_RING_CAP: usize = 2048;

#[derive(Debug)]
struct TraceCollector {
    ring: TraceRing,
    full: Option<Vec<TraceEvent>>,
}

impl TraceCollector {
    fn new() -> Self {
        let capture_full = std::env::var_os("SIM_TRACE_FULL").is_some();
        Self {
            ring: TraceRing::new(TRACE_RING_CAP),
            full: capture_full.then(Vec::new),
        }
    }

    fn record(&mut self, ev: TraceEvent) {
        self.ring.push(ev.clone());
        if let Some(full) = &mut self.full {
            full.push(ev);
        }
    }

    fn dump(self) -> TraceDump {
        TraceDump {
            ring: self.ring.dump(),
            full: self.full,
        }
    }
}

/// Deterministic scanner simulation runner.
///
/// Preconditions:
/// - `cfg.overlap >= engine.required_overlap()`.
/// - `cfg.chunk_size > 0` and `cfg.workers > 0`.
pub struct ScannerSimRunner {
    cfg: RunConfig,
    schedule_seed: u64,
}

impl ScannerSimRunner {
    /// Create a new runner with a fixed schedule seed.
    pub fn new(cfg: RunConfig, schedule_seed: u64) -> Self {
        Self { cfg, schedule_seed }
    }

    /// Execute a single scenario under the current schedule seed and fault plan.
    ///
    /// If `cfg.stability_runs > 1`, replays the same scenario under additional
    /// schedule seeds and compares the normalized finding sets.
    pub fn run(&self, scenario: &Scenario, engine: &Engine, fault_plan: &FaultPlan) -> RunOutcome {
        let (outcome, _trace) = self.run_with_trace(scenario, engine, fault_plan);
        outcome
    }

    /// Execute a scenario and return the outcome plus trace data.
    pub fn run_with_trace(
        &self,
        scenario: &Scenario,
        engine: &Engine,
        fault_plan: &FaultPlan,
    ) -> (RunOutcome, TraceDump) {
        let (base_outcome, base_trace) =
            self.run_once_catch_with_trace(scenario, engine, fault_plan, self.schedule_seed);
        let base_findings = match base_outcome {
            RunOutcome::Ok { findings } => findings,
            fail => return (fail, base_trace),
        };

        if self.cfg.stability_runs <= 1 {
            return (
                RunOutcome::Ok {
                    findings: base_findings,
                },
                base_trace,
            );
        }

        let baseline = normalize_findings(&base_findings);
        for i in 1..self.cfg.stability_runs {
            let seed = self.schedule_seed.wrapping_add(i as u64);
            let (candidate_outcome, candidate_trace) =
                self.run_once_catch_with_trace(scenario, engine, fault_plan, seed);
            match candidate_outcome {
                RunOutcome::Ok { findings } => {
                    let candidate = normalize_findings(&findings);
                    if candidate != baseline {
                        return (
                            RunOutcome::Failed(FailureReport {
                                kind: FailureKind::StabilityMismatch,
                                message: format!(
                                    "stability mismatch between seeds {} and {}",
                                    self.schedule_seed, seed
                                ),
                                step: 0,
                            }),
                            candidate_trace,
                        );
                    }
                }
                fail => return (fail, candidate_trace),
            }
        }

        (
            RunOutcome::Ok {
                findings: base_findings,
            },
            base_trace,
        )
    }

    // Wrap a single run to convert panics into a structured failure.
    fn run_once_catch_with_trace(
        &self,
        scenario: &Scenario,
        engine: &Engine,
        fault_plan: &FaultPlan,
        seed: u64,
    ) -> (RunOutcome, TraceDump) {
        let mut trace = TraceCollector::new();
        let res = catch_unwind(AssertUnwindSafe(|| {
            self.run_once(scenario, engine, fault_plan, seed, &mut trace)
        }));
        let outcome = match res {
            Ok(outcome) => outcome,
            Err(payload) => RunOutcome::Failed(FailureReport {
                kind: FailureKind::Panic,
                message: panic_message(payload),
                step: 0,
            }),
        };
        (outcome, trace.dump())
    }

    /// Execute a single schedule with no stability replay.
    fn run_once(
        &self,
        scenario: &Scenario,
        engine: &Engine,
        fault_plan: &FaultPlan,
        seed: u64,
        trace: &mut TraceCollector,
    ) -> RunOutcome {
        if self.cfg.workers == 0 {
            return self.fail(
                FailureKind::InvariantViolation { code: 1 },
                "workers must be > 0",
                0,
            );
        }
        if self.cfg.chunk_size == 0 {
            return self.fail(
                FailureKind::InvariantViolation { code: 2 },
                "chunk_size must be > 0",
                0,
            );
        }

        let overlap = self.cfg.overlap as usize;
        if overlap < engine.required_overlap() {
            return self.fail(
                FailureKind::InvariantViolation { code: 10 },
                "overlap smaller than engine.required_overlap()",
                0,
            );
        }

        let fs = SimFs::from_spec(&scenario.fs);
        let files = discover_file_paths(&fs, &scenario.fs, self.cfg.max_file_size);
        let total_bytes = total_file_bytes(&fs, &files);
        let fault_ops = estimate_fault_ops(fault_plan);
        let max_steps = resolve_max_steps(&self.cfg, files.len() as u64, total_bytes, fault_ops);

        let mut executor = SimExecutor::new(self.cfg.workers, seed);
        let mut tasks: Vec<ScannerTask> = Vec::new();
        let mut output = OutputCollector::new();
        let mut summaries: Vec<ObjectSummary> = Vec::new();
        let mut archive_roots: Vec<ArchiveRootSummary> = Vec::new();
        let mut clock = SimClock::new();
        let mut faults = FaultInjector::new(fault_plan.clone());
        let mut io_waiters: BTreeMap<u64, Vec<SimTaskId>> = BTreeMap::new();
        // Track file-task permits to mirror discovery backpressure invariants.
        let mut in_flight_objects: u32 = 0;
        let mut max_seen_in_flight: u32 = 0;
        // Set when discovery is blocked waiting for permits.
        let mut discover_waiting = false;

        let vpath_cap = vpath_bytes_cap(&files, &self.cfg.archive);
        let mut vpaths = VirtualPathTable::new(vpath_cap);
        let discovered =
            match build_discovered_files(&fs, &files, &mut vpaths, self.cfg.archive.enabled) {
                Ok(v) => v,
                Err(fail) => return RunOutcome::Failed(fail),
            };
        let mut archive_scratch = ArchiveScratch::<std::io::Cursor<Arc<[u8]>>>::new(
            &self.cfg.archive,
            self.cfg.chunk_size as usize,
            overlap,
        );
        #[cfg(any(test, feature = "sim-harness"))]
        if let Some(n) = self.cfg.archive_deadline_countdown {
            archive_scratch.set_deadline_check_countdown(Some(n));
        }
        let discover = DiscoverState::new(discovered);
        let discover_id = executor.spawn_external(SimTask {
            kind: TaskKind::Discover as u16,
        });
        trace.record(TraceEvent::TaskSpawn {
            task_id: discover_id.index() as u32,
            kind: TaskKind::Discover as u16,
        });
        insert_task(&mut tasks, discover_id, ScannerTask::Discover(discover));

        for step in 0..max_steps {
            deliver_due_io(&mut executor, &mut io_waiters, clock.now_ticks());

            if !executor.has_queued_tasks() {
                if all_tasks_completed(&executor, &tasks) {
                    let collected = output.finish();
                    summaries.sort_by_key(|s| s.file_id.0);
                    if in_flight_objects != 0 {
                        return self.fail(
                            FailureKind::InvariantViolation { code: 33 },
                            &format!(
                                "in-flight permits leaked at completion: {} outstanding (max_seen {})",
                                in_flight_objects, max_seen_in_flight
                            ),
                            step,
                        );
                    }
                    if let Err(fail) = self.run_oracles(
                        scenario,
                        engine,
                        &vpaths,
                        &archive_roots,
                        &collected,
                        &summaries,
                        step,
                    ) {
                        return RunOutcome::Failed(fail);
                    }
                    let CollectedFindings { recs: findings, .. } = collected;
                    return RunOutcome::Ok { findings };
                }
                if let Some(next_tick) = next_io_tick(&io_waiters) {
                    clock.advance_to(next_tick);
                    deliver_due_io(&mut executor, &mut io_waiters, clock.now_ticks());
                } else {
                    return self.fail(
                        FailureKind::Hang,
                        "no runnable tasks but incomplete work",
                        step,
                    );
                }
            }

            if !executor.has_queued_tasks() {
                return self.fail(
                    FailureKind::Hang,
                    "no runnable tasks after advancing time",
                    step,
                );
            }

            let (worker, task_id) = match executor.step() {
                StepResult::Idle => {
                    return self.fail(FailureKind::Hang, "executor idle with queued tasks", step);
                }
                StepResult::Ran {
                    worker,
                    task_id,
                    decision,
                } => {
                    trace.record(TraceEvent::StepChoose {
                        choices: decision.choices,
                        chosen: decision.chosen,
                    });
                    (worker, task_id)
                }
            };

            if executor.state(task_id) != SimTaskState::Runnable {
                return self.fail(
                    FailureKind::InvariantViolation { code: 3 },
                    "scheduled non-runnable task",
                    step,
                );
            }

            let task_idx = task_id.index();
            let mut discover_spawn: Option<Vec<DiscoveredFile>> = None;
            let mut discover_block = false;
            let mut discover_done = false;
            if let Some(task_state) = tasks.get_mut(task_idx) {
                match task_state {
                    ScannerTask::Discover(state) => {
                        if state.files.is_empty() {
                            discover_done = true;
                        } else {
                            let available = self
                                .cfg
                                .max_in_flight_objects
                                .saturating_sub(in_flight_objects);
                            if available == 0 {
                                // Mirror discovery backpressure: wait for a permit.
                                discover_block = true;
                            } else {
                                let mut batch = Vec::with_capacity(available as usize);
                                for _ in 0..available {
                                    if let Some(entry) = state.files.pop_front() {
                                        batch.push(entry);
                                    } else {
                                        break;
                                    }
                                }
                                if !batch.is_empty() {
                                    discover_spawn = Some(batch);
                                }
                                if state.files.is_empty() {
                                    discover_done = true;
                                } else {
                                    discover_block = true;
                                }
                            }
                        }
                    }
                    ScannerTask::ObjectScan(state) => {
                        let outcome = match state.step(
                            engine,
                            &fs,
                            &mut faults,
                            overlap,
                            self.cfg.chunk_size as usize,
                            &self.cfg.archive,
                            self.cfg.max_file_size,
                            &mut output,
                            &mut summaries,
                            &mut vpaths,
                            &mut archive_scratch,
                            &mut archive_roots,
                            trace,
                            step,
                            clock.now_ticks(),
                        ) {
                            Ok(outcome) => outcome,
                            Err(fail) => return RunOutcome::Failed(fail),
                        };
                        match outcome {
                            ScanStepOutcome::Done => {
                                executor.mark_completed(task_id);
                                if in_flight_objects == 0 {
                                    return self.fail(
                                        FailureKind::InvariantViolation { code: 30 },
                                        "in-flight underflow on file completion",
                                        step,
                                    );
                                }
                                in_flight_objects -= 1;
                                if discover_waiting
                                    && in_flight_objects < self.cfg.max_in_flight_objects
                                    && executor.state(discover_id) == SimTaskState::Blocked
                                {
                                    // Wake discovery when permits become available.
                                    executor.mark_runnable(discover_id);
                                    executor.enqueue_global(discover_id);
                                    discover_waiting = false;
                                }
                            }
                            ScanStepOutcome::Reschedule => {
                                executor.mark_runnable(task_id);
                                executor.enqueue_local(worker, task_id);
                            }
                            ScanStepOutcome::Blocked { ready_at } => {
                                executor.mark_blocked(task_id);
                                io_waiters.entry(ready_at).or_default().push(task_id);
                            }
                        }
                    }
                }
            } else {
                return self.fail(
                    FailureKind::InvariantViolation { code: 4 },
                    "task state missing",
                    step,
                );
            }

            if let Some(files) = discover_spawn {
                // Spawn file scan tasks deterministically in discovered order.
                for entry in files {
                    let state = ObjectScanState::new(
                        entry.path.clone(),
                        entry.file_id,
                        entry.archive_kind,
                        engine,
                        overlap,
                    );

                    let spawned_id = executor.spawn_local(
                        worker,
                        SimTask {
                            kind: TaskKind::ObjectScan as u16,
                        },
                    );
                    trace.record(TraceEvent::TaskSpawn {
                        task_id: spawned_id.index() as u32,
                        kind: TaskKind::ObjectScan as u16,
                    });
                    insert_task(
                        &mut tasks,
                        spawned_id,
                        ScannerTask::ObjectScan(Box::new(state)),
                    );

                    in_flight_objects = match in_flight_objects.checked_add(1) {
                        Some(next) => next,
                        None => {
                            return self.fail(
                                FailureKind::InvariantViolation { code: 32 },
                                "in-flight counter overflow",
                                step,
                            );
                        }
                    };
                    if in_flight_objects > max_seen_in_flight {
                        max_seen_in_flight = in_flight_objects;
                    }
                }

                if discover_done {
                    discover_waiting = false;
                    executor.mark_completed(task_id);
                    executor.remove_from_queues(task_id);
                } else if discover_block {
                    executor.mark_blocked(task_id);
                    discover_waiting = true;
                }
            } else if discover_done {
                discover_waiting = false;
                executor.mark_completed(task_id);
                executor.remove_from_queues(task_id);
            } else if discover_block {
                executor.mark_blocked(task_id);
                discover_waiting = true;
            }

            if in_flight_objects > self.cfg.max_in_flight_objects {
                return self.fail(
                    FailureKind::InvariantViolation { code: 31 },
                    &format!(
                        "in-flight budget exceeded: current {} > max {} (max_seen {})",
                        in_flight_objects, self.cfg.max_in_flight_objects, max_seen_in_flight
                    ),
                    step,
                );
            }
        }

        self.fail(FailureKind::Hang, "max steps exceeded", max_steps)
    }

    fn fail(&self, kind: FailureKind, message: &str, step: u64) -> RunOutcome {
        RunOutcome::Failed(FailureReport {
            kind,
            message: message.to_string(),
            step,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn run_oracles(
        &self,
        scenario: &Scenario,
        engine: &Engine,
        vpaths: &VirtualPathTable,
        archive_roots: &[ArchiveRootSummary],
        findings: &CollectedFindings,
        summaries: &[ObjectSummary],
        step: u64,
    ) -> Result<(), FailureReport> {
        oracle_ground_truth(scenario, vpaths, &findings.recs, summaries, step)?;
        oracle_differential(scenario, vpaths, engine, findings, summaries, step)?;
        oracle_archive_outcomes(archive_roots, summaries, &self.cfg.archive, vpaths, step)?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Task classification for the executor (used for tracing/debugging).
enum TaskKind {
    Discover = 1,
    ObjectScan = 2,
}

/// Normalized finding identity used for dedupe and stability checks.
///
/// Note: `step_id` is intentionally excluded because it is scratch-local.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct FindingKey {
    file_id: u32,
    rule_id: u32,
    span_start: u32,
    span_end: u32,
    root_hint_start: u64,
    root_hint_end: u64,
}

impl From<&FindingRec> for FindingKey {
    fn from(rec: &FindingRec) -> Self {
        // Use dedupe_with_span to determine whether span contributes to finding identity.
        // This is more accurate than checking step_id == STEP_ROOT since derived findings
        // can also have stable spans when dedupe_with_span is true.
        let (span_start, span_end) = if rec.dedupe_with_span {
            (rec.span_start, rec.span_end)
        } else {
            (0, 0)
        };
        Self {
            file_id: rec.file_id.0,
            rule_id: rec.rule_id,
            span_start,
            span_end,
            root_hint_start: rec.root_hint_start,
            root_hint_end: rec.root_hint_end,
        }
    }
}

/// Findings plus leaf transform metadata for differential normalization.
///
/// `leaf_transforms` is aligned with `recs` by index. Entries are `None` for
/// root findings or chains that contain no transform steps (e.g., UTF-16 only).
#[derive(Clone, Debug)]
struct CollectedFindings {
    recs: Vec<FindingRec>,
    leaf_transforms: Vec<Option<TransformId>>,
}

/// Output collector that enforces a no-duplicates invariant.
///
/// Set `SCANNER_SIM_DUP_DEBUG=1` to print diagnostic details when duplicate
/// findings are detected.
struct OutputCollector {
    findings: Vec<FindingRec>,
    leaf_transforms: Vec<Option<TransformId>>,
    seen: BTreeSet<FindingKey>,
}

fn leaf_transform_id(
    engine: &Engine,
    scratch: &mut ScanScratch,
    rec: &FindingRec,
) -> Option<TransformId> {
    // Leaf transform is the last transform step in the decode chain (if any).
    if rec.step_id == STEP_ROOT {
        return None;
    }
    let steps = scratch.materialize_decode_steps(rec.step_id);
    steps.iter().rev().find_map(|step| match step {
        DecodeStep::Transform { transform_idx, .. } => Some(engine.transform_id(*transform_idx)),
        DecodeStep::Utf16Window { .. } => None,
    })
}

fn append_leaf_transforms(
    engine: &Engine,
    scratch: &mut ScanScratch,
    recs: &[FindingRec],
    out: &mut Vec<Option<TransformId>>,
) {
    out.reserve(recs.len());
    for rec in recs {
        out.push(leaf_transform_id(engine, scratch, rec));
    }
}

impl OutputCollector {
    fn new() -> Self {
        Self {
            findings: Vec::new(),
            leaf_transforms: Vec::new(),
            seen: BTreeSet::new(),
        }
    }

    /// Append a batch of findings, rejecting duplicates by normalized key.
    fn append(
        &mut self,
        batch: &mut Vec<FindingRec>,
        engine: &Engine,
        scratch: &mut ScanScratch,
        step: u64,
    ) -> Result<(), FailureReport> {
        let mut local_seen: BTreeSet<FindingKey> = BTreeSet::new();
        for rec in batch.drain(..) {
            let key = FindingKey::from(&rec);
            if !local_seen.insert(key) {
                continue;
            }
            if !self.seen.insert(key) {
                if std::env::var_os("SCANNER_SIM_DUP_DEBUG").is_some() {
                    if let Some(prev) = self
                        .findings
                        .iter()
                        .find(|existing| FindingKey::from(*existing) == key)
                    {
                        eprintln!(
                            "duplicate finding details:\n  prev={prev:?}\n  new={rec:?}\n  key={key:?}"
                        );
                    } else {
                        eprintln!(
                            "duplicate finding details (prev not found): key={key:?} new={rec:?}"
                        );
                    }
                }
                return Err(FailureReport {
                    kind: FailureKind::InvariantViolation { code: 20 },
                    message: format!("duplicate finding emitted: {:?}", key),
                    step,
                });
            }
            let leaf_transform = leaf_transform_id(engine, scratch, &rec);
            self.findings.push(rec);
            self.leaf_transforms.push(leaf_transform);
        }
        Ok(())
    }

    /// Finish and return findings in emission order.
    fn finish(self) -> CollectedFindings {
        CollectedFindings {
            recs: self.findings,
            leaf_transforms: self.leaf_transforms,
        }
    }
}

enum ScannerTask {
    Discover(DiscoverState),
    ObjectScan(Box<ObjectScanState>),
}

/// Summary of the bytes observed for a scanned object during simulation.
///
/// `ground_truth_ok` is false if any data-affecting fault (error/cancel/corrupt)
/// occurred, which causes ground-truth checks to skip this file.
#[derive(Clone, Debug)]
struct ObjectSummary {
    file_id: FileId,
    root_file_id: FileId,
    observed: Vec<u8>,
    ground_truth_ok: bool,
}

/// Per-root archive outcome + stats.
#[derive(Clone, Debug)]
struct ArchiveRootSummary {
    root_file_id: FileId,
    outcome: ArchiveEnd,
    stats: ArchiveStats,
}

/// Result of executing one file-task quantum.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ScanStepOutcome {
    Done,
    Reschedule,
    Blocked { ready_at: u64 },
}

enum ScanMode {
    Plain(Box<FileScanState>),
    Archive(ArchiveScanState),
}

struct ObjectScanState {
    mode: ScanMode,
}

/// Pending IO read submitted with latency.
#[derive(Clone, Debug)]
struct PendingRead {
    fault: ReadFault,
    requested: usize,
    offset: u64,
    ready_at: u64,
    cancel_after: bool,
}

/// Discover task state (pre-sorted file list with stable IDs).
struct DiscoverState {
    files: VecDeque<DiscoveredFile>,
}

#[derive(Clone, Debug)]
struct DiscoveredFile {
    file_id: FileId,
    path: SimPath,
    archive_kind: Option<ArchiveKind>,
}

impl DiscoverState {
    fn new(mut files: Vec<DiscoveredFile>) -> Self {
        files.sort_by(|a, b| a.path.bytes.cmp(&b.path.bytes));
        Self {
            files: files.into(),
        }
    }
}

/// Archive scanning state for a single root file.
struct ArchiveScanState {
    file_id: FileId,
    path: SimPath,
    kind: ArchiveKind,
    open_fault: Option<IoFault>,
    open_fault_used: bool,
}

/// Per-file scanning state for deterministic chunked scans.
///
/// The task advances through open → read → scan. Reads may block on simulated
/// latency; a pending read stores the submission offset so we can assert no
/// cursor movement occurred while blocked.
///
/// Invariants:
/// - `handle.cursor` is the next payload byte offset in the file.
/// - `tail_len <= overlap` and `tail` stores the last `overlap` bytes of the
///   previous chunk buffer.
/// - `tail_len as u64 <= handle.cursor` whenever a handle is open.
struct FileScanState {
    file_id: FileId,
    path: SimPath,
    handle: Option<SimFileHandle>,
    open_fault: Option<IoFault>,
    open_fault_used: bool,
    pending: Option<PendingRead>,
    reads_done: u32,
    observed: Vec<u8>,
    ground_truth_ok: bool,
    tail: Vec<u8>,
    tail_len: usize,
    scratch: ScanScratch,
    batch: Vec<FindingRec>,
}

impl FileScanState {
    /// Initialize per-file scan state without touching IO.
    fn new(path: SimPath, file_id: FileId, engine: &Engine, overlap: usize) -> Self {
        Self {
            file_id,
            path,
            handle: None,
            open_fault: None,
            open_fault_used: false,
            pending: None,
            reads_done: 0,
            observed: Vec::new(),
            ground_truth_ok: true,
            tail: vec![0u8; overlap],
            tail_len: 0,
            scratch: engine.new_scratch(),
            batch: Vec::with_capacity(engine.max_findings_per_chunk()),
        }
    }

    /// Execute one simulation quantum for this file.
    #[allow(clippy::too_many_arguments)]
    fn step(
        &mut self,
        engine: &Engine,
        fs: &SimFs,
        faults: &mut FaultInjector,
        overlap: usize,
        chunk_size: usize,
        max_file_size: u64,
        output: &mut OutputCollector,
        step: u64,
        now: u64,
    ) -> Result<ScanStepOutcome, FailureReport> {
        if chunk_size == 0 {
            return Err(FailureReport {
                kind: FailureKind::InvariantViolation { code: 11 },
                message: "chunk_size must be > 0".to_string(),
                step,
            });
        }

        if self.handle.is_none() {
            if self.open_fault.is_none() {
                // Latch the open fault once per file to keep retries deterministic.
                self.open_fault = faults.on_open(&self.path.bytes);
            }
            if let Some(fault) = self.open_fault.clone() {
                match fault {
                    IoFault::ErrKind { .. } => {
                        self.ground_truth_ok = false;
                        return Ok(ScanStepOutcome::Done);
                    }
                    IoFault::EIntrOnce => {
                        if !self.open_fault_used {
                            self.open_fault_used = true;
                            return Ok(ScanStepOutcome::Reschedule);
                        }
                    }
                    IoFault::PartialRead { .. } => {}
                }
            }

            let handle = fs.open_file(&self.path).map_err(|e| FailureReport {
                kind: FailureKind::InvariantViolation { code: 12 },
                message: format!("open {:?}: {e}", self.path.bytes),
                step,
            })?;
            if handle.len > usize::MAX as u64 {
                return Err(FailureReport {
                    kind: FailureKind::InvariantViolation { code: 13 },
                    message: format!("file too large: {:?}", self.path.bytes),
                    step,
                });
            }
            if handle.len == 0 {
                return Ok(ScanStepOutcome::Done);
            }
            if handle.len > max_file_size {
                // Size-cap skip: return Done so the runner releases the permit.
                self.ground_truth_ok = false;
                return Ok(ScanStepOutcome::Done);
            }
            self.handle = Some(handle);
        }

        let Some(handle) = self.handle.as_mut() else {
            return Err(FailureReport {
                kind: FailureKind::InvariantViolation { code: 14 },
                message: "missing file handle".to_string(),
                step,
            });
        };

        if let Some(pending) = self.pending.take() {
            if pending.ready_at > now {
                self.pending = Some(pending);
                return Err(FailureReport {
                    kind: FailureKind::InvariantViolation { code: 15 },
                    message: "io completion before ready".to_string(),
                    step,
                });
            }
            if pending.offset != handle.cursor {
                return Err(FailureReport {
                    kind: FailureKind::InvariantViolation { code: 16 },
                    message: "io completion offset mismatch".to_string(),
                    step,
                });
            }
            // Complete the previously submitted read now that its latency elapsed.
            return self.complete_read(
                engine,
                fs,
                overlap,
                output,
                step,
                pending.fault,
                pending.requested,
                pending.cancel_after,
            );
        }

        let remaining = handle.len.saturating_sub(handle.cursor);
        if remaining == 0 {
            return Ok(ScanStepOutcome::Done);
        }
        let requested = chunk_size.min(remaining as usize);
        let fault = faults.on_read(&self.path.bytes);
        self.reads_done = self.reads_done.saturating_add(1);
        // Latch cancellation at submission time for schedule-independent behavior.
        let cancel_after = faults.should_cancel(&self.path.bytes, self.reads_done);

        if fault.latency_ticks > 0 {
            let ready_at = now.saturating_add(fault.latency_ticks);
            self.pending = Some(PendingRead {
                fault,
                requested,
                offset: handle.cursor,
                ready_at,
                cancel_after,
            });
            return Ok(ScanStepOutcome::Blocked { ready_at });
        }

        self.complete_read(
            engine,
            fs,
            overlap,
            output,
            step,
            fault,
            requested,
            cancel_after,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn complete_read(
        &mut self,
        engine: &Engine,
        fs: &SimFs,
        overlap: usize,
        output: &mut OutputCollector,
        step: u64,
        fault: ReadFault,
        requested: usize,
        cancel_after: bool,
    ) -> Result<ScanStepOutcome, FailureReport> {
        let Some(handle) = self.handle.as_mut() else {
            return Err(FailureReport {
                kind: FailureKind::InvariantViolation { code: 17 },
                message: "missing file handle".to_string(),
                step,
            });
        };

        if self.tail_len > overlap {
            return Err(FailureReport {
                kind: FailureKind::InvariantViolation { code: 18 },
                message: "tail_len exceeds overlap".to_string(),
                step,
            });
        }
        if (self.tail_len as u64) > handle.cursor {
            return Err(FailureReport {
                kind: FailureKind::InvariantViolation { code: 19 },
                message: "tail_len exceeds offset".to_string(),
                step,
            });
        }

        let ReadFault {
            fault: io_fault,
            corruption,
            ..
        } = fault;

        match io_fault {
            Some(IoFault::ErrKind { .. }) => {
                self.ground_truth_ok = false;
                Ok(ScanStepOutcome::Done)
            }
            Some(IoFault::EIntrOnce) => {
                if cancel_after && handle.cursor < handle.len {
                    self.ground_truth_ok = false;
                    return Ok(ScanStepOutcome::Done);
                }
                Ok(ScanStepOutcome::Reschedule)
            }
            Some(IoFault::PartialRead { max_len }) => {
                let capped = (max_len as usize).min(requested);
                self.read_and_scan(
                    engine,
                    fs,
                    overlap,
                    output,
                    step,
                    capped,
                    corruption,
                    cancel_after,
                )
            }
            None => self.read_and_scan(
                engine,
                fs,
                overlap,
                output,
                step,
                requested,
                corruption,
                cancel_after,
            ),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn read_and_scan(
        &mut self,
        engine: &Engine,
        fs: &SimFs,
        overlap: usize,
        output: &mut OutputCollector,
        step: u64,
        requested: usize,
        corruption: Option<Corruption>,
        cancel_after: bool,
    ) -> Result<ScanStepOutcome, FailureReport> {
        let Some(handle) = self.handle.as_mut() else {
            return Err(FailureReport {
                kind: FailureKind::InvariantViolation { code: 20 },
                message: "missing file handle".to_string(),
                step,
            });
        };

        if requested == 0 {
            if handle.cursor < handle.len {
                self.ground_truth_ok = false;
            }
            return Ok(ScanStepOutcome::Done);
        }

        let read_offset = handle.cursor;
        let data = fs
            .read_at(handle, read_offset, requested)
            .map_err(|e| FailureReport {
                kind: FailureKind::InvariantViolation { code: 21 },
                message: format!("read {:?}: {e}", self.path.bytes),
                step,
            })?;
        let mut payload = data.to_vec();
        if let Some(c) = corruption {
            apply_corruption(&mut payload, &c);
            self.ground_truth_ok = false;
        }

        let payload_len = payload.len();
        handle.cursor = handle.cursor.saturating_add(payload_len as u64);

        if payload_len == 0 {
            if handle.cursor < handle.len {
                self.ground_truth_ok = false;
            }
            return Ok(ScanStepOutcome::Done);
        }

        // Track the exact byte stream presented to the engine.
        self.observed.extend_from_slice(&payload);

        let mut chunk = Vec::with_capacity(self.tail_len + payload_len);
        chunk.extend_from_slice(&self.tail[..self.tail_len]);
        chunk.extend_from_slice(&payload);

        let base_offset = read_offset.saturating_sub(self.tail_len as u64);
        let new_bytes_start = read_offset;
        if base_offset.saturating_add(self.tail_len as u64) != new_bytes_start {
            return Err(FailureReport {
                kind: FailureKind::InvariantViolation { code: 22 },
                message: "prefix boundary mismatch".to_string(),
                step,
            });
        }
        engine.scan_chunk_into(&chunk, self.file_id, base_offset, &mut self.scratch);
        self.scratch.drop_prefix_findings(new_bytes_start);
        // Invariant: no finding may end at or before the prefix boundary.
        let findings = self.scratch.findings();
        let drop_hints = self.scratch.drop_hint_end();
        for (_rec, drop_end) in findings.iter().zip(drop_hints.iter()) {
            if *drop_end <= new_bytes_start {
                return Err(FailureReport {
                    kind: FailureKind::InvariantViolation { code: 23 },
                    message: "prefix dedupe failed".to_string(),
                    step,
                });
            }
        }
        self.scratch.drain_findings_into(&mut self.batch);
        if base_offset != 0 {
            let base_offset_u32 = base_offset.min(u32::MAX as u64) as u32;
            for rec in &mut self.batch {
                if rec.step_id == STEP_ROOT {
                    rec.span_start = rec.span_start.saturating_add(base_offset_u32);
                    rec.span_end = rec.span_end.saturating_add(base_offset_u32);
                }
            }
        }
        output.append(&mut self.batch, engine, &mut self.scratch, step)?;

        let total_len = chunk.len();
        let keep = overlap.min(total_len);
        if keep > 0 {
            self.tail[..keep].copy_from_slice(&chunk[total_len - keep..]);
        }
        self.tail_len = keep;

        let expected_next = base_offset.saturating_add(chunk.len() as u64);
        if expected_next != handle.cursor {
            return Err(FailureReport {
                kind: FailureKind::InvariantViolation { code: 24 },
                message: "base_offset + chunk_len mismatch".to_string(),
                step,
            });
        }

        if cancel_after && handle.cursor < handle.len {
            self.ground_truth_ok = false;
            return Ok(ScanStepOutcome::Done);
        }

        if handle.cursor < handle.len {
            Ok(ScanStepOutcome::Reschedule)
        } else {
            Ok(ScanStepOutcome::Done)
        }
    }

    fn take_summary(&mut self) -> ObjectSummary {
        ObjectSummary {
            file_id: self.file_id,
            root_file_id: self.file_id,
            observed: std::mem::take(&mut self.observed),
            ground_truth_ok: self.ground_truth_ok,
        }
    }
}

struct ArchiveEntryState {
    file_id: FileId,
    observed: Vec<u8>,
    ground_truth_ok: bool,
}

struct SimArchiveSink<'a> {
    engine: &'a Engine,
    output: &'a mut OutputCollector,
    scratch: &'a mut ScanScratch,
    batch: &'a mut Vec<FindingRec>,
    vpaths: &'a mut VirtualPathTable,
    summaries: &'a mut Vec<ObjectSummary>,
    root_file_id: FileId,
    trace: &'a mut TraceCollector,
    current: Option<ArchiveEntryState>,
    step: u64,
}

impl<'a> SimArchiveSink<'a> {
    #[allow(clippy::too_many_arguments)]
    fn new(
        engine: &'a Engine,
        output: &'a mut OutputCollector,
        scratch: &'a mut ScanScratch,
        batch: &'a mut Vec<FindingRec>,
        vpaths: &'a mut VirtualPathTable,
        summaries: &'a mut Vec<ObjectSummary>,
        root_file_id: FileId,
        trace: &'a mut TraceCollector,
        step: u64,
    ) -> Self {
        Self {
            engine,
            output,
            scratch,
            batch,
            vpaths,
            summaries,
            root_file_id,
            trace,
            current: None,
            step,
        }
    }
}

impl ArchiveEntrySink for SimArchiveSink<'_> {
    type Error = FailureReport;

    fn on_entry_start(&mut self, meta: &EntryMeta<'_>) -> Result<(), Self::Error> {
        let file_id = self
            .vpaths
            .try_insert_virtual(meta.display_path)
            .ok_or_else(|| FailureReport {
                kind: FailureKind::InvariantViolation { code: 50 },
                message: "virtual path budget exceeded".to_string(),
                step: self.step,
            })?;

        self.current = Some(ArchiveEntryState {
            file_id,
            observed: Vec::new(),
            ground_truth_ok: true,
        });
        self.trace.record(TraceEvent::ArchiveEntryStart {
            root: self.root_file_id.0,
            entry: file_id.0,
        });
        Ok(())
    }

    fn on_entry_chunk(&mut self, chunk: EntryChunk<'_>) -> Result<(), Self::Error> {
        let entry = self.current.as_mut().ok_or_else(|| FailureReport {
            kind: FailureKind::InvariantViolation { code: 51 },
            message: "archive entry chunk before start".to_string(),
            step: self.step,
        })?;

        self.engine
            .scan_chunk_into(chunk.data, entry.file_id, chunk.base_offset, self.scratch);
        self.scratch.drop_prefix_findings(chunk.new_bytes_start);

        let findings = self.scratch.findings();
        let drop_hints = self.scratch.drop_hint_end();
        for (_rec, drop_end) in findings.iter().zip(drop_hints.iter()) {
            if *drop_end <= chunk.new_bytes_start {
                return Err(FailureReport {
                    kind: FailureKind::InvariantViolation { code: 52 },
                    message: "archive prefix dedupe failed".to_string(),
                    step: self.step,
                });
            }
        }

        self.scratch.drain_findings_into(self.batch);
        if chunk.base_offset != 0 {
            let base_offset_u32 = chunk.base_offset.min(u32::MAX as u64) as u32;
            for rec in &mut *self.batch {
                if rec.step_id == STEP_ROOT {
                    rec.span_start = rec.span_start.saturating_add(base_offset_u32);
                    rec.span_end = rec.span_end.saturating_add(base_offset_u32);
                }
            }
        }
        self.output
            .append(self.batch, self.engine, self.scratch, self.step)?;

        let prefix = chunk.new_bytes_start.saturating_sub(chunk.base_offset) as usize;
        let new_end = prefix.saturating_add(chunk.new_bytes_len);
        if new_end > chunk.data.len() {
            return Err(FailureReport {
                kind: FailureKind::InvariantViolation { code: 53 },
                message: "archive chunk bounds invalid".to_string(),
                step: self.step,
            });
        }
        entry
            .observed
            .extend_from_slice(&chunk.data[prefix..new_end]);

        Ok(())
    }

    fn on_entry_end(&mut self) -> Result<(), Self::Error> {
        let entry = self.current.take().ok_or_else(|| FailureReport {
            kind: FailureKind::InvariantViolation { code: 54 },
            message: "archive entry end without start".to_string(),
            step: self.step,
        })?;

        self.summaries.push(ObjectSummary {
            file_id: entry.file_id,
            root_file_id: self.root_file_id,
            observed: entry.observed,
            ground_truth_ok: entry.ground_truth_ok,
        });
        self.trace.record(TraceEvent::ArchiveEntryEnd {
            root: self.root_file_id.0,
            entry: entry.file_id.0,
        });
        Ok(())
    }
}

impl ArchiveScanState {
    fn new(path: SimPath, file_id: FileId, kind: ArchiveKind) -> Self {
        Self {
            file_id,
            path,
            kind,
            open_fault: None,
            open_fault_used: false,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn step(
        &mut self,
        engine: &Engine,
        fs: &SimFs,
        faults: &mut FaultInjector,
        archive_cfg: &ArchiveConfig,
        max_file_size: u64,
        output: &mut OutputCollector,
        summaries: &mut Vec<ObjectSummary>,
        vpaths: &mut VirtualPathTable,
        scratch: &mut ArchiveScratch<std::io::Cursor<Arc<[u8]>>>,
        archive_roots: &mut Vec<ArchiveRootSummary>,
        trace: &mut TraceCollector,
        step: u64,
    ) -> Result<ScanStepOutcome, FailureReport> {
        let trace_root = self.file_id.0;
        let trace_kind = archive_kind_code(self.kind);
        if self.open_fault.is_none() {
            self.open_fault = faults.on_open(&self.path.bytes);
        }
        if let Some(fault) = self.open_fault.clone() {
            match fault {
                IoFault::ErrKind { .. } => {
                    let mut stats = ArchiveStats::default();
                    stats.record_archive_seen();
                    stats.record_archive_skipped(
                        ArchiveSkipReason::IoError,
                        &self.path.bytes,
                        false,
                    );
                    trace.record(TraceEvent::ArchiveStart {
                        root: trace_root,
                        kind: trace_kind,
                    });
                    trace.record(TraceEvent::ArchiveEnd {
                        root: trace_root,
                        outcome: archive_end_code(ArchiveEnd::Skipped(ArchiveSkipReason::IoError)),
                    });
                    archive_roots.push(ArchiveRootSummary {
                        root_file_id: self.file_id,
                        outcome: ArchiveEnd::Skipped(ArchiveSkipReason::IoError),
                        stats,
                    });
                    return Ok(ScanStepOutcome::Done);
                }
                IoFault::EIntrOnce => {
                    if !self.open_fault_used {
                        self.open_fault_used = true;
                        return Ok(ScanStepOutcome::Reschedule);
                    }
                }
                IoFault::PartialRead { .. } => {}
            }
        }

        let handle = fs.open_file(&self.path).map_err(|e| FailureReport {
            kind: FailureKind::InvariantViolation { code: 40 },
            message: format!("open {:?}: {e}", self.path.bytes),
            step,
        })?;
        if handle.len > max_file_size {
            let mut stats = ArchiveStats::default();
            stats.record_archive_seen();
            stats.record_archive_skipped(ArchiveSkipReason::IoError, &self.path.bytes, false);
            trace.record(TraceEvent::ArchiveStart {
                root: trace_root,
                kind: trace_kind,
            });
            trace.record(TraceEvent::ArchiveEnd {
                root: trace_root,
                outcome: archive_end_code(ArchiveEnd::Skipped(ArchiveSkipReason::IoError)),
            });
            archive_roots.push(ArchiveRootSummary {
                root_file_id: self.file_id,
                outcome: ArchiveEnd::Skipped(ArchiveSkipReason::IoError),
                stats,
            });
            return Ok(ScanStepOutcome::Done);
        }

        let data = fs.file_bytes(&self.path).map_err(|e| FailureReport {
            kind: FailureKind::InvariantViolation { code: 41 },
            message: format!("read {:?}: {e}", self.path.bytes),
            step,
        })?;
        let bytes: Arc<[u8]> = Arc::from(data);

        let mut stats = ArchiveStats::default();
        stats.record_archive_seen();

        let mut entry_scratch = engine.new_scratch();
        let mut batch = Vec::with_capacity(engine.max_findings_per_chunk());
        let entry_start = summaries.len();
        trace.record(TraceEvent::ArchiveStart {
            root: trace_root,
            kind: trace_kind,
        });
        let outcome = {
            let mut sink = SimArchiveSink::new(
                engine,
                output,
                &mut entry_scratch,
                &mut batch,
                vpaths,
                summaries,
                self.file_id,
                trace,
                step,
            );
            match self.kind {
                ArchiveKind::Gzip => scan_gzip_stream(
                    std::io::Cursor::new(bytes.clone()),
                    &self.path.bytes,
                    archive_cfg,
                    scratch,
                    &mut sink,
                    &mut stats,
                )?,
                ArchiveKind::Bzip2 => scan_bzip2_stream(
                    std::io::Cursor::new(bytes.clone()),
                    &self.path.bytes,
                    archive_cfg,
                    scratch,
                    &mut sink,
                    &mut stats,
                )?,
                ArchiveKind::Tar => {
                    let mut cursor = std::io::Cursor::new(bytes.clone());
                    scan_tar_stream(
                        &mut cursor,
                        &self.path.bytes,
                        archive_cfg,
                        scratch,
                        &mut sink,
                        &mut stats,
                        false,
                    )?
                }
                ArchiveKind::TarGz => scan_targz_stream(
                    std::io::Cursor::new(bytes.clone()),
                    &self.path.bytes,
                    archive_cfg,
                    scratch,
                    &mut sink,
                    &mut stats,
                )?,
                ArchiveKind::TarBz2 => scan_tarbz2_stream(
                    std::io::Cursor::new(bytes.clone()),
                    &self.path.bytes,
                    archive_cfg,
                    scratch,
                    &mut sink,
                    &mut stats,
                )?,
                ArchiveKind::Zip => scan_zip_source(
                    std::io::Cursor::new(bytes),
                    &self.path.bytes,
                    archive_cfg,
                    scratch,
                    &mut sink,
                    &mut stats,
                )?,
            }
        };
        trace.record(TraceEvent::ArchiveEnd {
            root: trace_root,
            outcome: archive_end_code(outcome),
        });

        match outcome {
            ArchiveEnd::Scanned => stats.record_archive_scanned(),
            ArchiveEnd::Skipped(reason) => {
                stats.record_archive_skipped(reason, &self.path.bytes, false);
            }
            ArchiveEnd::Partial(reason) => {
                stats.record_archive_partial(reason, &self.path.bytes, false);
            }
        }

        if outcome != ArchiveEnd::Scanned {
            for summary in &mut summaries[entry_start..] {
                summary.ground_truth_ok = false;
            }
        }

        archive_roots.push(ArchiveRootSummary {
            root_file_id: self.file_id,
            outcome,
            stats,
        });

        if scratch.abort_run() {
            return Err(FailureReport {
                kind: FailureKind::InvariantViolation { code: 42 },
                message: "archive scan requested abort_run".to_string(),
                step,
            });
        }

        Ok(ScanStepOutcome::Done)
    }
}

impl ObjectScanState {
    fn new(
        path: SimPath,
        file_id: FileId,
        archive_kind: Option<ArchiveKind>,
        engine: &Engine,
        overlap: usize,
    ) -> Self {
        let mode = match archive_kind {
            Some(kind) => ScanMode::Archive(ArchiveScanState::new(path, file_id, kind)),
            None => ScanMode::Plain(Box::new(FileScanState::new(path, file_id, engine, overlap))),
        };
        Self { mode }
    }

    #[allow(clippy::too_many_arguments)]
    fn step(
        &mut self,
        engine: &Engine,
        fs: &SimFs,
        faults: &mut FaultInjector,
        overlap: usize,
        chunk_size: usize,
        archive_cfg: &ArchiveConfig,
        max_file_size: u64,
        output: &mut OutputCollector,
        summaries: &mut Vec<ObjectSummary>,
        vpaths: &mut VirtualPathTable,
        scratch: &mut ArchiveScratch<std::io::Cursor<Arc<[u8]>>>,
        archive_roots: &mut Vec<ArchiveRootSummary>,
        trace: &mut TraceCollector,
        step: u64,
        now: u64,
    ) -> Result<ScanStepOutcome, FailureReport> {
        match &mut self.mode {
            ScanMode::Plain(state) => {
                let outcome = state.step(
                    engine,
                    fs,
                    faults,
                    overlap,
                    chunk_size,
                    max_file_size,
                    output,
                    step,
                    now,
                )?;
                if matches!(outcome, ScanStepOutcome::Done) {
                    summaries.push(state.take_summary());
                }
                Ok(outcome)
            }
            ScanMode::Archive(state) => state.step(
                engine,
                fs,
                faults,
                archive_cfg,
                max_file_size,
                output,
                summaries,
                vpaths,
                scratch,
                archive_roots,
                trace,
                step,
            ),
        }
    }
}

/// Insert a task into the slot indexed by its task id.
fn insert_task(tasks: &mut Vec<ScannerTask>, task_id: SimTaskId, task: ScannerTask) {
    if task_id.index() == tasks.len() {
        tasks.push(task);
    } else if task_id.index() < tasks.len() {
        tasks[task_id.index()] = task;
    }
}

/// Return whether every known task has reached the completed state.
fn all_tasks_completed(executor: &SimExecutor, tasks: &[ScannerTask]) -> bool {
    tasks
        .iter()
        .enumerate()
        .all(|(idx, _)| executor.state(SimTaskId::from_u32(idx as u32)) == SimTaskState::Completed)
}

fn deliver_due_io(
    executor: &mut SimExecutor,
    io_waiters: &mut BTreeMap<u64, Vec<SimTaskId>>,
    now: u64,
) {
    let due: Vec<u64> = io_waiters.range(..=now).map(|(k, _)| *k).collect();
    for key in due {
        if let Some(mut tasks) = io_waiters.remove(&key) {
            tasks.sort_by_key(|t| t.index());
            for task_id in tasks {
                if executor.state(task_id) == SimTaskState::Blocked {
                    executor.mark_runnable(task_id);
                    executor.enqueue_global(task_id);
                }
            }
        }
    }
}

fn next_io_tick(io_waiters: &BTreeMap<u64, Vec<SimTaskId>>) -> Option<u64> {
    io_waiters.keys().next().copied()
}

fn estimate_fault_ops(plan: &FaultPlan) -> u64 {
    let mut count = 0u64;
    for file in plan.per_file.values() {
        if file.open.is_some() {
            count = count.saturating_add(1);
        }
        if file.cancel_after_reads.is_some() {
            count = count.saturating_add(1);
        }
        for read in &file.reads {
            if read.fault.is_some() || read.latency_ticks > 0 || read.corruption.is_some() {
                count = count.saturating_add(1);
            }
        }
    }
    count
}

fn vpath_bytes_cap(files: &[SimPath], archive: &ArchiveConfig) -> usize {
    let root_bytes: usize = files.iter().map(|p| p.bytes.len()).sum();
    let per_archive = archive.max_virtual_path_bytes_per_archive;
    let archive_total = per_archive.saturating_mul(files.len().max(1));
    root_bytes.saturating_add(archive_total)
}

fn detect_archive_kind(fs: &SimFs, path: &SimPath) -> Option<ArchiveKind> {
    if let Some(kind) = detect_kind_from_name_bytes(&path.bytes) {
        return Some(kind);
    }
    let bytes = fs.file_bytes(path).ok()?;
    if bytes.is_empty() {
        return None;
    }
    let header_len = TAR_BLOCK_LEN.min(bytes.len());
    sniff_kind_from_header(&bytes[..header_len])
}

fn archive_kind_code(kind: ArchiveKind) -> u16 {
    match kind {
        ArchiveKind::Gzip => 1,
        ArchiveKind::Bzip2 => 2,
        ArchiveKind::Tar => 3,
        ArchiveKind::TarGz => 4,
        ArchiveKind::TarBz2 => 5,
        ArchiveKind::Zip => 6,
    }
}

fn archive_end_code(end: ArchiveEnd) -> u16 {
    match end {
        ArchiveEnd::Scanned => 1,
        ArchiveEnd::Skipped(_) => 2,
        ArchiveEnd::Partial(_) => 3,
    }
}

fn build_discovered_files(
    fs: &SimFs,
    files: &[SimPath],
    vpaths: &mut VirtualPathTable,
    archive_enabled: bool,
) -> Result<Vec<DiscoveredFile>, FailureReport> {
    let mut out = Vec::with_capacity(files.len());
    for path in files {
        let file_id = vpaths.try_insert_root(&path.bytes).ok_or(FailureReport {
            kind: FailureKind::InvariantViolation { code: 60 },
            message: "virtual path budget exceeded for root file".to_string(),
            step: 0,
        })?;
        let archive_kind = if archive_enabled {
            detect_archive_kind(fs, path)
        } else {
            None
        };
        out.push(DiscoveredFile {
            file_id,
            path: path.clone(),
            archive_kind,
        });
    }
    Ok(out)
}

fn apply_corruption(buf: &mut Vec<u8>, corruption: &Corruption) {
    match corruption {
        Corruption::TruncateTo { new_len } => {
            let len = (*new_len as usize).min(buf.len());
            buf.truncate(len);
        }
        Corruption::FlipBit { offset, mask } => {
            if let Some(byte) = buf.get_mut(*offset as usize) {
                *byte ^= *mask;
            }
        }
        Corruption::Overwrite { offset, bytes } => {
            let start = *offset as usize;
            for (idx, value) in bytes.iter().enumerate() {
                if let Some(byte) = buf.get_mut(start.saturating_add(idx)) {
                    *byte = *value;
                } else {
                    break;
                }
            }
        }
    }
}

#[derive(Clone, Debug)]
struct ExpectedEntry {
    path: SimPath,
    rule_id: u32,
    span: SpanU32,
    repr: SecretRepr,
    disposition: crate::sim_scanner::scenario::ExpectedDisposition,
    matched: bool,
}

/// Normalize findings into a stable, ordered key set.
fn normalize_findings(findings: &[FindingRec]) -> BTreeSet<FindingKey> {
    findings.iter().map(FindingKey::from).collect()
}

/// Normalize findings for differential comparison.
///
/// Derived-buffer `root_hint` spans are best-effort and can vary with chunk
/// boundaries (nested transforms over long URL/base64 runs). For differential
/// checks:
/// - Drop non-root findings that already have a covering root finding for the
///   same `(file_id, rule_id)` (avoid redundant duplicates).
/// - Drop non-root findings whose root-hint span exceeds the guaranteed overlap;
///   these are alignment-sensitive for long transform runs and are not stable
///   across chunk boundaries.
/// - Clamp remaining non-root hints to the last `required_overlap()` bytes so
///   the oracle focuses on semantic differences while staying consistent with
///   guaranteed overlap.
/// - Normalize base64-derived `root_hint_end` when padding is elided so
///   truncated spans (chunked) compare equal to padded spans (reference).
fn normalize_findings_for_diff(
    engine: &Engine,
    findings: &CollectedFindings,
) -> BTreeSet<FindingKey> {
    debug_assert_eq!(findings.recs.len(), findings.leaf_transforms.len());
    let overlap = engine.required_overlap() as u64;
    let mut root_spans: BTreeMap<(u32, u32), Vec<(u64, u64)>> = BTreeMap::new();
    for rec in &findings.recs {
        if rec.step_id == STEP_ROOT {
            root_spans
                .entry((rec.file_id.0, rec.rule_id))
                .or_default()
                .push((rec.span_start as u64, rec.span_end as u64));
        }
    }

    fn normalize_root_hint_end(rec: &FindingRec, leaf_transform: Option<TransformId>) -> u64 {
        if rec.step_id == STEP_ROOT {
            return rec.root_hint_end;
        }
        // Only Base64 uses 4/3 padding rules; other transforms must not normalize.
        if leaf_transform != Some(TransformId::Base64) {
            return rec.root_hint_end;
        }
        // Base64 decoding is padding-tolerant; chunked scans can surface a match
        // before trailing '=' arrives. Normalize to the minimal encoded length
        // when the observed span is within padding tolerance (<= 3 chars).
        let decoded_len = rec.span_end.saturating_sub(rec.span_start) as u64;
        let min_encoded = (decoded_len * 4).div_ceil(3);
        let actual_encoded = rec.root_hint_end.saturating_sub(rec.root_hint_start);
        if actual_encoded > min_encoded && actual_encoded <= min_encoded.saturating_add(3) {
            rec.root_hint_start.saturating_add(min_encoded)
        } else {
            rec.root_hint_end
        }
    }

    findings
        .recs
        .iter()
        .zip(findings.leaf_transforms.iter())
        .filter_map(|(rec, leaf_transform)| {
            let normalized_end = normalize_root_hint_end(rec, *leaf_transform);
            if rec.step_id != STEP_ROOT {
                let hint_len = normalized_end.saturating_sub(rec.root_hint_start);
                if hint_len > overlap {
                    return None;
                }
                if let Some(spans) = root_spans.get(&(rec.file_id.0, rec.rule_id)) {
                    if spans
                        .iter()
                        .any(|(start, end)| rec.root_hint_start <= *start && normalized_end >= *end)
                    {
                        return None;
                    }
                }
            }
            let (span_start, span_end) = if rec.step_id == STEP_ROOT {
                (rec.span_start, rec.span_end)
            } else {
                (0, 0)
            };
            let (root_hint_start, root_hint_end) = if rec.step_id == STEP_ROOT {
                (rec.root_hint_start, rec.root_hint_end)
            } else {
                (normalized_end.saturating_sub(overlap), normalized_end)
            };
            Some(FindingKey {
                file_id: rec.file_id.0,
                rule_id: rec.rule_id,
                span_start,
                span_end,
                root_hint_start,
                root_hint_end,
            })
        })
        .collect()
}

/// Discover file paths with type-hint fallback semantics.
///
/// This models DirWalker behavior: `Unknown` type hints must still attempt
/// metadata (here, a simulated open) to avoid silent drops.
fn discover_file_paths(fs: &SimFs, spec: &SimFsSpec, max_file_size: u64) -> Vec<SimPath> {
    let mut files = Vec::new();
    for node in &spec.nodes {
        let SimNodeSpec::File {
            path,
            contents,
            type_hint,
            discovery_len_hint,
        } = node
        else {
            continue;
        };

        let hint_len = discovery_len_hint.unwrap_or(contents.len() as u64);
        if hint_len == 0 || hint_len > max_file_size {
            continue;
        }

        let include = match type_hint {
            SimTypeHint::File => true,
            SimTypeHint::NotFile => false,
            SimTypeHint::Unknown => fs.open_file(path).is_ok(),
        };

        if include {
            files.push(path.clone());
        }
    }

    files.sort_by(|a, b| a.bytes.cmp(&b.bytes));
    files
}

/// Check that observed findings match the scenario's expected secrets.
///
/// Matches require the same `(file_id, rule_id)` and a representation-aware
/// span check against the finding's `root_hint` range:
/// strict containment for raw/url-percent secrets, and bounded slack for
/// base64/UTF-16 variants. Any extra finding is a ground-truth failure.
/// Files marked `ground_truth_ok = false` are skipped.
fn oracle_ground_truth(
    scenario: &Scenario,
    vpaths: &VirtualPathTable,
    findings: &[FindingRec],
    summaries: &[ObjectSummary],
    step: u64,
) -> Result<(), FailureReport> {
    let mut expected = Vec::with_capacity(scenario.expected.len());
    let mut index: BTreeMap<(u32, u32), Vec<usize>> = BTreeMap::new();
    let mut skip_files: BTreeSet<u32> = BTreeSet::new();

    for summary in summaries {
        // Files with data-affecting faults are excluded from ground-truth checks.
        if !summary.ground_truth_ok {
            skip_files.insert(summary.file_id.0);
        }
    }

    for exp in &scenario.expected {
        let file_id = match vpaths.file_id_for_path(&exp.path.bytes) {
            Some(id) => id,
            None => {
                return Err(FailureReport {
                    kind: FailureKind::OracleMismatch,
                    message: format!(
                        "expected secret references missing path {:?}",
                        exp.path.bytes
                    ),
                    step,
                });
            }
        };
        if skip_files.contains(&file_id.0) {
            continue;
        }
        let idx = expected.len();
        expected.push(ExpectedEntry {
            path: exp.path.clone(),
            rule_id: exp.rule_id,
            span: exp.root_span,
            repr: exp.repr.clone(),
            disposition: exp.disposition.clone(),
            matched: false,
        });
        index.entry((file_id.0, exp.rule_id)).or_default().push(idx);
    }

    for rec in findings {
        if skip_files.contains(&rec.file_id.0) {
            continue;
        }
        let Some(candidates) = index.get(&(rec.file_id.0, rec.rule_id)) else {
            return Err(FailureReport {
                kind: FailureKind::OracleMismatch,
                message: format!(
                    "unexpected finding in {:?} (rule_id {}, root_hint {}..{})",
                    vpaths
                        .path_bytes(rec.file_id)
                        .map(|p| p.to_vec())
                        .unwrap_or_default(),
                    rec.rule_id,
                    rec.root_hint_start,
                    rec.root_hint_end
                ),
                step,
            });
        };
        let mut matched = false;
        for &idx in candidates {
            let entry = &mut expected[idx];
            if span_matches_expected(
                entry.span,
                rec.root_hint_start,
                rec.root_hint_end,
                &entry.repr,
            ) {
                entry.matched = true;
                matched = true;
            }
        }
        if !matched {
            return Err(FailureReport {
                kind: FailureKind::OracleMismatch,
                message: format!(
                    "unexpected finding in {:?} (rule_id {}, root_hint {}..{})",
                    vpaths
                        .path_bytes(rec.file_id)
                        .map(|p| p.to_vec())
                        .unwrap_or_default(),
                    rec.rule_id,
                    rec.root_hint_start,
                    rec.root_hint_end
                ),
                step,
            });
        }
    }

    if let Some(miss) = expected
        .iter()
        .find(|e| !e.matched && matches!(e.disposition, ExpectedDisposition::MustFind))
    {
        return Err(FailureReport {
            kind: FailureKind::OracleMismatch,
            message: format!(
                "missing expected secret in {:?} (rule_id {}, span {}..{}, repr {:?})",
                miss.path.bytes, miss.rule_id, miss.span.start, miss.span.end, miss.repr
            ),
            step,
        });
    }

    Ok(())
}

/// Compare chunked findings against a single-chunk reference scan.
fn oracle_differential(
    scenario: &Scenario,
    vpaths: &VirtualPathTable,
    engine: &Engine,
    findings: &CollectedFindings,
    summaries: &[ObjectSummary],
    step: u64,
) -> Result<(), FailureReport> {
    let reference =
        reference_findings_observed(engine, summaries).map_err(|msg| FailureReport {
            kind: FailureKind::OracleMismatch,
            message: msg,
            step,
        })?;

    let observed = normalize_findings_for_diff(engine, findings);
    let expected = normalize_findings_for_diff(engine, &reference);
    let observed_len = observed.len();
    let expected_len = expected.len();

    let mut observed_root: BTreeSet<FindingKey> = BTreeSet::new();
    let mut observed_non_root: BTreeMap<(u32, u32), BTreeSet<u64>> = BTreeMap::new();
    for key in observed {
        if key.span_start == 0 && key.span_end == 0 {
            observed_non_root
                .entry((key.file_id, key.rule_id))
                .or_default()
                .insert(key.root_hint_end);
        } else {
            observed_root.insert(key);
        }
    }

    let mut expected_root: BTreeSet<FindingKey> = BTreeSet::new();
    let mut expected_non_root: Vec<FindingKey> = Vec::new();
    for key in expected {
        if key.span_start == 0 && key.span_end == 0 {
            expected_non_root.push(key);
        } else {
            expected_root.insert(key);
        }
    }

    if let Some(miss) = expected_root.difference(&observed_root).next() {
        let message = format!(
            "differential mismatch (sim {}, reference {}), missing {:?}",
            observed_len, expected_len, miss
        );
        return Err(FailureReport {
            kind: FailureKind::OracleMismatch,
            message,
            step,
        });
    }

    let strict_non_root = std::env::var_os("SCANNER_SIM_STRICT_NON_ROOT").is_some();
    if strict_non_root {
        let mut expected_root_ends: BTreeMap<(u32, u32), BTreeSet<u64>> = BTreeMap::new();
        for key in &expected_root {
            expected_root_ends
                .entry((key.file_id, key.rule_id))
                .or_default()
                .insert(key.span_end as u64);
        }

        // Allow small padding drift for transform findings (e.g., base64 `=` omission)
        // where chunking can produce equivalent decoded content with root_hint_end
        // differing by a few bytes.
        for exp in expected_non_root {
            // If a root finding already ends at this offset, treat the transform
            // finding as redundant (chunked scans may drop it).
            if let Some(root_ends) = expected_root_ends.get(&(exp.file_id, exp.rule_id)) {
                let lo = exp.root_hint_end.saturating_sub(3);
                let hi = exp.root_hint_end.saturating_add(3);
                if root_ends.range(lo..=hi).next().is_some() {
                    continue;
                }
            }

            let Some(ends) = observed_non_root.get_mut(&(exp.file_id, exp.rule_id)) else {
                let message = format!(
                    "differential mismatch (sim {}, reference {}), missing {:?}",
                    observed_len, expected_len, exp
                );
                return Err(FailureReport {
                    kind: FailureKind::OracleMismatch,
                    message,
                    step,
                });
            };
            if ends.remove(&exp.root_hint_end) {
                continue;
            }
            let lo = exp.root_hint_end.saturating_sub(3);
            let hi = exp.root_hint_end.saturating_add(3);
            if let Some(&candidate) = ends.range(lo..=hi).next() {
                ends.remove(&candidate);
                continue;
            }
            let message = format!(
                "differential mismatch (sim {}, reference {}), missing {:?}",
                observed_len, expected_len, exp
            );
            return Err(FailureReport {
                kind: FailureKind::OracleMismatch,
                message,
                step,
            });
        }
    }

    let mut expected_spans: BTreeMap<(u32, u32), Vec<SpanU32>> = BTreeMap::new();
    for exp in &scenario.expected {
        if let Some(id) = vpaths.file_id_for_path(&exp.path.bytes) {
            expected_spans
                .entry((id.0, exp.rule_id))
                .or_default()
                .push(exp.root_span);
        }
    }

    for extra in observed_root.difference(&expected_root) {
        let matches_expected = expected_spans
            .get(&(extra.file_id, extra.rule_id))
            .map(|spans| {
                spans
                    .iter()
                    .any(|s| s.start == extra.span_start && s.end == extra.span_end)
            })
            .unwrap_or(false);
        if matches_expected {
            continue;
        }
        let message = format!(
            "differential mismatch (sim {}, reference {}), extra {:?}",
            observed_len, expected_len, extra
        );
        return Err(FailureReport {
            kind: FailureKind::OracleMismatch,
            message,
            step,
        });
    }

    Ok(())
}

fn oracle_archive_outcomes(
    archive_roots: &[ArchiveRootSummary],
    summaries: &[ObjectSummary],
    archive_cfg: &ArchiveConfig,
    vpaths: &VirtualPathTable,
    step: u64,
) -> Result<(), FailureReport> {
    if archive_roots.is_empty() {
        return Ok(());
    }

    let mut observed: BTreeMap<u32, (u64, u64, u64)> = BTreeMap::new();
    for summary in summaries {
        let entry_bytes = summary.observed.len() as u64;
        let entry = observed.entry(summary.root_file_id.0).or_insert((0, 0, 0));
        entry.0 = entry.0.saturating_add(entry_bytes);
        entry.1 = entry.1.max(entry_bytes);
        entry.2 = entry.2.saturating_add(1);
    }

    for root in archive_roots {
        let root_path = vpaths
            .path_bytes(root.root_file_id)
            .map(|p| p.to_vec())
            .unwrap_or_default();
        let (total_bytes, max_entry_bytes, _entry_count) = observed
            .get(&root.root_file_id.0)
            .copied()
            .unwrap_or((0, 0, 0));

        if max_entry_bytes > archive_cfg.max_uncompressed_bytes_per_entry {
            return Err(FailureReport {
                kind: FailureKind::OracleMismatch,
                message: format!(
                    "archive entry exceeds per-entry cap in {:?}: {} > {}",
                    root_path, max_entry_bytes, archive_cfg.max_uncompressed_bytes_per_entry
                ),
                step,
            });
        }
        if total_bytes > archive_cfg.max_total_uncompressed_bytes_per_root {
            return Err(FailureReport {
                kind: FailureKind::OracleMismatch,
                message: format!(
                    "archive root exceeds output cap in {:?}: {} > {}",
                    root_path, total_bytes, archive_cfg.max_total_uncompressed_bytes_per_root
                ),
                step,
            });
        }

        let total_entries = root
            .stats
            .entries_scanned
            .saturating_add(root.stats.entries_skipped);
        let max_entries = root
            .stats
            .archives_seen
            .max(1)
            .saturating_mul(archive_cfg.max_entries_per_archive as u64);
        if total_entries > max_entries {
            return Err(FailureReport {
                kind: FailureKind::OracleMismatch,
                message: format!(
                    "archive entry count exceeds cap in {:?}: {} > {}",
                    root_path, total_entries, max_entries
                ),
                step,
            });
        }

        if root.stats.paths_truncated > total_entries {
            return Err(FailureReport {
                kind: FailureKind::OracleMismatch,
                message: format!(
                    "path truncation count exceeds entries in {:?}: {} > {}",
                    root_path, root.stats.paths_truncated, total_entries
                ),
                step,
            });
        }
        if root.stats.paths_had_traversal > total_entries {
            return Err(FailureReport {
                kind: FailureKind::OracleMismatch,
                message: format!(
                    "path traversal count exceeds entries in {:?}: {} > {}",
                    root_path, root.stats.paths_had_traversal, total_entries
                ),
                step,
            });
        }
        if root.stats.paths_component_cap_exceeded > total_entries {
            return Err(FailureReport {
                kind: FailureKind::OracleMismatch,
                message: format!(
                    "path component cap count exceeds entries in {:?}: {} > {}",
                    root_path, root.stats.paths_component_cap_exceeded, total_entries
                ),
                step,
            });
        }

        // Stat-counter oracle checks are only meaningful when recording is
        // enabled (debug builds with perf-stats feature). In release builds
        // the counters are zero-initialised stubs.
        if cfg!(all(feature = "perf-stats", debug_assertions)) {
            match root.outcome {
                ArchiveEnd::Skipped(reason) => {
                    let idx = reason.as_usize();
                    if root.stats.archive_skip_reasons[idx] == 0 || root.stats.archives_skipped == 0
                    {
                        return Err(FailureReport {
                            kind: FailureKind::OracleMismatch,
                            message: format!(
                                "archive skip reason not recorded for {:?}: {:?}",
                                root_path, reason
                            ),
                            step,
                        });
                    }
                }
                ArchiveEnd::Partial(reason) => {
                    let idx = reason.as_usize();
                    if root.stats.partial_reasons[idx] == 0 || root.stats.archives_partial == 0 {
                        return Err(FailureReport {
                            kind: FailureKind::OracleMismatch,
                            message: format!(
                                "archive partial reason not recorded for {:?}: {:?}",
                                root_path, reason
                            ),
                            step,
                        });
                    }
                }
                ArchiveEnd::Scanned => {}
            }

            let entry_skip_total: u64 = root.stats.entry_skip_reasons.iter().sum();
            if root.stats.entries_skipped > 0 && entry_skip_total == 0 {
                return Err(FailureReport {
                    kind: FailureKind::OracleMismatch,
                    message: format!("entry skip reasons missing for {:?}", root_path),
                    step,
                });
            }
        }
    }

    Ok(())
}

fn reference_findings_observed(
    engine: &Engine,
    summaries: &[ObjectSummary],
) -> Result<CollectedFindings, String> {
    let mut scratch = engine.new_scratch();
    let mut out = Vec::with_capacity(engine.max_findings_per_chunk());
    let mut out_transforms = Vec::with_capacity(engine.max_findings_per_chunk());
    let mut batch = Vec::with_capacity(engine.max_findings_per_chunk());

    for summary in summaries {
        let len = summary.observed.len();
        if len > u32::MAX as usize {
            return Err(format!(
                "reference scan requires <= u32::MAX bytes: file_id {:?}",
                summary.file_id
            ));
        }
        if summary.observed.is_empty() {
            continue;
        }
        engine.scan_chunk_into(&summary.observed, summary.file_id, 0, &mut scratch);
        scratch.drain_findings_into(&mut batch);
        append_leaf_transforms(engine, &mut scratch, &batch, &mut out_transforms);
        out.append(&mut batch);
    }

    Ok(CollectedFindings {
        recs: out,
        leaf_transforms: out_transforms,
    })
}

/// Compare an observed finding span against expected encoded bounds.
///
/// Tolerances are representation-specific:
/// - Base64 allows up to 2 trailing bytes to accommodate optional `=` padding.
/// - UTF-16 variants allow +/-1 byte drift at each edge due to chunk boundary
///   alignment when mapping between byte and code-unit views.
fn span_matches_expected(span: SpanU32, start: u64, end: u64, repr: &SecretRepr) -> bool {
    let span_start = span.start as u64;
    let span_end = span.end as u64;
    if span_start >= start && span_end <= end {
        return true;
    }
    if matches!(repr, SecretRepr::Base64) && span_start >= start && span_end > end {
        return span_end.saturating_sub(end) <= 2;
    }
    if matches!(repr, SecretRepr::Utf16Le | SecretRepr::Utf16Be) {
        let start_diff = span_start.abs_diff(start);
        let end_diff = span_end.abs_diff(end);
        return start_diff <= 1 && end_diff <= 1;
    }
    false
}

/// Sum file lengths for a scenario (missing paths contribute 0).
fn total_file_bytes(fs: &SimFs, files: &[SimPath]) -> u64 {
    let mut total = 0u64;
    for path in files {
        if let Ok(handle) = fs.open_file(path) {
            total = total.saturating_add(handle.len);
        }
    }
    total
}

/// Resolve the max steps bound. If `cfg.max_steps > 0`, honor it; otherwise
/// derive a conservative bound from file count, byte count, and fault ops.
fn resolve_max_steps(cfg: &RunConfig, file_count: u64, total_bytes: u64, fault_ops: u64) -> u64 {
    if cfg.max_steps > 0 {
        return cfg.max_steps;
    }
    let chunk = (cfg.chunk_size as u64).max(1);
    let chunks = total_bytes.saturating_add(chunk - 1) / chunk;
    let base = 32u64;
    let alpha = 8u64;
    let beta = 4u64;
    base.saturating_add(alpha.saturating_mul(file_count.saturating_add(chunks)))
        .saturating_add(beta.saturating_mul(fault_ops))
}

/// Format panic payloads into a stable message.
fn panic_message(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        s.to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "panic payload".to_string()
    }
}

#[cfg(test)]
#[path = "runner_tests.rs"]
mod tests;
