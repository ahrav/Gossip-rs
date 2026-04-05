//! Deterministic Git simulation runner.
//!
//! The runner executes stage tasks under a deterministic scheduler and
//! records a bounded trace for replay. End-of-run oracles validate output
//! shape (sorted/disjoint sets) and stability across schedule seeds.
//!
//! Stage pipeline:
//! `RepoOpen -> CommitWalk -> TreeDiff -> SpillDedupe -> PackExec -> Finalize`
//!
//! Each stage is executed exactly once per run. Stage outputs are carried in
//! `RunState` and validated at the end of the run before a `RunReport` is
//! emitted.
//!
use std::num::NonZeroU32;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::AtomicBool;

use blake3::Hasher;
use serde::{Deserialize, Serialize};
use tempfile::tempdir;

use crate::sim::executor::{SimExecutor, SimTask, SimTaskId, StepResult};
use crate::{
    build_pack_plans, ByteArena, BytesView, CandidateBuffer, CollectingUniqueBlobSink, CommitGraph,
    CommitPlanIter, CommitWalkLimits, FinalizeOutcome, FinalizeOutput, FinalizeStats,
    NeverSeenStore, OidBytes, PackCache, PackDecodeLimits, PackExecError, PackExecReport,
    PackPlanConfig, PackReadError, PackReader, PersistenceStore, PlannedCommit, RefWatermark,
    SpillLimits, SpillStats, Spiller, StartSetRef, TreeDiffLimits, TreeDiffWalker,
};

use super::commit_graph::SimCommitGraph;
use super::convert::{to_object_format, to_oid_bytes};
use super::fault::{
    corruption_kind_code, fault_kind_code, GitFaultInjector, GitFaultPlan, GitIoFault,
    GitResourceId,
};
use super::pack_bytes::SimPackBytes;
use super::pack_io::SimPackIo;
use super::persist::SimPersistStore;
use super::scenario::{GitRunConfig, GitScenario};
use super::start_set::SimStartSet;
use super::trace::{GitTraceEvent, GitTraceRing};
use super::tree_source::SimTreeSource;

/// Result of a Git simulation run.
#[derive(Clone, Debug)]
pub enum RunOutcome {
    /// Run completed without detected failures.
    Ok { report: RunReport },
    /// Run failed with a structured report.
    Failed(FailureReport),
}

/// Outcome of finalize in simulation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum SimFinalizeOutcome {
    Complete,
    Partial { skipped_count: usize },
}

impl From<FinalizeOutcome> for SimFinalizeOutcome {
    fn from(outcome: FinalizeOutcome) -> Self {
        match outcome {
            FinalizeOutcome::Complete => Self::Complete,
            FinalizeOutcome::Partial { skipped_count } => Self::Partial { skipped_count },
        }
    }
}

/// Summary report for a successful run.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunReport {
    /// Total steps executed.
    pub steps: u64,
    /// Commit count emitted by the commit walk.
    pub commit_count: u32,
    /// Candidate count emitted by tree diff.
    pub candidate_count: u32,
    /// Count of unique skipped OIDs (after dedup).
    pub skipped_count: usize,
    /// Finalize outcome.
    pub outcome: SimFinalizeOutcome,
    /// Hash of scanned OIDs (sorted, unique).
    pub scanned_hash: [u8; 32],
    /// Hash of skipped OIDs (sorted, unique).
    pub skipped_hash: [u8; 32],
    /// Hash of trace events (order-sensitive, bounded to the trace ring).
    pub trace_hash: [u8; 32],
    /// Raw trace events for corpus regeneration and debugging.
    ///
    /// Bounded by the trace ring capacity (`GitRunConfig::trace_capacity`).
    /// Serialized with `#[serde(default)]` so older corpus files that lack
    /// this field deserialize cleanly.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trace_dump: Vec<GitTraceEvent>,
}

/// Semantic subset of `RunReport` used for cross-seed stability checks.
///
/// `steps` and `trace_hash` are intentionally excluded so schedule variations
/// can be tolerated as long as externally visible scan results are identical.
#[derive(Clone, Debug, PartialEq, Eq)]
struct RunOutput {
    commit_count: u32,
    candidate_count: u32,
    outcome: SimFinalizeOutcome,
    scanned_hash: [u8; 32],
    skipped_hash: [u8; 32],
}

impl From<&RunReport> for RunOutput {
    fn from(report: &RunReport) -> Self {
        Self {
            commit_count: report.commit_count,
            candidate_count: report.candidate_count,
            outcome: report.outcome,
            scanned_hash: report.scanned_hash,
            skipped_hash: report.skipped_hash,
        }
    }
}

/// Structured failure report captured in artifacts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailureReport {
    /// Failure classification.
    pub kind: FailureKind,
    /// Human-readable message for logs and artifacts.
    pub message: String,
    /// Monotonic step counter at the time of failure.
    pub step: u64,
}

/// Failure classification for deterministic triage.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FailureKind {
    /// A panic escaped from harness logic.
    Panic,
    /// The simulation failed to reach a terminal state within the step budget.
    Hang,
    /// An invariant about ordering or gating was violated.
    InvariantViolation { code: u32 },
    /// A correctness oracle failed.
    OracleMismatch,
    /// The same scenario produced different outputs across schedules.
    StabilityMismatch,
}

/// Deterministic Git simulation runner.
///
/// The schedule seed drives the scheduler RNG; deterministic behavior is
/// expected given identical scenario, fault plan, and configuration.
pub struct GitSimRunner {
    cfg: GitRunConfig,
    schedule_seed: u64,
}

impl GitSimRunner {
    /// Create a new runner with a fixed schedule seed.
    pub fn new(cfg: GitRunConfig, schedule_seed: u64) -> Self {
        Self { cfg, schedule_seed }
    }

    /// Execute a single scenario under the current schedule seed and fault plan.
    pub fn run(&self, scenario: &GitScenario, fault_plan: &GitFaultPlan) -> RunOutcome {
        let base = match self.run_once_catch(scenario, fault_plan, self.schedule_seed) {
            RunOutcome::Ok { report } => report,
            fail => return fail,
        };

        if self.cfg.stability_runs <= 1 {
            return RunOutcome::Ok { report: base };
        }

        let baseline = RunOutput::from(&base);
        for i in 1..self.cfg.stability_runs {
            let seed = self.schedule_seed.wrapping_add(i as u64);
            match self.run_once_catch(scenario, fault_plan, seed) {
                RunOutcome::Ok { report } => {
                    let candidate = RunOutput::from(&report);
                    if candidate != baseline {
                        return RunOutcome::Failed(FailureReport {
                            kind: FailureKind::StabilityMismatch,
                            message: format!(
                                "stability mismatch between seeds {} and {}",
                                self.schedule_seed, seed
                            ),
                            step: report.steps,
                        });
                    }
                }
                fail => return fail,
            }
        }

        RunOutcome::Ok { report: base }
    }

    /// Returns the configured run settings.
    #[must_use]
    pub fn config(&self) -> &GitRunConfig {
        &self.cfg
    }

    /// Returns the base schedule seed.
    #[must_use]
    pub fn schedule_seed(&self) -> u64 {
        self.schedule_seed
    }

    fn run_once_catch(
        &self,
        scenario: &GitScenario,
        fault_plan: &GitFaultPlan,
        seed: u64,
    ) -> RunOutcome {
        let result = catch_unwind(AssertUnwindSafe(|| {
            self.run_once(scenario, fault_plan, seed)
        }));
        match result {
            Ok(outcome) => outcome,
            Err(payload) => {
                let msg = if let Some(s) = payload.downcast_ref::<&str>() {
                    format!("panic in git sim runner: {s}")
                } else if let Some(s) = payload.downcast_ref::<String>() {
                    format!("panic in git sim runner: {s}")
                } else {
                    "panic in git sim runner (non-string payload)".to_string()
                };
                RunOutcome::Failed(FailureReport {
                    kind: FailureKind::Panic,
                    message: msg,
                    step: 0,
                })
            }
        }
    }

    fn run_once(&self, scenario: &GitScenario, fault_plan: &GitFaultPlan, seed: u64) -> RunOutcome {
        let mut executor = SimExecutor::new(self.cfg.workers, seed);
        let mut tasks: Vec<StageKind> = Vec::new();

        let mut state = RunState::new(scenario, self.cfg.trace_capacity, fault_plan.clone());
        spawn_stage(&mut executor, &mut tasks, StageKind::RepoOpen);

        let max_steps = derive_max_steps(self.cfg.max_steps, scenario);
        let mut done = false;
        let mut steps = 0u64;

        for step in 1..=max_steps {
            if done {
                break;
            }

            match executor.step() {
                StepResult::Idle => {
                    return RunOutcome::Failed(FailureReport {
                        kind: FailureKind::Hang,
                        message: "no runnable tasks".to_string(),
                        step,
                    });
                }
                StepResult::Ran {
                    worker: _,
                    task_id,
                    decision,
                } => {
                    steps = step;
                    state.trace.push(GitTraceEvent::Decision {
                        code: (decision.choices << 16) | decision.chosen,
                    });
                    let stage = tasks[task_id.index()];
                    let stage_id = stage as u16;
                    state.trace.push(GitTraceEvent::StageEnter { stage_id });

                    let stage_result = match stage {
                        StageKind::RepoOpen => stage_repo_open(&mut state),
                        StageKind::CommitWalk => stage_commit_walk(&mut state),
                        StageKind::TreeDiff => stage_tree_diff(&mut state),
                        StageKind::SpillDedupe => stage_spill_dedupe(&mut state),
                        StageKind::PackExec => stage_pack_exec(&mut state),
                        StageKind::Finalize => stage_finalize(&mut state),
                    };

                    match stage_result {
                        Ok(items) => {
                            state
                                .trace
                                .push(GitTraceEvent::StageExit { stage_id, items });
                            executor.mark_completed(task_id);
                            executor.remove_from_queues(task_id);

                            match stage {
                                StageKind::RepoOpen => {
                                    spawn_stage(&mut executor, &mut tasks, StageKind::CommitWalk);
                                }
                                StageKind::CommitWalk => {
                                    spawn_stage(&mut executor, &mut tasks, StageKind::TreeDiff);
                                }
                                StageKind::TreeDiff => {
                                    spawn_stage(&mut executor, &mut tasks, StageKind::SpillDedupe);
                                }
                                StageKind::SpillDedupe => {
                                    spawn_stage(&mut executor, &mut tasks, StageKind::PackExec);
                                }
                                StageKind::PackExec => {
                                    spawn_stage(&mut executor, &mut tasks, StageKind::Finalize);
                                }
                                StageKind::Finalize => {
                                    done = true;
                                }
                            }
                        }
                        Err(mut failure) => {
                            failure.step = step;
                            return RunOutcome::Failed(failure);
                        }
                    }
                }
            }
        }

        if !done {
            return RunOutcome::Failed(FailureReport {
                kind: FailureKind::Hang,
                message: "max steps exceeded".to_string(),
                step: steps,
            });
        }

        let report = match build_report(&state, steps) {
            Ok(report) => report,
            Err(mut failure) => {
                failure.step = steps;
                return RunOutcome::Failed(failure);
            }
        };
        RunOutcome::Ok { report }
    }
}

/// Stable stage identifiers used by trace events and task dispatch.
///
/// Numeric discriminants are explicit to keep event encoding stable if enum
/// declaration order changes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StageKind {
    RepoOpen = 1,
    CommitWalk = 2,
    TreeDiff = 3,
    SpillDedupe = 4,
    PackExec = 5,
    Finalize = 6,
}

/// Mutable per-run state threaded through stage execution.
///
/// Most fields are populated monotonically as the stage pipeline advances.
/// `Option` fields represent stage prerequisites and are validated on access.
struct RunState<'a> {
    scenario: &'a GitScenario,
    trace: GitTraceRing,
    faults: GitFaultInjector,
    ref_arena: Option<ByteArena>,
    refs: Vec<StartSetRef>,
    commit_graph: Option<SimCommitGraph>,
    tree_source: Option<SimTreeSource>,
    plan: Vec<PlannedCommit>,
    candidates: Option<CandidateBuffer>,
    persist_store: SimPersistStore,
    spill_stats: Option<SpillStats>,
    unique_oids: Option<Vec<OidBytes>>,
    scanned: Vec<OidBytes>,
    skipped: Vec<OidBytes>,
    outcome: Option<FinalizeOutcome>,
}

impl<'a> RunState<'a> {
    fn new(scenario: &'a GitScenario, trace_capacity: u32, fault_plan: GitFaultPlan) -> Self {
        let (runner_plan, persist_plan) = partition_fault_plan(fault_plan);
        Self {
            scenario,
            trace: GitTraceRing::new(trace_capacity as usize),
            faults: GitFaultInjector::new(runner_plan),
            ref_arena: None,
            refs: Vec::new(),
            commit_graph: None,
            tree_source: None,
            plan: Vec::new(),
            candidates: None,
            persist_store: SimPersistStore::new(persist_plan),
            spill_stats: None,
            unique_oids: None,
            scanned: Vec::new(),
            skipped: Vec::new(),
            outcome: None,
        }
    }
}

/// Split a fault plan into runner-owned and persistence-owned partitions.
///
/// The runner injector handles artifact I/O faults (`CommitGraph`, `Midx`,
/// `Pack`, `Other`). The persistence store handles `Persist` and `SeenPersist`
/// faults via its own internal injector. Partitioning avoids cloning the full
/// plan into both consumers and makes the ownership boundary explicit.
fn partition_fault_plan(plan: GitFaultPlan) -> (GitFaultPlan, GitFaultPlan) {
    let (persist, runner): (Vec<_>, Vec<_>) = plan
        .resources
        .into_iter()
        .partition(|r| is_persist_resource(&r.resource));
    (
        GitFaultPlan { resources: runner },
        GitFaultPlan { resources: persist },
    )
}

/// Returns true for resources consumed by `SimPersistStore` rather than
/// the runner's `GitFaultInjector`. See `partition_fault_plan`.
fn is_persist_resource(id: &GitResourceId) -> bool {
    match id {
        GitResourceId::Persist | GitResourceId::SeenPersist => true,
        GitResourceId::CommitGraph
        | GitResourceId::Midx
        | GitResourceId::Pack { .. }
        | GitResourceId::Other(_) => false,
    }
}

/// Spawn one stage task and remember the stage kind at the assigned task index.
///
/// The `tasks` vector is a side table keyed by `SimTaskId::index()`, letting the
/// scheduler return compact task ids while the runner retains semantic stage
/// identity for dispatch and tracing.
fn spawn_stage(
    executor: &mut SimExecutor,
    tasks: &mut Vec<StageKind>,
    stage: StageKind,
) -> SimTaskId {
    let task = SimTask { kind: stage as u16 };
    let id = executor.spawn_external(task);
    if id.index() >= tasks.len() {
        tasks.resize(id.index() + 1, stage);
    }
    tasks[id.index()] = stage;
    id
}

/// Resolve the step budget for a run.
///
/// A non-zero configured value wins. Otherwise we derive a conservative
/// heuristic from repo shape to keep runaway schedules bounded while still
/// allowing small scenarios to complete.
fn derive_max_steps(max_steps: u64, scenario: &GitScenario) -> u64 {
    if max_steps != 0 {
        return max_steps;
    }
    // Heuristic to prevent hangs while allowing small scenarios to complete.
    let commits = scenario.repo.commits.len() as u64;
    let refs = scenario.repo.refs.len() as u64;
    let trees = scenario.repo.trees.len() as u64;
    1000 + commits.saturating_mul(8) + refs.saturating_mul(4) + trees.saturating_mul(2)
}

/// Stage 1: validate and materialize static repo structures.
///
/// Ref names are sorted for deterministic start-set construction before being
/// interned into `ByteArena`, so downstream hashing is independent of input
/// order in the scenario.
fn stage_repo_open(state: &mut RunState<'_>) -> Result<u32, FailureReport> {
    let repo = &state.scenario.repo;
    if let Some(artifacts) = &state.scenario.artifacts {
        if let Some(bytes) = &artifacts.commit_graph {
            let _ = apply_fault_to_bytes(
                &mut state.faults,
                &mut state.trace,
                &GitResourceId::CommitGraph,
                bytes,
            )?;
        }
    }
    let _start_set = SimStartSet::from_repo(repo).map_err(|err| failure_inv(1, err))?;
    let commit_graph = SimCommitGraph::from_repo(repo).map_err(|err| failure_inv(2, err))?;
    let tree_source = SimTreeSource::from_repo(repo).map_err(|err| failure_inv(3, err))?;

    let object_format = to_object_format(repo.object_format);

    let mut refs = repo.refs.clone();
    refs.sort_by(|a, b| a.name.cmp(&b.name));

    // Size the arena from total ref name bytes to avoid growth churn.
    let total_bytes: usize = refs.iter().map(|r| r.name.len()).sum();
    let mut arena = ByteArena::with_capacity(total_bytes as u32 + 1);
    let mut start_set_refs = Vec::with_capacity(refs.len());

    for r in refs {
        let name = arena
            .intern(&r.name)
            .ok_or_else(|| failure_inv(4, "ref name too long"))?;
        let tip = to_oid_bytes(&r.tip, object_format).map_err(|err| failure_inv(5, err))?;
        let watermark = match &r.watermark {
            Some(oid) => {
                let oid = to_oid_bytes(oid, object_format).map_err(|err| failure_inv(6, err))?;
                let pos = commit_graph
                    .lookup(&oid)
                    .map_err(|err| failure_inv(6, err))?
                    .ok_or_else(|| failure_inv(6, "watermark commit missing from commit graph"))?;
                let raw_gen = commit_graph.generation(pos);
                let gen = NonZeroU32::new(raw_gen)
                    .ok_or_else(|| failure_inv(6, "watermark generation must be nonzero"))?;
                Some(RefWatermark {
                    oid,
                    generation: gen,
                })
            }
            None => None,
        };
        start_set_refs.push(StartSetRef {
            name,
            tip,
            watermark,
        });
    }

    state.ref_arena = Some(arena);
    state.refs = start_set_refs;
    state.commit_graph = Some(commit_graph);
    state.tree_source = Some(tree_source);

    Ok(state.refs.len() as u32)
}

/// Stage 2: produce the commit execution plan from start refs.
fn stage_commit_walk(state: &mut RunState<'_>) -> Result<u32, FailureReport> {
    let commit_graph = state
        .commit_graph
        .as_ref()
        .ok_or_else(|| failure_inv(10, "commit graph missing"))?;

    let limits = CommitWalkLimits::default();
    let iter = CommitPlanIter::new_from_refs(&state.refs, commit_graph, limits)
        .map_err(|err| failure_inv(11, err))?;

    let mut plan = Vec::new();
    for item in iter {
        match item {
            Ok(commit) => plan.push(commit),
            Err(err) => return Err(failure_inv(12, err)),
        }
    }

    state.plan = plan;
    Ok(state.plan.len() as u32)
}

/// Stage 3: expand planned commits into blob candidates via tree diffs.
///
/// Root/snapshot commits diff against an empty tree; other commits diff against
/// each parent to preserve parent-specific context.
fn stage_tree_diff(state: &mut RunState<'_>) -> Result<u32, FailureReport> {
    let commit_graph = state
        .commit_graph
        .as_ref()
        .ok_or_else(|| failure_inv(20, "commit graph missing"))?;
    let tree_source = state
        .tree_source
        .as_mut()
        .ok_or_else(|| failure_inv(21, "tree source missing"))?;

    let limits = TreeDiffLimits::default();
    let oid_len = to_object_format(state.scenario.repo.object_format).oid_len();
    let mut walker = TreeDiffWalker::new(&limits, oid_len);
    let mut candidates = CandidateBuffer::new(&limits, oid_len);
    let abort = AtomicBool::new(false);

    for planned in &state.plan {
        let new_tree = commit_graph
            .root_tree_oid(planned.pos)
            .map_err(|err| failure_inv(22, err))?;
        let parents = commit_graph.parents(planned.pos);

        if planned.snapshot_root || parents.is_empty() {
            walker
                .diff_trees(
                    tree_source,
                    &mut candidates,
                    Some(&new_tree),
                    None,
                    planned.pos.0,
                    0,
                    &abort,
                )
                .map_err(|err| failure_inv(23, err))?;
        } else {
            for (idx, parent) in parents.iter().enumerate() {
                let old_tree = commit_graph
                    .root_tree_oid(*parent)
                    .map_err(|err| failure_inv(24, err))?;
                let parent_idx = u8::try_from(idx).map_err(|_| failure_inv(25, "parent idx"))?;
                walker
                    .diff_trees(
                        tree_source,
                        &mut candidates,
                        Some(&new_tree),
                        Some(&old_tree),
                        planned.pos.0,
                        parent_idx,
                        &abort,
                    )
                    .map_err(|err| failure_inv(26, err))?;
            }
        }
    }

    let count = candidates.len() as u32;
    state.candidates = Some(candidates);
    Ok(count)
}

/// Stage 4: spill/dedupe tree-diff candidates and persist seen-bitmap deltas.
///
/// Uses `NeverSeenStore` (all blobs considered unseen) and `SpillLimits::RESTRICTIVE`
/// to exercise the full spill pipeline with bounded resource usage. Seen-bitmap
/// persistence faults are injected through `state.persist_store`.
fn stage_spill_dedupe(state: &mut RunState<'_>) -> Result<u32, FailureReport> {
    let (stats, unique_oids) = {
        let candidates = state
            .candidates
            .as_ref()
            .ok_or_else(|| failure_inv(80, "candidates missing"))?;
        let oid_len = to_object_format(state.scenario.repo.object_format).oid_len();
        // The TempDir must outlive the Spiller — the spiller writes run
        // files to spill_dir.path() and cleans them up on finalize/drop.
        let spill_dir = tempdir().map_err(|err| failure_inv(81, err))?;
        let mut spiller = Spiller::new(SpillLimits::RESTRICTIVE, oid_len, spill_dir.path())
            .map_err(|err| failure_inv(82, err))?;

        for cand in candidates.iter_resolved() {
            spiller
                .push(
                    cand.oid,
                    cand.path,
                    cand.commit_id,
                    cand.parent_idx,
                    cand.change_kind,
                    cand.ctx_flags,
                    cand.cand_flags,
                )
                .map_err(|err| failure_inv(83, err))?;
        }

        let mut sink = CollectingUniqueBlobSink::default();
        let stats = spiller
            .finalize(&NeverSeenStore, &state.persist_store, &mut sink)
            .map_err(|err| failure_inv(84, err))?;
        let unique_oids = dedupe_sorted(sink.blobs.into_iter().map(|blob| blob.oid).collect());
        (stats, unique_oids)
    };

    let item_count = unique_oids.len() as u32;
    state.spill_stats = Some(stats);
    state.unique_oids = Some(unique_oids);
    Ok(item_count)
}

/// Stage 5: execute pack plans and partition candidates into scanned/skipped.
///
/// Fallback behavior is intentionally deterministic:
/// - no artifacts => treat semantic candidates as scanned
/// - incomplete artifacts => treat candidates as skipped
/// - full artifacts => execute pack decode path and collect per-object outcomes
fn stage_pack_exec(state: &mut RunState<'_>) -> Result<u32, FailureReport> {
    let Some(candidates) = state.candidates.as_ref() else {
        return Err(failure_inv(30, "candidates missing"));
    };
    let Some(unique_oids) = state.unique_oids.as_ref() else {
        return Err(failure_inv(85, "spill dedupe output missing"));
    };
    // Valid because stage_spill_dedupe uses NeverSeenStore, so no OIDs are
    // filtered by the seen store. If a filtering seen store is introduced,
    // this oracle must be relaxed to a subset check instead of equality.
    let candidate_oids = collect_unique_candidate_oids(candidates);
    if candidate_oids != *unique_oids {
        return Err(failure_oracle(
            "spill dedupe unique OIDs differ from tree-diff candidate OIDs",
        ));
    }

    let mut scanned: Vec<OidBytes> = Vec::new();
    let mut skipped: Vec<OidBytes> = Vec::new();

    // If there are no byte-level artifacts, treat the semantic candidates as scanned.
    let Some(artifacts) = &state.scenario.artifacts else {
        collect_semantic_scan(candidates, &mut scanned);
        state.scanned = dedupe_sorted(scanned);
        state.skipped = Vec::new();
        return Ok(state.scanned.len() as u32);
    };

    // If artifacts are present but incomplete, treat all candidates as skipped.
    if artifacts.midx.is_none() || artifacts.packs.is_empty() {
        collect_semantic_skip(candidates, &mut skipped);
        state.scanned = Vec::new();
        state.skipped = dedupe_sorted(skipped);
        return Ok(0);
    }

    let midx_bytes = artifacts.midx.clone().unwrap_or_default();
    let object_format = to_object_format(state.scenario.repo.object_format);

    let midx_faulted = apply_fault_to_bytes(
        &mut state.faults,
        &mut state.trace,
        &GitResourceId::Midx,
        &midx_bytes,
    )?;

    let midx_view =
        crate::MidxView::parse(&midx_faulted, object_format).map_err(|err| failure_inv(31, err))?;

    let pack_bytes = SimPackBytes::from_repo(&state.scenario.repo, artifacts)
        .map_err(|err| failure_inv(32, err))?;

    let mut pack_candidates = Vec::new();
    let mut path_arena = ByteArena::with_capacity(4 * 1024 * 1024);

    for cand in candidates.iter_resolved() {
        match midx_view.find_oid(&cand.oid) {
            Ok(Some(idx)) => {
                let (pack_id, offset) = midx_view
                    .offset_at(idx)
                    .map_err(|err| failure_inv(33, err))?;
                let path_ref = path_arena
                    .intern(cand.path)
                    .ok_or_else(|| failure_inv(34, "path arena full"))?;
                let ctx = crate::CandidateContext {
                    commit_id: cand.commit_id,
                    parent_idx: cand.parent_idx,
                    change_kind: cand.change_kind,
                    ctx_flags: cand.ctx_flags,
                    cand_flags: cand.cand_flags,
                    path_ref,
                };
                pack_candidates.push(crate::PackCandidate {
                    oid: cand.oid,
                    ctx,
                    pack_id,
                    offset,
                });
            }
            Ok(None) => skipped.push(cand.oid),
            Err(err) => return Err(failure_inv(35, err)),
        }
    }

    if pack_candidates.is_empty() {
        state.scanned = Vec::new();
        state.skipped = dedupe_sorted(skipped);
        return Ok(0);
    }

    let pack_views = pack_bytes
        .pack_views()
        .map_err(|err| failure_inv(36, err))?;
    let pack_views = pack_views.into_iter().map(Some).collect::<Vec<_>>();
    let plans = build_pack_plans(
        pack_candidates,
        &pack_views,
        &midx_view,
        &PackPlanConfig::default(),
    )
    .map_err(|err| failure_inv(37, err))?;

    let mut cache = PackCache::new(64 * 1024);
    let limits = PackDecodeLimits::new(64, 1024 * 1024, 1024 * 1024);
    let mut pack_list = Vec::with_capacity(pack_bytes.pack_count());
    for id in 0..pack_bytes.pack_count() {
        pack_list.push(
            pack_bytes
                .pack_bytes(id as u16)
                .map_err(|err| failure_inv(38, err))?,
        );
    }
    let mut external = SimPackIo::new(
        object_format,
        crate::BytesView::from_vec(midx_faulted),
        pack_list,
        crate::PackIoLimits::new(limits, 32),
    )
    .map_err(|err| failure_inv(39, err))?;

    let mut sink = CollectingSink::default();

    for plan in &plans {
        let reader_bytes = pack_bytes
            .pack_bytes(plan.pack_id)
            .map_err(|err| failure_inv(41, err))?;
        let mut reader = FaultyPackReader::new(
            GitResourceId::Pack {
                pack_id: plan.pack_id,
            },
            reader_bytes,
            &mut state.faults,
            &mut state.trace,
        );

        let report = crate::execute_pack_plan_with_reader(
            plan,
            &mut reader,
            &path_arena,
            &limits,
            &mut cache,
            &mut external,
            &mut sink,
        )
        .map_err(|err| failure_inv(40, err))?;

        collect_skipped_from_report(plan, &report, &mut skipped);
    }

    scanned.extend(sink.scanned);

    state.scanned = dedupe_sorted(scanned);
    state.skipped = dedupe_sorted(skipped);

    Ok(state.scanned.len() as u32)
}

/// Stage 6: derive finalize outcome and commit persistence.
///
/// Builds a minimal `FinalizeOutput` and routes it through the persist
/// store so that `Persist`-targeted faults in the fault plan are exercised.
/// Watermark ops are only produced on a `Complete` outcome, matching the
/// production pipeline's two-phase persistence contract.
fn stage_finalize(state: &mut RunState<'_>) -> Result<u32, FailureReport> {
    let skipped_count = state.skipped.len();
    let outcome = if skipped_count == 0 {
        FinalizeOutcome::Complete
    } else {
        FinalizeOutcome::Partial { skipped_count }
    };

    if matches!(outcome, FinalizeOutcome::Complete) && skipped_count != 0 {
        return Err(failure_inv(50, "complete with skips"));
    }

    // Build a minimal FinalizeOutput and commit it to the persist store.
    // This exercises Persist-targeted faults that partition_fault_plan routed
    // to the SimPersistStore. Data/watermark ops are empty because the
    // simulation does not model per-blob persistence at this level.
    let output = FinalizeOutput {
        data_ops: Vec::new(),
        watermark_ops: Vec::new(),
        outcome,
        stats: FinalizeStats::default(),
    };
    state
        .persist_store
        .commit_finalize(&output)
        .map_err(|err| failure_inv(51, err))?;

    state.outcome = Some(outcome);
    Ok(skipped_count as u32)
}

#[derive(Default)]
struct CollectingSink {
    scanned: Vec<OidBytes>,
}

impl crate::PackObjectSink for CollectingSink {
    fn emit(
        &mut self,
        candidate: &crate::PackCandidate,
        _path: &[u8],
        _bytes: &[u8],
    ) -> Result<(), PackExecError> {
        self.scanned.push(candidate.oid);
        Ok(())
    }
}

/// Map pack-exec skip offsets back to candidate OIDs.
///
/// `candidate_offsets` is sorted by offset, so we can recover all candidates at
/// a skipped offset with two `partition_point` calls and no extra indexing map.
fn collect_skipped_from_report(
    plan: &crate::PackPlan,
    report: &PackExecReport,
    out: &mut Vec<OidBytes>,
) {
    if report.skips.is_empty() {
        return;
    }
    let offsets = &plan.candidate_offsets;
    for skip in &report.skips {
        let start = offsets.partition_point(|c| c.offset < skip.offset);
        let end = offsets.partition_point(|c| c.offset <= skip.offset);
        for cand in &offsets[start..end] {
            let idx = cand.cand_idx as usize;
            if let Some(entry) = plan.candidates.get(idx) {
                out.push(entry.oid);
            }
        }
    }
}

/// Record every semantic candidate as scanned.
///
/// Used when byte-level artifacts are unavailable and we intentionally bypass
/// pack decode.
fn collect_semantic_scan(candidates: &CandidateBuffer, out: &mut Vec<OidBytes>) {
    collect_semantic_candidates(candidates, out);
}

/// Record every semantic candidate as skipped.
///
/// Used when byte-level artifacts are present but incomplete, so decode is not
/// attempted.
fn collect_semantic_skip(candidates: &CandidateBuffer, out: &mut Vec<OidBytes>) {
    collect_semantic_candidates(candidates, out);
}

/// Append all resolved semantic candidate OIDs to `out` in iteration order.
///
/// Shared by the semantic scan/skip fallback paths to keep behavior aligned.
fn collect_semantic_candidates(candidates: &CandidateBuffer, out: &mut Vec<OidBytes>) {
    for cand in candidates.iter_resolved() {
        out.push(cand.oid);
    }
}

/// Extract, sort, and deduplicate OIDs from a semantic candidate buffer.
///
/// The candidate buffer may contain duplicate OIDs (e.g., the same blob
/// referenced from multiple commits). This function normalizes them into
/// a canonical sorted-unique set for oracle comparisons.
fn collect_unique_candidate_oids(candidates: &CandidateBuffer) -> Vec<OidBytes> {
    let mut oids = Vec::with_capacity(candidates.len());
    collect_semantic_candidates(candidates, &mut oids);
    dedupe_sorted(oids)
}

/// Sort and deduplicate OIDs to normalize set-like outputs.
///
/// Downstream invariants and hashes assume canonical ordering.
fn dedupe_sorted(mut oids: Vec<OidBytes>) -> Vec<OidBytes> {
    oids.sort();
    oids.dedup();
    oids
}

/// Build the final run report after validating end-of-run invariants.
fn build_report(state: &RunState<'_>, steps: u64) -> Result<RunReport, FailureReport> {
    let commit_count = state.plan.len() as u32;
    let candidate_count = state
        .candidates
        .as_ref()
        .map(|c| c.len() as u32)
        .unwrap_or(0);
    let outcome = validate_outputs(state)?;

    let scanned_hash = hash_oids(&state.scanned);
    let skipped_hash = hash_oids(&state.skipped);
    let trace_dump = state.trace.dump();
    let trace_hash = hash_trace(&trace_dump);
    let skipped_count = state.skipped.len();

    Ok(RunReport {
        steps,
        commit_count,
        candidate_count,
        skipped_count,
        outcome: SimFinalizeOutcome::from(outcome),
        scanned_hash,
        skipped_hash,
        trace_hash,
        trace_dump,
    })
}

/// Hash a canonical OID set (already sorted + deduped).
fn hash_oids(oids: &[OidBytes]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    for oid in oids {
        hasher.update(oid.as_slice());
    }
    *hasher.finalize().as_bytes()
}

/// Hash trace events in emitted order.
fn hash_trace(events: &[GitTraceEvent]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    for ev in events {
        hash_event(&mut hasher, ev);
    }
    *hasher.finalize().as_bytes()
}

/// Encode one trace event into the trace hash stream.
///
/// Event tag bytes are stable and explicit to keep hash compatibility across
/// refactors.
fn hash_event(hasher: &mut Hasher, ev: &GitTraceEvent) {
    match ev {
        GitTraceEvent::StageEnter { stage_id } => {
            hasher.update(&[1]);
            hasher.update(&stage_id.to_le_bytes());
        }
        GitTraceEvent::StageExit { stage_id, items } => {
            hasher.update(&[2]);
            hasher.update(&stage_id.to_le_bytes());
            hasher.update(&items.to_le_bytes());
        }
        GitTraceEvent::Decision { code } => {
            hasher.update(&[3]);
            hasher.update(&code.to_le_bytes());
        }
        GitTraceEvent::FaultInjected {
            resource_id,
            op,
            kind,
        } => {
            hasher.update(&[4]);
            hasher.update(&resource_id.to_le_bytes());
            hasher.update(&op.to_le_bytes());
            hasher.update(&kind.to_le_bytes());
        }
    }
}

/// Apply a single configured read fault/corruption sequence to an in-memory
/// resource snapshot.
///
/// This path is used for whole-buffer artifacts (for example MIDX bytes) where
/// fault injection occurs before parser construction.
fn apply_fault_to_bytes(
    faults: &mut GitFaultInjector,
    trace: &mut GitTraceRing,
    resource: &GitResourceId,
    bytes: &[u8],
) -> Result<Vec<u8>, FailureReport> {
    let (fault, op) = faults.next_read(resource);
    record_fault_events(trace, resource, op, &fault);

    let mut out = bytes.to_vec();
    if let Some(io_fault) = &fault.fault {
        match io_fault {
            GitIoFault::ErrKind { kind } => {
                return Err(failure_inv(70, format!("fault err kind {kind}")));
            }
            GitIoFault::EIntrOnce => {
                return Err(failure_inv(71, "fault interrupted"));
            }
            GitIoFault::PartialRead { max_len } => {
                let max_len = (*max_len as usize).min(out.len());
                out.truncate(max_len);
            }
        }
    }

    if let Some(corruption) = &fault.corruption {
        apply_corruption_vec(&mut out, corruption);
    }

    Ok(out)
}

/// Emit deterministic fault events into the trace for replay/oracle checks.
fn record_fault_events(
    trace: &mut GitTraceRing,
    resource: &GitResourceId,
    op: u32,
    fault: &super::fault::GitReadFault,
) {
    if let Some(io_fault) = &fault.fault {
        trace.push(GitTraceEvent::FaultInjected {
            resource_id: resource.stable_id(),
            op,
            kind: fault_kind_code(io_fault),
        });
    }
    if let Some(corruption) = &fault.corruption {
        trace.push(GitTraceEvent::FaultInjected {
            resource_id: resource.stable_id(),
            op,
            kind: corruption_kind_code(corruption),
        });
    }
}

/// Apply corruption semantics to an owned byte buffer.
fn apply_corruption_vec(buf: &mut Vec<u8>, corruption: &super::fault::GitCorruption) {
    match corruption {
        super::fault::GitCorruption::TruncateTo { new_len } => {
            let new_len = (*new_len as usize).min(buf.len());
            buf.truncate(new_len);
        }
        super::fault::GitCorruption::FlipBit { offset, mask } => {
            let idx = *offset as usize;
            if idx < buf.len() {
                buf[idx] ^= *mask;
            }
        }
        super::fault::GitCorruption::Overwrite { offset, bytes } => {
            let start = *offset as usize;
            if start >= buf.len() {
                return;
            }
            let len = (buf.len() - start).min(bytes.len());
            buf[start..start + len].copy_from_slice(&bytes[..len]);
        }
    }
}

/// `PackReader` wrapper that injects deterministic per-read faults/corruption.
struct FaultyPackReader<'a> {
    resource: GitResourceId,
    bytes: BytesView,
    faults: &'a mut GitFaultInjector,
    trace: &'a mut GitTraceRing,
}

impl<'a> FaultyPackReader<'a> {
    fn new(
        resource: GitResourceId,
        bytes: BytesView,
        faults: &'a mut GitFaultInjector,
        trace: &'a mut GitTraceRing,
    ) -> Self {
        Self {
            resource,
            bytes,
            faults,
            trace,
        }
    }
}

impl PackReader for FaultyPackReader<'_> {
    fn len(&self) -> u64 {
        self.bytes.len() as u64
    }

    /// Read at `offset`, then apply configured I/O fault and corruption rules.
    ///
    /// Corruption is applied after copy into `dst` to mirror real-world on-wire
    /// corruption behavior.
    fn read_at(&mut self, offset: u64, dst: &mut [u8]) -> Result<usize, PackReadError> {
        let offset_usize = offset as usize;
        let bytes = self.bytes.as_slice();
        if offset_usize > bytes.len() {
            return Err(PackReadError::OutOfRange {
                offset,
                len: dst.len(),
            });
        }

        let (fault, op) = self.faults.next_read(&self.resource);
        record_fault_events(self.trace, &self.resource, op, &fault);

        if let Some(io_fault) = &fault.fault {
            match io_fault {
                GitIoFault::ErrKind { kind } => {
                    return Err(PackReadError::Io(format!("fault err kind {kind}")));
                }
                GitIoFault::EIntrOnce => {
                    return Err(PackReadError::Io("fault interrupted".to_string()));
                }
                GitIoFault::PartialRead { .. } => {}
            }
        }

        let available = &bytes[offset_usize..];
        let mut n = available.len().min(dst.len());

        if let Some(GitIoFault::PartialRead { max_len }) = &fault.fault {
            n = n.min(*max_len as usize);
        }

        dst[..n].copy_from_slice(&available[..n]);

        if let Some(corruption) = &fault.corruption {
            n = apply_corruption_read(dst, n, corruption);
        }

        Ok(n)
    }
}

/// Apply corruption semantics to a borrowed read buffer and returned length.
///
/// Length-changing corruption (`TruncateTo`) updates the logical byte count
/// while in-place corruption mutates only the visible prefix.
fn apply_corruption_read(
    buf: &mut [u8],
    mut len: usize,
    corruption: &super::fault::GitCorruption,
) -> usize {
    match corruption {
        super::fault::GitCorruption::TruncateTo { new_len } => {
            let new_len = (*new_len as usize).min(len);
            len = new_len;
        }
        super::fault::GitCorruption::FlipBit { offset, mask } => {
            let idx = *offset as usize;
            if idx < len {
                buf[idx] ^= *mask;
            }
        }
        super::fault::GitCorruption::Overwrite { offset, bytes } => {
            let start = *offset as usize;
            if start < len {
                let copy_len = (len - start).min(bytes.len());
                buf[start..start + copy_len].copy_from_slice(&bytes[..copy_len]);
            }
        }
    }
    len
}

/// Validate end-of-run invariants and correctness oracles.
fn validate_outputs(state: &RunState<'_>) -> Result<FinalizeOutcome, FailureReport> {
    let outcome = state
        .outcome
        .ok_or_else(|| failure_inv(60, "missing finalize outcome"))?;
    let unique_oids = state
        .unique_oids
        .as_ref()
        .ok_or_else(|| failure_inv(64, "missing spill dedupe output"))?;

    // Enforce set semantics: sorted, unique, and disjoint.
    if !is_sorted_unique(&state.scanned) {
        return Err(failure_inv(61, "scanned OIDs not sorted/unique"));
    }
    if !is_sorted_unique(&state.skipped) {
        return Err(failure_inv(62, "skipped OIDs not sorted/unique"));
    }
    if has_overlap(&state.scanned, &state.skipped) {
        return Err(failure_oracle("scanned and skipped sets overlap"));
    }

    let skipped_count = state.skipped.len();
    match outcome {
        FinalizeOutcome::Complete => {
            if skipped_count != 0 {
                return Err(failure_inv(63, "complete outcome with skips"));
            }
        }
        FinalizeOutcome::Partial {
            skipped_count: expected,
        } => {
            if expected != skipped_count {
                return Err(failure_oracle(format!(
                    "partial skipped_count mismatch: expected {expected}, got {skipped_count}"
                )));
            }
            if skipped_count == 0 {
                return Err(failure_oracle("partial outcome with zero skips"));
            }
        }
    }

    // Conservation check: scanned + skipped must account for every unique OID
    // from spill dedupe. Valid because NeverSeenStore passes all candidates
    // through; if a filtering seen store is introduced, this check must be
    // relaxed to allow for OIDs removed by the seen store.
    let mut accounted_oids = state.scanned.clone();
    accounted_oids.extend_from_slice(&state.skipped);
    let accounted_oids = dedupe_sorted(accounted_oids);
    if accounted_oids != *unique_oids {
        return Err(failure_oracle(
            "spill dedupe OIDs do not match the final scanned/skipped partition",
        ));
    }

    Ok(outcome)
}

/// Return true when `oids` is strictly increasing (sorted + unique).
fn is_sorted_unique(oids: &[OidBytes]) -> bool {
    oids.windows(2).all(|pair| pair[0] < pair[1])
}

/// Detect whether two sorted OID slices intersect.
///
/// This two-pointer walk runs in `O(left.len() + right.len())`.
fn has_overlap(left: &[OidBytes], right: &[OidBytes]) -> bool {
    let mut i = 0usize;
    let mut j = 0usize;
    while i < left.len() && j < right.len() {
        match left[i].cmp(&right[j]) {
            std::cmp::Ordering::Less => i += 1,
            std::cmp::Ordering::Greater => j += 1,
            std::cmp::Ordering::Equal => return true,
        }
    }
    false
}

/// Build an invariant-violation failure with a stable numeric code.
fn failure_inv<T: std::fmt::Display>(code: u32, err: T) -> FailureReport {
    FailureReport {
        kind: FailureKind::InvariantViolation { code },
        message: err.to_string(),
        step: 0,
    }
}

/// Build an oracle-mismatch failure.
fn failure_oracle<T: std::fmt::Display>(err: T) -> FailureReport {
    FailureReport {
        kind: FailureKind::OracleMismatch,
        message: err.to_string(),
        step: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sim_git_scan::fault::GitResourceFaults;
    use crate::sim_git_scan::scenario::{
        GitBlobSpec, GitCommitSpec, GitObjectFormat, GitOid, GitRefSpec, GitRepoModel, GitScenario,
        GitTreeEntryKind, GitTreeEntrySpec, GitTreeSpec,
    };
    use crate::sim_git_scan::PersistPhase;
    use crate::ChangeKind;

    fn oid(val: u8) -> GitOid {
        GitOid {
            bytes: vec![val; 20],
        }
    }

    /// Two independent root commits whose trees both reference the same blob OID.
    ///
    /// TreeDiff emits one candidate per root commit (diffed against empty tree),
    /// producing two candidates with identical OID `oid(30)`. SpillDedupe must
    /// deduplicate them down to a single unique OID.
    fn duplicate_oid_scenario() -> GitScenario {
        GitScenario {
            schema_version: super::super::scenario::GIT_SCENARIO_SCHEMA_VERSION,
            repo: GitRepoModel {
                object_format: GitObjectFormat::Sha1,
                refs: vec![
                    GitRefSpec {
                        name: b"refs/heads/a".to_vec(),
                        tip: oid(1),
                        watermark: None,
                    },
                    GitRefSpec {
                        name: b"refs/heads/b".to_vec(),
                        tip: oid(2),
                        watermark: None,
                    },
                ],
                commits: vec![
                    GitCommitSpec {
                        oid: oid(1),
                        parents: Vec::new(),
                        tree: oid(10),
                        generation: 1,
                    },
                    GitCommitSpec {
                        oid: oid(2),
                        parents: Vec::new(),
                        tree: oid(11),
                        generation: 1,
                    },
                ],
                trees: vec![
                    GitTreeSpec {
                        oid: oid(10),
                        entries: vec![GitTreeEntrySpec {
                            name: b"f.txt".to_vec(),
                            mode: 0o100644,
                            oid: oid(30),
                            kind: GitTreeEntryKind::Blob,
                        }],
                    },
                    GitTreeSpec {
                        oid: oid(11),
                        entries: vec![GitTreeEntrySpec {
                            name: b"g.txt".to_vec(),
                            mode: 0o100644,
                            oid: oid(30),
                            kind: GitTreeEntryKind::Blob,
                        }],
                    },
                ],
                blobs: vec![GitBlobSpec {
                    oid: oid(30),
                    bytes: b"shared".to_vec(),
                }],
            },
            artifacts: None,
        }
    }

    fn simple_scenario() -> GitScenario {
        GitScenario {
            schema_version: super::super::scenario::GIT_SCENARIO_SCHEMA_VERSION,
            repo: GitRepoModel {
                object_format: GitObjectFormat::Sha1,
                refs: vec![GitRefSpec {
                    name: b"refs/heads/main".to_vec(),
                    tip: oid(1),
                    watermark: None,
                }],
                commits: vec![GitCommitSpec {
                    oid: oid(1),
                    parents: Vec::new(),
                    tree: oid(2),
                    generation: 1,
                }],
                trees: vec![GitTreeSpec {
                    oid: oid(2),
                    entries: vec![GitTreeEntrySpec {
                        name: b"file.txt".to_vec(),
                        mode: 0o100644,
                        oid: oid(3),
                        kind: GitTreeEntryKind::Blob,
                    }],
                }],
                blobs: vec![GitBlobSpec {
                    oid: oid(3),
                    bytes: b"hello".to_vec(),
                }],
            },
            artifacts: None,
        }
    }

    #[test]
    fn trace_hash_matches_expected_stage_order() {
        let scenario = simple_scenario();
        let cfg = GitRunConfig {
            workers: 1,
            max_steps: 0,
            stability_runs: 1,
            trace_capacity: 64,
        };
        let runner = GitSimRunner::new(cfg, 7);
        let outcome = runner.run(&scenario, &GitFaultPlan::default());
        let report = match outcome {
            RunOutcome::Ok { report } => report,
            RunOutcome::Failed(fail) => panic!("unexpected failure: {fail:?}"),
        };

        let decision = GitTraceEvent::Decision { code: 1 << 16 };
        let expected = vec![
            decision.clone(),
            GitTraceEvent::StageEnter {
                stage_id: StageKind::RepoOpen as u16,
            },
            GitTraceEvent::StageExit {
                stage_id: StageKind::RepoOpen as u16,
                items: 1,
            },
            decision.clone(),
            GitTraceEvent::StageEnter {
                stage_id: StageKind::CommitWalk as u16,
            },
            GitTraceEvent::StageExit {
                stage_id: StageKind::CommitWalk as u16,
                items: 1,
            },
            decision.clone(),
            GitTraceEvent::StageEnter {
                stage_id: StageKind::TreeDiff as u16,
            },
            GitTraceEvent::StageExit {
                stage_id: StageKind::TreeDiff as u16,
                items: 1,
            },
            decision.clone(),
            GitTraceEvent::StageEnter {
                stage_id: StageKind::SpillDedupe as u16,
            },
            GitTraceEvent::StageExit {
                stage_id: StageKind::SpillDedupe as u16,
                items: 1,
            },
            decision.clone(),
            GitTraceEvent::StageEnter {
                stage_id: StageKind::PackExec as u16,
            },
            GitTraceEvent::StageExit {
                stage_id: StageKind::PackExec as u16,
                items: 1,
            },
            decision,
            GitTraceEvent::StageEnter {
                stage_id: StageKind::Finalize as u16,
            },
            GitTraceEvent::StageExit {
                stage_id: StageKind::Finalize as u16,
                items: 0,
            },
        ];

        let expected_hash = hash_trace(&expected);
        assert_eq!(report.trace_hash, expected_hash);
        assert_eq!(report.commit_count, 1);
        assert_eq!(report.candidate_count, 1);
        assert_eq!(report.skipped_count, 0);
        assert_eq!(report.outcome, SimFinalizeOutcome::Complete);
    }

    #[test]
    fn spill_dedupe_persists_seen_delta_ops() {
        let scenario = simple_scenario();
        let mut state = RunState::new(&scenario, 64, GitFaultPlan::default());

        assert_eq!(stage_repo_open(&mut state).unwrap(), 1);
        assert_eq!(stage_commit_walk(&mut state).unwrap(), 1);
        assert_eq!(stage_tree_diff(&mut state).unwrap(), 1);
        assert_eq!(stage_spill_dedupe(&mut state).unwrap(), 1);

        let seen_ops: Vec<_> = state
            .persist_store
            .log()
            .into_iter()
            .filter(|op| op.phase == PersistPhase::SeenDelta)
            .collect();
        assert_eq!(seen_ops.len(), 1);
        assert_eq!(seen_ops[0].key, vec![3; 20]);

        let spill_stats = state.spill_stats.as_ref().expect("spill stats");
        assert_eq!(spill_stats.spill_runs, 0);
        assert_eq!(spill_stats.spill_bytes, 0);
        assert_eq!(
            state.unique_oids.as_deref(),
            Some(&[OidBytes::sha1([3; 20])][..])
        );
    }

    #[test]
    fn runner_fails_when_seen_persist_fault_is_injected() {
        let scenario = simple_scenario();
        let plan = GitFaultPlan {
            resources: vec![GitResourceFaults {
                resource: GitResourceId::SeenPersist,
                reads: vec![super::super::fault::GitReadFault {
                    fault: Some(GitIoFault::ErrKind { kind: 1 }),
                    latency_ticks: 0,
                    corruption: None,
                }],
            }],
        };
        let cfg = GitRunConfig {
            workers: 1,
            max_steps: 0,
            stability_runs: 1,
            trace_capacity: 64,
        };
        let runner = GitSimRunner::new(cfg, 11);
        let outcome = runner.run(&scenario, &plan);
        let failure = match outcome {
            RunOutcome::Failed(fail) => fail,
            RunOutcome::Ok { report } => panic!("expected failure, got {report:?}"),
        };

        assert!(matches!(
            failure.kind,
            FailureKind::InvariantViolation { code: 84 }
        ));
        assert!(failure.message.contains("seen-persist"));
    }

    #[test]
    fn spill_dedupe_handles_zero_candidates() {
        let scenario = GitScenario {
            schema_version: super::super::scenario::GIT_SCENARIO_SCHEMA_VERSION,
            repo: GitRepoModel {
                object_format: GitObjectFormat::Sha1,
                refs: vec![GitRefSpec {
                    name: b"refs/heads/main".to_vec(),
                    tip: oid(1),
                    watermark: None,
                }],
                commits: vec![GitCommitSpec {
                    oid: oid(1),
                    parents: Vec::new(),
                    tree: oid(2),
                    generation: 1,
                }],
                trees: vec![GitTreeSpec {
                    oid: oid(2),
                    entries: Vec::new(),
                }],
                blobs: Vec::new(),
            },
            artifacts: None,
        };

        let mut state = RunState::new(&scenario, 64, GitFaultPlan::default());

        assert_eq!(stage_repo_open(&mut state).unwrap(), 1);
        assert_eq!(stage_commit_walk(&mut state).unwrap(), 1);
        assert_eq!(stage_tree_diff(&mut state).unwrap(), 0);
        assert_eq!(stage_spill_dedupe(&mut state).unwrap(), 0);

        let seen_ops: Vec<_> = state
            .persist_store
            .log()
            .into_iter()
            .filter(|op| op.phase == PersistPhase::SeenDelta)
            .collect();
        assert!(seen_ops.is_empty());

        let spill_stats = state.spill_stats.as_ref().expect("spill stats");
        assert_eq!(spill_stats.candidates_received, 0);
        assert_eq!(spill_stats.emitted_blobs, 0);
        assert_eq!(state.unique_oids.as_deref(), Some(&[][..]));
    }

    #[test]
    fn spill_dedupe_deduplicates_shared_blob_across_refs() {
        let scenario = duplicate_oid_scenario();
        let mut state = RunState::new(&scenario, 64, GitFaultPlan::default());

        assert_eq!(stage_repo_open(&mut state).unwrap(), 2);
        assert_eq!(stage_commit_walk(&mut state).unwrap(), 2);
        assert_eq!(stage_tree_diff(&mut state).unwrap(), 2);
        assert_eq!(stage_spill_dedupe(&mut state).unwrap(), 1);

        assert_eq!(
            state.unique_oids.as_deref(),
            Some(&[OidBytes::sha1([30; 20])][..])
        );

        let seen_ops: Vec<_> = state
            .persist_store
            .log()
            .into_iter()
            .filter(|op| op.phase == PersistPhase::SeenDelta)
            .collect();
        assert_eq!(seen_ops.len(), 1);
        assert_eq!(seen_ops[0].key, vec![30; 20]);

        let spill_stats = state.spill_stats.as_ref().expect("spill stats");
        assert_eq!(spill_stats.spill_runs, 0);
    }

    #[test]
    fn spiller_persists_seen_deltas_through_disk_spill() {
        let limits = SpillLimits {
            max_spill_bytes: 512 * 1024 * 1024,
            seen_batch_max_oids: 256,
            seen_batch_max_path_bytes: 64 * 1024,
            max_chunk_candidates: 1,
            max_chunk_path_bytes: 1024 * 1024,
            max_spill_runs: 16,
            max_path_len: 4 * 1024,
        };
        let spill_dir = tempdir().unwrap();
        let mut spiller = Spiller::new(limits, 20, spill_dir.path()).unwrap();

        let oids = [
            OidBytes::sha1([1; 20]),
            OidBytes::sha1([2; 20]),
            OidBytes::sha1([3; 20]),
        ];
        let paths: [&[u8]; 3] = [b"a.txt", b"b.txt", b"c.txt"];
        for (i, (oid, path)) in oids.iter().zip(paths.iter()).enumerate() {
            spiller
                .push(*oid, path, i as u32, 0, ChangeKind::Add, 0, 0)
                .unwrap();
        }

        let persist_store = SimPersistStore::default();
        let mut sink = CollectingUniqueBlobSink::default();
        let stats = spiller
            .finalize(&NeverSeenStore, &persist_store, &mut sink)
            .unwrap();

        assert!(stats.spill_runs > 0, "expected at least one spill run");
        assert!(stats.spill_bytes > 0, "expected nonzero spill bytes");
        assert_eq!(sink.blobs.len(), 3);

        let seen_ops: Vec<_> = persist_store
            .log()
            .into_iter()
            .filter(|op| op.phase == PersistPhase::SeenDelta)
            .collect();
        assert_eq!(seen_ops.len(), 3);
    }

    #[test]
    fn run_halts_when_step_budget_exceeded() {
        let scenario = simple_scenario();
        let cfg = GitRunConfig {
            workers: 1,
            max_steps: 2,
            stability_runs: 1,
            trace_capacity: 32,
        };
        let runner = GitSimRunner::new(cfg, 1);
        let outcome = runner.run(&scenario, &GitFaultPlan::default());
        let failure = match outcome {
            RunOutcome::Failed(fail) => fail,
            RunOutcome::Ok { .. } => panic!("expected hang failure"),
        };

        assert!(matches!(failure.kind, FailureKind::Hang));
        assert_eq!(failure.message, "max steps exceeded");
    }

    #[test]
    fn corrupt_midx_bytes_fail_parse() {
        let midx_bytes = build_minimal_midx();
        let plan = GitFaultPlan {
            resources: vec![super::super::fault::GitResourceFaults {
                resource: GitResourceId::Midx,
                reads: vec![super::super::fault::GitReadFault {
                    fault: None,
                    latency_ticks: 0,
                    corruption: Some(super::super::fault::GitCorruption::TruncateTo { new_len: 8 }),
                }],
            }],
        };

        let mut injector = GitFaultInjector::new(plan);
        let mut trace = GitTraceRing::new(16);
        let faulted =
            apply_fault_to_bytes(&mut injector, &mut trace, &GitResourceId::Midx, &midx_bytes)
                .expect("faulted bytes");

        let parsed = crate::MidxView::parse(&faulted, crate::ObjectFormat::Sha1);
        assert!(parsed.is_err(), "corrupt midx should fail parse");
    }

    #[test]
    fn pack_reader_partial_read_returns_error() {
        use crate::delta_test_helpers::{encode_entry_header_kind, zlib_compress as compress};
        use crate::pack_inflate::ObjectKind;
        use crate::pack_plan_model::CandidateAtOffset;
        use crate::{
            execute_pack_plan_with_reader, ByteArena, CandidateContext, ChangeKind, PackCache,
            PackCandidate, PackDecodeLimits, PackExecError, PackPlan, PackPlanStats,
        };
        use crate::{ExternalBase, ExternalBaseProvider, PackObjectSink};

        struct NoExternal;

        impl ExternalBaseProvider for NoExternal {
            fn load_base(
                &mut self,
                _oid: &crate::OidBytes,
            ) -> Result<Option<ExternalBase>, PackExecError> {
                Ok(None)
            }
        }

        #[derive(Default)]
        struct CollectingSink {
            scanned: Vec<crate::OidBytes>,
        }

        impl PackObjectSink for CollectingSink {
            fn emit(
                &mut self,
                candidate: &PackCandidate,
                _path: &[u8],
                _bytes: &[u8],
            ) -> Result<(), PackExecError> {
                self.scanned.push(candidate.oid);
                Ok(())
            }
        }

        fn build_pack(entries: &[(ObjectKind, &[u8])]) -> (Vec<u8>, Vec<u64>) {
            let mut bytes = Vec::new();
            bytes.extend_from_slice(b"PACK");
            bytes.extend_from_slice(&2u32.to_be_bytes());
            bytes.extend_from_slice(&(entries.len() as u32).to_be_bytes());

            let mut offsets = Vec::with_capacity(entries.len());
            for (kind, data) in entries {
                offsets.push(bytes.len() as u64);
                bytes.extend_from_slice(&encode_entry_header_kind(*kind, data.len()));
                bytes.extend_from_slice(&compress(data));
            }

            bytes.extend_from_slice(&[0u8; 20]);
            (bytes, offsets)
        }

        let (pack, offsets) = build_pack(&[(ObjectKind::Blob, b"hello")]);
        let plan = PackPlan {
            pack_id: 0,
            oid_len: 20,
            max_delta_depth: 0,
            candidates: vec![PackCandidate {
                oid: crate::OidBytes::sha1([0x11; 20]),
                ctx: CandidateContext {
                    commit_id: 1,
                    parent_idx: 0,
                    change_kind: ChangeKind::Add,
                    ctx_flags: 0,
                    cand_flags: 0,
                    path_ref: crate::ByteRef::new(0, 0),
                },
                pack_id: 0,
                offset: offsets[0],
            }],
            candidate_offsets: vec![CandidateAtOffset {
                offset: offsets[0],
                cand_idx: 0,
            }],
            need_offsets: vec![offsets[0]],
            delta_deps: Vec::new(),
            delta_dep_index: Vec::new(),
            exec_order: None,
            stats: PackPlanStats {
                candidate_count: 1,
                need_count: 1,
                external_bases: 0,
                forward_deps: 0,
                candidate_span: 0,
                ..PackPlanStats::empty()
            },
        };

        let plan_fault = GitFaultPlan {
            resources: vec![super::super::fault::GitResourceFaults {
                resource: GitResourceId::Pack { pack_id: 0 },
                reads: vec![super::super::fault::GitReadFault {
                    fault: Some(GitIoFault::PartialRead { max_len: 8 }),
                    latency_ticks: 0,
                    corruption: None,
                }],
            }],
        };

        let mut injector = GitFaultInjector::new(plan_fault);
        let mut trace = GitTraceRing::new(16);
        let mut reader = FaultyPackReader::new(
            GitResourceId::Pack { pack_id: 0 },
            BytesView::from_vec(pack),
            &mut injector,
            &mut trace,
        );

        let arena = ByteArena::with_capacity(32);
        let mut cache = PackCache::new(64 * 1024);
        let limits = PackDecodeLimits::new(64, 1024, 1024);
        let mut sink = CollectingSink::default();
        let mut external = NoExternal;

        let err = execute_pack_plan_with_reader(
            &plan,
            &mut reader,
            &arena,
            &limits,
            &mut cache,
            &mut external,
            &mut sink,
        )
        .expect_err("expected pack read error");
        assert!(matches!(err, PackExecError::PackRead(_)));
    }

    #[test]
    fn validate_outputs_rejects_mismatched_oid_partition() {
        let scenario = simple_scenario();
        let mut state = RunState::new(&scenario, 64, GitFaultPlan::default());

        stage_repo_open(&mut state).unwrap();
        stage_commit_walk(&mut state).unwrap();
        stage_tree_diff(&mut state).unwrap();
        stage_spill_dedupe(&mut state).unwrap();
        stage_pack_exec(&mut state).unwrap();
        stage_finalize(&mut state).unwrap();

        // Corrupt unique_oids so the conservation oracle fires.
        state.unique_oids = Some(vec![OidBytes::sha1([99; 20])]);

        let err = validate_outputs(&state).expect_err("expected oracle mismatch");
        assert!(matches!(err.kind, FailureKind::OracleMismatch));
        assert!(err.message.contains("scanned/skipped partition"));
    }

    #[test]
    fn pack_exec_rejects_mismatched_spill_oids() {
        let scenario = simple_scenario();
        let mut state = RunState::new(&scenario, 64, GitFaultPlan::default());

        stage_repo_open(&mut state).unwrap();
        stage_commit_walk(&mut state).unwrap();
        stage_tree_diff(&mut state).unwrap();
        stage_spill_dedupe(&mut state).unwrap();

        // Corrupt unique_oids so the pack-exec precondition oracle fires.
        state.unique_oids = Some(vec![OidBytes::sha1([99; 20])]);

        let err = stage_pack_exec(&mut state).expect_err("expected oracle mismatch");
        assert!(matches!(err.kind, FailureKind::OracleMismatch));
        assert!(err.message.contains("spill dedupe unique OIDs differ"));
    }

    #[test]
    fn partition_fault_plan_splits_resources_correctly() {
        let plan = GitFaultPlan {
            resources: vec![
                GitResourceFaults {
                    resource: GitResourceId::CommitGraph,
                    reads: Vec::new(),
                },
                GitResourceFaults {
                    resource: GitResourceId::Persist,
                    reads: Vec::new(),
                },
                GitResourceFaults {
                    resource: GitResourceId::Pack { pack_id: 0 },
                    reads: Vec::new(),
                },
                GitResourceFaults {
                    resource: GitResourceId::SeenPersist,
                    reads: Vec::new(),
                },
                GitResourceFaults {
                    resource: GitResourceId::Midx,
                    reads: Vec::new(),
                },
            ],
        };

        let (runner, persist) = partition_fault_plan(plan);

        let runner_ids: Vec<_> = runner.resources.iter().map(|r| &r.resource).collect();
        assert_eq!(
            runner_ids,
            vec![
                &GitResourceId::CommitGraph,
                &GitResourceId::Pack { pack_id: 0 },
                &GitResourceId::Midx,
            ]
        );

        let persist_ids: Vec<_> = persist.resources.iter().map(|r| &r.resource).collect();
        assert_eq!(
            persist_ids,
            vec![&GitResourceId::Persist, &GitResourceId::SeenPersist,]
        );

        // Empty plan produces two empty partitions.
        let (runner_empty, persist_empty) = partition_fault_plan(GitFaultPlan::default());
        assert!(runner_empty.resources.is_empty());
        assert!(persist_empty.resources.is_empty());
    }

    #[test]
    fn mixed_runner_and_persist_faults_route_correctly() {
        let scenario = simple_scenario();
        let plan = GitFaultPlan {
            resources: vec![
                GitResourceFaults {
                    resource: GitResourceId::Pack { pack_id: 0 },
                    reads: vec![super::super::fault::GitReadFault {
                        fault: Some(GitIoFault::ErrKind { kind: 1 }),
                        latency_ticks: 0,
                        corruption: None,
                    }],
                },
                GitResourceFaults {
                    resource: GitResourceId::SeenPersist,
                    reads: vec![super::super::fault::GitReadFault {
                        fault: Some(GitIoFault::ErrKind { kind: 1 }),
                        latency_ticks: 0,
                        corruption: None,
                    }],
                },
            ],
        };

        let cfg = GitRunConfig {
            workers: 1,
            max_steps: 0,
            stability_runs: 1,
            trace_capacity: 64,
        };
        let runner = GitSimRunner::new(cfg, 42);
        let outcome = runner.run(&scenario, &plan);

        // SeenPersist fault fires during spill dedupe (stage 4, code 84) before
        // pack exec, so the pack fault is never consumed.
        let failure = match outcome {
            RunOutcome::Failed(fail) => fail,
            RunOutcome::Ok { report } => panic!("expected failure, got {report:?}"),
        };

        assert!(
            matches!(failure.kind, FailureKind::InvariantViolation { code: 84 }),
            "expected InvariantViolation {{ code: 84 }}, got {:?}",
            failure.kind
        );
        assert!(
            failure.message.contains("seen-persist"),
            "expected message containing 'seen-persist', got {:?}",
            failure.message
        );
    }

    fn build_minimal_midx() -> Vec<u8> {
        const MIDX_MAGIC: [u8; 4] = *b"MIDX";
        const MIDX_VERSION: u8 = 1;
        const MIDX_HEADER_SIZE: usize = 12;
        const CHUNK_ENTRY_SIZE: usize = 12;
        const CHUNK_PNAM: [u8; 4] = *b"PNAM";
        const CHUNK_OIDF: [u8; 4] = *b"OIDF";
        const CHUNK_OIDL: [u8; 4] = *b"OIDL";
        const CHUNK_OOFF: [u8; 4] = *b"OOFF";
        const FANOUT_SIZE: usize = 256 * 4;

        let pack_names = vec![b"pack-test".to_vec()];
        let objects = vec![([0x11; 20], 0u16, 100u64)];

        let mut pnam = Vec::new();
        for name in &pack_names {
            pnam.extend_from_slice(name);
            pnam.push(0);
        }

        let mut oidf = vec![0u8; FANOUT_SIZE];
        let mut counts = [0u32; 256];
        for (oid, _, _) in &objects {
            counts[oid[0] as usize] += 1;
        }
        let mut running = 0u32;
        for (i, count) in counts.iter().enumerate() {
            running += count;
            let off = i * 4;
            oidf[off..off + 4].copy_from_slice(&running.to_be_bytes());
        }

        let mut oidl = Vec::with_capacity(objects.len() * 20);
        let mut ooff = Vec::with_capacity(objects.len() * 8);
        for (oid, pack_id, offset) in &objects {
            oidl.extend_from_slice(oid);
            ooff.extend_from_slice(&(*pack_id as u32).to_be_bytes());
            ooff.extend_from_slice(&(*offset as u32).to_be_bytes());
        }

        let chunk_count = 4u8;
        let header_size = MIDX_HEADER_SIZE;
        let chunk_table_size = (chunk_count as usize + 1) * CHUNK_ENTRY_SIZE;

        let pnam_off = (header_size + chunk_table_size) as u64;
        let oidf_off = pnam_off + pnam.len() as u64;
        let oidl_off = oidf_off + oidf.len() as u64;
        let ooff_off = oidl_off + oidl.len() as u64;
        let end_off = ooff_off + ooff.len() as u64;

        let mut out = Vec::new();
        out.extend_from_slice(&MIDX_MAGIC);
        out.push(MIDX_VERSION);
        out.push(1); // SHA-1
        out.push(chunk_count);
        out.push(0); // base count
        out.extend_from_slice(&(pack_names.len() as u32).to_be_bytes());

        let mut push_chunk = |id: [u8; 4], off: u64| {
            out.extend_from_slice(&id);
            out.extend_from_slice(&off.to_be_bytes());
        };

        push_chunk(CHUNK_PNAM, pnam_off);
        push_chunk(CHUNK_OIDF, oidf_off);
        push_chunk(CHUNK_OIDL, oidl_off);
        push_chunk(CHUNK_OOFF, ooff_off);
        push_chunk([0, 0, 0, 0], end_off);

        out.extend_from_slice(&pnam);
        out.extend_from_slice(&oidf);
        out.extend_from_slice(&oidl);
        out.extend_from_slice(&ooff);
        out
    }
}

#[cfg(all(test, feature = "stdx-proptest"))]
#[path = "runner_tests.rs"]
mod runner_tests;
