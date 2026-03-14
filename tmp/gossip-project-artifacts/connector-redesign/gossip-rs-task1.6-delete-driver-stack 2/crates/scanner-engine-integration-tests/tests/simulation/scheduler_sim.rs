#![cfg(any(test, feature = "scheduler-sim"))]
//! Determinism and corpus-replay coverage tests for the scheduler simulator.

use std::{env, fs};

use crate::scanner_rs::scheduler::rng::XorShift64;
use crate::scanner_rs::scheduler::sim_executor_harness::{
    DriverAction, DriverChoice, ExecTraceEventSimple, ExecTraceSource, ExternalEvent, FailureInfo,
    FailureKind, Instruction, LogicalTaskInit, ReproArtifact, ResourceSpec, ScheduledEvent,
    SimCase, SimExecCfg, SpawnPlacement, TaskProgram, Trace, TraceEvent, ViolationKind,
    assert_deterministic, run_with_choices, run_with_driver, trace_hash,
};

/// Aggregate coverage across the serialized corpus.
///
/// # Coverage Philosophy
///
/// The corpus aims to be "exhaustive-ish": every scheduler-relevant code path
/// should be exercised by at least one artifact. This provides regression
/// protection without requiring exhaustive enumeration of all interleavings.
///
/// # Coverage Categories
///
/// - **Instruction coverage**: Each bytecode instruction type
/// - **Placement coverage**: All spawn placement variants (`Local`, `Global`, `External`)
/// - **Queue coverage**: Pop from local, injector, and steal paths
/// - **Driver coverage**: Time advance and external event delivery
///
/// # Maintenance
///
/// When adding new instructions or scheduler features:
/// 1. Add corresponding coverage flags to this struct
/// 2. Update `observe_trace()` to track the new path
/// 3. Update `assert_complete()` to require coverage
/// 4. Add a corpus artifact in `tests/simulation/corpus/` that exercises the path
#[derive(Default)]
struct CorpusCoverage {
    multi_worker: bool,
    instr_yield: bool,
    instr_spawn: bool,
    instr_spawn_local: bool,
    instr_spawn_global: bool,
    instr_spawn_external: bool,
    instr_sleep: bool,
    instr_wait_io: bool,
    instr_try_acquire: bool,
    instr_release: bool,
    instr_jump: bool,
    instr_complete: bool,
    instr_panic: bool,
    pop_local: bool,
    pop_injector: bool,
    pop_steal: bool,
    advance_time: bool,
    external_io: bool,
    external_close_gate: bool,
    exec_panic_recorded: bool,
}

impl CorpusCoverage {
    fn observe_case(&mut self, case: &SimCase) {
        if case.exec_cfg.workers > 1 {
            self.multi_worker = true;
        }
    }

    fn observe_trace(&mut self, trace: &Trace) {
        for event in &trace.events {
            match event {
                TraceEvent::Step { action, .. } => {
                    if matches!(action, DriverAction::AdvanceTimeTo { .. }) {
                        self.advance_time = true;
                    }
                }
                TraceEvent::Exec { event } => match event {
                    ExecTraceEventSimple::Pop { source, .. } => match source {
                        ExecTraceSource::Local => self.pop_local = true,
                        ExecTraceSource::Injector => self.pop_injector = true,
                        ExecTraceSource::Steal => self.pop_steal = true,
                    },
                    ExecTraceEventSimple::PanicRecorded => {
                        self.exec_panic_recorded = true;
                    }
                    _ => {}
                },
                TraceEvent::TaskInstr { instr, .. } => match instr {
                    Instruction::Yield { .. } => {
                        self.instr_yield = true;
                    }
                    Instruction::Spawn { placement, .. } => {
                        self.instr_spawn = true;
                        match placement {
                            SpawnPlacement::Local => self.instr_spawn_local = true,
                            SpawnPlacement::Global => self.instr_spawn_global = true,
                            SpawnPlacement::External => self.instr_spawn_external = true,
                        }
                    }
                    Instruction::Sleep { .. } => self.instr_sleep = true,
                    Instruction::WaitIo { .. } => self.instr_wait_io = true,
                    Instruction::TryAcquire { .. } => self.instr_try_acquire = true,
                    Instruction::Release { .. } => self.instr_release = true,
                    Instruction::Jump { .. } => self.instr_jump = true,
                    Instruction::Complete => self.instr_complete = true,
                    Instruction::Panic => self.instr_panic = true,
                },
                TraceEvent::External { event } => match event {
                    ExternalEvent::IoComplete { .. } => self.external_io = true,
                    ExternalEvent::CloseGateJoin => self.external_close_gate = true,
                },
                TraceEvent::InvariantViolation { .. } => {}
            }
        }
    }

    fn assert_complete(&self) {
        let mut missing = Vec::new();
        if !self.multi_worker {
            missing.push("multi-worker case");
        }
        if !self.instr_yield {
            missing.push("instruction: Yield");
        }
        if !self.instr_spawn {
            missing.push("instruction: Spawn");
        }
        if !self.instr_spawn_local {
            missing.push("spawn placement: Local");
        }
        if !self.instr_spawn_global {
            missing.push("spawn placement: Global");
        }
        if !self.instr_spawn_external {
            missing.push("spawn placement: External");
        }
        if !self.instr_sleep {
            missing.push("instruction: Sleep");
        }
        if !self.instr_wait_io {
            missing.push("instruction: WaitIo");
        }
        if !self.instr_try_acquire {
            missing.push("instruction: TryAcquire");
        }
        if !self.instr_release {
            missing.push("instruction: Release");
        }
        if !self.instr_jump {
            missing.push("instruction: Jump");
        }
        if !self.instr_complete {
            missing.push("instruction: Complete");
        }
        if !self.pop_local {
            missing.push("pop source: Local");
        }
        if !self.pop_injector {
            missing.push("pop source: Injector");
        }
        if !self.pop_steal {
            missing.push("pop source: Steal");
        }
        if !self.advance_time {
            missing.push("driver action: AdvanceTimeTo");
        }
        if !self.external_io {
            missing.push("external: IoComplete");
        }
        if !self.external_close_gate {
            missing.push("external: CloseGateJoin");
        }

        assert!(
            missing.is_empty(),
            "corpus coverage missing: {}",
            missing.join(", ")
        );
    }
}

/// Minimal deterministic case used to sanity-check replay logic.
fn simple_case(seed: u64) -> SimCase {
    let exec_cfg = SimExecCfg {
        workers: 2,
        steal_tries: 2,
        seed,
        wake_on_hoard_threshold: 32,
    };

    let programs = vec![TaskProgram {
        name: "root".to_string(),
        code: vec![
            Instruction::Yield {
                placement: SpawnPlacement::Local,
            },
            Instruction::Complete,
        ],
    }];

    SimCase {
        exec_cfg,
        resources: vec![ResourceSpec { id: 0, total: 4 }],
        programs,
        tasks: vec![LogicalTaskInit {
            tid: 0,
            program: 0,
            pc: 0,
        }],
        initial_runnable: vec![0],
        external_events: vec![ScheduledEvent {
            at_step: 3,
            event: ExternalEvent::CloseGateJoin,
        }],
        max_steps: 50,
    }
}

/// Configuration for low-cost stress runs driven by the simulator.
///
/// These defaults are intentionally small to keep per-push CI fast; the
/// values can be increased via environment variables for ad-hoc or cron
/// workloads.
#[derive(Clone, Copy, Debug)]
struct StressConfig {
    seeds: u64,
    max_steps: u64,
    max_programs: usize,
    max_tasks: usize,
    seed_base: u64,
}

impl StressConfig {
    fn from_env() -> Self {
        Self {
            seeds: env_u64("SCHEDULER_SIM_STRESS_SEEDS", 16),
            max_steps: env_u64("SCHEDULER_SIM_STRESS_MAX_STEPS", 80).max(10),
            max_programs: env_usize("SCHEDULER_SIM_STRESS_MAX_PROGRAMS", 4).max(1),
            max_tasks: env_usize("SCHEDULER_SIM_STRESS_MAX_TASKS", 4).max(1),
            seed_base: env_u64("SCHEDULER_SIM_STRESS_SEED_BASE", 0xD00D_BEEF),
        }
    }
}

fn env_u64(key: &str, default: u64) -> u64 {
    env::var(key)
        .ok()
        .and_then(|val| val.parse().ok())
        .unwrap_or(default)
}

fn env_usize(key: &str, default: usize) -> usize {
    env::var(key)
        .ok()
        .and_then(|val| val.parse().ok())
        .unwrap_or(default)
}

#[derive(Clone, Copy, Debug)]
enum TemplateKind {
    Yield,
    SpawnLocal,
    SpawnGlobal,
    SpawnExternal,
    WaitIo,
    Sleep,
    Resource,
}

fn is_spawn_kind(kind: TemplateKind) -> bool {
    matches!(
        kind,
        TemplateKind::SpawnLocal | TemplateKind::SpawnGlobal | TemplateKind::SpawnExternal
    )
}

fn random_program(
    kind: TemplateKind,
    rng: &mut XorShift64,
    spawn_targets: &[usize],
    next_token: &mut u32,
) -> (TaskProgram, Option<u32>, bool) {
    let name = format!("{kind:?}");
    match kind {
        TemplateKind::Yield => (
            TaskProgram {
                name,
                code: vec![
                    Instruction::Yield {
                        placement: random_placement(rng),
                    },
                    Instruction::Complete,
                ],
            },
            None,
            false,
        ),
        TemplateKind::SpawnLocal | TemplateKind::SpawnGlobal | TemplateKind::SpawnExternal => {
            let placement = match kind {
                TemplateKind::SpawnLocal => SpawnPlacement::Local,
                TemplateKind::SpawnGlobal => SpawnPlacement::Global,
                TemplateKind::SpawnExternal => SpawnPlacement::External,
                _ => SpawnPlacement::Local,
            };
            let target = spawn_targets
                .get(rng.next_usize(spawn_targets.len()))
                .copied()
                .unwrap_or(0) as u32;
            (
                TaskProgram {
                    name,
                    code: vec![
                        Instruction::Spawn {
                            program: target,
                            placement,
                        },
                        Instruction::Complete,
                    ],
                },
                None,
                false,
            )
        }
        TemplateKind::WaitIo => {
            let token = *next_token;
            *next_token = next_token.saturating_add(1);
            (
                TaskProgram {
                    name,
                    code: vec![Instruction::WaitIo { token }, Instruction::Complete],
                },
                Some(token),
                false,
            )
        }
        TemplateKind::Sleep => {
            let ticks = 1 + rng.next_u32(3);
            (
                TaskProgram {
                    name,
                    code: vec![Instruction::Sleep { ticks }, Instruction::Complete],
                },
                None,
                false,
            )
        }
        TemplateKind::Resource => (
            TaskProgram {
                name,
                code: vec![
                    Instruction::TryAcquire {
                        res: 0,
                        units: 1,
                        ok: 1,
                        fail: 3,
                    },
                    Instruction::Release { res: 0, units: 1 },
                    Instruction::Complete,
                    Instruction::Complete,
                ],
            },
            None,
            true,
        ),
    }
}

fn random_placement(rng: &mut XorShift64) -> SpawnPlacement {
    match rng.next_usize(3) {
        0 => SpawnPlacement::Local,
        1 => SpawnPlacement::Global,
        _ => SpawnPlacement::External,
    }
}

fn tokens_for_kind(kind: TemplateKind) -> usize {
    match kind {
        TemplateKind::Yield => 1,
        TemplateKind::WaitIo | TemplateKind::Sleep => 1,
        TemplateKind::SpawnLocal | TemplateKind::SpawnGlobal | TemplateKind::SpawnExternal => 2,
        TemplateKind::Resource => 3,
    }
}

/// Fair, deterministic driver policy for stress runs.
///
/// # Policy
///
/// ```text
/// Priority 1: DeliverEvent   (ensures external events don't starve)
/// Priority 2: StepWorker     (round-robin across worker IDs)
/// Priority 3: AdvanceTimeTo  (implicit from enabled_actions)
/// ```
///
/// # Why Round-Robin?
///
/// A biased driver (e.g., always picking worker 0) can cause artificial
/// starvation that doesn't represent real scheduler behavior. Round-robin
/// ensures all workers get execution opportunities, so any starvation
/// violation represents a genuine scheduler bug.
///
/// # Determinism
///
/// The driver is deterministic given the same enabled action sequence.
/// This allows failed stress seeds to be replayed exactly.
struct FairDriver {
    next_worker: usize,
}

impl FairDriver {
    fn new() -> Self {
        Self { next_worker: 0 }
    }

    fn choose(&mut self, enabled: &[DriverAction]) -> DriverAction {
        if let Some(action) = enabled
            .iter()
            .find(|action| matches!(action, DriverAction::DeliverEvent { .. }))
        {
            return action.clone();
        }

        let mut worker_ids: Vec<usize> = enabled
            .iter()
            .filter_map(|action| match action {
                DriverAction::StepWorker { wid } => Some(*wid),
                _ => None,
            })
            .collect();

        if worker_ids.is_empty() {
            return enabled[0].clone();
        }

        worker_ids.sort_unstable();
        let target = worker_ids
            .iter()
            .copied()
            .find(|wid| *wid >= self.next_worker)
            .unwrap_or(worker_ids[0]);

        let max_wid = *worker_ids.last().unwrap_or(&0);
        self.next_worker = target.saturating_add(1);
        if self.next_worker > max_wid {
            self.next_worker = 0;
        }

        enabled
            .iter()
            .find(|action| matches!(action, DriverAction::StepWorker { wid } if *wid == target))
            .cloned()
            .unwrap_or_else(|| enabled[0].clone())
    }
}

/// Recording wrapper for `FairDriver` that emits choice indices.
///
/// This allows failing stress seeds to be captured as replayable artifacts.
struct RecordingDriver {
    fair: FairDriver,
    choices: Vec<DriverChoice>,
}

impl RecordingDriver {
    fn new() -> Self {
        Self {
            fair: FairDriver::new(),
            choices: Vec::new(),
        }
    }

    fn choose(&mut self, enabled: &[DriverAction]) -> DriverAction {
        let action = self.fair.choose(enabled);
        let idx = enabled
            .iter()
            .position(|candidate| *candidate == action)
            .unwrap_or(0);
        self.choices.push(DriverChoice { idx: idx as u16 });
        action
    }
}

/// Persist a replayable artifact for a failed stress seed.
fn write_failure_artifact(
    seed: u64,
    case: SimCase,
    choices: Vec<DriverChoice>,
    trace: &Trace,
    violation: &ViolationKind,
    message: &str,
    step: u64,
) {
    let artifact = ReproArtifact {
        schema_version: 1,
        seed,
        case,
        driver_choices: choices,
        expected_trace_hash: trace_hash(trace),
        failure: FailureInfo {
            kind: FailureKind::Violation(violation.clone()),
            step,
            message: message.to_string(),
        },
    };

    let out_dir = "tests/failures";
    fs::create_dir_all(out_dir).expect("create failure dir");
    let path = format!("{out_dir}/seed_{seed}.json");
    let json = serde_json::to_string_pretty(&artifact).expect("serialize failure artifact");
    fs::write(&path, json).expect("write failure artifact");
}

/// Build a small randomized case from a fixed seed.
///
/// # Validity Guarantees
///
/// Generated cases are always valid:
/// - At least one non-spawn program exists (prevents infinite spawn loops)
/// - Spawn targets reference valid program indices
/// - IO tokens have corresponding `IoComplete` events scheduled
/// - Resource programs reference resource ID 0 (created if needed)
///
/// # Termination Guarantee
///
/// Cases terminate within `max_steps` under a fair driver because:
/// - No instruction creates unbounded work (spawns are finite)
/// - External events are scheduled before `max_steps / 2`
/// - All blocking instructions (`WaitIo`, `Sleep`) have wakeup events
///
/// # Template Approach
///
/// We use bounded templates instead of arbitrary bytecode so the generated
/// programs stay valid and terminate under small step budgets. Each template
/// produces a self-contained program with known behavior.
fn random_case(seed: u64, cfg: StressConfig) -> SimCase {
    let mut rng = XorShift64::new(seed);

    let workers = 1 + rng.next_usize(2);
    let exec_cfg = SimExecCfg {
        workers,
        steal_tries: 2,
        seed,
        wake_on_hoard_threshold: 32,
    };

    let templates = [
        TemplateKind::Yield,
        TemplateKind::SpawnLocal,
        TemplateKind::SpawnGlobal,
        TemplateKind::SpawnExternal,
        TemplateKind::WaitIo,
        TemplateKind::Sleep,
        TemplateKind::Resource,
    ];

    let program_count = 1 + rng.next_usize(cfg.max_programs);
    let mut programs = Vec::with_capacity(program_count);
    let mut kinds = Vec::with_capacity(program_count);
    let mut io_tokens = Vec::new();
    let mut needs_resource = false;
    let mut next_token = 1u32;

    for _ in 0..program_count {
        kinds.push(templates[rng.next_usize(templates.len())]);
    }

    if kinds.iter().all(|kind| is_spawn_kind(*kind)) {
        kinds[program_count - 1] = TemplateKind::Yield;
    }

    let spawn_targets: Vec<usize> = kinds
        .iter()
        .enumerate()
        .filter_map(|(idx, kind)| (!is_spawn_kind(*kind)).then_some(idx))
        .collect();

    for kind in kinds.iter().copied() {
        let (program, token, uses_resource) =
            random_program(kind, &mut rng, &spawn_targets, &mut next_token);
        if let Some(token) = token {
            io_tokens.push(token);
        }
        if uses_resource {
            needs_resource = true;
        }
        programs.push(program);
    }

    let task_count = 1 + rng.next_usize(cfg.max_tasks);
    let mut tasks = Vec::with_capacity(task_count);
    let mut initial_runnable = Vec::new();

    for tid in 0..task_count {
        let program = rng.next_usize(programs.len());
        tasks.push(LogicalTaskInit {
            tid: tid as u32,
            program: program as u32,
            pc: 0,
        });
        let tokens = tokens_for_kind(kinds[program]);
        for _ in 0..tokens {
            initial_runnable.push(tid as u32);
        }
    }

    let mut external_events = Vec::new();
    let step_cap = (cfg.max_steps / 2).max(1) as u32;
    for token in io_tokens {
        let at_step = 1 + rng.next_u32(step_cap);
        external_events.push(ScheduledEvent {
            at_step: at_step as u64,
            event: ExternalEvent::IoComplete { token },
        });
    }

    if rng.next_usize(2) == 0 {
        let at_step = 1 + rng.next_u32(step_cap);
        external_events.push(ScheduledEvent {
            at_step: at_step as u64,
            event: ExternalEvent::CloseGateJoin,
        });
    }

    external_events.sort_by_key(|event| event.at_step);

    let resources = if needs_resource {
        vec![ResourceSpec { id: 0, total: 2 }]
    } else {
        vec![]
    };

    let max_steps = cfg.max_steps.max(10);

    SimCase {
        exec_cfg,
        resources,
        programs,
        tasks,
        initial_runnable,
        external_events,
        max_steps,
    }
}

/// Ensures deterministic traces for a fixed case + choices.
#[test]
fn scheduler_sim_deterministic_basic() {
    let case = simple_case(42);
    let choices = vec![DriverChoice { idx: 0 }; 16];
    assert_deterministic(&case, &choices);

    let trace = run_with_choices(&case, &choices);
    let _ = trace_hash(&trace);
}

/// Replays any stored repro artifacts and validates trace hashes.
#[test]
fn scheduler_sim_replay_corpus() {
    let corpus_dir = "tests/simulation/corpus";
    let entries = fs::read_dir(corpus_dir).unwrap_or_else(|_| panic!("missing {corpus_dir}"));
    let mut coverage = CorpusCoverage::default();
    let mut artifacts = 0usize;

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        artifacts = artifacts.saturating_add(1);
        let data = fs::read_to_string(&path).expect("read corpus");
        let artifact: ReproArtifact = serde_json::from_str(&data).expect("parse artifact");
        coverage.observe_case(&artifact.case);
        let trace = run_with_choices(&artifact.case, &artifact.driver_choices);
        coverage.observe_trace(&trace);
        let hash = trace_hash(&trace);
        assert_eq!(
            hash, artifact.expected_trace_hash,
            "trace hash mismatch for {path:?}"
        );
    }

    assert!(artifacts > 0, "no corpus artifacts found in {corpus_dir}");
    coverage.assert_complete();
}

/// Smoke-stress the scheduler simulator with small randomized cases.
///
/// This test asserts that the core safety/liveness oracles never emit
/// `InvariantViolation` for a modest seed budget. Use the env vars described
/// in `StressConfig::from_env` to scale the run for cron or local stress.
#[test]
fn scheduler_sim_stress_smoke() {
    let cfg = StressConfig::from_env();
    for i in 0..cfg.seeds {
        let seed = cfg.seed_base.wrapping_add(i);
        let case = random_case(seed, cfg);
        let mut driver = RecordingDriver::new();
        let trace = run_with_driver(&case, |enabled| driver.choose(enabled));
        if let Some(event) = trace
            .events
            .iter()
            .find(|event| matches!(event, TraceEvent::InvariantViolation { .. }))
        {
            let mut violation = None;
            let mut message = "";
            if let TraceEvent::InvariantViolation { kind, message: msg } = event {
                violation = Some(kind.clone());
                message = msg;
            }

            let step = trace
                .events
                .iter()
                .rev()
                .find_map(|event| match event {
                    TraceEvent::Step { n, .. } => Some(*n),
                    _ => None,
                })
                .unwrap_or(0);

            if let Some(violation) = violation {
                write_failure_artifact(
                    seed,
                    case,
                    driver.choices,
                    &trace,
                    &violation,
                    message,
                    step,
                );
            }

            panic!("stress invariant violation at seed {seed}: {event:?}");
        }
    }
}
