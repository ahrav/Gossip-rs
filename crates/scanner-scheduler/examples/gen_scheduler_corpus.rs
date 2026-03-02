//! Generates deterministic scheduler simulation corpus artifacts.
//!
//! The corpus is consumed by `tests/simulation/scheduler_sim.rs` to replay traces and
//! enforce coverage across scheduler paths (steal vs injector vs local),
//! driver actions (time advance, external delivery), and bytecode variants
//! (spawn/yield, IO, sleep, resources, jump).
//!
//! Run with:
//! - `cargo run --example gen_scheduler_corpus --features scheduler-sim`
//!
//! Output:
//! - `tests/simulation/corpus/*.json`
//!
//! Keep each case small and targeted; the replay test asserts aggregate
//! coverage so no single artifact needs to exercise everything.
use std::fs;
use std::path::Path;

use scanner_scheduler::scheduler::sim_executor_harness::{
    DriverChoice, ExternalEvent, FailureInfo, FailureKind, Instruction, LogicalTaskInit,
    ReproArtifact, ResourceSpec, ScheduledEvent, SimCase, SimExecCfg, SpawnPlacement, TaskProgram,
    run_with_choices, trace_hash,
};

const SCHEMA_VERSION: u32 = 1;
const CORPUS_DIR: &str = "tests/simulation/corpus";

/// Serialize and write a repro artifact to disk.
fn write_artifact(path: &Path, artifact: &ReproArtifact) {
    let json = serde_json::to_string_pretty(artifact).expect("serialize artifact");
    fs::write(path, json).expect("write artifact");
}

/// Build a replay artifact with a stable trace hash for the given case.
///
/// # Note on Failure Kind
///
/// Corpus artifacts use `FailureKind::Timeout` as a sentinel value since
/// they represent successful runs stored for regression testing, not actual
/// failures. The `step` field records the total trace length.
fn build_artifact(case: SimCase, choices: Vec<DriverChoice>) -> ReproArtifact {
    let trace = run_with_choices(&case, &choices);
    let hash = trace_hash(&trace);
    ReproArtifact {
        schema_version: SCHEMA_VERSION,
        seed: case.exec_cfg.seed,
        case,
        driver_choices: choices,
        expected_trace_hash: hash,
        failure: FailureInfo {
            kind: FailureKind::Timeout,
            step: trace.events.len() as u64,
            message: "corpus artifact".to_string(),
        },
    }
}

/// Yield + completion, plus a future join-close to exercise time advance.
///
/// # Coverage
///
/// - Local yield re-enqueue
/// - Time advance (`AdvanceTimeTo` action)
/// - `CloseGateJoin` external event
/// - Single-worker execution path
fn case_basic(seed: u64) -> (SimCase, Vec<DriverChoice>) {
    let exec_cfg = SimExecCfg {
        workers: 1,
        steal_tries: 2,
        seed,
        wake_on_hoard_threshold: 32,
    };

    let programs = vec![TaskProgram {
        name: "basic".to_string(),
        code: vec![
            Instruction::Yield {
                placement: SpawnPlacement::Local,
            },
            Instruction::Complete,
        ],
    }];

    let case = SimCase {
        exec_cfg,
        resources: vec![],
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
    };

    (case, vec![])
}

/// Local spawn + second worker stealing from a victim.
///
/// # Coverage
///
/// - `Spawn` instruction with `Local` placement
/// - Multi-worker configuration (2 workers)
/// - Work stealing path (`PopSource::Steal`)
/// - Explicit driver choices forcing steal interleaving
fn case_steal(seed: u64) -> (SimCase, Vec<DriverChoice>) {
    let exec_cfg = SimExecCfg {
        workers: 2,
        steal_tries: 2,
        seed,
        wake_on_hoard_threshold: 32,
    };

    let programs = vec![
        TaskProgram {
            name: "root".to_string(),
            code: vec![
                Instruction::Spawn {
                    program: 1,
                    placement: SpawnPlacement::Local,
                },
                Instruction::Complete,
            ],
        },
        TaskProgram {
            name: "child".to_string(),
            code: vec![Instruction::Complete],
        },
    ];

    let case = SimCase {
        exec_cfg,
        resources: vec![],
        programs,
        tasks: vec![LogicalTaskInit {
            tid: 0,
            program: 0,
            pc: 0,
        }],
        initial_runnable: vec![0],
        external_events: vec![],
        max_steps: 20,
    };

    // Step worker 0 to spawn, then worker 1 to steal.
    let choices = vec![DriverChoice { idx: 0 }, DriverChoice { idx: 1 }];
    (case, choices)
}

/// IO completion + sleep wakeup + join gate close.
///
/// # Coverage
///
/// - `WaitIo` instruction and `IoComplete` external event
/// - `Sleep` instruction and time-based wakeup
/// - Injector pop path (external spawns after wakeup)
fn case_io_sleep(seed: u64) -> (SimCase, Vec<DriverChoice>) {
    let exec_cfg = SimExecCfg {
        workers: 1,
        steal_tries: 2,
        seed,
        wake_on_hoard_threshold: 32,
    };

    let programs = vec![TaskProgram {
        name: "io_sleep".to_string(),
        code: vec![
            Instruction::WaitIo { token: 7 },
            Instruction::Sleep { ticks: 2 },
            Instruction::Complete,
        ],
    }];

    let case = SimCase {
        exec_cfg,
        resources: vec![],
        programs,
        tasks: vec![LogicalTaskInit {
            tid: 0,
            program: 0,
            pc: 0,
        }],
        initial_runnable: vec![0],
        external_events: vec![
            ScheduledEvent {
                at_step: 1,
                event: ExternalEvent::IoComplete { token: 7 },
            },
            ScheduledEvent {
                at_step: 5,
                event: ExternalEvent::CloseGateJoin,
            },
        ],
        max_steps: 40,
    };

    (case, vec![])
}

/// Resource acquire/release with both success and failure branches.
///
/// # Coverage
///
/// - `TryAcquire` instruction (success path via `ok` jump)
/// - `TryAcquire` instruction (failure path via `fail` jump)
/// - `Release` instruction
/// - Resource accounting model validation
fn case_resources(seed: u64) -> (SimCase, Vec<DriverChoice>) {
    let exec_cfg = SimExecCfg {
        workers: 1,
        steal_tries: 2,
        seed,
        wake_on_hoard_threshold: 32,
    };

    let programs = vec![
        TaskProgram {
            name: "resource_release".to_string(),
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
        TaskProgram {
            name: "resource_fail".to_string(),
            code: vec![
                Instruction::TryAcquire {
                    res: 0,
                    units: 1,
                    ok: 1,
                    fail: 2,
                },
                Instruction::Complete,
                Instruction::Complete,
            ],
        },
    ];

    let case = SimCase {
        exec_cfg,
        resources: vec![ResourceSpec { id: 0, total: 1 }],
        programs,
        tasks: vec![
            LogicalTaskInit {
                tid: 0,
                program: 0,
                pc: 0,
            },
            LogicalTaskInit {
                tid: 1,
                program: 1,
                pc: 0,
            },
        ],
        initial_runnable: vec![0, 1, 0],
        external_events: vec![],
        max_steps: 20,
    };

    // Two run-tokens for task 0 ensure acquire + release are both executed.
    (case, vec![])
}

/// Global injector spawn path.
///
/// # Coverage
///
/// - `Spawn` instruction with `Global` placement
/// - Injector pop path (task pushed to global queue)
/// - Wake-on-spawn behavior (sibling unpark)
fn case_global_spawn(seed: u64) -> (SimCase, Vec<DriverChoice>) {
    let exec_cfg = SimExecCfg {
        workers: 2,
        steal_tries: 2,
        seed,
        wake_on_hoard_threshold: 32,
    };

    let programs = vec![
        TaskProgram {
            name: "root".to_string(),
            code: vec![
                Instruction::Spawn {
                    program: 1,
                    placement: SpawnPlacement::Global,
                },
                Instruction::Complete,
            ],
        },
        TaskProgram {
            name: "child".to_string(),
            code: vec![Instruction::Complete],
        },
    ];

    let case = SimCase {
        exec_cfg,
        resources: vec![],
        programs,
        tasks: vec![LogicalTaskInit {
            tid: 0,
            program: 0,
            pc: 0,
        }],
        initial_runnable: vec![0],
        external_events: vec![],
        max_steps: 20,
    };

    (case, vec![DriverChoice { idx: 0 }; 4])
}

/// External spawn placement for a newly allocated task.
///
/// # Coverage
///
/// - `Spawn` instruction with `External` placement
/// - Gate-respecting spawn (may fail if gate closed)
/// - Injector path for externally spawned tasks
fn case_external_spawn(seed: u64) -> (SimCase, Vec<DriverChoice>) {
    let exec_cfg = SimExecCfg {
        workers: 1,
        steal_tries: 2,
        seed,
        wake_on_hoard_threshold: 32,
    };

    let programs = vec![
        TaskProgram {
            name: "external_spawn_root".to_string(),
            code: vec![Instruction::Spawn {
                program: 1,
                placement: SpawnPlacement::External,
            }],
        },
        TaskProgram {
            name: "external_spawn_child".to_string(),
            code: vec![Instruction::Complete],
        },
    ];

    let case = SimCase {
        exec_cfg,
        resources: vec![],
        programs,
        tasks: vec![LogicalTaskInit {
            tid: 0,
            program: 0,
            pc: 0,
        }],
        initial_runnable: vec![0],
        external_events: vec![],
        max_steps: 20,
    };

    (case, vec![])
}

/// Jump instruction to exercise control-flow variants.
///
/// # Coverage
///
/// - `Jump` instruction (unconditional PC transfer)
/// - Non-sequential bytecode execution
fn case_jump(seed: u64) -> (SimCase, Vec<DriverChoice>) {
    let exec_cfg = SimExecCfg {
        workers: 1,
        steal_tries: 2,
        seed,
        wake_on_hoard_threshold: 32,
    };

    let programs = vec![TaskProgram {
        name: "jump".to_string(),
        code: vec![Instruction::Jump { target: 1 }, Instruction::Complete],
    }];

    let case = SimCase {
        exec_cfg,
        resources: vec![],
        programs,
        tasks: vec![LogicalTaskInit {
            tid: 0,
            program: 0,
            pc: 0,
        }],
        initial_runnable: vec![0],
        external_events: vec![],
        max_steps: 10,
    };

    (case, vec![])
}

fn main() {
    let out_dir = Path::new(CORPUS_DIR);
    fs::create_dir_all(out_dir).expect("create corpus dir");

    let cases = vec![
        ("basic", case_basic(0xA1)),
        ("steal", case_steal(0xB2)),
        ("io_sleep", case_io_sleep(0xC3)),
        ("resources", case_resources(0xD4)),
        ("global_spawn", case_global_spawn(0xE5)),
        ("external_spawn", case_external_spawn(0xF6)),
        ("jump", case_jump(0xA7)),
    ];

    for (name, (case, choices)) in cases {
        let artifact = build_artifact(case, choices);
        let path = out_dir.join(format!("{name}.json"));
        write_artifact(&path, &artifact);
    }
}
