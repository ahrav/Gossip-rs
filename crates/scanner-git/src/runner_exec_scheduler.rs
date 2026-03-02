use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use memmap2::Mmap;

use super::{
    build_candidate_ranges, build_scheduler_shard_exec_plan, collect_skipped_candidates,
    empty_scheduler_output, merge_pack_exec_reports, merge_scanned_blobs, run_scheduler_pack_task,
    select_pack_exec_strategy, shard_count_for_pack, shard_ranges, ByteArena, BytesView,
    EngineAdapterConfig, GitScanCommonMetrics, GitScanError, ObjectFormat, PackDecodeLimits,
    PackExecError, PackExecScratch, PackExecStrategy, PackIoLimits, PackPlan, PackPlanHotDeps,
    SchedulerPackExecOutput, SchedulerPackScratch, SchedulerPackShared, SchedulerPackTask,
    SchedulerShardExecPlan, SchedulerShardMeta,
};
use scanner_scheduler::{Executor, ExecutorConfig, WorkerCtx};
use crate::events::EventSink;
use scanner_engine::Engine;

struct SchedulerExecEnv {
    engine: Arc<Engine>,
    event_sink: Arc<dyn EventSink>,
    midx_bytes: BytesView,
    object_format: ObjectFormat,
    pack_paths: Arc<Vec<PathBuf>>,
    loose_dirs: Arc<Vec<PathBuf>>,
    pack_mmaps: Arc<Vec<Option<Mmap>>>,
    path_arena: Arc<ByteArena>,
    spill_dir: Arc<PathBuf>,
    pack_decode: PackDecodeLimits,
    pack_io: PackIoLimits,
    adapter_cfg: EngineAdapterConfig,
    pack_cache_bytes: u32,
    exec_workers: usize,
    pin_threads: bool,
    commit_graph: Arc<crate::commit_graph::CommitGraphIndex>,
    commit_meta_seen: Arc<gossip_stdx::AtomicBitSet>,
}

impl SchedulerExecEnv {
    #[inline(always)]
    fn executor_config(&self) -> ExecutorConfig {
        ExecutorConfig {
            workers: self.exec_workers,
            seed: 0x853c49e6748fea9b,
            pin_threads: self.pin_threads,
            ..ExecutorConfig::default()
        }
    }

    fn build_shared(
        &self,
        plans: Arc<Vec<PackPlan>>,
        shard_meta: Option<Arc<Vec<SchedulerShardMeta>>>,
    ) -> Arc<SchedulerPackShared> {
        Arc::new(SchedulerPackShared {
            engine: Arc::clone(&self.engine),
            event_sink: Arc::clone(&self.event_sink),
            midx_bytes: self.midx_bytes.clone(),
            object_format: self.object_format,
            pack_paths: Arc::clone(&self.pack_paths),
            loose_dirs: Arc::clone(&self.loose_dirs),
            pack_mmaps: Arc::clone(&self.pack_mmaps),
            path_arena: Arc::clone(&self.path_arena),
            spill_dir: Arc::clone(&self.spill_dir),
            pack_decode: self.pack_decode,
            pack_io: self.pack_io,
            adapter_cfg: self.adapter_cfg,
            plans,
            shard_meta,
            commit_graph: Arc::clone(&self.commit_graph),
            commit_meta_seen: Arc::clone(&self.commit_meta_seen),
        })
    }
}

#[inline(always)]
fn scheduler_worker_scratch(pack_cache_bytes: u32) -> SchedulerPackScratch {
    SchedulerPackScratch {
        cache: super::PackCache::new(pack_cache_bytes),
        exec_scratch: PackExecScratch::default(),
        runtime: None,
    }
}

#[inline(always)]
fn store_scheduler_error(
    first_error: &Mutex<Option<GitScanError>>,
    abort_flag: &AtomicBool,
    err: GitScanError,
) {
    abort_flag.store(true, Ordering::Release);
    let mut guard = first_error
        .lock()
        .expect("scheduler pack error mutex poisoned");
    if guard.is_none() {
        *guard = Some(err);
    }
}

#[inline(always)]
fn take_scheduler_error(first_error: &Mutex<Option<GitScanError>>) -> Option<GitScanError> {
    first_error
        .lock()
        .expect("scheduler pack error mutex poisoned")
        .take()
}

#[inline(always)]
fn scheduler_queue_rejected_error(shard_queue: bool) -> GitScanError {
    GitScanError::PackExec(if shard_queue {
        PackExecError::SchedulerShardQueueRejected
    } else {
        PackExecError::SchedulerTaskQueueRejected
    })
}

fn collect_plan_outputs(
    plans: &[PackPlan],
    output_slots: &[Mutex<Option<SchedulerPackExecOutput>>],
) -> Result<Vec<SchedulerPackExecOutput>, GitScanError> {
    let mut merged = Vec::with_capacity(plans.len());
    for (plan_idx, slot) in output_slots.iter().enumerate() {
        let mut output = slot
            .lock()
            .expect("scheduler pack output slot poisoned")
            .take()
            .ok_or({
                GitScanError::PackExec(PackExecError::SchedulerPlanOutputMissing { plan_idx })
            })?;
        // Defer skip mapping to merge time so worker tasks avoid building
        // per-task skipped vectors in the hot path.
        collect_skipped_candidates(&plans[plan_idx], &output.report.skips, &mut output.skipped);
        merged.push(output);
    }
    Ok(merged)
}

fn execute_plan_tasks(
    env: SchedulerExecEnv,
    plans: Arc<Vec<PackPlan>>,
) -> Result<Vec<SchedulerPackExecOutput>, GitScanError> {
    let plan_count = plans.len();
    type OutputSlot = Mutex<Option<SchedulerPackExecOutput>>;
    let output_slots: Arc<Vec<OutputSlot>> =
        Arc::new((0..plan_count).map(|_| Mutex::new(None)).collect());
    let shared = env.build_shared(Arc::clone(&plans), None);
    let first_error: Arc<Mutex<Option<GitScanError>>> = Arc::new(Mutex::new(None));
    let abort_flag = Arc::new(AtomicBool::new(false));

    let pack_cache_bytes = env.pack_cache_bytes;
    let ex = Executor::<SchedulerPackTask>::new(
        env.executor_config(),
        move |_wid| scheduler_worker_scratch(pack_cache_bytes),
        {
            let shared = Arc::clone(&shared);
            let output_slots = Arc::clone(&output_slots);
            let first_error = Arc::clone(&first_error);
            let abort_flag = Arc::clone(&abort_flag);
            move |task, ctx: &mut WorkerCtx<SchedulerPackTask, SchedulerPackScratch>| {
                if abort_flag.load(Ordering::Acquire) {
                    return;
                }
                let seq = match task {
                    SchedulerPackTask::ExecPlan { seq } => seq,
                    SchedulerPackTask::ExecShard { .. } => return,
                };
                match run_scheduler_pack_task(
                    SchedulerPackTask::ExecPlan { seq },
                    &mut ctx.scratch,
                    &shared,
                ) {
                    Ok(output) => {
                        *output_slots[seq]
                            .lock()
                            .expect("scheduler pack output slot poisoned") = Some(output);
                    }
                    Err(err) => {
                        store_scheduler_error(first_error.as_ref(), abort_flag.as_ref(), err)
                    }
                }
            }
        },
    );

    let tasks: Vec<SchedulerPackTask> = (0..plan_count)
        .map(|seq| SchedulerPackTask::ExecPlan { seq })
        .collect();
    ex.spawn_external_batch(tasks)
        .map_err(|_| scheduler_queue_rejected_error(false))?;
    ex.join();

    if let Some(err) = take_scheduler_error(first_error.as_ref()) {
        return Err(err);
    }

    collect_plan_outputs(plans.as_ref(), output_slots.as_ref())
}

struct ShardDispatchPlan {
    shard_meta: Vec<SchedulerShardMeta>,
    tasks: Vec<SchedulerPackTask>,
}

fn build_shard_dispatch_plan(
    plans: &[PackPlan],
    shard_counts: &[(u16, usize)],
) -> ShardDispatchPlan {
    let mut shard_meta = Vec::with_capacity(plans.len());
    let mut tasks = Vec::new();

    for (plan_idx, plan) in plans.iter().enumerate() {
        let exec_plan = build_scheduler_shard_exec_plan(plan);
        let plan_hot_deps = PackPlanHotDeps::from_plan(plan);
        let exec_len = exec_plan.len();
        if exec_len == 0 {
            shard_meta.push(SchedulerShardMeta {
                exec_plan,
                plan_hot_deps,
                candidate_ranges: Vec::new(),
                shard_ranges: Vec::new(),
            });
            continue;
        }

        let candidate_ranges = if matches!(&exec_plan, SchedulerShardExecPlan::Explicit(_)) {
            let mut ranges = Vec::new();
            build_candidate_ranges(plan, &mut ranges);
            ranges
        } else {
            Vec::new()
        };
        let shard_count = shard_count_for_pack(shard_counts, plan.pack_id);
        let shard_ranges = shard_ranges(exec_len, shard_count);
        for shard_idx in 0..shard_ranges.len() {
            tasks.push(SchedulerPackTask::ExecShard {
                plan_idx,
                shard_idx,
            });
        }

        shard_meta.push(SchedulerShardMeta {
            exec_plan,
            plan_hot_deps,
            candidate_ranges,
            shard_ranges,
        });
    }

    ShardDispatchPlan { shard_meta, tasks }
}

fn build_shard_slot_bases(shard_meta: &[SchedulerShardMeta]) -> Vec<usize> {
    let mut shard_slot_base = Vec::with_capacity(shard_meta.len());
    let mut total_shard_slots = 0usize;
    for meta in shard_meta {
        shard_slot_base.push(total_shard_slots);
        total_shard_slots += meta.shard_ranges.len();
    }
    shard_slot_base
}

fn merge_shard_outputs(
    plans: &[PackPlan],
    shard_meta: &[SchedulerShardMeta],
    shard_slots: &[Mutex<Option<SchedulerPackExecOutput>>],
    shard_slot_base: &[usize],
) -> Result<Vec<SchedulerPackExecOutput>, GitScanError> {
    let mut merged = Vec::with_capacity(plans.len());
    for plan_idx in 0..plans.len() {
        let base = shard_slot_base[plan_idx];
        let shard_count = shard_meta[plan_idx].shard_ranges.len();
        if shard_count == 0 {
            merged.push(empty_scheduler_output());
            continue;
        }

        let mut reports = Vec::with_capacity(shard_count);
        let mut scanned_shards = Vec::with_capacity(shard_count);
        let mut skipped = Vec::new();
        let mut common_metrics = GitScanCommonMetrics::default();
        for shard_idx in 0..shard_count {
            let shard_output = shard_slots[base + shard_idx]
                .lock()
                .expect("scheduler shard output slot poisoned")
                .take()
                .ok_or({
                    GitScanError::PackExec(PackExecError::SchedulerShardOutputMissing {
                        plan_idx,
                        shard_idx,
                    })
                })?;
            reports.push(shard_output.report);
            scanned_shards.push(shard_output.scanned);
            common_metrics.merge_from(&shard_output.common_metrics);
        }

        let report = if reports.len() == 1 {
            reports.pop().expect("len checked")
        } else {
            merge_pack_exec_reports(reports)
        };
        collect_skipped_candidates(&plans[plan_idx], &report.skips, &mut skipped);
        let scanned = merge_scanned_blobs(scanned_shards);
        merged.push(SchedulerPackExecOutput {
            report,
            scanned,
            skipped,
            common_metrics,
        });
    }
    Ok(merged)
}

fn execute_sharded_tasks(
    env: SchedulerExecEnv,
    plans: Arc<Vec<PackPlan>>,
    shard_counts: Vec<(u16, usize)>,
) -> Result<Vec<SchedulerPackExecOutput>, GitScanError> {
    let plan_count = plans.len();
    let ShardDispatchPlan { shard_meta, tasks } =
        build_shard_dispatch_plan(plans.as_ref(), &shard_counts);

    if tasks.is_empty() {
        return Ok((0..plan_count).map(|_| empty_scheduler_output()).collect());
    }

    let shard_slot_base = Arc::new(build_shard_slot_bases(&shard_meta));
    let total_shard_slots = shard_meta
        .iter()
        .map(|meta| meta.shard_ranges.len())
        .sum::<usize>();
    type ShardSlot = Mutex<Option<SchedulerPackExecOutput>>;
    let shard_slots: Arc<Vec<ShardSlot>> =
        Arc::new((0..total_shard_slots).map(|_| Mutex::new(None)).collect());
    let shard_meta = Arc::new(shard_meta);

    let shared = env.build_shared(Arc::clone(&plans), Some(Arc::clone(&shard_meta)));
    let first_error: Arc<Mutex<Option<GitScanError>>> = Arc::new(Mutex::new(None));
    let abort_flag = Arc::new(AtomicBool::new(false));

    let pack_cache_bytes = env.pack_cache_bytes;
    let ex = Executor::<SchedulerPackTask>::new(
        env.executor_config(),
        move |_wid| scheduler_worker_scratch(pack_cache_bytes),
        {
            let shared = Arc::clone(&shared);
            let shard_slots = Arc::clone(&shard_slots);
            let shard_slot_base = Arc::clone(&shard_slot_base);
            let first_error = Arc::clone(&first_error);
            let abort_flag = Arc::clone(&abort_flag);
            move |task, ctx: &mut WorkerCtx<SchedulerPackTask, SchedulerPackScratch>| {
                if abort_flag.load(Ordering::Acquire) {
                    return;
                }
                let (plan_idx, shard_idx) = match task {
                    SchedulerPackTask::ExecShard {
                        plan_idx,
                        shard_idx,
                    } => (plan_idx, shard_idx),
                    SchedulerPackTask::ExecPlan { .. } => return,
                };
                match run_scheduler_pack_task(
                    SchedulerPackTask::ExecShard {
                        plan_idx,
                        shard_idx,
                    },
                    &mut ctx.scratch,
                    &shared,
                ) {
                    Ok(output) => {
                        let flat_idx = shard_slot_base[plan_idx] + shard_idx;
                        *shard_slots[flat_idx]
                            .lock()
                            .expect("scheduler shard output slot poisoned") = Some(output);
                    }
                    Err(err) => {
                        store_scheduler_error(first_error.as_ref(), abort_flag.as_ref(), err)
                    }
                }
            }
        },
    );

    ex.spawn_external_batch(tasks)
        .map_err(|_| scheduler_queue_rejected_error(true))?;
    ex.join();

    if let Some(err) = take_scheduler_error(first_error.as_ref()) {
        return Err(err);
    }

    merge_shard_outputs(
        plans.as_ref(),
        shard_meta.as_ref(),
        shard_slots.as_ref(),
        shard_slot_base.as_ref(),
    )
}

/// Execute pack plans via the scheduler `Executor` work-queue.
///
/// Selects a [`PackExecStrategy`] based on worker count and plan structure:
/// - **Serial / PackParallel**: each plan is one task; outputs are collected
///   into sequence-indexed slots for deterministic reassembly.
/// - **IntraPackSharded**: large plans are split into shards; per-shard
///   outputs are merged (reports summed, scanned blobs rebased) before
///   returning one output per plan.
///
/// On the first worker error, an abort flag prevents new tasks from starting.
/// The function joins all workers, then returns the first error encountered.
/// Outputs from successful plans are discarded on error.
struct SchedulerExecRequest {
    engine: Arc<Engine>,
    event_sink: Arc<dyn EventSink>,
    midx_bytes: BytesView,
    object_format: ObjectFormat,
    pack_paths: Arc<Vec<PathBuf>>,
    loose_dirs: Arc<Vec<PathBuf>>,
    pack_mmaps: Arc<Vec<Option<Mmap>>>,
    path_arena: Arc<ByteArena>,
    spill_dir: Arc<PathBuf>,
    plans: Vec<PackPlan>,
    pack_decode: PackDecodeLimits,
    pack_io: PackIoLimits,
    adapter_cfg: EngineAdapterConfig,
    pack_cache_bytes: u32,
    workers: usize,
    pin_threads: bool,
    commit_graph: Arc<crate::commit_graph::CommitGraphIndex>,
    commit_meta_seen: Arc<gossip_stdx::AtomicBitSet>,
}

fn execute_pack_plans_with_scheduler_request(
    request: SchedulerExecRequest,
) -> Result<Vec<SchedulerPackExecOutput>, GitScanError> {
    let SchedulerExecRequest {
        engine,
        event_sink,
        midx_bytes,
        object_format,
        pack_paths,
        loose_dirs,
        pack_mmaps,
        path_arena,
        spill_dir,
        plans,
        pack_decode,
        pack_io,
        adapter_cfg,
        pack_cache_bytes,
        workers,
        pin_threads,
        commit_graph,
        commit_meta_seen,
    } = request;
    if plans.is_empty() {
        return Ok(Vec::new());
    }

    let workers = workers.max(1);
    let strategy = select_pack_exec_strategy(workers, &plans);
    let exec_workers = match strategy {
        PackExecStrategy::Serial => 1,
        PackExecStrategy::PackParallel | PackExecStrategy::IntraPackSharded { .. } => workers,
    };

    let env = SchedulerExecEnv {
        engine,
        event_sink,
        midx_bytes,
        object_format,
        pack_paths,
        loose_dirs,
        pack_mmaps,
        path_arena,
        spill_dir,
        pack_decode,
        pack_io,
        adapter_cfg,
        pack_cache_bytes,
        exec_workers,
        pin_threads,
        commit_graph,
        commit_meta_seen,
    };

    let plans = Arc::new(plans);
    match strategy {
        PackExecStrategy::Serial | PackExecStrategy::PackParallel => execute_plan_tasks(env, plans),
        PackExecStrategy::IntraPackSharded { shard_counts } => {
            execute_sharded_tasks(env, plans, shard_counts)
        }
    }
}

pub(super) fn execute_pack_plans_with_scheduler(
    engine: Arc<Engine>,
    event_sink: Arc<dyn EventSink>,
    midx_bytes: BytesView,
    object_format: ObjectFormat,
    pack_paths: Arc<Vec<PathBuf>>,
    loose_dirs: Arc<Vec<PathBuf>>,
    pack_mmaps: Arc<Vec<Option<Mmap>>>,
    path_arena: Arc<ByteArena>,
    spill_dir: Arc<PathBuf>,
    plans: Vec<PackPlan>,
    pack_decode: PackDecodeLimits,
    pack_io: PackIoLimits,
    adapter_cfg: EngineAdapterConfig,
    pack_cache_bytes: u32,
    workers: usize,
    pin_threads: bool,
    commit_graph: Arc<crate::commit_graph::CommitGraphIndex>,
    commit_meta_seen: Arc<gossip_stdx::AtomicBitSet>,
) -> Result<Vec<SchedulerPackExecOutput>, GitScanError> {
    execute_pack_plans_with_scheduler_request(SchedulerExecRequest {
        engine,
        event_sink,
        midx_bytes,
        object_format,
        pack_paths,
        loose_dirs,
        pack_mmaps,
        path_arena,
        spill_dir,
        plans,
        pack_decode,
        pack_io,
        adapter_cfg,
        pack_cache_bytes,
        workers,
        pin_threads,
        commit_graph,
        commit_meta_seen,
    })
}
