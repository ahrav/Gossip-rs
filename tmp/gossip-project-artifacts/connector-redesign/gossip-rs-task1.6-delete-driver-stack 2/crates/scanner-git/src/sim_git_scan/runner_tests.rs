//! Property tests for Git simulation runner (feature-gated).

#![cfg(all(test, feature = "stdx-proptest"))]

use proptest::prelude::*;

use crate::sim_git_scan::scenario::{
    GitBlobSpec, GitCommitSpec, GitObjectFormat, GitOid, GitRefSpec, GitRepoModel, GitScenario,
    GitTreeEntryKind, GitTreeEntrySpec, GitTreeSpec,
};
use crate::sim_git_scan::{GitFaultPlan, GitRunConfig, GitSimRunner, RunOutcome};

fn oid(val: u8) -> GitOid {
    GitOid {
        bytes: vec![val; 20],
    }
}

fn simple_scenario() -> GitScenario {
    GitScenario {
        schema_version: crate::sim_git_scan::scenario::GIT_SCENARIO_SCHEMA_VERSION,
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

proptest! {
    #[test]
    fn stability_holds_across_schedule_seeds(seed in 0u64..10_000, workers in 1u32..=4) {
        let scenario = simple_scenario();
        let cfg = GitRunConfig {
            workers,
            max_steps: 0,
            stability_runs: 2,
            trace_capacity: 128,
        };
        let runner = GitSimRunner::new(cfg, seed);
        let outcome = runner.run(&scenario, &GitFaultPlan::default());
        prop_assert!(
            matches!(outcome, RunOutcome::Ok { .. }),
            "unexpected outcome: {outcome:?}"
        );
    }
}
