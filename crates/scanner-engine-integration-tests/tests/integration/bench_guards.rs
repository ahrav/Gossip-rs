// NOTE: This test is commented out pending benchmark migration from scanner-rs.
// The test reads `benches/timing_wheel.rs` from the scanner-rs crate, which has
// not yet been migrated to the gossip-rs workspace. Once the benchmark file is
// migrated, uncomment and update the path accordingly.

// use std::{fs, path::PathBuf};
//
// #[test]
// fn timing_wheel_push_reset_callback_is_noop() {
//     let bench_file = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("benches/timing_wheel.rs");
//     let src =
//         fs::read_to_string(&bench_file).expect("failed to read timing_wheel benchmark source");
//
//     let push_start = src
//         .find("fn bench_timing_wheel_push")
//         .expect("push benchmark function should exist");
//     let push_end = src[push_start..]
//         .find("fn bench_timing_wheel_advance_drain")
//         .map(|offset| push_start + offset)
//         .expect("advance_drain benchmark boundary should exist");
//     let push_fn = &src[push_start..push_end];
//
//     assert!(
//         !push_fn.contains("black_box(payload.hi_end)") && !push_fn.contains("black_box(payload.id)"),
//         "push benchmark reset drain should stay side-effect free; avoid per-item payload observation in reset callback"
//     );
// }
