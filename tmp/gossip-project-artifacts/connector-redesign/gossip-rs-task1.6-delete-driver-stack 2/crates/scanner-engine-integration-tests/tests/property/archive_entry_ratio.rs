//! Property tests for per-entry inflation ratio accounting.

use proptest::prelude::*;
use scanner_scheduler::archive::{
    ArchiveBudgets, ArchiveConfig, BudgetHit, ChargeResult, EntrySkipReason,
};

fn cfg_with_ratio(ratio: u32) -> ArchiveConfig {
    ArchiveConfig {
        enabled: true,
        max_archive_depth: 2,
        max_entries_per_archive: 512,
        max_uncompressed_bytes_per_entry: u64::MAX,
        max_total_uncompressed_bytes_per_archive: u64::MAX,
        max_total_uncompressed_bytes_per_root: u64::MAX,
        max_archive_metadata_bytes: u64::MAX,
        max_inflation_ratio: ratio,
        ..ArchiveConfig::default()
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(192))]

    /// The per-entry ratio fires exactly when entry output would exceed
    /// `entry_compressed_in * ratio`, independent of archive-level credit.
    #[test]
    fn entry_ratio_tracks_current_entry_only(
        ratio in 1u32..8,
        entries in prop::collection::vec(
            (
                1u16..64u16,
                prop::collection::vec((0u16..16u16, 1u16..64u16), 1..24)
            ),
            1..24
        )
    ) {
        let mut b = ArchiveBudgets::new(&cfg_with_ratio(ratio));
        b.enter_archive().unwrap();

        for (initial_comp, steps) in entries {
            b.begin_entry().unwrap();
            b.charge_compressed_in(initial_comp as u64);
            let mut model_in = initial_comp as u64;
            let mut model_out = 0u64;

            for (extra_comp, out_req) in steps {
                b.charge_compressed_in(extra_comp as u64);
                model_in = model_in.saturating_add(extra_comp as u64);

                let requested = out_req as u64;
                let max_out = model_in.saturating_mul(ratio as u64);
                let rem = max_out.saturating_sub(model_out);
                let expected_allowed = requested.min(rem);

                let (actual_allowed, hit) = match b.charge_decompressed_out(requested) {
                    ChargeResult::Ok => (requested, None),
                    ChargeResult::Clamp { allowed, hit } => (allowed, Some(hit)),
                };

                prop_assert_eq!(actual_allowed, expected_allowed);

                if expected_allowed < requested {
                    prop_assert_eq!(
                        hit,
                        Some(BudgetHit::SkipEntry(EntrySkipReason::EntryInflationRatioExceeded))
                    );
                } else {
                    prop_assert!(!matches!(
                        hit,
                        Some(BudgetHit::SkipEntry(EntrySkipReason::EntryInflationRatioExceeded))
                    ));
                }

                model_out = model_out.saturating_add(actual_allowed);
                if actual_allowed < requested {
                    break;
                }
            }

            b.end_entry(model_out > 0);
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(192))]

    /// Discarded bytes advance the entry ratio counter the same way
    /// decompressed bytes do.  The model tracks `model_out` as the sum of
    /// both `charge_decompressed_out` and `charge_discarded_out` amounts.
    #[test]
    fn discarded_out_advances_entry_ratio(
        ratio in 1u32..8,
        comp_in in 1u16..64u16,
        ops in prop::collection::vec(
            // (is_discard, bytes)
            (any::<bool>(), 1u16..32u16),
            1..32
        )
    ) {
        let mut b = ArchiveBudgets::new(&cfg_with_ratio(ratio));
        b.enter_archive().unwrap();
        b.begin_entry().unwrap();
        b.charge_compressed_in(comp_in as u64);

        let max_out = (comp_in as u64).saturating_mul(ratio as u64);
        let mut model_out = 0u64;

        for (is_discard, bytes) in ops {
            let requested = bytes as u64;
            let rem = max_out.saturating_sub(model_out);
            let expected_allowed = requested.min(rem);

            let (actual_allowed, hit) = if is_discard {
                match b.charge_discarded_out(requested) {
                    ChargeResult::Ok => (requested, None),
                    ChargeResult::Clamp { allowed, hit } => (allowed, Some(hit)),
                }
            } else {
                match b.charge_decompressed_out(requested) {
                    ChargeResult::Ok => (requested, None),
                    ChargeResult::Clamp { allowed, hit } => (allowed, Some(hit)),
                }
            };

            prop_assert_eq!(actual_allowed, expected_allowed,
                "is_discard={}, requested={}, model_out={}, max_out={}",
                is_discard, requested, model_out, max_out);

            if expected_allowed < requested {
                prop_assert_eq!(
                    hit,
                    Some(BudgetHit::SkipEntry(EntrySkipReason::EntryInflationRatioExceeded))
                );
            }

            model_out = model_out.saturating_add(actual_allowed);
            if actual_allowed < requested {
                break;
            }
        }
    }
}

#[test]
fn entry_ratio_handles_saturating_inputs() {
    let mut b = ArchiveBudgets::new(&cfg_with_ratio(u32::MAX));
    b.enter_archive().unwrap();
    b.begin_entry().unwrap();
    b.charge_compressed_in(u64::MAX);

    // Exercises saturated multiplication paths without panicking.
    assert_eq!(b.charge_decompressed_out(u64::MAX - 1), ChargeResult::Ok);
}
