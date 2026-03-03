//! Fuzz target for offline token validators.
//!
//! Exercises every [`OfflineValidationSpec`] variant with arbitrary byte
//! sequences to ensure no panics, no UB, and correct verdict semantics.
//!
//! The first byte of `data` selects the validator variant; the remainder is
//! passed as the secret. For the `Crc32Base62` variant, 3 additional bytes
//! are consumed to parameterise `prefix_skip`, `payload_len`, and
//! `checksum_len`.
//!
//! Invariant: every call must return `Valid`, `Invalid`, or `Indeterminate`
//! without panicking.

#![no_main]

use libfuzzer_sys::fuzz_target;
use scanner_engine::{fuzz_offline_validate, OfflineValidationSpec, OfflineVerdict};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let selector = data[0];
    let rest = &data[1..];

    let spec = match selector % 7 {
        0 => {
            // Crc32Base62 needs 3 parameter bytes.
            if rest.len() < 3 {
                return;
            }
            let spec = OfflineValidationSpec::Crc32Base62 {
                prefix_skip: rest[0],
                payload_len: rest[1],
                checksum_len: rest[2],
            };
            let secret = &rest[3..];
            let verdict = fuzz_offline_validate(spec, secret);
            assert!(
                matches!(
                    verdict,
                    OfflineVerdict::Valid | OfflineVerdict::Invalid | OfflineVerdict::Indeterminate
                ),
                "unexpected verdict: {verdict:?}",
            );
            return;
        }
        1 => OfflineValidationSpec::GithubFinegrainedPat,
        2 => OfflineValidationSpec::GrafanaServiceAccount,
        3 => OfflineValidationSpec::AwsAccessKey,
        4 => OfflineValidationSpec::SentryOrgToken,
        5 => OfflineValidationSpec::PyPiToken,
        6 => OfflineValidationSpec::SlackToken,
        _ => unreachable!(),
    };

    let verdict = fuzz_offline_validate(spec, rest);
    assert!(
        matches!(
            verdict,
            OfflineVerdict::Valid | OfflineVerdict::Invalid | OfflineVerdict::Indeterminate
        ),
        "unexpected verdict: {verdict:?}",
    );
});
