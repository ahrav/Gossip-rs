#![no_main]

//! Fuzz target for seen-bitmap delta and roaring bitmap deserialization.
//!
//! Exercises both parsers and verifies that successfully deserialized bitmaps
//! produce identical payloads after a serialize-then-deserialize round trip.

use libfuzzer_sys::fuzz_target;
use scanner_git::{RoaringSeenBitmap, SeenBitmapDelta};

fuzz_target!(|data: &[u8]| {
    let _ = SeenBitmapDelta::deserialize(data);
    if let Ok(bitmap) = RoaringSeenBitmap::deserialize(data) {
        let encoded = bitmap
            .serialize()
            .expect("serialize must succeed for a valid bitmap");
        let decoded =
            RoaringSeenBitmap::deserialize(&encoded).expect("round-trip deserialize failed");
        assert_eq!(bitmap, decoded, "round-trip produced different bitmap");
    }
});
