#![no_main]

//! Fuzz target for seen-bitmap delta and roaring bitmap deserialization.

use libfuzzer_sys::fuzz_target;
use scanner_git::{RoaringSeenBitmap, SeenBitmapDelta};

fuzz_target!(|data: &[u8]| {
    let _ = SeenBitmapDelta::deserialize(data);
    if let Ok(bitmap) = RoaringSeenBitmap::deserialize(data) {
        let encoded = bitmap.serialize();
        let _ = RoaringSeenBitmap::deserialize(&encoded);
    }
});
