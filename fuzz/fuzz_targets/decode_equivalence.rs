//! Fuzz target: decode-equivalence with the C oracle. Whenever we accept an
//! input, the C libzstd must also accept it and produce the identical bytes —
//! we must never accept something C rejects, nor decode it differently. The
//! streaming decoder is held to the same standard.
//!
//! Run with `cargo +nightly fuzz run decode_equivalence`. Mirrored
//! deterministically in `tests/fuzz_smoke.rs` for CI coverage.
#![no_main]

use libfuzzer_sys::fuzz_target;
use libzstd_bitexact_rs::{DecodeOptions, StreamDecoder};
use std::io::Read;

const LIMIT: usize = 64 << 20;

fuzz_target!(|data: &[u8]| {
    let theirs = zstd::bulk::decompress(data, LIMIT);

    if let Ok(ours) = DecodeOptions::new().limit(LIMIT).decompress(data) {
        match &theirs {
            Ok(theirs) => assert_eq!(&ours, theirs, "one-shot: accepted but outputs differ"),
            Err(e) => panic!("one-shot: we accepted input C rejects: {e}"),
        }
    }

    let mut out = Vec::new();
    let mut decoder = StreamDecoder::with_options(data, DecodeOptions::new().limit(LIMIT));
    if decoder.read_to_end(&mut out).is_ok() {
        match &theirs {
            Ok(theirs) => assert_eq!(&out, theirs, "streaming: accepted but outputs differ"),
            Err(e) => panic!("streaming: we accepted input C rejects: {e}"),
        }
    }
});
