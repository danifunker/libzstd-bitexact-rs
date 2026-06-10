//! Fuzz target: arbitrary input must never make the decoder panic, and must
//! never let it run away on memory. Both the one-shot and streaming paths are
//! exercised with a bounded output limit.
//!
//! Run with `cargo +nightly fuzz run decode_never_panic`. The same checks run
//! deterministically over a corpus in `tests/fuzz_smoke.rs` for CI coverage.
#![no_main]

use libfuzzer_sys::fuzz_target;
use libzstd_bitexact::{DecodeOptions, StreamDecoder};
use std::io::Read;

const LIMIT: usize = 64 << 20;

fuzz_target!(|data: &[u8]| {
    let _ = DecodeOptions::new().limit(LIMIT).decompress(data);

    let mut out = Vec::new();
    let mut decoder = StreamDecoder::with_options(data, DecodeOptions::new().limit(LIMIT));
    let _ = decoder.read_to_end(&mut out);
});
