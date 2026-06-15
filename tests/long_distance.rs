//! Differential tests for long-distance-matching frames and windows beyond
//! 128 MiB. Long-distance matching is an encoder-side decision; the decoder
//! merely sees sequences with large offsets and frames with large window
//! descriptors. These tests confirm the C oracle's LDM output round-trips
//! through both the one-shot and streaming decoders, and that a window log
//! above 27 (128 MiB) is accepted.

use libzstd_bitexact_rs::{DecodeOptions, StreamDecoder};
use std::io::{Read, Write};
use zstd::zstd_safe::CParameter;

/// xorshift64* — deterministic test data generator.
struct Rng(u64);
impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed.max(1))
    }
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn bytes(&mut self, len: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(len);
        while v.len() < len {
            v.extend_from_slice(&self.next_u64().to_le_bytes());
        }
        v.truncate(len);
        v
    }
}

fn compress_ldm(data: &[u8], window_log: u32, level: i32) -> Vec<u8> {
    let mut enc = zstd::stream::Encoder::new(Vec::new(), level).unwrap();
    enc.set_parameter(CParameter::EnableLongDistanceMatching(true))
        .unwrap();
    enc.set_parameter(CParameter::WindowLog(window_log))
        .unwrap();
    enc.set_parameter(CParameter::ContentSizeFlag(false))
        .unwrap();
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

fn window_log_of(frame: &[u8]) -> u32 {
    assert_eq!(frame[4] & 0x20, 0, "expected a windowed frame");
    10 + (frame[5] >> 3) as u32
}

fn stream_decode(frame: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    StreamDecoder::new(frame).read_to_end(&mut out).unwrap();
    out
}

#[test]
fn long_distance_matches_decode_correctly() {
    let mut rng = Rng::new(0x1D15_7A9C);

    // A distinctive head, ~4 MiB of filler, then the head again — a repeat
    // far enough apart that long-distance matching produces a multi-megabyte
    // offset (the case ordinary match finders miss).
    let head = rng.bytes(96 * 1024);
    let mut data = Vec::with_capacity(5 << 20);
    data.extend_from_slice(&head);
    while data.len() < 4 << 20 {
        // Semi-compressible filler so the stream is not all one giant match.
        let mut chunk = rng.bytes(8192);
        for b in chunk.iter_mut().take(2048) {
            *b = b' ' + (*b & 0x3F);
        }
        data.extend_from_slice(&chunk);
    }
    data.extend_from_slice(&head);

    // Window logs that do and do not span the 4 MiB repeat distance.
    for window_log in [21u32, 23, 24] {
        let frame = compress_ldm(&data, window_log, 19);
        let one_shot = libzstd_bitexact_rs::decompress(&frame)
            .unwrap_or_else(|e| panic!("one-shot LDM wlog {window_log}: {e}"));
        assert_eq!(one_shot, data, "one-shot LDM wlog {window_log}");
        assert_eq!(
            stream_decode(&frame),
            data,
            "streaming LDM wlog {window_log}"
        );
    }
}

#[test]
fn windows_beyond_128_mib_are_accepted() {
    // A large window descriptor with tiny content: the decoder must accept the
    // window (default windowLogMax is the format maximum, 31) without trying
    // to allocate the whole window — it only ever retains the content.
    let data = b"a little content living under a very large window. ".repeat(200);

    let mut saw_large = false;
    for window_log in [28u32, 30, 31] {
        let frame = compress_ldm(&data, window_log, 3);
        let actual = window_log_of(&frame);
        if actual > 27 {
            saw_large = true;
        }
        let one_shot = libzstd_bitexact_rs::decompress(&frame)
            .unwrap_or_else(|e| panic!("one-shot wlog {window_log} (actual {actual}): {e}"));
        assert_eq!(one_shot, data, "one-shot large window {actual}");
        assert_eq!(
            stream_decode(&frame),
            data,
            "streaming large window {actual}"
        );
    }
    assert!(
        saw_large,
        "expected at least one frame with a window above 128 MiB"
    );
}

#[test]
fn large_window_can_be_rejected_by_window_log_max() {
    // The window-log ceiling still composes: a frame above the configured max
    // is rejected even though it is a valid large-window frame.
    let data = b"content".repeat(1000);
    let frame = compress_ldm(&data, 28, 3);
    let actual = window_log_of(&frame);
    assert!(
        DecodeOptions::new()
            .window_log_max(actual - 1)
            .decompress(&frame)
            .is_err()
    );
    assert_eq!(
        DecodeOptions::new()
            .window_log_max(actual)
            .decompress(&frame)
            .unwrap(),
        data
    );
}
