//! A deterministic stand-in for the `cargo-fuzz` targets in `fuzz/`, so the
//! never-panic and decode-equivalence properties are exercised in ordinary CI
//! (which has no nightly toolchain or libFuzzer). It mirrors the two fuzz
//! targets: it must never panic on arbitrary input, and whenever we accept an
//! input the C oracle must accept it and agree byte-for-byte.

use libzstd_bitexact::{DecodeOptions, StreamDecoder};
use std::io::Read;

const LIMIT: usize = 16 << 20;

/// xorshift64* — deterministic, dependency-free generator.
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
    fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }
    fn byte(&mut self) -> u8 {
        (self.next_u64() & 0xFF) as u8
    }
}

/// The shared body of both fuzz targets: never panic, and never diverge from
/// the oracle on an accepted input (one-shot and streaming).
fn check(data: &[u8]) {
    let theirs = zstd::bulk::decompress(data, LIMIT);

    let ours = DecodeOptions::new().limit(LIMIT).decompress(data);
    if let Ok(ours) = &ours {
        match &theirs {
            Ok(theirs) => assert_eq!(ours, theirs, "one-shot accepted but differs: {data:02X?}"),
            Err(e) => panic!("one-shot accepted input C rejects ({e}): {data:02X?}"),
        }
    }

    let mut out = Vec::new();
    let mut decoder = StreamDecoder::with_options(data, DecodeOptions::new().limit(LIMIT));
    if decoder.read_to_end(&mut out).is_ok() {
        match &theirs {
            Ok(theirs) => assert_eq!(&out, theirs, "streaming accepted but differs: {data:02X?}"),
            Err(e) => panic!("streaming accepted input C rejects ({e}): {data:02X?}"),
        }
    }
}

#[test]
fn random_bytes_never_panic_and_stay_in_parity() {
    let mut rng = Rng::new(0xF0_02_F0_02);
    let magic = 0xFD2F_B528u32.to_le_bytes();
    for _ in 0..50_000 {
        let len = rng.below(96);
        let mut data = vec![0u8; len];
        for b in data.iter_mut() {
            *b = rng.byte();
        }
        // Bias a fraction toward the real frame magic so the inputs reach
        // header and block parsing rather than bouncing off prefix_unknown.
        if len >= 4 && rng.below(2) == 0 {
            data[..4].copy_from_slice(&magic);
        }
        check(&data);
    }
}

#[test]
fn mutated_valid_frames_stay_in_parity() {
    let mut rng = Rng::new(0x1234_5678_9ABC_DEF0);

    // A spread of real frames, then bit-flipped in handfuls of places.
    let bases: Vec<Vec<u8>> = {
        let text = b"the quick brown fox jumps over the lazy dog ".repeat(40);
        let runs = {
            let mut v = vec![1u8; 500];
            v.extend(std::iter::repeat_n(7u8, 300));
            v
        };
        let mut frames = Vec::new();
        for data in [text, runs, vec![0u8; 2000]] {
            for level in [1, 9, 19] {
                frames.push(zstd::bulk::compress(&data, level).unwrap());
            }
            // A window-descriptor frame (no declared content size) too.
            frames.push(zstd::stream::encode_all(&data[..], 3).unwrap());
        }
        frames
    };

    for base in &bases {
        for _ in 0..4000 {
            let mut m = base.clone();
            for _ in 0..(1 + rng.below(5)) {
                let at = rng.below(m.len());
                m[at] ^= 1 << rng.below(8);
            }
            check(&m);
        }
    }
}

#[test]
fn structurally_truncated_and_extended_frames() {
    let data = b"fuzz smoke corpus payload, mildly compressible 0123456789 ".repeat(60);
    let frame = zstd::bulk::compress(&data, 6).unwrap();
    let mut rng = Rng::new(0x0C0F_FEE0);

    // Every truncation, plus the frame with random trailing bytes appended.
    for len in 0..=frame.len() {
        check(&frame[..len]);
    }
    for _ in 0..2000 {
        let mut extended = frame.clone();
        for _ in 0..(1 + rng.below(8)) {
            extended.push(rng.byte());
        }
        check(&extended);
    }
}
